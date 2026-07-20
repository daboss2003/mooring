package web

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/crypto"
	"github.com/daboss2003/mooring/internal/dockerexec"
)

// dockerDownAcquireTimeout bounds how long a delete waits for the shared git/deploy
// slot before giving up. The operator just re-authenticated and expects a brief wait;
// if a long deploy still holds it, the delete refuses (nothing deleted) so it can never
// proceed to wipe records while the containers are still up.
const dockerDownAcquireTimeout = 45 * time.Second

// handleAppDelete permanently removes an app. It is the most destructive operator
// action, so beyond auth+CSRF it requires: the project must not be protected, the write
// plane must be armed (the teardown stops + removes containers), and the operator must
// RE-AUTHENTICATE (password, plus a TOTP code when 2FA is enabled) — gated by the same
// brute-force lockout as login. It then runs the full teardown: `compose down --volumes
// --remove-orphans` (containers, networks, AND data volumes), removes the run dir + the
// git object store (the local repo clone), and erases every per-app record. Irreversible.
func (s *Server) handleAppDelete(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("project")
	actor := sessionUser(r)
	peer := ClientIP(r.Context()).String()

	if s.cfg.IsProtectedProject(slug) {
		_ = s.audit.Log(r.Context(), audit.Event{Actor: actor, IP: peer, Action: "app_delete", Target: slug, Outcome: audit.Deny, Level: audit.Security, Detail: "protected project"})
		http.Error(w, "protected project", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if !s.appExists(slug) {
		http.Error(w, "app not found", http.StatusNotFound)
		return
	}
	// The teardown stops + removes containers, so it needs the write plane.
	if s.runner != nil {
		if ok, reason := s.runner.WriteAllowed(); !ok {
			http.Error(w, reason, http.StatusForbidden)
			return
		}
	}

	// Re-authenticate, behind the SAME lockout as login (a failed delete attempt counts
	// toward it, so this endpoint can't be used to brute-force the password).
	if s.locked(r.Context(), peer, actor) {
		_ = s.audit.Log(r.Context(), audit.Event{Actor: actor, IP: peer, Action: "app_delete", Target: slug, Outcome: audit.Deny, Level: audit.Security, Detail: "locked out"})
		http.Error(w, "too many attempts — try again later", http.StatusTooManyRequests)
		return
	}
	// Password first; TOTP only checked when the password matched (&&-short-circuit) so a
	// wrong password can't burn the single-use TOTP watermark.
	reauthOK := s.verifyOperatorPassword(r.Context(), actor, r.PostFormValue("password")) &&
		s.verifyTOTPOnce(r.Context(), actor, r.PostFormValue("totp"))
	if !reauthOK {
		s.recordFailure(r.Context(), peer, actor)
		_ = s.audit.Log(r.Context(), audit.Event{Actor: actor, IP: peer, Action: "app_delete", Target: slug, Outcome: audit.Deny, Level: audit.Security, Detail: "re-auth failed"})
		http.Error(w, "password or 2FA code incorrect — app not deleted", http.StatusForbidden)
		return
	}
	s.clearFailures(r.Context(), peer, actor)

	gateErr, errs := s.teardownApp(r.Context(), slug)
	if gateErr != nil {
		// Nothing was deleted — the app is intact; the operator can retry.
		_ = s.audit.Log(r.Context(), audit.Event{Actor: actor, IP: peer, Action: "app_delete", Target: slug, Outcome: audit.Deny, Level: audit.Security, Detail: "aborted before teardown: " + gateErr.Error()})
		http.Error(w, gateErr.Error(), http.StatusConflict)
		return
	}
	outcome, detail := audit.OK, "full teardown"
	if len(errs) > 0 {
		outcome, detail = audit.Error, fmt.Sprintf("%d teardown error(s) after containers were removed; first: %v", len(errs), errs[0])
		s.log.Warn("app delete completed with errors", "project", slug, "errors", len(errs), "first", errs[0])
	}
	_ = s.audit.Log(r.Context(), audit.Event{Actor: actor, IP: peer, Action: "app_delete", Target: slug, Outcome: outcome, Level: audit.Security, Detail: detail})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// appExists reports whether the slug names any app Mooring knows about (repo-backed,
// provisioned, or currently running in the snapshot).
func (s *Server) appExists(slug string) bool {
	if s.gitStore != nil {
		if _, ok, _ := s.gitStore.Get(slug); ok {
			return true
		}
	}
	if s.provStore != nil {
		if _, ok, _ := s.provStore.Get(slug); ok {
			return true
		}
	}
	if snap := s.snapshot(); snap != nil && snap.AppByProject(slug) != nil {
		return true
	}
	return false
}

// verifyOperatorPassword checks a re-entered password against the configured hash,
// behind the same bounded argon2id gate login uses (so it can't be used to OOM a box).
func (s *Server) verifyOperatorPassword(ctx context.Context, username, password string) bool {
	if password == "" {
		return false
	}
	sec := s.security()
	u, ok := sec.user(username)
	if !ok {
		return false
	}
	select {
	case s.verifySem <- struct{}{}:
	case <-time.After(2 * time.Second):
		return false
	case <-ctx.Done():
		return false
	}
	pwOK, _ := crypto.VerifyPassword(u.passwordHash, []byte(password))
	<-s.verifySem
	return pwOK
}

// teardownApp removes EVERYTHING an app owns. It returns (gateErr, errs):
//   - gateErr != nil means the GATE failed — the containers could not be stopped
//     (busy lock or `down` error) — so NOTHING destructive ran; the app is intact and
//     the caller should report failure and let the operator retry.
//   - gateErr == nil means containers/volumes are gone and the rest ran best-effort;
//     errs holds any non-fatal cleanup failures (e.g. a leftover DB row). Identity rows
//     (git config / provision registry) are deleted LAST so a mid-teardown failure
//     still leaves the app discoverable for an idempotent retry.
func (s *Server) teardownApp(ctx context.Context, slug string) (error, []error) {
	// Hold the shared git/deploy slot for the WHOLE teardown (bounded blocking acquire,
	// not best-effort): this both serializes us with any in-flight deploy/fetch AND
	// stops a NEW deploy from bringing the app back up (or rewriting the object store)
	// while we remove it. If the slot can't be had in time, abort with nothing deleted.
	actx, cancel := context.WithTimeout(ctx, dockerDownAcquireTimeout)
	acqErr := s.gitDeploy.Acquire(actx)
	cancel()
	if acqErr != nil {
		return fmt.Errorf("another git/deploy operation is in progress, so %q's containers could not be stopped — nothing was deleted; try again in a moment", slug), nil
	}
	defer s.gitDeploy.Release()

	// GATE: stop + remove containers, networks, AND named volumes (data) FIRST. This
	// must SUCCEED before any irreversible deletion — a skipped/failed `down` would
	// orphan live containers + data volumes while we wipe the records that track them.
	if s.runner != nil {
		runDir := s.appRunDir(slug)
		job := dockerexec.Job{Project: slug, Action: []string{"down", "--volumes", "--remove-orphans"}}
		composeAbs := filepath.Join(runDir, "docker-compose.yml")
		if fi, err := os.Stat(composeAbs); err == nil && !fi.IsDir() {
			job.Dir = runDir
			job.ConfigFiles = []string{composeAbs}
		}
		if derr := s.runner.Run(ctx, job, func(string) {}); derr != nil {
			return fmt.Errorf("could not stop and remove %q's containers/volumes — nothing was deleted: %w", slug, derr), nil
		}
	}

	var errs []error
	add := func(label string, err error) {
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", label, err))
		}
	}

	// On-disk trees, each confined to its owned parent (defense-in-depth).
	runDir := s.appRunDir(slug)
	if confinedUnder(runDir, s.appsRoot()) && filepath.Dir(filepath.Clean(runDir)) == filepath.Clean(s.appsRoot()) {
		add("run dir", os.RemoveAll(runDir))
	}
	gitRoot := filepath.Join(s.cfg.DataDir, "git")
	objDir := s.gitObjectDir(slug)
	if confinedUnder(objDir, gitRoot) && filepath.Dir(filepath.Clean(objDir)) == filepath.Clean(gitRoot) {
		add("git object store", os.RemoveAll(objDir))
	}

	// Clear the app's public edge + L4 routes and push the change live.
	if s.edgeRoutes != nil {
		add("edge routes", s.edgeRoutes.ReplaceProject(ctx, slug, nil))
		if s.edgeRecon != nil {
			_ = s.edgeRecon.Reconcile(ctx)
		}
	}
	if s.l4Routes != nil {
		add("l4 routes", s.l4Routes.ReplaceProject(ctx, slug, nil))
		if s.l4Reconcile != nil {
			_ = s.l4Reconcile(ctx)
		}
	}

	// Per-app records. Each delete runs on its own (no nested query while a cursor is
	// open — the single-connection pool would self-deadlock).
	if s.setupStore != nil {
		add("setup", s.setupStore.DeleteApp(ctx, slug))
	}
	if s.defStore != nil {
		add("definition", s.defStore.DeleteApp(ctx, slug))
	}
	if s.envStore != nil {
		add("env/secrets", s.envStore.DeleteApp(ctx, slug))
	}
	if s.cfgStore != nil {
		add("config files", s.cfgStore.DeleteApp(ctx, slug))
	}
	if s.scaling != nil {
		add("scaling", s.scaling.DeleteApp(ctx, slug))
	}
	if s.cronStore != nil {
		add("scheduled tasks", s.cronStore.DeleteApp(ctx, slug))
	}
	if s.selfHeal != nil {
		add("self-healing", s.selfHeal.DeleteApp(ctx, slug))
	}
	if s.opsStore != nil {
		add("ops", s.opsStore.DeleteApp(slug))
	}
	if s.imageScans != nil {
		add("vuln scans", s.imageScans.Delete(ctx, slug))
	}
	if s.alertStore != nil {
		add("alerts", s.alertStore.DeleteApp(ctx, slug))
	}
	if s.apiTokens != nil {
		_, err := s.apiTokens.RevokeAppScoped(ctx, slug)
		add("api tokens", err)
	}
	// Monitor + deploy history (re-created only for LIVE projects, and this one is gone).
	if s.db != nil {
		_, e1 := s.db.ExecContext(ctx, `DELETE FROM apps WHERE project=?`, slug)
		add("monitor apps", e1)
		_, e2 := s.db.ExecContext(ctx, `DELETE FROM container_metrics WHERE project=?`, slug)
		add("monitor metrics", e2)
		_, e3 := s.db.ExecContext(ctx, `DELETE FROM deploys WHERE project=?`, slug)
		add("deploy ledger", e3)
	}

	// Identity rows LAST: while either of these survives, appExists() still finds the
	// app, so an interrupted teardown can be retried to completion.
	if s.gitStore != nil {
		add("git config", s.gitStore.Delete(ctx, slug))
	}
	if s.provStore != nil {
		add("provision registry", s.provStore.Delete(ctx, slug))
	}

	return nil, errs
}
