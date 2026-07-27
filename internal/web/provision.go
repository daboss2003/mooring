package web

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/compose"
	"github.com/daboss2003/mooring/internal/dockerexec"
	"github.com/daboss2003/mooring/internal/monitor"
)

// M8 app provisioning (plan §7). Mooring GENERATES and owns the compose from a
// typed spec (mooring.yaml under the hood) — there is deliberately NO raw-compose
// or Dockerfile paste path: the same definition drives the app from the web or the
// CLI, dangerous compose keys cannot be expressed, and the generated YAML still
// passes §5.6. Commit writes to a 0700 staging dir + atomic rename(2), then a
// §0-gated deploy.

const composeFileName = "docker-compose.yml"

// provisionSlugRe gates the app id BEFORE it is ever used to build a run-dir path,
// fail-closed, on every wizard route.
var provisionSlugRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}$`)

type provisionedView struct {
	Slug     string
	Source   string
	Deployed bool
	UpCount  int
	Total    int
}

// handleProvisionNew redirects to the repo-connect flow. The single-service "New app"
// FORM was retired: a repo's mooring.yaml is the source of truth for an app, so
// creating an app means connecting a Git repo whose mooring.yaml defines it (Mooring
// scaffolds a starter if the repo has none). Old links/bookmarks land here.
func (s *Server) handleProvisionNew(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/git/new", http.StatusSeeOther)
}

// handleProvisionDeploy brings a committed provisioned app up — a §0-gated
// write-plane action: §5.6 the on-disk compose, materialize config files + env,
// then `docker compose up` under the one-docker-child semaphore.
func (s *Server) handleProvisionDeploy(w http.ResponseWriter, r *http.Request) {
	if s.provStore == nil || s.runner == nil {
		http.Error(w, "write plane unavailable", http.StatusServiceUnavailable)
		return
	}
	slug := r.PathValue("project")
	actor := sessionUser(r)
	peer := ClientIP(r.Context()).String()
	if s.cfg.IsProtectedProject(slug) {
		http.Error(w, "protected project", http.StatusForbidden)
		return
	}
	app, ok, err := s.provStore.Get(slug)
	if err != nil || !ok {
		http.Error(w, "app not found", http.StatusNotFound)
		return
	}
	if allowed, reason := s.runner.WriteAllowed(); !allowed {
		http.Error(w, reason, http.StatusForbidden)
		return
	}
	if !s.gitDeploy.TryAcquire() { // shared single-flight with git deploys
		http.Error(w, "a deploy is already in progress; try again shortly", http.StatusConflict)
		return
	}
	defer s.gitDeploy.Release()

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	clearWriteDeadline(w) // long-lived deploy stream — exempt from the 60s WriteTimeout
	flusher, _ := w.(http.Flusher)
	writeln := func(format string, a ...any) {
		fmt.Fprintf(w, format+"\n", a...)
		if flusher != nil {
			flusher.Flush()
		}
	}

	runDir := s.appRunDir(slug)
	composeAbs := filepath.Join(runDir, filepath.FromSlash(app.ComposePath))
	mapp := &monitor.App{Project: slug, WorkingDir: runDir, ConfigFiles: []string{composeAbs}}
	env := s.composeEnv(mapp)

	writeln("$ deploy %s", slug)
	if res := s.validateAppCompose(mapp, env); !res.OK() {
		if s.cfg.ComposeValidation.Mode != "review" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			writeln("deploy blocked by the §5.6 compose validator:")
			for _, v := range res.Violations {
				writeln("  - %s", v.String())
			}
			_ = s.audit.Log(r.Context(), audit.Event{Actor: actor, IP: peer, Action: "provision_deploy", Target: slug, Outcome: audit.Deny, Level: audit.Security, Detail: "compose validation failed"})
			return
		}
		writeln("WARNING (review mode): %d validator finding(s); proceeding.", len(res.Violations))
	}
	if err := s.materializeConfigFiles(mapp, env); err != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		writeln("deploy blocked: %v", err)
		return
	}
	envFile, cleanup, ferr := s.renderEnvFile(mapp, env)
	defer cleanup()
	if ferr != nil {
		writeln("could not render env file")
		return
	}
	depID := s.recordRepoDeployStart(context.Background(), slug, "provision", actor, "deploy")
	writeln("$ docker compose up -d --remove-orphans")
	job := dockerexec.Job{Project: slug, Dir: runDir, ConfigFiles: mapp.ConfigFiles, EnvFile: envFile, Action: []string{"up", "-d", "--remove-orphans"}}
	// Suppress the self-healing supervisor for this app while we intentionally
	// provision/recreate it (plan §8.5).
	defer s.leaseExpectedDown(r.Context(), slug)()
	onl := func(line string) { writeln("%s", line) }
	declared := s.reapScope(r.Context(), slug)
	runErr := s.runUpWithConflictReap(r.Context(), slug, declared,
		func(c context.Context, ol func(string)) error { return s.runner.Run(c, job, ol) },
		s.runner.RemoveContainers, onl)
	code, outcome := classifyExit(runErr)
	s.recordDeployFinish(context.Background(), depID, code, outcome)
	if runErr != nil {
		s.streamOOMHint(r.Context(), slug, declared, onl)
		writeln("\n[failed: %v]", runErr)
		_ = s.audit.Log(r.Context(), audit.Event{Actor: actor, IP: peer, Action: "provision_deploy", Target: slug, Outcome: audit.Error, Level: audit.Security})
		return
	}
	writeln("\n[done]")
	_ = s.audit.Log(r.Context(), audit.Event{Actor: actor, IP: peer, Action: "provision_deploy", Target: slug, Outcome: audit.OK, Level: audit.Security})
}

// handleProvisionDelete tears down a provisioned app: best-effort `compose down`,
// remove the run dir, drop the registry row. (Env/config rows are left for now;
// a full purge lands with backup/restore in M18.)
func (s *Server) handleProvisionDelete(w http.ResponseWriter, r *http.Request) {
	if s.provStore == nil {
		http.Error(w, "provisioning unavailable", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	slug := r.PathValue("project")
	if s.cfg.IsProtectedProject(slug) {
		http.Error(w, "protected project", http.StatusForbidden)
		return
	}
	app, ok, _ := s.provStore.Get(slug)
	if !ok {
		http.Error(w, "app not found", http.StatusNotFound)
		return
	}
	runDir := s.appRunDir(slug)
	// Best-effort stop (only if the write plane is armed and free).
	if s.runner != nil {
		if allowed, _ := s.runner.WriteAllowed(); allowed && s.gitDeploy.TryAcquire() {
			composeAbs := filepath.Join(runDir, filepath.FromSlash(app.ComposePath))
			job := dockerexec.Job{Project: slug, Dir: runDir, ConfigFiles: []string{composeAbs}, Action: []string{"down", "--remove-orphans"}}
			_ = s.runner.Run(r.Context(), job, func(string) {})
			s.gitDeploy.Release()
		}
	}
	// Remove the run dir, confined under appsRoot (defense-in-depth).
	if confinedUnder(runDir, s.appsRoot()) && filepath.Dir(filepath.Clean(runDir)) == filepath.Clean(s.appsRoot()) {
		_ = os.RemoveAll(runDir)
	}
	_ = s.provStore.Delete(r.Context(), slug)
	_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "provision_delete", Target: slug, Outcome: audit.OK, Level: audit.Security})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// provEnv builds the env used to validate a candidate (the encrypted store only;
// a not-yet-committed app has no on-disk .env). Resolved to a fixpoint so
// validate == deploy.
func (s *Server) provEnv(slug string) compose.Env {
	env := compose.Env{}
	if s.envStore != nil {
		if rendered, err := s.envStore.Render(slug); err == nil {
			for k, v := range rendered {
				env[k] = v
			}
		}
	}
	return resolveEnvValues(env)
}

// provisionedApps returns the registry rows annotated with live deploy status
// from the snapshot (for the home "Provisioned apps" panel).
func (s *Server) provisionedApps() []provisionedView {
	if s.provStore == nil {
		return nil
	}
	apps, err := s.provStore.List()
	if err != nil {
		return nil
	}
	snap := s.snapshot()
	var out []provisionedView
	for _, a := range apps {
		v := provisionedView{Slug: a.Slug, Source: a.Source}
		if snap != nil {
			if app := snap.AppByProject(a.Slug); app != nil {
				v.Deployed = true
				v.UpCount = app.UpCount()
				v.Total = app.Total()
			}
		}
		out = append(out, v)
	}
	return out
}
