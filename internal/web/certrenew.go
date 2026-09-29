package web

import (
	"context"
	"errors"
	"maps"
	"path/filepath"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/dockerexec"
	"github.com/daboss2003/mooring/internal/git"
	"github.com/daboss2003/mooring/internal/gitstore"
	"github.com/daboss2003/mooring/internal/monitor"
	"github.com/daboss2003/mooring/internal/selfheal"
)

// RunCertRenewWatcher closes the cert-renewal gap (plan §7.5): the edge auto-renews
// each leaf (~30 days before expiry), but the copy mounted into a TLS-terminating
// service (cert_bindings — EMQX :8883, a DoT resolver :853, …) is otherwise refreshed
// only on a deploy, so the service serves the OLD leaf until a manual redeploy. This
// watcher re-syncs each app's cert_bindings from the edge and, when a leaf ACTUALLY
// changed, recreates the affected services via the EXACT deploy machinery — no
// redeploy needed.
//
// Safe + idempotent by construction:
//   - acts ONLY when the synced leaf digest changed (changedServices); an unchanged
//     leaf is a no-op (re-sync writes identical bytes → same digest → nothing recreated)
//   - takes the single-flight deploy lock (gitDeploy) so it never races a deploy — with paced
//     starts only around each service's docker call, stopping when a git operation holds it
//   - holds an expected-down lease per app so self-heal ignores the brief recreate
//   - reuses syncCertBindings + managedDigests/changedServices + renderEnvFile + the
//     deploy's `up --force-recreate` job, so a renewal recreate == a deploy recreate
//
// Gated by the caller to the write plane + managed edge. Linux/runtime path — not
// exercised off-Linux.
func (s *Server) RunCertRenewWatcher(ctx context.Context, interval time.Duration) {
	if s.gitStore == nil || s.defStore == nil || s.runner == nil || s.edgeRecon == nil {
		return // no repo apps / no canonical / no write plane / edge not owned
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.certRenewTick(ctx)
		}
	}
}

func (s *Server) certRenewTick(ctx context.Context) {
	apps, err := s.gitStore.List()
	if err != nil {
		return
	}
	for _, cfg := range apps {
		if ctx.Err() != nil {
			return
		}
		if cfg.DeployedCommit == "" { // never deployed → nothing is mounted to refresh
			continue
		}
		def, derr := s.defStore.Current(cfg.Project)
		if derr != nil || def == nil || !defHasCertBindings(def) {
			continue
		}
		s.refreshCertsForApp(ctx, cfg, def)
	}
}

// refreshCertsForApp re-syncs one app's issued leaves and recreates the services whose
// leaf changed. A leaf that hasn't renewed is a no-op.
func (s *Server) refreshCertsForApp(ctx context.Context, cfg gitstore.Config, def *definition.Definition) {
	slug := cfg.Project
	rd := filepath.Clean(s.appRunDir(slug))

	// Re-copy each issued leaf into the run dir. Idempotent: identical bytes when not
	// renewed. Best-effort — a not-yet-issued cert / edge hiccup just skips this tick.
	if err := s.syncCertBindings(rd, def); err != nil {
		s.log.Debug("cert-renew: sync skipped", "app", slug, "err", err)
		return
	}
	oldDigests := readDigestState(rd)
	newDigests := s.managedDigests(rd, def)
	allChanged := changedServices(oldDigests, newDigests)
	if len(allChanged) == 0 {
		return // no leaf changed
	}
	// A scheduled-only service is never recreated here: naming it in `up … -- <svc>` would start it as a
	// long-running container. It picks the renewed leaf up on its next scheduled run.
	changed := withoutScheduled(def, allChanged)
	if len(changed) == 0 {
		// Only scheduled services use the renewed leaf — record the digests so it isn't rediscovered
		// on every tick.
		if werr := s.writeDigestState(rd, newDigests); werr != nil {
			s.log.Warn("cert-renew: could not record digests", "app", slug, "err", werr)
		}
		return
	}

	// Never recreate a service the operator has HELD (manually stopped): a cert renewal must not
	// relaunch a service the operator deliberately took down (self-heal + the scaler already skip held
	// services; the cert-renew recreate must too). Drop held services from the recreate set.
	if s.selfHeal != nil {
		if held, herr := s.selfHeal.ActiveHeld(); herr == nil && len(held) > 0 {
			kept := changed[:0:0]
			for _, svc := range changed {
				if held[selfheal.Key{App: slug, Service: svc}] {
					s.log.Info("cert-renew: skipping held service (operator-stopped)", "app", slug, "service", svc)
					continue
				}
				kept = append(kept, svc)
			}
			changed = kept
			if len(changed) == 0 {
				// Everything changed is held — record the new digests so we don't recheck every tick.
				if werr := s.writeDigestState(rd, newDigests); werr != nil {
					s.log.Warn("cert-renew: could not record digests", "app", slug, "err", werr)
				}
				return
			}
		}
	}

	// A leaf renewed → recreate the affected services, exactly as a deploy would.
	if s.pacedStartsEnabled() {
		s.renewCertsPaced(ctx, cfg, def, rd, changed, oldDigests, newDigests)
		return
	}
	if !s.gitDeploy.TryAcquire() {
		return // a deploy/another renewal holds the lock; retry next tick
	}
	defer s.gitDeploy.Release()
	defer s.beginForeground()()

	repo, err := git.Open(s.gitObjectDir(slug))
	if err != nil {
		s.log.Warn("cert-renew: open repo failed", "app", slug, "err", err)
		return
	}
	env := s.repoComposeEnv(ctx, repo, cfg.DeployedCommit, cfg)
	app := &monitor.App{Project: slug, WorkingDir: rd, ConfigFiles: []string{filepath.Join(rd, "docker-compose.yml")}}
	envFile, cleanup, ferr := s.renderEnvFile(app, env)
	defer cleanup()
	if ferr != nil {
		s.log.Warn("cert-renew: render env failed", "app", slug, "err", ferr)
		return
	}
	// Suppress the supervisor for this app while we intentionally recreate it.
	defer s.leaseExpectedDown(ctx, slug)()
	recreate := append([]string{"up", "-d", "--no-build", "--force-recreate", "--"}, changed...)
	job := dockerexec.Job{Project: slug, Dir: rd, ConfigFiles: app.ConfigFiles, EnvFile: envFile, Action: recreate}
	recreateStart := time.Now()
	rerr := s.runner.Run(ctx, job, func(l string) { s.log.Debug("cert-renew", "out", l) })
	s.recordStart(slug, "", recreateStart, false)
	if rerr != nil {
		s.log.Warn("cert-renew: recreate failed", "app", slug, "services", changed, "err", rerr)
		return
	}
	if werr := s.writeDigestState(rd, newDigests); werr != nil {
		s.log.Warn("cert-renew: could not record digests", "app", slug, "err", werr)
	}
	s.reconcileEdgeAfter(ctx) // the recreated containers have new addresses
	s.log.Info("cert-renew: renewed leaf synced + services recreated", "app", slug, "services", changed)
	_ = s.audit.Log(ctx, audit.Event{
		Actor: "system", Action: "cert_renew", Target: slug, Outcome: audit.OK,
		Level: audit.Security, Detail: "recreated: " + strings.Join(changed, ","),
	})
}

// renewCertsPaced is the renewal's recreate when starts are paced: the changed services one at a time,
// dependencies first, each waited for (recreateRenewed). The whole renewal counts as a foreground
// operation, so scheduled tasks don't take the docker slot in its settle gaps.
func (s *Server) renewCertsPaced(ctx context.Context, cfg gitstore.Config, def *definition.Definition, rd string, changed []string, oldDigests, newDigests map[string]string) {
	slug := cfg.Project
	defer s.beginForeground()()
	repo, err := git.Open(s.gitObjectDir(slug))
	if err != nil {
		s.log.Warn("cert-renew: open repo failed", "app", slug, "err", err)
		return
	}
	env := s.repoComposeEnv(ctx, repo, cfg.DeployedCommit, cfg)
	app := &monitor.App{Project: slug, WorkingDir: rd, ConfigFiles: []string{filepath.Join(rd, "docker-compose.yml")}}
	envFile, cleanup, ferr := s.renderEnvFile(app, env)
	defer cleanup()
	if ferr != nil {
		s.log.Warn("cert-renew: render env failed", "app", slug, "err", ferr)
		return
	}
	base := dockerexec.Job{Project: slug, Dir: rd, ConfigFiles: app.ConfigFiles, EnvFile: envFile}
	s.recreateRenewed(ctx, slug, rd, def, base, changed, oldDigests, newDigests)
}

// recreateRenewed force-recreates changed one service at a time (runRollout) and records the
// managed-file digests. The git-deploy single-flight is taken only around each docker call, never
// across a settle wait, so a renewal doesn't turn deploys and webhooks away while it waits; when a git
// operation holds it, the renewal stops without recording anything and the next tick picks up what is
// left. A service whose recreate didn't start keeps its old digest, so the next tick retries only it.
func (s *Server) recreateRenewed(ctx context.Context, slug, rd string, def *definition.Definition, base dockerexec.Job, changed []string, oldDigests, newDigests map[string]string) {
	rctx, cancel := context.WithTimeout(ctx, s.deployTimeout())
	defer cancel()
	// Suppress the supervisor for this app while we intentionally recreate it.
	defer s.leaseExpectedDown(rctx, slug)()
	gs := s.cfg.Server.StartGateSettings()
	var steps []rolloutStep
	for _, svc := range rolloutOrder(changed, lifecycleDeps(def)) {
		st := lifecycleStep(def, svc, gs)
		st.Job, st.Reap = base, true
		st.Job.Action, st.Job.Service = []string{"up", "-d", "--no-deps", "--no-build", "--force-recreate"}, svc
		steps = append(steps, st)
	}
	started := map[string]bool{}
	problems, err := s.runRollout(rctx, steps, rolloutOpts{
		App:     slug,
		OnLine:  func(l string) { s.log.Debug("cert-renew", "app", slug, "out", l) },
		Renew:   s.expectedDownRenewer(slug),
		Started: func(svc string) { started[svc] = true },
		Lock: func() bool {
			if !s.gitDeploy.TryAcquire() {
				return false
			}
			// Intentional: a git deploy that finished since this renewal began has re-synced the leaves,
			// recorded new digests and recreated what changed. Recreating the rest with this renewal's
			// env file (rendered for the commit deployed before it) could undo that deploy, so stop as
			// if it were still running.
			if !maps.Equal(readDigestState(rd), oldDigests) {
				s.gitDeploy.Release()
				return false
			}
			return true
		},
		Unlock: s.gitDeploy.Release,
	})
	recreated := make([]string, 0, len(started))
	for _, svc := range changed {
		if started[svc] {
			recreated = append(recreated, svc)
		}
	}
	// record is the digest state after this renewal: the new digest for each service it recreated, the old
	// one for the rest (retried next tick).
	record := maps.Clone(newDigests)
	for _, svc := range changed {
		if !started[svc] {
			record[svc] = oldDigests[svc]
		}
	}
	if err != nil {
		// Stopped part-way: another app's git operation holds the lock, or the renewal was interrupted. Keep
		// what was recreated, so the next tick doesn't recreate it again — unless a deploy of this app ran
		// meanwhile (the digest file moved on), whose own record then stands.
		if len(recreated) > 0 && maps.Equal(readDigestState(rd), oldDigests) {
			if werr := s.writeDigestState(rd, record); werr != nil {
				s.log.Warn("cert-renew: could not record digests", "app", slug, "err", werr)
			}
		}
		if errors.Is(err, errRolloutLocked) {
			s.log.Info("cert-renew: a git operation is running; the rest of the renewal waits for the next tick", "app", slug, "recreated", recreated)
		} else {
			s.log.Warn("cert-renew: renewal interrupted", "app", slug, "recreated", recreated, "err", err)
		}
		return
	}
	if len(recreated) == 0 {
		s.log.Warn("cert-renew: recreate failed", "app", slug, "services", changed, "problems", lifecycleProblemSummary(problems))
		return
	}
	if werr := s.writeDigestState(rd, record); werr != nil {
		s.log.Warn("cert-renew: could not record digests", "app", slug, "err", werr)
	}
	s.reconcileEdgeAfter(rctx) // the recreated containers have new addresses
	detail := "recreated: " + strings.Join(recreated, ",")
	if len(problems) > 0 {
		detail += "; problems: " + lifecycleProblemSummary(problems)
		s.log.Warn("cert-renew: renewed leaf synced; some services had problems", "app", slug, "recreated", recreated, "problems", lifecycleProblemSummary(problems))
	} else {
		s.log.Info("cert-renew: renewed leaf synced + services recreated", "app", slug, "services", recreated)
	}
	_ = s.audit.Log(ctx, audit.Event{
		Actor: "system", Action: "cert_renew", Target: slug, Outcome: audit.OK,
		Level: audit.Security, Detail: detail,
	})
}

// defHasCertBindings reports whether any service binds a managed cert.
func defHasCertBindings(def *definition.Definition) bool {
	for _, svc := range def.Spec.Compose.Services {
		if len(svc.CertBindings) > 0 {
			return true
		}
	}
	return false
}
