package web

import (
	"context"
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
//   - takes the single-flight deploy lock (gitDeploy) so it never races a deploy
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
	newDigests := s.managedDigests(rd, def)
	allChanged := changedServices(readDigestState(rd), newDigests)
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

// defHasCertBindings reports whether any service binds a managed cert.
func defHasCertBindings(def *definition.Definition) bool {
	for _, svc := range def.Spec.Compose.Services {
		if len(svc.CertBindings) > 0 {
			return true
		}
	}
	return false
}
