package web

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/dockerexec"
	"github.com/daboss2003/mooring/internal/monitor"
	"github.com/daboss2003/mooring/internal/scale"
	"github.com/daboss2003/mooring/internal/selfheal"
)

// expectedDownLease bounds how long a single write-plane action may suppress the
// supervisor — a fail-safe ceiling; the lease is released as soon as the action
// returns. A crashed action's lease auto-expires after this and is cleared on boot.
// It MUST be >= the longest action that holds it, or the lease lapses while the
// action is still running and the supervisor acts on an app mid-flight. The longest
// holder is a git deploy (its `docker compose up --build` runs inside the lease), so
// this tracks gitDeployTimeout; a slow build must never let self-heal fight the deploy.
const expectedDownLease = gitDeployTimeout

// rungAction maps a supervisor rung to the static argv for a whole-service action. restart
// changes no config; recreate/redeploy re-apply the compose (so they run the §5.6 validator +
// config-file materialization, healing drift) for this service only (--no-deps: never start a
// dependency the operator stopped) and never build (a missing image is a deploy's job, not
// self-heal's).
var rungAction = map[selfheal.Rung][]string{
	selfheal.RungRestart:  {"restart"},
	selfheal.RungRecreate: {"up", "-d", "--no-deps", "--no-build", "--force-recreate"},
	selfheal.RungRedeploy: {"up", "-d", "--no-deps", "--no-build", "--force-recreate"},
}

// serviceHasCopy reports whether id is one of service's containers in app (from the snapshot).
func serviceHasCopy(app monitor.App, service, id string) bool {
	for _, svc := range app.Services {
		if svc.Service == service && svc.ContainerID == id && id != "" {
			return true
		}
	}
	return false
}

// scalerManages reports whether the autoscaler keeps service's copy count (an enabled policy), so
// a removed copy is replaced.
func (s *Server) scalerManages(project, service string) bool {
	if s.scaling == nil {
		return false
	}
	pr, ok, err := s.scaling.PolicyFor(scale.Key{App: project, Service: service})
	return err == nil && ok && pr.Enabled
}

// Remediate makes *Server the supervisor's Actioner: it runs the rung through the
// SAME write path the operator uses (env render, §5.6 validation + config-file
// materialization for recreate/redeploy), but via RunHeld — the supervisor's safety
// gate already holds the one-docker-child semaphore, so re-acquiring would deadlock.
// Authority never widens what may run: a protected project is refused here too.
//
// With t.CopyID, the restart rung restarts only that copy (`docker restart <id>`). With t.Remove,
// the sick copies are removed (the autoscaler starts fresh ones, paced by the start gate) while the
// service's other copies keep serving. Copy ids must be containers of this app's service.
func (s *Server) Remediate(ctx context.Context, app monitor.App, service string, rung selfheal.Rung, t selfheal.Target) (err error) {
	defer func() {
		if err == nil {
			s.reconcileEdgeAfter(ctx) // a restarted/recreated container may have a new address
		}
	}()
	if s.runner == nil {
		return fmt.Errorf("write plane unavailable")
	}
	if s.cfg.IsProtectedProject(app.Project) {
		return fmt.Errorf("refusing to remediate a protected project %q", app.Project)
	}
	args, ok := rungAction[rung]
	if !ok {
		return fmt.Errorf("unknown rung %q", rung)
	}
	for _, id := range append([]string{t.CopyID}, t.Remove...) {
		if id != "" && (!hexIDRe.MatchString(id) || !serviceHasCopy(app, service, id)) {
			return fmt.Errorf("container %s is not a copy of %s/%s", shortContainerID(id), app.Project, service)
		}
	}
	logLine := func(l string) { s.log.Debug("selfheal", "service", service, "out", l) }
	switch {
	case t.CopyID != "" && (len(t.Remove) > 0 || rung != selfheal.RungRestart):
		return fmt.Errorf("a single-copy target is only valid for a restart")
	case len(t.Remove) > 0:
		// Intentional: never fall back to recreating the service here — that would start containers the
		// supervisor didn't pace. It decides between removal and a recreate itself.
		if !s.scalerManages(app.Project, service) {
			return fmt.Errorf("%s/%s: %w", app.Project, service, selfheal.ErrNoReplacement)
		}
		if s.edgeRecon != nil {
			_ = s.edgeRecon.DrainContainers(ctx, t.Remove) // stop dialing them before they go
		}
		if err := s.runner.RemoveContainersHeld(ctx, t.Remove, logLine); err != nil {
			if s.edgeRecon != nil {
				_ = s.edgeRecon.UndrainContainers(ctx, t.Remove)
			}
			return err
		}
		return nil
	case t.CopyID != "":
		return s.runner.RestartContainersHeld(ctx, []string{t.CopyID}, logLine)
	}

	env := s.composeEnv(&app)
	envFile, cleanup, err := s.renderEnvFile(&app, env)
	defer cleanup()
	if err != nil {
		return fmt.Errorf("render env file: %w", err)
	}

	// recreate/redeploy re-apply the compose → run the chokepoint validator + heal
	// managed config files (never deploy unsafe/un-rendered config, even to self-heal).
	if rung == selfheal.RungRecreate || rung == selfheal.RungRedeploy {
		if res := s.validateAppCompose(&app, env); !res.OK() && s.cfg.ComposeValidation.Mode != "review" {
			return fmt.Errorf("§5.6 compose validation failed (%d findings)", len(res.Violations))
		}
		if err := s.materializeConfigFiles(&app, env); err != nil {
			return fmt.Errorf("config-file materialization: %w", err)
		}
	}

	job := dockerexec.Job{Project: app.Project, Dir: app.WorkingDir, ConfigFiles: app.ConfigFiles, EnvFile: envFile, Action: args, Service: service}
	if len(args) > 0 && args[0] == "up" {
		// Recreate remediation is an `up` — recover a stranded name conflict too. This path ALREADY
		// holds the one-docker-child semaphore (RunHeld), so the reap must use the *Held variants
		// (re-acquiring the non-reentrant semaphore here would self-deadlock).
		declared := s.reapScope(ctx, app.Project)
		return s.runUpWithConflictReap(ctx, app.Project, declared,
			func(c context.Context, ol func(string)) error { return s.runner.RunHeld(c, job, ol) },
			s.runner.RemoveContainersHeld, nil)
	}
	return s.runner.RunHeld(ctx, job, nil)
}

// leaseExpectedDown acquires a bounded expected_down lease for project and returns
// a release function to defer — so the self-healing supervisor doesn't read an
// intentional restart/redeploy/provision/git-deploy as a crash loop. The release
// uses a background context so a cancelled request still clears the lease; the
// bounded `until` + boot-time clear cover a crash. A no-op when self-heal is absent.
//
// The lease is ONE row per app, so overlapping holders (a per-copy restart while a deploy runs, a cert
// renewal during a lifecycle action) are reference-counted here: every holder re-writes the row (so its
// expiry covers the latest holder too), and only the LAST holder's release deletes it. Without the count,
// the first holder to finish would delete the row under the others and self-heal would act mid-deploy.
func (s *Server) leaseExpectedDown(ctx context.Context, project string) func() {
	if s.selfHeal == nil {
		return func() {}
	}
	// Intentional: the row writes happen under leaseMu, so a last holder's delete can never land after
	// a new holder's upsert (which would drop the new holder's lease).
	s.leaseMu.Lock()
	if s.leaseHolders == nil {
		s.leaseHolders = map[string]int{}
	}
	s.leaseHolders[project]++
	_ = s.selfHeal.AcquireExpectedDown(ctx, project, time.Now().Add(expectedDownLease).Unix())
	s.leaseMu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			s.leaseMu.Lock()
			defer s.leaseMu.Unlock()
			s.leaseHolders[project]--
			if s.leaseHolders[project] > 0 {
				return // another holder still needs the app suspended
			}
			delete(s.leaseHolders, project)
			rctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = s.selfHeal.ReleaseExpectedDown(rctx, project)
		})
	}
}

// renewExpectedDown extends project's expected_down lease to expectedDownLease from now, if anything
// holds it — a rollout calls it after every step, so a long rollout can't outlive the lease row.
func (s *Server) renewExpectedDown(ctx context.Context, project string) {
	if s.selfHeal == nil {
		return
	}
	s.leaseMu.Lock()
	defer s.leaseMu.Unlock()
	if s.leaseHolders[project] > 0 {
		_ = s.selfHeal.AcquireExpectedDown(ctx, project, time.Now().Add(expectedDownLease).Unix())
	}
}

// SetCircuitClearer wires the supervisor's clear-circuit entry point (set by
// cmd_serve after both the server and the watcher exist — avoids an import cycle).
func (s *Server) SetCircuitClearer(c func(project, service string)) { s.circuitClearer = c }

// handleSupervisorClear resets a latched CIRCUIT_OPEN service so the supervisor will
// act on it again (the operator fixed the root cause).
func (s *Server) handleSupervisorClear(w http.ResponseWriter, r *http.Request) {
	project := r.PathValue("project")
	if s.cfg.IsProtectedProject(project) {
		http.Error(w, "protected project", http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	service := r.PostFormValue("service")
	if s.circuitClearer != nil {
		s.circuitClearer(project, service)
	}
	_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "supervisor_clear_circuit", Target: project + "/" + service, Outcome: audit.OK, Level: audit.Security})
	http.Redirect(w, r, "/apps/"+project, http.StatusSeeOther)
}

// heldServices returns the set of operator-held service names for a project (a manual stop /
// "pause auto-restart"). Read-only view for the app + service pages.
func (s *Server) heldServices(project string) map[string]bool {
	out := map[string]bool{}
	if s.selfHeal == nil {
		return out
	}
	all, err := s.selfHeal.ActiveHeld()
	if err != nil {
		return out
	}
	for k := range all {
		if k.App == project {
			out[k.Service] = true
		}
	}
	return out
}

// supervisorStates returns the persisted FSM states for a project (read-only view).
func (s *Server) supervisorStates(project string) map[string]string {
	out := map[string]string{}
	if s.selfHeal == nil {
		return out
	}
	all, err := s.selfHeal.LoadAll()
	if err != nil {
		return out
	}
	for k, f := range all {
		if k.App == project {
			out[k.Service] = string(f.Phase)
		}
	}
	return out
}
