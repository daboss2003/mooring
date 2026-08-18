package web

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/dockerexec"
	"github.com/daboss2003/mooring/internal/monitor"
	"github.com/daboss2003/mooring/internal/selfheal"
)

// expectedDownLease bounds how long a single write-plane action may suppress the
// supervisor — a generous ceiling; the lease is released as soon as the action
// returns. A crashed action's lease auto-expires after this and is cleared on boot.
const expectedDownLease = 15 * time.Minute

// rungAction maps a supervisor rung to the same static argv the operator's lifecycle
// uses. restart changes no config; recreate/redeploy re-apply the compose (so they
// run the §5.6 validator + config-file materialization, healing drift).
var rungAction = map[selfheal.Rung][]string{
	selfheal.RungRestart:  {"restart"},
	selfheal.RungRecreate: {"up", "-d", "--force-recreate"},
	selfheal.RungRedeploy: {"up", "-d", "--force-recreate"},
}

// Remediate makes *Server the supervisor's Actioner: it runs the rung through the
// SAME write path the operator uses (env render, §5.6 validation + config-file
// materialization for recreate/redeploy), but via RunHeld — the supervisor's safety
// gate already holds the one-docker-child semaphore, so re-acquiring would deadlock.
// Authority never widens what may run: a protected project is refused here too.
func (s *Server) Remediate(ctx context.Context, app monitor.App, service string, rung selfheal.Rung) error {
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
func (s *Server) leaseExpectedDown(ctx context.Context, project string) func() {
	if s.selfHeal == nil {
		return func() {}
	}
	_ = s.selfHeal.AcquireExpectedDown(ctx, project, time.Now().Add(expectedDownLease).Unix())
	return func() {
		rctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.selfHeal.ReleaseExpectedDown(rctx, project)
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
