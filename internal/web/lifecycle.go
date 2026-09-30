package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/compose"
	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/dockerexec"
	"github.com/daboss2003/mooring/internal/monitor"
	"github.com/daboss2003/mooring/internal/selfheal"
)

// actionArgs maps a lifecycle action to its static `docker compose` argv. Only
// these four are accepted; redeploy recreates with the current image/config.
var actionArgs = map[string][]string{
	"start":    {"start"},
	"stop":     {"stop"},
	"restart":  {"restart"},
	"redeploy": {"up", "-d", "--force-recreate"},
}

func (s *Server) handleAppAction(w http.ResponseWriter, r *http.Request) {
	s.runLifecycle(w, r, r.PathValue("project"), "", r.PathValue("action"))
}

func (s *Server) handleServiceAction(w http.ResponseWriter, r *http.Request) {
	s.runLifecycle(w, r, r.PathValue("project"), r.PathValue("service"), r.PathValue("action"))
}

// runLifecycle executes a gated, semaphored lifecycle action and streams its output back as the
// (chunked, flushed) response body. Start, restart and redeploy start services one at a time, each
// waited for (pacedLifecycle), unless the operator asked for all at once (now=1) or the start gate is
// off; then, and for a stop, it is one `docker compose` call.
func (s *Server) runLifecycle(w http.ResponseWriter, r *http.Request, project, service, action string) {
	ctx := r.Context()
	actor := sessionUser(r)
	peer := ClientIP(ctx).String()

	if s.runner == nil {
		http.Error(w, "write plane unavailable", http.StatusServiceUnavailable)
		return
	}
	args, ok := actionArgs[action]
	if !ok {
		http.Error(w, "unknown action", http.StatusNotFound)
		return
	}
	if action == "redeploy" && service != "" {
		// A service redeploy recreates just that service. Without --no-deps compose would also start the
		// services it depends on (stopped or held ones included) and recreate any whose config drifted.
		args = []string{"up", "-d", "--no-deps", "--force-recreate"}
	}
	// Protected set: the edge / socket-proxy are Mooring's, never lifecycle-able
	// as an app (plan §3).
	if s.cfg.IsProtectedProject(project) {
		_ = s.audit.Log(ctx, audit.Event{Actor: actor, IP: peer, Action: "lifecycle_" + action, Target: project, Outcome: audit.Deny, Level: audit.Security, Detail: "protected project"})
		http.Error(w, "this is a protected project and cannot be controlled as an app", http.StatusForbidden)
		return
	}
	if allowed, reason := s.runner.WriteAllowed(); !allowed {
		http.Error(w, reason, http.StatusForbidden)
		return
	}
	var app *monitor.App
	if snap := s.snapshot(); snap != nil {
		app = snap.AppByProject(project)
	}
	if app == nil {
		http.Error(w, "app not found", http.StatusNotFound)
		return
	}
	def := s.currentDef(project) // nil for an app without a stored definition
	// A scheduled-only service runs only as a one-shot `compose run` on its schedule. Naming it in a
	// start/restart/redeploy would enable its compose profile and start it as a long-running container.
	if action != "stop" && isScheduledService(def, service) {
		http.Error(w, "scheduled services run only on their schedule; they can't be started, restarted or redeployed", http.StatusConflict)
		return
	}
	paced := action != "stop" && r.URL.Query().Get("now") != "1" && s.pacedStartsEnabled()

	// Per-copy stop of a SCALED service: remove just the chosen replica instead of every copy. The
	// auto-scaler applies it race-free and lowers desired so it isn't relaunched. Falls through to the
	// normal whole-service stop when there's a single replica or the copy id is unknown.
	if action == "stop" && s.replicaStopper != nil {
		if copyID := r.URL.Query().Get("copy"); copyID != "" {
			if n, valid := replicaRunningCount(app, service, copyID); valid && n > 1 {
				s.replicaStopper(project, service, copyID)
				_ = s.audit.Log(ctx, audit.Event{Actor: actor, IP: peer, Action: "lifecycle_stop_replica", Target: project + "/" + service, Outcome: audit.OK, Level: audit.Info})
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.Header().Set("Cache-Control", "no-store")
				fmt.Fprintf(w, "Stopping this copy of %s — the autoscaler removes it and keeps the other copies running.\n", service)
				return
			}
		}
	}

	// Per-copy RESTART/START of a SCALED service: act on just the chosen container (`docker restart|start
	// <id>`) instead of `compose restart|start <service>`, which cycles/starts EVERY copy. The replica
	// count is unchanged, so — unlike a per-copy stop — no scaler coordination is needed. Runs on a
	// detached context so a client disconnect can't SIGKILL it mid-restart. Paced, it goes through a
	// one-step rollout (pacedCopyAction).
	if (action == "restart" || action == "start") && s.runner != nil {
		if copyID := r.URL.Query().Get("copy"); copyID != "" {
			if total, valid := serviceCopyStats(app, service, copyID); valid && total > 1 {
				if allowed, reason := s.runner.WriteAllowed(); !allowed {
					http.Error(w, reason, http.StatusForbidden)
					return
				}
				// The id goes to `docker restart|start <id>`, which has no `--` before it.
				if !hexIDRe.MatchString(copyID) {
					http.Error(w, "invalid copy id", http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.Header().Set("Cache-Control", "no-store")
				clearWriteDeadline(w)
				fl, _ := w.(http.Flusher)
				onl := func(l string) {
					fmt.Fprintln(w, l)
					if fl != nil {
						fl.Flush()
					}
				}
				fmt.Fprintf(w, "$ docker %s %s\n", action, shortContainerID(copyID))
				if fl != nil {
					fl.Flush()
				}
				if paced {
					s.pacedCopyAction(ctx, lifecycleReq{project: project, service: service, action: action, actor: actor, peer: peer}, def, copyID, onl)
					return
				}
				aCtx, aCancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Minute)
				defer aCancel()
				defer s.leaseExpectedDown(aCtx, project)() // suppress self-heal during the intentional cycle
				var e error
				copyStart := time.Now()
				if action == "restart" {
					e = s.runner.RestartContainers(aCtx, []string{copyID}, onl)
				} else {
					e = s.runner.StartContainers(aCtx, []string{copyID}, onl)
				}
				s.recordStart(project, service, copyStart, e == nil)
				outcome := audit.OK
				if e != nil {
					outcome = audit.Error
					fmt.Fprintf(w, "\n[failed: %v]\n", e)
				} else {
					s.reconcileEdgeAfter(aCtx)
					fmt.Fprintln(w, "\n[done]")
				}
				_ = s.audit.Log(ctx, audit.Event{Actor: actor, IP: peer, Action: "lifecycle_" + action + "_copy", Target: project + "/" + service, Outcome: outcome, Level: audit.Info})
				return
			}
		}
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no") // disable proxy buffering for live output
	clearWriteDeadline(w)                     // long-lived stream — exempt from the 60s WriteTimeout
	flusher, _ := w.(http.Flusher)
	writeln := func(format string, a ...any) {
		fmt.Fprintf(w, format+"\n", a...)
		if flusher != nil {
			flusher.Flush()
		}
	}

	// Build the env used for BOTH validation and the deploy --env-file, so what
	// we validate is exactly what `docker compose` renders (validate == deploy).
	env := s.composeEnv(app)
	envFile, cleanup, ferr := s.renderEnvFile(app, env)
	defer cleanup()
	if ferr != nil {
		http.Error(w, "could not render env file", http.StatusInternalServerError)
		return
	}

	// §5.6 gate before any `up` (redeploy applies the compose). start/stop/restart
	// only act on existing containers and change no config.
	if action == "redeploy" {
		if res := s.validateAppCompose(app, env); !res.OK() {
			if s.cfg.ComposeValidation.Mode != "review" {
				w.WriteHeader(http.StatusUnprocessableEntity)
				writeln("redeploy blocked by the §5.6 compose validator:")
				for _, v := range res.Violations {
					writeln("  - %s", v.String())
				}
				_ = s.audit.Log(ctx, audit.Event{Actor: actor, IP: peer, Action: "redeploy", Target: project, Outcome: audit.Deny, Level: audit.Security, Detail: "compose validation failed"})
				return
			}
			writeln("WARNING (review mode): compose has %d validator finding(s); proceeding.", len(res.Violations))
		}
		// Materialize managed config files + enforce the cert-wait gate (M5b),
		// host-side, before `up`. Any missing binding/cert is a hard failure.
		if err := s.materializeConfigFiles(app, env); err != nil {
			w.WriteHeader(http.StatusUnprocessableEntity)
			writeln("redeploy blocked: %v", err)
			_ = s.audit.Log(ctx, audit.Event{Actor: actor, IP: peer, Action: "redeploy", Target: project, Outcome: audit.Deny, Level: audit.Security, Detail: "config-file materialization failed"})
			return
		}
	}

	depID := s.recordDeployStart(ctx, project, service, action, actor)
	lr := lifecycleReq{project: project, service: service, action: action, actor: actor, peer: peer}
	if paced {
		s.pacedLifecycle(ctx, lr, app, def, envFile, depID, writeln)
		return
	}
	target := lr.target()
	writeln("$ docker compose %s%s", strings.Join(args, " "), serviceSuffix(service))

	job := dockerexec.Job{Project: project, Dir: app.WorkingDir, ConfigFiles: app.ConfigFiles, EnvFile: envFile, Action: args, Service: service}

	// Run the docker action on a DETACHED context, NOT the request context. Otherwise, if the operator
	// navigates away (or a proxy/network blip ends the streamed response) mid-action, r.Context() is
	// cancelled and the exec wrapper SIGKILLs the whole `docker compose` process group — leaving a stop
	// half-done (containers still up) and skipping the hold, so self-heal + the scaler relaunch it. That
	// is the "stop rarely works" bug. Detaching lets the action finish regardless of the client; output
	// still streams to w best-effort while the client is connected and harmlessly no-ops after it leaves.
	actionTimeout := 10 * time.Minute
	if action == "redeploy" {
		actionTimeout = 30 * time.Minute // a build can be slow
	}
	actionCtx, cancelAction := context.WithTimeout(context.WithoutCancel(ctx), actionTimeout)
	defer cancelAction()

	// A STOP records the hold BEFORE acting (durable intent): the service stays skipped by self-heal and
	// the scaler even if the stop is interrupted or errors, so it can never be relaunched behind the
	// operator's back. start/restart/redeploy CLEAR the hold, but only AFTER a successful action.
	if action == "stop" {
		s.applyHoldForAction(project, service, action, actor, app)
	}

	// Hold an expected_down lease so the self-healing supervisor doesn't read this
	// intentional restart/redeploy as a crash loop (plan §8.5).
	defer s.leaseExpectedDown(actionCtx, project)()
	onl := func(line string) { writeln("%s", line) }
	var runErr error
	actionStart := time.Now()
	if len(args) > 0 && args[0] == "up" {
		// A redeploy is an `up` — recover from a stranded name conflict (interrupted recreate).
		declared := s.reapScope(actionCtx, project)
		runErr = s.runUpWithConflictReap(actionCtx, project, declared,
			func(c context.Context, ol func(string)) error { return s.runner.Run(c, job, ol) },
			s.runner.RemoveContainers, onl)
	} else {
		runErr = s.runner.Run(actionCtx, job, onl) // restart/stop/start: no name-allocation to conflict
	}

	if action != "stop" {
		// The operator's action is never held back, but automatic starters wait for what it started.
		s.recordStart(project, service, actionStart, false)
	}
	code, outcome := classifyExit(runErr)
	s.recordDeployFinish(ctx, depID, code, outcome)
	if runErr == nil && action != "stop" {
		// start/restart/redeploy RELEASE the hold after a successful action (stop already set it above).
		s.applyHoldForAction(project, service, action, actor, app)
	}
	if runErr == nil {
		// New/stopped containers: re-point the edge now (a stopped service answers 503 at once instead
		// of the edge dialing a dead address until the next refresh).
		s.reconcileEdgeAfter(actionCtx)
	}
	level := audit.Info
	auditOutcome := audit.OK
	if runErr != nil {
		level, auditOutcome = audit.Security, audit.Error
		writeln("\n[failed: %v]", runErr)
	} else {
		writeln("\n[done]")
	}
	_ = s.audit.Log(ctx, audit.Event{Actor: actor, IP: peer, Action: "lifecycle_" + action, Target: target, Outcome: auditOutcome, Level: level})
}

func serviceSuffix(service string) string {
	if service == "" {
		return ""
	}
	return " -- " + service
}

// lifecycleReq is one operator lifecycle action, as runLifecycle validated it.
type lifecycleReq struct {
	project, service, action, actor, peer string
}

// target is the action's audit target: the app, or app/service.
func (lr lifecycleReq) target() string {
	if lr.service == "" {
		return lr.project
	}
	return lr.project + "/" + lr.service
}

// pacedStartsEnabled reports whether operator start/restart/redeploy actions and certificate renewals
// start services one at a time (a start gate is wired and server.start_gate is enabled).
func (s *Server) pacedStartsEnabled() bool {
	return s.startGate != nil && s.cfg.Server.StartGateSettings().Enabled
}

var lifecycleVerb = map[string]string{"start": "starting", "restart": "restarting", "redeploy": "redeploying"}

// pacedLifecycle starts, restarts or redeploys the service — or every non-scheduled service of the app,
// dependencies first — one at a time, each waited for (runRollout). A service that fails to start or
// doesn't settle is reported and the rest still run: a lifecycle action is often the recovery action.
// Only when nothing started does the action fail, as the single compose call would have.
func (s *Server) pacedLifecycle(ctx context.Context, lr lifecycleReq, app *monitor.App, def *definition.Definition, envFile string, depID int64, writeln func(string, ...any)) {
	defer s.beginForeground()()      // scheduled tasks and backups don't take the docker slot between its steps
	bg := context.WithoutCancel(ctx) // records and audit outlive a closed browser tab
	base := dockerexec.Job{Project: lr.project, Dir: app.WorkingDir, ConfigFiles: app.ConfigFiles, EnvFile: envFile}
	steps, order, running := lifecycleSteps(app, def, lr.service, lr.action, base, s.cfg.Server.StartGateSettings())
	if lr.service == "" {
		writeln("%s %s one service at a time: %s", lifecycleVerb[lr.action], lr.project, strings.Join(order, ", "))
	} else {
		writeln("%s %s", lifecycleVerb[lr.action], lr.target())
	}
	for _, svc := range running {
		writeln("%s: already running", svc)
	}

	// Detached (a client disconnect must not SIGKILL a half-done action) and bounded like a deploy: the
	// rollout's waits come on top of the docker calls.
	actionCtx, cancelAction := context.WithTimeout(context.WithoutCancel(ctx), s.deployTimeout())
	defer cancelAction()
	defer s.leaseExpectedDown(actionCtx, lr.project)()
	problems, notStarted := s.runLifecycleRollout(actionCtx, steps, rolloutOpts{
		App:    lr.project,
		OnLine: func(line string) { writeln("%s", line) },
		Renew:  s.expectedDownRenewer(lr.project),
		// Each service's hold is released as soon as its own start succeeded.
		Started: func(svc string) { s.applyHoldForAction(lr.project, svc, lr.action, lr.actor, app) },
	})

	if len(steps) > 0 && len(notStarted) == len(steps) {
		summary := lifecycleProblemSummary(problems)
		s.recordDeployFinish(bg, depID, -1, "error")
		writeln("\n[failed: %s]", summary)
		_ = s.audit.Log(bg, audit.Event{Actor: lr.actor, IP: lr.peer, Action: "lifecycle_" + lr.action, Target: lr.target(), Outcome: audit.Error, Level: audit.Security, Detail: summary})
		return
	}
	if len(notStarted) == 0 {
		s.applyHoldForAction(lr.project, lr.service, lr.action, lr.actor, app) // as the unpaced action: every hold
	} else {
		// Intentional: a service whose start failed keeps its hold (as after a failed unpaced action);
		// the ones that needed no start are released like the started ones.
		for _, svc := range running {
			s.applyHoldForAction(lr.project, svc, lr.action, lr.actor, app)
		}
	}
	if len(steps) > len(notStarted) {
		s.reconcileEdgeAfter(actionCtx) // new containers or addresses: re-point the edge now
	}
	outcome, detail := "ok", ""
	if len(problems) > 0 {
		outcome, detail = "problems", "problems: "+lifecycleProblemSummary(problems)
		streamLifecycleProblems(func(line string) { writeln("%s", line) }, problems)
	} else {
		writeln("\n[done]")
	}
	s.recordDeployFinish(bg, depID, 0, outcome)
	_ = s.audit.Log(bg, audit.Event{Actor: lr.actor, IP: lr.peer, Action: "lifecycle_" + lr.action, Target: lr.target(), Outcome: audit.OK, Level: audit.Info, Detail: detail})
}

// pacedCopyAction restarts or starts one copy of a scaled service through a one-step rollout: it waits
// for CPU headroom and other apps' starts (within deploy_wait), then for the copy to settle.
func (s *Server) pacedCopyAction(ctx context.Context, lr lifecycleReq, def *definition.Definition, copyID string, onLine func(string)) {
	defer s.beginForeground()()
	bg := context.WithoutCancel(ctx)
	gs := s.cfg.Server.StartGateSettings()
	st := lifecycleStep(def, lr.service, gs)
	st.Copies, st.CopyAction = []string{copyID}, lr.action
	// The unpaced copy action's 3m for the docker call, plus the rollout's waits.
	aCtx, aCancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Minute+gs.DeployWait+st.Deadline+time.Minute)
	defer aCancel()
	defer s.leaseExpectedDown(aCtx, lr.project)() // suppress self-heal during the intentional cycle
	problems, notStarted := s.runLifecycleRollout(aCtx, []rolloutStep{st}, rolloutOpts{
		App: lr.project, OnLine: onLine, Renew: s.expectedDownRenewer(lr.project),
	})
	outcome, detail := audit.OK, ""
	switch {
	case len(notStarted) > 0:
		outcome, detail = audit.Error, lifecycleProblemSummary(problems)
		onLine("\n[failed: " + detail + "]")
	case len(problems) > 0:
		s.reconcileEdgeAfter(aCtx)
		detail = "problems: " + lifecycleProblemSummary(problems)
		streamLifecycleProblems(onLine, problems)
	default:
		s.reconcileEdgeAfter(aCtx)
		onLine("\n[done]")
	}
	_ = s.audit.Log(bg, audit.Event{Actor: lr.actor, IP: lr.peer, Action: "lifecycle_" + lr.action + "_copy", Target: lr.target(), Outcome: outcome, Level: audit.Info, Detail: detail})
}

// runLifecycleRollout runs steps (runRollout) and also reports which services' steps never started:
// their docker call failed, or the rollout ended before them — those get a problem too.
func (s *Server) runLifecycleRollout(ctx context.Context, steps []rolloutStep, o rolloutOpts) ([]rolloutProblem, map[string]bool) {
	notStarted := map[string]bool{}
	if len(steps) == 0 {
		return nil, notStarted
	}
	started := map[string]bool{}
	then := o.Started
	o.Started = func(svc string) {
		started[svc] = true
		if then != nil {
			then(svc)
		}
	}
	problems, err := s.runRollout(ctx, steps, o)
	reported := func(svc string) bool {
		for _, p := range problems {
			if p.Service == svc {
				return true
			}
		}
		return false
	}
	for _, st := range steps {
		if started[st.Service] {
			continue
		}
		notStarted[st.Service] = true
		if err != nil && !reported(st.Service) {
			problems = append(problems, rolloutProblem{Service: st.Service, Reason: "not started: " + err.Error()})
		}
	}
	if last := steps[len(steps)-1].Service; err != nil && started[last] && !reported(last) {
		problems = append(problems, rolloutProblem{Service: last, Reason: "stopped waiting for it to settle: " + err.Error()})
	}
	return problems, notStarted
}

// lifecycleSteps plans a paced start/restart/redeploy: service, or else every non-scheduled service of
// the app, in dependency order (order), one step each. A start starts a service's stopped copies by id
// and leaves a service whose copies all run alone (running); a restart restarts every copy by id; a
// redeploy recreates the service. A service with no container at all is brought up.
func lifecycleSteps(app *monitor.App, def *definition.Definition, service, action string, base dockerexec.Job, gs config.StartGateSettings) (steps []rolloutStep, order, running []string) {
	names := []string{service}
	if service == "" {
		names = lifecycleServices(app, def)
	}
	order = rolloutOrder(names, lifecycleDeps(def))
	for _, svc := range order {
		st := lifecycleStep(def, svc, gs)
		ids, stopped := lifecycleCopies(app, svc)
		up := func(args ...string) {
			st.Job, st.Reap = base, true
			st.Job.Action, st.Job.Service = args, svc
		}
		switch {
		case action == "redeploy":
			up("up", "-d", "--no-deps", "--force-recreate")
			st.Timeout = 30 * time.Minute // an `up` without --no-build may build a missing image
		case len(ids) == 0:
			up("up", "-d", "--no-deps")
		case action == "restart":
			st.Copies, st.CopyAction = ids, "restart"
		case len(stopped) == 0:
			running = append(running, svc)
			continue
		default:
			st.Copies, st.CopyAction = stopped, "start"
		}
		steps = append(steps, st)
	}
	return steps, order, running
}

// lifecycleStep is svc's rollout step without its docker action: how long to wait for it to settle and
// how to judge what it started, from the definition (an app without one gets the defaults).
func lifecycleStep(def *definition.Definition, svc string, gs config.StartGateSettings) rolloutStep {
	st := rolloutStep{Service: svc}
	var hc *definition.Healthcheck
	if def != nil {
		if sd, ok := def.Spec.Compose.Services[svc]; ok {
			hc = sd.Healthcheck
			st.Notify = sd.OnUnhealthy() == definition.OnUnhealthyNotify
			st.Restarts = restartPolicy(sd.Restart)
			st.StopGrace = stopGrace(sd.StopGracePeriod)
		}
	}
	st.Deadline = settleDeadline(hc, gs.MaxSettle, gs.ServiceSettle)
	return st
}

// stopGrace parses a service's stop_grace_period (0 when unset or invalid).
func stopGrace(p string) time.Duration {
	if d, err := time.ParseDuration(p); err == nil && d > 0 {
		return d
	}
	return 0
}

// lifecycleServices lists the services an app-level action covers: the definition's non-scheduled
// services, or — for an app without a definition — the services it has containers for.
func lifecycleServices(app *monitor.App, def *definition.Definition) []string {
	if def == nil {
		return distinctServiceNames(app)
	}
	sched := def.Spec.ScheduledServiceSet()
	var out []string
	for name := range def.Spec.Compose.Services {
		if !sched[name] {
			out = append(out, name)
		}
	}
	return out
}

// lifecycleDeps is each service's depends_on (nil without a definition).
func lifecycleDeps(def *definition.Definition) map[string][]string {
	if def == nil {
		return nil
	}
	deps := make(map[string][]string, len(def.Spec.Compose.Services))
	for name, svc := range def.Spec.Compose.Services {
		deps[name] = svc.DependsOn
	}
	return deps
}

// lifecycleCopies returns the ids of svc's containers and of those not running. Only well-formed ids
// are kept: they go to `docker start|restart <id>`, which has no `--` before them.
func lifecycleCopies(app *monitor.App, svc string) (ids, stopped []string) {
	for _, c := range app.Services {
		if c.Service != svc || !hexIDRe.MatchString(c.ContainerID) {
			continue
		}
		ids = append(ids, c.ContainerID)
		if !c.Running() {
			stopped = append(stopped, c.ContainerID)
		}
	}
	return ids, stopped
}

// expectedDownRenewer renews project's expected_down lease after each rollout step (bounded; the
// request that started the rollout may be gone).
func (s *Server) expectedDownRenewer(project string) func() {
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s.renewExpectedDown(ctx, project)
	}
}

// lifecycleProblemSummary is the problems on one line, for an audit detail or a failure line.
func lifecycleProblemSummary(problems []rolloutProblem) string {
	parts := make([]string, 0, len(problems))
	for _, p := range problems {
		parts = append(parts, p.Service+": "+p.Reason)
	}
	return strings.Join(parts, "; ")
}

// streamLifecycleProblems ends a stream whose rollout carried on past problems: one ⚠ line each.
func streamLifecycleProblems(onLine func(string), problems []rolloutProblem) {
	onLine("\n[done — with problems]")
	for _, p := range problems {
		onLine("⚠ " + p.Service + ": " + p.Reason)
	}
}

// applyHoldForAction records/releases operator holds after a successful lifecycle action, so a
// manual stop stays stopped (self-heal + auto-scaler skip a held service) and any start-intent
// releases it. A per-service action scopes to that service; an app-level action covers every
// service. No-op when self-heal is absent. Detached, bounded context (the request may be gone).
func (s *Server) applyHoldForAction(project, service, action, actor string, app *monitor.App) {
	if s.selfHeal == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	now := time.Now().Unix()
	switch action {
	case "stop":
		if service != "" {
			_ = s.selfHeal.SetHeld(ctx, selfheal.Key{App: project, Service: service}, actor, now)
			return
		}
		for _, svc := range distinctServiceNames(app) { // app-level stop holds every service
			_ = s.selfHeal.SetHeld(ctx, selfheal.Key{App: project, Service: svc}, actor, now)
		}
	case "start", "restart", "redeploy":
		if service != "" {
			_ = s.selfHeal.ClearHeld(ctx, selfheal.Key{App: project, Service: service})
			return
		}
		_ = s.selfHeal.ClearHeldApp(ctx, project) // app-level start/redeploy releases every hold
	}
}

// serviceCopyStats returns how many containers a service has (running OR stopped) and whether copyID
// is one of them — used to decide between a per-copy restart/start (scaled, >1 copy) and the normal
// whole-service action. Unlike replicaRunningCount it counts stopped copies too (a "start this copy"
// targets a stopped one).
func serviceCopyStats(app *monitor.App, service, copyID string) (total int, validCopy bool) {
	if app == nil {
		return 0, false
	}
	for _, svc := range app.Services {
		if svc.Service != service {
			continue
		}
		total++
		if svc.ContainerID == copyID {
			validCopy = true
		}
	}
	return total, validCopy
}

// shortContainerID trims a container id to the conventional 12-char short form for display.
func shortContainerID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// replicaRunningCount returns how many replicas of a service are currently running, and whether
// copyID is one of them — used to decide between a per-copy stop (scaled, >1 running) and the normal
// whole-service stop.
func replicaRunningCount(app *monitor.App, service, copyID string) (n int, validCopy bool) {
	if app == nil {
		return 0, false
	}
	for _, svc := range app.Services {
		if svc.Service != service || !svc.Running() {
			continue
		}
		n++
		if svc.ContainerID == copyID {
			validCopy = true
		}
	}
	return n, validCopy
}

// distinctServiceNames returns the unique service names of an app's live containers (a scaled
// service has many copies sharing one name).
func distinctServiceNames(app *monitor.App) []string {
	if app == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, svc := range app.Services {
		if svc.Service == "" || seen[svc.Service] {
			continue
		}
		seen[svc.Service] = true
		out = append(out, svc.Service)
	}
	return out
}

// validateAppCompose reads the app's compose config file(s) and runs each through
// the §5.6 validator with the app's .env for ${VAR} resolution. Each file is
// checked individually, so a dangerous key in any override is caught.
// validateAppCompose reads the app's compose config file(s) and runs each through
// the §5.6 validator. NOTE (review #8/#11/#12/#14): the run_dir and config_files
// come from compose container labels (operator-deployed, not in-container-app
// controllable) and each file is validated individually rather than merged; the
// durable fix (Mooring-owned run_dir + cat-file of the pinned commit) lands with
// repo-path provisioning (M6/M8, plan §5.6(e)). Here we add the cheap guards that
// reduce blast radius now.
func (s *Server) validateAppCompose(app *monitor.App, env compose.Env) compose.Result {
	var res compose.Result
	reject := func(msg string) compose.Result {
		res.Violations = append(res.Violations, compose.Violation{Message: msg})
		return res
	}

	// run_dir sanity: must be an absolute, non-sensitive directory we can confine
	// binds under. Refuse to validate (and therefore to deploy) otherwise.
	rd := filepath.Clean(app.WorkingDir)
	if app.WorkingDir == "" || !filepath.IsAbs(rd) {
		return reject("app working directory is missing or not absolute; refusing to deploy")
	}
	if rd == "/" || isSensitiveDir(rd) {
		return reject("app working directory " + rd + " is a sensitive/forbidden path; refusing to deploy")
	}

	files := app.ConfigFiles
	if len(files) == 0 {
		return reject("no compose config files found for this project")
	}
	opts := compose.Options{ProtectedPaths: s.protectedHostPaths()}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			res.Violations = append(res.Violations, compose.Violation{Message: "cannot read compose file " + f})
			continue
		}
		r := compose.ValidateBytes(data, env, rd, opts)
		res.Violations = append(res.Violations, r.Violations...)
	}
	return res
}

// protectedHostPaths are Mooring-owned host paths a bind mount must never reach
// (the DB lives in DataDir; the master key lives in the config dir) — review #17.
func (s *Server) protectedHostPaths() []string {
	var p []string
	if s.cfg.DataDir != "" {
		p = append(p, s.cfg.DataDir)
	}
	if s.configPath != "" {
		p = append(p, filepath.Dir(s.configPath))
	}
	return p
}

// isSensitiveDir reports whether dir is (or is inside) a clearly sensitive host
// location that should never be an app run_dir.
func isSensitiveDir(dir string) bool {
	for _, sp := range []string{"/etc", "/proc", "/sys", "/dev", "/boot", "/root", "/var/run", "/run", "/var/lib/docker"} {
		if dir == sp || strings.HasPrefix(dir, sp+"/") {
			return true
		}
	}
	return false
}

func classifyExit(err error) (int, string) {
	if err == nil {
		return 0, "ok"
	}
	if errors.Is(err, dockerexec.ErrWritePlaneDisabled) {
		return -1, "disabled"
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), "error"
	}
	return -1, "error"
}

func (s *Server) recordDeployStart(ctx context.Context, project, service, action, actor string) int64 {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO deploys(project, service, action, source, actor, started_at) VALUES(?, ?, ?, 'manual', ?, ?)`,
		project, service, action, actor, time.Now().Unix())
	if err != nil {
		return 0
	}
	id, _ := res.LastInsertId()
	return id
}

func (s *Server) recordDeployFinish(ctx context.Context, id int64, code int, outcome string) {
	if id == 0 {
		return
	}
	// Use a detached context: the request ctx may be cancelled (client gone) but
	// the deploy record must still be finalized.
	_, _ = s.db.Exec(`UPDATE deploys SET finished_at=?, exit_code=?, outcome=? WHERE id=?`,
		time.Now().Unix(), code, outcome, id)
}

// handleServiceLogs streams a service's container logs over SSE through the
// read-only socket-proxy (read plane — no semaphore).
func (s *Server) handleServiceLogs(w http.ResponseWriter, r *http.Request) {
	if s.docker == nil {
		http.Error(w, "logs unavailable", http.StatusServiceUnavailable)
		return
	}
	project, service := r.PathValue("project"), r.PathValue("service")
	var containerID string
	if snap := s.snapshot(); snap != nil {
		if app := snap.AppByProject(project); app != nil {
			// ?copy=<id> streams a SPECIFIC replica's logs (a scaled service has many); the
			// selection is scoped to this app's own service containers, so a client can never
			// stream a container outside it. Empty/stale copy → the first (newest).
			if chosen, _, ok := selectCopy(app, service, r.URL.Query().Get("copy")); ok {
				containerID = chosen.ContainerID
			}
		}
	}
	if containerID == "" {
		http.Error(w, "service/container not found", http.StatusNotFound)
		return
	}
	// concurrency cap
	select {
	case s.logStreams <- struct{}{}:
		defer func() { <-s.logStreams }()
	default:
		http.Error(w, "too many concurrent log streams", http.StatusServiceUnavailable)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	clearWriteDeadline(w) // SSE log stream is long-lived — exempt from the 60s WriteTimeout
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	flusher.Flush()

	_ = s.docker.StreamLogs(r.Context(), containerID, 300, true, func(line string) {
		// SSE framing: a hostile log line must not inject events. Replace CR and
		// LF with spaces so an interior \r/\n can't split the data field (#16).
		safe := strings.NewReplacer("\r", " ", "\n", " ").Replace(line)
		fmt.Fprintf(w, "data: %s\n\n", safe)
		flusher.Flush()
	})
}
