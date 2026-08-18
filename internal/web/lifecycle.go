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

// runLifecycle executes a gated, semaphored `docker compose` action and streams
// its output back as the (chunked, flushed) response body.
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
	target := project
	if service != "" {
		target = project + "/" + service
	}
	writeln("$ docker compose %s%s", strings.Join(args, " "), serviceSuffix(service))

	job := dockerexec.Job{Project: project, Dir: app.WorkingDir, ConfigFiles: app.ConfigFiles, EnvFile: envFile, Action: args, Service: service}
	// Hold an expected_down lease so the self-healing supervisor doesn't read this
	// intentional restart/redeploy as a crash loop (plan §8.5).
	defer s.leaseExpectedDown(ctx, project)()
	onl := func(line string) { writeln("%s", line) }
	var runErr error
	if len(args) > 0 && args[0] == "up" {
		// A redeploy is an `up` — recover from a stranded name conflict (interrupted recreate).
		declared := s.reapScope(ctx, project)
		runErr = s.runUpWithConflictReap(ctx, project, declared,
			func(c context.Context, ol func(string)) error { return s.runner.Run(c, job, ol) },
			s.runner.RemoveContainers, onl)
	} else {
		runErr = s.runner.Run(ctx, job, onl) // restart/stop/start: no name-allocation to conflict
	}

	code, outcome := classifyExit(runErr)
	s.recordDeployFinish(ctx, depID, code, outcome)
	if runErr == nil {
		// A successful stop HOLDS the service(s) so the self-heal supervisor + auto-scaler leave
		// them down (a manual stop stays stopped); start/restart/redeploy RELEASES the hold. Uses a
		// detached context — the request ctx may already be cancelled now the stream has ended.
		s.applyHoldForAction(project, service, action, actor, app)
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
