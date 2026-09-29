package selfheal

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/alertstore"
	"github.com/daboss2003/mooring/internal/dockerexec"
	"github.com/daboss2003/mooring/internal/monitor"
	"github.com/daboss2003/mooring/internal/startgate"
)

// remediateTimeout bounds one remediation (a restart or a recreate of one service), on top of the
// service's stop grace period.
const remediateTimeout = 5 * time.Minute

// Actioner executes a remediation rung for one service. The watcher calls it ONLY
// after the safety gates pass, and while it HOLDS the one-docker-child
// semaphore (acquired non-blocking by the gate).
type Actioner interface {
	Remediate(ctx context.Context, app monitor.App, service string, rung Rung, t Target) error
}

// ErrNoReplacement is returned by an Actioner that refuses to remove copies because nothing would
// replace them (the service isn't autoscaled after all). The watcher treats it like a deferral: no
// attempt is consumed, and the next decision recreates the service instead.
var ErrNoReplacement = errors.New("no autoscaling policy would replace the removed copies")

// Target narrows a remediation to specific copies of the service.
type Target struct {
	CopyID string   // restart only this copy; "" = act on the whole service
	Remove []string // remove these sick copies instead (the autoscaler starts fresh ones); never set with CopyID
}

// ServiceInfo is what the supervisor needs from an app's definition about one service.
type ServiceInfo struct {
	DependsOn []string      // services of the same app it depends on
	Notify    bool          // on_unhealthy: notify — a failing healthcheck is reported, never restarted
	Interval  time.Duration // healthcheck interval (0 = Docker's default, 30s)
	Scheduled bool          // runs only on its schedule, so it is never running as a dependency
	Scaled    bool          // an enabled autoscaling policy keeps its copy count, so a removed copy is replaced
	StopGrace time.Duration // stop_grace_period (0 = Docker's default, 10s)
}

// Config configures a Watcher. The function/clock fields are injectable for tests.
type Config struct {
	Store        *Store
	Alerts       *alertstore.Store // nil → pages are logged only (alerting disabled)
	Snap         func() *monitor.Snapshot
	Sem          *dockerexec.Semaphore
	Act          Actioner
	Policy       Policy                  // the built-in/global default
	PolicyFor    func(app string) Policy // per-app override (nil → always Policy); see spec.self_healing
	Log          *slog.Logger
	Interval     time.Duration
	FloorBytes   uint64 // memory-headroom floor (0 = gate disabled, e.g. no host metrics)
	WritePlaneOK bool   // the §0 write-plane gate result
	// Paused, when set and true, defers every remediation (e.g. the docker read and write planes reach
	// different daemons, so an action would hit containers the read plane doesn't see). nil = never.
	Paused    func() bool
	Protected map[string]bool // project names that are the edge/control plane — never targets
	Now       func() int64    // injectable clock; defaults to time.Now().Unix
	// Gate paces container starts host-wide: a remediation that starts a container waits until it
	// admits the start, then records it. nil = no pacing.
	Gate *startgate.Gate
	// Observe folds a snapshot into Gate before the tick's decisions (nil = the caller feeds Gate).
	Observe func(*monitor.Snapshot)
	// Services returns what an app's definition says about its services (dependencies, on_unhealthy,
	// healthcheck interval). nil, or ok=false → no dependency awareness and restart on unhealthy.
	Services func(app string) (map[string]ServiceInfo, bool)
}

// Watcher is the bounded self-healing supervisor loop (plan §8.5).
type Watcher struct {
	cfg  Config
	fsms map[Key]FSM // in-memory FSM cache, recovered from the store on boot

	lastAt  time.Time               // the last snapshot stepped (each is stepped once)
	stable  map[Key]int64           // unix sec each service became fully healthy (tick goroutine only)
	waits   map[Key]*startgate.Wait // per-service start-gate deferral of the pending remediation
	settleW map[Key]bool            // a long settle deferral was already logged

	mu           sync.Mutex   // guards pendingClear only (NOT held during tick I/O)
	pendingClear map[Key]bool // operator clear-circuit requests, drained at tick start
}

// New builds a Watcher.
func New(cfg Config) *Watcher {
	if cfg.Now == nil {
		cfg.Now = func() int64 { return time.Now().Unix() }
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Watcher{cfg: cfg, fsms: map[Key]FSM{}, pendingClear: map[Key]bool{},
		stable: map[Key]int64{}, waits: map[Key]*startgate.Wait{}, settleW: map[Key]bool{}}
}

// ClearCircuit requests that a latched CIRCUIT_OPEN service be reset to HEALTHY (the
// operator's "I fixed the root cause, try again" button). It is safe to call from
// another goroutine (the web handler): it only records the request under a short
// lock; the watcher applies it at the start of the next tick, so it never races the
// fsm map and never blocks on tick I/O.
func (w *Watcher) ClearCircuit(k Key) {
	w.mu.Lock()
	w.pendingClear[k] = true
	w.mu.Unlock()
}

// drainClears applies any pending operator clear-circuit requests.
func (w *Watcher) drainClears(ctx context.Context, now int64) {
	w.mu.Lock()
	pending := w.pendingClear
	w.pendingClear = map[Key]bool{}
	w.mu.Unlock()
	for k := range pending {
		w.fsms[k] = FSM{Phase: Healthy}
		_ = w.cfg.Store.Save(ctx, k, w.fsms[k], now)
	}
}

// Run boots (clearing stale expected_down leases fail-closed, then recovering FSM
// state from SQLite) and ticks the supervisor until ctx is cancelled.
func (w *Watcher) Run(ctx context.Context) {
	// Fail-closed: a deploy that crashed without releasing its lease must not be able
	// to suppress a crash-loop alert across a restart. If we can't GUARANTEE the
	// stale leases are cleared, refuse to run rather than risk silent suppression —
	// the M10 rule-based alert engine still covers crash loops independently.
	if err := w.cfg.Store.ClearAllExpectedDown(ctx); err != nil {
		w.cfg.Log.Error("selfheal: refusing to start — could not clear stale expected_down leases on boot",
			"level", "security", "err", err)
		return
	}
	if all, err := w.cfg.Store.LoadAll(); err == nil {
		w.fsms = all
	}
	t := time.NewTicker(w.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			w.Tick(ctx)
		}
	}
}

// Tick runs one supervision pass over the latest snapshot. Exported for tests.
func (w *Watcher) Tick(ctx context.Context) {
	snap := w.cfg.Snap()
	if snap == nil || !snap.DockerOK || snap.ListFailed {
		return // never act on stale/absent data (a failed list shows no containers, not that none run)
	}
	if !snap.At.IsZero() {
		if snap.At.Equal(w.lastAt) {
			return // the ticker ran ahead of the monitor: count each observation once
		}
		w.lastAt = snap.At
	}
	if w.cfg.Observe != nil {
		w.cfg.Observe(snap)
	}
	now := w.cfg.Now()
	w.drainClears(ctx, now)
	leases, _ := w.cfg.Store.ActiveExpectedDown(now)
	held, _ := w.cfg.Store.ActiveHeld() // operator-held services: suspend remediation (never restart)

	// Headroom: free host memory this tick. If host metrics are unavailable the
	// headroom gate is disabled (floor 0) — the §0 gate + semaphore still apply.
	var headroom uint64
	floor := w.cfg.FloorBytes
	if snap.HostOK && snap.Host.MemTotal >= snap.Host.MemUsed {
		headroom = snap.Host.MemTotal - snap.Host.MemUsed
	} else {
		floor = 0
	}

	seen := map[Key]bool{}
	for _, app := range snap.Apps {
		var info map[string]ServiceInfo
		if w.cfg.Services != nil {
			info, _ = w.cfg.Services(app.Project)
		}
		groups, names := groupCopies(app, info)
		// Dependencies first, so a dependency's state this tick is known when its dependents step.
		for _, name := range dependencyOrder(names, info) {
			key := Key{App: app.Project, Service: name}
			seen[key] = true
			g := groups[name]
			obs := g.observation()
			obs.ExpectedDown = leases[app.Project]
			obs.Held = held[key]
			obs.Scaled = info[name].Scaled
			// WaitingOnEdge is refined once the cert inventory lands (M19); until
			// then it is conservatively false (never suppress a real failure).
			if !obs.Held && !obs.ExpectedDown && obs.failing() {
				obs.WaitingOnDependency, obs.Dependency = w.dependencyUnsettled(app.Project, name, info, groups, now)
			}
			w.stepService(ctx, app, name, key, obs, g, info[name].StopGrace, now, headroom, floor)
			if g.settled() {
				if w.stable[key] == 0 {
					w.stable[key] = now
				}
			} else {
				delete(w.stable, key)
			}
		}
	}
	if !snap.Truncated {
		w.prune(ctx, seen, leases, now) // a truncated list may omit services that still exist
	}
}

// copyGroup aggregates the containers of one service for a tick.
type copyGroup struct {
	ids       []string // every copy
	sickIDs   []string // copies down, or failing their healthcheck (unless notify)
	health    string   // the copy's health when there is one copy
	replicas  int
	running   int
	unhealthy int  // running copies failing their healthcheck that count as sick
	reported  int  // running copies failing their healthcheck on a notify service
	starting  int  // running copies whose healthcheck hasn't passed yet
	oom       bool // a sick copy was OOM-killed (or exited 137)
	exitCode  int  // a down copy's exit code
	restarts  int  // the highest restart count among the copies
	allSeen   bool // every copy was inspected this poll
}

// groupCopies aggregates an app's containers per service; names lists the services in first-seen order.
func groupCopies(app monitor.App, info map[string]ServiceInfo) (map[string]*copyGroup, []string) {
	groups := map[string]*copyGroup{}
	var names []string
	for _, svc := range app.Services {
		g := groups[svc.Service]
		if g == nil {
			g = &copyGroup{allSeen: true}
			groups[svc.Service] = g
			names = append(names, svc.Service)
		}
		g.replicas++
		g.health = svc.Health
		if svc.ContainerID != "" {
			g.ids = append(g.ids, svc.ContainerID)
		}
		if !svc.Inspected {
			g.allSeen = false
		}
		if svc.RestartCount > g.restarts {
			g.restarts = svc.RestartCount
		}
		switch {
		case !svc.Running():
			g.sickIDs = appendID(g.sickIDs, svc.ContainerID)
			if g.exitCode == 0 || svc.ExitCode == 137 {
				g.exitCode = svc.ExitCode
			}
			g.oom = g.oom || svc.OOMKilled || svc.ExitCode == 137
			continue
		case svc.Health == "unhealthy" && info[svc.Service].Notify:
			g.reported++
		case svc.Health == "unhealthy":
			g.unhealthy++
			g.sickIDs = appendID(g.sickIDs, svc.ContainerID)
			g.oom = g.oom || svc.OOMKilled
		case svc.Health == "starting":
			g.starting++
		}
		g.running++
	}
	for _, g := range groups {
		sort.Strings(g.sickIDs)
	}
	return groups, names
}

func appendID(ids []string, id string) []string {
	if id == "" {
		return ids
	}
	return append(ids, id)
}

// observation turns the group into the FSM's per-service Observation.
func (g *copyGroup) observation() Observation {
	o := Observation{
		Running:      g.running == g.replicas,
		RestartCount: g.restarts,
		OOMKilled:    g.oom,
		ExitCode:     g.exitCode,
		Replicas:     g.replicas,
		Sick:         g.replicas - g.running + g.unhealthy,
		SickIDs:      g.sickIDs,
		Reported:     g.reported,
	}
	switch {
	case g.unhealthy > 0:
		o.Health = "unhealthy"
	case g.replicas == 1 && g.reported == 0:
		o.Health = g.health
	default:
		o.Health = "healthy"
	}
	return o
}

// settled reports whether every copy is running, inspected, and healthy (or has no healthcheck):
// the service is usable as a dependency.
func (g *copyGroup) settled() bool {
	return g.replicas > 0 && g.allSeen && g.running == g.replicas && g.unhealthy == 0 && g.reported == 0 && g.starting == 0
}

// dependencyOrder lists names with each service after the services it depends on (transitively),
// otherwise in the given order. A dependency cycle is broken where it closes.
func dependencyOrder(names []string, info map[string]ServiceInfo) []string {
	if len(info) == 0 {
		return names
	}
	present := map[string]bool{}
	for _, n := range names {
		present[n] = true
	}
	out := make([]string, 0, len(names))
	state := map[string]int{} // 1 visiting, 2 done
	var visit func(n string)
	visit = func(n string) {
		if state[n] != 0 {
			return
		}
		state[n] = 1
		for _, d := range info[n].DependsOn {
			if present[d] {
				visit(d)
			}
		}
		state[n] = 2
		out = append(out, n)
	}
	for _, n := range names {
		visit(n)
	}
	return out
}

// dependencyUnsettled reports the first service that svc depends on (directly or transitively,
// nearest first) that is failing or hasn't been healthy long enough: down, failing its healthcheck
// (notify services too), still starting, not inspected, without containers, under remediation or
// held, or healthy for less than a grace of max(60s, 2 × svc's healthcheck interval) — a dependent's
// own healthcheck needs a couple of intervals to pass again. Restarting svc meanwhile can't help.
// The graph comes only from the app's verified definition.
func (w *Watcher) dependencyUnsettled(app, svc string, info map[string]ServiceInfo, groups map[string]*copyGroup, now int64) (bool, string) {
	if len(info[svc].DependsOn) == 0 {
		return false, ""
	}
	interval := info[svc].Interval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	grace := int64((2 * interval).Seconds())
	if grace < 60 {
		grace = 60
	}
	visited := map[string]bool{svc: true}
	queue := append([]string(nil), info[svc].DependsOn...)
	for len(queue) > 0 {
		d := queue[0]
		queue = queue[1:]
		if visited[d] {
			continue
		}
		visited[d] = true
		di, known := info[d]
		if !known || di.Scheduled {
			continue // not a long-running service of this app
		}
		g := groups[d]
		if g == nil || !g.settled() {
			return true, d
		}
		switch w.fsms[Key{App: app, Service: d}].Phase {
		case Suspect, Degraded, Remediating, Recovered, CircuitOpen, Held, WaitingOnDependency, Unhealthy:
			return true, d
		}
		if since := w.stable[Key{App: app, Service: d}]; since == 0 || now-since < grace {
			return true, d
		}
		queue = append(queue, di.DependsOn...)
	}
	return false, ""
}

// policy returns the effective policy for an app: its tuned spec.self_healing if one
// is configured, else the built-in default. The lookup is per tick so a redeploy that
// changes the policy takes effect without a restart.
func (w *Watcher) policy(app string) Policy {
	if w.cfg.PolicyFor != nil {
		return w.cfg.PolicyFor(app)
	}
	return w.cfg.Policy
}

// stepService decides and acts for one service.
func (w *Watcher) stepService(ctx context.Context, app monitor.App, service string, key Key, obs Observation, g *copyGroup, stopGrace time.Duration, now int64, headroom, floor uint64) {
	prev, ok := w.fsms[key]
	if !ok {
		prev = FSM{Phase: Healthy}
	}
	pol := w.policy(app.Project)
	d := Decide(prev, obs, pol, now)
	if d.Act != ActRemediate {
		delete(w.waits, key) // nothing pending: the next remediation starts a fresh start-gate wait
		delete(w.settleW, key)
	}

	switch d.Act {
	case ActNone:
		w.commit(ctx, key, d.Next, now)
	case ActResolve:
		w.emitInfra(ctx, app, service, "recovered", "resolved")
		w.commit(ctx, key, d.Next, now)
	case ActPage:
		w.emitInfra(ctx, app, service, d.Kind, "firing")
		w.commit(ctx, key, d.Next, now)
	case ActRemediate:
		w.remediate(ctx, app, service, key, d, obs, g, pol, stopGrace, now, headroom, floor)
	}
}

// remediate applies the safety gates to a proposed rung and acts accordingly.
// pol is the effective (per-app) policy for this service; stopGrace its stop_grace_period.
func (w *Watcher) remediate(ctx context.Context, app monitor.App, service string, key Key, d Decision, obs Observation, g *copyGroup, pol Policy, stopGrace time.Duration, now int64, headroom, floor uint64) {
	gi := GateInput{
		Rung:                 d.Rung,
		WritePlaneOK:         w.cfg.WritePlaneOK && (w.cfg.Paused == nil || !w.cfg.Paused()),
		RedeployEnabled:      pol.RedeployEnabled,
		AcquireSemaphore:     w.cfg.Sem.TryAcquire,
		ReleaseSemaphore:     w.cfg.Sem.Release,
		HeadroomBytes:        headroom,
		FloorBytes:           floor,
		IsEdgeOrControlPlane: w.cfg.Protected[app.Project],
	}
	starts := w.cfg.Gate != nil && len(d.Remove) == 0 // removing copies starts nothing
	if starts {
		wait := w.waits[key]
		if wait == nil {
			wait = &startgate.Wait{}
			w.waits[key] = wait
		}
		gi.Admit = func() (bool, string) {
			// The service's own copies neither hold its restart back nor count as host CPU, and a
			// service with no running copy is restored without waiting for CPU.
			dec := wait.Admit(w.cfg.Gate, time.Now(), startgate.AdmitOpts{ExcludeContainerIDs: g.ids, IgnoreCPU: g.running == 0})
			if dec.OK && wait.CPUWaivedAt(w.cfg.Gate, time.Now()) {
				w.cfg.Log.Warn("selfheal: remediating despite a busy host CPU (waited the start gate's max_wait)", "app", app.Project, "service", service)
			}
			return dec.OK, dec.Reason
		}
	}
	out, reason := Gates(gi)
	switch out {
	case GateProceed:
		// The gate acquired the semaphore; we hold it for exactly this action.
		defer w.cfg.Sem.Release()
		timeout := remediateTimeout
		if stopGrace > 0 {
			timeout += stopGrace // stopping a copy may take its whole grace period
		}
		actx, cancel := context.WithTimeout(ctx, timeout)
		started := time.Now()
		err := w.cfg.Act.Remediate(actx, app, service, d.Rung, Target{CopyID: d.Target, Remove: d.Remove})
		cancel()
		if starts {
			w.cfg.Gate.Record(app.Project, service, started, time.Now(), err == nil) // even on error: it may have started something
		}
		delete(w.waits, key)
		delete(w.settleW, key)
		if errors.Is(err, ErrNoReplacement) {
			// Intentional: no attempt consumed — nothing ran. The service isn't autoscaled after all, so
			// the next decision (with Scaled false) recreates it instead, through the start gate.
			w.commit(ctx, key, d.Next, now)
			w.cfg.Log.Warn("selfheal: sick copies not removed (not autoscaled); recreating the service next", "app", app.Project, "service", service)
			return
		}
		// The attempt is consumed whether or not the action succeeded (a failed
		// rung still counts toward the cap → the circuit eventually opens).
		w.commit(ctx, key, Commit(d, obs, pol, now), now)
		if err != nil {
			w.cfg.Log.Warn("selfheal: remediation failed", "app", app.Project, "service", service, "rung", d.Rung, "copy", shortID(d.Target), "remove", shortIDs(d.Remove), "err", err)
		} else {
			w.cfg.Log.Info("selfheal: remediated", "app", app.Project, "service", service, "rung", d.Rung, "copy", shortID(d.Target), "remove", shortIDs(d.Remove))
		}
	case GateDefer:
		// No attempt consumed; re-checked next tick.
		w.commit(ctx, key, d.Next, now)
		w.cfg.Log.Debug("selfheal: action deferred", "app", app.Project, "service", service, "reason", reason)
		if wait := w.waits[key]; wait != nil && w.cfg.Gate != nil && !w.settleW[key] &&
			wait.SettleWaited(time.Now()) > w.cfg.Gate.Config().MaxWait {
			w.settleW[key] = true
			w.cfg.Log.Warn("selfheal: remediation still waiting for other containers to finish starting", "app", app.Project, "service", service, "reason", reason)
		}
	case GatePage:
		// Headroom too low to safely restart: page instead of acting (plan §8.5).
		next := d.Next
		next.Phase = Degraded
		w.emitInfra(ctx, app, service, "low_headroom", "firing")
		w.commit(ctx, key, next, now)
	case GateSkip:
		// Edge/control plane is never a remediation target — leave it untouched.
	}
}

// shortID shortens a container id for logs.
func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// shortIDs shortens container ids for logs.
func shortIDs(ids []string) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = shortID(id)
	}
	return out
}

// prune drops FSM state for services that no longer exist (and whose app isn't
// mid-deploy under a lease), so the table doesn't grow unbounded.
func (w *Watcher) prune(ctx context.Context, seen map[Key]bool, leases map[string]bool, now int64) {
	for key := range w.fsms {
		if seen[key] || leases[key.App] {
			continue
		}
		delete(w.fsms, key)
		delete(w.stable, key)
		delete(w.waits, key)
		delete(w.settleW, key)
		_ = w.cfg.Store.Delete(ctx, key)
	}
}

func (w *Watcher) commit(ctx context.Context, key Key, f FSM, now int64) {
	w.fsms[key] = f
	_ = w.cfg.Store.Save(ctx, key, f, now)
}

// kindLevel maps a can't-fix taxonomy kind to its alert level. low_headroom, a long dependency
// wait and a reported (notify) failing healthcheck are WARNINGs (quiet-hours-suppressible); the
// give-up kinds are CRITICAL (always page).
func kindLevel(kind string) string {
	switch kind {
	case "low_headroom", "dependency_wait", "unhealthy_reported":
		return alert.LevelWarning
	}
	return alert.LevelCritical
}

// emitInfra enqueues a Mooring-originated infra alert (origin=mooring_infra,
// rule_id=0, never deferred). Names are CR/LF/NUL-stripped before they reach any
// channel (the email channel also builds MIME-safe, never placing a name in a
// header). A nil alert store (alerting disabled) logs the page instead.
func (w *Watcher) emitInfra(ctx context.Context, app monitor.App, service, kind, transition string) {
	target := sanitizeName(app.Project) + "/" + sanitizeName(service)
	if w.cfg.Alerts == nil {
		w.cfg.Log.Warn("selfheal: infra alert (no channels configured)", "kind", kind, "target", target, "transition", transition)
		return
	}
	summary := infraSummary(kind, transition, target)
	o := alert.Outbox{
		RuleID:     0, // infra sentinel
		Target:     target,
		Kind:       kind,
		Level:      kindLevel(kind),
		Transition: transition,
		Summary:    summary,
		DedupeKey:  "selfheal:" + target, // one open supervisor alert per service
	}
	if err := w.cfg.Alerts.EnqueueInfra(ctx, o); err != nil {
		w.cfg.Log.Warn("selfheal: enqueue infra alert failed", "err", err)
	}
}

// infraSummary builds the bounded, fixed-section body (plan §8.4) — no log dump.
func infraSummary(kind, transition, target string) string {
	if transition == "resolved" {
		return "Service " + target + " recovered and is healthy again."
	}
	switch kind {
	case "oom_killed_repeated":
		return "Service " + target + " is being OOM/at-limit killed repeatedly. Mooring is NOT restarting it (a restart would not help on a memory-starved box). Reduce its memory use or raise the host's RAM."
	case "low_headroom":
		return "Service " + target + " needs a restart but host memory headroom is below the safety floor. Mooring is holding off to avoid an OOM. Free memory or raise the floor."
	case "crashloop_capped":
		return "Service " + target + " is crash-looping and Mooring's restart/recreate attempts did not recover it. Manual investigation needed."
	case "unhealthy_capped":
		return "Service " + target + " is up but failing its healthcheck and did not recover after restart/recreate. Manual investigation needed."
	case "dependency_wait":
		return "Service " + target + " has been failing for 10 minutes while a service it depends on is failing or recovering. Mooring held off restarting it meanwhile and now resumes its normal restart/recreate attempts. Check the dependency."
	case "unhealthy_reported":
		return "Service " + target + " is failing its healthcheck. It declares on_unhealthy: notify, so Mooring reports it and does not restart it."
	default:
		return "Service " + target + " could not be self-healed (" + kind + ")."
	}
}

// sanitizeName strips CR/LF/NUL (defence in depth against header/log injection via
// an attacker-influenced project/service name) and bounds the length.
func sanitizeName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == 0 {
			return -1
		}
		return r
	}, s)
	if len(s) > 128 {
		s = s[:128]
	}
	return s
}
