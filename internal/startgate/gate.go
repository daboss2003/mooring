// Package startgate paces container starts across the host. A start is admitted only when no other
// recently started container is still starting up (not yet healthy, or — without a healthcheck — still
// in its start-up CPU burst) and the host has CPU headroom. The components that start containers on
// their own (the scaler, self-heal) consult one shared Gate, so starts happen one at a time instead of
// all at once: several services starting together on a small host starve each other of CPU and none
// of them becomes healthy.
//
// The gate is bookkeeping over monitor observations and performs no I/O. Callers fold each monitor
// snapshot in with Observe (idempotent per snapshot), ask Admit before starting a container, and
// Record every start they make.
package startgate

import (
	"fmt"
	"sync"
	"time"
)

// Config tunes the gate (config.yaml server.start_gate).
type Config struct {
	Enabled bool
	// CPUBusyPct: starts wait while the host CPU (mean of the last 3 samples, 0–100 across all cores)
	// is at or above this.
	CPUBusyPct float64
	// SettleGrace: a container without a healthcheck counts as starting for at least this long.
	SettleGrace time.Duration
	// CPUSettlePct: after SettleGrace, a container without a healthcheck is still starting while its
	// CPU is at or above this percentage of one core.
	CPUSettlePct float64
	// MaxSettle bounds how long one start holds other starts back, whatever its state.
	MaxSettle time.Duration
	// MaxWait: once an action has waited this long for CPU headroom, it stops waiting for CPU (Wait).
	MaxWait time.Duration
	// NumCPU is the host's CPU count (container CPU% is per core; host CPU% is across all cores).
	NumCPU int
}

// DefaultConfig returns the built-in tuning for a host with ncpu CPUs.
func DefaultConfig(ncpu int) Config {
	if ncpu < 1 {
		ncpu = 1
	}
	return Config{
		Enabled: true, CPUBusyPct: 85, SettleGrace: 30 * time.Second, CPUSettlePct: 50,
		MaxSettle: 3 * time.Minute, MaxWait: 10 * time.Minute, NumCPU: ncpu,
	}
}

// Container is one container as the monitor last saw it.
type Container struct {
	ID, App, Service string
	Running          bool
	Health           string // none | starting | healthy | unhealthy
	StartedAt        time.Time
	RestartCount     int
	CPUPercent       float64 // per core: 100 = one full core
	CPUValid         bool    // CPUPercent is a real sample (not the container's first poll)
	Inspected        bool    // Health, StartedAt and RestartCount are known for this observation
	Protected        bool    // Mooring's own infrastructure: never holds starts back
}

// Observation is one monitor snapshot, as far as the gate needs it.
type Observation struct {
	At         time.Time // when the snapshot's container listing began
	HostOK     bool
	HostCPUPct float64 // 0–100 across all cores
	Containers []Container
}

// AdmitOpts qualifies one admission request.
type AdmitOpts struct {
	// ExcludeContainerIDs are the target's own containers (the copies being restarted or replaced).
	// They never hold the start back, and their CPU is subtracted from the host's, so a runaway
	// service can always be restarted.
	ExcludeContainerIDs []string
	// IgnoreCPU skips the CPU check (the action already waited MaxWait for CPU, or it restores a
	// service with no running copy at all).
	IgnoreCPU bool
	// IgnoreApp: starts recorded for this app, and its containers still starting, don't hold the start
	// back. A rollout paces its own app itself (it waits for each service before the next) and only
	// waits here for other apps' starts and the CPU.
	IgnoreApp string
	// IgnoreStarts: no other start holds this one back (only the CPU check remains) — the action already
	// waited MaxWait for them.
	IgnoreStarts bool
}

// Decision kinds.
const (
	Settling = "settling" // another start is still settling
	CPUBusy  = "cpu"      // the host has no CPU headroom
)

// Decision is Admit's answer.
type Decision struct {
	OK      bool
	Kind    string // "" when OK; Settling or CPUBusy
	Reason  string
	Blocker string // "app/service" still settling, for Settling
}

// track is the gate's memory of one container.
type track struct {
	started   time.Time // StartedAt of the run being tracked; a new value means it (re)started
	since     time.Time // first observation of this run that saw it still starting
	done      bool      // this run settled, or MaxSettle passed: it holds nothing back until it restarts
	restarts  int       // RestartCount at the last inspected observation
	counted   bool      // restarts is set
	crashTill time.Time // RestartCount rose recently (crash loop): holds nothing back until then
}

// ledgerEntry is a start the gate was told about and has not yet seen settle.
type ledgerEntry struct {
	app, service string
	start, end   time.Time // the action began at start and returned at end
	ok           bool      // the action succeeded, so a container it started must show up
}

// Gate is the shared start gate. Safe for concurrent use.
type Gate struct {
	mu     sync.Mutex
	cfg    Config
	lastAt time.Time
	cpu    []float64 // the last host CPU samples, oldest first (at most 3)
	cur    []Container
	curIdx map[string]int // container id → index in cur
	tracks map[string]*track
	ledger []ledgerEntry
}

// New builds a Gate.
func New(cfg Config) *Gate {
	if cfg.NumCPU < 1 {
		cfg.NumCPU = 1
	}
	return &Gate{cfg: cfg, tracks: map[string]*track{}}
}

// Config returns the gate's tuning.
func (g *Gate) Config() Config {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.cfg
}

// Observe folds one monitor observation in. Each observation is applied once (a repeated or older
// one is ignored), so every caller can Observe the snapshot it holds before asking Admit.
func (g *Gate) Observe(o Observation) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !o.At.After(g.lastAt) {
		return
	}
	g.lastAt = o.At
	if o.HostOK {
		g.cpu = append(g.cpu, o.HostCPUPct)
		if len(g.cpu) > 3 {
			g.cpu = g.cpu[len(g.cpu)-3:]
		}
	}
	seen := make(map[string]bool, len(o.Containers))
	for _, c := range o.Containers {
		seen[c.ID] = true
		t := g.tracks[c.ID]
		if t == nil {
			t = &track{}
			g.tracks[c.ID] = t
		}
		if !c.Inspected {
			continue // nothing new is known about it: keep what we had
		}
		if !t.started.Equal(c.StartedAt) {
			t.started, t.since, t.done = c.StartedAt, time.Time{}, false // a new run
		}
		// A restart policy relaunching a crashing container raises RestartCount; its StartedAt
		// resets every time, so it would look freshly started forever. It holds nothing back —
		// self-heal owns it.
		if t.counted && c.RestartCount > t.restarts {
			t.crashTill = o.At.Add(g.cfg.MaxSettle)
		}
		t.restarts, t.counted = c.RestartCount, true
		if !c.Running || t.done {
			continue
		}
		if !g.startingLocked(c, o.At) {
			t.done = true
			continue
		}
		if t.since.IsZero() {
			t.since = o.At
		}
		if g.ageLocked(c, t, o.At) >= g.cfg.MaxSettle {
			t.done = true // started long enough ago: stop holding others back, whatever it reports
		}
	}
	for id := range g.tracks {
		if !seen[id] {
			delete(g.tracks, id) // removed
		}
	}
	g.cur = append(g.cur[:0], o.Containers...)
	g.curIdx = make(map[string]int, len(g.cur))
	for i, c := range g.cur {
		g.curIdx[c.ID] = i
	}
	g.retireLocked(o)
}

// startingLocked reports whether a running, inspected container's current state is still start-up.
func (g *Gate) startingLocked(c Container, at time.Time) bool {
	switch c.Health {
	case "healthy", "unhealthy":
		return false // up — or failing, which is self-heal's concern, not a start in progress
	case "starting":
		return true
	default: // no healthcheck: the start-up grace, then until its CPU drops
		if !c.StartedAt.IsZero() && at.Sub(c.StartedAt) < g.cfg.SettleGrace {
			return true
		}
		return !c.CPUValid || c.CPUPercent >= g.cfg.CPUSettlePct
	}
}

// ageLocked is how long the tracked run has been starting: from its StartedAt, or from the first
// observation that saw it starting when StartedAt is unknown.
func (g *Gate) ageLocked(c Container, t *track, at time.Time) time.Duration {
	if !c.StartedAt.IsZero() {
		return at.Sub(c.StartedAt)
	}
	if t.since.IsZero() {
		return 0
	}
	return at.Sub(t.since)
}

// holdsLocked reports whether container c holds other starts back at time now.
func (g *Gate) holdsLocked(c Container, now time.Time) bool {
	t := g.tracks[c.ID]
	if t == nil || !c.Running || !c.Inspected || c.Protected || t.done || t.since.IsZero() {
		return false // unknown, stopped, Mooring's own, or not starting
	}
	if now.Before(t.crashTill) {
		return false
	}
	return g.ageLocked(c, t, now) < g.cfg.MaxSettle
}

// Unsettled reports whether container id, as the latest observation saw it, is still starting up
// (by the rules that hold other starts back, ignoring their exemptions) or crash-looping. Unknown
// containers, and every container while the gate is disabled, report false.
func (g *Gate) Unsettled(id string, now time.Time) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	t := g.tracks[id]
	if !g.cfg.Enabled || t == nil {
		return false
	}
	if now.Before(t.crashTill) {
		return true
	}
	i, ok := g.curIdx[id]
	if !ok {
		return false
	}
	c := g.cur[i]
	return c.Running && c.Inspected && !t.done && !t.since.IsZero() && g.ageLocked(c, t, now) < g.cfg.MaxSettle
}

// expiry is when a ledger entry stops holding starts back even without evidence.
func (g *Gate) expiry(e ledgerEntry) time.Time { return e.end.Add(g.cfg.MaxSettle + 30*time.Second) }

// retireLocked drops the ledger entries this observation shows settled, and expired ones. It takes
// evidence: an observation whose listing began after the action returned, in which no running
// container of the service started by the action is still starting (containers started after the
// action began count as the action's). After a successful action, one of its containers must also
// be in the observation (inspected): until then the entry holds. A container the observation couldn't
// inspect keeps the entry.
func (g *Gate) retireLocked(o Observation) {
	keep := g.ledger[:0]
	for _, e := range g.ledger {
		if !o.At.Before(g.expiry(e)) {
			continue
		}
		if !o.At.After(e.end) {
			keep = append(keep, e) // the listing may predate what the action started
			continue
		}
		settled, seen := true, false
		for _, c := range o.Containers {
			if c.App != e.app || (e.service != "" && c.Service != e.service) {
				continue
			}
			if !c.Inspected {
				if c.Running {
					settled = false
					break
				}
				continue
			}
			if c.StartedAt.Before(e.start.Add(-time.Second)) {
				continue // an older copy
			}
			seen = true
			if t := g.tracks[c.ID]; c.Running && t != nil && !t.done && !o.At.Before(t.crashTill) {
				settled = false
				break
			}
		}
		if !settled || (e.ok && !seen) {
			keep = append(keep, e)
		}
	}
	g.ledger = keep
}

// Record notes a container start on app/service (service "" = any service of the app) by an action
// that began at start and returned at end; ok is whether it succeeded. Call it after the docker child returns, even when it failed:
// until the gate sees what the action started settle (bounded by MaxSettle), other starts wait.
func (g *Gate) Record(app, service string, start, end time.Time, ok bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.cfg.Enabled {
		return
	}
	keep := g.ledger[:0]
	for _, e := range g.ledger {
		if end.Before(g.expiry(e)) {
			keep = append(keep, e)
		}
	}
	g.ledger = append(keep, ledgerEntry{app: app, service: service, start: start, end: end, ok: ok})
}

// Admit reports whether a container start may begin at now.
func (g *Gate) Admit(now time.Time, o AdmitOpts) Decision {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.cfg.Enabled {
		return Decision{OK: true}
	}
	for _, e := range g.ledger {
		if o.IgnoreStarts || (o.IgnoreApp != "" && e.app == o.IgnoreApp) {
			continue
		}
		if now.Before(g.expiry(e)) {
			who := e.app
			if e.service != "" {
				who += "/" + e.service
			}
			return Decision{Kind: Settling, Blocker: who,
				Reason: fmt.Sprintf("%s was started %s ago and is still starting", who, now.Sub(e.start).Round(time.Second))}
		}
	}
	excluded := make(map[string]bool, len(o.ExcludeContainerIDs))
	for _, id := range o.ExcludeContainerIDs {
		excluded[id] = true
	}
	for _, c := range g.cur {
		if !o.IgnoreStarts && !excluded[c.ID] && (o.IgnoreApp == "" || c.App != o.IgnoreApp) && g.holdsLocked(c, now) {
			return Decision{Kind: Settling, Blocker: c.App + "/" + c.Service,
				Reason: fmt.Sprintf("%s/%s is still starting", c.App, c.Service)}
		}
	}
	if !o.IgnoreCPU {
		if pct, busy := g.cpuLocked(excluded); busy {
			return Decision{Kind: CPUBusy, Reason: fmt.Sprintf("host CPU %.0f%% (limit %.0f%%)", pct, g.cfg.CPUBusyPct)}
		}
	}
	return Decision{OK: true}
}

// cpuLocked returns the host CPU (mean of the last samples, minus the excluded containers' share)
// and whether it is at or above CPUBusyPct. With fewer than two samples it reports not busy.
func (g *Gate) cpuLocked(excluded map[string]bool) (float64, bool) {
	if len(g.cpu) < 2 {
		return 0, false
	}
	pct := 0.0
	for _, v := range g.cpu {
		pct += v
	}
	pct /= float64(len(g.cpu))
	for _, c := range g.cur {
		if excluded[c.ID] && c.Running && c.CPUValid {
			pct -= c.CPUPercent / float64(g.cfg.NumCPU)
		}
	}
	if pct < 0 {
		pct = 0
	}
	return pct, pct >= g.cfg.CPUBusyPct
}

// Wait tracks one action's time deferred by the gate, so the action waits for CPU at most MaxWait in
// total (one CPU budget per action, not per step). The zero value is ready; one Wait per action.
type Wait struct {
	cpuSince    time.Time // first CPU deferral
	settleSince time.Time // first settle deferral
}

// Admit asks g, skipping the CPU check once this action has waited MaxWait for CPU, and other starts
// once it has waited MaxWait for them (a long rollout of another app must not keep it waiting).
func (w *Wait) Admit(g *Gate, now time.Time, o AdmitOpts) Decision {
	maxWait := g.Config().MaxWait
	if !w.cpuSince.IsZero() && now.Sub(w.cpuSince) >= maxWait {
		o.IgnoreCPU = true
	}
	if !w.settleSince.IsZero() && now.Sub(w.settleSince) >= maxWait {
		o.IgnoreStarts = true
	}
	d := g.Admit(now, o)
	switch d.Kind {
	case CPUBusy:
		if w.cpuSince.IsZero() {
			w.cpuSince = now
		}
	case Settling:
		if w.settleSince.IsZero() {
			w.settleSince = now
		}
	}
	return d
}

// CPUWaivedAt reports whether the action has used up its CPU budget at now.
func (w *Wait) CPUWaivedAt(g *Gate, now time.Time) bool {
	return !w.cpuSince.IsZero() && now.Sub(w.cpuSince) >= g.Config().MaxWait
}

// SettleWaited is how long the action has been deferred by settling starts (zero if never).
func (w *Wait) SettleWaited(now time.Time) time.Duration {
	if w.settleSince.IsZero() {
		return 0
	}
	return now.Sub(w.settleSince)
}
