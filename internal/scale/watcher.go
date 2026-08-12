package scale

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/alertstore"
	"github.com/daboss2003/mooring/internal/dockerexec"
	"github.com/daboss2003/mooring/internal/monitor"
	"github.com/daboss2003/mooring/internal/ops"
)

// customSignal reads one custom metric spec into a per-replica controller Signal. Phase 1 sources
// only "ops" (queue depth from the app's ops probe).
//
// Present distinguishes "can't measure" from "measured zero", which the controller treats very
// differently (absent → HOLD; zero → permits scale-down). It is Present:false ONLY when the probe
// itself is unavailable — no ops interface, a degraded/errored (BASIC) response, or running==0. A
// HEALTHY (RICH) response whose selector matches nothing means the queue DRAINED / was delisted →
// value 0, Present:true, so an idle worker can actually scale back down (fixing the "drained queue
// disappears → pinned forever" trap).
func customSignal(app *monitor.App, spec MetricSpec, running int) Signal {
	sig := Signal{Name: spec.Name}
	if spec.Source != "ops" || app == nil || app.Ops == nil || running <= 0 {
		return sig // probe unavailable → hold
	}
	res := app.Ops
	if res.Mode != ops.RICH || res.Err != "" {
		return sig // probe degraded / errored → hold (can't measure the backlog)
	}
	sig.Value = float64(sumQueue(res, spec.Select)) / float64(running) // service-total → per-replica
	sig.Present = true
	return sig
}

// cumulativeCounter reports whether an ops queue counter name is a monotonic LIFETIME total rather
// than current backlog. These are EXCLUDED from the unfiltered (select:"") sum so a counter like
// `completed` — which only ever grows — can't drive an unstoppable ramp to the capacity ceiling.
func cumulativeCounter(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "completed", "failed", "done", "processed", "total", "errored", "succeeded", "dead", "prioritized_completed":
		return true
	}
	return false
}

// sumQueue sums the ops queue counts selected by sel. sel=="" sums the BACKLOG — every counter
// EXCEPT cumulative lifetime totals (completed/failed/…), so a monotonic counter can't cause a
// runaway. A non-empty sel is the operator's explicit choice: counters under a queue whose Name==sel
// OR counters whose Name==sel (summed as-is — if they name a cumulative counter, that's on them).
// A selector that matches nothing returns 0 (the caller has already confirmed a healthy probe, so
// "no match" means drained, not missing).
func sumQueue(res *ops.Result, sel string) int64 {
	var total int64
	for _, q := range res.Queues {
		for _, c := range q.Counts {
			switch {
			case sel == "":
				if !cumulativeCounter(c.Name) {
					total += c.Value
				}
			case q.Name == sel || c.Name == sel:
				total += c.Value
			}
		}
	}
	if total < 0 { // an app reporting a negative count can't drag the signal below zero
		total = 0
	}
	return total
}

// Scaler performs the actual replica change for a service (static-argv
// `docker compose up -d --no-deps --no-recreate --scale <svc>=<n>`). The watcher
// calls it only after the §0 gate + a non-blocking semaphore acquire, holding the
// one-docker-child semaphore.
type Scaler interface {
	Scale(ctx context.Context, app, service string, replicas int) error
}

// EdgeReconciler updates the edge replica pool for a service after a count change
// (discover live replicas → validated pool → reload). May be nil (then the route's
// single upstream DNS-round-robins across replicas).
type EdgeReconciler interface {
	ReconcilePool(ctx context.Context, app, service string, replicas int) error
}

// Reserves are the host headroom the capacity guard subtracts before funding this
// app's replicas (control plane + edge slice + a safety floor), plus the near-OOM
// and per-replica-floor guards.
type Reserves struct {
	MemReserveBytes    uint64 // control plane + edge + safety floor (memory)
	CPUReserveMilli    uint64 // control plane + edge (cpu)
	MemFreeFloor       uint64 // keep at least this much memory free (measured budget)
	CPUFreeFloor       uint64
	NearOOMFreeBytes   uint64
	PerReplicaMemFloor uint64
}

// Config configures the auto-scaling Watcher.
type Config struct {
	Store        *Store
	Alerts       *alertstore.Store // nil → refusals are logged only
	Snap         func() *monitor.Snapshot
	Sem          *dockerexec.Semaphore
	Scaler       Scaler
	Edge         EdgeReconciler // optional
	Reserves     Reserves
	Log          *slog.Logger
	Interval     time.Duration
	WritePlaneOK bool
	HostCPUMilli uint64                                        // total host CPU (milli); 0 disables the CPU budget
	IsCandidate  func(app, service string) (ServiceSpec, bool) // C1–C6 from compose; nil → trust the policy opt-in
	Now          func() int64
}

// Watcher is the auto-scaling controller loop (plan §8A).
type Watcher struct {
	cfg     Config
	states  map[Key]State
	refused map[Key]bool // services with an open scale_refused_no_capacity alert
}

// New builds a Watcher.
func New(cfg Config) *Watcher {
	if cfg.Now == nil {
		cfg.Now = func() int64 { return time.Now().Unix() }
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	return &Watcher{cfg: cfg, states: map[Key]State{}, refused: map[Key]bool{}}
}

// Run recovers state and ticks until ctx is cancelled.
func (w *Watcher) Run(ctx context.Context) {
	if all, err := w.cfg.Store.LoadStates(); err == nil {
		w.states = all
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

// replicaGroup aggregates the running replicas of one service in the snapshot.
type replicaGroup struct {
	running    int
	cpuSum     float64
	memMaxPct  float64
	allHealthy bool
}

// Tick runs one control pass. Exported for tests.
func (w *Watcher) Tick(ctx context.Context) {
	snap := w.cfg.Snap()
	if snap == nil || !snap.DockerOK {
		return
	}
	now := w.cfg.Now()
	policies, err := w.cfg.Store.EnabledPolicies()
	if err != nil || len(policies) == 0 {
		return
	}

	groups := w.groupReplicas(snap)

	// Cross-app budget: memory/cpu reserved by ALL enabled services' DESIRED replicas
	// (red-team: reserve against desired, not observed). This is a LIVE running total
	// — when a service scales up earlier in this tick, the reservation grows so a
	// LATER service in the SAME tick is sized against it. Without this, two services
	// scaling in one tick would each see the other's stale (pre-scale) desired and
	// could jointly over-commit the host into an OOM.
	lb := &liveBudget{}
	for k, p := range policies {
		d := w.desired(k, groups[k], p)
		lb.mem += uint64(d) * p.PerReplicaMem
		lb.cpu += uint64(d) * p.PerReplicaCPU
	}

	for k, p := range policies {
		w.stepService(ctx, snap, k, p, groups[k], lb, now)
	}
}

// liveBudget is the running cross-app reservation, mutated as services scale within
// a single tick so later services account for earlier in-tick scale-ups.
type liveBudget struct{ mem, cpu uint64 }

func adjust(v uint64, delta int, per uint64) uint64 {
	n := int64(v) + int64(delta)*int64(per)
	if n < 0 {
		return 0
	}
	return uint64(n)
}

func (w *Watcher) groupReplicas(snap *monitor.Snapshot) map[Key]replicaGroup {
	out := map[Key]replicaGroup{}
	for _, app := range snap.Apps {
		for _, svc := range app.Services {
			k := Key{App: app.Project, Service: svc.Service}
			g := out[k]
			if g.running == 0 {
				g.allHealthy = true // seed; cleared by any unhealthy/down replica
			}
			if !svc.Running() {
				g.allHealthy = false
				out[k] = g
				continue
			}
			g.running++
			g.cpuSum += svc.CPUPercent
			if svc.MemLimit > 0 {
				if pct := float64(svc.MemBytes) / float64(svc.MemLimit) * 100; pct > g.memMaxPct {
					g.memMaxPct = pct
				}
			}
			if svc.Health == "unhealthy" {
				g.allHealthy = false
			}
			out[k] = g
		}
	}
	return out
}

// desired returns the controller's current desired count for a service (persisted
// state, or the observed running count clamped to the policy floor on first sight).
func (w *Watcher) desired(k Key, g replicaGroup, p PolicyRow) int {
	if st, ok := w.states[k]; ok && st.Replicas > 0 {
		return st.Replicas
	}
	d := g.running
	if d < p.Min {
		d = p.Min
	}
	return d
}

func (w *Watcher) stepService(ctx context.Context, snap *monitor.Snapshot, k Key, p PolicyRow, g replicaGroup, lb *liveBudget, now int64) {
	st, ok := w.states[k]
	if !ok || st.Replicas == 0 {
		st = State{Replicas: w.desired(k, g, p)}
	}
	oldDesired := st.Replicas
	// Keep the live cross-app budget in sync with whatever this service ends up at
	// (a no-op for ActNone/Refused; a delta for an actual scale) so later services in
	// THIS tick reserve against the new total.
	defer func() {
		delta := w.states[k].Replicas - oldDesired
		if delta != 0 {
			lb.mem = adjust(lb.mem, delta, p.PerReplicaMem)
			lb.cpu = adjust(lb.cpu, delta, p.PerReplicaCPU)
		}
	}()

	// Candidacy (C1–C6) is re-checked every tick: a service that lost candidacy
	// (gained a host port / RW volume) is scaled back to the floor and left alone.
	if w.cfg.IsCandidate != nil {
		spec, _ := w.cfg.IsCandidate(k.App, k.Service)
		spec.OptedIn = true // the enabled policy IS the opt-in (C7)
		if ok, reason := Candidacy(spec); !ok {
			st.BreachSince = 0 // clear stale hysteresis so a later re-gain starts fresh
			if st.Replicas > p.Min {
				w.act(ctx, k, p.Min, st, now, "lost candidacy: "+reason)
			} else {
				w.save(ctx, k, st, now)
			}
			return
		}
	}

	// Host-capacity guard on fresh data, reserving against OTHER apps' desired (the
	// live running total minus this service's own current contribution).
	otherMem := adjust(lb.mem, -st.Replicas, p.PerReplicaMem)
	otherCPU := adjust(lb.cpu, -st.Replicas, p.PerReplicaCPU)
	ceiling, nearOOM, capReason := MaxReplicas(CapacityInput{
		Mem:       Budget{HostTotal: snap.Host.MemTotal, HostFree: hostFree(snap), Reserved: w.cfg.Reserves.MemReserveBytes + otherMem, FreeFloor: w.cfg.Reserves.MemFreeFloor, PerReplica: p.PerReplicaMem, Current: st.Replicas},
		CPU:       Budget{HostTotal: w.cfg.HostCPUMilli, HostFree: w.cfg.HostCPUMilli, Reserved: w.cfg.Reserves.CPUReserveMilli + otherCPU, FreeFloor: w.cfg.Reserves.CPUFreeFloor, PerReplica: p.PerReplicaCPU, Current: st.Replicas},
		PolicyMax: p.Max, PerReplicaMemFloor: w.cfg.Reserves.PerReplicaMemFloor, NearOOMFreeBytes: w.cfg.Reserves.NearOOMFreeBytes,
	})

	metrics := Metrics{AllHealthy: g.allHealthy}
	if g.running > 0 {
		metrics.CPUMeanPct = g.cpuSum / float64(g.running)
	}
	metrics.MemMaxPct = g.memMaxPct
	// Custom signals (Phase 1: queue depth from the app's ops probe), each aggregated to a
	// per-replica value. Absent data (no ops interface, probe degraded, unknown selector) yields
	// Present:false, which the controller treats as HOLD — never scale up on missing data, never
	// shed capacity we can't measure.
	if len(p.Metrics) > 0 {
		app := snap.AppByProject(k.App)
		for _, spec := range p.Metrics {
			metrics.Signals = append(metrics.Signals, customSignal(app, spec, g.running))
		}
	}

	d := Decide(st, metrics, p.Policy, ceiling, now)
	switch d.Action {
	case ActNone:
		w.resolveRefused(ctx, k) // load dropped → the refusal condition is gone
		w.save(ctx, k, d.Next, now)
	case ActUp, ActDown:
		w.scaleGated(ctx, k, d, now)
	case ActRefused:
		w.emitRefused(ctx, k, nearOOM, capReason)
		w.save(ctx, k, d.Next, now)
	}
}

// scaleGated applies the §0 + semaphore gates, then scales + reconciles the pool.
func (w *Watcher) scaleGated(ctx context.Context, k Key, d Decision, now int64) {
	if !w.cfg.WritePlaneOK {
		return // §0 write-plane gate closed — try next tick
	}
	if !w.cfg.Sem.TryAcquire() {
		return // never queue a docker child — skip this tick (plan §8A)
	}
	defer w.cfg.Sem.Release()
	w.act(ctx, k, d.Target, d.Next, now, d.Reason)
}

// act performs the scale + edge-pool reconcile and persists the new desired state.
// On a scale-DOWN the edge pool is reconciled FIRST so the edge stops sending new
// connections to the replica about to be removed (best-effort drain).
func (w *Watcher) act(ctx context.Context, k Key, target int, next State, now int64, reason string) {
	next.Replicas = target
	down := target < currentDesired(w.states[k])
	if down && w.cfg.Edge != nil {
		_ = w.cfg.Edge.ReconcilePool(ctx, k.App, k.Service, target)
	}
	if err := w.cfg.Scaler.Scale(ctx, k.App, k.Service, target); err != nil {
		w.cfg.Log.Warn("scale: action failed", "app", k.App, "service", k.Service, "target", target, "err", err)
		return // don't persist a desired we couldn't apply
	}
	if !down && w.cfg.Edge != nil {
		_ = w.cfg.Edge.ReconcilePool(ctx, k.App, k.Service, target)
	}
	if !down {
		w.resolveRefused(ctx, k) // a successful scale-up clears any open refusal
	}
	w.cfg.Log.Info("scaled", "app", k.App, "service", k.Service, "replicas", target, "reason", reason)
	w.save(ctx, k, next, now)
}

func currentDesired(st State) int {
	if st.Replicas == 0 {
		return 1
	}
	return st.Replicas
}

func (w *Watcher) save(ctx context.Context, k Key, st State, now int64) {
	w.states[k] = st
	_ = w.cfg.Store.SaveState(ctx, k, st, now)
}

// emitRefused raises scale_refused_no_capacity (plan §8.4) — never a silent hold.
func (w *Watcher) emitRefused(ctx context.Context, k Key, nearOOM bool, reason string) {
	target := sanitizeName(k.App) + "/" + sanitizeName(k.Service)
	msg := "Service " + target + " wanted to scale up but the host has no capacity"
	if nearOOM {
		msg = "Service " + target + " wanted to scale up but the host is near OOM (scaling is a no-op until memory frees up)"
	}
	if reason != "" {
		msg += ": " + sanitizeName(reason)
	}
	if w.cfg.Alerts == nil {
		w.cfg.Log.Warn("scale: refused (no channels configured)", "target", target, "reason", reason)
		return
	}
	w.refused[k] = true
	_ = w.cfg.Alerts.EnqueueInfra(ctx, alert.Outbox{
		RuleID: 0, Target: target, Kind: "scale_refused_no_capacity", Level: alert.LevelWarning,
		Transition: "firing", Summary: msg, DedupeKey: "scale:" + target,
	})
}

// resolveRefused clears an open scale_refused_no_capacity alert once the service can
// scale again (capacity returned) or no longer wants to (load dropped).
func (w *Watcher) resolveRefused(ctx context.Context, k Key) {
	if !w.refused[k] {
		return
	}
	delete(w.refused, k)
	if w.cfg.Alerts == nil {
		return
	}
	target := sanitizeName(k.App) + "/" + sanitizeName(k.Service)
	_ = w.cfg.Alerts.EnqueueInfra(ctx, alert.Outbox{
		RuleID: 0, Target: target, Kind: "scale_refused_no_capacity", Level: alert.LevelWarning,
		Transition: "resolved", Summary: "Service " + target + " no longer needs more capacity (resolved).", DedupeKey: "scale:" + target,
	})
}

func hostFree(snap *monitor.Snapshot) uint64 {
	if !snap.HostOK || snap.Host.MemTotal < snap.Host.MemUsed {
		return 0
	}
	return snap.Host.MemTotal - snap.Host.MemUsed
}

func sanitizeName(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == 0 {
			return -1
		}
		return r
	}, s)
	if len(s) > 160 {
		s = s[:160]
	}
	return s
}
