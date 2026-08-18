package scale

import (
	"context"
	"log/slog"
	"strings"
	"sync"
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

// Edge-metric selectors (source:edge): the two edge-measured values a policy can scale on.
const (
	selEdgeP95 = "p95_latency_ms" // service p95 request latency (ms), absolute
	selEdgeRPS = "req_per_sec"    // service request rate (req/s), tracked per replica
)

// edgeSignal reads one source:edge metric spec into a controller Signal from the edge's rolling
// latency/rate aggregator. The value is measured by Mooring's own edge (not self-reported by the
// app), so the app can't fabricate it — though, like any latency/rate signal, a client shaping
// traffic still influences it. Returns (signal, include): include=false OMITS the signal entirely
// (it neither votes up nor pins down) when there is no managed edge to measure with.
//
// The subtle case is ABSENCE of samples for this service, which must be split two ways:
//   - edge is LIVE (delivering logs for some service) but this one is silent → genuinely idle → a
//     MEASURED 0 (Present) so an idle service can scale down.
//   - edge is NOT live (enable-time lag, a broken/stalled capture) → we are BLIND → HOLD
//     (Present:false), because the low-CPU/mem I/O-bound services this feature exists for would
//     otherwise be wrongly shed on data we simply don't have (CPU/mem can't protect them — they run
//     cool by definition).
func (w *Watcher) edgeSignal(spec MetricSpec, k Key, running int) (Signal, bool) {
	if w.cfg.EdgeStats == nil || running <= 0 {
		return Signal{}, false // no managed edge (or no replicas) → OMIT: inert, never pins scaling
	}
	sig := Signal{Name: spec.Name}
	p95, rps, present := w.cfg.EdgeStats(k.App, k.Service)
	if !present {
		if w.cfg.EdgeLive == nil || !w.cfg.EdgeLive() {
			return sig, true // blind → HOLD (Present:false)
		}
		sig.Present = true // edge live, this service silent → measured 0 (permits scale-down)
		return sig, true
	}
	switch spec.Select {
	case selEdgeP95:
		sig.Value = p95 // service-level latency; absolute (adding replicas lowers it)
	case selEdgeRPS:
		sig.Value = rps / float64(running) // service-total rate → per-replica
	default:
		return Signal{}, false // unknown selector (schema rejects this) → OMIT, defense in depth
	}
	sig.Present = true
	return sig, true
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
	// EdgeStats returns the edge-measured p95 latency (ms) and request rate (req/s) for a service
	// over the rolling window, plus whether ANY request was sampled in it. It backs source:edge
	// metrics. nil = no managed edge on this host → source:edge metrics are OMITTED (inert), so they
	// neither help nor pin scaling.
	EdgeStats func(app, service string) (p95Ms, reqPerSec float64, present bool)
	// EdgeLive reports whether the edge is delivering access logs at all right now (any service).
	// It lets edgeSignal tell a genuinely-idle service (edge live, no samples → may scale down) from
	// a blind window (enable-time lag / broken capture → HOLD, never shed on data we don't have).
	// Wired together with EdgeStats (both set, or both nil).
	EdgeLive func() bool
	// Held returns the set of operator-HELD services (a manual stop / "pause auto-restart"). A held
	// service is skipped entirely each tick — never reconciled, scaled, or reserved-for — so a
	// service the operator deliberately stopped is not relaunched by the scaler. Read once per tick.
	// nil → nothing held.
	Held func() map[Key]bool
	// CircuitOpen returns services whose self-heal circuit is OPEN (self-heal gave up on a crash loop
	// and is paging instead of restarting). The scaler must NOT relaunch them — reconciling a crashed
	// replica back up would re-arm exactly the loop the breaker exists to stop. Read once per tick.
	CircuitOpen func() map[Key]bool
	// BusyApps returns apps holding a self-heal expected_down lease (an operator lifecycle/deploy
	// action is in flight). The scaler skips their services meanwhile — it must not fight the write
	// plane, and this also closes the brief window during an operator STOP before its hold row lands
	// (self-heal holds the lease until after the hold is written). Read once per tick.
	BusyApps func() map[string]bool
	Now      func() int64
}

// Watcher is the auto-scaling controller loop (plan §8A).
type Watcher struct {
	cfg     Config
	states  map[Key]State
	refused map[Key]bool // services with an open scale_refused_no_capacity alert

	mu           sync.Mutex  // guards pendingNudge only (drained at tick start; never held during tick I/O)
	pendingNudge map[Key]int // operator manual ±replica requests, applied at the next tick
	nudges       map[Key]int // this tick's drained nudges (tick goroutine only)
}

// Nudge requests a manual one-step change (+1 / −1) to a service's desired replica count. It only
// RECORDS the request under a short lock; the controller applies it at the start of the next tick,
// so it uses fresh capacity data and never races the state map. A nudged service stays under normal
// autoscaling afterward: it scales back down under sustained no-load (after the down-cooldown) and
// up under load — the manual step is a boost the controller still manages, not a pin. Repeated
// clicks before the next tick accumulate. A held or non-scalable service's nudge is a harmless no-op
// (the tick simply never applies it).
func (w *Watcher) Nudge(app, service string, delta int) {
	if delta == 0 {
		return
	}
	w.mu.Lock()
	if w.pendingNudge == nil {
		w.pendingNudge = map[Key]int{}
	}
	w.pendingNudge[Key{App: app, Service: service}] += delta
	w.mu.Unlock()
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
	// A service is SKIPPED entirely this tick — not reconciled, scaled, or reserved-for — when the
	// operator held it, when self-heal gave up on it (circuit open), or while a lifecycle/deploy
	// action is in flight for its app (expected_down lease). In every case something else owns the
	// service's up/down state and the scaler must defer, so it never relaunches a service that is
	// intentionally down.
	var held, circuit map[Key]bool
	var busy map[string]bool
	if w.cfg.Held != nil {
		held = w.cfg.Held()
	}
	if w.cfg.CircuitOpen != nil {
		circuit = w.cfg.CircuitOpen()
	}
	if w.cfg.BusyApps != nil {
		busy = w.cfg.BusyApps()
	}
	skip := func(k Key) bool { return held[k] || circuit[k] || busy[k.App] }

	// Drain any operator manual ±replica requests for this tick (applied per service in stepService,
	// using this tick's fresh capacity ceiling).
	w.mu.Lock()
	w.nudges = w.pendingNudge
	w.pendingNudge = map[Key]int{}
	w.mu.Unlock()

	lb := &liveBudget{}
	for k, p := range policies {
		if skip(k) {
			continue // don't reserve capacity for a service that's intentionally down
		}
		d := w.desired(k, groups[k], p)
		lb.mem += uint64(d) * p.PerReplicaMem
		lb.cpu += uint64(d) * p.PerReplicaCPU
	}

	for k, p := range policies {
		if skip(k) {
			continue // never reconcile/scale a service that is held, given-up-on, or mid-lifecycle
		}
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
	// First sight (no persisted state): seed from what's actually RUNNING, NOT clamped up to
	// the floor. Clamping to p.Min here was a bug: it made Decide see cur==min and hold, so a
	// service that a deploy launched with 1 replica but declares min:2 would sit at 1 forever
	// (nothing else reconciles running→desired). Seeding the observed count lets Decide's
	// min-floor branch see cur<min and grow it to the floor. Never seed 0 — a persisted 0 reads
	// as "no state" and would re-seed every tick.
	if g.running < 1 {
		return 1
	}
	return g.running
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

	// Manual ±replica nudge: an explicit one-step operator override, applied this tick and bounded by
	// the SAME [min, policyMax, capacity-ceiling] limits as an automatic decision (a manual boost can
	// never push the host past the capacity guard). LastChange is armed so the boost survives at least
	// one down-cooldown before autoscaling may shed it. It then rejoins normal autoscaling.
	if delta := w.nudges[k]; delta != 0 {
		delete(w.nudges, k)
		target := st.Replicas + delta
		if target < p.Min {
			target = p.Min
		}
		if p.Max > 0 && target > p.Max {
			target = p.Max
		}
		if target > ceiling {
			target = ceiling
		}
		if target < 1 {
			target = 1
		}
		next := st
		next.Replicas = target
		next.LastChange = now
		if g.running != target {
			w.scaleGated(ctx, k, Decision{Target: target, Next: next, Reason: "manual scale"}, now)
		} else {
			w.save(ctx, k, next, now)
		}
		return
	}

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
			switch spec.Source {
			case "edge":
				if sig, ok := w.edgeSignal(spec, k, g.running); ok {
					metrics.Signals = append(metrics.Signals, sig)
				}
			default:
				metrics.Signals = append(metrics.Signals, customSignal(app, spec, g.running))
			}
		}
	}

	d := Decide(st, metrics, p.Policy, ceiling, now)
	switch d.Action {
	case ActNone:
		w.resolveRefused(ctx, k) // load dropped → the refusal condition is gone
		// Reconcile observed→desired. The controller only issues Scale on a Decide state
		// transition, so a service whose RUNNING count is below its DESIRED — a deploy that
		// launched fewer replicas than the floor, or a replica that died with no load change —
		// would otherwise sit under-provisioned forever (this is the "desired 2 but only 1
		// running" symptom). If we are steady but short of desired and capacity allows, re-assert
		// desired. (A future manual "hold" on a service must also gate this, so a deliberately
		// stopped replica is not relaunched.)
		if g.running < d.Next.Replicas && d.Next.Replicas <= ceiling {
			w.scaleGated(ctx, k, Decision{Target: d.Next.Replicas, Next: d.Next, Reason: "reconcile running→desired"}, now)
			return
		}
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
		// The refusal is a HOST-CAPACITY decision — "no alert channels" only means we can't notify
		// beyond this log. Say so plainly (the old "refused (no channels configured)" read as if the
		// missing channel caused the refusal).
		w.cfg.Log.Warn("scale: up refused — the host has no capacity for another replica (add an alert channel to be notified of this)",
			"target", target, "reason", reason, "near_oom", nearOOM)
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
