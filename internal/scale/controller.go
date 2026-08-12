package scale

// The auto-scaling controller (plan §8A): one pure decision per tick over the
// poller snapshot. Hysteresis is ALL THREE of: a sustained-breach time window, a
// ≥20-point dead band between the up and down thresholds, and asymmetric cooldowns
// (up-eager, down-lazy). Down steps are always 1 and require all replicas healthy;
// up ramps one step under sustained load. The host-capacity ceiling caps every
// decision and a blocked scale-up becomes a refusal (an alert, never a silent hold).

// Action is what the watcher should do with the decision.
type Action string

const (
	ActNone    Action = "none"
	ActUp      Action = "up"
	ActDown    Action = "down"
	ActRefused Action = "refused" // wanted to scale up but the capacity ceiling blocked it
)

// Metrics is the per-service signal: per-replica CPU MEAN and mem MAX aggregated
// across the running replicas (plan §8A), plus whether every replica is healthy, plus
// any CUSTOM signals (e.g. queue depth from the ops probe) already aggregated to a
// per-replica value by the watcher.
type Metrics struct {
	CPUMeanPct float64
	MemMaxPct  float64
	AllHealthy bool
	Signals    []Signal // custom per-service signals, keyed by name
}

// Signal is one custom metric input for a tick, already aggregated by the watcher to the
// per-replica value the thresholds compare against (so a service-TOTAL like queue depth is
// divided by the running replica count → target-tracking falls out of the same threshold
// compare). Present=false means the metric was unavailable this tick (probe down / degraded);
// a missing signal must never drive a scale-up and must BLOCK scale-down (we can't confirm the
// load has dropped), so the service holds rather than shedding capacity blind.
type Signal struct {
	Name    string
	Value   float64
	Present bool
}

// SignalPolicy is one custom signal's scale rule: a per-replica up threshold (scale up when the
// per-replica value is at/above Up) and a down threshold (below which it permits scale-down).
// Up>Down is the per-signal dead band. For a target-tracking metric like queue depth, Up is the
// target queue-per-replica.
type SignalPolicy struct {
	Name string
	Up   float64
	Down float64
}

// Policy is the operator's scaling policy for one service.
type Policy struct {
	Min, Max         int
	UpCPUPct         float64
	UpMemPct         float64
	DownCPUPct       float64
	DownMemPct       float64
	BreachForSecs    int64
	CooldownUpSecs   int64
	CooldownDownSecs int64
	Signals          []SignalPolicy // custom signals (additive; CPU/mem unchanged)
}

// deadBand is the minimum gap required between an up and the matching down
// threshold (plan §8A: "≥ 20-pt dead band").
const deadBand = 20.0

// Valid checks the policy invariants config validation must enforce: a sane replica
// range, the ≥20-pt dead band on BOTH signals, and up-eager/down-lazy cooldowns.
func (p Policy) Valid() (bool, string) {
	switch {
	case p.Min < 1:
		return false, "min replicas must be >= 1"
	case p.Max < p.Min:
		return false, "max replicas must be >= min"
	case p.DownCPUPct < 0 || p.UpCPUPct > 100 || p.DownMemPct < 0 || p.UpMemPct > 100:
		return false, "thresholds must be within 0–100"
	case p.UpCPUPct <= p.DownCPUPct || p.UpMemPct <= p.DownMemPct:
		return false, "up thresholds must be above down thresholds"
	case p.UpCPUPct-p.DownCPUPct < deadBand:
		return false, "cpu up/down thresholds must differ by >= 20 points (dead band)"
	case p.UpMemPct-p.DownMemPct < deadBand:
		return false, "mem up/down thresholds must differ by >= 20 points (dead band)"
	case p.BreachForSecs <= 0:
		return false, "breach_for must be positive (anti-flap time window)"
	case p.CooldownDownSecs < p.CooldownUpSecs:
		return false, "down cooldown must be >= up cooldown (down-lazy)"
	}
	// Custom signals: a per-signal dead band (up strictly above down — a fixed 20-point gap is
	// meaningless across scales like 300ms vs 100 queued, so we require only up>down and let the
	// operator size the gap), non-negative thresholds, a name, and no duplicates.
	seen := map[string]bool{}
	for _, s := range p.Signals {
		switch {
		case s.Name == "":
			return false, "a custom scaling signal needs a name"
		case seen[s.Name]:
			return false, "duplicate custom scaling signal " + s.Name
		case s.Down < 0 || s.Up < 0:
			return false, "custom signal " + s.Name + " thresholds must be >= 0"
		case s.Up <= s.Down:
			return false, "custom signal " + s.Name + " up threshold must be above its down threshold (dead band)"
		}
		seen[s.Name] = true
	}
	return true, ""
}

// State is the persisted controller state for one service. Replicas is the DESIRED
// count the controller is driving toward (the watcher reconciles observed→desired).
type State struct {
	Replicas    int
	BreachSince int64 // unix sec; when the current up-breach started (0 = not breaching)
	LastChange  int64 // unix sec; last scale action (for the cooldowns)
}

// Decision is the pure outcome; the watcher persists Next and, on Up/Down, performs
// the scale (+ edge-pool reconcile). On Refused it raises scale_refused_no_capacity.
type Decision struct {
	Target int
	Action Action
	Reason string
	Next   State
}

// Decide steps the controller for one service. ceiling is the host-capacity guard's
// hard cap for this tick (from MaxReplicas).
func Decide(st State, m Metrics, p Policy, ceiling int, now int64) Decision {
	cur := st.Replicas
	hardMax := p.Max
	if ceiling < hardMax {
		hardMax = ceiling
	}

	// Capacity force-down: if we are above the hard ceiling (e.g. another app grew
	// and shrank our budget), shed toward it — reducing pressure is always safe. The
	// watcher drains each removed replica from the edge pool first.
	if cur > hardMax && hardMax >= p.Min {
		ns := st
		ns.Replicas = hardMax
		ns.LastChange = now
		ns.BreachSince = 0
		return Decision{Target: hardMax, Action: ActDown, Reason: "over the host-capacity ceiling", Next: ns}
	}

	// Min floor, enforced EVERY tick: a raised min (or a service otherwise below its floor) grows
	// toward min immediately — regardless of load or cooldown — but never past the capacity ceiling.
	// This is what makes "increase min" take effect for an ALREADY-RUNNING service; the first-sight
	// desired() only seeds min for a brand-new one. If capacity can't fund the min, refuse + alert
	// rather than silently ignore the operator's floor.
	if cur < p.Min {
		target := p.Min
		if target > hardMax {
			target = hardMax // capacity may not allow the full min; grow as far as it can
		}
		if target > cur {
			ns := st
			ns.Replicas = target
			ns.LastChange = now
			ns.BreachSince = 0
			return Decision{Target: target, Action: ActUp, Reason: "below min replicas", Next: ns}
		}
		return Decision{Target: cur, Action: ActRefused, Reason: "cannot reach min replicas: no host capacity", Next: st}
	}

	wantUp := m.CPUMeanPct >= p.UpCPUPct || m.MemMaxPct >= p.UpMemPct
	wantDown := m.CPUMeanPct < p.DownCPUPct && m.MemMaxPct < p.DownMemPct && m.AllHealthy

	// Custom signals extend the SAME hysteresis engine. Three states per policy signal:
	//   - NOT emitted this tick (absent from m.Signals) → the source can't measure it here at all
	//     (e.g. a source:edge metric on a host with no managed edge) → truly INERT: neither up nor
	//     down. It must NOT block scale-down, or a metric that can never apply would pin the service.
	//   - emitted but Present:false (probe down / edge blind) → BLOCKS scale-down, so we never shed
	//     capacity we currently can't measure. Never contributes to scale-up.
	//   - emitted and Present → at/above up wants up (OR); at/above down blocks down (AND).
	for _, sp := range p.Signals {
		s, ok := signalByName(m.Signals, sp.Name)
		if !ok {
			continue // not emitted this tick → inert
		}
		if s.Present && s.Value >= sp.Up {
			wantUp = true
		}
		if !s.Present || s.Value >= sp.Down {
			wantDown = false
		}
	}

	if wantUp {
		ns := st
		if ns.BreachSince == 0 {
			ns.BreachSince = now // start the sustained-breach timer
		}
		if now-ns.BreachSince < p.BreachForSecs {
			return hold(ns, "up-breach not yet sustained")
		}
		if now-st.LastChange < p.CooldownUpSecs {
			return hold(ns, "up cooldown")
		}
		if cur >= p.Max {
			return hold(ns, "at policy max")
		}
		if cur >= ceiling {
			// Sustained desire to grow, but the capacity guard blocks it: refuse and
			// alert (never a silent hold). Keep the breach timer so it re-fires.
			return Decision{Target: cur, Action: ActRefused, Reason: "scale-up refused: no host capacity", Next: ns}
		}
		ns.Replicas = cur + 1 // up-eager, one step per tick
		ns.LastChange = now
		ns.BreachSince = 0
		return Decision{Target: ns.Replicas, Action: ActUp, Reason: "sustained load", Next: ns}
	}

	// Not breaching up → reset the breach timer.
	ns := st
	ns.BreachSince = 0
	if wantDown {
		if now-st.LastChange < p.CooldownDownSecs {
			return hold(ns, "down cooldown")
		}
		if cur <= p.Min {
			return hold(ns, "at policy min")
		}
		ns.Replicas = cur - 1 // down step always 1
		ns.LastChange = now
		return Decision{Target: ns.Replicas, Action: ActDown, Reason: "load shed", Next: ns}
	}
	return hold(ns, "steady")
}

func hold(ns State, reason string) Decision {
	return Decision{Target: ns.Replicas, Action: ActNone, Reason: reason, Next: ns}
}

// signalByName finds a custom signal by name in the tick's metrics.
func signalByName(sigs []Signal, name string) (Signal, bool) {
	for _, s := range sigs {
		if s.Name == name {
			return s, true
		}
	}
	return Signal{}, false
}
