// Package selfheal is the bounded self-healing supervisor (plan §8.5): it restarts
// crashed/stuck services and ESCALATES to a Mooring-originated infra alert (§8.4)
// when it gives up — designed so that on a constrained box it can only REDUCE
// pressure or hold steady, NEVER manufacture an OOM (worst case: it declines to act
// and pages you).
//
// This file is the PURE decision core: a per-(app,service) finite-state machine
// driven entirely by already-polled snapshot data. It performs no I/O — the watcher
// (watcher.go) supplies observations, applies the four safety gates, executes the
// chosen rung through the write-plane runner, and persists the result. Keeping the
// decision pure makes the safety properties exhaustively testable.
package selfheal

// Phase is the supervisor state for one (app,service). The happy path is
// HEALTHY → SUSPECT → DEGRADED → REMEDIATING → (RECOVERED → HEALTHY) and the giving-
// up path is → CIRCUIT_OPEN. WAITING_ON_EDGE / EXPECTED_DOWN are suspensions where
// the supervisor deliberately does NOT act.
type Phase string

const (
	Healthy       Phase = "HEALTHY"
	Suspect       Phase = "SUSPECT"
	Degraded      Phase = "DEGRADED"
	Remediating   Phase = "REMEDIATING"
	CircuitOpen   Phase = "CIRCUIT_OPEN"
	Recovered     Phase = "RECOVERED"
	WaitingOnEdge Phase = "WAITING_ON_EDGE"
	ExpectedDown  Phase = "EXPECTED_DOWN"
	Held          Phase = "HELD" // operator hold: deliberately stopped / auto-restart paused
)

// Rung is one step of the remediation ladder, in escalating order.
type Rung string

const (
	RungNone     Rung = ""
	RungRestart  Rung = "restart"
	RungRecreate Rung = "recreate" // --force-recreate: re-runs host-side template render + cert-sync
	RungRedeploy Rung = "redeploy" // off by default, ≥1 GB only
)

// ladderOrder is the escalation order; each rung is tried at most once per window.
var ladderOrder = []Rung{RungRestart, RungRecreate, RungRedeploy}

// Act is what the watcher should do this tick.
type Act string

const (
	ActNone      Act = "none"      // nothing to do (healthy, or suspended)
	ActRemediate Act = "remediate" // run Decision.Rung (subject to the safety gates)
	ActPage      Act = "page"      // give up: emit an infra alert (Decision.Kind)
	ActResolve   Act = "resolve"   // recovered: clear any open infra alert
)

// Observation is the per-tick view of one service, derived from the latest snapshot
// (no extra I/O). ExpectedDown / WaitingOnEdge are computed by the watcher.
type Observation struct {
	Running       bool
	Health        string // none|healthy|unhealthy|starting
	RestartCount  int
	OOMKilled     bool
	ExitCode      int
	WaitingOnEdge bool // a service still waiting on its edge-issued cert
	ExpectedDown  bool // a VALID write-plane lease is held for this app
	Held          bool // the operator has deliberately stopped/paused this service (never restart)
}

// oomKilled reports an OOM kill, counting exit-137 / at-limit kills too (plan §8.5),
// not just the OOMKilled flag.
func (o Observation) oomKilled() bool { return o.OOMKilled || o.ExitCode == 137 }

// down reports the service is not running.
func (o Observation) down() bool { return !o.Running }

// unhealthy reports the service is running but failing its healthcheck.
func (o Observation) unhealthy() bool { return o.Running && o.Health == "unhealthy" }

// healthyNow reports the service is up and not failing (a "starting" healthcheck is
// not yet healthy but is benign until the slow-start watchdog deadline).
func (o Observation) healthyNow() bool {
	return o.Running && o.Health != "unhealthy"
}

// failing reports a remediable failure signal (down or unhealthy).
func (o Observation) failing() bool { return o.down() || o.unhealthy() }

// FSM is the persisted per-(app,service) state.
type FSM struct {
	Phase           Phase
	UnhealthyStreak int   // consecutive failing ticks (anti-flap sustain)
	HealthyStreak   int   // consecutive healthy ticks (recovery stabilization)
	Attempts        int   // remediation attempts in the current window
	LastRung        Rung  // highest rung attempted this window
	BackoffUntil    int64 // unix sec; no remediation before this deadline
	WindowStart     int64 // unix sec; start of the current attempt window
	OOMStrikes      int   // consecutive OOM-classified failures
	DegradedSince   int64 // unix sec; first failing tick of the current episode
	Open            bool  // an infra alert is currently open for this service
}

// Policy holds the tunables (plan §8.5 / Tier-1 selfheal.* config).
type Policy struct {
	SustainTicks    int   // failing ticks before the first remediation (anti-flap)
	AttemptCap      int   // remediations per window before the circuit opens
	StabilizeTicks  int   // healthy ticks required to declare RECOVERED
	OOMStrikeCap    int   // OOM-classified failures before short-circuiting the ladder
	WindowSeconds   int64 // attempt-window length; attempts reset after it elapses
	BackoffBaseSecs int64 // exponential backoff base between attempts
	BackoffMaxSecs  int64 // backoff ceiling
	RedeployEnabled bool  // rung-3 redeploy (≥1 GB host AND operator opt-in)
}

// DefaultPolicy is the conservative built-in policy.
func DefaultPolicy() Policy {
	return Policy{
		SustainTicks: 2, AttemptCap: 3, StabilizeTicks: 3, OOMStrikeCap: 2,
		WindowSeconds: 1800, BackoffBaseSecs: 30, BackoffMaxSecs: 600,
		RedeployEnabled: false,
	}
}

// Decision is the pure outcome of stepping the FSM for one service.
type Decision struct {
	Next   FSM    // the FSM to persist IF the action is taken (or is a no-op/page)
	Act    Act    // what the watcher should do
	Rung   Rung   // the rung to run when Act==ActRemediate
	Kind   string // the can't-fix taxonomy kind when Act==ActPage
	Reason string // human-readable, for the event/audit
}

// nextRung returns the lowest ladder rung above lastRung that is currently
// available, or RungNone if the ladder is exhausted (which opens the circuit).
func nextRung(last Rung, p Policy) Rung {
	startIdx := 0
	if last != RungNone {
		for i, r := range ladderOrder {
			if r == last {
				startIdx = i + 1
				break
			}
		}
	}
	for _, r := range ladderOrder[startIdx:] {
		if r == RungRedeploy && !p.RedeployEnabled {
			continue // structurally unavailable on a small box / when off
		}
		return r
	}
	return RungNone
}

// backoff returns the backoff deadline for the Nth attempt (exponential, capped).
func backoff(now int64, attempt int, p Policy) int64 {
	d := p.BackoffBaseSecs
	for i := 1; i < attempt && d < p.BackoffMaxSecs; i++ {
		d *= 2
	}
	if d > p.BackoffMaxSecs {
		d = p.BackoffMaxSecs
	}
	return now + d
}

// Decide steps the FSM for one service. It is a pure function of the prior state,
// the observation, the policy, and the current time. It NEVER performs an action;
// it only decides what should happen. The watcher applies the safety gates to a
// returned ActRemediate before executing, and only then commits Decision.Next.
func Decide(prev FSM, o Observation, p Policy, now int64) Decision {
	f := prev // copy; we mutate the copy

	// Suspensions take precedence — the supervisor must not "fix" what it doesn't own.
	// An operator HOLD is the strongest: a deliberate stop / "pause auto-restart". Suspend
	// remediation entirely and reset the failure accounting so the intentional-down state is
	// never read as a crash loop. This is what lets the operator stop a bouncing service and
	// have it STAY stopped instead of being restarted until the circuit trips.
	if o.Held {
		f.Phase = Held
		f.UnhealthyStreak, f.HealthyStreak, f.DegradedSince = 0, 0, 0
		return Decision{Next: f, Act: ActNone, Reason: "operator hold (auto-restart paused)"}
	}
	if o.ExpectedDown {
		// A valid write-plane lease is held: the app is intentionally down. Reset the
		// failure accounting so a deploy doesn't look like a crash loop.
		f.Phase = ExpectedDown
		f.UnhealthyStreak, f.HealthyStreak, f.DegradedSince = 0, 0, 0
		return Decision{Next: f, Act: ActNone, Reason: "expected_down lease held"}
	}
	if o.WaitingOnEdge && !o.healthyNow() {
		// Waiting on an edge-issued cert: the startup deadline is suspended; never
		// restart. (A cert that never issues is an edge/cert alert raised elsewhere.)
		f.Phase = WaitingOnEdge
		f.UnhealthyStreak, f.HealthyStreak = 0, 0
		return Decision{Next: f, Act: ActNone, Reason: "waiting on edge-issued cert"}
	}

	// Healthy path.
	if o.healthyNow() {
		f.UnhealthyStreak = 0
		f.DegradedSince = 0
		if prev.Phase == Healthy || prev.Phase == ExpectedDown || prev.Phase == WaitingOnEdge || prev.Phase == Held {
			f.Phase = Healthy
			f.HealthyStreak = 0
			return Decision{Next: f, Act: ActNone}
		}
		// Was failing/remediating/open: require a stabilization streak before we
		// declare recovery — kills the restart→up→dies sawtooth.
		f.HealthyStreak++
		if f.HealthyStreak >= p.StabilizeTicks {
			wasOpen := f.Open
			f = FSM{Phase: Healthy} // full reset: attempts/window/backoff cleared
			if wasOpen {
				return Decision{Next: f, Act: ActResolve, Reason: "recovered and stabilized"}
			}
			return Decision{Next: f, Act: ActNone, Reason: "recovered"}
		}
		f.Phase = Recovered
		return Decision{Next: f, Act: ActNone, Reason: "stabilizing"}
	}

	// --- Failing path ---
	f.HealthyStreak = 0
	if f.DegradedSince == 0 {
		f.DegradedSince = now
	}
	f.UnhealthyStreak++

	// Roll the attempt window: a quiet window resets the attempt budget.
	if f.WindowStart == 0 || now-f.WindowStart > p.WindowSeconds {
		f.WindowStart = now
		f.Attempts = 0
		f.LastRung = RungNone
	}

	// Already given up this window — keep paging-state latched, do nothing.
	if f.Phase == CircuitOpen {
		return Decision{Next: f, Act: ActNone, Reason: "circuit open"}
	}

	// OOM short-circuit: restarting an OOM-killer on a small box is futile.
	if o.oomKilled() {
		f.OOMStrikes++
		if f.OOMStrikes >= p.OOMStrikeCap {
			f.Phase = CircuitOpen
			f.Open = true
			return Decision{Next: f, Act: ActPage, Kind: "oom_killed_repeated", Reason: "repeated OOM/at-limit kills; not restarting"}
		}
	} else {
		f.OOMStrikes = 0
	}

	// Anti-flap sustain: don't act until the failure persists.
	if f.UnhealthyStreak < p.SustainTicks {
		f.Phase = Suspect
		return Decision{Next: f, Act: ActNone, Reason: "suspect (sustain window)"}
	}

	// In backoff between attempts → hold.
	if now < f.BackoffUntil {
		f.Phase = Degraded
		return Decision{Next: f, Act: ActNone, Reason: "backoff"}
	}

	// Out of attempts this window → open the circuit and page.
	if f.Attempts >= p.AttemptCap {
		f.Phase = CircuitOpen
		f.Open = true
		return Decision{Next: f, Act: ActPage, Kind: capKind(o), Reason: "remediation cap reached"}
	}

	// Choose the next rung; if the ladder is exhausted, open the circuit.
	rung := nextRung(f.LastRung, p)
	if rung == RungNone {
		f.Phase = CircuitOpen
		f.Open = true
		return Decision{Next: f, Act: ActPage, Kind: capKind(o), Reason: "remediation ladder exhausted"}
	}

	// Propose the rung. The attempt is NOT consumed here: the watcher applies the
	// four safety gates, and only if the action actually EXECUTES does it call
	// CommitRemediation (attempt consumed, backoff armed). A gate-deferred action
	// persists this Next as-is, so a deferral never burns an attempt.
	f.Phase = Remediating
	return Decision{Next: f, Act: ActRemediate, Rung: rung, Reason: "remediating: " + string(rung)}
}

// CommitRemediation advances the FSM after a rung has actually been executed: it
// consumes an attempt, records the rung, and arms the backoff. The watcher calls
// it ONLY when the safety gates passed and the action ran.
func CommitRemediation(f FSM, rung Rung, p Policy, now int64) FSM {
	f.Attempts++
	f.LastRung = rung
	f.BackoffUntil = backoff(now, f.Attempts, p)
	return f
}

// capKind maps a capped failure to its can't-fix taxonomy kind (plan §8.4).
func capKind(o Observation) string {
	switch {
	case o.oomKilled():
		return "oom_killed_repeated"
	case o.unhealthy():
		return "unhealthy_capped"
	default:
		return "crashloop_capped"
	}
}
