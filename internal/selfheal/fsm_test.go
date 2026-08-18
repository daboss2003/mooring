package selfheal

import "testing"

func testPolicy() Policy {
	return Policy{
		SustainTicks: 2, AttemptCap: 3, StabilizeTicks: 3, OOMStrikeCap: 2,
		WindowSeconds: 1800, BackoffBaseSecs: 30, BackoffMaxSecs: 600,
		RedeployEnabled: false,
	}
}

var down = Observation{Running: false, ExitCode: 1}
var healthy = Observation{Running: true, Health: "healthy"}
var unhealthy = Observation{Running: true, Health: "unhealthy"}

// step simulates one watcher tick: Decide, and (when a remediation is proposed and
// would pass its gates) commit the attempt — i.e. the action actually executed.
func step(prev FSM, o Observation, p Policy, now int64) Decision {
	d := Decide(prev, o, p, now)
	if d.Act == ActRemediate {
		d.Next = CommitRemediation(d.Next, d.Rung, p, now)
	}
	return d
}

func TestHealthyStaysHealthyNoAction(t *testing.T) {
	d := Decide(FSM{Phase: Healthy}, healthy, testPolicy(), 0)
	if d.Act != ActNone || d.Next.Phase != Healthy {
		t.Errorf("healthy service should be a no-op, got act=%s phase=%s", d.Act, d.Next.Phase)
	}
}

func TestExpectedDownSuspends(t *testing.T) {
	// Even a down container is left alone while a write-plane lease is held.
	o := Observation{Running: false, ExpectedDown: true}
	d := Decide(FSM{Phase: Degraded, UnhealthyStreak: 5}, o, testPolicy(), 100)
	if d.Act != ActNone || d.Next.Phase != ExpectedDown {
		t.Errorf("expected_down must suspend remediation, got act=%s phase=%s", d.Act, d.Next.Phase)
	}
	if d.Next.UnhealthyStreak != 0 {
		t.Error("expected_down must reset failure accounting (a deploy isn't a crash loop)")
	}
}

func TestHeldSuspendsAndNeverRestarts(t *testing.T) {
	// A held (operator-stopped) service is left down no matter how it looks — even mid-crash-loop.
	o := Observation{Running: false, ExitCode: 1, Held: true}
	d := Decide(FSM{Phase: Remediating, UnhealthyStreak: 9, Attempts: 2}, o, testPolicy(), 100)
	if d.Act != ActNone || d.Next.Phase != Held {
		t.Errorf("operator hold must suspend remediation, got act=%s phase=%s", d.Act, d.Next.Phase)
	}
	if d.Next.UnhealthyStreak != 0 || d.Next.DegradedSince != 0 {
		t.Error("a hold must reset failure accounting (a deliberate stop isn't a crash loop)")
	}
	// Hold outranks an expected_down lease too (both set → still held, never restarted).
	d = Decide(FSM{}, Observation{Running: false, Held: true, ExpectedDown: true}, testPolicy(), 100)
	if d.Act != ActNone || d.Next.Phase != Held {
		t.Errorf("hold must take precedence, got act=%s phase=%s", d.Act, d.Next.Phase)
	}
	// Releasing the hold on a now-healthy service returns straight to HEALTHY (no stabilization lag).
	d = Decide(FSM{Phase: Held}, healthy, testPolicy(), 200)
	if d.Act != ActNone || d.Next.Phase != Healthy {
		t.Errorf("released + healthy must go to HEALTHY, got act=%s phase=%s", d.Act, d.Next.Phase)
	}
}

func TestWaitingOnEdgeNeverRestarts(t *testing.T) {
	o := Observation{Running: false, WaitingOnEdge: true}
	d := Decide(FSM{}, o, testPolicy(), 100)
	if d.Act != ActNone || d.Next.Phase != WaitingOnEdge {
		t.Errorf("waiting-on-edge must not restart, got act=%s phase=%s", d.Act, d.Next.Phase)
	}
}

func TestSustainWindowBeforeActing(t *testing.T) {
	p := testPolicy()
	// First failing tick → SUSPECT, no action (anti-flap).
	d := Decide(FSM{Phase: Healthy}, down, p, 0)
	if d.Act != ActNone || d.Next.Phase != Suspect {
		t.Fatalf("first failing tick should be SUSPECT/no-op, got act=%s phase=%s", d.Act, d.Next.Phase)
	}
	// Second failing tick (streak == SustainTicks) → REMEDIATING with restart.
	d = Decide(d.Next, down, p, 10)
	if d.Act != ActRemediate || d.Rung != RungRestart {
		t.Fatalf("sustained failure should remediate with restart, got act=%s rung=%s", d.Act, d.Rung)
	}
	// Decide must NOT consume the attempt (a deferred action mustn't burn the budget).
	if d.Next.Attempts != 0 {
		t.Errorf("Decide must not consume an attempt before the action executes, got %d", d.Next.Attempts)
	}
	// The watcher commits the attempt only after the gates pass and the rung runs.
	committed := CommitRemediation(d.Next, d.Rung, p, 10)
	if committed.Attempts != 1 || committed.BackoffUntil <= 10 || committed.LastRung != RungRestart {
		t.Errorf("CommitRemediation must consume an attempt + arm backoff, got %+v", committed)
	}
}

func TestBackoffHoldsBetweenAttempts(t *testing.T) {
	p := testPolicy()
	f := FSM{Phase: Remediating, UnhealthyStreak: 2, Attempts: 1, LastRung: RungRestart, BackoffUntil: 100, WindowStart: 1, DegradedSince: 1}
	d := Decide(f, down, p, 50) // now < BackoffUntil
	if d.Act != ActNone || d.Next.Phase != Degraded {
		t.Errorf("inside backoff should hold, got act=%s phase=%s", d.Act, d.Next.Phase)
	}
}

func TestLadderEscalatesThenCircuitOpens(t *testing.T) {
	p := testPolicy() // RedeployEnabled=false → ladder tops out at recreate
	// After restart, past backoff → recreate (and the watcher executes it).
	f := FSM{Phase: Degraded, UnhealthyStreak: 3, Attempts: 1, LastRung: RungRestart, BackoffUntil: 40, WindowStart: 1, DegradedSince: 0}
	d := step(f, down, p, 100)
	if d.Act != ActRemediate || d.Rung != RungRecreate {
		t.Fatalf("second rung should be recreate, got act=%s rung=%s", d.Act, d.Rung)
	}
	// After recreate, ladder exhausted (redeploy off) → circuit opens + page.
	d = Decide(d.Next, down, p, 1000) // past the new backoff
	if d.Act != ActPage || d.Next.Phase != CircuitOpen {
		t.Fatalf("exhausted ladder must open the circuit + page, got act=%s phase=%s", d.Act, d.Next.Phase)
	}
	if d.Kind != "crashloop_capped" {
		t.Errorf("a down service that can't be fixed should page crashloop_capped, got %q", d.Kind)
	}
}

func TestRedeployRungOnlyWhenEnabled(t *testing.T) {
	p := testPolicy()
	p.RedeployEnabled = true
	f := FSM{Phase: Degraded, UnhealthyStreak: 3, Attempts: 2, LastRung: RungRecreate, BackoffUntil: 40, WindowStart: 1}
	d := Decide(f, down, p, 100)
	if d.Act != ActRemediate || d.Rung != RungRedeploy {
		t.Fatalf("with redeploy enabled the third rung should be redeploy, got act=%s rung=%s", d.Act, d.Rung)
	}
}

func TestAttemptCapOpensCircuit(t *testing.T) {
	p := testPolicy()
	p.RedeployEnabled = true // so the cap, not ladder-exhaustion, is what trips
	f := FSM{Phase: Degraded, UnhealthyStreak: 4, Attempts: 3, LastRung: RungRedeploy, BackoffUntil: 40, WindowStart: 1}
	d := Decide(f, down, p, 100)
	if d.Act != ActPage || d.Next.Phase != CircuitOpen {
		t.Fatalf("attempt cap must open the circuit, got act=%s phase=%s", d.Act, d.Next.Phase)
	}
}

func TestOOMShortCircuitsLadder(t *testing.T) {
	p := testPolicy()
	oom := Observation{Running: false, OOMKilled: true}
	// First OOM strike: still within OOMStrikeCap(2), so it falls through to normal
	// handling (sustain). Second consecutive OOM strike → short-circuit to page.
	f := FSM{Phase: Degraded, UnhealthyStreak: 2, OOMStrikes: 1, WindowStart: 0}
	d := Decide(f, oom, p, 100)
	if d.Act != ActPage || d.Kind != "oom_killed_repeated" {
		t.Fatalf("repeated OOM must short-circuit to a page, got act=%s kind=%s", d.Act, d.Kind)
	}
	if d.Next.Phase != CircuitOpen {
		t.Errorf("repeated OOM must open the circuit (restarting an OOM-killer is futile), got %s", d.Next.Phase)
	}
}

func TestExit137CountsAsOOM(t *testing.T) {
	p := testPolicy()
	o := Observation{Running: false, ExitCode: 137}
	f := FSM{Phase: Degraded, UnhealthyStreak: 2, OOMStrikes: 1, WindowStart: 0}
	d := Decide(f, o, p, 100)
	if d.Kind != "oom_killed_repeated" {
		t.Errorf("exit-137 must be treated as an OOM kill, got kind=%q", d.Kind)
	}
}

func TestUnhealthyCappedKind(t *testing.T) {
	p := testPolicy()
	p.RedeployEnabled = true
	f := FSM{Phase: Degraded, UnhealthyStreak: 4, Attempts: 3, LastRung: RungRedeploy, BackoffUntil: 40, WindowStart: 1}
	d := Decide(f, unhealthy, p, 100)
	if d.Kind != "unhealthy_capped" {
		t.Errorf("a running-but-unhealthy capped failure should page unhealthy_capped, got %q", d.Kind)
	}
}

func TestRecoveryRequiresStabilization(t *testing.T) {
	p := testPolicy() // StabilizeTicks=3
	f := FSM{Phase: Remediating, Attempts: 2, LastRung: RungRecreate, Open: true, BackoffUntil: 5}
	// Healthy ticks must accrue a streak before RECOVERED — no premature reset.
	d := Decide(f, healthy, p, 100)
	if d.Act != ActNone || d.Next.Phase != Recovered || d.Next.Attempts != 2 {
		t.Fatalf("one healthy tick must not reset the budget, got act=%s phase=%s attempts=%d", d.Act, d.Next.Phase, d.Next.Attempts)
	}
	d = Decide(d.Next, healthy, p, 110)
	d = Decide(d.Next, healthy, p, 120) // 3rd healthy tick → recovered
	if d.Act != ActResolve || d.Next.Phase != Healthy {
		t.Fatalf("after the stabilization streak the service should recover + resolve, got act=%s phase=%s", d.Act, d.Next.Phase)
	}
	if d.Next.Attempts != 0 || d.Next.Open {
		t.Error("recovery must reset attempts and clear the open alert")
	}
}

func TestSawtoothDoesNotResetBudget(t *testing.T) {
	p := testPolicy()
	f := FSM{Phase: Remediating, Attempts: 2, LastRung: RungRecreate, BackoffUntil: 5, WindowStart: 1}
	// One healthy tick (stabilizing)...
	d := Decide(f, healthy, p, 100)
	if d.Next.Attempts != 2 {
		t.Fatalf("a single healthy tick must preserve the attempt budget, got %d", d.Next.Attempts)
	}
	// ...then it dies again before stabilizing: the budget is intact, so it can cap.
	d = Decide(d.Next, down, p, 110)
	if d.Next.Attempts < 2 {
		t.Errorf("a sawtooth recovery must not refill the attempt budget, got %d", d.Next.Attempts)
	}
}

func TestCircuitOpenLatches(t *testing.T) {
	p := testPolicy()
	f := FSM{Phase: CircuitOpen, Open: true, Attempts: 3, WindowStart: 0}
	d := Decide(f, down, p, 100)
	if d.Act != ActNone || d.Next.Phase != CircuitOpen {
		t.Errorf("an open circuit must latch (stop acting), got act=%s phase=%s", d.Act, d.Next.Phase)
	}
}

// The headline property at the FSM layer: a CIRCUIT_OPEN service never proposes a
// remediation — it can only page or (on recovery) resolve.
func TestCircuitOpenNeverRemediates(t *testing.T) {
	p := testPolicy()
	for _, o := range []Observation{down, unhealthy, {Running: false, OOMKilled: true}} {
		d := Decide(FSM{Phase: CircuitOpen, Open: true, Attempts: 3, WindowStart: 0}, o, p, 100)
		if d.Act == ActRemediate {
			t.Errorf("CIRCUIT_OPEN must never remediate (obs=%+v)", o)
		}
	}
}
