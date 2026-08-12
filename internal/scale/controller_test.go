package scale

import "testing"

func testCtlPolicy() Policy {
	return Policy{
		Min: 1, Max: 5,
		UpCPUPct: 80, DownCPUPct: 40, // 40-pt dead band
		UpMemPct: 80, DownMemPct: 40,
		BreachForSecs: 60, CooldownUpSecs: 60, CooldownDownSecs: 300,
	}
}

func TestPolicyValidation(t *testing.T) {
	if ok, _ := testCtlPolicy().Valid(); !ok {
		t.Fatal("the baseline policy should be valid")
	}
	bad := testCtlPolicy()
	bad.DownCPUPct = 70 // dead band only 10
	if ok, _ := bad.Valid(); ok {
		t.Error("a <20-pt dead band must be rejected")
	}
	bad = testCtlPolicy()
	bad.CooldownDownSecs = 10 // less than up cooldown
	if ok, _ := bad.Valid(); ok {
		t.Error("down cooldown < up cooldown (not down-lazy) must be rejected")
	}
	// Out-of-range thresholds (negative / >100 / inverted) must be rejected.
	for _, mut := range []func(p *Policy){
		func(p *Policy) { p.DownCPUPct = -5 },
		func(p *Policy) { p.UpCPUPct = 150 },
		func(p *Policy) { p.UpMemPct = 30; p.DownMemPct = 60 }, // inverted
	} {
		p := testCtlPolicy()
		mut(&p)
		if ok, _ := p.Valid(); ok {
			t.Error("an out-of-range / inverted threshold policy must be rejected")
		}
	}
}

var hot = Metrics{CPUMeanPct: 90, MemMaxPct: 50, AllHealthy: true}
var cold = Metrics{CPUMeanPct: 10, MemMaxPct: 10, AllHealthy: true}
var warm = Metrics{CPUMeanPct: 60, MemMaxPct: 50, AllHealthy: true} // in the dead band

func TestScaleUpRequiresSustainedBreach(t *testing.T) {
	p := testCtlPolicy()
	st := State{Replicas: 1}
	// First hot tick starts the breach timer but does NOT act. (now is real unix time,
	// never 0 — 0 is the "not breaching" sentinel.)
	d := Decide(st, hot, p, 5, 1000)
	if d.Action != ActNone || d.Next.BreachSince == 0 {
		t.Fatalf("first breach tick should start the timer, not act; got %s breachSince=%d", d.Action, d.Next.BreachSince)
	}
	// Before breach_for elapses → still no action.
	d = Decide(d.Next, hot, p, 5, 1030)
	if d.Action != ActNone {
		t.Fatalf("breach not yet sustained should hold, got %s", d.Action)
	}
	// After breach_for → scale up one step.
	d = Decide(d.Next, hot, p, 5, 1070)
	if d.Action != ActUp || d.Target != 2 {
		t.Fatalf("sustained breach should scale up to 2, got %s target=%d", d.Action, d.Target)
	}
}

func TestDeadBandHoldsSteady(t *testing.T) {
	// In the dead band (between down and up thresholds): neither up nor down.
	d := Decide(State{Replicas: 2}, warm, testCtlPolicy(), 5, 1000)
	if d.Action != ActNone {
		t.Errorf("a signal in the dead band must hold steady, got %s", d.Action)
	}
}

func TestDownLazyAndStepOne(t *testing.T) {
	p := testCtlPolicy()
	st := State{Replicas: 4, LastChange: 0}
	// Within the down cooldown → hold.
	if d := Decide(st, cold, p, 5, 100); d.Action != ActNone {
		t.Fatalf("within down cooldown should hold, got %s", d.Action)
	}
	// Past the (long) down cooldown → shed exactly one.
	d := Decide(st, cold, p, 5, 400)
	if d.Action != ActDown || d.Target != 3 {
		t.Fatalf("down should step by exactly 1 (4→3), got %s target=%d", d.Action, d.Target)
	}
}

func TestDownRequiresAllHealthy(t *testing.T) {
	p := testCtlPolicy()
	m := cold
	m.AllHealthy = false
	if d := Decide(State{Replicas: 3, LastChange: 0}, m, p, 5, 400); d.Action == ActDown {
		t.Error("must not scale down while a replica is unhealthy")
	}
}

func TestScaleUpRefusedAtCapacity(t *testing.T) {
	p := testCtlPolicy()
	// Sustained breach + cooldown ok, but the capacity ceiling == current (2).
	st := State{Replicas: 2, BreachSince: 1, LastChange: 0}
	d := Decide(st, hot, p, 2 /* ceiling */, 1000)
	if d.Action != ActRefused {
		t.Fatalf("a sustained scale-up blocked by capacity must REFUSE (alert), got %s", d.Action)
	}
	if d.Next.BreachSince == 0 {
		t.Error("a refusal must keep the breach timer so it re-fires next tick")
	}
}

func TestCapacityForcesDownWhenOverCeiling(t *testing.T) {
	p := testCtlPolicy()
	// 4 replicas but the ceiling dropped to 2 (another app grew) → shed toward 2.
	d := Decide(State{Replicas: 4}, warm, p, 2, 1000)
	if d.Action != ActDown || d.Target != 2 {
		t.Errorf("over-ceiling must force a drained scale-down to the ceiling, got %s target=%d", d.Action, d.Target)
	}
}

func TestNeverBelowMinOrAboveMax(t *testing.T) {
	p := testCtlPolicy()
	// At min, cold → no down.
	if d := Decide(State{Replicas: 1, LastChange: 0}, cold, p, 5, 9999); d.Action == ActDown {
		t.Error("must not scale below min")
	}
	// At max, hot+sustained → no up (held at max).
	st := State{Replicas: 5, BreachSince: 1, LastChange: 0}
	if d := Decide(st, hot, p, 5, 9999); d.Action == ActUp {
		t.Error("must not scale above max")
	}
}

// Custom signals extend the same engine: a signal above its up threshold drives up (OR), a
// signal at/above its down threshold blocks down (AND), and a MISSING signal blocks down but
// never drives up (hold-safe). CPU/mem cold throughout so only the custom signal is in play.
func TestCustomSignalScaling(t *testing.T) {
	p := testCtlPolicy()
	p.Signals = []SignalPolicy{{Name: "queue", Up: 100, Down: 40}} // per-replica queue depth
	base := State{Replicas: 2, BreachSince: 940, LastChange: 0}    // breach already sustained, no cooldown

	// Queue per-replica at 150 (> up 100) with cold CPU/mem → scale UP.
	m := Metrics{CPUMeanPct: 10, MemMaxPct: 10, AllHealthy: true, Signals: []Signal{{Name: "queue", Value: 150, Present: true}}}
	if d := Decide(base, m, p, 5, 1000); d.Action != ActUp {
		t.Fatalf("queue above up threshold should scale up, got %s (%s)", d.Action, d.Reason)
	}

	// Cold CPU/mem AND queue below down (30 < 40) → scale DOWN allowed.
	down := State{Replicas: 3, LastChange: 0}
	mLow := Metrics{CPUMeanPct: 10, MemMaxPct: 10, AllHealthy: true, Signals: []Signal{{Name: "queue", Value: 30, Present: true}}}
	if d := Decide(down, mLow, p, 5, 1000); d.Action != ActDown {
		t.Errorf("cold + queue below down should scale down, got %s", d.Action)
	}

	// Queue in the dead band (60, between down 40 and up 100) → HOLD (no up, and down blocked).
	mMid := Metrics{CPUMeanPct: 10, MemMaxPct: 10, AllHealthy: true, Signals: []Signal{{Name: "queue", Value: 60, Present: true}}}
	if d := Decide(down, mMid, p, 5, 1000); d.Action != ActNone {
		t.Errorf("queue in the dead band should hold, got %s", d.Action)
	}

	// MISSING signal (probe down): must NOT scale up, and must BLOCK scale-down even though
	// CPU/mem are cold — we can't confirm the queue drained, so we hold capacity.
	mMissing := Metrics{CPUMeanPct: 10, MemMaxPct: 10, AllHealthy: true, Signals: []Signal{{Name: "queue", Present: false}}}
	if d := Decide(down, mMissing, p, 5, 1000); d.Action != ActNone {
		t.Errorf("a missing custom signal must block scale-down (hold), got %s", d.Action)
	}
}

func TestCustomSignalValidation(t *testing.T) {
	p := testCtlPolicy()
	p.Signals = []SignalPolicy{{Name: "queue", Up: 100, Down: 40}}
	if ok, _ := p.Valid(); !ok {
		t.Fatal("a valid custom signal should pass")
	}
	for _, mut := range []func(p *Policy){
		func(p *Policy) { p.Signals = []SignalPolicy{{Name: "", Up: 10, Down: 1}} },          // no name
		func(p *Policy) { p.Signals = []SignalPolicy{{Name: "q", Up: 40, Down: 40}} },         // up not above down
		func(p *Policy) { p.Signals = []SignalPolicy{{Name: "q", Up: 10, Down: -1}} },         // negative
		func(p *Policy) { p.Signals = []SignalPolicy{{Name: "q", Up: 10, Down: 1}, {Name: "q", Up: 20, Down: 2}} }, // dup
	} {
		p := testCtlPolicy()
		mut(&p)
		if ok, _ := p.Valid(); ok {
			t.Error("an invalid custom signal policy must be rejected")
		}
	}
}

// Raising min for an ALREADY-RUNNING service must grow it to the new floor immediately (the bug:
// it was only applied on first sight, so a raised min was silently ignored under low load).
func TestMinFloorEnforcedEveryTick(t *testing.T) {
	p := testCtlPolicy()
	p.Min = 3 // operator just raised min from (say) 2 to 3
	// Service currently at 2, cold load (no CPU/mem breach), no cooldown blocking.
	d := Decide(State{Replicas: 2, LastChange: 0}, cold, p, 5, 10_000)
	if d.Action != ActUp || d.Target != 3 {
		t.Fatalf("raising min must grow to the floor: got %s target=%d (%s)", d.Action, d.Target, d.Reason)
	}
	// At the floor with cold load → steady (no thrash back down below min).
	if d := Decide(State{Replicas: 3, LastChange: 0}, cold, p, 5, 10_000); d.Action != ActNone {
		t.Errorf("at min with cold load should hold, got %s", d.Action)
	}
	// Min above the capacity ceiling: grow as far as capacity allows, then refuse (never silent).
	if d := Decide(State{Replicas: 2, LastChange: 0}, cold, p, 2 /*ceiling*/, 10_000); d.Action != ActUp || d.Target != 2 {
		// ceiling 2 == cur 2 → can't grow → refuse
		if d.Action != ActRefused {
			t.Errorf("min above capacity should grow-then-refuse, got %s target=%d", d.Action, d.Target)
		}
	}
}

func TestOmittedSignalIsInert(t *testing.T) {
	p := testCtlPolicy()
	p.Signals = []SignalPolicy{{Name: "edge_lat", Up: 800, Down: 300}} // mirrored from the policy…

	// …but the signal is OMITTED from m.Signals entirely (no managed edge to measure it). It must be
	// INERT: cold CPU/mem must still be allowed to scale DOWN (regression — it used to pin/ratchet).
	down := State{Replicas: 3, LastChange: 0}
	m := Metrics{CPUMeanPct: 10, MemMaxPct: 10, AllHealthy: true, Signals: nil}
	if d := Decide(down, m, p, 5, 1000); d.Action != ActDown {
		t.Errorf("an omitted (unmeasurable) signal must be inert, allowing scale-down; got %s (%s)", d.Action, d.Reason)
	}

	// And an omitted signal must never drive scale-up on its own.
	up := State{Replicas: 2, BreachSince: 940, LastChange: 0}
	if d := Decide(up, m, p, 5, 1000); d.Action == ActUp {
		t.Errorf("an omitted signal must not drive scale-up; got %s", d.Action)
	}
}
