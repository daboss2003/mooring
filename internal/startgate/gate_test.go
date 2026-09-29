package startgate

import (
	"strings"
	"testing"
	"time"
)

var t0 = time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)

func testGate() *Gate {
	cfg := DefaultConfig(4)
	return New(cfg)
}

// running builds a running, inspected container.
func running(id, svc, health string, started time.Time, cpu float64) Container {
	return Container{ID: id, App: "app", Service: svc, Running: true, Health: health, StartedAt: started,
		CPUPercent: cpu, CPUValid: true, Inspected: true}
}

func obs(at time.Time, host float64, cs ...Container) Observation {
	return Observation{At: at, HostOK: true, HostCPUPct: host, Containers: cs}
}

func TestStartingContainerHoldsUntilHealthy(t *testing.T) {
	g := testGate()
	g.Observe(obs(t0, 10, running("a", "api", "starting", t0.Add(-5*time.Second), 90)))
	if d := g.Admit(t0, AdmitOpts{}); d.OK || d.Kind != Settling || d.Blocker != "app/api" {
		t.Fatalf("a starting container must hold other starts back: %+v", d)
	}
	g.Observe(obs(t0.Add(10*time.Second), 10, running("a", "api", "healthy", t0.Add(-5*time.Second), 90)))
	if d := g.Admit(t0.Add(10*time.Second), AdmitOpts{}); !d.OK {
		t.Fatalf("a healthy container holds nothing back: %+v", d)
	}
}

func TestNoHealthcheckSettlesOnGraceThenCPU(t *testing.T) {
	g := testGate()
	start := t0
	g.Observe(obs(t0.Add(5*time.Second), 10, running("w", "worker", "none", start, 5)))
	if d := g.Admit(t0.Add(5*time.Second), AdmitOpts{}); d.OK {
		t.Fatal("inside the settle grace a container without a healthcheck is still starting")
	}
	g.Observe(obs(t0.Add(40*time.Second), 10, running("w", "worker", "none", start, 80)))
	if d := g.Admit(t0.Add(40*time.Second), AdmitOpts{}); d.OK {
		t.Fatal("past the grace but still burning CPU: still starting")
	}
	g.Observe(obs(t0.Add(50*time.Second), 10, running("w", "worker", "none", start, 3)))
	if d := g.Admit(t0.Add(50*time.Second), AdmitOpts{}); !d.OK {
		t.Fatalf("CPU dropped: settled: %+v", d)
	}
	// Once settled, later load is not start-up: it never holds starts back again.
	g.Observe(obs(t0.Add(60*time.Second), 10, running("w", "worker", "none", start, 95)))
	if d := g.Admit(t0.Add(60*time.Second), AdmitOpts{}); !d.OK {
		t.Fatalf("a settled container's later CPU must not count as starting: %+v", d)
	}
}

func TestFirstCPUSampleIsNotEvidence(t *testing.T) {
	g := testGate()
	c := running("w", "worker", "none", t0.Add(-time.Minute), 0)
	c.CPUValid = false // first poll: the monitor has no CPU delta yet
	g.Observe(obs(t0, 10, c))
	if d := g.Admit(t0, AdmitOpts{}); d.OK {
		t.Fatal("no CPU sample yet: can't tell the start-up burst is over")
	}
}

func TestStartingNeverHoldsLongerThanMaxSettle(t *testing.T) {
	g := testGate()
	start := t0
	for i := 0; i <= 8; i++ {
		at := t0.Add(time.Duration(i) * 30 * time.Second)
		g.Observe(obs(at, 10, running("a", "api", "starting", start, 90)))
	}
	at := t0.Add(4 * time.Minute)
	if d := g.Admit(at, AdmitOpts{}); !d.OK {
		t.Fatalf("a container stuck in starting past max_settle must stop holding starts back: %+v", d)
	}
	// And it stays released: it must not re-arm on the next poll.
	g.Observe(obs(at.Add(10*time.Second), 10, running("a", "api", "starting", start, 90)))
	if d := g.Admit(at.Add(10*time.Second), AdmitOpts{}); !d.OK {
		t.Fatalf("released container re-armed: %+v", d)
	}
}

func TestAgeCountsWithoutNewObservations(t *testing.T) {
	g := testGate()
	g.Observe(obs(t0, 10, running("a", "api", "starting", t0, 90)))
	// The monitor stopped: the blocker still ages out on the wall clock.
	if d := g.Admit(t0.Add(4*time.Minute), AdmitOpts{}); !d.OK {
		t.Fatalf("a frozen observation must not hold starts back forever: %+v", d)
	}
}

func TestRestartedContainerSettlesAgain(t *testing.T) {
	g := testGate()
	g.Observe(obs(t0, 10, running("a", "api", "healthy", t0.Add(-time.Hour), 5)))
	// `docker restart` keeps the id and resets StartedAt.
	g.Observe(obs(t0.Add(10*time.Second), 10, running("a", "api", "starting", t0.Add(5*time.Second), 90)))
	if d := g.Admit(t0.Add(10*time.Second), AdmitOpts{}); d.OK {
		t.Fatal("a restarted container is starting again")
	}
}

func TestCrashLoopingContainerNeverHolds(t *testing.T) {
	g := testGate()
	c := running("a", "api", "starting", t0, 90)
	c.RestartCount = 3
	g.Observe(obs(t0, 10, c))
	c.RestartCount, c.StartedAt = 4, t0.Add(20*time.Second)
	g.Observe(obs(t0.Add(25*time.Second), 10, c))
	if d := g.Admit(t0.Add(25*time.Second), AdmitOpts{}); !d.OK {
		t.Fatalf("a crash-looping container (restart count rising) must never hold starts back: %+v", d)
	}
}

func TestExclusionAppliesToSettleAndCPU(t *testing.T) {
	g := testGate()
	hot := running("a", "api", "starting", t0, 380) // 3.8 cores of 4
	g.Observe(obs(t0, 95, hot))
	g.Observe(obs(t0.Add(10*time.Second), 96, hot))
	if d := g.Admit(t0.Add(10*time.Second), AdmitOpts{}); d.OK {
		t.Fatal("without exclusion the starting, CPU-heavy container blocks")
	}
	d := g.Admit(t0.Add(10*time.Second), AdmitOpts{ExcludeContainerIDs: []string{"a"}})
	if !d.OK {
		t.Fatalf("the target's own container must neither hold its restart back nor count as host CPU: %+v", d)
	}
}

func TestCPUBusyNeedsTwoSamplesAndHostOK(t *testing.T) {
	g := testGate()
	g.Observe(obs(t0, 99))
	if d := g.Admit(t0, AdmitOpts{}); !d.OK {
		t.Fatalf("one sample is not enough to call the host busy: %+v", d)
	}
	g.Observe(obs(t0.Add(10*time.Second), 97))
	if d := g.Admit(t0.Add(10*time.Second), AdmitOpts{}); d.OK || d.Kind != CPUBusy {
		t.Fatalf("host busy: %+v", d)
	}
	if d := g.Admit(t0.Add(10*time.Second), AdmitOpts{IgnoreCPU: true}); !d.OK {
		t.Fatalf("IgnoreCPU skips the CPU check: %+v", d)
	}
	g.Observe(Observation{At: t0.Add(20 * time.Second), HostOK: false})
	if d := g.Admit(t0.Add(20*time.Second), AdmitOpts{}); d.OK {
		t.Fatal("a failed host sample keeps the previous samples (it adds nothing)")
	}
}

func TestDisabledGateAdmitsEverything(t *testing.T) {
	cfg := DefaultConfig(2)
	cfg.Enabled = false
	g := New(cfg)
	g.Observe(obs(t0, 99, running("a", "api", "starting", t0, 90)))
	g.Observe(obs(t0.Add(time.Second), 99, running("a", "api", "starting", t0, 90)))
	g.Record("app", "api", t0, t0.Add(time.Second), true)
	if d := g.Admit(t0.Add(time.Second), AdmitOpts{}); !d.OK {
		t.Fatalf("disabled: %+v", d)
	}
}

func TestLedgerNeedsEvidenceFromAfterTheAction(t *testing.T) {
	g := testGate()
	start, end := t0, t0.Add(8*time.Second)
	// A snapshot whose listing began BEFORE the action returned proves nothing, even when the
	// service looks settled in it.
	g.Observe(obs(t0.Add(2*time.Second), 10, running("old", "api", "healthy", t0.Add(-time.Hour), 5)))
	g.Record("app", "api", start, end, true)
	g.Observe(obs(end, 10, running("old", "api", "healthy", t0.Add(-time.Hour), 5)))
	if d := g.Admit(end.Add(time.Second), AdmitOpts{}); d.OK || d.Kind != Settling {
		t.Fatalf("a snapshot taken no later than the action's end must not retire it: %+v", d)
	}
	// After the action: the new copy is starting — still held.
	g.Observe(obs(end.Add(5*time.Second), 10,
		running("old", "api", "healthy", t0.Add(-time.Hour), 5),
		running("new", "api", "starting", t0.Add(3*time.Second), 90)))
	if d := g.Admit(end.Add(5*time.Second), AdmitOpts{}); d.OK {
		t.Fatal("the copy the action started is still starting")
	}
	// The new copy is healthy: retired.
	g.Observe(obs(end.Add(20*time.Second), 10,
		running("old", "api", "healthy", t0.Add(-time.Hour), 5),
		running("new", "api", "healthy", t0.Add(3*time.Second), 20)))
	if d := g.Admit(end.Add(20*time.Second), AdmitOpts{}); !d.OK {
		t.Fatalf("settled: %+v", d)
	}
}

func TestLedgerHeldByUninspectedCopy(t *testing.T) {
	g := testGate()
	g.Record("app", "api", t0, t0.Add(time.Second), true)
	c := running("new", "api", "starting", t0, 90)
	c.Inspected = false
	g.Observe(obs(t0.Add(10*time.Second), 10, c))
	if d := g.Admit(t0.Add(10*time.Second), AdmitOpts{}); d.OK {
		t.Fatal("a copy the gate couldn't inspect can't prove the start settled")
	}
}

func TestLedgerFailedActionRetiresOnNextSnapshot(t *testing.T) {
	g := testGate()
	g.Record("app", "api", t0, t0.Add(time.Second), false) // the action failed; nothing started
	g.Observe(obs(t0.Add(10*time.Second), 10, running("old", "api", "healthy", t0.Add(-time.Hour), 5)))
	if d := g.Admit(t0.Add(10*time.Second), AdmitOpts{}); !d.OK {
		t.Fatalf("nothing is starting: %+v", d)
	}
}

func TestLedgerExpires(t *testing.T) {
	g := testGate()
	g.Record("app", "api", t0, t0.Add(time.Second), true)
	if d := g.Admit(t0.Add(2*time.Minute), AdmitOpts{}); d.OK {
		t.Fatal("inside the bound, an unproven start holds")
	}
	if d := g.Admit(t0.Add(4*time.Minute), AdmitOpts{}); !d.OK {
		t.Fatalf("past max_settle+30s the entry expires even without evidence: %+v", d)
	}
}

func TestProtectedAndStoppedNeverHold(t *testing.T) {
	g := testGate()
	p := running("edge", "caddy", "starting", t0, 90)
	p.Protected = true
	s := running("gone", "api", "starting", t0, 0)
	s.Running = false
	g.Observe(obs(t0, 10, p, s))
	if d := g.Admit(t0, AdmitOpts{}); !d.OK {
		t.Fatalf("protected/stopped containers hold nothing back: %+v", d)
	}
}

func TestWaitSpendsOneCPUBudgetPerAction(t *testing.T) {
	g := testGate()
	g.Observe(obs(t0, 95))
	g.Observe(obs(t0.Add(time.Second), 95))
	var w Wait
	if d := w.Admit(g, t0.Add(time.Second), AdmitOpts{}); d.OK {
		t.Fatal("busy host: deferred")
	}
	if d := w.Admit(g, t0.Add(9*time.Minute), AdmitOpts{}); d.OK {
		t.Fatal("still inside the budget")
	}
	if d := w.Admit(g, t0.Add(11*time.Minute), AdmitOpts{}); !d.OK {
		t.Fatalf("after max_wait the action stops waiting for CPU: %+v", d)
	}
	if !w.CPUWaivedAt(g, t0.Add(11*time.Minute)) {
		t.Fatal("waived")
	}
	// A second step of the same action doesn't get a fresh budget.
	if d := w.Admit(g, t0.Add(12*time.Minute), AdmitOpts{}); !d.OK {
		t.Fatalf("one budget per action: %+v", d)
	}
	// But settling still gates it.
	g.Observe(obs(t0.Add(12*time.Minute), 95, running("a", "api", "starting", t0.Add(12*time.Minute), 90)))
	if d := w.Admit(g, t0.Add(12*time.Minute), AdmitOpts{}); d.OK || !strings.Contains(d.Reason, "starting") {
		t.Fatalf("the CPU waiver doesn't skip the settle check: %+v", d)
	}
}

func TestUnsettledForTheScaler(t *testing.T) {
	g := testGate()
	c := running("a", "api", "none", t0, 90)
	g.Observe(obs(t0.Add(10*time.Second), 10, c))
	if !g.Unsettled("a", t0.Add(10*time.Second)) {
		t.Fatal("inside the grace: unsettled")
	}
	c.CPUPercent = 2
	g.Observe(obs(t0.Add(40*time.Second), 10, c))
	if g.Unsettled("a", t0.Add(40*time.Second)) {
		t.Fatal("settled")
	}
	// A crash-looper holds nothing back, but it is not settled either.
	c.RestartCount, c.StartedAt = 1, t0.Add(45*time.Second)
	g.Observe(obs(t0.Add(50*time.Second), 10, c))
	if !g.Unsettled("a", t0.Add(50*time.Second)) {
		t.Fatal("crash-looping: unsettled")
	}
	if g.Unsettled("zzz", t0) {
		t.Fatal("unknown id: false")
	}
}

func TestLedgerSuccessfulStartMustShowUp(t *testing.T) {
	g := testGate()
	g.Record("app", "api", t0, t0.Add(time.Second), true)
	// A later snapshot that doesn't list the started copy proves nothing.
	g.Observe(obs(t0.Add(10*time.Second), 10, running("old", "api", "healthy", t0.Add(-time.Hour), 5)))
	if d := g.Admit(t0.Add(10*time.Second), AdmitOpts{}); d.OK {
		t.Fatal("a successful start whose copy isn't visible yet must keep holding")
	}
	g.Observe(obs(t0.Add(20*time.Second), 10,
		running("old", "api", "healthy", t0.Add(-time.Hour), 5),
		running("new", "api", "healthy", t0.Add(500*time.Millisecond), 5)))
	if d := g.Admit(t0.Add(20*time.Second), AdmitOpts{}); !d.OK {
		t.Fatalf("its copy is up: %+v", d)
	}
}

func TestLedgerAppWideEntry(t *testing.T) {
	g := testGate()
	// A deploy started some of the app's services; unchanged ones kept running.
	g.Record("app", "", t0, t0.Add(5*time.Second), false)
	g.Observe(obs(t0.Add(10*time.Second), 10,
		running("db", "db", "healthy", t0.Add(-time.Hour), 5),
		running("api", "api", "starting", t0.Add(2*time.Second), 90)))
	if d := g.Admit(t0.Add(10*time.Second), AdmitOpts{}); d.OK || d.Blocker != "app" {
		t.Fatalf("the deploy's new api copy is starting: %+v", d)
	}
	g.Observe(obs(t0.Add(20*time.Second), 10,
		running("db", "db", "healthy", t0.Add(-time.Hour), 5),
		running("api", "api", "healthy", t0.Add(2*time.Second), 20)))
	if d := g.Admit(t0.Add(20*time.Second), AdmitOpts{}); !d.OK {
		t.Fatalf("everything the deploy started has settled: %+v", d)
	}
}

func TestIgnoreAppSkipsTheRolloutsOwnStarts(t *testing.T) {
	g := testGate()
	g.Record("app", "api", t0, t0.Add(time.Second), true)
	g.Observe(obs(t0.Add(10*time.Second), 10, running("new", "api", "starting", t0.Add(500*time.Millisecond), 90)))
	if d := g.Admit(t0.Add(10*time.Second), AdmitOpts{}); d.OK {
		t.Fatal("without IgnoreApp the app's own start holds")
	}
	if d := g.Admit(t0.Add(10*time.Second), AdmitOpts{IgnoreApp: "app"}); !d.OK {
		t.Fatalf("a rollout of app isn't held by app's own starts: %+v", d)
	}
	other := running("o1", "db", "starting", t0.Add(5*time.Second), 90)
	other.App = "other"
	g.Observe(obs(t0.Add(20*time.Second), 10, running("new", "api", "starting", t0.Add(500*time.Millisecond), 90), other))
	if d := g.Admit(t0.Add(20*time.Second), AdmitOpts{IgnoreApp: "app"}); d.OK || d.Blocker != "other/db" {
		t.Fatalf("another app's start still holds: %+v", d)
	}
}

func TestWaitStopsWaitingForOtherStartsAfterMaxWait(t *testing.T) {
	g := testGate()
	var w Wait
	// Another app's rollout keeps starting services, so there is always a start in progress.
	check := func(at time.Duration) Decision {
		g.Record("other", "", t0.Add(at-time.Second), t0.Add(at), false)
		return w.Admit(g, t0.Add(at), AdmitOpts{})
	}
	if d := check(time.Second); d.OK {
		t.Fatal("another start in progress holds the action first")
	}
	if d := check(9 * time.Minute); d.OK {
		t.Fatal("still inside max_wait")
	}
	if d := check(11 * time.Minute); !d.OK {
		t.Fatalf("after max_wait other starts no longer hold it: %+v", d)
	}
}
