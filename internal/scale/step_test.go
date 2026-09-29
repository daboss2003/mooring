package scale

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/hostmon"
	"github.com/daboss2003/mooring/internal/monitor"
	"github.com/daboss2003/mooring/internal/startgate"
)

func minPolicy(t *testing.T, st *Store, min, max int) {
	t.Helper()
	pr := PolicyRow{
		Policy:  Policy{Min: min, Max: max, UpCPUPct: 80, DownCPUPct: 40, UpMemPct: 80, DownMemPct: 40, BreachForSecs: 60, CooldownUpSecs: 60, CooldownDownSecs: 300},
		Enabled: true, PerReplicaMem: 256 << 20, PerReplicaCPU: 100,
	}
	if err := st.SavePolicy(context.Background(), Key{App: "shop", Service: "web"}, pr); err != nil {
		t.Fatal(err)
	}
}

// copies builds a snapshot of shop/web with the given per-copy states ("healthy", "starting",
// "unhealthy", "exited", "unknown").
func copies(at time.Time, states ...string) *monitor.Snapshot {
	var svcs []monitor.ServiceStatus
	for i, st := range states {
		c := monitor.ServiceStatus{Service: "web", ContainerID: string(rune('a' + i)), State: "running", Health: st,
			CPUPercent: 3, MemBytes: 40 << 20, MemLimit: 512 << 20, Inspected: true, StartedAt: at.Add(-time.Hour), CPUValid: true}
		switch st {
		case "exited":
			c.State, c.Health = "exited", "none"
		case "unknown":
			c.Health, c.Inspected = "none", false
		}
		svcs = append(svcs, c)
	}
	return &monitor.Snapshot{At: at, DockerOK: true, HostOK: true, Host: hostmon.Sample{MemTotal: 8 * GiBw, MemUsed: 1 * GiBw},
		Apps: []monitor.App{{Project: "shop", Services: svcs}}}
}

// withCPU sets the CPU of every shop/web copy in a copies() snapshot.
func withCPU(s *monitor.Snapshot, pct float64) *monitor.Snapshot {
	for i := range s.Apps[0].Services {
		s.Apps[0].Services[i].CPUPercent = pct
	}
	return s
}

// Growing to min:3 from one copy is three separate +1 steps, each after the previous copy is up.
func TestMinFloorAddsOneCopyAtATime(t *testing.T) {
	st := testStore(t)
	minPolicy(t, st, 3, 5)
	var snap *monitor.Snapshot
	var clock int64 = 1000
	sc := &fakeScaler{}
	w := newWatcher(t, st, &snap, &clock, sc, nil)
	t0 := time.Now()

	snap = copies(t0, "healthy")
	w.Tick(context.Background())
	if sc.last() != 2 {
		t.Fatalf("first step must add one copy (target 2), got %v", sc.calls)
	}
	if got := w.states[Key{App: "shop", Service: "web"}].Replicas; got != 3 {
		t.Fatalf("desired must be recorded at the full floor (3), got %d", got)
	}
	// The new copy is still starting: nothing more is added.
	snap = copies(t0.Add(10*time.Second), "healthy", "starting")
	clock += 10
	w.Tick(context.Background())
	if sc.count() != 1 {
		t.Fatalf("no copy may be added while one is starting, got %v", sc.calls)
	}
	// It is healthy: the reconcile adds the third.
	snap = copies(t0.Add(20*time.Second), "healthy", "healthy")
	clock += 10
	w.Tick(context.Background())
	if sc.count() != 2 || sc.last() != 3 {
		t.Fatalf("then the third copy, got %v", sc.calls)
	}
	snap = copies(t0.Add(30*time.Second), "healthy", "healthy", "healthy")
	clock += 10
	w.Tick(context.Background())
	if sc.count() != 2 {
		t.Fatalf("at the floor: no more calls, got %v", sc.calls)
	}
}

// A nudge of +3 raises desired by three at once but starts the copies one by one.
func TestNudgeStepsOneCopyAtATime(t *testing.T) {
	st := testStore(t)
	minPolicy(t, st, 1, 5)
	var snap *monitor.Snapshot
	var clock int64 = 1000
	sc := &fakeScaler{}
	w := newWatcher(t, st, &snap, &clock, sc, nil)
	t0 := time.Now()
	snap = copies(t0, "healthy")
	w.Nudge("shop", "web", 1)
	w.Nudge("shop", "web", 1)
	w.Nudge("shop", "web", 1)
	w.Tick(context.Background())
	if sc.count() != 1 || sc.last() != 2 {
		t.Fatalf("one copy per step, got %v", sc.calls)
	}
	if got := w.states[Key{App: "shop", Service: "web"}].Replicas; got != 4 {
		t.Fatalf("desired must be 4, got %d", got)
	}
	for i, states := range [][]string{{"healthy", "healthy"}, {"healthy", "healthy", "healthy"}} {
		snap = copies(t0.Add(time.Duration(i+1)*10*time.Second), states...)
		clock += 10
		w.Tick(context.Background())
	}
	if sc.count() != 3 || sc.calls[1] != 3 || sc.calls[2] != 4 {
		t.Fatalf("want steps 2,3,4, got %v", sc.calls)
	}
}

// No copy is added while another copy is down, unhealthy, starting or of unknown state — the scaler
// never starts an exited copy (self-heal restarts it, paced) and never piles on a sick service.
func TestAddingACopyWaitsForEveryCopy(t *testing.T) {
	for _, blocker := range []string{"exited", "unhealthy", "starting", "unknown"} {
		st := testStore(t)
		minPolicy(t, st, 1, 5)
		var snap *monitor.Snapshot
		var clock int64 = 1000
		sc := &fakeScaler{}
		w := newWatcher(t, st, &snap, &clock, sc, nil)
		w.states[Key{App: "shop", Service: "web"}] = State{Replicas: 3}
		snap = copies(time.Now(), "healthy", blocker)
		w.Tick(context.Background())
		for _, c := range sc.calls {
			if c > 2 {
				t.Fatalf("%s copy: no copy may be added, got %v", blocker, sc.calls)
			}
		}
	}
}

// Self-heal working on the service holds the scaler's additions.
func TestAddingACopyWaitsForSelfHeal(t *testing.T) {
	st := testStore(t)
	minPolicy(t, st, 2, 5)
	var snap *monitor.Snapshot
	var clock int64 = 1000
	sc := &fakeScaler{}
	w := newWatcher(t, st, &snap, &clock, sc, nil)
	w.cfg.SelfHealBusy = func() map[Key]bool { return map[Key]bool{{App: "shop", Service: "web"}: true} }
	w.states[Key{App: "shop", Service: "web"}] = State{Replicas: 2}
	snap = copies(time.Now(), "healthy")
	w.Tick(context.Background())
	if sc.count() != 0 {
		t.Fatalf("self-heal busy: no copy added, got %v", sc.calls)
	}
}

// With the start gate, a step is recorded; the next step waits until the new copy has settled even
// when the snapshot doesn't show it yet, and a new snapshot is required for every step.
func TestStepsArePacedByTheStartGate(t *testing.T) {
	st := testStore(t)
	minPolicy(t, st, 3, 5)
	var snap *monitor.Snapshot
	var clock int64 = 1000
	sc := &fakeScaler{}
	w := newWatcher(t, st, &snap, &clock, sc, nil)
	gate := startgate.New(startgate.DefaultConfig(4))
	w.cfg.Gate = gate
	w.cfg.Observe = func(s *monitor.Snapshot) {
		var cs []startgate.Container
		for _, c := range s.Apps[0].Services {
			cs = append(cs, startgate.Container{ID: c.ContainerID, App: "shop", Service: "web", Running: c.Running(), Health: c.Health,
				StartedAt: c.StartedAt, CPUPercent: c.CPUPercent, CPUValid: c.CPUValid, Inspected: c.Inspected})
		}
		gate.Observe(startgate.Observation{At: s.At, Containers: cs})
	}
	t0 := time.Now()
	snap = copies(t0, "healthy")
	w.Tick(context.Background())
	if sc.count() != 1 {
		t.Fatalf("first step, got %v", sc.calls)
	}
	// Same snapshot again: skipped. A new one that doesn't list the new copy yet: the gate's record
	// of the successful step still holds the next one back; so does the new copy while it starts.
	w.Tick(context.Background())
	snap = copies(time.Now(), "healthy")
	clock += 10
	w.Tick(context.Background())
	newCopyStarted := time.Now() // the step's copy started after the step began
	snap = copies(time.Now(), "healthy", "starting")
	snap.Apps[0].Services[1].StartedAt = newCopyStarted
	clock += 10
	w.Tick(context.Background())
	if sc.count() != 1 {
		t.Fatalf("the recorded step must hold the next one until its copy settles, got %v", sc.calls)
	}
	// The new copy shows up healthy in a later snapshot: the next step runs.
	time.Sleep(10 * time.Millisecond)
	snap = copies(time.Now(), "healthy", "healthy")
	snap.Apps[0].Services[1].StartedAt = newCopyStarted
	clock += 10
	w.Tick(context.Background())
	if sc.count() != 2 || sc.last() != 3 {
		t.Fatalf("once settled the next step runs, got %v", sc.calls)
	}
}

// observeInto feeds every container of a snapshot, and the host CPU, into gate.
func observeInto(gate *startgate.Gate) func(*monitor.Snapshot) {
	return func(s *monitor.Snapshot) {
		o := startgate.Observation{At: s.At, HostOK: s.HostOK, HostCPUPct: s.Host.CPUPercent}
		for _, a := range s.Apps {
			for _, c := range a.Services {
				o.Containers = append(o.Containers, startgate.Container{ID: c.ContainerID, App: a.Project, Service: c.Service, Running: c.Running(),
					Health: c.Health, StartedAt: c.StartedAt, CPUPercent: c.CPUPercent, CPUValid: c.CPUValid, Inspected: c.Inspected})
			}
		}
		gate.Observe(o)
	}
}

// A service whose containers are all gone is restored one copy at a time, with its desired count
// kept (no copy running is no load measured, not an idle service). The first copy doesn't wait for
// host CPU, but it does wait for another start on the host to settle.
func TestRestoresAServiceWithNoContainers(t *testing.T) {
	k := Key{App: "shop", Service: "web"}
	t0 := time.Now()
	// noWeb lists shop with its db but without any web container, on a host whose CPU is busy.
	noWeb := func(at time.Time, others ...monitor.App) *monitor.Snapshot {
		s := copies(at)
		s.Apps[0].Services = []monitor.ServiceStatus{{Service: "db", ContainerID: "db1", State: "running", Health: "healthy",
			Inspected: true, StartedAt: at.Add(-time.Hour), CPUValid: true}}
		s.Host.CPUPercent = 95
		s.Apps = append(s.Apps, others...)
		return s
	}
	busyGate := func(t *testing.T) *startgate.Gate {
		gate := startgate.New(startgate.DefaultConfig(4))
		gate.Observe(startgate.Observation{At: t0.Add(-20 * time.Second), HostOK: true, HostCPUPct: 95})
		gate.Observe(startgate.Observation{At: t0.Add(-10 * time.Second), HostOK: true, HostCPUPct: 95})
		if d := gate.Admit(time.Now(), startgate.AdmitOpts{}); d.Kind != startgate.CPUBusy {
			t.Fatalf("precondition: the host CPU must be busy, got %+v", d)
		}
		return gate
	}
	setup := func(t *testing.T) (*Watcher, *fakeScaler, **monitor.Snapshot, *int64) {
		st := testStore(t)
		minPolicy(t, st, 1, 5)
		snap := new(*monitor.Snapshot)
		clock := new(int64)
		*clock = 1000
		sc := &fakeScaler{}
		w := newWatcher(t, st, snap, clock, sc, nil)
		w.cfg.Restorable = func(string, string) bool { return true }
		w.states[k] = State{Replicas: 2}
		return w, sc, snap, clock
	}

	t.Run("one copy at a time", func(t *testing.T) {
		w, sc, snap, clock := setup(t)
		*snap = noWeb(t0)
		w.Tick(context.Background())
		if sc.count() != 1 || sc.last() != 1 {
			t.Fatalf("the first step must start one copy (target 1), got %v", sc.calls)
		}
		if got := w.states[k].Replicas; got != 2 {
			t.Fatalf("desired must stay 2 while the copies are restored, got %d", got)
		}
		// From here on the copy's load sits in the dead band, so only the restore moves the count.
		*snap = withCPU(copies(t0.Add(10*time.Second), "starting"), 60)
		*clock += 10
		w.Tick(context.Background())
		if sc.count() != 1 {
			t.Fatalf("no copy may be added while the first one starts, got %v", sc.calls)
		}
		*snap = withCPU(copies(t0.Add(20*time.Second), "healthy"), 60)
		*clock += 10
		w.Tick(context.Background())
		if sc.count() != 2 || sc.last() != 2 {
			t.Fatalf("then the second copy, got %v", sc.calls)
		}
	})

	t.Run("host CPU busy", func(t *testing.T) {
		w, sc, snap, _ := setup(t)
		gate := busyGate(t)
		w.cfg.Gate, w.cfg.Observe = gate, observeInto(gate)
		*snap = noWeb(t0)
		w.Tick(context.Background())
		if sc.count() != 1 || sc.last() != 1 {
			t.Fatalf("with no copy running the host CPU must not hold the first copy back, got %v", sc.calls)
		}
	})

	t.Run("another start settling", func(t *testing.T) {
		w, sc, snap, clock := setup(t)
		gate := busyGate(t)
		w.cfg.Gate, w.cfg.Observe = gate, observeInto(gate)
		api := func(health string) monitor.App {
			return monitor.App{Project: "blog", Services: []monitor.ServiceStatus{{Service: "api", ContainerID: "api1", State: "running",
				Health: health, Inspected: true, StartedAt: t0.Add(-5 * time.Second)}}}
		}
		*snap = noWeb(t0, api("starting"))
		w.Tick(context.Background())
		if sc.count() != 0 {
			t.Fatalf("another container still starting must defer the first copy, got %v", sc.calls)
		}
		*snap = noWeb(t0.Add(10*time.Second), api("healthy"))
		*clock += 10
		w.Tick(context.Background())
		if sc.count() != 1 || sc.last() != 1 {
			t.Fatalf("once it has settled the first copy starts, got %v", sc.calls)
		}
	})
}

// A manual scale-down whose scale call fails is dropped, not retried on every tick (which froze the
// service's autoscaling): the next snapshot runs the normal decision path.
func TestFailedManualScaleDownIsDropped(t *testing.T) {
	st := testStore(t)
	minPolicy(t, st, 1, 5)
	var snap *monitor.Snapshot
	var clock int64 = 1000
	sc := &fakeScaler{err: errors.New("compose failed")}
	w := newWatcher(t, st, &snap, &clock, sc, nil)
	k := Key{App: "shop", Service: "web"}
	w.states[k] = State{Replicas: 2, BreachSince: 1} // an up-breach sustained long ago, cooldown clear
	t0 := time.Now()
	snap = withCPU(copies(t0, "healthy", "healthy"), 95)
	w.Nudge("shop", "web", -1)
	w.Tick(context.Background())
	if sc.count() != 1 || sc.last() != 1 {
		t.Fatalf("the −1 must be tried once (target 1), got %v", sc.calls)
	}
	if got := w.states[k].Replicas; got != 2 {
		t.Fatalf("a failed scale-down must not lower desired, got %d", got)
	}
	snap = withCPU(copies(t0.Add(10*time.Second), "healthy", "healthy"), 95)
	clock += 10
	w.Tick(context.Background())
	if sc.count() != 1 {
		t.Fatalf("right after a failed call the service backs off, got %v", sc.calls)
	}
	snap = withCPU(copies(t0.Add(70*time.Second), "healthy", "healthy"), 95)
	clock += 60
	w.Tick(context.Background())
	if sc.count() != 2 || sc.last() != 3 {
		t.Fatalf("the failed −1 must not be retried; after the back-off the load step (target 3) runs instead, got %v", sc.calls)
	}
}

// A service with a policy but no containers is restored only when the snapshot is complete, its app
// still has containers, and the deployed definition declares it long-running and autoscaled.
func TestRestoreNeedsADeclaredServiceAndItsApp(t *testing.T) {
	k := Key{App: "shop", Service: "web"}
	withDB := func(s *monitor.Snapshot) *monitor.Snapshot {
		s.Apps[0].Services = []monitor.ServiceStatus{{Service: "db", ContainerID: "db1", State: "running", Health: "healthy", Inspected: true}}
		return s
	}
	cases := []struct {
		name       string
		restorable bool
		snap       *monitor.Snapshot
	}{
		{"stale policy (dropped or scheduled service)", false, withDB(copies(time.Now()))},
		{"app has no containers", true, func() *monitor.Snapshot { s := copies(time.Now()); s.Apps = nil; return s }()},
		{"truncated container list", true, func() *monitor.Snapshot { s := withDB(copies(time.Now())); s.Truncated = true; return s }()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := testStore(t)
			minPolicy(t, st, 1, 5)
			snap := tc.snap
			var clock int64 = 1000
			sc := &fakeScaler{}
			w := newWatcher(t, st, &snap, &clock, sc, nil)
			w.cfg.Restorable = func(string, string) bool { return tc.restorable }
			w.states[k] = State{Replicas: 2}
			w.Tick(context.Background())
			if sc.count() != 0 {
				t.Fatalf("no restore expected, got %v", sc.calls)
			}
		})
	}
}

// A scale call that keeps failing backs off (1m, then 2m, …) instead of running every tick.
func TestFailedScaleCallBacksOff(t *testing.T) {
	st := testStore(t)
	minPolicy(t, st, 2, 5)
	var snap *monitor.Snapshot
	var clock int64 = 1000
	sc := &fakeScaler{err: errors.New("compose failed")}
	w := newWatcher(t, st, &snap, &clock, sc, nil)
	w.states[Key{App: "shop", Service: "web"}] = State{Replicas: 2}
	t0 := time.Now()
	tick := func(dt int64) {
		clock += dt
		snap = copies(t0.Add(time.Duration(clock-1000)*time.Second), "healthy")
		w.Tick(context.Background())
	}
	tick(0) // reconcile 1→2 fails
	tick(10)
	tick(40)
	if sc.count() != 1 {
		t.Fatalf("inside the first back-off minute nothing runs, got %v", sc.calls)
	}
	tick(20) // t+70
	if sc.count() != 2 {
		t.Fatalf("after a minute it tries again, got %v", sc.calls)
	}
	tick(70) // t+140: inside the second (2m) back-off
	if sc.count() != 2 {
		t.Fatalf("the second back-off is two minutes, got %v", sc.calls)
	}
	sc.err = nil
	tick(60) // t+200: past it
	if sc.count() != 3 {
		t.Fatalf("after two minutes it tries again, got %v", sc.calls)
	}
	if _, backing := w.failed[Key{App: "shop", Service: "web"}]; backing {
		t.Fatal("a successful call ends the back-off")
	}
}

// A manual scale-down that can't run yet (writes paused) is kept and applied once writes resume.
func TestDeferredManualScaleDownIsKept(t *testing.T) {
	st := testStore(t)
	minPolicy(t, st, 1, 5)
	var snap *monitor.Snapshot
	var clock int64 = 1000
	sc := &fakeScaler{}
	w := newWatcher(t, st, &snap, &clock, sc, nil)
	k := Key{App: "shop", Service: "web"}
	w.states[k] = State{Replicas: 2, LastChange: 1000} // inside the down cooldown: only the nudge can shed
	paused := true
	w.cfg.Paused = func() bool { return paused }
	t0 := time.Now()
	w.Nudge("shop", "web", -1)
	for i := 0; i < 2; i++ {
		snap = copies(t0.Add(time.Duration(i)*10*time.Second), "healthy", "healthy")
		clock += 10
		w.Tick(context.Background())
	}
	if sc.count() != 0 {
		t.Fatalf("writes paused: nothing may run, got %v", sc.calls)
	}
	paused = false
	snap = copies(t0.Add(20*time.Second), "healthy", "healthy")
	clock += 10
	w.Tick(context.Background())
	if sc.count() != 1 || sc.last() != 1 {
		t.Fatalf("the kept −1 must run once writes resume, got %v", sc.calls)
	}
	if got := w.states[k].Replicas; got != 1 {
		t.Fatalf("desired must drop to 1, got %d", got)
	}
}

// A scale call gets time for the copies a scale-down stops to use their stop grace.
func TestScaleCallCoversStopGrace(t *testing.T) {
	st := testStore(t)
	minPolicy(t, st, 1, 5)
	var snap *monitor.Snapshot
	var clock int64 = 1000
	sc := &fakeScaler{}
	w := newWatcher(t, st, &snap, &clock, sc, nil)
	w.cfg.StopGrace = func(app, service string) time.Duration {
		if app == "shop" && service == "web" {
			return 10 * time.Minute
		}
		return 0
	}
	w.states[Key{App: "shop", Service: "web"}] = State{Replicas: 2}
	snap = copies(time.Now(), "healthy", "healthy")
	w.Nudge("shop", "web", -1)
	before := time.Now()
	w.Tick(context.Background())
	if sc.count() != 1 || sc.last() != 1 {
		t.Fatalf("the −1 must scale to 1, got %v", sc.calls)
	}
	if dl := sc.deadlines[0]; dl.IsZero() || dl.Sub(before) < scaleCallTimeout+10*time.Minute {
		t.Fatalf("the scale call must get %v plus the 10m stop grace, got a deadline %v away", scaleCallTimeout, dl.Sub(before))
	}
}

// A snapshot whose container list failed shows no containers although they may be running: the
// scaler takes no action on it (it would otherwise restore copies that exist).
func TestListFailedSnapshotIsSkipped(t *testing.T) {
	st := testStore(t)
	minPolicy(t, st, 1, 5)
	var snap *monitor.Snapshot
	var clock int64 = 1000
	sc := &fakeScaler{}
	w := newWatcher(t, st, &snap, &clock, sc, nil)
	k := Key{App: "shop", Service: "web"}
	w.states[k] = State{Replicas: 2}
	observed := false
	w.cfg.Observe = func(*monitor.Snapshot) { observed = true }
	snap = &monitor.Snapshot{At: time.Now(), DockerOK: true, ListFailed: true, HostOK: true,
		Host: hostmon.Sample{MemTotal: 8 * GiBw, MemUsed: 1 * GiBw}}
	w.Tick(context.Background())
	if sc.count() != 0 {
		t.Fatalf("a failed container list must not be acted on, got %v", sc.calls)
	}
	if observed {
		t.Fatal("a failed container list must not be fed to the start gate")
	}
	if got := w.states[k]; got != (State{Replicas: 2}) {
		t.Fatalf("state must be untouched, got %+v", got)
	}
}
