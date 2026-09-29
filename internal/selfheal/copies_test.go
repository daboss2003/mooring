package selfheal

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/hostmon"
	"github.com/daboss2003/mooring/internal/monitor"
	"github.com/daboss2003/mooring/internal/startgate"
)

// multiSnap builds a one-app snapshot from the given containers.
func multiSnap(svcs ...monitor.ServiceStatus) *monitor.Snapshot {
	return &monitor.Snapshot{
		DockerOK: true, HostOK: true,
		Host: hostmon.Sample{MemTotal: 2 << 30, MemUsed: 1 << 30},
		Apps: []monitor.App{{Project: "shop", Services: svcs}},
	}
}

func copyOf(svc, id, state, health string) monitor.ServiceStatus {
	c := monitor.ServiceStatus{Service: svc, ContainerID: id, State: state, Health: health, Inspected: true}
	if state != "running" {
		c.ExitCode = 1
	}
	return c
}

// setCopy replaces the container with id in the snapshot (or drops it when repl is nil).
func setCopy(snap *monitor.Snapshot, id string, repl *monitor.ServiceStatus) {
	svcs := snap.Apps[0].Services[:0:0]
	for _, c := range snap.Apps[0].Services {
		switch {
		case c.ContainerID != id:
			svcs = append(svcs, c)
		case repl != nil:
			svcs = append(svcs, *repl)
		}
	}
	snap.Apps[0].Services = svcs
}

// A reboot left three copies exited: they are restarted one per action, each counting as progress,
// and the circuit never opens.
func TestWatcherRestartsExitedCopiesOneAtATime(t *testing.T) {
	var clock int64
	snap := multiSnap(copyOf("web", "c1", "exited", "none"), copyOf("web", "c2", "exited", "none"), copyOf("web", "c3", "exited", "none"))
	act := &fakeActioner{}
	act.after = func(_ string, rung Rung, tg Target) {
		if rung == RungRestart && tg.CopyID != "" {
			up := copyOf("web", tg.CopyID, "running", "healthy")
			setCopy(snap, tg.CopyID, &up)
		}
	}
	w := newTestWatcher(t, &snap, &clock, act)
	for i := 0; i < 12; i++ {
		clock = int64(i)*100 + 1000
		w.Tick(context.Background())
	}
	if len(act.targets) != 3 || act.targets[0].CopyID != "c1" || act.targets[1].CopyID != "c2" || act.targets[2].CopyID != "c3" {
		t.Fatalf("want three single-copy restarts c1,c2,c3; got %v %+v", act.calls, act.targets)
	}
	for i, c := range act.calls {
		if c != "web:restart" {
			t.Fatalf("action %d = %s, want restarts only", i, c)
		}
	}
	f := w.fsms[Key{App: "shop", Service: "web"}]
	if f.Phase != Healthy || f.Attempts != 1 {
		t.Fatalf("progress restarts consume no attempt and end healthy; got %+v", f)
	}
}

// scaledWeb makes "web" an autoscaled service (a removed copy is replaced).
func scaledWeb(string) (map[string]ServiceInfo, bool) {
	return map[string]ServiceInfo{"web": {Scaled: true}}, true
}

// One copy of three keeps crashing: restart it, then replace it; when the replacement crashes too —
// even many minutes later — the circuit opens instead of looping.
func TestWatcherCrashLoopingCopyEndsInTheCircuit(t *testing.T) {
	var clock int64
	snap := multiSnap(copyOf("web", "c1", "running", "healthy"), copyOf("web", "c2", "running", "healthy"), copyOf("web", "c3", "exited", "none"))
	act := &fakeActioner{}
	act.after = func(_ string, rung Rung, tg Target) {
		switch {
		case len(tg.Remove) > 0: // the autoscaler starts a fresh copy
			fresh := copyOf("web", "c4", "running", "healthy")
			setCopy(snap, tg.Remove[0], &fresh)
		case rung == RungRestart: // it comes back… for a while
			up := copyOf("web", tg.CopyID, "running", "healthy")
			setCopy(snap, tg.CopyID, &up)
		}
	}
	w := newTestWatcher(t, &snap, &clock, act)
	w.cfg.Services = scaledWeb
	tick := func(at int64) { clock = at; w.Tick(context.Background()) }
	key := Key{App: "shop", Service: "web"}

	tick(1000)
	tick(1100) // restart c3
	for at := int64(1200); at <= 1500; at += 100 {
		tick(at) // healthy, stabilizes
	}
	crashed := copyOf("web", "c3", "exited", "none")
	setCopy(snap, "c3", &crashed) // five minutes later it crashes again
	tick(1600)
	tick(1700) // replace c3 → c4
	for at := int64(1800); at <= 2100; at += 100 {
		tick(at)
	}
	c4down := copyOf("web", "c4", "exited", "none")
	setCopy(snap, "c4", &c4down) // the replacement crashes too, still inside the window
	tick(2200)
	tick(2300)
	tick(2400)

	if len(act.calls) != 2 || act.calls[0] != "web:restart" || act.targets[0].CopyID != "c3" ||
		act.calls[1] != "web:recreate" || !slices.Equal(act.targets[1].Remove, []string{"c3"}) || act.targets[1].CopyID != "" {
		t.Fatalf("want restart c3, then remove c3; got %v %+v", act.calls, act.targets)
	}
	if f := w.fsms[key]; f.Phase != CircuitOpen || !f.Open {
		t.Fatalf("a flapping copy must end CIRCUIT_OPEN, got %+v", f)
	}
}

// Sick copies with every sibling sick too are not removed, even on an autoscaled service: each gets
// its restart, then the service is recreated whole.
func TestWatcherRecreatesWhenNoCopyIsHealthy(t *testing.T) {
	var clock int64
	snap := multiSnap(copyOf("web", "c1", "exited", "none"), copyOf("web", "c2", "exited", "none"))
	act := &fakeActioner{}
	w := newTestWatcher(t, &snap, &clock, act)
	w.cfg.Services = scaledWeb
	for i := 0; i < 6; i++ {
		clock = int64(i)*100 + 1000
		w.Tick(context.Background())
	}
	if len(act.calls) != 3 || act.targets[0].CopyID != "c1" || act.targets[1].CopyID != "c2" ||
		act.calls[2] != "web:recreate" || act.targets[2].Remove != nil || act.targets[2].CopyID != "" {
		t.Fatalf("want restarts of c1 and c2, then a whole-service recreate; got %v %+v", act.calls, act.targets)
	}
}

// The reviewer's case: an autoscaled service keeps one healthy copy while two stay exited. Each
// stopped copy gets one restart (only the first consumes an attempt, although it didn't help), then
// every copy still sick is removed so the autoscaler starts fresh ones — none is left stopped, which
// would hold the autoscaler back until the circuit opened with one copy of three.
func TestWatcherRemovesTheStoppedCopiesOfAScaledService(t *testing.T) {
	for _, tc := range []struct {
		name   string
		c3Up   bool // c3 comes back after its restart
		remove []string
	}{
		{"both stay down", false, []string{"c2", "c3"}},
		{"one comes back", true, []string{"c2"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var clock int64
			snap := multiSnap(copyOf("web", "c1", "running", "healthy"), copyOf("web", "c2", "exited", "none"), copyOf("web", "c3", "exited", "none"))
			act := &fakeActioner{}
			act.after = func(_ string, rung Rung, tg Target) {
				switch {
				case len(tg.Remove) > 0: // the autoscaler starts a fresh copy for each one removed
					for _, id := range tg.Remove {
						fresh := copyOf("web", "new-"+id, "running", "healthy")
						setCopy(snap, id, &fresh)
					}
				case rung == RungRestart && tg.CopyID == "c3" && tc.c3Up:
					up := copyOf("web", "c3", "running", "healthy")
					setCopy(snap, "c3", &up)
				}
			}
			w := newTestWatcher(t, &snap, &clock, act)
			w.cfg.Services = scaledWeb
			key := Key{App: "shop", Service: "web"}
			tick := func(at int64) { clock = at; w.Tick(context.Background()) }

			tick(1000)
			tick(1100)
			if len(act.calls) != 1 || act.targets[0].CopyID != "c2" || w.fsms[key].Attempts != 1 {
				t.Fatalf("want a restart of c2 as attempt 1; got %v %+v %+v", act.calls, act.targets, w.fsms[key])
			}
			tick(1200)
			if len(act.calls) != 2 || act.calls[1] != "web:restart" || act.targets[1].CopyID != "c3" || w.fsms[key].Attempts != 1 {
				t.Fatalf("want a free restart of c3; got %v %+v %+v", act.calls, act.targets, w.fsms[key])
			}
			tick(1300)
			if len(act.calls) != 3 || act.calls[2] != "web:recreate" || act.targets[2].CopyID != "" ||
				!slices.Equal(act.targets[2].Remove, tc.remove) || w.fsms[key].Attempts != 2 {
				t.Fatalf("want the recreate to remove %v; got %v %+v %+v", tc.remove, act.calls, act.targets, w.fsms[key])
			}
			for at := int64(1400); at <= 1800; at += 100 {
				tick(at)
			}
			if f := w.fsms[key]; f.Phase != Healthy || f.Open || len(act.calls) != 3 {
				t.Fatalf("with fresh copies it ends healthy, not in the circuit; got %+v %v", f, act.calls)
			}
		})
	}
}

// Without an autoscaling policy nothing would replace a removed copy, so the recreate rung recreates
// the whole service. That starts containers: it waits for the start gate and is recorded with it.
func TestWatcherRecreatesAnUnscaledServiceThroughTheStartGate(t *testing.T) {
	var clock int64
	snap := multiSnap(copyOf("web", "c1", "running", "healthy"), copyOf("web", "c2", "exited", "none"),
		copyOf("web", "c3", "exited", "none"), copyOf("db", "d1", "running", "healthy"))
	gate := startgate.New(startgate.DefaultConfig(2))
	longAgo := time.Now().Add(-time.Hour)
	startedAt := map[string]time.Time{} // runs started during the test; everything else started longAgo
	act := &fakeActioner{}
	act.after = func(_ string, _ Rung, tg Target) {
		if tg.CopyID != "" {
			startedAt[tg.CopyID] = time.Now() // restarted, and exits again at once
		}
	}
	w := newTestWatcher(t, &snap, &clock, act)
	w.cfg.Gate = gate
	w.cfg.Observe = func(s *monitor.Snapshot) {
		var cs []startgate.Container
		for _, c := range s.Apps[0].Services {
			at, ok := startedAt[c.ContainerID]
			if !ok {
				at = longAgo
			}
			cs = append(cs, startgate.Container{ID: c.ContainerID, App: "shop", Service: c.Service, Running: c.Running(),
				Health: c.Health, StartedAt: at, CPUValid: true, Inspected: true})
		}
		gate.Observe(startgate.Observation{At: s.At, Containers: cs})
	}
	key := Key{App: "shop", Service: "web"}
	tick := func(at int64) { clock = at; snap.At = time.Now(); w.Tick(context.Background()) }

	tick(1000)
	tick(1100)
	tick(1200)
	if len(act.calls) != 2 || act.targets[0].CopyID != "c2" || act.targets[1].CopyID != "c3" {
		t.Fatalf("want restarts of c2 then c3; got %v %+v", act.calls, act.targets)
	}
	// db restarted and is still starting when the recreate is due: the recreate waits, without an attempt.
	startedAt["d1"] = time.Now()
	starting := copyOf("db", "d1", "running", "starting")
	setCopy(snap, "d1", &starting)
	tick(1300)
	tick(1400)
	if len(act.calls) != 2 || w.fsms[key].Attempts != 1 {
		t.Fatalf("a starting container must defer the recreate without an attempt: %v %+v", act.calls, w.fsms[key])
	}
	healthy := copyOf("db", "d1", "running", "healthy")
	setCopy(snap, "d1", &healthy)
	tick(1500)
	if len(act.calls) != 3 || act.calls[2] != "web:recreate" || act.targets[2].CopyID != "" || act.targets[2].Remove != nil {
		t.Fatalf("once db settled, want a whole-service recreate; got %v %+v", act.calls, act.targets)
	}
	if d := gate.Admit(time.Now(), startgate.AdmitOpts{}); d.OK {
		t.Fatal("the recreate must be recorded with the gate so the next start waits for it")
	}
}

// The API fails because its database is down: the database is restarted, the API waits.
func TestWatcherWaitsOnAFailingDependency(t *testing.T) {
	var clock int64
	snap := multiSnap(copyOf("api", "a1", "running", "unhealthy"), copyOf("db", "d1", "exited", "none"))
	act := &fakeActioner{}
	w := newTestWatcher(t, &snap, &clock, act)
	w.cfg.Services = func(string) (map[string]ServiceInfo, bool) {
		return map[string]ServiceInfo{"api": {DependsOn: []string{"db"}}, "db": {}}, true
	}
	for i := 0; i < 4; i++ {
		clock = int64(i)*100 + 1000
		w.Tick(context.Background())
	}
	for _, c := range act.calls {
		if c != "db:restart" && c != "db:recreate" {
			t.Fatalf("only the dependency may be remediated; got %v", act.calls)
		}
	}
	if len(act.calls) == 0 {
		t.Fatal("the failing dependency must be remediated")
	}
	if p := w.fsms[Key{App: "shop", Service: "api"}].Phase; p != WaitingOnDependency {
		t.Fatalf("the dependent must wait on its dependency, got %s", p)
	}
}

// The wait is bounded: after DependencyWaitSecs it is paged and the dependent is remediated again.
func TestDependencyWaitIsBounded(t *testing.T) {
	p := testPolicy()
	o := Observation{Running: true, Health: "unhealthy", Replicas: 1, Sick: 1, SickIDs: []string{"a1"}, WaitingOnDependency: true, Dependency: "db"}
	d := Decide(FSM{Phase: Healthy}, o, p, 1000)
	if d.Next.Phase != WaitingOnDependency || d.Act != ActNone {
		t.Fatalf("waits first: %+v", d)
	}
	d = Decide(d.Next, o, p, 1000+DependencyWaitSecs)
	if d.Act != ActPage || d.Kind != "dependency_wait" || !d.Next.DepPaged {
		t.Fatalf("after the bound it pages: %+v", d)
	}
	d = Decide(d.Next, o, p, 1000+DependencyWaitSecs+10)
	d = Decide(d.Next, o, p, 1000+DependencyWaitSecs+20)
	if d.Act != ActRemediate || d.Rung != RungRestart || d.Target != "a1" {
		t.Fatalf("then it goes back to its ladder: %+v", d)
	}
}

// An open circuit stays open while the service is waiting on a dependency (or the edge).
func TestCircuitLatchSurvivesSuspensions(t *testing.T) {
	p := testPolicy()
	for _, o := range []Observation{
		{Running: false, WaitingOnDependency: true, Dependency: "db"},
		{Running: false, WaitingOnEdge: true},
	} {
		d := Decide(FSM{Phase: CircuitOpen, Open: true, WindowStart: 90}, o, p, 100)
		if d.Next.Phase != CircuitOpen || d.Act != ActNone {
			t.Fatalf("latch lost for %+v: %+v", o, d)
		}
	}
}

// Healthy again through a suspension with an alert open resolves the alert — after a dependency wait
// only once the service has stabilized, which also ends the wait.
func TestResolveThroughSuspension(t *testing.T) {
	p := testPolicy()
	up := Observation{Running: true, Health: "healthy"}
	for _, ph := range []Phase{ExpectedDown, Held, WaitingOnEdge} {
		d := Decide(FSM{Phase: ph, Open: true}, up, p, 100)
		if d.Act != ActResolve || d.Next.Open || d.Next.Phase != Healthy {
			t.Fatalf("from %s: %+v", ph, d)
		}
	}
	for _, f := range []FSM{
		{Phase: WaitingOnDependency, Open: true, DepWaitSince: 50, DepPaged: true},
		// several copies: the ladder is kept through the recovery
		{Phase: WaitingOnDependency, Open: true, DepWaitSince: 50, DepPaged: true, ReplicasAtAction: 3, WindowStart: 90, Attempts: 1, LastRung: RungRestart},
	} {
		d := Decision{Next: f}
		for i := 1; i < p.StabilizeTicks; i++ {
			d = Decide(d.Next, up, p, 100+int64(i))
			if d.Act != ActNone || d.Next.Phase != Recovered || !d.Next.Open || d.Next.DepWaitSince != 50 {
				t.Fatalf("from WAITING_ON_DEPENDENCY it stabilizes first (tick %d): %+v", i, d)
			}
		}
		d = Decide(d.Next, up, p, 100+int64(p.StabilizeTicks))
		if d.Act != ActResolve || d.Next.Open || d.Next.Phase != Healthy || d.Next.DepWaitSince != 0 || d.Next.DepPaged ||
			d.Next.LastRung != f.LastRung {
			t.Fatalf("stabilized: resolve and end the dependency wait; got %+v", d)
		}
	}
}

// A crash-looping dependent is sometimes seen running: a brief non-failing tick doesn't restart the
// wait's clock, so the wait is still paged DependencyWaitSecs after it began.
func TestDependencyWaitSurvivesABriefRecovery(t *testing.T) {
	p := testPolicy()
	wait := Observation{Running: false, Replicas: 1, Sick: 1, SickIDs: []string{"a1"}, WaitingOnDependency: true, Dependency: "db"}
	up := Observation{Running: true, Health: "healthy", Replicas: 1}
	d := Decide(FSM{Phase: Healthy}, wait, p, 1000)
	d = Decide(d.Next, up, p, 1100)
	if d.Act != ActNone || d.Next.Phase != Recovered || d.Next.DepWaitSince != 1000 {
		t.Fatalf("a running tick stabilizes and keeps the clock: %+v", d)
	}
	d = Decide(d.Next, wait, p, 1200)
	d = Decide(d.Next, wait, p, 1000+DependencyWaitSecs-1)
	if d.Act != ActNone || d.Next.Phase != WaitingOnDependency {
		t.Fatalf("still waiting: %+v", d)
	}
	d = Decide(d.Next, wait, p, 1000+DependencyWaitSecs)
	if d.Act != ActPage || d.Kind != "dependency_wait" {
		t.Fatalf("the wait is paged DependencyWaitSecs after it began: %+v", d)
	}
	// Failing for its own reasons (the dependency is fine) ends the wait: a later one starts afresh.
	own := wait
	own.WaitingOnDependency, own.Dependency = false, ""
	d = Decide(d.Next, own, p, 2000)
	if d.Next.DepWaitSince != 0 || d.Next.DepPaged {
		t.Fatalf("a failure of its own ends the wait: %+v", d)
	}
}

// A latched circuit stays open while a notify service's copies run but fail their healthcheck: that
// is not recovery, and it is not reported again.
func TestCircuitLatchSurvivesANotifyReport(t *testing.T) {
	o := Observation{Running: true, Health: "healthy", Replicas: 1, Reported: 1}
	d := Decide(FSM{Phase: CircuitOpen, Open: true, HealthyStreak: 2}, o, testPolicy(), 100)
	if d.Next.Phase != CircuitOpen || d.Act != ActNone || !d.Next.Open || d.Next.HealthyStreak != 0 {
		t.Fatalf("latch lost: %+v", d)
	}
}

// A failed container list shows no containers although some may be running: the watcher neither acts
// on it nor prunes the state of the services it can't see.
func TestWatcherIgnoresAFailedContainerList(t *testing.T) {
	var clock int64
	good := multiSnap(copyOf("web", "w1", "exited", "none"))
	snap := good
	act := &fakeActioner{}
	w := newTestWatcher(t, &snap, &clock, act)
	key := Key{App: "shop", Service: "web"}
	clock = 1000
	w.Tick(context.Background()) // SUSPECT
	snap = &monitor.Snapshot{DockerOK: true, ListFailed: true}
	for i := 1; i < 5; i++ {
		clock = int64(i)*100 + 1000
		w.Tick(context.Background())
	}
	if f, ok := w.fsms[key]; !ok || f.Phase != Suspect || f.UnhealthyStreak != 1 || len(act.calls) != 0 {
		t.Fatalf("a failed list must change nothing: %+v %v %v", f, ok, act.calls)
	}
	if all, err := w.cfg.Store.LoadAll(); err != nil || all[key].Phase != Suspect {
		t.Fatalf("the stored state must survive a failed list: %+v %v", all, err)
	}
	snap = good
	clock = 1500
	w.Tick(context.Background())
	if len(act.calls) != 1 || act.targets[0].CopyID != "w1" {
		t.Fatalf("with the list back, the kept streak carries on to a restart: %v", act.calls)
	}
}

// A remediation's deadline covers the service's stop grace period on top of its own bound.
func TestWatcherRemediationDeadlineCoversStopGrace(t *testing.T) {
	var clock int64
	snap := multiSnap(copyOf("web", "w1", "exited", "none"))
	act := &fakeActioner{}
	w := newTestWatcher(t, &snap, &clock, act)
	w.cfg.Services = func(string) (map[string]ServiceInfo, bool) {
		return map[string]ServiceInfo{"web": {StopGrace: 10 * time.Minute}}, true
	}
	before := time.Now()
	for i := 0; i < 2; i++ {
		clock = int64(i)*100 + 1000
		w.Tick(context.Background())
	}
	if len(act.deadlines) != 1 {
		t.Fatalf("want one remediation; got %v", act.calls)
	}
	if left := act.deadlines[0].Sub(before); left < remediateTimeout+10*time.Minute || left > remediateTimeout+11*time.Minute {
		t.Fatalf("the deadline must be the 5m bound plus the 10m stop grace; got %s", left)
	}
}

// on_unhealthy: notify — a failing healthcheck is reported once and never restarted; an exited copy
// still is.
func TestWatcherNotifyReportsNeverRestarts(t *testing.T) {
	var clock int64
	snap := multiSnap(copyOf("web", "w1", "running", "unhealthy"))
	act := &fakeActioner{}
	w := newTestWatcher(t, &snap, &clock, act)
	w.cfg.Services = func(string) (map[string]ServiceInfo, bool) {
		return map[string]ServiceInfo{"web": {Notify: true}}, true
	}
	for i := 0; i < 8; i++ {
		clock = int64(i)*100 + 1000
		w.Tick(context.Background())
	}
	key := Key{App: "shop", Service: "web"}
	if len(act.calls) != 0 {
		t.Fatalf("notify must never restart for a failing healthcheck: %v", act.calls)
	}
	if f := w.fsms[key]; f.Phase != Unhealthy || !f.Open {
		t.Fatalf("want UNHEALTHY with the alert open, got %+v", f)
	}
	down := copyOf("web", "w1", "exited", "none")
	setCopy(snap, "w1", &down)
	for i := 8; i < 11; i++ {
		clock = int64(i)*100 + 1000
		w.Tick(context.Background())
	}
	if len(act.calls) == 0 || act.calls[0] != "web:restart" {
		t.Fatalf("an exited copy is still restarted: %v", act.calls)
	}
}

// Another container still starting defers the restart without consuming an attempt; once it has
// settled the restart runs and is recorded with the gate.
func TestWatcherWaitsForTheStartGate(t *testing.T) {
	var clock int64
	snap := multiSnap(copyOf("web", "w1", "exited", "none"), copyOf("db", "d1", "running", "starting"))
	act := &fakeActioner{}
	w := newTestWatcher(t, &snap, &clock, act)
	gate := startgate.New(startgate.DefaultConfig(2))
	w.cfg.Gate = gate
	now := time.Now()
	started := now.Add(-5 * time.Second)
	w.cfg.Observe = func(s *monitor.Snapshot) {
		var cs []startgate.Container
		for _, c := range s.Apps[0].Services {
			cs = append(cs, startgate.Container{ID: c.ContainerID, App: "shop", Service: c.Service, Running: c.Running(),
				Health: c.Health, StartedAt: started, CPUValid: true, Inspected: true})
		}
		gate.Observe(startgate.Observation{At: s.At, Containers: cs})
	}
	for i := 0; i < 4; i++ {
		clock = int64(i)*100 + 1000
		snap.At = now.Add(time.Duration(i) * time.Second)
		w.Tick(context.Background())
	}
	key := Key{App: "shop", Service: "web"}
	if len(act.calls) != 0 || w.fsms[key].Attempts != 0 {
		t.Fatalf("a starting container must defer the restart without an attempt: %v %+v", act.calls, w.fsms[key])
	}
	healthy := copyOf("db", "d1", "running", "healthy")
	setCopy(snap, "d1", &healthy)
	clock = 1500
	snap.At = now.Add(10 * time.Second)
	w.Tick(context.Background())
	if len(act.calls) != 1 || act.targets[0].CopyID != "w1" {
		t.Fatalf("once settled the restart runs: %v", act.calls)
	}
	if d := gate.Admit(time.Now(), startgate.AdmitOpts{}); d.OK {
		t.Fatal("the restart must be recorded with the gate so the next start waits for it")
	}
}

// Each snapshot counts once: a tick that sees the same snapshot again does nothing.
func TestWatcherSkipsARepeatedSnapshot(t *testing.T) {
	var clock int64
	snap := multiSnap(copyOf("web", "w1", "exited", "none"))
	snap.At = time.Now()
	act := &fakeActioner{}
	w := newTestWatcher(t, &snap, &clock, act)
	for i := 0; i < 5; i++ {
		clock = int64(i)*100 + 1000
		w.Tick(context.Background())
	}
	if f := w.fsms[Key{App: "shop", Service: "web"}]; f.UnhealthyStreak != 1 || len(act.calls) != 0 {
		t.Fatalf("one snapshot is one observation: %+v %v", f, act.calls)
	}
}

// A notify service that was reporting a failing healthcheck still waits the sustain window before
// restarting a copy that then exits.
func TestNotifyStreakDoesNotSkipTheSustainWindow(t *testing.T) {
	p := testPolicy()
	rep := Observation{Running: true, Health: "healthy", Replicas: 1, Reported: 1}
	f := FSM{Phase: Healthy}
	for i := int64(0); i < 5; i++ {
		f = Decide(f, rep, p, 100+i*10).Next
	}
	if f.Phase != Unhealthy {
		t.Fatalf("reporting: %+v", f)
	}
	down := Observation{Running: false, Replicas: 1, Sick: 1, SickIDs: []string{"w1"}}
	d := Decide(f, down, p, 200)
	if d.Act == ActRemediate {
		t.Fatalf("the first failing tick must not act: %+v", d)
	}
	d = Decide(d.Next, down, p, 210)
	if d.Act != ActRemediate || d.Target != "w1" {
		t.Fatalf("after the sustain window it restarts the copy: %+v", d)
	}
}

// An Actioner that refuses a removal (the service isn't autoscaled after all) costs no attempt, and the
// next decision — with Scaled now false — recreates the whole service instead.
func TestRefusedRemovalBecomesARecreate(t *testing.T) {
	var clock int64
	snap := multiSnap(copyOf("web", "c1", "running", "healthy"), copyOf("web", "c2", "exited", "none"))
	scaled := true
	act := &fakeActioner{}
	w := newTestWatcher(t, &snap, &clock, act)
	w.cfg.Act = refusingActioner{act}
	w.cfg.Services = func(string) (map[string]ServiceInfo, bool) {
		return map[string]ServiceInfo{"web": {Scaled: scaled}}, true
	}
	key := Key{App: "shop", Service: "web"}
	tick := func(at int64) { clock = at; w.Tick(context.Background()) }
	tick(1000)
	tick(1100) // restart c2 (attempt 1); it stays down
	tick(1200) // recreate → Remove [c2] → refused
	if n := len(act.calls); n != 2 || len(act.targets[1].Remove) != 1 {
		t.Fatalf("want restart then a removal attempt, got %v %+v", act.calls, act.targets)
	}
	if f := w.fsms[key]; f.Attempts != 1 || f.LastRung != RungRestart {
		t.Fatalf("a refused removal must not use an attempt or move the ladder: %+v", f)
	}
	scaled = false
	tick(1300)
	if n := len(act.calls); n != 3 || act.calls[2] != "web:recreate" || act.targets[2].CopyID != "" || act.targets[2].Remove != nil {
		t.Fatalf("then the whole service is recreated, got %v %+v", act.calls, act.targets)
	}
}

// refusingActioner answers every removal with ErrNoReplacement.
type refusingActioner struct{ *fakeActioner }

func (r refusingActioner) Remediate(ctx context.Context, app monitor.App, service string, rung Rung, t Target) error {
	err := r.fakeActioner.Remediate(ctx, app, service, rung, t)
	if len(t.Remove) > 0 {
		return ErrNoReplacement
	}
	return err
}

// A snapshot whose container list was capped may omit services that exist: their state is kept.
func TestTruncatedSnapshotKeepsState(t *testing.T) {
	var clock int64
	snap := multiSnap(copyOf("web", "w1", "exited", "none"))
	act := &fakeActioner{}
	w := newTestWatcher(t, &snap, &clock, act)
	key := Key{App: "shop", Service: "web"}
	clock = 1000
	w.Tick(context.Background())
	snap = multiSnap(copyOf("db", "d1", "running", "healthy"))
	snap.Truncated = true
	clock = 1100
	w.Tick(context.Background())
	if _, ok := w.fsms[key]; !ok {
		t.Fatal("a truncated snapshot must not prune a service it doesn't list")
	}
}

// A notify service only reporting its healthcheck is running, so it isn't waiting on a dependency:
// the wait clock is cleared. And a failing streak doesn't carry into the report.
func TestNotifyReportClearsDependencyClockAndStreak(t *testing.T) {
	p := testPolicy()
	f := FSM{Phase: WaitingOnDependency, DepWaitSince: 100, UnhealthyStreak: 5}
	rep := Observation{Running: true, Health: "healthy", Replicas: 1, Reported: 1}
	d := Decide(f, rep, p, 200)
	if d.Next.DepWaitSince != 0 || d.Next.DepPaged {
		t.Fatalf("the dependency clock must be cleared while only reporting: %+v", d.Next)
	}
	if d.Act == ActPage {
		t.Fatalf("the first reported tick must not page (failing ticks don't count): %+v", d)
	}
	d = Decide(d.Next, rep, p, 210)
	if d.Act != ActPage || d.Kind != "unhealthy_reported" {
		t.Fatalf("after the sustain window it pages: %+v", d)
	}
}
