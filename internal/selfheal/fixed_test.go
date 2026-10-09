package selfheal

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/monitor"
	"github.com/daboss2003/mooring/internal/startgate"
)

// fixedWeb makes "web" a service with a fixed count of n copies (replicas: n).
func fixedWeb(n int) func(string) (map[string]ServiceInfo, bool) {
	return func(string) (map[string]ServiceInfo, bool) {
		return map[string]ServiceInfo{"web": {Replicas: n}, "db": {}}, true
	}
}

// restoreAdds simulates Remediate's `up --no-recreate --scale web=min(copies+1, n)`: every restore
// (after its removals) adds one running, healthy copy of web, up to n.
func restoreAdds(snap **monitor.Snapshot, n int) func(string, Rung, Target) {
	next := 0
	return func(_ string, _ Rung, tg Target) {
		for _, id := range tg.Remove {
			setCopy(*snap, id, nil)
		}
		if !tg.Restore || webCopies(*snap) >= n {
			return
		}
		next++
		(*snap).Apps[0].Services = append((*snap).Apps[0].Services, copyOf("web", fmt.Sprintf("new%d", next), "running", "healthy"))
	}
}

// webCopies counts web's containers in snap.
func webCopies(snap *monitor.Snapshot) int {
	n := 0
	for _, c := range snap.Apps[0].Services {
		if c.Service == "web" {
			n++
		}
	}
	return n
}

// A fixed-count service with a copy missing (removed outside Mooring) gets it back: once the failure
// has lasted the sustain window, one restore — counted as an attempt, the ladder untouched — and the
// service ends healthy.
func TestFixedCountRestoresAMissingCopy(t *testing.T) {
	var clock int64
	snap := multiSnap(copyOf("web", "c1", "running", "healthy"), copyOf("web", "c2", "running", "healthy"))
	act := &fakeActioner{}
	act.after = restoreAdds(&snap, 3)
	w := newTestWatcher(t, &snap, &clock, act)
	w.cfg.Services = fixedWeb(3)
	key := Key{App: "shop", Service: "web"}
	tick := func(at int64) { clock = at; w.Tick(context.Background()) }

	tick(1000)
	if len(act.calls) != 0 || w.fsms[key].Phase != Suspect {
		t.Fatalf("the first tick only suspects: %v %+v", act.calls, w.fsms[key])
	}
	tick(1100)
	if len(act.calls) != 1 || act.calls[0] != "web:restore" || !act.targets[0].Restore || act.targets[0].Remove != nil || act.targets[0].CopyID != "" {
		t.Fatalf("want one restore of the missing copy; got %v %+v", act.calls, act.targets)
	}
	if f := w.fsms[key]; f.Attempts != 1 || f.LastRung != RungNone || f.ReplicasAtAction != 3 {
		t.Fatalf("a restore is an attempt, not a rung; got %+v", f)
	}
	for at := int64(1200); at <= 1600; at += 100 {
		tick(at)
	}
	if f := w.fsms[key]; f.Phase != Healthy || len(act.calls) != 1 {
		t.Fatalf("with the copy back it ends healthy, nothing more run; got %+v %v", f, act.calls)
	}
}

// A restore that never brings the copy back is bounded by the attempt cap: the circuit opens and the
// service is paged as missing copies, instead of restoring every tick forever.
func TestFixedCountRestoreEndsInTheCircuit(t *testing.T) {
	var clock int64
	snap := multiSnap(copyOf("web", "c1", "running", "healthy"), copyOf("web", "c2", "running", "healthy"))
	act := &fakeActioner{fail: true}
	w := newTestWatcher(t, &snap, &clock, act)
	w.cfg.Services = fixedWeb(3)
	key := Key{App: "shop", Service: "web"}
	for i := 0; i < 20; i++ {
		clock = int64(i)*100 + 1000
		w.Tick(context.Background())
	}
	if len(act.calls) != testPolicy().AttemptCap {
		t.Fatalf("want %d restores before giving up; got %v", testPolicy().AttemptCap, act.calls)
	}
	for _, c := range act.calls {
		if c != "web:restore" {
			t.Fatalf("only restores may run; got %v", act.calls)
		}
	}
	if f := w.fsms[key]; f.Phase != CircuitOpen || !f.Open {
		t.Fatalf("want CIRCUIT_OPEN with the alert open; got %+v", f)
	}
	o := Observation{Running: true, Health: "healthy", Replicas: 2, Declared: 3}
	if k := capKind(o); k != "copies_missing" {
		t.Fatalf("a capped restore pages as %q, want copies_missing", k)
	}
}

// Every existing gate holds a restore back: an operator hold, a write-plane lease, an open circuit, a
// busy docker slot and a start the gate is still waiting for. None of them consumes an attempt.
func TestFixedCountRestoreRespectsEveryGate(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, w *Watcher, snap *monitor.Snapshot)
	}{
		{"held", func(t *testing.T, w *Watcher, _ *monitor.Snapshot) {
			if err := w.cfg.Store.SetHeld(context.Background(), Key{App: "shop", Service: "web"}, "op", 1); err != nil {
				t.Fatal(err)
			}
		}},
		{"expected_down lease", func(t *testing.T, w *Watcher, _ *monitor.Snapshot) {
			if err := w.cfg.Store.AcquireExpectedDown(context.Background(), "shop", 1<<40); err != nil {
				t.Fatal(err)
			}
		}},
		{"circuit open", func(t *testing.T, w *Watcher, _ *monitor.Snapshot) {
			w.fsms[Key{App: "shop", Service: "web"}] = FSM{Phase: CircuitOpen, Open: true, WindowStart: 1000, Attempts: 3}
		}},
		{"docker slot busy", func(t *testing.T, w *Watcher, _ *monitor.Snapshot) {
			if !w.cfg.Sem.TryAcquire() {
				t.Fatal("could not take the slot")
			}
			t.Cleanup(w.cfg.Sem.Release)
		}},
		{"start gate waiting", func(t *testing.T, w *Watcher, snap *monitor.Snapshot) {
			gate := startgate.New(startgate.DefaultConfig(2))
			w.cfg.Gate = gate
			starting := copyOf("db", "d1", "running", "starting")
			snap.Apps[0].Services = append(snap.Apps[0].Services, starting)
			w.cfg.Observe = func(s *monitor.Snapshot) {
				var cs []startgate.Container
				for _, c := range s.Apps[0].Services {
					cs = append(cs, startgate.Container{ID: c.ContainerID, App: "shop", Service: c.Service, Running: c.Running(),
						Health: c.Health, StartedAt: time.Now().Add(-5 * time.Second), CPUValid: true, Inspected: true})
				}
				gate.Observe(startgate.Observation{At: s.At, Containers: cs})
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var clock int64
			snap := multiSnap(copyOf("web", "c1", "running", "healthy"), copyOf("web", "c2", "running", "healthy"))
			act := &fakeActioner{}
			w := newTestWatcher(t, &snap, &clock, act)
			w.cfg.Services = fixedWeb(3)
			tc.setup(t, w, snap)
			base := time.Now()
			for i := 0; i < 8; i++ {
				clock = int64(i)*100 + 1000
				snap.At = base.Add(time.Duration(i) * time.Second)
				w.Tick(context.Background())
			}
			if len(act.calls) != 0 {
				t.Fatalf("the restore must not run: %v", act.calls)
			}
			if f := w.fsms[Key{App: "shop", Service: "web"}]; tc.name != "circuit open" && f.Attempts != 0 {
				t.Fatalf("a held-back restore consumes no attempt: %+v", f)
			}
		})
	}
}

// A fixed-count service with no container at all is restored while the rest of its app runs — but not
// from a truncated container list, not in an app with nothing running (the operator stopped it), and
// not for a single fixed copy or a scheduled service.
func TestFixedCountRestoresAServiceWithNoContainer(t *testing.T) {
	for _, tc := range []struct {
		name     string
		info     map[string]ServiceInfo
		db       string // db's state
		truncate bool
		restore  bool
	}{
		{"restored", map[string]ServiceInfo{"web": {Replicas: 2}, "db": {}}, "running", false, true},
		{"truncated list", map[string]ServiceInfo{"web": {Replicas: 2}, "db": {}}, "running", true, false},
		{"app stopped", map[string]ServiceInfo{"web": {Replicas: 2}, "db": {}}, "exited", false, false},
		{"one fixed copy", map[string]ServiceInfo{"web": {Replicas: 1}, "db": {}}, "running", false, false},
		{"scheduled", map[string]ServiceInfo{"web": {Replicas: 2, Scheduled: true}, "db": {}}, "running", false, false},
		{"autoscaled", map[string]ServiceInfo{"web": {Replicas: 2, Scaled: true}, "db": {}}, "running", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var clock int64
			snap := multiSnap(copyOf("db", "d1", tc.db, "none"))
			snap.Truncated = tc.truncate
			act := &fakeActioner{}
			w := newTestWatcher(t, &snap, &clock, act)
			w.cfg.Services = func(string) (map[string]ServiceInfo, bool) { return tc.info, true }
			if tc.db != "running" {
				// keep db out of the picture: it is held, as an app-level stop leaves it
				_ = w.cfg.Store.SetHeld(context.Background(), Key{App: "shop", Service: "db"}, "op", 1)
			}
			for i := 0; i < 3; i++ {
				clock = int64(i)*100 + 1000
				w.Tick(context.Background())
			}
			var webCalls []Target
			for i, c := range act.calls {
				if c == "web:restore" {
					webCalls = append(webCalls, act.targets[i])
				}
			}
			if got := len(webCalls) > 0 && webCalls[0].Restore; got != tc.restore {
				t.Fatalf("restored = %v, want %v; calls %v", got, tc.restore, act.calls)
			}
		})
	}
}

// A sick copy of a fixed count next to a healthy one: restart it, then remove only it and restore the
// count — the healthy copies are never recreated.
func TestFixedCountRecreateRemovesOnlyTheSickCopies(t *testing.T) {
	var clock int64
	snap := multiSnap(copyOf("web", "c1", "running", "healthy"), copyOf("web", "c2", "running", "healthy"), copyOf("web", "c3", "exited", "none"))
	act := &fakeActioner{}
	act.after = restoreAdds(&snap, 3)
	w := newTestWatcher(t, &snap, &clock, act)
	w.cfg.Services = fixedWeb(3)
	key := Key{App: "shop", Service: "web"}
	for i := 0; i < 10; i++ {
		clock = int64(i)*100 + 1000
		w.Tick(context.Background())
	}
	if len(act.calls) != 2 || act.calls[0] != "web:restart" || act.targets[0].CopyID != "c3" ||
		act.calls[1] != "web:recreate" || !slices.Equal(act.targets[1].Remove, []string{"c3"}) || !act.targets[1].Restore || act.targets[1].CopyID != "" {
		t.Fatalf("want restart c3, then remove c3 and restore; got %v %+v", act.calls, act.targets)
	}
	for _, c := range snap.Apps[0].Services {
		if c.ContainerID == "c1" || c.ContainerID == "c2" {
			continue
		}
		if c.ContainerID == "c3" {
			t.Fatal("the sick copy must be gone")
		}
	}
	if f := w.fsms[key]; f.Phase != Healthy || f.Open {
		t.Fatalf("with the count restored it ends healthy; got %+v", f)
	}
}

// Replacing a sick copy of a fixed count starts a container, so — unlike an autoscaled removal — it
// waits for the start gate and is recorded with it.
func TestFixedCountReplacementGoesThroughTheStartGate(t *testing.T) {
	var clock int64
	snap := multiSnap(copyOf("web", "c1", "running", "healthy"), copyOf("web", "c2", "exited", "none"), copyOf("db", "d1", "running", "healthy"))
	gate := startgate.New(startgate.DefaultConfig(2))
	longAgo := time.Now().Add(-time.Hour)
	startedAt := map[string]time.Time{}
	act := &fakeActioner{}
	act.after = func(_ string, _ Rung, tg Target) {
		if tg.CopyID != "" {
			startedAt[tg.CopyID] = time.Now() // restarted, and exits again at once
		}
	}
	w := newTestWatcher(t, &snap, &clock, act)
	w.cfg.Services = fixedWeb(2)
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
	tick(1100) // restart c2; it stays down
	if len(act.calls) != 1 || act.targets[0].CopyID != "c2" {
		t.Fatalf("want a restart of c2; got %v %+v", act.calls, act.targets)
	}
	startedAt["d1"] = time.Now()
	starting := copyOf("db", "d1", "running", "starting")
	setCopy(snap, "d1", &starting)
	tick(1200)
	tick(1300)
	if len(act.calls) != 1 || w.fsms[key].Attempts != 1 {
		t.Fatalf("a starting container must defer the replacement without an attempt: %v %+v", act.calls, w.fsms[key])
	}
	healthy := copyOf("db", "d1", "running", "healthy")
	setCopy(snap, "d1", &healthy)
	tick(1400)
	if len(act.calls) != 2 || act.calls[1] != "web:recreate" || !slices.Equal(act.targets[1].Remove, []string{"c2"}) || !act.targets[1].Restore {
		t.Fatalf("once db settled, want c2 removed and the count restored; got %v %+v", act.calls, act.targets)
	}
	if d := gate.Admit(time.Now(), startgate.AdmitOpts{}); d.OK {
		t.Fatal("the replacement must be recorded with the gate so the next start waits for it")
	}
}

// An Actioner that refuses a restore (the deployed definition no longer declares the count) costs no
// attempt.
func TestRefusedRestoreCostsNoAttempt(t *testing.T) {
	var clock int64
	snap := multiSnap(copyOf("web", "c1", "running", "healthy"))
	act := &fakeActioner{}
	w := newTestWatcher(t, &snap, &clock, act)
	w.cfg.Act = notFixedActioner{act}
	w.cfg.Services = fixedWeb(2)
	for i := 0; i < 6; i++ {
		clock = int64(i)*100 + 1000
		w.Tick(context.Background())
	}
	if len(act.calls) == 0 {
		t.Fatal("want the restore attempted")
	}
	if f := w.fsms[Key{App: "shop", Service: "web"}]; f.Attempts != 0 || f.Phase == CircuitOpen {
		t.Fatalf("a refused restore must not use an attempt: %+v", f)
	}
}

// notFixedActioner answers every restore with ErrNotFixed.
type notFixedActioner struct{ *fakeActioner }

func (r notFixedActioner) Remediate(ctx context.Context, app monitor.App, service string, rung Rung, t Target) error {
	err := r.fakeActioner.Remediate(ctx, app, service, rung, t)
	if t.Restore {
		return ErrNotFixed
	}
	return err
}

// Every copy of a fixed count sick: nothing healthy to keep, so the recreate rung recreates the service.
func TestFixedCountRecreatesWhenNoCopyIsHealthy(t *testing.T) {
	var clock int64
	snap := multiSnap(copyOf("web", "c1", "exited", "none"), copyOf("web", "c2", "exited", "none"))
	act := &fakeActioner{}
	w := newTestWatcher(t, &snap, &clock, act)
	w.cfg.Services = fixedWeb(2)
	for i := 0; i < 6; i++ {
		clock = int64(i)*100 + 1000
		w.Tick(context.Background())
	}
	if len(act.calls) != 3 || act.calls[2] != "web:recreate" || act.targets[2].Remove != nil || act.targets[2].Restore {
		t.Fatalf("want restarts of c1 and c2, then a whole-service recreate; got %v %+v", act.calls, act.targets)
	}
}

// A single fixed copy is supervised exactly like a service without replicas: restart, then a
// whole-service recreate.
func TestFixedCountOfOneBehavesAsBefore(t *testing.T) {
	run := func(info func(string) (map[string]ServiceInfo, bool)) ([]string, []Target) {
		var clock int64
		snap := multiSnap(copyOf("web", "c1", "exited", "none"), copyOf("db", "d1", "running", "healthy"))
		act := &fakeActioner{}
		w := newTestWatcher(t, &snap, &clock, act)
		w.cfg.Services = info
		for i := 0; i < 8; i++ {
			clock = int64(i)*100 + 1000
			w.Tick(context.Background())
		}
		return act.calls, act.targets
	}
	wantCalls, wantTargets := run(func(string) (map[string]ServiceInfo, bool) {
		return map[string]ServiceInfo{"web": {}, "db": {}}, true
	})
	gotCalls, gotTargets := run(fixedWeb(1))
	if !slices.Equal(gotCalls, wantCalls) || len(gotTargets) != len(wantTargets) {
		t.Fatalf("replicas: 1 = %v %+v, want as without replicas %v %+v", gotCalls, gotTargets, wantCalls, wantTargets)
	}
	for i := range gotTargets {
		if gotTargets[i].CopyID != wantTargets[i].CopyID || gotTargets[i].Restore || gotTargets[i].Remove != nil {
			t.Fatalf("target %d = %+v, want %+v", i, gotTargets[i], wantTargets[i])
		}
	}
}

// A truncated container list may list only some copies: that is not a missing copy.
func TestFixedCountIgnoresATruncatedList(t *testing.T) {
	var clock int64
	snap := multiSnap(copyOf("web", "c1", "running", "healthy"))
	snap.Truncated = true
	act := &fakeActioner{}
	w := newTestWatcher(t, &snap, &clock, act)
	w.cfg.Services = fixedWeb(3)
	for i := 0; i < 5; i++ {
		clock = int64(i)*100 + 1000
		w.Tick(context.Background())
	}
	if len(act.calls) != 0 || w.fsms[Key{App: "shop", Service: "web"}].Phase != Healthy {
		t.Fatalf("no restore from a truncated list: %v %+v", act.calls, w.fsms[Key{App: "shop", Service: "web"}])
	}
}

// A restore keeps the ladder where it is: a copy that then fails still escalates from the rung it
// reached, and the restore's attempt counts toward the cap.
func TestRestoreDoesNotMoveTheLadder(t *testing.T) {
	p := testPolicy()
	f := FSM{Phase: Degraded, LastRung: RungRestart, Attempts: 1, WindowStart: 900, UnhealthyStreak: 5}
	o := Observation{Running: true, Health: "healthy", Replicas: 2, Declared: 3}
	d := Decide(f, o, p, 1000)
	if d.Act != ActRemediate || d.Rung != RungRestore || !d.Restore || d.Remove != nil {
		t.Fatalf("want a restore: %+v", d)
	}
	next := Commit(d, o, p, 1000)
	if next.Attempts != 2 || next.LastRung != RungRestart || next.BackoffUntil <= 1000 || next.ReplicasAtAction != 3 {
		t.Fatalf("a restore consumes an attempt and arms the backoff, ladder unchanged: %+v", next)
	}
}

// A fixed count missing many copies gets them all back, one copy per restore: only the first restore
// uses an attempt, and each later one runs because the one before added its copy — 20 missing copies
// never open the circuit.
func TestFixedCountRestoresManyMissingCopiesOneAtATime(t *testing.T) {
	var clock int64
	snap := multiSnap(copyOf("db", "d1", "running", "healthy"))
	act := &fakeActioner{}
	act.after = restoreAdds(&snap, 20)
	w := newTestWatcher(t, &snap, &clock, act)
	w.cfg.Services = fixedWeb(20)
	key := Key{App: "shop", Service: "web"}
	for i := 0; i < 400 && webCopies(snap) < 20; i++ {
		clock = 1000 + int64(i)*10
		w.Tick(context.Background())
		if w.fsms[key].Phase == CircuitOpen {
			t.Fatalf("the circuit opened with %d of 20 copies back: %+v", webCopies(snap), w.fsms[key])
		}
	}
	if n := webCopies(snap); n != 20 {
		t.Fatalf("restored %d of 20 copies; calls %v", n, act.calls)
	}
	if len(act.calls) != 20 {
		t.Fatalf("want one restore per copy (20); got %d: %v", len(act.calls), act.calls)
	}
	for i, c := range act.calls {
		if c != "web:restore" || !act.targets[i].Restore || act.targets[i].Remove != nil {
			t.Fatalf("call %d = %s %+v, want a restore", i, c, act.targets[i])
		}
	}
	if f := w.fsms[key]; f.Attempts != 1 {
		t.Fatalf("only the first restore uses an attempt: %+v", f)
	}
	for i := 0; i < 5; i++ {
		clock += 10
		w.Tick(context.Background())
	}
	if f := w.fsms[key]; f.Phase != Healthy || f.Open || len(act.calls) != 20 {
		t.Fatalf("with every copy back it ends healthy and nothing more runs: %+v %d calls", f, len(act.calls))
	}
}

// Restores that stop adding copies use an attempt each, so the circuit still opens: two restores add a
// copy, the third doesn't, and the attempts run out after the cap.
func TestFixedCountRestoreThatStopsAddingCopiesEndsInTheCircuit(t *testing.T) {
	var clock int64
	snap := multiSnap(copyOf("db", "d1", "running", "healthy"))
	act := &fakeActioner{}
	adds := restoreAdds(&snap, 6)
	added := 0
	act.after = func(svc string, r Rung, tg Target) {
		if added < 2 {
			added++
			adds(svc, r, tg)
			return
		}
		act.fail = true // from now on `up` fails and no copy appears
	}
	w := newTestWatcher(t, &snap, &clock, act)
	w.cfg.Services = fixedWeb(6)
	key := Key{App: "shop", Service: "web"}
	for i := 0; i < 200; i++ {
		clock = 1000 + int64(i)*10
		w.Tick(context.Background())
	}
	if f := w.fsms[key]; f.Phase != CircuitOpen || !f.Open {
		t.Fatalf("want CIRCUIT_OPEN with the alert open; got %+v", f)
	}
	// restore 1 (attempt 1, adds), restore 2 (free, adds), restore 3 (free, adds nothing),
	// restores 4 and 5 (attempts 2 and 3), then the cap.
	if len(act.calls) != 5 || webCopies(snap) != 2 {
		t.Fatalf("want 5 restores and 2 copies; got %d restores, %d copies: %v", len(act.calls), webCopies(snap), act.calls)
	}
}

// A restore runs without an attempt — even at the cap — only when the previous restore's copy showed
// up; otherwise the cap opens the circuit as copies_missing. Commit records the count it aims for.
func TestFreeRestoreNeedsTheLastCopy(t *testing.T) {
	p := testPolicy()
	f := FSM{Phase: Degraded, Attempts: p.AttemptCap, WindowStart: 900, UnhealthyStreak: 5, RestoreTarget: 3}
	o := Observation{Running: true, Health: "healthy", Replicas: 3, Declared: 5}
	d := Decide(f, o, p, 1000)
	if d.Act != ActRemediate || d.Rung != RungRestore || !d.Restore || !d.FreeRestore || d.Remove != nil {
		t.Fatalf("the last restore added its copy: want a free restore at the cap; got %+v", d)
	}
	next := Commit(d, o, p, 1000)
	if next.Attempts != p.AttemptCap || next.BackoffUntil != 0 || next.RestoreTarget != 4 || next.LastRung != RungNone {
		t.Fatalf("a free restore uses no attempt, arms no backoff and aims one copy higher: %+v", next)
	}
	d = Decide(next, o, p, 1010) // the copy it started didn't show up
	if d.Act != ActPage || d.Kind != "copies_missing" || d.Next.Phase != CircuitOpen {
		t.Fatalf("a restore that added nothing counts toward the cap: want a copies_missing page; got %+v", d)
	}

	// A charged restore of a service with no container aims for one copy; a replacement aims one above
	// what is left after its removals; neither aims past the declared count.
	for _, tc := range []struct {
		o      Observation
		remove []string
		want   int
	}{
		{Observation{Running: true, Replicas: 0, Declared: 4}, nil, 1},
		{Observation{Running: false, Replicas: 4, Sick: 2, Declared: 4}, []string{"a", "b"}, 3},
		{Observation{Running: true, Replicas: 5, Declared: 4}, nil, 4},
	} {
		got := Commit(Decision{Next: FSM{}, Rung: RungRecreate, Restore: true, Remove: tc.remove}, tc.o, p, 1000).RestoreTarget
		if got != tc.want {
			t.Errorf("%+v remove %v: target %d, want %d", tc.o, tc.remove, got, tc.want)
		}
	}
}

// A suspension or a recovery forgets the last restore, so a later shortfall starts over with an attempt.
func TestRestoreTargetIsForgotten(t *testing.T) {
	p := testPolicy()
	f := FSM{Phase: Degraded, WindowStart: 900, Attempts: 1, RestoreTarget: 3, UnhealthyStreak: 5}
	short := Observation{Running: true, Health: "healthy", Replicas: 3, Declared: 4}
	for _, o := range []Observation{{Held: true}, {ExpectedDown: true}} {
		if d := Decide(f, o, p, 1000); d.Next.RestoreTarget != 0 {
			t.Fatalf("%+v: the restore target must be cleared: %+v", o, d.Next)
		}
	}
	whole := Observation{Running: true, Health: "healthy", Replicas: 4, Declared: 4}
	d := Decision{Next: FSM{Phase: Remediating, WindowStart: 900, Attempts: 1, RestoreTarget: 3, ReplicasAtAction: 4}}
	for i := 0; i < p.StabilizeTicks; i++ {
		d = Decide(d.Next, whole, p, 1000+int64(i))
	}
	if d.Next.Phase != Healthy || d.Next.RestoreTarget != 0 {
		t.Fatalf("recovered: the restore target must be cleared: %+v", d.Next)
	}
	d = Decide(d.Next, short, p, 1100) // a copy is removed again: suspect, then restore
	if d = Decide(d.Next, short, p, 1110); d.Rung != RungRestore || d.FreeRestore {
		t.Fatalf("after a recovery the next restore uses an attempt: %+v", d)
	}
}

// Remediate answering ErrNothingMissing (the service already has its count) costs no attempt, and the
// start gate records no start for it.
func TestNothingMissingCostsNoAttempt(t *testing.T) {
	var clock int64
	snap := multiSnap(copyOf("web", "c1", "running", "healthy"), copyOf("db", "d1", "running", "healthy"))
	act := &fakeActioner{}
	w := newTestWatcher(t, &snap, &clock, act)
	w.cfg.Act = nothingMissingActioner{act}
	w.cfg.Services = fixedWeb(2)
	gate := startgate.New(startgate.DefaultConfig(2))
	w.cfg.Gate = gate
	base := time.Now()
	for i := 0; i < 6; i++ {
		clock = int64(i)*100 + 1000
		snap.At = base.Add(time.Duration(i) * time.Second)
		w.Tick(context.Background())
	}
	if len(act.calls) == 0 {
		t.Fatal("want the restore attempted")
	}
	if f := w.fsms[Key{App: "shop", Service: "web"}]; f.Attempts != 0 || f.Phase == CircuitOpen {
		t.Fatalf("a refused restore must not use an attempt: %+v", f)
	}
	if d := gate.Admit(time.Now(), startgate.AdmitOpts{}); !d.OK {
		t.Fatalf("a refused restore started nothing, so it must not hold other starts back: %+v", d)
	}
}

// nothingMissingActioner answers every restore with ErrNothingMissing.
type nothingMissingActioner struct{ *fakeActioner }

func (r nothingMissingActioner) Remediate(ctx context.Context, app monitor.App, service string, rung Rung, t Target) error {
	err := r.fakeActioner.Remediate(ctx, app, service, rung, t)
	if t.Restore {
		return ErrNothingMissing
	}
	return err
}

// logBuffer collects a watcher's log output.
type logBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// An app stopped as a whole holds a fixed service that has no container too: its state — an open
// circuit and its alert — is kept while nothing runs, and the alert resolves once the app is started
// and the copies are back.
func TestHeldFixedServiceWithoutCopiesKeepsItsState(t *testing.T) {
	var clock int64
	snap := multiSnap(copyOf("db", "d1", "exited", "none"))
	act := &fakeActioner{}
	w := newTestWatcher(t, &snap, &clock, act)
	logs := &logBuffer{}
	w.cfg.Log = slog.New(slog.NewTextHandler(logs, nil))
	w.cfg.Services = fixedWeb(2)
	key := Key{App: "shop", Service: "web"}
	w.fsms[key] = FSM{Phase: CircuitOpen, Open: true, WindowStart: 900, Attempts: 3}
	ctx := context.Background()
	for _, svc := range []string{"web", "db"} {
		if err := w.cfg.Store.SetHeld(ctx, Key{App: "shop", Service: svc}, "op", 1); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		clock = int64(i)*100 + 1000
		w.Tick(ctx)
	}
	f, ok := w.fsms[key]
	if !ok || !f.Open || f.Phase != Held || len(act.calls) != 0 {
		t.Fatalf("a held service keeps its state and its open alert while the app is stopped: %+v ok=%v calls %v", f, ok, act.calls)
	}

	// The operator starts the app: the holds go and every copy runs again.
	if err := w.cfg.Store.ClearHeldApp(ctx, "shop"); err != nil {
		t.Fatal(err)
	}
	snap = multiSnap(copyOf("db", "d1", "running", "healthy"), copyOf("web", "c1", "running", "healthy"), copyOf("web", "c2", "running", "healthy"))
	clock += 100
	w.Tick(ctx)
	if f := w.fsms[key]; f.Open || f.Phase != Healthy {
		t.Fatalf("back with every copy: the alert resolves; got %+v", f)
	}
	if out := logs.String(); !strings.Contains(out, "target=shop/web transition=resolved") {
		t.Fatalf("want the open alert resolved; log:\n%s", out)
	}
}

// When a service with an open alert is gone from an app that is still listed (no container, nothing
// declares it to be restored), its state is dropped and the alert is resolved rather than left open. A
// whole app gone from the list (deleted) is dropped without an alert.
func TestPrunedServiceResolvesItsAlert(t *testing.T) {
	var clock int64
	snap := multiSnap(copyOf("db", "d1", "running", "healthy"))
	act := &fakeActioner{}
	w := newTestWatcher(t, &snap, &clock, act)
	logs := &logBuffer{}
	w.cfg.Log = slog.New(slog.NewTextHandler(logs, nil))
	gone := Key{App: "shop", Service: "old"}
	deleted := Key{App: "other", Service: "api"}
	quiet := Key{App: "shop", Service: "quiet"}
	w.fsms[gone] = FSM{Phase: CircuitOpen, Open: true}
	w.fsms[deleted] = FSM{Phase: CircuitOpen, Open: true}
	w.fsms[quiet] = FSM{Phase: Healthy}
	clock = 1000
	w.Tick(context.Background())
	for _, k := range []Key{gone, deleted, quiet} {
		if _, ok := w.fsms[k]; ok {
			t.Fatalf("%v must be pruned", k)
		}
	}
	out := logs.String()
	if !strings.Contains(out, "kind=service_gone target=shop/old transition=resolved") {
		t.Fatalf("the open alert of the gone service must be resolved; log:\n%s", out)
	}
	if strings.Contains(out, "target=other/api") || strings.Contains(out, "target=shop/quiet") {
		t.Fatalf("no alert for a deleted app's service or a service without an open alert; log:\n%s", out)
	}
	if s := infraSummary("service_gone", "resolved", "shop/old"); strings.Contains(s, "healthy") {
		t.Fatalf("a gone service did not recover: %q", s)
	}
}
