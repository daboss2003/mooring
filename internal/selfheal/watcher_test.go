package selfheal

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/dockerexec"
	"github.com/daboss2003/mooring/internal/hostmon"
	"github.com/daboss2003/mooring/internal/monitor"
	"github.com/daboss2003/mooring/internal/store"
)

// fakeActioner records remediation calls instead of running docker.
type fakeActioner struct {
	mu        sync.Mutex
	calls     []string // "service:rung"
	targets   []Target
	deadlines []time.Time // each call's context deadline (zero if none)
	fail      bool
	after     func(service string, rung Rung, t Target) // simulates the action's effect (optional)
}

func (f *fakeActioner) Remediate(ctx context.Context, app monitor.App, service string, rung Rung, t Target) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, service+":"+string(rung))
	f.targets = append(f.targets, t)
	dl, _ := ctx.Deadline()
	f.deadlines = append(f.deadlines, dl)
	if f.after != nil {
		f.after(service, rung, t)
	}
	if f.fail {
		return io.EOF
	}
	return nil
}

func (f *fakeActioner) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.calls) }

// snapOf builds a one-app snapshot with a single service in a given state.
func snapOf(svc monitor.ServiceStatus, memTotal, memUsed uint64) *monitor.Snapshot {
	return &monitor.Snapshot{
		DockerOK: true,
		HostOK:   true,
		Host:     hostmon.Sample{MemTotal: memTotal, MemUsed: memUsed},
		Apps:     []monitor.App{{Project: "shop", Services: []monitor.ServiceStatus{svc}}},
	}
}

func newTestWatcher(t *testing.T, snapPtr **monitor.Snapshot, clock *int64, act Actioner) *Watcher {
	t.Helper()
	p := testPolicy()
	cfg := Config{
		Store:        testStore(t),
		Snap:         func() *monitor.Snapshot { return *snapPtr },
		Sem:          dockerexec.NewSemaphore(),
		Act:          act,
		Policy:       p,
		Log:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		FloorBytes:   256 << 20,
		WritePlaneOK: true,
		Now:          func() int64 { return *clock },
	}
	return New(cfg)
}

func downSvc() monitor.ServiceStatus {
	return monitor.ServiceStatus{Service: "web", State: "exited", ExitCode: 1}
}
func upSvc() monitor.ServiceStatus {
	return monitor.ServiceStatus{Service: "web", State: "running", Health: "healthy"}
}

// A crash-looping service is remediated after the sustain window, escalates rungs,
// then opens the circuit — and the Actioner is only ever called for real rungs.
func TestWatcherRemediatesThenCircuitOpens(t *testing.T) {
	var snap *monitor.Snapshot
	var clock int64
	act := &fakeActioner{}
	w := newTestWatcher(t, &snap, &clock, act)
	snap = snapOf(downSvc(), 2<<30, 1<<30) // plenty of headroom
	ctx := context.Background()
	key := Key{App: "shop", Service: "web"}

	// Drive ticks with the clock advancing well past each backoff.
	for i := 0; i < 12; i++ {
		clock = int64(i)*100 + 1000
		w.Tick(ctx)
	}
	if act.count() == 0 {
		t.Fatal("a sustained crash loop must trigger at least one remediation")
	}
	// Ladder is restart then recreate (redeploy off) → exactly two real actions.
	if act.count() != 2 {
		t.Errorf("expected restart+recreate (2 actions) before the circuit opens, got %d (%v)", act.count(), act.calls)
	}
	if w.fsms[key].Phase != CircuitOpen {
		t.Errorf("an unrecoverable crash loop must end CIRCUIT_OPEN, got %s", w.fsms[key].Phase)
	}
}

// A held expected_down lease suppresses all remediation (a deploy isn't a crash loop).
func TestWatcherExpectedDownSuppresses(t *testing.T) {
	var snap *monitor.Snapshot
	var clock int64
	act := &fakeActioner{}
	w := newTestWatcher(t, &snap, &clock, act)
	snap = snapOf(downSvc(), 2<<30, 1<<30)
	ctx := context.Background()
	_ = w.cfg.Store.AcquireExpectedDown(ctx, "shop", 1<<40) // lease held far into the future

	for i := 0; i < 12; i++ {
		clock = int64(i)*100 + 1000
		w.Tick(ctx)
	}
	if act.count() != 0 {
		t.Errorf("expected_down must suppress remediation, but %d actions ran", act.count())
	}
	if w.fsms[Key{App: "shop", Service: "web"}].Phase != ExpectedDown {
		t.Error("a leased app's service should be EXPECTED_DOWN")
	}
}

// Below the headroom floor, the watcher must PAGE and NEVER call the Actioner.
func TestWatcherLowHeadroomPagesNeverActs(t *testing.T) {
	var snap *monitor.Snapshot
	var clock int64
	act := &fakeActioner{}
	w := newTestWatcher(t, &snap, &clock, act)
	snap = snapOf(downSvc(), 2<<30, 2<<30-(100<<20)) // only ~100 MiB free, below the 256 MiB floor
	ctx := context.Background()

	for i := 0; i < 12; i++ {
		clock = int64(i)*100 + 1000
		w.Tick(ctx)
	}
	if act.count() != 0 {
		t.Errorf("below the headroom floor the watcher must not act, but %d actions ran", act.count())
	}
}

// The semaphore being held elsewhere defers the action (never queues) and does not
// consume an attempt.
func TestWatcherSemaphoreBusyDefersNoAttempt(t *testing.T) {
	var snap *monitor.Snapshot
	var clock int64
	act := &fakeActioner{}
	w := newTestWatcher(t, &snap, &clock, act)
	snap = snapOf(downSvc(), 2<<30, 1<<30)
	ctx := context.Background()
	// Hold the docker-child semaphore so the gate's TryAcquire always fails.
	if !w.cfg.Sem.TryAcquire() {
		t.Fatal("could not pre-acquire the semaphore")
	}
	defer w.cfg.Sem.Release()

	for i := 0; i < 12; i++ {
		clock = int64(i)*100 + 1000
		w.Tick(ctx)
	}
	if act.count() != 0 {
		t.Errorf("a busy semaphore must defer (never run), but %d actions ran", act.count())
	}
	if w.fsms[Key{App: "shop", Service: "web"}].Attempts != 0 {
		t.Errorf("a deferred action must not consume an attempt, got %d", w.fsms[Key{App: "shop", Service: "web"}].Attempts)
	}
}

// Fail-closed: if the boot-time clear of stale expected_down leases fails, the
// watcher must REFUSE to start (rather than risk a stale lease silently suppressing
// a crash-loop page). Simulated by closing the DB so ClearAllExpectedDown errors.
func TestWatcherRefusesToStartIfLeaseClearFails(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.Close() // any store write/read now errors
	clock := int64(1000)
	w := New(Config{
		Store:    NewStore(db),
		Snap:     func() *monitor.Snapshot { return nil },
		Sem:      dockerexec.NewSemaphore(),
		Act:      &fakeActioner{},
		Policy:   testPolicy(),
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		Interval: time.Hour, // so a successful start would block, not return
		Now:      func() int64 { return clock },
	})
	done := make(chan struct{})
	go func() { w.Run(context.Background()); close(done) }()
	select {
	case <-done: // good: it returned without entering the ticker loop
	case <-time.After(2 * time.Second):
		t.Fatal("watcher must refuse to start when the boot lease-clear fails")
	}
}

// A service that recovers and holds healthy resolves back to HEALTHY.
func TestWatcherRecovers(t *testing.T) {
	var snap *monitor.Snapshot
	var clock int64
	act := &fakeActioner{}
	w := newTestWatcher(t, &snap, &clock, act)
	ctx := context.Background()
	key := Key{App: "shop", Service: "web"}

	// Fail, remediate once.
	snap = snapOf(downSvc(), 2<<30, 1<<30)
	for i := 0; i < 3; i++ {
		clock = int64(i)*100 + 1000
		w.Tick(ctx)
	}
	// Now healthy; hold it for the stabilization streak.
	snap = snapOf(upSvc(), 2<<30, 1<<30)
	for i := 3; i < 8; i++ {
		clock = int64(i)*100 + 1000
		w.Tick(ctx)
	}
	if w.fsms[key].Phase != Healthy || w.fsms[key].Attempts != 0 {
		t.Errorf("a recovered service should reset to clean HEALTHY, got %+v", w.fsms[key])
	}
}
