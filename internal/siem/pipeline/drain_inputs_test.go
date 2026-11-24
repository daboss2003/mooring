package pipeline

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/hostlog"
)

// recorder is a subscriber that keeps what it is handed.
type recorder struct {
	mu  sync.Mutex
	evs []siem.Event
}

func (r *recorder) sub(e siem.Event) { r.mu.Lock(); r.evs = append(r.evs, e); r.mu.Unlock() }

func (r *recorder) bySrc() map[string]int {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]int{}
	for _, e := range r.evs {
		out[e.Src]++
	}
	return out
}

func drainCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// DrainInputs hands everything queued in the main and audit lanes, and the batch Run holds, to the
// store and the subscribers before it returns: a subscriber that stops right after (detection) has
// seen every source event.
func TestDrainInputsDeliversQueued(t *testing.T) {
	rec := &recorder{}
	h := newHarness(t, 256, func(o *Options) { o.Subscribers = []func(siem.Event){rec.sub} })
	for i := 0; i < 200; i++ { // queued before Run starts: still in the lanes
		h.p.AppLine(1, "app", "svc", "c", "x")
	}
	for i := 0; i < 5; i++ {
		h.p.Audit(h.clk.Now(), audit.Event{Action: "login"})
	}
	h.run()
	h.settle() // all taken into Run's batch; none committed (the fake clock never reaches batchWait)
	if n := len(rec.bySrc()); n != 0 {
		t.Fatalf("subscribers saw events before the drain: %v", rec.bySrc())
	}
	for i := 0; i < 20; i++ { // and some still queued when the drain begins
		h.p.AppLine(1, "app", "svc", "c", "late")
		h.p.HostLine(hostlog.Line{Source: hostlog.SourceAuth, Text: "sshd", At: h.clk.Now()})
	}
	h.p.Audit(h.clk.Now(), audit.Event{Action: "logout"})
	if err := h.p.DrainInputs(drainCtx(t)); err != nil {
		t.Fatalf("DrainInputs: %v", err)
	}
	if got := rec.bySrc(); got[siem.SrcApp] != 220 || got[siem.SrcMooring] != 6 || got[siem.SrcHost] != 20 {
		t.Errorf("subscribers saw %v when DrainInputs returned, want 220 app, 6 mooring, 20 host", got)
	}
	stored := map[string]int{}
	for _, e := range h.st.events() {
		stored[e.Src]++
	}
	if stored[siem.SrcApp] != 220 || stored[siem.SrcMooring] != 6 || stored[siem.SrcHost] != 20 {
		t.Errorf("stored %v when DrainInputs returned, want every source event appended", stored)
	}
	if n, _ := h.p.Queue(); n != 0 {
		t.Errorf("%d items left in the source lanes", n)
	}
}

// After DrainInputs, source input is refused and counted as dropped (and reported at shutdown),
// while Emit still works until Run stops: the engine's last detections are stored.
func TestDrainInputsRefusesSourcesKeepsEmit(t *testing.T) {
	rec := &recorder{}
	h := newHarness(t, 64, func(o *Options) { o.Subscribers = []func(siem.Event){rec.sub} })
	h.run()
	if err := h.p.DrainInputs(drainCtx(t)); err != nil {
		t.Fatalf("DrainInputs: %v", err)
	}
	h.p.AppLine(1, "app", "svc", "c", "late")
	h.p.EdgeLine([]byte("GET /late"))
	h.p.HostLine(hostlog.Line{Source: hostlog.SourceAuth, Text: "sshd", At: h.clk.Now()})
	h.p.Audit(h.clk.Now(), audit.Event{Action: "login"})
	if n, _ := h.p.Queue(); n != 0 {
		t.Fatalf("%d source items queued after DrainInputs", n)
	}
	for _, src := range []string{siem.SrcApp, siem.SrcEdge, siem.SrcHost, siem.SrcMooring} {
		if s := source(h.p, src); s.Dropped != 1 || s.Events != 0 {
			t.Errorf("%s after DrainInputs: %+v, want the line refused and counted", src, s)
		}
	}
	for i := 0; i < 3; i++ {
		if !h.p.Emit(detection(i)) {
			t.Fatalf("Emit %d refused after DrainInputs", i)
		}
	}
	h.settleAll()
	h.advance(time.Second)
	if got := rec.bySrc(); got[siem.SrcSIEM] != 3 {
		t.Errorf("subscribers saw %v, want the 3 emitted events", got)
	}
	h.shutdown()
	if h.p.Emit(detection(9)) {
		t.Error("Emit took an event after Run stopped")
	}
	evs := h.st.events()
	emitted := 0
	for _, e := range evs {
		if e.Kind == "siem.detection" {
			emitted++
		}
	}
	if emitted != 3 {
		t.Errorf("stored %d emitted events, want 3", emitted)
	}
	if d := droppedEvents(evs); d[siem.SrcApp] != 1 || d[siem.SrcEdge] != 1 || d[siem.SrcHost] != 1 || d[siem.SrcMooring] != 1 {
		t.Errorf("drop reports at shutdown %v, want each refused line reported", d)
	}
}

// The drain is bounded by its budget: what it can't take in time is counted as dropped, so every
// line is either delivered or counted and nothing is left for later.
func TestDrainInputsIsBounded(t *testing.T) {
	h := newHarness(t, 1024, nil)
	h.p.drain = 100 * time.Millisecond
	slow := h.p.parse.app
	h.p.parse.app = func(at time.Time, app, svc, copy, text string) siem.Event {
		time.Sleep(2 * time.Millisecond)
		return slow(at, app, svc, copy, text)
	}
	pushApp(h, 1000, "x")
	h.run()
	began := time.Now()
	if err := h.p.DrainInputs(drainCtx(t)); err != nil {
		t.Fatalf("DrainInputs: %v", err)
	}
	if took := time.Since(began); took > time.Second {
		t.Errorf("DrainInputs took %v, over its budget", took)
	}
	app := source(h.p, siem.SrcApp)
	if app.Events+app.Dropped != 1000 || app.Dropped == 0 {
		t.Errorf("app: %d taken + %d dropped, want 1000 with some dropped", app.Events, app.Dropped)
	}
	if n, _ := h.p.Queue(); n != 0 || h.p.qBytes.Load() != 0 {
		t.Errorf("%d items (%d bytes) left in the queue", n, h.p.qBytes.Load())
	}
	// The ctx deadline bounds it too, when it is the earlier one: Run stops draining then as well,
	// so stopping right after takes no longer.
	h2 := newHarness(t, 1024, nil)
	h2.p.parse.app = h.p.parse.app
	pushApp(h2, 1000, "x")
	h2.run()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	began = time.Now()
	_ = h2.p.DrainInputs(ctx)
	h2.shutdown()
	if took := time.Since(began); took > time.Second {
		t.Errorf("DrainInputs and shutdown took %v: Run went on draining past the context's deadline", took)
	}
	if app := source(h2.p, siem.SrcApp); app.Events+app.Dropped != 1000 || app.Dropped == 0 {
		t.Errorf("ctx deadline: %d taken + %d dropped, want 1000 with some dropped", app.Events, app.Dropped)
	}
}

// A line past its check when the drain begins is waited for, so it is delivered before DrainInputs
// returns, never left behind.
func TestDrainInputsWaitsForLinesInFlight(t *testing.T) {
	rec := &recorder{}
	h := newHarness(t, 64, func(o *Options) { o.Subscribers = []func(siem.Event){rec.sub} })
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	h.p.enqueueHook = func() { once.Do(func() { close(entered); <-release }) }
	h.run()
	go h.p.AppLine(1, "app", "svc", "c", "in flight")
	<-entered
	done := make(chan error, 1)
	go func() { done <- h.p.DrainInputs(drainCtx(t)) }()
	select {
	case err := <-done:
		t.Fatalf("DrainInputs returned (%v) while a line was in flight", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("DrainInputs: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("DrainInputs did not return")
	}
	if got := rec.bySrc(); got[siem.SrcApp] != 1 {
		t.Errorf("subscribers saw %v, want the in-flight line", got)
	}
}

// DrainInputs never hangs: Run already returned, Run never started (its context ends it), a
// pipeline without a redactor, a nil pipeline.
func TestDrainInputsWithoutRun(t *testing.T) {
	h := newHarness(t, 64, nil)
	h.run()
	h.shutdown()
	if err := h.p.DrainInputs(drainCtx(t)); err != nil {
		t.Errorf("after Run returned: %v, want nil (its shutdown drained everything)", err)
	}

	h2 := newHarness(t, 64, nil)
	h2.p.AppLine(1, "app", "svc", "c", "x")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := h2.p.DrainInputs(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Run never started: %v, want the context's error", err)
	}

	p := New(Options{Log: discard}) // no redactor: Run collects nothing
	rctx, stop := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(rctx); close(done) }()
	began := time.Now()
	if err := p.DrainInputs(drainCtx(t)); err != nil || time.Since(began) > time.Second {
		t.Errorf("no redactor: %v after %v, want nil at once", err, time.Since(began))
	}
	stop()
	<-done

	var nilP *Pipeline
	if err := nilP.DrainInputs(context.Background()); err != nil {
		t.Errorf("nil pipeline: %v", err)
	}
}
