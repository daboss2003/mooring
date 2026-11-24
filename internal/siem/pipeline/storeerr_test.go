package pipeline

import (
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/store"
)

type logBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (l *logBuf) Write(p []byte) (int, error) { l.mu.Lock(); defer l.mu.Unlock(); return l.b.Write(p) }
func (l *logBuf) String() string              { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

func pushApp(h *harness, n int, prefix string) {
	for i := 0; i < n; i++ {
		h.p.AppLine(1, "app", "svc", "c", prefix+strconv.Itoa(i))
	}
}

func msgs(evs []siem.Event) string {
	var out []string
	for _, e := range evs {
		if e.Kind != siem.KindDropped {
			out = append(out, e.Msg)
		}
	}
	return strings.Join(out, ",")
}

func storeDrops(evs []siem.Event) map[string]float64 {
	out := map[string]float64{}
	for _, e := range evs {
		if e.Kind == siem.KindDropped && e.F["source"] == "store" {
			r, _ := e.F["reason"].(string)
			out[r] += e.F["count"].(float64)
		}
	}
	return out
}

// After a partial append only the events the store didn't take are retried, so nothing is stored
// twice.
func TestPartialAppendRetriesOnlyTheRest(t *testing.T) {
	h := newHarness(t, 64, nil)
	h.st.setErrs(&store.AppendError{Written: 2, Err: errors.New("short write")})
	h.run()
	pushApp(h, 5, "e")
	h.advance(time.Second) // 2 of 5 stored
	h.advance(time.Second) // the other 3 retried
	if got := msgs(h.st.events()); got != "e0,e1,e2,e3,e4" {
		t.Fatalf("stored %q, want each event once", got)
	}
	if _, _, calls := h.st.snapshot(); strings.Join(calls, " ") != "append:5 append:3 flush" {
		t.Errorf("store calls %v", calls)
	}

	// A partial append on the retry loses only what it didn't take.
	h.st.setErrs(&store.AppendError{Written: 1, Err: errors.New("short write")}, &store.AppendError{Written: 1, Err: errors.New("short write")})
	pushApp(h, 5, "f")
	h.advance(time.Second)
	h.advance(time.Second)
	if got := msgs(h.st.events()); got != "e0,e1,e2,e3,e4,f0,f1" {
		t.Fatalf("stored %q", got)
	}
	if n := h.p.lostErr.Load(); n != 3 {
		t.Errorf("lost after the retry: %d, want 3", n)
	}
	h.advance(time.Minute)
	h.advance(time.Second)
	if d := storeDrops(h.st.events()); d["error"] != 3 {
		t.Errorf("store drop report %v, want error:3", d)
	}
}

// A Written outside [0, len] from the store is clamped.
func TestAppendErrorWrittenIsClamped(t *testing.T) {
	h := newHarness(t, 64, nil)
	h.st.setErrs(&store.AppendError{Written: 99, Err: errors.New("x")}, &store.AppendError{Written: -3, Err: errors.New("x")})
	h.run()
	pushApp(h, 2, "a")
	h.advance(time.Second) // "all" written: nothing to retry
	pushApp(h, 2, "b")
	h.advance(time.Second) // none written: both retried
	h.advance(time.Second)
	_, _, calls := h.st.snapshot()
	var appends []string
	for _, c := range calls {
		if strings.HasPrefix(c, "append") {
			appends = append(appends, c)
		}
	}
	if strings.Join(appends, " ") != "append:2 append:2 append:2" {
		t.Errorf("store appends %v: Written 99 retries nothing, Written -3 retries both", appends)
	}
	if got := msgs(h.st.events()); got != "a0,a1,b0,b1" {
		t.Errorf("stored %q", got)
	}
}

// At the disk-pressure threshold a batch isn't retried: it is counted as lost for the disk, and the
// siem.dropped event that says so is stored once the store takes events again.
func TestDiskPressureIsNotRetried(t *testing.T) {
	var subs int
	var mu sync.Mutex
	h := newHarness(t, 64, func(o *Options) {
		o.Subscribers = []func(siem.Event){func(siem.Event) { mu.Lock(); subs++; mu.Unlock() }}
	})
	pressure := func(n int) []error {
		errs := make([]error, n)
		for i := range errs {
			errs[i] = store.ErrDiskPressure
		}
		return errs
	}
	h.st.setErrs(pressure(20)...)
	h.run()
	pushApp(h, 3, "lost")
	h.advance(time.Second)
	h.advance(time.Second)
	if _, _, calls := h.st.snapshot(); strings.Join(calls, " ") != "append:3" {
		t.Fatalf("a refused batch was retried: %v", calls)
	}
	if n := h.p.lostDisk.Load(); n != 3 {
		t.Fatalf("lost for the disk: %d, want 3", n)
	}
	// A minute passes while the disk still refuses: no drop event is stored or lost meanwhile.
	pushApp(h, 2, "lost")
	h.advance(time.Minute)
	h.advance(time.Second)
	if n := h.p.lostDisk.Load(); n != 5 {
		t.Fatalf("lost for the disk: %d, want 5 (the report itself must not count)", n)
	}
	if _, _, calls := h.st.snapshot(); strings.Join(calls, " ") != "append:3 append:2" {
		t.Fatalf("a drop report was sent to a store refusing events: %v", calls)
	}
	// The disk recovers: events are stored, then the report.
	h.st.setErrs()
	pushApp(h, 1, "back")
	h.advance(time.Second)
	h.advance(time.Minute)
	h.advance(time.Second)
	evs := h.st.events()
	if d := storeDrops(evs); d["disk"] != 5 || len(d) != 1 {
		t.Errorf("store drop report %v, want disk:5", d)
	}
	if got := msgs(evs); got != "back0" {
		t.Errorf("stored %q", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if subs < 6 {
		t.Errorf("subscribers saw %d events: a refused batch still reaches them", subs)
	}
}

// A drop report the store refuses is taken back, not counted as a loss: its counts are reported
// again once the store takes events.
func TestRefusedDropReportIsReportedAgain(t *testing.T) {
	h := newHarness(t, 64, nil)
	h.st.setErrs(store.ErrDiskPressure)
	h.run()
	pushApp(h, 3, "lost")
	h.advance(time.Second) // refused: 3 lost
	pushApp(h, 1, "ok")
	h.advance(time.Second) // stored: the disk allows again
	h.st.setErrs(store.ErrDiskPressure)
	h.advance(time.Minute) // the report (disk:3) is queued ...
	h.advance(time.Second) // ... and refused
	if n := h.p.lostDisk.Load(); n != 3 {
		t.Fatalf("lost for the disk: %d, want 3 (a refused report is not an event lost)", n)
	}
	pushApp(h, 1, "ok again")
	h.advance(time.Second)
	h.advance(time.Minute)
	h.advance(time.Second)
	if d := storeDrops(h.st.events()); d["disk"] != 3 {
		t.Errorf("store drop report %v, want disk:3 once the store takes events", d)
	}
}

// A partial append that stops at the disk threshold keeps what was written and doesn't retry.
func TestPartialAppendAtDiskPressure(t *testing.T) {
	h := newHarness(t, 64, nil)
	h.st.setErrs(&store.AppendError{Written: 2, Err: fmt.Errorf("segment: %w", store.ErrDiskPressure)})
	h.run()
	pushApp(h, 5, "e")
	h.advance(time.Second)
	h.advance(time.Second)
	if got := msgs(h.st.events()); got != "e0,e1" {
		t.Fatalf("stored %q", got)
	}
	if h.p.lostDisk.Load() != 3 || h.p.lostErr.Load() != 0 {
		t.Errorf("lost disk %d error %d, want 3 and 0", h.p.lostDisk.Load(), h.p.lostErr.Load())
	}
}

// Shutdown accounts for every line: those queued after the drain began are counted as dropped, as
// are lines handed in after Run returned, and one log line gives the counts.
func TestShutdownCountsEveryLine(t *testing.T) {
	var logs logBuf
	h := newHarness(t, 64, func(o *Options) { o.Log = slog.New(slog.NewTextHandler(&logs, nil)) })
	var calls int64
	var callsMu sync.Mutex
	refill := h.p.parse.app
	h.p.parse.app = func(at time.Time, app, svc, copy, text string) siem.Event {
		callsMu.Lock()
		calls++
		callsMu.Unlock()
		h.p.AppLine(1, "app", "svc", "c", "again") // a producer that never stops
		return refill(at, app, svc, copy, text)
	}
	pushApp(h, 64, "x")
	h.run()
	time.Sleep(20 * time.Millisecond)
	h.shutdown()
	h.p.AppLine(1, "app", "svc", "c", "after Run returned")
	h.p.EdgeLine([]byte("GET /late"))

	callsMu.Lock()
	defer callsMu.Unlock()
	app := source(h.p, siem.SrcApp)
	if handed := 64 + calls + 1; app.Events+app.Dropped != handed {
		t.Errorf("app: %d taken + %d dropped != %d handed in", app.Events, app.Dropped, handed)
	}
	if source(h.p, siem.SrcEdge).Dropped != 1 {
		t.Error("an edge line after Run returned must be counted as dropped")
	}
	if n, _ := h.p.Queue(); n != 0 {
		t.Errorf("%d items left in the queue after Run returned", n)
	}
	out := logs.String()
	if !strings.Contains(out, "security logs: stopped") || !strings.Contains(out, "dropped_app=") {
		t.Errorf("no shutdown line with counts: %s", out)
	}
}

// What the drain's time budget leaves in the queue is counted as dropped, not left behind.
func TestShutdownCountsWhatTheDrainLeft(t *testing.T) {
	h := newHarness(t, 1024, nil)
	h.p.drain = 50 * time.Millisecond
	slow := h.p.parse.app
	h.p.parse.app = func(at time.Time, app, svc, copy, text string) siem.Event {
		time.Sleep(2 * time.Millisecond)
		return slow(at, app, svc, copy, text)
	}
	pushApp(h, 1000, "x")
	h.run()
	h.shutdown()
	app := source(h.p, siem.SrcApp)
	if app.Events+app.Dropped != 1000 || app.Dropped == 0 {
		t.Errorf("app: %d taken + %d dropped, want 1000 with some dropped", app.Events, app.Dropped)
	}
	if n, _ := h.p.Queue(); n != 0 || h.p.qBytes.Load() != 0 {
		t.Errorf("%d items (%d bytes) left in the queue", n, h.p.qBytes.Load())
	}
}

// Losses from the final store attempt at shutdown are counted and logged.
func TestShutdownLogsFinalStoreLosses(t *testing.T) {
	var logs logBuf
	h := newHarness(t, 64, func(o *Options) { o.Log = slog.New(slog.NewTextHandler(&logs, nil)) })
	h.st.setFail(2)
	pushApp(h, 4, "x")
	h.run()
	h.shutdown()
	if n := h.p.lostErr.Load(); n != 4 {
		t.Fatalf("lost at shutdown: %d, want 4", n)
	}
	out := logs.String()
	if !strings.Contains(out, "security logs: stopped") || !strings.Contains(out, "lost_store_error=4") {
		t.Errorf("the shutdown line must give the store losses: %s", out)
	}
}

// A line handed in while shutdown begins (past the closing check, not yet queued) is waited for, so
// it is processed or counted, never left in the queue after Run returns.
func TestShutdownWaitsForLinesInFlight(t *testing.T) {
	for _, lane := range []string{"app", "audit"} {
		h := newHarness(t, 64, nil)
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		h.p.enqueueHook = func() {
			once.Do(func() { close(entered); <-release })
		}
		h.run()
		if lane == "app" {
			go h.p.AppLine(1, "app", "svc", "c", "in flight")
		} else {
			go h.p.Audit(h.clk.Now(), audit.Event{Action: "login"})
		}
		<-entered
		h.stop()
		select {
		case <-h.done:
			t.Fatalf("%s: Run returned while a line was in flight", lane)
		case <-time.After(50 * time.Millisecond):
		}
		close(release)
		select {
		case <-h.done:
		case <-time.After(10 * time.Second):
			t.Fatal("Run did not return")
		}
		h.stop = nil
		var s siem.SourceStatus
		if lane == "app" {
			s = source(h.p, siem.SrcApp)
		} else {
			s = source(h.p, siem.SrcMooring)
		}
		if s.Events+s.Dropped != 1 {
			t.Errorf("%s: the in-flight line: %d taken + %d dropped, want it accounted once", lane, s.Events, s.Dropped)
		}
		if n, _ := h.p.Queue(); n != 0 {
			t.Errorf("%s: %d items left in the queue after Run returned", lane, n)
		}
	}
}
