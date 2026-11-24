package servicelog

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type stampedLine struct {
	ts   time.Time
	text string
}

type streamCall struct {
	id    string
	tail  int
	since time.Time
}

// fakeStreamer plays scripted lines like Docker's logs endpoint: it applies since (inclusive) and
// tail to the backlog, then ends the stream (EOF) or, with hold, waits for the context.
type fakeStreamer struct {
	mu     sync.Mutex
	calls  []streamCall
	perID  map[string]int
	script func(id string, n int) (lines []stampedLine, hold bool)
	// exited, when set, is waited on after a held stream's context ends (a slow tailer exit).
	exited chan struct{}
	// afterCancel lines are delivered after a held stream's context ends, as the Docker client
	// flushes a buffered line when its stream is cut.
	afterCancel []stampedLine
}

func newFakeStreamer(script func(id string, n int) ([]stampedLine, bool)) *fakeStreamer {
	return &fakeStreamer{perID: map[string]int{}, script: script}
}

func (f *fakeStreamer) StreamLogsSince(ctx context.Context, id string, tail int, since time.Time, follow bool, onLine func(time.Time, string)) error {
	f.mu.Lock()
	n := f.perID[id]
	f.perID[id]++
	f.calls = append(f.calls, streamCall{id: id, tail: tail, since: since})
	exited := f.exited
	f.mu.Unlock()
	lines, hold := f.script(id, n)
	var backlog []stampedLine
	for _, l := range lines {
		if since.IsZero() || !l.ts.Before(since) {
			backlog = append(backlog, l)
		}
	}
	if len(backlog) > tail {
		backlog = backlog[len(backlog)-tail:]
	}
	for _, l := range backlog {
		onLine(l.ts, l.text)
	}
	if hold {
		<-ctx.Done()
		if len(f.afterCancel) > 0 {
			time.Sleep(50 * time.Millisecond) // a stream slow to wind down
		}
		for _, l := range f.afterCancel {
			onLine(l.ts, l.text)
		}
		if exited != nil && n == 0 {
			<-exited
		}
		return ctx.Err()
	}
	return nil
}

func (f *fakeStreamer) callsFor(id string) []streamCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []streamCall
	for _, c := range f.calls {
		if c.id == id {
			out = append(out, c)
		}
	}
	return out
}

// sinkRec records what the line sink receives.
type sinkRec struct {
	mu    sync.Mutex
	lines []Line
}

func (r *sinkRec) add(l Line) { r.mu.Lock(); r.lines = append(r.lines, l); r.mu.Unlock() }
func (r *sinkRec) get() []Line {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Line(nil), r.lines...)
}

// testManager builds a started Manager (root context and run start set, as Run does) without its
// reconcile loop, so a test drives reconcile itself.
func testManager(t *testing.T, store *Store, f *fakeStreamer, now func() time.Time) *Manager {
	t.Helper()
	m := NewManager(store, f, discard)
	m.now = now
	ctx, cancel := context.WithCancel(bg)
	t.Cleanup(func() { cancel(); waitIdle(t, m) })
	m.begin(ctx)
	return m
}

// waitIdle waits until no tailer is active (each scripted stream has ended).
func waitIdle(t *testing.T, m *Manager) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		m.mu.Lock()
		n := len(m.active)
		m.mu.Unlock()
		if n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d tailer(s) still active", n)
		}
		time.Sleep(time.Millisecond)
	}
}

const cid = "0123456789abcdef0123456789abcdef"

var shortCid = cid[:12]

func stamp(sec int64) time.Time { return time.Unix(1_700_000_000+sec, 0).UTC() }

// The sink sees every line a tailer reads, including the ones the store's per-service rate cap
// drops.
func TestSinkSeesLinesBeforeTheRateCap(t *testing.T) {
	c := &clock{t: 5000}
	store := newTestStore(t, t.TempDir(), c, nil)
	lines := make([]stampedLine, rateCapPerSec+100)
	for i := range lines {
		lines[i] = stampedLine{ts: stamp(1).Add(time.Duration(i)), text: "line " + strconv.Itoa(i)}
	}
	f := newFakeStreamer(func(string, int) ([]stampedLine, bool) { return lines, false })
	m := testManager(t, store, f, c.now)
	var rec sinkRec
	m.SetLineSink(rec.add)
	m.reconcile([]Target{{ContainerID: cid, App: "shop", Service: "api"}})
	waitIdle(t, m)

	got := rec.get()
	if len(got) != len(lines) {
		t.Fatalf("sink got %d lines, want all %d", len(got), len(lines))
	}
	if stored := search(store, "shop", "api"); len(stored) != rateCapPerSec {
		t.Errorf("store kept %d lines, want the rate cap %d", len(stored), rateCapPerSec)
	}
	l := got[7]
	if l.App != "shop" || l.Svc != "api" || l.Copy != shortCid || l.Text != "line 7" || l.At != 5000 || !l.TS.Equal(lines[7].ts) {
		t.Errorf("sink line: %+v", l)
	}
}

// With no store (service logs off) the tailers still run and feed the sink.
func TestNilStoreFeedsOnlyTheSink(t *testing.T) {
	f := newFakeStreamer(func(string, int) ([]stampedLine, bool) {
		return []stampedLine{{stamp(1), "hello"}, {stamp(2), "world"}}, false
	})
	at := func() time.Time { return stamp(0) }
	m := testManager(t, nil, f, at)
	var rec sinkRec
	m.SetLineSink(rec.add)
	m.reconcile([]Target{{ContainerID: cid, App: "shop", Service: "api"}})
	waitIdle(t, m)
	if got := rec.get(); len(got) != 2 || got[0].Text != "hello" || got[1].Text != "world" {
		t.Fatalf("sink: %+v", got)
	}
	// Without a sink either, lines are simply read and dropped.
	m2 := testManager(t, nil, f, at)
	m2.reconcile([]Target{{ContainerID: cid, App: "shop", Service: "api"}})
	waitIdle(t, m2)
}

// A container seen for the first time is attached from the manager's start, with a bounded
// backlog: a new container's first lines are kept, and a Mooring restart re-reads nothing it had.
func TestFirstAttachStartsAtRunStart(t *testing.T) {
	start := stamp(100)
	now := start
	var nowMu sync.Mutex
	clockNow := func() time.Time { nowMu.Lock(); defer nowMu.Unlock(); return now }
	f := newFakeStreamer(func(id string, n int) ([]stampedLine, bool) {
		// Output from before this run (already captured by the previous one) and after it.
		return []stampedLine{{stamp(10), "before the restart"}, {stamp(100), "at start"}, {stamp(130), "new container line"}}, false
	})
	m := testManager(t, nil, f, clockNow)
	var rec sinkRec
	m.SetLineSink(rec.add)
	nowMu.Lock()
	now = stamp(200) // the container is first seen well after the manager started
	nowMu.Unlock()
	m.reconcile([]Target{{ContainerID: cid, App: "shop", Service: "api"}})
	waitIdle(t, m)
	calls := f.callsFor(cid)
	if len(calls) != 1 || !calls[0].since.Equal(start) || calls[0].tail != backfillTail {
		t.Fatalf("first attach: %+v, want since=%v tail=%d", calls, start, backfillTail)
	}
	got := rec.get()
	if len(got) != 2 || got[0].Text != "at start" || got[1].Text != "new container line" {
		t.Errorf("lines: %+v", got)
	}
}

// A re-attach (the stream ended: the container restarted) starts at the last line's timestamp and
// skips the lines already emitted at that boundary; past the boundary nothing is skipped, even a
// line stamped earlier (a clock step).
func TestReattachSinceLastLineAndDedupe(t *testing.T) {
	f := newFakeStreamer(func(id string, n int) ([]stampedLine, bool) {
		if n == 0 {
			return []stampedLine{{stamp(1), "a"}, {stamp(2), "b"}, {stamp(3), "c"}}, false
		}
		// Docker drops b (before since) itself; c is at since and must be skipped here.
		return []stampedLine{{stamp(2), "b"}, {stamp(3), "c"}, {stamp(3), "c"}, {stamp(4), "d"}, {stamp(3), "after a clock step"}}, false
	})
	m := testManager(t, nil, f, func() time.Time { return stamp(0) })
	var rec sinkRec
	m.SetLineSink(rec.add)
	tg := []Target{{ContainerID: cid, App: "shop", Service: "api"}}
	m.reconcile(tg)
	waitIdle(t, m)
	m.reconcile(tg)
	waitIdle(t, m)

	calls := f.callsFor(cid)
	if len(calls) != 2 || !calls[1].since.Equal(stamp(3)) || calls[1].tail != backfillTail {
		t.Fatalf("re-attach: %+v, want since=%v tail=%d", calls, stamp(3), backfillTail)
	}
	var texts []string
	for _, l := range rec.get() {
		texts = append(texts, l.Text)
	}
	if want := "a,b,c,d,after a clock step"; strings.Join(texts, ",") != want {
		t.Errorf("lines %q, want %q", strings.Join(texts, ","), want)
	}
}

// A container that leaves the running set and comes back keeps its cursor; a cursor is forgotten
// once its container has been gone for cursorTTL.
func TestCursorKeptAcrossCancelAndPrunedAfterTTL(t *testing.T) {
	var mu sync.Mutex
	now := stamp(0)
	clockNow := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }
	f := newFakeStreamer(func(id string, n int) ([]stampedLine, bool) {
		return []stampedLine{{stamp(int64(10 + n)), "line " + strconv.Itoa(n)}}, true
	})
	m := testManager(t, nil, f, clockNow)
	tg := []Target{{ContainerID: cid, App: "shop", Service: "api"}}
	m.reconcile(tg)
	waitLines(t, f, cid, 1)
	waitCursor(t, m, cid, stamp(10))
	m.reconcile(nil) // stopped: the tailer is cancelled
	waitIdle(t, m)
	advance(time.Hour)
	m.reconcile(nil)
	m.reconcile(tg)
	waitLines(t, f, cid, 2)
	if calls := f.callsFor(cid); !calls[1].since.Equal(stamp(10)) {
		t.Fatalf("back in the running set: since %v, want the cursor %v", calls[1].since, stamp(10))
	}
	waitCursor(t, m, cid, stamp(11))

	m.reconcile(nil)
	waitIdle(t, m)
	advance(cursorTTL / 2)
	m.reconcile(nil)
	advance(cursorTTL/2 + time.Minute)
	m.reconcile(nil)
	m.mu.Lock()
	_, kept := m.cursors[cid]
	m.mu.Unlock()
	if kept {
		t.Fatal("a cursor gone for longer than cursorTTL must be forgotten")
	}
	m.reconcile(tg)
	waitLines(t, f, cid, 3)
	if calls := f.callsFor(cid); !calls[2].since.Equal(stamp(0)) {
		t.Errorf("after the TTL a container is attached as new (since the run start): %v", calls[2].since)
	}
}

// The cursor map is bounded: past maxCursors the longest-gone entries are forgotten first.
func TestCursorMapIsBounded(t *testing.T) {
	m := testManager(t, nil, newFakeStreamer(func(string, int) ([]stampedLine, bool) { return nil, false }), func() time.Time { return stamp(0) })
	m.mu.Lock()
	for i := 0; i < maxCursors+10; i++ {
		c := &cursor{gone: stamp(int64(i))}
		m.cursors["c"+strconv.Itoa(i)] = c
	}
	m.mu.Unlock()
	m.reconcile(nil)
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.cursors) != maxCursors {
		t.Fatalf("%d cursors kept, want %d", len(m.cursors), maxCursors)
	}
	if _, ok := m.cursors["c0"]; ok {
		t.Error("the longest-gone cursor must go first")
	}
	if _, ok := m.cursors["c"+strconv.Itoa(maxCursors+9)]; !ok {
		t.Error("the most recently gone cursor must be kept")
	}
}

// A cancelled tailer that exits late never removes or cancels the tailer that replaced it.
func TestLateTailerExitKeepsItsReplacement(t *testing.T) {
	f := newFakeStreamer(func(string, int) ([]stampedLine, bool) { return nil, true })
	f.exited = make(chan struct{})
	m := testManager(t, nil, f, func() time.Time { return stamp(0) })
	tg := []Target{{ContainerID: cid, App: "shop", Service: "api"}}
	m.reconcile(tg)
	waitLines(t, f, cid, 1)
	m.reconcile(nil) // cancels the first tailer; its stream is slow to return
	m.reconcile(tg)  // the replacement starts
	waitLines(t, f, cid, 2)
	close(f.exited) // now the first tailer exits
	time.Sleep(20 * time.Millisecond)
	m.mu.Lock()
	tl := m.active[cid]
	m.mu.Unlock()
	if tl == nil || tl.ctx.Err() != nil {
		t.Fatal("the late exit of a replaced tailer removed or cancelled its replacement")
	}
}

// Run starts the reconcile loop, stamps the run start and stops every tailer when ctx ends.
func TestRunAttachesAndStops(t *testing.T) {
	f := newFakeStreamer(func(string, int) ([]stampedLine, bool) { return []stampedLine{{stamp(5), "x"}}, true })
	m := NewManager(nil, f, discard)
	var rec sinkRec
	m.SetLineSink(rec.add)
	ctx, cancel := context.WithCancel(bg)
	done := make(chan struct{})
	before := time.Now()
	go func() {
		m.Run(ctx, 10*time.Millisecond, func() []Target { return []Target{{ContainerID: cid, App: "shop", Service: "api"}} })
		close(done)
	}()
	waitLines(t, f, cid, 1)
	if calls := f.callsFor(cid); calls[0].since.Before(before) || calls[0].since.After(time.Now()) {
		t.Errorf("since %v is not the run start", calls[0].since)
	}
	cancel()
	<-done
	waitIdle(t, m)
	if got := rec.get(); len(got) != 0 {
		// stamp(5) is long before the run start, so Docker (the fake) filters it out.
		t.Errorf("a line from before the run start was emitted: %+v", got)
	}
}

// TS is not part of the JSON form, so nothing that serializes a Line changes.
func TestLineTSNotSerialized(t *testing.T) {
	b, err := json.Marshal(Line{At: 1, App: "a", Svc: "s", Text: "t", TS: stamp(1)})
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `{"at":1,"app":"a","svc":"s","text":"t"}` {
		t.Errorf("json: %s", b)
	}
}

func waitLines(t *testing.T, f *fakeStreamer, id string, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(f.callsFor(id)) < n {
		if time.Now().After(deadline) {
			t.Fatalf("waited for %d stream call(s) for %s, got %d", n, id, len(f.callsFor(id)))
		}
		time.Sleep(time.Millisecond)
	}
}

func waitCursor(t *testing.T, m *Manager, id string, want time.Time) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		m.mu.Lock()
		c := m.cursors[id]
		m.mu.Unlock()
		if c != nil && c.last.Load() == want.UnixNano() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("cursor for %s never reached %v", id, want)
		}
		time.Sleep(time.Millisecond)
	}
}
