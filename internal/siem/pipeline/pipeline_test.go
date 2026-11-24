package pipeline

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/hostlog"
	"github.com/daboss2003/mooring/internal/siem/redact"
	"github.com/daboss2003/mooring/internal/siem/store"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// fakeStore records Append and Flush calls; failN makes the next failN Appends fail.
type fakeStore struct {
	mu      sync.Mutex
	appends [][]siem.Event
	flushes int
	calls   []string
	failN   int
	errs    []error   // returned by the next Appends, in order (an *store.AppendError stores its first Written)
	order   *[]string // shared call log with subscribers, when set
}

func (s *fakeStore) Append(evs []siem.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, "append:"+strconv.Itoa(len(evs)))
	if s.order != nil {
		*s.order = append(*s.order, "append")
	}
	if len(s.errs) > 0 {
		err := s.errs[0]
		s.errs = s.errs[1:]
		var ae *store.AppendError
		if errors.As(err, &ae) && ae.Written > 0 {
			s.appends = append(s.appends, append([]siem.Event(nil), evs[:min(ae.Written, len(evs))]...))
		}
		return err
	}
	if s.failN > 0 {
		s.failN--
		return errors.New("write failed")
	}
	s.appends = append(s.appends, append([]siem.Event(nil), evs...))
	return nil
}

func (s *fakeStore) setErrs(errs ...error) { s.mu.Lock(); s.errs = errs; s.mu.Unlock() }

func (s *fakeStore) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flushes++
	s.calls = append(s.calls, "flush")
	return nil
}

func (s *fakeStore) setFail(n int) { s.mu.Lock(); s.failN = n; s.mu.Unlock() }

func (s *fakeStore) snapshot() (appends [][]siem.Event, flushes int, calls []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]siem.Event(nil), s.appends...), s.flushes, append([]string(nil), s.calls...)
}

func (s *fakeStore) events() []siem.Event {
	a, _, _ := s.snapshot()
	var out []siem.Event
	for _, b := range a {
		out = append(out, b...)
	}
	return out
}

// testParsers are deterministic stand-ins for package parse, so these tests pin the pipeline and
// not the parsers.
func testParsers() parsers {
	host := func(name string) func(string, time.Time, *time.Location) (siem.Event, bool) {
		return func(line string, now time.Time, loc *time.Location) (siem.Event, bool) {
			if line == "" {
				return siem.Event{}, false
			}
			return siem.Event{TS: now, Src: siem.SrcHost, Msg: line, F: map[string]any{"parser": name, "loc": loc.String()}}, true
		}
	}
	return parsers{
		app: func(at time.Time, app, svc, copy, text string) siem.Event {
			return siem.Event{TS: at, Src: siem.SrcApp, App: app, Svc: svc, Copy: copy, Msg: text}
		},
		edge: func(raw []byte, now time.Time) (siem.Event, bool) {
			if !bytes.HasPrefix(raw, []byte("GET")) && !bytes.HasPrefix(raw, []byte("XET")) {
				return siem.Event{}, false
			}
			return siem.Event{TS: now, Src: siem.SrcEdge, Kind: siem.KindHTTPRequest, Msg: string(raw)}, true
		},
		audit: func(ts time.Time, ev audit.Event) siem.Event {
			return siem.Event{TS: ts, Src: siem.SrcMooring, Kind: siem.KindMooringPrefix + ev.Action, Actor: ev.Actor}
		},
		auth: host("auth"),
		f2b:  host("fail2ban"),
		journal: func(raw []byte) (siem.Event, bool) {
			return siem.Event{Src: siem.SrcHost, Msg: string(raw), F: map[string]any{"parser": "journal"}}, true
		},
	}
}

type harness struct {
	t     *testing.T
	p     *Pipeline
	st    *fakeStore
	clk   *fakeClock
	tick  chan time.Time
	stop  context.CancelFunc
	done  chan struct{}
	start time.Time
}

func newHarness(t *testing.T, queue int, mod func(*Options)) *harness {
	t.Helper()
	clk := &fakeClock{t: time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)}
	opt := Options{QueueSize: queue, Now: clk.Now, Log: discard}
	if mod != nil {
		mod(&opt)
	}
	p := New(opt)
	st := &fakeStore{}
	p.st = st
	p.redact = func(*siem.Event) {}
	p.parse = testParsers()
	h := &harness{t: t, p: p, st: st, clk: clk, tick: make(chan time.Time), start: clk.Now()}
	p.tick = h.tick
	t.Cleanup(func() {
		if h.stop != nil {
			h.stop()
			<-h.done
		}
	})
	return h
}

func (h *harness) run() {
	ctx, cancel := context.WithCancel(context.Background())
	h.stop, h.done = cancel, make(chan struct{})
	go func() { h.p.Run(ctx); close(h.done) }()
}

// shutdown cancels Run and waits for it to return.
func (h *harness) shutdown() {
	h.t.Helper()
	h.stop()
	select {
	case <-h.done:
	case <-time.After(10 * time.Second):
		h.t.Fatal("Run did not return after its context ended")
	}
	h.stop = nil
}

// settle waits until both lanes are empty and then until Run has handled a tick at the current
// (fake) time: everything queued is processed and every timer due now has run.
func (h *harness) settle() {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(h.p.q)+len(h.p.aq) > 0 {
		if time.Now().After(deadline) {
			h.t.Fatal("queue never drained")
		}
		time.Sleep(100 * time.Microsecond)
	}
	// Run is one goroutine: the second send is received only after the first tick was handled.
	h.tick <- h.clk.Now()
	h.tick <- h.clk.Now()
}

// advance processes what is queued at the current time, then moves the clock and settles again.
func (h *harness) advance(d time.Duration) {
	h.settle()
	h.clk.Advance(d)
	h.settle()
}

func source(p *Pipeline, name string) siem.SourceStatus {
	for _, s := range p.Sources() {
		if s.Name == name {
			return s
		}
	}
	return siem.SourceStatus{}
}

func droppedEvents(evs []siem.Event) map[string]float64 {
	out := map[string]float64{}
	for _, e := range evs {
		if e.Kind == siem.KindDropped {
			out[e.F["source"].(string)] += e.F["count"].(float64)
		}
	}
	return out
}

// Input methods never block, whatever the load: a full queue drops and counts.
func TestInputsNeverBlock(t *testing.T) {
	for _, running := range []bool{false, true} {
		h := newHarness(t, 64, nil)
		if running {
			h.run()
		}
		const producers, each = 8, 3000
		var wg sync.WaitGroup
		finished := make(chan struct{})
		for w := 0; w < producers; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				buf := []byte("GET /x")
				for i := 0; i < each; i++ {
					h.p.AppLine(int64(i), "app", "svc", "c", "line")
					h.p.EdgeLine(buf)
					h.p.HostLine(hostlog.Line{Source: hostlog.SourceAuth, Text: "sshd", At: h.clk.Now()})
					if i%3 == 0 {
						h.p.Audit(h.clk.Now(), audit.Event{Action: "login"})
					}
				}
			}(w)
		}
		go func() { wg.Wait(); close(finished) }()
		select {
		case <-finished:
		case <-time.After(10 * time.Second):
			t.Fatalf("running=%v: producers blocked on a full queue", running)
		}
		if running {
			h.shutdown()
			produced := int64(producers * each)
			got := map[string]int64{}
			for _, e := range h.st.events() {
				got[e.Src]++
			}
			for _, src := range []string{siem.SrcApp, siem.SrcEdge, siem.SrcHost} {
				if s := source(h.p, src); s.Events+s.Dropped != produced || got[src] != s.Events {
					t.Errorf("running %s: events %d + dropped %d != produced %d (stored %d)", src, s.Events, s.Dropped, produced, got[src])
				}
			}
			continue
		}
		queued, capacity := h.p.Queue()
		if capacity != 64+auditLaneSize || queued != capacity {
			t.Errorf("Queue() = %d/%d, want a full %d", queued, capacity, 64+auditLaneSize)
		}
		var dropped int64
		for _, src := range []string{siem.SrcApp, siem.SrcEdge, siem.SrcHost} {
			dropped += source(h.p, src).Dropped
		}
		if want := int64(3*producers*each - 64); dropped != want {
			t.Errorf("dropped %d app+edge+host lines, want %d", dropped, want)
		}
		if got, want := source(h.p, siem.SrcMooring).Dropped, int64(producers*(each/3)-auditLaneSize); got != want {
			t.Errorf("dropped %d audit events, want %d", got, want)
		}
	}
}

// Every minute with drops, one siem.dropped event per source reports how many were dropped since
// the last report.
func TestDroppedEventsPerSource(t *testing.T) {
	h := newHarness(t, 4, nil)
	for i := 0; i < 10; i++ {
		h.p.AppLine(1, "app", "svc", "c", "x")
	}
	h.p.EdgeLine([]byte("GET /a"))
	h.p.EdgeLine([]byte("GET /b"))
	h.p.EdgeLine([]byte("GET /c"))
	h.p.HostLine(hostlog.Line{Source: hostlog.SourceAuth, Text: "a"})
	h.p.HostLine(hostlog.Line{Source: hostlog.SourceAuth, Text: "b"})
	for i := 0; i < auditLaneSize+6; i++ {
		h.p.Audit(h.clk.Now(), audit.Event{Action: "x"})
	}
	h.run()
	h.settle()
	h.advance(59 * time.Second)
	if d := droppedEvents(h.st.events()); len(d) != 0 {
		t.Fatalf("a drop report before a minute passed: %v", d)
	}
	h.advance(time.Second) // the report
	h.advance(time.Second) // its batch is stored
	want := map[string]float64{siem.SrcApp: 6, siem.SrcEdge: 3, siem.SrcHost: 2, siem.SrcMooring: 6}
	d := droppedEvents(h.st.events())
	if len(d) != len(want) {
		t.Fatalf("drop report %v, want %v", d, want)
	}
	for k, v := range want {
		if d[k] != v {
			t.Errorf("source %s: reported %v dropped, want %v", k, d[k], v)
		}
	}
	for _, e := range h.st.events() {
		if e.Kind == siem.KindDropped && (e.Src != siem.SrcSIEM || e.Lvl != siem.LvlWarn || e.V != siem.SchemaVersion) {
			t.Errorf("drop event shape: %+v", e)
		}
	}

	// A minute without drops reports nothing; the next report counts only the new drops.
	h.advance(61 * time.Second)
	h.advance(time.Second)
	if got := len(h.st.events()); droppedEvents(h.st.events())[siem.SrcEdge] != 3 {
		t.Fatalf("a quiet minute added drop events (%d events)", got)
	}
	h.p.EdgeLine(make([]byte, maxEdgeLine+1))
	h.advance(61 * time.Second)
	h.advance(time.Second)
	if d := droppedEvents(h.st.events()); d[siem.SrcEdge] != 4 || d[siem.SrcApp] != 6 {
		t.Errorf("the second report must count only new drops: %v", d)
	}
}

// Mooring audit events have their own lane: an app flood can't drop them, and they are taken first.
func TestAuditLaneSurvivesAppFlood(t *testing.T) {
	h := newHarness(t, 8, nil)
	for i := 0; i < 1000; i++ {
		h.p.AppLine(1, "app", "svc", "c", "flood")
	}
	for i := 0; i < 20; i++ {
		h.p.Audit(h.clk.Now(), audit.Event{Action: "login", Actor: "a" + strconv.Itoa(i)})
	}
	if d := source(h.p, siem.SrcMooring).Dropped; d != 0 {
		t.Fatalf("%d audit events dropped under an app flood", d)
	}
	h.run()
	h.advance(time.Second)
	evs := h.st.events()
	if len(evs) != 28 {
		t.Fatalf("stored %d events, want 20 audit + 8 app", len(evs))
	}
	for i := 0; i < 20; i++ {
		if evs[i].Src != siem.SrcMooring {
			t.Fatalf("event %d is %s: audit events must be taken before queued app lines", i, evs[i].Src)
		}
	}
}

// Taking audit events first is bounded: under a flood of them the main lane still gets turns.
func TestAuditPriorityIsBounded(t *testing.T) {
	h := newHarness(t, 8, nil)
	for i := 0; i < auditLaneSize; i++ {
		h.p.Audit(h.clk.Now(), audit.Event{Action: "login_failed"})
	}
	for i := 0; i < 8; i++ {
		h.p.AppLine(1, "app", "svc", "c", "x")
	}
	h.run()
	h.advance(time.Second)
	evs := h.st.events()
	if len(evs) != auditLaneSize+8 {
		t.Fatalf("stored %d events", len(evs))
	}
	firstApp, lastAudit := -1, -1
	for i, e := range evs {
		if e.Src == siem.SrcApp && firstApp < 0 {
			firstApp = i
		}
		if e.Src == siem.SrcMooring {
			lastAudit = i
		}
	}
	if firstApp < 64 || firstApp > lastAudit {
		t.Errorf("first app event at %d, last audit event at %d: the main lane must get a turn after each 64 audit events", firstApp, lastAudit)
	}
}

// A batch is stored at 512 events at once, or after 1 s.
func TestBatchBySizeAndTime(t *testing.T) {
	h := newHarness(t, 1024, nil)
	h.run()
	for i := 0; i < 511; i++ {
		h.p.AppLine(1, "app", "svc", "c", "x")
	}
	h.settle()
	if _, _, calls := h.st.snapshot(); len(calls) != 0 {
		t.Fatalf("stored before the batch was full or due: %v", calls)
	}
	h.p.AppLine(1, "app", "svc", "c", "x")
	h.settle()
	if a, _, _ := h.st.snapshot(); len(a) != 1 || len(a[0]) != 512 {
		t.Fatalf("a full batch must be stored at once: %d appends", len(a))
	}

	for i := 0; i < 3; i++ {
		h.p.AppLine(1, "app", "svc", "c", "y")
	}
	h.settle()
	h.advance(999 * time.Millisecond)
	if a, _, _ := h.st.snapshot(); len(a) != 1 {
		t.Fatal("a partial batch was stored before 1s")
	}
	h.advance(time.Millisecond)
	if a, _, _ := h.st.snapshot(); len(a) != 2 || len(a[1]) != 3 {
		t.Fatalf("a partial batch must be stored after 1s: %d appends", len(a))
	}
}

// Flush follows new appends at most every 2 s, and not at all when nothing new was appended.
func TestFlushCadence(t *testing.T) {
	h := newHarness(t, 64, nil)
	h.run()
	h.p.AppLine(1, "app", "svc", "c", "x")
	h.settle()
	h.advance(time.Second) // appended at +1s; the last flush (start) is only 1s old
	if _, f, calls := h.st.snapshot(); f != 0 || len(calls) != 1 {
		t.Fatalf("flushed too early: %v", calls)
	}
	h.advance(time.Second) // +2s
	if _, f, _ := h.st.snapshot(); f != 1 {
		t.Fatalf("flushes at +2s: %d, want 1", f)
	}
	h.advance(10 * time.Second)
	if _, f, _ := h.st.snapshot(); f != 1 {
		t.Fatalf("flushed with nothing new appended: %d", f)
	}
	// After a quiet spell a new append is flushed in the same tick.
	h.p.AppLine(1, "app", "svc", "c", "y")
	h.settle()
	h.advance(time.Second)
	if _, f, calls := h.st.snapshot(); f != 2 || calls[len(calls)-1] != "flush" {
		t.Fatalf("after a quiet spell: %v", calls)
	}
	// Under a steady flow, no more than one flush per 2 s.
	for i := 0; i < 8; i++ {
		h.p.AppLine(1, "app", "svc", "c", "z")
		h.settle()
		h.advance(time.Second)
	}
	if _, f, _ := h.st.snapshot(); f != 2+4 {
		t.Errorf("8 s of steady appends: %d flushes in total, want 6", f)
	}
}

// Subscribers see every event once, redacted, after it was handed to the store.
func TestSubscribersSeeRedactedEventsAfterAppend(t *testing.T) {
	var order []string
	var mu sync.Mutex
	var got []siem.Event
	h := newHarness(t, 64, func(o *Options) {
		o.Subscribers = []func(siem.Event){func(e siem.Event) {
			mu.Lock()
			defer mu.Unlock()
			order = append(order, "sub")
			got = append(got, e)
		}}
	})
	h.st.order = &order
	h.p.redact = func(e *siem.Event) { e.Msg = strings.ReplaceAll(e.Msg, "hunter2", "[redacted]") }
	h.run()
	h.p.AppLine(1, "app", "svc", "c", "password=hunter2")
	h.advance(time.Second)
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 || got[0].Msg != "password=[redacted]" {
		t.Fatalf("subscriber saw %+v", got)
	}
	if evs := h.st.events(); len(evs) != 1 || evs[0].Msg != "password=[redacted]" {
		t.Fatalf("store got %+v", evs)
	}
	if strings.Join(order, ",") != "append,sub" {
		t.Errorf("order %v: subscribers must run after the store append", order)
	}
}

// Events are normalized before redaction and again after it, so what is stored keeps the bounds.
func TestNormalizedBeforeAndAfterRedaction(t *testing.T) {
	h := newHarness(t, 64, nil)
	var sawMsg int
	h.p.redact = func(e *siem.Event) {
		sawMsg = len(e.Msg)
		e.Msg = strings.Repeat("[REDACTED]", siem.MaxMsg)
	}
	h.run()
	h.p.AppLine(1, "app", "svc", "c", strings.Repeat("y ", 2*siem.MaxMsg))
	h.advance(time.Second)
	evs := h.st.events()
	if len(evs) != 1 || len(evs[0].Msg) > siem.MaxMsg {
		t.Fatalf("stored Msg of %d bytes, over %d", len(evs[0].Msg), siem.MaxMsg)
	}
	if sawMsg > siem.MaxMsg+cutSlack || sawMsg < siem.MaxMsg {
		t.Errorf("the redactor saw a Msg of %d bytes, want it bounded at %d + %d", sawMsg, siem.MaxMsg, cutSlack)
	}
	if evs[0].Lvl != siem.LvlInfo || evs[0].V != siem.SchemaVersion {
		t.Errorf("the stored event is normalized: %+v", evs[0])
	}
}

// A parser or redactor panic loses only that event; it is counted.
func TestParserPanicRecovered(t *testing.T) {
	h := newHarness(t, 64, nil)
	base := h.p.parse.app
	h.p.parse.app = func(at time.Time, app, svc, copy, text string) siem.Event {
		if text == "boom" {
			var m map[string]int
			m["x"]++ // a nil-map write: a runtime panic
		}
		return base(at, app, svc, copy, text)
	}
	h.p.redact = func(e *siem.Event) {
		if e.Msg == "redactor boom" {
			panic("redactor bug")
		}
	}
	h.run()
	for _, s := range []string{"a", "boom", "b", "redactor boom", "c"} {
		h.p.AppLine(1, "app", "svc", "c", s)
	}
	h.advance(time.Second)
	var msgs []string
	for _, e := range h.st.events() {
		msgs = append(msgs, e.Msg)
	}
	if strings.Join(msgs, ",") != "a,b,c" {
		t.Fatalf("stored %v, want a,b,c", msgs)
	}
	if n := h.p.panics.Load(); n != 2 {
		t.Errorf("panics counted: %d, want 2", n)
	}
	if s := source(h.p, siem.SrcApp); s.Dropped != 2 || s.Events != 3 {
		t.Errorf("app source: %+v", s)
	}
}

// A subscriber panic is recovered too: the pipeline and the other subscribers carry on.
func TestSubscriberPanicRecovered(t *testing.T) {
	var n int
	var mu sync.Mutex
	h := newHarness(t, 64, func(o *Options) {
		o.Subscribers = []func(siem.Event){
			func(siem.Event) { panic("subscriber bug") },
			func(siem.Event) { mu.Lock(); n++; mu.Unlock() },
		}
	})
	h.run()
	h.p.AppLine(1, "app", "svc", "c", "a")
	h.p.AppLine(1, "app", "svc", "c", "b")
	h.advance(time.Second)
	mu.Lock()
	defer mu.Unlock()
	if n != 2 || len(h.st.events()) != 2 {
		t.Fatalf("after a subscriber panic: second subscriber saw %d, store has %d", n, len(h.st.events()))
	}
}

// On shutdown Run drains what is queued, stores it and flushes last.
func TestShutdownDrains(t *testing.T) {
	h := newHarness(t, 256, nil)
	for i := 0; i < 200; i++ {
		h.p.AppLine(1, "app", "svc", "c", "x"+strconv.Itoa(i))
	}
	for i := 0; i < 5; i++ {
		h.p.Audit(h.clk.Now(), audit.Event{Action: "logout"})
	}
	h.p.AppLine(1, "app", "svc", "c", "overflow") // a pending drop count is reported too
	for i := 0; i < 60; i++ {
		h.p.AppLine(1, "app", "svc", "c", "overflow")
	}
	h.run()
	h.shutdown()
	evs := h.st.events()
	var app, mooring int
	for _, e := range evs {
		switch e.Src {
		case siem.SrcApp:
			app++
		case siem.SrcMooring:
			mooring++
		}
	}
	if app != 256 || mooring != 5 {
		t.Errorf("drained %d app + %d audit events, want 256 + 5", app, mooring)
	}
	if d := droppedEvents(evs); d[siem.SrcApp] != 5 {
		t.Errorf("the drop count at shutdown must be stored: %v", d)
	}
	if _, _, calls := h.st.snapshot(); calls[len(calls)-1] != "flush" {
		t.Errorf("the last store call must be a flush: %v", calls)
	}
}

// The shutdown drain is bounded: producers that never stop can't keep Run from returning.
func TestShutdownDrainIsBounded(t *testing.T) {
	h := newHarness(t, 64, nil)
	// A producer that never stops: every line taken puts a new one in the queue, so the queue never
	// empties by itself.
	refill := h.p.parse.app
	h.p.parse.app = func(at time.Time, app, svc, copy, text string) siem.Event {
		h.p.AppLine(1, "app", "svc", "c", "again")
		return refill(at, app, svc, copy, text)
	}
	for i := 0; i < 64; i++ {
		h.p.AppLine(1, "app", "svc", "c", "x")
	}
	h.run()
	time.Sleep(20 * time.Millisecond)
	began := time.Now()
	h.shutdown()
	if took := time.Since(began); took > 2*time.Second {
		t.Errorf("shutdown took %v with a producer still running: the drain must take only what was queued", took)
	}

	// The drain also stops at its time budget when items are slow to process.
	h2 := newHarness(t, 1024, nil)
	h2.p.drain = 100 * time.Millisecond
	base := h2.p.parse.app
	h2.p.parse.app = func(at time.Time, app, svc, copy, text string) siem.Event {
		time.Sleep(2 * time.Millisecond)
		return base(at, app, svc, copy, text)
	}
	for i := 0; i < 1000; i++ {
		h2.p.AppLine(1, "app", "svc", "c", "slow")
	}
	h2.run()
	began = time.Now()
	h2.shutdown()
	if took := time.Since(began); took > time.Second {
		t.Errorf("shutdown took %v, over its drain budget", took)
	}
	if n := len(h2.st.events()); n >= 1000 {
		t.Errorf("all %d slow items were drained past the budget", n)
	}
}

// A failed append is retried once with the next store attempt, then dropped and counted; the
// subscribers see each event exactly once either way.
func TestStoreErrorRetriedOnceThenDropped(t *testing.T) {
	var subs int
	var mu sync.Mutex
	h := newHarness(t, 64, func(o *Options) {
		o.Subscribers = []func(siem.Event){func(siem.Event) { mu.Lock(); subs++; mu.Unlock() }}
	})
	h.run()
	h.st.setFail(1)
	h.p.AppLine(1, "app", "svc", "c", "first")
	h.settle()
	h.advance(time.Second) // fails
	if evs := h.st.events(); len(evs) != 0 {
		t.Fatalf("stored after a failure: %+v", evs)
	}
	h.advance(time.Second) // retried, works
	if evs := h.st.events(); len(evs) != 1 || evs[0].Msg != "first" {
		t.Fatalf("the failed batch must be retried: %+v", evs)
	}

	h.st.setFail(2)
	h.p.AppLine(1, "app", "svc", "c", "second")
	h.settle()
	h.advance(time.Second) // fails
	h.advance(time.Second) // the retry fails: dropped
	h.advance(time.Second)
	if n := h.p.lostErr.Load(); n != 1 {
		t.Fatalf("store-lost counter: %d, want 1", n)
	}
	for _, e := range h.st.events() {
		if e.Msg == "second" {
			t.Fatal("an event dropped after its retry was stored")
		}
	}
	h.advance(time.Minute)
	h.advance(time.Second)
	if d := droppedEvents(h.st.events()); d["store"] != 1 {
		t.Errorf("events the store lost must be reported: %v", d)
	}
	mu.Lock()
	defer mu.Unlock()
	if subs != 2+1 { // first, second, and the drop report
		t.Errorf("subscriber calls: %d, want 3 (each event once)", subs)
	}
}

// An edge line is copied (the caller reuses its buffer) and one over 1 MiB is dropped and counted.
func TestEdgeLineIsCopiedAndBounded(t *testing.T) {
	h := newHarness(t, 64, nil)
	buf := []byte("GET /a")
	h.p.EdgeLine(buf)
	buf[0] = 'X'
	h.p.EdgeLine(make([]byte, maxEdgeLine+1))
	big := append([]byte("GET "), bytes.Repeat([]byte("z"), maxEdgeLine-4)...)
	h.p.EdgeLine(big)
	h.p.EdgeLine([]byte("not an access log line"))
	h.run()
	h.advance(time.Second)
	evs := h.st.events()
	if len(evs) != 2 || evs[0].Msg != "GET /a" || !strings.HasPrefix(evs[1].Msg, "GET") || len(evs[1].Msg) > siem.MaxMsg {
		t.Fatalf("edge events: %d", len(evs))
	}
	if s := source(h.p, siem.SrcEdge); s.Dropped != 1 || s.Events != 2 {
		t.Errorf("edge source: %+v", s)
	}
}

// The bytes held in the queue are bounded too: past the budget a line is dropped even when the
// queue has free slots, and the budget is given back as lines are taken.
func TestQueueByteBudget(t *testing.T) {
	h := newHarness(t, 64, nil)
	h.p.maxBytes = 1000
	line := strings.Repeat("q", 300)
	for i := 0; i < 4; i++ {
		h.p.AppLine(1, "app", "svc", "", line)
	}
	if s := source(h.p, siem.SrcApp); s.Dropped != 1 {
		t.Fatalf("over the byte budget: %d dropped, want 1", s.Dropped)
	}
	h.run()
	h.settle()
	for i := 0; i < 3; i++ {
		h.p.AppLine(1, "app", "svc", "", line)
	}
	h.settle()
	if s := source(h.p, siem.SrcApp); s.Dropped != 1 || s.Events != 6 {
		t.Errorf("the budget must be released as lines are taken: %+v", s)
	}
	if n := h.p.qBytes.Load(); n != 0 {
		t.Errorf("%d bytes still reserved with an empty queue", n)
	}
}

// Host lines go to their source's parser, with the host's time zone; an unknown source is dropped.
func TestHostLinesByParserAndLocation(t *testing.T) {
	loc := time.FixedZone("WAT", 3600)
	h := newHarness(t, 64, func(o *Options) { o.HostLoc = loc })
	read := h.clk.Now().Add(-time.Minute)
	h.p.HostLine(hostlog.Line{Source: hostlog.SourceAuth, Text: "sshd line", At: read})
	h.p.HostLine(hostlog.Line{Source: hostlog.SourceFail2Ban, Text: "ban line", At: read})
	h.p.HostLine(hostlog.Line{Source: hostlog.SourceJournal, Text: `{"MESSAGE":"x"}`, At: read})
	h.p.HostLine(hostlog.Line{Source: "mystery", Text: "?", At: read})
	h.run()
	h.advance(time.Second)
	evs := h.st.events()
	if len(evs) != 3 {
		t.Fatalf("host events: %+v", evs)
	}
	for i, want := range []string{"auth", "fail2ban", "journal"} {
		if evs[i].F["parser"] != want {
			t.Errorf("event %d went to %v, want %s", i, evs[i].F["parser"], want)
		}
	}
	if evs[0].F["loc"] != "WAT" || evs[1].F["loc"] != "WAT" || !evs[0].TS.Equal(read) {
		t.Errorf("syslog parsers get HostLoc and the read time: %+v", evs[:2])
	}
	if s := source(h.p, siem.SrcHost); s.Dropped != 1 || s.Events != 3 {
		t.Errorf("host source: %+v", s)
	}
	// HostLoc defaults to the local zone.
	if p := New(Options{}); p.loc != time.Local {
		t.Errorf("default HostLoc: %v", p.loc)
	}
}

// Sources reports the four sources with their counters; Queue the waiting events and capacity.
func TestSourcesAndQueue(t *testing.T) {
	h := newHarness(t, 16, nil)
	h.p.AppLine(1, "app", "svc", "c", "x")
	h.p.Audit(h.clk.Now(), audit.Event{Action: "login"})
	if n, c := h.p.Queue(); n != 2 || c != 16+auditLaneSize {
		t.Errorf("Queue() = %d/%d", n, c)
	}
	h.run()
	h.settle()
	var names []string
	for _, s := range h.p.Sources() {
		names = append(names, s.Name)
		if !s.OK {
			t.Errorf("%s not OK", s.Name)
		}
	}
	if strings.Join(names, ",") != "app,edge,mooring,host" {
		t.Errorf("sources %v", names)
	}
	if s := source(h.p, siem.SrcApp); s.Events != 1 || !s.LastSeen.Equal(h.clk.Now()) {
		t.Errorf("app: %+v", s)
	}
	if s := source(h.p, siem.SrcEdge); s.Events != 0 || !s.LastSeen.IsZero() {
		t.Errorf("edge: %+v", s)
	}
	if n, _ := h.p.Queue(); n != 0 {
		t.Errorf("queue not empty: %d", n)
	}
}

// Without a redactor nothing is stored (fail closed).
func TestNoRedactorStoresNothing(t *testing.T) {
	h := newHarness(t, 16, nil)
	h.p.redact = nil
	h.run()
	h.p.AppLine(1, "app", "svc", "c", "token=abc")
	time.Sleep(20 * time.Millisecond)
	h.shutdown()
	if _, _, calls := h.st.snapshot(); len(calls) != 0 {
		t.Fatalf("stored without a redactor: %v", calls)
	}
}

// The real parsers and redactor are the defaults (their documented basics only).
func TestDefaultParsersAndRedactor(t *testing.T) {
	key := bytes.Repeat([]byte{7}, 32)
	r, err := redact.New(key, redact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	p := New(Options{Redactor: r, Log: discard})
	st := &fakeStore{}
	p.st = st
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { p.Run(ctx); close(done) }()
	ts := time.Date(2026, 11, 23, 9, 0, 0, 0, time.UTC)
	p.AppLine(ts.Unix(), "shop", "api", "0123456789ab", "plain text line")
	p.Audit(ts, audit.Event{Action: "login", Actor: "owner"})
	cancel()
	<-done
	evs := st.events()
	if len(evs) != 2 {
		t.Fatalf("events: %+v", evs)
	}
	var app, moor siem.Event
	for _, e := range evs {
		switch e.Src {
		case siem.SrcApp:
			app = e
		case siem.SrcMooring:
			moor = e
		}
	}
	if app.App != "shop" || app.Svc != "api" || app.Copy != "0123456789ab" || app.Msg != "plain text line" || !app.TS.Equal(ts) || app.V != siem.SchemaVersion {
		t.Errorf("app event: %+v", app)
	}
	if moor.Kind != siem.KindMooringPrefix+"login" || !moor.TS.Equal(ts) {
		t.Errorf("audit event: %+v", moor)
	}
}

// A nil Pipeline (security logs off) ignores input.
func TestNilPipeline(t *testing.T) {
	var p *Pipeline
	p.AppLine(1, "a", "s", "c", "x")
	p.EdgeLine([]byte("x"))
	p.Audit(time.Now(), audit.Event{})
	p.HostLine(hostlog.Line{})
	if p.Sources() != nil {
		t.Error("nil Sources")
	}
	if n, c := p.Queue(); n != 0 || c != 0 {
		t.Error("nil Queue")
	}
}
