package detect

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/store"
)

// t0 is the tests' wall clock start; events are timed relative to it.
var t0 = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

type clock struct{ ns atomic.Int64 }

func newClock(t time.Time) *clock {
	c := &clock{}
	c.ns.Store(t.UnixNano())
	return c
}
func (c *clock) now() time.Time          { return time.Unix(0, c.ns.Load()).UTC() }
func (c *clock) set(t time.Time)         { c.ns.Store(t.UnixNano()) }
func (c *clock) advance(d time.Duration) { c.ns.Add(int64(d)) }

type sink struct {
	mu  sync.Mutex
	evs []siem.Event
}

func (s *sink) emit(e siem.Event) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.evs = append(s.evs, e)
	return true
}

func (s *sink) events() []siem.Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]siem.Event(nil), s.evs...)
}

type fakeAlerter struct {
	mu  sync.Mutex
	got []alert.Outbox
}

func (f *fakeAlerter) EnqueueInfra(_ context.Context, o alert.Outbox) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, o)
	return nil
}

func (f *fakeAlerter) all() []alert.Outbox {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]alert.Outbox(nil), f.got...)
}

type harness struct {
	e     *Engine
	clk   *clock
	out   *sink
	al    *fakeAlerter
	dir   string
	main  *store.DB
	mopts func(*Options)
	// incidents keeps incident grouping on (production's default). Off, the harness tests the
	// per-detection alerts: a detection that joins an incident has none (the incident alerts).
	incidents bool
}

// newHarness builds an engine on a fresh directory with a fake alerter and event sink. With
// withMain, a fresh Mooring database (all migrations) backs the rule store.
func newHarness(t testing.TB, withMain bool, mod ...func(*Options)) *harness {
	t.Helper()
	h := &harness{clk: newClock(t0), out: &sink{}, al: &fakeAlerter{}, dir: t.TempDir()}
	if withMain {
		db, err := store.Open(filepath.Join(t.TempDir(), "mooring.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		h.main = db
	}
	h.mopts = func(o *Options) {
		for _, m := range mod {
			m(o)
		}
	}
	h.open(t)
	return h
}

func (h *harness) options() Options {
	o := Options{Dir: h.dir, MainDB: h.main, Alerter: h.al, Emit: h.out.emit, Now: h.clk.now}
	h.mopts(&o)
	return o
}

func (h *harness) open(t testing.TB) {
	t.Helper()
	e, err := New(h.options())
	if err != nil {
		t.Fatal(err)
	}
	e.lim.incidents = h.incidents
	h.e = e
	t.Cleanup(func() { e.Close() })
}

// reopen closes the engine (saving its state as Run's shutdown does) and opens a new one on the
// same directory and database.
func (h *harness) reopen(t *testing.T) {
	t.Helper()
	h.e.flush(true)
	h.e.persist()
	if err := h.e.Close(); err != nil {
		t.Fatal(err)
	}
	h.open(t)
}

// only replaces the rules in force with rs (compiled without the pack).
func (h *harness) only(t testing.TB, rs ...siem.Rule) {
	t.Helper()
	set := &ruleSet{byID: map[string]*compiled{}}
	for _, r := range rs {
		if r.Name == "" {
			r.Name = r.ID
		}
		if r.Severity == "" {
			r.Severity = siem.SevMedium
		}
		r.Enabled = true
		if err := validate(&r, h.clk.now()); err != nil {
			t.Fatalf("rule %s: %v", r.ID, err)
		}
		var info packInfo
		if p := packByID[r.ID]; p != nil {
			info = p.info
		}
		c, err := compile(r, info, h.e.opt.MapValue)
		if err != nil {
			t.Fatal(err)
		}
		set.list = append(set.list, c)
		set.byID[r.ID] = c
		set.listed = append(set.listed, c.r)
	}
	h.e.rules.Store(set)
}

// feed evaluates events synchronously, as the Run goroutine does, with the clock moved forward
// to each event's time (events arrive as they happen).
func (h *harness) feed(evs ...siem.Event) {
	for i := range evs {
		if evs[i].TS.After(h.clk.now()) {
			h.clk.set(evs[i].TS)
		}
		h.feedRaw(evs[i])
	}
}

// feedRaw evaluates events without touching the clock.
func (h *harness) feedRaw(evs ...siem.Event) {
	for i := range evs {
		ev := evs[i]
		ev.Normalize(h.clk.now())
		h.e.process(&ev)
	}
}

// alerts drains the alert queue as the worker does when every send succeeds: each alert is
// reported back as sent, and returned.
func (h *harness) alerts() []alert.Outbox {
	var out []alert.Outbox
	for {
		select {
		case j := <-h.e.alerts:
			out = append(out, j.o)
			h.e.finishAlert(alertResult{job: j, ok: true})
		default:
			return out
		}
	}
}

// failAlerts drains the alert queue as the worker does when every send fails for good.
func (h *harness) failAlerts() []alert.Outbox {
	var out []alert.Outbox
	for {
		select {
		case j := <-h.e.alerts:
			out = append(out, j.o)
			h.e.finishAlert(alertResult{job: j, ok: false})
		default:
			return out
		}
	}
}

// detections returns the stored detections of a rule (after writing what is pending).
func (h *harness) detections(t *testing.T, ruleID string) []siem.Detection {
	t.Helper()
	h.e.flush(true)
	ds, err := h.e.Detections(context.Background(), siem.DetectionFilter{RuleID: ruleID, Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	return ds
}

func (h *harness) all(t *testing.T) []siem.Detection {
	t.Helper()
	return h.detections(t, "")
}

// ev builds an event at t0+at.
func ev(at time.Duration, src, kind, out, ip, actor string, f map[string]any) siem.Event {
	return siem.Event{TS: t0.Add(at), Src: src, Kind: kind, Out: out, IP: ip, Actor: actor, F: f}
}

func sshFail(at time.Duration, ip string) siem.Event {
	return ev(at, siem.SrcHost, siem.KindSSHLogin, siem.OutFailure, ip, "root", map[string]any{"method": "password", "user": "root"})
}

func geo(cc, city string, lat, lon float64) *siem.Geo {
	return &siem.Geo{Country: cc, City: city, Lat: lat, Lon: lon}
}
