package pipeline

import (
	"context"
	"math"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/siem"
)

// settleAll is settle that also waits for the emitted lane.
func (h *harness) settleAll() {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(h.p.q)+len(h.p.aq)+len(h.p.eq) > 0 {
		if time.Now().After(deadline) {
			h.t.Fatal("queue never drained")
		}
		time.Sleep(100 * time.Microsecond)
	}
	h.settle()
}

// detection is an event as the detection code emits it.
func detection(n int) siem.Event {
	return siem.Event{Src: siem.SrcSIEM, Kind: "siem.detection", Lvl: siem.LvlWarn, IP: "41.58.1.1",
		F: map[string]any{"rule": "ssh.bruteforce", "n": float64(n)}, Msg: "detection " + strconv.Itoa(n)}
}

// The enricher runs after redaction and before Normalize, and what it sets is stored.
func TestEnricherSeesRedactedEvent(t *testing.T) {
	var saw []siem.Event
	var mu sync.Mutex
	h := newHarness(t, 64, func(o *Options) {
		o.Enricher = func(e *siem.Event) {
			mu.Lock()
			c := *e
			c.F = map[string]any{"password": e.F["password"]}
			saw = append(saw, c)
			mu.Unlock()
			e.Geo = &siem.Geo{Country: "NG", ASN: 36923, Lists: []string{"tor-exit"}}
		}
	})
	h.p.parse.app = func(at time.Time, app, svc, copy, text string) siem.Event {
		return siem.Event{TS: at, Src: siem.SrcApp, App: app, IP: "41.58.1.1", Msg: text, F: map[string]any{"password": "hunter2"}}
	}
	h.p.redact = func(e *siem.Event) {
		if _, ok := e.F["password"]; ok {
			e.F["password"] = "[redacted]"
		}
	}
	h.run()
	h.p.AppLine(1, "app", "svc", "c", "sign-in")
	h.advance(time.Second)
	mu.Lock()
	defer mu.Unlock()
	if len(saw) != 1 {
		t.Fatalf("enricher called %d times, want 1", len(saw))
	}
	if saw[0].F["password"] != "[redacted]" {
		t.Errorf("the enricher saw password %v: it must run after redaction", saw[0].F["password"])
	}
	if saw[0].V != 0 {
		t.Error("the enricher saw a normalized event: it must run before Normalize")
	}
	evs := h.st.events()
	if len(evs) != 1 || evs[0].Geo == nil || evs[0].Geo.Country != "NG" || evs[0].Geo.ASN != 36923 {
		t.Fatalf("stored %+v", evs)
	}
}

// What an enricher sets is bounded before it is stored: a NaN coordinate can't be encoded.
func TestEnricherGeoBounded(t *testing.T) {
	h := newHarness(t, 64, func(o *Options) {
		o.Enricher = func(e *siem.Event) {
			lists := make([]string, 20)
			for i := range lists {
				lists[i] = "list-" + strconv.Itoa(i) + strings.Repeat("x", 100)
			}
			e.Geo = &siem.Geo{Country: strings.Repeat("N", 300), City: strings.Repeat("c", 5000), Org: strings.Repeat("o", 5000),
				Lat: math.NaN(), Lon: math.Inf(-1), Lists: lists}
		}
	})
	h.run()
	h.p.AppLine(1, "app", "svc", "c", "x")
	h.advance(time.Second)
	evs := h.st.events()
	if len(evs) != 1 || evs[0].Geo == nil {
		t.Fatalf("stored %+v", evs)
	}
	g := evs[0].Geo
	if g.Lat != 0 || g.Lon != 0 || len(g.City) > siem.MaxShort || len(g.Org) > siem.MaxShort || len(g.Country) > siem.MaxShort ||
		len(g.Lists) > maxGeoLists || len(g.Lists[0]) > maxGeoListName {
		t.Errorf("Geo not bounded: lat %v lon %v city %d org %d cc %d lists %d (%d)", g.Lat, g.Lon, len(g.City), len(g.Org), len(g.Country), len(g.Lists), len(g.Lists[0]))
	}
}

// An enricher panic is recovered and counted; the event is stored without Geo.
func TestEnricherPanicCounted(t *testing.T) {
	h := newHarness(t, 64, func(o *Options) {
		o.Enricher = func(e *siem.Event) {
			e.Geo = &siem.Geo{Country: "XX"} // half done
			if e.Msg == "boom" {
				panic("enricher bug")
			}
		}
	})
	h.run()
	h.p.AppLine(1, "app", "svc", "c", "a")
	h.p.AppLine(1, "app", "svc", "c", "boom")
	h.advance(time.Second)
	evs := h.st.events()
	if len(evs) != 2 || evs[1].Msg != "boom" {
		t.Fatalf("stored %+v: the event must be kept", evs)
	}
	if evs[1].Geo != nil {
		t.Errorf("the half-set Geo of a failed enrichment was kept: %+v", evs[1].Geo)
	}
	if evs[0].Geo == nil {
		t.Error("the other event lost its Geo")
	}
	if n := h.p.panics.Load(); n != 1 {
		t.Errorf("panics %d, want 1", n)
	}
	if s := source(h.p, siem.SrcApp); s.Events != 2 || s.Dropped != 0 {
		t.Errorf("app source %+v: an enricher panic doesn't drop the event", s)
	}
}

// The enricher sees no siem events: neither the pipeline's own reports nor emitted ones.
func TestEnricherSkipsSIEMEvents(t *testing.T) {
	var calls atomic.Int64
	h := newHarness(t, 4, func(o *Options) {
		o.Enricher = func(e *siem.Event) { calls.Add(1) }
	})
	h.p.parse.app = func(at time.Time, app, svc, copy, text string) siem.Event {
		if text == "as siem" {
			return siem.Event{TS: at, Src: siem.SrcSIEM, Kind: "siem.forged", Msg: text}
		}
		return siem.Event{TS: at, Src: siem.SrcApp, Msg: text}
	}
	for i := 0; i < 6; i++ { // 2 dropped: a siem.dropped report follows
		h.p.AppLine(1, "app", "svc", "c", "x")
	}
	h.run()
	h.settle()
	h.p.AppLine(1, "app", "svc", "c", "as siem")
	if !h.p.Emit(detection(1)) {
		t.Fatal("Emit refused a siem event")
	}
	h.settleAll()
	h.advance(time.Minute)
	h.advance(time.Second)
	if d := droppedEvents(h.st.events()); d[siem.SrcApp] != 2 {
		t.Fatalf("no drop report: %v", d)
	}
	if n := calls.Load(); n != 4 {
		t.Errorf("enricher called %d times, want 4 (the app events only)", n)
	}
}

// Emit takes only siem events (not the pipeline's own drop reports).
func TestEmitRefusesOtherSources(t *testing.T) {
	h := newHarness(t, 64, nil)
	for _, src := range []string{siem.SrcApp, siem.SrcEdge, siem.SrcMooring, siem.SrcHost, "", "SIEM", "siem "} {
		e := detection(1)
		e.Src = src
		if h.p.Emit(e) {
			t.Errorf("Emit took an event of source %q", src)
		}
	}
	e := detection(1)
	e.Kind = siem.KindDropped
	if h.p.Emit(e) {
		t.Error("Emit took a siem.dropped event")
	}
	if len(h.p.eq) != 0 {
		t.Fatalf("%d refused events queued", len(h.p.eq))
	}
	if !h.p.Emit(detection(2)) || len(h.p.eq) != 1 {
		t.Error("a siem event was refused")
	}
	var nilP *Pipeline
	if nilP.Emit(detection(3)) {
		t.Error("a nil pipeline took an event")
	}
}

// The emitted lane holds emitLaneSize events; past that Emit drops, counts and reports them under
// source "siem", without blocking.
func TestEmitLaneFull(t *testing.T) {
	h := newHarness(t, 64, nil)
	for i := 0; i < emitLaneSize; i++ {
		if !h.p.Emit(detection(i)) {
			t.Fatalf("Emit %d refused before the lane was full", i)
		}
	}
	done := make(chan bool)
	go func() { done <- h.p.Emit(detection(-1)) }()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("Emit took an event past the lane's capacity")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Emit blocked on a full lane")
	}
	h.p.Emit(detection(-2))
	h.run()
	h.settleAll()
	h.advance(time.Minute)
	h.advance(time.Second)
	evs := h.st.events()
	if d := droppedEvents(evs); d[siem.SrcSIEM] != 2 {
		t.Errorf("drop report %v, want 2 for source siem", d)
	}
	emitted := 0
	for _, e := range evs {
		if e.Kind == "siem.detection" {
			emitted++
		}
	}
	if emitted != emitLaneSize {
		t.Errorf("stored %d emitted events, want %d", emitted, emitLaneSize)
	}
}

// Emitted events go through Normalize, the store and the subscribers, but not the parsers, the
// redactor or the enricher.
func TestEmittedEventsStoredAndDelivered(t *testing.T) {
	var subs []siem.Event
	var mu sync.Mutex
	var redacted, enriched atomic.Int64
	h := newHarness(t, 64, func(o *Options) {
		o.Subscribers = []func(siem.Event){func(e siem.Event) { mu.Lock(); subs = append(subs, e); mu.Unlock() }}
		o.Enricher = func(*siem.Event) { enriched.Add(1) }
	})
	h.p.redact = func(e *siem.Event) { redacted.Add(1) }
	h.run()
	e := detection(7)
	e.Msg = strings.Repeat("m", 2*siem.MaxMsg)
	e.F["key"] = "kept as emitted"
	e.Geo = &siem.Geo{Country: "NG", Lat: math.NaN()}
	if !h.p.Emit(e) {
		t.Fatal("refused")
	}
	h.settleAll()
	h.advance(time.Second)
	evs := h.st.events()
	if len(evs) != 1 {
		t.Fatalf("stored %d events, want 1", len(evs))
	}
	got := evs[0]
	if got.V != siem.SchemaVersion || got.TS.IsZero() || len(got.Msg) != siem.MaxMsg || got.F["key"] != "kept as emitted" {
		t.Errorf("stored %+v: want it normalized and otherwise as emitted", got)
	}
	if got.Geo == nil || got.Geo.Country != "NG" || got.Geo.Lat != 0 {
		t.Errorf("Geo %+v: kept, bounded", got.Geo)
	}
	if e.Geo.Country != "NG" || !math.IsNaN(e.Geo.Lat) {
		t.Error("bounding changed the emitter's own Geo")
	}
	if redacted.Load() != 0 || enriched.Load() != 0 {
		t.Errorf("emitted event redacted %d / enriched %d times, want 0", redacted.Load(), enriched.Load())
	}
	mu.Lock()
	defer mu.Unlock()
	if len(subs) != 1 || subs[0].Kind != "siem.detection" {
		t.Errorf("subscribers saw %+v", subs)
	}
	if s := source(h.p, siem.SrcApp); s.Events != 0 {
		t.Errorf("an emitted event was counted as app: %+v", s)
	}
}

// The emitted lane is taken after the audit lane and before the main lane.
func TestEmitPriority(t *testing.T) {
	h := newHarness(t, 64, nil)
	for i := 0; i < 8; i++ {
		h.p.AppLine(1, "app", "svc", "c", "x")
	}
	for i := 0; i < 3; i++ {
		h.p.Emit(detection(i))
	}
	for i := 0; i < 5; i++ {
		h.p.Audit(h.clk.Now(), audit.Event{Action: "login"})
	}
	h.run()
	h.settleAll()
	h.advance(time.Second)
	var order []string
	for _, e := range h.st.events() {
		order = append(order, e.Src)
	}
	want := strings.Repeat("mooring,", 5) + strings.Repeat("siem,", 3) + strings.TrimSuffix(strings.Repeat("app,", 8), ",")
	if strings.Join(order, ",") != want {
		t.Errorf("order %v, want %s", order, want)
	}
}

// Taking emitted events first is bounded too: a full emitted lane doesn't starve the main lane.
func TestEmitPriorityIsBounded(t *testing.T) {
	h := newHarness(t, 8, nil)
	for i := 0; i < emitLaneSize; i++ {
		h.p.Emit(detection(i))
	}
	for i := 0; i < 8; i++ {
		h.p.AppLine(1, "app", "svc", "c", "x")
	}
	h.run()
	h.settleAll()
	h.advance(time.Second)
	evs := h.st.events()
	firstApp, lastEmitted := -1, -1
	for i, e := range evs {
		if e.Src == siem.SrcApp && firstApp < 0 {
			firstApp = i
		}
		if e.Src == siem.SrcSIEM {
			lastEmitted = i
		}
	}
	if firstApp < emitBurst || firstApp > lastEmitted {
		t.Errorf("first app event at %d, last emitted at %d: emitted events go first, %d at a time", firstApp, lastEmitted, emitBurst)
	}
}

// Shutdown stores what was emitted; an Emit after shutdown began is refused and counted.
func TestShutdownDrainsEmitted(t *testing.T) {
	h := newHarness(t, 64, nil)
	for i := 0; i < emitLaneSize; i++ {
		h.p.Emit(detection(i))
	}
	h.p.AppLine(1, "app", "svc", "c", "x")
	// Run starts with its context already ended: it takes at most a few bursts of the full lane
	// before it sees that, and shutdown drains the rest.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.p.Run(ctx)
	n := 0
	for _, e := range h.st.events() {
		if e.Kind == "siem.detection" {
			n++
		}
	}
	if n != emitLaneSize {
		t.Errorf("stored %d emitted events at shutdown, want %d", n, emitLaneSize)
	}
	if h.p.Emit(detection(99)) {
		t.Error("Emit took an event after shutdown")
	}
	for _, d := range h.p.dropTotals() {
		if d.source == siem.SrcSIEM && d.n != 1 {
			t.Errorf("siem drops %d, want 1", d.n)
		}
	}
}

// Emitted events still queued past the drain budget are counted as dropped: every emitted event is
// either stored or counted.
func TestShutdownCountsLeftoverEmitted(t *testing.T) {
	h := newHarness(t, 64, nil)
	h.p.drain = 0 // shutdown processes nothing: what Run hasn't taken yet is leftover
	for i := 0; i < emitLaneSize; i++ {
		h.p.Emit(detection(i))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.p.Run(ctx)
	stored := 0
	for _, e := range h.st.events() {
		if e.Kind == "siem.detection" {
			stored++
		}
	}
	var dropped int64
	for _, d := range h.p.dropTotals() {
		if d.source == siem.SrcSIEM {
			dropped = d.n
		}
	}
	if int64(stored)+dropped != emitLaneSize || len(h.p.eq) != 0 {
		t.Errorf("stored %d + dropped %d != emitted %d (%d left in the lane)", stored, dropped, emitLaneSize, len(h.p.eq))
	}
}
