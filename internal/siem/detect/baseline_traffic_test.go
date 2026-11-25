package detect

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

// served is a KnownHost serving the host names f accepts, each counted under its own name, with
// the routes read.
func served(f func(string) bool) hostFn {
	return func(h string) (string, bool, bool) {
		if h == "" || !f(h) {
			return "", false, true
		}
		return h, true, true
	}
}

func knownHosts(hosts ...string) hostFn {
	m := map[string]bool{}
	for _, h := range hosts {
		m[h] = true
	}
	return served(func(h string) bool { return m[h] })
}

// routes is a KnownHost like serve's: exact host names, and the apexes of catch-all routes (every
// label under one counts as "*.<apex>"). With ready, the routes are read only while *ready is set.
func routes(exact, apexes []string, ready *bool) hostFn {
	ex, ap := map[string]bool{}, map[string]bool{}
	for _, h := range exact {
		ex[h] = true
	}
	for _, a := range apexes {
		ap[a] = true
	}
	return routesOf(ex, ap, ready)
}

// routesOf is routes over sets the test may change.
func routesOf(ex, ap map[string]bool, ready *bool) hostFn {
	return func(h string) (string, bool, bool) {
		switch {
		case ready != nil && !*ready:
			return "", false, false
		case h == "":
			return "", false, true
		case ex[h]:
			return h, true, true
		case strings.HasPrefix(h, "*.") && ap[h[2:]]:
			return h, true, true
		}
		if i := strings.IndexByte(h, '.'); i > 0 && ap[h[i+1:]] {
			return "*." + h[i+1:], true, true
		}
		return "", false, true
	}
}

// load is a host's requests and server errors in one hour.
type load struct{ req, errs int }

// runTraffic feeds hours of edge requests from from (an hour start), spread over each minute, and
// ticks the engine every minute as Run does (every second there). loads gives each host's load for
// an hour start; skipTicks leaves the ticks of [from, to) out (Mooring stalled).
func runTraffic(h *harness, from time.Time, hours int, loads func(hour time.Time) map[string]load, skip ...[2]time.Time) {
	for i := range hours {
		hs := from.Add(time.Duration(i) * time.Hour)
		l := loads(hs)
		for m := range 60 {
			mt := hs.Add(time.Duration(m) * time.Minute)
			trafficMinute(h, mt, m, l)
			tick := mt.Add(30 * time.Second)
			skipped := false
			for _, s := range skip {
				if !tick.Before(s[0]) && tick.Before(s[1]) {
					skipped = true
				}
			}
			h.clk.set(tick.UTC())
			if !skipped {
				h.e.baselineTick()
			}
		}
	}
}

// trafficMinute feeds minute m (at mt) of an hour of loads l.
func trafficMinute(h *harness, mt time.Time, m int, l map[string]load) {
	for host, c := range l {
		n, ne := c.req/60, c.errs/60
		if m < c.req%60 {
			n++
		}
		if m < c.errs%60 {
			ne++
		}
		for k := range n {
			st := 200.0
			if k < ne {
				st = 502
			}
			h.feed(siem.Event{TS: mt.Add(time.Duration(k) * 10 * time.Millisecond).UTC(), Src: siem.SrcEdge,
				Kind: siem.KindHTTPRequest, IP: "198.51.100.1", F: map[string]any{"host": host, "status": st, "path": "/"}})
		}
	}
}

// usual is shop's ordinary week: 240 requests (1 server error) an hour 09:00–13:00, api's 50.
func usual(hour time.Time) map[string]load {
	l := hour.In(tokyo)
	if l.Hour() >= 9 && l.Hour() < 13 {
		return map[string]load{"shop.example.com": {240, 1}, "api.example.com": {50, 0}}
	}
	return nil
}

func trafficRules(mods ...func(*siem.Rule)) []siem.Rule {
	return []siem.Rule{blRule(ruleTrafficSurge, mods...), blRule(ruleTrafficDrop, mods...)}
}

func TestBaselineTrafficSurgeAndDrop(t *testing.T) {
	h := blHarness(t, tokyo, knownHosts("shop.example.com", "api.example.com"), trafficRules()...)
	week1 := func(hour time.Time) map[string]load {
		l := usual(hour)
		// A host name no route serves: never counted.
		if hour.Equal(at(1, 10, 0)) {
			l = map[string]load{"shop.example.com": {240, 1}, "api.example.com": {50, 0}, "evil.example.com": {5000, 900}}
		}
		// Week 2's Monday 12:00 surges, with only one earlier week of that hour: still learning.
		if hour.Equal(at(7, 12, 0)) {
			l = map[string]load{"shop.example.com": {1500, 1}, "api.example.com": {50, 0}}
		}
		return l
	}
	runTraffic(h, at(0, 0, 0), 14*24, week1)
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("two learning weeks:\n%s", summaries(ds))
	}
	if h.e.bl.traffic.peek("evil.example.com") != nil || h.e.bl.traffic.len() != 2 {
		t.Fatalf("hosts tracked: %d", h.e.bl.traffic.len())
	}

	week3 := func(hour time.Time) map[string]load {
		l := usual(hour)
		switch {
		case hour.Equal(at(15, 10, 0)): // Tuesday 10:00: 1500 requests, usually 240
			l = map[string]load{"shop.example.com": {1500, 1}, "api.example.com": {50, 0}}
		case hour.Equal(at(16, 11, 0)): // Wednesday 11:00: 80 server errors, usually 1
			l = map[string]load{"shop.example.com": {240, 80}, "api.example.com": {50, 0}}
		case hour.Equal(at(17, 9, 0)): // Thursday 09:00: 20 requests, usually 240; api 0 of its usual 50 (below count)
			l = map[string]load{"shop.example.com": {20, 0}}
		}
		return l
	}
	// The surge hour itself, not yet closed: nothing.
	runTraffic(h, at(14, 0, 0), 24+11, week3)
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("before the hour closed:\n%s", summaries(ds))
	}
	runTraffic(h, at(15, 11, 0), 6*24-11, week3)
	ds := h.all(t)
	want := []string{
		"baseline.traffic_drop [1]: host shop.example.com — 20 requests (usually about 240) in the hour 09:00–10:00 Thu",
		"baseline.traffic_surge [1]: host shop.example.com — 80 server errors (usually about 1) in the hour 11:00–12:00 Wed",
		"baseline.traffic_surge [1]: host shop.example.com — 1500 requests (usually about 240) in the hour 10:00–11:00 Tue",
	}
	if got := summaries(ds); got != strings.Join(want, "\n") {
		t.Fatalf("week 3:\n%s\nwant:\n%s", got, strings.Join(want, "\n"))
	}
	if ds[2].Last != at(15, 10, 59).Add(59*time.Second).UTC() || ds[2].Key != "shop.example.com" {
		t.Fatalf("surge detection: %+v", ds[2])
	}

	// Week 4, Tuesday 10:00: 1200 requests. The earlier weeks of that hour had 240, 240 and 1500:
	// median 240 (5× is 1200, so it fires); their mean (660) would not.
	week4 := func(hour time.Time) map[string]load {
		if hour.Equal(at(22, 10, 0)) {
			return map[string]load{"shop.example.com": {1200, 1}, "api.example.com": {50, 0}}
		}
		return usual(hour)
	}
	runTraffic(h, at(21, 0, 0), 2*24, week4)
	ds = h.detections(t, ruleTrafficSurge)
	if len(ds) != 3 || ds[0].Summary != "host shop.example.com — 1200 requests (usually about 240) in the hour 10:00–11:00 Tue" {
		t.Fatalf("median of 3 weeks:\n%s", summaries(ds))
	}
}

// factor and count are each rule's own; learn sets how many earlier weeks an hour needs.
func TestBaselineTrafficTunables(t *testing.T) {
	week := func(spike int) func(time.Time) map[string]load {
		return func(hour time.Time) map[string]load {
			if hour.Equal(at(15, 10, 0)) {
				return map[string]load{"shop.example.com": {spike, 1}}
			}
			return usual(hour)
		}
	}
	for _, tc := range []struct {
		name  string
		rules []siem.Rule
		spike int
		want  int
	}{
		{"factor 10: 1500 < 2400", trafficRules(func(r *siem.Rule) { r.Factor = 10 }), 1500, 0},
		{"factor 5", trafficRules(), 1500, 1},
		{"count 2000: 1500 below", trafficRules(func(r *siem.Rule) { r.Count = 2000 }), 1500, 0},
		{"learn 21d: 2 weeks only", trafficRules(func(r *siem.Rule) { r.Learn = 21 * day }), 1500, 0},
		{"surge off, drop on", []siem.Rule{blRule(ruleTrafficDrop)}, 1500, 0},
		{"drop off, surge counts alone", []siem.Rule{blRule(ruleTrafficSurge)}, 1500, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := blHarness(t, tokyo, knownHosts("shop.example.com"), tc.rules...)
			runTraffic(h, at(0, 0, 0), 16*24, week(tc.spike))
			if ds := h.all(t); len(ds) != tc.want {
				t.Fatalf("%d detections, want %d:\n%s", len(ds), tc.want, summaries(ds))
			}
		})
	}
}

// Hours Mooring didn't watch whole are neither compared nor learned: the hour it starts in, hours
// it was stalled, hours both rules were off.
func TestBaselineTrafficWatchedHoursOnly(t *testing.T) {
	rs := trafficRules()
	h := blHarness(t, tokyo, knownHosts("shop.example.com"), rs...)
	runTraffic(h, at(0, 0, 0), 15*24, usual) // two weeks and Monday
	// Tuesday: stalled 10:20–10:25 (no tick for 5 minutes), no requests 10:00–11:00.
	quiet := func(hour time.Time) map[string]load {
		if hour.Equal(at(15, 10, 0)) {
			return nil
		}
		return usual(hour)
	}
	runTraffic(h, at(15, 0, 0), 12, quiet, [2]time.Time{at(15, 10, 20), at(15, 10, 25)})
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("an hour with a stall compared:\n%s", summaries(ds))
	}
	// A restart at 11:30 Wednesday: 11:00 is not watched whole (and 12:00 is: it drops).
	runTraffic(h, at(15, 12, 0), 23, usual)
	h.feed(siem.Event{TS: at(16, 11, 10).UTC(), Src: siem.SrcEdge, Kind: siem.KindHTTPRequest,
		F: map[string]any{"host": "shop.example.com", "status": 200.0}})
	h.clk.set(at(16, 11, 30).UTC())
	h.blReopen(t, tokyo, rs...)
	idle(h, at(16, 11, 30), 60) // 11:00 closes at 12:02
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("the hour of the restart compared:\n%s", summaries(ds))
	}
	idle(h, at(16, 12, 30), 60) // 12:00 closes at 13:02
	ds := h.all(t)
	if len(ds) != 1 || ds[0].Summary != "host shop.example.com — 0 requests (usually about 240) in the hour 12:00–13:00 Wed" {
		t.Fatalf("after a restart (weeks learned before it kept):\n%s", summaries(ds))
	}
	// Thursday 09:00 without requests (watched); 10:00 too, with both rules off for a moment.
	idle(h, at(16, 13, 30), 30)
	runTraffic(h, at(16, 14, 0), 19, usual)
	idle(h, at(17, 9, 0), 70)
	h.only(t)
	h.e.baselineTick()
	h.only(t, rs...)
	idle(h, at(17, 10, 10), 60)
	if ds := h.all(t); len(ds) != 2 || ds[0].Summary != "host shop.example.com — 0 requests (usually about 240) in the hour 09:00–10:00 Thu" {
		t.Fatalf("09:00 Thursday (watched) drops, 10:00 (rules off) doesn't:\n%s", summaries(ds))
	}
}

// idle ticks every minute for minutes from from, with no requests.
func idle(h *harness, from time.Time, minutes int) {
	for m := range minutes {
		h.clk.set(from.Add(time.Duration(m)*time.Minute + 30*time.Second).UTC())
		h.e.baselineTick()
	}
}

// A host name whose route is removed is forgotten when the next hour ends.
func TestBaselineTrafficForgetsRemovedHosts(t *testing.T) {
	on := map[string]bool{"shop.example.com": true, "old.example.com": true}
	h := blHarness(t, tokyo, served(func(s string) bool { return on[s] }), trafficRules()...)
	both := func(hour time.Time) map[string]load {
		if l := usual(hour); l != nil {
			return map[string]load{"shop.example.com": {240, 1}, "old.example.com": {240, 0}}
		}
		return nil
	}
	runTraffic(h, at(0, 0, 0), 15*24+9, both)
	h.e.saveBaselines()
	on["old.example.com"] = false
	runTraffic(h, at(15, 9, 0), 4, func(time.Time) map[string]load { return map[string]load{"shop.example.com": {240, 1}} })
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("a removed host's missing traffic fired:\n%s", summaries(ds))
	}
	if h.e.bl.traffic.peek("old.example.com") != nil || h.e.bl.traffic.peek("shop.example.com") == nil {
		t.Fatal("removed host kept")
	}
	h.e.saveBaselines()
	var n int
	if err := h.e.db.w.QueryRow(`SELECT COUNT(*) FROM baselines WHERE kind = 'traffic' AND key = 'old.example.com'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("removed host's row: %d, %v", n, err)
	}
}

func TestBaselineTrafficSlotRing(t *testing.T) {
	var s tslot
	s.record(10, tcount{req: 1})
	s.record(11, tcount{req: 2})
	s.record(13, tcount{req: 4}) // week 12 had none
	if got := s.prior(14); len(got) != 3 {
		t.Fatalf("prior(14) %v", got)
	}
	s.record(14, tcount{req: 5}) // week 10 falls out
	got := s.prior(15)
	if len(got) != 3 || got[0].req != 5 || got[1].req != 4 || got[2].req != 2 {
		t.Fatalf("prior(15) %v", got)
	}
	if got := s.prior(14); len(got) != 2 {
		t.Fatalf("prior(14) excludes week 14 itself: %v", got)
	}
	s.record(9, tcount{req: 9}) // too old: ignored
	if got := s.prior(19); len(got) != 0 {
		t.Fatalf("weeks older than 4 before 19: %v", got)
	}
	s.record(30, tcount{req: 7})
	if got := s.prior(31); len(got) != 1 || got[0].req != 7 {
		t.Fatalf("after a gap: %v", got)
	}
	// A skipped week's place is cleared: week 24 held none, so its place (week 20's) is no value.
	var r tslot
	for w := int32(20); w <= 23; w++ {
		r.record(w, tcount{req: uint32(w)})
	}
	r.record(25, tcount{req: 25})
	if got := r.prior(26); len(got) != 3 || got[0].req != 25 || got[1].req != 23 || got[2].req != 22 {
		t.Fatalf("prior(26) after skipping week 24: %v", got)
	}
	if middle([]float64{240, 1500, 240}, false) != 240 || middle([]float64{240, 1500, 240}, true) != 240 ||
		middle([]float64{4, 2}, false) != 2 || middle([]float64{4, 2}, true) != 4 || middle([]float64{1, 9, 3, 7}, false) != 3 ||
		middle([]float64{1, 9, 3, 7}, true) != 7 || middle(nil, true) != 0 {
		t.Fatal("middle")
	}
	if weeksFor(14*day) != 2 || weeksFor(7*day) != 1 || weeksFor(8*day) != 2 || weeksFor(28*day) != 4 {
		t.Fatal("weeksFor")
	}
	var x hostTraffic
	x.from, x.quiet = 123, 7
	x.slots[5].record(2900, tcount{req: 300, err: 3})
	x.slots[5].record(2901, tcount{req: 310})
	y, err := decodeTraffic(x.encode())
	if err != nil || y.from != 123 || y.quiet != 7 || y.slots[5] != x.slots[5] || y.slots[4].mask != 0 {
		t.Fatalf("round trip: %+v %v", y.slots[5], err)
	}
	for _, bad := range [][]byte{nil, {2}, append(x.encode(), 1), x.encode()[:10]} {
		if _, err := decodeTraffic(bad); err == nil {
			t.Errorf("decodeTraffic accepted %d bytes", len(bad))
		}
	}
}

// A line of an hour that arrives within trafficGrace after the hour ended still counts in it; a
// later one doesn't (the hour is closed).
func TestBaselineTrafficLateLines(t *testing.T) {
	h := blHarness(t, tokyo, knownHosts("shop.example.com"), trafficRules()...)
	req := func(ts time.Time) {
		h.feedRaw(siem.Event{TS: ts.UTC(), Src: siem.SrcEdge, Kind: siem.KindHTTPRequest,
			F: map[string]any{"host": "shop.example.com", "status": 200.0}})
	}
	idle(h, at(0, 9, 0), 61) // to 10:00:30
	req(at(0, 10, 0).Add(40 * time.Second))
	idle(h, at(0, 10, 1), 60)                // to 11:00:30
	req(at(0, 10, 59).Add(50 * time.Second)) // 40s late
	x := h.e.bl.traffic.peek("shop.example.com")
	hr := floorDiv(at(0, 10, 0).Unix(), 3600)
	if c := x.v.take(hr - 1); c.req != 0 {
		t.Fatalf("09:00: %+v", c)
	}
	found := false
	for _, b := range x.v.open {
		if b.h == hr && b.req == 2 {
			found = true
		}
	}
	if !found {
		t.Fatalf("10:00 bucket after a late line: %+v", x.v.open)
	}
	idle(h, at(0, 11, 1), 2) // 11:02:30: closed
	if h.e.bl.closed != hr {
		t.Fatalf("closed %d, want %d", h.e.bl.closed, hr)
	}
	// 10:00 is the hour shop was first seen in: not counted whole, so not recorded.
	slot, week := slotOf(at(0, 10, 0), tokyo), int32(weekOf(at(0, 10, 0), tokyo))
	if x.v.slots[slot].mask != 0 {
		t.Fatalf("the first hour was recorded: %+v", x.v.slots[slot])
	}
	// A host name no route serves isn't tracked at all, not even until its hour ends.
	h.feedRaw(siem.Event{TS: at(0, 11, 2).UTC(), Src: siem.SrcEdge, Kind: siem.KindHTTPRequest,
		F: map[string]any{"host": "random-1.example.com", "status": 200.0}})
	if h.e.bl.traffic.peek("random-1.example.com") != nil {
		t.Fatal("unknown host tracked")
	}
	idle(h, at(0, 11, 3), 60) // 11:00 closes at 12:02: recorded (no requests)
	if s := x.v.slots[slot+1]; s.mask == 0 || s.week != week {
		t.Fatalf("11:00 not recorded: %+v", s)
	}
	req(at(0, 10, 59))
	for _, b := range x.v.open {
		if b.h == hr {
			t.Fatalf("a line after its hour closed was counted: %+v", x.v.open)
		}
	}
}

// slotHas reports whether host's hour of the week of hs holds a count for hs's week.
func slotHas(h *harness, host string, hs time.Time) bool {
	x := h.e.bl.traffic.peek(host)
	if x == nil {
		return false
	}
	s, w := x.v.slots[slotOf(hs, tokyo)], int32(weekOf(hs, tokyo))
	return s.mask&(1<<wpos(w)) != 0 && s.week >= w
}

// A catch-all route serves every label under its apex: all of them count as one host name, so a
// client inventing labels can't fill the table (and push the learned hosts out).
func TestBaselineTrafficCatchAllCountsOnce(t *testing.T) {
	exact := map[string]bool{"shop.example.com": true, "old.apex.example": true}
	h := blHarness(t, tokyo, routesOf(exact, map[string]bool{"apex.example": true}, nil), trafficRules()...)
	b := h.e.bl
	setCap(b.traffic, 40)
	runTraffic(h, at(0, 0, 0), 2*24, func(time.Time) map[string]load {
		return map[string]load{"shop.example.com": {6, 0}, "old.apex.example": {6, 0}}
	})
	if x := b.traffic.peek("shop.example.com"); x == nil || !x.prot || b.traffic.peek("old.apex.example") == nil {
		t.Fatal("shop or old not learned")
	}
	// old's own route removed: the catch-all serves it now, counted as "*.apex.example".
	delete(exact, "old.apex.example")
	// 16 hours of 120 new labels each.
	for hr := range 16 {
		runTraffic(h, at(2, hr, 0), 1, func(time.Time) map[string]load {
			l := map[string]load{}
			for i := range 120 {
				l[fmt.Sprintf("x%d-%d.apex.example", hr, i)] = load{1, 0}
			}
			return l
		})
	}
	idle(h, at(2, 16, 0), 5)
	x := b.traffic.peek("*.apex.example")
	if b.traffic.len() != 2 || x == nil || b.traffic.peek("shop.example.com") == nil {
		t.Fatalf("%d host names tracked", b.traffic.len())
	}
	s := x.v.slots[slotOf(at(2, 15, 0), tokyo)]
	if c := s.v[wpos(s.week)]; s.mask == 0 || c.req != 120 {
		t.Fatalf("the catch-all's 15:00: %+v", s)
	}
}

// A host name without a request for 4 weeks of watched hours is forgotten (its row deleted).
func TestBaselineTrafficForgetsQuietHosts(t *testing.T) {
	h := blHarness(t, tokyo, knownHosts("shop.example.com", "old.example.com"), trafficRules()...)
	b := h.e.bl
	runTraffic(h, at(0, 0, 0), 3, func(time.Time) map[string]load {
		return map[string]load{"shop.example.com": {60, 0}, "old.example.com": {60, 0}}
	})
	h.e.saveBaselines()
	// Hourly ticks (the hours still watched), shop with a request every hour, old with none.
	b.maxGap = 2 * time.Hour
	hourly := func(from time.Time, hours int) {
		for i := range hours {
			hs := from.Add(time.Duration(i) * time.Hour)
			h.feed(siem.Event{TS: hs.Add(30 * time.Minute).UTC(), Src: siem.SrcEdge, Kind: siem.KindHTTPRequest,
				F: map[string]any{"host": "shop.example.com", "status": 200.0}})
			h.clk.set(hs.Add(time.Hour + 3*time.Minute).UTC())
			h.e.baselineTick()
		}
	}
	// 02:00 had old's last requests; from 03:00 on, trafficForget hours closed without one.
	hourly(at(0, 3, 0), trafficForget-1)
	if x := b.traffic.peek("old.example.com"); x == nil || x.v.quiet != trafficForget-1 {
		t.Fatalf("old forgotten too early: %+v", x)
	}
	hourly(at(0, 3, 0).Add((trafficForget-1)*time.Hour), 1)
	if b.traffic.peek("old.example.com") != nil || b.traffic.peek("shop.example.com") == nil {
		t.Fatal("the quiet host kept, or the busy one forgotten")
	}
	h.e.saveBaselines()
	if rows := blRows(t, h, "traffic"); rows["old.example.com"] != nil || rows["shop.example.com"] == nil {
		t.Fatalf("rows: %d", len(rows))
	}
}

// Until the edge's routes were read (KnownHost not ready) nothing is forgotten (nor its row
// deleted), no request counted, and no hour compared or learned, up to the first hour after.
func TestBaselineTrafficWaitsForRoutes(t *testing.T) {
	// A host known but the routes not read: not counted.
	stale := blHarness(t, tokyo, func(h string) (string, bool, bool) { return h, h != "", false }, trafficRules()...)
	stale.feed(siem.Event{TS: at(0, 9, 0).UTC(), Src: siem.SrcEdge, Kind: siem.KindHTTPRequest,
		F: map[string]any{"host": "shop.example.com", "status": 200.0}})
	if stale.e.bl.traffic.len() != 0 {
		t.Fatal("a request counted before the routes were read")
	}

	ready := true
	rs := trafficRules()
	h := blHarness(t, tokyo, routes([]string{"shop.example.com", "new.example.com"}, nil, &ready), rs...)
	runTraffic(h, at(0, 0, 0), 14*24+9, usual) // two weeks, then Monday to 09:00
	h.e.saveBaselines()
	ready = false
	h.blReopen(t, tokyo, rs...)
	week3 := func(time.Time) map[string]load {
		return map[string]load{"shop.example.com": {240, 1}, "new.example.com": {60, 0}}
	}
	runTraffic(h, at(14, 9, 0), 2, week3) // 09:00 and 10:00: the routes not read
	// 11:00: read at 11:50.
	l := week3(at(14, 11, 0))
	for m := range 60 {
		mt := at(14, 11, m)
		if m == 50 {
			ready = true
		}
		trafficMinute(h, mt, m, l)
		h.clk.set(mt.Add(30 * time.Second).UTC())
		h.e.baselineTick()
	}
	runTraffic(h, at(14, 12, 0), 2, week3)
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("hours before the routes were read compared:\n%s", summaries(ds))
	}
	b := h.e.bl
	if x := b.traffic.peek("shop.example.com"); x == nil || x.v.from >= floorDiv(at(1, 0, 0).Unix(), 3600) ||
		!slotHas(h, "shop.example.com", at(7, 10, 0)) || blRows(t, h, "traffic")["shop.example.com"] == nil {
		t.Fatal("a host (its history) forgotten before the routes were read")
	}
	for hh := 9; hh <= 11; hh++ {
		if slotHas(h, "shop.example.com", at(14, hh, 0)) {
			t.Errorf("%02d:00 (routes not read for all of it) learned", hh)
		}
	}
	if !slotHas(h, "shop.example.com", at(14, 12, 0)) {
		t.Error("12:00 (routes read) not learned")
	}
	if x := b.traffic.peek("new.example.com"); x == nil || x.v.from != floorDiv(at(14, 11, 0).Unix(), 3600)+1 {
		t.Fatalf("new.example.com learned before the routes were read: %+v", x)
	}
}

// An hour in which the engine dropped events unevaluated (its queue was full) is not watched
// whole: neither compared nor learned.
func TestBaselineTrafficDroppedEvents(t *testing.T) {
	h := blHarness(t, tokyo, knownHosts("shop.example.com"), trafficRules()...)
	runTraffic(h, at(0, 0, 0), 14*24+10, usual)
	few := func(time.Time) map[string]load { return map[string]load{"shop.example.com": {30, 0}} }
	// Monday 10:00 of week 3: 30 requests reached the rules, others were dropped at 10:40.
	l := few(at(14, 10, 0))
	for m := range 60 {
		mt := at(14, 10, m)
		trafficMinute(h, mt, m, l)
		if m == 40 {
			h.e.dropped.Add(1)
		}
		h.clk.set(mt.Add(30 * time.Second).UTC())
		h.e.baselineTick()
	}
	runTraffic(h, at(14, 11, 0), 1, usual)
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("an hour with dropped events compared:\n%s", summaries(ds))
	}
	// The same 30 requests at 12:00, nothing dropped: a drop.
	runTraffic(h, at(14, 12, 0), 1, few)
	runTraffic(h, at(14, 13, 0), 1, usual)
	if ds := h.all(t); len(ds) != 1 || ds[0].Summary != "host shop.example.com — 30 requests (usually about 240) in the hour 12:00–13:00 Mon" {
		t.Fatalf("a watched hour:\n%s", summaries(ds))
	}
	if slotHas(h, "shop.example.com", at(14, 10, 0)) || !slotHas(h, "shop.example.com", at(14, 11, 0)) {
		t.Fatal("10:00 (events dropped) learned, or 11:00 not")
	}
}

// A flood that fills the engine's queue (events dropped unevaluated) still fires a surge: the
// hour's counts are a lower bound. The hour is not learned.
func TestBaselineTrafficSurgeWhileDropping(t *testing.T) {
	h := blHarness(t, tokyo, knownHosts("shop.example.com"), trafficRules()...)
	runTraffic(h, at(0, 0, 0), 14*24+10, usual)
	l := map[string]load{"shop.example.com": {6000, 0}}
	for m := range 60 {
		mt := at(14, 10, m)
		trafficMinute(h, mt, m, l)
		if m == 30 {
			h.e.dropped.Add(500)
		}
		h.clk.set(mt.Add(30 * time.Second).UTC())
		h.e.baselineTick()
	}
	runTraffic(h, at(14, 11, 0), 2, usual) // 11:00 closes at 12:02
	if ds := h.all(t); len(ds) != 1 ||
		summaries(ds) != "baseline.traffic_surge [1]: host shop.example.com — 6000 requests (usually about 240) in the hour 10:00–11:00 Mon" {
		t.Fatalf("a surge with events dropped:\n%s", summaries(ds))
	}
	if slotHas(h, "shop.example.com", at(14, 10, 0)) || !slotHas(h, "shop.example.com", at(14, 11, 0)) {
		t.Fatal("10:00 (events dropped) learned, or 11:00 not")
	}
}

// With two earlier weeks, a drop compares with the lower and a surge with the higher (never their
// mean): one spike week (while learning) doesn't make an ordinary hour a drop a week later.
func TestBaselineTrafficSpikeWeekNoFalseDrop(t *testing.T) {
	h := blHarness(t, tokyo, knownHosts("shop.example.com", "api.example.com"), trafficRules()...)
	loads := func(hour time.Time) map[string]load {
		switch {
		case hour.Equal(at(8, 10, 0)), hour.Equal(at(8, 12, 0)): // week 2, Tuesday: two 10x spikes (learning: silent)
			return map[string]load{"shop.example.com": {2400, 1}, "api.example.com": {50, 0}}
		case hour.Equal(at(15, 11, 0)): // week 3, Tuesday 11:00: 1500, usually 240 both weeks
			return map[string]load{"shop.example.com": {1500, 1}, "api.example.com": {50, 0}}
		case hour.Equal(at(15, 12, 0)): // week 3, Tuesday 12:00: 1500, 5x the lower week but not the higher
			return map[string]load{"shop.example.com": {1500, 1}, "api.example.com": {50, 0}}
		}
		return usual(hour)
	}
	runTraffic(h, at(0, 0, 0), 14*24, loads)
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("learning:\n%s", summaries(ds))
	}
	runTraffic(h, at(14, 0, 0), 2*24, loads)
	ds := h.all(t)
	if len(ds) != 1 || ds[0].Summary != "host shop.example.com — 1500 requests (usually about 240) in the hour 11:00–12:00 Tue" {
		t.Fatalf("week 3 (ordinary at 10:00 after a spike week, a surge at 11:00, none at 12:00):\n%s", summaries(ds))
	}
	// Week 4's Tuesday 10:00 at 2400 again: earlier weeks 240, 2400, 240 — a surge.
	runTraffic(h, at(21, 0, 0), 24+10, usual)
	runTraffic(h, at(22, 10, 0), 2, func(hour time.Time) map[string]load {
		if hour.Equal(at(22, 10, 0)) {
			return map[string]load{"shop.example.com": {2400, 1}, "api.example.com": {50, 0}}
		}
		return usual(hour)
	})
	if ds := h.detections(t, ruleTrafficSurge); len(ds) != 2 ||
		ds[0].Summary != "host shop.example.com — 2400 requests (usually about 240) in the hour 10:00–11:00 Tue" {
		t.Fatalf("week 4:\n%s", summaries(ds))
	}
}

// The hour named is the one counted, with its real local start and end.
func TestBaselineTrafficHourLabelHalfHourZone(t *testing.T) {
	ist := time.FixedZone("IST", 5*3600+1800)
	start := time.Date(2026, 12, 1, 4, 0, 0, 0, time.UTC) // 09:30–10:30 IST
	if got := hourSpan(start, ist); got != "09:30–10:30 Tue" {
		t.Fatalf("hourSpan %q", got)
	}
	if got := hourSpan(time.Date(2026, 12, 1, 18, 0, 0, 0, time.UTC), ist); got != "23:30–00:30 Tue" {
		t.Fatalf("hourSpan across midnight %q", got)
	}
}
