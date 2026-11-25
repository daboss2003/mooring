package detect

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

// Lines that differ only in masked values (numbers, addresses, durations, IDs) are one template.
func TestPatternSameTemplateForMaskedValues(t *testing.T) {
	h := patHarness(t, nil)
	var evs []siem.Event
	for i := range 50 {
		evs = append(evs, appLine(t0.Add(time.Duration(i)*time.Second), "shop", "web", siem.LvlInfo,
			fmt.Sprintf("user %d logged in from 203.0.113.%d:%d in %dms req=%08x", i, i, 40000+i, i*3, 0xabc00000+i*7919)))
	}
	h.mine(evs...)
	ps := h.patterns(t, siem.PatternFilter{})
	if len(ps) != 1 || ps[0].Template != "user <NUM> logged in from <IP> in <NUM> req=<HEX>" || ps[0].Count != 50 {
		t.Fatalf("patterns: %+v", ps)
	}
	if p := ps[0]; p.Scope != "app:shop/web" || p.App != "shop" || p.Service != "web" || p.Level != siem.LvlInfo ||
		!p.First.Equal(t0) || !p.Last.Equal(t0.Add(49*time.Second)) || p.State != siem.PatternLearned || !validPatternID(p.ID) {
		t.Fatalf("pattern: %+v", p)
	}
	// Another service of the app, and the host, are scopes of their own.
	h.mine(appLine(t0.Add(time.Minute), "shop", "worker", siem.LvlWarn, "user 1 logged in from 203.0.113.1:1 in 1ms req=00000001"),
		hostLine(t0.Add(time.Minute), "", "user 1 logged in from 203.0.113.1:1 in 1ms req=00000001"))
	if ps := h.patterns(t, siem.PatternFilter{}); len(ps) != 3 {
		t.Fatalf("%d patterns over three scopes", len(ps))
	}
	if ps := h.patterns(t, siem.PatternFilter{Host: true}); len(ps) != 1 || ps[0].Scope != "host" || ps[0].App != "" {
		t.Fatalf("host: %+v", ps)
	}
}

// Drain: lines of one shape that share most tokens join one template, the differing positions
// become <*> (key=<*> for the values of one key); lines sharing less start their own.
func TestPatternDrainMerges(t *testing.T) {
	h := patHarness(t, nil)
	h.mine(appLine(t0, "shop", "web", "", "connected to db primary"),
		appLine(t0, "shop", "web", "", "connected to db replica"),
		appLine(t0, "shop", "web", "", "login user=alice result ok"),
		appLine(t0, "shop", "web", "", "login user=bob result ok"),
		appLine(t0, "shop", "web", "", "connected over tls very slowly"),
		appLine(t0, "shop", "web", "", "queue alpha drained items quickly today"),
		appLine(t0, "shop", "web", "", "queue alpha drained items slowly today"),
		appLine(t0, "shop", "web", "", "queue alpha failed hard on startup"))
	got := map[string]int64{}
	for _, p := range h.patterns(t, siem.PatternFilter{}) {
		got[p.Template] = p.Count
	}
	want := map[string]int64{"connected to db <*>": 2, "login user=<*> result ok": 2, "connected over tls very slowly": 1,
		"queue alpha drained items <*> today": 2, "queue alpha failed hard on startup": 1}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("templates %v, want %v", got, want)
	}
	// The ID stays the one the template was made with.
	p := h.tmplOf("shop", "web", "connected to db primary")
	if p == nil || p.id != patternID("app:shop/web", "connected to db primary", 0) {
		t.Fatal("ID changed when the template merged")
	}
}

// A repeated line costs no allocation: tokenize, mask, fingerprint, count.
func TestPatternRepeatLineNoAlloc(t *testing.T) {
	h := patHarness(t, nil)
	msg := "GET /api/orders 200 15ms from 203.0.113.7 user=alice"
	h.mine(appLine(t0, "shop", "web", siem.LvlInfo, msg))
	m := h.pm()
	l := patLine{ts: t0.UnixNano(), lvl: 1, app: "shop", svc: "web", msg: msg}
	rs := m.loadRules()
	now := t0.UnixNano()
	allocs := testing.AllocsPerRun(500, func() { m.mine(&l, false, &rs, now) })
	if allocs != 0 {
		t.Fatalf("%v allocations per repeated line", allocs)
	}
	if p := h.tmplOf("shop", "web", msg); p == nil || p.count < 500 {
		t.Fatal("repeats not counted")
	}
}

// A scope learns for the rule's learning period: templates seen meanwhile are learned; one first
// seen after it is new and reported once it settled (Window after its first line): pattern.new
// (low) below warn, pattern.new_error (medium) at warn or above. The summary names the pattern's ID
// and the scope, never its text; the detection joins no incident; it is reported once, also across
// a restart.
func TestPatternNewAfterLearning(t *testing.T) {
	h := patHarness(t, nil)
	h.incidents = true
	h.e.lim.incidents = true
	start := t0
	h.patTick(start)
	h.mine(appLine(start, "shop", "web", siem.LvlInfo, "cache warmed in 12ms"))
	h.mine(appLine(start.Add(6*day), "shop", "web", siem.LvlInfo, "startup banner frobnicated widgets"))
	h.patTick(start.Add(6*day + time.Hour))
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("detections while learning: %v", ds)
	}
	after := start.Add(7*day + time.Hour)
	h.mine(appLine(after, "shop", "web", siem.LvlInfo, "cache warmed in 15ms"),
		appLine(after, "shop", "web", siem.LvlInfo, "quarterly sprocket reconciliation began"),
		appLine(after.Add(time.Second), "shop", "web", siem.LvlError, "payment gateway rejected merchant credentials"),
		appLine(after.Add(2*time.Second), "shop", "web", siem.LvlError, "payment gateway rejected merchant credentials"))
	newP, errP := h.tmplOf("shop", "web", "quarterly sprocket reconciliation began"), h.tmplOf("shop", "web", "payment gateway rejected merchant credentials")
	if newP == nil || errP == nil || newP.state != siem.PatternNew || errP.state != siem.PatternNew ||
		h.tmplOf("shop", "web", "startup banner frobnicated widgets").state != siem.PatternLearned {
		t.Fatal("states after learning")
	}
	h.patTick(after.Add(4 * time.Minute))
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("reported before it settled: %v", ds)
	}
	h.patTick(after.Add(5*time.Minute + 3*time.Second))
	nd, ed := h.detections(t, rulePatternNew), h.detections(t, rulePatternNewError)
	if len(nd) != 1 || len(ed) != 1 || len(h.all(t)) != 2 {
		t.Fatalf("new %v, new_error %v", nd, ed)
	}
	n, e := nd[0], ed[0]
	if n.Key != newP.id || n.Severity != siem.SevLow || n.App != "shop" || n.Service != "web" || n.Count != 1 ||
		e.Key != errP.id || e.Severity != siem.SevMedium || e.Count != 2 {
		t.Fatalf("detections: %+v / %+v", n, e)
	}
	if want := "log pattern " + newP.id + " — new in shop/web: 1 line in 5m3s (info)"; n.Summary != want {
		t.Fatalf("summary %q, want %q", n.Summary, want)
	}
	for _, d := range []siem.Detection{n, e} {
		for _, w := range []string{"sprocket", "reconciliation", "payment", "gateway", "credentials", "merchant"} {
			if strings.Contains(d.Summary, w) {
				t.Fatalf("summary has the template's text: %q", d.Summary)
			}
		}
		if !strings.HasSuffix(e.Summary, "(error)") {
			t.Fatalf("new_error summary %q", e.Summary)
		}
	}
	if len(h.e.incs) != 0 || len(h.e.incNew) != 0 {
		t.Fatal("a pattern detection opened an incident")
	}
	for _, ev := range h.out.events() {
		if ev.F["incident_id"] != nil || ev.F["rule"] == rulePatternNew && ev.F["key"] != newP.id {
			t.Fatalf("emitted %+v", ev)
		}
	}
	// Reported once: more lines, more ticks, a restart.
	h.mine(appLine(after.Add(10*time.Minute), "shop", "web", siem.LvlInfo, "quarterly sprocket reconciliation began"))
	h.patTick(after.Add(11 * time.Minute))
	h.patReopen(t)
	h.patTick(after.Add(12 * time.Minute))
	h.mine(appLine(after.Add(13*time.Minute), "shop", "web", siem.LvlInfo, "quarterly sprocket reconciliation began"))
	h.patTick(after.Add(20 * time.Minute))
	if ds := h.all(t); len(ds) != 2 || ds[0].Count+ds[1].Count != 3 {
		t.Fatalf("after more lines and a restart: %v", ds)
	}
}

// A new template is reported once it has Count lines, however long after it settled that is; a
// rule switched off reports nothing then or later.
func TestPatternNewWaitsForCount(t *testing.T) {
	h := patHarness(t, nil)
	h.only(t, patRule(rulePatternNew, func(r *siem.Rule) { r.Count = 3 }), patRule(rulePatternNewError))
	h.e.rules.Load().byID[rulePatternNewError].r.Enabled = false
	h.learnedScope("shop", "web", t0.Add(-8*day))
	h.mine(appLine(t0, "shop", "web", siem.LvlInfo, "rare thing happened"),
		appLine(t0, "shop", "web", siem.LvlError, "rare failure happened twice now"))
	h.patTick(t0.Add(time.Hour))
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("reported with one line: %v", ds)
	}
	h.mine(appLine(t0.Add(2*time.Hour), "shop", "web", siem.LvlInfo, "rare thing happened"),
		appLine(t0.Add(3*time.Hour), "shop", "web", siem.LvlInfo, "rare thing happened"))
	h.patTick(t0.Add(3*time.Hour + time.Second))
	if ds := h.detections(t, rulePatternNew); len(ds) != 1 || ds[0].Count != 3 {
		t.Fatalf("at the third line: %v", ds)
	}
	if p := h.tmplOf("shop", "web", "rare failure happened twice now"); p == nil || !p.reported || p.pending {
		t.Fatal("the switched-off rule's template is still waiting")
	}
	h.only(t, patPack()...)
	h.patTick(t0.Add(4 * time.Hour))
	if ds := h.detections(t, rulePatternNewError); len(ds) != 0 {
		t.Fatalf("reported once the rule was on again: %v", ds)
	}
}

// The owner's states: expected silences pattern.new and pattern.spike, ignored pattern.spike,
// learned watches again. Anything else, or an unknown ID, is refused.
func TestPatternStatesSuppress(t *testing.T) {
	h := patHarness(t, nil)
	h.learnedScope("shop", "web", t0.Add(-8*day))
	h.mine(appLine(t0, "shop", "web", siem.LvlInfo, "first odd line"), appLine(t0, "shop", "web", siem.LvlInfo, "second odd entry here"))
	a, b := h.tmplOf("shop", "web", "first odd line"), h.tmplOf("shop", "web", "second odd entry here")
	ctx := context.Background()
	if err := h.e.SetPatternState(ctx, a.id, siem.PatternExpected, "owner"); err != nil {
		t.Fatal(err)
	}
	h.patTick(t0.Add(10 * time.Minute))
	if ds := h.detections(t, rulePatternNew); len(ds) != 1 || ds[0].Key != b.id {
		t.Fatalf("expected one reported: %v", ds)
	}
	for _, c := range []struct{ id, state string }{{a.id, siem.PatternNew}, {a.id, "bogus"}, {"p0000000000000000", siem.PatternIgnored}} {
		if err := h.e.SetPatternState(ctx, c.id, c.state, "owner"); !errors.Is(err, siem.ErrInvalidInput) {
			t.Fatalf("%s → %s: %v", c.id, c.state, err)
		}
	}
	// Spikes: a template old enough, 200 lines in a minute against no history.
	spikeOf := func(state string) int {
		h := patHarness(t, nil)
		h.learnedScope("shop", "web", t0.Add(-9*day))
		h.mine(appLine(t0.Add(-4*day), "shop", "web", siem.LvlInfo, "job tick done"))
		p := h.tmplOf("shop", "web", "job tick done")
		if state != "" {
			if err := h.e.SetPatternState(ctx, p.id, state, "owner"); err != nil {
				t.Fatal(err)
			}
		}
		h.pm().hours = hourMeta{}
		for h2 := floorDiv(t0.Unix(), 3600) - 8*24; h2 < floorDiv(t0.Unix(), 3600); h2++ {
			h.pm().hours.set(h2, hourLearned)
		}
		var evs []siem.Event
		for i := range 200 {
			evs = append(evs, appLine(t0.Add(time.Duration(i)*100*time.Millisecond), "shop", "web", siem.LvlInfo, "job tick done"))
		}
		h.mine(evs...)
		h.patFire()
		return len(h.detections(t, rulePatternSpike))
	}
	if spikeOf("") != 1 || spikeOf(siem.PatternLearned) != 1 || spikeOf(siem.PatternExpected) != 0 || spikeOf(siem.PatternIgnored) != 0 {
		t.Fatalf("spikes: none %d learned %d expected %d ignored %d", spikeOf(""), spikeOf(siem.PatternLearned),
			spikeOf(siem.PatternExpected), spikeOf(siem.PatternIgnored))
	}
}

// runHours mines, from from (an hour start), hours of lines: load gives a template's lines in an
// hour, spread over its minutes; the engine ticks every 2 minutes (Run: every second).
func runHours(h *harness, from time.Time, hours int, load func(hour time.Time) map[string]int) {
	for i := range hours {
		hs := from.Add(time.Duration(i) * time.Hour)
		l := load(hs)
		for mi := 0; mi < 60; mi += 2 {
			var evs []siem.Event
			for x := mi; x < mi+2; x++ {
				mt := hs.Add(time.Duration(x) * time.Minute)
				for msg, n := range l {
					k := n / 60
					if x < n%60 {
						k++
					}
					for j := range k {
						evs = append(evs, appLine(mt.Add(time.Duration(j)*time.Millisecond), "shop", "web", siem.LvlInfo, msg))
					}
				}
			}
			h.mine(evs...)
			h.patTick(hs.Add(time.Duration(mi)*time.Minute + 90*time.Second))
		}
	}
}

// pattern.spike: a known template's lines in the last Window against its usual count at that time of
// day (that local hour and the hours either side, on the previous 7 days): a burst over the usual
// fires, the same burst where it is usual doesn't.
func TestPatternSpike(t *testing.T) {
	berlin, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Skip(err)
	}
	h := patHarness(t, berlin)
	day0 := time.Date(2026, 11, 10, 0, 0, 0, 0, berlin)
	h.clk.set(day0.Add(-time.Minute))
	h.learnedScope("shop", "web", day0.Add(-time.Hour)) // its templates are made while it learns
	const quiet, busy, side = "nightly report sent", "order placed ok", "cache refresh finished"
	runHours(h, day0, 7*24+10, func(hr time.Time) map[string]int {
		l := hr.In(berlin)
		if l.Day() == 17 {
			return nil
		}
		m := map[string]int{quiet: 1}
		switch l.Hour() {
		case 9, 10, 11:
			m[busy] = 600 // usually 100 in 10 minutes
		}
		switch l.Hour() {
		case 8, 9, 11, 12:
			m[side] = 600 // around 10:00, not at 10:00
		}
		return m
	})
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("detections while building history: %v", ds)
	}
	m := h.pm()
	if st := m.hours.state(floorDiv(day0.Add(3*day+10*time.Hour).Unix(), 3600)); st != hourLearned {
		t.Fatalf("a watched hour is %d", st)
	}
	burst := func(msg string, n int, at time.Time) {
		var evs []siem.Event
		for i := range n {
			evs = append(evs, appLine(at.Add(time.Duration(i)*time.Second), "shop", "web", siem.LvlInfo, msg))
		}
		h.mine(evs...)
		h.patFire()
	}
	at := time.Date(2026, 11, 17, 10, 0, 0, 0, berlin)
	h.patTick(at)
	burst(quiet, 150, at)
	burst(busy, 450, at)
	burst(side, 300, at) // usual: the middle of 14 hours of 600 (09:00, 11:00) and 7 of 0 (10:00) → 100 in 10m
	ds := h.detections(t, rulePatternSpike)
	if len(ds) != 1 || ds[0].Key != h.tmplOf("shop", "web", quiet).id {
		t.Fatalf("spikes: %v", ds)
	}
	if want := "log pattern " + ds[0].Key + " — shop/web: 100 lines in 10m, usually about 0.2"; ds[0].Summary != want {
		t.Fatalf("summary %q, want %q", ds[0].Summary, want)
	}
	// Past Factor × the usual it fires for the busy one too.
	burst(busy, 300, at.Add(500*time.Second))
	if ds := h.detections(t, rulePatternSpike); len(ds) != 2 {
		t.Fatalf("busy template past 5× its usual: %v", ds)
	}
}

// Hours count as history only when watched whole: not the hour the miner started in, nor one with a
// gap in the ticks, nor (lossy) one in which the miner's queue dropped lines.
func TestPatternWatchedHours(t *testing.T) {
	h := patHarness(t, nil)
	m := h.pm()
	base := time.Date(2026, 11, 24, 5, 30, 0, 0, time.UTC)
	tickEvery := func(from, to time.Time) {
		for at := from; at.Before(to); at = at.Add(time.Minute) {
			h.patTick(at)
		}
	}
	tickEvery(base, base.Add(4*time.Hour))
	hr := func(x int) int64 { return floorDiv(base.Unix(), 3600) + int64(x) }
	if m.hours.state(hr(0)) != hourOff || m.hours.state(hr(1)) != hourLearned || m.hours.state(hr(2)) != hourLearned {
		t.Fatalf("first hours: %d %d %d", m.hours.state(hr(0)), m.hours.state(hr(1)), m.hours.state(hr(2)))
	}
	// A 5-minute gap in hour 4, then lines dropped in hour 5.
	tickEvery(base.Add(4*time.Hour), base.Add(4*time.Hour+10*time.Minute))
	tickEvery(base.Add(4*time.Hour+15*time.Minute), base.Add(5*time.Hour+10*time.Minute))
	m.dropped.Add(1) // at 10:40
	tickEvery(base.Add(5*time.Hour+10*time.Minute), base.Add(8*time.Hour))
	if m.hours.state(hr(3)) != hourLearned || m.hours.state(hr(4)) != hourOff || m.hours.state(hr(5)) != hourLossy ||
		m.hours.state(hr(6)) != hourLearned {
		t.Fatalf("hours 3-6: %d %d %d %d", m.hours.state(hr(3)), m.hours.state(hr(4)), m.hours.state(hr(5)), m.hours.state(hr(6)))
	}
	// They survive a restart; the hours while stopped are not watched.
	h.patReopen(t)
	m = h.pm()
	tickEvery(base.Add(10*time.Hour), base.Add(13*time.Hour))
	if m.hours.state(hr(5)) != hourLossy || m.hours.state(hr(6)) != hourLearned || m.hours.state(hr(8)) != hourOff ||
		m.hours.state(hr(10)) != hourOff || m.hours.state(hr(11)) != hourLearned {
		t.Fatalf("after a restart: %d %d %d %d %d", m.hours.state(hr(5)), m.hours.state(hr(6)), m.hours.state(hr(8)),
			m.hours.state(hr(10)), m.hours.state(hr(11)))
	}
}

// pattern.churn: once a scope has learned, more new templates than its cap allows (a minute's, an
// hour's) overflow, and the scope's churn is reported (key: the scope); while it learns, not.
func TestPatternChurnOnCap(t *testing.T) {
	h := patHarness(t, nil)
	h.learnedScope("shop", "web", t0.Add(-8*day))
	h.learnedScope("shop", "fresh", t0.Add(-time.Hour))
	var evs []siem.Event
	for i := range 25 {
		w := fmt.Sprintf("%c%c%c", 'a'+i%26, 'b'+i%25, 'c'+i%24)
		evs = append(evs, appLine(t0, "shop", "web", siem.LvlInfo, "x"+w+" y"+w+" z"+w),
			appLine(t0, "shop", "fresh", siem.LvlInfo, "x"+w+" y"+w+" z"+w))
	}
	h.mine(evs...)
	h.patFire()
	st := h.e.PatternStats()
	if st.Patterns != 40 || st.Overflowed != 10 || st.Unmined != 10 || st.Lines != 50 {
		t.Fatalf("stats %+v", st)
	}
	ds := h.detections(t, rulePatternChurn)
	if len(ds) != 1 || ds[0].Key != "app:shop/web" || ds[0].Service != "web" || ds[0].Severity != siem.SevMedium || ds[0].Count != 1 {
		t.Fatalf("churn: %v", ds)
	}
	if want := "log scope app:shop/web — new log patterns past the cap (20 a minute, 100 an hour); 1 line not sorted into a pattern"; ds[0].Summary != want {
		t.Fatalf("summary %q", ds[0].Summary)
	}
	// The next minute the cap starts again.
	h.mine(appLine(t0.Add(time.Minute), "shop", "web", siem.LvlInfo, "brand new line"))
	if h.tmplOf("shop", "web", "brand new line") == nil {
		t.Fatal("no template the next minute")
	}
}

// Past the CPU budget (MaxCPUPercent of the miner's busy time in a one-second slice, checked every
// patBatch lines) only lines that fit a known template (its fingerprint) are counted; the others are
// unmined until the slice ends. Twice past it the goroutine pauses until the slice ends.
func TestPatternBudget(t *testing.T) {
	h := patHarness(t, nil, func(o *Options) { o.Patterns.MaxCPUPercent = 5 })
	m := h.pm()
	if m.bud.limit != 50*time.Millisecond {
		t.Fatalf("limit %v", m.bud.limit)
	}
	clk := time.Unix(1_800_000_000, 0)
	m.clock = func() time.Time { clk = clk.Add(30 * time.Millisecond); return clk }
	known := "known line here"
	l := func(msg string) []patLine {
		return []patLine{{ts: t0.UnixNano(), app: "shop", svc: "web", lvl: 1, msg: msg}}
	}
	m.step(l(known))         // 30ms
	m.step(l("another one")) // 60ms: over from the next batch
	if m.bud.busy != 60*time.Millisecond {
		t.Fatalf("busy %v", m.bud.busy)
	}
	m.step(append(l(known), l("not seen before")...))
	if p := h.tmplOf("shop", "web", known); p == nil || p.count != 2 || h.tmplOf("shop", "web", "not seen before") != nil ||
		m.unmined.Load() != 1 || m.lines.Load() != 4 {
		t.Fatalf("over budget: unmined %d lines %d", m.unmined.Load(), m.lines.Load())
	}
	if pct := h.e.PatternStats().BudgetPct; pct < 2.9 || pct > 3.1 { // 90ms of 60 × 50ms
		t.Fatalf("budget pct %v", pct)
	}
	pause := m.step(l("still over"))
	if pause <= 0 || pause > time.Second {
		t.Fatalf("pause %v at %v busy", pause, m.bud.busy)
	}
	clk = clk.Add(time.Second)
	m.step(l("not seen before"))
	if h.tmplOf("shop", "web", "not seen before") == nil {
		t.Fatal("not mined in the next slice")
	}
}

// offerPattern never blocks: past the queue's slots or bytes a line is dropped and counted.
func TestPatternQueueFull(t *testing.T) {
	h := patHarness(t, nil)
	m := h.pm()
	start := time.Now()
	for i := range patQueue + 904 {
		ev := appLine(t0, "shop", "web", "", fmt.Sprint("line ", i))
		h.e.offerPattern(&ev)
	}
	if time.Since(start) > 5*time.Second || len(m.q) != patQueue || m.dropped.Load() != 904 {
		t.Fatalf("queued %d, dropped %d", len(m.q), m.dropped.Load())
	}
	if st := h.e.PatternStats(); st.Dropped != 904 {
		t.Fatalf("stats %+v", st)
	}
	h.drainQueue()
	if m.qSize.Load() != 0 {
		t.Fatalf("queued bytes %d after the drain", m.qSize.Load())
	}
	// Long lines: the byte budget holds first; a line is cut to maxPatLine.
	big := strings.Repeat("y", 4*maxPatLine)
	for range patQueue {
		ev := appLine(t0, "shop", "web", "", big)
		h.e.offerPattern(&ev)
	}
	if n := len(m.q); n >= patQueue || int64(n)*(maxPatLine+patLineCost+7) > patQueueBytes || m.qSize.Load() > patQueueBytes {
		t.Fatalf("%d long lines queued (%d bytes)", n, m.qSize.Load())
	}
	if l := <-m.q; len(l.msg) != maxPatLine {
		t.Fatalf("a line of %d bytes queued", len(l.msg))
	}
}

// What is mined: an app's lines with a message (not of an excluded app); the host's unclassified
// lines from a file or written by root through the journal. Not: classified host events, another
// journal sender's lines, the edge's, Mooring's, the SIEM's own; nothing with patterns off.
func TestPatternFeed(t *testing.T) {
	h := patHarness(t, nil, func(o *Options) { o.Patterns.ExcludeApps = []string{"noisy"} })
	m := h.pm()
	in := []siem.Event{
		appLine(t0, "shop", "web", "", "kept app line"),
		appLine(t0, "noisy", "web", "", "excluded app line"),
		appLine(t0, "shop", "web", "", ""),
		appLine(t0, "", "web", "", "an app line without an app"),
		hostLine(t0, "", "kept file line"),
		hostLine(t0, "0", "kept root journal line"),
		hostLine(t0, "1000", "logger -t sshd forged"),
		{TS: t0, Src: siem.SrcHost, Kind: siem.KindLog, Msg: "odd sender type", F: map[string]any{"sender_uid": 0.0}},
		{TS: t0, Src: siem.SrcHost, Kind: siem.KindSSHLogin, Msg: "Accepted password for root"},
		{TS: t0, Src: siem.SrcEdge, Kind: siem.KindHTTPRequest, Msg: "GET /"},
		{TS: t0, Src: siem.SrcMooring, Kind: "mooring.login", Msg: "login"},
		{TS: t0, Src: siem.SrcSIEM, Kind: "siem.detection", Msg: "x"},
	}
	for i := range in {
		h.e.offerPattern(&in[i])
	}
	var got []string
	for len(m.q) > 0 {
		got = append(got, (<-m.q).msg)
	}
	if want := "[kept app line kept file line kept root journal line]"; fmt.Sprint(got) != want {
		t.Fatalf("queued %v", got)
	}
	// Through the pipeline's subscriber too (timely events only).
	sub := h.e.Subscriber()
	sub(appLine(h.clk.now(), "shop", "web", "", "via the subscriber"))
	sub(appLine(h.clk.now().Add(-2*day), "shop", "web", "", "too old"))
	if len(m.q) != 1 || (<-m.q).msg != "via the subscriber" {
		t.Fatal("subscriber")
	}
	off := newHarness(t, false)
	ev := appLine(t0, "shop", "web", "", "patterns off")
	off.e.offerPattern(&ev)
	if off.e.miner() != nil || off.e.patternFires() != nil || off.e.PatternStats().Enabled {
		t.Fatal("patterns off")
	}
	if ps, err := off.e.Patterns(context.Background(), siem.PatternFilter{}); err != nil || len(ps) != 0 {
		t.Fatalf("patterns off: %v %v", ps, err)
	}
}

// Hostile random lines can't grow the miner past its caps: scopes, templates per scope and in all,
// tree nodes, the fingerprint cache; the protected share stays within three quarters.
func TestPatternCapsUnderFlood(t *testing.T) {
	h := patHarness(t, nil)
	m := h.pm()
	m.lim = patLimits{scopes: 6, scopeTemplates: 40, templates: 150, newPerMin: 1000, newPerHour: 100000, leafClusters: 8,
		kids: 10, cache: 300}
	rng := rand.New(rand.NewPCG(1, 2))
	word := func() string {
		b := make([]byte, 1+rng.IntN(12))
		for i := range b {
			b[i] = "abcdefghijklmnopqrstuvwxyzABCDEF0123456789=\"' :/[]-_."[rng.IntN(53)]
		}
		return string(b)
	}
	for round := range 40 {
		var evs []siem.Event
		for i := range 500 {
			n := 1 + rng.IntN(70)
			ws := make([]string, n)
			for j := range ws {
				ws[j] = word()
			}
			at := t0.Add(time.Duration(round)*time.Hour + time.Duration(i)*time.Millisecond)
			evs = append(evs, appLine(at, "app", fmt.Sprint("svc", rng.IntN(9)), siem.LvlInfo, strings.Join(ws, " ")))
		}
		h.mine(evs...)
		checkPatBounds(t, m)
	}
	if m.ntmpl == 0 || len(m.scopes) != 6 || m.overflowed.Load() == 0 {
		t.Fatalf("%d templates, %d scopes, %d overflowed", m.ntmpl, len(m.scopes), m.overflowed.Load())
	}
	// One scope alone past its cap; one leaf (same length, same first two tokens) past its cap.
	var svcs []string
	for k := range m.scopes {
		svcs = append(svcs, k.svc)
	}
	svcs = sortedStrings(svcs)
	var evs []siem.Event
	for i := range 300 {
		evs = append(evs, appLine(t0.Add(41*time.Hour), "app", svcs[0], siem.LvlInfo,
			fmt.Sprintf("flood%c%c next%c%c", 'a'+i%26, 'a'+i/26, 'a'+i/26, 'a'+i%26)+strings.Repeat(" x", i%7)),
			appLine(t0.Add(41*time.Hour), "app", svcs[1], siem.LvlInfo, fmt.Sprintf("GET /fixed %s %s q%c", word(), word(), 'a'+i%26)))
	}
	h.mine(evs...)
	checkPatBounds(t, m)
	m.mu.Lock()
	if n := m.scopes[scopeKey{app: "app", svc: svcs[0]}].n; n != m.lim.scopeTemplates {
		t.Errorf("a flooded scope holds %d templates", n)
	}
	m.mu.Unlock()
	// The tree keeps no empty nodes, so the caps never stop new templates for good.
	h.mine(appLine(t0.Add(54*time.Hour), "app", svcs[2], siem.LvlInfo, "a fresh shape of line at the end"))
	if h.tmplOf("app", svcs[2], "a fresh shape of line at the end") == nil {
		t.Error("no template for a fresh line after the flood")
	}
	h.e.savePatterns()
	if n := len(patRows(t, h)); n != m.ntmpl {
		t.Fatalf("%d rows for %d templates", n, m.ntmpl)
	}
}

// The usual count of a time of day survives a daylight saving change: the previous days' hours are
// the same wall-clock hours (09:00–11:00 local), not 24-hour steps (which land an hour off before
// the change).
func TestPatternSpikeDST(t *testing.T) {
	berlin, err := time.LoadLocation("Europe/Berlin")
	if err != nil {
		t.Skip(err)
	}
	h := patHarness(t, berlin)
	day0 := time.Date(2026, 10, 20, 0, 0, 0, 0, berlin) // summer time ends on 25 October
	h.clk.set(day0.Add(-time.Minute))
	h.learnedScope("shop", "web", day0.Add(-time.Hour))
	const msg = "morning batch item done"
	end := time.Date(2026, 10, 27, 10, 0, 0, 0, berlin)
	runHours(h, day0, int(end.Sub(day0)/time.Hour), func(hr time.Time) map[string]int {
		switch l := hr.In(berlin); {
		case l.Day() == 27:
			return nil
		case l.Hour() >= 8 && l.Hour() <= 10:
			return map[string]int{msg: 600}
		}
		return nil
	})
	h.patTick(end)
	var evs []siem.Event
	for i := range 300 {
		evs = append(evs, appLine(end.Add(time.Duration(i)*time.Second), "shop", "web", siem.LvlInfo, msg))
	}
	h.mine(evs...)
	h.patFire()
	if ds := h.detections(t, rulePatternSpike); len(ds) != 0 {
		t.Fatalf("a usual burst spiked across the clock change: %v", ds)
	}
}

// Templates seen in two hours or more are protected from eviction, at most three quarters of a
// scope's and of all templates; past that the least recently used go back to the others.
func TestPatternProtectedShare(t *testing.T) {
	h := patHarness(t, nil)
	m := h.pm()
	m.lim = patLimits{scopes: 6, scopeTemplates: 40, templates: 150, newPerMin: 1000, newPerHour: 100000, leafClusters: 8,
		kids: 100, cache: 600}
	for hr := range 3 {
		var evs []siem.Event
		for i := range 140 {
			evs = append(evs, appLine(t0.Add(time.Duration(hr)*time.Hour), "app", fmt.Sprint("s", i%6), siem.LvlInfo,
				fmt.Sprintf("steady%c%c next%c%c end", 'a'+i%26, 'a'+i/26, 'a'+i/26, 'a'+i%26)))
		}
		h.mine(evs...)
		checkPatBounds(t, m)
	}
	if n := m.plru.Len(); n != m.lim.templates/4*3 || m.ntmpl != 140 {
		t.Fatalf("%d protected of %d templates", n, m.ntmpl)
	}
	for _, sc := range m.scopes {
		if sc.plru.Len() > m.lim.scopeTemplates/4*3 {
			t.Fatalf("scope %s: %d protected", sc.name, sc.plru.Len())
		}
	}
}
