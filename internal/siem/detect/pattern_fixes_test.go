package detect

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

// A daily job whose lines all fall in one hour isn't a spike on the eighth day (its usual is that
// hour's own count on the previous days, not the middle of it and its two quiet neighbours); the
// same burst at a time of day that was quiet all week is one.
func TestPatternSpikeDailyOneHourJob(t *testing.T) {
	h := patHarness(t, nil)
	day0 := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	h.clk.set(day0.Add(-time.Minute))
	h.learnedScope("shop", "web", day0.Add(-time.Hour))
	const msg = "nightly export row written"
	end := day0.Add(7*day + 2*time.Hour)
	runHours(h, day0, int(end.Sub(day0)/time.Hour), func(hr time.Time) map[string]int {
		if hr.UTC().Hour() == 2 {
			return map[string]int{msg: 600}
		}
		return nil
	})
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("detections during the week of history: %d (%s)", len(ds), ds[0].Summary)
	}
	burst := func(at time.Time) int {
		h.patTick(at)
		var evs []siem.Event
		for i := range 300 {
			evs = append(evs, appLine(at.Add(time.Duration(i)*time.Second), "shop", "web", siem.LvlInfo, msg))
		}
		h.mine(evs...)
		h.patFire()
		return len(h.detections(t, rulePatternSpike))
	}
	if n := burst(end); n != 0 {
		t.Fatalf("the job at its daily hour spiked: %d", n)
	}
	// The hour after the job's (a neighbour of it) is no spike either: the highest of the three.
	if n := burst(end.Add(time.Hour)); n != 0 {
		t.Fatalf("the job an hour late spiked: %d", n)
	}
	ds := h.detections(t, rulePatternSpike)
	if n := burst(end.Add(12 * time.Hour)); n != 1 {
		t.Fatalf("the job's lines at 14:00, quiet all week: %d spikes (%v)", n, ds)
	}
}

// usualOf needs three watched hours of one hour of the day: two days of history are none.
func TestPatternSpikeNeedsThreeDaysOfAnHour(t *testing.T) {
	h := patHarness(t, nil)
	day0 := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	h.clk.set(day0.Add(-time.Minute))
	h.learnedScope("shop", "web", day0.Add(-time.Hour))
	runHours(h, day0, 2*24+12, func(hr time.Time) map[string]int { return map[string]int{"tick": 1} })
	m := h.pm()
	m.mu.Lock()
	defer m.mu.Unlock()
	var tp *ptmpl
	for _, x := range m.byID {
		tp = x
	}
	at := day0.Add(2*day + 12*time.Hour)
	if _, ok := m.usualOf(tp, at.UnixNano(), 10*time.Minute); ok {
		t.Fatal("a usual from two days of history")
	}
	tp.usualKey = 0
	// With a third day it is known.
	for hr := floorDiv(at.Unix(), 3600); hr < floorDiv(at.Unix(), 3600)+24; hr++ {
		m.hours.set(hr, hourLearned)
	}
	if _, ok := m.usualOf(tp, at.Add(day).UnixNano(), 10*time.Minute); !ok {
		t.Fatal("no usual from three days of history")
	}
}

func churnLines(at time.Time, round, n int) []siem.Event {
	var evs []siem.Event
	for i := range n {
		w := fmt.Sprintf("%c%c%c", 'a'+i%26, 'a'+i/26, 'a'+round)
		evs = append(evs, appLine(at, "shop", "web", "", "zz"+w+" qq"+w+" ww"+w))
	}
	return evs
}

// A template the owner marked (expected, ignored) isn't forgotten for room while unmarked ones
// exist, however much the scope churns.
func TestPatternOwnerMarkNotEvicted(t *testing.T) {
	h := patHarness(t, nil)
	m := h.pm()
	m.lim = patLimits{scopes: 6, scopeTemplates: 40, templates: 150, newPerMin: 1000, newPerHour: 100000, leafClusters: 64, kids: 100, cache: 600}
	h.learnedScope("shop", "web", t0.Add(-8*day))
	h.patTick(t0)
	const line = "nightly reconciliation finished okay"
	h.mine(appLine(t0, "shop", "web", "", line))
	id := h.tmplOf("shop", "web", line).id
	if err := h.e.SetPatternState(context.Background(), id, siem.PatternIgnored, "o"); err != nil {
		t.Fatal(err)
	}
	// Each churned template is seen in two hours, so protected.
	for round := range 3 {
		for hr := range 2 {
			h.mine(churnLines(t0.Add(time.Duration(1+round*2+hr)*time.Hour), round, 35)...)
			checkPatBounds(t, m)
		}
	}
	if _, ok, _ := h.e.Pattern(context.Background(), id); !ok {
		t.Fatal("the owner's ignored template was forgotten for room")
	}
	h.mine(appLine(t0.Add(10*time.Hour), "shop", "web", "", line))
	if p := h.tmplOf("shop", "web", line); p == nil || p.id != id || p.state != siem.PatternIgnored {
		t.Fatalf("after the churn the line's template: %+v", p)
	}
}

// When only marked templates are left to forget for room, the mark outlives the template: the
// same template made again (also after a restart) has the owner's state, not new. Setting learned
// drops the mark; deleting the app drops its marks.
func TestPatternOwnerMarkOutlivesEviction(t *testing.T) {
	ctx := context.Background()
	h := patHarness(t, nil)
	h.pm().lim.scopeTemplates = 3
	old := defaultPatLimits
	defaultPatLimits.scopeTemplates = 3
	defer func() { defaultPatLimits = old }()
	h.learnedScope("shop", "web", t0.Add(-8*day))
	h.patTick(t0)
	msgs := []string{"alpha first line here", "beta second entry now okay", "gamma third thing", "delta fourth message with words"}
	states := []string{siem.PatternIgnored, siem.PatternExpected, siem.PatternIgnored}
	ids := make([]string, 3)
	for i := range 3 {
		h.mine(appLine(t0.Add(time.Duration(i)*time.Second), "shop", "web", "", msgs[i]))
		ids[i] = h.tmplOf("shop", "web", msgs[i]).id
		if err := h.e.SetPatternState(ctx, ids[i], states[i], "o"); err != nil {
			t.Fatal(err)
		}
	}
	// A fourth template: the least recently used marked one (alpha) makes room.
	h.mine(appLine(t0.Add(time.Minute), "shop", "web", "", msgs[3]))
	if h.tmplOf("shop", "web", msgs[3]) == nil || h.tmplOf("shop", "web", msgs[0]) != nil {
		t.Fatal("setup: alpha wasn't forgotten for delta")
	}
	checkPatBounds(t, h.pm())
	// It comes back as the owner left it (the unmarked delta makes room for it, not a marked one).
	h.mine(appLine(t0.Add(2*time.Minute), "shop", "web", "", msgs[0]))
	if p := h.tmplOf("shop", "web", msgs[0]); p == nil || p.id != ids[0] || p.state != siem.PatternIgnored || p.pending {
		t.Fatalf("alpha made again: %+v", p)
	}
	if h.tmplOf("shop", "web", msgs[3]) != nil || h.tmplOf("shop", "web", msgs[1]) == nil || h.tmplOf("shop", "web", msgs[2]) == nil {
		t.Fatal("a marked template made room while an unmarked one was left")
	}
	// The marks are stored: after a restart beta (now the least recently seen) makes room for a
	// new line and comes back expected.
	h.patTick(t0.Add(3 * time.Minute))
	h.patReopen(t)
	h.mine(appLine(t0.Add(4*time.Minute), "shop", "web", "", "epsilon fifth kind of line seen"))
	if h.tmplOf("shop", "web", msgs[1]) != nil {
		t.Fatal("setup: beta wasn't forgotten for epsilon")
	}
	h.mine(appLine(t0.Add(5*time.Minute), "shop", "web", "", msgs[1]))
	if p := h.tmplOf("shop", "web", msgs[1]); p == nil || p.id != ids[1] || p.state != siem.PatternExpected {
		t.Fatalf("beta made again after a restart: %+v", p)
	}
	h.patTick(t0.Add(20 * time.Minute))
	// Only gamma is reported: made new and set ignored, which doesn't cancel the report; the marked
	// ones made again (alpha, beta) aren't new, and delta and epsilon were forgotten before settling.
	if ds := h.all(t); len(ds) != 1 || ds[0].Key != ids[2] {
		t.Fatalf("new reports: %v, want gamma's only", ds)
	}
	checkPatBounds(t, h.pm())
	// Watch again: the mark is gone with the state, so the template made again is new.
	if err := h.e.SetPatternState(ctx, ids[0], siem.PatternLearned, "o"); err != nil {
		t.Fatal(err)
	}
	h.mine(appLine(t0.Add(21*time.Minute), "shop", "web", "", "zeta sixth and last kind of line seen here"))
	if h.tmplOf("shop", "web", msgs[0]) != nil {
		t.Fatal("setup: alpha (unmarked now) wasn't forgotten for zeta")
	}
	h.mine(appLine(t0.Add(23*time.Minute), "shop", "web", "", msgs[0]))
	if p := h.tmplOf("shop", "web", msgs[0]); p == nil || p.state != siem.PatternNew {
		t.Fatalf("alpha after learned: %+v", p)
	}
	// An app delete drops its marks (memory and rows).
	h.patTick(t0.Add(24 * time.Minute))
	var n int
	if err := h.e.db.w.QueryRow(`SELECT COUNT(*) FROM pattern_marks`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("%d stored marks, %v (want beta's and gamma's)", n, err)
	}
	if err := h.e.DeleteAppPatterns(ctx, "shop"); err != nil {
		t.Fatal(err)
	}
	if err := h.e.db.w.QueryRow(`SELECT COUNT(*) FROM pattern_marks`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("%d stored marks when DeleteAppPatterns returned, %v", n, err)
	}
	h.patTick(t0.Add(25 * time.Minute))
	h.learnedScope("shop", "web", t0.Add(-8*day))
	h.mine(appLine(t0.Add(40*time.Minute), "shop", "web", "", msgs[1]))
	if p := h.tmplOf("shop", "web", msgs[1]); p == nil || p.state != siem.PatternNew {
		t.Fatalf("beta after the app was deleted: %+v", p)
	}
	h.e.savePatterns()
	if err := h.e.db.w.QueryRow(`SELECT COUNT(*) FROM pattern_marks`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("%d stored marks after the app delete, %v", n, err)
	}
}

// At most maxPatMarks marks are kept: past that the one set longest ago goes.
func TestPatternOwnerMarksBounded(t *testing.T) {
	h := patHarness(t, nil)
	m := h.pm()
	m.mu.Lock()
	for i := range maxPatMarks + 10 {
		m.setMark(fmt.Sprintf("p%016x", i), "app:shop/web", siem.PatternIgnored, t0.Add(time.Duration(i)*time.Second).UnixNano())
	}
	n, first, last := len(m.marks), m.marks[fmt.Sprintf("p%016x", 0)], m.marks[fmt.Sprintf("p%016x", maxPatMarks+9)]
	m.mu.Unlock()
	if n != maxPatMarks || first != nil || last == nil {
		t.Fatalf("%d marks, oldest %v, newest %v", n, first, last)
	}
	h.e.savePatterns()
	var rows int
	if err := h.e.db.w.QueryRow(`SELECT COUNT(*) FROM pattern_marks`).Scan(&rows); err != nil || rows != maxPatMarks {
		t.Fatalf("%d rows, %v", rows, err)
	}
	// Damaged rows (the newest, so among those read) are dropped at load, with the rows past the cap.
	for _, q := range []string{
		`INSERT INTO pattern_marks(id, scope, state, set_ns) VALUES ('P0000000000000000', 'app:shop/web', 'ignored', ?)`,
		`INSERT INTO pattern_marks(id, scope, state, set_ns) VALUES ('pffffffffffffff01', 'nowhere', 'ignored', ?)`,
		`INSERT INTO pattern_marks(id, scope, state, set_ns) VALUES ('pffffffffffffff02', 'app:shop/web', 'new', ?)`,
		`INSERT INTO pattern_marks(id, scope, state, set_ns) VALUES ('pffffffffffffff03', 'app:shop/web', 'learned', ?)`,
	} {
		if _, err := h.e.db.w.Exec(q, t0.Add(day).UnixNano()); err != nil {
			t.Fatal(err)
		}
	}
	h.patReopen(t)
	if n := len(h.pm().marks); n != maxPatMarks-4 {
		t.Fatalf("%d marks loaded, want %d", n, maxPatMarks-4)
	}
	h.e.savePatterns()
	if err := h.e.db.w.QueryRow(`SELECT COUNT(*) FROM pattern_marks`).Scan(&rows); err != nil || rows != maxPatMarks-4 {
		t.Fatalf("%d rows after the damaged ones, %v", rows, err)
	}
}

// A template the owner marked is kept patOwnerForget without a line (an unmarked one patForget),
// then forgotten with its mark.
func TestPatternOwnerMarkedForgetLater(t *testing.T) {
	ctx := context.Background()
	h := patHarness(t, nil)
	h.patTick(t0)
	// The owner's template is the only one of its scope: the scope stays with it.
	h.mine(appLine(t0, "shop", "audit", "", "yearly audit export done"), appLine(t0, "shop", "web", "", "plain line seen once"),
		appLine(t0, "shop", "web", "", "keep me around"))
	id, plain := h.tmplOf("shop", "audit", "yearly audit export done").id, h.tmplOf("shop", "web", "plain line seen once").id
	keep := h.tmplOf("shop", "web", "keep me around").id
	for _, x := range []string{id, keep} {
		if err := h.e.SetPatternState(ctx, x, siem.PatternExpected, "o"); err != nil {
			t.Fatal(err)
		}
	}
	run := func(from, to time.Time) {
		for at := from; at.Before(to); at = at.Add(6 * time.Hour) {
			h.patTick(at)
			h.mine(appLine(at, "shop", "web", "", "keep me around"))
		}
	}
	run(t0.Add(time.Hour), t0.Add(patOwnerForget-day))
	if _, ok, _ := h.e.Pattern(ctx, plain); ok {
		t.Fatal("an unmarked quiet template is kept")
	}
	if p, ok, _ := h.e.Pattern(ctx, id); !ok || p.State != siem.PatternExpected {
		t.Fatalf("the owner's template after %v: %v", patOwnerForget-day, ok)
	}
	run(t0.Add(patOwnerForget-day), t0.Add(patOwnerForget+2*day))
	if _, ok, _ := h.e.Pattern(ctx, id); ok {
		t.Fatal("the owner's template is kept for good")
	}
	// Its mark went with it; the mark of the template with lines all along stays, however old.
	m := h.pm()
	if m.marks[id] != nil || m.marks[keep] == nil {
		t.Fatalf("marks: the quiet one's %v, the active one's %v", m.marks[id] != nil, m.marks[keep] != nil)
	}
	// Forgotten for room now, the active one's mark counts its patOwnerForget from here.
	at := t0.Add(patOwnerForget + 2*day)
	m.mu.Lock()
	m.evict(m.byID[keep], nil, at.UnixNano())
	m.mu.Unlock()
	for x := at; x.Before(at.Add(3 * time.Hour)); x = x.Add(time.Hour) {
		h.patTick(x)
	}
	if m.marks[keep] == nil {
		t.Fatal("a mark was dropped as soon as its template was forgotten for room")
	}
}

// A clock that ran ahead and was corrected (while running, or between two runs): the hours close
// again, scopes and templates don't keep times in the future (learning, settling, the spike's
// history), samples are still cleared after the retention, and a deleted app's lines are mined again.
func TestPatternClockSetBack(t *testing.T) {
	for _, mode := range []string{"running", "restart", "restart on the wrong clock"} {
		t.Run(mode, func(t *testing.T) {
			restart := mode == "restart"
			h := patHarness(t, nil, func(o *Options) { o.Patterns.SampleRetention = 2 * day })
			future := t0.Add(400 * day)
			h.patTick(future)
			for at := future; !at.After(future.Add(3 * time.Hour)); at = at.Add(time.Minute) {
				h.patTick(at)
			}
			h.mine(appLine(future.Add(3*time.Hour), "shop", "web", "", "hello wrong clock"))
			if err := h.e.DeleteAppPatterns(context.Background(), "gone"); err != nil {
				t.Fatal(err)
			}
			h.patTick(future.Add(3*time.Hour + time.Second))
			if h.pm().hours.closed < floorDiv(future.Unix(), 3600) {
				t.Fatal("setup: no hour closed on the wrong clock")
			}
			if mode == "restart on the wrong clock" {
				// Loaded while the clock is still ahead; set back before the first tick.
				h.patReopen(t)
			}
			h.clk.set(t0)
			if restart {
				h.patReopen(t)
				// Put right at the load, before any tick: the dashboard reads from then on.
				if p := h.patterns(t, siem.PatternFilter{}); len(p) != 1 || p[0].First.After(t0.Add(patSkew)) || p[0].Last.After(t0.Add(patSkew)) {
					t.Fatalf("after the load: %+v", p)
				}
			}
			h.patTick(t0)
			h.mine(appLine(t0, "shop", "api", "", "user 1 signed in"))
			id := h.tmplOf("shop", "api", "user 1 signed in").id
			wrong := h.tmplOf("shop", "web", "hello wrong clock")
			if wrong == nil {
				t.Fatal("the template made on the wrong clock is gone")
			}
			end := t0.Add(2*day + 3*time.Hour)
			for at := t0.Add(time.Minute); at.Before(end); at = at.Add(time.Minute) {
				h.clk.set(at)
				h.e.patternTick()
			}
			m := h.pm()
			m.mu.Lock()
			st := m.hours.state(floorDiv(t0.Add(5*time.Hour).Unix(), 3600))
			sc := m.scopes[scopeKey{app: "shop", svc: "web"}]
			scFirst, tFirst, tLast, sampleAt := sc.first, wrong.first, wrong.last, wrong.sampleAt
			learning := m.learning(sc, t0.Add(7*day+time.Minute).UnixNano(), int64(7*day))
			m.mu.Unlock()
			if st != hourLearned {
				t.Errorf("an hour watched whole after the clock was set back is %d", st)
			}
			if p, _, _ := h.e.Pattern(context.Background(), id); p.Sample != "" {
				t.Errorf("sample kept past the retention: %q", p.Sample)
			}
			if p, ok, _ := h.e.Pattern(context.Background(), wrong.id); !ok || p.Sample != "" {
				t.Errorf("the wrong clock's sample kept past the retention: %q (%v)", p.Sample, ok)
			}
			if lim := t0.Add(patSkew).UnixNano(); scFirst > lim || tFirst > lim || tLast > lim || sampleAt > lim || learning {
				t.Errorf("times left in the future: scope first %v, template first %v last %v sample %v; learning a week on: %v",
					time.Unix(0, scFirst).UTC(), time.Unix(0, tFirst).UTC(), time.Unix(0, tLast).UTC(), time.Unix(0, sampleAt).UTC(), learning)
			}
			// The app deleted on the wrong clock is mined again (appGoneFor after the correction at most).
			h.mine(appLine(end, "gone", "web", "", "back again"))
			if h.tmplOf("gone", "web", "back again") == nil {
				t.Error("a deleted app's lines aren't mined long after the clock was set back")
			}
		})
	}
}

// A clock set back by less than an hour (no closed hour is ahead of it): the times past it are
// brought back all the same.
func TestPatternClockSetBackWithinTheHour(t *testing.T) {
	h := patHarness(t, nil)
	h.learnedScope("shop", "web", t0.Add(-8*day))
	for at := t0.Add(30 * time.Minute); !at.After(t0.Add(40 * time.Minute)); at = at.Add(time.Minute) {
		h.patTick(at)
	}
	h.mine(appLine(t0.Add(40*time.Minute), "shop", "web", "", "made half an hour ahead"))
	tp := h.tmplOf("shop", "web", "made half an hour ahead")
	h.patTick(t0.Add(10 * time.Minute))
	if h.pm().hours.closed >= floorDiv(t0.Unix(), 3600) {
		t.Fatal("setup: a closed hour is ahead of the clock")
	}
	if got := time.Unix(0, tp.first).UTC(); got.After(t0.Add(10*time.Minute + patSkew)) {
		t.Fatalf("the template's first line is still at %v", got)
	}
	// It settles 5 minutes on, not 35.
	h.patTick(t0.Add(16 * time.Minute))
	if ds := h.detections(t, rulePatternNew); len(ds) != 1 {
		t.Fatalf("new reports 6 minutes after the clock was set back: %v", ds)
	}
	// A step back within patSkew is no correction.
	h.mine(appLine(t0.Add(17*time.Minute), "shop", "web", "", "another line made just ahead"))
	tp = h.tmplOf("shop", "web", "another line made just ahead")
	h.patTick(t0.Add(17 * time.Minute))
	h.patTick(t0.Add(16 * time.Minute))
	if tp.first != t0.Add(17*time.Minute).UnixNano() {
		t.Fatal("a step back of a minute moved a template's first line")
	}
}

// The sample expiry and the forgetting don't wait for an hour to close: they run with a run's
// first tick and then every patSweepEvery by the clock.
func TestPatternSweepByTheClock(t *testing.T) {
	h := patHarness(t, nil, func(o *Options) { o.Patterns.SampleRetention = 2 * day })
	for at := t0; !at.After(t0.Add(10 * time.Minute)); at = at.Add(time.Minute) {
		h.patTick(at) // the hour before closes at 12:02; the next at 13:02
	}
	h.mine(appLine(t0.Add(10*time.Minute), "shop", "web", "", "user 1 signed in"))
	tp := h.tmplOf("shop", "web", "user 1 signed in")
	m := h.pm()
	tick := func(at time.Time) string {
		h.clk.set(at)
		m.mu.Lock()
		defer m.mu.Unlock()
		m.tick(at)
		return tp.sample
	}
	m.mu.Lock()
	tp.sampleAt = t0.Add(-3 * day).UnixNano() // expired
	m.sweepAt = t0.Add(10*time.Minute - patSweepEvery + time.Minute)
	m.mu.Unlock()
	if s := tick(t0.Add(10*time.Minute + 30*time.Second)); s == "" {
		t.Fatal("swept before patSweepEvery passed")
	}
	if s := tick(t0.Add(11 * time.Minute)); s != "" {
		t.Fatalf("not swept patSweepEvery after the last sweep (no hour closed): %q", s)
	}
	// A run's first tick sweeps.
	m.mu.Lock()
	tp.sample, tp.sampleAt = "x", t0.Add(-3*day).UnixNano()
	m.sweepAt = time.Time{}
	m.mu.Unlock()
	if s := tick(t0.Add(12 * time.Minute)); s != "" {
		t.Fatalf("the first tick didn't sweep: %q", s)
	}
}

// An hour in which the miner was over its CPU budget and left lines uncounted is no history
// (lossy, as when the queue dropped lines).
func TestPatternOverBudgetHourLossy(t *testing.T) {
	h := patHarness(t, nil, func(o *Options) { o.Patterns.MaxCPUPercent = 5 })
	m := h.pm()
	h.patTick(t0.Add(-time.Hour))
	clk := time.Unix(1_800_000_000, 0)
	m.clock = func() time.Time { return clk }
	l := func(ts time.Time, msg string) []patLine {
		return []patLine{{ts: ts.UnixNano(), app: "shop", svc: "web", lvl: 1, msg: msg}}
	}
	tickTo := func(from, to time.Time) {
		for at := from; !at.After(to); at = at.Add(time.Minute) {
			h.clk.set(at)
			h.e.patternTick()
		}
	}
	at := t0.Add(10 * time.Minute) // the hour before is closed by then
	tickTo(t0.Add(-59*time.Minute), at)
	m.step(l(at, "order shipped to alice"))
	m.step(l(at, "order shipped to bob"))
	m.clock = func() time.Time { clk = clk.Add(60 * time.Millisecond); return clk }
	m.step(l(at, "order shipped to bob")) // over the budget from here
	m.clock = func() time.Time { return clk }
	for i := range 500 {
		m.step(l(at, fmt.Sprintf("order shipped to user%c%c", 'a'+i%26, 'a'+i/26)))
	}
	tp := h.tmplOf("shop", "web", "order shipped to bob")
	if tp == nil || tp.count >= 503 || m.unmined.Load() == 0 {
		t.Fatalf("setup: every line was counted (%d unmined)", m.unmined.Load())
	}
	tickTo(at.Add(time.Minute), t0.Add(2*time.Hour+3*time.Minute))
	m.mu.Lock()
	st, before, after := m.hours.state(floorDiv(t0.Unix(), 3600)), m.hours.state(floorDiv(t0.Unix(), 3600)-1), m.hours.state(floorDiv(t0.Unix(), 3600)+1)
	m.mu.Unlock()
	if st != hourLossy || before != hourLearned || after != hourLearned {
		t.Fatalf("the hour with uncounted lines is %d (want lossy, %d); the one before %d, after %d", st, hourLossy, before, after)
	}
}

// The fingerprint cache's bound over all scopes holds, and a scope with few lines keeps its
// entries when another filled the cache.
func TestPatternCacheGlobalCap(t *testing.T) {
	h := patHarness(t, nil)
	m := h.pm()
	m.lim = patLimits{scopes: 6, scopeTemplates: 100, templates: 1000, newPerMin: 1000, newPerHour: 100000, leafClusters: 64, kids: 100, cache: 10}
	h.patTick(t0)
	for i := range 10 {
		h.mine(appLine(t0, "big", "web", "", fmt.Sprintf("alpha%c beta%c gamma%c", 'a'+i, 'a'+i, 'a'+i)))
	}
	for range 3 {
		for i := range 5 {
			h.mine(appLine(t0, "small", "web", "", fmt.Sprintf("one%c two%c three%c", 'a'+i, 'a'+i, 'a'+i)))
		}
		checkPatBounds(t, m)
	}
	m.mu.Lock()
	small, nc := len(m.scopes[scopeKey{app: "small", svc: "web"}].cache), m.ncache
	m.mu.Unlock()
	if nc > m.lim.cache || small != 5 {
		t.Fatalf("%d cached of %d at most; the small scope has %d of its 5 lines", nc, m.lim.cache, small)
	}
}

// A panic the engine recovers from (safe) under the miner's lock leaves the lock free: tick, a
// state change, a save.
func TestPatternPanicLeavesLockFree(t *testing.T) {
	free := func(t *testing.T, m *miner) {
		t.Helper()
		got := make(chan bool, 1)
		go func() {
			ok := m.mu.TryLock()
			if ok {
				m.mu.Unlock()
			}
			got <- ok
		}()
		if !<-got {
			t.Fatal("the miner's lock is still held after a recovered panic")
		}
	}
	t.Run("tick", func(t *testing.T) {
		h := patHarness(t, nil)
		h.pm().clock = func() time.Time { panic("boom") }
		h.e.safe(h.e.patternTick)
		free(t, h.pm())
	})
	t.Run("state", func(t *testing.T) {
		h := patHarness(t, nil)
		h.mine(appLine(t0, "shop", "web", "", "some line here"))
		id := h.tmplOf("shop", "web", "some line here").id
		h.e.savePatterns()
		h.pm().dirtySet = nil // a write to it panics
		h.e.safe(func() { _ = h.e.SetPatternState(context.Background(), id, siem.PatternIgnored, "o") })
		free(t, h.pm())
		h.pm().dirtySet = map[*ptmpl]struct{}{}
	})
	for _, full := range []bool{false, true} {
		t.Run(fmt.Sprint("save full=", full), func(t *testing.T) {
			h := patHarness(t, nil)
			m := h.pm()
			m.urgent = append(m.urgent, &ptmpl{dirty: true}) // no scope: its row panics
			h.e.safe(func() { h.e.savePatternsNow(full) })
			free(t, m)
		})
	}
	t.Run("rewrite", func(t *testing.T) {
		h := patHarness(t, nil)
		m := h.pm()
		bad := &ptmpl{id: "p0000000000000000"}
		m.mu.Lock()
		m.resync = true
		m.byID[bad.id] = bad
		bad.gel = m.lru.PushFront(bad)
		m.mu.Unlock()
		h.e.safe(func() { h.e.savePatternsNow(true) })
		free(t, m)
		m.mu.Lock()
		m.lru.Remove(bad.gel)
		delete(m.byID, bad.id)
		m.resync = false
		m.mu.Unlock()
	})
}

// With patterns switched off the stored sample lines are cleared at start; with them on, a sample
// past the retention isn't loaded.
func TestPatternSamplesClearedAtStart(t *testing.T) {
	on := true
	h := patHarness(t, nil, func(o *Options) { o.Patterns.Enabled = on; o.Patterns.SampleRetention = 2 * day })
	h.patTick(t0)
	h.mine(appLine(t0, "shop", "web", "", "customer note: call me at home"))
	id := h.tmplOf("shop", "web", "customer note: call me at home").id
	h.e.savePatterns()
	stored := func() (n int, sample string, at int64) {
		if err := h.e.db.w.QueryRow(`SELECT COUNT(*), COALESCE(MAX(sample),''), COALESCE(MAX(sample_ns),0) FROM patterns`).Scan(&n, &sample, &at); err != nil {
			t.Fatal(err)
		}
		return
	}
	if n, s, _ := stored(); n != 1 || s == "" {
		t.Fatalf("setup: %d rows, sample %q", n, s)
	}
	// On, within the retention: loaded.
	h.clk.set(t0.Add(day))
	h.patReopen(t)
	if p, ok, _ := h.e.Pattern(context.Background(), id); !ok || p.Sample == "" {
		t.Fatalf("a sample within the retention wasn't loaded (%v)", ok)
	}
	// On, past it: not served from the first moment, and cleared in the store by the next save.
	h.clk.set(t0.Add(3 * day))
	h.patReopen(t)
	if p, ok, _ := h.e.Pattern(context.Background(), id); !ok || p.Sample != "" {
		t.Fatalf("an expired sample was loaded: %q (%v)", p.Sample, ok)
	}
	h.e.savePatterns()
	if n, s, at := stored(); n != 1 || s != "" || at != 0 {
		t.Fatalf("after the load: %d rows, sample %q at %d", n, s, at)
	}
	// Off: cleared at start, the template's row kept.
	h.mine(appLine(t0.Add(3*day), "shop", "web", "", "customer note: call me at home"))
	h.e.savePatterns()
	if _, s, _ := stored(); s == "" {
		t.Fatal("setup: no sample stored again")
	}
	on = false
	h.reopen(t)
	if n, s, at := stored(); n != 1 || s != "" || at != 0 {
		t.Fatalf("patterns off: %d rows, sample %q at %d", n, s, at)
	}
}

// A line learned into a template of the <*> child (its first token came past a node's children
// cap) is that template's after a restart too: the template is stored with the path it took.
func TestPatternRestartAtKidsCap(t *testing.T) {
	old := defaultPatLimits
	defaultPatLimits.kids = 3
	defer func() { defaultPatLimits = old }()
	h := patHarness(t, nil)
	h.patTick(t0)
	h.mine(appLine(t0, "shop", "web", "", "alpha one two"),
		appLine(t0.Add(time.Second), "shop", "web", "", "beta three four"),
		appLine(t0.Add(2*time.Second), "shop", "web", "", "gamma five six"),
		appLine(t0.Add(3*time.Second), "shop", "web", "", "delta five six"))
	w := h.tmplOf("shop", "web", "delta five six")
	if w == nil || w != h.tmplOf("shop", "web", "gamma five six") {
		t.Fatalf("setup: delta not merged with gamma: %v", w)
	}
	// alpha and beta are seen again later, so they are read back after it.
	h.mine(appLine(t0.Add(time.Hour), "shop", "web", "", "alpha one two"), appLine(t0.Add(time.Hour), "shop", "web", "", "beta three four"))
	h.patReopen(t)
	after := t0.Add(8 * day)
	h.patTick(after)
	h.mine(appLine(after, "shop", "web", "", "delta five six"), appLine(after, "shop", "web", "", "epsilon five six"))
	for _, msg := range []string{"delta five six", "epsilon five six"} {
		if w2 := h.tmplOf("shop", "web", msg); w2 == nil || w2.id != w.id || w2.state != siem.PatternLearned {
			t.Fatalf("%q after a restart: %+v, want the learned %s", msg, w2, w.id)
		}
	}
	if n := h.pm().ntmpl; n != 3 {
		t.Fatalf("%d templates", n)
	}
	h.patTick(after.Add(6 * time.Minute))
	if ds := h.all(t); len(ds) != 0 {
		t.Fatalf("a learned line reported as new: %v", ds)
	}
	checkPatBounds(t, h.pm())
}

// A line whose first token has a child of its own since is still its old template's, in the <*>
// child's leaf: both are looked in before a template is made.
func TestPatternLooksInWildcardSibling(t *testing.T) {
	h := patHarness(t, nil)
	m := h.pm()
	m.lim.kids = 3
	h.mine(appLine(t0, "shop", "web", "", "alpha one two"),
		appLine(t0, "shop", "web", "", "beta three four"),
		appLine(t0, "shop", "web", "", "gamma five six")) // past the cap: in the <*> child
	w := h.tmplOf("shop", "web", "gamma five six")
	m.mu.Lock()
	m.forget(m.byID[patternID("app:shop/web", "alpha one two", 0)])
	m.mu.Unlock()
	h.mine(appLine(t0, "shop", "web", "", "gamma seven eight")) // gamma has a child of its own now
	if x := h.tmplOf("shop", "web", "gamma seven eight"); x == nil || x == w {
		t.Fatal("setup: no template of its own for gamma seven eight")
	}
	n := m.ntmpl
	h.mine(appLine(t0, "shop", "web", "", "gamma five nine"))
	if x := h.tmplOf("shop", "web", "gamma five nine"); x != w || m.ntmpl != n || w.text != "gamma five <*>" || w.count != 2 {
		t.Fatalf("gamma five nine: template %+v (%d templates, were %d), want %s", x, m.ntmpl, n, w.id)
	}
	checkPatBounds(t, m)
}

// Past a scope's cap at load the rows seen most recently are kept.
func TestPatternLoadKeepsNewest(t *testing.T) {
	h := patHarness(t, nil)
	h.patTick(t0)
	msg := func(i int) string {
		return fmt.Sprintf("message%c number%c here%c okay%c", 'a'+i, 'a'+i, 'a'+i, 'a'+i)
	}
	for i := range 6 {
		h.mine(appLine(t0.Add(time.Duration(i)*time.Minute), "shop", "web", "", msg(i)))
	}
	old := defaultPatLimits
	defaultPatLimits.scopeTemplates = 3
	defer func() { defaultPatLimits = old }()
	h.patReopen(t)
	var kept []int
	for i := range 6 {
		if h.tmplOf("shop", "web", msg(i)) != nil {
			kept = append(kept, i)
		}
	}
	if fmt.Sprint(kept) != "[3 4 5]" {
		t.Fatalf("kept %v, want the three seen last", kept)
	}
	// The most recently seen is the last to be forgotten for room.
	m := h.pm()
	m.mu.Lock()
	back := backOf(&m.scopes[scopeKey{app: "shop", svc: "web"}].lru, &m.lru)
	m.mu.Unlock()
	if back == nil || back.id != patternID("app:shop/web", msg(3), 0) {
		t.Fatalf("the least recently used after the load: %+v", back)
	}
	h.e.savePatterns()
	if n := len(patRows(t, h)); n != 3 {
		t.Fatalf("%d rows after the load's save", n)
	}
	checkPatBounds(t, m)
}

// A scope with no template left and no line for patForget is dropped (its row too), so it doesn't
// count toward the scopes' cap; one with lines is kept. When its last line was mined is stored (to
// the day), so a restart neither starts the 30 days again nor forgets a recent line.
func TestPatternEmptyScopeDropped(t *testing.T) {
	h := patHarness(t, nil)
	h.patTick(t0)
	h.mine(appLine(t0, "shop", "once", "", "a job that ran one time"), appLine(t0, "shop", "web", "", "keep me around"))
	h.e.savePatterns()
	if !patScopeRows(t, h)["app:shop/once"] {
		t.Fatal("setup: no row for the scope")
	}
	run := func(from, to time.Time) {
		for at := from; at.Before(to); at = at.Add(time.Hour) {
			h.patTick(at)
			if at.Hour() == 0 {
				h.mine(appLine(at, "shop", "web", "", "keep me around"))
			}
		}
	}
	has := func() bool {
		m := h.pm()
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.scopes[scopeKey{app: "shop", svc: "once"}] != nil
	}
	run(t0.Add(time.Hour), t0.Add(10*day))
	// A last line ten days on; then its template goes (as when forgotten for room).
	h.mine(appLine(t0.Add(10*day), "shop", "once", "", "a job that ran one time"))
	m := h.pm()
	m.mu.Lock()
	for _, tp := range m.byID {
		if tp.sc.svc == "once" {
			m.forget(tp)
		}
	}
	m.mu.Unlock()
	run(t0.Add(10*day), t0.Add(20*day))
	h.patReopen(t)
	run(t0.Add(20*day), t0.Add(39*day))
	if !has() {
		t.Fatal("the scope was dropped within 30 days of its last line (after a restart)")
	}
	run(t0.Add(39*day), t0.Add(41*day))
	if has() {
		t.Fatal("an empty scope is kept 31 days after its last line")
	}
	m = h.pm()
	m.mu.Lock()
	web := m.scopes[scopeKey{app: "shop", svc: "web"}]
	m.mu.Unlock()
	if web == nil {
		t.Fatal("the active scope was dropped")
	}
	h.e.savePatterns()
	if rows := patScopeRows(t, h); rows["app:shop/once"] || !rows["app:shop/web"] {
		t.Fatalf("scope rows %v", rows)
	}
	if st := h.e.PatternStats(); st.Scopes != 1 {
		t.Fatalf("stats %+v", st)
	}
}

// A line that makes no template (its leaf is full: counted under the most similar one) forgets
// none for room either.
func TestPatternCreateEvictsOnlyForATemplate(t *testing.T) {
	h := patHarness(t, nil)
	m := h.pm()
	m.lim = patLimits{scopes: 6, scopeTemplates: 10, templates: 150, newPerMin: 1000, newPerHour: 100000, leafClusters: 4, kids: 100, cache: 600}
	var evs []siem.Event
	for i := range 4 {
		w := string(rune('a' + i))
		evs = append(evs, appLine(t0, "shop", "web", "", "GET /fixed a"+w+" b"+w+" c"+w))
	}
	for i := range 6 {
		w := string(rune('a' + i))
		evs = append(evs, appLine(t0, "shop", "web", "", "other"+w+" line"+w+" here"+w))
	}
	h.mine(evs...)
	if m.ntmpl != 10 {
		t.Fatalf("setup: %d templates", m.ntmpl)
	}
	h.mine(appLine(t0.Add(time.Second), "shop", "web", "", "GET /fixed xx yy zz"))
	var lines int64
	for _, ev := range evs {
		tp := h.tmplOf("shop", "web", ev.Msg)
		if tp == nil {
			t.Fatalf("a line that made no template forgot the one of %q", ev.Msg)
		}
		lines += tp.count
	}
	if m.ntmpl != 10 || lines != 11 {
		t.Fatalf("%d templates with %d lines, want the 10 with 11", m.ntmpl, lines)
	}
	if st := h.e.PatternStats(); st.Overflowed != 0 || st.Unmined != 0 {
		t.Fatalf("stats %+v", st)
	}
	// One that does make a template still makes room.
	h.mine(appLine(t0.Add(2*time.Second), "shop", "web", "", "brand new shape of line"))
	if m.ntmpl != 10 || h.tmplOf("shop", "web", "brand new shape of line") == nil {
		t.Fatalf("no room made for a new template: %d", m.ntmpl)
	}
	checkPatBounds(t, m)
}

// pattern.churn's summary names what held the lines back: the new-template cap, no room for the
// line's template, or both; never the line's text.
func TestPatternChurnSummaryByCause(t *testing.T) {
	// Seven two-word lines sharing no word, with 3 children a node and 2 templates a leaf: the fifth
	// and sixth fill the <*>/<*> leaf, the seventh has no room.
	fill := func(h *harness, n int) {
		m := h.pm()
		m.lim.kids, m.lim.leafClusters = 3, 2
		h.learnedScope("shop", "web", t0.Add(-8*day))
		var evs []siem.Event
		for i := range n {
			w := string(rune('a' + i))
			evs = append(evs, appLine(t0, "shop", "web", "", "first"+w+" second"+w))
		}
		h.mine(evs...)
		h.patFire()
	}
	h := patHarness(t, nil)
	fill(h, 7)
	ds := h.detections(t, rulePatternChurn)
	if len(ds) != 1 || h.pm().ntmpl != 6 {
		t.Fatalf("churn: %v (%d templates, %d overflowed)", ds, h.pm().ntmpl, h.pm().overflowed.Load())
	}
	if want := "log scope app:shop/web — no room left for new log patterns; 1 line not sorted into a pattern"; ds[0].Summary != want {
		t.Fatalf("summary %q, want %q", ds[0].Summary, want)
	}
	// The next firing names its own cause only.
	h.pm().lim.newPerMin = 0
	h.mine(appLine(t0.Add(patChurnEvery+time.Minute), "shop", "web", "", "another shape of line entirely here now"))
	select {
	case f := <-h.pm().fires:
		if want := "new log patterns past the cap (0 a minute, 100 an hour); 1 line not sorted into a pattern"; f.what != want {
			t.Fatalf("the next firing: %q, want %q", f.what, want)
		}
	default:
		t.Fatal("no second churn firing")
	}
	// Both causes before the rule's count is reached: both named.
	h = patHarness(t, nil)
	h.only(t, patRule(rulePatternChurn, func(r *siem.Rule) { r.Count = 2 }), patRule(rulePatternNew), patRule(rulePatternNewError))
	fill(h, 6)
	h.pm().lim.newPerMin = 1
	at := t0.Add(time.Minute)
	h.mine(appLine(at, "shop", "web", "", "firstx secondx"), // no room
		appLine(at, "shop", "web", "", "a longer line of some more words"),        // the minute's one template
		appLine(at, "shop", "web", "", "another shape of line entirely here now")) // past the cap
	h.patFire()
	ds = h.detections(t, rulePatternChurn)
	if len(ds) != 1 {
		t.Fatalf("churn after both causes: %v", ds)
	}
	if want := "log scope app:shop/web — new log patterns past the cap (1 a minute, 100 an hour) and no room left for new ones; 2 lines not sorted into a pattern"; ds[0].Summary != want {
		t.Fatalf("summary %q, want %q", ds[0].Summary, want)
	}
}

// Ignored silences a pattern's spikes only: set on a new template not reported yet, its
// pattern.new report still comes (also after a restart). Expected cancels it. A learned template
// set ignored is never reported as new.
func TestPatternIgnoredKeepsNewReport(t *testing.T) {
	for _, restart := range []bool{false, true} {
		t.Run(fmt.Sprint("restart=", restart), func(t *testing.T) {
			ctx := context.Background()
			h := patHarness(t, nil)
			h.patTick(t0.Add(-8 * day))
			h.mine(appLine(t0.Add(-8*day), "shop", "web", "", "learned while the scope learned"))
			h.patTick(t0)
			h.mine(appLine(t0, "shop", "web", "", "ignored before its report"), appLine(t0, "shop", "web", "", "expected before its report came"))
			ign, exp := h.tmplOf("shop", "web", "ignored before its report"), h.tmplOf("shop", "web", "expected before its report came")
			old := h.tmplOf("shop", "web", "learned while the scope learned")
			for id, st := range map[string]string{ign.id: siem.PatternIgnored, exp.id: siem.PatternExpected, old.id: siem.PatternIgnored} {
				if err := h.e.SetPatternState(ctx, id, st, "o"); err != nil {
					t.Fatal(err)
				}
			}
			if restart {
				h.patTick(t0.Add(time.Minute))
				h.patReopen(t)
			}
			h.patTick(t0.Add(6 * time.Minute))
			ds := h.detections(t, rulePatternNew)
			if len(ds) != 1 || ds[0].Key != ign.id {
				t.Fatalf("new reports: %v, want the ignored template's only", ds)
			}
			if p, _, _ := h.e.Pattern(ctx, ign.id); p.State != siem.PatternIgnored {
				t.Fatalf("its state after the report: %s", p.State)
			}
			// Once.
			h.patReopen(t)
			h.patTick(t0.Add(20 * time.Minute))
			if ds := h.all(t); len(ds) != 1 {
				t.Fatalf("after another restart: %v", ds)
			}
		})
	}
}

// Every new pattern gets a detection of its own: the miner sends at most patReportsPerHour reports
// a rule and hour (below the engine's cap on new detections, which would roll the rest up), the
// oldest first; the rest wait for the next hour. The count survives a restart.
func TestPatternNewReportsPaced(t *testing.T) {
	if patReportsPerHour >= newPerHour {
		t.Fatalf("patReportsPerHour %d must stay below the engine's newPerHour %d", patReportsPerHour, newPerHour)
	}
	setup := func(at time.Time) (*harness, []string) {
		h := patHarness(t, nil)
		m := h.pm()
		m.lim.newPerMin, m.lim.newPerHour = 1000, 1000
		h.learnedScope("shop", "web", at.Add(-8*day))
		h.patTick(at)
		ids := make([]string, 100)
		for i := range ids {
			msg := fmt.Sprintf("alpha%c%c beta%c%c gamma%c%c", 'a'+i%26, 'a'+i/26, 'a'+i%26, 'a'+i/26, 'a'+i%26, 'a'+i/26)
			h.mine(appLine(at.Add(time.Duration(i)*time.Millisecond), "shop", "web", "", msg))
			ids[i] = h.tmplOf("shop", "web", msg).id
		}
		return h, ids
	}
	keys := func(h *harness) map[string]bool {
		out := map[string]bool{}
		for _, d := range h.detections(t, rulePatternNew) {
			out[d.Key] = true
		}
		return out
	}
	h, ids := setup(t0)
	h.patTick(t0.Add(3 * time.Minute)) // the hour before closes here: the tick below saves for the reports only
	h.patTick(t0.Add(6 * time.Minute))
	got := keys(h)
	if len(got) != patReportsPerHour {
		t.Fatalf("the first hour: %d detections, want %d", len(got), patReportsPerHour)
	}
	for i, id := range ids {
		if got[id] != (i < patReportsPerHour) {
			t.Fatalf("pattern %d reported: %v (the oldest %d first)", i, got[id], patReportsPerHour)
		}
	}
	h.patTick(t0.Add(30 * time.Minute))
	h.patReopen(t)
	h.patTick(t0.Add(40 * time.Minute))
	if n := len(keys(h)); n != patReportsPerHour {
		t.Fatalf("later in the hour, after a restart: %d detections", n)
	}
	h.patTick(t0.Add(time.Hour + time.Minute))
	if n := len(keys(h)); n != 2*patReportsPerHour {
		t.Fatalf("the second hour: %d detections", n)
	}
	h.patTick(t0.Add(2*time.Hour + time.Minute))
	got = keys(h)
	if len(got) != 100 || len(h.all(t)) != 100 {
		t.Fatalf("the third hour: %d detections of %d in all, want every pattern's own", len(got), len(h.all(t)))
	}
	for _, id := range ids {
		if !got[id] {
			t.Fatalf("pattern %s has no detection", id)
		}
	}
	// Reports sent in an hour's last minute count for the next hour too (the engine may record
	// them after the hour turned).
	h, _ = setup(t0.Add(50 * time.Minute))
	h.patTick(t0.Add(59*time.Minute + 30*time.Second))
	if n := len(keys(h)); n != patReportsPerHour {
		t.Fatalf("late in the hour: %d detections", n)
	}
	h.patTick(t0.Add(time.Hour + 10*time.Second))
	if n := len(keys(h)); n != patReportsPerHour {
		t.Fatalf("just after the hour turned: %d detections", n)
	}
	h.patTick(t0.Add(2*time.Hour + 10*time.Second))
	if n := len(keys(h)); n != 2*patReportsPerHour {
		t.Fatalf("the hour after: %d detections", n)
	}
	// … for the next hour only.
	h, _ = setup(t0.Add(50 * time.Minute))
	h.patTick(t0.Add(59*time.Minute + 30*time.Second))
	h.patTick(t0.Add(2*time.Hour + 10*time.Second))
	if n := len(keys(h)); n != 2*patReportsPerHour {
		t.Fatalf("two hours after late reports: %d detections", n)
	}
}
