package detect

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

var persistLines = []siem.Event{
	appLine(t0, "shop", "web", siem.LvlInfo, "order 17 placed by h:0123456789abcdef in 12ms"),
	appLine(t0, "shop", "web", siem.LvlInfo, "order 18 placed by h:0123456789abcdee in 15ms"),
	appLine(t0.Add(time.Second), "shop", "web", siem.LvlWarn, "connected to db primary"),
	appLine(t0.Add(2*time.Second), "shop", "web", siem.LvlInfo, "connected to db replica"),
	appLine(t0.Add(3*time.Second), "shop", "worker", siem.LvlError, "job 991 failed: timeout after 30s"),
	hostLine(t0.Add(4*time.Second), "", "kernel: eth0 link up at 1000Mbps"),
}

// IDs, templates, counts and states survive a restart, and the trees are rebuilt: the same lines go
// to the same templates. The same first lines make the same IDs on another box too.
func TestPatternStableIDsAcrossRestart(t *testing.T) {
	h := patHarness(t, nil)
	h.mine(persistLines...)
	before := h.patterns(t, siem.PatternFilter{Sort: "first"})
	if len(before) != 4 {
		t.Fatalf("%d patterns", len(before))
	}
	if err := h.e.SetPatternState(context.Background(), before[0].ID, siem.PatternIgnored, "owner"); err != nil {
		t.Fatal(err)
	}
	before[0].State = siem.PatternIgnored
	h.patReopen(t)
	after := h.patterns(t, siem.PatternFilter{Sort: "first"})
	if fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatalf("after a restart:\n%v\nwant\n%v", after, before)
	}
	h.mine(persistLines...)
	again := h.patterns(t, siem.PatternFilter{Sort: "first"})
	if fmt.Sprint(idsOf(again)) != fmt.Sprint(idsOf(before)) {
		t.Fatalf("the same lines made other templates: %v", again)
	}
	for i := range again {
		if again[i].Count != 2*before[i].Count {
			t.Fatalf("%s: count %d, want %d", again[i].ID, again[i].Count, 2*before[i].Count)
		}
	}
	checkPatBounds(t, h.pm())
	other := patHarness(t, nil)
	other.mine(persistLines...)
	if ids := idsOf(other.patterns(t, siem.PatternFilter{Sort: "first"})); fmt.Sprint(ids) != fmt.Sprint(idsOf(before)) {
		t.Fatalf("another box: %v, want %v", ids, idsOf(before))
	}
}

// The write tick saves at most patTickRows templates; a full save all of them.
func TestPatternTickSavesInSlices(t *testing.T) {
	h := patHarness(t, nil)
	var evs []siem.Event
	for i := range 300 {
		evs = append(evs, appLine(t0, "shop", fmt.Sprint("s", i%5), siem.LvlInfo, fmt.Sprintf("w%c%c x%d", 'a'+i%26, 'a'+i/26, i)))
	}
	m := h.pm()
	m.lim.newPerMin, m.lim.newPerHour = 1000, 1000
	h.mine(evs...)
	if n := len(h.patterns(t, siem.PatternFilter{Limit: 200})); n != 200 {
		t.Fatalf("%d listed", n)
	}
	h.e.patternTick()
	if n := len(patRows(t, h)); n != patTickRows {
		t.Fatalf("one tick saved %d rows", n)
	}
	h.e.savePatterns()
	if n := len(patRows(t, h)); n != 300 || len(patScopeRows(t, h)) != 5 {
		t.Fatalf("a full save: %d rows, %d scopes", n, len(patScopeRows(t, h)))
	}
}

// A stored tokenizer version other than the current one has every scope learn again for 24 hours:
// templates made meanwhile are learned, not new; after that new ones are new again.
func TestPatternTokenizerVersionRelearn(t *testing.T) {
	newState := func(bump bool) (during, later string) {
		h := patHarness(t, nil)
		h.learnedScope("shop", "web", t0.Add(-30*day))
		h.mine(appLine(t0, "shop", "web", siem.LvlInfo, "an old known line"))
		h.e.savePatterns()
		if bump {
			patTokVersion++
			defer func() { patTokVersion-- }()
		}
		h.patReopen(t)
		h.mine(appLine(t0.Add(time.Hour), "shop", "web", siem.LvlInfo, "made after the upgrade"))
		h.mine(appLine(t0.Add(26*time.Hour), "shop", "web", siem.LvlInfo, "made a day after it all"))
		h.e.savePatterns()
		if bump {
			var v int
			if err := h.e.db.w.QueryRow(`SELECT tokenizer FROM pattern_scopes WHERE scope = 'app:shop/web'`).Scan(&v); err != nil || v != patTokVersion {
				t.Fatalf("stored tokenizer %d, %v", v, err)
			}
		}
		return h.tmplOf("shop", "web", "made after the upgrade").state, h.tmplOf("shop", "web", "made a day after it all").state
	}
	if d, l := newState(false); d != siem.PatternNew || l != siem.PatternNew {
		t.Fatalf("same tokenizer: %s, %s", d, l)
	}
	if d, l := newState(true); d != siem.PatternLearned || l != siem.PatternNew {
		t.Fatalf("tokenizer changed: %s, %s", d, l)
	}
}

// A row that doesn't decode, of no valid scope, an ID that isn't one, or larger than a valid row
// can be is discarded (and deleted); the others load.
func TestPatternDamagedRows(t *testing.T) {
	h := patHarness(t, nil)
	h.mine(persistLines...)
	h.e.savePatterns()
	w := h.e.db.w
	good := patRows(t, h)
	for _, q := range []string{
		`INSERT INTO patterns(id, scope, state, last_ns, data, updated_ns) VALUES ('p1111111111111111', 'app:shop/web', 'learned', 1, x'0102', 1)`,
		`INSERT INTO patterns(id, scope, state, last_ns, data, updated_ns) SELECT 'p2222222222222222', 'nowhere', state, last_ns, data, 1 FROM patterns LIMIT 1`,
		`INSERT INTO patterns(id, scope, state, last_ns, data, updated_ns) SELECT 'P2222222222222222', scope, state, last_ns, data, 1 FROM patterns LIMIT 1`,
		`INSERT INTO patterns(id, scope, state, last_ns, data, updated_ns) SELECT 'p3333333333333333', scope, 'weird', last_ns, data, 1 FROM patterns LIMIT 1`,
		`INSERT INTO patterns(id, scope, state, last_ns, data, updated_ns) VALUES ('p4444444444444444', 'app:shop/web', 'learned', 1, zeroblob(70000), 1)`,
		`INSERT INTO pattern_meta(name, data) VALUES ('hours', x'09') ON CONFLICT(name) DO UPDATE SET data = excluded.data`,
	} {
		if _, err := w.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	h.patReopen(t)
	if n := len(h.patterns(t, siem.PatternFilter{})); n != len(good) {
		t.Fatalf("%d patterns loaded, want %d", n, len(good))
	}
	h.patTick(h.clk.now())
	h.e.savePatterns()
	if rows := patRows(t, h); fmt.Sprint(rows) != fmt.Sprint(good) {
		t.Fatalf("rows after the save: %v", rows)
	}
}

// DeleteAppPatterns forgets an app's scopes: the saved rows at once, the templates in memory at the
// miner's next step or tick (with any row saved in between); for appGoneFor the app's lines aren't
// mined. Other apps (one whose slug starts the same) and the host are kept. KeepAppPatterns
// forgets every app not listed.
func TestPatternDeleteKeepApps(t *testing.T) {
	ctx := context.Background()
	h := patHarness(t, nil)
	for _, app := range []string{"shop", "shopx", "other"} {
		h.mine(appLine(t0, app, "web", "", "hello from "+app), appLine(t0, app, "worker", "", "working hard"))
	}
	h.mine(hostLine(t0, "", "host line"))
	h.e.savePatterns()
	m := h.pm()
	scopesOf := func() string {
		m.mu.Lock()
		defer m.mu.Unlock()
		var out []string
		for n := range m.byName {
			out = append(out, n)
		}
		return fmt.Sprint(sortedStrings(out))
	}
	// A row of shop's the engine took for saving before the delete, written after it.
	id1 := idsOf(h.patterns(t, siem.PatternFilter{App: "shop", Service: "web"}))[0]
	m.mu.Lock()
	m.markDirty(m.byID[id1])
	late := m.take(10, false)
	m.mu.Unlock()
	if err := h.e.DeleteAppPatterns(ctx, "shop"); err != nil {
		t.Fatal(err)
	}
	rowScopes := func() string {
		rows, err := h.e.db.w.Query(`SELECT scope FROM patterns ORDER BY scope`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var s string
			_ = rows.Scan(&s)
			out = append(out, s)
		}
		return fmt.Sprint(out)
	}
	if got := rowScopes(); got != "[app:other/web app:other/worker app:shopx/web app:shopx/worker host]" || patScopeRows(t, h)["app:shop/web"] {
		t.Fatalf("rows after the call: %s", got)
	}
	if err := h.e.db.writePatterns(ctx, late, h.clk.now().UnixNano()); err != nil {
		t.Fatal(err)
	}
	h.patTick(t0.Add(time.Second))
	if got := scopesOf(); got != "[app:other/web app:other/worker app:shopx/web app:shopx/worker host]" {
		t.Fatalf("scopes after the tick: %s", got)
	}
	h.e.savePatterns()
	if got := rowScopes(); strings.Contains(got, "app:shop/") {
		t.Fatalf("the row saved in between is still there: %s", got)
	}
	// Its lines still queued aren't mined for appGoneFor; after that the app learns again.
	h.mine(appLine(t0.Add(time.Minute), "shop", "web", "", "hello from shop"))
	if strings.Contains(scopesOf(), "app:shop/") {
		t.Fatal("a deleted app's line was mined")
	}
	h.mine(appLine(t0.Add(appGoneFor+time.Minute), "shop", "web", "", "hello from shop"))
	if !strings.Contains(scopesOf(), "app:shop/web") {
		t.Fatal("an app of that slug made again isn't mined")
	}
	if err := h.e.KeepAppPatterns(ctx, []string{"shopx"}); err != nil {
		t.Fatal(err)
	}
	h.patTick(h.clk.now())
	h.e.savePatterns()
	if got := scopesOf(); got != "[app:shopx/web app:shopx/worker host]" {
		t.Fatalf("after KeepAppPatterns: %s", got)
	}
	if got := rowScopes(); got != "[app:shopx/web app:shopx/worker host]" {
		t.Fatalf("rows after KeepAppPatterns: %s", got)
	}
	for _, s := range []string{"", "a/b", strings.Repeat("s", siem.MaxShort+1)} {
		if err := h.e.DeleteAppPatterns(ctx, s); !errors.Is(err, siem.ErrInvalidInput) {
			t.Fatalf("slug %q: %v", s, err)
		}
		if err := h.e.KeepAppPatterns(ctx, []string{"ok", s}); !errors.Is(err, siem.ErrInvalidInput) {
			t.Fatalf("keep %q: %v", s, err)
		}
	}
	// With patterns off it still deletes an earlier run's rows.
	off := newHarness(t, false)
	if _, err := off.e.db.w.Exec(`INSERT INTO patterns(id, scope, state, last_ns, data, updated_ns) VALUES
		('p1111111111111111', 'app:gone/web', 'learned', 1, x'00', 1)`); err != nil {
		t.Fatal(err)
	}
	if err := off.e.DeleteAppPatterns(ctx, "gone"); err != nil || len(patRows(t, off)) != 0 {
		t.Fatalf("patterns off: %v, %d rows", err, len(patRows(t, off)))
	}
	if err := h.e.Close(); err != nil {
		t.Fatal(err)
	}
	if err := h.e.DeleteAppPatterns(ctx, "shopx"); !errors.Is(err, errClosed) {
		t.Fatalf("closed: %v", err)
	}
}

func sortedStrings(s []string) []string {
	out := append([]string(nil), s...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// A template's sample line is refreshed at most hourly and cleared once SampleRetention passed
// since it was taken (at an hour's end); a template quiet for patForget is forgotten.
func TestPatternSampleAndForget(t *testing.T) {
	h := patHarness(t, nil, func(o *Options) { o.Patterns.SampleRetention = 2 * day })
	ctx := context.Background()
	h.patTick(t0)
	h.mine(appLine(t0, "shop", "web", "", "user 1 signed in"), appLine(t0, "shop", "web", "", "keep me around"))
	id := h.tmplOf("shop", "web", "user 1 signed in").id
	keep := h.tmplOf("shop", "web", "keep me around").id
	h.mine(appLine(t0.Add(30*time.Minute), "shop", "web", "", "user 2 signed in"))
	p, ok, err := h.e.Pattern(ctx, id)
	if err != nil || !ok || p.Sample != "user 1 signed in" || len(p.Hourly) != 168 || p.Hourly[167] != 2 || p.Count != 2 {
		t.Fatalf("pattern %+v %v %v", p, ok, err)
	}
	if ps := h.patterns(t, siem.PatternFilter{}); ps[0].Sample != "" || ps[0].Hourly != nil {
		t.Fatal("Patterns lists the sample or the hours")
	}
	h.mine(appLine(t0.Add(90*time.Minute), "shop", "web", "", "user 3 signed in"))
	if p, _, _ := h.e.Pattern(ctx, id); p.Sample != "user 3 signed in" || p.Hourly[167] != 1 || p.Hourly[166] != 2 {
		t.Fatalf("after an hour: %q %v", p.Sample, p.Hourly[165:])
	}
	for at := t0.Add(2 * time.Hour); at.Before(t0.Add(2*day + 3*time.Hour)); at = at.Add(time.Hour) {
		h.patTick(at)
		h.mine(appLine(at, "shop", "web", "", "keep me around"))
	}
	if p, _, _ := h.e.Pattern(ctx, id); p.Sample != "" {
		t.Fatalf("sample kept past the retention: %q", p.Sample)
	}
	h.e.savePatterns()
	var sample string
	if err := h.e.db.w.QueryRow(`SELECT sample FROM patterns WHERE id = ?`, id).Scan(&sample); err != nil || sample != "" {
		t.Fatalf("stored sample %q, %v", sample, err)
	}
	h.mine(appLine(t0.Add(2*day+4*time.Hour), "shop", "web", "", "user 9 signed in"))
	if p, _, _ := h.e.Pattern(ctx, id); p.Sample != "user 9 signed in" {
		t.Fatalf("seen again: %q", p.Sample)
	}
	// 30 days without a line: forgotten (its row too); the one seen meanwhile stays.
	for at := t0.Add(2*day + 5*time.Hour); at.Before(t0.Add(33 * day)); at = at.Add(time.Hour) {
		h.patTick(at)
		if at.Hour() == 0 {
			h.mine(appLine(at, "shop", "web", "", "keep me around"))
		}
	}
	if _, ok, _ := h.e.Pattern(ctx, id); ok {
		t.Fatal("a quiet template wasn't forgotten")
	}
	if _, ok, _ := h.e.Pattern(ctx, keep); !ok {
		t.Fatal("an active template was forgotten")
	}
	h.e.savePatterns()
	if rows := patRows(t, h); rows[id] != "" || rows[keep] == "" {
		t.Fatalf("rows: %v", rows)
	}
}

// The Detections filter Key matches exactly (a pattern's ID, an address), with the other filters and
// the keyset paging.
func TestDetectionFilterKey(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, thresholdRule(1, time.Minute))
	for i, ip := range []string{"203.0.113.7", "203.0.113.70", "203.0.113.7", "198.51.100.1"} {
		h.feed(sshFail(time.Duration(i)*2*time.Hour, ip))
	}
	h.e.flush(true)
	list := func(f siem.DetectionFilter) []siem.Detection {
		ds, err := h.e.Detections(context.Background(), f)
		if err != nil {
			t.Fatal(err)
		}
		return ds
	}
	ds := list(siem.DetectionFilter{Key: "203.0.113.7", Limit: 10})
	if len(ds) != 2 || ds[0].Key != "203.0.113.7" || ds[1].Key != "203.0.113.7" || !ds[0].Last.After(ds[1].Last) {
		t.Fatalf("by key: %v", ds)
	}
	page := list(siem.DetectionFilter{Key: "203.0.113.7", Limit: 1})
	next := list(siem.DetectionFilter{Key: "203.0.113.7", Limit: 1, BeforeLast: page[0].Last, Before: page[0].ID})
	if len(page) != 1 || len(next) != 1 || next[0].ID != ds[1].ID {
		t.Fatalf("paged: %v then %v", page, next)
	}
	if ds := list(siem.DetectionFilter{Key: "203.0.113", Limit: 10}); len(ds) != 0 {
		t.Fatalf("a prefix matched: %v", ds)
	}
	if ds := list(siem.DetectionFilter{Key: "198.51.100.1", RuleID: "nope", Limit: 10}); len(ds) != 0 {
		t.Fatalf("with another rule: %v", ds)
	}
	if ds := list(siem.DetectionFilter{Limit: 10}); len(ds) != 4 {
		t.Fatalf("no key: %d", len(ds))
	}
}

// stopPatterns (the first step of Run's shutdown) stops the miner and hands its last firings to the
// engine, so the final flush writes them.
func TestPatternShutdownHandsOverFirings(t *testing.T) {
	h := patHarness(t, nil)
	h.learnedScope("shop", "web", t0.Add(-8*day))
	h.mine(appLine(t0, "shop", "web", siem.LvlInfo, "late breaking line"))
	m := h.pm()
	p := h.tmplOf("shop", "web", "late breaking line")
	m.start()
	m.mu.Lock()
	m.reports(func() *patRules { r := m.loadRules(); return &r }(), t0.Add(time.Hour).UnixNano())
	m.mu.Unlock()
	h.e.stopPatterns()
	if len(m.fires) != 0 {
		t.Fatal("firings left in the channel")
	}
	h.e.flush(true)
	if ds := h.detections(t, rulePatternNew); len(ds) != 1 || ds[0].Key != p.id {
		t.Fatalf("detections after the stop: %v", ds)
	}
	h.e.stopPatterns() // again: nothing to stop
}

// Run end to end: lines through the pipeline's subscriber are mined by the miner's goroutine, the
// engine's write tick reports the new template, the detection is stored by the time Run returns,
// and the learned state is saved at shutdown. Dashboard calls run meanwhile (go test -race).
func TestPatternRun(t *testing.T) {
	h := patHarness(t, nil)
	h.learnedScope("shop", "web", t0.Add(-8*day))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); h.e.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-done })
	sub := h.e.Subscriber()
	stop := make(chan struct{})
	busy := make(chan struct{})
	go func() {
		defer close(busy)
		for {
			select {
			case <-stop:
				return
			default:
			}
			ps, _ := h.e.Patterns(context.Background(), siem.PatternFilter{Sort: "count"})
			for _, p := range ps {
				_, _, _ = h.e.Pattern(context.Background(), p.ID)
				if p.Level == siem.LvlInfo { // the error template stays new, to be reported
					_ = h.e.SetPatternState(context.Background(), p.ID, siem.PatternExpected, "owner")
				}
			}
			_ = h.e.PatternStats()
			_ = h.e.DeleteAppPatterns(context.Background(), "other")
			time.Sleep(time.Millisecond)
		}
	}()
	for i := range 2000 {
		sub(appLine(t0, "shop", "web", siem.LvlInfo, fmt.Sprint("request ", i, " served")))
		sub(appLine(t0, "other", "web", siem.LvlInfo, "other app line"))
	}
	sub(appLine(t0, "shop", "web", siem.LvlError, "disk almost full on volume data"))
	deadline := time.Now().Add(10 * time.Second)
	for h.e.PatternStats().Lines < 2001 {
		if time.Now().After(deadline) {
			t.Fatalf("mined %d lines", h.e.PatternStats().Lines)
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(stop)
	<-busy
	h.clk.advance(6 * time.Minute)
	var ds []siem.Detection
	for len(ds) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("no detection")
		}
		time.Sleep(20 * time.Millisecond)
		ds, _ = h.e.Detections(context.Background(), siem.DetectionFilter{RuleID: rulePatternNewError})
	}
	cancel()
	<-done
	if ds[0].App != "shop" || ds[0].Service != "web" || !strings.HasPrefix(ds[0].Key, "p") {
		t.Fatalf("detection %+v", ds[0])
	}
	if n := len(patRows(t, h)); n < 2 {
		t.Fatalf("%d rows saved at shutdown", n)
	}
}

// Patterns filters (app, service, host, states, level), sorts and pages; bad filters are refused.
func TestPatternService(t *testing.T) {
	ctx := context.Background()
	h := patHarness(t, nil)
	h.learnedScope("api", "web", t0.Add(-8*day))
	h.mine(appLine(t0, "shop", "web", siem.LvlInfo, "alpha line one"),
		appLine(t0.Add(time.Minute), "shop", "worker", siem.LvlError, "beta failure two"),
		appLine(t0.Add(2*time.Minute), "api", "web", siem.LvlWarn, "gamma warning three"),
		hostLine(t0.Add(3*time.Minute), "", "delta host four"))
	for i := range 5 {
		h.mine(appLine(t0.Add(4*time.Minute+time.Duration(i)*time.Second), "shop", "web", siem.LvlInfo, "alpha line one"))
	}
	h.mine(appLine(t0.Add(5*time.Minute), "api", "web", siem.LvlWarn, "gamma warning three"))
	ids := func(f siem.PatternFilter) string {
		var out []string
		for _, p := range h.patterns(t, f) {
			out = append(out, strings.Fields(p.Template)[0])
		}
		return strings.Join(out, ",")
	}
	for f, want := range map[*siem.PatternFilter]string{
		{}:                                  "gamma,alpha,delta,beta",
		{Sort: "first"}:                     "delta,gamma,beta,alpha",
		{Sort: "count"}:                     "alpha,gamma,delta,beta",
		{App: "shop"}:                       "alpha,beta",
		{App: "shop", Service: "worker"}:    "beta",
		{Host: true}:                        "delta",
		{MinLevel: siem.LvlWarn}:            "gamma,beta",
		{States: []string{siem.PatternNew}}: "gamma",
		{Offset: 1, Limit: 2}:               "alpha,delta",
		{Offset: 10}:                        "",
	} {
		if got := ids(*f); got != want {
			t.Errorf("%+v: %s, want %s", *f, got, want)
		}
	}
	for _, f := range []siem.PatternFilter{{Service: "web"}, {Host: true, App: "shop"}, {States: []string{"bogus"}},
		{MinLevel: "loud"}, {Sort: "random"}} {
		if _, err := h.e.Patterns(ctx, f); !errors.Is(err, siem.ErrInvalidInput) {
			t.Errorf("%+v: %v", f, err)
		}
	}
	if _, ok, err := h.e.Pattern(ctx, "p0000000000000000"); ok || err != nil {
		t.Fatalf("unknown pattern: %v %v", ok, err)
	}
	h.patTick(t0.Add(10 * time.Minute))
	st := h.e.PatternStats()
	if !st.Enabled || st.Scopes != 4 || st.Patterns != 4 || st.Lines != 10 || st.Unmined != 0 ||
		fmt.Sprint(st.Learning) != "[app:shop/web app:shop/worker host]" {
		t.Fatalf("stats %+v", st)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := h.e.Patterns(cctx, siem.PatternFilter{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled: %v", err)
	}
}

// The pattern rules: in the pack (low, then medium), GroupBy app, no MITRE; their tunables are
// bounded and what a rule doesn't use is cleared; a custom rule can't be one.
func TestValidatePatternRule(t *testing.T) {
	sev := map[string]siem.Severity{rulePatternNew: siem.SevLow, rulePatternNewError: siem.SevMedium,
		rulePatternSpike: siem.SevMedium, rulePatternChurn: siem.SevMedium}
	for id, s := range sev {
		p := packByID[id]
		if p == nil || p.Severity != s || p.GroupBy != "app" || len(p.MITRE) != 0 || p.Baseline != siem.BaselinePattern || !p.Enabled {
			t.Fatalf("%s in the pack: %+v", id, p)
		}
		r := cloneRule(p.Rule)
		if err := validate(&r, t0); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
	}
	bad := map[string]func(*siem.Rule){
		"new count 0":        func(r *siem.Rule) { r.ID, r.Count = rulePatternNew, 0 },
		"new settle 30s":     func(r *siem.Rule) { r.ID, r.Window = rulePatternNew, 30*time.Second },
		"new settle 2d":      func(r *siem.Rule) { r.ID, r.Window = rulePatternNewError, 2*day },
		"new learn 30m":      func(r *siem.Rule) { r.ID, r.Learn = rulePatternNew, 30*time.Minute },
		"spike window 2h":    func(r *siem.Rule) { r.ID, r.Window = rulePatternSpike, 2*time.Hour },
		"spike factor 1":     func(r *siem.Rule) { r.ID, r.Factor = rulePatternSpike, 1 },
		"spike learn 8d":     func(r *siem.Rule) { r.ID, r.Learn = rulePatternSpike, 8*day },
		"spike learn 1h":     func(r *siem.Rule) { r.ID, r.Learn = rulePatternSpike, time.Hour },
		"churn count 0":      func(r *siem.Rule) { r.ID, r.Count = rulePatternChurn, 0 },
		"group by ip":        func(r *siem.Rule) { r.ID, r.GroupBy = rulePatternNew, "ip" },
		"unknown id":         func(r *siem.Rule) { r.ID = "pattern.other" },
		"custom":             func(r *siem.Rule) { r.ID, r.Builtin = "custom.mine", false },
		"spike count 100001": func(r *siem.Rule) { r.ID, r.Count = rulePatternSpike, maxCount+1 },
	}
	for name, mod := range bad {
		r := cloneRule(packByID[rulePatternSpike].Rule)
		mod(&r)
		if p := packByID[r.ID]; p != nil && r.ID != rulePatternSpike {
			base := cloneRule(p.Rule)
			mod(&base)
			r = base
		}
		if err := validate(&r, t0); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	r := cloneRule(packByID[rulePatternChurn].Rule)
	r.Window, r.Factor, r.Learn, r.Field, r.SpeedKMH = time.Hour, 3, day, "ip", 5
	if err := validate(&r, t0); err != nil || r.Window != 0 || r.Factor != 0 || r.Learn != 0 || r.Field != "" || r.SpeedKMH != 0 {
		t.Fatalf("churn cleared: %+v %v", r, err)
	}
	r = cloneRule(packByID[rulePatternNew].Rule)
	r.Factor = 9
	if err := validate(&r, t0); err != nil || r.Factor != 0 {
		t.Fatalf("new cleared: %+v %v", r, err)
	}
	// The owner can raise one to high through the rule store, like any built-in rule.
	hm := newHarness(t, true)
	r = cloneRule(packByID[rulePatternNewError].Rule)
	r.Severity = siem.SevHigh
	if err := hm.e.SaveRule(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if c := hm.e.rules.Load().byID[rulePatternNewError]; c.r.Severity != siem.SevHigh {
		t.Fatalf("severity %s", c.r.Severity)
	}
}
