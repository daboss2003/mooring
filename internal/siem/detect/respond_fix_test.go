package detect

import (
	"slices"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

func edgeUA(at time.Duration, ip, fetchSite, ua string) siem.Event {
	e := edgeHit(at, ip, fetchSite)
	if ua != "" {
		e.F["ua"] = ua
	}
	return e
}

// What sent an edge request: fetch metadata means a browser; without it, a browser's or a mail
// client's User-Agent is a browser agent. Only the edge's events say either.
func TestSentBy(t *testing.T) {
	for _, tc := range []struct {
		src, site, ua  string
		browser, agent bool
	}{
		{siem.SrcEdge, "cross-site", "", true, false},
		{siem.SrcEdge, "cross-site", chromeWin, true, false},
		{siem.SrcEdge, "", chromeWin, false, true},
		{siem.SrcEdge, "", "mozilla/4.0 (compatible; ms-office)", false, true},
		{siem.SrcEdge, "", "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0)", false, true},
		{siem.SrcEdge, "", "Thunderbird/115.3", false, true},
		{siem.SrcEdge, "", "Word MS-Office 2019", false, true},
		{siem.SrcEdge, "", "curl/8.5.0", false, false},
		{siem.SrcEdge, "", "x Mozilla/5.0", false, false},
		{siem.SrcEdge, "", "", false, false},
		{siem.SrcApp, "none", chromeWin, false, false},
		{siem.SrcMooring, "", chromeWin, false, false},
	} {
		e := siem.Event{Src: tc.src, TS: t0, F: map[string]any{}}
		if tc.site != "" {
			e.F["fetch_site"] = tc.site
		}
		if tc.ua != "" {
			e.F["ua"] = tc.ua
		}
		got := evidenceOf(&e)
		if got.Browser != tc.browser || got.BrowserAgent != tc.agent {
			t.Errorf("%s site %q ua %q: browser %v agent %v, want %v %v", tc.src, tc.site, tc.ua,
				got.Browser, got.BrowserAgent, tc.browser, tc.agent)
		}
	}
}

// Finding 1: every counted event says whether a browser sent it, not only the last four (the
// evidence kept): 96 requests a page made a visitor's browser send, then 4 scripted ones, block
// nobody.
func TestResponseBrowserCountedBeyondEvidence(t *testing.T) {
	h, fr := respHarness(t, false)
	r := edgeRule(100)
	r.Window = 5 * time.Minute
	h.only(t, r)
	for i := range 96 {
		h.feed(edgeHit(time.Duration(i)*100*time.Millisecond, addrX, "cross-site"))
	}
	for i := range 4 {
		h.feed(edgeHit(time.Duration(30+i*30)*time.Second, addrX, ""))
	}
	h.e.flush(false)
	if ds := h.all(t); len(ds) != 1 {
		t.Fatalf("detections %+v", ds)
	}
	if got := fr.all(); len(got) != 0 {
		t.Fatalf("browser-sent requests counted toward a block: %+v", got)
	}
	// 100 scripted requests from another address: blocked.
	for i := range 100 {
		h.feed(edgeHit(3*time.Minute+time.Duration(i)*100*time.Millisecond, addrY, ""))
	}
	h.e.flush(false)
	if got := fr.all(); len(got) != 1 || got[0].Target != addrY || !got[0].Automatic {
		t.Fatalf("scripted requests: %+v", got)
	}
}

// A browser's request that left the window no longer counts; the key's state starts again after
// a firing.
func TestResponseBrowserOutsideWindow(t *testing.T) {
	h, fr := respHarness(t, false)
	r := edgeRule(3)
	r.Window = 5 * time.Minute
	h.only(t, r)
	h.feed(edgeHit(0, addrX, "same-origin"))
	for i := range 3 {
		h.feed(edgeHit(10*time.Minute+time.Duration(i)*time.Second, addrX, ""))
	}
	h.e.flush(false)
	if got := fr.all(); len(got) != 1 || !got[0].Automatic {
		t.Fatalf("a browser request before the window: %+v", got)
	}
	// A browser's request inside the window: no block; the next address is judged on its own.
	h.feed(edgeHit(20*time.Minute, addrY, "none"), edgeHit(20*time.Minute+time.Second, addrY, ""),
		edgeHit(20*time.Minute+2*time.Second, addrY, ""))
	h.e.flush(false)
	if got := fr.all(); len(got) != 1 {
		t.Fatalf("browser request in the window: %+v", got)
	}
	for i := range 3 {
		h.feed(edgeHit(20*time.Minute+3*time.Second+time.Duration(i)*time.Second, addrZ, ""))
	}
	h.e.flush(false)
	if got := fr.all(); len(got) != 2 || got[1].Target != addrZ {
		t.Fatalf("another address: %+v", got)
	}
}

// The same for the other rule types that count events: distinct, sequence and anomaly.
func TestResponseBrowserCountedOtherTypes(t *testing.T) {
	path := func(at time.Duration, ip, site, p string) siem.Event {
		e := edgeHit(at, ip, site)
		e.F["path"] = p
		return e
	}
	paths := []string{"/a", "/b", "/c", "/d", "/e", "/f", "/g", "/h"}
	for _, tc := range []struct {
		name string
		r    siem.Rule
	}{
		{"distinct", siem.Rule{ID: "custom.d", Type: siem.RuleDistinct, Query: "src:edge kind:http.request", GroupBy: "ip",
			Field: "f.path", Count: 8, Window: time.Hour, Response: blockResp(time.Hour)}},
		{"sequence", siem.Rule{ID: "custom.s", Type: siem.RuleSequence, Query: "src:edge kind:http.request f.status:404",
			Then: "src:edge kind:http.request f.status:200", GroupBy: "ip", Count: 7, Window: time.Hour,
			Response: blockResp(time.Hour)}},
		{"anomaly", siem.Rule{ID: "custom.a", Type: siem.RuleAnomaly, Query: "src:edge kind:http.request", GroupBy: "ip",
			Count: 8, Window: time.Hour, Factor: 2, Response: blockResp(time.Hour)}},
	} {
		// Event which of the 8 (-1: none) carries fetch metadata (site) or a browser's agent (agent).
		run := func(which int, site, agent string) []siem.ResponseRequest {
			h, fr := respHarness(t, false)
			h.only(t, tc.r)
			for i, p := range paths {
				e := path(time.Duration(i)*time.Second, addrX, "", p)
				if i == which && site != "" {
					e.F["fetch_site"] = site
				}
				if i == which && agent != "" {
					e.F["ua"] = agent
				}
				if tc.r.Type == siem.RuleSequence && i == len(paths)-1 {
					e.F["status"] = 200.0
				}
				h.feed(e)
			}
			h.e.flush(false)
			if ds := h.all(t); len(ds) != 1 {
				t.Fatalf("%s: detections %+v", tc.name, ds)
			}
			return fr.all()
		}
		if got := run(-1, "", ""); len(got) != 1 || !got[0].Automatic {
			t.Errorf("%s, scripted: %+v", tc.name, got)
		}
		// The first counted event (long out of the evidence kept) and the last (a sequence's closing
		// event).
		for _, i := range []int{0, len(paths) - 1} {
			if got := run(i, "cross-site", ""); len(got) != 0 {
				t.Errorf("%s, event %d sent by a browser: %+v", tc.name, i, got)
			}
			if got := run(i, "", chromeWin); len(got) != 1 || got[0].Automatic {
				t.Errorf("%s, event %d with a browser's agent: %+v", tc.name, i, got)
			}
		}
	}
}

// Owner decision: a counted request with a browser's (or mail client's) User-Agent and no fetch
// metadata makes the block a recommendation; fetch metadata anywhere in the count still means no
// request; a rule that needs a listed address blocks whatever sent the request.
func TestResponseBrowserAgentRecommendsOnly(t *testing.T) {
	h, fr := respHarness(t, false)
	h.only(t, edgeRule(3))
	h.feed(edgeUA(0, addrX, "", chromeWin), edgeUA(time.Second, addrX, "", "curl/8"), edgeUA(2*time.Second, addrX, "", "curl/8"))
	h.e.flush(false)
	got := fr.all()
	if len(got) != 1 || got[0].Automatic || got[0].Target != addrX || got[0].Action != siem.ResponseBlock {
		t.Fatalf("a browser agent in the count: %+v", got)
	}
	h.feed(edgeUA(0, addrY, "", chromeWin), edgeUA(time.Second, addrY, "same-site", chromeWin), edgeUA(2*time.Second, addrY, "", ""))
	h.e.flush(false)
	if got := fr.all(); len(got) != 1 {
		t.Fatalf("fetch metadata beside a browser agent: %+v", got)
	}
	h.feed(edgeUA(0, addrZ, "", "curl/8"), edgeUA(time.Second, addrZ, "", ""), edgeUA(2*time.Second, addrZ, "", "python-requests/2"))
	h.e.flush(false)
	if got := fr.all(); len(got) != 2 || !got[1].Automatic || got[1].Target != addrZ {
		t.Fatalf("scripted agents: %+v", got)
	}

	h, fr = respHarness(t, false)
	h.only(t, siem.Rule{ID: "custom.listed", Type: siem.RuleThreshold, Query: "src:edge kind:http.request list:spamhaus-drop",
		GroupBy: "ip", Count: 1, Window: time.Hour, Response: blockResp(24 * time.Hour)})
	e := edgeUA(0, addrX, "", chromeWin)
	e.Geo = &siem.Geo{Lists: []string{"spamhaus-drop"}}
	h.feed(e)
	h.e.flush(false)
	if got := fr.all(); len(got) != 1 || !got[0].Automatic {
		t.Fatalf("listed address with a browser agent: %+v", got)
	}
}

// Finding 2: what a block may do follows from the sources the rule's query lets through, not from
// the event that happened to fire: a rule that also counts an app's (forgeable) events only
// recommends, whatever fired it.
func TestResponseMixedSourceRuleRecommendsOnly(t *testing.T) {
	h, fr := respHarness(t, false)
	h.only(t, siem.Rule{ID: "custom.mixed", Type: siem.RuleThreshold, Query: "-src:host -src:mooring kind:t.x",
		GroupBy: "ip", Count: 3, Window: time.Hour, Response: blockResp(time.Hour)})
	app := func(at time.Duration, ip string) siem.Event {
		e := incEv(at, siem.SrcApp, "t.x", ip, "", nil)
		e.App = "shop"
		return e
	}
	// Two events an app's log line claimed, then one the edge saw: the edge's event fires it.
	h.feed(app(0, addrX), app(time.Second, addrX), incEv(2*time.Second, siem.SrcEdge, "t.x", addrX, "", nil))
	// Edge events alone: still a rule that counts app events.
	for i := range 3 {
		h.feed(incEv(time.Minute+time.Duration(i)*time.Second, siem.SrcEdge, "t.x", addrY, "", nil))
	}
	h.e.flush(false)
	got := fr.all()
	if len(got) != 2 || got[0].Automatic || got[1].Automatic || got[0].Target != addrX || got[1].Target != addrY {
		t.Fatalf("mixed-source rule: %+v", got)
	}
	// A sequence whose first query is the edge's and whose closing one also takes app events.
	h, fr = respHarness(t, false)
	h.only(t, siem.Rule{ID: "custom.seq", Type: siem.RuleSequence, Query: "src:edge kind:t.x",
		Then: "-src:host -src:mooring kind:t.y", GroupBy: "ip", Count: 2, Window: time.Hour, Response: blockResp(time.Hour)})
	h.feed(incEv(0, siem.SrcEdge, "t.x", addrX, "", nil), incEv(time.Second, siem.SrcEdge, "t.x", addrX, "", nil),
		incEv(2*time.Second, siem.SrcEdge, "t.y", addrX, "", nil))
	h.e.flush(false)
	if got := fr.all(); len(got) != 1 || got[0].Automatic {
		t.Fatalf("mixed-source sequence: %+v", got)
	}
}

// Finding 2: a custom rule over several sources' sign-ins can't sign anyone out: the events of an
// app or the host are forgeable, and would count toward the Mooring account's sign-out.
func TestResponseRevokeNeedsMooringOnly(t *testing.T) {
	h, fr := respHarness(t, false)
	rules := h.unchecked(t, siem.Rule{ID: "custom.signin", Type: siem.RuleThreshold, Query: "out:success kind~.login",
		GroupBy: "actor", Count: 2, Window: time.Hour, Response: revokeResp})
	if got := rules["custom.signin"].respOK; len(got) != 0 {
		t.Fatalf("a rule over every source may %v", got)
	}
	app := ev(0, siem.SrcApp, "auth.login", siem.OutSuccess, addrY, "alice", nil)
	app.App = "shop"
	h.feed(signIn(0, siem.OutSuccess, addrZ, "alice"), signIn(time.Second, siem.OutSuccess, addrZ, "alice"))
	h.e.flush(false)
	if got := fr.all(); len(got) != 0 {
		t.Fatalf("requests %+v", got)
	}
	for _, r := range []siem.Rule{
		{ID: "custom.a", Type: siem.RuleThreshold, Query: "out:success kind~.login", GroupBy: "actor", Count: 1,
			Window: time.Hour, Response: revokeResp},
		{ID: "custom.b", Type: siem.RuleThreshold, Query: "-src:host -src:edge out:success", GroupBy: "ip", Count: 1,
			Window: time.Hour, Response: revokeResp},
		{ID: "custom.c", Type: siem.RuleSequence, Query: "out:failure", Then: "src:mooring out:success", GroupBy: "ip",
			Count: 2, Window: time.Hour, Response: revokeResp},
		{ID: "custom.d", Type: siem.RuleSequence, Query: "src:mooring out:failure", Then: "out:success", GroupBy: "ip",
			Count: 2, Window: time.Hour, Response: revokeResp},
	} {
		r.Name, r.Severity = r.ID, siem.SevLow
		if err := validate(&r, t0); err == nil {
			t.Errorf("%s (%q then %q) may sign out", r.ID, r.Query, r.Then)
		}
	}
}

// Finding 3: a rule over several sources keeps an account's detections of each source apart, so a
// detection of an app's (or the host's) "alice" never takes the place of Mooring's alice's and its
// sign-out. Both are keyed "alice" for the owner.
func TestResponseScopesKeepAccountsApart(t *testing.T) {
	h, fr := respHarness(t, false)
	rules := h.unchecked(t, siem.Rule{ID: "custom.signin", Type: siem.RuleThreshold, Query: "out:success kind~.login",
		GroupBy: "actor", Count: 1, Window: time.Hour, Response: revokeResp})
	rules["custom.signin"].respOK = []string{siem.ResponseRevoke} // as the sign-in baseline rule's
	app := ev(0, siem.SrcApp, "auth.login", siem.OutSuccess, addrY, "alice", nil)
	app.App = "shop"
	h.feed(app, ev(time.Second, siem.SrcHost, siem.KindSSHLogin, siem.OutSuccess, addrX, "alice", nil))
	h.e.flush(false)
	if got := fr.all(); len(got) != 0 {
		t.Fatalf("app and host accounts: %+v", got)
	}
	h.feed(signIn(2*time.Second, siem.OutSuccess, addrZ, "alice"))
	h.e.flush(false)
	got := fr.all()
	if len(got) != 1 || got[0].Target != "alice" || got[0].Action != siem.ResponseRevoke || !got[0].Automatic {
		t.Fatalf("Mooring's alice after an app's: %+v", got)
	}
	ds := h.all(t)
	if len(ds) != 3 {
		t.Fatalf("detections %+v", ds)
	}
	for _, d := range ds {
		if d.Key != "alice" || d.Count != 1 {
			t.Fatalf("detection %+v", d)
		}
	}
	// Each scope's detection is still updated by its own later firings, from memory and read back.
	app.TS = app.TS.Add(time.Minute)
	h.feed(app, signIn(time.Minute, siem.OutSuccess, addrZ, "alice"))
	if got := fr.all(); len(got) != 1 {
		t.Fatalf("updates asked again: %+v", got)
	}
	h.retireAll()
	app.TS = app.TS.Add(time.Minute)
	h.feed(app, signIn(2*time.Minute, siem.OutSuccess, addrZ, "alice"))
	h.e.flush(true)
	ds = h.all(t)
	n := 0
	for _, d := range ds {
		n += d.Count
	}
	if len(ds) != 3 || n != 7 {
		t.Fatalf("after updates: %d detections, %d firings: %+v", len(ds), n, ds)
	}
	// Read back, Mooring's alice's detection asks once more (the responder's cooldown refuses it);
	// the app's still asks nothing.
	got = fr.all()
	if len(got) != 2 || got[1].Target != "alice" || got[1].DetectionID != got[0].DetectionID || got[1].Action != siem.ResponseRevoke {
		t.Fatalf("read back: %+v", got)
	}
}

// A rule pinned to one source, and any address-keyed rule, coalesce as before.
func TestScopeSplitOnlyForMixedAccountRules(t *testing.T) {
	h, _ := respHarness(t, false)
	h.only(t,
		siem.Rule{ID: "custom.ip", Type: siem.RuleThreshold, Query: "kind:t.x", GroupBy: "ip", Count: 1, Window: time.Hour},
		siem.Rule{ID: "custom.app", Type: siem.RuleThreshold, Query: "src:app kind:t.x", GroupBy: "actor", Count: 1, Window: time.Hour})
	a := incEv(0, siem.SrcApp, "t.x", addrX, "alice", nil)
	a.App = "shop"
	b := incEv(time.Second, siem.SrcApp, "t.x", addrX, "alice", nil)
	b.App = "blog"
	h.feed(a, b, incEv(2*time.Second, siem.SrcHost, "t.x", addrX, "", nil))
	for _, tc := range []struct {
		rule  string
		count int
	}{{"custom.ip", 3}, {"custom.app", 2}} {
		if ds := h.detections(t, tc.rule); len(ds) != 1 || ds[0].Count != tc.count {
			t.Errorf("%s: %+v", tc.rule, ds)
		}
	}
}

// Finding 3 with the built-in rule: an unusual sign-in of an app's alice doesn't swallow the
// sign-out of Mooring's alice an hour later.
func TestSigninUnusualRevokesMooringAfterAppDetection(t *testing.T) {
	fr := &fakeResponder{}
	h := newHarness(t, false, func(o *Options) { o.Responder = fr })
	h.e.bl.loc = tokyo
	h.only(t, blRule("baseline.signin_unusual"))
	app := func(when time.Time, g *siem.Geo, ua string) siem.Event {
		return siem.Event{TS: when.UTC(), Src: siem.SrcApp, App: "shop", Kind: "auth.login", Out: siem.OutSuccess,
			IP: "198.51.100.7", Actor: "alice", F: map[string]any{"ua": ua}, Geo: g}
	}
	for d := 0; d < 28; d++ {
		if d%7 < 5 {
			h.feed(mooringSignIn(at(d, 9, 10), "alice", jpKDDI, chromeWin), app(at(d, 9, 20), jpKDDI, chromeWin))
		}
	}
	h.feed(app(at(28, 9, 0), ngExample, firefoxLx))
	h.e.flush(false)
	if ds := h.all(t); len(ds) != 1 {
		t.Fatalf("the app account's unusual sign-in:\n%s", summaries(ds))
	}
	if got := fr.all(); len(got) != 0 {
		t.Fatalf("an app account signed out: %+v", got)
	}
	h.feed(mooringSignIn(at(28, 9, 30), "alice", ngExample, firefoxLx))
	h.e.flush(false)
	if ds := h.all(t); len(ds) != 2 {
		t.Fatalf("Mooring's alice's unusual sign-in:\n%s", summaries(ds))
	}
	got := fr.all()
	if len(got) != 1 || got[0].Action != siem.ResponseRevoke || got[0].Target != "alice" || !got[0].Automatic ||
		got[0].RuleID != "baseline.signin_unusual" {
		t.Fatalf("Mooring's alice not signed out: %+v", got)
	}
}

// Finding 4: a detection that keeps firing keeps asking for its block, at most every blockAskEvery,
// whatever the block's length (the responder skips the requests made while the address is still
// blocked, and the block list lengthens the repeat after it ended).
func TestResponseBlockAskedAgainWhileItKeepsFiring(t *testing.T) {
	h, fr := respHarness(t, false)
	r := edgeRule(1)
	r.Response = blockResp(10 * time.Minute)
	h.only(t, r)
	// One firing every 4 minutes for 40 minutes: one detection throughout.
	for i := range 11 {
		h.feed(edgeHit(time.Duration(i)*4*time.Minute, addrX, ""))
		h.e.flush(false)
	}
	got := fr.all()
	// Asked at 0, 8m, 16m, 24m, 32m and 40m: every second firing (4m is inside the interval).
	if len(got) != 6 {
		t.Fatalf("%d requests: %+v", len(got), got)
	}
	if ds := h.all(t); len(ds) != 1 || ds[0].Count != 11 {
		t.Fatalf("detections %+v", ds)
	}
	for i, r := range got {
		if r.Target != addrX || !r.Automatic || r.Duration != 10*time.Minute || r.DetectionID != got[0].DetectionID ||
			r.DetectionID == 0 || !r.At.Equal(t0.Add(time.Duration(i)*8*time.Minute)) {
			t.Fatalf("request %d: %+v", i, r)
		}
	}
	// A sign-out is asked once per detection and account whatever the time.
	h, fr = respHarness(t, false)
	h.only(t, siem.Rule{ID: "custom.actor", Type: siem.RuleThreshold, Query: "src:mooring kind:mooring.login out:success",
		GroupBy: "actor", Count: 1, Window: time.Hour, Response: revokeResp})
	for i := range 5 {
		h.feed(signIn(time.Duration(i)*20*time.Minute, siem.OutSuccess, addrX, "alice"))
		h.e.flush(false)
	}
	if got := fr.all(); len(got) != 1 {
		t.Fatalf("sign-outs: %+v", got)
	}
}

// A repeat request is decided like a first one: not for a firing a browser sent (which doesn't
// hold the next request back either), not within the interval, not while the rule is snoozed.
func TestResponseBlockRepeatIsDecidedAgain(t *testing.T) {
	h, fr := respHarness(t, false)
	r := edgeRule(1)
	r.Response = blockResp(5 * time.Minute)
	h.only(t, r)
	h.feed(edgeHit(0, addrX, ""))
	h.e.flush(false)
	h.feed(edgeHit(blockAskEvery-time.Second, addrX, ""))
	h.e.flush(false)
	if got := fr.all(); len(got) != 1 {
		t.Fatalf("asked again within the interval: %+v", got)
	}
	h.feed(edgeHit(8*time.Minute, addrX, "cross-site"))
	h.e.flush(false)
	if got := fr.all(); len(got) != 1 {
		t.Fatalf("a browser's request repeated the block: %+v", got)
	}
	h.feed(edgeHit(9*time.Minute, addrX, ""))
	if got := fr.all(); len(got) != 2 || got[1].DetectionID != got[0].DetectionID || got[1].DetectionID == 0 {
		t.Fatalf("repeat (sent at once: the detection has its ID): %+v", got)
	}
	h.feed(edgeHit(9*time.Minute+time.Second, addrX, ""))
	h.clk.advance(writeEvery)
	h.e.flush(false)
	if got := fr.all(); len(got) != 2 {
		t.Fatalf("asked twice: %+v", got)
	}
	// The rule snoozed meanwhile: no repeat.
	h.e.rules.Load().byID["custom.edge"].r.SnoozedUntil = h.clk.now().Add(time.Hour)
	h.feed(edgeHit(30*time.Minute, addrX, ""))
	h.e.flush(false)
	if got := fr.all(); len(got) != 2 {
		t.Fatalf("a snoozed rule's detection repeated its block: %+v", got)
	}
}

// The address baseline's firing says what sent the requests it counted (owner decision, reversing
// "a baseline rule only recommends"; TestBaselineIPBlockFollowsSenders feeds real requests): its
// block is automatic when the firing carries no browser and no browser agent, a recommendation with
// a browser agent, and none when a counted request or the firing one came from a browser. A
// baseline of another kind keyed by an address (none passes validation today) keeps no senders:
// its block is a recommendation. A rule that fires on one event (new value) is judged on that event.
func TestResponseBaselineAndOneEventRules(t *testing.T) {
	h, fr := respHarness(t, false)
	h.only(t, blRule("baseline.ip_behaviour", func(r *siem.Rule) { r.Response = blockResp(time.Hour) }),
		siem.Rule{ID: "custom.nv", Type: siem.RuleNewValue, Query: "src:edge kind:http.request", GroupBy: "ip",
			Field: "f.host", Response: blockResp(time.Hour)})
	rules := h.e.rules.Load().byID
	// As a stored rule that slipped past validation: a traffic baseline keyed by an address.
	other, err := compile(siem.Rule{ID: "baseline.other", Name: "Other", Type: siem.RuleBaseline, Baseline: siem.BaselineTraffic,
		Severity: siem.SevLow, Enabled: true, Query: "src:edge kind:http.request", GroupBy: "ip", Response: blockResp(time.Hour)},
		packInfo{}, nil)
	if err != nil || !other.autoBlock || !slices.Contains(other.respOK, siem.ResponseBlock) {
		t.Fatalf("compile: %v %+v", err, other)
	}
	rules["baseline.other"] = other
	counted := func(ip string, f firing) {
		e := edgeHit(0, ip, "")
		e.Normalize(h.clk.now())
		f.count, f.evidence = 60, []siem.Evidence{evidenceOf(&e)}
		h.e.fire(rules["baseline.ip_behaviour"], ip, &e, f)
		h.e.flush(false)
	}
	fire := func(rule, ip, site string) {
		e := edgeHit(0, ip, site)
		e.Normalize(h.clk.now())
		h.e.fire(rules[rule], ip, &e, firing{count: 60, evidence: []siem.Evidence{evidenceOf(&e)}})
		h.e.flush(false)
	}
	fire("baseline.ip_behaviour", addrX, "")
	if got := fr.all(); len(got) != 1 || !got[0].Automatic || got[0].Target != addrX {
		t.Fatalf("address baseline, scripted requests: %+v", got)
	}
	fire("baseline.ip_behaviour", addrY, "same-origin")
	if got := fr.all(); len(got) != 1 {
		t.Fatalf("baseline rule fired by a browser's request: %+v", got)
	}
	counted("192.0.2.50", firing{browser: true})
	if got := fr.all(); len(got) != 1 {
		t.Fatalf("address baseline, a browser's request counted: %+v", got)
	}
	counted("192.0.2.51", firing{agent: true})
	if got := fr.all(); len(got) != 2 || got[1].Automatic || got[1].Target != "192.0.2.51" {
		t.Fatalf("address baseline, a browser agent's request counted: %+v", got)
	}
	fire("baseline.other", "192.0.2.52", "")
	if got := fr.all(); len(got) != 3 || got[2].Automatic || got[2].Target != "192.0.2.52" {
		t.Fatalf("a baseline of another kind keyed by an address: %+v", got)
	}
	fr.mu.Lock()
	fr.got = fr.got[:1]
	fr.mu.Unlock()
	fire("custom.nv", addrY, "same-origin")
	if got := fr.all(); len(got) != 1 {
		t.Fatalf("new-value rule fired by a browser's request: %+v", got)
	}
	fire("custom.nv", addrZ, "")
	if got := fr.all(); len(got) != 2 || !got[1].Automatic || got[1].Target != addrZ {
		t.Fatalf("new-value rule fired by a scripted request: %+v", got)
	}
}
