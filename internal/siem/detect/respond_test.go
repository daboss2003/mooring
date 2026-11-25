package detect

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

type fakeResponder struct {
	mu   sync.Mutex
	got  []siem.ResponseRequest
	full bool
}

func (f *fakeResponder) Respond(r siem.ResponseRequest) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.full {
		return false
	}
	f.got = append(f.got, r)
	return true
}

func (f *fakeResponder) all() []siem.ResponseRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]siem.ResponseRequest(nil), f.got...)
}

// respHarness is an engine with incidents on (production's default) and a fake responder.
func respHarness(t *testing.T, withMain bool) (*harness, *fakeResponder) {
	t.Helper()
	fr := &fakeResponder{}
	h := newHarness(t, withMain, func(o *Options) { o.Responder = fr })
	h.incidents = true
	h.e.lim.incidents = true
	return h, fr
}

func blockResp(d time.Duration) siem.RuleResponse {
	return siem.RuleResponse{Action: siem.ResponseBlock, Duration: d}
}

var revokeResp = siem.RuleResponse{Action: siem.ResponseRevoke}

// edgeRule counts edge requests per address and blocks the address for an hour.
func edgeRule(count int) siem.Rule {
	return siem.Rule{ID: "custom.edge", Name: "Edge", Type: siem.RuleThreshold, Severity: siem.SevLow,
		Query: "src:edge kind:http.request", GroupBy: "ip", Count: count, Window: time.Hour, Response: blockResp(time.Hour)}
}

func edgeHit(at time.Duration, ip, fetchSite string) siem.Event {
	f := map[string]any{"status": 404.0}
	if fetchSite != "" {
		f["fetch_site"] = fetchSite
	}
	return ev(at, siem.SrcEdge, siem.KindHTTPRequest, "", ip, "", f)
}

func signIn(at time.Duration, out, ip, actor string) siem.Event {
	return ev(at, siem.SrcMooring, "mooring.login", out, ip, actor, nil)
}

// unchecked replaces the rules in force with rs compiled without validation (a stored rule that
// slipped past it), so the engine's own checks are what's tested.
func (h *harness) unchecked(t *testing.T, rs ...siem.Rule) map[string]*compiled {
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
		c, err := compile(r, packInfo{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		set.list = append(set.list, c)
		set.byID[r.ID] = c
		set.listed = append(set.listed, c.r)
	}
	h.e.rules.Store(set)
	return set.byID
}

func TestResponseEdgeAddressBlocksAutomatically(t *testing.T) {
	h, fr := respHarness(t, false)
	h.only(t, edgeRule(3))
	for i := range 3 {
		h.feed(edgeHit(time.Duration(i)*time.Second, addrX, ""))
	}
	if got := fr.all(); len(got) != 0 {
		t.Fatalf("sent before the detection was written: %+v", got)
	}
	h.e.flush(false)
	got := fr.all()
	if len(got) != 1 {
		t.Fatalf("requests %+v", got)
	}
	r := got[0]
	ds := h.all(t)
	incs := h.incList(t)
	if r.Action != siem.ResponseBlock || r.Target != addrX || !r.Automatic || r.Duration != time.Hour ||
		r.RuleID != "custom.edge" || r.RuleName != "Edge" || r.Severity != siem.SevLow || r.Summary == "" ||
		!r.At.Equal(h.clk.now()) {
		t.Fatalf("request %+v", r)
	}
	if len(ds) != 1 || r.DetectionID != ds[0].ID || r.DetectionID == 0 || r.Summary != ds[0].Summary {
		t.Fatalf("detection ID %d, stored %+v", r.DetectionID, ds)
	}
	if len(incs) != 1 || r.IncidentID != incs[0].ID || r.IncidentID == 0 {
		t.Fatalf("incident ID %d, incidents %+v", r.IncidentID, incs)
	}

	// An IPv6 address is blocked as its /64, the detection's key.
	h.feed(edgeHit(time.Minute, "2001:db8:1:2::5", ""), edgeHit(time.Minute, "2001:db8:1:2::6", ""),
		edgeHit(time.Minute, "2001:db8:1:2::7", ""))
	h.e.flush(false)
	if got := fr.all(); len(got) != 2 || got[1].Target != "2001:db8:1:2::/64" || !got[1].Automatic {
		t.Fatalf("IPv6: %+v", got)
	}
}

// A detection's updates within blockAskEvery of its request ask for nothing more; a later firing
// asks again (the responder skips a request for an address still blocked), and so may the first
// firing after the detection was read back from detect.db; a new detection of the key asks too.
func TestResponseUpdatesAskNothingWithinTheInterval(t *testing.T) {
	h, fr := respHarness(t, false)
	h.only(t, edgeRule(1))
	for i := range 5 {
		h.feed(edgeHit(time.Duration(i)*time.Minute, addrX, ""))
		h.clk.advance(writeEvery)
		h.e.flush(false)
	}
	if got := fr.all(); len(got) != 1 {
		t.Fatalf("updates asked again: %+v", got)
	}
	// Retired from memory and read back from detect.db: the same detection, which doesn't remember
	// its request and asks at its next firing, whatever the time since.
	h.retireAll()
	h.feed(edgeHit(4*time.Minute+30*time.Second, addrX, ""))
	h.e.flush(true)
	got := fr.all()
	if len(got) != 2 || got[1].DetectionID != got[0].DetectionID || got[1].DetectionID == 0 {
		t.Fatalf("read back and updated: %+v", got)
	}
	// From then on it is held to the interval again.
	h.feed(edgeHit(9*time.Minute, addrX, ""))
	if got := fr.all(); len(got) != 2 {
		t.Fatalf("within the interval of the read-back detection's request: %+v", got)
	}
	// Past the coalescing window: a new detection.
	h.feed(edgeHit(3*time.Hour, addrX, ""))
	h.e.flush(false)
	if got := fr.all(); len(got) != 3 || got[0].DetectionID == got[2].DetectionID {
		t.Fatalf("new detection: %+v", got)
	}
}

// An address an app's own log reported is recommended only, even from a rule that would block.
func TestResponseAppAddressRecommendOnly(t *testing.T) {
	h, fr := respHarness(t, false)
	h.only(t, siem.Rule{ID: "custom.app", Type: siem.RuleThreshold, Query: "src:app kind~.login out:failure",
		GroupBy: "ip", Count: 2, Window: time.Hour, Response: blockResp(time.Hour)})
	for i := range 2 {
		e := ev(time.Duration(i)*time.Second, siem.SrcApp, "auth.login", siem.OutFailure, addrY, "a", nil)
		e.App = "shop"
		h.feed(e)
	}
	h.e.flush(false)
	got := fr.all()
	if len(got) != 1 || got[0].Automatic || got[0].Target != addrY || got[0].Action != siem.ResponseBlock {
		t.Fatalf("requests %+v", got)
	}
}

// A request with browser fetch metadata among those a counting rule counted makes its block a
// recommendation (owner decision, v0.33.1; no request at all before: a scanner can send the header
// too); a listed address (count 1) is blocked whatever sent its request.
func TestResponseBrowserEvidence(t *testing.T) {
	h, fr := respHarness(t, false)
	h.only(t, edgeRule(3))
	h.feed(edgeHit(0, addrX, ""), edgeHit(time.Second, addrX, "cross-site"), edgeHit(2*time.Second, addrX, ""))
	h.e.flush(false)
	if got := fr.all(); !recommended(got, addrX) {
		t.Fatalf("a counting rule's detection with browser evidence: %+v", got)
	}
	h.feed(edgeHit(0, addrY, ""), edgeHit(time.Second, addrY, ""), edgeHit(2*time.Second, addrY, ""))
	h.e.flush(false)
	if got := fr.all(); len(got) != 2 || got[1].Target != addrY || !got[1].Automatic {
		t.Fatalf("no browser evidence: %+v", got)
	}

	h, fr = respHarness(t, false)
	listed := siem.Rule{ID: "custom.listed", Type: siem.RuleThreshold, Query: "src:edge kind:http.request list:spamhaus-drop",
		GroupBy: "ip", Count: 1, Window: time.Hour, Response: blockResp(24 * time.Hour)}
	h.only(t, listed)
	e := edgeHit(0, addrX, "same-origin")
	e.Geo = &siem.Geo{Lists: []string{"spamhaus-drop"}}
	h.feed(e)
	h.e.flush(false)
	if got := fr.all(); len(got) != 1 || !got[0].Automatic || got[0].Duration != 24*time.Hour {
		t.Fatalf("listed address with browser evidence: %+v", got)
	}

	// A one-event rule that doesn't need a listed address (a page's visitors can be made to request
	// any path) only recommends on a browser's request too; on a scripted one it blocks.
	h, fr = respHarness(t, false)
	h.only(t, siem.Rule{ID: "custom.wplogin", Type: siem.RuleThreshold, Query: "src:edge kind:http.request f.path:/wp-login.php",
		GroupBy: "ip", Count: 1, Window: time.Hour, Response: blockResp(time.Hour)})
	wp := func(ip, site string) siem.Event {
		e := edgeHit(0, ip, site)
		e.F["path"] = "/wp-login.php"
		return e
	}
	h.feed(wp(addrX, "cross-site"))
	h.e.flush(false)
	if got := fr.all(); !recommended(got, addrX) {
		t.Fatalf("a one-event rule without a list on a browser's request: %+v", got)
	}
	h.feed(wp(addrY, ""))
	h.e.flush(false)
	if got := fr.all(); len(got) != 2 || got[1].Target != addrY || !got[1].Automatic {
		t.Fatalf("a one-event rule on a scripted request: %+v", got)
	}
}

// The engine's own scope check: a block only for an address the edge saw (automatic) or an app
// reported (recommend only); Mooring's and the host's addresses ask for nothing.
func TestResponseBlockScopes(t *testing.T) {
	h, fr := respHarness(t, false)
	rules := h.unchecked(t, siem.Rule{ID: "custom.any", Type: siem.RuleThreshold, Query: "kind:t.x", GroupBy: "ip",
		Count: 1, Window: time.Hour, Response: blockResp(time.Hour)})
	// As if its query pinned src:edge.
	rules["custom.any"].respOK, rules["custom.any"].autoBlock = []string{siem.ResponseBlock}, true
	h.feed(incEv(0, siem.SrcMooring, "t.x", addrX, "", nil), incEv(0, siem.SrcHost, "t.x", addrY, "", nil))
	h.e.flush(false)
	if got := fr.all(); len(got) != 0 {
		t.Fatalf("Mooring or host address: %+v", got)
	}
	app := incEv(0, siem.SrcApp, "t.x", addrZ, "", nil)
	app.App = "shop"
	h.feed(app, incEv(time.Second, siem.SrcEdge, "t.x", "192.0.2.45", "", nil))
	h.e.flush(false)
	got := fr.all()
	if len(got) != 2 || got[0].Target != addrZ || got[0].Automatic || got[1].Target != "192.0.2.45" || !got[1].Automatic {
		t.Fatalf("app and edge addresses: %+v", got)
	}
}

// A stored rule whose response no longer validates asks for nothing (the engine checks the rule's
// query too): a failure-driven sign-out, a block of Mooring's addresses.
func TestResponseRuleMustAllowIt(t *testing.T) {
	h, fr := respHarness(t, false)
	h.unchecked(t,
		siem.Rule{ID: "custom.fail", Type: siem.RuleThreshold, Query: "src:mooring kind:mooring.login out:failure",
			GroupBy: "actor", Count: 1, Window: time.Hour, Response: revokeResp},
		siem.Rule{ID: "custom.mblock", Type: siem.RuleThreshold, Query: "src:mooring kind:mooring.login",
			GroupBy: "ip", Count: 1, Window: time.Hour, Response: blockResp(time.Hour)})
	h.feed(signIn(0, siem.OutFailure, addrX, "alice"))
	h.e.flush(false)
	if got := fr.all(); len(got) != 0 {
		t.Fatalf("requests %+v", got)
	}
}

func TestResponseRevokeTargets(t *testing.T) {
	h, fr := respHarness(t, false)
	h.only(t,
		siem.Rule{ID: "custom.actor", Type: siem.RuleThreshold, Query: "src:mooring kind:mooring.login out:success",
			GroupBy: "actor", Count: 1, Window: time.Hour, Response: revokeResp},
		siem.Rule{ID: "custom.seq", Type: siem.RuleSequence, Query: "src:mooring kind:mooring.login out:failure",
			Then: "src:mooring kind:mooring.login out:success", GroupBy: "ip", Count: 2, Window: time.Hour,
			Response: revokeResp})
	h.feed(signIn(0, siem.OutFailure, addrX, "mallory"), signIn(time.Second, siem.OutFailure, addrX, "mallory"),
		signIn(2*time.Second, siem.OutSuccess, addrX, "alice"))
	h.e.flush(false)
	got := fr.all()
	if len(got) != 2 {
		t.Fatalf("requests %+v", got)
	}
	by := map[string]siem.ResponseRequest{}
	for _, r := range got {
		by[r.RuleID] = r
	}
	if r := by["custom.actor"]; r.Action != siem.ResponseRevoke || r.Target != "alice" || !r.Automatic || r.Duration != 0 {
		t.Fatalf("actor key: %+v", r)
	}
	if r := by["custom.seq"]; r.Action != siem.ResponseRevoke || r.Target != "alice" || !r.Automatic {
		t.Fatalf("the success event's actor: %+v", r)
	}
}

// A rule over every source's sign-ins (baseline.signin_unusual's kind) signs out only Mooring
// accounts: the engine's own scope check.
func TestResponseRevokeOnlyMooringScope(t *testing.T) {
	h, fr := respHarness(t, false)
	rules := h.unchecked(t, siem.Rule{ID: "custom.signin", Type: siem.RuleThreshold, Query: "out:success kind~.login",
		GroupBy: "actor", Count: 1, Window: time.Hour, Response: revokeResp})
	rules["custom.signin"].respOK = []string{siem.ResponseRevoke} // as the sign-in baseline rule's
	app := ev(0, siem.SrcApp, "auth.login", siem.OutSuccess, addrY, "bob", nil)
	app.App = "shop"
	h.feed(ev(0, siem.SrcHost, siem.KindSSHLogin, siem.OutSuccess, addrX, "root", nil), app)
	h.e.flush(false)
	if got := fr.all(); len(got) != 0 {
		t.Fatalf("host and app accounts: %+v", got)
	}
	h.feed(signIn(time.Second, siem.OutSuccess, addrZ, "alice"))
	h.e.flush(false)
	if got := fr.all(); len(got) != 1 || got[0].Target != "alice" {
		t.Fatalf("Mooring account: %+v", got)
	}
}

func TestResponseNotForMutedSnoozedRollupOpsOrDisabled(t *testing.T) {
	ctx := context.Background()
	// Muted for the address: recorded, no request.
	h, fr := respHarness(t, true)
	h.only(t, edgeRule(1))
	if err := h.e.addMutes(ctx, []siem.Mute{{RuleID: "custom.edge", Entity: siem.Entity{Kind: siem.EntityAddress, Key: addrX}}},
		h.clk.now().Add(muteFor), "owner", 0); err != nil {
		t.Fatal(err)
	}
	h.feed(edgeHit(0, addrX, ""))
	h.e.flush(false)
	if got := fr.all(); len(got) != 0 {
		t.Fatalf("muted: %+v", got)
	}
	h.feed(edgeHit(0, addrY, ""))
	h.e.flush(false)
	if got := fr.all(); len(got) != 1 || got[0].Target != addrY {
		t.Fatalf("not muted: %+v", got)
	}

	// Snoozed.
	h, fr = respHarness(t, false)
	r := edgeRule(1)
	r.SnoozedUntil = h.clk.now().Add(time.Hour)
	h.only(t, r)
	h.feed(edgeHit(0, addrX, ""))
	h.e.flush(false)
	if got := fr.all(); len(got) != 0 {
		t.Fatalf("snoozed: %+v", got)
	}

	// Rolled up past the rule's new detections this hour.
	h, fr = respHarness(t, false)
	h.e.lim.newPerHour = 1
	h.only(t, edgeRule(1))
	h.feed(edgeHit(0, addrX, ""), edgeHit(time.Second, addrY, ""), edgeHit(2*time.Second, addrZ, ""))
	h.e.flush(false)
	if got := fr.all(); len(got) != 1 || got[0].Target != addrX {
		t.Fatalf("rollup: %+v", got)
	}

	// An app's /ops detection, even with a rule's ID.
	h, fr = respHarness(t, false)
	h.only(t, edgeRule(1))
	h.e.report(siem.Detection{RuleID: "custom.edge", RuleName: "x", Key: addrX, Severity: siem.SevHigh, App: "shop",
		Evidence: []siem.Evidence{{TS: h.clk.now(), IP: addrX}}})
	h.e.flush(false)
	if got := fr.all(); len(got) != 0 {
		t.Fatalf("ops: %+v", got)
	}

	// A firing of a rule switched off meanwhile.
	h, fr = respHarness(t, false)
	rules := h.unchecked(t, edgeRule(1))
	c := rules["custom.edge"]
	c.r.Enabled = false
	e := edgeHit(0, addrX, "")
	e.Normalize(h.clk.now())
	h.e.fire(c, addrX, &e, firing{count: 1, evidence: []siem.Evidence{evidenceOf(&e)}})
	h.e.flush(false)
	if got := fr.all(); len(got) != 0 {
		t.Fatalf("disabled: %+v", got)
	}
	c.r.Enabled = true
	h.e.fire(c, addrY, &e, firing{count: 1, evidence: []siem.Evidence{evidenceOf(&e)}})
	h.e.flush(false)
	if got := fr.all(); len(got) != 1 || got[0].Target != addrY {
		t.Fatalf("enabled: %+v", got)
	}
}

// While detect.db writes fail, a request goes once, without the detection's ID: at the failed
// write, or at once while the writes are known to fail. The write that later works sends nothing.
func TestResponseWhileWritesFail(t *testing.T) {
	h, fr := respHarness(t, false)
	h.only(t, edgeRule(1))
	restore := failWrites(t, h)
	h.feed(edgeHit(0, addrX, ""))
	if got := fr.all(); len(got) != 0 {
		t.Fatalf("before the write: %+v", got)
	}
	h.e.flush(false)
	got := fr.all()
	if len(got) != 1 || got[0].DetectionID != 0 || got[0].IncidentID != 0 || got[0].Target != addrX {
		t.Fatalf("after the failed write: %+v (write errors %d)", got, h.e.writeErrors.Load())
	}
	// During the backoff: at its commit. An update of the one already sent asks nothing more.
	h.feed(edgeHit(time.Second, addrY, ""), edgeHit(2*time.Second, addrX, ""))
	if got := fr.all(); len(got) != 2 || got[1].Target != addrY || got[1].DetectionID != 0 {
		t.Fatalf("during the backoff: %+v", got)
	}
	h.clk.advance(writeBackoffMax)
	h.e.flush(false)
	restore()
	h.clk.advance(writeBackoffMax)
	h.e.flush(false)
	if ds := h.all(t); len(ds) != 2 {
		t.Fatalf("written later: %+v", ds)
	}
	if got := fr.all(); len(got) != 2 {
		t.Fatalf("sent again once written: %+v", got)
	}
}

// A detection dropped unwritten sends its request then; a request already sent is never sent
// again.
func TestResponseDroppedUnwritten(t *testing.T) {
	h, fr := respHarness(t, false)
	h.only(t, edgeRule(1))
	h.feed(edgeHit(0, addrX, ""))
	var a *activeDet
	for d := range h.e.dirty {
		a = d
	}
	if a == nil || a.resp == nil {
		t.Fatalf("not marked: %+v", a)
	}
	h.e.respondDropped(a)
	h.e.respondDropped(a)
	h.e.flush(false)
	if got := fr.all(); len(got) != 1 || got[0].DetectionID != 0 {
		t.Fatalf("requests %+v", got)
	}
}

// A request the responder doesn't take is not tried again (the responder counts it).
func TestResponseNotTakenIsNotRetried(t *testing.T) {
	h, fr := respHarness(t, false)
	h.only(t, edgeRule(1))
	fr.full = true
	h.feed(edgeHit(0, addrX, ""))
	h.e.flush(false)
	fr.full = false
	h.feed(edgeHit(time.Minute, addrX, ""))
	h.clk.advance(writeEvery)
	h.e.flush(false)
	if got := fr.all(); len(got) != 0 {
		t.Fatalf("retried: %+v", got)
	}
}

func TestRuleResponses(t *testing.T) {
	h := newHarness(t, false)
	rule := func(typ, q, then, group string) siem.Rule {
		return siem.Rule{Type: typ, Query: q, Then: then, GroupBy: group}
	}
	for _, tc := range []struct {
		r    siem.Rule
		want string // the action, or a part of why
	}{
		{rule(siem.RuleThreshold, "src:edge kind:http.request", "", "ip"), siem.ResponseBlock},
		{rule(siem.RuleThreshold, "src:app kind~.login out:failure", "", "ip"), siem.ResponseBlock},
		{rule(siem.RuleThreshold, "src:e* kind:http.request", "", "ip"), siem.ResponseBlock},
		{rule(siem.RuleThreshold, "-src:host -src:mooring kind:x", "", "ip"), siem.ResponseBlock},
		{rule(siem.RuleThreshold, "kind:http.request", "", "ip"), "doesn't pin src:edge"},
		{rule(siem.RuleThreshold, "-src:host kind:x", "", "ip"), "doesn't pin src:edge"},
		{rule(siem.RuleThreshold, "src:edge kind:http.request", "", "f.host"), "keyed by an address"},
		{rule(siem.RuleThreshold, "src:mooring kind:mooring.login out:failure", "", "ip"), "allowlisted addresses"},
		{rule(siem.RuleThreshold, "src:host kind:ssh.login out:failure", "", "ip"), "SSH"},
		{rule(siem.RuleThreshold, "src:edge src:host", "", "ip"), "matches no source"},
		{rule(siem.RuleThreshold, "src:mooring kind:mooring.login out:success", "", "actor"), siem.ResponseRevoke},
		{rule(siem.RuleThreshold, "src:mooring kind:mooring.login out:success", "", "ip"), siem.ResponseRevoke},
		// A block of a rule that also counts an app's events is offered (it only recommends).
		{rule(siem.RuleSequence, "src:edge kind:x", "-src:host -src:mooring kind:y", "ip"), siem.ResponseBlock},
		{rule(siem.RuleSequence, "src:edge kind:x", "-src:host kind:y", "ip"), "doesn't pin src:edge"},
		// A sign-out needs Mooring's events only: an app's or the host's are forgeable.
		{rule(siem.RuleThreshold, "out:success kind~.login", "", "actor"), "must pin src:mooring"},
		{rule(siem.RuleThreshold, "-src:host -src:edge -src:app out:success", "", "actor"), siem.ResponseRevoke},
		{rule(siem.RuleThreshold, "-src:host -src:edge out:success", "", "actor"), "must pin src:mooring"},
		{siem.Rule{Type: siem.RuleBaseline, Baseline: siem.BaselineSignIn, Query: "out:success kind~.login", GroupBy: "actor"},
			siem.ResponseRevoke},
		{siem.Rule{Type: siem.RuleBaseline, Baseline: siem.BaselineSignIn, Query: "kind~.login", GroupBy: "actor"},
			"successful Mooring sign-ins"},
		{siem.Rule{Type: siem.RuleBaseline, Baseline: siem.BaselineSignIn, Query: "src:host out:success", GroupBy: "actor"},
			"Mooring accounts"},
		{siem.Rule{Type: siem.RuleBaseline, Baseline: siem.BaselineAdmin, Query: "out:success kind~.login", GroupBy: "actor"},
			"must pin src:mooring"},
		{rule(siem.RuleSequence, "src:mooring out:failure", "src:mooring out:success", "ip"), siem.ResponseRevoke},
		{rule(siem.RuleSequence, "out:failure", "src:mooring out:success", "ip"), "both of the rule's queries must pin src:mooring"},
		{rule(siem.RuleSequence, "src:mooring out:failure", "out:success", "ip"), "both of the rule's queries must pin src:mooring"},
		{rule(siem.RuleSequence, "src:host out:failure", "src:mooring out:success", "ip"), "both of the rule's queries must pin src:mooring"},
		{rule(siem.RuleSequence, "src:mooring out:success", "src:mooring out:failure", "ip"), "allowlisted addresses"},
		{rule(siem.RuleThreshold, "src:mooring kind:mooring.login", "", "actor"), "successful Mooring sign-ins"},
		{rule(siem.RuleThreshold, "src:mooring kind:mooring.login -out:failure", "", "actor"), "successful Mooring sign-ins"},
		{rule(siem.RuleThreshold, "src:mooring kind:mooring.login out!=failure", "", "actor"), "successful Mooring sign-ins"},
		{rule(siem.RuleThreshold, "src:mooring kind:mooring.login -out:failure -out:o*", "", "actor"), "successful Mooring sign-ins"},
		{rule(siem.RuleThreshold, "src:host kind:ssh.login out:success", "", "actor"), "Mooring accounts"},
		{rule(siem.RuleThreshold, "src:mooring kind:mooring.login out:success", "", "f.target"), "keyed by an address"},
	} {
		actions, why := h.e.RuleResponses(tc.r)
		switch tc.want {
		case siem.ResponseBlock, siem.ResponseRevoke:
			if len(actions) != 1 || actions[0] != tc.want || why != "" {
				t.Errorf("%q then %q by %s: %v %q, want %s", tc.r.Query, tc.r.Then, tc.r.GroupBy, actions, why, tc.want)
			}
		default:
			if len(actions) != 0 || !strings.Contains(why, tc.want) {
				t.Errorf("%q then %q by %s: %v %q, want none: %q", tc.r.Query, tc.r.Then, tc.r.GroupBy, actions, why, tc.want)
			}
		}
	}
}

func TestValidateResponse(t *testing.T) {
	base := func(resp siem.RuleResponse) siem.Rule {
		r := edgeRule(3)
		r.Response = resp
		return r
	}
	revoker := func(q string, resp siem.RuleResponse) siem.Rule {
		return siem.Rule{ID: "custom.r", Name: "r", Type: siem.RuleThreshold, Severity: siem.SevHigh, Query: q,
			GroupBy: "actor", Count: 1, Window: time.Hour, Response: resp}
	}
	for _, tc := range []struct {
		r    siem.Rule
		want string // "" valid
	}{
		{base(blockResp(time.Hour)), ""},
		{base(blockResp(5 * time.Minute)), ""},
		{base(blockResp(7 * 24 * time.Hour)), ""},
		{base(blockResp(4 * time.Minute)), "between 5m and 7d"},
		{base(blockResp(7*24*time.Hour + time.Second)), "between 5m and 7d"},
		{base(blockResp(0)), "between 5m and 7d"},
		{base(siem.RuleResponse{Action: "lock"}), "unknown response"},
		{base(revokeResp), "Mooring accounts"},
		{revoker("src:mooring kind:mooring.login out:success", revokeResp), ""},
		{revoker("src:mooring kind:mooring.login out:failure", revokeResp), "successful Mooring sign-ins"},
		{revoker("src:mooring kind:mooring.login out:success", blockResp(time.Hour)), "keyed by an address"},
	} {
		r := tc.r
		err := validate(&r, t0)
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%+v: %v", tc.r.Response, err)
		case tc.want != "" && (!errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%q %+v: %v, want %q", tc.r.Query, tc.r.Response, err, tc.want)
		}
	}
	// A sign-out takes no duration, and no response none: cleared, like other parameters a rule
	// doesn't use.
	r := revoker("src:mooring kind:mooring.login out:success", siem.RuleResponse{Action: siem.ResponseRevoke, Duration: time.Hour})
	if err := validate(&r, t0); err != nil || r.Response.Duration != 0 {
		t.Fatalf("revoke duration: %v %+v", err, r.Response)
	}
	r = base(siem.RuleResponse{Duration: time.Hour})
	if err := validate(&r, t0); err != nil || r.Response != (siem.RuleResponse{}) {
		t.Fatalf("no response: %v %+v", err, r.Response)
	}
}

func TestSaveRuleResponse(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	// A custom rule can't take a response its query doesn't allow; one it does is stored.
	r := customRule("blocker")
	r.Response = blockResp(time.Hour)
	if err := h.e.SaveRule(ctx, r); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "pin src:edge") {
		t.Fatalf("unpinned block: %v", err)
	}
	r.Query = "src:edge kind:http.request f.status:401"
	if err := h.e.SaveRule(ctx, r); err != nil {
		t.Fatal(err)
	}
	h.reopen(t)
	if got, _ := findRule(t, h.e, r.ID); got.Response != blockResp(time.Hour) {
		t.Fatalf("custom rule's response after restart: %+v", got.Response)
	}
	// A built-in rule's response is a tunable.
	b, _ := findRule(t, h.e, "mooring.login_bruteforce")
	b.Response = blockResp(time.Hour)
	if err := h.e.SaveRule(ctx, b); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "allowlisted") {
		t.Fatalf("block on a Mooring rule: %v", err)
	}
}

// The response is a tunable that changes nothing the rule learned: its state is kept when it is
// changed, cleared, stored, read back and reset.
func TestResponseTunableKeepsLearnedState(t *testing.T) {
	h := newHarness(t, true)
	ctx := context.Background()
	const id = "mooring.login_new_country"
	h.mooringLogin(0, "alice", "NG")
	h.e.syncRules()
	st := h.e.states[id]
	if st == nil || st.nv == nil {
		t.Fatal("nothing learned")
	}
	r, _ := findRule(t, h.e, id)
	if r.Response != revokeResp {
		t.Fatalf("pack default: %+v", r.Response)
	}
	r.Response = siem.RuleResponse{}
	if err := h.e.SaveRule(ctx, r); err != nil {
		t.Fatal(err)
	}
	h.e.syncRules()
	if h.e.states[id] != st {
		t.Fatal("changing the response reset the learned state")
	}
	if got, _ := findRule(t, h.e, id); got.Response != (siem.RuleResponse{}) {
		t.Fatalf("cleared: %+v", got.Response)
	}
	h.reopen(t)
	if got, _ := findRule(t, h.e, id); got.Response != (siem.RuleResponse{}) {
		t.Fatalf("cleared, after restart: %+v", got.Response)
	}
	if err := h.e.ResetRule(ctx, id); err != nil {
		t.Fatal(err)
	}
	if got, _ := findRule(t, h.e, id); got.Response != revokeResp {
		t.Fatalf("after reset: %+v", got.Response)
	}
	// A setting stored before responses existed keeps the pack's response.
	old, _ := json.Marshal(map[string]any{"enabled": true, "severity": "critical", "count": 0, "window": 0,
		"factor": 0, "learn": int64(3 * day), "speed_kmh": 0})
	if _, err := h.main.Exec(`INSERT INTO security_rules(id, json, updated_at) VALUES (?, ?, 1)`, id, string(old)); err != nil {
		t.Fatal(err)
	}
	h.reopen(t)
	if got, _ := findRule(t, h.e, id); got.Response != revokeResp || got.Severity != siem.SevCritical {
		t.Fatalf("old stored setting: %+v", got)
	}
	// A stored response that no longer validates falls back to the pack's alone.
	bad, _ := json.Marshal(map[string]any{"enabled": true, "severity": "critical", "learn": int64(3 * day),
		"response": map[string]any{"action": "block", "duration": int64(time.Hour)}})
	if _, err := h.main.Exec(`UPDATE security_rules SET json = ? WHERE id = ?`, string(bad), id); err != nil {
		t.Fatal(err)
	}
	h.reopen(t)
	if got, _ := findRule(t, h.e, id); got.Response != revokeResp || got.Severity != siem.SevCritical {
		t.Fatalf("invalid stored response: %+v", got)
	}
	// A valid stored response is kept when another stored field doesn't validate.
	mixed, _ := json.Marshal(map[string]any{"enabled": true, "severity": "critical", "learn": int64(3 * day),
		"snoozed_until": t0.Add(365 * day), "response": map[string]any{}})
	if _, err := h.main.Exec(`UPDATE security_rules SET json = ? WHERE id = ?`, string(mixed), id); err != nil {
		t.Fatal(err)
	}
	h.reopen(t)
	if got, _ := findRule(t, h.e, id); got.Response != (siem.RuleResponse{}) || got.Severity != siem.SevCritical ||
		!got.SnoozedUntil.IsZero() {
		t.Fatalf("stored response beside an invalid snooze: %+v", got)
	}
}

func (h *harness) mooringLogin(at time.Duration, user, cc string) {
	e := signIn(at, siem.OutSuccess, addrX, user)
	e.Geo = &siem.Geo{Country: cc}
	h.feed(e)
}

func TestPackDefaultResponses(t *testing.T) {
	want := map[string]siem.RuleResponse{
		"edge.spamhaus_ip":                     blockResp(24 * time.Hour),
		"edge.dshield_ip":                      blockResp(24 * time.Hour),
		"edge.scan":                            blockResp(time.Hour),
		"mooring.login_new_country":            revokeResp,
		"mooring.login_travel":                 revokeResp,
		"mooring.login_tor":                    revokeResp,
		"mooring.login_success_after_failures": revokeResp,
		"baseline.signin_unusual":              revokeResp,
	}
	for _, p := range pack {
		if p.Response != want[p.ID] {
			t.Errorf("%s: response %+v, want %+v", p.ID, p.Response, want[p.ID])
		}
		if p.Response.Action == "" {
			continue
		}
		if actions, why := ruleResponses(p.Rule); len(actions) != 1 || actions[0] != p.Response.Action {
			t.Errorf("%s: may take %v (%s)", p.ID, actions, why)
		}
	}
	if len(want) != 8 {
		t.Fatal(len(want))
	}
}

// The pack's sign-in rules ask for a sign-out of the right account; its edge rules for a block.
func TestPackResponses(t *testing.T) {
	h, fr := respHarness(t, false)
	h.mooringLogin(0, "alice", "NG")
	h.clk.advance(8 * day)
	h.mooringLogin(8*day, "alice", "GH")
	h.e.flush(false)
	got := fr.all()
	if len(got) != 1 || got[0].RuleID != "mooring.login_new_country" || got[0].Target != "alice" || !got[0].Automatic {
		t.Fatalf("new country: %+v", got)
	}
	for i := range 5 {
		h.feed(signIn(8*day+time.Duration(i+1)*time.Second, siem.OutFailure, addrY, "bob"))
	}
	h.feed(signIn(8*day+10*time.Second, siem.OutSuccess, addrY, "carol"))
	h.e.flush(false)
	got = fr.all()
	if len(got) != 2 || got[1].RuleID != "mooring.login_success_after_failures" || got[1].Target != "carol" {
		t.Fatalf("success after failures: %+v", got)
	}
	for i := range 100 {
		h.feed(edgeHit(8*day+time.Minute+time.Duration(i)*time.Millisecond, addrZ, ""))
	}
	h.e.flush(false)
	got = fr.all()
	if len(got) != 3 || got[2].RuleID != "edge.scan" || got[2].Target != addrZ || got[2].Duration != time.Hour || !got[2].Automatic {
		t.Fatalf("scan: %+v", got)
	}
}

func TestNoteResponse(t *testing.T) {
	h, _ := respHarness(t, false)
	ctx := context.Background()
	h.only(t, edgeRule(1))
	h.feed(edgeHit(0, addrX, ""))
	incs := h.incList(t)
	if len(incs) != 1 {
		t.Fatal(incs)
	}
	id := incs[0].ID
	if err := h.e.NoteResponse(ctx, id, siem.IncidentEvent{Text: "x"}); err == nil {
		t.Fatal("not running: no error")
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); h.e.Run(runCtx) }()
	defer func() { cancel(); <-done }()
	waitFor(t, "running", h.e.running.Load)

	ev := siem.IncidentEvent{Kind: siem.TimelineNote, DetectionID: 7, RuleID: "edge.scan", RuleName: "Web scan",
		Severity: siem.SevLow, Text: "blocked " + addrX + "/32 for 1h <@here>\n" + strings.Repeat("x", 400)}
	if err := h.e.NoteResponse(ctx, id, ev); err != nil {
		t.Fatal(err)
	}
	if err := h.e.NoteResponse(ctx, id+100, ev); !errors.Is(err, siem.ErrInvalidInput) {
		t.Fatalf("unknown incident: %v", err)
	}
	if err := h.e.NoteResponse(ctx, 0, ev); !errors.Is(err, siem.ErrInvalidInput) {
		t.Fatalf("incident 0: %v", err)
	}
	if err := h.e.NoteResponse(ctx, id, siem.IncidentEvent{Text: " \n"}); !errors.Is(err, siem.ErrInvalidInput) {
		t.Fatalf("empty text: %v", err)
	}
	inc, ok, err := h.e.Incident(ctx, id)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
	var got []siem.IncidentEvent
	for _, x := range inc.Timeline {
		if x.Kind == siem.TimelineResponse {
			got = append(got, x)
		}
	}
	if len(got) != 1 {
		t.Fatalf("timeline %+v", inc.Timeline)
	}
	x := got[0]
	if !strings.HasPrefix(x.Text, "blocked "+addrX+"/32 for 1h <@here> x") || len(x.Text) > maxSummary ||
		strings.ContainsAny(x.Text, "\n") || x.DetectionID != 7 || x.RuleID != "edge.scan" || x.Severity != siem.SevLow ||
		x.TS.IsZero() || x.Actor != "" {
		t.Fatalf("entry %+v", x)
	}
	// At most maxResponseEntries per incident: past it, nothing more is added (and no error).
	for range maxResponseEntries + 5 {
		if err := h.e.NoteResponse(ctx, id, siem.IncidentEvent{Text: "refused"}); err != nil {
			t.Fatal(err)
		}
	}
	if n := countRows(t, h, `SELECT COUNT(*) FROM incident_timeline WHERE kind = 'response'`); n != maxResponseEntries {
		t.Fatalf("%d response entries", n)
	}
}
