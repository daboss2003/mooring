package detect

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

// retireAll forgets every active detection, so the next firing reads its detection back from
// detect.db (as after an eviction or a restart).
func (h *harness) retireAll() {
	h.e.flush(true)
	for mk, el := range h.e.active {
		h.e.retire(el)
		delete(h.e.active, mk)
	}
}

// Every firing of a block rule is judged on its own: a detection whose first firing only
// recommended (a browser's request) or asked for nothing (a snoozed rule, a mute since lifted) asks
// for its block at a later firing that qualifies.
func TestResponseBlockAskedAtALaterFiringThatQualifies(t *testing.T) {
	// The first firing was a browser's request: a recommendation (no request at all before v0.33.1).
	h, fr := respHarness(t, false)
	h.only(t, edgeRule(1))
	h.feed(edgeHit(0, addrX, "cross-site"))
	h.e.flush(false)
	if got := fr.all(); !recommended(got, addrX) {
		t.Fatalf("a browser's request: %+v", got)
	}
	// A recommendation doesn't hold the automatic block back: the scripted firing a minute later
	// asks for it at once (v0.33.1).
	h.feed(edgeHit(time.Minute, addrX, ""))
	h.e.flush(false)
	got := fr.all()
	ds := h.all(t)
	if len(ds) != 1 || ds[0].Count != 2 {
		t.Fatalf("detections %+v", ds)
	}
	if len(got) != 2 || got[1].Target != addrX || !got[1].Automatic || got[1].DetectionID != ds[0].ID || got[1].DetectionID == 0 {
		t.Fatalf("the scripted firing after a browser's: %+v", got)
	}
	// A later browser firing recommends again, never blocks.
	h.feed(edgeHit(20*time.Minute, addrX, "same-origin"))
	h.e.flush(false)
	if got := fr.all(); len(got) != 3 || got[2].Automatic || got[2].Target != addrX {
		t.Fatalf("a later browser firing: %+v", got)
	}

	// The first firing came while the rule was snoozed.
	h, fr = respHarness(t, false)
	h.only(t, edgeRule(1))
	c := h.e.rules.Load().byID["custom.edge"]
	c.r.SnoozedUntil = h.clk.now().Add(10 * time.Minute)
	h.feed(edgeHit(0, addrX, ""), edgeHit(9*time.Minute, addrX, ""))
	h.e.flush(false)
	if got := fr.all(); len(got) != 0 {
		t.Fatalf("snoozed: %+v", got)
	}
	h.feed(edgeHit(11*time.Minute, addrX, ""))
	h.e.flush(false)
	if got := fr.all(); len(got) != 1 || !got[0].Automatic {
		t.Fatalf("after the snooze: %+v", got)
	}
	if ds := h.all(t); len(ds) != 1 || ds[0].Count != 3 {
		t.Fatalf("detections %+v", ds)
	}

	// The first firing was muted; the mute was lifted since.
	ctx := context.Background()
	h, fr = respHarness(t, true)
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
	stop := h.run(t)
	if err := h.e.RemoveMute(ctx, "custom.edge", addr(addrX), "owner"); err != nil {
		t.Fatal(err)
	}
	stop()
	h.feed(edgeHit(time.Minute, addrX, ""))
	h.e.flush(false)
	if got := fr.all(); len(got) != 1 || got[0].Target != addrX {
		t.Fatalf("after the mute was lifted: %+v", got)
	}
	if ds := h.all(t); len(ds) != 1 {
		t.Fatalf("detections %+v", ds)
	}
}

// A detection asks for its block at most once every blockAskEvery, however often it fires, and for
// one block at a time while its request waits for the detection's write.
func TestResponseBlockAskedAtMostEveryFiveMinutes(t *testing.T) {
	h, fr := respHarness(t, false)
	h.only(t, edgeRule(1))
	for i := range 13 {
		h.feed(edgeHit(time.Duration(i)*time.Minute, addrX, ""))
		h.e.flush(false)
	}
	got := fr.all()
	if len(got) != 3 {
		t.Fatalf("%d requests in 12 minutes of firings: %+v", len(got), got)
	}
	for i, r := range got {
		if r.Target != addrX || !r.Automatic || r.Duration != time.Hour || r.DetectionID != got[0].DetectionID ||
			r.DetectionID == 0 || !r.At.Equal(t0.Add(time.Duration(i)*blockAskEvery)) {
			t.Fatalf("request %d: %+v", i, r)
		}
	}
	h.feed(edgeHit(10*time.Minute+blockAskEvery-time.Second, addrX, ""))
	if got := fr.all(); len(got) != 3 {
		t.Fatalf("a second short of the interval: %+v", got)
	}
	h.feed(edgeHit(10*time.Minute+blockAskEvery, addrX, ""))
	if got := fr.all(); len(got) != 4 {
		t.Fatalf("at the interval: %+v", got)
	}
	// Intentional in the engine: a clock that stepped back doesn't silence the detection.
	h.clk.set(t0.Add(12 * time.Minute))
	h.feedRaw(edgeHit(12*time.Minute, addrX, ""))
	if got := fr.all(); len(got) != 5 {
		t.Fatalf("after the clock stepped back: %+v", got)
	}

	// One request waits for the write, however long that takes.
	h, fr = respHarness(t, false)
	h.only(t, edgeRule(1))
	h.feed(edgeHit(0, addrX, ""), edgeHit(blockAskEvery+time.Minute, addrX, ""))
	if got := fr.all(); len(got) != 0 {
		t.Fatalf("sent before the detection was written: %+v", got)
	}
	h.e.flush(false)
	if got := fr.all(); len(got) != 1 || got[0].DetectionID == 0 {
		t.Fatalf("two firings before the write: %+v", got)
	}
}

// A sign-out is asked once per detection and account: an address-keyed rule asks for each account
// that signs in from the address, each once, also when two fire before the detection is written.
func TestResponseSignOutOncePerAccount(t *testing.T) {
	h, fr := respHarness(t, false)
	h.only(t, siem.Rule{ID: "custom.tor", Type: siem.RuleThreshold, Query: "src:mooring kind:mooring.login out:success",
		GroupBy: "ip", Count: 1, Window: time.Hour, Response: revokeResp})
	h.feed(signIn(0, siem.OutSuccess, addrX, "alice"), signIn(time.Second, siem.OutSuccess, addrX, "bob"))
	if got := fr.all(); len(got) != 0 {
		t.Fatalf("sent before the detection was written: %+v", got)
	}
	h.e.flush(false)
	got := fr.all()
	if len(got) != 2 || got[0].Target != "alice" || got[1].Target != "bob" || got[0].DetectionID == 0 ||
		got[0].DetectionID != got[1].DetectionID || !got[0].Automatic || !got[1].Automatic ||
		got[0].Action != siem.ResponseRevoke || got[1].Action != siem.ResponseRevoke {
		t.Fatalf("two accounts from one address: %+v", got)
	}
	h.feed(signIn(10*time.Minute, siem.OutSuccess, addrX, "alice"), signIn(20*time.Minute, siem.OutSuccess, addrX, "bob"))
	h.e.flush(false)
	if got := fr.all(); len(got) != 2 {
		t.Fatalf("the same accounts again: %+v", got)
	}
	h.feed(signIn(30*time.Minute, siem.OutSuccess, addrX, "carol"))
	if got := fr.all(); len(got) != 3 || got[2].Target != "carol" || got[2].DetectionID != got[0].DetectionID {
		t.Fatalf("a third account: %+v", got)
	}
	if ds := h.all(t); len(ds) != 1 || ds[0].Count != 5 {
		t.Fatalf("detections %+v", ds)
	}
	// Read back from detect.db, the detection may ask once more per account (the responder's
	// cooldown refuses the repeat).
	h.retireAll()
	h.feed(signIn(40*time.Minute, siem.OutSuccess, addrX, "alice"))
	if got := fr.all(); len(got) != 4 || got[3].Target != "alice" || got[3].DetectionID != got[0].DetectionID {
		t.Fatalf("read back: %+v", got)
	}
	h.feed(signIn(41*time.Minute, siem.OutSuccess, addrX, "alice"))
	if got := fr.all(); len(got) != 4 {
		t.Fatalf("read back, the same account again: %+v", got)
	}

	// The accounts remembered per detection are bounded: past maxSignOuts the oldest is forgotten
	// (and may be asked for again).
	h, fr = respHarness(t, false)
	h.only(t, siem.Rule{ID: "custom.tor", Type: siem.RuleThreshold, Query: "src:mooring kind:mooring.login out:success",
		GroupBy: "ip", Count: 1, Window: time.Hour, Response: revokeResp})
	at := time.Duration(0)
	in := func(user string) {
		at += time.Second
		h.feed(signIn(at, siem.OutSuccess, addrX, user))
	}
	for i := range maxSignOuts {
		in(fmt.Sprintf("u%d", i))
	}
	in("u0")
	h.e.flush(false)
	if got := fr.all(); len(got) != maxSignOuts {
		t.Fatalf("%d requests for %d accounts", len(got), maxSignOuts)
	}
	in("extra") // u0 is forgotten
	in(fmt.Sprintf("u%d", maxSignOuts-1))
	if got := fr.all(); len(got) != maxSignOuts+1 || got[maxSignOuts].Target != "extra" {
		t.Fatalf("one account past the bound: %d requests", len(got))
	}
	in("u0")
	if got := fr.all(); len(got) != maxSignOuts+2 || got[maxSignOuts+1].Target != "u0" {
		t.Fatalf("the forgotten account: %d requests", len(got))
	}
	var a *activeDet
	for _, el := range h.e.active {
		a = el.Value.(*activeDet)
	}
	if a == nil || len(a.signedOut) != maxSignOuts {
		t.Fatalf("accounts remembered: %+v", a)
	}
}

// A browser's (or a browser agent's) request merged into the window entry of its second is flagged
// for as long as that entry is counted, whichever of the second's events came first.
func TestResponseBrowserMergedIntoItsSecond(t *testing.T) {
	run := func(first, second siem.Event) []siem.ResponseRequest {
		t.Helper()
		h, fr := respHarness(t, false)
		r := edgeRule(3)
		r.Window = time.Minute
		h.only(t, r)
		// Two requests in second 0, the one at 0.1s arriving after the one at 0.9s (merged into its
		// entry); the third fires the rule while only the entry's time (0.9s) is inside the window.
		h.feed(first)
		h.feedRaw(second)
		h.feed(edgeHit(time.Minute+500*time.Millisecond, addrX, ""))
		h.e.flush(false)
		if ds := h.all(t); len(ds) != 1 || ds[0].Count != 3 {
			t.Fatalf("detections %+v", ds)
		}
		return fr.all()
	}
	late, early := 900*time.Millisecond, 100*time.Millisecond
	if got := run(edgeHit(late, addrX, ""), edgeHit(early, addrX, "")); len(got) != 1 || !got[0].Automatic {
		t.Fatalf("scripted requests: %+v", got)
	}
	if got := run(edgeHit(late, addrX, ""), edgeHit(early, addrX, "cross-site")); !recommended(got, addrX) {
		t.Fatalf("a browser's request merged into its second's entry: %+v", got)
	}
	if got := run(edgeHit(late, addrX, "cross-site"), edgeHit(early, addrX, "")); !recommended(got, addrX) {
		t.Fatalf("a browser's request first in its second: %+v", got)
	}
	if got := run(edgeHit(late, addrX, ""), edgeUA(early, addrX, "", chromeWin)); len(got) != 1 || got[0].Automatic {
		t.Fatalf("a browser agent's request merged into its second's entry: %+v", got)
	}
}

// A request with a browser's agent counts over the whole window like a browser's, not only among
// the few events kept as evidence; one that left the window no longer does.
func TestResponseBrowserAgentCountedBeyondEvidence(t *testing.T) {
	h, fr := respHarness(t, false)
	r := edgeRule(preEvidence + 4)
	r.Window = 5 * time.Minute
	h.only(t, r)
	h.feed(edgeUA(0, addrX, "", chromeWin))
	for i := range preEvidence + 3 {
		h.feed(edgeUA(time.Duration(i+1)*time.Second, addrX, "", "curl/8"))
	}
	h.e.flush(false)
	got := fr.all()
	if len(got) != 1 || got[0].Automatic || got[0].Target != addrX {
		t.Fatalf("a browser agent's request among the counted: %+v", got)
	}
	// The same from another address, the browser agent's request long before the window.
	h.feed(edgeUA(10*time.Minute, addrY, "", chromeWin))
	for i := range preEvidence + 4 {
		h.feed(edgeUA(20*time.Minute+time.Duration(i)*time.Second, addrY, "", "curl/8"))
	}
	h.e.flush(false)
	if got := fr.all(); len(got) != 2 || !got[1].Automatic || got[1].Target != addrY {
		t.Fatalf("a browser agent's request before the window: %+v", got)
	}
}

// An anomaly rule's window is counted to slot precision, so its oldest slot is counted whole: a
// browser's request anywhere in that slot is one of the counted, also before the window's exact
// start.
func TestResponseAnomalyOldestSlotBrowser(t *testing.T) {
	run := func(site, ua string) []siem.ResponseRequest {
		t.Helper()
		h, fr := respHarness(t, false)
		h.only(t, siem.Rule{ID: "custom.a", Type: siem.RuleAnomaly, Query: "src:edge kind:http.request", GroupBy: "ip",
			Count: 8, Window: time.Hour, Factor: 2, Response: blockResp(time.Hour)})
		// 30s into the first one-minute slot; the firing's window starts at 45s, inside that slot.
		h.feed(edgeUA(30*time.Second, addrX, site, ua))
		for i := range 6 {
			h.feed(edgeHit(30*time.Minute+time.Duration(i)*time.Second, addrX, ""))
		}
		h.feed(edgeHit(time.Hour+45*time.Second, addrX, ""))
		h.e.flush(false)
		if ds := h.all(t); len(ds) != 1 || ds[0].Count != 8 {
			t.Fatalf("the first slot's request isn't counted: %+v", ds)
		}
		return fr.all()
	}
	if got := run("", ""); len(got) != 1 || !got[0].Automatic {
		t.Fatalf("scripted: %+v", got)
	}
	if got := run("cross-site", ""); !recommended(got, addrX) {
		t.Fatalf("a browser's request in the oldest counted slot: %+v", got)
	}
	if got := run("", chromeWin); len(got) != 1 || got[0].Automatic {
		t.Fatalf("a browser agent's request in the oldest counted slot: %+v", got)
	}
}
