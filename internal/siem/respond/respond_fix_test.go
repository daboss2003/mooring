package respond

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/blocklist"
	"github.com/daboss2003/mooring/internal/siem"
)

// Finding 5: a panic while a response is decided (recovered by the worker, or by the page's
// handler) releases the lock: nothing hangs afterwards.
func TestPanicReleasesTheLock(t *testing.T) {
	ctx := context.Background()
	var boom atomic.Bool
	e := newEnv(t, siem.ResponseModeRecommend, func(o *Options) {
		now := o.Now
		o.Now = func() time.Time {
			if boom.Load() {
				panic("clock")
			}
			return now()
		}
	})
	e.r.handle(blockReq("203.0.113.7", true))
	id := e.only().ID
	recovered := func(f func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Error("no panic: the test doesn't reach the locked part")
			}
		}()
		f()
	}
	for name, f := range map[string]func(){
		"handle":          func() { e.r.handle(blockReq("203.0.113.8", true)) },
		"Apply":           func() { _ = e.r.Apply(ctx, id, "owner") },
		"Dismiss":         func() { _ = e.r.Dismiss(ctx, id, "owner") },
		"LiftForIncident": func() { _, _ = e.r.LiftForIncident(ctx, 5, "owner") },
		"maintain":        func() { e.r.maintain(ctx) },
	} {
		boom.Store(true)
		recovered(f)
		boom.Store(false)
		if !e.r.mu.TryLock() {
			t.Fatalf("%s: a panic left the lock held", name)
		}
		e.r.mu.Unlock()
	}
	// The worker recovers and goes on.
	boom.Store(true)
	e.r.safe(func() { e.r.handle(blockReq("203.0.113.9", true)) })
	boom.Store(false)
	if err := e.r.SetPause(ctx, siem.ResponseModeRecommend, "owner"); err != nil {
		t.Fatal(err)
	}
}

// Finding 6: once the block is placed, the outcome is recorded even when the request that asked
// was cancelled meanwhile: the row doesn't stay a recommendation that could be applied again.
func TestApplyRecordsAfterTheRequestIsCancelled(t *testing.T) {
	e := newEnv(t, siem.ResponseModeRecommend)
	e.r.handle(blockReq("203.0.113.7", true))
	e.r.handle(revokeReq("alice"))
	rs := e.list(siem.ResponseFilter{})
	ctx, cancel := context.WithCancel(context.Background())
	e.blocks.onBlock = cancel
	if err := e.r.Apply(ctx, rs[1].ID, "owner"); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := e.r.Response(context.Background(), rs[1].ID); got.State != siem.ResponseApplied || got.By != "owner" {
		t.Fatalf("after a cancelled request: %+v", got)
	}
	if err := e.r.Apply(context.Background(), rs[1].ID, "owner"); !errors.Is(err, siem.ErrInvalidInput) {
		t.Fatalf("applied twice: %v", err)
	}
	if n := len(e.blocks.requests()); n != 1 {
		t.Fatalf("%d blocks placed", n)
	}
	// LiftForIncident: the blocks are lifted, so its recommendations are dismissed all the same.
	e.r.handle(blockReq("203.0.113.8", true)) // incident 5
	ctx, cancel = context.WithCancel(context.Background())
	e.blocks.onUnblockIncident = cancel
	if _, err := e.r.LiftForIncident(ctx, 5, "owner"); err != nil {
		t.Fatal(err)
	}
	if got := e.list(siem.ResponseFilter{States: []string{siem.ResponseRecommended}, IncidentID: 5}); len(got) != 0 {
		t.Fatalf("left open: %+v", got)
	}
}

// Finding 7: an open recommendation belongs to its incident. A second incident asking for the
// same block gets its own row, so marking the first a false positive dismisses the first's.
func TestRecommendationPerIncident(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, siem.ResponseModeRecommend)
	e.r.handle(blockReq("203.0.113.7", true)) // incident 5
	other := blockReq("203.0.113.7", true)
	other.IncidentID, other.DetectionID = 9, 30
	e.r.handle(other)
	none := blockReq("203.0.113.7", true)
	none.IncidentID, none.DetectionID = 0, 31
	e.r.handle(none)
	e.r.handle(none)
	rs := e.list(siem.ResponseFilter{})
	if len(rs) != 3 || rs[2].IncidentID != 5 || rs[2].DetectionID != 11 || rs[1].IncidentID != 9 || rs[0].IncidentID != 0 {
		t.Fatalf("recommendations %+v", rs)
	}
	if _, err := e.r.LiftForIncident(ctx, 5, "owner"); err != nil {
		t.Fatal(err)
	}
	rs = e.list(siem.ResponseFilter{})
	if rs[2].State != siem.ResponseDismissed || rs[1].State != siem.ResponseRecommended || rs[0].State != siem.ResponseRecommended {
		t.Fatalf("after the first incident's false positive: %+v", rs)
	}
}

// Finding 8: requests still queued when the responder stops and the drain time is over are
// recorded as failed (interrupted), not applied and not lost.
func TestLeftoverRequestsRecordedAtStop(t *testing.T) {
	e := newEnv(t, siem.ResponseModeEnforce)
	e.r.drainFor = 0
	for i := range 5 {
		if !e.r.Respond(blockReq(fmt.Sprintf("203.0.113.%d", i+1), true)) {
			t.Fatal("not taken")
		}
	}
	e.r.Respond(revokeReq("alice"))
	e.r.Respond(revokeReq("")) // malformed: nothing to record
	// As Run does when it stops (Run itself may take a queued request before it sees the stop).
	e.r.drain()
	rs := e.list(siem.ResponseFilter{})
	if len(rs) != 6 {
		t.Fatalf("%d of 6 recorded: %+v", len(rs), rs)
	}
	for _, x := range rs {
		if x.State != siem.ResponseFailed || x.Reason != "interrupted" || !x.Automatic || x.RuleID == "" {
			t.Fatalf("left over %+v", x)
		}
	}
	if rs[5].Target != "203.0.113.1/32" || rs[5].IncidentID != 5 || rs[5].DetectionID != 11 || rs[0].Target != "alice" {
		t.Fatalf("targets %+v", rs)
	}
	if n := len(e.blocks.requests()); n != 0 || len(e.rev.calls) != 0 {
		t.Fatalf("applied after the drain time: %d blocks, revokes %v", n, e.rev.calls)
	}
	if len(e.r.queue) != 0 {
		t.Fatalf("%d still queued", len(e.r.queue))
	}
	// With automated response off nothing is recorded, as for a handled request.
	e = newEnv(t, siem.ResponseModeOff)
	e.r.drainFor = 0
	e.r.Respond(blockReq("203.0.113.1", true))
	e.r.drain()
	if rs := e.list(siem.ResponseFilter{}); len(rs) != 0 {
		t.Fatalf("mode off recorded %+v", rs)
	}
}

// Finding 9: the siem.response event of a sign-out names the account as events store it (the
// keyed hash of an email username), never the username; the row, the timeline, the alert and the
// audit record keep the username.
func TestRevokeEventNamesTheStoredActor(t *testing.T) {
	ctx := context.Background()
	const hashed, user = "h:0123456789abcdef", "alice@example.com"
	check := func(what string, events []siem.Event) {
		t.Helper()
		if len(events) != 1 {
			t.Fatalf("%s: events %+v", what, events)
		}
		ev := events[0]
		if ev.Actor != hashed || ev.F["target"] != hashed || !strings.Contains(ev.Msg, hashed) ||
			strings.Contains(ev.Msg, "alice") || ev.F["state"] != siem.ResponseApplied {
			t.Fatalf("%s: event %+v", what, ev)
		}
	}
	e := newEnv(t, siem.ResponseModeEnforce)
	e.r.handle(revokeReq(hashed))
	if x := e.only(); x.Target != user || x.State != siem.ResponseApplied {
		t.Fatalf("row %+v", x)
	}
	notes, alerts, audits, events := e.take()
	check("automatic", events)
	if events[0].Msg != "signed "+hashed+" out (1 session)" {
		t.Fatalf("message %q", events[0].Msg)
	}
	if notes[0].ev.Text != "signed "+user+" out (1 session)" || audits[0].Target != user ||
		!strings.HasPrefix(alerts[0].Summary, "Mooring signed aliceexample.com out of 1 session") {
		t.Fatalf("timeline %+v, audit %+v, alert %+v", notes, audits, alerts)
	}
	// Applied by the owner from a recommendation.
	e = newEnv(t, siem.ResponseModeRecommend)
	e.r.handle(revokeReq(hashed))
	x := e.only()
	if x.Target != hashed {
		t.Fatalf("recommendation %+v", x)
	}
	e.take()
	if err := e.r.Apply(ctx, x.ID, "owner"); err != nil {
		t.Fatal(err)
	}
	if got := e.only(); got.Target != user || got.State != siem.ResponseApplied {
		t.Fatalf("applied row %+v", got)
	}
	_, _, _, events = e.take()
	check("applied by the owner", events)
	if events[0].F["by"] != "owner" {
		t.Fatalf("event %+v", events[0].F)
	}
	// A plain username is its own stored form.
	e = newEnv(t, siem.ResponseModeEnforce)
	e.r.handle(revokeReq("alice"))
	if _, _, _, events := e.take(); events[0].Actor != "alice" || events[0].Msg != "signed alice out (3 sessions)" {
		t.Fatalf("plain username: %+v", events)
	}
}

// Several users stored as one actor: the revoker's comma-separated list is recorded as it is, and
// cleaned for the alert.
func TestRevokeSeveralUsernames(t *testing.T) {
	e := newEnv(t, siem.ResponseModeEnforce)
	e.rev.by["h:00000000000000aa"] = revokeResult{"Alice@example.com, alice@example.com", 4, nil}
	e.r.handle(revokeReq("h:00000000000000aa"))
	if x := e.only(); x.Target != "Alice@example.com, alice@example.com" || x.State != siem.ResponseApplied {
		t.Fatalf("row %+v", x)
	}
	_, alerts, _, events := e.take()
	if !strings.HasPrefix(alerts[0].Summary, "Mooring signed Aliceexample.com, aliceexample.com out of 4 sessions") ||
		events[0].Actor != "h:00000000000000aa" {
		t.Fatalf("alert %+v event %+v", alerts, events)
	}
	// The cooldown is the stored actor's.
	e.clk.advance(time.Minute)
	e.r.handle(revokeReq("h:00000000000000aa"))
	if x := e.list(siem.ResponseFilter{})[0]; x.State != siem.ResponseRefused || x.Reason != "cooldown" {
		t.Fatalf("cooldown %+v", x)
	}
}

// Contract: Responses filters by detection.
func TestResponsesFilterByDetection(t *testing.T) {
	e := newEnv(t, siem.ResponseModeEnforce)
	for i := range 4 {
		r := blockReq(fmt.Sprintf("203.0.113.%d", i+1), true)
		r.DetectionID = int64(40 + i%2)
		e.r.handle(r)
	}
	rs := e.list(siem.ResponseFilter{DetectionID: 41})
	if len(rs) != 2 || rs[0].DetectionID != 41 || rs[1].DetectionID != 41 {
		t.Fatalf("detection 41: %+v", rs)
	}
	if rs := e.list(siem.ResponseFilter{DetectionID: 99}); len(rs) != 0 {
		t.Fatalf("detection 99: %+v", rs)
	}
	if rs := e.list(siem.ResponseFilter{}); len(rs) != 4 {
		t.Fatalf("any detection: %+v", rs)
	}
	if _, err := e.r.Responses(context.Background(), siem.ResponseFilter{DetectionID: -1}); !errors.Is(err, siem.ErrInvalidInput) {
		t.Fatalf("detection -1: %v", err)
	}
}

// Contract: a pause to off whose lift of the automatic blocks failed is stored and in force, says
// so with siem.ErrBlocksNotLifted, and the lift is tried again by maintenance until it works.
func TestSetPauseBlocksNotLifted(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, siem.ResponseModeEnforce)
	e.blocks.liftErr = errors.New("database is locked")
	err := e.r.SetPause(ctx, siem.ResponseModeOff, "owner")
	if !errors.Is(err, siem.ErrBlocksNotLifted) || errors.Is(err, siem.ErrInvalidInput) {
		t.Fatalf("pause with a failed lift: %v", err)
	}
	if st, _ := e.r.Status(ctx); st.Paused != siem.ResponseModeOff || st.Effective != siem.ResponseModeOff || st.PausedBy != "owner" {
		t.Fatalf("the pause is not in force: %+v", st)
	}
	e.r.handle(blockReq("203.0.113.7", true))
	if rs := e.list(siem.ResponseFilter{}); len(rs) != 0 {
		t.Fatalf("acted while paused: %+v", rs)
	}
	e.r.maintain(ctx) // fails again
	e.blocks.liftErr, e.blocks.liftN = nil, 3
	e.r.maintain(ctx)
	e.r.maintain(ctx) // nothing owed any more
	if len(e.blocks.lifts) != 3 || e.blocks.lifts[2] != "siem automated response paused" {
		t.Fatalf("lifts %v", e.blocks.lifts)
	}
	// Kept across a restart while it is owed.
	e = newEnv(t, siem.ResponseModeEnforce)
	e.blocks.liftErr = errors.New("database is locked")
	if err := e.r.SetPause(ctx, siem.ResponseModeOff, "owner"); !errors.Is(err, siem.ErrBlocksNotLifted) {
		t.Fatal(err)
	}
	e.blocks.liftErr = nil
	e.reopen()
	if len(e.blocks.lifts) != 2 {
		t.Fatalf("after a restart: lifts %v", e.blocks.lifts)
	}
	// A pause that worked returns no error.
	if err := e.r.SetPause(ctx, siem.ResponseModeOff, "owner"); err != nil {
		t.Fatal(err)
	}
}

// Intent: a sign-out whose target isn't an account name as events store one (space around it,
// control characters, too long) is recorded as refused, and the revoker is never asked.
func TestInvalidRevokeTargetIsRecorded(t *testing.T) {
	long := strings.Repeat("a", siem.MaxShort+1)
	for _, mode := range []string{siem.ResponseModeEnforce, siem.ResponseModeRecommend} {
		e := newEnv(t, mode)
		// Each prints as another name: a refusal of the same target for the same reason within the
		// hour is recorded once (TestRepeatedRefusalsOfEveryKind).
		for _, target := range []string{" alice", "bob\n", "car\x00ol", long} {
			e.r.handle(revokeReq(target))
		}
		rs := e.list(siem.ResponseFilter{})
		if len(rs) != 4 || len(e.rev.calls) != 0 {
			t.Fatalf("%s: recorded %+v, revoker called %v", mode, rs, e.rev.calls)
		}
		for i, want := range []string{long[:siem.MaxShort], "carol", "bob", "alice"} {
			x := rs[i]
			if x.State != siem.ResponseRefused || x.Reason != "invalid_target" || x.Target != want ||
				x.Action != siem.ResponseRevoke || x.RuleID != "mooring.login_tor" || x.IncidentID != 6 {
				t.Fatalf("%s: response %d: %+v", mode, i, x)
			}
		}
		notes, alerts, audits, events := e.take()
		if len(notes) != 4 || notes[0].ev.Text != "sign-out of alice refused: invalid_target" || len(alerts) != 0 ||
			len(events) != 4 || events[0].F["reason"] != "invalid_target" {
			t.Fatalf("%s: timeline %+v alerts %+v events %+v", mode, notes, alerts, events)
		}
		// Mooring's own refusal is audited in enforce mode, like its other automatic decisions.
		if want := map[string]int{siem.ResponseModeEnforce: 4, siem.ResponseModeRecommend: 0}[mode]; len(audits) != want {
			t.Fatalf("%s: %d audit records", mode, len(audits))
		}
	}
	e := newEnv(t, siem.ResponseModeOff)
	e.r.handle(revokeReq(" alice"))
	if rs := e.list(siem.ResponseFilter{}); len(rs) != 0 {
		t.Fatalf("mode off recorded %+v", rs)
	}
}

// Intent: applying a recommendation when the block list (or the revoker) fails, rather than
// refuses, leaves it open to be applied again; a refusal is final.
func TestApplyFailureLeavesTheRecommendationOpen(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, siem.ResponseModeRecommend)
	e.r.handle(blockReq("203.0.113.7", true))
	x := e.only()
	e.take()
	e.blocks.err = errors.New("database is locked")
	err := e.r.Apply(ctx, x.ID, "owner")
	if err == nil || errors.Is(err, siem.ErrInvalidInput) || !strings.Contains(err.Error(), "database is locked") {
		t.Fatalf("failed apply: %v", err)
	}
	got := e.only()
	if got.State != siem.ResponseRecommended || got.By != "" || got.Reason != "" || !got.Updated.Equal(x.Updated) {
		t.Fatalf("after a failed apply: %+v", got)
	}
	if notes, alerts, audits, events := e.take(); len(notes)+len(alerts)+len(audits)+len(events) != 0 {
		t.Fatalf("a failed apply was reported: %+v %+v %+v %+v", notes, alerts, audits, events)
	}
	e.blocks.err = nil
	if err := e.r.Apply(ctx, x.ID, "owner"); err != nil {
		t.Fatalf("applied again: %v", err)
	}
	if got := e.only(); got.State != siem.ResponseApplied || got.By != "owner" {
		t.Fatalf("applied again: %+v", got)
	}
	// The revoker failing.
	e.r.handle(revokeReq("erin"))
	y := e.list(siem.ResponseFilter{States: []string{siem.ResponseRecommended}})[0]
	e.rev.by["erin"] = revokeResult{"", 0, errors.New("database is locked")}
	if err := e.r.Apply(ctx, y.ID, "owner"); err == nil || errors.Is(err, siem.ErrInvalidInput) {
		t.Fatalf("failed sign-out: %v", err)
	}
	if got, _, _ := e.r.Response(ctx, y.ID); got.State != siem.ResponseRecommended || got.Target != "erin" {
		t.Fatalf("after a failed sign-out: %+v", got)
	}
	e.rev.by["erin"] = revokeResult{"erin", 1, nil}
	if err := e.r.Apply(ctx, y.ID, "owner"); err != nil {
		t.Fatal(err)
	}
	// A refusal is final.
	e.r.handle(blockReq("198.51.100.9", true))
	z := e.list(siem.ResponseFilter{States: []string{siem.ResponseRecommended}})[0]
	e.blocks.refuse["198.51.100.9/32"] = &blocklist.RefusedError{Code: blocklist.RefuseSelf, Detail: "your own address"}
	if err := e.r.Apply(ctx, z.ID, "owner"); !errors.Is(err, siem.ErrInvalidInput) {
		t.Fatalf("refused apply: %v", err)
	}
	if got, _, _ := e.r.Response(ctx, z.ID); got.State != siem.ResponseRefused || got.Reason != blocklist.RefuseSelf {
		t.Fatalf("refused %+v", got)
	}
}

// Intent: a recommended block longer than the longest manual block is applied for that long.
func TestApplyClampsToTheManualMaximum(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, siem.ResponseModeRecommend, func(o *Options) { o.ManualMaxDuration = 2 * time.Hour })
	long := blockReq("203.0.113.7", true)
	long.Duration = 7 * 24 * time.Hour
	e.r.handle(long)
	e.r.handle(blockReq("203.0.113.8", true)) // 1h
	rs := e.list(siem.ResponseFilter{})
	for _, x := range rs {
		if err := e.r.Apply(ctx, x.ID, "owner"); err != nil {
			t.Fatal(err)
		}
	}
	reqs := e.blocks.requests()
	if len(reqs) != 2 || reqs[0].Duration != time.Hour || reqs[1].Duration != 2*time.Hour {
		t.Fatalf("blocks %+v", reqs)
	}
	if got, _, _ := e.r.Response(ctx, rs[1].ID); got.State != siem.ResponseApplied || got.Duration != 2*time.Hour {
		t.Fatalf("applied %+v", got)
	}
	// Not known: asked for as recommended.
	e = newEnv(t, siem.ResponseModeRecommend)
	e.r.handle(long)
	if err := e.r.Apply(ctx, e.only().ID, "owner"); err != nil {
		t.Fatal(err)
	}
	if reqs := e.blocks.requests(); reqs[0].Duration != 7*24*time.Hour {
		t.Fatalf("blocks %+v", reqs)
	}
}

// A detection that keeps firing asks again every few minutes: the waiting recommendation takes the
// newest request without another event or timeline entry, and one the owner dismissed is not
// recommended again for dismissQuiet (then it is, as a new one).
func TestRecommendationAskedAgainIsQuiet(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, siem.ResponseModeRecommend)
	req := blockReq("203.0.113.7", true)
	e.r.handle(req)
	if notes, _, _, events := e.take(); len(notes) != 1 || len(events) != 1 {
		t.Fatalf("first request: %d timeline entries, %d events; want 1, 1", len(notes), len(events))
	}
	again := req
	again.DetectionID, again.Summary = 77, "newer"
	e.r.handle(again)
	e.r.handle(again)
	x := e.only()
	if notes, _, _, events := e.take(); len(notes) != 0 || len(events) != 0 || x.DetectionID != 77 || x.Summary != "newer" {
		t.Fatalf("asked again: %d timeline entries, %d events, row %+v; want none, and the newest request on the row", len(notes), len(events), x)
	}
	if err := e.r.Dismiss(ctx, x.ID, "owner"); err != nil {
		t.Fatal(err)
	}
	e.take()
	e.clk.advance(dismissQuiet - time.Minute)
	e.r.handle(again)
	if rs := e.list(siem.ResponseFilter{}); len(rs) != 1 || rs[0].State != siem.ResponseDismissed {
		t.Fatalf("asked again within %s of the dismissal: %+v; want only the dismissed row", dismissQuiet, rs)
	}
	if notes, _, _, events := e.take(); len(notes) != 0 || len(events) != 0 {
		t.Fatalf("a request after a dismissal made %d timeline entries, %d events", len(notes), len(events))
	}
	// Another incident's request for the address is its own recommendation.
	other := again
	other.IncidentID = 99
	e.r.handle(other)
	if rs := e.list(siem.ResponseFilter{States: []string{siem.ResponseRecommended}}); len(rs) != 1 || rs[0].IncidentID != 99 {
		t.Fatalf("another incident's request: %+v", rs)
	}
	e.clk.advance(2 * time.Minute)
	e.r.handle(again)
	if rs := e.list(siem.ResponseFilter{States: []string{siem.ResponseRecommended}}); len(rs) != 2 {
		t.Fatalf("after %s: %d open recommendations, want 2 (recommended again)", dismissQuiet, len(rs))
	}
}

// A recommendation whose block was placed but never recorded (the write failed, then Mooring
// restarted) is still "recommended": applying it finds its own block in force (the block names the
// response) and only records it; a block of the address placed for something else doesn't count.
func TestApplyFindsItsOwnBlockInForce(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t, siem.ResponseModeRecommend)
	e.r.handle(blockReq("203.0.113.7", true))
	x := e.only()
	p := netip.MustParsePrefix(x.Target)
	held := blocklist.Block{Prefix: p, Source: blocklist.SourceManual, ResponseID: x.ID, State: blocklist.StateActive,
		Created: e.clk.now().Add(-10 * time.Minute), Until: e.clk.now().Add(50 * time.Minute)}
	e.blocks.held = map[netip.Prefix]blocklist.Block{p: held}
	e.take()
	if err := e.r.Apply(ctx, x.ID, "owner"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	got := e.only()
	if len(e.blocks.reqs) != 0 || got.State != siem.ResponseApplied || got.By != "owner" || got.Duration != 50*time.Minute {
		t.Fatalf("its own block in force: %d block requests, row %+v; want none, applied by owner with 50m left", len(e.blocks.reqs), got)
	}

	// Another response's block of the address, or its own block that ran out: applied as usual.
	for name, other := range map[string]blocklist.Block{
		"another response's": {Prefix: netip.MustParsePrefix("203.0.113.8/32"), ResponseID: 9999, State: blocklist.StateActive, Until: e.clk.now().Add(time.Hour)},
		"its own, run out":   {Prefix: netip.MustParsePrefix("203.0.113.8/32"), State: blocklist.StateExpired, Until: e.clk.now().Add(-time.Minute)},
	} {
		e2 := newEnv(t, siem.ResponseModeRecommend)
		e2.r.handle(blockReq("203.0.113.8", true))
		y := e2.only()
		if name == "its own, run out" {
			other.ResponseID = y.ID
		}
		e2.blocks.held = map[netip.Prefix]blocklist.Block{other.Prefix: other}
		if err := e2.r.Apply(ctx, y.ID, "owner"); err != nil || len(e2.blocks.reqs) != 1 {
			t.Errorf("%s block: apply %v, %d block requests; want the block placed", name, err, len(e2.blocks.reqs))
		}
	}
}
