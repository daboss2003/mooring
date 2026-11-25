package respond

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/blocklist"
	"github.com/daboss2003/mooring/internal/siem"
)

// quiet fails the test when anything followed from a request: a timeline entry, an alert, an audit
// record or an event.
func (e *env) quiet(what string) {
	e.t.Helper()
	notes, alerts, audits, events := e.take()
	if len(notes)+len(alerts)+len(audits)+len(events) != 0 {
		e.t.Fatalf("%s: notes %+v alerts %+v audits %+v events %+v", what, notes, alerts, audits, events)
	}
}

func (e *env) blocksThisHour() int {
	e.t.Helper()
	st, err := e.r.Status(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	return st.BlocksThisHour
}

// A request to block an address that is still blocked, with two minutes or more to go, needs
// nothing: no record, no cap count, no audit record, no event, no timeline entry, and the block
// list isn't asked. Within the block's last two minutes, or once it ended, it is handled as before.
func TestBlockOfAnAddressStillBlockedIsSkipped(t *testing.T) {
	const prefix = "203.0.113.7/32"
	e := newEnv(t, siem.ResponseModeEnforce)
	e.blocks.keep = true
	req := blockReq("203.0.113.7", true)
	e.r.handle(req)
	if x := e.only(); x.State != siem.ResponseApplied || x.Target != prefix {
		t.Fatalf("first: %+v", x)
	}
	e.take()
	for _, after := range []time.Duration{10 * time.Minute, 58*time.Minute - 10*time.Minute} {
		e.clk.advance(after)
		e.r.handle(req)
		e.only()
		e.quiet("still blocked")
	}
	if n := len(e.blocks.requests()); n != 1 || e.r.Skipped() != 2 || e.blocksThisHour() != 1 {
		t.Fatalf("block list asked %d times, skipped %d, counted %d", n, e.r.Skipped(), e.blocksThisHour())
	}
	// A second into the block's last two minutes: handled (the block list lengthens it).
	e.clk.advance(time.Second)
	e.r.handle(req)
	rs := e.list(siem.ResponseFilter{})
	if len(rs) != 2 || rs[0].State != siem.ResponseApplied || len(e.blocks.requests()) != 2 || e.r.Skipped() != 2 {
		t.Fatalf("in the last two minutes: %+v", rs)
	}
	if notes, _, audits, events := e.take(); len(notes) != 1 || len(audits) != 1 || len(events) != 1 {
		t.Fatalf("in the last two minutes: notes %+v audits %+v events %+v", notes, audits, events)
	}

	// A block suspended (covered by a protected address for now) is still in force: skipped. One
	// that was removed, or whose time ran out, is not.
	p := netip.MustParsePrefix(prefix)
	for _, tc := range []struct {
		state   string
		left    time.Duration
		skipped bool
	}{
		{blocklist.StateSuspended, time.Hour, true},
		{blocklist.StateActive, blockAhead, true},
		{blocklist.StateActive, blockAhead - time.Second, false},
		{blocklist.StateRemoved, time.Hour, false},
		{blocklist.StateExpired, time.Hour, false},
		{blocklist.StateExpired, -time.Minute, false},
	} {
		e := newEnv(t, siem.ResponseModeEnforce)
		e.blocks.held = map[netip.Prefix]blocklist.Block{p: {Prefix: p, State: tc.state, Until: e.clk.now().Add(tc.left)}}
		e.r.handle(req)
		if rs := e.list(siem.ResponseFilter{}); (len(rs) == 0) != tc.skipped || (e.r.Skipped() == 1) != tc.skipped ||
			(len(e.blocks.requests()) == 0) != tc.skipped {
			t.Fatalf("%s with %s left: responses %+v, skipped %d", tc.state, tc.left, rs, e.r.Skipped())
		}
	}

	// An IPv6 address is looked up as its /64.
	e = newEnv(t, siem.ResponseModeEnforce)
	p6 := netip.MustParsePrefix("2001:db8:1:2::/64")
	e.blocks.held = map[netip.Prefix]blocklist.Block{p6: {Prefix: p6, State: blocklist.StateActive, Until: e.clk.now().Add(time.Hour)}}
	e.r.handle(blockReq("2001:db8:1:2::9", true))
	e.r.handle(blockReq("2001:db8:1:3::9", true))
	if x := e.only(); x.Target != "2001:db8:1:3::/64" || e.r.Skipped() != 1 {
		t.Fatalf("IPv6: %+v", x)
	}

	// Only a block looks at the block list: a sign-out of an account named like a blocked address
	// is handled.
	e = newEnv(t, siem.ResponseModeEnforce)
	e.blocks.held = map[netip.Prefix]blocklist.Block{p: {Prefix: p, State: blocklist.StateActive, Until: e.clk.now().Add(time.Hour)}}
	e.rev.by["203.0.113.7"] = revokeResult{"203.0.113.7", 1, nil}
	e.r.handle(revokeReq("203.0.113.7"))
	if x := e.only(); x.Action != siem.ResponseRevoke || x.State != siem.ResponseApplied || e.r.Skipped() != 0 {
		t.Fatalf("a sign-out: %+v", x)
	}

	// The block list can't say: handled as before (it decides).
	e = newEnv(t, siem.ResponseModeEnforce)
	e.blocks.getErr = errors.New("database is locked")
	e.r.handle(req)
	if x := e.only(); x.State != siem.ResponseApplied || e.r.Skipped() != 0 {
		t.Fatalf("lookup failed: %+v", x)
	}
}

// The same for a request that would only be recorded as a recommendation (recommend mode, or a
// recommend-only request in enforce mode): none while the address is still blocked.
func TestRecommendationForAnAddressStillBlockedIsSkipped(t *testing.T) {
	p := netip.MustParsePrefix("203.0.113.7/32")
	for _, tc := range []struct {
		mode string
		auto bool
	}{{siem.ResponseModeRecommend, true}, {siem.ResponseModeEnforce, false}} {
		e := newEnv(t, tc.mode)
		e.blocks.held = map[netip.Prefix]blocklist.Block{p: {Prefix: p, State: blocklist.StateActive, Source: blocklist.SourceManual,
			Until: e.clk.now().Add(time.Hour)}}
		e.r.handle(blockReq("203.0.113.7", tc.auto))
		if rs := e.list(siem.ResponseFilter{}); len(rs) != 0 || e.r.Skipped() != 1 {
			t.Fatalf("%s: %+v", tc.mode, rs)
		}
		e.quiet(tc.mode)
		e.r.handle(blockReq("198.51.100.9", tc.auto))
		if x := e.only(); x.State != siem.ResponseRecommended || x.Target != "198.51.100.9/32" {
			t.Fatalf("%s, not blocked: %+v", tc.mode, x)
		}
		// Off: nothing is looked up or counted.
		if err := e.r.SetPause(context.Background(), siem.ResponseModeOff, "owner"); err != nil {
			t.Fatal(err)
		}
		e.r.handle(blockReq("203.0.113.7", tc.auto))
		if e.r.Skipped() != 1 {
			t.Fatalf("%s, paused off: skipped %d", tc.mode, e.r.Skipped())
		}
	}
}

// A refusal for the same reason as the newest response of the same action and target within the
// last hour is not recorded again: a protected address that keeps firing records one refusal an
// hour. The block list is still asked each time (the address may no longer be protected).
func TestRepeatedRefusalRecordedOnceAnHour(t *testing.T) {
	const prefix = "203.0.113.7/32"
	e := newEnv(t, siem.ResponseModeEnforce)
	e.blocks.refuse[prefix] = &blocklist.RefusedError{Code: blocklist.RefuseAllowlist, Detail: "inside ip_allowlist"}
	req := blockReq("203.0.113.7", true)
	// Every 5 minutes for 2 hours: recorded at 0, 1h and 2h.
	for i := range 25 {
		e.r.handle(req)
		rs := e.list(siem.ResponseFilter{})
		if want := 1 + i/12; len(rs) != want {
			t.Fatalf("after %d minutes: %d refusals, want %d: %+v", i*5, len(rs), want, rs)
		}
		e.clk.advance(5 * time.Minute)
	}
	rs := e.list(siem.ResponseFilter{})
	for i, x := range rs {
		if x.State != siem.ResponseRefused || x.Reason != blocklist.RefuseAllowlist || x.Target != prefix ||
			!x.Created.Equal(t0.Add(time.Duration(len(rs)-1-i)*time.Hour)) {
			t.Fatalf("refusal %d: %+v", i, x)
		}
	}
	notes, alerts, audits, events := e.take()
	if len(notes) != 3 || len(alerts) != 0 || len(audits) != 3 || len(events) != 3 {
		t.Fatalf("notes %d alerts %d audits %d events %d", len(notes), len(alerts), len(audits), len(events))
	}
	if n := len(e.blocks.requests()); n != 25 || e.r.Skipped() != 22 {
		t.Fatalf("block list asked %d times, skipped %d", n, e.r.Skipped())
	}
	if n := e.count(`SELECT COUNT(*) FROM security_responses`); n != 3 {
		t.Fatalf("%d rows (a skipped refusal's row was left behind)", n)
	}

	// Another reason, another address and another action are each recorded; so is the same refusal
	// after a response that was no refusal, and it is remembered across a restart.
	e = newEnv(t, siem.ResponseModeEnforce)
	e.blocks.refuse[prefix] = &blocklist.RefusedError{Code: blocklist.RefuseAllowlist}
	e.blocks.refuse["198.51.100.9/32"] = &blocklist.RefusedError{Code: blocklist.RefuseAllowlist}
	step := func(what string, r siem.ResponseRequest, want int) {
		t.Helper()
		e.clk.advance(time.Minute)
		e.r.handle(r)
		if rs := e.list(siem.ResponseFilter{}); len(rs) != want {
			t.Fatalf("%s: %d responses, want %d: %+v", what, len(rs), want, rs)
		}
	}
	step("first", req, 1)
	step("the same again", req, 1)
	e.reopen()
	step("after a restart", req, 1)
	step("another address", blockReq("198.51.100.9", true), 2)
	step("the first address again", req, 2)
	e.blocks.refuse[prefix] = &blocklist.RefusedError{Code: blocklist.RefuseSession}
	step("another reason", req, 3)
	step("that reason again", req, 3)
	e.blocks.refuse[prefix] = &blocklist.RefusedError{Code: blocklist.RefuseAllowlist}
	step("the first reason after another", req, 4)
	delete(e.blocks.refuse, prefix)
	step("applied", req, 5)
	e.blocks.refuse[prefix] = &blocklist.RefusedError{Code: blocklist.RefuseAllowlist}
	step("the first reason after a block", req, 6)
	// A row in the future (the clock stepped back since) hides nothing.
	e.clk.advance(-30 * time.Minute)
	step("after the clock stepped back", req, 7)
}

// The refusals the responder decides by itself are held to the same: an address that is no
// address, the hourly cap, an account signed out within the hour, an unknown account, a target
// that is no account name, and no revoker.
func TestRepeatedRefusalsOfEveryKind(t *testing.T) {
	twice := func(e *env, what string, req siem.ResponseRequest, reason string) {
		t.Helper()
		before := len(e.list(siem.ResponseFilter{}))
		skipped := e.r.Skipped()
		e.r.handle(req)
		rs := e.list(siem.ResponseFilter{})
		if len(rs) != before+1 || rs[0].State != siem.ResponseRefused || rs[0].Reason != reason {
			t.Fatalf("%s: %+v", what, rs)
		}
		e.take()
		e.clk.advance(10 * time.Minute)
		e.r.handle(req)
		if rs := e.list(siem.ResponseFilter{}); len(rs) != before+1 || e.r.Skipped() != skipped+1 {
			t.Fatalf("%s, again: %+v", what, rs)
		}
		e.quiet(what)
		if n := e.count(`SELECT COUNT(*) FROM security_responses`); n != before+1 {
			t.Fatalf("%s: %d rows", what, n)
		}
		e.clk.advance(50 * time.Minute)
		e.r.handle(req)
		if rs := e.list(siem.ResponseFilter{}); len(rs) != before+2 || rs[0].Reason != reason {
			t.Fatalf("%s, an hour later: %+v", what, rs)
		}
	}
	e := newEnv(t, siem.ResponseModeEnforce)
	twice(e, "no address", blockReq("not-an-address", true), blocklist.RefuseInvalid)
	twice(e, "unknown account", revokeReq("mallory"), reasonUnknown)
	if len(e.rev.calls) != 3 {
		t.Fatalf("the revoker is asked each time: %v", e.rev.calls)
	}
	twice(e, "no account name", revokeReq("a\nb"), reasonInvalidTarget)
	e.r.SetRevoker(nil)
	twice(e, "no revoker", revokeReq("alice"), reasonNoRevoker)

	e = newEnv(t, siem.ResponseModeRecommend)
	twice(e, "no address, recommend mode", blockReq("not-an-address", true), blocklist.RefuseInvalid)

	e = newEnv(t, siem.ResponseModeEnforce, func(o *Options) { o.Blocks = nil })
	twice(e, "no edge", blockReq("203.0.113.7", true), blocklist.RefuseNoEdge)

	// The hourly cap: per address.
	e = newEnv(t, siem.ResponseModeEnforce, func(o *Options) { o.MaxBlocksPerHour = 1 })
	e.r.handle(blockReq("192.0.2.1", true))
	e.r.handle(blockReq("203.0.113.7", true))
	e.r.handle(blockReq("203.0.113.7", true))
	e.r.handle(blockReq("198.51.100.9", true))
	rs := e.list(siem.ResponseFilter{})
	if len(rs) != 3 || rs[0].Reason != reasonCap || rs[0].Target != "198.51.100.9/32" || rs[1].Reason != reasonCap ||
		rs[1].Target != "203.0.113.7/32" || rs[2].State != siem.ResponseApplied || e.r.Skipped() != 1 {
		t.Fatalf("cap: %+v", rs)
	}
	if _, alerts, _, _ := e.take(); len(alerts) != 1 {
		t.Fatalf("cap alerts: %+v", alerts)
	}

	// The cooldown: alice is signed out, and asked for again every 10 minutes.
	e = newEnv(t, siem.ResponseModeEnforce)
	for i := range 7 {
		e.r.handle(revokeReq("alice"))
		rs := e.list(siem.ResponseFilter{})
		// Signed out at 0, refused (cooldown) at 10m, nothing until the hour is over: signed out again.
		want := []string{siem.ResponseApplied, siem.ResponseRefused, siem.ResponseRefused, siem.ResponseRefused,
			siem.ResponseRefused, siem.ResponseRefused, siem.ResponseApplied}[i]
		n := []int{1, 2, 2, 2, 2, 2, 3}[i]
		if len(rs) != n || rs[0].State != want {
			t.Fatalf("after %d minutes: %+v", i*10, rs)
		}
		e.clk.advance(10 * time.Minute)
	}
	if len(e.rev.calls) != 2 || e.r.Skipped() != 4 {
		t.Fatalf("revoker calls %v, skipped %d", e.rev.calls, e.r.Skipped())
	}
}

// failUpdates makes every UPDATE of security_responses fail until restore is called.
func (e *env) failUpdates() (restore func()) {
	e.t.Helper()
	ctx := context.Background()
	if _, err := e.db.ExecContext(ctx, `CREATE TABLE fail_updates(x)`); err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.db.ExecContext(ctx, `INSERT INTO fail_updates VALUES (1)`); err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.db.ExecContext(ctx, `CREATE TRIGGER fail_updates_t BEFORE UPDATE ON security_responses
		WHEN EXISTS(SELECT 1 FROM fail_updates) BEGIN SELECT RAISE(ABORT, 'disk full'); END`); err != nil {
		e.t.Fatal(err)
	}
	return func() {
		e.t.Helper()
		if _, err := e.db.ExecContext(ctx, `DELETE FROM fail_updates`); err != nil {
			e.t.Fatal(err)
		}
	}
}

func (e *env) count(q string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.db.QueryRowContext(context.Background(), q, args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

// Apply: the action was done and recording it failed. The error says the action WAS done, its
// event, timeline entry and alert follow all the same, the action is not done a second time while
// the record is owed, and the record is written once the database takes it.
func TestApplyDoneButNotRecorded(t *testing.T) {
	ctx := context.Background()
	for _, action := range []string{siem.ResponseRevoke, siem.ResponseBlock} {
		e := newEnv(t, siem.ResponseModeRecommend)
		done := func() int {
			if action == siem.ResponseRevoke {
				return len(e.rev.calls)
			}
			return len(e.blocks.requests())
		}
		if action == siem.ResponseRevoke {
			e.r.handle(revokeReq("alice"))
		} else {
			e.r.handle(blockReq("203.0.113.7", true))
		}
		x := e.only()
		e.take()
		restore := e.failUpdates()
		err := e.r.Apply(ctx, x.ID, "owner")
		if err == nil || errors.Is(err, siem.ErrInvalidInput) || !strings.Contains(err.Error(), "WAS") ||
			!strings.Contains(err.Error(), "disk full") {
			t.Fatalf("%s: apply: %v", action, err)
		}
		notes, alerts, _, events := e.take()
		wantAlerts := 0
		if action == siem.ResponseRevoke {
			wantAlerts = 1 // an applied sign-out alerts
		}
		if done() != 1 || len(alerts) != wantAlerts || len(events) != 1 || events[0].F["state"] != siem.ResponseApplied ||
			events[0].F["by"] != "owner" || len(notes) != 1 || notes[0].id != x.IncidentID || notes[0].ev.Actor != "owner" {
			t.Fatalf("%s: done %d, alerts %+v, events %+v, notes %+v", action, done(), alerts, events, notes)
		}
		if got := e.only(); got.State != siem.ResponseRecommended {
			t.Fatalf("%s: row %+v", action, got)
		}
		// Applied or dismissed again while the record is owed: nothing is done a second time.
		err = e.r.Apply(ctx, x.ID, "owner")
		if err == nil || errors.Is(err, siem.ErrInvalidInput) || !strings.Contains(err.Error(), "already") || done() != 1 {
			t.Fatalf("%s: second apply: %v (done %d)", action, err, done())
		}
		if err := e.r.Dismiss(ctx, x.ID, "owner"); err == nil || errors.Is(err, siem.ErrInvalidInput) {
			t.Fatalf("%s: dismiss while owed: %v", action, err)
		}
		e.quiet(action + ", while the record is owed")
		// The database takes writes again: the record is written at the next try, as applied.
		restore()
		if err := e.r.Apply(ctx, x.ID, "owner"); !errors.Is(err, siem.ErrInvalidInput) || !strings.Contains(err.Error(), "it is applied") {
			t.Fatalf("%s: apply once recorded: %v", action, err)
		}
		got := e.only()
		if got.State != siem.ResponseApplied || got.By != "owner" || done() != 1 {
			t.Fatalf("%s: recorded %+v (done %d)", action, got, done())
		}
		e.quiet(action + ", once recorded")
	}

	// Maintenance writes an owed record too.
	e := newEnv(t, siem.ResponseModeRecommend)
	e.r.handle(revokeReq("alice"))
	x := e.only()
	restore := e.failUpdates()
	if err := e.r.Apply(ctx, x.ID, "owner"); err == nil {
		t.Fatal("no error")
	}
	e.r.maintain(ctx)
	if got := e.only(); got.State != siem.ResponseRecommended {
		t.Fatalf("while updates fail: %+v", got)
	}
	restore()
	e.r.maintain(ctx)
	if got := e.only(); got.State != siem.ResponseApplied || got.By != "owner" || got.Target != "alice" {
		t.Fatalf("after maintenance: %+v", got)
	}
	e.r.maintain(ctx)
	if len(e.r.unsettled) != 0 {
		t.Fatalf("still owed: %+v", e.r.unsettled)
	}

	// A refusal that can't be recorded did nothing: the recommendation stays open and can be applied
	// again.
	e = newEnv(t, siem.ResponseModeRecommend)
	e.r.handle(revokeReq("mallory"))
	x = e.only()
	e.take()
	restore = e.failUpdates()
	if err := e.r.Apply(ctx, x.ID, "owner"); err == nil || strings.Contains(err.Error(), "WAS") {
		t.Fatalf("refusal not recorded: %v", err)
	}
	e.quiet("refusal not recorded")
	restore()
	if err := e.r.Apply(ctx, x.ID, "owner"); !errors.Is(err, siem.ErrInvalidInput) {
		t.Fatalf("refusal: %v", err)
	}
	if got := e.only(); got.State != siem.ResponseRefused || len(e.rev.calls) != 2 {
		t.Fatalf("refusal recorded: %+v", got)
	}
}
