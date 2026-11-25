package blocklist

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

// A restart must not publish a block that was suspended when last saved: at Open the dashboard isn't
// up, so the guard knows no API token CIDRs and no sessions. The block stays suspended (with its
// reason) until Run's first step re-checks it against the full guard.
func TestOpenKeepsSuspendedBlocksUnpublished(t *testing.T) {
	var webUp atomic.Bool
	h := newHarness(t, func(o *Options) {
		o.Guard.TokenCIDRs = func() []netip.Prefix {
			if webUp.Load() {
				return pfx("198.51.100.0/28")
			}
			return nil
		}
		o.Guard.Sessions = func(context.Context) []netip.Addr {
			if webUp.Load() {
				return []netip.Addr{netip.MustParseAddr("198.51.100.150")}
			}
			return nil
		}
	})
	ctx := context.Background()
	h.mustBlock(h.manual("198.51.100.7", time.Hour, ""))
	h.mustBlock(h.manual("198.51.100.150", time.Hour, ""))
	h.mustBlock(h.manual("198.51.100.210", time.Hour, ""))
	webUp.Store(true)
	h.clk.add(2 * time.Minute)
	h.b.step(ctx)
	if got := h.snapshot(); !reflect.DeepEqual(got, []string{"198.51.100.210/32"}) {
		t.Fatalf("running, dashboard up: snapshot = %v", got)
	}

	webUp.Store(false) // a restart: the dashboard doesn't exist yet
	h.reopen()
	if got := h.snapshot(); !reflect.DeepEqual(got, []string{"198.51.100.210/32"}) {
		t.Errorf("after Open, before Run: snapshot = %v, want only the block that wasn't suspended", got)
	}
	if h.b.Blocked(netip.MustParseAddr("198.51.100.7")) || h.b.Blocked(netip.MustParseAddr("198.51.100.150")) {
		t.Error("a block suspended before the restart is served after it")
	}
	for p, why := range map[string]string{"198.51.100.7/32": RefuseTokenCIDR, "198.51.100.150/32": RefuseSession} {
		if blk, _, _ := h.b.Get(ctx, netip.MustParsePrefix(p)); blk.State != StateSuspended || blk.SuspendedWhy != why {
			t.Errorf("%s after Open: state %q why %q, want suspended (%s)", p, blk.State, blk.SuspendedWhy, why)
		}
	}
	// A change before Run (the responder is already running) must not resume them either.
	h.mustBlock(h.manual("198.51.100.211", time.Hour, ""))
	h.release()
	if h.b.Blocked(netip.MustParseAddr("198.51.100.7")) || h.b.Blocked(netip.MustParseAddr("198.51.100.150")) {
		t.Error("a change before Run resumed a block suspended before the restart")
	}

	// Run's first step has the dashboard: still covered, still suspended.
	webUp.Store(true)
	h.b.step(ctx)
	if got := h.snapshot(); !reflect.DeepEqual(got, []string{"198.51.100.210/32", "198.51.100.211/32"}) {
		t.Errorf("after the first step: snapshot = %v", got)
	}
	// Once the full guard no longer covers them they resume, and that is saved too.
	webUp.Store(false)
	h.clk.add(time.Minute)
	h.b.step(ctx)
	if got := h.snapshot(); len(got) != 4 {
		t.Errorf("no longer covered: snapshot = %v, want all four", got)
	}
	h.reopen()
	if got := h.snapshot(); len(got) != 4 {
		t.Errorf("restart after the resume: snapshot = %v, want all four", got)
	}
}

// A block suspended because a config.yaml entry covered it is published at Open once the entry is gone
// only after the first step; one newly covered by the static guard is suspended at Open.
func TestOpenSuspendsNewlyCovered(t *testing.T) {
	h := newHarness(t)
	h.mustBlock(h.auto("192.0.2.1", time.Hour))
	h.release()
	h.g.setAllow("203.0.113.0/24", "192.0.2.0/30")
	h.reopen()
	if got := h.snapshot(); len(got) != 0 {
		t.Errorf("snapshot = %v, want none (now allowlisted)", got)
	}
	var why string
	if err := h.db.QueryRow(`SELECT suspended_why FROM edge_blocks WHERE prefix = '192.0.2.1/32'`).Scan(&why); err != nil || why != RefuseAllowlist {
		t.Errorf("stored suspension = %q, %v", why, err)
	}
}

// An extension doesn't change the block's ladder step: 1h extended at +50m, then a repeat, is 4h.
func TestExtensionKeepsLadderStep(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.mustBlock(h.auto("198.51.100.7", time.Hour))
	h.clk.add(50 * time.Minute)
	h.mustBlock(h.auto("198.51.100.7", time.Hour))
	h.clk.add(2 * time.Hour)
	h.b.step(ctx)
	blk := h.mustBlock(h.auto("198.51.100.7", time.Hour))
	if d := blk.Until.Sub(blk.Created); d != 4*time.Hour || blk.Hits != 2 {
		t.Errorf("repeat after an extended first block: %s, hits %d; want 4h, hits 2", d, blk.Hits)
	}
	// The step survives a restart.
	h.clk.add(5 * time.Hour)
	h.reopen()
	h.b.step(ctx)
	blk = h.mustBlock(h.auto("198.51.100.7", time.Hour))
	if d := blk.Until.Sub(blk.Created); d != 16*time.Hour || blk.Hits != 3 {
		t.Errorf("third block: %s, hits %d; want 16h, hits 3", d, blk.Hits)
	}
}

// A manual block is not a repeat: the automatic block after it starts at the first step, and an
// automatic block's step is kept across a manual block of the same prefix.
func TestManualBlockIsNotARepeat(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	m := h.mustBlock(h.manual("198.51.100.7", 7*24*time.Hour, ""))
	if m.Hits != 0 {
		t.Errorf("a manual block's hits = %d, want 0 (automatic blocks only)", m.Hits)
	}
	h.clk.add(8 * 24 * time.Hour)
	h.b.step(ctx)
	blk := h.mustBlock(h.auto("198.51.100.7", time.Hour))
	if d := blk.Until.Sub(blk.Created); d != time.Hour || blk.Hits != 1 {
		t.Errorf("automatic after a manual block: %s, hits %d; want 1h, hits 1", d, blk.Hits)
	}
	h.clk.add(2 * time.Hour)
	h.b.step(ctx)
	if m = h.mustBlock(h.manual("198.51.100.7", 2*time.Hour, "")); m.Hits != 1 {
		t.Errorf("manual after one automatic block: hits %d, want 1", m.Hits)
	}
	h.clk.add(3 * time.Hour)
	h.b.step(ctx)
	blk = h.mustBlock(h.auto("198.51.100.7", time.Hour))
	if d := blk.Until.Sub(blk.Created); d != 4*time.Hour || blk.Hits != 2 {
		t.Errorf("automatic repeat across a manual block: %s, hits %d; want 4h, hits 2", d, blk.Hits)
	}
}

// A false-positive lift and an owner's unblock reset the prefix's repeat history: after the
// exemption its next automatic block is the first step again. Switching automated response off
// (LiftAutomatic) doesn't.
func TestUnblockResetsRepeatHistory(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	first := func(what string, blk Block) {
		t.Helper()
		if d := blk.Until.Sub(blk.Created); d != time.Hour || blk.Hits != 1 {
			t.Errorf("%s: %s, hits %d; want 1h, hits 1", what, d, blk.Hits)
		}
	}
	auto := func(prefix string, incident int64) Block {
		t.Helper()
		return h.mustBlock(h.b.Block(ctx, Request{Prefix: prefix, Source: SourceAuto, Duration: time.Hour, IncidentID: incident}))
	}
	auto("198.51.100.7", 5)
	auto("198.51.100.8", 5)
	h.clk.add(61 * time.Minute)
	h.b.step(ctx) // both ran out
	auto("198.51.100.7", 5)
	if n, err := h.b.UnblockIncident(ctx, 5, "owner", 24*time.Hour); n != 1 || err != nil {
		t.Fatalf("UnblockIncident = %d, %v", n, err)
	}
	h.clk.add(25 * time.Hour)
	first("after a false positive (block in force)", auto("198.51.100.7", 6))
	first("after a false positive (block ran out)", auto("198.51.100.8", 6))

	auto("198.51.100.9", 0)
	if err := h.b.Unblock(ctx, netip.MustParsePrefix("198.51.100.9/32"), "owner"); err != nil {
		t.Fatal(err)
	}
	h.clk.add(25 * time.Hour)
	first("after an owner's unblock", auto("198.51.100.9", 0))

	auto("198.51.100.10", 0)
	if n, err := h.b.LiftAutomatic(ctx, "siem", "automated response is off"); err != nil || n == 0 {
		t.Fatalf("LiftAutomatic = %d, %v", n, err)
	}
	if blk := auto("198.51.100.10", 0); blk.Until.Sub(blk.Created) != 4*time.Hour || blk.Hits != 2 {
		t.Errorf("after LiftAutomatic: %s, hits %d; want 4h, hits 2 (no reset)", blk.Until.Sub(blk.Created), blk.Hits)
	}
}

// The cap counts blocks still in force by time, and never the requested prefix itself: a block that
// ran out but isn't swept yet doesn't fill the list.
func TestCapIgnoresExpiredUnswept(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.MaxAuto = 1 })
	h.mustBlock(h.auto("198.51.100.7", time.Hour))
	h.clk.add(2 * time.Hour) // no sweep yet
	if _, err := h.auto("198.51.100.8", time.Hour); err != nil {
		t.Errorf("another prefix while the only block has run out: %v", err)
	}
	h2 := newHarness(t, func(o *Options) { o.MaxAuto = 1 })
	h2.mustBlock(h2.auto("198.51.100.7", time.Hour))
	h2.clk.add(2 * time.Hour)
	if _, err := h2.auto("198.51.100.7", time.Hour); err != nil {
		t.Errorf("the prefix that ran out, blocked again: %v", err)
	}
	if st := h2.b.Status(); st.ActiveAuto != 1 {
		t.Errorf("status = %+v", st)
	}
	_, err := h2.auto("198.51.100.9", time.Hour)
	refused(t, err, RefuseFull)
}

// The clock jumps forward (the sweep drops the block), then back: the block is in force again by
// time, so memory is read from the database again — the page, the edge and Unblock agree.
func TestClockBackReloads(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	p := netip.MustParsePrefix("198.51.100.7/32")
	h.mustBlock(h.auto("198.51.100.7", time.Hour))
	h.b.step(ctx)
	h.clk.add(48 * time.Hour)
	h.b.step(ctx)
	if len(h.b.Snapshot()) != 0 {
		t.Fatal("not swept")
	}
	h.clk.add(-48*time.Hour + 2*time.Minute)
	h.b.step(ctx)
	bl, err := h.b.List(ctx, Filter{States: []string{StateActive}})
	if err != nil || len(bl) != 1 {
		t.Fatalf("List = %v, %v", bl, err)
	}
	if got := h.snapshot(); !reflect.DeepEqual(got, []string{"198.51.100.7/32"}) {
		t.Errorf("snapshot = %v, want the block the page shows as active", got)
	}
	if st := h.b.Status(); st.ActiveAuto != 1 {
		t.Errorf("status = %+v", st)
	}
	if err := h.b.Unblock(ctx, p, "owner"); err != nil {
		t.Errorf("Unblock = %v", err)
	}

	// Without a sweep in between: a request right after the step back extends the block (not a
	// repeat), and Unblock finds it.
	h2 := newHarness(t)
	h2.mustBlock(h2.auto("198.51.100.7", time.Hour))
	h2.b.step(ctx)
	h2.clk.add(48 * time.Hour)
	h2.b.step(ctx)
	h2.clk.add(-48*time.Hour + 2*time.Minute)
	blk := h2.mustBlock(h2.auto("198.51.100.7", time.Hour))
	if blk.Hits != 1 || !blk.Created.Equal(t0) {
		t.Errorf("request after the step back: %+v, want the same block extended", blk)
	}
	h3 := newHarness(t)
	h3.mustBlock(h3.auto("198.51.100.7", time.Hour))
	h3.b.step(ctx)
	h3.clk.add(48 * time.Hour)
	h3.b.step(ctx)
	h3.clk.add(-48*time.Hour + 2*time.Minute)
	if err := h3.b.Unblock(ctx, p, "owner"); err != nil {
		t.Errorf("Unblock right after the step back = %v", err)
	}
}

func failingApply(fail *atomic.Bool) func(context.Context) error {
	return func(context.Context) error {
		if fail.Load() {
			return errors.New("edge: admin /load unreachable")
		}
		return nil
	}
}

// fireApplyAlert fails the apply until the alert fires.
func fireApplyAlert(h *harness, fail *atomic.Bool) {
	h.t.Helper()
	fail.Store(true)
	h.b.SetApply(failingApply(fail))
	h.mustBlock(h.auto("198.51.100.7", time.Hour))
	for i := 0; i < 4; i++ {
		h.clk.add(61 * time.Second)
		h.b.step(context.Background())
	}
	if n := h.alerts.count(alertKeyApply, "firing"); n != 1 {
		h.t.Fatalf("apply alerts firing = %d, want 1", n)
	}
}

// The apply alert raised before a restart is resolved by the first apply that works after it, and
// isn't raised a second time while it is open.
func TestApplyAlertResolvedAfterRestart(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	var fail atomic.Bool
	fireApplyAlert(h, &fail)
	h.reopen() // the apply works again
	h.clk.add(61 * time.Second)
	h.b.step(ctx)
	if n := h.alerts.count(alertKeyApply, "resolved"); n != 1 || !h.b.Status().Applied {
		t.Errorf("after the restart and a good apply: resolved = %d, applied %v; want 1, true", n, h.b.Status().Applied)
	}
	// Still failing after a restart: the open alert isn't raised again.
	h2 := newHarness(t)
	fireApplyAlert(h2, &fail)
	h2.reopen()
	h2.b.SetApply(failingApply(&fail))
	for i := 0; i < 4; i++ {
		h2.clk.add(61 * time.Second)
		h2.b.step(ctx)
	}
	if n := h2.alerts.count(alertKeyApply, "firing"); n != 1 {
		t.Errorf("firing after a restart with the alert open = %d, want 1", n)
	}
	// Nothing open: a restart sends no "resolved".
	h3 := newHarness(t)
	h3.mustBlock(h3.auto("198.51.100.7", time.Hour))
	h3.b.step(ctx)
	h3.reopen()
	h3.b.step(ctx)
	if n := len(h3.alerts.list()); n != 0 {
		t.Errorf("alerts with nothing open = %v", h3.alerts.list())
	}
}

// A "resolved" that couldn't be queued is retried on the next step, without a list change.
func TestApplyAlertResolveRetried(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	var fail atomic.Bool
	fireApplyAlert(h, &fail)
	fail.Store(false)
	h.alerts.setErr(errors.New("database is locked"))
	h.clk.add(61 * time.Second)
	h.b.step(ctx) // applied; the resolve isn't queued
	if !h.b.Status().Applied {
		t.Fatal("not applied")
	}
	h.alerts.setErr(nil)
	h.clk.add(61 * time.Second)
	h.b.step(ctx)
	if n := h.alerts.count(alertKeyApply, "resolved"); n != 1 {
		t.Errorf("resolved = %d, want 1 (retried)", n)
	}
	h.clk.add(61 * time.Second)
	h.b.step(ctx)
	if n := h.alerts.count(alertKeyApply, "resolved"); n != 1 {
		t.Errorf("resolved = %d, want 1 (sent once)", n)
	}
}

// The full-list alert is resolved once the list is below its cap again (also after a restart).
func TestFullAlertResolved(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.MaxAuto = 1 })
	ctx := context.Background()
	h.mustBlock(h.auto("198.51.100.7", time.Hour))
	_, err := h.auto("198.51.100.8", time.Hour)
	refused(t, err, RefuseFull)
	h.clk.add(time.Minute)
	h.b.step(ctx)
	if n := h.alerts.count(alertKeyFull, "resolved"); n != 0 {
		t.Fatalf("resolved while full = %d", n)
	}
	h.reopen()
	h.clk.add(time.Hour)
	h.b.step(ctx)
	if n := h.alerts.count(alertKeyFull, "resolved"); n != 1 {
		t.Errorf("resolved once below the cap = %d, want 1", n)
	}
	h.clk.add(time.Minute)
	h.b.step(ctx)
	if n := h.alerts.count(alertKeyFull, "resolved"); n != 1 {
		t.Errorf("resolved = %d, want 1 (sent once)", n)
	}
}

// Every security_blocking alert names the target "blocklist".
func TestAlertTargets(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.MaxAuto = 1 })
	ctx := context.Background()
	var fail atomic.Bool
	fireApplyAlert(h, &fail)
	fail.Store(false)
	h.clk.add(61 * time.Second)
	h.b.step(ctx)
	_, err := h.auto("198.51.100.8", time.Hour)
	refused(t, err, RefuseFull)
	_, err = h.auto("104.16.0.1", time.Hour)
	refused(t, err, RefuseCDN)
	h.clk.add(2 * time.Hour)
	h.b.step(ctx)
	keys := map[string]bool{}
	for _, o := range h.alerts.list() {
		keys[o.DedupeKey+" "+o.Transition] = true
		if o.Target != "blocklist" || o.Kind != alertKind {
			t.Errorf("alert %s (%s): target %q kind %q", o.DedupeKey, o.Transition, o.Target, o.Kind)
		}
	}
	for _, k := range []string{alertKeyApply + " firing", alertKeyApply + " resolved", alertKeyFull + " firing", alertKeyFull + " resolved", alertKeyCDN + " firing"} {
		if !keys[k] {
			t.Errorf("no %s alert in %v", k, keys)
		}
	}
}

// An alerter that can't say which alerts are open: the first apply that works after Open resolves
// the apply alert once, whatever was open.
func TestApplyAlertResolvedWithoutOpenList(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.Alerter = plainAlerter{o.Alerter.(*alerts)} })
	ctx := context.Background()
	h.mustBlock(h.auto("198.51.100.7", time.Hour))
	h.b.step(ctx)
	h.clk.add(61 * time.Second)
	h.b.step(ctx)
	if n := h.alerts.count(alertKeyApply, "resolved"); n != 1 {
		t.Errorf("resolved = %d, want 1", n)
	}
	// It still fires after three failures.
	var fail atomic.Bool
	h.reopen()
	fail.Store(true)
	h.b.SetApply(failingApply(&fail))
	for i := 0; i < 4; i++ {
		h.clk.add(61 * time.Second)
		h.b.step(ctx)
	}
	if n := h.alerts.count(alertKeyApply, "firing"); n != 1 {
		t.Errorf("firing = %d, want 1", n)
	}
}

// An allowlist or token entry the guard can't put in canonical form protects its whole family (an
// IPv4-mapped range wider than /96 covers every IPv4 address; an invalid entry, everything).
func TestGuardFailsClosedOnOddEntries(t *testing.T) {
	h := newHarness(t)
	h.g.mu.Lock()
	h.g.allow = []netip.Prefix{netip.MustParsePrefix("::ffff:10.0.0.0/90")}
	h.g.mu.Unlock()
	_, err := h.auto("198.51.100.7", time.Hour)
	refused(t, err, RefuseAllowlist)
	h.mustBlock(h.auto("2001:db8:1:2::/64", time.Hour))

	h.g.mu.Lock()
	h.g.allow = nil
	h.g.tokens = []netip.Prefix{{}}
	h.g.mu.Unlock()
	_, err = h.auto("198.51.100.7", time.Hour)
	refused(t, err, RefuseTokenCIDR)
	_, err = h.auto("2001:db8:9:9::/64", time.Hour)
	refused(t, err, RefuseTokenCIDR)
	// The block placed before the entry appeared is suspended by it.
	h.clk.add(time.Minute)
	h.b.step(context.Background())
	if len(h.b.Snapshot()) != 0 {
		t.Errorf("snapshot = %v", h.snapshot())
	}

	// The same for the entries fixed at start.
	h2 := newHarness(t, func(o *Options) { o.Guard.Configured = []netip.Prefix{netip.MustParsePrefix("::ffff:0.0.0.0/64")} })
	_, err = h2.manual("198.51.100.7", time.Hour, "")
	refused(t, err, RefuseNeverBlock)
}

// Unblocking a manual range also exempts automatic blocks of the addresses inside it.
func TestUnblockRangeExemptsAddressesInside(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.mustBlock(h.manual("192.0.2.0/25", time.Hour, ""))
	h.mustBlock(h.manual("2001:db8:5::/48", time.Hour, ""))
	for _, p := range []string{"192.0.2.0/25", "2001:db8:5::/48"} {
		if err := h.b.Unblock(ctx, netip.MustParsePrefix(p), "owner"); err != nil {
			t.Fatal(err)
		}
	}
	h.clk.add(time.Hour)
	_, err := h.auto("192.0.2.50", time.Hour)
	refused(t, err, RefuseExempt)
	_, err = h.auto("2001:db8:5:77::/64", time.Hour)
	refused(t, err, RefuseExempt)
	h.mustBlock(h.auto("198.51.100.20", time.Hour))     // outside the range
	h.mustBlock(h.auto("2001:db8:6:1::/64", time.Hour)) // outside the range
	h.mustBlock(h.manual("192.0.2.51", time.Hour, ""))  // manual blocks stay possible
	h.clk.add(ExemptAfterUnblock)
	h.mustBlock(h.auto("192.0.2.50", time.Hour))
	h.mustBlock(h.auto("2001:db8:5:77::/64", time.Hour))
}

// Status.L4 is true only when security_logs.blocking.l4 is on and an L4 load balancer takes the list.
func TestStatusL4(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.L4 = true })
	if st := h.b.Status(); !st.L4 || st.L4Why != "" {
		t.Errorf("l4 on, SetL4 not called: %+v", st)
	}
	h.b.SetL4(false, "edge.l4_enabled is off")
	if st := h.b.Status(); st.L4 || st.L4Why != "edge.l4_enabled is off" {
		t.Errorf("l4 on, no load balancer: %+v", st)
	}
	h.b.SetL4(true, "")
	if st := h.b.Status(); !st.L4 || st.L4Why != "" {
		t.Errorf("l4 on, load balancer runs: %+v", st)
	}
	off := newHarness(t)
	off.b.SetL4(true, "")
	if st := off.b.Status(); st.L4 || st.L4Why != "" {
		t.Errorf("l4 off in config: %+v", st)
	}
	off.b.SetL4(false, "edge.l4_enabled is off")
	if st := off.b.Status(); st.L4 || st.L4Why != "" {
		t.Errorf("l4 off in config, no load balancer: %+v", st)
	}
}

// An automatic request in the last RenewAhead of an automatic block is the address coming back as
// its block ends: a repeat (the next step of the ladder), not an extension at the first step's
// length. Earlier than that it extends; at the cap it is still taken (its own entry doesn't count).
func TestAutomaticRequestAtABlocksEndIsARepeat(t *testing.T) {
	h := newHarness(t)
	h.mustBlock(h.auto("198.51.100.7", 10*time.Minute))
	h.clk.add(5 * time.Minute)
	if blk := h.mustBlock(h.auto("198.51.100.7", 10*time.Minute)); blk.Hits != 1 || blk.Until.Sub(blk.Created) != 15*time.Minute {
		t.Fatalf("mid-block request: hits %d, length %s; want an extension (hits 1, 15m from its start)", blk.Hits, blk.Until.Sub(blk.Created))
	}
	h.clk.add(9 * time.Minute) // 1 minute before its end
	blk := h.mustBlock(h.auto("198.51.100.7", 10*time.Minute))
	if d := blk.Until.Sub(h.clk.now()); blk.Hits != 2 || d != 40*time.Minute {
		t.Fatalf("request in the block's last %s: hits %d, %s from now; want the next step (hits 2, 40m)", RenewAhead, blk.Hits, d)
	}
	// A manual block in force is only extended by an automatic request, whenever it comes.
	h.mustBlock(h.manual("198.51.100.9", time.Hour, ""))
	h.clk.add(59 * time.Minute)
	if m := h.mustBlock(h.auto("198.51.100.9", 10*time.Minute)); m.Source != SourceManual || m.Hits != 0 {
		t.Errorf("automatic request at a manual block's end: source %s, hits %d; want the manual block extended", m.Source, m.Hits)
	}
}

func TestRepeatAtABlocksEndAtTheCap(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.MaxAuto = 1 })
	h.mustBlock(h.auto("198.51.100.7", 10*time.Minute))
	h.clk.add(9 * time.Minute)
	if blk, err := h.auto("198.51.100.7", 10*time.Minute); err != nil || blk.Hits != 2 {
		t.Fatalf("a repeat of the only block at the cap: %+v, %v; want it placed (hits 2)", blk, err)
	}
}
