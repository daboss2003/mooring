package blocklist

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

// A repeat within RepeatWindow is RepeatFactor times longer than the previous automatic block, up to
// MaxAutoDuration; never shorter than the rule's own first length; past the window it starts over.
func TestEscalation(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for i, want := range []time.Duration{time.Hour, 4 * time.Hour, 16 * time.Hour, 24 * time.Hour, 24 * time.Hour} {
		blk := h.mustBlock(h.auto("192.0.2.1", time.Hour))
		if d := blk.Until.Sub(blk.Created); d != want || blk.Hits != i+1 {
			t.Fatalf("block %d: %s, hits %d; want %s, hits %d", i+1, d, blk.Hits, want, i+1)
		}
		h.clk.add(want + time.Minute)
		h.b.step(ctx)
	}
	h.clk.add(RepeatWindow)
	if blk := h.mustBlock(h.auto("192.0.2.1", time.Hour)); blk.Until.Sub(blk.Created) != time.Hour || blk.Hits != 1 {
		t.Errorf("past the repeat window: %s, hits %d; want 1h, hits 1", blk.Until.Sub(blk.Created), blk.Hits)
	}
	// A rule's own first length wins when it is longer than the escalation.
	h2 := newHarness(t)
	h2.mustBlock(h2.auto("192.0.2.2", 5*time.Minute))
	h2.clk.add(10 * time.Minute)
	if blk := h2.mustBlock(h2.auto("192.0.2.2", 3*time.Hour)); blk.Until.Sub(blk.Created) != 3*time.Hour {
		t.Errorf("repeat with a longer rule length: %s, want 3h", blk.Until.Sub(blk.Created))
	}
	// A configured maximum below the escalation caps it; a tiny duration is raised to MinDuration.
	h3 := newHarness(t, func(o *Options) { o.MaxAutoDuration = 2 * time.Hour })
	if blk := h3.mustBlock(h3.auto("192.0.2.3", time.Second)); blk.Until.Sub(blk.Created) != MinDuration {
		t.Errorf("1s block lasts %s, want %s", blk.Until.Sub(blk.Created), MinDuration)
	}
	if blk := h3.mustBlock(h3.auto("192.0.2.4", 5*time.Hour)); blk.Until.Sub(blk.Created) != 2*time.Hour {
		t.Errorf("5h block lasts %s, want the 2h maximum", blk.Until.Sub(blk.Created))
	}
}

// An owner's unblock exempts the prefix from automatic blocks for ExemptAfterUnblock (manual blocks
// stay possible); Unblock of a prefix with nothing in force is ErrNotFound.
func TestUnblockExempts(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.mustBlock(h.auto("192.0.2.1", time.Hour))
	if err := h.b.Unblock(ctx, netip.MustParsePrefix("192.0.2.1/32"), "owner"); err != nil {
		t.Fatal(err)
	}
	if err := h.b.Unblock(ctx, netip.MustParsePrefix("192.0.2.1/32"), "owner"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second unblock = %v, want ErrNotFound", err)
	}
	if err := h.b.Unblock(ctx, netip.MustParsePrefix("192.0.2.77/32"), "owner"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unblock of an unknown prefix = %v, want ErrNotFound", err)
	}
	blk, ok, err := h.b.Get(ctx, netip.MustParsePrefix("::ffff:192.0.2.1/128"))
	if err != nil || !ok || blk.State != StateRemoved || blk.RemovedBy != "owner" || !blk.ExemptUntil.Equal(t0.Add(ExemptAfterUnblock)) {
		t.Fatalf("after unblock: %+v ok=%v err=%v", blk, ok, err)
	}
	h.clk.add(time.Hour)
	_, err = h.auto("192.0.2.1", time.Hour)
	refused(t, err, RefuseExempt)
	h.mustBlock(h.manual("192.0.2.1", time.Hour, ""))
	if err := h.b.Unblock(ctx, netip.MustParsePrefix("192.0.2.1/32"), "owner"); err != nil {
		t.Fatal(err)
	}
	h.clk.add(ExemptAfterUnblock + time.Minute)
	h.mustBlock(h.auto("192.0.2.1", time.Hour))
	if got := h.ev.actions("192.0.2.1/32"); !reflect.DeepEqual(got, []string{"applied", "removed", "applied", "removed", "applied"}) {
		t.Errorf("events = %v", got)
	}
}

// UnblockIncident lifts the incident's automatic blocks only and exempts every automatic prefix ever
// blocked for it — one whose time already ran out too.
func TestUnblockIncident(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	place := func(prefix, src string, incident int64, d time.Duration) {
		t.Helper()
		h.mustBlock(h.b.Block(ctx, Request{Prefix: prefix, Source: src, Duration: d, IncidentID: incident, By: "owner"}))
	}
	place("192.0.2.9", SourceAuto, 7, 5*time.Minute)
	h.clk.add(6 * time.Minute)
	h.b.step(ctx) // 192.0.2.9 expires
	place("192.0.2.1", SourceAuto, 7, time.Hour)
	place("192.0.2.2", SourceAuto, 7, time.Hour)
	place("192.0.2.3", SourceAuto, 8, time.Hour)
	place("192.0.2.4", SourceManual, 7, time.Hour)
	n, err := h.b.UnblockIncident(ctx, 7, "owner", 30*24*time.Hour)
	if err != nil || n != 2 {
		t.Fatalf("UnblockIncident = %d, %v; want 2", n, err)
	}
	h.release()
	if got := h.snapshot(); !reflect.DeepEqual(got, []string{"192.0.2.3/32", "192.0.2.4/32"}) {
		t.Errorf("snapshot = %v", got)
	}
	h.clk.add(48 * time.Hour)
	for _, p := range []string{"192.0.2.1", "192.0.2.9"} {
		_, err := h.auto(p, time.Hour)
		refused(t, err, RefuseExempt)
	}
	if n, _ := h.b.UnblockIncident(ctx, 0, "owner", time.Hour); n != 0 {
		t.Errorf("incident 0 lifted %d", n)
	}
}

// LiftAutomatic lifts every automatic block in force and leaves the manual ones, without exempting.
func TestLiftAutomatic(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.mustBlock(h.auto("192.0.2.1", time.Hour))
	h.mustBlock(h.auto("2001:db8:1:2::/64", time.Hour))
	h.mustBlock(h.manual("192.0.2.64/26", time.Hour, ""))
	n, err := h.b.LiftAutomatic(ctx, "siem", "automated response is off")
	if err != nil || n != 2 {
		t.Fatalf("LiftAutomatic = %d, %v", n, err)
	}
	h.release()
	if got := h.snapshot(); !reflect.DeepEqual(got, []string{"192.0.2.64/26"}) {
		t.Errorf("snapshot = %v", got)
	}
	h.mustBlock(h.auto("192.0.2.1", time.Hour)) // no exemption
	ev := h.ev.kind(kindBlock)
	var why string
	for _, e := range ev {
		if e.F["action"] == "removed" {
			why, _ = e.F["why"].(string)
		}
	}
	if why != "automated response is off" {
		t.Errorf("removed event why = %q", why)
	}
}

// At MaxAuto automatic blocks in force a new one is refused (full) with a warning at most once an
// hour; extending a block in force and manual blocks are unaffected.
func TestCapFull(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.MaxAuto = 2 })
	h.mustBlock(h.auto("192.0.2.1", time.Hour))
	h.mustBlock(h.auto("192.0.2.2", 2*time.Hour)) // still in force an hour later (one that ran out is no entry)
	_, err := h.auto("192.0.2.3", time.Hour)
	refused(t, err, RefuseFull)
	_, err = h.auto("192.0.2.4", time.Hour)
	refused(t, err, RefuseFull)
	if n := h.alerts.count(alertKeyFull, "firing"); n != 1 {
		t.Errorf("full alerts = %d, want 1 within the hour", n)
	}
	h.clk.add(30 * time.Minute)
	h.mustBlock(h.auto("192.0.2.1", time.Hour)) // an extension adds no entry
	h.mustBlock(h.manual("192.0.2.5", time.Hour, ""))
	h.clk.add(31 * time.Minute)
	_, err = h.auto("192.0.2.6", time.Hour)
	refused(t, err, RefuseFull)
	if n := h.alerts.count(alertKeyFull, "firing"); n != 2 {
		t.Errorf("full alerts = %d, want 2 an hour later", n)
	}
	for _, o := range h.alerts.list() {
		if o.Kind != alertKind || o.Level != "warning" {
			t.Errorf("alert %+v", o)
		}
	}
	if st := h.b.Status(); st.ActiveAuto != 2 || st.ActiveManual != 1 || st.MaxAuto != 2 || st.MaxManual != MaxManual {
		t.Errorf("status = %+v", st)
	}
}

// A CDN refusal of an automatic block warns that the edge looks proxied, at most once a day.
func TestCDNRefusalAlertOncePerDay(t *testing.T) {
	h := newHarness(t)
	for i := 0; i < 3; i++ {
		_, err := h.auto(fmt.Sprintf("104.16.0.%d", i+1), time.Hour)
		refused(t, err, RefuseCDN)
	}
	_, err := h.manual("104.16.9.0/24", time.Hour, "")
	refused(t, err, RefuseCDN)
	if n := h.alerts.count(alertKeyCDN, "firing"); n != 1 {
		t.Fatalf("cdn alerts = %d, want 1", n)
	}
	if s := h.alerts.list()[0].Summary; !strings.Contains(s, "edge.trusted_proxies") {
		t.Errorf("summary = %q", s)
	}
	h.clk.add(24 * time.Hour)
	_, err = h.auto("104.16.0.9", time.Hour)
	refused(t, err, RefuseCDN)
	if n := h.alerts.count(alertKeyCDN, "firing"); n != 2 {
		t.Errorf("cdn alerts = %d, want 2 a day later", n)
	}
}

// Refusals are coalesced per (prefix, code) with a count and first/last times, each is emitted as a
// siem.block_refused event, and a junk prefix is stored cleaned.
func TestRefusalCoalescing(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	_, _ = h.auto("10.1.2.3", time.Hour)
	h.clk.add(time.Minute)
	_, _ = h.auto("10.1.2.3/32", time.Hour)
	_, _ = h.auto("192.0.2.200", time.Hour)            // trusted proxy
	_, _ = h.manual("192.0.2.200", time.Second, "")    // duration
	_, _ = h.auto("bad\x00\n<script>value", time.Hour) // invalid
	rs, err := h.b.Refusals(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Refusal{}
	for _, r := range rs {
		got[r.Prefix+" "+r.Code] = r
	}
	if len(rs) != 4 {
		t.Fatalf("refusals = %+v", rs)
	}
	if r := got["10.1.2.3/32 local"]; r.Count != 2 || !r.First.Equal(t0) || !r.Last.Equal(t0.Add(time.Minute)) || r.Source != SourceAuto || r.RuleID != "edge.scan" {
		t.Errorf("coalesced refusal = %+v", r)
	}
	if _, ok := got["192.0.2.200/32 trusted_proxy"]; !ok {
		t.Error("missing the trusted proxy refusal")
	}
	if _, ok := got["192.0.2.200/32 duration"]; !ok {
		t.Error("missing the duration refusal")
	}
	if _, ok := got["bad<script>value invalid"]; !ok {
		t.Errorf("junk prefix not stored cleaned: %v", rs)
	}
	if n := len(h.ev.kind(kindBlockRefused)); n != 5 {
		t.Errorf("block_refused events = %d, want 5", n)
	}
	if rs, _ := h.b.Refusals(ctx, 1); len(rs) != 1 {
		t.Errorf("limit 1 returned %d", len(rs))
	}
}

// Blocking a prefix in force extends it to the later end; a manual request takes over an automatic
// block (LiftAutomatic no longer lifts it); an automatic request never takes over a manual one.
func TestExtendInForce(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.mustBlock(h.auto("192.0.2.1", time.Hour))
	h.clk.add(30 * time.Minute)
	blk := h.mustBlock(h.auto("192.0.2.1", time.Hour))
	if !blk.Until.Equal(t0.Add(90*time.Minute)) || blk.Hits != 1 || !blk.Created.Equal(t0) {
		t.Errorf("extended: %+v", blk)
	}
	blk = h.mustBlock(h.auto("192.0.2.1", 5*time.Minute)) // a shorter request never shortens it
	if !blk.Until.Equal(t0.Add(90 * time.Minute)) {
		t.Errorf("a shorter request moved the end to %s", blk.Until)
	}
	blk = h.mustBlock(h.manual("192.0.2.1", 48*time.Hour, ""))
	if blk.Source != SourceManual || blk.By != "owner" || !blk.Until.Equal(t0.Add(30*time.Minute+48*time.Hour)) {
		t.Errorf("manual over automatic: %+v", blk)
	}
	if n, _ := h.b.LiftAutomatic(ctx, "siem", ""); n != 0 {
		t.Errorf("LiftAutomatic lifted %d, want 0 (now manual)", n)
	}
	if blk = h.mustBlock(h.auto("192.0.2.1", time.Hour)); blk.Source != SourceManual {
		t.Errorf("an automatic request took over a manual block: %+v", blk)
	}
	if got := h.ev.actions("192.0.2.1/32"); !reflect.DeepEqual(got, []string{"applied", "extended", "extended", "extended", "extended"}) {
		t.Errorf("events = %v", got)
	}
	stored, _, _ := h.b.Get(ctx, netip.MustParsePrefix("192.0.2.1/32"))
	if stored.Source != SourceManual || !stored.Until.Equal(blk.Until) {
		t.Errorf("stored = %+v", stored)
	}
}

// A restart (Open) restores the blocks in force, publishes them at once, never publishes an expired
// or invalid row, and cuts a block ending past the longest block of its source (a clock that stepped
// back) to that, in the database too. A loaded block now covered by a protected address is suspended.
func TestOpenRestoresAndClamps(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.mustBlock(h.auto("192.0.2.1", time.Hour))
	h.mustBlock(h.manual("192.0.2.64/26", 48*time.Hour, ""))
	insert := func(prefix, src string, until time.Time) {
		t.Helper()
		if _, err := h.db.Exec(`INSERT INTO edge_blocks(prefix, source, created_at, until_at) VALUES (?,?,?,?)`,
			prefix, src, t0.Unix(), until.Unix()); err != nil {
			t.Fatal(err)
		}
	}
	insert("192.0.2.9/32", SourceAuto, t0.Add(365*24*time.Hour))
	insert("192.0.2.10/24", SourceManual, t0.Add(time.Hour)) // not canonical
	insert("192.0.0.0/16", SourceManual, t0.Add(time.Hour))  // too wide
	insert("192.0.2.12/31", SourceAuto, t0.Add(time.Hour))   // not an automatic width
	insert("192.0.2.13/32", "robot", t0.Add(time.Hour))      // unknown source
	insert("192.0.2.11/32", SourceAuto, t0.Add(-time.Hour))  // expired
	insert("10.0.0.0/24", SourceManual, t0.Add(time.Hour))   // a private range
	h.clk.add(time.Minute)
	h.reopen()
	if got := h.snapshot(); !reflect.DeepEqual(got, []string{"192.0.2.1/32", "192.0.2.9/32", "192.0.2.64/26"}) {
		t.Errorf("snapshot after restart = %v", got)
	}
	blk, _, _ := h.b.Get(ctx, netip.MustParsePrefix("192.0.2.9/32"))
	if want := t0.Add(time.Minute + 24*time.Hour); !blk.Until.Equal(want) {
		t.Errorf("far block until %s, want %s", blk.Until, want)
	}
	var until int64
	if err := h.db.QueryRow(`SELECT until_at FROM edge_blocks WHERE prefix = '192.0.2.9/32'`).Scan(&until); err != nil || until != t0.Add(time.Minute+24*time.Hour).Unix() {
		t.Errorf("clamp not written back: %d %v", until, err)
	}
	if blk, _, _ := h.b.Get(ctx, netip.MustParsePrefix("10.0.0.0/24")); blk.State != StateSuspended || blk.SuspendedWhy != RefuseLocal {
		t.Errorf("private range after restart: %+v", blk)
	}
	if blk, _, _ := h.b.Get(ctx, netip.MustParsePrefix("192.0.2.11/32")); blk.State != StateExpired {
		t.Errorf("expired row: %+v", blk)
	}
	if !h.b.Blocked(netip.MustParseAddr("192.0.2.9")) || h.b.Blocked(netip.MustParseAddr("192.0.2.11")) {
		t.Error("Blocked after restart")
	}
}

// Blocked answers from memory for /32, IPv6 /64 and wider manual ranges, IPv4-mapped addresses
// included — for the released list only.
func TestBlockedLookups(t *testing.T) {
	h := newHarness(t)
	h.mustBlock(h.auto("192.0.2.1", time.Hour))
	h.mustBlock(h.auto("2001:db8:1:2::/64", time.Hour))
	h.mustBlock(h.manual("198.51.100.0/27", time.Hour, ""))
	h.mustBlock(h.manual("2001:db8:5::/56", time.Hour, ""))
	h.mustBlock(h.manual("2001:db8:6::7", time.Hour, ""))
	if h.b.Blocked(netip.MustParseAddr("192.0.2.1")) {
		t.Error("a block not yet released to the edge must not report Blocked")
	}
	h.release()
	cases := map[string]bool{
		"192.0.2.1": true, "192.0.2.2": false, "::ffff:192.0.2.1": true,
		"2001:db8:1:2::abcd": true, "2001:db8:1:2:ffff:ffff:ffff:ffff": true, "2001:db8:1:3::1": false,
		"198.51.100.17": true, "198.51.100.31": true, "198.51.100.32": false,
		"2001:db8:5:ff::1": true, "2001:db8:5:100::1": false,
		"2001:db8:6::7": true, "2001:db8:6::8": false,
	}
	for a, want := range cases {
		if got := h.b.Blocked(netip.MustParseAddr(a)); got != want {
			t.Errorf("Blocked(%s) = %v, want %v", a, got, want)
		}
	}
	if h.b.Blocked(netip.Addr{}) {
		t.Error("Blocked(zero) must be false")
	}
	if h.b.L4Snapshot() != nil {
		t.Error("L4Snapshot must be nil without Options.L4")
	}
	l4 := newHarness(t, func(o *Options) { o.L4 = true })
	if s := l4.b.L4Snapshot(); s == nil || len(s) != 0 {
		t.Errorf("L4 with no blocks = %#v, want empty", s)
	}
	l4.mustBlock(l4.auto("192.0.2.1", time.Hour))
	l4.mustBlock(l4.auto("2001:db8:1:2::/64", time.Hour))
	l4.release()
	if got := l4.b.L4Snapshot(); !reflect.DeepEqual(got, pfx("192.0.2.1/32")) {
		t.Errorf("L4Snapshot = %v, want IPv4 only", got)
	}
	if len(l4.b.Snapshot()) != 2 {
		t.Errorf("Snapshot = %v", l4.b.Snapshot())
	}
}

// List filters by state, source and incident, newest first, with a limit; Get finds any row.
func TestListAndGet(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.mustBlock(h.b.Block(ctx, Request{Prefix: "192.0.2.1", Source: SourceAuto, Duration: 5 * time.Minute, IncidentID: 3}))
	h.clk.add(time.Minute)
	h.mustBlock(h.manual("192.0.2.2", time.Hour, ""))
	h.clk.add(time.Minute)
	h.mustBlock(h.auto("192.0.2.3", time.Hour))
	h.clk.add(time.Minute)
	h.mustBlock(h.auto("192.0.2.4", time.Hour))
	if err := h.b.Unblock(ctx, netip.MustParsePrefix("192.0.2.4/32"), "owner"); err != nil {
		t.Fatal(err)
	}
	h.clk.add(3 * time.Minute) // 192.0.2.1 expired
	h.g.setAllow("203.0.113.0/24", "192.0.2.3/32")
	h.clk.add(time.Minute)
	h.b.step(ctx) // 192.0.2.3 suspended
	list := func(f Filter) []string {
		t.Helper()
		bs, err := h.b.List(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, b := range bs {
			out = append(out, b.Prefix.Addr().String()+":"+b.State)
		}
		return out
	}
	all := []string{"192.0.2.4:removed", "192.0.2.3:suspended", "192.0.2.2:active", "192.0.2.1:expired"}
	if got := list(Filter{}); !reflect.DeepEqual(got, all) {
		t.Errorf("all = %v", got)
	}
	for f, want := range map[string][]string{
		StateActive:    {"192.0.2.2:active"},
		StateSuspended: {"192.0.2.3:suspended"},
		StateExpired:   {"192.0.2.1:expired"},
		StateRemoved:   {"192.0.2.4:removed"},
	} {
		if got := list(Filter{States: []string{f}}); !reflect.DeepEqual(got, want) {
			t.Errorf("state %s = %v, want %v", f, got, want)
		}
	}
	if got := list(Filter{States: []string{StateActive, StateSuspended}}); len(got) != 2 {
		t.Errorf("in force = %v", got)
	}
	if got := list(Filter{Source: SourceManual}); !reflect.DeepEqual(got, []string{"192.0.2.2:active"}) {
		t.Errorf("manual = %v", got)
	}
	if got := list(Filter{IncidentID: 3}); !reflect.DeepEqual(got, []string{"192.0.2.1:expired"}) {
		t.Errorf("incident 3 = %v", got)
	}
	if got := list(Filter{Limit: 2}); !reflect.DeepEqual(got, all[:2]) {
		t.Errorf("limit 2 = %v", got)
	}
	if _, err := h.b.List(ctx, Filter{States: []string{"bogus"}}); err == nil {
		t.Error("an unknown state must be an error")
	}
	if _, ok, err := h.b.Get(ctx, netip.MustParsePrefix("192.0.2.99/32")); ok || err != nil {
		t.Errorf("Get unknown = %v, %v", ok, err)
	}
	if blk, ok, _ := h.b.Get(ctx, netip.MustParsePrefix("192.0.2.3/32")); !ok || blk.SuspendedWhy != RefuseAllowlist {
		t.Errorf("Get suspended = %+v", blk)
	}
}

// Prune deletes rows 30 days after their block ended (keeping a running exemption) and refusals
// older than 30 days, and keeps the newest maxRefusals refusals.
func TestPrune(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.mustBlock(h.auto("192.0.2.1", 5*time.Minute))
	if err := h.b.Unblock(ctx, netip.MustParsePrefix("192.0.2.1/32"), "owner"); err != nil {
		t.Fatal(err)
	}
	h.mustBlock(h.auto("192.0.2.2", 5*time.Minute))
	h.mustBlock(h.b.Block(ctx, Request{Prefix: "192.0.2.3", Source: SourceAuto, Duration: 5 * time.Minute, IncidentID: 9}))
	if _, err := h.b.UnblockIncident(ctx, 9, "owner", 60*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	_, _ = h.auto("10.0.0.1", time.Hour) // a refusal
	h.clk.add(29 * 24 * time.Hour)
	h.b.prune(ctx, h.clk.now())
	count := func(q string) int {
		var n int
		if err := h.db.QueryRow(q).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(`SELECT COUNT(*) FROM edge_blocks`); n != 3 {
		t.Errorf("29 days on: %d rows, want 3", n)
	}
	h.clk.add(2 * 24 * time.Hour)
	h.b.prune(ctx, h.clk.now())
	if n := count(`SELECT COUNT(*) FROM edge_blocks`); n != 1 {
		t.Errorf("31 days on: %d rows, want 1 (the exempt one)", n)
	}
	if n := count(`SELECT COUNT(*) FROM edge_block_refusals`); n != 0 {
		t.Errorf("old refusals kept: %d", n)
	}
	now := h.clk.now().Unix()
	for i := 0; i < maxRefusals+5; i++ {
		if _, err := h.db.Exec(`INSERT INTO edge_block_refusals(prefix, code, source, first_at, last_at) VALUES (?, 'local', 'auto', ?, ?)`,
			fmt.Sprintf("10.%d.%d.%d/32", i>>16, (i>>8)&255, i&255), now, now+int64(i)); err != nil {
			t.Fatal(err)
		}
	}
	h.b.prune(ctx, h.clk.now())
	if n := count(`SELECT COUNT(*) FROM edge_block_refusals`); n != maxRefusals {
		t.Errorf("refusals = %d, want %d", n, maxRefusals)
	}
	if n := count(`SELECT COUNT(*) FROM edge_block_refusals WHERE prefix IN ('10.0.0.0/32','10.0.0.4/32')`); n != 0 {
		t.Error("the oldest refusals must go first")
	}
}
