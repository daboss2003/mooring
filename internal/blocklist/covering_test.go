package blocklist

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

func (h *harness) covering(p string) string {
	blk, ok := h.b.Covering(netip.MustParsePrefix(p))
	if !ok {
		return ""
	}
	return blk.Prefix.String()
}

// Covering finds a block by what it overlaps, whatever the number of blocks placed after it: List
// returns the newest 1000 only, so an older range was missed by a scan of the list.
func TestCoveringFindsABlockBeyondTheListLimit(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.MaxAuto = 2000 })
	ctx := context.Background()
	h.mustBlock(h.manual("192.0.2.0/25", 24*time.Hour, ""))
	h.clk.add(time.Minute)
	const newer = 1001
	for i := range newer {
		h.mustBlock(h.auto(fmt.Sprintf("45.0.%d.%d", i/250, 1+i%250), 12*time.Hour))
	}
	list, err := h.b.List(ctx, Filter{States: []string{StateActive}, Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	for _, blk := range list {
		if blk.Prefix.String() == "192.0.2.0/25" {
			t.Fatal("the oldest block is in the newest 1000: the test no longer covers the list's limit")
		}
	}
	blk, ok := h.b.Covering(netip.MustParsePrefix("192.0.2.50/32"))
	if !ok || blk.Prefix.String() != "192.0.2.0/25" || blk.Source != SourceManual || blk.State != StateActive || !blk.Until.Equal(t0.Add(24*time.Hour)) {
		t.Fatalf("Covering(192.0.2.50) = %+v, %v; want the manual 192.0.2.0/25", blk, ok)
	}
}

func TestCovering(t *testing.T) {
	h := newHarness(t)
	h.mustBlock(h.manual("192.0.2.0/25", 2*time.Hour, ""))
	h.mustBlock(h.manual("192.0.2.0/26", 2*time.Hour, ""))
	h.mustBlock(h.manual("192.0.2.7", 2*time.Hour, ""))
	h.mustBlock(h.manual("198.51.100.230", 2*time.Hour, ""))
	h.mustBlock(h.manual("198.51.100.0/27", time.Hour, "")) // 198.51.100.0/28 will be a token CIDR: suspended
	h.mustBlock(h.manual("2001:db8:1::/48", 2*time.Hour, ""))
	h.mustBlock(h.manual("2001:db8:9:9::2", 2*time.Hour, ""))
	h.mustBlock(h.manual("2001:db8:9:9::1", 2*time.Hour, ""))
	h.mustBlock(h.manual("2001:db8:9:9:8000::/65", 2*time.Hour, ""))
	h.mustBlock(h.manual("2001:db8:7:7::/64", 30*time.Minute, ""))

	for p, want := range map[string]string{
		"192.0.2.7/32":             "192.0.2.0/25",           // the widest block containing it, never its own
		"192.0.2.0/26":             "192.0.2.0/25",           // a range's own block is skipped; a wider one beats the address inside
		"192.0.2.0/25":             "192.0.2.0/26",           // nothing contains it: the widest block inside
		"192.0.2.0/24":             "192.0.2.0/25",           //
		"192.0.2.200/32":           "",                       // outside every block
		"198.51.100.230/32":        "",                       // only its own block
		"::ffff:192.0.2.7/128":     "192.0.2.0/25",           // IPv4-mapped is IPv4
		"2001:db8:1:2::/64":        "2001:db8:1::/48",        //
		"2001:db8:1:2::5/128":      "2001:db8:1::/48",        //
		"2001:db8:9:9::/64":        "2001:db8:9:9:8000::/65", // the widest of the blocks inside
		"2001:db8:9:9::1/128":      "",                       //
		"2001:db8:9:9:8000::4/128": "2001:db8:9:9:8000::/65", //
		"2001:db8:7:7::1/128":      "2001:db8:7:7::/64",      //
		"2001:db8:8::/48":          "",                       //
	} {
		if got := h.covering(p); got != want {
			t.Errorf("Covering(%s) = %q, want %q", p, got, want)
		}
	}
	if _, ok := h.b.Covering(netip.Prefix{}); ok {
		t.Error("Covering of the zero prefix found a block")
	}
	// Equally wide blocks inside: always the same one (the lowest).
	if err := h.b.Unblock(context.Background(), netip.MustParsePrefix("2001:db8:9:9:8000::/65"), "owner"); err != nil {
		t.Fatal(err)
	}
	for range 20 {
		if got := h.covering("2001:db8:9:9::/64"); got != "2001:db8:9:9::1/128" {
			t.Fatalf("Covering(2001:db8:9:9::/64) = %q, want the lowest of the equally wide blocks inside", got)
		}
	}

	// A suspended block is not applied: it covers nothing.
	if got := h.covering("198.51.100.20/32"); got != "198.51.100.0/27" {
		t.Fatalf("before the suspension: Covering(198.51.100.20) = %q", got)
	}
	h.g.mu.Lock()
	h.g.tokens = pfx("198.51.100.0/28")
	h.g.mu.Unlock()
	h.b.step(context.Background())
	if got := h.covering("198.51.100.20/32"); got != "" {
		t.Errorf("a suspended block covers 198.51.100.20: %q", got)
	}
	// A block whose time ran out covers nothing, swept or not.
	h.clk.add(45 * time.Minute)
	if got := h.covering("2001:db8:7:7::1/128"); got != "" {
		t.Errorf("an expired block (not yet swept) covers an address: %q", got)
	}
	if got := h.covering("192.0.2.7/32"); got != "192.0.2.0/25" {
		t.Errorf("after 45 minutes: Covering(192.0.2.7) = %q", got)
	}
	// A removed block covers nothing.
	if err := h.b.Unblock(context.Background(), netip.MustParsePrefix("192.0.2.0/25"), "owner"); err != nil {
		t.Fatal(err)
	}
	if got := h.covering("192.0.2.7/32"); got != "192.0.2.0/26" {
		t.Errorf("after the /25 was removed: Covering(192.0.2.7) = %q, want the /26", got)
	}
}
