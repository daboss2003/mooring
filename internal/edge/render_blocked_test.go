package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"math/rand"
	"net/netip"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// blockRoute is the part of a rendered route the block-list tests inspect.
type blockRoute struct {
	Match []struct {
		Host     []string `json:"host"`
		RemoteIP *struct {
			Ranges []string `json:"ranges"`
		} `json:"remote_ip"`
		ClientIP *struct {
			Ranges []string `json:"ranges"`
		} `json:"client_ip"`
	} `json:"match"`
	Handle []struct {
		Handler    string          `json:"handler"`
		StatusCode int             `json:"status_code"`
		Body       string          `json:"body"`
		Headers    json.RawMessage `json:"headers"` // static_response: field → values
	} `json:"handle"`
	Terminal bool `json:"terminal"`
}

func blockRoutes(t *testing.T, out []byte) []blockRoute {
	t.Helper()
	var doc struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes []blockRoute `json:"routes"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Apps.HTTP.Servers["edge"].Routes
}

// isDenyRoute reports whether r is the block list's route (and returns its ranges).
func isDenyRoute(r blockRoute) ([]string, bool) {
	if len(r.Handle) != 1 || r.Handle[0].StatusCode != 403 || len(r.Match) != 1 {
		return nil, false
	}
	m := r.Match[0]
	switch {
	case m.RemoteIP != nil && m.ClientIP == nil && len(m.Host) == 0:
		return m.RemoteIP.Ranges, true
	case m.ClientIP != nil && m.RemoteIP == nil && len(m.Host) == 0:
		return m.ClientIP.Ranges, true
	}
	return nil, false
}

func prefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParsePrefix(s)
	}
	return out
}

func adminBase() BaseConfig {
	base := baseCfg()
	base.AdminHostname = "admin.example.com"
	base.AdminAllowlist = []string{"203.0.113.0/24", "2001:db8:aaaa::/48", "192.0.2.5"}
	base.AdminUpstream = "127.0.0.1:9001"
	return base
}

// With no block list and Refuse0RTT off, the document is byte-identical to the golden render from
// before the block list existed — an empty list included.
func TestRenderBlockedEmptyIsGolden(t *testing.T) {
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, blocked := range [][]netip.Prefix{nil, {}} {
		base, routes, certOnly := goldenFixture()
		base.Blocked = blocked
		full, err := Render(base, routes, certOnly)
		if err != nil {
			t.Fatal(err)
		}
		floor, err := Render(BootFloor(base), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		got := append(append(append([]byte{}, full...), '\n'), floor...)
		if !bytes.Equal(got, want) {
			t.Errorf("Blocked=%#v changed the render:\n%s", blocked, got)
		}
	}
	// A list whose every entry is left out renders no deny route either.
	base, routes, certOnly := goldenFixture()
	plain, _ := Render(base, routes, certOnly)
	base.Blocked = prefixes("10.1.2.3/32", "203.0.113.9/32", "104.16.0.1/32")
	out, err := Render(base, routes, certOnly)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, plain) {
		t.Errorf("a list with only refused entries must render like no list:\n%s", out)
	}
}

// The deny route sits right after the admin vhost and before every app route: it matches the TCP peer
// (remote_ip) without trusted proxies, answers a fixed 403 that no cache keeps, and is terminal.
func TestRenderBlockedRouteAfterAdmin(t *testing.T) {
	base := adminBase()
	base.Blocked = prefixes("198.51.100.9/32", "2001:db8:1:2::/64", "198.51.100.0/24")
	routes := []Route{pooledRoute("app.example.com"), pooledRoute("shop.example.com")}
	out, err := Render(base, routes, []CertHost{{Hostname: "mqtt.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	rs := blockRoutes(t, out)
	if len(rs) < 3 || len(rs[0].Match) != 1 || !reflect.DeepEqual(rs[0].Match[0].Host, []string{"admin.example.com"}) {
		t.Fatalf("the admin vhost must stay the first route:\n%s", out)
	}
	ranges, ok := isDenyRoute(rs[1])
	if !ok {
		t.Fatalf("route 1 must be the deny route:\n%s", out)
	}
	if rs[1].Match[0].RemoteIP == nil {
		t.Error("without trusted proxies the deny route must match remote_ip")
	}
	if want := []string{"198.51.100.0/24", "198.51.100.9/32", "2001:db8:1:2::/64"}; !reflect.DeepEqual(ranges, want) {
		t.Errorf("ranges = %v, want %v (sorted)", ranges, want)
	}
	h := rs[1].Handle[0]
	if h.Handler != "static_response" || h.Body != "403 Forbidden\n" || !rs[1].Terminal {
		t.Errorf("deny handler = %+v terminal=%v", h, rs[1].Terminal)
	}
	var hdr map[string][]string
	if err := json.Unmarshal(h.Headers, &hdr); err != nil || !reflect.DeepEqual(hdr, map[string][]string{"Cache-Control": {"no-store"}, "Content-Type": {"text/plain; charset=utf-8"}}) {
		t.Errorf("deny headers = %s (%v)", h.Headers, err)
	}
	for i, r := range rs {
		if _, deny := isDenyRoute(r); deny && i != 1 {
			t.Errorf("route %d is a second deny route", i)
		}
	}
	// Without an admin vhost the deny route is the first route.
	base.AdminHostname = ""
	out, err = Render(base, routes, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := isDenyRoute(blockRoutes(t, out)[0]); !ok {
		t.Errorf("without an admin vhost the deny route must be first:\n%s", out)
	}
}

// Behind trusted proxies the deny route matches the client address Caddy derived (client_ip), never
// the TCP peer (the proxy), while the admin vhost keeps matching the TCP peer.
func TestRenderBlockedClientIPWithTrustedProxies(t *testing.T) {
	base := adminBase()
	base.TrustedProxies = []string{"cloudflare", "198.51.100.0/24"}
	base.Blocked = prefixes("192.0.2.77/32")
	out, err := Render(base, []Route{pooledRoute("app.example.com")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rs := blockRoutes(t, out)
	if rs[0].Match[0].RemoteIP == nil || rs[0].Match[0].ClientIP != nil {
		t.Errorf("admin vhost must match remote_ip only:\n%s", out)
	}
	ranges, ok := isDenyRoute(rs[1])
	if !ok || rs[1].Match[0].ClientIP == nil {
		t.Fatalf("with trusted proxies the deny route must match client_ip:\n%s", out)
	}
	if !reflect.DeepEqual(ranges, []string{"192.0.2.77/32"}) {
		t.Errorf("ranges = %v", ranges)
	}
}

// Abuse test: an ip_allowlist address forced into the block list never lands in the deny route (it is
// left out, the rest still render), and the admin vhost still comes first for the allowlisted peer.
func TestRenderBlockedNeverDeniesAllowlistedPeer(t *testing.T) {
	base := adminBase()
	base.Blocked = prefixes("203.0.113.7/32", "203.0.113.0/24", "192.0.2.0/24", "2001:db8:aaaa:1::/64", "198.51.100.9/32")
	out, err := Render(base, []Route{pooledRoute("app.example.com")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rs := blockRoutes(t, out)
	if rs[0].Match[0].RemoteIP == nil || !reflect.DeepEqual(rs[0].Match[0].RemoteIP.Ranges, base.AdminAllowlist) {
		t.Fatalf("the admin vhost must be first with the allowlist:\n%s", out)
	}
	ranges, ok := isDenyRoute(rs[1])
	if !ok || !reflect.DeepEqual(ranges, []string{"198.51.100.9/32"}) {
		t.Fatalf("deny ranges = %v (ok %v), want only 198.51.100.9/32:\n%s", ranges, ok, out)
	}
	_, dropped := filterBlocked(base)
	if len(dropped) != 4 {
		t.Fatalf("dropped = %v, want the 4 allowlisted entries", dropped)
	}
	for _, d := range dropped {
		if d.why != "overlaps ip_allowlist" {
			t.Errorf("%s dropped for %q", d.p, d.why)
		}
	}
}

// Every entry the edge must never block is left out: trusted proxies, CDN ranges, non-public ranges,
// non-canonical and too-wide ranges. The documentation ranges stay blockable.
func TestRenderBlockedDropsProtected(t *testing.T) {
	base := baseCfg()
	base.TrustedProxies = []string{"198.51.100.0/24"}
	bad := map[netip.Prefix]string{
		netip.MustParsePrefix("198.51.100.7/32"):             "overlaps edge.trusted_proxies",
		netip.MustParsePrefix("104.16.0.5/32"):               "overlaps a CDN's published ranges",
		netip.MustParsePrefix("2606:4700:1::/64"):            "overlaps a CDN's published ranges",
		netip.MustParsePrefix("10.1.2.3/32"):                 "not a public address range",
		netip.MustParsePrefix("127.0.0.1/32"):                "not a public address range",
		netip.MustParsePrefix("100.64.1.1/32"):               "not a public address range",
		netip.MustParsePrefix("169.254.1.1/32"):              "not a public address range",
		netip.MustParsePrefix("172.16.5.0/24"):               "not a public address range",
		netip.MustParsePrefix("192.168.1.1/32"):              "not a public address range",
		netip.MustParsePrefix("224.0.0.1/32"):                "not a public address range",
		netip.MustParsePrefix("255.255.255.255/32"):          "not a public address range",
		netip.MustParsePrefix("0.0.0.0/32"):                  "not a public address range",
		netip.MustParsePrefix("fd00:1::/64"):                 "not a public address range",
		netip.MustParsePrefix("fe80::/64"):                   "not a public address range",
		netip.MustParsePrefix("ff02::/64"):                   "not a public address range",
		netip.MustParsePrefix("::1/128"):                     "not a public address range",
		netip.MustParsePrefix("::/128"):                      "not a public address range",
		netip.MustParsePrefix("::ffff:1.2.3.4/128"):          "not in canonical form",
		netip.PrefixFrom(netip.MustParseAddr("1.2.3.4"), 24): "not in canonical form",
		netip.MustParsePrefix("1.2.0.0/16"):                  "wider than /24 (IPv4) or /48 (IPv6)",
		netip.MustParsePrefix("2001:db8::/32"):               "wider than /24 (IPv4) or /48 (IPv6)",
		netip.MustParsePrefix("0.0.0.0/0"):                   "wider than /24 (IPv4) or /48 (IPv6)",
		{}:                                                   "not an address range",
	}
	good := prefixes("192.0.2.0/24", "203.0.113.7/32", "2001:db8:1:2::/64", "2001:db8:5::/48", "8.8.8.8/32")
	for p, why := range bad {
		if err := BlockAllowed(base, p); err == nil || err.Error() != why {
			t.Errorf("BlockAllowed(%s) = %v, want %q", p, err, why)
		}
		base.Blocked = append(base.Blocked, p)
	}
	for _, p := range good {
		if err := BlockAllowed(base, p); err != nil {
			t.Errorf("BlockAllowed(%s) = %v, want nil", p, err)
		}
		base.Blocked = append(base.Blocked, p)
	}
	out, err := Render(base, []Route{pooledRoute("app.example.com")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ranges, ok := isDenyRoute(blockRoutes(t, out)[0])
	if !ok {
		t.Fatalf("no deny route:\n%s", out)
	}
	if want := []string{"8.8.8.8/32", "192.0.2.0/24", "203.0.113.7/32", "2001:db8:1:2::/64", "2001:db8:5::/48"}; !reflect.DeepEqual(ranges, want) {
		t.Errorf("ranges = %v\nwant     %v", ranges, want)
	}
	// An allowlist entry that can't be parsed fails closed: nothing is blocked.
	base.AdminAllowlist = []string{"not-an-address"}
	if err := BlockAllowed(base, netip.MustParsePrefix("8.8.8.8/32")); err == nil {
		t.Error("an unparseable allowlist must refuse every entry")
	}
	out, err = Render(base, []Route{pooledRoute("app.example.com")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := isDenyRoute(blockRoutes(t, out)[0]); ok {
		t.Errorf("an unparseable allowlist must render no deny route:\n%s", out)
	}
	// An allowlist of every address protects every address.
	base.AdminAllowlist = []string{"0.0.0.0/0", "::/0"}
	if err := BlockAllowed(base, netip.MustParsePrefix("8.8.8.8/32")); err == nil || err.Error() != "overlaps ip_allowlist" {
		t.Errorf("allowlist 0.0.0.0/0: %v", err)
	}
}

// The deny route is deterministic: the same set in any order, with duplicates, renders the same
// bytes; Render never reorders the caller's slice; past the cap the first entries in order render.
func TestRenderBlockedDeterministicAndCapped(t *testing.T) {
	base := baseCfg()
	var list []netip.Prefix
	for i := 0; i < maxBlocked+50; i++ {
		list = append(list, netip.PrefixFrom(netip.AddrFrom4([4]byte{11, byte(i >> 16), byte(i >> 8), byte(i)}), 32))
	}
	list = append(list, list[:20]...) // duplicates
	rng := rand.New(rand.NewSource(1))
	shuffled := slices.Clone(list)
	rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	keep := slices.Clone(shuffled)

	base.Blocked = list
	a, err := Render(base, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	base.Blocked = shuffled
	b, err := Render(base, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Error("the same set in another order rendered differently")
	}
	if !slices.Equal(shuffled, keep) {
		t.Error("Render modified base.Blocked")
	}
	ranges, ok := isDenyRoute(blockRoutes(t, a)[0])
	if !ok || len(ranges) != maxBlocked {
		t.Fatalf("rendered %d ranges, want the cap %d", len(ranges), maxBlocked)
	}
	last := maxBlocked - 1
	if ranges[0] != "11.0.0.0/32" || ranges[last] != netip.PrefixFrom(netip.AddrFrom4([4]byte{11, 0, byte(last >> 8), byte(last)}), 32).String() {
		t.Errorf("the cap must keep the first entries in order: %s … %s", ranges[0], ranges[maxBlocked-1])
	}
	_, dropped := filterBlocked(base)
	if len(dropped) != 50 || !strings.Contains(dropped[0].why, "11000") {
		t.Errorf("dropped %d past the cap (%v)", len(dropped), dropped[:min(len(dropped), 1)])
	}
}

// Refuse0RTT refuses QUIC 0-RTT without trusted proxies; the boot floor leaves the field out and
// serves no HTTP/3 (Caddy applies allow_0rtt only when it opens the QUIC listener), and drops the
// block list.
func TestRenderRefuse0RTT(t *testing.T) {
	base, routes, certOnly := goldenFixture()
	base.Refuse0RTT = true
	base.Blocked = prefixes("192.0.2.1/32")
	out, err := Render(base, routes, certOnly)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Apps struct {
			HTTP struct {
				Servers map[string]map[string]json.RawMessage `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	srv := doc.Apps.HTTP.Servers["edge"]
	if got := string(srv["allow_0rtt"]); got != "false" {
		t.Errorf("allow_0rtt = %q, want false", got)
	}
	for _, k := range []string{"protocols", "trusted_proxies", "client_ip_headers"} {
		if _, ok := srv[k]; ok {
			t.Errorf("%s must not render for Refuse0RTT alone", k)
		}
	}
	floor := BootFloor(base)
	if !floor.NoHTTP3 || floor.Refuse0RTT || floor.Blocked != nil {
		t.Errorf("BootFloor = NoHTTP3 %v Refuse0RTT %v Blocked %v", floor.NoHTTP3, floor.Refuse0RTT, floor.Blocked)
	}
	if !base.Refuse0RTT || len(base.Blocked) != 1 {
		t.Error("BootFloor must not modify its argument")
	}
	fout, err := Render(floor, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := string(fout)
	if strings.Contains(s, "allow_0rtt") || strings.Contains(s, "192.0.2.1") || !strings.Contains(s, `"h1"`) {
		t.Errorf("boot floor with Refuse0RTT:\n%s", s)
	}
}

func TestCDNRanges(t *testing.T) {
	got := CDNRanges()
	if len(got) != len(cloudflareRanges) {
		t.Fatalf("CDNRanges has %d ranges, want %d", len(got), len(cloudflareRanges))
	}
	for i, p := range got {
		if p.String() != cloudflareRanges[i] {
			t.Errorf("CDNRanges[%d] = %s, want %s", i, p, cloudflareRanges[i])
		}
	}
	got[0] = netip.Prefix{}
	if CDNRanges()[0] != netip.MustParsePrefix(cloudflareRanges[0]) {
		t.Error("CDNRanges must return a copy")
	}
}

// The reconciler renders the block list hook's snapshot on every reconcile, pushes a changed list,
// skips an unchanged one, and reports a left-out entry to the drop hook once while it stays left out.
func TestReconcilerBlocklistAndDrops(t *testing.T) {
	rec, body, loads, done := newRecWithRoute(t, "172.18.0.5:8080", "http")
	defer done()
	rec.base.AdminAllowlist = []string{"203.0.113.0/24"}
	var list atomic.Pointer[[]netip.Prefix]
	set := func(ps ...string) { l := prefixes(ps...); list.Store(&l) }
	set("198.51.100.9/32", "203.0.113.7/32")
	rec.SetBlocklist(func() []netip.Prefix { return *list.Load() })
	var mu sync.Mutex
	var reports []string
	rec.SetBlockDrop(func(p netip.Prefix, why string) {
		mu.Lock()
		reports = append(reports, p.String()+" "+why)
		mu.Unlock()
	})
	ctx := context.Background()
	if err := rec.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if s := string(*body); !strings.Contains(s, `"198.51.100.9/32"`) || strings.Contains(s, "203.0.113.7") {
		t.Fatalf("pushed config must deny only 198.51.100.9:\n%s", s)
	}
	if err := rec.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt32(loads); n != 1 {
		t.Errorf("an unchanged list must not /load again (%d loads)", n)
	}
	set("198.51.100.10/32", "203.0.113.7/32")
	if err := rec.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if n := atomic.LoadInt32(loads); n != 2 || !strings.Contains(string(*body), `"198.51.100.10/32"`) {
		t.Errorf("a changed list must be pushed (%d loads):\n%s", n, *body)
	}
	mu.Lock()
	got := slices.Clone(reports)
	mu.Unlock()
	if want := []string{"203.0.113.7/32 overlaps ip_allowlist"}; !reflect.DeepEqual(got, want) {
		t.Errorf("drop reports = %v, want %v (once)", got, want)
	}
	// Left out again after it was back in: reported again.
	set("198.51.100.10/32")
	_ = rec.Reconcile(ctx)
	set("203.0.113.7/32")
	_ = rec.Reconcile(ctx)
	mu.Lock()
	n := len(reports)
	mu.Unlock()
	if n != 2 {
		t.Errorf("an entry left out again must be reported again: %d reports", n)
	}
}

// FuzzRenderBlocked: arbitrary block list entries never fail the render, every rendered range is a
// canonical range BlockAllowed accepts and that was asked for, ranges are sorted and unique and at most
// maxBlocked, no ip_allowlist / trusted proxy / CDN address is ever in the deny route, and the admin
// vhost stays the first route with the deny route right after it.
func FuzzRenderBlocked(f *testing.F) {
	// Seeds (see fuzzPrefixes: an IPv4 bit byte b is /(b%40-4), IPv6 /(b%140-6), mapped /(96+b%40)):
	// an allowlisted address next to a blockable one; an allowlisted and a blockable IPv6 /64; an
	// IPv4-mapped /128 and a plain address; trusted proxies with a CDN address, a /24 and an
	// unmasked range; trusted proxies with an address inside one of them; no trusted proxies with a
	// CDN address and two blockable addresses out of order.
	f.Add([]byte{0, 203, 0, 113, 7, 36, 0, 198, 51, 100, 9, 36})
	f.Add([]byte{0, 104, 16, 0, 1, 36, 0, 9, 9, 9, 9, 36, 0, 8, 8, 8, 8, 36})
	f.Add([]byte{1, 0x20, 0x01, 0x0d, 0xb8, 0xaa, 0xaa, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 70,
		1, 0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 70})
	f.Add([]byte{2, 1, 2, 3, 4, 32, 3, 9, 32, 0, 10, 36})
	f.Add([]byte{4, 104, 16, 0, 1, 36, 0, 192, 0, 2, 0, 28, 0, 1, 2, 3, 4, 11})
	f.Add([]byte{4, 198, 51, 100, 7, 36, 0, 8, 8, 8, 8, 36})
	f.Fuzz(func(t *testing.T, data []byte) {
		base := adminBase()
		if len(data) > 0 && data[0]&4 != 0 {
			base.TrustedProxies = []string{"cloudflare", "198.51.100.0/24"}
		}
		asked := fuzzPrefixes(data)
		base.Blocked = asked
		out, err := Render(base, []Route{pooledRoute("app.example.com")}, nil)
		if err != nil {
			t.Fatalf("render failed: %v", err)
		}
		rs := blockRoutes(t, out)
		if len(rs) < 2 || len(rs[0].Match) != 1 || !reflect.DeepEqual(rs[0].Match[0].Host, []string{"admin.example.com"}) {
			t.Fatalf("the admin vhost must be the first route:\n%s", out)
		}
		protected := []netip.Prefix{}
		for _, s := range base.AdminAllowlist {
			p, _ := parseAllowEntry(s)
			protected = append(protected, p)
		}
		for _, e := range base.TrustedProxies {
			ps, _ := ParseTrustedProxy(e)
			protected = append(protected, ps...)
		}
		protected = append(protected, CDNRanges()...)
		for i, r := range rs {
			ranges, deny := isDenyRoute(r)
			if !deny {
				continue
			}
			if i != 1 {
				t.Fatalf("deny route at %d, want 1", i)
			}
			if len(ranges) > maxBlocked {
				t.Fatalf("%d ranges, cap %d", len(ranges), maxBlocked)
			}
			if (len(base.TrustedProxies) > 0) != (r.Match[0].ClientIP != nil) {
				t.Fatalf("matcher must be client_ip exactly when proxies are trusted")
			}
			var prev netip.Prefix
			for j, s := range ranges {
				p, err := netip.ParsePrefix(s)
				if err != nil || p != p.Masked() || p.Addr().Is4In6() || p.String() != s {
					t.Fatalf("non-canonical range %q", s)
				}
				if j > 0 && comparePrefix(prev, p) >= 0 {
					t.Fatalf("ranges not sorted and unique: %s then %s", prev, p)
				}
				prev = p
				if err := BlockAllowed(base, p); err != nil {
					t.Fatalf("rendered %s that BlockAllowed refuses: %v", p, err)
				}
				if overlapsAny(p, protected) {
					t.Fatalf("rendered %s, which overlaps a protected range", p)
				}
				if !slices.Contains(asked, p) {
					t.Fatalf("rendered %s, which was not in the list", p)
				}
			}
		}
	})
}

// fuzzPrefixes decodes fuzz data into prefixes of every shape: IPv4, IPv6 and IPv4-mapped addresses,
// any (also invalid) bit count, unmasked.
func fuzzPrefixes(data []byte) []netip.Prefix {
	var out []netip.Prefix
	for len(data) > 0 && len(out) < 256 {
		kind := data[0] % 4
		data = data[1:]
		switch kind {
		case 0, 3:
			if len(data) < 5 {
				return out
			}
			a := netip.AddrFrom4([4]byte(data[:4]))
			out = append(out, netip.PrefixFrom(a, int(data[4])%40-4))
			data = data[5:]
		case 1:
			if len(data) < 17 {
				return out
			}
			a := netip.AddrFrom16([16]byte(data[:16]))
			out = append(out, netip.PrefixFrom(a, int(data[16])%140-6))
			data = data[17:]
		case 2:
			if len(data) < 5 {
				return out
			}
			a := netip.AddrFrom16(netip.AddrFrom4([4]byte(data[:4])).As16())
			out = append(out, netip.PrefixFrom(a, 96+int(data[4])%40))
			data = data[5:]
		}
	}
	return out
}
