package blocklist

import (
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// A request's prefix is read canonically: bare addresses are /32 or /128, IPv4-mapped is IPv4, host
// bits are masked; zones, junk and impossible widths are refused.
func TestParsePrefix(t *testing.T) {
	ok := map[string]string{
		"203.0.113.7":            "203.0.113.7/32",
		" 203.0.113.7 ":          "203.0.113.7/32",
		"203.0.113.7/24":         "203.0.113.0/24",
		"::ffff:203.0.113.7":     "203.0.113.7/32",
		"::ffff:203.0.113.7/120": "203.0.113.0/24",
		"2001:db8:1:2::5/64":     "2001:db8:1:2::/64",
		"2001:db8:1:2::5":        "2001:db8:1:2::5/128",
		"2001:DB8:1:2::/64":      "2001:db8:1:2::/64",
	}
	for in, want := range ok {
		p, err := parsePrefix(in)
		if err != nil || p.String() != want {
			t.Errorf("parsePrefix(%q) = %v, %v; want %s", in, p, err, want)
		}
	}
	for _, in := range []string{"", "  ", "x", "fe80::1%eth0", "fe80::1%eth0/64", "1.2.3.4/33", "::ffff:1.2.3.4/90",
		"1.2.3.4/-1", "1.2.3.4/032", "1.2.3", strings.Repeat("1", 65), "203.0.113.7;"} {
		if p, err := parsePrefix(in); err == nil {
			t.Errorf("parsePrefix(%q) = %v, want an error", in, p)
		}
	}
}

func TestWidths(t *testing.T) {
	cases := []struct {
		p      string
		src    string
		wantOK bool
	}{
		{"203.0.113.7/32", SourceAuto, true},
		{"203.0.113.6/31", SourceAuto, false},
		{"2001:db8:1:2::/64", SourceAuto, true},
		{"2001:db8:1:2::5/128", SourceAuto, false},
		{"2001:db8:1::/48", SourceAuto, false},
		{"203.0.113.0/24", SourceManual, true},
		{"203.0.112.0/23", SourceManual, false},
		{"203.0.113.7/32", SourceManual, true},
		{"2001:db8:1::/48", SourceManual, true},
		{"2001:db8::/47", SourceManual, false},
		{"2001:db8:1:2::5/128", SourceManual, true},
	}
	for _, c := range cases {
		if got := widthOK(netip.MustParsePrefix(c.p), c.src); got != c.wantOK {
			t.Errorf("widthOK(%s, %s) = %v, want %v", c.p, c.src, got, c.wantOK)
		}
	}
}

// This server's own addresses: the `/32 host LOCAL` leaves of fib_trie (each once) and the
// addresses in if_inet6; a malformed line is skipped, missing files give none.
func TestOwnAddrsFromProc(t *testing.T) {
	got := ownAddrs(filepath.Join("testdata", "fib_trie"), filepath.Join("testdata", "if_inet6"))
	want := pfx("10.0.0.5/32", "127.0.0.1/32", "198.51.100.200/32", "::1/128", "2001:db8:ffff:1::5/128", "fe80::1/128")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ownAddrs = %v\nwant       %v", got, want)
	}
	if got := ownAddrs(filepath.Join("testdata", "missing"), filepath.Join("testdata", "missing")); len(got) != 0 {
		t.Errorf("missing files must give no addresses, got %v", got)
	}
}

// Every guard refusal code, with overlap checked in both directions.
func TestGuardRefusals(t *testing.T) {
	h := newHarness(t)
	h.g.tokens = pfx("198.51.100.32/28")
	h.g.sessions = []netip.Addr{netip.MustParseAddr("192.0.2.50"), netip.MustParseAddr("::ffff:192.0.2.60")}
	hour := time.Hour
	cases := []struct {
		name   string
		manual bool
		prefix string
		self   string
		code   string
	}{
		{"private", false, "10.1.2.3", "", RefuseLocal},
		{"loopback", false, "127.0.0.1", "", RefuseLocal},
		{"cgnat", false, "100.64.0.9", "", RefuseLocal},
		{"link-local", false, "169.254.1.1", "", RefuseLocal},
		{"multicast", false, "224.0.0.1", "", RefuseLocal},
		{"broadcast", false, "255.255.255.255", "", RefuseLocal},
		{"unspecified", false, "0.0.0.0", "", RefuseLocal},
		{"ula", false, "fd00:1:2:3::/64", "", RefuseLocal},
		{"ipv6 link-local", false, "fe80::/64", "", RefuseLocal},
		{"ipv6 multicast", false, "ff02::/64", "", RefuseLocal},
		{"private range manual", true, "172.16.5.0/24", "", RefuseLocal},
		{"own IPv4 (/proc)", false, "198.51.100.200", "", RefuseLocal},
		{"own IPv6 (/proc) in the /64", false, "2001:db8:ffff:1::/64", "", RefuseLocal},
		{"range containing own", true, "198.51.100.0/24", "", RefuseLocal},
		{"self", true, "198.51.100.0/27", "198.51.100.9", RefuseSelf},
		{"allowlist: address inside", false, "203.0.113.9", "", RefuseAllowlist},
		{"allowlist: range containing it", true, "203.0.113.0/24", "", RefuseAllowlist},
		{"token CIDR inside a manual range", true, "198.51.100.32/27", "", RefuseTokenCIDR},
		{"token CIDR address", false, "198.51.100.33", "", RefuseTokenCIDR},
		{"trusted proxy", false, "192.0.2.200", "", RefuseProxy},
		{"range containing a proxy", true, "192.0.2.0/24", "", RefuseProxy},
		{"cdn", false, "104.16.1.1", "", RefuseCDN},
		{"cdn ipv6", false, "2606:4700:1:2::/64", "", RefuseCDN},
		{"never_block", false, "198.51.100.70", "", RefuseNeverBlock},
		{"session", false, "192.0.2.50", "", RefuseSession},
		{"session (IPv4-mapped)", true, "192.0.2.56/29", "", RefuseSession},
	}
	for _, c := range cases {
		var err error
		if c.manual {
			_, err = h.manual(c.prefix, hour, c.self)
		} else {
			_, err = h.auto(c.prefix, hour)
		}
		t.Run(c.name, func(t *testing.T) { refused(t, err, c.code) })
	}
	if len(h.b.Snapshot()) != 0 {
		t.Errorf("refused blocks must never be published: %v", h.b.Snapshot())
	}
	// The documentation ranges are blockable.
	for _, p := range []string{"192.0.2.1", "198.51.100.1", "2001:db8:1:2::/64"} {
		h.mustBlock(h.auto(p, hour))
	}
	h.mustBlock(h.manual("192.0.2.64/26", hour, "203.0.113.5"))
}

// The checks that come before the guard: source, prefix, width, the edge, Caddy and durations.
func TestRequestRefusals(t *testing.T) {
	h := newHarness(t)
	_, err := h.b.Block(t.Context(), Request{Prefix: "192.0.2.1", Source: "robot", Duration: time.Hour})
	refused(t, err, RefuseInvalid)
	_, err = h.auto("not-an-ip", time.Hour)
	refused(t, err, RefuseInvalid)
	_, err = h.auto("192.0.2.0/31", time.Hour)
	refused(t, err, RefuseWidth)
	_, err = h.manual("192.0.0.0/22", time.Hour, "")
	refused(t, err, RefuseWidth)
	_, err = h.manual("192.0.2.1", time.Minute, "")
	refused(t, err, RefuseDuration)
	_, err = h.manual("192.0.2.1", 31*24*time.Hour, "")
	refused(t, err, RefuseDuration)
	_, err = h.auto("192.0.2.1", 0)
	refused(t, err, RefuseDuration)

	h.caddy.Lock()
	h.caddy.ok, h.caddy.why = false, "running Caddy 2.10.2"
	h.caddy.Unlock()
	_, err = h.auto("192.0.2.1", time.Hour)
	refused(t, err, RefuseOldCaddy)
	h.mustBlock(h.manual("192.0.2.2", time.Hour, "")) // manual blocks don't need 0-RTT refused
	st := h.b.Status()
	if st.Automatic || !strings.Contains(st.AutomaticWhy, "2.10.2") {
		t.Errorf("status with an old Caddy: %+v", st)
	}

	off := newHarness(t, func(o *Options) { o.EdgeOwned = false })
	_, err = off.auto("192.0.2.1", time.Hour)
	refused(t, err, RefuseNoEdge)
	_, err = off.manual("192.0.2.1", time.Hour, "")
	refused(t, err, RefuseNoEdge)
	if st := off.b.Status(); st.EdgeOwned || st.Automatic || st.AutomaticWhy == "" {
		t.Errorf("status without the edge: %+v", st)
	}
}
