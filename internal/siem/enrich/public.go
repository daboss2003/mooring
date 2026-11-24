package enrich

import "net/netip"

// nonPublic4 are the IPv4 special-purpose ranges that never belong to a client on the internet
// (RFC 6890 and its updates).
var nonPublic4 = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // this network
	netip.MustParsePrefix("10.0.0.0/8"),      // private
	netip.MustParsePrefix("100.64.0.0/10"),   // shared address space (CGNAT)
	netip.MustParsePrefix("127.0.0.0/8"),     // loopback
	netip.MustParsePrefix("169.254.0.0/16"),  // link-local
	netip.MustParsePrefix("172.16.0.0/12"),   // private
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation
	netip.MustParsePrefix("192.88.99.0/24"),  // 6to4 relay anycast (deprecated)
	netip.MustParsePrefix("192.168.0.0/16"),  // private
	netip.MustParsePrefix("198.18.0.0/15"),   // benchmarking
	netip.MustParsePrefix("198.51.100.0/24"), // documentation
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation
	netip.MustParsePrefix("224.0.0.0/4"),     // multicast
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, broadcast
}

// IPv6: only global unicast (2000::/3) can be public; these parts of it are not.
var (
	global6    = netip.MustParsePrefix("2000::/3")
	nonPublic6 = []netip.Prefix{
		netip.MustParsePrefix("2001::/23"),     // IETF protocol assignments (Teredo, benchmarking, ORCHID …)
		netip.MustParsePrefix("2001:db8::/32"), // documentation
		netip.MustParsePrefix("2002::/16"),     // 6to4
		netip.MustParsePrefix("3fff::/20"),     // documentation
	}
)

// Public reports whether ip is a public unicast address: not private, loopback, link-local, CGNAT,
// unique-local, multicast, unspecified, documentation or another special-purpose range. An
// IPv4-mapped IPv6 address is judged as its IPv4 address. Enrichment skips the others, and the
// feeds client refuses to dial them.
func Public(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" {
		return false
	}
	ip = ip.Unmap()
	if ip.Is4() {
		for _, p := range nonPublic4 {
			if p.Contains(ip) {
				return false
			}
		}
		return true
	}
	if !global6.Contains(ip) {
		return false
	}
	for _, p := range nonPublic6 {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}
