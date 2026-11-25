package blocklist

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"
)

// parsePrefix reads a request's prefix in canonical form: a bare address is a /32 or /128,
// IPv4-mapped IPv6 is IPv4, and the host bits are masked. A zone is refused.
func parsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 64 {
		return netip.Prefix{}, errors.New("not an address or CIDR")
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		a, aerr := netip.ParseAddr(s)
		if aerr != nil || a.Zone() != "" {
			return netip.Prefix{}, errors.New("not an address or CIDR")
		}
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	if p.Addr().Is4In6() {
		bits := p.Bits() - 96
		if bits < 0 {
			return netip.Prefix{}, errors.New("not an address or CIDR")
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), bits)
	}
	return p.Masked(), nil
}

// canon is p in canonical form (IPv4-mapped as IPv4, masked); the zero Prefix when p is invalid.
func canon(p netip.Prefix) netip.Prefix {
	if !p.IsValid() {
		return netip.Prefix{}
	}
	if p.Addr().Is4In6() {
		if p.Bits() < 96 {
			return netip.Prefix{}
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p.Masked()
}

var (
	all4 = netip.PrefixFrom(netip.IPv4Unspecified(), 0)
	all6 = netip.PrefixFrom(netip.IPv6Unspecified(), 0)
)

// maxOddLogged bounds the guard entries remembered as logged.
const maxOddLogged = 256

// canonGuard is the protected entries ps (of the guard part what) in canonical form. Intentional:
// an entry with no canonical form is never dropped, it protects more instead (fail closed) — an
// IPv4-mapped range wider than /96 contains every IPv4 address, so it protects all of IPv4; an
// invalid entry protects everything. Each is logged once.
func (b *Blocker) canonGuard(what string, ps []netip.Prefix) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ps))
	for _, p := range ps {
		if c := canon(p); c.IsValid() {
			out = append(out, c)
			continue
		}
		covers := "every address"
		if p.IsValid() {
			out = append(out, all4)
			covers = "every IPv4 address"
		} else {
			out = append(out, all4, all6)
		}
		key := what + " " + p.String()
		b.oddMu.Lock()
		_, seen := b.odd[key]
		switch {
		case seen:
		case len(b.odd) >= maxOddLogged:
			seen = true // enough of them logged
		default:
			if b.odd == nil {
				b.odd = map[string]struct{}{}
			}
			b.odd[key] = struct{}{}
		}
		b.oddMu.Unlock()
		if !seen {
			b.log.Warn("blocklist: a protected entry has no canonical form; blocks it might cover are refused", "kind", what, "entry", p.String(), "protects", covers)
		}
	}
	return out
}

// widthOK reports whether p is a prefix source may block: automatic, a single IPv4 address or an
// IPv6 /64; manual, up to /24 (IPv4) or /48 (IPv6).
func widthOK(p netip.Prefix, source string) bool {
	if source == SourceAuto {
		return (p.Addr().Is4() && p.Bits() == 32) || (p.Addr().Is6() && p.Bits() == 64)
	}
	return (p.Addr().Is4() && p.Bits() >= ManualIPv4Bits) || (p.Addr().Is6() && p.Bits() >= ManualIPv6Bits)
}

// localRanges4 are the IPv4 ranges never blocked: this network, private (RFC 1918), shared (CGNAT),
// loopback, link-local, multicast and reserved (with broadcast). IPv6 is blockable only inside
// global unicast 2000::/3, which leaves out unspecified, loopback, ULA, link-local and multicast.
// The edge renderer re-checks the same ranges (edge.BlockAllowed). The documentation ranges
// (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32) stay blockable.
var (
	localRanges4 = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("224.0.0.0/4"),
		netip.MustParsePrefix("240.0.0.0/4"),
	}
	globalUnicast6 = netip.MustParsePrefix("2000::/3")
)

func overlap(p netip.Prefix, set []netip.Prefix) (netip.Prefix, bool) {
	for _, q := range set {
		if p.Overlaps(q) {
			return q, true
		}
	}
	return netip.Prefix{}, false
}

// protSet is every protected address at one moment: the built-in ranges plus what Guard names.
type protSet struct {
	own, allow, tokens, proxies, cdn, configured, sessions []netip.Prefix
}

// staticGuard is the part of Guard that doesn't change while Mooring runs, canonical.
type staticGuard struct {
	proxies, cdn, configured []netip.Prefix
}

// sessionTimeout bounds Guard.Sessions.
const sessionTimeout = 5 * time.Second

// protected reads the protected set now. The guard funcs are called on a context of their own: a
// caller's cancelled context must not make Sessions return nothing (and so protect nothing).
func (b *Blocker) protected(ctx context.Context) protSet {
	g := b.o.Guard
	ps := protSet{proxies: b.static.proxies, cdn: b.static.cdn, configured: b.static.configured}
	if own := b.self.Load(); own != nil {
		ps.own = *own
	}
	if g.Allowlist != nil {
		ps.allow = b.canonGuard("ip_allowlist", g.Allowlist())
	}
	if g.TokenCIDRs != nil {
		ps.tokens = b.canonGuard("API token range", g.TokenCIDRs())
	}
	if g.Sessions != nil {
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sessionTimeout)
		for _, a := range g.Sessions(sctx) {
			if a.IsValid() {
				a = a.Unmap().WithZone("")
				ps.sessions = append(ps.sessions, netip.PrefixFrom(a, a.BitLen()))
			}
		}
		cancel()
	}
	return ps
}

// covered returns the Refuse* code (and a detail safe to show) of the first protected address p
// overlaps, in either direction; "" when it overlaps none. self, when valid, is the requesting
// owner's own address (manual requests only).
func (ps protSet) covered(p netip.Prefix, self netip.Addr) (code, detail string) {
	a := p.Addr()
	if _, ok := overlap(p, localRanges4); ok || (a.Is6() && !globalUnicast6.Contains(a)) {
		return RefuseLocal, "a loopback, private, link-local, shared, multicast or reserved address range"
	}
	if _, ok := overlap(p, ps.own); ok {
		return RefuseLocal, "this server's own address"
	}
	if self.IsValid() && p.Contains(self) {
		return RefuseSelf, "covers your own address"
	}
	if q, ok := overlap(p, ps.allow); ok {
		return RefuseAllowlist, "overlaps ip_allowlist entry " + q.String()
	}
	if q, ok := overlap(p, ps.tokens); ok {
		return RefuseTokenCIDR, "overlaps an API token's allowed range " + q.String()
	}
	if q, ok := overlap(p, ps.proxies); ok {
		return RefuseProxy, "overlaps trusted proxy " + q.String()
	}
	if q, ok := overlap(p, ps.cdn); ok {
		return RefuseCDN, "overlaps CDN range " + q.String()
	}
	if q, ok := overlap(p, ps.configured); ok {
		return RefuseNeverBlock, "overlaps never_block entry " + q.String()
	}
	if _, ok := overlap(p, ps.sessions); ok {
		return RefuseSession, "covers the address of a signed-in dashboard session"
	}
	return "", ""
}

// This server's own addresses, from /proc (the service can't list interfaces over netlink). Off
// Linux the files don't exist and none are known.
var (
	procFibTrie = "/proc/net/fib_trie"
	procIfInet6 = "/proc/net/if_inet6"
)

const (
	maxOwnAddrs = 4096
	maxProcRead = 64 << 20 // a host with a full routing table has a large fib_trie
)

// refreshSelf re-reads this server's own addresses.
func (b *Blocker) refreshSelf() {
	own := ownAddrs(procFibTrie, procIfInet6)
	b.self.Store(&own)
}

// ownAddrs reads the IPv4 addresses of the local routing table (`/32 host LOCAL` leaves of
// fib_trie) and the IPv6 interface addresses (if_inet6), as /32 and /128 prefixes.
func ownAddrs(fibTrie, ifInet6 string) []netip.Prefix {
	seen := map[netip.Addr]bool{}
	var out []netip.Prefix
	add := func(a netip.Addr) {
		a = a.Unmap()
		if !a.IsValid() || seen[a] || len(out) >= maxOwnAddrs {
			return
		}
		seen[a] = true
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	var leaf netip.Addr
	scan(fibTrie, func(line string) {
		// "|-- 203.0.113.7" names a leaf; a following "/32 host LOCAL" makes it a local address.
		t := strings.TrimSpace(line)
		if s, ok := strings.CutPrefix(t, "|-- "); ok {
			leaf, _ = netip.ParseAddr(strings.TrimSpace(s))
			return
		}
		if strings.HasPrefix(t, "/32 host LOCAL") && leaf.Is4() {
			add(leaf)
		}
	})
	scan(ifInet6, func(line string) {
		f := strings.Fields(line)
		if len(f) == 0 || len(f[0]) != 32 {
			return
		}
		raw, err := hex.DecodeString(f[0])
		if err != nil {
			return
		}
		add(netip.AddrFrom16([16]byte(raw)))
	})
	return out
}

func scan(path string, fn func(string)) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(io.LimitReader(f, maxProcRead))
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	for sc.Scan() {
		fn(sc.Text())
	}
}
