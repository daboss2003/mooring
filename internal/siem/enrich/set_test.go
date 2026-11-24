package enrich

import (
	"math/rand/v2"
	"net/netip"
	"testing"
)

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

func rng(from, to string) Range { return Range{From: addr(from), To: addr(to)} }

func pfx(s string) Range { return PrefixRange(netip.MustParsePrefix(s)) }

// Range edges are inclusive, for IPv4 and IPv6; one address past either end is out.
func TestSetRangeEdges(t *testing.T) {
	s := NewSet([]Range{
		pfx("203.0.112.0/24"),
		rng("198.51.100.10", "198.51.100.20"),
		rng("192.0.2.7", "192.0.2.7"),
		pfx("2001:db8:1::/48"),
		rng("2001:db8:2::5", "2001:db8:2::9"),
		pfx("0.0.0.0/32"), // the very first address
		pfx("255.255.255.255/32"),
		pfx("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"),
	}, nil)
	in := []string{"203.0.112.0", "203.0.112.255", "203.0.112.77", "198.51.100.10", "198.51.100.20", "198.51.100.15",
		"192.0.2.7", "2001:db8:1::", "2001:db8:1:ffff:ffff:ffff:ffff:ffff", "2001:db8:2::5", "2001:db8:2::9",
		"0.0.0.0", "255.255.255.255", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"}
	out := []string{"203.0.111.255", "203.0.113.0", "198.51.100.9", "198.51.100.21", "192.0.2.6", "192.0.2.8",
		"2001:db8::ffff:ffff:ffff:ffff:ffff", "2001:db8:2::", "2001:db8:2::4", "2001:db8:2::a", "0.0.0.1", "255.255.255.254",
		"::", "::cb00:7000"} // ::203.0.112.0 is IPv6, not the IPv4 address
	for _, a := range in {
		if !s.Contains(addr(a)) {
			t.Errorf("%s: not found, want in", a)
		}
	}
	for _, a := range out {
		if s.Contains(addr(a)) {
			t.Errorf("%s: found, want out", a)
		}
	}
}

// An IPv4-mapped IPv6 address is looked up as its IPv4 address, and a range written with mapped
// addresses is an IPv4 range.
func TestSetV4Mapped(t *testing.T) {
	s := NewSet([]Range{pfx("203.0.113.0/24"), rng("::ffff:198.51.100.0", "::ffff:198.51.100.255")}, nil)
	for _, a := range []string{"::ffff:203.0.113.9", "203.0.113.9", "198.51.100.1", "::ffff:198.51.100.1"} {
		if !s.Contains(addr(a)) {
			t.Errorf("%s: not found", a)
		}
	}
	if s.Contains(addr("::ffff:203.0.114.0")) || s.Contains(addr("203.0.114.0")) {
		t.Error("an address past the range was found")
	}
}

// Invalid ranges are skipped: reversed, mixed families, zero addresses, zones.
func TestSetSkipsInvalidRanges(t *testing.T) {
	s := NewSet([]Range{
		rng("203.0.113.20", "203.0.113.10"),
		rng("203.0.113.1", "2001:db8::1"),
		{},
		{From: addr("203.0.113.1")},
		rng("fe80::1%eth0", "fe80::9%eth0"),
		pfx("198.51.100.0/24"),
	}, nil)
	if s.Len() != 1 {
		t.Errorf("Len %d, want only the one valid range", s.Len())
	}
	for _, a := range []string{"203.0.113.15", "203.0.113.1", "fe80::5"} {
		if s.Contains(addr(a)) {
			t.Errorf("%s found through an invalid range", a)
		}
	}
	if !s.Contains(addr("198.51.100.5")) {
		t.Error("the valid range was lost")
	}
}

// Overlapping and adjacent ranges in any order merge; lookups stay exact.
func TestSetMergesOverlaps(t *testing.T) {
	s := NewSet([]Range{
		rng("10.0.0.50", "10.0.0.60"),
		rng("10.0.0.0", "10.0.0.10"),
		rng("10.0.0.5", "10.0.0.20"),
		rng("10.0.0.21", "10.0.0.30"), // adjacent: merges
		rng("10.0.0.40", "10.0.0.55"),
		rng("10.0.0.0", "10.0.0.10"), // duplicate
	}, nil)
	got := s.Ranges()
	want := []Range{rng("10.0.0.0", "10.0.0.30"), rng("10.0.0.40", "10.0.0.60")}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("merged %v, want %v", got, want)
	}
	for a, in := range map[string]bool{"10.0.0.30": true, "10.0.0.31": false, "10.0.0.39": false, "10.0.0.40": true, "10.0.0.61": false} {
		if s.Contains(addr(a)) != in {
			t.Errorf("%s: Contains %v, want %v", a, !in, in)
		}
	}
}

// Random sets agree with a linear scan.
func TestSetMatchesLinearScan(t *testing.T) {
	r := rand.New(rand.NewPCG(1, 2))
	for round := 0; round < 50; round++ {
		var ranges []Range
		for i := 0; i < 1+r.IntN(40); i++ {
			lo := r.Uint32N(5000)
			hi := lo + r.Uint32N(300)
			if r.IntN(10) == 0 {
				hi = lo
			}
			ranges = append(ranges, Range{From: v4(lo), To: v4(hi)})
			b := [16]byte{0x20, 0x01, 0x0d, 0xb8}
			b[14], b[15] = byte(lo>>8), byte(lo)
			e := b
			e[14], e[15] = byte(hi>>8), byte(hi)
			ranges = append(ranges, Range{From: netip.AddrFrom16(b), To: netip.AddrFrom16(e)})
		}
		s := NewSet(ranges, nil)
		for x := uint32(0); x < 5400; x += 7 {
			for _, a := range []netip.Addr{v4(x), v6low(x)} {
				want := false
				for _, rg := range ranges {
					if rg.From.BitLen() == a.BitLen() && rg.From.Compare(a) <= 0 && a.Compare(rg.To) <= 0 {
						want = true
						break
					}
				}
				if got := s.Contains(a); got != want {
					t.Fatalf("round %d: %s Contains %v, want %v", round, a, got, want)
				}
			}
		}
	}
}

func v4(x uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{198, byte(x >> 16), byte(x >> 8), byte(x)})
}

func v6low(x uint32) netip.Addr {
	b := [16]byte{0x20, 0x01, 0x0d, 0xb8}
	b[14], b[15] = byte(x>>8), byte(x)
	return netip.AddrFrom16(b)
}

// The ASN set: membership, 0 never a member, duplicates counted once.
func TestSetASNs(t *testing.T) {
	s := NewSet(nil, []uint32{64500, 13335, 64500, 0, 4200000000})
	for asn, want := range map[uint32]bool{64500: true, 13335: true, 4200000000: true, 0: false, 64501: false, 1: false} {
		if s.HasASN(asn) != want {
			t.Errorf("HasASN(%d) = %v, want %v", asn, !want, want)
		}
	}
	if s.Len() != 3 {
		t.Errorf("Len %d, want 3", s.Len())
	}
	if got := s.ASNs(); len(got) != 3 || got[0] != 13335 || got[2] != 4200000000 {
		t.Errorf("ASNs %v", got)
	}
}

// A nil or empty Set contains nothing.
func TestSetNilAndEmpty(t *testing.T) {
	var nilSet *Set
	empty := NewSet(nil, nil)
	for _, s := range []*Set{nilSet, empty} {
		if s.Contains(addr("8.8.8.8")) || s.Contains(addr("2001:db8::1")) || s.HasASN(1) || s.Len() != 0 {
			t.Errorf("%v: not empty", s)
		}
	}
	if nilSet.Contains(netip.Addr{}) {
		t.Error("the zero address is in a nil set")
	}
}

// PrefixRange covers exactly the prefix, masked.
func TestPrefixRange(t *testing.T) {
	r := PrefixRange(netip.MustParsePrefix("203.0.113.77/24"))
	if r != rng("203.0.113.0", "203.0.113.255") {
		t.Errorf("v4: %v", r)
	}
	r = PrefixRange(netip.MustParsePrefix("2001:db8::/127"))
	if r != rng("2001:db8::", "2001:db8::1") {
		t.Errorf("v6: %v", r)
	}
	if r := PrefixRange(netip.Prefix{}); r.From.IsValid() || r.To.IsValid() {
		t.Errorf("invalid prefix gave %v", r)
	}
}
