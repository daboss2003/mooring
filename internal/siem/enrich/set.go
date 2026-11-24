package enrich

import (
	"net/netip"
	"slices"
)

// Range is an inclusive address range of one family.
type Range struct{ From, To netip.Addr }

// PrefixRange is the range p covers (zero Range for an invalid prefix).
func PrefixRange(p netip.Prefix) Range {
	if !p.IsValid() {
		return Range{}
	}
	p = p.Masked()
	lo := p.Addr()
	b := lo.As16()
	host := 128 - p.Bits()
	if lo.Is4() {
		host = 32 - p.Bits()
	}
	for i := 15; i >= 0 && host > 0; i-- {
		n := min(host, 8)
		b[i] |= byte(1<<n - 1)
		host -= n
	}
	hi := netip.AddrFrom16(b)
	if lo.Is4() {
		hi = hi.Unmap()
	}
	return Range{From: lo, To: hi}
}

type span4 struct{ lo, hi uint32 }

type span6 struct{ lo, hi [16]byte }

// Set is a threat-intel list: address ranges (IPv4 and IPv6, sorted and merged, looked up by binary
// search) and autonomous system numbers. A Set never changes after NewSet, so lookups need no lock.
type Set struct {
	v4   []span4
	v6   []span6
	asns []uint32 // sorted, distinct, no 0
}

// NewSet builds a Set. Invalid ranges (an invalid or zoned address, From after To, two families)
// and ASN 0 are skipped; IPv4-mapped IPv6 ranges become IPv4 ranges; overlapping and adjacent
// ranges are merged.
func NewSet(ranges []Range, asns []uint32) *Set {
	s := &Set{}
	for _, r := range ranges {
		from, to := r.From.Unmap(), r.To.Unmap()
		if !from.IsValid() || !to.IsValid() || from.Zone() != "" || to.Zone() != "" ||
			from.Is4() != to.Is4() || from.Compare(to) > 0 {
			continue
		}
		if from.Is4() {
			s.v4 = append(s.v4, span4{lo: u32(from), hi: u32(to)})
		} else {
			s.v6 = append(s.v6, span6{lo: from.As16(), hi: to.As16()})
		}
	}
	slices.SortFunc(s.v4, func(a, b span4) int { return cmpU32(a.lo, b.lo) })
	s.v4 = merge4(s.v4)
	slices.SortFunc(s.v6, func(a, b span6) int { return cmp16(a.lo, b.lo) })
	s.v6 = merge6(s.v6)
	for _, a := range asns {
		if a != 0 {
			s.asns = append(s.asns, a)
		}
	}
	slices.Sort(s.asns)
	s.asns = slices.Compact(s.asns)
	return s
}

func merge4(in []span4) []span4 {
	out := in[:0]
	for _, r := range in {
		if n := len(out); n > 0 && (r.lo <= out[n-1].hi || out[n-1].hi != ^uint32(0) && r.lo == out[n-1].hi+1) {
			out[n-1].hi = max(out[n-1].hi, r.hi)
			continue
		}
		out = append(out, r)
	}
	return slices.Clip(out)
}

func merge6(in []span6) []span6 {
	out := in[:0]
	for _, r := range in {
		if n := len(out); n > 0 {
			last := &out[n-1]
			next, ok := inc16(last.hi)
			if cmp16(r.lo, last.hi) <= 0 || ok && next == r.lo {
				if cmp16(r.hi, last.hi) > 0 {
					last.hi = r.hi
				}
				continue
			}
		}
		out = append(out, r)
	}
	return slices.Clip(out)
}

// Contains reports whether ip is in one of the ranges (an IPv4-mapped address as its IPv4 address).
func (s *Set) Contains(ip netip.Addr) bool {
	if s == nil || !ip.IsValid() {
		return false
	}
	ip = ip.Unmap()
	if ip.Is4() {
		x := u32(ip)
		// The first range ending at or after x is the only one that can hold it (merged, sorted).
		i, _ := slices.BinarySearchFunc(s.v4, x, func(r span4, x uint32) int { return cmpU32(r.hi, x) })
		return i < len(s.v4) && s.v4[i].lo <= x
	}
	x := ip.As16()
	i, _ := slices.BinarySearchFunc(s.v6, x, func(r span6, x [16]byte) int { return cmp16(r.hi, x) })
	return i < len(s.v6) && cmp16(s.v6[i].lo, x) <= 0
}

// HasASN reports whether asn is on the list (0 never is).
func (s *Set) HasASN(asn uint32) bool {
	if s == nil || asn == 0 {
		return false
	}
	_, ok := slices.BinarySearch(s.asns, asn)
	return ok
}

// Len is the number of merged ranges plus ASNs.
func (s *Set) Len() int {
	if s == nil {
		return 0
	}
	return len(s.v4) + len(s.v6) + len(s.asns)
}

// Ranges returns the merged ranges, IPv4 first.
func (s *Set) Ranges() []Range {
	if s == nil {
		return nil
	}
	out := make([]Range, 0, len(s.v4)+len(s.v6))
	for _, r := range s.v4 {
		out = append(out, Range{From: from32(r.lo), To: from32(r.hi)})
	}
	for _, r := range s.v6 {
		out = append(out, Range{From: netip.AddrFrom16(r.lo), To: netip.AddrFrom16(r.hi)})
	}
	return out
}

// ASNs returns the ASNs, sorted.
func (s *Set) ASNs() []uint32 {
	if s == nil {
		return nil
	}
	return slices.Clone(s.asns)
}

func u32(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func from32(x uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(x >> 24), byte(x >> 16), byte(x >> 8), byte(x)})
}

func cmpU32(a, b uint32) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func cmp16(a, b [16]byte) int {
	for i := range a {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// inc16 is a+1; ok is false when a is the last address.
func inc16(a [16]byte) ([16]byte, bool) {
	for i := 15; i >= 0; i-- {
		a[i]++
		if a[i] != 0 {
			return a, true
		}
	}
	return a, false
}
