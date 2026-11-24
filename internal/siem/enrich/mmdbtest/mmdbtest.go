// Package mmdbtest writes small MaxMind DB files (format 2.0) for tests: an IPv6 search tree with
// IPv4 networks in its ::/96 subtree, a data section of one record per network, and the metadata.
// Only tests import it.
package mmdbtest

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"
	"sort"
)

// Network is one network and its record.
type Network struct {
	Prefix string // "203.0.113.0/24" or "2001:db8::/32"
	Data   map[string]any
}

// Options are the metadata.
type Options struct {
	DatabaseType string // e.g. "DBIP-City-Lite"
	BuildEpoch   uint64
	// NodeCountDelta is added to the metadata's node_count (a corrupt file); 0 for a valid one.
	NodeCountDelta int
}

// CityEntry is one network of a City database.
type CityEntry struct {
	Prefix, City, Country string
	Lat, Lon              float64
}

// ASNEntry is one network of an ASN database.
type ASNEntry struct {
	Prefix string
	ASN    uint32
	Org    string
}

// City writes a City database (DatabaseType "DBIP-City-Lite") in DB-IP's record layout.
func City(entries ...CityEntry) []byte {
	nets := make([]Network, 0, len(entries))
	for _, e := range entries {
		nets = append(nets, Network{Prefix: e.Prefix, Data: map[string]any{
			"city":      map[string]any{"names": map[string]any{"en": e.City, "de": e.City + " (de)"}},
			"continent": map[string]any{"code": "AF"},
			"country":   map[string]any{"iso_code": e.Country, "is_in_european_union": false},
			"location":  map[string]any{"latitude": e.Lat, "longitude": e.Lon},
		}})
	}
	return Write(Options{DatabaseType: "DBIP-City-Lite", BuildEpoch: 1793500000}, nets)
}

// ASN writes an ASN database (DatabaseType "DBIP-ASN-Lite (compat=GeoLite2-ASN)").
func ASN(entries ...ASNEntry) []byte {
	nets := make([]Network, 0, len(entries))
	for _, e := range entries {
		nets = append(nets, Network{Prefix: e.Prefix, Data: map[string]any{
			"autonomous_system_number":       e.ASN,
			"autonomous_system_organization": e.Org,
		}})
	}
	return Write(Options{DatabaseType: "DBIP-ASN-Lite (compat=GeoLite2-ASN)", BuildEpoch: 1793500000}, nets)
}

type node struct {
	child [2]*node
	data  [2]int // data record index + 1 (0: none)
}

// Write encodes nets (non-overlapping prefixes) as a MaxMind DB with 24-bit records. It panics on
// a bad or overlapping prefix: test input only.
func Write(opt Options, nets []Network) []byte {
	root := &node{}
	var data bytes.Buffer
	var offsets []int
	for i, n := range nets {
		p := netip.MustParsePrefix(n.Prefix).Masked()
		a, bits := p.Addr(), p.Bits()
		if a.Is4() {
			a, bits = netip.AddrFrom16(a.As16()), bits+96 // ::a.b.c.d, not ::ffff:a.b.c.d
			b := a.As16()
			for j := 10; j < 12; j++ {
				b[j] = 0
			}
			a = netip.AddrFrom16(b)
		}
		if bits == 0 {
			panic("mmdbtest: a /0 network")
		}
		ip := a.As16()
		cur := root
		for d := 0; d < bits; d++ {
			bit := ip[d/8] >> (7 - d%8) & 1
			if cur.data[bit] != 0 {
				panic(fmt.Sprintf("mmdbtest: %s overlaps an earlier network", n.Prefix))
			}
			if d == bits-1 {
				if cur.child[bit] != nil {
					panic(fmt.Sprintf("mmdbtest: %s overlaps an earlier network", n.Prefix))
				}
				cur.data[bit] = i + 1
				break
			}
			if cur.child[bit] == nil {
				cur.child[bit] = &node{}
			}
			cur = cur.child[bit]
		}
		offsets = append(offsets, data.Len())
		encode(&data, n.Data)
	}
	// Breadth-first numbering, root = 0.
	order := []*node{root}
	index := map[*node]int{root: 0}
	for i := 0; i < len(order); i++ {
		for _, c := range order[i].child {
			if c != nil {
				index[c] = len(order)
				order = append(order, c)
			}
		}
	}
	count := len(order)
	var out bytes.Buffer
	rec := func(n *node, side int) uint32 {
		switch {
		case n.child[side] != nil:
			return uint32(index[n.child[side]])
		case n.data[side] != 0:
			return uint32(count + 16 + offsets[n.data[side]-1])
		}
		return uint32(count)
	}
	for _, n := range order {
		for side := 0; side < 2; side++ {
			v := rec(n, side)
			if v >= 1<<24 {
				panic("mmdbtest: too large for 24-bit records")
			}
			out.Write([]byte{byte(v >> 16), byte(v >> 8), byte(v)})
		}
	}
	out.Write(make([]byte, 16))
	out.Write(data.Bytes())
	out.WriteString("\xAB\xCD\xEFMaxMind.com")
	encode(&out, map[string]any{
		"binary_format_major_version": uint16(2),
		"binary_format_minor_version": uint16(0),
		"build_epoch":                 opt.BuildEpoch,
		"database_type":               opt.DatabaseType,
		"description":                 map[string]any{"en": "mmdbtest " + opt.DatabaseType},
		"ip_version":                  uint16(6),
		"languages":                   []any{"en", "de"},
		"node_count":                  uint32(count + opt.NodeCountDelta),
		"record_size":                 uint16(24),
	})
	return out.Bytes()
}

// Data types of the format.
const (
	tString = 2
	tDouble = 3
	tUint16 = 5
	tUint32 = 6
	tMap    = 7
	tUint64 = 9
	tArray  = 11
	tBool   = 14
)

func ctrl(b *bytes.Buffer, typ, size int) {
	var first byte
	if typ <= 7 {
		first = byte(typ) << 5
	}
	var extra []byte
	switch {
	case size < 29:
		first |= byte(size)
	case size < 29+256:
		first |= 29
		extra = []byte{byte(size - 29)}
	case size < 285+65536:
		first |= 30
		s := size - 285
		extra = []byte{byte(s >> 8), byte(s)}
	default:
		first |= 31
		s := size - 65821
		extra = []byte{byte(s >> 16), byte(s >> 8), byte(s)}
	}
	b.WriteByte(first)
	if typ > 7 {
		b.WriteByte(byte(typ - 7))
	}
	b.Write(extra)
}

func uintBytes(v uint64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	i := 0
	for i < 8 && buf[i] == 0 {
		i++
	}
	return buf[i:]
}

func encode(b *bytes.Buffer, v any) {
	switch t := v.(type) {
	case string:
		ctrl(b, tString, len(t))
		b.WriteString(t)
	case float64:
		ctrl(b, tDouble, 8)
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], math.Float64bits(t))
		b.Write(buf[:])
	case uint16:
		u := uintBytes(uint64(t))
		ctrl(b, tUint16, len(u))
		b.Write(u)
	case uint32:
		u := uintBytes(uint64(t))
		ctrl(b, tUint32, len(u))
		b.Write(u)
	case uint64:
		u := uintBytes(t)
		ctrl(b, tUint64, len(u))
		b.Write(u)
	case bool:
		n := 0
		if t {
			n = 1
		}
		ctrl(b, tBool, n)
	case []any:
		ctrl(b, tArray, len(t))
		for _, e := range t {
			encode(b, e)
		}
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		ctrl(b, tMap, len(keys))
		for _, k := range keys {
			encode(b, k)
			encode(b, t[k])
		}
	default:
		panic(fmt.Sprintf("mmdbtest: can't encode %T", v))
	}
}
