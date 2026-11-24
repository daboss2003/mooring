package feeds

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem/enrich"
)

// checkList is what every parsed list must satisfy: entries, and no range broader than allowed.
func checkList(t *testing.T, l list) {
	if l.entries < 1 || l.entries > maxEntries {
		t.Fatalf("entries %d", l.entries)
	}
	for _, r := range l.ranges {
		if !r.From.IsValid() || !r.To.IsValid() || r.From.Compare(r.To) > 0 || tooBroad(r) {
			t.Fatalf("bad range %v", r)
		}
	}
	for _, a := range l.asns {
		if a == 0 {
			t.Fatal("ASN 0")
		}
	}
}

func FuzzParseSpamhaus(f *testing.F) {
	f.Add([]byte(spamhausFile(`{"cidr":"1.10.16.0/20"}`, `{"cidr":"2001:678:254::/48"}`)), false)
	f.Add([]byte(spamhausFile(`{"asn":245}`)), true)
	f.Add([]byte(spamhausFile(`{"cidr":"::ffff:0.0.0.0/80"}`, `{"cidr":"0.0.0.0/0"}`)), false)
	f.Fuzz(func(t *testing.T, b []byte, asn bool) {
		if l, err := parseSpamhaus(b, asn); err == nil {
			checkList(t, l)
		}
	})
}

func FuzzParseTor(f *testing.F) {
	f.Add([]byte(torList(100, "# x", "2a0b:f4c2::1")))
	f.Fuzz(func(t *testing.T, b []byte) {
		if l, err := parseTor(b); err == nil {
			checkList(t, l)
		}
	})
}

func FuzzParseDShield(f *testing.F) {
	f.Add([]byte(dshieldSample))
	f.Fuzz(func(t *testing.T, b []byte) {
		if l, err := parseDShield(b); err == nil {
			checkList(t, l)
		}
	})
}

func FuzzDecodeSnapshot(f *testing.F) {
	b, _ := encodeSnapshot(NameTor, "2026-11-24T10:00Z", time.Unix(1795541204, 0),
		list{ranges: []enrich.Range{{From: mustAddr("185.220.0.1"), To: mustAddr("185.220.0.9")}}, asns: []uint32{245}, entries: 2})
	f.Add(b)
	for _, r := range []string{"::ffff:1.2.3.4-::1:0:0:0", "::ffff:0.0.0.0-ffff::", "1.0.0.0-1.255.255.255\",\"2.0.0.0-2.0.0.255"} {
		f.Add([]byte(`{"v":1,"name":"tor-exits","version":"2026-11-24T10:00Z","fetched":"2026-11-24T10:00:00Z","entries":1,"ranges":["` + r + `"]}`))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		snap, s, err := decodeSnapshot(b, NameTor)
		if err != nil {
			return
		}
		if snap.Name != NameTor || !versionRe.MatchString(snap.Version) || s.Len() == 0 {
			t.Fatalf("accepted %+v", snap)
		}
		// Every entry is within the bounds a parser allows (merged ranges may be broader).
		for _, e := range snap.Ranges {
			a, z, isRange := strings.Cut(e, "-")
			if !isRange {
				z = a
			}
			from, err1 := netip.ParseAddr(a)
			to, err2 := netip.ParseAddr(z)
			if r := (enrich.Range{From: from.Unmap(), To: to.Unmap()}); err1 != nil || err2 != nil || r.From.Compare(r.To) > 0 || tooBroad(r) {
				t.Fatalf("bad entry %q", e)
			}
		}
		for _, r := range s.Ranges() {
			if !r.From.IsValid() || r.From.Is4() != r.To.Is4() || r.From.Compare(r.To) > 0 {
				t.Fatalf("bad range %v", r)
			}
		}
	})
}

func mustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }
