package feeds

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem/enrich"
)

// spamhausFile builds a DROP file the way Spamhaus publishes it: one JSON object per line, then a
// metadata line whose size is the byte count of the data lines and records their number.
func spamhausFile(lines ...string) string {
	data := ""
	for _, l := range lines {
		data += l + "\n"
	}
	return data + fmt.Sprintf(`{"type":"metadata","timestamp":1795541204,"size":%d,"records":%d,"copyright":"(c) 2026 The Spamhaus Project SLU","terms":"https://www.spamhaus.org/drop/terms/"}`+"\n", len(data), len(lines))
}

func setOf(t *testing.T, ranges []enrich.Range, asns []uint32) *enrich.Set {
	t.Helper()
	return enrich.NewSet(ranges, asns)
}

func TestParseSpamhausCIDR(t *testing.T) {
	body := spamhausFile(
		`{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}`,
		`{"cidr":"223.254.0.0/16","sblid":"SBL212803","rir":"apnic"}`,
		`{"cidr":"2001:678:254::/48","sblid":"SBL697648","rir":"ripencc"}`,
	)
	l, err := parseSpamhaus([]byte(body), false)
	if err != nil {
		t.Fatal(err)
	}
	if l.entries != 3 || len(l.asns) != 0 {
		t.Errorf("entries %d asns %v", l.entries, l.asns)
	}
	if want := time.Unix(1795541204, 0).UTC(); !l.date.Equal(want) {
		t.Errorf("date %v, want %v", l.date, want)
	}
	s := setOf(t, l.ranges, nil)
	for a, want := range map[string]bool{"1.10.16.0": true, "1.10.31.255": true, "1.10.32.0": false, "223.254.9.9": true,
		"2001:678:254:ffff::1": true, "2001:678:255::": false} {
		if s.Contains(netip.MustParseAddr(a)) != want {
			t.Errorf("%s: want %v", a, want)
		}
	}
}

func TestParseSpamhausASN(t *testing.T) {
	body := spamhausFile(
		`{"asn":245,"rir":"arin","domain":"example.net","cc":"US","asname":"EXAMPLE-AS"}`,
		`{"asn":403005,"rir":"arin","domain":"example.host","cc":"SC","asname":"EXAMPLE2"}`,
	)
	l, err := parseSpamhaus([]byte(body), true)
	if err != nil {
		t.Fatal(err)
	}
	if l.entries != 2 || len(l.asns) != 2 || l.asns[0] != 245 || l.asns[1] != 403005 || len(l.ranges) != 0 {
		t.Errorf("%+v", l)
	}
}

// A DROP file is refused unless its metadata line is there and matches what came before it.
func TestParseSpamhausRefuses(t *testing.T) {
	good := spamhausFile(`{"cidr":"1.10.16.0/20","sblid":"SBL1"}`, `{"cidr":"1.19.0.0/16","sblid":"SBL2"}`)
	lines := strings.SplitAfter(good, "\n")
	cases := map[string]string{
		"empty":                       "",
		"no metadata (truncated)":     lines[0] + lines[1],
		"cut inside the metadata":     good[:len(good)-40],
		"cut inside a data line":      good[:20],
		"a data line removed":         lines[1] + lines[2],
		"records mismatch":            strings.Replace(good, `"records":2`, `"records":3`, 1),
		"size mismatch":               strings.Replace(good, fmt.Sprintf(`"size":%d`, len(lines[0])+len(lines[1])), `"size":5`, 1),
		"metadata not last":           lines[2] + lines[0] + lines[1],
		"metadata of another type":    strings.Replace(good, `"type":"metadata"`, `"type":"data"`, 1),
		"zero entries":                spamhausFile(),
		"only invalid entries":        spamhausFile(`{"cidr":"not a prefix"}`, `{"cidr":"0.0.0.0/0"}`, `{"asn":7}`),
		"garbage":                     "<html>Service unavailable</html>\n",
		"metadata line not an object": lines[0] + lines[1] + "[1,2,3]\n",
	}
	for name, body := range cases {
		if l, err := parseSpamhaus([]byte(body), false); err == nil {
			t.Errorf("%s: accepted (%d entries)", name, l.entries)
		}
	}
	if _, err := parseSpamhaus([]byte(spamhausFile(`{"asn":0}`, `{"asn":-5}`, `{"asn":4294967296}`, `{"cidr":"1.2.3.0/24"}`)), true); err == nil {
		t.Error("an ASN list with no valid ASN accepted")
	}
	over := []byte(spamhausFile(`{"cidr":"1.10.16.0/20","pad":"` + strings.Repeat("x", spamhausCap) + `"}`))
	if _, err := parseSpamhaus(over, false); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Errorf("a file over the cap: %v", err)
	}
}

// Invalid and too broad entries are skipped; the rest is used.
func TestParseSpamhausSkipsBadLines(t *testing.T) {
	body := spamhausFile(
		`{"cidr":"1.10.16.0/20"}`,
		`not json at all`,
		`{"cidr":"300.1.1.0/24"}`,
		`{"cidr":"0.0.0.0/0"}`,
		`{"cidr":"10.0.0.0/7"}`,
		`{"cidr":"2000::/3"}`,
		`{"cidr":"2a14:c380:11::/48"}`,
		`{"cidr":"fe80::1%eth0/64"}`,
		`{"sblid":"SBL9"}`,
		`{}`,
		`{"cidr":"1.2.3.4/24"}`,
		`{"cidr":"::ffff:0.0.0.0/96"}`,
		`{"cidr":"::ffff:5.6.7.0/120"}`,
		`{"cidr":"::ffff:0.0.0.0/80"}`,
	)
	l, err := parseSpamhaus([]byte(body), false)
	if err != nil {
		t.Fatal(err)
	}
	s := setOf(t, l.ranges, nil)
	if l.entries != 4 || l.invalid != 10 {
		t.Errorf("entries %d invalid %d, want 4 and 10", l.entries, l.invalid)
	}
	if !s.Contains(netip.MustParseAddr("5.6.7.9")) || s.Contains(netip.MustParseAddr("5.6.8.0")) {
		t.Error("an IPv4-mapped prefix isn't its IPv4 prefix")
	}
	if !s.Contains(netip.MustParseAddr("1.2.3.200")) || s.Contains(netip.MustParseAddr("10.1.1.1")) || s.Contains(netip.MustParseAddr("8.8.8.8")) {
		t.Error("wrong membership")
	}
	// CRLF line ends are accepted (the size counts them).
	crlf := strings.ReplaceAll(spamhausFile(`{"cidr":"1.10.16.0/20"}`), "\n", "\r\n")
	crlf = strings.Replace(crlf, `"size":24`, `"size":25`, 1)
	if l, err := parseSpamhaus([]byte(crlf), false); err != nil || l.entries != 1 {
		t.Errorf("CRLF: %v %+v", err, l)
	}
}

func torList(n int, extra ...string) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, "185.220.%d.%d\n", i/250, i%250+1)
	}
	for _, e := range extra {
		b.WriteString(e + "\n")
	}
	return b.String()
}

func TestParseTor(t *testing.T) {
	l, err := parseTor([]byte(torList(120, "# a comment", "", "  2a0b:f4c2::1  ", "garbage", "1.2.3", "10.0.0.1:9001", "fe80::1%eth0", "185.220.0.1\r")))
	if err != nil {
		t.Fatal(err)
	}
	if l.entries != 121 || l.invalid != 4 { // 185.220.0.1 is listed twice
		t.Errorf("entries %d invalid %d, want 121 distinct and 4", l.entries, l.invalid)
	}
	s := setOf(t, l.ranges, nil)
	for a, want := range map[string]bool{"185.220.0.1": true, "185.220.0.120": true, "185.220.0.0": false, "2a0b:f4c2::1": true, "2a0b:f4c2::2": false} {
		if s.Contains(netip.MustParseAddr(a)) != want {
			t.Errorf("%s: want %v", a, want)
		}
	}
	for name, body := range map[string]string{
		"99 addresses":   torList(99),
		"empty":          "",
		"html":           "<html>\n" + strings.Repeat("<p>not an address</p>\n", 200),
		"99 + garbage":   torList(99, strings.Repeat("x\n", 500)),
		"over the cap":   torList(100, strings.Repeat("#", torCap)),
		"100 duplicates": strings.Repeat("185.220.0.1\n", 100),
	} {
		if _, err := parseTor([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := parseTor([]byte(torList(100))); err != nil {
		t.Errorf("100 addresses refused: %v", err)
	}
}

// dshieldSample is block.txt as published since 2026 (an ISO date without a zone, no column header
// line); the networks are examples.
const dshieldSample = `#
#   DShield.org Recommended Block List
#    (c) $year DShield.org
#   some rights reserved. Details http://creativecommons.org/licenses/by-nc-sa/2.5/
#   use on your own risk. No warranties implied.
#   primary URL: https://feeds.dshield.org/block.txt
#     PGP Sign.: https://feeds.dshield.org/block.txt.asc
#
#   comments: isc@example.org
#    updated: 2026-11-24T19:30:50.730860
#
#    This list summarizes the top 20 attacking class C (/24) subnets
#   over the last three days. The number of 'attacks' indicates the
#   number of targets reporting scans from this subnet.
#
#
#    Columns (tab delimited):
#
#    (1) start of netblock
#    (2) end of netblock
#    (3) subnet (/24 for class C)
#    (4) number of targets scanned
#    (5) name of Network
#    (6) Country
#    (7) contact email address
#
#    If a range is assigned to multiple users, the first one is listed.
#
45.148.10.0	45.148.10.255	24	2939	EXAMPLE NET	NL	abuse@example.net
080.082.077.000	080.082.077.255	24	1500	PADDED	NL	abuse@example.org
193.32.162.0	193.32.162.255	24	800	-	-	-
`

// dshieldSampleOld is the earlier layout: a "Mon Jan 2 15:04:05 2006 UTC" date and a header line.
const dshieldSampleOld = `#
#   DShield.org Recommended Block List
#   (c) 2007 DShield.org
#   primary URL: http://feeds.dshield.org/block.txt
#
#    updated: Tue Nov 24 15:21:35 2026 UTC
#
#    Columns (tab delimited):
#    (1) start of netblock
#    (2) end of netblock
#    (3) subnet (netblock/cidr)
#
Start	End	Netblock	Attacks	Name	Country	email
45.148.10.0	45.148.10.255	24	2939	EXAMPLE NET	NL	abuse@example.net
080.082.077.000	080.082.077.255	24	1500	PADDED	NL	abuse@example.org
193.32.162.0	193.32.162.255	24	800	X	RO	abuse@example.com
# completed
`

func TestParseDShield(t *testing.T) {
	for name, c := range map[string]struct {
		body string
		date time.Time
	}{
		"current layout": {dshieldSample, time.Date(2026, 11, 24, 19, 30, 50, 730860000, time.UTC)},
		"earlier layout": {dshieldSampleOld, time.Date(2026, 11, 24, 15, 21, 35, 0, time.UTC)},
	} {
		l, err := parseDShield([]byte(c.body))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if l.entries != 3 || l.invalid != 0 {
			t.Errorf("%s: entries %d invalid %d, want 3 and 0", name, l.entries, l.invalid)
		}
		if !l.date.Equal(c.date) || l.date.Location() != time.UTC {
			t.Errorf("%s: date %v, want %v", name, l.date, c.date)
		}
	}
	for d, want := range map[string]time.Time{
		"2026-11-24T19:30:50":           time.Date(2026, 11, 24, 19, 30, 50, 0, time.UTC),
		"2026-11-24T19:30:50Z":          time.Date(2026, 11, 24, 19, 30, 50, 0, time.UTC),
		"2026-11-24T19:30:50.5+01:00":   time.Date(2026, 11, 24, 18, 30, 50, 500000000, time.UTC),
		"Tue Nov 24 09:01:02 2026 UTC":  time.Date(2026, 11, 24, 9, 1, 2, 0, time.UTC),
		"yesterday":                     {},
		"2026-11-24":                    {},
		"2026-13-24T19:30:50.730860":    {},
		"2026-11-24T19:30:50.730860 xx": {},
	} {
		l, err := parseDShield([]byte("#    updated: " + d + "\n45.148.10.0\t45.148.10.255\t24\n"))
		if err != nil || !l.date.Equal(want) {
			t.Errorf("updated: %s → %v %v, want %v", d, l.date, err, want)
		}
	}
	l, err := parseDShield([]byte(dshieldSample))
	if err != nil {
		t.Fatal(err)
	}
	s := setOf(t, l.ranges, nil)
	for a, want := range map[string]bool{"45.148.10.0": true, "45.148.10.255": true, "45.148.11.0": false, "80.82.77.9": true, "193.32.162.1": true} {
		if s.Contains(netip.MustParseAddr(a)) != want {
			t.Errorf("%s: want %v", a, want)
		}
	}
	bad := dshieldSample + "1.0.0.0\t1.255.255.255\t8\t1\tbroad\n" + // more than a /8? exactly /8: allowed
		"2.0.0.0\t3.255.255.255\t7\t1\ttoo broad\n" +
		"9.9.9.9\t9.9.9.1\t24\t1\treversed\n" +
		"9.9.9.0\t2001:db8::1\t24\t1\tmixed\n" +
		"256.1.1.1\t256.1.1.255\t24\t1\tbad\n" +
		"1.2.3.0\n" +
		"0001.2.3.0\t1.2.3.255\t24\t1\tfour digits\n"
	l, err = parseDShield([]byte(bad))
	if err != nil {
		t.Fatal(err)
	}
	if l.entries != 4 || l.invalid != 6 {
		t.Errorf("entries %d invalid %d, want 4 and 6", l.entries, l.invalid)
	}
	for name, body := range map[string]string{
		"only comments": "# updated: Tue Nov 24 15:21:35 2026 UTC\n#\n",
		"header only":   "Start\tEnd\tNetblock\n",
		"empty":         "",
		"over the cap":  dshieldSample + strings.Repeat("#", dshieldCap),
	} {
		if _, err := parseDShield([]byte(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// No date line: the date is zero (the fetch time is used).
	if l, err := parseDShield([]byte("45.148.10.0\t45.148.10.255\t24\n")); err != nil || !l.date.IsZero() {
		t.Errorf("no date: %v %v", err, l.date)
	}
}

// Snapshots round-trip, and a damaged one is refused whole.
func TestSnapshotRoundTrip(t *testing.T) {
	l := list{ranges: []enrich.Range{enrich.PrefixRange(netip.MustParsePrefix("1.10.16.0/20")),
		{From: netip.MustParseAddr("185.220.0.1"), To: netip.MustParseAddr("185.220.0.1")},
		enrich.PrefixRange(netip.MustParsePrefix("2001:678:254::/48"))}, asns: []uint32{245, 403005}, entries: 5}
	set := enrich.NewSet(l.ranges, l.asns)
	fetched := time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)
	b, err := encodeSnapshot(NameSpamhaus, "2026-11-24T17:26Z", fetched, l)
	if err != nil {
		t.Fatal(err)
	}
	snap, got, err := decodeSnapshot(b, NameSpamhaus)
	if err != nil {
		t.Fatal(err)
	}
	if snap.Version != "2026-11-24T17:26Z" || !snap.Fetched.Equal(fetched) || snap.Entries != 5 {
		t.Errorf("snapshot %+v", snap)
	}
	if fmt.Sprint(got.Ranges(), got.ASNs()) != fmt.Sprint(set.Ranges(), set.ASNs()) {
		t.Errorf("ranges %v %v, want %v %v", got.Ranges(), got.ASNs(), set.Ranges(), set.ASNs())
	}
	for name, mod := range map[string]func(string) string{
		"another feed's": func(s string) string { return strings.Replace(s, `"name":"spamhaus-drop"`, `"name":"tor-exits"`, 1) },
		"a bad range":    func(s string) string { return strings.Replace(s, "185.220.0.1", "185.220.0.x", 1) },
		"a reversed one": func(s string) string { return strings.Replace(s, "1.10.16.0-1.10.31.255", "1.10.31.255-1.10.16.0", 1) },
		"a version bump": func(s string) string { return strings.Replace(s, `"v":1`, `"v":2`, 1) },
		"truncated":      func(s string) string { return s[:len(s)/2] },
		"an unknown key": func(s string) string { return strings.Replace(s, `"entries":5`, `"entries":5,"extra":1`, 1) },
		"a bad version":  func(s string) string { return strings.Replace(s, "2026-11-24T17:26Z", "2026 11\n24", 1) },
		"zero ASN":       func(s string) string { return strings.Replace(s, "[245,", "[0,", 1) },
		"too broad range": func(s string) string {
			return strings.Replace(s, "1.10.16.0-1.10.31.255", "0.0.0.0-255.255.255.255", 1)
		},
	} {
		if _, _, err := decodeSnapshot([]byte(mod(string(b))), NameSpamhaus); err == nil {
			t.Errorf("%s snapshot accepted", name)
		}
	}
	empty, err := encodeSnapshot(NameTor, "2026-11-24T10:00Z", fetched, list{})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := decodeSnapshot(empty, NameTor); err == nil {
		t.Error("an empty snapshot accepted")
	}
}

// Entries that are each within the bounds but merge into a broader range (adjacent networks) are
// loaded back: the snapshot keeps them as listed.
func TestSnapshotKeepsEntriesThatMerge(t *testing.T) {
	var l list
	for _, p := range []string{"1.0.0.0/8", "2.0.0.0/24", "2a0b:ff00::/24", "2a0c::/32"} {
		r, ok := prefixEntry(p)
		if !ok {
			t.Fatalf("%s refused", p)
		}
		l.ranges, l.entries = append(l.ranges, r), l.entries+1
	}
	if n := len(enrich.NewSet(l.ranges, nil).Ranges()); n != 2 {
		t.Fatalf("setup: %d merged ranges, want 2", n)
	}
	b, err := encodeSnapshot(NameSpamhaus, "2026-11-24T10:00Z", time.Now(), l)
	if err != nil {
		t.Fatal(err)
	}
	snap, s, err := decodeSnapshot(b, NameSpamhaus)
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	if snap.Entries != 4 || len(snap.Ranges) != 4 {
		t.Errorf("snapshot %+v", snap)
	}
	for a, want := range map[string]bool{"1.0.0.0": true, "1.255.255.255": true, "2.0.0.255": true, "2.0.1.0": false,
		"2a0b:ff00::": true, "2a0b:ffff:ffff::1": true, "2a0c:0:ffff::1": true, "2a0c:1::": false, "2a0b:fe00::": false} {
		if s.Contains(netip.MustParseAddr(a)) != want {
			t.Errorf("%s: want %v", a, want)
		}
	}
}

// A snapshot range whose ends are of two families once an IPv4-mapped end is unmapped is refused,
// never a panic; tooBroad says so for any such range and for an invalid one.
func TestSnapshotMixedFamilies(t *testing.T) {
	snapWith := func(r string) []byte {
		return []byte(`{"v":1,"name":"tor-exits","version":"2026-11-24T10:00Z","fetched":"2026-11-24T10:00:00Z","entries":1,"ranges":["` + r + `"]}`)
	}
	for _, r := range []string{"::ffff:1.2.3.4-::1:0:0:0", "::1-::ffff:1.2.3.4", "1.2.3.4-::1", "::ffff:0.0.0.0-ffff::", "::-::ffff:255.255.255.255"} {
		func() {
			defer func() {
				if v := recover(); v != nil {
					t.Errorf("%s: panic %v", r, v)
				}
			}()
			if _, _, err := decodeSnapshot(snapWith(r), NameTor); err == nil {
				t.Errorf("%s accepted", r)
			}
		}()
	}
	// Both ends IPv4 once unmapped: the IPv4 range.
	_, s, err := decodeSnapshot(snapWith("::ffff:1.2.3.4-1.2.3.9"), NameTor)
	if err != nil || !s.Contains(netip.MustParseAddr("1.2.3.5")) || s.Contains(netip.MustParseAddr("1.2.3.10")) {
		t.Errorf("a mapped IPv4 end: %v", err)
	}
	v4, v6, mapped := netip.MustParseAddr("1.2.3.4"), netip.MustParseAddr("::1:0:0:0"), netip.MustParseAddr("::ffff:1.2.3.4")
	for _, r := range []enrich.Range{{From: mapped, To: v6}, {From: v4, To: v6}, {From: v6, To: mapped}, {From: v6, To: v4},
		{From: netip.Addr{}, To: v4}, {From: v4, To: netip.Addr{}}, {From: v6, To: netip.Addr{}}, {}} {
		func() {
			defer func() {
				if v := recover(); v != nil {
					t.Errorf("tooBroad(%v): panic %v", r, v)
				}
			}()
			if !tooBroad(r) {
				t.Errorf("tooBroad(%v) = false", r)
			}
		}()
	}
}
