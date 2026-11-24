package feeds

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/siem/enrich"
)

// Size caps of the downloaded lists and of a snapshot read back.
const (
	spamhausCap = 4 << 20   // each of drop_v4.json, drop_v6.json, asndrop.json
	torCap      = 2 << 20   // torbulkexitlist
	dshieldCap  = 256 << 10 // block.txt
	snapshotCap = 16 << 20
)

// Entry bounds of a list.
const (
	maxEntries    = 500000 // entries in one list
	torMinEntries = 100    // fewer distinct addresses than this: not a real exit list
	// The broadest network a list may name: wider entries are skipped (an IPv4 /8, an IPv6 /16).
	maxSpan4 = 1 << 24

	versionLayout = "2006-01-02T15:04Z" // a list's version: its own date, UTC
)

// versionRe is a feed version: a DB-IP month or a list's date.
var versionRe = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}(-[0-9]{2}T[0-9]{2}:[0-9]{2}Z)?$`)

// list is a parsed threat-intel list.
type list struct {
	ranges  []enrich.Range
	asns    []uint32
	entries int       // valid entries (distinct addresses for the Tor list)
	invalid int       // data lines skipped
	date    time.Time // the list's own date; zero when it has none
}

var errNoEntries = errors.New("the list has no valid entries")

func tooLarge(limit int) error { return fmt.Errorf("the list is larger than %d KiB", limit>>10) }

// spamhausMeta is the last line of a DROP file.
type spamhausMeta struct {
	Type      string `json:"type"`
	Timestamp int64  `json:"timestamp"`
	Size      int64  `json:"size"`
	Records   int    `json:"records"`
}

// parseSpamhaus parses a Spamhaus DROP file: one JSON object per line ({"cidr": …} in drop_v4.json
// and drop_v6.json, {"asn": …} in asndrop.json when asnList), then a metadata line whose size is
// the byte count of the lines before it and records their number. A file without that line, or
// whose size or count differs, is refused (truncated or altered); lines that don't hold a valid
// entry are skipped; a file with no valid entry is refused.
func parseSpamhaus(body []byte, asnList bool) (list, error) {
	if len(body) > spamhausCap {
		return list{}, tooLarge(spamhausCap)
	}
	trimmed := bytes.TrimRight(body, "\r\n")
	cut := bytes.LastIndexByte(trimmed, '\n') + 1
	data := body[:cut]
	var meta spamhausMeta
	if err := json.Unmarshal(bytes.TrimSpace(trimmed[cut:]), &meta); err != nil || meta.Type != "metadata" {
		return list{}, errors.New("no metadata line (truncated?)")
	}
	if meta.Size != int64(len(data)) || meta.Records != bytes.Count(data, []byte("\n")) {
		return list{}, fmt.Errorf("the metadata (%d bytes, %d records) doesn't match the data (%d bytes, %d lines)",
			meta.Size, meta.Records, len(data), bytes.Count(data, []byte("\n")))
	}
	if meta.Records > maxEntries {
		return list{}, fmt.Errorf("more than %d entries", maxEntries)
	}
	var l list
	if meta.Timestamp > 0 {
		l.date = time.Unix(meta.Timestamp, 0).UTC()
	}
	for line := range bytes.Lines(data) {
		line = bytes.TrimSpace(line)
		var ent struct {
			CIDR *string      `json:"cidr"`
			ASN  *json.Number `json:"asn"`
		}
		if json.Unmarshal(line, &ent) != nil {
			l.invalid++
			continue
		}
		switch {
		case asnList && ent.ASN != nil:
			if n, err := strconv.ParseUint(ent.ASN.String(), 10, 32); err == nil && n > 0 {
				l.asns = append(l.asns, uint32(n))
				l.entries++
				continue
			}
		case !asnList && ent.CIDR != nil:
			if r, ok := prefixEntry(*ent.CIDR); ok {
				l.ranges = append(l.ranges, r)
				l.entries++
				continue
			}
		}
		l.invalid++
	}
	if l.entries == 0 {
		return list{}, errNoEntries
	}
	return l, nil
}

// prefixEntry parses one list prefix; false when it isn't a valid prefix or is broader than an
// IPv4 /8 or an IPv6 /16 (an IPv4-mapped IPv6 prefix counts as the IPv4 prefix).
func prefixEntry(s string) (enrich.Range, bool) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return enrich.Range{}, false
	}
	if a := p.Addr(); a.Is4In6() {
		if p.Bits() < 96 {
			return enrich.Range{}, false
		}
		p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
	}
	r := enrich.PrefixRange(p)
	if !r.From.IsValid() || tooBroad(r) {
		return enrich.Range{}, false
	}
	return r, true
}

// tooBroad reports whether r covers more than an IPv4 /8 or crosses an IPv6 /16 boundary; an
// invalid end, or ends of two families (an IPv4-mapped end counts as IPv4), is too broad too.
func tooBroad(r enrich.Range) bool {
	from, to := r.From.Unmap(), r.To.Unmap()
	if !from.IsValid() || !to.IsValid() || from.Is4() != to.Is4() {
		return true
	}
	if from.Is4() {
		a, b := from.As4(), to.As4()
		lo := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
		hi := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
		return hi-lo >= maxSpan4
	}
	a, b := from.As16(), to.As16()
	return a[0] != b[0] || a[1] != b[1]
}

// parseTor parses the Tor bulk exit list: one address per line ('#' comments and blank lines
// skipped). Fewer than 100 distinct addresses is refused.
func parseTor(body []byte) (list, error) {
	if len(body) > torCap {
		return list{}, tooLarge(torCap)
	}
	seen := map[netip.Addr]struct{}{}
	var l list
	for line := range bytes.Lines(body) {
		s := strings.TrimSpace(string(line))
		if s == "" || s[0] == '#' {
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			l.invalid++
			continue
		}
		a = a.Unmap()
		if _, dup := seen[a]; dup {
			continue
		}
		if len(seen) == maxEntries {
			return list{}, fmt.Errorf("more than %d entries", maxEntries)
		}
		seen[a] = struct{}{}
		l.ranges = append(l.ranges, enrich.Range{From: a, To: a})
	}
	l.entries = len(seen)
	if l.entries < torMinEntries {
		return list{}, fmt.Errorf("only %d addresses (at least %d expected)", l.entries, torMinEntries)
	}
	return l, nil
}

// dshieldDateLayouts are the forms of block.txt's "updated:" date: ISO 8601 without a zone (UTC;
// the file's form since 2026), with one, and the earlier "Tue Nov 24 15:21:35 2026 UTC".
var dshieldDateLayouts = []string{"2006-01-02T15:04:05.999999999", time.RFC3339Nano, "Mon Jan _2 15:04:05 2006 MST"}

// dshieldDate parses an "updated:" date; zero when it is in none of dshieldDateLayouts.
func dshieldDate(s string) time.Time {
	for _, layout := range dshieldDateLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// parseDShield parses DShield's block.txt: '#' comments (one of them "updated: <date>"), maybe a
// header line, then tab-separated lines starting with the first and last address of a block. A
// line whose addresses don't parse, are reversed, aren't IPv4 or span more than a /8 is skipped; a
// file with no valid block is refused.
func parseDShield(body []byte) (list, error) {
	if len(body) > dshieldCap {
		return list{}, tooLarge(dshieldCap)
	}
	var l list
	for line := range bytes.Lines(body) {
		s := strings.TrimSpace(string(line))
		if s == "" {
			continue
		}
		if s[0] == '#' {
			if _, d, ok := strings.Cut(s, "updated:"); ok && l.date.IsZero() {
				l.date = dshieldDate(strings.TrimSpace(d))
			}
			continue
		}
		if s[0] < '0' || s[0] > '9' { // the column header
			continue
		}
		f := strings.Fields(s)
		if len(f) < 2 {
			l.invalid++
			continue
		}
		from, ok1 := paddedIPv4(f[0])
		to, ok2 := paddedIPv4(f[1])
		r := enrich.Range{From: from, To: to}
		if !ok1 || !ok2 || from.Compare(to) > 0 || tooBroad(r) {
			l.invalid++
			continue
		}
		if l.entries == maxEntries {
			return list{}, fmt.Errorf("more than %d entries", maxEntries)
		}
		l.ranges = append(l.ranges, r)
		l.entries++
	}
	if l.entries == 0 {
		return list{}, errNoEntries
	}
	return l, nil
}

// paddedIPv4 parses a dotted IPv4 address whose parts may have leading zeros ("080.082.077.000").
func paddedIPv4(s string) (netip.Addr, bool) {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return netip.Addr{}, false
	}
	var b [4]byte
	for i, p := range parts {
		if len(p) == 0 || len(p) > 3 || strings.Trim(p, "0123456789") != "" {
			return netip.Addr{}, false
		}
		n, _ := strconv.Atoi(p)
		if n > 255 {
			return netip.Addr{}, false
		}
		b[i] = byte(n)
	}
	return netip.AddrFrom4(b), true
}

// snapshot is a parsed list as written to Dir: loaded at start, so enrichment works after a
// restart without a download.
type snapshot struct {
	V       int       `json:"v"`
	Name    string    `json:"name"`
	Version string    `json:"version"`
	Fetched time.Time `json:"fetched"`
	Entries int       `json:"entries"`
	Ranges  []string  `json:"ranges,omitempty"` // "a" or "a-b"
	ASNs    []uint32  `json:"asns,omitempty"`
}

// encodeSnapshot writes l's entries as the parser returned them.
//
// Intentional: the entries, not the Set's merged ranges: adjacent entries merge into a range
// broader than any one entry may be (1.0.0.0/8 + 2.0.0.0/24), and decodeSnapshot checks each range
// against the parsers' bounds.
func encodeSnapshot(name, version string, fetched time.Time, l list) ([]byte, error) {
	snap := snapshot{V: 1, Name: name, Version: version, Fetched: fetched.UTC(), Entries: l.entries, ASNs: l.asns}
	snap.Ranges = make([]string, 0, len(l.ranges))
	for _, r := range l.ranges {
		if r.From == r.To {
			snap.Ranges = append(snap.Ranges, r.From.String())
		} else {
			snap.Ranges = append(snap.Ranges, r.From.String()+"-"+r.To.String())
		}
	}
	return json.Marshal(snap)
}

// decodeSnapshot reads back a snapshot of feed name; anything malformed refuses it whole. Each
// range must be within the bounds the parsers allow an entry (tooBroad); an IPv4-mapped end is its
// IPv4 address.
func decodeSnapshot(b []byte, name string) (snapshot, *enrich.Set, error) {
	var snap snapshot
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&snap); err != nil {
		return snapshot{}, nil, fmt.Errorf("unreadable: %w", err)
	}
	switch {
	case snap.V != 1:
		return snapshot{}, nil, fmt.Errorf("format %d", snap.V)
	case snap.Name != name:
		return snapshot{}, nil, fmt.Errorf("written for %q", snap.Name)
	case !versionRe.MatchString(snap.Version):
		return snapshot{}, nil, errors.New("bad version")
	case snap.Entries < 1 || snap.Entries > maxEntries || len(snap.Ranges)+len(snap.ASNs) == 0 || len(snap.Ranges)+len(snap.ASNs) > maxEntries:
		return snapshot{}, nil, errors.New("bad entry count")
	}
	ranges := make([]enrich.Range, 0, len(snap.Ranges))
	for _, s := range snap.Ranges {
		a, b, isRange := strings.Cut(s, "-")
		if !isRange {
			b = a
		}
		from, err1 := netip.ParseAddr(a)
		to, err2 := netip.ParseAddr(b)
		from, to = from.Unmap(), to.Unmap()
		r := enrich.Range{From: from, To: to}
		if err1 != nil || err2 != nil || from.Zone() != "" || to.Zone() != "" || from.Is4() != to.Is4() || from.Compare(to) > 0 || tooBroad(r) {
			return snapshot{}, nil, fmt.Errorf("bad range %q", s)
		}
		ranges = append(ranges, r)
	}
	for _, a := range snap.ASNs {
		if a == 0 {
			return snapshot{}, nil, errors.New("bad ASN 0")
		}
	}
	return snap, enrich.NewSet(ranges, snap.ASNs), nil
}
