// Package enrich adds what is known about a security event's client IP before the event is stored:
// its country, city, approximate coordinates, autonomous system and organisation (DB-IP Lite
// databases) and the threat-intel lists it is on (Spamhaus DROP, Tor exits, DShield). The data
// files are downloaded and refreshed by package feeds, which hands them to an Enricher.
package enrich

import (
	"container/list"
	"math"
	"net/netip"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"unicode"
	"unicode/utf8"

	"github.com/daboss2003/mooring/internal/siem"
)

// List names (siem.Geo.Lists; searched as list:<name>).
const (
	ListSpamhaus = "spamhaus-drop" // Spamhaus DROP (IPv4, IPv6) and ASN-DROP
	ListTor      = "tor-exit"      // Tor exit relays
	ListDShield  = "dshield"       // DShield's recommended block list
)

// Bounds of what Enrich sets.
const (
	MaxLists = 8   // names in Geo.Lists
	MaxCity  = 64  // bytes of Geo.City
	MaxOrg   = 128 // bytes of Geo.Org
)

// cacheSize bounds the lookup cache (addresses).
const cacheSize = 16384

var listNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

type namedSet struct {
	name string
	set  *Set
}

// Enricher sets siem.Event.Geo. Its databases and lists are swapped while it runs (SetCity, SetASN,
// SetList); every swap empties the lookup cache. Safe for concurrent use. The zero value is not
// usable: use New.
type Enricher struct {
	city, asn atomic.Pointer[DB]
	lists     atomic.Pointer[[]namedSet] // sorted by name; replaced whole (copy on write)
	listMu    sync.Mutex                 // serializes SetList
	gen       atomic.Uint64              // bumped by every swap; cache entries of an older one are stale
	cache     lru
	misses    atomic.Int64 // database lookups (cache misses), for tests
}

// New returns an Enricher with no databases and no lists (Enrich sets nothing until they arrive).
func New() *Enricher {
	x := &Enricher{}
	x.cache.init(cacheSize)
	return x
}

// Enrich sets e.Geo for a public e.IP that a database or list knows about; it leaves e.Geo alone
// for an empty, malformed or non-public address (see Public) and when nothing is known. Lookups are
// cached (at most 16384 addresses). Each event gets its own copy of the Geo.
func (x *Enricher) Enrich(e *siem.Event) {
	if x == nil || e == nil || e.IP == "" {
		return
	}
	ip, err := netip.ParseAddr(e.IP)
	if err != nil || !Public(ip) {
		return
	}
	ip = ip.Unmap()
	gen := x.gen.Load()
	g, ok := x.cache.get(ip, gen)
	if !ok {
		x.misses.Add(1)
		g = x.lookup(ip)
		x.cache.put(ip, gen, g, &x.gen)
	}
	if g != nil {
		c := *g
		c.Lists = slices.Clone(g.Lists)
		e.Geo = &c
	}
}

// lookup asks the databases and lists about ip (nil when none knows it).
func (x *Enricher) lookup(ip netip.Addr) *siem.Geo {
	var g siem.Geo
	if d := current(&x.city); d != nil {
		var rec cityRecord
		if d.decode(ip, &rec) {
			g.Country = countryCode(rec.Country.ISOCode)
			g.City = cleanText(rec.City.Names.En, MaxCity)
			if lat, lon := rec.Location.Latitude, rec.Location.Longitude; validCoord(lat, 90) && validCoord(lon, 180) {
				g.Lat, g.Lon = lat, lon
			}
		}
	}
	if d := current(&x.asn); d != nil {
		var rec asnRecord
		if d.decode(ip, &rec) {
			g.ASN = rec.Number
			g.Org = cleanText(rec.Org, MaxOrg)
		}
	}
	if ls := x.lists.Load(); ls != nil {
		for _, l := range *ls {
			if len(g.Lists) == MaxLists {
				break
			}
			if l.set.Contains(ip) || l.set.HasASN(g.ASN) {
				g.Lists = append(g.Lists, l.name)
			}
		}
	}
	if g.Country == "" && g.City == "" && g.Lat == 0 && g.Lon == 0 && g.ASN == 0 && g.Org == "" && len(g.Lists) == 0 {
		return nil
	}
	return &g
}

// current takes a reference on the database p points to (nil when none). A database swapped out
// and closed between the load and the reference is skipped for the one now in place.
func current(p *atomic.Pointer[DB]) *DB {
	for range 3 {
		d := p.Load()
		if d == nil {
			return nil
		}
		if d.acquire() {
			return d
		}
	}
	return nil
}

// decode looks ip up into rec and drops the reference current took; false when the database has no
// record for ip or it can't be decoded.
func (d *DB) decode(ip netip.Addr, rec any) bool {
	defer d.release()
	res := d.r.Lookup(ip)
	if !res.Found() {
		return false
	}
	return res.Decode(rec) == nil
}

// SetCity makes d the City database (nil: none) and takes over its reference: the database it
// replaces is closed once no lookup uses it.
func (x *Enricher) SetCity(d *DB) { x.swap(&x.city, d) }

// SetASN makes d the ASN database (nil: none), like SetCity.
func (x *Enricher) SetASN(d *DB) { x.swap(&x.asn, d) }

func (x *Enricher) swap(p *atomic.Pointer[DB], d *DB) {
	old := p.Swap(d)
	x.invalidate()
	if old != nil && old != d {
		old.Close()
	}
}

// SetList makes s the list called name (nil removes it). A name must be lowercase letters, digits
// and '-', at most 32 bytes; another is ignored.
func (x *Enricher) SetList(name string, s *Set) {
	if !listNameRe.MatchString(name) {
		return
	}
	x.listMu.Lock()
	defer x.listMu.Unlock()
	var next []namedSet
	if cur := x.lists.Load(); cur != nil {
		next = slices.DeleteFunc(slices.Clone(*cur), func(l namedSet) bool { return l.name == name })
	}
	if s != nil {
		next = append(next, namedSet{name: name, set: s})
		slices.SortFunc(next, func(a, b namedSet) int { return strings.Compare(a.name, b.name) })
	}
	x.lists.Store(&next)
	x.invalidate()
}

// Close drops the databases and lists; Enrich sets nothing afterwards.
func (x *Enricher) Close() {
	x.SetCity(nil)
	x.SetASN(nil)
	x.listMu.Lock()
	x.lists.Store(nil)
	x.invalidate()
	x.listMu.Unlock()
}

func (x *Enricher) invalidate() {
	x.gen.Add(1)
	x.cache.reset()
}

// countryCode is s when it is an ISO 3166-1 alpha-2 code (uppercased), else "".
func countryCode(s string) string {
	if len(s) != 2 {
		return ""
	}
	b := []byte(s)
	for i, c := range b {
		switch {
		case c >= 'A' && c <= 'Z':
		case c >= 'a' && c <= 'z':
			b[i] = c - 'a' + 'A'
		default:
			return ""
		}
	}
	return string(b)
}

func validCoord(v, limit float64) bool {
	return !math.IsNaN(v) && v >= -limit && v <= limit
}

// cleanText drops invalid UTF-8 and control and format characters from a database string, trims
// spaces and cuts it to n bytes on a rune boundary. It reads at most 16n bytes of s.
func cleanText(s string, n int) string {
	if len(s) > 16*n {
		s = s[:16*n]
	}
	var b strings.Builder
	for _, r := range s {
		if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			continue
		}
		b.WriteRune(r)
		if b.Len() > n+utf8.UTFMax {
			break
		}
	}
	return siem.Cut(strings.TrimSpace(b.String()), n)
}

// lru is the lookup cache: address → Geo (nil: nothing known), with the generation it was looked
// up in.
type lru struct {
	mu  sync.Mutex
	max int
	ll  list.List
	m   map[netip.Addr]*list.Element
}

type lruEntry struct {
	key netip.Addr
	gen uint64
	geo *siem.Geo
}

func (c *lru) init(max int) {
	c.max = max
	c.m = make(map[netip.Addr]*list.Element, max)
	c.ll.Init()
}

func (c *lru) get(key netip.Addr, gen uint64) (*siem.Geo, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el := c.m[key]
	if el == nil {
		return nil, false
	}
	ent := el.Value.(*lruEntry)
	if ent.gen != gen {
		return nil, false
	}
	c.ll.MoveToFront(el)
	return ent.geo, true
}

// put stores geo for key unless a swap happened since gen was read (cur moved on).
func (c *lru) put(key netip.Addr, gen uint64, geo *siem.Geo, cur *atomic.Uint64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if cur.Load() != gen {
		return
	}
	if el := c.m[key]; el != nil {
		el.Value = &lruEntry{key: key, gen: gen, geo: geo}
		c.ll.MoveToFront(el)
		return
	}
	c.m[key] = c.ll.PushFront(&lruEntry{key: key, gen: gen, geo: geo})
	if c.ll.Len() > c.max {
		last := c.ll.Back()
		c.ll.Remove(last)
		delete(c.m, last.Value.(*lruEntry).key)
	}
}

func (c *lru) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.m)
	c.ll.Init()
}

func (c *lru) len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ll.Len()
}
