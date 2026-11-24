package enrich

import (
	"fmt"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/enrich/mmdbtest"
)

// openTestDB writes b to a new file in a temp dir and opens it with OpenDB.
func openTestDB(t testing.TB, b []byte, kind string) *DB {
	t.Helper()
	d, err := openBytes(t, b, kind)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	return d
}

func openBytes(t testing.TB, b []byte, kind string) (*DB, error) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "db.mmdb"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	return OpenDB(root, "db.mmdb", kind, 64<<20)
}

// Test networks: public ones, plus a private and a documentation network that a lookup would find
// if the address checks didn't skip them.
func testCity(city string) []byte {
	return mmdbtest.City(
		mmdbtest.CityEntry{Prefix: "41.58.0.0/18", City: city, Country: "NG", Lat: 6.42728, Lon: 3.4211},
		mmdbtest.CityEntry{Prefix: "8.8.8.0/24", City: "Mountain View", Country: "US", Lat: 37.422, Lon: -122.085},
		mmdbtest.CityEntry{Prefix: "2001:4860::/32", City: "Montreal", Country: "CA", Lat: 45.5019, Lon: -73.5674},
		mmdbtest.CityEntry{Prefix: "10.0.0.0/8", City: "Private", Country: "ZZ", Lat: 1, Lon: 1},
		mmdbtest.CityEntry{Prefix: "203.0.113.0/24", City: "Documentation", Country: "ZZ", Lat: 1, Lon: 1},
		mmdbtest.CityEntry{Prefix: "100.64.0.0/10", City: "CGNAT", Country: "ZZ", Lat: 1, Lon: 1},
	)
}

func testASN() []byte {
	return mmdbtest.ASN(
		mmdbtest.ASNEntry{Prefix: "41.58.0.0/16", ASN: 36923, Org: "SWIFT NETWORKS LIMITED"},
		mmdbtest.ASNEntry{Prefix: "8.8.8.0/24", ASN: 15169, Org: "Google LLC"},
		mmdbtest.ASNEntry{Prefix: "2001:4860::/32", ASN: 15169, Org: "Google LLC"},
		mmdbtest.ASNEntry{Prefix: "10.0.0.0/8", ASN: 64512, Org: "Private"},
		mmdbtest.ASNEntry{Prefix: "185.220.100.0/22", ASN: 64496, Org: "Listed Hosting"},
	)
}

func newTestEnricher(t testing.TB) *Enricher {
	t.Helper()
	x := New()
	x.SetCity(openTestDB(t, testCity("Lagos"), KindCity))
	x.SetASN(openTestDB(t, testASN(), KindASN))
	t.Cleanup(x.Close)
	return x
}

func enrich(x *Enricher, ip string) *siem.Geo {
	e := siem.Event{IP: ip}
	x.Enrich(&e)
	return e.Geo
}

func TestPublic(t *testing.T) {
	for _, a := range []string{"10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1", "127.0.0.1", "169.254.169.254",
		"100.64.0.1", "100.127.255.255", "0.0.0.0", "0.1.2.3", "192.0.0.8", "192.0.2.1", "198.51.100.1", "203.0.113.9",
		"198.18.0.1", "198.19.255.255", "192.88.99.1", "224.0.0.1", "239.255.255.250", "240.0.0.1", "255.255.255.255",
		"::", "::1", "fe80::1", "fc00::1", "fd12:3456::1", "ff02::1", "2001:db8::1", "3fff::1", "64:ff9b::808:808",
		"::ffff:10.0.0.1", "::ffff:127.0.0.1", "2001::1", "2002:c000:0204::1", "100::1", "::808:808"} {
		if Public(addr(a)) {
			t.Errorf("%s is public, want not", a)
		}
	}
	for _, a := range []string{"8.8.8.8", "1.1.1.1", "41.58.1.1", "100.63.255.255", "100.128.0.0", "172.32.0.1",
		"198.20.0.1", "192.0.3.1", "223.255.255.255", "2001:4860:4860::8888", "::ffff:8.8.8.8", "2a14:c380:11::1", "2c0f:f248::1"} {
		if !Public(addr(a)) {
			t.Errorf("%s is not public, want public", a)
		}
	}
	if Public(netip.Addr{}) {
		t.Error("the zero Addr is public")
	}
}

// A public address gets every field from both databases.
func TestEnrichFillsGeo(t *testing.T) {
	x := newTestEnricher(t)
	x.SetList(ListTor, NewSet([]Range{pfx("41.58.1.0/24")}, nil))
	g := enrich(x, "41.58.1.1")
	if g == nil {
		t.Fatal("no Geo for a public address in both databases")
	}
	want := siem.Geo{Country: "NG", City: "Lagos", Lat: 6.42728, Lon: 3.4211, ASN: 36923, Org: "SWIFT NETWORKS LIMITED", Lists: []string{ListTor}}
	if fmt.Sprint(*g) != fmt.Sprint(want) {
		t.Errorf("Geo %+v, want %+v", *g, want)
	}
	if g := enrich(x, "2001:4860:4860::8888"); g == nil || g.Country != "CA" || g.ASN != 15169 || g.City != "Montreal" {
		t.Errorf("IPv6: %+v", g)
	}
	if g := enrich(x, "::ffff:8.8.8.8"); g == nil || g.Country != "US" || g.ASN != 15169 {
		t.Errorf("IPv4-mapped: %+v", g)
	}
	// Only in the ASN database.
	if g := enrich(x, "185.220.101.7"); g == nil || g.ASN != 64496 || g.Country != "" || g.City != "" {
		t.Errorf("ASN only: %+v", g)
	}
	// In neither database and no list: no Geo.
	if g := enrich(x, "9.9.9.9"); g != nil {
		t.Errorf("unknown address: %+v", g)
	}
}

// Private, loopback, CGNAT, documentation and malformed addresses are skipped, even when a
// database has a network for them.
func TestEnrichSkipsNonPublic(t *testing.T) {
	x := newTestEnricher(t)
	x.SetList(ListDShield, NewSet([]Range{pfx("10.0.0.0/8"), pfx("203.0.113.0/24"), pfx("100.64.0.0/10")}, nil))
	for _, ip := range []string{"10.1.2.3", "203.0.113.5", "100.64.1.1", "::ffff:10.1.2.3", "", "not-an-ip", "41.58.1.1:443",
		"[41.58.1.1]", "fe80::1%eth0", "[redacted]", " 41.58.1.1", "041.058.001.001"} {
		e := siem.Event{IP: ip}
		x.Enrich(&e)
		if e.Geo != nil {
			t.Errorf("%q enriched: %+v", ip, *e.Geo)
		}
	}
	var nilX *Enricher
	e := siem.Event{IP: "41.58.1.1"}
	nilX.Enrich(&e)
	if e.Geo != nil {
		t.Error("a nil Enricher set Geo")
	}
}

// Strings from a database are bounded and cleaned; a bad country code or coordinate is dropped.
func TestEnrichBoundsFields(t *testing.T) {
	long := "Lagos\x00\x1b[31m‮" + strings.Repeat("é", 100) + "\n"
	city := mmdbtest.City(
		mmdbtest.CityEntry{Prefix: "41.58.0.0/18", City: long, Country: "ng", Lat: 95, Lon: 3},
		mmdbtest.CityEntry{Prefix: "8.8.8.0/24", City: "x", Country: "USA", Lat: math.NaN(), Lon: 1},
		mmdbtest.CityEntry{Prefix: "1.1.1.0/24", City: "​Sydney\u0085", Country: "A1", Lat: -33.8, Lon: math.Inf(1)},
		mmdbtest.CityEntry{Prefix: "9.9.9.0/24", City: "Berkeley", Country: "US", Lat: -90, Lon: 180},
	)
	asn := mmdbtest.ASN(mmdbtest.ASNEntry{Prefix: "41.58.0.0/16", ASN: 36923, Org: strings.Repeat("Org\t", 100)})
	x := New()
	defer x.Close()
	x.SetCity(openTestDB(t, city, KindCity))
	x.SetASN(openTestDB(t, asn, KindASN))

	g := enrich(x, "41.58.1.1")
	if g == nil {
		t.Fatal("no Geo")
	}
	if len(g.City) > MaxCity || strings.ContainsAny(g.City, "\x00\x1b\n‮") || !strings.HasPrefix(g.City, "Lagos[31m") {
		t.Errorf("city %q (%d bytes)", g.City, len(g.City))
	}
	if !strings.HasSuffix(g.City, "é") { // cut on a UTF-8 boundary
		t.Errorf("city %q not cut on a rune boundary", g.City)
	}
	if g.Country != "NG" {
		t.Errorf("country %q, want NG", g.Country)
	}
	if g.Lat != 0 || g.Lon != 0 {
		t.Errorf("latitude 95 kept: %v,%v", g.Lat, g.Lon)
	}
	if len(g.Org) > MaxOrg || strings.Contains(g.Org, "\t") || !strings.HasPrefix(g.Org, "OrgOrg") {
		t.Errorf("org %q (%d bytes)", g.Org, len(g.Org))
	}
	if g := enrich(x, "8.8.8.8"); g == nil || g.Country != "" || g.Lat != 0 || g.Lon != 0 || g.City != "x" {
		t.Errorf("country USA / NaN latitude: %+v", g)
	}
	if g := enrich(x, "1.1.1.1"); g == nil || g.Country != "" || g.Lat != 0 || g.Lon != 0 || g.City != "Sydney" {
		t.Errorf("country A1 / Inf longitude / format characters: %+v", g)
	}
	if g := enrich(x, "9.9.9.9"); g == nil || g.Lat != -90 || g.Lon != 180 {
		t.Errorf("coordinates at the bounds dropped: %+v", g)
	}
}

// Lists: by range, by the address's ASN, sorted, at most MaxLists, invalid names refused.
func TestEnrichLists(t *testing.T) {
	x := newTestEnricher(t)
	x.SetList(ListTor, NewSet([]Range{pfx("41.58.1.0/24")}, nil))
	x.SetList(ListSpamhaus, NewSet([]Range{pfx("198.51.100.0/24")}, []uint32{36923}))
	x.SetList(ListDShield, NewSet([]Range{pfx("41.58.0.0/16")}, nil))
	g := enrich(x, "41.58.1.1")
	if g == nil || strings.Join(g.Lists, ",") != "dshield,spamhaus-drop,tor-exit" {
		t.Fatalf("lists %+v", g)
	}
	// The ASN rule needs the ASN database's answer: 41.58.200.1 is in AS36923 but in no listed range.
	if g := enrich(x, "41.58.200.1"); g == nil || strings.Join(g.Lists, ",") != "dshield,spamhaus-drop" {
		t.Errorf("ASN-DROP membership: %+v", g)
	}
	x.SetList(ListDShield, nil) // removed
	if g := enrich(x, "41.58.200.1"); g == nil || strings.Join(g.Lists, ",") != "spamhaus-drop" {
		t.Errorf("after removing dshield: %+v", g)
	}
	for i := 0; i < 12; i++ {
		x.SetList(fmt.Sprintf("extra-%02d", i), NewSet([]Range{pfx("41.58.1.0/24")}, nil))
	}
	g = enrich(x, "41.58.1.1")
	if g == nil || len(g.Lists) != MaxLists || g.Lists[0] != "extra-00" || g.Lists[MaxLists-1] != "extra-07" {
		t.Errorf("lists not cut to the first %d sorted names: %+v", MaxLists, g)
	}
	for _, bad := range []string{"", "Tor", "a b", strings.Repeat("a", 33), "x\n"} {
		x.SetList(bad, NewSet([]Range{pfx("8.8.8.0/24")}, nil))
	}
	if g := enrich(x, "8.8.8.8"); g == nil || len(g.Lists) != 0 {
		t.Errorf("a list with an invalid name was used: %+v", g)
	}
	// Lists alone (no databases) still give a Geo.
	y := New()
	defer y.Close()
	y.SetList(ListTor, NewSet([]Range{pfx("8.8.8.0/24")}, nil))
	if g := enrich(y, "8.8.8.8"); g == nil || strings.Join(g.Lists, ",") != "tor-exit" || g.Country != "" {
		t.Errorf("lists without databases: %+v", g)
	}
}

// Lookups are cached; any swap invalidates the cache; each event gets its own copy.
func TestEnrichCache(t *testing.T) {
	x := newTestEnricher(t)
	enrich(x, "41.58.1.1")
	enrich(x, "41.58.1.1")
	if n := x.misses.Load(); n != 1 {
		t.Fatalf("%d database lookups for the same address twice, want 1", n)
	}
	x.SetCity(openTestDB(t, testCity("Ikeja"), KindCity))
	if g := enrich(x, "41.58.1.1"); g == nil || g.City != "Ikeja" {
		t.Fatalf("after a City swap: %+v", g)
	}
	x.SetList(ListTor, NewSet([]Range{pfx("41.58.1.0/24")}, nil))
	if g := enrich(x, "41.58.1.1"); g == nil || len(g.Lists) != 1 {
		t.Fatalf("after a list swap: %+v", g)
	}
	x.SetASN(openTestDB(t, mmdbtest.ASN(mmdbtest.ASNEntry{Prefix: "41.58.0.0/16", ASN: 64499, Org: "New"}), KindASN))
	if g := enrich(x, "41.58.1.1"); g == nil || g.ASN != 64499 {
		t.Fatalf("after an ASN swap: %+v", g)
	}
	// Each event's Geo is its own copy.
	a, b := enrich(x, "41.58.1.1"), enrich(x, "41.58.1.1")
	a.Lists[0], a.City = "changed", "changed"
	if b.Lists[0] != ListTor || b.City != "Ikeja" || enrich(x, "41.58.1.1").City != "Ikeja" {
		t.Error("events share a Geo")
	}
	// A miss for an unknown address is cached too.
	before := x.misses.Load()
	enrich(x, "9.9.9.9")
	enrich(x, "9.9.9.9")
	if x.misses.Load() != before+1 {
		t.Error("a negative answer isn't cached")
	}
}

// A lookup that started before a swap is never cached: its answer may come from the old data.
func TestEnrichCacheDropsStaleAnswer(t *testing.T) {
	x := newTestEnricher(t)
	ip := addr("41.58.1.1")
	gen := x.gen.Load()
	stale := &siem.Geo{City: "stale"}
	x.SetList(ListTor, nil) // a swap while the lookup ran
	x.cache.put(ip, gen, stale, &x.gen)
	if g := enrich(x, "41.58.1.1"); g == nil || g.City != "Lagos" {
		t.Errorf("a stale answer was served: %+v", g)
	}
}

// The cache holds at most cacheSize addresses.
func TestEnrichCacheBounded(t *testing.T) {
	x := newTestEnricher(t)
	for i := 0; i < cacheSize+5000; i++ {
		enrich(x, netip.AddrFrom4([4]byte{41, 58, byte(i >> 8), byte(i)}).String())
	}
	if n := x.cache.len(); n > cacheSize || n < cacheSize-1 {
		t.Errorf("cache holds %d entries, want %d", n, cacheSize)
	}
	// The newest are kept, the oldest evicted.
	before := x.misses.Load()
	newest := cacheSize + 4999
	enrich(x, netip.AddrFrom4([4]byte{41, 58, byte(newest >> 8), byte(newest)}).String())
	if x.misses.Load() != before {
		t.Error("the newest address was evicted")
	}
	enrich(x, "41.58.0.0")
	if x.misses.Load() != before+1 {
		t.Error("the oldest address wasn't evicted")
	}
}

// Enrich runs concurrently with swaps (go test -race): no data race, no lookup on a closed
// database, and every swapped-out database is closed once nothing uses it.
func TestEnrichConcurrentSwaps(t *testing.T) {
	x := New()
	defer x.Close()
	var (
		mu  sync.Mutex
		old []*DB
	)
	swapCity := func(name string) {
		d := openTestDB(t, testCity(name), KindCity)
		mu.Lock()
		old = append(old, d)
		mu.Unlock()
		x.SetCity(d)
	}
	swapCity("Lagos")
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				g := enrich(x, netip.AddrFrom4([4]byte{41, 58, byte(w), byte(i)}).String())
				if g != nil && g.Country != "NG" {
					t.Errorf("wrong country %+v", g)
					return
				}
			}
		}(w)
	}
	for i := 0; i < 60; i++ {
		swapCity(fmt.Sprintf("Lagos-%d", i))
		x.SetASN(openTestDB(t, testASN(), KindASN))
		x.SetList(ListTor, NewSet([]Range{pfx("41.58.0.0/24")}, nil))
	}
	close(stop)
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	for i, d := range old[:len(old)-1] {
		if !d.closed() {
			t.Errorf("swapped-out database %d never closed", i)
		}
	}
	if old[len(old)-1].closed() {
		t.Error("the database in use was closed")
	}
	x.Close()
	if !old[len(old)-1].closed() {
		t.Error("Close left the database in use open")
	}
	if g := enrich(x, "41.58.1.1"); g != nil {
		t.Errorf("enriched after Close: %+v", g)
	}
}

// A database in use is never unmapped under a lookup: release waits for the last user.
func TestDBRefcount(t *testing.T) {
	d := openTestDB(t, testCity("Lagos"), KindCity)
	if !d.acquire() {
		t.Fatal("acquire on an open database failed")
	}
	d.Close() // the owner lets go while a lookup holds it
	if d.closed() {
		t.Fatal("closed while a lookup held it")
	}
	var rec cityRecord
	if err := d.r.Lookup(addr("41.58.1.1")).Decode(&rec); err != nil || rec.City.Names.En != "Lagos" {
		t.Fatalf("lookup while held: %v %+v", err, rec)
	}
	d.release()
	if !d.closed() {
		t.Fatal("not closed after the last release")
	}
	if d.acquire() {
		t.Error("acquire succeeded on a closed database")
	}
	d.Close() // a second Close is harmless
}

func BenchmarkEnrichCached(b *testing.B) {
	x := newTestEnricher(b)
	x.SetList(ListTor, NewSet([]Range{pfx("41.58.1.0/24")}, nil))
	e := siem.Event{IP: "41.58.1.1"}
	x.Enrich(&e)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.Geo = nil
		x.Enrich(&e)
	}
	if e.Geo == nil {
		b.Fatal("no Geo")
	}
}

func BenchmarkEnrichUncached(b *testing.B) {
	x := newTestEnricher(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e := siem.Event{IP: "41.58.1.1"}
		x.cache.reset()
		x.Enrich(&e)
	}
}
