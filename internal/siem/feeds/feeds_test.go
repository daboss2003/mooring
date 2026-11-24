package feeds

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/enrich"
	"github.com/daboss2003/mooring/internal/siem/enrich/mmdbtest"
)

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type response struct {
	status  int
	body    []byte
	header  map[string]string
	chunked bool   // no Content-Length
	repeat  int    // body is written this many times, chunked; the bytes written are counted
	written *int64 // where repeat's count goes
}

// feedServer serves the feed files over TLS by path; a path it doesn't know answers 404.
type feedServer struct {
	srv   *httptest.Server
	mu    sync.Mutex
	files map[string]response
	hits  map[string]int
	uas   map[string][]string
	hold  map[string]chan struct{} // the request waits until it is closed or the client gives up
}

func newFeedServer(t *testing.T) *feedServer {
	fs := &feedServer{files: map[string]response{}, hits: map[string]int{}, uas: map[string][]string{}, hold: map[string]chan struct{}{}}
	fs.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fs.mu.Lock()
		fs.hits[r.URL.Path]++
		fs.uas[r.URL.Path] = append(fs.uas[r.URL.Path], r.UserAgent())
		resp, ok := fs.files[r.URL.Path]
		hold := fs.hold[r.URL.Path]
		fs.mu.Unlock()
		if hold != nil {
			select {
			case <-hold:
			case <-r.Context().Done():
				return
			}
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		for k, v := range resp.header {
			w.Header().Set(k, v)
		}
		if resp.status != 0 {
			w.WriteHeader(resp.status)
		}
		if resp.chunked || resp.repeat > 0 {
			w.(http.Flusher).Flush() // headers out without a Content-Length
		}
		if resp.repeat == 0 {
			w.Write(resp.body)
			return
		}
		for i := 0; i < resp.repeat; i++ {
			n, err := w.Write(resp.body)
			fs.mu.Lock()
			*resp.written += int64(n)
			fs.mu.Unlock()
			if err != nil {
				return
			}
		}
	}))
	t.Cleanup(fs.srv.Close)
	return fs
}

func (fs *feedServer) set(path string, r response) { fs.mu.Lock(); fs.files[path] = r; fs.mu.Unlock() }
func (fs *feedServer) del(path string)             { fs.mu.Lock(); delete(fs.files, path); fs.mu.Unlock() }
func (fs *feedServer) hit(path string) int         { fs.mu.Lock(); defer fs.mu.Unlock(); return fs.hits[path] }
func (fs *feedServer) total(prefix string) int {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	n := 0
	for p, h := range fs.hits {
		if strings.HasPrefix(p, prefix) {
			n += h
		}
	}
	return n
}

func gz(t testing.TB, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write(b)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func cityFile(t testing.TB, city string) []byte {
	return gz(t, mmdbtest.City(mmdbtest.CityEntry{Prefix: "41.58.0.0/18", City: city, Country: "NG", Lat: 6.4, Lon: 3.4}))
}

func asnFile(t testing.TB, org string) []byte {
	return gz(t, mmdbtest.ASN(mmdbtest.ASNEntry{Prefix: "41.58.0.0/16", ASN: 36923, Org: org}))
}

const (
	cityPath = "/free/dbip-city-lite-"
	asnPath  = "/free/dbip-asn-lite-"
)

// serveAll serves a valid file for every feed (DB-IP for month).
func (fs *feedServer) serveAll(t *testing.T, month string) {
	fs.set(cityPath+month+".mmdb.gz", response{body: cityFile(t, "Lagos-"+month)})
	fs.set(asnPath+month+".mmdb.gz", response{body: asnFile(t, "SWIFT "+month)})
	fs.set("/drop/drop_v4.json", response{body: []byte(spamhausFile(`{"cidr":"41.58.1.0/24","sblid":"SBL1"}`, `{"cidr":"1.10.16.0/20","sblid":"SBL2"}`))})
	fs.set("/drop/drop_v6.json", response{body: []byte(spamhausFile(`{"cidr":"2001:678:254::/48","sblid":"SBL3"}`))})
	fs.set("/drop/asndrop.json", response{body: []byte(spamhausFile(`{"asn":64496,"rir":"arin"}`))})
	fs.set("/torbulkexitlist", response{body: []byte(torList(150, "41.58.2.2")), header: map[string]string{"Last-Modified": "Tue, 24 Nov 2026 09:00:00 GMT"}})
	fs.set("/block.txt", response{body: []byte(dshieldSample + "41.58.3.0\t41.58.3.255\t24\t10\tX\tNG\tx@example.com\n")})
}

type testEnv struct {
	t   *testing.T
	fs  *feedServer
	clk *fakeClock
	dir string
}

func newEnv(t *testing.T, start time.Time) *testEnv {
	return &testEnv{t: t, fs: newFeedServer(t), clk: &fakeClock{t: start}, dir: filepath.Join(t.TempDir(), "feeds")}
}

// manager is a Manager on the env's dir, server and clock, with every feed on and no DShield
// contact unless mod changes it.
func (e *testEnv) manager(mod func(*Options)) (*Manager, *enrich.Enricher) {
	e.t.Helper()
	x := enrich.New()
	e.t.Cleanup(x.Close)
	opt := Options{
		Dir: e.dir, Enricher: x, GeoIP: true, Spamhaus: true, Tor: true, Version: "1.2.3", Log: discard, Now: e.clk.Now,
		client: e.fs.srv.Client(),
		urls: urls{dbip: e.fs.srv.URL + "/free/", spamhaus: e.fs.srv.URL + "/drop/", tor: e.fs.srv.URL + "/torbulkexitlist",
			dshield: e.fs.srv.URL + "/block.txt"},
	}
	if mod != nil {
		mod(&opt)
	}
	m, err := New(opt)
	if err != nil {
		e.t.Fatal(err)
	}
	return m, x
}

func status(m *Manager, name string) siem.FeedStatus {
	for _, s := range m.FeedStatus() {
		if s.Name == name {
			return s
		}
	}
	return siem.FeedStatus{}
}

func geo(x *enrich.Enricher, ip string) *siem.Geo {
	e := siem.Event{IP: ip}
	x.Enrich(&e)
	return e.Geo
}

func run(m *Manager) { m.runDue(context.Background()) }

// The first run fetches every enabled feed; the data is used at once and kept in Dir.
func TestFirstRunFetchesEverything(t *testing.T) {
	e := newEnv(t, time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC))
	e.fs.serveAll(t, "2026-11")
	m, x := e.manager(nil)
	run(m)
	now := e.clk.Now()
	g := geo(x, "41.58.1.1")
	if g == nil || g.City != "Lagos-2026-11" || g.Org != "SWIFT 2026-11" || strings.Join(g.Lists, ",") != "spamhaus-drop" {
		t.Fatalf("Geo %+v", g)
	}
	if g := geo(x, "41.58.2.2"); g == nil || strings.Join(g.Lists, ",") != "tor-exit" {
		t.Errorf("tor: %+v", g)
	}
	for name, want := range map[string]siem.FeedStatus{
		NameCity:     {Name: NameCity, Enabled: true, Version: "2026-11", Updated: now, NextTry: now.Add(24 * time.Hour)},
		NameASN:      {Name: NameASN, Enabled: true, Version: "2026-11", Updated: now, NextTry: now.Add(24 * time.Hour)},
		NameSpamhaus: {Name: NameSpamhaus, Enabled: true, Version: "2026-11-24T17:26Z", Updated: now, Entries: 4, NextTry: now.Add(24 * time.Hour)},
		NameTor:      {Name: NameTor, Enabled: true, Version: "2026-11-24T09:00Z", Updated: now, Entries: 151, NextTry: now.Add(6 * time.Hour)},
		NameDShield:  {Name: NameDShield},
	} {
		if got := status(m, name); got != want {
			t.Errorf("%s: %+v\nwant %+v", name, got, want)
		}
	}
	if e.fs.total("/block.txt") != 0 {
		t.Error("DShield fetched without a contact")
	}
	for p, uas := range e.fs.uas {
		for _, ua := range uas {
			if ua != "Mooring/1.2.3" {
				t.Errorf("%s: User-Agent %q", p, ua)
			}
		}
	}
	fi, err := os.Stat(e.dir)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("dir %v %v", fi.Mode(), err)
	}
	ents, _ := os.ReadDir(e.dir)
	var names []string
	for _, de := range ents {
		names = append(names, de.Name())
		if fi, _ := de.Info(); fi.Mode().Perm() != 0o600 {
			t.Errorf("%s is %v", de.Name(), fi.Mode())
		}
	}
	if got := strings.Join(names, ","); got != "dbip-asn.mmdb,dbip-city.mmdb,spamhaus-drop.json,state.json,tor-exits.json" {
		t.Errorf("files %s", got)
	}
}

// The current month's file missing (404), the previous month's is used; that same version is never
// downloaded again; the current one is taken when it appears.
func TestDBIPMonthFallback(t *testing.T) {
	e := newEnv(t, time.Date(2026, 11, 1, 3, 0, 0, 0, time.UTC))
	e.fs.serveAll(t, "2026-10")
	m, x := e.manager(nil)
	run(m)
	if s := status(m, NameCity); s.Version != "2026-10" || s.LastError != "" {
		t.Fatalf("status %+v", s)
	}
	if e.fs.hit(cityPath+"2026-11.mmdb.gz") != 1 || e.fs.hit(cityPath+"2026-10.mmdb.gz") != 1 {
		t.Fatalf("hits %v", e.fs.hits)
	}
	e.clk.Advance(24 * time.Hour)
	run(m)
	if e.fs.hit(cityPath+"2026-11.mmdb.gz") != 2 || e.fs.hit(cityPath+"2026-10.mmdb.gz") != 1 {
		t.Errorf("the version in use was downloaded again: %v", e.fs.hits)
	}
	if s := status(m, NameCity); s.Version != "2026-10" || s.LastError != "" || !s.NextTry.Equal(e.clk.Now().Add(24*time.Hour)) {
		t.Errorf("no newer version is not an error: %+v", s)
	}
	e.fs.set(cityPath+"2026-11.mmdb.gz", response{body: cityFile(t, "Lagos-2026-11")})
	e.clk.Advance(24 * time.Hour)
	run(m)
	if g := geo(x, "41.58.1.1"); g == nil || g.City != "Lagos-2026-11" {
		t.Errorf("the new month isn't used: %+v", g)
	}
	if s := status(m, NameCity); s.Version != "2026-11" {
		t.Errorf("status %+v", s)
	}
	// With the current month in use, a check asks for nothing.
	before := e.fs.total("/free/")
	e.clk.Advance(24 * time.Hour)
	run(m)
	if e.fs.total("/free/") != before+1 { // the ASN file is still on 2026-10: only it asks for 2026-11
		t.Errorf("requests %v", e.fs.hits)
	}
}

// January falls back to December of the year before; neither month there is an error.
func TestDBIPMonths(t *testing.T) {
	cur, prev := months(time.Date(2026, 1, 1, 0, 30, 0, 0, time.UTC))
	if cur != "2026-01" || prev != "2025-12" {
		t.Errorf("%s %s", cur, prev)
	}
	cur, prev = months(time.Date(2026, 3, 31, 23, 0, 0, 0, time.FixedZone("x", -5*3600))) // 2026-04-01 04:00 UTC
	if cur != "2026-04" || prev != "2026-03" {
		t.Errorf("UTC month: %s %s", cur, prev)
	}
	e := newEnv(t, time.Date(2026, 11, 2, 0, 0, 0, 0, time.UTC))
	m, _ := e.manager(func(o *Options) { o.Spamhaus, o.Tor = false, false })
	run(m)
	if s := status(m, NameCity); s.LastError == "" || !strings.Contains(s.LastError, "2026-11") || !strings.Contains(s.LastError, "2026-10") {
		t.Errorf("no file for either month: %+v", s)
	}
}

// After a restart the files on disk are used at once, without a network; nothing is fetched before
// it is due.
func TestRestartUsesFilesOffline(t *testing.T) {
	e := newEnv(t, time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC))
	e.fs.serveAll(t, "2026-11")
	m, _ := e.manager(nil)
	run(m)
	want := m.FeedStatus()
	e.fs.srv.Close()

	e.clk.Advance(time.Hour)
	m2, x2 := e.manager(nil)
	g := geo(x2, "41.58.1.1")
	if g == nil || g.City != "Lagos-2026-11" || g.ASN != 36923 || strings.Join(g.Lists, ",") != "spamhaus-drop" {
		t.Fatalf("after a restart: %+v", g)
	}
	if g := geo(x2, "41.58.2.2"); g == nil || strings.Join(g.Lists, ",") != "tor-exit" {
		t.Errorf("tor after a restart: %+v", g)
	}
	got := m2.FeedStatus()
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("status after a restart %+v\nwant %+v", got[i], want[i])
		}
	}
	run(m2) // nothing is due: the closed server would make every attempt fail
	for _, s := range m2.FeedStatus() {
		if s.LastError != "" {
			t.Errorf("%s fetched before it was due: %s", s.Name, s.LastError)
		}
	}
}

// A download over a cap, not gzip, corrupt, or of the wrong type is refused: the previous file
// stays in use and on disk, and no temporary file is left.
func TestDBIPRefusedKeepsPrevious(t *testing.T) {
	e := newEnv(t, time.Date(2026, 11, 1, 3, 0, 0, 0, time.UTC))
	e.fs.serveAll(t, "2026-10")
	m, x := e.manager(func(o *Options) { o.Spamhaus, o.Tor = false, false })
	run(m)
	if status(m, NameCity).Version != "2026-10" {
		t.Fatal("setup")
	}
	city := m.feed(NameCity)
	// A valid database just over each cap: refused only by the cap.
	raw := mmdbtest.City(mmdbtest.CityEntry{Prefix: "41.58.0.0/18", City: "Lagos-big", Country: "NG"})
	packed := gz(t, raw)
	const roomy = 1 << 20
	var streamed int64
	emptyMember := gz(t, nil)
	for name, c := range map[string]struct {
		r               response
		compCap, rawCap int64
		want            string // in the error
	}{
		"uncompressed over the cap":        {response{body: packed}, roomy, int64(len(raw) - 1), "uncompressed"},
		"compressed over the cap":          {response{body: packed}, int64(len(packed) - 1), roomy, "download is larger"},
		"compressed over the cap, chunked": {response{body: packed, chunked: true}, int64(len(packed) - 1), roomy, "download is larger"},
		"a gzip bomb":                      {response{body: gz(t, make([]byte, 8<<20)), chunked: true}, roomy, roomy, "uncompressed"},
		"endless empty gzip members":       {response{body: bytes.Repeat(emptyMember, 4096), repeat: 1 << 10, written: &streamed}, 64 << 10, roomy, "download is larger"},
		"declared over the cap":            {response{body: packed, header: map[string]string{"Content-Length": strconv.Itoa(roomy + 1)}}, roomy, roomy, "download is larger"},
		"not gzip":                         {response{body: raw}, roomy, roomy, "gzip"},
		"truncated gzip":                   {response{body: packed[:len(packed)/2]}, roomy, roomy, "gunzip"},
		"corrupt database":                 {response{body: gz(t, []byte(strings.Repeat("garbage", 1000)))}, roomy, roomy, "enrich"},
		"an ASN database":                  {response{body: asnFile(t, "wrong type")}, roomy, roomy, "database type"},
		"an empty file":                    {response{body: nil}, roomy, roomy, "gzip"},
		"an empty database":                {response{body: gz(t, nil)}, roomy, roomy, "empty"},
		"a server error":                   {response{status: 500, body: []byte("oops")}, roomy, roomy, "500"},
		"a gzip member then garbage":       {response{body: append(append([]byte{}, packed...), []byte("trailing junk")...)}, roomy, roomy, "gunzip"},
	} {
		t.Run(name, func(t *testing.T) {
			e.fs.set(cityPath+"2026-11.mmdb.gz", c.r)
			city.compCap, city.rawCap = c.compCap, c.rawCap
			city.st.NextTry, city.st.LastAttempt = time.Time{}, time.Time{}
			run(m)
			if s := status(m, NameCity); s.Version != "2026-10" || !strings.Contains(s.LastError, c.want) {
				t.Errorf("status %+v, want an error with %q", s, c.want)
			}
			if g := geo(x, "41.58.1.1"); g == nil || g.City != "Lagos-2026-10" {
				t.Errorf("the previous database isn't in use: %+v", g)
			}
			ents, _ := os.ReadDir(e.dir)
			for _, de := range ents {
				if strings.Contains(de.Name(), ".tmp") {
					t.Errorf("left behind: %s", de.Name())
				}
			}
			root, _ := os.OpenRoot(e.dir)
			defer root.Close()
			d, err := enrich.OpenDB(root, "dbip-city.mmdb", enrich.KindCity, 1<<20)
			if err != nil {
				t.Fatalf("the file on disk: %v", err)
			}
			d.Close()
		})
	}
	// The endless stream stopped being read at the cap (the server wrote far less than its 80 MiB).
	e.fs.mu.Lock()
	if streamed >= 16<<20 {
		t.Errorf("%d bytes of an endless download were read", streamed)
	}
	e.fs.mu.Unlock()
	// The same file exactly at the caps is taken.
	e.fs.set(cityPath+"2026-11.mmdb.gz", response{body: packed})
	city.compCap, city.rawCap = int64(len(packed)), int64(len(raw))
	city.st.NextTry, city.st.LastAttempt = time.Time{}, time.Time{}
	run(m)
	if s := status(m, NameCity); s.Version != "2026-11" || s.LastError != "" {
		t.Errorf("status %+v", s)
	}
	if g := geo(x, "41.58.1.1"); g == nil || g.City != "Lagos-big" {
		t.Errorf("Geo %+v", g)
	}
}

// The production caps.
func TestDBIPCaps(t *testing.T) {
	e := newEnv(t, time.Now())
	m, _ := e.manager(nil)
	if c := m.feed(NameCity); c.compCap != 120<<20 || c.rawCap != 256<<20 || c.timeout != 15*time.Minute {
		t.Errorf("city caps %d %d %v", c.compCap, c.rawCap, c.timeout)
	}
	if c := m.feed(NameASN); c.compCap != 20<<20 || c.rawCap != 40<<20 || c.timeout != 15*time.Minute {
		t.Errorf("asn caps %d %d %v", c.compCap, c.rawCap, c.timeout)
	}
	for _, n := range []string{NameSpamhaus, NameTor, NameDShield} {
		if c := m.feed(n); c.timeout != time.Minute {
			t.Errorf("%s timeout %v", n, c.timeout)
		}
	}
}

func readState(t *testing.T, dir string) map[string]feedState {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	var s stateFile
	if err := json.Unmarshal(b, &s); err != nil {
		t.Fatal(err)
	}
	return s.Feeds
}

// A failure backs off 1 h, 2 h, 4 h … 24 h; the state survives a restart, so a restart doesn't
// retry early.
func TestBackoffPersisted(t *testing.T) {
	e := newEnv(t, time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC))
	e.fs.set("/torbulkexitlist", response{status: 503, body: []byte("busy")})
	only := func(o *Options) { o.GeoIP, o.Spamhaus = false, false }
	m, _ := e.manager(only)
	start := e.clk.Now()
	run(m)
	s := status(m, NameTor)
	if !strings.Contains(s.LastError, "503") || !s.NextTry.Equal(start.Add(time.Hour)) {
		t.Fatalf("after one failure: %+v", s)
	}
	e.clk.Advance(30 * time.Minute)
	run(m)
	if e.fs.hit("/torbulkexitlist") != 1 {
		t.Fatal("retried before the backoff")
	}
	e.clk.Advance(30 * time.Minute)
	run(m)
	if e.fs.hit("/torbulkexitlist") != 2 || !status(m, NameTor).NextTry.Equal(e.clk.Now().Add(2*time.Hour)) {
		t.Fatalf("second failure: hits %d status %+v", e.fs.hit("/torbulkexitlist"), status(m, NameTor))
	}
	if st := readState(t, e.dir)[NameTor]; st.Fails != 2 || !st.NextTry.Equal(e.clk.Now().Add(2*time.Hour)) {
		t.Errorf("persisted %+v", st)
	}
	// A restart keeps the backoff.
	e.clk.Advance(time.Hour)
	m2, _ := e.manager(only)
	if s := status(m2, NameTor); !s.NextTry.Equal(e.clk.Now().Add(time.Hour)) || !strings.Contains(s.LastError, "503") {
		t.Errorf("after a restart: %+v", s)
	}
	run(m2)
	if e.fs.hit("/torbulkexitlist") != 2 {
		t.Fatal("a restart retried early")
	}
	e.clk.Advance(time.Hour)
	run(m2)
	if e.fs.hit("/torbulkexitlist") != 3 || !status(m2, NameTor).NextTry.Equal(e.clk.Now().Add(4*time.Hour)) {
		t.Errorf("third failure: %+v", status(m2, NameTor))
	}
	// Success resets it; the next fetch is the feed's interval away.
	e.fs.set("/torbulkexitlist", response{body: []byte(torList(150))})
	e.clk.Advance(4 * time.Hour)
	run(m2)
	if s := status(m2, NameTor); s.LastError != "" || !s.NextTry.Equal(e.clk.Now().Add(6*time.Hour)) || s.Entries != 150 {
		t.Errorf("after a success: %+v", s)
	}
	if st := readState(t, e.dir)[NameTor]; st.Fails != 0 {
		t.Errorf("fails %d after a success", st.Fails)
	}
	for fails, want := range map[int]time.Duration{1: time.Hour, 2: 2 * time.Hour, 3: 4 * time.Hour, 5: 16 * time.Hour, 6: 24 * time.Hour, 7: 24 * time.Hour, 64: 24 * time.Hour, 1 << 20: 24 * time.Hour} {
		if got := backoff(fails); got != want {
			t.Errorf("backoff(%d) = %v, want %v", fails, got, want)
		}
	}
}

// Spamhaus: at most once a day after a success, never twice within an hour, across restarts — also
// when an attempt was cut short by a shutdown.
func TestSpamhausLimitsAcrossRestarts(t *testing.T) {
	e := newEnv(t, time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC))
	e.fs.serveAll(t, "2026-11")
	only := func(o *Options) { o.GeoIP, o.Tor = false, false }
	m, _ := e.manager(only)
	run(m)
	if e.fs.hit("/drop/drop_v4.json") != 1 {
		t.Fatal("setup")
	}
	e.clk.Advance(2 * time.Hour)
	m2, _ := e.manager(only)
	run(m2)
	e.clk.Advance(21*time.Hour + 59*time.Minute)
	run(m2)
	if n := e.fs.hit("/drop/drop_v4.json"); n != 1 {
		t.Fatalf("fetched %d times within a day", n)
	}
	e.clk.Advance(time.Minute)
	run(m2)
	if n := e.fs.hit("/drop/drop_v4.json"); n != 2 {
		t.Fatalf("not fetched after a day: %d", n)
	}

	// An attempt cut short: the state records it before the request, so a restart waits an hour.
	hold := make(chan struct{})
	e.fs.mu.Lock()
	e.fs.hold["/drop/drop_v4.json"] = hold
	e.fs.mu.Unlock()
	defer close(hold)
	e.clk.Advance(24 * time.Hour)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m2.runDue(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for e.fs.hit("/drop/drop_v4.json") != 3 {
		if time.Now().After(deadline) {
			t.Fatal("the request never came")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if st := readState(t, e.dir)[NameSpamhaus]; !st.LastAttempt.Equal(e.clk.Now()) || st.Fails != 0 {
		t.Errorf("after a cut-short attempt: %+v", st)
	}
	e.fs.mu.Lock()
	delete(e.fs.hold, "/drop/drop_v4.json")
	e.fs.mu.Unlock()
	e.clk.Advance(59 * time.Minute)
	m3, _ := e.manager(only)
	run(m3)
	if n := e.fs.hit("/drop/drop_v4.json"); n != 3 {
		t.Fatalf("retried %d within the hour", n-3)
	}
	e.clk.Advance(time.Minute)
	run(m3)
	if n := e.fs.hit("/drop/drop_v4.json"); n != 4 {
		t.Errorf("not retried after the hour: %d", n)
	}
	// A failed attempt that downloaded a file (drop_v4.json, drop_v6.json) waits a day too.
	e.fs.set("/drop/asndrop.json", response{status: 500})
	e.clk.Advance(24 * time.Hour)
	run(m3)
	if s := status(m3, NameSpamhaus); s.LastError == "" || !s.NextTry.Equal(e.clk.Now().Add(24*time.Hour)) {
		t.Errorf("after a failure: %+v", s)
	}
	if spamhausGap := m3.feed(NameSpamhaus).minGap; spamhausGap != time.Hour {
		t.Errorf("min gap %v", spamhausGap)
	}
}

// Spamhaus: an attempt that received any of its files waits at least a day, failures included; one
// that received none backs off as usual. Also when a shutdown cut it short.
func TestSpamhausWaitsADayAfterAnyDownload(t *testing.T) {
	only := func(o *Options) { o.GeoIP, o.Tor = false, false }
	v4 := "/drop/drop_v4.json"
	limited := response{status: 429, header: map[string]string{"Retry-After": "7200"}}
	for name, c := range map[string]struct {
		mod  func(fs *feedServer)
		wait time.Duration
	}{
		"the last file fails":       {func(fs *feedServer) { fs.set("/drop/asndrop.json", response{status: 500}) }, 24 * time.Hour},
		"the last file is missing":  {func(fs *feedServer) { fs.del("/drop/asndrop.json") }, 24 * time.Hour},
		"the first file is refused": {func(fs *feedServer) { fs.set(v4, response{body: []byte("<html>busy</html>\n")}) }, 24 * time.Hour},
		"the first file is too big": {func(fs *feedServer) { fs.set(v4, response{body: bytes.Repeat([]byte("x"), spamhausCap+1)}) }, 24 * time.Hour},
		"the first file fails":      {func(fs *feedServer) { fs.set(v4, response{status: 503}) }, time.Hour},
		"the first file is limited": {func(fs *feedServer) { fs.set(v4, limited) }, 2 * time.Hour},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC))
			e.fs.serveAll(t, "2026-11")
			c.mod(e.fs)
			m, _ := e.manager(only)
			run(m)
			start := e.clk.Now()
			if s := status(m, NameSpamhaus); s.LastError == "" || !s.NextTry.Equal(start.Add(c.wait)) {
				t.Fatalf("status %+v, want the next try in %v", s, c.wait)
			}
			e.fs.serveAll(t, "2026-11")
			e.clk.Advance(c.wait - time.Minute)
			m2, _ := e.manager(only) // across a restart too
			run(m2)
			if n := e.fs.hit(v4); n != 1 {
				t.Fatalf("retried within %v", c.wait)
			}
			e.clk.Advance(time.Minute)
			run(m2)
			if n := e.fs.hit(v4); n != 2 || status(m2, NameSpamhaus).LastError != "" {
				t.Errorf("not retried after %v: %d %+v", c.wait, n, status(m2, NameSpamhaus))
			}
		})
	}

	// Cut short by a shutdown after drop_v4.json arrived: a day, also after a restart.
	e := newEnv(t, time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC))
	e.fs.serveAll(t, "2026-11")
	hold := make(chan struct{})
	defer close(hold)
	e.fs.mu.Lock()
	e.fs.hold["/drop/drop_v6.json"] = hold
	e.fs.mu.Unlock()
	m, _ := e.manager(only)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.runDue(ctx); close(done) }()
	waitHit(t, e.fs, "/drop/drop_v6.json", 1)
	cancel()
	<-done
	start := e.clk.Now()
	if st := readState(t, e.dir)[NameSpamhaus]; !st.LastAttempt.Equal(start) || !st.NextTry.Equal(start.Add(24*time.Hour)) || st.Fails != 0 {
		t.Errorf("after a cut-short attempt that downloaded: %+v", st)
	}
	e.fs.mu.Lock()
	delete(e.fs.hold, "/drop/drop_v6.json")
	e.fs.mu.Unlock()
	e.clk.Advance(23*time.Hour + 59*time.Minute)
	m2, _ := e.manager(only)
	run(m2)
	if n := e.fs.hit(v4); n != 1 {
		t.Fatalf("retried %d within the day", n-1)
	}
	e.clk.Advance(time.Minute)
	run(m2)
	if n := e.fs.hit(v4); n != 2 {
		t.Errorf("not retried after the day: %d", n)
	}
}

// waitHit waits until path has been requested n times.
func waitHit(t *testing.T, fs *feedServer, path string, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for fs.hit(path) < n {
		if time.Now().After(deadline) {
			t.Fatalf("%s: the request never came", path)
		}
		time.Sleep(time.Millisecond)
	}
}

// The next try is saved before the request: the state a crash leaves mid-attempt (here: a copy of
// the directory taken while the request is held) doesn't retry early — Spamhaus a day later, as if
// the attempt had downloaded, another feed after the first backoff rather than its least gap.
func TestCrashMidAttemptKeepsTheWait(t *testing.T) {
	for _, c := range []struct {
		name, held string
		mod        func(*Options)
		wait       time.Duration
	}{
		{NameSpamhaus, "/drop/asndrop.json", func(o *Options) { o.GeoIP, o.Tor = false, false }, 24 * time.Hour},
		{NameTor, "/torbulkexitlist", func(o *Options) { o.GeoIP, o.Spamhaus = false, false }, time.Hour},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC))
			e.fs.serveAll(t, "2026-11")
			hold := make(chan struct{})
			e.fs.mu.Lock()
			e.fs.hold[c.held] = hold
			e.fs.mu.Unlock()
			m, _ := e.manager(c.mod)
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() { m.runDue(ctx); close(done) }()
			waitHit(t, e.fs, c.held, 1)
			// The crash: what is on disk now is all the next start has.
			crashed := filepath.Join(t.TempDir(), "feeds")
			if err := os.MkdirAll(crashed, 0o700); err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(filepath.Join(e.dir, "state.json"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(crashed, "state.json"), b, 0o600); err != nil {
				t.Fatal(err)
			}
			cancel()
			close(hold)
			<-done
			start := e.clk.Now()
			if st := readState(t, crashed)[c.name]; !st.LastAttempt.Equal(start) || !st.NextTry.Equal(start.Add(c.wait)) {
				t.Fatalf("state saved before the request %+v, want the next try in %v", st, c.wait)
			}
			e.fs.mu.Lock()
			delete(e.fs.hold, c.held)
			e.fs.mu.Unlock()
			e.dir = crashed
			before := e.fs.hit(c.held)
			e.clk.Advance(c.wait - time.Minute)
			m2, _ := e.manager(c.mod)
			run(m2)
			if e.fs.hit(c.held) != before {
				t.Fatalf("retried within %v of a crash", c.wait)
			}
			e.clk.Advance(time.Minute)
			run(m2)
			if e.fs.hit(c.held) != before+1 || status(m2, c.name).LastError != "" {
				t.Errorf("not retried after %v: %+v", c.wait, status(m2, c.name))
			}
		})
	}
}

// When the schedule can't be saved before an attempt, nothing is requested: the attempt is a
// failure (backed off), so no restart can repeat a request it doesn't know was made.
func TestStateNotSavedSkipsTheAttempt(t *testing.T) {
	e := newEnv(t, time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC))
	e.fs.serveAll(t, "2026-11")
	// state.json a directory: every save fails.
	if err := os.MkdirAll(filepath.Join(e.dir, "state.json", "x"), 0o700); err != nil {
		t.Fatal(err)
	}
	m, _ := e.manager(nil)
	run(m)
	if n := e.fs.total("/"); n != 0 {
		t.Fatalf("%d requests without a saved schedule: %v", n, e.fs.hits)
	}
	for _, s := range m.FeedStatus() {
		if s.Enabled && (!strings.Contains(s.LastError, "schedule") || !s.NextTry.Equal(e.clk.Now().Add(time.Hour))) {
			t.Errorf("%+v", s)
		}
	}
	e.clk.Advance(59 * time.Minute)
	run(m)
	if n := e.fs.total("/"); n != 0 {
		t.Fatalf("retried within the backoff: %v", e.fs.hits)
	}
	if err := os.RemoveAll(filepath.Join(e.dir, "state.json")); err != nil {
		t.Fatal(err)
	}
	e.clk.Advance(time.Minute)
	run(m)
	if e.fs.hit("/drop/drop_v4.json") != 1 || e.fs.hit("/torbulkexitlist") != 1 {
		t.Errorf("not fetched once the state could be saved: %v", e.fs.hits)
	}
	if st := readState(t, e.dir)[NameSpamhaus]; st.Fails != 0 || st.LastSuccess.IsZero() {
		t.Errorf("state %+v", st)
	}
}

// A time in the future (the clock was set back) is moved back to now, with the wait that followed
// it: the spacing is kept, and no feed is held off more than a day.
func TestFutureStateClamped(t *testing.T) {
	e := newEnv(t, time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC))
	e.fs.serveAll(t, "2026-11")
	if err := os.MkdirAll(e.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	now := e.clk.Now()
	st := stateFile{V: 1, Feeds: map[string]feedState{
		NameTor:      {LastAttempt: now.Add(30 * 24 * time.Hour), NextTry: now.Add(300 * 24 * time.Hour), Fails: 3},
		NameSpamhaus: {LastAttempt: now.Add(time.Hour), LastSuccess: now.Add(time.Hour), Updated: now.Add(time.Hour), NextTry: now.Add(25 * time.Hour)},
		NameDShield:  {LastAttempt: now.Add(2 * time.Hour), NextTry: now.Add(3 * time.Hour)},
	}}
	b, _ := json.Marshal(st)
	if err := os.WriteFile(filepath.Join(e.dir, "state.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	m, _ := e.manager(func(o *Options) { o.GeoIP, o.DShieldContact = false, "soc@example.com" })
	for name, want := range map[string]time.Duration{NameTor: 24 * time.Hour, NameSpamhaus: 24 * time.Hour, NameDShield: time.Hour} {
		if s := status(m, name); !s.NextTry.Equal(now.Add(want)) {
			t.Errorf("%s after loading future times: next try %v, want %v", name, s.NextTry, now.Add(want))
		}
		if st := m.feed(name).st; st.LastAttempt.After(now) || st.LastSuccess.After(now) || st.Updated.After(now) {
			t.Errorf("%s: a time after now kept: %+v", name, st)
		}
	}
	run(m)
	if n := e.fs.total("/"); n != 0 {
		t.Fatalf("fetched within the spacing: %v", e.fs.hits)
	}
	e.clk.Advance(time.Hour)
	run(m)
	if e.fs.hit("/block.txt") != 1 || e.fs.hit("/torbulkexitlist") != 0 || e.fs.hit("/drop/drop_v4.json") != 0 {
		t.Fatalf("hits %v after an hour", e.fs.hits)
	}
	e.clk.Advance(23 * time.Hour)
	run(m)
	if e.fs.hit("/torbulkexitlist") != 1 || e.fs.hit("/drop/drop_v4.json") != 1 {
		t.Fatalf("hits %v: future times held the feeds off more than a day", e.fs.hits)
	}
	// The clock set back 30 days while running: each feed's wait after its last attempt is kept by
	// the new clock, not 30 days longer.
	e.clk.Advance(-30 * 24 * time.Hour)
	run(m)
	if e.fs.hit("/torbulkexitlist") != 1 || e.fs.hit("/drop/drop_v4.json") != 1 {
		t.Fatalf("hits %v: a clock step back fetched at once", e.fs.hits)
	}
	if s := status(m, NameTor); !s.NextTry.Equal(e.clk.Now().Add(6*time.Hour)) || s.Updated.After(e.clk.Now()) {
		t.Errorf("tor after the step back: %+v", s)
	}
	if s := status(m, NameSpamhaus); !s.NextTry.Equal(e.clk.Now().Add(24 * time.Hour)) {
		t.Errorf("spamhaus after the step back: %+v", s)
	}
	e.clk.Advance(6 * time.Hour)
	run(m)
	if e.fs.hit("/torbulkexitlist") != 2 || e.fs.hit("/drop/drop_v4.json") != 1 {
		t.Errorf("hits %v six hours after the step back", e.fs.hits)
	}
	e.clk.Advance(18 * time.Hour)
	run(m)
	if e.fs.hit("/drop/drop_v4.json") != 2 {
		t.Errorf("hits %v a day after the step back", e.fs.hits)
	}
}

// No file on disk stops New: one a loader can't decode, or a loader that panics, leaves that feed
// empty and reported; the other feeds load.
func TestLoadSurvivesHostileFiles(t *testing.T) {
	e := newEnv(t, time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC))
	e.fs.serveAll(t, "2026-11")
	m, _ := e.manager(nil)
	run(m)
	for _, r := range []string{"::ffff:1.2.3.4-::1:0:0:0", "::ffff:0.0.0.0-ffff::"} {
		snap := `{"v":1,"name":"tor-exits","version":"2026-11-24T10:00Z","fetched":"2026-11-24T10:00:00Z","entries":1,"ranges":["` + r + `"]}`
		if err := os.WriteFile(filepath.Join(e.dir, "tor-exits.json"), []byte(snap), 0o600); err != nil {
			t.Fatal(err)
		}
		func() {
			defer func() {
				if v := recover(); v != nil {
					t.Fatalf("New panicked on %s: %v", r, v)
				}
			}()
			m2, x2 := e.manager(nil)
			if s := status(m2, NameTor); s.Version != "" || s.Entries != 0 || !strings.Contains(s.LastError, "bad range") {
				t.Errorf("%s: %+v", r, s)
			}
			if g := geo(x2, "41.58.1.1"); g == nil || g.City == "" || strings.Join(g.Lists, ",") != "spamhaus-drop" {
				t.Errorf("the other feeds didn't load: %+v", g)
			}
		}()
	}
	// A loader that panics, after it put data in the enricher: the feed starts empty.
	m3, x3 := e.manager(nil)
	tor, city := m3.feed(NameTor), m3.feed(NameCity)
	tor.load = func(*feed) error {
		x3.SetList(enrich.ListTor, enrich.NewSet([]enrich.Range{{From: mustAddr("41.58.2.2"), To: mustAddr("41.58.2.2")}}, nil))
		panic("decoder bug")
	}
	city.load = func(*feed) error { var p *feed; return p.load(p) } // a nil dereference
	func() {
		defer func() {
			if v := recover(); v != nil {
				t.Fatalf("loading panicked: %v", v)
			}
		}()
		m3.loadFeeds()
	}()
	for _, n := range []string{NameTor, NameCity} {
		if s := status(m3, n); s.Version != "" || !strings.Contains(s.LastError, "failed unexpectedly") {
			t.Errorf("%s: %+v", n, s)
		}
	}
	if s := status(m3, NameTor); !strings.Contains(s.LastError, "decoder bug") {
		t.Errorf("tor: %+v", s)
	}
	if g := geo(x3, "41.58.2.2"); g == nil || g.City != "" || len(g.Lists) != 0 || g.ASN != 36923 {
		t.Errorf("a feed whose load panicked kept data, or another feed lost its own: %+v", g)
	}
	if s := status(m3, NameSpamhaus); s.LastError != "" || s.Version == "" {
		t.Errorf("spamhaus: %+v", s)
	}
}

// List entries that merge into a range broader than any entry may be (adjacent networks) are used
// after a restart too.
func TestMergingEntriesSurviveRestart(t *testing.T) {
	e := newEnv(t, time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC))
	e.fs.serveAll(t, "2026-11")
	e.fs.set("/drop/drop_v4.json", response{body: []byte(spamhausFile(`{"cidr":"1.0.0.0/8"}`, `{"cidr":"2.0.0.0/24"}`))})
	e.fs.set("/drop/drop_v6.json", response{body: []byte(spamhausFile(`{"cidr":"2a0b:ff00::/24"}`, `{"cidr":"2a0c::/32"}`))})
	only := func(o *Options) { o.GeoIP, o.Tor = false, false }
	m, _ := e.manager(only)
	run(m)
	want := status(m, NameSpamhaus)
	if want.LastError != "" || want.Entries != 5 {
		t.Fatalf("setup: %+v", want)
	}
	m2, x2 := e.manager(only)
	if s := status(m2, NameSpamhaus); s != want {
		t.Errorf("after a restart %+v\nwant %+v", s, want)
	}
	for _, a := range []string{"1.255.255.255", "2.0.0.9", "2a0b:ffff::1", "2a0c::1"} {
		if g := geo(x2, a); g == nil || strings.Join(g.Lists, ",") != "spamhaus-drop" {
			t.Errorf("%s after a restart: %+v", a, g)
		}
	}
}

// installList refuses a list whose snapshot the next start would refuse: what is in use is always
// what a restart loads.
func TestInstallRefusesWhatALoadWould(t *testing.T) {
	e := newEnv(t, time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC))
	e.fs.serveAll(t, "2026-11")
	m, x := e.manager(func(o *Options) { o.GeoIP, o.Spamhaus = false, false })
	run(m)
	before, err := os.ReadFile(filepath.Join(e.dir, "tor-exits.json"))
	if err != nil {
		t.Fatal(err)
	}
	for name, l := range map[string]list{
		"a range broader than a /8": {ranges: []enrich.Range{{From: mustAddr("41.0.0.0"), To: mustAddr("43.255.255.255")}}, entries: 1},
		"no entry counted":          {ranges: []enrich.Range{{From: mustAddr("41.58.9.9"), To: mustAddr("41.58.9.9")}}},
	} {
		if _, err := m.installList(m.feed(NameTor), l, e.clk.Now()); err == nil {
			t.Errorf("%s: installed", name)
		}
		if after, _ := os.ReadFile(filepath.Join(e.dir, "tor-exits.json")); !bytes.Equal(after, before) {
			t.Errorf("%s: the snapshot was replaced", name)
		}
		if g := geo(x, "41.58.9.9"); g != nil && len(g.Lists) != 0 {
			t.Errorf("%s: put in use: %+v", name, g)
		}
		if g := geo(x, "41.58.2.2"); g == nil || strings.Join(g.Lists, ",") != "tor-exit" {
			t.Errorf("%s: the list in use was dropped: %+v", name, g)
		}
	}
}

// Close releases the directory; it is safe twice, and a Manager closed makes no request.
func TestClose(t *testing.T) {
	e := newEnv(t, time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC))
	e.fs.serveAll(t, "2026-11")
	m, _ := e.manager(nil)
	m.Close()
	if _, err := m.root.Lstat("."); err == nil {
		t.Error("the directory is still open")
	}
	m.Close()
	run(m)
	if n := e.fs.total("/"); n != 0 {
		t.Errorf("%d requests after Close", n)
	}
}

// A damaged state file or snapshot is ignored: the feed is fetched again; nothing stale is used.
func TestDamagedFilesIgnored(t *testing.T) {
	e := newEnv(t, time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC))
	e.fs.serveAll(t, "2026-11")
	m, _ := e.manager(nil)
	run(m)
	if err := os.WriteFile(filepath.Join(e.dir, "tor-exits.json"), []byte(`{"v":1,"name":"tor-exits","ranges":["x"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.dir, "dbip-asn.mmdb"), []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A snapshot that is a symlink (even to a valid one inside Dir) is refused.
	if err := os.Rename(filepath.Join(e.dir, "spamhaus-drop.json"), filepath.Join(e.dir, "other.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("other.json", filepath.Join(e.dir, "spamhaus-drop.json")); err != nil {
		t.Fatal(err)
	}
	m2, x2 := e.manager(nil)
	if s := status(m2, NameSpamhaus); s.Version != "" || !strings.Contains(s.LastError, "regular file") {
		t.Errorf("a symlinked snapshot: %+v", s)
	}
	if g := geo(x2, "41.58.2.2"); g != nil && len(g.Lists) != 0 {
		t.Errorf("a damaged snapshot was used: %+v", g)
	}
	if g := geo(x2, "41.58.1.1"); g == nil || g.ASN != 0 || g.City == "" {
		t.Errorf("a damaged database was used, or the good one wasn't: %+v", g)
	}
	for _, n := range []string{NameTor, NameASN} {
		if s := status(m2, n); s.Version != "" || s.LastError == "" {
			t.Errorf("%s: %+v", n, s)
		}
	}
	if err := os.WriteFile(filepath.Join(e.dir, "state.json"), []byte("{garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	m3, _ := e.manager(nil)
	before := e.fs.total("/")
	run(m3)
	if e.fs.total("/") == before {
		t.Error("nothing fetched after the state was lost")
	}
	if s := status(m3, NameTor); s.LastError != "" || s.Entries != 151 {
		t.Errorf("tor after a refetch: %+v", s)
	}
}

// DShield is fetched only with a contact, which goes in its User-Agent and nowhere else.
func TestDShieldContact(t *testing.T) {
	e := newEnv(t, time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC))
	e.fs.serveAll(t, "2026-11")
	m, x := e.manager(func(o *Options) { o.DShieldContact = "soc@example.com" })
	run(m)
	if e.fs.hit("/block.txt") != 1 {
		t.Fatal("DShield not fetched with a contact")
	}
	for p, uas := range e.fs.uas {
		want := "Mooring/1.2.3"
		if p == "/block.txt" {
			want = "Mooring/1.2.3 (+soc@example.com)"
		}
		for _, ua := range uas {
			if ua != want {
				t.Errorf("%s: User-Agent %q, want %q", p, ua, want)
			}
		}
	}
	s := status(m, NameDShield)
	if !s.Enabled || s.Version != "2026-11-24T19:30Z" || s.Entries != 4 || !s.NextTry.Equal(e.clk.Now().Add(24*time.Hour)) {
		t.Errorf("status %+v", s)
	}
	if g := geo(x, "41.58.3.3"); g == nil || strings.Join(g.Lists, ",") != "dshield" {
		t.Errorf("Geo %+v", g)
	}
	// Turned off again: not used, not fetched.
	m2, x2 := e.manager(nil)
	if g := geo(x2, "41.58.3.3"); g != nil && len(g.Lists) != 0 {
		t.Errorf("DShield used without a contact: %+v", g)
	}
	e.clk.Advance(48 * time.Hour)
	run(m2)
	if e.fs.hit("/block.txt") != 1 {
		t.Error("DShield fetched without a contact")
	}
	if s := status(m2, NameDShield); s.Enabled || !s.NextTry.IsZero() || s.Version != "" {
		t.Errorf("disabled status %+v", s)
	}
	if _, err := New(Options{Dir: e.dir, Enricher: enrich.New(), DShieldContact: "a@b.cd\r\nX: y"}); err == nil {
		t.Error("a contact with a line break accepted")
	}
}

// HTTP 429 backs off at least 5 minutes, or as long as Retry-After says (at most 24 h).
func TestDShield429(t *testing.T) {
	for retryAfter, want := range map[string]time.Duration{"": time.Hour, "120": time.Hour, "7200": 2 * time.Hour, "999999999": 24 * time.Hour} {
		e := newEnv(t, time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC))
		h := map[string]string{}
		if retryAfter != "" {
			h["Retry-After"] = retryAfter
		}
		e.fs.set("/block.txt", response{status: http.StatusTooManyRequests, header: h})
		m, _ := e.manager(func(o *Options) {
			o.GeoIP, o.Spamhaus, o.Tor, o.DShieldContact = false, false, false, "soc@example.com"
		})
		run(m)
		s := status(m, NameDShield)
		if !s.NextTry.Equal(e.clk.Now().Add(want)) || !strings.Contains(s.LastError, "429") {
			t.Errorf("Retry-After %q: %+v, want next try in %v", retryAfter, s, want)
		}
		if got := rateLimitDelay(1, 2*time.Minute); got < 5*time.Minute {
			t.Errorf("rate-limit delay %v under 5 minutes", got)
		}
	}
}

// Status names and order are fixed; a disabled feed is neither loaded nor fetched.
func TestStatusAndDisabledFeeds(t *testing.T) {
	e := newEnv(t, time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC))
	e.fs.serveAll(t, "2026-11")
	m, _ := e.manager(nil)
	run(m)
	var names []string
	for _, s := range m.FeedStatus() {
		names = append(names, s.Name)
	}
	if strings.Join(names, ",") != "dbip-city,dbip-asn,spamhaus-drop,tor-exits,dshield" {
		t.Errorf("names %v", names)
	}
	var src siem.FeedStatusSource = m
	_ = src
	m2, x2 := e.manager(func(o *Options) { o.GeoIP, o.Tor = false, false })
	if g := geo(x2, "41.58.1.1"); g == nil || g.City != "" || g.ASN != 0 || strings.Join(g.Lists, ",") != "spamhaus-drop" {
		t.Errorf("disabled GeoIP used: %+v", g)
	}
	e.clk.Advance(48 * time.Hour)
	run(m2)
	if e.fs.hit(cityPath+"2026-11.mmdb.gz") != 1 || e.fs.hit("/torbulkexitlist") != 1 || e.fs.hit("/drop/drop_v4.json") != 2 {
		t.Errorf("hits %v: disabled feeds fetched, or the enabled one not", e.fs.hits)
	}
	for _, s := range m2.FeedStatus() {
		on := s.Name == NameSpamhaus
		if s.Enabled != on || (!on && (s.Version != "" || !s.NextTry.IsZero())) {
			t.Errorf("%+v", s)
		}
	}
}

// New: required options, stale temporary files removed, the dir created 0700.
func TestNew(t *testing.T) {
	if _, err := New(Options{Enricher: enrich.New()}); err == nil {
		t.Error("no Dir accepted")
	}
	dir := filepath.Join(t.TempDir(), "a", "feeds")
	if _, err := New(Options{Dir: dir}); err == nil {
		t.Error("no Enricher accepted")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"dbip-city.mmdb.tmp-0011aabb", "state.json.tmp-99", "keep.txt"} {
		os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600)
	}
	if _, err := New(Options{Dir: dir, Enricher: enrich.New()}); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 || ents[0].Name() != "keep.txt" {
		t.Errorf("left %v", ents)
	}
	if fi, _ := os.Stat(filepath.Dir(dir)); fi.Mode().Perm() != 0o700 {
		t.Errorf("parent %v", fi.Mode())
	}
	for v, want := range map[string]string{"1.2.3": "Mooring/1.2.3", "v0.31.0-rc1+abc": "Mooring/v0.31.0-rc1+abc", "": "Mooring/dev", "1 2\r\n": "Mooring/dev", strings.Repeat("9", 100): "Mooring/dev"} {
		if got := userAgent(v); got != want {
			t.Errorf("userAgent(%q) = %q, want %q", v, got, want)
		}
	}
}

// Run fetches what is due, waits at most an hour between checks, and returns when ctx ends.
func TestRun(t *testing.T) {
	e := newEnv(t, time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC))
	e.fs.serveAll(t, "2026-11")
	waits := make(chan time.Duration, 4)
	fire := make(chan time.Time)
	m, _ := e.manager(nil)
	m.after = func(d time.Duration) <-chan time.Time { waits <- d; return fire }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { m.Run(ctx); close(done) }()
	select {
	case d := <-waits:
		if d != time.Hour { // the next feed (tor) is 6 h away: Run checks again within the hour
			t.Errorf("first wait %v", d)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run never waited")
	}
	if e.fs.hit("/torbulkexitlist") != 1 || e.fs.hit(cityPath+"2026-11.mmdb.gz") != 1 {
		t.Errorf("hits %v", e.fs.hits)
	}
	// A second Run while one runs returns at once.
	second := make(chan struct{})
	go func() { m.Run(ctx); close(second) }()
	select {
	case <-second:
	case <-time.After(5 * time.Second):
		t.Error("a second Run didn't return")
	}
	e.clk.Advance(6 * time.Hour)
	fire <- time.Now()
	<-waits
	if e.fs.hit("/torbulkexitlist") != 2 {
		t.Errorf("tor not fetched again after 6 h: %d", e.fs.hit("/torbulkexitlist"))
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run didn't return after its context ended")
	}
}

// feed is the feed called name (tests).
func (m *Manager) feed(name string) *feed {
	for _, f := range m.feeds {
		if f.name == name {
			return f
		}
	}
	return nil
}

type countWriter struct{ n int64 }

func (w *countWriter) Write(p []byte) (int, error) { w.n += int64(len(p)); return len(p), nil }
func (w *countWriter) Sync() error                 { return nil }

type countSource struct {
	r io.Reader
	n int64
}

func (s *countSource) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	s.n += int64(n)
	return n, err
}

// gunzip never writes more than rawCap+1 bytes nor reads more than compCap+1 bytes, whatever the
// stream holds.
func TestGunzipStopsAtTheCaps(t *testing.T) {
	w := &countWriter{}
	_, err := gunzip(w, bytes.NewReader(gz(t, make([]byte, 8<<20))), 1<<20, 64<<10)
	if err == nil || !strings.Contains(err.Error(), "uncompressed") || w.n > 64<<10+1 {
		t.Errorf("a gzip bomb: %v, %d bytes written", err, w.n)
	}
	src := &countSource{r: bytes.NewReader(bytes.Repeat(gz(t, nil), 50000))} // ~1 MB of empty members
	w = &countWriter{}
	_, err = gunzip(w, src, 4<<10, 1<<20)
	if err == nil || !strings.Contains(err.Error(), "download is larger") || src.n > 4<<10+1 {
		t.Errorf("an endless stream: %v, %d bytes read", err, src.n)
	}
	w = &countWriter{}
	raw := mmdbtest.City(mmdbtest.CityEntry{Prefix: "41.58.0.0/18", City: "x"})
	if n, err := gunzip(w, bytes.NewReader(gz(t, raw)), 1<<20, int64(len(raw))); err != nil || n != int64(len(raw)) || w.n != n {
		t.Errorf("a file at the cap: %v, %d", err, n)
	}
}
