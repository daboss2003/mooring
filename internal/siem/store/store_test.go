package store

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/query"
)

var (
	discard = slog.New(slog.NewTextHandler(io.Discard, nil))
	bg      = context.Background()
	h10     = time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock(t time.Time) *clock { return &clock{t: t} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) set(t time.Time) {
	c.mu.Lock()
	c.t = t
	c.mu.Unlock()
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func testOptions(dir string, c *clock) Options {
	return Options{
		Dir: dir, Box: "box1", HotRetention: 14 * 24 * time.Hour, MaxDiskBytes: 1 << 30,
		Log: discard, Now: c.now, ArchiveConfigured: true,
	}
}

func openStore(t *testing.T, dir string, c *clock, mod func(*Options)) *Store {
	t.Helper()
	opt := testOptions(dir, c)
	if mod != nil {
		mod(&opt)
	}
	s, err := Open(opt)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func storeDir(t *testing.T) string { return filepath.Join(t.TempDir(), "security-logs") }

func mkev(c *clock, kind, lvl string, i int) siem.Event {
	e := siem.Event{
		TS: c.now(), Src: siem.SrcApp, App: "web", Svc: "api", Kind: kind, Lvl: lvl,
		Msg: fmt.Sprintf("event %d", i), F: map[string]any{"i": float64(i)},
	}
	e.Normalize(c.now())
	return e
}

func mustAppend(t *testing.T, s *Store, evs ...siem.Event) {
	t.Helper()
	if err := s.Append(evs); err != nil {
		t.Fatalf("Append: %v", err)
	}
}

func mustFlush(t *testing.T, s *Store) {
	t.Helper()
	if err := s.Flush(); err != nil {
		t.Fatalf("Flush: %v", err)
	}
}

func msgs(evs []siem.Event) []string {
	out := make([]string, len(evs))
	for i, e := range evs {
		out[i] = e.Msg
	}
	return out
}

func searchAll(t *testing.T, s *Store, q string) Result {
	t.Helper()
	pq, err := query.Parse(q)
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.Search(bg, pq, maxLimit)
	if err != nil {
		t.Fatalf("Search(%q): %v", q, err)
	}
	return r
}

// readSegment decodes a segment file and returns its lines and the error that ended the read.
func readSegmentFile(t *testing.T, path string) ([]string, error) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	var lines []string
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 64<<10), maxLine)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}

func fileSHA(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func segNames(s *Store) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, g := range s.segs {
		out = append(out, g.name)
	}
	return out
}

func segByName(s *Store, name string) *seg {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, g := range s.segs {
		if g.name == name {
			cp := *g
			return &cp
		}
	}
	return nil
}

func countRows(t *testing.T, s *Store, where string, args ...any) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM `+where, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// abandon simulates a crash: files and databases are closed without a flush, seal or gzip trailer.
func abandon(s *Store) {
	s.mu.Lock()
	for _, g := range s.segs {
		if g.w != nil {
			_ = g.w.f.Close()
			g.w = nil
		}
	}
	s.closed.Store(true)
	s.mu.Unlock()
	_ = s.rdb.Close()
	_ = s.db.Close()
	_ = s.lock.Close()
}

func TestAppendFlushAndReadWhileWriting(t *testing.T) {
	c := newClock(h10.Add(5 * time.Minute))
	dir := storeDir(t)
	s := openStore(t, dir, c, nil)
	mustAppend(t, s, mkev(c, siem.KindLog, siem.LvlInfo, 1), mkev(c, "auth.login", siem.LvlInfo, 2))
	c.add(time.Second)
	mustAppend(t, s, mkev(c, siem.KindLog, siem.LvlWarn, 3))
	mustFlush(t, s)

	r := searchAll(t, s, "")
	if got := msgs(r.Events); strings.Join(got, ",") != "event 3,event 2,event 1" {
		t.Fatalf("search = %q, want newest first", got)
	}
	// The open segment decodes up to the flushed point while the writer keeps it open.
	path := filepath.Join(dir, "segments", "2026112310-box1-1.ndjson.gz")
	lines, err := readSegmentFile(t, path)
	if len(lines) != 3 || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("open segment: %d lines, err %v; want 3 and an unexpected EOF", len(lines), err)
	}
	var e siem.Event
	if err := json.Unmarshal([]byte(lines[0]), &e); err != nil || e.Msg != "event 1" || e.V != 1 {
		t.Fatalf("line 0 = %q (%v)", lines[0], err)
	}
	// Classified events (auth.login, and the warn log line) are indexed; plain info logs are not.
	if n := countRows(t, s, `events`); n != 2 {
		t.Errorf("indexed %d events, want 2", n)
	}
	mustAppend(t, s, mkev(c, "auth.logout", siem.LvlInfo, 4))
	mustFlush(t, s)
	if got := len(searchAll(t, s, "").Events); got != 4 {
		t.Errorf("after a second flush: %d events", got)
	}
	if s.Segments() != 1 || s.DiskBytes() <= 0 {
		t.Errorf("Segments %d DiskBytes %d", s.Segments(), s.DiskBytes())
	}
	if got := s.Oldest(); !got.Equal(h10.Add(5 * time.Minute)) {
		t.Errorf("Oldest = %v", got)
	}
	if s.DB() == nil {
		t.Error("DB() = nil")
	}
}

func TestHourRolloverUsesCaptureTime(t *testing.T) {
	c := newClock(h10.Add(59*time.Minute + 59*time.Second))
	dir := storeDir(t)
	s := openStore(t, dir, c, nil)
	mustAppend(t, s, mkev(c, siem.KindLog, siem.LvlInfo, 1))
	c.set(h10.Add(time.Hour + time.Second))
	// An event claiming an old timestamp still goes to the hour it was captured in.
	liar := mkev(c, siem.KindLog, siem.LvlInfo, 2)
	liar.TS = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	mustAppend(t, s, liar)
	mustFlush(t, s)
	want := []string{"2026112310-box1-1.ndjson.gz", "2026112311-box1-1.ndjson.gz"}
	if got := segNames(s); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("segments = %q, want %q", got, want)
	}
	if g := segByName(s, want[0]); !g.open {
		t.Error("the previous hour was sealed before SealDue")
	}
	if err := s.SealDue(); err != nil {
		t.Fatal(err)
	}
	if g := segByName(s, want[0]); g.open || g.sha == "" {
		t.Error("SealDue left the previous hour open")
	}
	if g := segByName(s, want[1]); !g.open {
		t.Error("SealDue sealed the current hour")
	}
	// The segment's TS range covers the lying event, so a search for 2020 still scans it.
	q := query.Query{From: time.Date(2019, 1, 1, 0, 0, 0, 0, time.UTC), To: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)}
	r, err := s.Search(bg, q, 10)
	if err != nil || len(r.Events) != 1 || r.Events[0].Msg != "event 2" {
		t.Fatalf("search 2020 = %v %v", msgs(r.Events), err)
	}
	if _, err := os.Stat(filepath.Join(dir, "segments", want[1])); err != nil {
		t.Fatal(err)
	}
}

func TestSizeCapRolls(t *testing.T) {
	c := newClock(h10)
	s := openStore(t, storeDir(t), c, nil)
	s.maxEvents = 3
	for i := 1; i <= 7; i++ {
		mustAppend(t, s, mkev(c, siem.KindLog, siem.LvlInfo, i))
	}
	mustFlush(t, s)
	want := []string{"2026112310-box1-1.ndjson.gz", "2026112310-box1-2.ndjson.gz", "2026112310-box1-3.ndjson.gz"}
	if got := segNames(s); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("segments = %q", got)
	}
	for i, n := range []int{3, 3, 1} {
		g := segByName(s, want[i])
		if g.events != n || g.open != (i == 2) {
			t.Errorf("%s: %d events open=%v", want[i], g.events, g.open)
		}
	}
	// Byte cap, inside one batch.
	s.maxEvents = segMaxEvents
	s.maxRaw = 600
	batch := make([]siem.Event, 6)
	for i := range batch {
		batch[i] = mkev(c, siem.KindLog, siem.LvlInfo, 10+i)
		batch[i].Msg = strings.Repeat("x", 200)
	}
	mustAppend(t, s, batch...)
	if got := len(segNames(s)); got < 5 {
		t.Errorf("byte cap: %d segments, want at least 5", got)
	}
	s.mu.Lock()
	for _, g := range s.segs {
		if g.w != nil && g.w.raw > s.maxRaw && g.events > 1 {
			t.Errorf("%s holds %d bytes > cap", g.name, g.w.raw)
		}
	}
	s.mu.Unlock()
	// A new hour starts again at seq 1.
	c.add(time.Hour)
	mustAppend(t, s, mkev(c, siem.KindLog, siem.LvlInfo, 99))
	if got := segNames(s); got[len(got)-1] != "2026112311-box1-1.ndjson.gz" {
		t.Errorf("new hour segment = %q", got[len(got)-1])
	}
	mustFlush(t, s)
	if n := len(searchAll(t, s, "").Events); n != 14 {
		t.Errorf("search found %d of 14 events", n)
	}
}

// chainOK checks every sealed segment: SHA256 is the file's hash and PrevSHA256 links to the
// segment sealed before it.
func chainOK(t *testing.T, s *Store, segs []Segment, firstPrev string) {
	t.Helper()
	prev := firstPrev
	for _, g := range segs {
		if g.SHA256 != fileSHA(t, g.Path) {
			t.Errorf("%s: SHA256 %s is not the file's hash", g.Name, g.SHA256)
		}
		if g.PrevSHA256 != prev {
			t.Errorf("%s: PrevSHA256 %q, want %q", g.Name, g.PrevSHA256, prev)
		}
		prev = g.SHA256
	}
}

func TestSealHashChain(t *testing.T) {
	c := newClock(h10)
	dir := storeDir(t)
	s := openStore(t, dir, c, nil)
	s.maxEvents = 2
	for i := 0; i < 9; i++ {
		mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, i))
		c.add(20 * time.Minute)
	}
	c.add(time.Hour)
	if err := s.SealDue(); err != nil {
		t.Fatal(err)
	}
	segs, err := s.Unarchived()
	if err != nil {
		t.Fatal(err)
	}
	if len(segs) < 5 {
		t.Fatalf("%d sealed segments", len(segs))
	}
	chainOK(t, s, segs, "")
	for _, g := range segs {
		lines, err := readSegmentFile(t, g.Path)
		if err != nil || len(lines) != g.Events {
			t.Errorf("%s: sealed file decodes %d lines (%v), manifest says %d", g.Name, len(lines), err, g.Events)
		}
		if g.First.IsZero() || g.Last.Before(g.First) || g.Hour.Minute() != 0 {
			t.Errorf("%s: First %v Last %v Hour %v", g.Name, g.First, g.Last, g.Hour)
		}
		if fi, _ := os.Stat(g.Path); fi.Size() != g.Bytes {
			t.Errorf("%s: Bytes %d, file %d", g.Name, g.Bytes, fi.Size())
		}
	}
	last := segs[len(segs)-1].SHA256

	// The chain continues across a restart and after every sealed segment has been pruned.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	c.add(30 * 24 * time.Hour)
	s2 := openStore(t, dir, c, nil)
	if err := s2.Prune(); err != nil {
		t.Fatal(err)
	}
	if left, _ := s2.Unarchived(); len(left) != 0 {
		t.Fatalf("prune left %d segments", len(left))
	}
	mustAppend(t, s2, mkev(c, "auth.login", siem.LvlInfo, 100))
	c.add(time.Hour)
	if err := s2.SealDue(); err != nil {
		t.Fatal(err)
	}
	segs2, _ := s2.Unarchived()
	if len(segs2) != 1 {
		t.Fatalf("%d segments after restart", len(segs2))
	}
	chainOK(t, s2, segs2, last)
}

func TestCrashRecovery(t *testing.T) {
	c := newClock(h10.Add(10 * time.Minute))
	dir := storeDir(t)
	s := openStore(t, dir, c, nil)
	for i := 0; i < 5; i++ {
		mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, i))
	}
	mustFlush(t, s)
	firstFlush := segByName(s, "2026112310-box1-1.ndjson.gz").flushed
	for i := 5; i < 10; i++ {
		e := mkev(c, "auth.login", siem.LvlInfo, i)
		e.Msg = strings.Repeat(fmt.Sprintf("tail %d ", i), 40)
		mustAppend(t, s, e)
	}
	mustFlush(t, s)
	abandon(s)

	segDir := filepath.Join(dir, "segments")
	name := "2026112310-box1-1.ndjson.gz"
	path := filepath.Join(segDir, name)
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Kill mid-write: the file ends halfway through the second flushed block.
	if err := os.Truncate(path, firstFlush+(fi.Size()-firstFlush)/2); err != nil {
		t.Fatal(err)
	}
	// A segment file the database has no row for, and one whose bytes aren't gzip at all.
	orphan := filepath.Join(segDir, "2026112309-box1-1.ndjson.gz")
	if err := os.WriteFile(orphan, mustRead(t, path), 0o600); err != nil {
		t.Fatal(err)
	}
	junk := filepath.Join(segDir, "2026112308-box1-1.ndjson.gz")
	if err := os.WriteFile(junk, []byte("not gzip"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A symlink with a segment name is never followed or recovered.
	outside := filepath.Join(t.TempDir(), "outside.gz")
	if err := os.WriteFile(outside, mustRead(t, path), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(segDir, "2026112307-box1-1.ndjson.gz")); err != nil {
		t.Fatal(err)
	}

	s2 := openStore(t, dir, c, nil)
	g := segByName(s2, name)
	if g == nil || g.open || g.sha != fileSHA(t, path) {
		t.Fatalf("recovered segment = %+v", g)
	}
	if g.events < 5 || g.events >= 10 {
		t.Errorf("recovered %d events, want the 5 of the first block and fewer than 10", g.events)
	}
	if o := segByName(s2, filepath.Base(orphan)); o == nil || o.open || o.sha != fileSHA(t, orphan) {
		t.Errorf("orphan file not recovered: %+v", o)
	}
	if j := segByName(s2, filepath.Base(junk)); j == nil || j.events != 0 || j.sha != fileSHA(t, junk) {
		t.Errorf("junk file: %+v", j)
	}
	if segByName(s2, "2026112307-box1-1.ndjson.gz") != nil {
		t.Error("a symlinked segment was recovered")
	}
	segs, _ := s2.Unarchived()
	chainOK(t, s2, segs, "")
	// Search reads the truncated segment up to where it breaks.
	r := searchAll(t, s2, "kind:auth.login")
	if len(r.Events) < 10 { // 5+ from the truncated file, 5+ from the orphan copy, via the index or the scan
		t.Errorf("search after recovery found %d events", len(r.Events))
	}
	scan, err := s2.searchScan(bg, query.Query{}, maxLimit)
	if err != nil || len(scan.Events) != g.events*2 {
		t.Errorf("scan after recovery: %d events (%v), want %d", len(scan.Events), err, g.events*2)
	}
	// New events start a new seq in the same hour.
	mustAppend(t, s2, mkev(c, "auth.login", siem.LvlInfo, 50))
	if got := segNames(s2); got[len(got)-1] != "2026112310-box1-2.ndjson.gz" {
		t.Errorf("segments after recovery = %q", got)
	}
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRecoveryDropsRowsWithoutFiles(t *testing.T) {
	c := newClock(h10)
	dir := storeDir(t)
	s := openStore(t, dir, c, nil)
	mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, 1))
	c.add(time.Hour)
	mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, 2))
	if err := s.SealDue(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// The sealed (unarchived) hour-10 file and the open hour-11 file both vanish.
	for _, n := range []string{"2026112310-box1-1.ndjson.gz", "2026112311-box1-1.ndjson.gz"} {
		if err := os.Remove(filepath.Join(dir, "segments", n)); err != nil {
			t.Fatal(err)
		}
	}
	s2 := openStore(t, dir, c, nil)
	if n := countRows(t, s2, `segments WHERE name LIKE '2026112310%' OR name LIKE '2026112311-box1-1%'`); n != 0 {
		t.Errorf("%d rows kept for missing files", n)
	}
	// Both unarchived segments that vanished are recorded as lost.
	mustFlush(t, s2)
	r := searchAll(t, s2, "kind:siem.dropped")
	var lost []string
	for _, e := range r.Events {
		lost = append(lost, fmt.Sprint(e.F["segment"], " ", e.F["reason"]))
	}
	sort.Strings(lost)
	if strings.Join(lost, ",") != "2026112310-box1-1.ndjson.gz segment file missing,2026112311-box1-1.ndjson.gz segment file missing" {
		t.Fatalf("dropped events = %q", lost)
	}
	// The vanished segment's name is not reused in the same hour.
	if got := segNames(s2); got[len(got)-1] != "2026112311-box1-2.ndjson.gz" {
		t.Errorf("segments = %q", got)
	}
}

func TestCleanCloseFinishesTheGzipStream(t *testing.T) {
	c := newClock(h10)
	dir := storeDir(t)
	s := openStore(t, dir, c, nil)
	mustAppend(t, s, mkev(c, siem.KindLog, siem.LvlInfo, 1), mkev(c, siem.KindLog, siem.LvlInfo, 2))
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	path := filepath.Join(dir, "segments", "2026112310-box1-1.ndjson.gz")
	if lines, err := readSegmentFile(t, path); len(lines) != 2 || err != nil {
		t.Fatalf("closed segment: %d lines, %v", len(lines), err)
	}
	if err := s.Append([]siem.Event{mkev(c, siem.KindLog, siem.LvlInfo, 3)}); err == nil {
		t.Error("Append after Close succeeded")
	}
	if _, err := s.Search(bg, query.Query{}, 10); err == nil {
		t.Error("Search after Close succeeded")
	}
	// Close seals nothing: the next Open seals it.
	s2 := openStore(t, dir, c, nil)
	if g := segByName(s2, "2026112310-box1-1.ndjson.gz"); g == nil || g.open || g.events != 2 || g.sha != fileSHA(t, path) {
		t.Fatalf("after reopen: %+v", g)
	}
}

func TestPruneByAgeAndArchiveState(t *testing.T) {
	c := newClock(h10)
	dir := storeDir(t)
	s := openStore(t, dir, c, func(o *Options) { o.HotRetention = 24 * time.Hour })
	// Three hours, each its own segment; hour 10 is archived, 11 and 12 are not.
	for i := 0; i < 3; i++ {
		mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, i))
		c.add(time.Hour)
	}
	if err := s.SealDue(); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkArchived("2026112310-box1-1.ndjson.gz", "v1/2026/11/23/10/box1-1.ndjson.gz.enc", c.now()); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, s, `events WHERE segment = ?`, "2026112310-box1-1.ndjson.gz"); n != 1 {
		t.Fatalf("%d index rows for hour 10", n)
	}
	// One day after hour 11 ended: the archived hour 10 goes, the unarchived ones stay.
	c.set(h10.Add(2*time.Hour + 24*time.Hour))
	if err := s.Prune(); err != nil {
		t.Fatal(err)
	}
	if got := segNames(s); strings.Join(got, " ") != "2026112311-box1-1.ndjson.gz 2026112312-box1-1.ndjson.gz" {
		t.Fatalf("after age prune: %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "segments", "2026112310-box1-1.ndjson.gz")); !errors.Is(err, fs.ErrNotExist) {
		t.Error("archived segment file kept")
	}
	if n := countRows(t, s, `events WHERE segment = ?`, "2026112310-box1-1.ndjson.gz"); n != 0 {
		t.Errorf("%d index rows kept for a pruned segment", n)
	}
	if n := countRows(t, s, `segments WHERE name = ?`, "2026112310-box1-1.ndjson.gz"); n != 0 {
		t.Error("manifest row kept")
	}
	// Past retention + 7 days an unarchived segment goes too, recorded as lost.
	c.set(h10.Add(2*time.Hour + 24*time.Hour + 7*24*time.Hour))
	if err := s.Prune(); err != nil {
		t.Fatal(err)
	}
	if got := segNames(s); len(got) != 2 || got[0] != "2026112312-box1-1.ndjson.gz" {
		t.Fatalf("after grace prune: %q", got)
	}
	mustFlush(t, s)
	r := searchAll(t, s, "kind:siem.dropped")
	if len(r.Events) != 1 || r.Events[0].F["segment"] != "2026112311-box1-1.ndjson.gz" || r.Events[0].Src != siem.SrcSIEM {
		t.Fatalf("dropped events = %+v", r.Events)
	}
}

func TestPruneWithoutArchiveIgnoresArchiveState(t *testing.T) {
	c := newClock(h10)
	s := openStore(t, storeDir(t), c, func(o *Options) {
		o.HotRetention = 24 * time.Hour
		o.ArchiveConfigured = false
	})
	mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, 1))
	c.add(time.Hour)
	mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, 2))
	if err := s.SealDue(); err != nil {
		t.Fatal(err)
	}
	c.set(h10.Add(time.Hour + 24*time.Hour))
	if err := s.Prune(); err != nil {
		t.Fatal(err)
	}
	if got := segNames(s); len(got) != 1 || got[0] != "2026112311-box1-1.ndjson.gz" {
		t.Fatalf("after prune: %q", got)
	}
	mustFlush(t, s)
	if r := searchAll(t, s, "kind:siem.dropped"); len(r.Events) != 0 {
		t.Errorf("retention without an archive recorded a loss: %+v", r.Events)
	}
}

// Without an archiver nothing else calls SealDue: Prune seals what is due, so the retention still
// applies and no hour stays open.
func TestPruneSealsDueSegments(t *testing.T) {
	c := newClock(h10)
	s := openStore(t, storeDir(t), c, func(o *Options) {
		o.HotRetention = 24 * time.Hour
		o.ArchiveConfigured = false
	})
	mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, 1))
	c.add(time.Hour)
	if err := s.Prune(); err != nil {
		t.Fatal(err)
	}
	if g := segByName(s, "2026112310-box1-1.ndjson.gz"); g == nil || g.open {
		t.Fatalf("Prune left the previous hour open: %+v", g)
	}
	c.add(24 * time.Hour)
	if err := s.Prune(); err != nil {
		t.Fatal(err)
	}
	if n := s.Segments(); n != 0 {
		t.Errorf("%d segments after the retention", n)
	}
}

func TestPruneDiskCap(t *testing.T) {
	c := newClock(h10)
	s := openStore(t, storeDir(t), c, nil)
	for i := 0; i < 4; i++ {
		// Unindexed and incompressible: the segment sizes, not database pages, decide the cap.
		e := randomEvents(c, i+1)[i]
		e.Kind = siem.KindLog
		mustAppend(t, s, e)
		c.add(time.Hour)
	}
	mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, 9)) // the open, current segment
	if err := s.SealDue(); err != nil {
		t.Fatal(err)
	}
	names := segNames(s)
	if len(names) != 5 {
		t.Fatalf("segments %q", names)
	}
	// Archive hours 12 and 13 (not the oldest ones): they go first.
	for _, n := range names[2:4] {
		if err := s.MarkArchived(n, "k/"+n, c.now()); err != nil {
			t.Fatal(err)
		}
	}
	s.mu.Lock()
	s.reclaimLocked() // a settled database (WAL truncated), so the sizes below hold during Prune
	s.mu.Unlock()
	var segBytes int64
	for _, n := range names[:4] {
		segBytes += segByName(s, n).bytes
	}
	s.mu.Lock()
	dbAndOpen := s.segBytesLocked() + s.dbLiveBytes() - segBytes // as the cap measures
	s.mu.Unlock()
	// Room for the database, the open segment and one more sealed segment.
	s.opt.MaxDiskBytes = dbAndOpen + max(segByName(s, names[0]).bytes, segByName(s, names[1]).bytes) + 10
	if err := s.Prune(); err != nil {
		t.Fatal(err)
	}
	got := segNames(s)
	if len(got) != 2 || got[0] != names[1] || got[1] != names[4] {
		t.Fatalf("after disk cap: %q (from %q)", got, names)
	}
	mustFlush(t, s)
	r := searchAll(t, s, "kind:siem.dropped")
	if len(r.Events) != 1 || r.Events[0].F["segment"] != names[0] || r.Events[0].F["reason"] != "disk cap" {
		t.Fatalf("dropped events = %+v", r.Events)
	}
	// A cap that can't be met: the open segment and the newest unarchived sealed one stay.
	s.opt.MaxDiskBytes = 1
	if err := s.Prune(); err != nil {
		t.Fatal(err)
	}
	if got := segNames(s); len(got) != 2 || got[0] != names[1] || got[1] != names[4] {
		t.Fatalf("after an impossible cap: %q", got)
	}
}

func TestMarkArchivedAndUnarchived(t *testing.T) {
	c := newClock(h10)
	dir := storeDir(t)
	s := openStore(t, dir, c, nil)
	mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, 1))
	c.add(time.Hour)
	mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, 2))
	if segs, _ := s.Unarchived(); len(segs) != 0 {
		t.Fatalf("open segments listed as unarchived: %+v", segs)
	}
	if err := s.SealDue(); err != nil {
		t.Fatal(err)
	}
	segs, err := s.Unarchived()
	if err != nil || len(segs) != 1 || segs[0].Name != "2026112310-box1-1.ndjson.gz" || segs[0].Seq != 1 || !segs[0].Hour.Equal(h10) {
		t.Fatalf("Unarchived = %+v %v", segs, err)
	}
	at := h10.Add(90 * time.Minute)
	if err := s.MarkArchived(segs[0].Name, "p/v1/key", at); err != nil {
		t.Fatal(err)
	}
	if segs, _ := s.Unarchived(); len(segs) != 0 {
		t.Fatalf("still unarchived: %+v", segs)
	}
	// A segment pruned while its upload ran is not an error.
	if err := s.MarkArchived("2026112309-box1-1.ndjson.gz", "x", at); err != nil {
		t.Errorf("MarkArchived(unknown) = %v", err)
	}
	if err := s.MarkArchived("2026112311-box1-1.ndjson.gz", "x", at); err == nil {
		t.Error("MarkArchived of an open segment succeeded")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2 := openStore(t, dir, c, nil)
	g := segByName(s2, "2026112310-box1-1.ndjson.gz")
	if g == nil || g.key != "p/v1/key" || g.archivedAt != at.UnixNano() {
		t.Fatalf("archive state not persisted: %+v", g)
	}
}

func TestAppendSanitizesUnencodableEvents(t *testing.T) {
	c := newClock(h10)
	s := openStore(t, storeDir(t), c, nil)
	nan := mkev(c, "auth.login", siem.LvlInfo, 1)
	nan.F["bad"] = math.NaN()
	nan.Geo = &siem.Geo{Lat: math.Inf(1), Country: "NG"}
	huge := mkev(c, "auth.login", siem.LvlInfo, 2)
	huge.Geo = &siem.Geo{Lists: make([]string, 0, 3000)}
	for i := 0; i < 3000; i++ {
		huge.Geo.Lists = append(huge.Geo.Lists, strings.Repeat("l", 400))
	}
	ok := mkev(c, "auth.login", siem.LvlInfo, 3)
	if err := s.Append([]siem.Event{nan, huge, ok}); err != nil {
		t.Fatal(err)
	}
	mustFlush(t, s)
	r := searchAll(t, s, "")
	if got := strings.Join(msgs(r.Events), ","); got != "event 3,event 1" {
		t.Fatalf("stored %q", got)
	}
	if _, has := r.Events[1].F["bad"]; has || r.Events[1].F["i"] != 1.0 || r.Events[1].Geo.Country != "NG" {
		t.Errorf("sanitized event = %+v", r.Events[1])
	}
}

func TestFileModes(t *testing.T) {
	c := newClock(h10)
	dir := storeDir(t)
	s := openStore(t, dir, c, nil)
	mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, 1))
	mustFlush(t, s)
	check := func(p string, want fs.FileMode) {
		t.Helper()
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != want {
			t.Errorf("%s: mode %v, want %v", p, fi.Mode().Perm(), want)
		}
	}
	check(dir, 0o700)
	check(filepath.Join(dir, "segments"), 0o700)
	check(filepath.Join(dir, "tmp"), 0o700)
	check(filepath.Join(dir, "segments", "2026112310-box1-1.ndjson.gz"), 0o600)
	for _, f := range []string{"security.db", "security.db-wal", "security.db-shm"} {
		check(filepath.Join(dir, f), 0o600)
	}
	if s.TempDir() != filepath.Join(dir, "tmp") {
		t.Errorf("TempDir = %q", s.TempDir())
	}
	// An existing directory that is too open is tightened.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	openStore(t, dir, c, nil)
	check(dir, 0o700)
}

func TestOpenRefusesSymlinks(t *testing.T) {
	c := newClock(h10)
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(testOptions(link, c)); err == nil {
		t.Fatal("Open accepted a symlinked Dir")
	}
	for _, sub := range []string{"segments", "tmp", "security.db", "security.db-wal"} {
		dir := filepath.Join(base, "d-"+strings.ReplaceAll(sub, ".", "_"))
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(real, filepath.Join(dir, sub)); err != nil {
			t.Fatal(err)
		}
		if s, err := Open(testOptions(dir, c)); err == nil {
			_ = s.Close()
			t.Errorf("Open accepted a symlinked %s", sub)
		}
	}
}

func TestOpenValidatesOptions(t *testing.T) {
	c := newClock(h10)
	for _, mod := range []func(*Options){
		func(o *Options) { o.Dir = "" },
		func(o *Options) { o.Box = "" },
		func(o *Options) { o.Box = "../x" },
		func(o *Options) { o.Box = ".hidden" },
	} {
		opt := testOptions(storeDir(t), c)
		mod(&opt)
		if s, err := Open(opt); err == nil {
			_ = s.Close()
			t.Errorf("Open(%+v) succeeded", opt)
		}
	}
	// Defaults fill unset values.
	s := openStore(t, storeDir(t), c, func(o *Options) {
		o.HotRetention, o.MaxDiskBytes, o.Log, o.Now = 0, 0, nil, nil
	})
	if s.opt.HotRetention != defaultHotRetention || s.opt.MaxDiskBytes != defaultMaxDiskBytes || s.opt.Log == nil || s.opt.Now == nil {
		t.Errorf("defaults not applied: %+v", s.opt)
	}
}

func TestSecondOpenRefused(t *testing.T) {
	c := newClock(h10)
	dir := storeDir(t)
	openStore(t, dir, c, nil)
	if s, err := Open(testOptions(dir, c)); err == nil {
		_ = s.Close()
		t.Fatal("a second Open of the same directory succeeded")
	}
}

func TestMigrations(t *testing.T) {
	c := newClock(h10)
	dir := storeDir(t)
	s := openStore(t, dir, c, nil)
	var av int
	if err := s.db.QueryRow(`PRAGMA auto_vacuum`).Scan(&av); err != nil || av != 2 {
		t.Errorf("auto_vacuum = %d (%v), want 2 (incremental)", av, err)
	}
	var jm string
	if err := s.db.QueryRow(`PRAGMA journal_mode`).Scan(&jm); err != nil || jm != "wal" {
		t.Errorf("journal_mode = %q", jm)
	}
	var syncMode int
	if err := s.db.QueryRow(`PRAGMA synchronous`).Scan(&syncMode); err != nil || syncMode != 1 {
		t.Errorf("synchronous = %d (%v), want 1 (NORMAL)", syncMode, err)
	}
	ms, err := loadMigrations()
	if err != nil || len(ms) < 3 {
		t.Fatalf("migrations: %d (%v)", len(ms), err)
	}
	var v int
	if err := s.db.QueryRow(`SELECT MAX(version) FROM schema_version`).Scan(&v); err != nil || v != len(ms) {
		t.Errorf("schema version %d (%v)", v, err)
	}
	if _, err := s.db.Exec(`INSERT INTO schema_version(version, name) VALUES (99, 'future')`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if s2, err := Open(testOptions(dir, c)); err == nil || !strings.Contains(err.Error(), "newer") {
		if s2 != nil {
			_ = s2.Close()
		}
		t.Fatalf("Open of a newer database: %v", err)
	}
	// The failed Open closed the database and released the directory lock: undo the future
	// version by hand and the store opens again.
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "security.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM schema_version WHERE version = 99`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	openStore(t, dir, c, nil)
}

// TestNoNestedStatements runs every operation against single-connection pools: a statement run while
// rows or a transaction are open would deadlock and hit the deadline.
func TestNoNestedStatements(t *testing.T) {
	c := newClock(h10)
	dir := storeDir(t)
	run := func(name string, fn func() error) {
		t.Helper()
		done := make(chan error, 1)
		go func() { done <- fn() }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("%s did not return: nested statement on a single connection?", name)
		}
	}
	s := openStore(t, dir, c, nil)
	s.rdb.SetMaxOpenConns(1)
	s.maxEvents = 3
	for i := 0; i < 20; i++ {
		run("Append", func() error { return s.Append([]siem.Event{mkev(c, "auth.login", siem.LvlWarn, i)}) })
		c.add(10 * time.Minute)
	}
	run("Flush", s.Flush)
	run("SealDue", s.SealDue)
	segs, _ := s.Unarchived()
	for _, g := range segs[:3] {
		run("MarkArchived", func() error { return s.MarkArchived(g.Name, "k", c.now()) })
	}
	run("Search index", func() error {
		pq, _ := query.Parse("kind:auth.login")
		r, err := s.searchIndex(bg, pq, 4)
		if err == nil && len(r.Events) != 4 {
			err = fmt.Errorf("%d events", len(r.Events))
		}
		return err
	})
	run("Search", func() error { _, err := s.Search(bg, query.Query{}, 5); return err })
	run("Export", func() error { _, err := s.Export(bg, query.Query{}, io.Discard, 100); return err })
	c.add(40 * 24 * time.Hour)
	run("Prune", s.Prune)
	run("Close", s.Close)
	// Recovery with several rows, on a single connection.
	s2 := openStore(t, dir, c, nil)
	for i := 0; i < 6; i++ {
		run("Append", func() error { return s2.Append([]siem.Event{mkev(c, "auth.login", siem.LvlWarn, i)}) })
	}
	abandon(s2)
	run("Open", func() error {
		s3, err := Open(testOptions(dir, c))
		if err == nil {
			err = s3.Close()
		}
		return err
	})
}

func TestUnwritableDiskReportsErrors(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	c := newClock(h10)
	dir := storeDir(t)
	s := openStore(t, dir, c, nil)
	segDir := filepath.Join(dir, "segments")
	if err := os.Chmod(segDir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(segDir, 0o700)
	if err := s.Append([]siem.Event{mkev(c, "auth.login", siem.LvlInfo, 1)}); err == nil {
		t.Fatal("Append into an unwritable directory succeeded")
	}
	if err := os.Chmod(segDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, 2))
	mustFlush(t, s)
	if r := searchAll(t, s, ""); len(r.Events) != 1 {
		t.Errorf("after the disk recovered: %d events", len(r.Events))
	}
}

// reclaimLocked returns every free page and truncates the WAL: a settled database, for tests that
// measure sizes. Caller holds s.mu.
func (s *Store) reclaimLocked() {
	_, _ = s.exec(`PRAGMA incremental_vacuum`)
	s.checkpointLocked()
}
