package servicelog

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type clock struct{ t int64 }

func (c *clock) now() time.Time { return time.Unix(c.t, 0) }

var (
	discard = slog.New(slog.NewTextHandler(io.Discard, nil))
	bg      = context.Background()
)

func newTestStore(t *testing.T, dir string, c *clock, mod func(*Options)) *Store {
	t.Helper()
	opts := Options{Dir: dir, Log: discard}
	if mod != nil {
		mod(&opts)
	}
	return newStore(opts, c.now)
}

func search(s *Store, app, svc string) []Line {
	out, _ := s.Search(bg, app, svc, "", "", 0, 0, maxSearchLimit)
	return out
}

// segFiles lists one service's segment files, oldest first.
func segFiles(t *testing.T, dir, app, svc string) []segment {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(dir, app, svc))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		t.Fatal(err)
	}
	var out []segment
	for _, e := range ents {
		if g, ok := parseSegmentName(e.Name()); ok {
			out = append(out, g)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].seq < out[j].seq })
	return out
}

// diskLines counts the lines in one service's segment files.
func diskLines(t *testing.T, dir, app, svc string) int {
	t.Helper()
	n := 0
	for _, g := range segFiles(t, dir, app, svc) {
		b, err := os.ReadFile(filepath.Join(dir, app, svc, g.name))
		if err != nil {
			t.Fatal(err)
		}
		n += strings.Count(string(b), "\n")
	}
	return n
}

func dirBytes(t *testing.T, root string) int64 {
	t.Helper()
	var n int64
	_ = filepath.Walk(root, func(_ string, fi os.FileInfo, err error) error {
		if err == nil && fi.Mode().IsRegular() {
			n += fi.Size()
		}
		return nil
	})
	return n
}

func TestRecordSearchAndCopyFilter(t *testing.T) {
	c := &clock{t: 1000}
	s := newTestStore(t, t.TempDir(), c, nil)

	s.Record("shop", "api", "aaaaaaaaaaaa", "starting up")
	c.t++
	s.Record("shop", "api", "aaaaaaaaaaaa", "ERROR: db connection refused")
	s.Record("shop", "api", "bbbbbbbbbbbb", "replica 2 healthy")
	s.Record("blog", "web", "cccccccccccc", "unrelated app line")

	all := search(s, "shop", "api")
	if len(all) != 3 || all[0].Text != "replica 2 healthy" || all[0].App != "shop" || all[0].Svc != "api" {
		t.Fatalf("expected 3 api lines newest-first, got %+v", all)
	}
	if got, _ := s.Search(bg, "shop", "api", "", "error", 0, 0, 100); len(got) != 1 || got[0].Text != "ERROR: db connection refused" {
		t.Errorf("text filter: %+v", got)
	}
	if got, _ := s.Search(bg, "shop", "api", "bbbbbbbbbbbb", "", 0, 0, 100); len(got) != 1 || got[0].Copy != "bbbbbbbbbbbb" {
		t.Errorf("copy filter: %+v", got)
	}
	if got, _ := s.Search(bg, "shop", "api", "", "unrelated", 0, 0, 100); len(got) != 0 {
		t.Errorf("cross-app leak: %+v", got)
	}
	if cs := s.Copies("shop", "api"); len(cs) != 2 {
		t.Errorf("expected 2 copies, got %v", cs)
	}
}

func TestSearchIsWordAnd(t *testing.T) {
	s := newTestStore(t, t.TempDir(), &clock{t: 1000}, nil)
	s.Record("shop", "api", "id", `{"level":"error","statusCode":502,"msg":"upstream down"}`)
	s.Record("shop", "api", "id", `{"level":"info","statusCode":200,"msg":"ok"}`)
	s.Flush() // search must work the same on disk as in memory

	if got, _ := s.Search(bg, "shop", "api", "", "statusCode 502", 0, 0, 10); len(got) != 1 || !strings.HasPrefix(got[0].Text, `{"level":"error"`) {
		t.Fatalf("word-AND search should find the 502 line, got %+v", got)
	}
	if got, _ := s.Search(bg, "shop", "api", "", "502 error", 0, 0, 10); len(got) != 1 {
		t.Errorf("word order must not matter, got %d", len(got))
	}
	if got, _ := s.Search(bg, "shop", "api", "", "statusCode 200 error", 0, 0, 10); len(got) != 0 {
		t.Errorf("a line missing a required word must not match, got %d", len(got))
	}
	if got, _ := s.Search(bg, "shop", "api", "", "   ", 0, 0, 10); len(got) != 2 {
		t.Errorf("blank query should return all, got %d", len(got))
	}
}

// A chatty service is pruned to its own line budget and never evicts another service's history.
func TestPerServiceLimitDoesNotEvictOtherServices(t *testing.T) {
	c := &clock{t: 1000}
	dir := t.TempDir()
	s := newTestStore(t, dir, c, nil)
	s.Record("quiet", "svc", "id", "the one important line")
	for i := 0; i < DefaultPolicy.MaxLines+1500; i++ {
		if i%rateCapPerSec == 0 {
			c.t++
		}
		s.Record("noisy", "svc", "id", "line "+strconv.Itoa(i))
	}
	s.Flush()

	if got := search(s, "quiet", "svc"); len(got) != 1 {
		t.Fatalf("quiet service evicted by a chatty one: %+v", got)
	}
	got := search(s, "noisy", "svc")
	if len(got) != DefaultPolicy.MaxLines {
		t.Fatalf("search must show exactly the service's %d most recent lines, got %d", DefaultPolicy.MaxLines, len(got))
	}
	if got[0].Text != "line "+strconv.Itoa(DefaultPolicy.MaxLines+1499) {
		t.Errorf("newest line first, got %q", got[0].Text)
	}
	if onDisk := diskLines(t, dir, "noisy", "svc"); onDisk < DefaultPolicy.MaxLines || onDisk >= DefaultPolicy.MaxLines+DefaultPolicy.segmentLines() {
		t.Errorf("on-disk lines %d not within [max, max+segment] after prune", onDisk)
	}
}

func TestRateCapDropsWithMarker(t *testing.T) {
	c := &clock{t: 1000}
	s := newTestStore(t, t.TempDir(), c, nil)
	for i := 0; i < rateCapPerSec+50; i++ {
		s.Record("app", "svc", "id", "spam")
	}
	c.t++
	s.Record("app", "svc", "id", "next second")

	lines, _ := s.Search(bg, "app", "svc", "", "", 0, 0, rateCapPerSec+100)
	if len(lines) != rateCapPerSec+2 {
		t.Errorf("rate cap not enforced: kept %d", len(lines))
	}
	if lines[1].Copy != "" || !strings.Contains(lines[1].Text, "50 line(s) dropped") {
		t.Errorf("expected a coalesced dropped-lines marker before the next-second line, got %+v", lines[1])
	}
}

func TestTimeWindowAndDelete(t *testing.T) {
	c := &clock{t: 9000}
	dir := t.TempDir()
	s := newTestStore(t, dir, c, nil)
	s.Record("app", "svc", "id", "old line")
	s.Record("other", "svc", "id", "keep me")
	c.t = 10000
	s.Record("app", "svc", "id", "recent line")
	s.Flush()

	if got, _ := s.Search(bg, "app", "svc", "", "", 9500, 0, 100); len(got) != 1 || got[0].Text != "recent line" {
		t.Errorf("since bound: %+v", got)
	}
	if got, _ := s.Search(bg, "app", "svc", "", "", 0, 9500, 100); len(got) != 1 || got[0].Text != "old line" {
		t.Errorf("until bound: %+v", got)
	}
	s.Delete("app")
	s.Flush()
	if got := search(s, "app", "svc"); len(got) != 0 {
		t.Errorf("delete should remove the app's lines: %+v", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "app")); !os.IsNotExist(err) {
		t.Errorf("delete must remove the app's directory, stat err = %v", err)
	}
	if got := search(s, "other", "svc"); len(got) != 1 {
		t.Errorf("delete must not touch another app: %+v", got)
	}
	reload := newTestStore(t, dir, c, nil)
	if got := search(reload, "app", "svc"); len(got) != 0 {
		t.Fatalf("a deleted app's lines must not survive a restart: %+v", got)
	}
}

func TestRestartPersistence(t *testing.T) {
	c := &clock{t: 1000}
	dir := t.TempDir()
	s := newTestStore(t, dir, c, nil)
	s.Record("shop", "api", "aaaaaaaaaaaa", "first")
	s.Flush()
	c.t++
	s.Record("shop", "api", "bbbbbbbbbbbb", "second")
	s.Flush()

	c.t++
	s2 := newTestStore(t, dir, c, nil)
	got := search(s2, "shop", "api")
	if len(got) != 2 || got[0].Text != "second" || got[1].Text != "first" {
		t.Fatalf("reload from disk: %+v", got)
	}
	if cs := s2.Copies("shop", "api"); len(cs) != 2 {
		t.Errorf("copies must be known after a restart: %v", cs)
	}
	s2.Record("shop", "api", "aaaaaaaaaaaa", "third")
	s2.Flush()
	if got := search(s2, "shop", "api"); len(got) != 3 || got[0].Text != "third" {
		t.Fatalf("a restarted store appends after the old lines: %+v", got)
	}
	// The segment the first run left open was closed at load; the restarted store writes a new one.
	segs := segFiles(t, dir, "shop", "api")
	for i, g := range segs {
		if g.open != (i == len(segs)-1) {
			t.Errorf("only the newest segment may be open: %+v", segs)
		}
	}
}

// A crash mid-write can leave the open segment ending in a torn line. After a restart new lines go to
// a fresh segment, so they are never glued onto the torn bytes.
func TestTornLastLineAfterCrash(t *testing.T) {
	c := &clock{t: 1000}
	dir := t.TempDir()
	svcDir := filepath.Join(dir, "shop", "api")
	if err := os.MkdirAll(svcDir, 0o700); err != nil {
		t.Fatal(err)
	}
	torn := `{"at":1000,"copy":"aaaaaaaaaaaa","text":"before the crash"}` + "\n" + `{"at":1000,"text":"half a li`
	if err := os.WriteFile(filepath.Join(svcDir, "0000000003_1000.jsonl"), []byte(torn), 0o600); err != nil {
		t.Fatal(err)
	}
	c.t++
	s := newTestStore(t, dir, c, nil)
	s.Record("shop", "api", "aaaaaaaaaaaa", "after the restart")
	s.Flush()
	got := search(s, "shop", "api")
	if len(got) != 2 || got[0].Text != "after the restart" || got[1].Text != "before the crash" {
		t.Fatalf("lines around a torn line: %+v", got)
	}
	segs := segFiles(t, dir, "shop", "api")
	if len(segs) != 2 || segs[0].open || segs[0].lines != 1 || segs[1].seq != 4 {
		t.Errorf("the torn segment is closed with its real line count and a new one started: %+v", segs)
	}
}

// Files and directories are private to the Mooring user.
func TestFileModes(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "service-logs")
	s := newTestStore(t, dir, &clock{t: 1000}, nil)
	s.Record("shop", "api", "id", "token=abc")
	s.Flush()
	for _, p := range []string{dir, filepath.Join(dir, "shop"), filepath.Join(dir, "shop", "api")} {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o700 {
			t.Errorf("%s: mode %v err %v, want 0700", p, fi.Mode().Perm(), err)
		}
	}
	segs := segFiles(t, dir, "shop", "api")
	if len(segs) != 1 {
		t.Fatalf("want one segment, got %+v", segs)
	}
	fi, err := os.Stat(filepath.Join(dir, "shop", "api", segs[0].name))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("segment mode %v err %v, want 0600", fi.Mode().Perm(), err)
	}
}

func TestSegmentsRotateBySizeLinesAndAge(t *testing.T) {
	c := &clock{t: 100000}
	dir := t.TempDir()
	s := newTestStore(t, dir, c, nil)
	s.SetPolicySource(func(app, svc string) (Policy, bool) {
		return Policy{Retain: 30 * 24 * time.Hour, MaxLines: 100000}, true
	})
	s.Flush() // learn the policy

	// Size: a tiny segment cap closes a segment once it is full.
	s.segMaxBytes = 2 << 10
	for i := 0; i < 40; i++ {
		s.Record("app", "size", "id", strings.Repeat("x", 200))
		s.Flush()
	}
	if n := len(segFiles(t, dir, "app", "size")); n < 3 {
		t.Errorf("size rotation: want several segments, got %d", n)
	}
	for _, g := range segFiles(t, dir, "app", "size") {
		if !g.open && g.lines == 0 {
			t.Errorf("a closed segment records its line count: %+v", g)
		}
	}
	s.segMaxBytes = defaultSegMaxBytes

	// Lines: a segment holds at most segmentLines() lines, even when one buffered batch is larger.
	pol := Policy{Retain: 30 * 24 * time.Hour, MaxLines: 400}
	s.SetPolicySource(func(app, svc string) (Policy, bool) { return pol, true })
	s.Record("app", "lines", "id", "warm")
	s.Flush()
	for i := 0; i < 3*pol.segmentLines(); i++ {
		if i%rateCapPerSec == 0 {
			c.t++
		}
		s.Record("app", "lines", "id", "l")
	}
	s.Flush() // one batch of 300 lines
	segs := segFiles(t, dir, "app", "lines")
	if len(segs) < 4 {
		t.Errorf("line rotation: want ≥4 segments, got %d", len(segs))
	}
	for _, g := range segs {
		b, _ := os.ReadFile(filepath.Join(dir, "app", "lines", g.name))
		if n := strings.Count(string(b), "\n"); n > pol.segmentLines() {
			t.Errorf("segment %s holds %d lines, over %d", g.name, n, pol.segmentLines())
		}
	}

	// Age: a segment older than segmentAge() is closed before more lines are added.
	s.Record("app", "age", "id", "morning")
	s.Flush()
	c.t += int64(pol.segmentAge()/time.Second) + 1
	s.Record("app", "age", "id", "evening")
	s.Flush()
	segs = segFiles(t, dir, "app", "age")
	if len(segs) != 2 || segs[0].open || !segs[1].open || segs[0].lines != 1 {
		t.Errorf("age rotation: %+v", segs)
	}
}

func TestPruneByAge(t *testing.T) {
	c := &clock{t: 1_000_000}
	dir := t.TempDir()
	s := newTestStore(t, dir, c, nil)
	s.SetPolicySource(func(app, svc string) (Policy, bool) { return Policy{Retain: 2 * time.Hour}, true })
	s.Record("app", "svc", "id", "ancient")
	s.Flush()
	c.t += 3600
	s.Record("app", "svc", "id", "an hour later")
	s.Flush()
	c.t += 3600 + 60 // "ancient" is now 2h01m old
	s.Record("app", "svc", "id", "now")
	s.Flush()

	got := search(s, "app", "svc")
	if len(got) != 2 || got[1].Text != "an hour later" {
		t.Fatalf("lines past retain must not be shown: %+v", got)
	}
	for _, g := range segFiles(t, dir, "app", "svc") {
		if g.first == 1_000_000 {
			t.Errorf("the expired segment must be deleted from disk: %+v", g)
		}
	}
	c.t += 10 * 3600
	s.Flush()
	if got := search(s, "app", "svc"); len(got) != 0 {
		t.Errorf("everything expired: %+v", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "app")); !os.IsNotExist(err) {
		t.Errorf("an empty service's directories are removed, stat err = %v", err)
	}
}

// Pruning is per segment, so a kept segment can hold lines past retain: search hides them.
func TestSearchHidesExpiredLinesInAKeptSegment(t *testing.T) {
	c := &clock{t: 1_000_000}
	s := newTestStore(t, t.TempDir(), c, nil)
	s.SetPolicySource(func(app, svc string) (Policy, bool) { return Policy{Retain: 2 * time.Hour}, true })
	s.Record("app", "svc", "id", "expired")
	c.t += 600 // same segment (segmentAge is 15m)
	s.Record("app", "svc", "id", "still in window")
	s.Flush()
	c.t += 2*3600 - 300 // "expired" is 2h05m old, the other line 1h55m
	s.Flush()
	if got := search(s, "app", "svc"); len(got) != 1 || got[0].Text != "still in window" {
		t.Fatalf("lines past retain must be hidden: %+v", got)
	}
}

func TestPruneByLines(t *testing.T) {
	c := &clock{t: 1000}
	dir := t.TempDir()
	s := newTestStore(t, dir, c, nil)
	pol := Policy{MaxLines: 300}
	s.SetPolicySource(func(app, svc string) (Policy, bool) { return pol, true })
	eff := Effective(pol, s.ceil)
	// 2050 lines in 100-line segments: whole-segment pruning leaves 350 on disk.
	for i := 0; i < 2050; i++ {
		if i%rateCapPerSec == 0 {
			c.t++
		}
		s.Record("app", "svc", "id", "n"+strconv.Itoa(i))
		if i%37 == 0 {
			s.Flush()
		}
	}
	s.Flush()
	total := diskLines(t, dir, "app", "svc")
	if total <= 300 || total >= 300+eff.segmentLines() {
		t.Fatalf("on-disk lines %d: want more than max_lines and less than max_lines + one segment", total)
	}
	got := search(s, "app", "svc")
	if len(got) != 300 || got[0].Text != "n2049" || got[299].Text != "n1750" {
		t.Fatalf("search must show exactly the 300 newest lines, got %d (%q … %q)", len(got), got[0].Text, got[len(got)-1].Text)
	}
}

// The global disk budget removes the oldest segments first, across services.
func TestGlobalDiskCapEvictsOldestAcrossServices(t *testing.T) {
	c := &clock{t: 1000}
	dir := t.TempDir()
	s := newTestStore(t, dir, c, nil)
	s.SetPolicySource(func(app, svc string) (Policy, bool) {
		return Policy{Retain: 30 * 24 * time.Hour, MaxLines: 1_000_000}, true
	})
	s.Flush()
	s.segMaxBytes = 1 << 10
	line := strings.Repeat("y", 100)
	// "old" writes first, "new" afterwards, so every "old" segment is older than every "new" one.
	for i := 0; i < 60; i++ {
		c.t += 10
		s.Record("old", "svc", "id", line)
		s.Flush()
	}
	for i := 0; i < 60; i++ {
		c.t += 10
		s.Record("new", "svc", "id", line)
		s.Flush()
	}
	before := dirBytes(t, dir)
	s.maxDisk = before / 2
	s.Flush()
	if after := dirBytes(t, dir); after > s.maxDisk {
		t.Fatalf("disk use %d over the %d budget", after, s.maxDisk)
	}
	if got := search(s, "new", "svc"); len(got) != 60 {
		t.Errorf("the newer service must be untouched while older segments exist: %d lines", len(got))
	}
	if got := search(s, "old", "svc"); len(got) == 60 {
		t.Errorf("the oldest segments must be evicted first")
	}
	s.maxDisk = 1
	s.Flush()
	if after := dirBytes(t, dir); after > 1 {
		t.Errorf("a tiny budget removes everything: %d bytes left", after)
	}
}

func TestSearchNewestFirstAcrossSegmentsWithFilters(t *testing.T) {
	c := &clock{t: 5000}
	dir := t.TempDir()
	s := newTestStore(t, dir, c, nil)
	s.segMaxBytes = 512
	for i := 0; i < 90; i++ {
		c.t++
		cp := "aaaaaaaaaaaa"
		if i%3 == 0 {
			cp = "bbbbbbbbbbbb"
		}
		s.Record("app", "svc", cp, "msg "+strconv.Itoa(i)+" "+map[bool]string{true: "ERROR", false: "ok"}[i%10 == 0])
		if i%5 == 0 {
			s.Flush()
		}
	}
	// Some lines are still pending (unflushed): search merges them with the segments.
	if n := len(segFiles(t, dir, "app", "svc")); n < 3 {
		t.Fatalf("want several segments, got %d", n)
	}
	all := search(s, "app", "svc")
	if len(all) != 90 {
		t.Fatalf("want all 90 lines, got %d", len(all))
	}
	for i := 1; i < len(all); i++ {
		if all[i].At > all[i-1].At {
			t.Fatalf("not newest-first at %d: %d after %d", i, all[i].At, all[i-1].At)
		}
	}
	if all[0].Text != "msg 89 ok" || all[89].Text != "msg 0 ERROR" {
		t.Errorf("ends: %q … %q", all[0].Text, all[89].Text)
	}
	errs, _ := s.Search(bg, "app", "svc", "", "error", 0, 0, 100)
	if len(errs) != 9 || errs[0].Text != "msg 80 ERROR" {
		t.Errorf("text filter across segments: %d %+v", len(errs), errs)
	}
	bs, _ := s.Search(bg, "app", "svc", "bbbbbbbbbbbb", "", 0, 0, 100)
	if len(bs) != 30 {
		t.Errorf("copy filter across segments: %d", len(bs))
	}
	win, _ := s.Search(bg, "app", "svc", "", "", 5011, 5020, 100) // msg 10 .. msg 19
	if len(win) != 10 || win[0].Text != "msg 19 ok" || win[9].Text != "msg 10 ERROR" {
		t.Errorf("time window: %+v", win)
	}
	capped, more := s.Search(bg, "app", "svc", "", "", 0, 0, 25)
	if len(capped) != 25 || !more || capped[0].Text != "msg 89 ok" {
		t.Errorf("cap: %d more=%v", len(capped), more)
	}
	if _, more := s.Search(bg, "app", "svc", "", "error", 0, 0, 9); more {
		t.Errorf("exactly limit matches is not truncated")
	}
}

func TestEffectivePolicyClampsToCeilingsAndDefaults(t *testing.T) {
	ceil := Policy{Retain: 30 * 24 * time.Hour, MaxLines: 200_000}
	cases := []struct {
		req, want Policy
	}{
		{Policy{}, DefaultPolicy},
		{Policy{Retain: 72 * time.Hour}, Policy{Retain: 72 * time.Hour, MaxLines: 2000}},
		{Policy{MaxLines: 50_000}, Policy{Retain: 48 * time.Hour, MaxLines: 50_000}},
		{Policy{Retain: 90 * 24 * time.Hour, MaxLines: 5_000_000}, ceil},
		{Policy{Retain: time.Hour, MaxLines: 100}, Policy{Retain: time.Hour, MaxLines: 100}},
	}
	for _, tc := range cases {
		if got := Effective(tc.req, ceil); got != tc.want {
			t.Errorf("Effective(%+v) = %+v, want %+v", tc.req, got, tc.want)
		}
	}
	// A ceiling below the default lowers the default too.
	if got := Effective(Policy{}, Policy{Retain: 24 * time.Hour, MaxLines: 500}); got != (Policy{Retain: 24 * time.Hour, MaxLines: 500}) {
		t.Errorf("default clamped to a low ceiling: %+v", got)
	}
	// The store applies its ceilings to what the definition asks for.
	s := newTestStore(t, t.TempDir(), &clock{t: 1000}, func(o *Options) { o.Ceiling = Policy{Retain: 7 * 24 * time.Hour, MaxLines: 10_000} })
	s.SetPolicySource(func(app, svc string) (Policy, bool) {
		if svc == "big" {
			return Policy{Retain: 30 * 24 * time.Hour, MaxLines: 1_000_000}, true
		}
		return Policy{}, true
	})
	if got := s.Policy("app", "big"); got != (Policy{Retain: 7 * 24 * time.Hour, MaxLines: 10_000}) {
		t.Errorf("store clamps to its ceiling: %+v", got)
	}
	if got := s.Policy("app", "small"); got != DefaultPolicy {
		t.Errorf("unset = default: %+v", got)
	}
	if got := s.Policy("../x", "big"); got != DefaultPolicy {
		t.Errorf("a bad name never reaches the source: %+v", got)
	}
}

// A policy the source can't read (ok=false) never shrinks history to the default: the store keeps
// the last known policy.
func TestUnknownPolicyKeepsLastKnown(t *testing.T) {
	c := &clock{t: 1_000_000}
	s := newTestStore(t, t.TempDir(), c, nil)
	ok := true
	s.SetPolicySource(func(app, svc string) (Policy, bool) { return Policy{Retain: 30 * 24 * time.Hour}, ok })
	s.Record("app", "svc", "id", "three days ago")
	s.Flush()
	c.t += 3 * 24 * 3600
	ok = false
	s.Record("app", "svc", "id", "now")
	s.Flush()
	if got := search(s, "app", "svc"); len(got) != 2 {
		t.Fatalf("a failed policy read pruned history: %+v", got)
	}
}

// A policy the source can't read is the default once a flush has tried to read it: a service never keeps
// the ceiling because its `logs:` is unknown. Until that first attempt nothing has been pruned and the
// whole history is searchable. Policy always reports what the store applies.
func TestUnreadablePolicyIsTheDefaultAfterTheFirstFlush(t *testing.T) {
	c := &clock{t: 1_000_000}
	dir := t.TempDir()
	// A previous run kept 30 days for "svc": one line from 3 days ago and 2500 recent lines.
	prev := newTestStore(t, dir, c, nil)
	prev.SetPolicySource(func(app, svc string) (Policy, bool) {
		return Policy{Retain: 30 * 24 * time.Hour, MaxLines: 100_000}, true
	})
	prev.segMaxBytes = 4 << 10 // small segments, so pruning to the line cap can remove whole ones
	prev.Record("app", "svc", "id", "three days ago")
	prev.Record("app", "readable", "id", "line")
	prev.Flush()
	c.t += 3 * 24 * 3600
	for i := 0; i < 2500; i++ {
		if i%rateCapPerSec == 0 {
			c.t++
		}
		prev.Record("app", "svc", "id", "recent-"+strconv.Itoa(i))
		if i%50 == 49 {
			prev.Flush()
		}
	}
	prev.Flush()

	// After a restart the definition can't be read for "svc" (and nothing was cached).
	s := newTestStore(t, dir, c, nil)
	s.SetPolicySource(func(app, svc string) (Policy, bool) {
		if svc == "readable" {
			return Policy{Retain: 72 * time.Hour}, true
		}
		return Policy{}, false
	})
	if got := s.Policy("app", "svc"); got != s.ceil {
		t.Errorf("before the first flush: Policy = %+v, want the ceiling %+v (nothing is cut yet)", got, s.ceil)
	}
	if got, _ := s.Search(bg, "app", "svc", "", "three days", 0, 0, 10); len(got) != 1 {
		t.Errorf("before the first flush the whole history is searchable: %+v", got)
	}
	if got := s.Policy("app", "readable"); got != (Policy{Retain: 72 * time.Hour, MaxLines: DefaultPolicy.MaxLines}) {
		t.Errorf("a readable policy is used from the start: %+v", got)
	}

	s.Flush()
	if got := s.Policy("app", "svc"); got != DefaultPolicy {
		t.Errorf("after a flush: Policy = %+v, want the default", got)
	}
	if got, _ := s.Search(bg, "app", "svc", "", "three days", 0, 0, 10); len(got) != 0 {
		t.Errorf("an unreadable policy kept lines past the default retain: %+v", got)
	}
	if got := search(s, "app", "svc"); len(got) != DefaultPolicy.MaxLines || got[0].Text != "recent-2499" {
		t.Errorf("an unreadable policy must cut to the default %d lines, got %d", DefaultPolicy.MaxLines, len(got))
	}
	for _, g := range segFiles(t, dir, "app", "svc") {
		if g.first == 1_000_000 {
			t.Errorf("the segment past the default retain must be deleted: %+v", g)
		}
	}
	if onDisk := diskLines(t, dir, "app", "svc"); onDisk >= DefaultPolicy.MaxLines+DefaultPolicy.segmentLines() {
		t.Errorf("on-disk lines %d not pruned to the default", onDisk)
	}
}

// Search stops as soon as its context ends: it opens no further segment and reports more.
func TestSearchStopsWhenTheContextEnds(t *testing.T) {
	c := &clock{t: 5000}
	s := newTestStore(t, t.TempDir(), c, nil)
	s.segMaxBytes = 512
	for i := 0; i < 200; i++ {
		c.t++
		s.Record("app", "svc", "id", "line "+strconv.Itoa(i))
		s.Flush()
	}
	ctx, cancel := context.WithCancel(bg)
	defer cancel()
	opens := 0
	s.searchOpen = func(p string) (*os.File, error) {
		opens++
		cancel() // the viewer leaves while the first segment is being read
		return openSegment(p)
	}
	got, more := s.Search(ctx, "app", "svc", "", "", 0, 0, maxSearchLimit)
	if !more || len(got) != 0 || opens != 1 {
		t.Fatalf("cancelled search: %d lines, more=%v, %d segments opened; want 0, true, 1", len(got), more, opens)
	}
	// A search that is already cancelled when it starts reads nothing.
	opens = 0
	s.searchOpen = openSegment
	if got, more := s.Search(ctx, "app", "svc", "", "", 0, 0, maxSearchLimit); len(got) != 0 || !more {
		t.Errorf("search with a cancelled context: %d lines, more=%v", len(got), more)
	}
}

// Waiting for a search slot honours the context: with every slot taken, a search gives up when its
// context ends instead of waiting forever.
func TestSearchSlotWaitHonoursTheContext(t *testing.T) {
	s := newTestStore(t, t.TempDir(), &clock{t: 1000}, nil)
	s.Record("app", "svc", "id", "x")
	for i := 0; i < searchSlots; i++ {
		s.searchSem <- struct{}{}
	}
	ctx, cancel := context.WithTimeout(bg, 50*time.Millisecond)
	defer cancel()
	done := make(chan bool, 1)
	go func() {
		got, more := s.Search(ctx, "app", "svc", "", "", 0, 0, 10)
		done <- len(got) == 0 && more
	}()
	select {
	case ok := <-done:
		if !ok {
			t.Error("a search that never got a slot must return nothing, with more")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a search waited for a slot past its context")
	}
	// The time budget bounds the wait even when the caller's context never ends.
	s.timeBudget = 50 * time.Millisecond
	go func() {
		got, more := s.Search(bg, "app", "svc", "", "", 0, 0, 10)
		done <- len(got) == 0 && more
	}()
	select {
	case ok := <-done:
		if !ok {
			t.Error("a search that never got a slot must return nothing, with more")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a search waited for a slot past its time budget")
	}
}

// A search in progress holds no service lock while it reads segments: Record and Flush carry on.
func TestSearchDoesNotBlockRecord(t *testing.T) {
	c := &clock{t: 5000}
	s := newTestStore(t, t.TempDir(), c, nil)
	s.segMaxBytes = 512
	for i := 0; i < 50; i++ {
		c.t++
		s.Record("app", "svc", "id", "line "+strconv.Itoa(i))
		s.Flush()
	}
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	s.searchOpen = func(p string) (*os.File, error) {
		once.Do(func() { close(entered); <-release })
		return openSegment(p)
	}
	searched := make(chan int, 1)
	go func() { got := search(s, "app", "svc"); searched <- len(got) }()
	<-entered
	recorded := make(chan struct{})
	go func() {
		s.Record("app", "svc", "id", "while searching")
		s.Flush()
		close(recorded)
	}()
	select {
	case <-recorded:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("Record waited for an in-flight search")
	}
	close(release)
	if n := <-searched; n < 50 {
		t.Errorf("the search returned %d lines, want at least the 50 recorded before it", n)
	}
	if got, _ := s.Search(bg, "app", "svc", "", "while searching", 0, 0, 10); len(got) != 1 {
		t.Errorf("the line recorded during the search was lost: %+v", got)
	}
}

// One search reads at most its byte budget: past it, it returns the newest matches found and more.
func TestSearchByteBudgetReturnsPartialResults(t *testing.T) {
	c := &clock{t: 5000}
	s := newTestStore(t, t.TempDir(), c, nil)
	s.SetPolicySource(func(app, svc string) (Policy, bool) { return Policy{MaxLines: 100_000}, true })
	s.Flush()
	s.segMaxBytes = 16 << 10
	for i := 0; i < 3000; i++ {
		if i%rateCapPerSec == 0 {
			c.t++
		}
		s.Record("app", "svc", "id", "line-"+strconv.Itoa(i)+"-"+strings.Repeat("z", 100))
	}
	s.Flush()
	if len(segFiles(t, s.dir, "app", "svc")) < 10 {
		t.Fatal("want many segments")
	}
	s.scanBudget = 40 << 10
	got, more := s.Search(bg, "app", "svc", "", "", 0, 0, maxSearchLimit)
	if !more || len(got) == 0 || len(got) >= 2000 {
		t.Fatalf("over budget: %d lines, more=%v; want a partial result with more", len(got), more)
	}
	if !strings.HasPrefix(got[0].Text, "line-2999-") {
		t.Errorf("a partial result starts at the newest line, got %q", got[0].Text)
	}
	s.scanBudget = searchScanBudget
	if got, more := s.Search(bg, "app", "svc", "", "", 0, 0, maxSearchLimit); len(got) != maxSearchLimit || !more {
		t.Errorf("within budget: %d lines, more=%v", len(got), more)
	}
}

// Segments outside the search window are never opened.
func TestSearchSkipsSegmentsOutsideTheWindow(t *testing.T) {
	c := &clock{t: 10_000}
	s := newTestStore(t, t.TempDir(), c, nil)
	s.segMaxBytes = 512
	for i := 0; i < 100; i++ {
		c.t += 10
		s.Record("app", "svc", "id", "line "+strconv.Itoa(i))
		s.Flush()
	}
	opened := map[string]bool{}
	s.searchOpen = func(p string) (*os.File, error) { opened[filepath.Base(p)] = true; return openSegment(p) }
	got, _ := s.Search(bg, "app", "svc", "", "", 10_400, 10_500, maxSearchLimit) // line 39 .. line 49
	if len(got) != 11 || got[0].Text != "line 49" || got[10].Text != "line 39" {
		t.Fatalf("window: %+v", got)
	}
	for _, g := range segFiles(t, s.dir, "app", "svc") {
		outside := g.last < 10_400 || g.first > 10_500
		if outside && opened[g.name] {
			t.Errorf("segment %s (%d..%d) is outside the window but was opened", g.name, g.first, g.last)
		}
	}
}

// A segment closed (renamed) or pruned after a search listed it: a renamed one is found again, a pruned
// one ends there, and the rest of the search goes on.
func TestSearchToleratesSegmentsChangedMidSearch(t *testing.T) {
	c := &clock{t: 5000}
	dir := t.TempDir()
	s := newTestStore(t, dir, c, nil)
	s.segMaxBytes = 1 << 10
	for i := 0; i < 60; i++ {
		c.t++
		s.Record("app", "svc", "id", "line "+strconv.Itoa(i)+" "+strings.Repeat("p", 40))
		s.Flush()
	}
	segs := segFiles(t, dir, "app", "svc")
	if len(segs) < 4 || !segs[len(segs)-1].open {
		t.Fatalf("want several segments, the newest open: %+v", segs)
	}
	pruned := segs[1]
	sl := s.service("app", "svc", false)
	first := true
	s.searchOpen = func(p string) (*os.File, error) {
		if first {
			first = false
			// Between the listing and this open, the open segment is closed (renamed) and an older one
			// is pruned.
			sl.mu.Lock()
			sl.closeActiveLocked()
			sl.mu.Unlock()
			if err := os.Remove(filepath.Join(dir, "app", "svc", pruned.name)); err != nil {
				t.Error(err)
			}
		}
		return openSegment(p)
	}
	got := search(s, "app", "svc")
	if want := 60 - pruned.lines; len(got) != want || got[0].Text != "line 59 "+strings.Repeat("p", 40) {
		t.Fatalf("got %d lines (newest %q), want %d with the renamed segment's lines first", len(got), got[0].Text, want)
	}
}

// After an app is deleted, a late line from one of its tailers doesn't recreate its files. Capture for
// the name starts again once deletedAppTTL has passed.
func TestDeleteBlocksLateRecords(t *testing.T) {
	c := &clock{t: 1000}
	dir := t.TempDir()
	s := newTestStore(t, dir, c, nil)
	s.Record("app", "svc", "id", "before the delete")
	s.Record("other", "svc", "id", "keep")
	s.Flush()
	s.Delete("app")
	s.Record("app", "svc", "id", "late line")
	s.Record("app", "worker", "id", "late line")
	s.Flush()
	if _, err := os.Stat(filepath.Join(dir, "app")); !os.IsNotExist(err) {
		t.Fatalf("a late line recreated the deleted app's directory (stat err %v)", err)
	}
	if got := search(s, "app", "svc"); len(got) != 0 {
		t.Errorf("a late line was kept: %+v", got)
	}
	s.Record("other", "svc", "id", "still captured")
	if got := search(s, "other", "svc"); len(got) != 2 {
		t.Errorf("another app's capture must go on: %+v", got)
	}
	c.t += int64(deletedAppTTL/time.Second) + 1
	s.Record("app", "svc", "id", "a new app with the same name")
	if got := search(s, "app", "svc"); len(got) != 1 {
		t.Errorf("capture for the name must resume after %s: %+v", deletedAppTTL, got)
	}
}

func TestDiskPressureBacksOff(t *testing.T) {
	c := &clock{t: 1_000_000}
	dir := t.TempDir()
	used := uint64(50)
	s := newTestStore(t, dir, c, func(o *Options) {
		o.DiskUsage = func() (uint64, uint64, bool) { return used, 100, true }
		o.DiskThresholdPct = 75
	})
	s.SetPolicySource(func(app, svc string) (Policy, bool) {
		return Policy{Retain: 30 * 24 * time.Hour, MaxLines: 100_000}, true
	})
	s.Record("app", "svc", "id", "a week ago")
	s.Flush()
	c.t += 7 * 24 * 3600
	for i := 0; i < 3000; i++ {
		if i%rateCapPerSec == 0 {
			c.t++
		}
		s.Record("app", "svc", "id", "recent-"+strconv.Itoa(i)+"-x")
	}
	s.Flush()
	find := func(q string) int {
		got, _ := s.Search(bg, "app", "svc", "", q, 0, 0, 10)
		return len(got)
	}
	if find("week") != 1 || find("recent-0-x") != 1 || s.Paused() {
		t.Fatalf("below the threshold the service's own 30d/100000 policy applies (paused=%v)", s.Paused())
	}

	used = 80
	s.Flush()
	if !s.Paused() {
		t.Fatal("at/above the threshold capture must pause")
	}
	if find("week") != 0 {
		t.Error("under pressure history is cut to the default 48h")
	}
	if find("recent-999-x") != 0 || find("recent-1000-x") != 1 {
		t.Errorf("under pressure history is cut to the default %d lines", DefaultPolicy.MaxLines)
	}
	for _, g := range segFiles(t, dir, "app", "svc") {
		if g.first == 1_000_000 {
			t.Errorf("under pressure the files are pruned too: %+v", g)
		}
	}
	c.t++
	for i := 0; i < 7; i++ {
		s.Record("app", "svc", "id", "dropped while paused")
	}
	if got, _ := s.Search(bg, "app", "svc", "", "paused", 0, 0, 100); len(got) != 0 {
		t.Fatalf("new lines are dropped while paused: %+v", got)
	}

	used = 60
	c.t++
	s.Flush()
	if s.Paused() {
		t.Fatal("capture resumes once usage drops below the threshold")
	}
	s.Record("app", "svc", "id", "back")
	got, _ := s.Search(bg, "app", "svc", "", "", 0, 0, 3)
	if len(got) != 3 || got[0].Text != "back" || !strings.Contains(got[1].Text, "7 line(s) dropped") || got[1].Copy != "" {
		t.Fatalf("resume writes a counted marker: %+v", got)
	}
}

func TestMigratesLegacyJSONL(t *testing.T) {
	c := &clock{t: 1_000_000}
	data := t.TempDir()
	legacy := filepath.Join(data, "service-logs.jsonl")
	dir := filepath.Join(data, "service-logs")
	var b strings.Builder
	enc := json.NewEncoder(&b)
	old := c.t - int64(DefaultPolicy.Retain/time.Second) - 60
	for _, l := range []Line{
		{At: old, App: "shop", Svc: "api", Copy: "aaaaaaaaaaaa", Text: "expired"},
		{At: c.t - 30, App: "shop", Svc: "api", Copy: "aaaaaaaaaaaa", Text: "one"},
		{At: c.t - 20, App: "blog", Svc: "web", Copy: "bbbbbbbbbbbb", Text: "blog line"},
		{At: c.t - 10, App: "shop", Svc: "api", Copy: "cccccccccccc", Text: "two"},
		{At: c.t - 5, App: "../etc", Svc: "x", Text: "escape"},
	} {
		_ = enc.Encode(l)
	}
	b.WriteString("not json\n")
	if err := os.WriteFile(legacy, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacy+".tmp", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	s := newTestStore(t, dir, c, func(o *Options) { o.LegacyFile = legacy })
	got := search(s, "shop", "api")
	if len(got) != 2 || got[0].Text != "two" || got[1].Text != "one" || got[0].Copy != "cccccccccccc" {
		t.Fatalf("migrated lines: %+v", got)
	}
	if got := search(s, "blog", "web"); len(got) != 1 {
		t.Errorf("every service is migrated: %+v", got)
	}
	for _, p := range []string{legacy, legacy + ".tmp"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s must be removed after the import (err %v)", p, err)
		}
	}
	if _, err := os.Stat(filepath.Join(data, "etc")); !os.IsNotExist(err) {
		t.Errorf("a bad name in the old file must not create anything")
	}
	// Re-running the import (e.g. a crash before the old file was removed) never duplicates lines.
	if err := os.WriteFile(legacy, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	s2 := newTestStore(t, dir, c, func(o *Options) { o.LegacyFile = legacy })
	if got := search(s2, "shop", "api"); len(got) != 2 {
		t.Errorf("a second import duplicated lines: %+v", got)
	}
}

func TestPurgeRemovesEverything(t *testing.T) {
	data := t.TempDir()
	dir := filepath.Join(data, "service-logs")
	legacy := filepath.Join(data, "service-logs.jsonl")
	s := newTestStore(t, dir, &clock{t: 1000}, nil)
	s.Record("shop", "api", "id", "secret")
	s.Flush()
	_ = os.WriteFile(legacy, []byte("{}\n"), 0o600)
	_ = os.WriteFile(legacy+".tmp", []byte("{}\n"), 0o600)
	Purge(dir, legacy)
	for _, p := range []string{dir, legacy, legacy + ".tmp"} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s survived Purge (err %v)", p, err)
		}
	}
}

// App and service names come from container labels: anything that isn't a plain name is refused
// before it reaches a path.
func TestPathConfinement(t *testing.T) {
	data := t.TempDir()
	dir := filepath.Join(data, "service-logs")
	sentinel := filepath.Join(data, "sentinel")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := newTestStore(t, dir, &clock{t: 1000}, nil)
	bad := []string{"", "..", ".", "../x", "a/b", `a\b`, ".hidden", "UPPER", "-lead", "a b", "a\x00b", strings.Repeat("a", 64)}
	for _, n := range bad {
		s.Record(n, "svc", "id", "x")
		s.Record("app", n, "id", "x")
		if got, _ := s.Search(bg, n, "svc", "", "", 0, 0, 10); got != nil {
			t.Errorf("search with app %q returned %v", n, got)
		}
		if got, _ := s.Search(bg, "app", n, "", "", 0, 0, 10); got != nil {
			t.Errorf("search with service %q returned %v", n, got)
		}
		s.Delete(n)
	}
	s.Flush()
	ents, _ := os.ReadDir(dir)
	if len(ents) != 0 {
		t.Errorf("bad names created entries: %v", ents)
	}
	if b, err := os.ReadFile(sentinel); err != nil || string(b) != "keep" {
		t.Errorf("a file outside the log dir was touched: %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Errorf("Delete with a bad name must not remove the root: %v", err)
	}
	// Valid names at the edges are accepted.
	s.Record("a", strings.Repeat("b", 63), "id", "ok")
	s.Record("0app", "svc_1-x", "id", "ok")
	if len(search(s, "a", strings.Repeat("b", 63))) != 1 || len(search(s, "0app", "svc_1-x")) != 1 {
		t.Error("valid names must be accepted")
	}
}

// Loading ignores symlinks and files that aren't segments, so nothing outside the log dir is read.
func TestLoadIgnoresSymlinksAndJunk(t *testing.T) {
	data := t.TempDir()
	dir := filepath.Join(data, "service-logs")
	c := &clock{t: 1000}
	s := newTestStore(t, dir, c, nil)
	s.Record("shop", "api", "id", "real")
	s.Flush()

	outside := filepath.Join(data, "outside")
	if err := os.MkdirAll(filepath.Join(outside, "svc"), 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(outside, "svc", "0000000001_1000.jsonl"), []byte(`{"at":1000,"text":"outside"}`+"\n"), 0o600)
	if err := os.Symlink(outside, filepath.Join(dir, "linked")); err != nil {
		t.Skip("symlinks unsupported:", err)
	}
	_ = os.Symlink(filepath.Join(outside, "svc", "0000000001_1000.jsonl"), filepath.Join(dir, "shop", "api", "0000000099_1000.jsonl"))
	_ = os.WriteFile(filepath.Join(dir, "shop", "api", "notes.txt"), []byte("junk"), 0o600)

	s2 := newTestStore(t, dir, c, nil)
	if got := search(s2, "linked", "svc"); len(got) != 0 {
		t.Errorf("a symlinked app dir was followed: %+v", got)
	}
	ents, _ := os.ReadDir(filepath.Join(outside, "svc"))
	if len(ents) != 1 || ents[0].Name() != "0000000001_1000.jsonl" {
		t.Errorf("loading modified files outside the log dir: %v", ents)
	}
	if got := search(s2, "shop", "api"); len(got) != 1 || got[0].Text != "real" {
		t.Errorf("a symlinked segment was read: %+v", got)
	}
}

// Capture time never goes backwards within a service, so files stay in time order.
func TestCaptureTimeIsMonotonic(t *testing.T) {
	c := &clock{t: 2000}
	s := newTestStore(t, t.TempDir(), c, nil)
	s.Record("app", "svc", "id", "a")
	c.t = 1500 // the wall clock steps back
	s.Record("app", "svc", "id", "b")
	got := search(s, "app", "svc")
	if len(got) != 2 || got[0].Text != "b" || got[0].At < got[1].At {
		t.Fatalf("time order broken: %+v", got)
	}
}

func TestServiceCap(t *testing.T) {
	s := newTestStore(t, t.TempDir(), &clock{t: 1000}, nil)
	for i := 0; i < maxServices+5; i++ {
		s.Record("app", "s"+strconv.Itoa(i), "id", "x")
	}
	if got := search(s, "app", "s"+strconv.Itoa(maxServices+1)); len(got) != 0 {
		t.Errorf("services past the cap must not be tracked")
	}
	if got := search(s, "app", "s0"); len(got) != 1 {
		t.Errorf("services under the cap are tracked")
	}
}

// Record, Search, Copies, Flush and Delete run concurrently without races or deadlocks.
func TestConcurrentUse(t *testing.T) {
	var mu sync.Mutex
	c := &clock{t: 1000}
	now := func() time.Time { mu.Lock(); defer mu.Unlock(); return c.now() }
	s := newStore(Options{Dir: t.TempDir(), Log: discard}, now)
	s.segMaxBytes = 1 << 10
	s.SetPolicySource(func(app, svc string) (Policy, bool) { return Policy{MaxLines: 300}, true })
	var wg sync.WaitGroup
	done := make(chan struct{})
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 2000; i++ {
				s.Record("app"+strconv.Itoa(w%2), "svc", "c"+strconv.Itoa(w), "line "+strconv.Itoa(i))
			}
		}(w)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			s.Search(bg, "app0", "svc", "", "line 1", 0, 0, 100)
			s.Copies("app1", "svc")
			s.Flush()
			s.Delete("app1")
			mu.Lock()
			c.t++
			mu.Unlock()
		}
	}()
	time.Sleep(50 * time.Millisecond)
	close(done)
	wg.Wait()
	s.Flush()
	if got := search(s, "app0", "svc"); len(got) == 0 || len(got) > 300 {
		t.Errorf("after concurrent use: %d lines", len(got))
	}
}

func TestEachLineBackward(t *testing.T) {
	content := "first\n" + strings.Repeat("L", 50) + "\nthird\n\nfifth-no-newline"
	for _, chunk := range []int{1, 3, 7, 64, 4096} {
		var got []string
		r := strings.NewReader(content)
		if err := eachLineBackward(r, int64(len(content)), chunk, func(b []byte) bool {
			got = append(got, string(b))
			return true
		}); err != nil {
			t.Fatal(err)
		}
		want := []string{"fifth-no-newline", "third", strings.Repeat("L", 50), "first"}
		if strings.Join(got, "|") != strings.Join(want, "|") {
			t.Errorf("chunk %d: got %q", chunk, got)
		}
	}
	// Stops when fn returns false.
	n := 0
	_ = eachLineBackward(strings.NewReader(content), int64(len(content)), 4, func([]byte) bool { n++; return n < 2 })
	if n != 2 {
		t.Errorf("early stop: %d calls", n)
	}
}
