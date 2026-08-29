package servicelog

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T, now func() time.Time) *Store {
	t.Helper()
	return newWithClock(filepath.Join(t.TempDir(), "s.jsonl"), now, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func TestRecordSearchAndCopyFilter(t *testing.T) {
	clk := int64(1000)
	s := newTestStore(t, func() time.Time { return time.Unix(clk, 0) })

	s.Record("shop", "api", "aaaaaaaaaaaa", "starting up")
	clk++
	s.Record("shop", "api", "aaaaaaaaaaaa", "ERROR: db connection refused")
	s.Record("shop", "api", "bbbbbbbbbbbb", "replica 2 healthy")
	s.Record("blog", "web", "cccccccccccc", "unrelated app line")

	// Newest-first, merged across copies.
	all := s.Search("shop", "api", "", "", 0, 0, 100)
	if len(all) != 3 || all[0].Text != "replica 2 healthy" {
		t.Fatalf("expected 3 api lines newest-first, got %+v", all)
	}
	// Text filter (case-insensitive).
	if got := s.Search("shop", "api", "", "error", 0, 0, 100); len(got) != 1 || got[0].Text != "ERROR: db connection refused" {
		t.Errorf("text filter: %+v", got)
	}
	// Copy filter narrows to one replica.
	if got := s.Search("shop", "api", "bbbbbbbbbbbb", "", 0, 0, 100); len(got) != 1 || got[0].Copy != "bbbbbbbbbbbb" {
		t.Errorf("copy filter: %+v", got)
	}
	// A different app's line never leaks in.
	if got := s.Search("shop", "api", "", "unrelated", 0, 0, 100); len(got) != 0 {
		t.Errorf("cross-app leak: %+v", got)
	}
	if cs := s.Copies("shop", "api"); len(cs) != 2 {
		t.Errorf("expected 2 copies, got %v", cs)
	}
}

func TestSearchIsWordAnd(t *testing.T) {
	s := newTestStore(t, func() time.Time { return time.Unix(1000, 0) })
	s.Record("shop", "api", "id", `{"level":"error","statusCode":502,"msg":"upstream down"}`)
	s.Record("shop", "api", "id", `{"level":"info","statusCode":200,"msg":"ok"}`)

	// The reported bug: "statusCode 502" (two words, in a line where they're not adjacent) must match.
	if got := s.Search("shop", "api", "", "statusCode 502", 0, 0, 10); len(got) != 1 || got[0].Text[:20] != `{"level":"error","st` {
		t.Fatalf("word-AND search should find the 502 line, got %+v", got)
	}
	// Order-independent: words can appear in any order.
	if got := s.Search("shop", "api", "", "502 error", 0, 0, 10); len(got) != 1 {
		t.Errorf("word order must not matter, got %d", len(got))
	}
	// All words required: a line missing one word does not match.
	if got := s.Search("shop", "api", "", "statusCode 200 error", 0, 0, 10); len(got) != 0 {
		t.Errorf("a line missing a required word must not match, got %d", len(got))
	}
	// Empty query returns everything.
	if got := s.Search("shop", "api", "", "   ", 0, 0, 10); len(got) != 2 {
		t.Errorf("blank query should return all, got %d", len(got))
	}
}

func TestPerServiceRingDoesNotEvictOtherServices(t *testing.T) {
	s := newTestStore(t, func() time.Time { return time.Unix(1000, 0) })
	// One chatty service floods its own ring...
	for i := 0; i < perServiceMax+500; i++ {
		s.Record("noisy", "svc", "id", "line")
	}
	// ...while a quiet service recorded a single line long "before".
	s.Record("quiet", "svc", "id", "the one important line")

	// The quiet service's line must survive (chatty only evicts its OWN history).
	if got := s.Search("quiet", "svc", "", "", 0, 0, 10); len(got) != 1 {
		t.Fatalf("quiet service evicted by a chatty one: %+v", got)
	}
	// The chatty service is ring-capped, not unbounded.
	if got := s.Search("noisy", "svc", "", "", 0, 0, perServiceMax+1000); len(got) > perServiceMax {
		t.Errorf("per-service ring not capped: %d", len(got))
	}
}

func TestRateCapDropsWithMarker(t *testing.T) {
	clk := int64(1000)
	s := newTestStore(t, func() time.Time { return time.Unix(clk, 0) })
	// Blow past the per-second rate cap within one second.
	for i := 0; i < rateCapPerSec+50; i++ {
		s.Record("app", "svc", "id", "spam")
	}
	// Roll the clock to the next second and record once — this flushes the dropped-count marker.
	clk++
	s.Record("app", "svc", "id", "next second")

	lines := s.Search("app", "svc", "", "", 0, 0, rateCapPerSec+100)
	// Accepted lines are capped at the rate limit (+ the marker + the next-second line).
	if len(lines) > rateCapPerSec+2 {
		t.Errorf("rate cap not enforced: kept %d", len(lines))
	}
	foundMarker := false
	for _, l := range lines {
		if l.Copy == "" && len(l.Text) > 0 && l.Text[0] == 0xE2 { // "…" starts with 0xE2 (UTF-8 horizontal ellipsis)
			foundMarker = true
		}
	}
	if !foundMarker {
		t.Errorf("expected a coalesced dropped-lines marker; lines=%d", len(lines))
	}
}

func TestTimeWindowAndDelete(t *testing.T) {
	clk := int64(10000)
	s := newTestStore(t, func() time.Time { return time.Unix(clk, 0) })
	clk = 9000
	s.Record("app", "svc", "id", "old line")
	clk = 10000
	s.Record("app", "svc", "id", "recent line")

	// [since, until] window excludes the old line.
	if got := s.Search("app", "svc", "", "", 9500, 0, 100); len(got) != 1 || got[0].Text != "recent line" {
		t.Errorf("since bound: %+v", got)
	}
	s.Delete("app")
	if got := s.Search("app", "svc", "", "", 0, 0, 100); len(got) != 0 {
		t.Errorf("delete should remove the app's lines: %+v", got)
	}
}

func TestPersistAndReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.jsonl")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clk := int64(1000)
	s := newWithClock(path, func() time.Time { return time.Unix(clk, 0) }, log)
	s.Record("shop", "api", "id", "persisted line")
	s.Flush()

	// A fresh store over the same path reloads the retained line.
	s2 := newWithClock(path, func() time.Time { return time.Unix(clk, 0) }, log)
	if got := s2.Search("shop", "api", "", "", 0, 0, 10); len(got) != 1 || got[0].Text != "persisted line" {
		t.Fatalf("reload from disk: %+v", got)
	}
}

func TestDeleteThenFlushPurgesFromDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.jsonl")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	clk := int64(1000)
	s := newWithClock(path, func() time.Time { return time.Unix(clk, 0) }, log)
	s.Record("doomed", "svc", "id", "secret: token=abc")
	s.Flush()

	// App teardown: Delete + Flush must persist the removal NOW (so a later reload can't resurrect it).
	s.Delete("doomed")
	s.Flush()

	reload := newWithClock(path, func() time.Time { return time.Unix(clk, 0) }, log)
	if got := reload.Search("doomed", "svc", "", "", 0, 0, 10); len(got) != 0 {
		t.Fatalf("a deleted app's lines must not survive on disk after Delete+Flush: %+v", got)
	}
}

func TestTTLPrunesOnLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.jsonl")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Write a line far in the past, then reload "now" well past the TTL.
	old := newWithClock(path, func() time.Time { return time.Unix(1000, 0) }, log)
	old.Record("shop", "api", "id", "ancient")
	old.Flush()

	future := int64(1000) + int64(defaultTTL/time.Second) + 3600
	fresh := newWithClock(path, func() time.Time { return time.Unix(future, 0) }, log)
	if got := fresh.Search("shop", "api", "", "", 0, 0, 10); len(got) != 0 {
		t.Errorf("expired line should be pruned on load, got %+v", got)
	}
}
