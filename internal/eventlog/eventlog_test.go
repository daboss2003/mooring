package eventlog

import (
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"
)

func newTestStore(t *testing.T) (*Store, *int64) {
	t.Helper()
	var nowUnix int64 = 1_000_000
	s := newWithClock(filepath.Join(t.TempDir(), "events.jsonl"), func() time.Time { return time.Unix(nowUnix, 0) })
	return s, &nowUnix
}

func TestDedupCollapsesRepeats(t *testing.T) {
	s, now := newTestStore(t)
	for i := 0; i < 100; i++ {
		*now += 10
		s.Record("WARN", "scale: refused", "target=credlock/api")
	}
	s.Record("WARN", "scale: refused", "target=credlock/resolver") // a DIFFERENT target = its own row
	s.Record("ERROR", "backup failed", "app=db")

	list := s.List()
	if len(list) != 3 {
		t.Fatalf("expected 3 deduped rows, got %d: %+v", len(list), list)
	}
	// The api-refusal row must carry the full count + a moving last-seen.
	var api *Event
	for i := range list {
		if list[i].Msg == "scale: refused" && list[i].Attrs == "target=credlock/api" {
			api = &list[i]
		}
	}
	if api == nil || api.Count != 100 {
		t.Fatalf("api refusal must collapse to one row ×100, got %+v", api)
	}
	if api.Last <= api.First {
		t.Error("last-seen must advance past first-seen for a repeating event")
	}
}

func TestTTLPrunesOldEvents(t *testing.T) {
	s, now := newTestStore(t)
	s.Record("WARN", "old thing", "")
	*now += int64((25 * time.Hour).Seconds()) // past the 24h window
	s.Record("WARN", "new thing", "")
	list := s.List()
	if len(list) != 1 || list[0].Msg != "new thing" {
		t.Fatalf("the 25h-old event must be pruned, got %+v", list)
	}
}

func TestCapEvictsOldest(t *testing.T) {
	s, now := newTestStore(t)
	s.maxRows = 3
	for i, m := range []string{"a", "b", "c"} {
		*now += int64(i + 1)
		s.Record("WARN", m, "")
	}
	*now++
	s.Record("WARN", "d", "") // exceeds cap → evicts the oldest ("a")
	list := s.List()
	if len(list) != 3 {
		t.Fatalf("cap must hold at 3, got %d", len(list))
	}
	for _, e := range list {
		if e.Msg == "a" {
			t.Error("the oldest row (a) must have been evicted")
		}
	}
}

func TestPersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	var nowUnix int64 = 2_000_000

	clock := func() time.Time { return time.Unix(nowUnix, 0) }
	s1 := newWithClock(path, clock)
	s1.Record("ERROR", "deploy failed", "app=web")
	s1.Record("WARN", "deploy failed", "app=web") // different level = different row
	if err := s1.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	// Reload from disk into a fresh store (same clock) — the events must survive a restart.
	if got := len(newWithClock(path, clock).List()); got != 2 {
		t.Fatalf("reloaded store should have 2 events, got %d", got)
	}

	// A too-old file is dropped on load.
	nowUnix += int64((48 * time.Hour).Seconds())
	if got := len(newWithClock(path, clock).List()); got != 0 {
		t.Errorf("events older than the TTL must not reload, got %d", got)
	}
	_ = os.Remove(path)
}

// The slog handler must tee WARN+ERROR (not INFO/DEBUG) into the store, carrying .With attrs, and
// always pass through to the base handler.
func TestHandlerTeesWarnAndError(t *testing.T) {
	s, _ := newTestStore(t)
	base := slog.NewTextHandler(os.NewFile(0, os.DevNull), &slog.HandlerOptions{Level: slog.LevelDebug})
	log := slog.New(NewHandler(base, s))

	log.Info("just info")                                    // NOT captured
	log.Warn("scale: refused", "target", "credlock/api")     // captured
	log.With("project", "credlock").Error("git poll failed") // captured, with the .With attr

	list := s.List()
	if len(list) != 2 {
		t.Fatalf("only WARN+ERROR should be captured, got %d: %+v", len(list), list)
	}
	var sawWith bool
	for _, e := range list {
		if e.Msg == "git poll failed" && e.Attrs == "project=credlock" {
			sawWith = true
		}
		if e.Msg == "just info" {
			t.Error("INFO must not be captured")
		}
	}
	if !sawWith {
		t.Errorf("a .With() attr must be carried into the event: %+v", list)
	}
}

func TestConcurrentSafe(t *testing.T) {
	s, _ := newTestStore(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 300; j++ {
				s.Record("WARN", "concurrent event", "worker="+strconv.Itoa(id%3)) // record from the "log path"
				if j%50 == 0 {
					_ = s.List()  // the web read
					_ = s.Flush() // the periodic flusher
				}
			}
		}(i)
	}
	wg.Wait()
	if len(s.List()) == 0 {
		t.Error("expected events after concurrent recording")
	}
}
