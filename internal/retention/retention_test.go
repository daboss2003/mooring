package retention

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/store"
)

func newDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func insertEvent(t *testing.T, db *store.DB, ts int64, action, level string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO events(ts, actor, ip, action, target, outcome, level, detail) VALUES(?, 'op', '', ?, 't', 'ok', ?, 'd')`,
		ts, action, level); err != nil {
		t.Fatal(err)
	}
}

func countEvents(t *testing.T, db *store.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func defaultCfg() Config {
	return Config{Interval: time.Hour, EventsMaxAge: 365 * 24 * time.Hour, EventsMaxRows: 1_000_000, ArchiveMaxBytes: 64 << 20}
}

// Old INFO rows are pruned; recent rows are kept.
func TestAgePruneKeepsRecentDropsOld(t *testing.T) {
	db := newDB(t)
	now := time.Now()
	old := now.Add(-400 * 24 * time.Hour).Unix()
	recent := now.Add(-1 * time.Hour).Unix()
	insertEvent(t, db, old, "old1", "info")
	insertEvent(t, db, old, "old2", "info")
	insertEvent(t, db, recent, "recent", "info")

	r := New(db, quietLog(), t.TempDir(), defaultCfg())
	n, err := r.Pass(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("pruned %d, want 2", n)
	}
	if got := countEvents(t, db); got != 1 {
		t.Errorf("remaining %d, want 1 (the recent row)", got)
	}
}

// A security row that ages out is ARCHIVED to NDJSON before being deleted.
func TestSecurityRowArchivedBeforeDelete(t *testing.T) {
	db := newDB(t)
	dir := t.TempDir()
	old := time.Now().Add(-400 * 24 * time.Hour).Unix()
	insertEvent(t, db, old, "old-info", "info")
	insertEvent(t, db, old, "intrusion", "security")

	r := New(db, quietLog(), dir, defaultCfg())
	if _, err := r.Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := countEvents(t, db); got != 0 {
		t.Errorf("remaining %d, want 0", got)
	}
	// The security row must be in the archive; the info row must NOT be.
	f, err := os.Open(filepath.Join(dir, "events-archive.ndjson"))
	if err != nil {
		t.Fatalf("archive missing: %v", err)
	}
	defer f.Close()
	var archived []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var e eventRow
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("bad archive line: %v", err)
		}
		archived = append(archived, e.Action+"/"+e.Level)
	}
	if len(archived) != 1 || archived[0] != "intrusion/security" {
		t.Errorf("archive = %v, want [intrusion/security]", archived)
	}
}

// The archived row keeps the request's User-Agent (events.user_agent, migration 0039).
func TestSecurityRowArchiveKeepsUserAgent(t *testing.T) {
	db := newDB(t)
	dir := t.TempDir()
	old := time.Now().Add(-400 * 24 * time.Hour).Unix()
	if _, err := db.Exec(`INSERT INTO events(ts, actor, ip, action, target, outcome, level, detail, user_agent)
		VALUES(?, 'op', '203.0.113.7', 'login', '', 'deny', 'security', 'invalid password', 'curl/8.5.0')`, old); err != nil {
		t.Fatal(err)
	}
	if _, err := New(db, quietLog(), dir, defaultCfg()).Pass(context.Background()); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "events-archive.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	var e eventRow
	if err := json.Unmarshal(bytes.TrimSpace(b), &e); err != nil {
		t.Fatalf("archive line %q: %v", b, err)
	}
	if e.UA != "curl/8.5.0" {
		t.Errorf("archived UA = %q, want curl/8.5.0", e.UA)
	}
}

// FAIL-CLOSED: if the security row cannot be archived, NOTHING is deleted — the
// audit evidence is preserved in the DB.
func TestArchiveFailureAbortsWithoutDeleting(t *testing.T) {
	db := newDB(t)
	dir := t.TempDir()
	// Make the archive path un-openable by planting a directory where the file
	// would go, so OpenFile(O_WRONLY) fails.
	if err := os.Mkdir(filepath.Join(dir, "events-archive.ndjson"), 0o700); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-400 * 24 * time.Hour).Unix()
	insertEvent(t, db, old, "old-info", "info")
	insertEvent(t, db, old, "intrusion", "security")

	r := New(db, quietLog(), dir, defaultCfg())
	if _, err := r.Pass(context.Background()); err == nil {
		t.Fatal("expected the pass to fail closed when the archive cannot be written")
	}
	// Both rows must remain — the security row was never dropped.
	if got := countEvents(t, db); got != 2 {
		t.Errorf("remaining %d, want 2 (fail-closed: nothing deleted)", got)
	}
}

// SetConfig is reloaded (SIGHUP) concurrently with config()/Pass; run under
// -race this proves the atomic.Pointer[Config] reload is data-race-free and that
// storing &cfg (a parameter) is safe in Go (escape analysis heap-promotes it —
// there is no use-after-free). Belt-and-suspenders against a mistaken review.
func TestConfigReloadConcurrentRaceFree(t *testing.T) {
	db := newDB(t)
	r := New(db, quietLog(), t.TempDir(), defaultCfg())
	done := make(chan struct{})
	go func() {
		for i := 0; i < 2000; i++ {
			r.SetConfig(Config{
				Interval: time.Duration(i+1) * time.Second, EventsMaxAge: 24 * time.Hour,
				EventsMaxRows: 1000 + i, ArchiveMaxBytes: 1 << 20,
			})
		}
		close(done)
	}()
	for i := 0; i < 2000; i++ {
		c := r.config()
		if c.EventsMaxRows < 1000 { // dereferenced value is always a valid, sane Config
			t.Fatalf("config() returned a corrupt value: %+v", c)
		}
	}
	<-done
}

// The hard row cap trims the oldest rows (security ones archived first).
func TestMaxRowsCapTrimsOldest(t *testing.T) {
	db := newDB(t)
	dir := t.TempDir()
	base := time.Now().Add(-2 * time.Hour).Unix()
	for i := 0; i < 10; i++ {
		lvl := "info"
		if i == 0 {
			lvl = "security" // the oldest row is a security row
		}
		insertEvent(t, db, base+int64(i), "e", lvl)
	}
	cfg := defaultCfg()
	cfg.EventsMaxRows = 4 // keep only the 4 newest
	r := New(db, quietLog(), dir, cfg)
	n, err := r.Pass(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 6 {
		t.Errorf("pruned %d, want 6", n)
	}
	if got := countEvents(t, db); got != 4 {
		t.Errorf("remaining %d, want 4", got)
	}
	// The oldest (security) row must have been archived before its deletion.
	b, err := os.ReadFile(filepath.Join(dir, "events-archive.ndjson"))
	if err != nil || len(b) == 0 {
		t.Errorf("expected the oldest security row archived: %v", err)
	}
}
