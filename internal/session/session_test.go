package session

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/store"
)

func openDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "sess.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestCreateLoadDelete(t *testing.T) {
	ctx := context.Background()
	m := New(openDB(t), 30*time.Minute, 12*time.Hour)
	raw, err := m.Create(ctx, "operator", "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	sess, err := m.Load(ctx, raw)
	if err != nil || sess.Username != "operator" {
		t.Fatalf("load failed: %v / %+v", err, sess)
	}
	if err := m.Delete(ctx, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Load(ctx, raw); !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete, load = %v, want ErrNotFound", err)
	}
}

func TestIdleTimeout(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	m := New(db, 1*time.Second, 12*time.Hour)
	raw, _ := m.Create(ctx, "operator", "127.0.0.1", "test")
	// Force last_seen far into the past.
	_, _ = db.Exec(`UPDATE sessions SET last_seen_at = ?`, time.Now().Add(-time.Hour).Unix())
	if _, err := m.Load(ctx, raw); !errors.Is(err, ErrNotFound) {
		t.Errorf("idled-out session loaded: %v", err)
	}
}

// Peek is a read-only liveness check: it returns a live session WITHOUT advancing
// last_seen (so an unfocused tab polling it can't keep itself alive), but enforces the
// same idle/absolute expiry as Load.
func TestPeek(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	m := New(db, 30*time.Minute, 12*time.Hour)
	raw, _ := m.Create(ctx, "operator", "127.0.0.1", "test")

	// A still-valid but known last_seen: Peek must NOT advance it.
	old := time.Now().Add(-5 * time.Minute).Unix()
	_, _ = db.Exec(`UPDATE sessions SET last_seen_at = ?`, old)
	if _, err := m.Peek(ctx, raw); err != nil {
		t.Fatalf("Peek of a live session: %v", err)
	}
	var after int64
	_ = db.QueryRow(`SELECT last_seen_at FROM sessions`).Scan(&after)
	if after != old {
		t.Errorf("Peek advanced last_seen %d -> %d (must be read-only)", old, after)
	}
	// Contrast: Load DOES advance it.
	if _, err := m.Load(ctx, raw); err != nil {
		t.Fatal(err)
	}
	_ = db.QueryRow(`SELECT last_seen_at FROM sessions`).Scan(&after)
	if after == old {
		t.Error("Load should have advanced last_seen")
	}

	// Peek still enforces idle expiry (forced far past the idle window -> gone).
	_, _ = db.Exec(`UPDATE sessions SET last_seen_at = ?`, time.Now().Add(-time.Hour).Unix())
	if _, err := m.Peek(ctx, raw); !errors.Is(err, ErrNotFound) {
		t.Error("Peek must enforce idle expiry, not just read")
	}
}

// ActivePeers lists the address of every session still valid (each address once), skipping
// sessions past their idle or absolute expiry and peer values that aren't addresses.
func TestActivePeers(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	m := New(db, 30*time.Minute, 12*time.Hour)
	if got, err := m.ActivePeers(ctx); err != nil || len(got) != 0 {
		t.Fatalf("no sessions: %v, %v", got, err)
	}
	// ::ffff:203.0.113.7 is 203.0.113.7: listed once.
	for _, p := range []string{"203.0.113.7", "203.0.113.7", "::ffff:203.0.113.7", "2001:db8::1", "198.51.100.9", "198.51.100.10", "not-an-ip", "fe80::1%eth0", ""} {
		if _, err := m.Create(ctx, "operator", p, "test"); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	// 198.51.100.9 idled out, 198.51.100.10 is past its absolute expiry: neither is listed.
	if _, err := db.Exec(`UPDATE sessions SET last_seen_at = ? WHERE peer_ip = '198.51.100.9'`, now.Add(-31*time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE sessions SET absolute_exp = ? WHERE peer_ip = '198.51.100.10'`, now.Add(-time.Second).Unix()); err != nil {
		t.Fatal(err)
	}
	got, err := m.ActivePeers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var strs []string
	for _, a := range got {
		strs = append(strs, a.String())
	}
	slices.Sort(strs)
	if want := []string{"2001:db8::1", "203.0.113.7"}; !slices.Equal(strs, want) {
		t.Errorf("ActivePeers = %v, want %v", strs, want)
	}
	// A statement right after it works: the rows were closed before it returned (the DB has one
	// connection, so rows left open would block it).
	if _, err := m.ActivePeers(ctx); err != nil {
		t.Fatal(err)
	}
	tctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if _, err := m.DeleteAll(tctx); err != nil {
		t.Fatalf("a statement after ActivePeers: %v", err)
	}
}

// The high-severity fix (review #1): a backward wall-clock step plus a restart
// must NOT resurrect an already-expired session.
func TestBackwardClockCannotResurrectSession(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	realNow := time.Now()

	// Persist a clock high-water mark at "real now": the system has observed time
	// up to here, even though the wall clock is about to be stepped back.
	if _, err := db.Exec(`INSERT INTO settings(key, value) VALUES(?, ?)`,
		highWaterKey, strconv.FormatInt(realNow.Unix(), 10)); err != nil {
		t.Fatal(err)
	}
	// Insert a session that is ALREADY expired relative to the high-water mark
	// (absolute_exp one hour before realNow).
	raw := "raw-session-id-for-test"
	if _, err := db.Exec(
		`INSERT INTO sessions(id_hash, username, created_at, last_seen_at, absolute_exp, created_mono, peer_ip, user_agent)
		 VALUES(?, ?, ?, ?, ?, 0, '', '')`,
		hashID(raw), "operator",
		realNow.Add(-13*time.Hour).Unix(), realNow.Add(-13*time.Hour).Unix(), realNow.Add(-time.Hour).Unix(),
	); err != nil {
		t.Fatal(err)
	}

	// Simulate a restart AFTER a backward wall-clock step (boot wall = 13h ago).
	m := New(db, 30*time.Minute, 12*time.Hour)
	m.bootWall = realNow.Add(-13 * time.Hour)
	m.bootMono = monoNow()
	// New already seeded hw from the persisted high-water; the stepped-back
	// bootWall does not lower it.

	if _, err := m.Load(ctx, raw); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired session resurrected after backward clock step: err=%v", err)
	}
	// And GC must purge it rather than strand it.
	if err := m.GC(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&n)
	if n != 0 {
		t.Errorf("GC left %d expired session(s) after backward step", n)
	}
}
