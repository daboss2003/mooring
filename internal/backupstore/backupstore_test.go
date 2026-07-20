package backupstore

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/backup"
	"github.com/daboss2003/mooring/internal/store"
)

func newStore(t *testing.T) (*Store, *store.DB, []byte) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	return New(db, filepath.Join(t.TempDir(), "backups"), key), db, key
}

func TestCreateListDeleteRoundTrip(t *testing.T) {
	s, db, key := newStore(t)
	ctx := context.Background()
	// Put a recognizable row in the DB so we can confirm the snapshot captured it.
	if _, err := db.Exec(`CREATE TABLE marker(v TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO marker(v) VALUES('hello-backup')`); err != nil {
		t.Fatal(err)
	}

	rec, err := s.Create(ctx, time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if rec.SizeBytes == 0 || rec.SHA256 == "" {
		t.Errorf("record missing size/sha: %+v", rec)
	}
	// The archive exists; the transient plaintext snapshot does not.
	if _, err := os.Stat(s.FilePath(rec)); err != nil {
		t.Errorf("archive missing: %v", err)
	}
	if matches, _ := filepath.Glob(filepath.Join(filepath.Dir(s.FilePath(rec)), ".*snapshot")); len(matches) != 0 {
		t.Errorf("plaintext snapshot left behind: %v", matches)
	}

	// The encrypted archive is owner-only.
	fi, err := os.Stat(s.FilePath(rec))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("archive perms = %o, want 0600", fi.Mode().Perm())
	}

	// It's listed.
	list, err := s.List(ctx)
	if err != nil || len(list) != 1 || list[0].ID != rec.ID {
		t.Fatalf("list: %v %+v", err, list)
	}

	// It decrypts back to a valid SQLite DB containing our marker row.
	enc, err := os.ReadFile(s.FilePath(rec))
	if err != nil {
		t.Fatal(err)
	}
	var dec bytes.Buffer
	if err := backup.Decrypt(&dec, bytes.NewReader(enc), key); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	restored := filepath.Join(t.TempDir(), "restored.db")
	if err := os.WriteFile(restored, dec.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	rdb, err := store.Open(restored)
	if err != nil {
		t.Fatalf("restored db won't open: %v", err)
	}
	defer rdb.Close()
	var got string
	if err := rdb.QueryRow(`SELECT v FROM marker`).Scan(&got); err != nil || got != "hello-backup" {
		t.Errorf("restored snapshot missing data: got %q err %v", got, err)
	}

	// Delete removes both the row and the file.
	if err := s.Delete(ctx, rec.ID); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.List(ctx); len(list) != 0 {
		t.Error("backup still listed after delete")
	}
	if _, err := os.Stat(s.FilePath(rec)); !os.IsNotExist(err) {
		t.Error("archive file still present after delete")
	}
}

func TestWrongKeyFailsToDecrypt(t *testing.T) {
	s, _, _ := newStore(t)
	rec, err := s.Create(context.Background(), time.Unix(1_700_000_000, 0))
	if err != nil {
		t.Fatal(err)
	}
	enc, _ := os.ReadFile(s.FilePath(rec))
	wrong := make([]byte, 32) // all zeros, != the store key
	if err := backup.Decrypt(&bytes.Buffer{}, bytes.NewReader(enc), wrong); err == nil {
		t.Error("a backup must not decrypt under the wrong key")
	}
}

func TestUnavailableWithoutKey(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := New(db, t.TempDir(), []byte("short"))
	if s.Available() {
		t.Error("a non-32-byte key must make the store unavailable")
	}
	if _, err := s.Create(context.Background(), time.Now()); err == nil {
		t.Error("create must fail without a valid key")
	}
}

// Deleting a volume snapshot keeps backup_inventory truthful: it repoints to the newest
// surviving snapshot, and drops the row entirely when none remain (else the prune denylist
// could treat a volume with no backups as safe to delete → data loss).
func TestDeleteKeepsInventoryTruthful(t *testing.T) {
	s, _, _ := newStore(t)
	ctx := context.Background()
	mk := func(t *testing.T, at int64) string {
		id, err := s.NewID()
		if err != nil {
			t.Fatal(err)
		}
		rec := Record{ID: id, CreatedAt: at, SizeBytes: 1, File: id + ".mbk", SHA256: "x", Kind: "volume", Project: "shop", Target: "shop_data", Location: "local"}
		if err := s.Catalog(ctx, rec); err != nil {
			t.Fatal(err)
		}
		return id
	}
	older := mk(t, 100)
	newer := mk(t, 200)
	// Inventory tracks the newest.
	if v, _ := s.BackedUpVolumes(ctx); !v["shop_data"] {
		t.Fatal("volume should be inventoried")
	}
	// Delete the newest → inventory must repoint to the older (still backed up).
	if err := s.Delete(ctx, newer); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.BackedUpVolumes(ctx); !v["shop_data"] {
		t.Fatal("after deleting newest, the older snapshot still backs up the volume")
	}
	// Delete the last one → inventory row must be gone (no snapshot backs the volume).
	if err := s.Delete(ctx, older); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.BackedUpVolumes(ctx); v["shop_data"] {
		t.Fatal("with no snapshots left, the volume must NOT be reported as backed up")
	}
}
