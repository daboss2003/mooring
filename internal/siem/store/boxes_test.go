package store

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

func boxes(t *testing.T, s *Store) string {
	t.Helper()
	b, err := s.Boxes()
	if err != nil {
		t.Fatal(err)
	}
	return strings.Join(b, " ")
}

// Boxes lists every box name the store wrote segments under, so the archive can prune objects
// stored under a previous host name. The list survives pruning and restarts.
func TestBoxes(t *testing.T) {
	c := newClock(h10)
	dir := storeDir(t)
	s := openStore(t, dir, c, nil)
	if got := boxes(t, s); got != "box1" {
		t.Fatalf("fresh store: %q", got)
	}
	mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, 1))
	c.add(time.Hour)
	if err := s.SealDue(); err != nil {
		t.Fatal(err)
	}
	segs, _ := s.Unarchived()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// The host was renamed.
	c.add(time.Hour)
	s2 := openStore(t, dir, c, func(o *Options) { o.Box = "box2" })
	if got := boxes(t, s2); got != "box1 box2" {
		t.Fatalf("after a rename: %q", got)
	}
	// Removing every segment of a box keeps the box.
	c.add(60 * 24 * time.Hour)
	mustAppend(t, s2, mkev(c, "auth.login", siem.LvlInfo, 2))
	if err := s2.Prune(); err != nil {
		t.Fatal(err)
	}
	if segByName(s2, segs[0].Name) != nil {
		t.Fatal("old segment not pruned")
	}
	if got := boxes(t, s2); got != "box1 box2" {
		t.Fatalf("after pruning box1's segments: %q", got)
	}
	if err := s2.Close(); err != nil {
		t.Fatal(err)
	}
	// A segment file of another box, older than both, is recovered and listed first.
	other := filepath.Join(dir, "segments", "2026112308-old-host-1.ndjson.gz")
	if err := os.WriteFile(other, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	s3 := openStore(t, dir, c, func(o *Options) { o.Box = "box2" })
	if got := boxes(t, s3); got != "old-host box1 box2" {
		t.Fatalf("after recovering another box's file: %q", got)
	}
	// A name in the table that isn't a safe file name is never returned.
	if _, err := s3.db.Exec(`INSERT INTO boxes(name, first_seen) VALUES ('../etc', 0), ('', 0)`); err != nil {
		t.Fatal(err)
	}
	if got := boxes(t, s3); got != "old-host box1 box2" {
		t.Fatalf("unsafe names listed: %q", got)
	}
	if err := s3.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s3.Boxes(); err == nil {
		t.Error("Boxes after Close succeeded")
	}
	// Renamed back: box1 keeps the time it was first seen.
	c.add(time.Hour)
	s4 := openStore(t, dir, c, nil)
	if got := boxes(t, s4); got != "old-host box1 box2" {
		t.Fatalf("after renaming back to box1: %q", got)
	}
}

// The first Open after migration 0003 fills the table from the segments and seqs a version-2
// database already holds.
func TestBoxesBackfilledByMigration(t *testing.T) {
	c := newClock(h10)
	dir := storeDir(t)
	s := openStore(t, dir, c, nil)
	mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, 1))
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// Back to version 2: no boxes table; a box known only from seqs, one only from a segment row.
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "security.db"))
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`DROP TABLE boxes`,
		`DROP TABLE row_gc`,
		`DROP TABLE clock`,
		`DELETE FROM schema_version WHERE version >= 3`,
		`INSERT INTO seqs(hour, box, seq) VALUES (1795413600, 'seq-only', 3)`,
		`INSERT INTO segments(name, hour, seq, box, path, state) VALUES ('2026112308-row-only-1.ndjson.gz', 1795420800, 1, 'row-only', 'x', 'sealed')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	_ = db.Close()
	s2 := openStore(t, dir, c, func(o *Options) { o.Box = "new-name" })
	got := boxes(t, s2)
	for _, want := range []string{"seq-only", "row-only", "box1", "new-name"} {
		if !strings.Contains(" "+got+" ", " "+want+" ") {
			t.Errorf("Boxes = %q, missing %s", got, want)
		}
	}
	if !strings.HasPrefix(got, "seq-only row-only") || !strings.HasSuffix(got, "new-name") {
		t.Errorf("Boxes = %q, want oldest first", got)
	}
}
