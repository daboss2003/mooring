package web

import (
	"os"
	"path/filepath"
	"testing"
)

// removeDeletedTrackedFiles must propagate git deletions into a reused run dir WITHOUT
// touching anything that isn't a git-tracked regular file — the data-safety invariant
// that makes the clean-extract safe on a data-bearing run dir.
func TestRemoveDeletedTrackedFiles(t *testing.T) {
	rd := t.TempDir()
	mk := func(rel string, dir bool) {
		p := filepath.Join(rd, filepath.FromSlash(rel))
		if dir {
			if err := os.MkdirAll(p, 0o755); err != nil {
				t.Fatal(err)
			}
			return
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// On-disk run dir: source files, a bind-mounted DATA dir + file, and Mooring-owned state.
	mk("src/keep.ts", false)
	mk("src/gone.ts", false)            // deleted in the new commit
	mk("pkg/removed.js", false)         // deleted in the new commit
	mk("pgdata/db.sqlite", false)       // bind-mount DATA — never git-tracked
	mk(".mooring/state/digests", false) // Mooring-owned — never git-tracked
	mk("emptydir", true)                // a directory that (hypothetically) appears in a stale list

	old := []string{"src/keep.ts", "src/gone.ts", "pkg/removed.js", "emptydir"}
	neu := []string{"src/keep.ts"} // gone.ts + removed.js deleted; keep.ts stays

	n := removeDeletedTrackedFiles(old, neu, rd)
	if n != 2 {
		t.Fatalf("removed %d, want 2 (src/gone.ts + pkg/removed.js)", n)
	}

	gone := func(rel string) bool {
		_, err := os.Lstat(filepath.Join(rd, filepath.FromSlash(rel)))
		return os.IsNotExist(err)
	}
	// Deleted git files are gone.
	for _, rel := range []string{"src/gone.ts", "pkg/removed.js"} {
		if !gone(rel) {
			t.Errorf("%s should have been removed", rel)
		}
	}
	// Everything else survives: kept source, bind DATA, Mooring state, and the directory.
	for _, rel := range []string{"src/keep.ts", "pgdata/db.sqlite", ".mooring/state/digests", "emptydir"} {
		if gone(rel) {
			t.Errorf("%s must NOT have been removed (data-safety)", rel)
		}
	}
}

// A path that escapes the run dir (defensive; git never produces one) is never deleted.
func TestRemoveDeletedTrackedFilesConfinement(t *testing.T) {
	parent := t.TempDir()
	rd := filepath.Join(parent, "run")
	if err := os.MkdirAll(rd, 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(parent, "secret.txt")
	if err := os.WriteFile(outside, []byte("keep me"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A malicious/old file list containing a traversal path must not delete outside rd.
	n := removeDeletedTrackedFiles([]string{"../secret.txt"}, nil, rd)
	if n != 0 {
		t.Fatalf("removed %d, want 0 (traversal must be refused)", n)
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("file outside the run dir was touched: %v", err)
	}
}
