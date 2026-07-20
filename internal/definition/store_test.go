package definition

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/daboss2003/mooring/internal/store"
)

func testStore(t *testing.T) (*Store, *store.DB) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return NewStore(db, []byte("0123456789abcdef0123456789abcdef")), db
}

func TestStoreRoundTripAndCurrent(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	d := base()
	if got, err := s.Current("shop"); err != nil || got != nil {
		t.Fatalf("no version yet should be (nil,nil), got %v %v", got, err)
	}
	id1, err := s.SaveCanonical(ctx, d, "first", "")
	if err != nil {
		t.Fatal(err)
	}
	// A second version becomes the live canonical.
	d2 := base()
	d2.Spec.Scaling = []Scaling{{Service: "web", Max: 4}}
	if _, err := s.SaveCanonical(ctx, d2, "second", ""); err != nil {
		t.Fatal(err)
	}
	cur, err := s.Current("shop")
	if err != nil || len(cur.Spec.Scaling) == 0 || cur.Spec.Scaling[0].Max != 4 {
		t.Fatalf("Current must return the latest version, got %+v err=%v", cur, err)
	}
	// Rollback re-derives an earlier version (re-parsed + re-validated).
	v1, err := s.Version("shop", id1)
	if err != nil || len(v1.Spec.Scaling) != 0 {
		t.Fatalf("Version(id1) should re-derive the first def, got %+v err=%v", v1, err)
	}
	if vs, _ := s.List("shop"); len(vs) != 2 {
		t.Errorf("expected 2 versions, got %d", len(vs))
	}
}

// A git-deploy version records the commit it shipped (a rollback target); a dashboard edit
// records none. CommitForVersion is slug-scoped so a cross-app id never resolves.
func TestStoreCommitProvenance(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	sha := "0123456789abcdef0123456789abcdef01234567"
	gitID, err := s.SaveCanonical(ctx, base(), "git deploy: 012345678901", sha)
	if err != nil {
		t.Fatal(err)
	}
	dashID, err := s.SaveCanonical(ctx, base(), "dashboard: scaling web", "")
	if err != nil {
		t.Fatal(err)
	}
	if c, err := s.CommitForVersion("shop", gitID); err != nil || c != sha {
		t.Fatalf("CommitForVersion(git) = %q,%v; want %q", c, err, sha)
	}
	if c, err := s.CommitForVersion("shop", dashID); err != nil || c != "" {
		t.Fatalf("CommitForVersion(dashboard) = %q,%v; want empty (not a rollback target)", c, err)
	}
	// Slug-scoped: the git version's id must not resolve under a different slug.
	if c, _ := s.CommitForVersion("other", gitID); c != "" {
		t.Fatalf("cross-slug CommitForVersion must not resolve, got %q", c)
	}
	// List surfaces the commit on the history row.
	vs, err := s.List("shop")
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, v := range vs {
		if v.ID == gitID {
			found = true
			if v.Commit != sha {
				t.Errorf("List row commit = %q; want %q", v.Commit, sha)
			}
		}
	}
	if !found {
		t.Error("git-deploy version missing from List")
	}
}

// The rollback sha is bound into the row MAC: tampering commit_sha alone (a DB-write attacker
// repointing a version to an unreviewed commit) must be caught fail-closed, since the rollback
// path skips the git-ref staged cross-check.
func TestStoreCommitTamperRejected(t *testing.T) {
	s, db := testStore(t)
	ctx := context.Background()
	sha := "0123456789abcdef0123456789abcdef01234567"
	id, err := s.SaveCanonical(ctx, base(), "git deploy", sha)
	if err != nil {
		t.Fatal(err)
	}
	evil := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee0"
	if _, err := db.Exec(`UPDATE definition_versions SET commit_sha=? WHERE id=?`, evil, id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CommitForVersion("shop", id); err != ErrTampered {
		t.Fatalf("tampered commit_sha must surface ErrTampered, got %v", err)
	}
	// Current/Version over the same tampered row must also fail closed.
	if _, err := s.Version("shop", id); err != ErrTampered {
		t.Fatalf("Version over a commit-tampered row must be ErrTampered, got %v", err)
	}
}

func TestStoreHMACTamperRejected(t *testing.T) {
	s, db := testStore(t)
	ctx := context.Background()
	if _, err := s.SaveCanonical(ctx, base(), "", ""); err != nil {
		t.Fatal(err)
	}
	// Tamper the stored YAML — the HMAC must catch it (a DB tamper can't be loaded).
	if _, err := db.Exec(`UPDATE definition_versions SET yaml=replace(yaml,'shop','evil')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Current("shop"); err != ErrTampered {
		t.Errorf("a tampered definition must surface ErrTampered, got %v", err)
	}
}
