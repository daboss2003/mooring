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

// ListPage returns one page of history (newest first), reports hasMore accurately, and never
// bleeds one slug's rows into another's page.
func TestStoreListPage(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	const total = 25
	for i := 0; i < total; i++ {
		if _, err := s.SaveCanonical(ctx, base(), "v", ""); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}

	// Page 1 of 20: full page + an older page exists.
	p1, more1, err := s.ListPage("shop", 20, 0)
	if err != nil || len(p1) != 20 || !more1 {
		t.Fatalf("page1: len=%d more=%v err=%v, want 20 rows + hasMore", len(p1), more1, err)
	}
	// Newest first, and the id sequence descends across the page.
	if p1[0].ID <= p1[19].ID {
		t.Errorf("page must be newest-first: first id %d should exceed last id %d", p1[0].ID, p1[19].ID)
	}

	// Page 2: the remaining 5, no further page.
	p2, more2, err := s.ListPage("shop", 20, 20)
	if err != nil || len(p2) != 5 || more2 {
		t.Fatalf("page2: len=%d more=%v err=%v, want 5 rows + no more", len(p2), more2, err)
	}
	// Page 2 continues strictly below page 1 (no overlap, no gap).
	if p2[0].ID != p1[19].ID-1 {
		t.Errorf("page2 first id %d should be one below page1 last id %d", p2[0].ID, p1[19].ID)
	}

	// A slug with no history yields an empty page, not an error.
	if rows, more, err := s.ListPage("ghost", 20, 0); err != nil || len(rows) != 0 || more {
		t.Errorf("empty slug: len=%d more=%v err=%v, want 0/false/nil", len(rows), more, err)
	}

	// Defensive: non-positive limit falls back to a default page size (no unbounded query).
	if rows, _, err := s.ListPage("shop", 0, 0); err != nil || len(rows) != 20 {
		t.Errorf("limit<=0 should default to 20, got len=%d err=%v", len(rows), err)
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

// DeleteVersion trims a past version from history but REFUSES the latest (the live canonical).
func TestStoreDeleteVersion(t *testing.T) {
	s, _ := testStore(t)
	ctx := context.Background()
	id1, err := s.SaveCanonical(ctx, base(), "first", "")
	if err != nil {
		t.Fatal(err)
	}
	id2, err := s.SaveCanonical(ctx, base(), "second", "")
	if err != nil {
		t.Fatal(err)
	}
	// The latest (id2) is the live canonical and must not be deletable.
	if err := s.DeleteVersion(ctx, "shop", id2); err == nil {
		t.Fatal("deleting the latest/live version must be refused")
	}
	// An older version is deletable.
	if err := s.DeleteVersion(ctx, "shop", id1); err != nil {
		t.Fatalf("deleting an older version should succeed, got %v", err)
	}
	if vs, _ := s.List("shop"); len(vs) != 1 || vs[0].ID != id2 {
		t.Fatalf("after delete, only the live version should remain, got %+v", vs)
	}
	// Deleting an unknown id is an error (idempotent-safe: no rows changed).
	if err := s.DeleteVersion(ctx, "shop", 99999); err == nil {
		t.Error("deleting an unknown version should error")
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
