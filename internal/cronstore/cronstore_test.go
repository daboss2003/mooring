package cronstore

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/daboss2003/mooring/internal/store"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return New(db)
}

func TestCronStoreRoundTrip(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	// Never-run task → zero value.
	if r, err := s.Get(ctx, "shop", "cleanup"); err != nil || r.LastRun != 0 {
		t.Fatalf("never-run should be zero, got %+v %v", r, err)
	}
	// Record a successful run.
	if err := s.Record(ctx, "shop", "cleanup", 1000, true); err != nil {
		t.Fatal(err)
	}
	r, err := s.Get(ctx, "shop", "cleanup")
	if err != nil || r.LastRun != 1000 || !r.LastOK {
		t.Fatalf("after Record ok: %+v %v", r, err)
	}
	// Upsert a later failed run.
	if err := s.Record(ctx, "shop", "cleanup", 2000, false); err != nil {
		t.Fatal(err)
	}
	r, _ = s.Get(ctx, "shop", "cleanup")
	if r.LastRun != 2000 || r.LastOK {
		t.Fatalf("upsert failed run: %+v", r)
	}
	// A different task is independent.
	if r, _ := s.Get(ctx, "shop", "other"); r.LastRun != 0 {
		t.Fatal("distinct task should be independent")
	}
	// DeleteApp clears the app's rows.
	if err := s.DeleteApp(ctx, "shop"); err != nil {
		t.Fatal(err)
	}
	if r, _ := s.Get(ctx, "shop", "cleanup"); r.LastRun != 0 {
		t.Fatal("DeleteApp should remove the row")
	}
}
