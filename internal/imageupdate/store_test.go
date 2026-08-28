package imageupdate

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/daboss2003/mooring/internal/store"
)

func testDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestStoreSaveListGetDelete(t *testing.T) {
	st := NewStore(testDB(t))
	ctx := context.Background()

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(st.Save(ctx, Row{Project: "shop", Service: "db", ImageRef: "postgres:16", DeployedDigest: "sha256:a", LatestDigest: "sha256:b", UpdateAvailable: true, CheckedAt: 100}))
	must(st.Save(ctx, Row{Project: "shop", Service: "cache", ImageRef: "redis:7", DeployedDigest: "sha256:c", LatestDigest: "sha256:c", UpdateAvailable: false, CheckedAt: 100}))
	must(st.Save(ctx, Row{Project: "blog", Service: "db", ImageRef: "mysql:8", CheckedAt: 100}))

	// List: updates-available first, then app/service alphabetical.
	list, err := st.List(ctx)
	must(err)
	if len(list) != 3 {
		t.Fatalf("want 3 rows, got %d", len(list))
	}
	if !list[0].UpdateAvailable || list[0].Project != "shop" || list[0].Service != "db" {
		t.Errorf("update-available row must sort first, got %+v", list[0])
	}

	// Upsert overwrites in place (no duplicate key).
	must(st.Save(ctx, Row{Project: "shop", Service: "db", ImageRef: "postgres:16", DeployedDigest: "sha256:b", LatestDigest: "sha256:b", UpdateAvailable: false, CheckedAt: 200}))
	got, ok, err := st.Get(ctx, "shop", "db")
	must(err)
	if !ok || got.UpdateAvailable || got.CheckedAt != 200 {
		t.Errorf("upsert should clear update + bump checked_at, got %+v", got)
	}
	if list, _ := st.List(ctx); len(list) != 3 {
		t.Errorf("upsert must not add a row, got %d", len(list))
	}

	// Delete scopes to the app.
	must(st.Delete(ctx, "shop"))
	list, err = st.List(ctx)
	must(err)
	if len(list) != 1 || list[0].Project != "blog" {
		t.Errorf("delete should leave only blog, got %+v", list)
	}
}

func TestStorePruneExcept(t *testing.T) {
	st := NewStore(testDB(t))
	ctx := context.Background()
	_ = st.Save(ctx, Row{Project: "shop", Service: "db", CheckedAt: 1})
	_ = st.Save(ctx, Row{Project: "shop", Service: "gone", CheckedAt: 1})
	_ = st.Save(ctx, Row{Project: "blog", Service: "db", CheckedAt: 1})

	// Keep only shop/db — shop/gone and blog/db must be pruned.
	if err := st.PruneExcept(ctx, map[string]map[string]bool{"shop": {"db": true}}); err != nil {
		t.Fatal(err)
	}
	list, _ := st.List(ctx)
	if len(list) != 1 || list[0].Project != "shop" || list[0].Service != "db" {
		t.Fatalf("prune should leave only shop/db, got %+v", list)
	}
}
