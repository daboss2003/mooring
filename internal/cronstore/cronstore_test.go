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

func TestHistoryLifecycle(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()

	// Start a run → it appears as running (in-flight) and in history unfinished.
	id, err := s.StartRun(ctx, "shop", "cleanup", "worker", 1000)
	if err != nil || id == 0 {
		t.Fatalf("StartRun: id=%d err=%v", id, err)
	}
	run, _ := s.Running(ctx)
	if len(run) != 1 || run[0].ID != id || run[0].Finished || run[0].Slug != "shop" || run[0].Service != "worker" {
		t.Fatalf("Running should list the in-flight run, got %+v", run)
	}

	// Finish it → no longer running; history shows the outcome + duration.
	if err := s.FinishRun(ctx, id, 1090, false, 2, "boom: permission denied", "line1\nboom: permission denied"); err != nil {
		t.Fatal(err)
	}
	if run, _ := s.Running(ctx); len(run) != 0 {
		t.Errorf("finished run must not be Running, got %+v", run)
	}
	hist, more, err := s.History(ctx, "shop", 20, 0)
	if err != nil || len(hist) != 1 || more {
		t.Fatalf("History: len=%d more=%v err=%v", len(hist), more, err)
	}
	if h := hist[0]; !h.Finished || h.OK || h.ExitCode != 2 || h.Detail == "" || h.FinishedAt != 1090 {
		t.Errorf("finished history row wrong: %+v", h)
	}
	// History omits the (large) log; GetRun includes it.
	if hist[0].Log != "" {
		t.Error("History listing must not fetch the log column")
	}
	full, ok, _ := s.GetRun(ctx, id)
	if !ok || full.Log == "" || full.ExitCode != 2 {
		t.Errorf("GetRun must return the run with its log, got ok=%v %+v", ok, full)
	}

	// Cross-app history (slug "") includes it; a different app's history does not.
	if all, _, _ := s.History(ctx, "", 20, 0); len(all) != 1 {
		t.Errorf("all-apps history should include the run, got %d", len(all))
	}
	if other, _, _ := s.History(ctx, "blog", 20, 0); len(other) != 0 {
		t.Errorf("another app's history should be empty, got %d", len(other))
	}

	// Prune deletes finished runs older than the cutoff; a running one is never pruned.
	rid, _ := s.StartRun(ctx, "shop", "live", "worker", 2000)
	if err := s.PruneHistory(ctx, 1500); err != nil { // cutoff after the finished run's start (1000)
		t.Fatal(err)
	}
	if _, ok, _ := s.GetRun(ctx, id); ok {
		t.Error("the old finished run should have been pruned")
	}
	if _, ok, _ := s.GetRun(ctx, rid); !ok {
		t.Error("a still-running row must never be pruned")
	}

	// Boot reconcile marks the leftover running row as finished+interrupted.
	if err := s.ReconcileRunningOnBoot(ctx, 2100); err != nil {
		t.Fatal(err)
	}
	if r, _ := s.Running(ctx); len(r) != 0 {
		t.Errorf("ReconcileRunningOnBoot must clear in-flight rows, got %+v", r)
	}
	if got, _, _ := s.GetRun(ctx, rid); !got.Finished || got.OK {
		t.Errorf("interrupted run must be finished+failed, got %+v", got)
	}
}
