package imageupdate

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/dockerexec"
)

// fakeExec dispatches on argv[0]: "image" = local inspect, "buildx" = registry inspect.
type fakeExec struct {
	mu       sync.Mutex
	local    map[string]string
	registry map[string]string
	regErr   map[string]error
	busy     bool
	calls    int
}

func (f *fakeExec) CaptureTry(_ context.Context, argv []string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.busy {
		return "", dockerexec.ErrBusy
	}
	if argv[0] == "image" { // image inspect <ref> --format ...
		return f.local[argv[2]], nil
	}
	ref := argv[3] // buildx imagetools inspect <ref> --format ...
	if e := f.regErr[ref]; e != nil {
		return "", e
	}
	return f.registry[ref], nil
}

type fakeSink struct {
	mu   sync.Mutex
	sent []alert.Outbox
}

func (f *fakeSink) EnqueueInfra(_ context.Context, o alert.Outbox) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, o)
	return nil
}
func (f *fakeSink) count() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.sent) }

func dig(c byte) string { return "sha256:" + strings.Repeat(string(c), 64) }

func newRunner(t *testing.T, x digestExec, sink alertSink, targets []Target) (*Runner, *Store) {
	t.Helper()
	st := NewStore(testDB(t))
	r := NewRunner(x, st, sink, func(context.Context) []Target { return targets }, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	var clk int64 = 1000
	r.now = func() int64 { return clk }
	return r, st
}

func TestCheckAllDetectsUpdateAndAlertsOnce(t *testing.T) {
	x := &fakeExec{
		local:    map[string]string{"postgres:16": "postgres@" + dig('a')},
		registry: map[string]string{"postgres:16": dig('b')}, // registry moved → update available
	}
	sink := &fakeSink{}
	r, st := newRunner(t, x, sink, []Target{{Project: "shop", Service: "db", Ref: "postgres:16"}})
	ctx := context.Background()

	r.CheckAll(ctx)
	row, ok, _ := st.Get(ctx, "shop", "db")
	if !ok || !row.UpdateAvailable || row.LatestDigest != dig('b') || row.DeployedDigest != dig('a') {
		t.Fatalf("update should be detected, got %+v", row)
	}
	if sink.count() != 1 {
		t.Fatalf("want exactly one alert, got %d", sink.count())
	}
	if sink.sent[0].Kind != "image_update_available" || sink.sent[0].DedupeKey == "" {
		t.Errorf("wrong alert shape: %+v", sink.sent[0])
	}

	// Same digest next cycle → no re-page.
	r.CheckAll(ctx)
	if sink.count() != 1 {
		t.Errorf("a steady update must not re-page, got %d", sink.count())
	}

	// Registry moves again → a NEW digest re-pages once.
	x.registry["postgres:16"] = dig('c')
	r.CheckAll(ctx)
	if sink.count() != 2 {
		t.Errorf("a new digest must re-page, got %d", sink.count())
	}
}

func TestUpToDateNoAlert(t *testing.T) {
	x := &fakeExec{
		local:    map[string]string{"redis:7": "redis@" + dig('a')},
		registry: map[string]string{"redis:7": dig('a')},
	}
	sink := &fakeSink{}
	r, st := newRunner(t, x, sink, []Target{{Project: "shop", Service: "cache", Ref: "redis:7"}})
	r.CheckAll(context.Background())
	row, _, _ := st.Get(context.Background(), "shop", "cache")
	if row.UpdateAvailable {
		t.Error("matching digests must not flag an update")
	}
	if sink.count() != 0 {
		t.Errorf("up-to-date must not alert, got %d", sink.count())
	}
}

func TestRegistryErrorStoresErrorNoAlert(t *testing.T) {
	x := &fakeExec{
		local:  map[string]string{"mysql:8": "mysql@" + dig('a')},
		regErr: map[string]error{"mysql:8": errors.New("unauthorized")},
	}
	sink := &fakeSink{}
	r, st := newRunner(t, x, sink, []Target{{Project: "blog", Service: "db", Ref: "mysql:8"}})
	r.CheckAll(context.Background())
	row, ok, _ := st.Get(context.Background(), "blog", "db")
	if !ok || row.Error == "" || row.UpdateAvailable {
		t.Errorf("a failed registry check stores an error and never flags/alerts, got %+v", row)
	}
	if sink.count() != 0 {
		t.Errorf("a failed check must not alert, got %d", sink.count())
	}
}

func TestBusyWritePlaneSkips(t *testing.T) {
	x := &fakeExec{busy: true}
	sink := &fakeSink{}
	r, st := newRunner(t, x, sink, []Target{{Project: "shop", Service: "db", Ref: "postgres:16"}})
	r.CheckAll(context.Background())
	if list, _ := st.List(context.Background()); len(list) != 0 {
		t.Errorf("a busy slot must skip (no row written), got %d rows", len(list))
	}
	if sink.count() != 0 {
		t.Errorf("busy must not alert, got %d", sink.count())
	}
}

func TestDigestPinnedSkipped(t *testing.T) {
	x := &fakeExec{}
	sink := &fakeSink{}
	pinned := "postgres@" + dig('a')
	r, st := newRunner(t, x, sink, []Target{{Project: "shop", Service: "db", Ref: pinned}})
	r.CheckAll(context.Background())
	if x.calls != 0 {
		t.Errorf("a digest-pinned ref must not be checked at all, got %d exec calls", x.calls)
	}
	if list, _ := st.List(context.Background()); len(list) != 0 {
		t.Errorf("a digest-pinned ref must not produce a row, got %d", len(list))
	}
}

// failOnceSink fails the first N enqueues, then succeeds.
type failOnceSink struct {
	fakeSink
	failsLeft int
}

func (f *failOnceSink) EnqueueInfra(ctx context.Context, o alert.Outbox) error {
	f.mu.Lock()
	if f.failsLeft > 0 {
		f.failsLeft--
		f.mu.Unlock()
		return errors.New("outbox write failed")
	}
	f.mu.Unlock()
	return f.fakeSink.EnqueueInfra(ctx, o)
}

func TestFailedEnqueueRetriesNextCycle(t *testing.T) {
	x := &fakeExec{
		local:    map[string]string{"postgres:16": "postgres@" + dig('a')},
		registry: map[string]string{"postgres:16": dig('b')},
	}
	sink := &failOnceSink{failsLeft: 1}
	r, _ := newRunner(t, x, sink, []Target{{Project: "shop", Service: "db", Ref: "postgres:16"}})
	ctx := context.Background()

	r.CheckAll(ctx) // enqueue FAILS — dedup key must NOT be recorded
	if sink.count() != 0 {
		t.Fatalf("first enqueue should have failed (0 delivered), got %d", sink.count())
	}
	r.CheckAll(ctx) // same digest, but the alert must be RETRIED (not suppressed) and now succeed
	if sink.count() != 1 {
		t.Errorf("a failed enqueue must be retried next cycle, got %d delivered", sink.count())
	}
}

// vanishingTargets returns a service on the FIRST enumeration (the check loop) but not on the SECOND
// (the prune re-enumeration) — simulating an app torn down mid-pass.
type vanishingTargets struct {
	calls int
}

func TestCheckAllPrunesAppDeletedMidPass(t *testing.T) {
	x := &fakeExec{
		local:    map[string]string{"postgres:16": "postgres@" + dig('a')},
		registry: map[string]string{"postgres:16": dig('b')},
	}
	st := NewStore(testDB(t))
	vt := &vanishingTargets{}
	targets := func(context.Context) []Target {
		vt.calls++
		if vt.calls == 1 {
			return []Target{{Project: "gone", Service: "db", Ref: "postgres:16"}}
		}
		return nil // by the prune re-enumeration the app is gone
	}
	r := NewRunner(x, st, &fakeSink{}, targets, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.CheckAll(context.Background())

	// The row inserted during the check loop must be pruned the SAME pass by the fresh re-enumeration.
	if list, _ := st.List(context.Background()); len(list) != 0 {
		t.Errorf("an app that vanished mid-pass must be pruned this pass, got %+v", list)
	}
}

func TestCheckAllPrunesVanishedServices(t *testing.T) {
	x := &fakeExec{
		local:    map[string]string{"postgres:16": "postgres@" + dig('a')},
		registry: map[string]string{"postgres:16": dig('a')},
	}
	sink := &fakeSink{}
	r, st := newRunner(t, x, sink, []Target{{Project: "shop", Service: "db", Ref: "postgres:16"}})
	// Pre-seed a stale row for a service that no longer exists in targets.
	_ = st.Save(context.Background(), Row{Project: "shop", Service: "old", ImageRef: "redis:7"})
	r.CheckAll(context.Background())
	list, _ := st.List(context.Background())
	if len(list) != 1 || list[0].Service != "db" {
		t.Errorf("vanished service must be pruned, got %+v", list)
	}
}
