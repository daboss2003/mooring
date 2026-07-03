package imagescan

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/store"
)

type fakeScanner struct {
	img map[string]Report
	fs  map[string]Report
}

func (f *fakeScanner) ScanImage(_ context.Context, ref string) (Report, error) {
	return f.img[ref], nil
}
func (f *fakeScanner) ScanFS(_ context.Context, dir, label string) (Report, error) {
	return f.fs[dir], nil
}

type fakeSink struct{ sent []alert.Outbox }

func (f *fakeSink) EnqueueInfra(_ context.Context, o alert.Outbox) error {
	f.sent = append(f.sent, o)
	return nil
}

func testDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestRunnerAggregatesStoresAndPages(t *testing.T) {
	sc := &fakeScanner{
		img: map[string]Report{"emqx/emqx:5.8.3": {Target: "emqx", High: 1}},
		fs:  map[string]Report{"/run/app": {Target: "credlock deps", Critical: 2, High: 3}},
	}
	st := NewStore(testDB(t))
	sink := &fakeSink{}
	targets := func(context.Context) []Target {
		return []Target{
			{Project: "credlock", Kind: KindImage, Ref: "emqx/emqx:5.8.3", Label: "emqx"},
			{Project: "credlock", Kind: KindFS, Ref: "/run/app", Label: "credlock deps"},
		}
	}
	r := NewRunner(sc, st, sink, targets, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.ScanAll(context.Background())

	got, ok, err := st.Get(context.Background(), "credlock")
	if err != nil || !ok {
		t.Fatalf("get: %v ok=%v", err, ok)
	}
	if got.Critical != 2 || got.High != 4 || len(got.Reports) != 2 {
		t.Errorf("aggregate wrong: %+v", got)
	}
	// Critical present → a CRITICAL page, deduped by signature.
	if len(sink.sent) != 1 || sink.sent[0].Level != alert.LevelCritical {
		t.Fatalf("expected one critical page: %+v", sink.sent)
	}
	// Re-scan with the SAME result must not re-page.
	r.ScanAll(context.Background())
	if len(sink.sent) != 1 {
		t.Errorf("re-paged a steady state: %d", len(sink.sent))
	}
}

func TestRunnerCleanAppNoPage(t *testing.T) {
	sc := &fakeScanner{img: map[string]Report{"nginx:1": {Target: "nginx"}}}
	st := NewStore(testDB(t))
	sink := &fakeSink{}
	targets := func(context.Context) []Target {
		return []Target{{Project: "blog", Kind: KindImage, Ref: "nginx:1", Label: "nginx"}}
	}
	NewRunner(sc, st, sink, targets, 0, slog.New(slog.NewTextHandler(io.Discard, nil))).ScanAll(context.Background())
	if len(sink.sent) != 0 {
		t.Error("a clean app must not page")
	}
	if got, _, _ := st.Get(context.Background(), "blog"); got.Actionable() {
		t.Error("clean app not actionable")
	}
}
