package diskgc

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type fakePruner struct{ imagePrunes, cachePrunes int }

func (f *fakePruner) PruneImagesHeld(ctx context.Context, onLine func(string)) error {
	f.imagePrunes++
	if onLine != nil {
		onLine("Total reclaimed space: 1.2GB")
	}
	return nil
}
func (f *fakePruner) PruneBuildCacheHeld(ctx context.Context, keep string, onLine func(string)) error {
	f.cachePrunes++
	return nil
}

type fakeSem struct {
	free     bool
	acquired int
}

func (s *fakeSem) TryAcquire() bool {
	if s.free {
		s.acquired++
		return true
	}
	return false
}
func (s *fakeSem) Release() {}

func sampler(used, total uint64, ok bool) Sampler {
	return func() (uint64, uint64, bool) { return used, total, ok }
}

func TestCheckPrunesAtOrAboveThreshold(t *testing.T) {
	p := &fakePruner{}
	var alerted int
	r := New(sampler(80, 100, true), p, &fakeSem{free: true}, 75, time.Hour, "5GB", true,
		func(l, ti, d string) { alerted++ }, nil)
	if !r.Check(context.Background()) {
		t.Fatal("80% ≥ 75% should prune")
	}
	if p.imagePrunes != 1 || p.cachePrunes != 1 {
		t.Errorf("expected one image + one cache prune, got %d/%d", p.imagePrunes, p.cachePrunes)
	}
	if alerted != 1 {
		t.Errorf("expected one alert, got %d", alerted)
	}
}

func TestCheckSkipsBelowThreshold(t *testing.T) {
	p := &fakePruner{}
	r := New(sampler(50, 100, true), p, &fakeSem{free: true}, 75, time.Hour, "5GB", true, nil, nil)
	if r.Check(context.Background()) {
		t.Fatal("50% < 75% must NOT prune")
	}
	if p.imagePrunes != 0 {
		t.Error("nothing should be pruned below threshold")
	}
}

func TestCheckSkipsWhenDockerBusy(t *testing.T) {
	p := &fakePruner{}
	r := New(sampler(90, 100, true), p, &fakeSem{free: false}, 75, time.Hour, "5GB", true, nil, nil)
	if r.Check(context.Background()) {
		t.Fatal("a busy docker slot must skip (never queue)")
	}
	if p.imagePrunes != 0 {
		t.Error("must not prune when the docker slot is held")
	}
}

func TestCheckSkipsWhenSampleUnavailable(t *testing.T) {
	p := &fakePruner{}
	r := New(sampler(0, 0, false), p, &fakeSem{free: true}, 75, time.Hour, "5GB", true, nil, nil)
	if r.Check(context.Background()) {
		t.Fatal("no disk sample → skip")
	}
}

func TestAlertDedupedWithinWindow(t *testing.T) {
	p := &fakePruner{}
	var alerted int
	r := New(sampler(90, 100, true), p, &fakeSem{free: true}, 75, time.Hour, "5GB", true,
		func(l, ti, d string) { alerted++ }, nil)
	r.Check(context.Background())
	r.Check(context.Background())
	if alerted != 1 {
		t.Errorf("second prune within 6h must not re-alert, got %d alerts", alerted)
	}
}

type errPruner struct{}

func (errPruner) PruneImagesHeld(ctx context.Context, onLine func(string)) error {
	return errors.New("write plane disabled")
}
func (errPruner) PruneBuildCacheHeld(ctx context.Context, keep string, onLine func(string)) error {
	return errors.New("write plane disabled")
}

// buildCacheGC=false honors the operator's opt-out: the image prune still runs, the cache prune
// does not.
func TestBuildCacheOptOutSkipsCachePrune(t *testing.T) {
	p := &fakePruner{}
	r := New(sampler(80, 100, true), p, &fakeSem{free: true}, 75, time.Hour, "5GB", false, nil, nil)
	r.Check(context.Background())
	if p.imagePrunes != 1 {
		t.Errorf("image prune should still run, got %d", p.imagePrunes)
	}
	if p.cachePrunes != 0 {
		t.Errorf("build-cache prune must be skipped when opted out, got %d", p.cachePrunes)
	}
}

// When both prunes fail (e.g. write plane disabled), the alert must NOT falsely claim success.
func TestAlertHonestWhenNothingReclaimed(t *testing.T) {
	var title string
	r := New(sampler(90, 100, true), errPruner{}, &fakeSem{free: true}, 75, time.Hour, "5GB", true,
		func(l, ti, d string) { title = ti }, nil)
	r.Check(context.Background())
	if title == "" {
		t.Fatal("disk pressure should still raise an alert")
	}
	if strings.Contains(strings.ToLower(title), "reclaimed") {
		t.Errorf("must not claim reclamation when nothing was reclaimed, got %q", title)
	}
}
