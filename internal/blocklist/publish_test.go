package blocklist

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The edge takes the list at most once a minute: changes within the minute are batched into one
// apply, Snapshot (what the edge renders) only changes when it is released, and an unchanged list
// is never applied again.
func TestBatchedApply(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	var mu sync.Mutex
	var applied []int
	h.b.SetApply(func(context.Context) error {
		mu.Lock()
		applied = append(applied, len(h.b.Snapshot()))
		mu.Unlock()
		return nil
	})
	got := func() []int { mu.Lock(); defer mu.Unlock(); return append([]int(nil), applied...) }
	h.b.step(ctx)
	if !reflect.DeepEqual(got(), []int{0}) {
		t.Fatalf("first step must apply the list once: %v", got())
	}
	h.mustBlock(h.auto("192.0.2.1", time.Hour))
	h.clk.add(10 * time.Second)
	h.b.step(ctx)
	if len(got()) != 1 || len(h.b.Snapshot()) != 0 {
		t.Fatalf("a change within the minute must wait: applies %v, snapshot %v", got(), h.snapshot())
	}
	h.clk.add(51 * time.Second)
	h.b.step(ctx)
	if !reflect.DeepEqual(got(), []int{0, 1}) {
		t.Fatalf("a minute after the last apply the change is applied: %v", got())
	}
	h.mustBlock(h.auto("192.0.2.2", time.Hour))
	h.mustBlock(h.auto("192.0.2.3", time.Hour))
	h.clk.add(30 * time.Second)
	h.b.step(ctx)
	h.clk.add(31 * time.Second)
	h.b.step(ctx)
	if !reflect.DeepEqual(got(), []int{0, 1, 3}) {
		t.Fatalf("two blocks in one minute must be one apply: %v", got())
	}
	for i := 0; i < 5; i++ {
		h.clk.add(time.Minute)
		h.b.step(ctx)
	}
	if len(got()) != 3 {
		t.Errorf("an unchanged list was applied again: %v", got())
	}
	st := h.b.Status()
	if !st.Applied || st.ApplyErr != "" || !st.LastApplied.Equal(t0.Add(122*time.Second)) {
		t.Errorf("status = %+v", st)
	}
	h.mustBlock(h.auto("192.0.2.4", time.Hour))
	if h.b.Status().Applied {
		t.Error("a change not yet applied must show Applied false")
	}
}

// An apply failing three times in a row raises one security_blocking warning; it is retried once a
// minute (not sooner) and the next success resolves the alert.
func TestApplyFailureAlertAndResolve(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	var calls atomic.Int32
	var fail atomic.Bool
	fail.Store(true)
	h.b.SetApply(func(context.Context) error {
		calls.Add(1)
		if fail.Load() {
			return errors.New("edge: admin /load unreachable")
		}
		return nil
	})
	h.b.step(ctx)
	h.clk.add(10 * time.Second)
	h.b.step(ctx)
	if n := calls.Load(); n != 1 {
		t.Fatalf("a failed apply must wait a minute before the retry: %d calls", n)
	}
	h.clk.add(time.Minute)
	h.b.step(ctx)
	if n := len(h.alerts.list()); n != 0 {
		t.Fatalf("two failures in a row must not alert yet (%d alerts)", n)
	}
	for i := 0; i < 2; i++ {
		h.clk.add(time.Minute)
		h.b.step(ctx)
	}
	if n := calls.Load(); n != 4 {
		t.Fatalf("calls = %d, want 4", n)
	}
	if n := h.alerts.count(alertKeyApply, "firing"); n != 1 {
		t.Errorf("apply alerts = %d, want 1", n)
	}
	st := h.b.Status()
	if st.Applied || st.ApplyErr != "edge: admin /load unreachable" {
		t.Errorf("status while failing = %+v", st)
	}
	fail.Store(false)
	h.clk.add(time.Minute)
	h.b.step(ctx)
	if n := h.alerts.count(alertKeyApply, "resolved"); n != 1 {
		t.Errorf("resolved alerts = %d, want 1", n)
	}
	if st := h.b.Status(); !st.Applied || st.ApplyErr != "" {
		t.Errorf("status after recovery = %+v", st)
	}
	for _, o := range h.alerts.list() {
		if o.Kind != alertKind || o.DedupeKey != alertKeyApply {
			t.Errorf("alert %+v", o)
		}
	}
	// Without an apply func the list is still released, and the problem is shown.
	h.b.SetApply(nil)
	h.mustBlock(h.auto("192.0.2.1", time.Hour))
	h.clk.add(time.Minute)
	h.b.step(ctx)
	if st := h.b.Status(); st.Applied || st.ApplyErr == "" || len(h.b.Snapshot()) != 1 {
		t.Errorf("no apply func: %+v snapshot %v", st, h.snapshot())
	}
}

// A block in force that becomes covered by a protected address (the allowlist changed, a session
// signed in) is suspended — not published, shown as suspended with the reason — and resumes when it
// is no longer covered.
func TestSuspendAndResume(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.mustBlock(h.auto("192.0.2.1", time.Hour))
	h.mustBlock(h.auto("192.0.2.2", time.Hour))
	h.release()
	h.g.setAllow("203.0.113.0/24", "192.0.2.0/31")
	h.clk.add(time.Minute)
	h.b.step(ctx)
	if got := h.snapshot(); !reflect.DeepEqual(got, []string{"192.0.2.2/32"}) {
		t.Errorf("snapshot with 192.0.2.1 allowlisted = %v", got)
	}
	blk, _, _ := h.b.Get(ctx, netip.MustParsePrefix("192.0.2.1/32"))
	if blk.State != StateSuspended || blk.SuspendedWhy != RefuseAllowlist {
		t.Errorf("block = %+v", blk)
	}
	h.g.mu.Lock()
	h.g.sessions = []netip.Addr{netip.MustParseAddr("192.0.2.2")}
	h.g.mu.Unlock()
	h.g.setAllow("203.0.113.0/24")
	h.clk.add(time.Minute)
	h.b.step(ctx)
	if got := h.snapshot(); !reflect.DeepEqual(got, []string{"192.0.2.1/32"}) {
		t.Errorf("snapshot after the change = %v", got)
	}
	if got := h.ev.actions("192.0.2.1/32"); !reflect.DeepEqual(got, []string{"applied", "suspended", "resumed"}) {
		t.Errorf("192.0.2.1 events = %v", got)
	}
	if got := h.ev.actions("192.0.2.2/32"); !reflect.DeepEqual(got, []string{"applied", "suspended"}) {
		t.Errorf("192.0.2.2 events = %v", got)
	}
	if st := h.b.Status(); st.ActiveAuto != 2 {
		t.Errorf("a suspended block still counts against the cap: %+v", st)
	}
}

// The sweep drops a block when its time runs out: an expired event, and the next release no longer
// carries it.
func TestExpirySweep(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	h.mustBlock(h.auto("192.0.2.1", 5*time.Minute))
	h.b.step(ctx)
	if got := h.snapshot(); !reflect.DeepEqual(got, []string{"192.0.2.1/32"}) {
		t.Fatalf("snapshot = %v", got)
	}
	h.clk.add(4 * time.Minute)
	h.b.step(ctx)
	if len(h.b.Snapshot()) != 1 {
		t.Fatal("expired too early")
	}
	h.clk.add(time.Minute)
	h.b.step(ctx)
	if len(h.b.Snapshot()) != 0 || h.b.Blocked(netip.MustParseAddr("192.0.2.1")) {
		t.Errorf("an expired block is still published: %v", h.snapshot())
	}
	if got := h.ev.actions("192.0.2.1/32"); !reflect.DeepEqual(got, []string{"applied", "expired"}) {
		t.Errorf("events = %v", got)
	}
	if blk, _, _ := h.b.Get(ctx, netip.MustParsePrefix("192.0.2.1/32")); blk.State != StateExpired {
		t.Errorf("state = %s", blk.State)
	}
}

// A mass change emits at most maxBlockEvents per-block events and one counting the rest.
func TestEventsBounded(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	for i := 0; i < maxBlockEvents+20; i++ {
		h.mustBlock(h.auto(fmt.Sprintf("192.0.%d.%d", 2+i/200, 1+i%200), time.Hour))
	}
	before := len(h.ev.kind(kindBlock))
	if n, err := h.b.LiftAutomatic(ctx, "siem", "off"); err != nil || n != maxBlockEvents+20 {
		t.Fatalf("lift = %d, %v", n, err)
	}
	evs := h.ev.kind(kindBlock)[before:]
	if len(evs) != maxBlockEvents+1 || evs[maxBlockEvents].F["count"] != float64(20) {
		t.Errorf("lift emitted %d events (last %v)", len(evs), evs[len(evs)-1].F)
	}
}

// Snapshot, L4Snapshot and Blocked are lock-free reads safe against concurrent changes (-race).
func TestSnapshotConcurrent(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.L4 = true })
	ctx := context.Background()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a := netip.MustParseAddr("192.0.2.7")
			for {
				select {
				case <-stop:
					return
				default:
				}
				for _, p := range h.b.Snapshot() {
					_ = p.String()
				}
				_ = h.b.L4Snapshot()
				_ = h.b.Blocked(a)
				_ = h.b.Status()
			}
		}()
	}
	for i := 0; i < 60; i++ {
		h.mustBlock(h.auto(fmt.Sprintf("192.0.2.%d", i+1), time.Hour))
		if i%3 == 0 {
			_ = h.b.Unblock(ctx, netip.MustParsePrefix(fmt.Sprintf("192.0.2.%d/32", i+1)), "owner")
		}
		h.clk.add(61 * time.Second)
		h.b.step(ctx)
	}
	close(stop)
	wg.Wait()
	if len(h.b.Snapshot()) != 40 {
		t.Errorf("snapshot has %d entries, want 40", len(h.b.Snapshot()))
	}
}

// Run applies the list soon after it starts and on a change (a minute after the last apply), and
// Close stops it; Run after Close returns at once.
func TestRunAndClose(t *testing.T) {
	h := newHarness(t, func(o *Options) { o.Now = nil })
	called := make(chan struct{}, 8)
	h.b.SetApply(func(context.Context) error { called <- struct{}{}; return nil })
	done := make(chan struct{})
	go func() { h.b.Run(context.Background()); close(done) }()
	select {
	case <-called:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not apply the list at start")
	}
	h.b.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not stop Run")
	}
	h.b.Close()
	ran := make(chan struct{})
	go func() { h.b.Run(context.Background()); close(ran) }()
	select {
	case <-ran:
	case <-time.After(5 * time.Second):
		t.Fatal("Run after Close must return at once")
	}
}
