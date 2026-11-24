package detect

import (
	"bytes"
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/pipeline"
	"github.com/daboss2003/mooring/internal/siem/redact"
)

// An alert time in the future (the clock was ahead when it was raised, then corrected) doesn't mute
// the key: a new detection after the correction is alerted.
func TestFutureCooldownDoesNotMute(t *testing.T) {
	h := newHarness(t, false)
	h.only(t, oneRule(siem.SevCritical))
	ip := "203.0.113.50"
	h.clk.set(t0.Add(6 * time.Hour)) // clock ahead
	h.feed(sshFail(6*time.Hour, ip))
	if got := h.alerts(); len(got) != 1 {
		t.Fatalf("first alert: %d", len(got))
	}
	h.reopen(t)
	h.only(t, oneRule(siem.SevCritical))
	h.clk.set(t0.Add(2 * time.Hour)) // corrected back by 4 h; a new attack
	before := len(h.alerts())
	h.feed(sshFail(2*time.Hour, ip))
	if got := len(h.alerts()) - before; got != 1 {
		t.Fatalf("%d alerts after the clock was corrected, want 1 (a future alert time muted the key)", got)
	}
}

// The final flush hands every detection's event to the pipeline even when there are more than its
// emit lane holds: a full lane is waited on briefly, not dropped at once.
func TestFinalFlushEmitsEveryDetection(t *testing.T) {
	red, err := redact.New(bytes.Repeat([]byte{7}, 32), redact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	counted := make(chan siem.Event, 100000)
	// A slow pipeline (its store is busy): the 256-slot emit lane fills faster than it drains.
	p := pipeline.New(pipeline.Options{Redactor: red, Subscribers: []func(siem.Event){func(e siem.Event) {
		if e.Kind == KindDetection {
			counted <- e
			time.Sleep(300 * time.Microsecond)
		}
	}}})
	pctx, stopPipe := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); p.Run(pctx) }()

	h := newHarness(t, false, func(o *Options) { o.Emit = p.Emit })
	h.e.lim.newPerHour = 1 << 20
	h.only(t, oneRule(siem.SevLow))
	const n = 1000
	for i := range n {
		h.feed(sshFail(time.Duration(i)*time.Millisecond, ipv4(i)))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h.e.Run(ctx)
	stopPipe()
	<-done
	close(counted)
	got := 0
	for range counted {
		got++
	}
	if got != n || h.e.Stats().EmitDropped != 0 {
		t.Fatalf("%d of %d detection events reached the pipeline (EmitDropped %d)", got, n, h.e.Stats().EmitDropped)
	}
}

type hangingAlerter struct{ calls atomic.Int64 }

func (h *hangingAlerter) EnqueueInfra(ctx context.Context, _ alert.Outbox) error {
	h.calls.Add(1)
	<-ctx.Done()
	return ctx.Err()
}

// At shutdown the alert worker stops taking queued alerts one by one (each can hang for the whole
// alert timeout against a stalled database): what is still queued gets only the bounded shutdown
// pass. Go's select picks at random between a cancelled context and a ready queue, so the case is
// repeated: without the stop check some run takes extra full-timeout attempts.
func TestShutdownBoundedWithHangingAlerter(t *testing.T) {
	const timeout = 40 * time.Millisecond
	for run := range 40 {
		ha := &hangingAlerter{}
		h := newHarness(t, false, func(o *Options) { o.Alerter = ha })
		h.e.lim.alertTimeout = timeout
		h.e.lim.alertBackoff = []time.Duration{time.Hour, time.Hour} // no retry falls due
		h.only(t, oneRule(siem.SevCritical))
		for i := range 20 {
			h.e.Subscriber()(sshFail(time.Duration(i)*time.Millisecond, ipv4(i)))
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); h.e.Run(ctx) }()
		deadline := time.Now().Add(5 * time.Second)
		for ha.calls.Load() == 0 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		start := time.Now()
		cancel()
		<-done
		// In flight when cancelled (≤ timeout) + the shutdown pass (≤ timeout, plus one attempt
		// started just before its end) + the final write. Each queued alert taken the normal way
		// would add a whole timeout.
		if took := time.Since(start); took > 4*timeout+50*time.Millisecond {
			t.Fatalf("run %d: Run returned %v after cancel, want ≤ about %v", run, took, 4*timeout)
		}
	}
}
