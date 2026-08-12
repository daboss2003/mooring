package edgemetrics

import (
	"testing"
	"time"
)

func TestAggregatorP95AndRate(t *testing.T) {
	base := time.Unix(1_000_000, 0)
	cur := base
	a := New(10 * time.Second)
	a.now = func() time.Time { return cur }
	k := Key{App: "credlock", Service: "api"}

	// 100 requests: 95 at 100ms, 5 at 500ms → p95 should land at the boundary (100ms), and the
	// 5 slow ones push it up. Record them all "now".
	for i := 0; i < 95; i++ {
		a.Record(k, 100)
	}
	for i := 0; i < 5; i++ {
		a.Record(k, 500)
	}
	p95, rate, present := a.Stats(k)
	if !present {
		t.Fatal("expected present with data in the window")
	}
	if p95 != 100 && p95 != 500 { // nearest-rank p95 of this mix sits at the 95th sample
		t.Errorf("p95 = %v, want ~100-500 boundary", p95)
	}
	if rate != 10 { // 100 requests / 10s window
		t.Errorf("rate = %v req/s, want 10", rate)
	}

	// Advance past the window → the samples age out → present=false (HOLD, not zero-load).
	cur = base.Add(11 * time.Second)
	if _, _, present := a.Stats(k); present {
		t.Error("after the window elapses with no new requests, Stats must report absent")
	}
}

func TestAggregatorWindowSlides(t *testing.T) {
	base := time.Unix(2_000_000, 0)
	cur := base
	a := New(10 * time.Second)
	a.now = func() time.Time { return cur }
	k := Key{App: "x", Service: "y"}

	a.Record(k, 200) // old
	cur = base.Add(6 * time.Second)
	a.Record(k, 400) // recent
	cur = base.Add(12 * time.Second) // old sample (t=0) now outside the 10s window; recent (t=6) still in
	p95, rate, present := a.Stats(k)
	if !present || p95 != 400 {
		t.Errorf("only the in-window sample should count: p95=%v present=%v", p95, present)
	}
	if rate != 0.1 { // 1 request / 10s
		t.Errorf("rate = %v, want 0.1", rate)
	}
}

func TestAggregatorBoundedMemory(t *testing.T) {
	a := New(time.Hour) // long window so nothing prunes by time
	k := Key{App: "a", Service: "b"}
	for i := 0; i < maxSamples+5000; i++ {
		a.Record(k, 1)
	}
	a.mu.Lock()
	n := len(a.byKey[k])
	a.mu.Unlock()
	if n > maxSamples {
		t.Errorf("retained %d samples, must be capped at %d", n, maxSamples)
	}
}

func TestAggregatorRateNotCapped(t *testing.T) {
	// Regression: above the sample cap, rate must NOT pin at maxSamples/window. Simulate a true
	// ~4000 req/s: feed maxSamples+ requests spread over the span they'd really occupy.
	base := time.Unix(7_000_000, 0)
	cur := base
	a := New(30 * time.Second)
	a.now = func() time.Time { return cur }
	k := Key{App: "shop", Service: "api"}

	const rate = 4000 // req/s, well above maxSamples/window (20000/30 ≈ 667)
	// Record maxSamples+2000 requests, advancing the clock so they span the true rate.
	total := maxSamples + 2000
	for i := 0; i < total; i++ {
		cur = base.Add(time.Duration(float64(i) / rate * float64(time.Second)))
		a.Record(k, 5)
	}
	_, got, present := a.Stats(k)
	if !present {
		t.Fatal("expected present")
	}
	// The retained newest maxSamples span ~maxSamples/rate seconds; dividing by that span recovers
	// ~rate, not the ~667 the old (count/window) formula pinned at.
	if got < rate*0.8 || got > rate*1.2 {
		t.Errorf("rate = %.0f req/s, want ~%d (must not saturate at ~667)", got, rate)
	}
}

func TestAggregatorLive(t *testing.T) {
	base := time.Unix(8_000_000, 0)
	cur := base
	a := New(30 * time.Second) // liveness horizon == window == 30s
	a.now = func() time.Time { return cur }
	k := Key{App: "shop", Service: "api"}

	if a.Live() {
		t.Error("a fresh aggregator (no samples ever) must not be Live")
	}
	a.Record(k, 10)
	if !a.Live() {
		t.Error("right after a sample the edge must be Live")
	}
	cur = base.Add(29 * time.Second) // within the liveness horizon
	if !a.Live() {
		t.Error("within the liveness horizon the edge stays Live")
	}
	cur = base.Add(31 * time.Second) // past it — aligned with the presence window so no shed gap
	if a.Live() {
		t.Error("past the liveness horizon with no new samples the edge is no longer Live")
	}
}

func TestAggregatorForget(t *testing.T) {
	a := New(time.Second)
	k := Key{App: "a", Service: "b"}
	a.Record(k, 1)
	a.Forget(k)
	if _, _, present := a.Stats(k); present {
		t.Error("Forget must drop the service's samples")
	}
}
