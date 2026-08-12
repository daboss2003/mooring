// Package edgemetrics aggregates the managed edge's (Caddy's) per-request access log into a small
// set of per-service signals the autoscaler can read: p95 request latency and request rate over a
// short sliding window. The numbers are MEASURED BY MOORING (not self-reported by the app), so the
// app can't fabricate them — but, like any latency/rate signal, they reflect whatever traffic
// reaches the edge, so a client shaping traffic still influences them (see the scaler's use of them).
//
// Memory is bounded two ways: samples older than the window are pruned on every access, and each
// service keeps at most maxSamples recent requests (a busy service degrades to a rolling sample,
// never unbounded growth). Everything is O(window) and lock-guarded — the recorder is called from
// the edge log-reader goroutine, the reader from the scaler tick.
package edgemetrics

import (
	"sort"
	"sync"
	"time"
)

// Key identifies one scaled service (compose project + service).
type Key struct{ App, Service string }

// maxSamples caps per-service retained requests so a flood can't grow memory without bound; beyond
// it the oldest sample is dropped (the window still yields a representative p95/rate).
const maxSamples = 20000

type sample struct {
	tNano int64
	durMs float64
}

// Aggregator holds a bounded sliding window of request durations per service.
type Aggregator struct {
	mu             sync.Mutex
	window         time.Duration
	liveness       time.Duration // how recently ANY request must have been seen for the edge to count as "delivering logs"
	byKey          map[Key][]sample
	lastSampleNano int64            // most recent Record across ALL keys (0 = none yet); backs Live
	now            func() time.Time // injectable for tests
}

// New builds an Aggregator over the given window (e.g. 30s). A window <= 0 defaults to 30s. The
// liveness horizon (used by Live to tell "idle" from "blind") equals the window: it must NOT exceed
// the horizon after which a service's own samples are pruned, otherwise a total capture break leaves
// a gap where a service reads present=false (pruned) while Live() still reports true — during which a
// loaded service could be wrongly shed. Aligning them means "blind" (no samples anywhere in the
// window) and "not present" (no samples for this service in the window) flip together.
func New(window time.Duration) *Aggregator {
	if window <= 0 {
		window = 30 * time.Second
	}
	return &Aggregator{window: window, liveness: window, byKey: map[Key][]sample{}, now: time.Now}
}

// Record adds one completed request's latency (milliseconds) for a service. Called from the edge
// log reader; host→Key resolution is the caller's job (an unresolved host is simply not recorded).
func (a *Aggregator) Record(k Key, durMs float64) {
	if durMs < 0 {
		durMs = 0
	}
	now := a.now().UnixNano()
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.prune(k, now)
	s = append(s, sample{tNano: now, durMs: durMs})
	if len(s) > maxSamples {
		s = s[len(s)-maxSamples:] // keep the newest maxSamples
	}
	a.byKey[k] = s
	a.lastSampleNano = now // the edge is delivering logs (any service) → Live
}

// Live reports whether the edge is currently delivering access logs at all — i.e. SOME service
// recorded a request within the liveness horizon. The scaler uses it to distinguish "this service is
// genuinely idle" (edge live, but no samples for it → zero load, may scale down) from "we are blind"
// (edge not delivering — enable-time lag, a broken/stalled capture, or no managed edge → HOLD, never
// shed a service we can't measure). Returns false before the first sample ever.
func (a *Aggregator) Live() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.lastSampleNano == 0 {
		return false
	}
	return a.now().UnixNano()-a.lastSampleNano <= a.liveness.Nanoseconds()
}

// Stats returns the p95 latency (ms) and request rate (req/s) for a service over the window, and
// present=false when there is NO data in the window. The rate is accurate even above the sample cap:
// once the per-service reservoir saturates (maxSamples), it is divided by the ACTUAL retained span,
// not the nominal window (see below), so it never pins at maxSamples/window.
func (a *Aggregator) Stats(k Key) (p95Ms, reqPerSec float64, present bool) {
	now := a.now().UnixNano()
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.prune(k, now)
	a.byKey[k] = s
	if len(s) == 0 {
		return 0, 0, false
	}
	durs := make([]float64, len(s))
	for i, x := range s {
		durs[i] = x.durMs
	}
	sort.Float64s(durs)
	// Nearest-rank p95: index ceil(0.95*n)-1, clamped.
	idx := int(0.95*float64(len(durs)) + 0.9999)
	if idx > len(durs) {
		idx = len(durs)
	}
	if idx < 1 {
		idx = 1
	}
	p95Ms = durs[idx-1]
	// Rate = requests ÷ time. Normally that time is the whole window. But when the reservoir is at
	// the cap the OLDEST retained request is newer than one window ago (we dropped older ones to
	// bound memory), so those maxSamples arrived in a SHORTER span — dividing by the full window
	// would under-report and pin the rate at maxSamples/window regardless of true load. Divide by the
	// actual retained span instead, which recovers the true rate (the newest maxSamples arrived in
	// exactly that span). Guard span>0 for a frozen test clock.
	divisor := a.window.Seconds()
	if len(s) >= maxSamples {
		if span := float64(now-s[0].tNano) / 1e9; span > 0 && span < divisor {
			divisor = span
		}
	}
	reqPerSec = float64(len(s)) / divisor
	return p95Ms, reqPerSec, true
}

// prune drops samples older than the window. Caller holds the lock.
func (a *Aggregator) prune(k Key, now int64) []sample {
	s := a.byKey[k]
	cutoff := now - a.window.Nanoseconds()
	i := 0
	for i < len(s) && s[i].tNano < cutoff {
		i++
	}
	if i == 0 {
		return s
	}
	if i >= len(s) {
		return s[:0]
	}
	// Compact to the front so the backing array is reused.
	return append(s[:0], s[i:]...)
}

// Forget drops a service's samples entirely (e.g. on app delete / policy removal) so a deleted
// service can't leak memory.
func (a *Aggregator) Forget(k Key) {
	a.mu.Lock()
	delete(a.byKey, k)
	a.mu.Unlock()
}
