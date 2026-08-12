package scale

import "testing"

func TestEdgeSignal(t *testing.T) {
	k := Key{App: "shop", Service: "api"}
	// A watcher whose EdgeStats reports p95=800ms, 40 req/s, sampled; edge is live.
	w := &Watcher{cfg: Config{
		EdgeLive: func() bool { return true },
		EdgeStats: func(app, service string) (float64, float64, bool) {
			if app == k.App && service == k.Service {
				return 800, 40, true
			}
			return 0, 0, false
		},
	}}

	// p95 latency: absolute value, included + Present.
	s, ok := w.edgeSignal(MetricSpec{Name: "lat", Source: "edge", Select: selEdgeP95, Up: 500, Down: 200}, k, 2)
	if !ok || !s.Present || s.Value != 800 {
		t.Errorf("p95 signal = (%+v, include=%v), want value 800 present included", s, ok)
	}

	// req/s: service-total divided by the 2 running replicas → 20 per replica.
	s, ok = w.edgeSignal(MetricSpec{Name: "rps", Source: "edge", Select: selEdgeRPS, Up: 30, Down: 10}, k, 2)
	if !ok || !s.Present || s.Value != 20 {
		t.Errorf("rps signal = (%+v, include=%v), want value 20 present included", s, ok)
	}

	// Unknown selector → OMITTED (never pins), defense in depth (schema also rejects it).
	if _, ok := w.edgeSignal(MetricSpec{Name: "x", Source: "edge", Select: "bogus", Up: 1, Down: 0}, k, 2); ok {
		t.Error("unknown selector must be omitted, not included")
	}
}

func TestEdgeSignalIdleVsBlind(t *testing.T) {
	k := Key{App: "shop", Service: "api"}
	spec := MetricSpec{Name: "lat", Source: "edge", Select: selEdgeP95, Up: 500, Down: 200}
	stats := func(app, service string) (float64, float64, bool) { return 0, 0, false } // no samples for this svc

	// Edge LIVE (some other service has traffic) but this one silent → genuinely idle → measured 0,
	// Present (so an idle service can scale down).
	live := &Watcher{cfg: Config{EdgeStats: stats, EdgeLive: func() bool { return true }}}
	if s, ok := live.edgeSignal(spec, k, 3); !ok || !s.Present || s.Value != 0 {
		t.Errorf("idle-on-live-edge must be measured-0/present, got (%+v, include=%v)", s, ok)
	}

	// Edge NOT live (enable lag / broken capture) → BLIND → HOLD (Present:false), so a low-CPU/mem
	// I/O-bound service is never shed on data we don't have.
	blind := &Watcher{cfg: Config{EdgeStats: stats, EdgeLive: func() bool { return false }}}
	if s, ok := blind.edgeSignal(spec, k, 3); !ok || s.Present {
		t.Errorf("blind edge must HOLD (present:false, included), got (%+v, include=%v)", s, ok)
	}
}

func TestEdgeSignalUnwiredOmits(t *testing.T) {
	k := Key{App: "shop", Service: "api"}
	spec := MetricSpec{Name: "lat", Source: "edge", Select: selEdgeP95, Up: 500, Down: 200}
	w := &Watcher{cfg: Config{}} // no EdgeStats wired (no managed edge)
	if _, ok := w.edgeSignal(spec, k, 2); ok {
		t.Error("with no managed edge the signal must be OMITTED (inert), not held")
	}
	// running<=0 also omits (no per-replica base).
	live := &Watcher{cfg: Config{EdgeStats: func(a, s string) (float64, float64, bool) { return 0, 0, false }, EdgeLive: func() bool { return true }}}
	if _, ok := live.edgeSignal(spec, k, 0); ok {
		t.Error("running<=0 must be omitted")
	}
}
