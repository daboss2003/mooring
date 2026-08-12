package scale

import (
	"testing"

	"github.com/daboss2003/mooring/internal/monitor"
	"github.com/daboss2003/mooring/internal/ops"
)

func TestCustomSignalAggregation(t *testing.T) {
	res := &ops.Result{Mode: ops.RICH, Queues: []ops.Queue{
		{Name: "jobs", Counts: []ops.QueueCount{{Name: "waiting", Value: 300}, {Name: "active", Value: 100}, {Name: "completed", Value: 1_000_000}}},
		{Name: "email", Counts: []ops.QueueCount{{Name: "waiting", Value: 40}}},
	}}
	app := &monitor.App{Project: "credlock", Ops: res}

	// Select the "jobs" queue, 4 replicas → (300+100+1_000_000)/4 — the operator's EXPLICIT queue
	// select sums that queue as-is (including completed, which is their choice).
	if s := customSignal(app, MetricSpec{Name: "q", Source: "ops", Select: "jobs"}, 4); !s.Present || s.Value != 250100 {
		t.Errorf("explicit jobs select = %v present=%v", s.Value, s.Present)
	}
	// Empty selector → BACKLOG only: (300+100+40)/4 = 110. The monotonic `completed:1_000_000` is
	// EXCLUDED, so a lifetime counter can't drive a runaway (the audit's finding #1).
	if s := customSignal(app, MetricSpec{Name: "q", Source: "ops"}, 4); !s.Present || s.Value != 110 {
		t.Errorf("backlog per-replica = %v, want 110 (cumulative counters excluded)", s.Value)
	}

	// Absent (probe unavailable) → Present:false so the controller HOLDS.
	for name, tc := range map[string]struct {
		app  *monitor.App
		spec MetricSpec
		run  int
	}{
		"no ops interface": {&monitor.App{Project: "x"}, MetricSpec{Name: "q", Source: "ops"}, 4},
		"degraded to BASIC": {&monitor.App{Ops: &ops.Result{Mode: ops.BASIC}}, MetricSpec{Name: "q", Source: "ops"}, 4},
		"probe errored":     {&monitor.App{Ops: &ops.Result{Mode: ops.RICH, Err: "timeout"}}, MetricSpec{Name: "q", Source: "ops"}, 4},
		"running is zero":   {app, MetricSpec{Name: "q", Source: "ops", Select: "jobs"}, 0},
		"unknown source":   {app, MetricSpec{Name: "q", Source: "prometheus"}, 4},
	} {
		if s := customSignal(tc.app, tc.spec, tc.run); s.Present {
			t.Errorf("%s: signal must be absent (Present:false), got %+v", name, s)
		}
	}

	// A HEALTHY probe whose selector matches nothing = the queue DRAINED/was delisted → value 0,
	// Present:TRUE (permits scale-down) — NOT absent. This is the audit's finding #2 fix.
	if s := customSignal(app, MetricSpec{Name: "q", Source: "ops", Select: "ghost"}, 4); !s.Present || s.Value != 0 {
		t.Errorf("a drained/absent selector on a healthy probe must be present with value 0, got %+v", s)
	}
	// A healthy probe with the whole queue set gone → backlog 0, present → scales down.
	if s := customSignal(&monitor.App{Ops: &ops.Result{Mode: ops.RICH}}, MetricSpec{Name: "q", Source: "ops"}, 2); !s.Present || s.Value != 0 {
		t.Errorf("drained backlog on a healthy probe must be present with value 0, got %+v", s)
	}
}

// syncSignals mirrors the persisted MetricSpec thresholds into the controller's Policy.Signals.
func TestSyncSignals(t *testing.T) {
	pr := PolicyRow{Metrics: []MetricSpec{{Name: "q", Source: "ops", Up: 100, Down: 40}}}
	pr.syncSignals()
	if len(pr.Policy.Signals) != 1 || pr.Policy.Signals[0].Name != "q" || pr.Policy.Signals[0].Up != 100 {
		t.Fatalf("syncSignals did not mirror thresholds into Policy.Signals: %+v", pr.Policy.Signals)
	}
	// A JSON round-trip through the store column preserves the specs and re-syncs.
	raw, err := marshalSignals(pr.Metrics)
	if err != nil || raw == "" {
		t.Fatalf("marshalSignals: %q err=%v", raw, err)
	}
	var back PolicyRow
	if err := back.unmarshalSignals(raw); err != nil {
		t.Fatal(err)
	}
	if len(back.Metrics) != 1 || back.Metrics[0].Select != "" || back.Policy.Signals[0].Down != 40 {
		t.Errorf("round-trip lost data: %+v / %+v", back.Metrics, back.Policy.Signals)
	}
	// Empty specs marshal to "" (existing CPU/mem-only policies stay clean).
	if raw, _ := marshalSignals(nil); raw != "" {
		t.Errorf("no signals should marshal to empty string, got %q", raw)
	}
}
