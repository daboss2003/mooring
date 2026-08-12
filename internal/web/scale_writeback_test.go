package web

import (
	"testing"

	"github.com/daboss2003/mooring/internal/definition"
)

func TestUpsertScaling(t *testing.T) {
	list := []definition.Scaling{{Service: "api", Max: 3}, {Service: "worker", Max: 2}}
	// Replace an existing service in place (no duplicate).
	list = upsertScaling(list, definition.Scaling{Service: "api", Max: 5})
	if len(list) != 2 {
		t.Fatalf("replace must not grow the list: %d", len(list))
	}
	if list[0].Service != "api" || list[0].Max != 5 {
		t.Fatalf("api entry not replaced in place: %+v", list[0])
	}
	// Append a new service.
	list = upsertScaling(list, definition.Scaling{Service: "resolver", Max: 4})
	if len(list) != 3 || list[2].Service != "resolver" {
		t.Fatalf("new service not appended: %+v", list)
	}
}

// A write-back must always produce a policy the controller accepts — unset fields
// take the dashboard defaults so the dead-band / breach / cooldown contract holds.
func TestScalingPolicyRowDefaultsAreValid(t *testing.T) {
	// Minimal entry: only cpu thresholds set; mem/breach/cooldown unset.
	pr := scalingPolicyRow(definition.Scaling{Service: "api", Enabled: true, Min: 1, Max: 4, UpCPUPct: 65, DownCPUPct: 25, PerReplicaMemMiB: 96})
	if ok, why := pr.Policy.Valid(); !ok {
		t.Fatalf("defaulted policy must be controller-valid, got %q", why)
	}
	if pr.Policy.UpMemPct != 80 || pr.Policy.DownMemPct != 40 {
		t.Errorf("mem thresholds should default to 80/40, got %v/%v", pr.Policy.UpMemPct, pr.Policy.DownMemPct)
	}
	if pr.Policy.BreachForSecs != 60 || pr.Policy.CooldownUpSecs != 60 || pr.Policy.CooldownDownSecs != 300 {
		t.Errorf("breach/cooldown defaults wrong: %+v", pr.Policy)
	}
	if pr.PerReplicaMem != 96<<20 {
		t.Errorf("per-replica mem should convert MiB→bytes, got %d", pr.PerReplicaMem)
	}
	if !pr.Enabled {
		t.Error("enabled flag not carried")
	}

	// Explicit breach/cooldown round-trip (lossless write-back of the advanced fields).
	pr = scalingPolicyRow(definition.Scaling{Service: "api", Min: 1, Max: 2, UpCPUPct: 70, DownCPUPct: 30, UpMemPct: 70, DownMemPct: 30, BreachForSecs: 90, CooldownUpSecs: 30, CooldownDownSecs: 600})
	if pr.Policy.BreachForSecs != 90 || pr.Policy.CooldownUpSecs != 30 || pr.Policy.CooldownDownSecs != 600 {
		t.Errorf("explicit breach/cooldown not preserved: %+v", pr.Policy)
	}
	if ok, why := pr.Policy.Valid(); !ok {
		t.Fatalf("explicit policy must be valid, got %q", why)
	}
}

func TestDashboardScalingSavePreservesMetrics(t *testing.T) {
	// A service configured (in mooring.yaml) with a source:edge metric...
	existing := []definition.Scaling{{
		Service: "api", Enabled: true, Min: 2, Max: 8,
		Metrics: []definition.ScalingMetric{{Name: "latency", Source: "edge", Select: "p95_latency_ms", Up: 800, Down: 300}},
	}}
	// ...then tuned via the CPU/mem dashboard panel (which knows nothing about metrics).
	formEntry := definition.Scaling{Service: "api", Enabled: true, Min: 2, Max: 10, UpCPUPct: 70, DownCPUPct: 30}

	merged := preserveMetrics(existing, formEntry)
	if len(merged.Metrics) != 1 || merged.Metrics[0].Select != "p95_latency_ms" {
		t.Fatalf("dashboard save must PRESERVE the source:edge metric, got %+v", merged.Metrics)
	}
	// The tuned CPU/min/max still take effect.
	if merged.Max != 10 || merged.UpCPUPct != 70 {
		t.Errorf("form values must apply: %+v", merged)
	}
	// A service with no prior metrics stays empty (no phantom metrics).
	if got := preserveMetrics(existing, definition.Scaling{Service: "other"}); got.Metrics != nil {
		t.Errorf("unrelated service must not inherit metrics: %+v", got.Metrics)
	}
}
