package web

import (
	"testing"

	"github.com/daboss2003/mooring/internal/monitor"
)

func TestUnhealthyReplicaIDs(t *testing.T) {
	app := monitor.App{Project: "shop", Services: []monitor.ServiceStatus{
		{Service: "web", ContainerID: "c1", State: "running", Health: "healthy"},
		{Service: "web", ContainerID: "c2", State: "running", Health: "unhealthy"},
		{Service: "web", ContainerID: "c3", State: "exited"},
		{Service: "web", ContainerID: "c4", State: "running", Health: "starting"},  // still coming up — NOT sick
		{Service: "api", ContainerID: "a1", State: "running", Health: "unhealthy"}, // other service — ignored
	}}
	bad, total := unhealthyReplicaIDs(app, "web")
	if total != 4 {
		t.Fatalf("web replica total = %d, want 4", total)
	}
	got := map[string]bool{}
	for _, id := range bad {
		got[id] = true
	}
	// Only the unhealthy (c2) and the down (c3) are restarted; the healthy (c1) and starting (c4) are left.
	if len(bad) != 2 || !got["c2"] || !got["c3"] {
		t.Errorf("bad replicas = %v, want exactly {c2, c3}", bad)
	}

	// Single-replica service: total 1 ⇒ the caller uses a whole-service restart, not targeted.
	single := monitor.App{Services: []monitor.ServiceStatus{{Service: "solo", ContainerID: "s1", State: "exited"}}}
	if _, total := unhealthyReplicaIDs(single, "solo"); total != 1 {
		t.Errorf("single-replica total = %d, want 1", total)
	}
}
