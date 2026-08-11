package web

import (
	"testing"

	"github.com/daboss2003/mooring/internal/monitor"
)

func TestSelectCopy(t *testing.T) {
	app := &monitor.App{Services: []monitor.ServiceStatus{
		{Service: "api", ContainerID: "newestaaaaaa", Name: "app-api-2"}, // first in the (newest-first) list
		{Service: "api", ContainerID: "olderbbbbbbb", Name: "app-api-1"},
		{Service: "web", ContainerID: "webccccccccc", Name: "app-web-1"},
	}}

	// No copy id → the first match (previously the ONLY behavior — always the newest).
	c, copies, ok := selectCopy(app, "api", "")
	if !ok || c.ContainerID != "newestaaaaaa" {
		t.Fatalf("default should be the first api copy, got %+v ok=%v", c, ok)
	}
	if len(copies) != 2 {
		t.Errorf("want 2 api copies for the switcher, got %d", len(copies))
	}

	// An explicit copy id selects THAT copy — the actual bug fix.
	if c, _, ok := selectCopy(app, "api", "olderbbbbbbb"); !ok || c.ContainerID != "olderbbbbbbb" {
		t.Fatalf("explicit copy id should select the older copy, got %+v ok=%v", c, ok)
	}

	// A stale/foreign copy id falls back to the first — and can NEVER select a container outside
	// this service (the loop only ranges this app's own service containers).
	if c, _, ok := selectCopy(app, "api", "webccccccccc"); !ok || c.ContainerID != "newestaaaaaa" {
		t.Fatalf("a copy id from a DIFFERENT service must not select it; want fallback to first, got %+v", c)
	}
	if c, _, ok := selectCopy(app, "api", "does-not-exist"); !ok || c.ContainerID != "newestaaaaaa" {
		t.Fatalf("an unknown copy id must fall back to the first, got %+v", c)
	}

	// Unknown service / nil app → not found.
	if _, _, ok := selectCopy(app, "ghost", ""); ok {
		t.Error("an unknown service must return ok=false")
	}
	if _, _, ok := selectCopy(nil, "api", ""); ok {
		t.Error("a nil app must return ok=false")
	}
}
