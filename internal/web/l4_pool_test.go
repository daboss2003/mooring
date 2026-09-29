package web

import (
	"context"
	"reflect"
	"testing"

	"github.com/daboss2003/mooring/internal/l4"
)

// DiscoverL4Pools keeps running replicas of the route's (project, service), attaches the
// route's port, and returns the pool sorted, keyed by l4.PoolKey. A service with no live
// replica yields no entry (the renderer then skips that listener). Reuses the
// containersJSON fixture + dockerServingContainers helper from edge_pool_test.go.
func TestDiscoverL4Pools(t *testing.T) {
	dc := dockerServingContainers(t, containersJSON)
	routes := []l4.Route{{AppID: "shop", Listen: 53, Protocol: "udp", Service: "web", Port: 5353}}
	got, ok := DiscoverL4Pools(context.Background(), dc, quietWebLog(), routes, nil)
	want := map[string][]string{l4.PoolKey(routes[0]): {"172.18.0.5:5353", "172.18.0.6:5353"}}
	if !ok || !reflect.DeepEqual(got, want) {
		t.Errorf("DiscoverL4Pools = %v, %v; want %v, true", got, ok, want)
	}
	none, ok := DiscoverL4Pools(context.Background(), dc, quietWebLog(),
		[]l4.Route{{AppID: "shop", Listen: 53, Protocol: "udp", Service: "ghost", Port: 53}}, nil)
	if !ok || len(none) != 0 {
		t.Errorf("a service with no replica must yield no pool (route skipped) with ok=true, got %v, %v", none, ok)
	}
	// Discovery itself unavailable → ok=false, so the caller keeps last-known pools instead of
	// unbinding every listener.
	if _, ok := DiscoverL4Pools(context.Background(), nil, quietWebLog(), routes, nil); ok {
		t.Error("a nil docker client must report ok=false")
	}
}

// ServiceIP returns the lowest routable bridge IP of a running replica (deterministic),
// and ok=false for an unknown service (→ the prober reports a clear BASIC failure).
func TestServiceIP(t *testing.T) {
	dc := dockerServingContainers(t, containersJSON)
	if ip, ok := ServiceIP(context.Background(), dc, "shop", "web"); !ok || ip != "172.18.0.5" {
		t.Errorf("ServiceIP = %q, %v; want 172.18.0.5, true", ip, ok)
	}
	if _, ok := ServiceIP(context.Background(), dc, "shop", "ghost"); ok {
		t.Error("an unknown service must return ok=false")
	}
	if _, ok := ServiceIP(context.Background(), nil, "shop", "web"); ok {
		t.Error("a nil docker client must return ok=false")
	}
}
