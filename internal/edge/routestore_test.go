package edge

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/daboss2003/mooring/internal/store"
)

func newRouteStore(t *testing.T) *RouteStore {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return NewRouteStore(db)
}

func TestRouteStoreRoundTripAndRender(t *testing.T) {
	s := newRouteStore(t)
	ctx := context.Background()
	if err := s.Save(ctx, Route{Hostname: "App.Example.com", Upstream: "shop-web:8080", UpstreamScheme: "http", HSTS: true, SecurityHeaders: true, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	routes, err := s.List()
	if err != nil || len(routes) != 1 {
		t.Fatalf("list: %v %d", err, len(routes))
	}
	if routes[0].Hostname != "app.example.com" { // normalized lowercase
		t.Errorf("hostname not normalized: %q", routes[0].Hostname)
	}
	// The stored set renders to a valid config.
	if _, err := Render(baseCfg(), routes, nil); err != nil {
		t.Fatalf("render stored routes: %v", err)
	}
	_ = s.Delete(ctx, routes[0].ID())
	if r, _ := s.List(); len(r) != 0 {
		t.Error("route not deleted")
	}
}

// The store refuses to persist an unsafe route (control-plane upstream).
func TestRouteStoreRejectsControlPlaneUpstream(t *testing.T) {
	s := newRouteStore(t)
	if err := s.Save(context.Background(), Route{Hostname: "x.example.com", Upstream: "127.0.0.1:9000", UpstreamScheme: "http", Enabled: true}); err == nil {
		t.Error("a control-plane upstream must be rejected at the store")
	}
}

// ReplaceProject makes mooring.yaml the source of truth: it swaps one project's
// routes atomically and never touches another project's, and a cross-app hostname
// collision is rejected (the original owner survives).
func TestReplaceProject(t *testing.T) {
	s := newRouteStore(t)
	ctx := context.Background()
	if err := s.ReplaceProject(ctx, "shop", []Route{
		{Hostname: "shop.example.com", Upstream: "web:8080", Enabled: true},
		{Hostname: "api.example.com", Upstream: "api:3000", Enabled: true},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceProject(ctx, "blog", []Route{{Hostname: "blog.example.com", Upstream: "blog:80", Enabled: true}}); err != nil {
		t.Fatal(err)
	}
	// Re-applying shop replaces only shop's routes; blog is untouched.
	if err := s.ReplaceProject(ctx, "shop", []Route{{Hostname: "shop.example.com", Upstream: "web:9090", Enabled: true}}); err != nil {
		t.Fatal(err)
	}
	routes, _ := s.List()
	if len(routes) != 2 {
		t.Fatalf("expected shop(1)+blog(1)=2 routes, got %d", len(routes))
	}
	// A second app claiming a hostname another app owns is rejected; owner survives.
	err := s.ReplaceProject(ctx, "evil", []Route{{Hostname: "blog.example.com", Upstream: "evil:80", Enabled: true}})
	if err == nil {
		t.Fatal("a cross-app hostname collision must be rejected")
	}
	routes, _ = s.List()
	if len(routes) != 2 {
		t.Fatalf("owner's route must survive a rejected collision, got %d routes", len(routes))
	}
}

// Apps may share a hostname on different path prefixes, but an equivalent spelling of a prefix
// another app holds ("" for "/", "/api/" for "/api") is the same claim and is refused, inside
// the write transaction.
func TestReplaceProjectRefusesEquivalentPrefixOfAnotherApp(t *testing.T) {
	s := newRouteStore(t)
	ctx := context.Background()
	route := func(prefix string) Route {
		return Route{Hostname: "a.example.com", PathPrefix: prefix, Upstream: "web:8080", UpstreamScheme: "http", Enabled: true}
	}
	if err := s.ReplaceProject(ctx, "alpha", []Route{route("/"), route("/api")}); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"", "/", "/api/", "/api"} {
		if err := s.ReplaceProject(ctx, "beta", []Route{route(p)}); err == nil {
			t.Errorf("beta claiming %q on alpha's hostname was accepted", p)
		}
		if owner, taken, err := s.HostnameOwner(ctx, "A.example.com", p, "beta"); err != nil || !taken || owner != "alpha" {
			t.Errorf("HostnameOwner(%q) = %q, %v, %v; want alpha", p, owner, taken, err)
		}
		if err := s.Save(ctx, Route{AppID: "beta", Hostname: "a.example.com", PathPrefix: p, Upstream: "web:8080", UpstreamScheme: "http", Enabled: true}); err == nil {
			t.Errorf("Save: beta claiming %q on alpha's hostname was accepted", p)
		}
	}
	if err := s.ReplaceProject(ctx, "beta", []Route{route("/blog")}); err != nil {
		t.Errorf("a distinct prefix on a shared hostname must still be allowed: %v", err)
	}
	if err := s.ReplaceProject(ctx, "alpha", []Route{route(""), route("/api/")}); err != nil {
		t.Errorf("an app re-spelling its own prefixes must be allowed: %v", err)
	}
}
