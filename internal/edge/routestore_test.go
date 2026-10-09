package edge

import (
	"context"
	"os"
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

func lbByRoute(t *testing.T, s *RouteStore) map[string]Route {
	t.Helper()
	routes, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]Route{}
	for _, r := range routes {
		out[r.Hostname+r.PathPrefix] = r
	}
	return out
}

// lb is persisted by ReplaceProject (deploys) and Save (insert and update), and read back by List.
func TestRouteStoreLBRoundTrip(t *testing.T) {
	s := newRouteStore(t)
	ctx := context.Background()
	if err := s.ReplaceProject(ctx, "shop", []Route{
		{Hostname: "a.example.com", PathPrefix: "/", Upstream: "web:8080", Enabled: true, LB: "cookie"},
		{Hostname: "a.example.com", PathPrefix: "/api", Upstream: "api:3000", Enabled: true, LB: "round_robin"},
		{Hostname: "b.example.com", Upstream: "web:8080", Enabled: true},
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(ctx, Route{AppID: "blog", Hostname: "c.example.com", Upstream: "blog:80", UpstreamScheme: "http", Enabled: true, LB: "ip_hash"}); err != nil {
		t.Fatal(err)
	}
	got := lbByRoute(t, s)
	for key, want := range map[string]string{"a.example.com/": "cookie", "a.example.com/api": "round_robin", "b.example.com": "", "c.example.com": "ip_hash"} {
		if got[key].LB != want {
			t.Errorf("%s: lb = %q, want %q", key, got[key].LB, want)
		}
	}
	c := got["c.example.com"]
	c.LB = "least_conn"
	if err := s.Save(ctx, c); err != nil {
		t.Fatal(err)
	}
	if got := lbByRoute(t, s)["c.example.com"].LB; got != "least_conn" {
		t.Errorf("Save update: lb = %q, want least_conn", got)
	}
	// A redeploy replaces the value.
	if err := s.ReplaceProject(ctx, "shop", []Route{{Hostname: "a.example.com", PathPrefix: "/", Upstream: "web:8080", Enabled: true, LB: "ip_hash"}}); err != nil {
		t.Fatal(err)
	}
	if got := lbByRoute(t, s)["a.example.com/"].LB; got != "ip_hash" {
		t.Errorf("ReplaceProject: lb = %q, want ip_hash", got)
	}
	// An invalid value never reaches the table.
	if err := s.ReplaceProject(ctx, "shop", []Route{{Hostname: "a.example.com", Upstream: "web:8080", Enabled: true, LB: "sticky"}}); err == nil {
		t.Error("ReplaceProject must refuse an invalid lb")
	}
	if err := s.Save(ctx, Route{AppID: "blog", Hostname: "d.example.com", Upstream: "blog:80", UpstreamScheme: "http", Enabled: true, LB: "sticky"}); err == nil {
		t.Error("Save must refuse an invalid lb")
	}
}

// Migration 0034 adds the lb column to an existing app_routes table; rows that predate it read
// back as "" (least_conn).
func TestRouteStoreLBMigrationKeepsExistingRows(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	db, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var applied int
	if err := db.QueryRow(`SELECT COUNT(*) FROM schema_meta WHERE name = '0034_app_routes_lb.sql'`).Scan(&applied); err != nil || applied != 1 {
		t.Fatalf("migration 0034 not recorded: %d %v", applied, err)
	}
	// Recreate the pre-0034 table shape holding a route, then apply the migration file to it.
	if _, err := db.Exec(`ALTER TABLE app_routes DROP COLUMN lb`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO app_routes(app_id, hostname, upstream, upstream_scheme, path_prefix, redirect_http, hsts, security_headers, enabled, tls_ca, created_at)
		VALUES('shop', 'old.example.com', 'web:8080', 'http', '', 1, 1, 1, 1, '', 0)`); err != nil {
		t.Fatal(err)
	}
	mig, err := os.ReadFile(filepath.Join("..", "store", "migrations", "0034_app_routes_lb.sql"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(string(mig)); err != nil {
		t.Fatalf("migration 0034 on an existing table: %v", err)
	}
	routes, err := NewRouteStore(db).List()
	if err != nil || len(routes) != 1 {
		t.Fatalf("list after migration: %v %d", err, len(routes))
	}
	if routes[0].LB != "" || routes[0].Hostname != "old.example.com" {
		t.Errorf("existing row after migration = %+v, want lb \"\"", routes[0])
	}
	db.Close()
}
