package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/daboss2003/mooring/internal/edge"
	"github.com/daboss2003/mooring/internal/store"
)

// verifyEnv is a Server whose edge reconciler discovers containers from the containersJSON fixture and
// applies to a fake Caddy admin.
func verifyEnv(t *testing.T, routes ...edge.Route) (*Server, *edge.Reconciler) {
	s, rec, _ := verifyEnvWithAdmin(t, routes...)
	return s, rec
}

// verifyEnvWithAdmin also returns a switch that makes the fake Caddy admin reject every /load.
func verifyEnvWithAdmin(t *testing.T, routes ...edge.Route) (*Server, *edge.Reconciler, *atomic.Bool) {
	t.Helper()
	reject := &atomic.Bool{}
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if reject.Load() {
			http.Error(w, "rejected", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(admin.Close)
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	rs := edge.NewRouteStore(db)
	for _, rt := range routes {
		if err := rs.Save(context.Background(), rt); err != nil {
			t.Fatal(err)
		}
	}
	rec := edge.NewReconciler(rs, edge.NewAdmin(admin.Listener.Addr().String()), edge.BaseConfig{
		AdminListen: "127.0.0.1:2019", ACMEEmail: "ops@example.com", ACMECA: "https://acme.example/directory",
	}, quietWebLog())
	s := &Server{docker: dockerServingContainers(t, containersJSON), log: quietWebLog(), edgeRecon: rec, edgeRoutes: rs}
	rec.SetPoolDiscoverer(s.DiscoverEdgePools)
	if err := rec.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s, rec, reject
}

func shopWeb() edge.Route {
	return edge.Route{AppID: "shop", Hostname: "app.example.com", Upstream: "web:8080", UpstreamScheme: "http", Enabled: true}
}

func writeIDsOf(ids ...string) func(context.Context, string) ([]string, error) {
	return func(context.Context, string) ([]string, error) { return ids, nil }
}

// Every dial is a running container of this app's route service that the write plane also lists.
func TestVerifyEdgeTargetsPasses(t *testing.T) {
	s, _ := verifyEnv(t, shopWeb())
	var lines []string
	if err := s.verifyEdgeTargets(context.Background(), "shop", 0, writeIDsOf("1", "2"), func(l string) { lines = append(lines, l) }); err != nil {
		t.Fatalf("verification should pass, got %v", err)
	}
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "✓ app.example.com → 172.18.0.5:8080, 172.18.0.6:8080") {
		t.Fatalf("want one ✓ line naming the dials, got %v", lines)
	}
}

// A dialed container the docker CLI doesn't know means the planes see different daemons.
func TestVerifyEdgeTargetsCatchesSplitDaemons(t *testing.T) {
	s, _ := verifyEnv(t, shopWeb())
	err := s.verifyEdgeTargets(context.Background(), "shop", 0, writeIDsOf("1"), func(string) {})
	if err == nil || !strings.Contains(err.Error(), "different Docker daemons") {
		t.Fatalf("want a split-daemon failure, got %v", err)
	}
}

// A route with nothing running behind it is not served: the deploy must fail, not report success.
func TestVerifyEdgeTargetsCatchesUnservedRoute(t *testing.T) {
	ghost := edge.Route{AppID: "shop", Hostname: "ghost.example.com", Upstream: "ghost:8080", UpstreamScheme: "http", Enabled: true}
	s, _ := verifyEnv(t, shopWeb(), ghost)
	err := s.verifyEdgeTargets(context.Background(), "shop", 0, writeIDsOf("1", "2"), func(string) {})
	if err == nil || !strings.Contains(err.Error(), "ghost.example.com: not served") {
		t.Fatalf("want an unserved-route failure, got %v", err)
	}
}

// A dial that lands on another app's container (e.g. discovery pointed at the wrong daemon) fails.
func TestVerifyEdgeTargetsCatchesForeignContainer(t *testing.T) {
	s, rec := verifyEnv(t, shopWeb())
	rec.SetPoolDiscoverer(func(_ context.Context, routes []edge.Route, _ map[string]bool) edge.Discovery {
		return edge.Discovery{OK: true, Evaluated: map[string]bool{edge.PoolKey(routes[0]): true},
			Pools: map[string][]string{edge.PoolKey(routes[0]): {"172.20.0.2:8080"}}}
	})
	if err := rec.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	err := s.verifyEdgeTargets(context.Background(), "shop", 0, writeIDsOf("1", "2", "5"), func(string) {})
	if err == nil || !strings.Contains(err.Error(), "is other/web, not shop/web") {
		t.Fatalf("want a foreign-container failure, got %v", err)
	}
}

// Another app's routes are not this deploy's concern, and a host without a managed edge skips the check.
func TestVerifyEdgeTargetsScope(t *testing.T) {
	s, _ := verifyEnv(t, shopWeb())
	if err := s.verifyEdgeTargets(context.Background(), "blog", 0, writeIDsOf(), func(string) {}); err != nil {
		t.Fatalf("an app with no routes has nothing to verify, got %v", err)
	}
	if err := (&Server{}).verifyEdgeTargets(context.Background(), "shop", 0, writeIDsOf(), func(string) {}); err != nil {
		t.Fatalf("no managed edge → skip, got %v", err)
	}
}

// If the edge can't be re-applied during verification (Caddy rejects /load, admin unreachable), the
// deploy fails — the check must never pass by reading the state an OLDER commit left behind.
func TestVerifyEdgeTargetsFailsWhenEdgeNotApplied(t *testing.T) {
	s, _, reject := verifyEnvWithAdmin(t, shopWeb())
	// A route added by this deploy (the stored set) that the edge never got.
	api := edge.Route{AppID: "shop", Hostname: "api.example.com", Upstream: "api:3000", UpstreamScheme: "http", Enabled: true}
	if err := s.edgeRoutes.Save(context.Background(), api); err != nil {
		t.Fatal(err)
	}
	reject.Store(true)
	err := s.verifyEdgeTargets(context.Background(), "shop", 0, writeIDsOf("1", "2", "9"), func(string) {})
	if err == nil || !strings.Contains(err.Error(), "edge config not applied") {
		t.Fatalf("want an 'edge config not applied' failure, got %v", err)
	}
}

// A write-plane listing error is reported as such (not as a split-daemon verdict), for every route on
// that service.
func TestVerifyEdgeTargetsReportsListingError(t *testing.T) {
	www := edge.Route{AppID: "shop", Hostname: "www.example.com", Upstream: "web:8080", UpstreamScheme: "http", Enabled: true}
	s, _ := verifyEnv(t, shopWeb(), www)
	calls := 0
	failing := func(context.Context, string) ([]string, error) { calls++; return nil, errors.New("docker slot busy") }
	err := s.verifyEdgeTargets(context.Background(), "shop", 0, failing, func(string) {})
	if err == nil || strings.Contains(err.Error(), "different Docker daemons") || strings.Count(err.Error(), "could not list web") != 2 {
		t.Fatalf("both routes must report the listing error, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("the listing must be done once per service per pass, got %d calls", calls)
	}
}
