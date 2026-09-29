package edge

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/store"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// The reconciler renders the route set and POSTs the whole document to /load.
func TestReconcilePushesWholeConfig(t *testing.T) {
	var gotPath string
	var gotBody []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rs := NewRouteStore(db)
	if err := rs.Save(context.Background(), Route{Hostname: "app.example.com", Upstream: "web:8080", UpstreamScheme: "http", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rec := NewReconciler(rs, NewAdmin(ts.Listener.Addr().String()), baseCfg(), quietLog())
	rec.SetPoolDiscoverer(func(_ context.Context, routes []Route, _ map[string]bool) Discovery {
		return Discovery{OK: true, Evaluated: map[string]bool{PoolKey(routes[0]): true},
			Pools: map[string][]string{PoolKey(routes[0]): {"172.18.0.5:8080"}}}
	})
	if err := rec.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if gotPath != "/load" {
		t.Errorf("admin path = %q, want /load", gotPath)
	}
	if !strings.Contains(string(gotBody), "app.example.com") || !strings.Contains(string(gotBody), "172.18.0.5:8080") {
		t.Errorf("pushed config missing the route:\n%s", gotBody)
	}
}

// With no container discovery at all, a service-name upstream has nothing safe to dial: the route
// answers 503 (its host and certificate stay) and the name is never handed to Caddy.
func TestReconcileWithoutDiscoveryNeverDialsName(t *testing.T) {
	var gotBody []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	db, _ := store.Open(filepath.Join(t.TempDir(), "test.db"))
	defer db.Close()
	rs := NewRouteStore(db)
	_ = rs.Save(context.Background(), Route{Hostname: "app.example.com", Upstream: "web:8080", UpstreamScheme: "http", Enabled: true})
	rec := NewReconciler(rs, NewAdmin(ts.Listener.Addr().String()), baseCfg(), quietLog())
	if err := rec.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	body := strings.Join(strings.Fields(string(gotBody)), "")
	if strings.Contains(body, "web:8080") {
		t.Errorf("the service name must never be dialed:\n%s", body)
	}
	if !strings.Contains(body, `"status_code":503`) || !strings.Contains(body, "app.example.com") {
		t.Errorf("want a 503 route that keeps its host:\n%s", body)
	}
	if st := rec.RouteStatuses(); len(st) != 1 || st[0].State != RouteUnroutable {
		t.Errorf("status = %+v, want unroutable", st)
	}
}

// A discovered replica pool replaces the single service-name dial and lights up the
// least-conn + passive-health machinery (auto-scaling edge pool).
func TestReconcileAppliesDiscoveredPool(t *testing.T) {
	var gotBody []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rs := NewRouteStore(db)
	if err := rs.Save(context.Background(), Route{Hostname: "app.example.com", Upstream: "web:8080", UpstreamScheme: "http", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rec := NewReconciler(rs, NewAdmin(ts.Listener.Addr().String()), baseCfg(), quietLog())
	rec.SetPoolDiscoverer(func(_ context.Context, routes []Route, _ map[string]bool) Discovery {
		return Discovery{OK: true, Evaluated: map[string]bool{PoolKey(routes[0]): true},
			Pools: map[string][]string{PoolKey(routes[0]): {"172.18.0.5:8080", "172.18.0.6:8080"}}}
	})
	if err := rec.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	for _, want := range []string{"172.18.0.5:8080", "172.18.0.6:8080", "least_conn", "passive"} {
		if !strings.Contains(string(gotBody), want) {
			t.Errorf("pushed config missing %q:\n%s", want, gotBody)
		}
	}
	// The pool overrides the service-name selector — it must not also be dialed.
	if strings.Contains(string(gotBody), "web:8080") {
		t.Errorf("a pooled route should not also dial the service name:\n%s", gotBody)
	}
}

// Discovery ran and found no running container for the route's service: the route answers 503
// (never the service-name dial) and gets no LB machinery.
func TestReconcileNoContainerServes503(t *testing.T) {
	var gotBody []byte
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	db, _ := store.Open(filepath.Join(t.TempDir(), "test.db"))
	defer db.Close()
	rs := NewRouteStore(db)
	_ = rs.Save(context.Background(), Route{Hostname: "app.example.com", Upstream: "web:8080", UpstreamScheme: "http", Enabled: true})
	rec := NewReconciler(rs, NewAdmin(ts.Listener.Addr().String()), baseCfg(), quietLog())
	rec.SetPoolDiscoverer(func(_ context.Context, routes []Route, _ map[string]bool) Discovery {
		return Discovery{OK: true, Evaluated: map[string]bool{PoolKey(routes[0]): true}}
	})
	if err := rec.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	body := strings.Join(strings.Fields(string(gotBody)), "")
	if strings.Contains(body, "web:8080") || strings.Contains(body, "least_conn") {
		t.Errorf("no container must mean no dial at all:\n%s", body)
	}
	if !strings.Contains(body, `"status_code":503`) || !strings.Contains(body, `"Retry-After":["5"]`) {
		t.Errorf("want a 503 with Retry-After:\n%s", body)
	}
	st := rec.RouteStatuses()
	if len(st) != 1 || st[0].State != RouteUnroutable || !strings.Contains(st[0].Reason, "no running container") {
		t.Errorf("status = %+v", st)
	}
}

// fakeClock is a settable clock for the Reconciler.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) advance(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

func newRecWithRoute(t *testing.T, up string, scheme string) (*Reconciler, *[]byte, *int32, func()) {
	t.Helper()
	body := new([]byte)
	loads := new(int32)
	var mu sync.Mutex
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		*body = b
		mu.Unlock()
		atomic.AddInt32(loads, 1)
		w.WriteHeader(http.StatusOK)
	}))
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	rs := NewRouteStore(db)
	if err := rs.Save(context.Background(), Route{AppID: "shop", Hostname: "app.example.com", Upstream: up, UpstreamScheme: scheme, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rec := NewReconciler(rs, NewAdmin(ts.Listener.Addr().String()), baseCfg(), quietLog())
	return rec, body, loads, func() { ts.Close(); db.Close() }
}

// A discovery outage keeps dialing the addresses last confirmed — but only for lkgTTL; after that the
// route answers 503 rather than risk a reused IP.
func TestReconcileDiscoveryDownUsesLastKnownThenExpires(t *testing.T) {
	rec, body, _, done := newRecWithRoute(t, "web:8080", "http")
	defer done()
	clk := &fakeClock{t: time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)}
	rec.now = clk.now
	up := true
	rec.SetPoolDiscoverer(func(_ context.Context, routes []Route, _ map[string]bool) Discovery {
		if !up {
			return Discovery{} // socket-proxy down
		}
		return Discovery{OK: true, Evaluated: map[string]bool{PoolKey(routes[0]): true},
			Pools: map[string][]string{PoolKey(routes[0]): {"172.18.0.5:8080"}}}
	})
	if err := rec.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	up = false
	clk.advance(time.Minute)
	if err := rec.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(*body), "172.18.0.5:8080") {
		t.Fatalf("discovery down within lkgTTL must keep the last-known pool:\n%s", *body)
	}
	if st := rec.RouteStatuses(); st[0].State != RouteLastKnown {
		t.Fatalf("state = %s, want last_known", st[0].State)
	}
	clk.advance(lkgTTL)
	if err := rec.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(*body), "172.18.0.5:8080") || strings.Contains(string(*body), "web:8080") {
		t.Fatalf("past lkgTTL the route must answer 503, dialing nothing:\n%s", *body)
	}
	if st := rec.RouteStatuses(); st[0].State != RouteUnroutable {
		t.Fatalf("state = %s, want unroutable", st[0].State)
	}
}

// Containers being removed are excluded from discovery until they are gone — the exclusion lives in
// the Reconciler, so every reconcile (not just the drain call) honours it.
func TestDrainContainersExcludesFromDiscovery(t *testing.T) {
	rec, _, _, done := newRecWithRoute(t, "web:8080", "http")
	defer done()
	var seen []map[string]bool
	rec.SetPoolDiscoverer(func(_ context.Context, routes []Route, ex map[string]bool) Discovery {
		seen = append(seen, ex)
		return Discovery{OK: true, Evaluated: map[string]bool{PoolKey(routes[0]): true},
			Pools: map[string][]string{PoolKey(routes[0]): {"172.18.0.5:8080"}}}
	})
	if err := rec.DrainContainers(context.Background(), []string{"abc123"}); err != nil {
		t.Fatal(err)
	}
	if err := rec.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 || !seen[0]["abc123"] || !seen[1]["abc123"] {
		t.Fatalf("both reconciles must exclude the draining container: %v", seen)
	}
}

// A reconcile whose discovery is older than one already committed must not overwrite it.
func TestReconcileOlderDiscoveryNeverOverwritesNewer(t *testing.T) {
	rec, body, loads, done := newRecWithRoute(t, "web:8080", "http")
	defer done()
	release := make(chan struct{})
	entered := make(chan struct{})
	var calls int32
	rec.SetPoolDiscoverer(func(_ context.Context, routes []Route, _ map[string]bool) Discovery {
		ip := "172.18.0.9:8080" // the newer discovery
		if atomic.AddInt32(&calls, 1) == 1 {
			close(entered)
			<-release // the first (older) discovery finishes last
			ip = "172.18.0.1:8080"
		}
		return Discovery{OK: true, Evaluated: map[string]bool{PoolKey(routes[0]): true},
			Pools: map[string][]string{PoolKey(routes[0]): {ip}}}
	})
	errc := make(chan error, 1)
	go func() { errc <- rec.Reconcile(context.Background()) }()
	<-entered
	if err := rec.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(loads); got != 1 {
		t.Fatalf("the older discovery must not /load; loads = %d", got)
	}
	if !strings.Contains(string(*body), "172.18.0.9:8080") {
		t.Fatalf("the newer discovery must be what is served:\n%s", *body)
	}
}

// After Caddy is relaunched (it boots on the route-less base config) the next render must be loaded
// even though it is identical to the last one applied.
func TestReloadAfterRestartForcesLoad(t *testing.T) {
	rec, _, loads, done := newRecWithRoute(t, "172.18.0.5:8080", "http")
	defer done()
	if err := rec.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := rec.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(loads); got != 1 {
		t.Fatalf("identical reconciles must skip the load; loads = %d", got)
	}
	rec.ReloadAfterRestart(context.Background())
	if got := atomic.LoadInt32(loads); got != 2 {
		t.Fatalf("a Caddy restart must force a load; loads = %d", got)
	}
}

// State changes reach the status hook once; a steady state only grows its streak.
func TestStatusHookReportsTransitionsOnce(t *testing.T) {
	rec, _, _, done := newRecWithRoute(t, "web:8080", "http")
	defer done()
	var got []StatusChange
	rec.SetStatusHook(func(c []StatusChange) { got = append(got, c...) })
	running := true
	rec.SetPoolDiscoverer(func(_ context.Context, routes []Route, _ map[string]bool) Discovery {
		d := Discovery{OK: true, Evaluated: map[string]bool{PoolKey(routes[0]): true}}
		if running {
			d.Pools = map[string][]string{PoolKey(routes[0]): {"172.18.0.5:8080"}}
		}
		return d
	})
	for i := 0; i < 2; i++ {
		_ = rec.Reconcile(context.Background())
	}
	running = false
	for i := 0; i < 3; i++ {
		_ = rec.Reconcile(context.Background())
	}
	if len(got) != 2 || got[0].Cur.State != RouteRoutable || got[1].Prev.State != RouteRoutable || got[1].Cur.State != RouteUnroutable {
		t.Fatalf("want exactly [→routable, routable→unroutable], got %+v", got)
	}
	if st := rec.RouteStatuses(); st[0].Streak != 3 {
		t.Fatalf("streak = %d, want 3", st[0].Streak)
	}
}

// An https upstream is dialed at the container IP with SNI/verification pinned to the service name.
func TestHTTPSUpstreamDialsIPWithServerName(t *testing.T) {
	rec, body, _, done := newRecWithRoute(t, "api:8443", "https")
	defer done()
	rec.SetPoolDiscoverer(func(_ context.Context, routes []Route, _ map[string]bool) Discovery {
		return Discovery{OK: true, Evaluated: map[string]bool{PoolKey(routes[0]): true},
			Pools: map[string][]string{PoolKey(routes[0]): {"172.18.0.7:8443"}}}
	})
	if err := rec.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	b := strings.Join(strings.Fields(string(*body)), "")
	if !strings.Contains(b, `"dial":"172.18.0.7:8443"`) || !strings.Contains(b, `"server_name":"api"`) {
		t.Fatalf("https must dial the IP with server_name=api:\n%s", b)
	}
	if strings.Contains(b, `"dial":"api:8443"`) {
		t.Fatalf("https must not dial the service name:\n%s", b)
	}
}

// Reconcile is idempotent: re-rendering the same route set (the steady pool-refresh
// case) is byte-identical to the last applied config, so it skips the Caddy /load.
func TestReconcileIdempotentSkipsReload(t *testing.T) {
	var loads int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&loads, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	db, _ := store.Open(filepath.Join(t.TempDir(), "test.db"))
	defer db.Close()
	rs := NewRouteStore(db)
	_ = rs.Save(context.Background(), Route{Hostname: "app.example.com", Upstream: "web:8080", UpstreamScheme: "http", Enabled: true})
	rec := NewReconciler(rs, NewAdmin(ts.Listener.Addr().String()), baseCfg(), quietLog())
	for i := 0; i < 3; i++ {
		if err := rec.Reconcile(context.Background()); err != nil {
			t.Fatalf("reconcile %d: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&loads); got != 1 {
		t.Errorf("3 identical reconciles → %d /load calls, want 1 (idempotent skip)", got)
	}
}

// A non-2xx from the admin (Caddy rejected the config) surfaces as an error; the
// live config is unaffected (Caddy /load is transactional).
func TestLoadRejectionIsError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("bad config"))
	}))
	defer ts.Close()
	a := NewAdmin(ts.Listener.Addr().String())
	if err := a.Load(context.Background(), []byte(`{}`)); err == nil {
		t.Error("a 4xx from the admin must be an error")
	}
}

// A render error (unsafe route) never reaches the admin.
func TestReconcileNeverAppliesUnsafe(t *testing.T) {
	called := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	defer ts.Close()
	db, _ := store.Open(filepath.Join(t.TempDir(), "test.db"))
	defer db.Close()
	rs := NewRouteStore(db)
	// Insert an unsafe row directly (bypassing Save's validation) to prove render
	// is the backstop.
	_, _ = db.Exec(`INSERT INTO app_routes(hostname, upstream, upstream_scheme, enabled, created_at) VALUES('x.example.com','127.0.0.1:2019','http',1,0)`)
	rec := NewReconciler(rs, NewAdmin(ts.Listener.Addr().String()), baseCfg(), quietLog())
	if err := rec.Reconcile(context.Background()); err == nil {
		t.Error("reconcile should fail on an unsafe route")
	}
	if called {
		t.Error("an unsafe config must never be pushed to the admin")
	}
}

// The admin client must NOT follow a redirect (a compromised Caddy could 307 the
// config POST elsewhere) — it surfaces the 3xx as a non-2xx error instead.
func TestAdminDoesNotFollowRedirects(t *testing.T) {
	hit := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit++
		if r.URL.Path == "/load" {
			http.Redirect(w, r, "/elsewhere", http.StatusTemporaryRedirect)
			return
		}
		t.Errorf("redirect was followed to %s", r.URL.Path)
	}))
	defer ts.Close()
	a := NewAdmin(ts.Listener.Addr().String())
	if err := a.Load(context.Background(), []byte(`{}`)); err == nil {
		t.Error("a 3xx must surface as an error, not be followed")
	}
	if hit != 1 {
		t.Errorf("expected exactly one request (no redirect follow), got %d", hit)
	}
}

// Concurrent reconciles must be serialized: no data race on lastGood, and the
// last writer's config is what ends up applied. Run with -race to catch the
// lastGood data race the mutex closes.
func TestReconcileConcurrentIsSerialized(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	db, _ := store.Open(filepath.Join(t.TempDir(), "test.db"))
	defer db.Close()
	rs := NewRouteStore(db)
	if err := rs.Save(context.Background(), Route{Hostname: "app.example.com", Upstream: "web:80", UpstreamScheme: "http", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	rec := NewReconciler(rs, NewAdmin(ts.Listener.Addr().String()), baseCfg(), quietLog())

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = rec.Reconcile(context.Background()) }()
	}
	wg.Wait()
	rec.mu.Lock()
	got := len(rec.lastGood)
	rec.mu.Unlock()
	if got == 0 {
		t.Error("lastGood should hold the latest applied config")
	}
}

// Caddy's admin endpoint enforces an origin allow-list (enforce_origin:
// 127.0.0.1 / ::1 / localhost, no port — see render.go) and checks BOTH the request's
// Host header AND its Origin header. Over a unix socket the DialContext always dials
// the socket (ignoring the URL host), so what Caddy sees is the Host (= base URL host)
// and the Origin header. Both must be in the allow-list: a Host of "unix" → 403 "host
// not allowed: unix"; an empty Origin → 403 "client is not allowed to access from
// origin ”". So base host and origin host must both be allowed.
func TestUnixAdminHostIsAllowedOrigin(t *testing.T) {
	a := NewAdmin("unix//run/mooring/caddy-admin.sock")
	allowed := map[string]bool{"http://127.0.0.1": true, "http://[::1]": true, "http://localhost": true}
	if !allowed[a.base] {
		t.Errorf("unix admin base = %q — its Host is not in Caddy's admin origin allow-list, so /load is 403'd (host not allowed). want one of %v", a.base, allowed)
	}
	if !allowed[a.origin] {
		t.Errorf("unix admin origin = %q — not in Caddy's allow-list, so /load is 403'd (origin ''). want one of %v", a.origin, allowed)
	}
}

// End-to-end: a /load request must carry a non-empty Origin header whose host is in
// Caddy's allow-list (the bare host, no admin port). Without it Caddy 403s "origin ”".
func TestAdminSendsAllowedOriginHeader(t *testing.T) {
	var gotOrigin, gotHost string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOrigin, gotHost = r.Header.Get("Origin"), r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	a := NewAdmin(ts.Listener.Addr().String()) // httptest binds 127.0.0.1:PORT
	if err := a.Load(context.Background(), []byte(`{}`)); err != nil {
		t.Fatalf("load: %v", err)
	}
	if gotOrigin != "http://127.0.0.1" { // host only, NO port (Caddy origins are bare hosts)
		t.Errorf("Origin header = %q, want http://127.0.0.1", gotOrigin)
	}
	if !strings.HasPrefix(gotHost, "127.0.0.1") {
		t.Errorf("Host header = %q, want 127.0.0.1[:port]", gotHost)
	}
}

func TestAvailableFailClosedOffLinux(t *testing.T) {
	ok, why := Available("definitely-not-a-real-binary-xyz")
	if ok {
		t.Skip("host can own the edge")
	}
	if why == "" {
		t.Error("unavailable must carry a reason")
	}
}
