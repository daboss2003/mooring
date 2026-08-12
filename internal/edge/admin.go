package edge

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Admin talks to the child Caddy's admin API — the SINGLE source of truth for its
// config (SBD-2). It is reached ONLY over a unix socket (preferred) or loopback
// :2019; there is no on-disk config Caddy auto-loads. /load is transactional:
// Caddy validates + atomically swaps, and REJECTS a bad document while keeping the
// running config — so a failed apply never takes the edge down (SBD-8 floor).
type Admin struct {
	base   string // http base, e.g. "http://127.0.0.1:2019" or "http://localhost" (unix socket)
	origin string // value for the Origin header — its host MUST be in Caddy's admin
	// origin allow-list (render.go: 127.0.0.1/::1/localhost, no port). Caddy's
	// enforce_origin checks BOTH the Host AND the Origin header; a request with no
	// Origin is rejected 403 "client is not allowed to access from origin ''".
	client *http.Client
}

// NewAdmin builds an admin client for a Caddy admin listen address:
// "unix//run/mooring/caddy-admin.sock" (dialed over the socket) or "127.0.0.1:2019".
func NewAdmin(listen string) *Admin {
	if strings.HasPrefix(listen, "unix/") {
		sock := strings.TrimPrefix(listen, "unix/") // "unix//x" → "/x"
		d := &net.Dialer{Timeout: 5 * time.Second}
		return &Admin{
			// "localhost", NOT "unix": the DialContext below always dials the socket
			// (it ignores the URL host), so this only sets the request's Host header —
			// and Caddy's admin endpoint enforces an origin allow-list (enforce_origin:
			// 127.0.0.1/::1/localhost, see render.go). "http://unix" → Host: unix →
			// 403 "host not allowed: unix"; "localhost" is allowed and is Caddy's own
			// unix-admin convention (curl --unix-socket … http://localhost/…).
			base:   "http://localhost",
			origin: "http://localhost",
			client: &http.Client{
				Timeout:       15 * time.Second,
				CheckRedirect: noRedirect,
				Transport: &http.Transport{
					DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
						return d.DialContext(ctx, "unix", sock)
					},
				},
			},
		}
	}
	// TCP path. Caddy's admin origin allow-list holds BARE hosts (no port), so the
	// Origin header must carry the host without the admin port (the Host header keeps
	// the port for dialing).
	host := listen
	if h, _, err := net.SplitHostPort(listen); err == nil {
		host = h
	}
	originHost := host
	if strings.Contains(originHost, ":") { // IPv6 literal needs brackets in a URL
		originHost = "[" + originHost + "]"
	}
	return &Admin{base: "http://" + listen, origin: "http://" + originHost, client: &http.Client{Timeout: 15 * time.Second, CheckRedirect: noRedirect}}
}

// noRedirect refuses to follow any redirect (consistent with every other Mooring
// outbound client) — a compromised child Caddy must not be able to 307 the config
// POST (which carries the whole edge config) to an attacker endpoint.
func noRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// Load POSTs the WHOLE config document to /load (declarative, never incremental).
// A non-2xx response means Caddy rejected it (the previous config keeps running).
func (a *Admin) Load(ctx context.Context, configJSON []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.base+"/load", bytes.NewReader(configJSON))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", a.origin) // Caddy enforce_origin rejects an empty Origin
	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("edge: admin /load unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return fmt.Errorf("edge: admin rejected config (status %d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// Reconciler renders the WHOLE edge config from the declarative route set and
// pushes it via the admin API. It retains the last-known-good document so a
// caller can revert (SBD-8).
type Reconciler struct {
	store     *RouteStore
	admin     *Admin
	base      BaseConfig
	log       *slog.Logger
	certHosts func() []CertHost // cert-only ACME subjects (spec.cert_bindings) + their CA; may be nil
	// poolFn discovers the live replica endpoints for a set of routes — the auto-scaling
	// edge pool, recomputed from read-only container discovery each reconcile. It returns
	// pools keyed by PoolKey(route); a route absent from the map (or with an empty pool)
	// keeps its single service-name dial and connections DNS-round-robin (the v1 path).
	// It is invoked OUTSIDE the reconcile lock (it does slow socket-proxy I/O) — see
	// Reconcile. nil disables pool discovery entirely.
	poolFn   func(ctx context.Context, routes []Route) map[string][]string
	// accessLog reports whether the edge should emit the per-request access log this render (turned
	// on only while some enabled scaling policy uses a source:edge metric, so an edge with no such
	// metric pays nothing). Consulted per reconcile so it reacts to a deploy WITHOUT a restart. nil
	// = never (the default). See BaseConfig.AccessLog.
	accessLog func() bool
	mu        sync.Mutex // serializes the render→Load→lastGood commit (atomic, last-wins)
	lastGood  []byte
}

// PoolKey identifies the upstream a route's replica pool is computed for — its owning
// app plus its service:port selector. Routes that share an upstream share a pool.
func PoolKey(rt Route) string { return rt.AppID + "|" + rt.Upstream }

// NewReconciler builds a Reconciler.
func NewReconciler(store *RouteStore, admin *Admin, base BaseConfig, log *slog.Logger) *Reconciler {
	return &Reconciler{store: store, admin: admin, base: base, log: log}
}

// SetCertHosts registers a provider for cert-only ACME subjects (hostnames Mooring
// must obtain a cert for without a proxy route — spec.cert_bindings).
func (r *Reconciler) SetCertHosts(fn func() []CertHost) { r.certHosts = fn }

// SetPoolDiscoverer registers the live-replica endpoint discoverer. When set, each
// reconcile asks fn for a route's current replica endpoints (ip:port) and, if it
// returns any, dials that pool (least-conn + passive health, via Render) instead of
// the single service-name upstream. fn must return only endpoints that are safe to
// dial; Render re-validates every member regardless (SBD-4 backstop).
func (r *Reconciler) SetPoolDiscoverer(fn func(ctx context.Context, routes []Route) map[string][]string) {
	r.poolFn = fn
}

// SetAccessLog registers the predicate that decides, per reconcile, whether to render the edge's
// per-request access log (STDOUT JSON, consumed in-process for edge-measured autoscaling). It is
// consulted on every reconcile so enabling a source:edge metric takes effect on the next cycle
// (≤ the refresh cadence) with no restart. nil (the default) means never emit it.
func (r *Reconciler) SetAccessLog(fn func() bool) { r.accessLog = fn }

// renderBase returns the base config for this reconcile, applying the reactive access-log decision.
func (r *Reconciler) renderBase() BaseConfig {
	base := r.base
	if r.accessLog != nil {
		base.AccessLog = r.accessLog()
	}
	return base
}

// ReconcilePool satisfies scale.EdgeReconciler: after the auto-scaler changes a
// service's replica count, re-render the WHOLE edge config (which re-discovers every
// route's live pool) and apply it. The app/service/replicas args are advisory — the
// reconcile recomputes from live container discovery, so it always reflects truth.
func (r *Reconciler) ReconcilePool(ctx context.Context, app, service string, replicas int) error {
	return r.Reconcile(ctx)
}

func (r *Reconciler) certOnly() []CertHost {
	if r.certHosts == nil {
		return nil
	}
	return r.certHosts()
}

// Reconcile renders the current route set and applies it. On a render error
// (an unsafe route) it does NOT touch the live config. On an apply error the
// previous config keeps running (Caddy /load is transactional).
func (r *Reconciler) Reconcile(ctx context.Context) error {
	// Discover the live replica pools FIRST, OUTSIDE the lock: discovery does slow
	// socket-proxy I/O (one container list), and holding the reconcile mutex across it
	// would block a concurrent route-save for the whole call. We snapshot the route set,
	// discover against it, then re-read + render + apply under the lock below.
	var pools map[string][]string
	if r.poolFn != nil {
		if snapshot, err := r.store.List(); err == nil {
			pools = r.poolFn(ctx, snapshot)
		}
		// A list/discovery error just yields no pools → every route falls back to its
		// single service-name dial (fail-safe). It never aborts the reconcile.
	}

	// Serialize the render→Load→lastGood commit. Without this, two concurrent reconciles
	// could have their /load calls complete OUT OF ORDER, landing a stale config after a
	// newer one (and racing lastGood). We re-read the route set HERE (not the snapshot
	// above) so whichever reconcile commits last reflects the current routes and wins; a
	// route added after the snapshot just misses its pool for this one cycle (it gets the
	// single dial now, and its pool on the next reconcile the route-save itself triggers).
	r.mu.Lock()
	defer r.mu.Unlock()
	routes, err := r.store.List()
	if err != nil {
		return fmt.Errorf("edge: list routes: %w", err)
	}
	// Apply discovered pools by upstream identity. An empty/absent pool (discovery error,
	// socket-proxy down, a replica with no IP yet, an https upstream) leaves the route on
	// its single service-name dial — the v1 DNS-round-robin behavior. Discovery is a
	// fail-safe enhancement that never breaks a route; Render re-validates every dial.
	for i := range routes {
		if !routes[i].Enabled {
			continue
		}
		if pool := pools[PoolKey(routes[i])]; len(pool) > 0 {
			routes[i].Pool = pool
		}
	}
	cfg, err := Render(r.renderBase(), routes, r.certOnly())
	if err != nil {
		return fmt.Errorf("edge: render: %w", err) // unsafe route → never applied
	}
	// Idempotent: if the rendered document is byte-identical to the last applied one
	// (the common case for the periodic pool refresh when the replica set is stable),
	// skip the /load — Mooring is the sole source of truth for Caddy's config, so a
	// matching render means the live config is already correct. Avoids needless reloads.
	if bytes.Equal(cfg, r.lastGood) {
		return nil
	}
	if err := r.admin.Load(ctx, cfg); err != nil {
		return err
	}
	r.lastGood = cfg
	return nil
}

// RevertToLastGood re-applies the last successfully-loaded config (SBD-8 recovery
// path; the typed base render is the floor when there is no last-good yet).
func (r *Reconciler) RevertToLastGood(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	cfg := r.lastGood
	if cfg == nil {
		var err error
		if cfg, err = Render(r.renderBase(), nil, nil); err != nil {
			return err
		}
	}
	return r.admin.Load(ctx, cfg)
}
