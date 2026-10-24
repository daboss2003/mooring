package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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
		return &ConfigRejectedError{Status: resp.StatusCode, Body: strings.TrimSpace(string(body))}
	}
	return nil
}

// ConfigRejectedError is Caddy refusing a config at /load — as opposed to its admin API being
// unreachable (a transport error).
type ConfigRejectedError struct {
	Status int
	Body   string
}

func (e *ConfigRejectedError) Error() string {
	return fmt.Sprintf("edge: admin rejected config (status %d): %s", e.Status, e.Body)
}

// Discovery is one container-discovery pass over the route set (see SetPoolDiscoverer).
type Discovery struct {
	// Pools maps PoolKey(route) → the sorted ip:port endpoints of the running containers behind it.
	// An Evaluated key with no entry means discovery ran and found no routable running container.
	Pools map[string][]string
	// Evaluated is the set of PoolKeys the pass looked up. A route saved after the pass took its route
	// snapshot is absent — it gets its pool on the next reconcile (the save triggers one).
	Evaluated map[string]bool
	// OK is false when discovery itself failed (socket-proxy down, list error): no container
	// information at all, as opposed to "listed fine, nothing running".
	OK bool
}

// RouteState is how the edge currently serves a route.
type RouteState string

const (
	RouteRoutable   RouteState = "routable"   // proxies to discovered container addresses
	RouteLastKnown  RouteState = "last_known" // discovery unavailable: proxies to the addresses it last confirmed (≤ lkgTTL old)
	RouteUnroutable RouteState = "unroutable" // no running container, or discovery unavailable past lkgTTL: answers 503
	RoutePending    RouteState = "pending"    // saved after this pass's discovery ran: 503 until the next reconcile
)

// RouteStatus is the served state of one enabled route after the last committed reconcile.
type RouteStatus struct {
	Hostname   string
	PathPrefix string
	AppID      string
	Upstream   string // the service:port selector
	State      RouteState
	Dials      []string // what Caddy was given (routable / last_known only)
	Reason     string
	Since      time.Time // when the route entered State
	Streak     int       // consecutive committed reconciles in State
}

// StatusChange is a route whose State changed in a committed reconcile. Prev is the zero value for a
// route seen for the first time.
type StatusChange struct{ Prev, Cur RouteStatus }

const (
	// lkgTTL bounds how long a route keeps dialing its last-confirmed addresses while discovery is down:
	// a container recreated meanwhile gets a new IP the edge can't learn, and its old IP can be reused by
	// another container on the same network. Past this the route answers 503 instead.
	lkgTTL = 5 * time.Minute
	// drainTTL bounds how long a container marked for removal stays excluded from discovery.
	drainTTL = 2 * time.Minute
)

type lkgPool struct {
	dials     []string
	confirmed time.Time
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
	// poolFn discovers the running container endpoints behind each route from the read-only container
	// list, excluding the given (draining) container ids. It runs OUTSIDE the reconcile lock (slow
	// socket-proxy I/O) — see Reconcile. Routes are only ever dialed at discovered addresses: with no
	// poolFn a route whose upstream is a service name has nothing to dial and answers 503.
	poolFn func(ctx context.Context, routes []Route, exclude map[string]bool) Discovery
	// accessLog reports whether the edge should emit the per-request access log this render (turned
	// on only while some enabled scaling policy uses a source:edge metric, so an edge with no such
	// metric pays nothing). Consulted per reconcile so it reacts to a deploy WITHOUT a restart. nil
	// = never (the default). See BaseConfig.AccessLog.
	accessLog func() bool
	// catchAllOK reports whether a namespace apex STILL has operator consent (+ dns01) for a catch-all
	// route, right now. Consulted per reconcile so revoking consent (`catch_all: false`) or dropping
	// dns01 drops a STORED catch-all at the next cycle WITHOUT a redeploy — the gate at apply time only
	// covers when a route is (re)applied, so without this a stored catch-all would keep serving after
	// the operator revoked it (fail-open). nil = don't re-check (every catch-all kept).
	catchAllOK func(apex string) bool
	// wildcards, when set, returns the DNS-01 wildcards to render THIS cycle — only the namespaces
	// whose DNS plugin is in the running Caddy. Consulted per reconcile so a plugin installed after
	// Mooring started (a background install + edge restart) brings its wildcard in without restarting
	// Mooring. A wildcard whose module the binary lacks would make Caddy reject the whole /load, so it
	// must never be rendered early. nil = base.Wildcards as built at start.
	wildcards func() []WildcardCert
	// onWildcardReject, when set, is told about each wildcard Caddy refused (and its error, with every
	// dns01 token redacted) — see loadWithoutWildcards. Called UNDER r.mu, so the owner's wildcards hook
	// already leaves the refused one out of the next reconcile; it must not call back into the Reconciler.
	onWildcardReject func(w WildcardCert, err error)
	// onStatus receives the routes whose served state changed in a committed reconcile. Called after
	// the lock is released; it must not call back into the Reconciler synchronously.
	onStatus func([]StatusChange)
	now      func() time.Time // test clock; nil = time.Now

	// hooksMu guards poolFn and onStatus: they are wired after the Caddy supervisor has started, and a
	// Caddy launch reconciles from its own goroutine.
	hooksMu sync.RWMutex

	gen atomic.Uint64 // discovery generation, taken before each discovery starts

	mu           sync.Mutex // serializes the render→Load→lastGood commit (atomic, last-wins)
	lastGood     []byte
	committedGen uint64                 // generation of the discovery behind the committed render
	lkg          map[string]lkgPool     // PoolKey → last confirmed endpoints
	status       map[string]RouteStatus // routeKey → served state

	dmu      sync.Mutex
	draining map[string]time.Time // container id → exclusion expiry
}

func (r *Reconciler) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// routeKey identifies a route for status tracking (hostnames are unique per path prefix).
func routeKey(rt Route) string {
	return strings.ToLower(strings.TrimSpace(rt.Hostname)) + "\x00" + rt.PathPrefix
}

// upstreamService is the service half of a service:port selector.
func upstreamService(up string) string {
	if host, _, err := net.SplitHostPort(up); err == nil {
		return host
	}
	return up
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

// SetPoolDiscoverer registers the container-endpoint discoverer. Each reconcile asks fn for every
// route's running container endpoints (ip:port) and dials exactly those (a pool of >1 gets least-conn +
// passive health, via Render). fn must skip the excluded (draining) container ids and return only
// endpoints that are safe to dial; Render re-validates every member regardless (SBD-4 backstop).
func (r *Reconciler) SetPoolDiscoverer(fn func(ctx context.Context, routes []Route, exclude map[string]bool) Discovery) {
	r.hooksMu.Lock()
	r.poolFn = fn
	r.hooksMu.Unlock()
}

// SetStatusHook registers fn to receive the routes whose served state changed in a committed
// reconcile (e.g. to log the transition and raise/resolve an alert). fn runs after the reconcile lock
// is released and must not call back into the Reconciler synchronously.
func (r *Reconciler) SetStatusHook(fn func([]StatusChange)) {
	r.hooksMu.Lock()
	r.onStatus = fn
	r.hooksMu.Unlock()
}

// hooks returns the currently wired discoverer and status hook.
func (r *Reconciler) hooks() (func(ctx context.Context, routes []Route, exclude map[string]bool) Discovery, func([]StatusChange)) {
	r.hooksMu.RLock()
	defer r.hooksMu.RUnlock()
	return r.poolFn, r.onStatus
}

// RouteStatuses returns the served state of every enabled route as of the last committed reconcile,
// sorted by hostname then path prefix.
func (r *Reconciler) RouteStatuses() []RouteStatus {
	r.mu.Lock()
	out := make([]RouteStatus, 0, len(r.status))
	for _, st := range r.status {
		cp := st
		cp.Dials = append([]string(nil), st.Dials...)
		out = append(out, cp)
	}
	r.mu.Unlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Hostname != out[j].Hostname {
			return out[i].Hostname < out[j].Hostname
		}
		return out[i].PathPrefix < out[j].PathPrefix
	})
	return out
}

// DrainContainers stops the edge dialing the given containers ahead of their removal, and re-applies
// the config now. The exclusion lives inside the Reconciler (so a concurrent reconcile can't put the
// containers back) and expires after drainTTL.
func (r *Reconciler) DrainContainers(ctx context.Context, ids []string) error {
	r.dmu.Lock()
	if r.draining == nil {
		r.draining = map[string]time.Time{}
	}
	exp := r.clock().Add(drainTTL)
	for _, id := range ids {
		if id != "" {
			r.draining[id] = exp
		}
	}
	r.dmu.Unlock()
	return r.Reconcile(ctx)
}

// UndrainContainers puts containers back into discovery (a removal that was drained for failed, so the
// copy is still running and should serve again) and re-applies the config now.
func (r *Reconciler) UndrainContainers(ctx context.Context, ids []string) error {
	r.dmu.Lock()
	for _, id := range ids {
		delete(r.draining, id)
	}
	r.dmu.Unlock()
	return r.Reconcile(ctx)
}

// drainingSet is the current, unexpired draining set (expired entries are pruned).
func (r *Reconciler) drainingSet() map[string]bool {
	r.dmu.Lock()
	defer r.dmu.Unlock()
	if len(r.draining) == 0 {
		return nil
	}
	now := r.clock()
	out := make(map[string]bool, len(r.draining))
	for id, exp := range r.draining {
		if now.After(exp) {
			delete(r.draining, id)
			continue
		}
		out[id] = true
	}
	return out
}

// ReloadAfterRestart re-feeds a freshly (re)launched Caddy. A relaunched child boots on the route-less
// base config while lastGood still holds the full document, so an unchanged render would be skipped as
// already applied and every app host would answer 404 until something changed. Clearing lastGood forces
// the next render to /load; the new admin API takes a moment to answer, so this retries for up to a
// minute (the periodic refresher keeps trying after that).
func (r *Reconciler) ReloadAfterRestart(ctx context.Context) {
	r.mu.Lock()
	r.lastGood = nil
	r.mu.Unlock()
	deadline := time.Now().Add(time.Minute)
	for {
		rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		err := r.Reconcile(rctx)
		cancel()
		if err == nil {
			return
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			if r.log != nil {
				r.log.Warn("edge: could not re-apply the config after a Caddy restart; the refresher will retry", "err", err)
			}
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}

// SetAccessLog registers the predicate that decides, per reconcile, whether to render the edge's
// per-request access log (STDOUT JSON, consumed in-process for edge-measured autoscaling). It is
// consulted on every reconcile so enabling a source:edge metric takes effect on the next cycle
// (≤ the refresh cadence) with no restart. nil (the default) means never emit it.
func (r *Reconciler) SetAccessLog(fn func() bool) { r.accessLog = fn }

// SetWildcards registers the per-reconcile DNS-01 wildcard set (see wildcards).
func (r *Reconciler) SetWildcards(fn func() []WildcardCert) { r.wildcards = fn }

// SetWildcardReject registers the hook told about each wildcard Caddy refused (see onWildcardReject).
// The owner must stop offering it (SetWildcards), or every reconcile would try it again.
func (r *Reconciler) SetWildcardReject(fn func(w WildcardCert, err error)) {
	r.onWildcardReject = fn
}

// SetCatchAllConsent registers the live operator-consent check for catch-all routes (see catchAllOK):
// a stored `*.apex` catch-all is dropped at the next reconcile if its namespace no longer consents.
func (r *Reconciler) SetCatchAllConsent(fn func(apex string) bool) { r.catchAllOK = fn }

// keepCatchAlls drops any stored catch-all route whose namespace has lost operator consent (or dns01),
// so a revoked catch-all stops serving at the next reconcile rather than lingering until a redeploy.
// A non-catch-all route is always kept. With no consent hook wired, every route is kept (no re-check).
func (r *Reconciler) keepCatchAlls(routes []Route) []Route {
	if r.catchAllOK == nil {
		return routes
	}
	kept := routes[:0]
	for _, rt := range routes {
		if rt.CatchAll {
			apex := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(rt.Hostname)), "*.")
			if !r.catchAllOK(apex) {
				continue // consent/dns01 revoked → drop; the names fall back to the default 404
			}
		}
		kept = append(kept, rt)
	}
	return kept
}

// renderBase returns the base config for this reconcile, applying the reactive access-log decision.
func (r *Reconciler) renderBase() BaseConfig {
	base := r.base
	if r.accessLog != nil {
		base.AccessLog = r.accessLog()
	}
	if r.wildcards != nil {
		base.Wildcards = r.wildcards()
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
	// Discover the running containers FIRST, OUTSIDE the lock: discovery does slow socket-proxy I/O
	// (one container list), and holding the reconcile mutex across it would block a concurrent
	// route-save for the whole call. The generation is taken before discovery starts, so a reconcile
	// whose discovery began later is recognisably newer.
	gen := r.gen.Add(1)
	poolFn, onStatus := r.hooks()
	var disc Discovery
	if poolFn != nil {
		if snapshot, err := r.store.List(); err == nil {
			disc = poolFn(ctx, snapshot, r.drainingSet())
		}
		// A route-list error leaves disc.OK false: handled exactly like discovery being unavailable.
	}

	// Serialize the render→Load→lastGood commit. Without this, two concurrent reconciles could have
	// their /load calls complete OUT OF ORDER, landing a stale config after a newer one. The route set is
	// re-read HERE so whichever reconcile commits reflects the current routes.
	r.mu.Lock()
	if gen < r.committedGen {
		// A reconcile whose discovery started after this one's has already committed: this discovery is
		// older than what the edge serves now, and applying it could only move the edge backwards.
		r.mu.Unlock()
		return nil
	}
	routes, err := r.store.List()
	if err != nil {
		r.mu.Unlock()
		return fmt.Errorf("edge: list routes: %w", err)
	}
	// Drop a stored catch-all whose namespace has lost consent/dns01 since it was applied, so a
	// revoked catch-all stops serving now rather than lingering until the app redeploys (fail-open).
	routes = r.keepCatchAlls(routes)
	now := r.clock()
	lkg, status, changes := r.plan(routes, disc, poolFn != nil, now)
	base := r.renderBase()
	cfg, err := Render(base, routes, r.certOnly())
	if err != nil {
		r.mu.Unlock()
		return fmt.Errorf("edge: render: %w", err) // unsafe route → never applied
	}
	// Idempotent: a render byte-identical to the last applied one (the common case for the periodic
	// refresh when nothing moved) skips the /load — Mooring is the sole source of Caddy's config.
	var rejected []wildcardRejection
	if !bytes.Equal(cfg, r.lastGood) {
		if err := r.admin.Load(ctx, cfg); err != nil {
			applied, rej, lerr := r.loadWithoutWildcards(ctx, base, routes, cfg, err)
			if lerr != nil {
				r.mu.Unlock()
				return redactTokens(lerr, base.Wildcards)
			}
			rejected, cfg = rej, applied
		}
		r.lastGood = cfg
	}
	r.committedGen = gen
	r.lkg, r.status = lkg, status
	// The owner records each refusal before the lock is released, so a concurrent reconcile already
	// leaves the refused wildcard out instead of running the whole isolation again.
	for i := range rejected {
		rejected[i].err = redactTokens(rejected[i].err, base.Wildcards)
		if r.onWildcardReject != nil {
			r.onWildcardReject(rejected[i].w, rejected[i].err)
		}
	}
	r.mu.Unlock()
	for _, rj := range rejected {
		if r.log != nil {
			r.log.Error("edge: Caddy rejected the DNS-01 wildcard config; serving every route without this wildcard",
				"wildcard", "*."+rj.w.Domain, "provider", rj.w.DNS01Provider, "err", rj.err)
		}
	}
	if onStatus != nil && len(changes) > 0 {
		onStatus(changes)
	}
	return nil
}

// wildcardRejection is one wildcard Caddy refused, with Caddy's error (not yet redacted).
type wildcardRejection struct {
	w   WildcardCert
	err error
}

// loadWithoutWildcards handles a rejected /load of full. A DNS-01 wildcard is the one part of the config
// whose validity depends on a provider module Mooring doesn't control (its field names, the token's
// format): if Caddy refuses a render that carries wildcards, the same render WITHOUT them is loaded so
// every route keeps working, instead of the edge being stuck on its previous (or empty boot) config.
// To tell a wildcard problem from a transient one (the admin API answering 4xx while a restarted child
// settles), the full render is tried once more after the bare one loads. If Caddy refuses it again, the
// wildcards are added back one at a time on top of the ones it accepted, so one namespace's bad config
// doesn't take another namespace's wildcard down with it; a wildcard is blamed only when Caddy refuses
// it twice. It returns the config now applied and the wildcards Caddy refused, or the error to give up
// with. Called under r.mu.
func (r *Reconciler) loadWithoutWildcards(ctx context.Context, base BaseConfig, routes []Route, full []byte, loadErr error) (applied []byte, rejected []wildcardRejection, err error) {
	var rej *ConfigRejectedError
	if len(base.Wildcards) == 0 || !errors.As(loadErr, &rej) {
		return nil, nil, loadErr
	}
	nb := base
	nb.Wildcards = nil
	bare, rerr := Render(nb, routes, r.certOnly())
	if rerr != nil {
		return nil, nil, loadErr
	}
	if lerr := r.admin.Load(ctx, bare); lerr != nil {
		return nil, nil, loadErr // not the wildcards' fault: the bare config doesn't load either
	}
	if lerr := r.admin.Load(ctx, full); lerr == nil {
		return full, nil, nil // the first rejection was transient
	} else if !errors.As(lerr, &rej) {
		// Can't pin it (the admin API went away mid-check). The bare config stays loaded and nothing is
		// reported; the next reconcile tries the full render again.
		return bare, nil, nil
	}
	applied = bare
	var accepted []WildcardCert
	for _, w := range base.Wildcards {
		nb.Wildcards = append(append([]WildcardCert(nil), accepted...), w)
		cfg, rerr := Render(nb, routes, r.certOnly())
		if rerr != nil {
			rejected = append(rejected, wildcardRejection{w, rerr})
			continue
		}
		lerr := r.admin.Load(ctx, cfg)
		if errors.As(lerr, &rej) {
			lerr = r.admin.Load(ctx, cfg)
		}
		switch {
		case lerr == nil:
			accepted, applied = nb.Wildcards, cfg
		case errors.As(lerr, &rej):
			rejected = append(rejected, wildcardRejection{w, lerr})
		default:
			// The admin API went away mid-check: keep what is loaded and report only the wildcards already
			// pinned; the next reconcile tries the rest again.
			return applied, rejected, nil
		}
	}
	return applied, rejected, nil
}

// redactTokens removes every dns01 api_token of ws from a Caddy rejection's text. A provider module may
// echo the token in its error (caddy-dns/cloudflare prints one whose format it doesn't accept), and these
// errors reach the journal, deploy logs, the dashboard and alert channels. Other errors can't carry the
// rendered config and are returned unchanged.
func redactTokens(err error, ws []WildcardCert) error {
	var rej *ConfigRejectedError
	if err == nil || !errors.As(err, &rej) {
		return err
	}
	body := rej.Body
	for _, w := range ws {
		for _, form := range tokenForms(w.DNS01Token) {
			body = strings.ReplaceAll(body, form, "[redacted]")
		}
	}
	if body == rej.Body {
		return err
	}
	return &ConfigRejectedError{Status: rej.Status, Body: body}
}

// NewRedactWriter returns a writer that passes everything to w with each secret (in every tokenForms
// form) replaced by "[redacted]". Output is held back until the end of a line, so a secret split across
// two writes is still caught; a line longer than 64 KiB is passed on unredacted at that point. Flush
// writes out a final partial line. With no non-empty secret it returns w itself.
func NewRedactWriter(w io.Writer, secrets []string) io.Writer {
	var forms []string
	for _, s := range secrets {
		forms = append(forms, tokenForms(s)...)
	}
	if len(forms) == 0 {
		return w
	}
	sort.Slice(forms, func(i, j int) bool { return len(forms[i]) > len(forms[j]) })
	return &redactWriter{w: w, forms: forms}
}

type redactWriter struct {
	mu    sync.Mutex
	w     io.Writer
	forms []string
	buf   []byte
}

const redactLineMax = 64 << 10

func (r *redactWriter) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.buf = append(r.buf, p...)
	cut := bytes.LastIndexByte(r.buf, '\n') + 1
	if cut == 0 {
		if len(r.buf) < redactLineMax {
			return len(p), nil // wait for the end of the line
		}
		cut = len(r.buf)
	}
	err := r.emit(r.buf[:cut])
	r.buf = append(r.buf[:0], r.buf[cut:]...)
	return len(p), err
}

// Flush writes out (redacted) whatever partial line is held back.
func (r *redactWriter) Flush() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.buf) == 0 {
		return nil
	}
	err := r.emit(r.buf)
	r.buf = r.buf[:0]
	return err
}

func (r *redactWriter) emit(b []byte) error {
	s := string(b)
	for _, f := range r.forms {
		s = strings.ReplaceAll(s, f, "[redacted]")
	}
	_, err := io.WriteString(r.w, s)
	return err
}

// tokenForms is how a token can appear in Caddy's JSON error body: as is, JSON-escaped, and trimmed. A
// blank token has none (replacing whitespace would mangle every line).
func tokenForms(tok string) []string {
	if strings.TrimSpace(tok) == "" {
		return nil
	}
	var out []string
	add := func(s string) {
		if s == "" {
			return
		}
		for _, o := range out {
			if o == s {
				return
			}
		}
		out = append(out, s)
	}
	add(tok)
	if b, err := json.Marshal(tok); err == nil {
		add(strings.TrimSuffix(strings.TrimPrefix(string(b), `"`), `"`))
	}
	add(strings.TrimSpace(tok))
	// Longest first, so a form that contains another is replaced whole.
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

// plan decides, for every enabled route, what the edge dials — setting routes[i].Pool or
// routes[i].Unroutable — and returns the next last-known-good pools, the route statuses, and the
// routes whose state changed. It never lets a route fall back to its service-name upstream. Called
// under r.mu.
func (r *Reconciler) plan(routes []Route, disc Discovery, discovering bool, now time.Time) (map[string]lkgPool, map[string]RouteStatus, []StatusChange) {
	lkg := make(map[string]lkgPool, len(r.lkg))
	for k, v := range r.lkg {
		lkg[k] = v
	}
	status := make(map[string]RouteStatus, len(routes))
	live := map[string]bool{}
	var changes []StatusChange
	for i := range routes {
		rt := &routes[i]
		if !rt.Enabled {
			continue
		}
		key := PoolKey(*rt)
		live[key] = true
		st := RouteStatus{Hostname: rt.Hostname, PathPrefix: rt.PathPrefix, AppID: rt.AppID, Upstream: rt.Upstream}
		svc := rt.AppID + "/" + upstreamService(rt.Upstream)
		pool := disc.Pools[key]
		prev, havePrev := lkg[key]
		fresh := havePrev && now.Sub(prev.confirmed) < lkgTTL
		switch {
		case len(rt.dials()) > 0:
			// The upstream is already an IP literal (tests, hand-seeded routes): nothing to discover.
			st.State, st.Dials = RouteRoutable, rt.dials()
		case !discovering:
			rt.Unroutable = true
			st.State, st.Reason = RouteUnroutable, "container discovery is not configured"
		case disc.OK && disc.Evaluated[key] && len(pool) > 0:
			rt.Pool = pool
			lkg[key] = lkgPool{dials: pool, confirmed: now}
			st.State, st.Dials = RouteRoutable, pool
		case disc.OK && disc.Evaluated[key]:
			delete(lkg, key)
			rt.Unroutable = true
			st.State, st.Reason = RouteUnroutable, "no running container for "+svc
		case disc.OK && fresh:
			// Saved after this pass's route snapshot, but an identical upstream was confirmed recently.
			rt.Pool = prev.dials
			st.State, st.Dials, st.Reason = RouteLastKnown, prev.dials, "awaiting the next discovery"
		case disc.OK:
			rt.Unroutable = true
			st.State, st.Reason = RoutePending, "awaiting the next discovery"
		case fresh:
			rt.Pool = prev.dials
			st.State, st.Dials = RouteLastKnown, prev.dials
			st.Reason = "container discovery unavailable; using the addresses confirmed at " + prev.confirmed.UTC().Format("15:04:05 UTC")
		default:
			rt.Unroutable = true
			st.State, st.Reason = RouteUnroutable, "container discovery unavailable"
		}
		k := routeKey(*rt)
		if old, ok := r.status[k]; ok && old.State == st.State {
			st.Since, st.Streak = old.Since, old.Streak+1
		} else {
			st.Since, st.Streak = now, 1
			changes = append(changes, StatusChange{Prev: old, Cur: st})
		}
		status[k] = st
	}
	for k := range lkg {
		if !live[k] {
			delete(lkg, k) // the route is gone
		}
	}
	return lkg, status, changes
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
