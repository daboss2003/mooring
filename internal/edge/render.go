// Package edge owns the managed edge (plan §6): Mooring supervises a child Caddy
// and is the SINGLE SOURCE OF TRUTH for its config via the admin API. The config
// is NEVER stored as text — this package RENDERS the whole Caddy JSON document
// from typed structs (SBD-7), baking in the secure-by-default baseline (§6.1):
// admin on loopback/unix only, no admin vhost unless explicitly configured (and
// then IP-allowlist-first), ACME pinned to one CA for only the configured app
// hostnames, no wildcard/catch-all proxy, and NO upstream may target a
// control-plane port (struct-validated AND re-checked at render).
package edge

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// controlPorts are Mooring's own ports; an edge upstream may NEVER target them
// (SBD-4). The admin-vhost→:9000 route is injected by Mooring, not via this set.
var controlPorts = map[string]bool{"9000": true, "2019": true, "2375": true}

var (
	hostnameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62})(\.[a-z0-9]([a-z0-9-]{0,62}))+$`)
	upHostRe   = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	pathRe     = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$`)
)

// Route is one operator-desired edge vhost (Layer 1, from app_routes).
type Route struct {
	id              int64 // row id (RouteStore-managed)
	AppID           string
	Hostname        string
	Upstream        string   // host:port of the app endpoint (single-replica)
	Pool            []string // host:port of each live replica (M14 auto-scaling); overrides Upstream when set
	UpstreamScheme  string   // http | https
	PathPrefix      string
	RedirectHTTP    bool
	HSTS            bool
	SecurityHeaders bool
	Enabled         bool
	CA              string // "" = default issuer (BaseConfig.ACMECA); else a BaseConfig.CAs name
	// Unroutable, set by the Reconciler (never persisted), renders the route as a 503 instead of a
	// proxy: its (app, service) has no running container to dial. The host matcher, security headers
	// and ACME subject stay, so the certificate keeps renewing and the host answers 503, not 404.
	Unroutable bool
}

// CA is an additional ACME issuer (a private/internal CA) a subject can opt into by
// Name. Mapped from config.yaml edge.cas.
type CA struct {
	Name         string
	DirectoryURL string
	Email        string   // "" → falls back to BaseConfig.ACMEEmail
	TrustedRoots []string // PEM file paths Caddy trusts for the CA's own https ("" → system roots)
}

// BaseConfig is Layer 0 — the protected base, injected from typed config (never
// operator text).
type BaseConfig struct {
	AdminListen    string   // "unix//run/mooring/caddy-admin.sock" or "127.0.0.1:2019"
	ACMEEmail      string   // pinned ACME contact
	ACMECA         string   // pinned default issuer directory URL
	CAs            []CA     // extra named issuers (private CAs) a subject can opt into
	AdminHostname  string   // "" = NO admin vhost (reach the UI via SSH tunnel)
	AdminAllowlist []string // IP-allowlist CIDRs for the admin vhost (typed, mandatory if AdminHostname set)
	AdminUpstream  string   // the ONLY loopback upstream, identity-pinned (e.g. 127.0.0.1:9000)
	// Wildcards enable OPTIONAL *.<Domain> wildcard certs via ACME DNS-01 — one entry per
	// operator-declared subdomain namespace (the default base_domain and each edge.base_domains)
	// that sets dns01. Any default-CA subject at/under a wildcard's Domain is served by that
	// wildcard (dropped from per-name HTTP-01 issuance). Empty slice = all per-name HTTP-01.
	Wildcards []WildcardCert
	// AccessLog, when true, makes the edge emit a per-request JSON access log to STDOUT (captured
	// in-process by the supervisor for the latency aggregator) while keeping Caddy's own logs +
	// errors on STDERR (→ journald). Enabled only when a scaled service opts into an edge metric,
	// so most edges pay nothing for it.
	AccessLog bool
}

// WildcardCert is one *.<Domain> DNS-01 wildcard: a namespace apex + the DNS provider
// credentials that answer its ACME DNS-01 challenge. The provider module must be compiled into
// the caddy binary (Mooring installs it via `caddy add-package`).
type WildcardCert struct {
	Domain        string
	DNS01Provider string // caddy DNS module name
	DNS01Token    string // provider credential (secret)
}

// dials returns the addresses this route proxies to: the discovered container endpoints (Pool). The
// stored Upstream is a compose SERVICE-NAME selector ("web:3000") that the host process running Caddy
// cannot resolve — only Docker's per-network DNS can — so it is dialed ONLY when its host is already an
// IP literal. A route with no dial is rendered as a 503 (see unavailableHandler); the edge never asks
// the host resolver for a service name, which could fail (502) or answer with the wrong container.
func (r Route) dials() []string {
	if len(r.Pool) > 0 {
		return r.Pool
	}
	if host, _, err := net.SplitHostPort(r.Upstream); err == nil {
		if _, perr := netip.ParseAddr(host); perr == nil {
			return []string{r.Upstream}
		}
	}
	return nil
}

// upstreamServiceName is the host part of the service:port selector — the name an https upstream's
// certificate is verified against when the edge dials the container's IP.
func (r Route) upstreamServiceName() string {
	host, _, err := net.SplitHostPort(r.Upstream)
	if err != nil {
		return ""
	}
	if _, perr := netip.ParseAddr(host); perr == nil {
		return "" // already an IP: verify against the dial host as usual
	}
	return host
}

// unavailableHandler is the response for a route with no container to dial: a fixed 503 with
// Retry-After. The body is constant — it names no app, service or address.
func unavailableHandler() caddyHandler {
	return caddyHandler{
		Handler:    "static_response",
		StatusCode: 503,
		StaticHeaders: map[string][]string{
			"Content-Type":  {"text/plain; charset=utf-8"},
			"Cache-Control": {"no-store"},
			"Retry-After":   {"5"},
		},
		Body: "503 Service Unavailable\n",
	}
}

// ValidateRoute enforces every route-level safety rule (SBD-4). Returns the first
// violation. A wildcard/catch-all hostname is rejected; an upstream targeting a
// control-plane port or a loopback/link-local literal IP is rejected.
func ValidateRoute(r Route) error {
	h := strings.ToLower(strings.TrimSpace(r.Hostname))
	if len(h) > 253 || !hostnameRe.MatchString(h) {
		return fmt.Errorf("hostname %q is invalid (must be a fully-qualified DNS name, no wildcards)", r.Hostname)
	}
	if r.UpstreamScheme != "http" && r.UpstreamScheme != "https" {
		return fmt.Errorf("upstream_scheme must be http or https")
	}
	// The stored upstream selector AND every address the route may dial are validated (SBD-4). The
	// selector is checked even though it is never dialed itself: it names the port every discovered
	// replica is dialed on, and an unsafe one (a control-plane port, a loopback name) is rejected
	// outright rather than being quietly rendered as a 503.
	if err := validateUpstream(r.Upstream); err != nil {
		return err
	}
	for _, d := range r.Pool {
		if err := validateUpstream(d); err != nil {
			return err
		}
		// A pool holds discovered container addresses only — never a name the edge would have to
		// resolve (the host resolver can't answer compose names, and could answer wrongly).
		if host, _, err := net.SplitHostPort(d); err != nil {
			return fmt.Errorf("pool member %q must be ip:port", d)
		} else if _, perr := netip.ParseAddr(host); perr != nil {
			return fmt.Errorf("pool member %q is not an IP address", d)
		}
	}
	if r.PathPrefix != "" && (!pathRe.MatchString(r.PathPrefix) || strings.Contains(r.PathPrefix, "..")) {
		return fmt.Errorf("path_prefix %q is invalid", r.PathPrefix)
	}
	return nil
}

// validateUpstream rejects a control-plane port and any loopback/link-local
// literal-IP target (the admin upstream is injected separately, never here).
func validateUpstream(up string) error {
	host, port, err := net.SplitHostPort(strings.TrimSpace(up))
	if err != nil {
		return fmt.Errorf("upstream %q must be host:port", up)
	}
	if controlPorts[port] {
		return fmt.Errorf("upstream %q targets a reserved control-plane port", up)
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("upstream %q has an invalid port", up)
	}
	if host == "" || !upHostRe.MatchString(host) {
		return fmt.Errorf("upstream host %q is invalid", up)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("upstream %q targets a loopback/link-local address (control-plane reachable)", up)
		}
	} else if isLoopbackHostname(host) {
		// A literal-IP check alone misses host NAMES that resolve to loopback
		// (e.g. localhost) — reject the well-known ones. The DEFINITIVE backstop
		// for an arbitrary DNS name (or a rebind) that resolves to loopback at dial
		// time is the edge slice's egress firewall (plan §6, OS layer): 9000/2019/
		// 2375 + loopback are physically unreachable from the edge.
		return fmt.Errorf("upstream %q targets a loopback hostname", up)
	}
	return nil
}

// isLoopbackHostname reports whether a (non-literal-IP) host name is a well-known
// loopback alias.
func isLoopbackHostname(host string) bool {
	h := strings.ToLower(host)
	return h == "localhost" || strings.HasSuffix(h, ".localhost") ||
		h == "ip6-localhost" || h == "ip6-loopback"
}

// Render builds the whole Caddy JSON document from the base + the enabled routes
// (Layer 0 protected base ⊕ Layer 1 per-app routes). The edge config is ALWAYS
// rendered from these typed structs — the operator never authors Caddy config
// (neither a file nor a portal field); everything originates from mooring.yaml /
// the typed route model. It re-validates every route (defense in depth) and FAILS
// if any is unsafe — a bad route can never become a partially-applied config.
// certOnly are hostnames Caddy must obtain+renew an ACME cert for WITHOUT a proxy
// route — a consumer app (e.g. an MQTT broker) terminates TLS itself using the synced
// cert (spec.cert_bindings). Caddy still answers the ACME challenge on :80/:443.
// CertHost is a cert-only ACME subject (a cert binding's hostname) + the named CA it
// should be issued from ("" = the default issuer).
type CertHost struct {
	Hostname string
	CA       string
}

// bySpecificity orders routes so Caddy, which stops at the first matching terminal route,
// tries a hostname's longest path prefix first: /socket.io wins over / whatever order the
// routes were stored in. Hosts keep their first-appearance order (distinct hosts never
// overlap), and equal-length prefixes keep their relative order.
func bySpecificity(routes []Route) []Route {
	hostRank := map[string]int{}
	for _, r := range routes {
		h := strings.ToLower(strings.TrimSpace(r.Hostname))
		if _, ok := hostRank[h]; !ok {
			hostRank[h] = len(hostRank)
		}
	}
	out := append([]Route(nil), routes...)
	sort.SliceStable(out, func(i, j int) bool {
		hi := hostRank[strings.ToLower(strings.TrimSpace(out[i].Hostname))]
		hj := hostRank[strings.ToLower(strings.TrimSpace(out[j].Hostname))]
		if hi != hj {
			return hi < hj
		}
		return len(strings.TrimRight(out[i].PathPrefix, "/")) > len(strings.TrimRight(out[j].PathPrefix, "/"))
	})
	return out
}

func Render(base BaseConfig, routes []Route, certOnly []CertHost) ([]byte, error) {
	persistOff := false
	admin := &caddyAdmin{Listen: base.AdminListen, EnforceOrigin: true, Origins: []string{"127.0.0.1", "::1", "localhost"}, Config: &caddyAdminConfig{Persist: &persistOff}}

	var httpRoutes []caddyRoute
	var subjects []string
	seen := map[string]bool{}
	subjectCA := map[string]string{} // hostname -> CA name ("" / absent = default issuer)

	// SBD-1: the admin vhost is rendered ONLY if explicitly configured, with the
	// IP allowlist as the FIRST matcher, upstream pinned to the loopback admin.
	if base.AdminHostname != "" {
		ah := strings.ToLower(strings.TrimSpace(base.AdminHostname))
		if !hostnameRe.MatchString(ah) {
			return nil, fmt.Errorf("admin.hostname %q is invalid", base.AdminHostname)
		}
		if len(base.AdminAllowlist) == 0 {
			return nil, fmt.Errorf("admin vhost requires a non-empty IP allowlist (SBD-1)")
		}
		if base.AdminUpstream == "" {
			return nil, fmt.Errorf("admin vhost requires the pinned admin upstream")
		}
		httpRoutes = append(httpRoutes, caddyRoute{
			Match: []caddyMatch{{Host: []string{ah}, RemoteIP: &caddyRemoteIP{Ranges: base.AdminAllowlist}}},
			Handle: []caddyHandler{{
				Handler:   "reverse_proxy",
				Upstreams: []caddyUpstream{{Dial: base.AdminUpstream}},
				Headers:   xffOverwrite(),
			}},
			Terminal: true,
		})
		subjects = append(subjects, ah)
		seen[ah] = true
	}

	// A host's certificate issuer comes from its first enabled route in the caller's order,
	// independent of the specificity ordering below.
	hostCA := map[string]string{}
	for _, r := range routes {
		if h := strings.ToLower(strings.TrimSpace(r.Hostname)); r.Enabled {
			if _, ok := hostCA[h]; !ok {
				hostCA[h] = r.CA
			}
		}
	}
	for _, r := range bySpecificity(routes) {
		if !r.Enabled {
			continue
		}
		if err := ValidateRoute(r); err != nil {
			return nil, fmt.Errorf("route %s: %w", r.Hostname, err)
		}
		h := strings.ToLower(strings.TrimSpace(r.Hostname))
		if h == strings.ToLower(strings.TrimSpace(base.AdminHostname)) {
			return nil, fmt.Errorf("route %q collides with the admin vhost", r.Hostname)
		}
		match := caddyMatch{Host: []string{h}}
		if p := strings.TrimRight(r.PathPrefix, "/"); p != "" {
			// The prefix itself (/api) and everything under it (/api/…), never a sibling (/apiv2).
			match.Path = []string{p, p + "/*"}
		} else if r.PathPrefix != "" {
			match.Path = []string{"/*"}
		}
		var handlers []caddyHandler
		if r.SecurityHeaders || r.HSTS {
			handlers = append(handlers, caddyHandler{Handler: "headers", Response: &caddyHeaderOps{Set: securityHeaderBundle(r)}})
		}
		dials := r.dials()
		if r.Unroutable || len(dials) == 0 {
			// No container to dial: answer 503 for this host (and keep its certificate renewing).
			handlers = append(handlers, unavailableHandler())
			httpRoutes = append(httpRoutes, caddyRoute{Match: []caddyMatch{match}, Handle: handlers, Terminal: true})
			if !seen[h] {
				subjects = append(subjects, h)
				seen[h] = true
				subjectCA[h] = hostCA[h]
			}
			continue
		}
		var ups []caddyUpstream
		for _, d := range dials {
			ups = append(ups, caddyUpstream{Dial: d})
		}
		rp := caddyHandler{
			Handler:   "reverse_proxy",
			Upstreams: ups,
			Headers:   xffOverwrite(),
		}
		// A replica pool (M14): least-conn LB + passive health checks so a sick
		// replica is taken out until it recovers. A single upstream needs neither.
		if len(ups) > 1 {
			rp.LoadBalancing = &caddyLoadBalancing{SelectionPolicy: map[string]any{"policy": "least_conn"}}
			rp.HealthChecks = &caddyHealthChecks{Passive: &caddyPassiveHealth{FailDuration: "30s", MaxFails: 3}}
		}
		if r.UpstreamScheme == "https" {
			tls := map[string]any{}
			// The edge dials the container's IP; SNI and certificate verification still target the
			// service name, exactly as a name dial would.
			if name := r.upstreamServiceName(); name != "" {
				tls["server_name"] = name
			}
			rp.Transport = map[string]any{"protocol": "http", "tls": tls}
		}
		handlers = append(handlers, rp)
		httpRoutes = append(httpRoutes, caddyRoute{Match: []caddyMatch{match}, Handle: handlers, Terminal: true})
		if !seen[h] {
			subjects = append(subjects, h)
			seen[h] = true
			subjectCA[h] = hostCA[h]
		}
	}

	// Cert-only subjects: issue+renew a cert (so a consumer app can serve TLS with
	// it) but add NO proxy route — validated FQDN, deduped, never the admin host. Each
	// carries its chosen CA (default issuer when empty).
	for _, ch := range certOnly {
		h := strings.ToLower(strings.TrimSpace(ch.Hostname))
		if len(h) > 253 || !hostnameRe.MatchString(h) {
			return nil, fmt.Errorf("cert-only hostname %q is invalid", h)
		}
		if !seen[h] {
			subjects = append(subjects, h)
			seen[h] = true
			subjectCA[h] = ch.CA
		}
	}

	// SBD-4: default unmatched Host → 404 (never proxy, no catch-all).
	httpRoutes = append(httpRoutes, caddyRoute{Handle: []caddyHandler{{Handler: "static_response", StatusCode: 404}}})

	edgeServer := caddyServer{Listen: []string{":443", ":80"}, Routes: httpRoutes}
	cfg := caddyConfig{
		Admin: admin,
		Apps: caddyApps{
			HTTP: caddyHTTP{Servers: map[string]caddyServer{"edge": edgeServer}},
		},
	}
	// Opt-in per-request access log (for edge-measured autoscaling signals). Access → STDOUT (JSON,
	// captured in-process); the default logger keeps Caddy's own logs + errors on STDERR/journald
	// and EXCLUDES the access namespace so requests don't double-log to journald.
	if base.AccessLog {
		srv := cfg.Apps.HTTP.Servers["edge"]
		srv.Logs = &caddyServerLogs{DefaultLoggerName: accessLoggerName}
		cfg.Apps.HTTP.Servers["edge"] = srv
		accessNS := "http.log.access." + accessLoggerName
		cfg.Logging = &caddyLogging{Logs: map[string]caddyLog{
			"default":        {Writer: caddyLogWriter{Output: "stderr"}, Exclude: []string{accessNS}},
			accessLoggerName: {Writer: caddyLogWriter{Output: "stdout"}, Encoder: &caddyLogEncoder{Format: "json"}, Include: []string{accessNS}},
		}}
	}
	// SBD-3: ACME issuing ONLY for the configured subjects; on_demand omitted (off).
	// No subjects → no automation policy (base serves nothing — the safe recovery floor).
	// Subjects are grouped by their chosen CA: each named CA gets its own automation
	// policy (its issuer directory + optional trusted roots), and everything else uses
	// the default issuer. An unknown CA name falls back to the default (defensive — the
	// apply layer already rejects unknown names).
	// Optional *.<domain> wildcards via DNS-01, ONE per operator-declared namespace that set
	// dns01 (base.Wildcards). Any DEFAULT-CA subject at/under a namespace apex is served by that
	// namespace's wildcard, so drop it from per-name issuance (dodges HTTP-01 rate limits and
	// covers non-HTTP-reachable names). A named-CA subject, or a subject outside every wildcard
	// apex, keeps its own HTTP-01 cert. Each wildcard string is Mooring-generated (never operator
	// route input), so it never passes through the no-wildcard hostname check.
	if len(base.Wildcards) > 0 {
		kept := make([]string, 0, len(subjects))
		for _, h := range subjects {
			if subjectCA[h] == "" && coveredByAnyWildcard(h, base.Wildcards) {
				continue // covered by some namespace's wildcard
			}
			kept = append(kept, h)
		}
		subjects = kept
	}
	if len(subjects) > 0 || len(base.Wildcards) > 0 {
		caByName := map[string]CA{}
		for _, c := range base.CAs {
			caByName[c.Name] = c
		}
		groups := map[string][]string{} // CA name ("" = default) -> its subjects
		var order []string              // CA names in first-seen order
		for _, h := range subjects {
			name := subjectCA[h]
			if name != "" {
				if _, ok := caByName[name]; !ok {
					name = "" // unknown → default issuer
				}
			}
			if _, ok := groups[name]; !ok {
				order = append(order, name)
			}
			groups[name] = append(groups[name], h)
		}
		policies := make([]caddyTLSPolicy, 0, len(order)+len(base.Wildcards))
		for _, name := range order {
			iss := caddyIssuer{Module: "acme", CA: base.ACMECA, Email: base.ACMEEmail}
			if name != "" {
				c := caByName[name]
				email := c.Email
				if email == "" {
					email = base.ACMEEmail
				}
				iss = caddyIssuer{Module: "acme", CA: c.DirectoryURL, Email: email, TrustedRoots: c.TrustedRoots}
			}
			policies = append(policies, caddyTLSPolicy{Subjects: groups[name], Issuers: []caddyIssuer{iss}})
		}
		automate := append([]string(nil), subjects...)
		for _, w := range base.Wildcards {
			if w.Domain == "" || w.DNS01Provider == "" {
				continue
			}
			wc := "*." + w.Domain
			// One DNS-01 policy per namespace wildcard (default ACME CA/email + that namespace's
			// DNS provider + token).
			dnsIss := caddyIssuer{
				Module: "acme", CA: base.ACMECA, Email: base.ACMEEmail,
				Challenges: &caddyChallenges{DNS: &caddyDNSChallenge{Provider: map[string]any{
					"name": w.DNS01Provider, "api_token": w.DNS01Token,
				}}},
			}
			policies = append(policies, caddyTLSPolicy{Subjects: []string{wc}, Issuers: []caddyIssuer{dnsIss}})
			automate = append(automate, wc)
		}
		cfg.Apps.TLS = &caddyTLS{
			// automate makes Caddy actually obtain a cert for every subject — including
			// cert-only ones (no proxy route references them, so auto-HTTPS wouldn't
			// pick them up).
			Certificates: &caddyCertificates{Automate: automate},
			Automation:   caddyAutomation{Policies: policies},
		}
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// coveredByAnyWildcard reports whether host is a single-label subdomain of ANY configured
// wildcard namespace apex (so it can be dropped from per-name issuance in favor of that
// wildcard). Namespace apexes are validated disjoint (no nesting) in config, so at most one
// wildcard can match.
func coveredByAnyWildcard(host string, wildcards []WildcardCert) bool {
	for _, w := range wildcards {
		if w.Domain != "" && w.DNS01Provider != "" && coveredByWildcard(host, w.Domain) {
			return true
		}
	}
	return false
}

// coveredByWildcard reports whether a *.base certificate covers host. A wildcard matches
// EXACTLY one label (RFC 6125): it covers foo.base but NOT the apex `base` nor a deeper name
// like a.b.base. So only a single-label subdomain may be dropped in favor of the wildcard;
// the apex and multi-label names must keep their own cert (else they'd get none).
func coveredByWildcard(host, base string) bool {
	suffix := "." + base
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	label := host[:len(host)-len(suffix)]
	return label != "" && !strings.Contains(label, ".")
}

// xffOverwrite sets X-Forwarded-For to the real TCP peer (overwrite, not append),
// matching Mooring's own XFF invariant so an app behind the edge sees the true
// client and a forged upstream XFF can't slip through.
func xffOverwrite() *caddyProxyHeaders {
	return &caddyProxyHeaders{Request: &caddyHeaderOps{Set: map[string][]string{
		"X-Forwarded-For": {"{http.request.remote.host}"},
	}}}
}

func securityHeaderBundle(r Route) map[string][]string {
	set := map[string][]string{
		"X-Content-Type-Options": {"nosniff"},
		"Referrer-Policy":        {"no-referrer"},
	}
	if r.HSTS {
		// HSTS is only ever sent on the HTTPS vhost Caddy serves for a managed host.
		set["Strict-Transport-Security"] = []string{"max-age=31536000; includeSubDomains"}
	}
	return set
}
