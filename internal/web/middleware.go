package web

import (
	"net"
	"net/http"
	"net/netip"
	"path"
	"strings"

	"github.com/daboss2003/mooring/internal/session"
)

// The request pipeline, in the exact order the security model mandates (plan §5):
//
//	1 IP allowlist  →  2 trusted-proxy/XFF resolve  →  3 security headers
//	→ 4 rate limiter → 5 session loader → 6 auth → 7 CSRF + Origin → 8 router → 9 audit
//
// Steps 1–2 are fused (the XFF resolve is meaningless without the peer check).
// Steps 6–7 are applied per-route inside the router (auth gates protected routes;
// CSRF gates state-changers including the unauthenticated /login POST), so auth
// always precedes CSRF where both apply. Step 9 (audit) is emitted by handlers
// for the specific privileged actions the plan enumerates.

// allowlistMiddleware is the FIRST middleware. It enforces the IP allowlist on
// the unspoofable TCP peer, resolving a single overwritten XFF only when the
// peer is a configured trusted proxy (plan §5.2 XFF invariant). Non-allowlisted
// requests get a bare 404 (notfound) — never an auth prompt that confirms the
// service exists. /healthz is exempt so a loopback liveness probe always works.
func (s *Server) allowlistMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		peer, ok := peerAddr(r)
		if !ok {
			notFound(w)
			return
		}
		sec := s.security()
		client := peer

		// A request on the dedicated managed-edge listener is ALWAYS behind our own
		// supervised Caddy (a loopback peer): require the XFF and gate the real client,
		// regardless of the global trust_proxy config (the tunnel listener keeps its own
		// peer-allowlisting). This is what lets the two access paths coexist safely.
		trusted := (sec.trustProxy && prefixesContain(sec.trustedProxies, peer)) || fromEdge(r.Context())
		if trusted {
			// The peer IS a trusted edge: REQUIRE exactly one valid overwritten
			// XFF value. Missing, malformed, or an appended chain fails closed
			// EXPLICITLY (deny) — we do not fall back to allowlisting the peer, so
			// the guarantee holds even if the edge IP is mistakenly in the
			// allowlist (review #15).
			single, ok := singleXFF(r.Header.Values("X-Forwarded-For"))
			if !ok {
				s.auditDeny(r, peer, peer)
				notFound(w)
				return
			}
			ip, err := netip.ParseAddr(single)
			if err != nil {
				s.auditDeny(r, peer, peer)
				notFound(w)
				return
			}
			client = ip.Unmap()
		}
		// If the peer is NOT trusted, XFF is ignored entirely and the peer itself
		// is allowlisted — a hostile container forging XFF cannot get in.

		// The webhook endpoint is allowlist-EXEMPT (CI runners have arbitrary
		// egress IPs) but NOT unprotected: it is HMAC-gated, replay-protected,
		// per-token rate-limited, and FETCH-ONLY (plan §5.7). We still resolve and
		// stamp the client IP so the general per-IP rate limiter has a real key.
		// Match the CLEANED path (what the mux will route) so a traversal like
		// /webhook/../something cannot ride the exemption to a non-webhook route.
		cleaned := path.Clean(r.URL.Path) + "/"
		if !strings.HasPrefix(cleaned, "/webhook/") {
			admitted := prefixesContain(sec.allowlist, client)
			// The scoped-API surface (/api/v1) may ALSO be reached from any IP inside
			// the precomputed union of active token CIDRs — a bounded, reload-scoped
			// exception so a CI runner's egress IP passes the network gate. This is
			// decided WITHOUT parsing the bearer (no enumeration oracle / no
			// unauthenticated DB lookup): the union is precomputed. It opens ONLY the
			// API surface, never the browser admin plane, and the presented token is
			// re-bound to its OWN CIDR at auth time (the union is a coarse gate).
			if !admitted && strings.HasPrefix(cleaned, "/api/v1/") {
				admitted = prefixesContain(sec.tokenCIDRUnion, client)
			}
			if !admitted {
				s.auditDeny(r, peer, client)
				notFound(w)
				return
			}
		}

		r = r.WithContext(withClientIP(r.Context(), client))
		next.ServeHTTP(w, r)
	})
}

// securityHeadersMiddleware sets the fixed strict admin-plane headers (plan §5.4).
func (s *Server) securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// form-action is enforced on the REDIRECT target of a form POST, not just its
		// action. The "Connect with GitHub" button POSTs to /github/connect, which
		// 303-redirects to https://github.com/login/oauth/authorize — so when GitHub
		// OAuth is configured we must allow github.com as a form target, else the
		// browser blocks the redirect ("violates form-action 'self'"). The return hop
		// (github.com -> /github/callback) is a top-level GET navigation, not covered
		// by form-action. Kept off unless GitHub is enabled (smallest surface).
		formAction := "form-action 'self'"
		if s.cfg.GitHub.Enabled() {
			formAction = "form-action 'self' https://github.com"
		}
		h.Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "+
				"object-src 'none'; frame-ancestors 'none'; base-uri 'none'; "+formAction)
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		// same-origin (NOT no-referrer): with no-referrer the browser sends `Origin:
		// null` even on a same-origin POST (Fetch spec), which the CSRF origin check
		// rejects — making login unwinnable. same-origin sends the real Origin on
		// same-origin requests and nothing cross-origin (no off-site leak).
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		// HSTS is safe to assert: the admin plane is only ever reached over the
		// TLS edge or a loopback tunnel.
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		// Strip any Server header Go might add downstream.
		h.Del("Server")
		next.ServeHTTP(w, r)
	})
}

// rateLimitMiddleware applies the general per-IP limiter (pipeline step 4).
func (s *Server) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		key := ClientIP(r.Context()).String()
		if !s.limiter.allow(key) {
			http.Error(w, "rate limited", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// sessionMiddleware loads the session cookie into context (pipeline step 5). It
// never fails the request; requireAuth (step 6) enforces presence on protected
// routes.
func (s *Server) sessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(s.cookieName()); err == nil && c.Value != "" {
			// The focus-loss watchdog's status probe must NOT advance last_seen — else an
			// unfocused tab polling "am I still logged in?" would keep its own session
			// alive forever. Peek there; Load (which refreshes) everywhere else.
			load := s.sessions.Load
			if r.URL.Path == sessionStatusPath {
				load = s.sessions.Peek
			}
			if sess, err := load(r.Context(), c.Value); err == nil {
				r = r.WithContext(withSession(r.Context(), sess))
			} else if err == session.ErrNotFound {
				// Stale/expired cookie: clear it so the browser stops sending it.
				s.clearSessionCookie(w)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// --- helpers ---

func peerAddr(r *http.Request) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	// strip IPv6 zone if present
	if i := strings.IndexByte(host, '%'); i >= 0 {
		host = host[:i]
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

// singleXFF returns the lone XFF token, or ok=false if there is not exactly one
// (none, or an appended chain — both fail closed).
func singleXFF(values []string) (string, bool) {
	var tokens []string
	for _, v := range values {
		for _, t := range strings.Split(v, ",") {
			if t = strings.TrimSpace(t); t != "" {
				tokens = append(tokens, t)
			}
		}
	}
	if len(tokens) != 1 {
		return "", false
	}
	return tokens[0], true
}

func prefixesContain(prefixes []netip.Prefix, ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func notFound(w http.ResponseWriter) {
	http.Error(w, "404 page not found", http.StatusNotFound)
}

// capBody bounds a request body before any handler (or requireCSRF) reads it, so
// an oversized form can't buffer unbounded memory (review #11). An over-limit
// body makes the subsequent ParseForm/FormValue fail, which the handlers map to
// 400/403.
func capBody(max int64, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, max)
		next(w, r)
	}
}
