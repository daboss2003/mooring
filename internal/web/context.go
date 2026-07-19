package web

import (
	"context"
	"net/netip"

	"github.com/daboss2003/mooring/internal/session"
)

type ctxKey int

const (
	clientIPKey ctxKey = iota
	sessionKey
	csrfTokenKey
	tokenIDKey
	fromEdgeKey
)

// withFromEdge marks a request as arriving on the dedicated managed-edge listener (Caddy
// dialing our loopback admin upstream). The allowlist middleware then REQUIRES a single
// X-Forwarded-For and gates the real client from it — the edge is a trusted proxy by
// construction here, so this needs no trusted_proxies config entry.
func withFromEdge(ctx context.Context) context.Context {
	return context.WithValue(ctx, fromEdgeKey, true)
}

// fromEdge reports whether the request came in on the managed-edge listener.
func fromEdge(ctx context.Context) bool {
	v, _ := ctx.Value(fromEdgeKey).(bool)
	return v
}

func withClientIP(ctx context.Context, ip netip.Addr) context.Context {
	return context.WithValue(ctx, clientIPKey, ip)
}

// ClientIP returns the resolved client IP (the real peer, or the single
// overwritten XFF value when the peer is a trusted proxy). Zero value if unset.
func ClientIP(ctx context.Context) netip.Addr {
	ip, _ := ctx.Value(clientIPKey).(netip.Addr)
	return ip
}

func withSession(ctx context.Context, s *session.Session) context.Context {
	return context.WithValue(ctx, sessionKey, s)
}

// SessionFrom returns the loaded session, or nil if unauthenticated.
func SessionFrom(ctx context.Context) *session.Session {
	s, _ := ctx.Value(sessionKey).(*session.Session)
	return s
}

func withCSRF(ctx context.Context, token string) context.Context {
	return context.WithValue(ctx, csrfTokenKey, token)
}

// CSRFToken returns the per-request CSRF token for template injection.
func CSRFToken(ctx context.Context) string {
	t, _ := ctx.Value(csrfTokenKey).(string)
	return t
}

func withTokenID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, tokenIDKey, id)
}

// TokenID returns the authenticated API token id (for audit), or "" on the browser
// plane.
func TokenID(ctx context.Context) string {
	id, _ := ctx.Value(tokenIDKey).(string)
	return id
}
