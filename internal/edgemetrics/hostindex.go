package edgemetrics

import (
	"strings"
	"sync"
)

// Route maps a matched edge vhost (host + optional path prefix) to the service that serves it, so an
// access-log line can be attributed to the right (App, Service) for the latency aggregator.
type Route struct {
	Host       string // the route's hostname (as the client sends it in the Host header)
	PathPrefix string // "" = the whole host; else the leading path this route serves
	Key        Key    // the service this route fronts
}

// HostIndex resolves an access-log (host, path) to a service Key. It is swapped WHOLESALE on route
// changes (Set) and looked up per request (Lookup) under an RWMutex, so per-request reads never
// block each other and a route reload is a single pointer swap. A host that isn't in the index
// (e.g. a 404 for an arbitrary attacker Host header) resolves to ok=false and is never recorded.
type HostIndex struct {
	mu sync.RWMutex
	m  map[string][]hostRoute // lower-cased host -> its routes (longest path prefix wins)
}

type hostRoute struct {
	prefix string
	key    Key
}

// NewHostIndex builds an empty index (Lookup returns ok=false for everything until Set is called).
func NewHostIndex() *HostIndex { return &HostIndex{m: map[string][]hostRoute{}} }

// Set replaces the whole routing table. Routes with an empty host or an incomplete Key are dropped
// (they could never be attributed anyway).
func (h *HostIndex) Set(routes []Route) {
	m := make(map[string][]hostRoute, len(routes))
	for _, r := range routes {
		host := strings.ToLower(strings.TrimSpace(r.Host))
		if host == "" || r.Key.App == "" || r.Key.Service == "" {
			continue
		}
		m[host] = append(m[host], hostRoute{prefix: strings.TrimRight(r.PathPrefix, "/"), key: r.Key})
	}
	h.mu.Lock()
	h.m = m
	h.mu.Unlock()
}

// Lookup returns the service Key serving (host, path): among the routes for that host, the one whose
// path prefix is the LONGEST prefix of path (a "" prefix matches anything). ok=false when the host
// is unknown — so unmatched/hostile traffic (a request with a bogus Host header that fell through to
// Caddy's 404) is never attributed to any service.
func (h *HostIndex) Lookup(host, path string) (Key, bool) {
	key, _, ok := h.LookupRoute(host, path)
	return key, ok
}

// LookupRoute is Lookup but also returns the matched route's path prefix — the route identity
// (host + prefix) the per-route error log groups by. "" prefix means the whole-host route.
func (h *HostIndex) LookupRoute(host, path string) (key Key, prefix string, ok bool) {
	host = strings.ToLower(host)
	h.mu.RLock()
	routes := h.m[host]
	h.mu.RUnlock()
	var best hostRoute
	found := false
	for _, r := range routes {
		if pathUnderPrefix(path, r.prefix) && (!found || len(r.prefix) > len(best.prefix)) {
			best, found = r, true
		}
	}
	if !found {
		return Key{}, "", false
	}
	return best.key, best.prefix, true
}

// pathUnderPrefix reports whether reqPath is served by a route mounted at prefix ("" = the whole
// host). It matches on path-SEGMENT boundaries, so /apiary is not considered under /api.
func pathUnderPrefix(reqPath, prefix string) bool {
	if prefix == "" {
		return true
	}
	return reqPath == prefix || strings.HasPrefix(reqPath, prefix+"/")
}
