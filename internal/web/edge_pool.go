package web

import (
	"context"
	"net"
	"sort"
	"strconv"

	"github.com/daboss2003/mooring/internal/edge"
	"github.com/daboss2003/mooring/internal/monitor"
)

// DiscoverEdgePools resolves each route to the running container endpoints (ip:port) of its backing
// service, for the managed edge to dial directly (edge.Reconciler.SetPoolDiscoverer). The host process
// running Caddy cannot resolve compose service names — only Docker's per-network DNS can — so routes are
// only ever dialed at these discovered bridge addresses; a route with none answers 503.
//
// The result says whether discovery itself worked (OK) and which routes it looked at (Evaluated), so
// the edge can tell "no running container" (503) from "no information" (keep the last-known addresses
// for a while). Containers in exclude (being drained ahead of removal) are skipped, and so are replicas
// that aren't ready yet whenever at least one ready replica exists — see servingReplicas. Every endpoint
// is filtered here and re-validated by edge.Render (SBD-4).
func (s *Server) DiscoverEdgePools(ctx context.Context, routes []edge.Route, exclude map[string]bool) edge.Discovery {
	reps, ok := discoverReplicas(ctx, s.docker, s.log)
	if !ok {
		return edge.Discovery{}
	}
	health := containerHealth(s.snapshot())
	disc := edge.Discovery{OK: true, Pools: map[string][]string{}, Evaluated: map[string]bool{}}
	for _, rt := range routes {
		if !rt.Enabled || rt.AppID == "" {
			continue
		}
		service, port, ok := parseUpstream(rt.Upstream)
		if !ok {
			continue
		}
		key := edge.PoolKey(rt)
		if disc.Evaluated[key] {
			continue // routes sharing an upstream share a pool — compute once
		}
		disc.Evaluated[key] = true
		if eps := endpoints(servingReplicas(reps[svcKey(rt.AppID, service)], exclude, health), port); len(eps) > 0 {
			disc.Pools[key] = eps
		}
	}
	return disc
}

// containerHealth maps container id → the health the monitor last observed ("healthy", "unhealthy",
// "starting", or "none" for a container without a healthcheck).
func containerHealth(snap *monitor.Snapshot) map[string]string {
	out := map[string]string{}
	if snap == nil {
		return out
	}
	for _, a := range snap.Apps {
		for _, sv := range a.Services {
			if sv.ContainerID != "" {
				out[sv.ContainerID] = sv.Health
			}
		}
	}
	return out
}

// healthOf looks a container's observed health up by id (tolerating an abbreviated id on either side).
func healthOf(health map[string]string, id string) (string, bool) {
	if h, ok := health[id]; ok {
		return h, true
	}
	for cid, h := range health {
		if sameContainer(cid, id) {
			return h, true
		}
	}
	return "", false
}

// servingReplicas picks the replicas the edge should dial. Excluded (draining) containers are dropped.
// Then, if at least one remaining replica is ready — last observed healthy, or running without a
// healthcheck — replicas still starting, unhealthy, or not yet observed by the monitor are dropped too,
// so a new copy takes traffic only once it is ready. When none is ready, every remaining replica serves:
// a service that is only starting (a first deploy) is dialed rather than answered with a 503.
func servingReplicas(rs []replica, exclude map[string]bool, health map[string]string) []replica {
	var remaining []replica
	for _, r := range rs {
		drained := false
		for id := range exclude {
			if sameContainer(id, r.ID) {
				drained = true
				break
			}
		}
		if !drained {
			remaining = append(remaining, r)
		}
	}
	var ready []replica
	for _, r := range remaining {
		if h, ok := healthOf(health, r.ID); ok && (h == "healthy" || h == "none") {
			ready = append(ready, r)
		}
	}
	if len(ready) > 0 {
		return ready
	}
	return remaining
}

// endpoints renders replicas as sorted, de-duplicated ip:port dials (a stable replica set re-renders
// byte-identically, so the edge skips an unchanged reload).
func endpoints(rs []replica, port int) []string {
	seen := map[string]bool{}
	eps := make([]string, 0, len(rs))
	for _, r := range rs {
		ep := net.JoinHostPort(r.IP, strconv.Itoa(port))
		if !seen[ep] {
			seen[ep] = true
			eps = append(eps, ep)
		}
	}
	sort.Strings(eps)
	return eps
}
