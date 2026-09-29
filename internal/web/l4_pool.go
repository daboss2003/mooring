package web

import (
	"context"
	"log/slog"

	"github.com/daboss2003/mooring/internal/docker"
	"github.com/daboss2003/mooring/internal/l4"
	"github.com/daboss2003/mooring/internal/monitor"
)

// DiscoverL4Pools resolves each L4 route to the running container endpoints (ip:port) of its backing
// service, so the host nginx dials bridge IPs directly and never has to resolve a compose service name
// (which it can't — and one unresolvable upstream makes `nginx -t` reject the WHOLE config). Counterpart
// of DiscoverEdgePools, keyed by l4.PoolKey(route); a route with no running replica gets no pool and the
// renderer skips it. ok=false means discovery itself failed (socket-proxy down, list error) — the caller
// keeps each route's last-known pool for a while instead of unbinding every listener. Replicas that
// aren't ready yet are left out whenever a ready one exists (see servingReplicas); health comes from
// the latest monitor snapshot and may be nil.
//
// It is a free function (not a *Server method like DiscoverEdgePools) because the L4 reconcile closure
// is built BEFORE the *Server — web.New needs that closure — so it has only the docker client.
func DiscoverL4Pools(ctx context.Context, dc *docker.Client, log *slog.Logger, routes []l4.Route, snap *monitor.Snapshot) (map[string][]string, bool) {
	reps, ok := discoverReplicas(ctx, dc, log)
	if !ok {
		return nil, false
	}
	health := containerHealth(snap)
	out := map[string][]string{}
	for _, rt := range routes {
		if rt.AppID == "" {
			continue
		}
		key := l4.PoolKey(rt)
		if _, done := out[key]; done {
			continue
		}
		if eps := endpoints(servingReplicas(reps[svcKey(rt.AppID, rt.Service)], nil, health), rt.Port); len(eps) > 0 {
			out[key] = eps
		}
	}
	return out, true
}
