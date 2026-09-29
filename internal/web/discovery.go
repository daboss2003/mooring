package web

import (
	"context"
	"log/slog"
	"net/netip"
	"sort"
	"strings"

	"github.com/daboss2003/mooring/internal/docker"
)

// Container-discovery helpers shared by the three planes that must turn a compose
// SERVICE NAME into a routable container IP — the managed edge (DiscoverEdgePools),
// the L4 LB (DiscoverL4Pools), and the ops prober (ServiceIP). All three exist because
// Mooring's host processes (Caddy, nginx, the control plane) cannot resolve compose
// service names — those live only on Docker's per-network embedded DNS — so each must
// dial a discovered docker-bridge IP instead. Keeping the lookup in one place stops the
// three from drifting. Source of truth is the READ-ONLY socket-proxy.

// svcKey is the (project, service) index key. NUL can't appear in either, so it's a
// collision-free separator.
func svcKey(project, service string) string { return project + "\x00" + service }

// replica is one running container of a compose service, as the read plane lists it.
type replica struct {
	ID string // full container id
	IP string // the bridge address the host dials
}

// discoverReplicas lists running containers ONCE and groups each routable replica (id + one bridge IP)
// by svcKey(project, service). ok=false means the listing itself failed (nil client, socket-proxy down, a
// list error) — as opposed to listing fine and finding nothing — so callers can tell "no container" from
// "no information". One-off `compose run` containers are skipped: they are never a service's serving
// replica. A multi-homed replica uses its `<project>_default` address when it has one, else its first
// routable address in network-name order (stable across renders).
func discoverReplicas(ctx context.Context, dc *docker.Client, log *slog.Logger) (map[string][]replica, bool) {
	if dc == nil {
		return nil, false
	}
	cs, err := dc.ListContainers(ctx, false) // running only
	if err != nil {
		if log != nil {
			log.Debug("container discovery failed", "err", err)
		}
		return nil, false
	}
	out := map[string][]replica{}
	for _, c := range cs {
		if !strings.EqualFold(c.State, "running") {
			continue
		}
		proj, svc := c.Project(), c.Service()
		if proj == "" || svc == "" || strings.EqualFold(c.Labels["com.docker.compose.oneoff"], "true") {
			continue
		}
		if ip := replicaIP(c, proj); ip != "" {
			out[svcKey(proj, svc)] = append(out[svcKey(proj, svc)], replica{ID: c.ID, IP: ip})
		}
	}
	return out, true
}

// replicaIP picks the address the host dials for one container: its compose project's default network
// when it is attached to it, else its first routable address.
func replicaIP(c docker.Container, project string) string {
	if n, ok := c.NetworkSettings.Networks[project+"_default"]; ok {
		if ip := strings.TrimSpace(n.IPAddress); routableUpstreamIP(ip) {
			return ip
		}
	}
	for _, ip := range c.IPs() {
		if routableUpstreamIP(ip) {
			return ip
		}
	}
	return ""
}

// ReplicaIPsByService lists running containers ONCE and groups one routable bridge IP
// per replica, keyed by svcKey(project, service). A nil client or a list error yields
// nil (callers fail safe).
func ReplicaIPsByService(ctx context.Context, dc *docker.Client, log *slog.Logger) map[string][]string {
	reps, ok := discoverReplicas(ctx, dc, log)
	if !ok {
		return nil
	}
	out := make(map[string][]string, len(reps))
	for k, rs := range reps {
		for _, r := range rs {
			out[k] = append(out[k], r.IP)
		}
	}
	return out
}

// sameContainer reports whether two container ids refer to the same container, allowing one to be an
// abbreviated (≥12 hex) prefix of the other.
func sameContainer(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	if len(a) > len(b) {
		a, b = b, a
	}
	return len(a) >= 12 && strings.HasPrefix(b, a)
}

// ServiceIP returns one routable bridge IP for a running replica of (project, service),
// chosen deterministically (lowest IP). For single-service callers (the ops prober).
// ok=false when there is no running replica or the socket-proxy is down — fail-safe.
func ServiceIP(ctx context.Context, dc *docker.Client, project, service string) (string, bool) {
	ips := ReplicaIPsByService(ctx, dc, nil)[svcKey(project, service)]
	if len(ips) == 0 {
		return "", false
	}
	sort.Strings(ips)
	return ips[0], true
}

// replicaIPsByService is the *Server convenience wrapper used by the edge and L4 pool
// discoverers (both run after the server is built).
func (s *Server) replicaIPsByService(ctx context.Context) map[string][]string {
	return ReplicaIPsByService(ctx, s.docker, s.log)
}

// routableUpstreamIP reports whether ip is a plausible app-container address — a
// non-loopback, non-link-local, non-unspecified literal. This pre-filters discovery so
// one pathological IP can't fail a whole render; edge/L4 ValidateRoute remain the
// authoritative control-plane/loopback backstops applied to every dial regardless.
func routableUpstreamIP(ip string) bool {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsUnspecified() || addr.IsMulticast() {
		return false
	}
	return true
}
