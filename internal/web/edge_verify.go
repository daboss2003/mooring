package web

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/docker"
	"github.com/daboss2003/mooring/internal/edge"
)

// verifyEdgeTargets runs right after a deploy applied its routes. Every enabled route the app now has
// in the route store must be applied to the edge with its current upstream, be served (not answering
// 503), and dial ONLY running, non-one-off containers of this app's route service — containers the
// write plane (the docker CLI the deploy just used) also lists, which proves both planes see the same
// daemon. It streams one line per route and returns an error naming every failure: a deploy must not
// report success for something the edge is not serving.
//
// Each pass first re-applies the edge (so a reconcile that failed during the deploy can't leave the
// check reading an older state); within window, a failing pass is retried. writeIDs lists the
// service's running container ids via the write plane.
func (s *Server) verifyEdgeTargets(ctx context.Context, slug string, window time.Duration,
	writeIDs func(ctx context.Context, svc string) ([]string, error), onLine func(string)) error {
	return s.verifyEdgeTargetsExcept(ctx, slug, window, writeIDs, onLine, nil)
}

// verifyEdgeTargetsExcept is verifyEdgeTargets for a paced deploy: the routes of the services in
// excused (the deploy's reported problems) are still checked and listed, but can't fail the deploy.
func (s *Server) verifyEdgeTargetsExcept(ctx context.Context, slug string, window time.Duration,
	writeIDs func(ctx context.Context, svc string) ([]string, error), onLine func(string), excused map[string]bool) error {
	if s.edgeRecon == nil || s.edgeRoutes == nil {
		return nil // the edge isn't Mooring's on this host: nothing to verify
	}
	deadline := time.Now().Add(window)
	for {
		var lines, failures []string
		rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		rerr := s.edgeRecon.Reconcile(rctx)
		cancel()
		if rerr != nil {
			lines = []string{"✗ edge config not applied: " + rerr.Error()}
			failures = []string{"edge config not applied: " + rerr.Error()}
		} else {
			lines, failures = s.checkEdgeTargets(ctx, slug, writeIDs)
			failures = s.dropExcusedRoutes(slug, failures, excused)
		}
		if len(failures) == 0 || time.Now().After(deadline) || ctx.Err() != nil {
			for _, l := range lines {
				onLine(l)
			}
			if len(failures) > 0 {
				return fmt.Errorf("edge verification failed: %s", strings.Join(failures, "; "))
			}
			return nil
		}
		select {
		case <-ctx.Done():
		case <-time.After(3 * time.Second):
		}
	}
}

// dropExcusedRoutes removes from failures ("<host>: <why>") the routes whose service is in excused.
func (s *Server) dropExcusedRoutes(slug string, failures []string, excused map[string]bool) []string {
	if len(excused) == 0 || len(failures) == 0 {
		return failures
	}
	stored, err := s.edgeRoutes.List()
	if err != nil {
		return failures
	}
	hosts := map[string]bool{}
	for _, rt := range stored {
		if svc, _, ok := parseUpstream(rt.Upstream); ok && rt.AppID == slug && excused[svc] {
			hosts[rt.Hostname+rt.PathPrefix] = true
		}
	}
	kept := failures[:0]
	for _, f := range failures {
		host, _, _ := strings.Cut(f, ": ")
		if !hosts[host] {
			kept = append(kept, f)
		}
	}
	return kept
}

// statusKey matches an edge.RouteStatus to its stored route (hostnames are unique per path prefix).
func statusKey(hostname, pathPrefix string) string {
	return strings.ToLower(strings.TrimSpace(hostname)) + "\x00" + pathPrefix
}

// checkEdgeTargets is one verification pass: the report lines and the failures (empty = all good).
func (s *Server) checkEdgeTargets(ctx context.Context, slug string,
	writeIDs func(ctx context.Context, svc string) ([]string, error)) (lines, failures []string) {
	fail := func(host, why string) {
		lines = append(lines, "✗ "+host+": "+why)
		failures = append(failures, host+": "+why)
	}
	stored, err := s.edgeRoutes.List()
	if err != nil {
		fail(slug, "route store unavailable: "+err.Error())
		return lines, failures
	}
	var want []edge.Route
	for _, rt := range stored {
		if rt.AppID == slug && rt.Enabled {
			want = append(want, rt)
		}
	}
	if len(want) == 0 {
		return nil, nil
	}
	applied := map[string]edge.RouteStatus{}
	for _, st := range s.edgeRecon.RouteStatuses() {
		applied[statusKey(st.Hostname, st.PathPrefix)] = st
	}
	if s.docker == nil {
		fail(slug, "no container view to verify against")
		return lines, failures
	}
	lctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	cs, err := s.docker.ListContainers(lctx, false)
	cancel()
	if err != nil {
		fail(slug, "container view unavailable: "+err.Error())
		return lines, failures
	}
	byIP := map[string]docker.Container{}
	for _, c := range cs {
		if strings.EqualFold(c.State, "running") {
			for _, ip := range c.IPs() {
				byIP[ip] = c
			}
		}
	}
	type listing struct {
		ids []string
		err error
	}
	written := map[string]listing{}
	for _, rt := range want {
		host := rt.Hostname + rt.PathPrefix
		svc, _, ok := parseUpstream(rt.Upstream)
		if !ok {
			fail(host, "unparseable upstream "+rt.Upstream)
			continue
		}
		st, found := applied[statusKey(rt.Hostname, rt.PathPrefix)]
		switch {
		case !found:
			fail(host, "not applied to the edge")
			continue
		case st.Upstream != rt.Upstream:
			fail(host, "the edge still serves "+st.Upstream+", not "+rt.Upstream)
			continue
		case st.State != edge.RouteRoutable:
			why := string(st.State)
			if st.Reason != "" {
				why += " (" + st.Reason + ")"
			}
			fail(host, "not served: "+why)
			continue
		}
		var ids []string
		why := ""
		for _, d := range st.Dials {
			ip, _, err := net.SplitHostPort(d)
			c, present := byIP[ip]
			switch {
			case err != nil || !present:
				why = d + " is not a running container"
			case c.Project() != slug || c.Service() != svc:
				why = fmt.Sprintf("%s is %s/%s, not %s/%s", d, c.Project(), c.Service(), slug, svc)
			case strings.EqualFold(c.Labels["com.docker.compose.oneoff"], "true"):
				why = d + " is a one-off container"
			}
			if why != "" {
				break
			}
			ids = append(ids, c.ID)
		}
		if why == "" {
			l, cached := written[svc]
			if !cached {
				l.ids, l.err = writeIDs(ctx, svc) // waits for the docker slot under the deploy's deadline
				written[svc] = l
			}
			if l.err != nil {
				why = "could not list " + svc + " through the docker CLI: " + l.err.Error()
			}
			for _, id := range ids {
				if why != "" {
					break
				}
				if !containsContainer(l.ids, id) {
					why = "container " + shortContainerID(id) + " is not known to the docker CLI — the read and write planes reach different Docker daemons"
				}
			}
		}
		if why != "" {
			fail(host, why)
			continue
		}
		short := make([]string, len(ids))
		for i, id := range ids {
			short[i] = shortContainerID(id)
		}
		lines = append(lines, fmt.Sprintf("✓ %s → %s (container %s)", host, strings.Join(st.Dials, ", "), strings.Join(short, ", ")))
	}
	return lines, failures
}

// containsContainer reports whether ids holds id (full or abbreviated on either side).
func containsContainer(ids []string, id string) bool {
	for _, w := range ids {
		if sameContainer(w, id) {
			return true
		}
	}
	return false
}
