package web

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/edge"
	"github.com/daboss2003/mooring/internal/selfheal"
)

// upstreamServiceName is the service half of a service:port upstream selector.
func upstreamServiceName(up string) string {
	if svc, _, ok := parseUpstream(up); ok {
		return svc
	}
	return up
}

// edgeUnroutableAlertAfter is how long a route must stay unroutable before it raises an alert, so a
// container being recreated (a moment with nothing to dial) doesn't page.
const edgeUnroutableAlertAfter = 60 * time.Second

// reconcileEdgeAfter re-applies the edge config right after containers were restarted or recreated
// outside a deploy (self-heal, lifecycle actions, cert renewal), so a new container address is dialed at
// once instead of at the next periodic refresh. Best-effort and bounded; never fails the action.
func (s *Server) reconcileEdgeAfter(ctx context.Context) {
	if s.edgeRecon == nil {
		return
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer cancel()
	if err := s.edgeRecon.Reconcile(rctx); err != nil && s.log != nil {
		s.log.Debug("edge reconcile after a container action failed; the periodic refresh will retry", "err", err)
	}
}

// OnEdgeRouteStatus logs every change in how the edge serves a route (edge.Reconciler.SetStatusHook).
// Losing the route — unroutable, pending, or serving last-known addresses because discovery is down — is
// a Warn so it lands in the Activity tab; getting it back is Info.
func (s *Server) OnEdgeRouteStatus(changes []edge.StatusChange) {
	if s.log == nil {
		return
	}
	for _, c := range changes {
		cur := c.Cur
		host := cur.Hostname + cur.PathPrefix
		args := []any{"host", host, "app", cur.AppID, "upstream", cur.Upstream, "state", string(cur.State)}
		if c.Prev.State != "" {
			args = append(args, "was", string(c.Prev.State))
		}
		if cur.Reason != "" {
			args = append(args, "reason", cur.Reason)
		}
		if len(cur.Dials) > 0 {
			args = append(args, "dials", strings.Join(cur.Dials, ","))
		}
		switch cur.State {
		case edge.RouteRoutable:
			s.log.Info("edge: route is served", args...)
		default:
			s.log.Warn("edge: route is not being served normally", args...)
		}
	}
}

// CheckEdgeRouteAlerts raises an infra alert for each route that has been unroutable (answering 503)
// for longer than edgeUnroutableAlertAfter, and resolves it once the route is served again. Routes of
// an app whose deploy or lifecycle action is in progress are left alone: the deploy reports its own
// outcome. Called after every successful edge reconcile.
func (s *Server) CheckEdgeRouteAlerts(ctx context.Context) {
	if s.edgeRecon == nil || s.alertStore == nil {
		return
	}
	now := time.Now()
	var leased map[string]bool
	var held map[selfheal.Key]bool
	if s.selfHeal != nil {
		leased, _ = s.selfHeal.ActiveExpectedDown(now.Unix())
		held, _ = s.selfHeal.ActiveHeld()
	}
	statuses := s.edgeRecon.RouteStatuses()
	s.edgeAlertMu.Lock()
	defer s.edgeAlertMu.Unlock()
	if s.edgeAlerted == nil {
		// First check since boot: re-adopt the alerts raised before a restart, so they still resolve.
		s.edgeAlerted = map[string]bool{}
		if open, err := s.alertStore.OpenInfraAlerts(ctx, "edge_unroutable"); err == nil {
			for key := range open {
				s.edgeAlerted[key] = true
			}
		}
	}
	live := map[string]bool{}
	for _, st := range statuses {
		key := "edge:" + st.Hostname + st.PathPrefix
		live[key] = true
		open := s.edgeAlerted[key]
		// A service the operator stopped answers 503 on purpose: no alert, and one raised before the
		// stop is resolved.
		stopped := held[selfheal.Key{App: st.AppID, Service: upstreamServiceName(st.Upstream)}]
		switch {
		case stopped && open:
			if err := s.alertStore.EnqueueInfra(ctx, alert.Outbox{
				Target: st.AppID, Kind: "edge_unroutable", Level: alert.LevelWarning, Transition: "resolved",
				Summary:   fmt.Sprintf("%s%s: its service was stopped by the operator", st.Hostname, st.PathPrefix),
				DedupeKey: key,
			}); err == nil {
				delete(s.edgeAlerted, key)
			}
		case st.State == edge.RouteUnroutable && !open && !stopped && !leased[st.AppID] && now.Sub(st.Since) >= edgeUnroutableAlertAfter:
			if err := s.alertStore.EnqueueInfra(ctx, alert.Outbox{
				Target: st.AppID, Kind: "edge_unroutable", Level: alert.LevelWarning, Transition: "firing",
				Summary:   fmt.Sprintf("%s%s answers 503: %s", st.Hostname, st.PathPrefix, st.Reason),
				DedupeKey: key,
			}); err == nil {
				s.edgeAlerted[key] = true
			}
		case st.State != edge.RouteUnroutable && open:
			if err := s.alertStore.EnqueueInfra(ctx, alert.Outbox{
				Target: st.AppID, Kind: "edge_unroutable", Level: alert.LevelWarning, Transition: "resolved",
				Summary:   fmt.Sprintf("%s%s is served again", st.Hostname, st.PathPrefix),
				DedupeKey: key,
			}); err == nil {
				delete(s.edgeAlerted, key)
			}
		}
	}
	// A route that no longer exists (app deleted, route removed) resolves its alert too.
	for key := range s.edgeAlerted {
		if !live[key] {
			_ = s.alertStore.EnqueueInfra(ctx, alert.Outbox{Kind: "edge_unroutable", Level: alert.LevelWarning,
				Transition: "resolved", Summary: strings.TrimPrefix(key, "edge:") + " was removed", DedupeKey: key})
			delete(s.edgeAlerted, key)
		}
	}
}
