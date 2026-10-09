package web

import (
	"net/http"
	"strconv"
	"strings"
)

// M11 managed-edge UI. Per-app public routes are READ-ONLY in the dashboard: they are
// declared in the app's mooring.yaml (the single source of truth) and reconciled onto
// the edge at deploy. This page shows the deployed routes; to add/change/remove one,
// edit mooring.yaml and deploy.

type edgeRouteView struct {
	ID              int64
	AppID           string
	Hostname        string
	Upstream        string
	UpstreamScheme  string
	PathPrefix      string
	HSTS            bool
	SecurityHeaders bool
	Enabled         bool
	LB              string // replica selection; "least_conn" when the route sets none
}

type edgeView struct {
	Reason string // non-empty when the edge isn't owned (banner)
	Routes []edgeRouteView
}

func (s *Server) handleEdge(w http.ResponseWriter, r *http.Request) {
	if s.edgeRoutes == nil {
		http.Error(w, "edge unavailable", http.StatusServiceUnavailable)
		return
	}
	ev := &edgeView{Reason: s.edgeReason}
	if routes, err := s.edgeRoutes.List(); err == nil {
		for _, rt := range routes {
			lb := rt.LB
			if lb == "" {
				lb = "least_conn"
			}
			ev.Routes = append(ev.Routes, edgeRouteView{
				ID: rt.ID(), AppID: rt.AppID, Hostname: rt.Hostname, Upstream: rt.Upstream,
				UpstreamScheme: rt.UpstreamScheme, PathPrefix: rt.PathPrefix,
				HSTS: rt.HSTS, SecurityHeaders: rt.SecurityHeaders, Enabled: rt.Enabled, LB: lb,
			})
		}
	}
	s.render(w, r, "edge.html", tmplData{
		Title:     "Edge routes — Mooring",
		CSRFToken: CSRFToken(r.Context()),
		Username:  sessionUser(r),
		Edge:      ev,
	})
}

// parseUpstream splits a "service:port" selector into its parts. Used by the edge LB
// pool discovery to derive the service + port from a route's upstream selector.
func parseUpstream(s string) (service string, port int, ok bool) {
	s = strings.TrimSpace(s)
	i := strings.LastIndexByte(s, ':')
	if i <= 0 || i == len(s)-1 {
		return "", 0, false
	}
	p, err := strconv.Atoi(s[i+1:])
	if err != nil || p < 1 || p > 65535 {
		return "", 0, false
	}
	return s[:i], p, true
}
