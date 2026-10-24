package web

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/daboss2003/mooring/internal/edge"
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
	CatchAll        bool   // a namespace catch-all route (hostname is *.<apex>)
}

// edgeDarkView is a catch-all the catch-all watch found serving no certificate (banner).
type edgeDarkView struct {
	Apex  string
	Cause string
}

// edgePluginView is one DNS provider's Caddy plugin state.
type edgePluginView struct {
	Provider  string
	State     string // installed | installing | failed | permanent | unreadable
	Attempts  int    // failed install attempts so far
	NextRetry int64  // unix seconds of the next install retry; 0 when none is pending
	Err       string // the last install failure, truncated
}

// edgeRefusedView is a namespace whose wildcard config Caddy refused.
type edgeRefusedView struct {
	Apex   string
	Reason string // Caddy's error (dns01 tokens redacted), truncated
}

type edgeView struct {
	Reason  string // non-empty when the edge isn't owned (banner)
	Dark    []edgeDarkView
	Plugins []edgePluginView
	Refused []edgeRefusedView
	Routes  []edgeRouteView
}

// pluginView maps a provider's plugin state to its Edge page row.
func pluginView(st edge.ProviderStatus) edgePluginView {
	v := edgePluginView{Provider: st.Provider, Attempts: st.Attempts, Err: deployText(st.Err, 300)}
	switch {
	case st.OK:
		v.State, v.Err = "installed", ""
	case st.Permanent:
		v.State = "permanent" // an unknown provider, or not installable on this host: Err says which
	case st.Err != "" && !st.Installing:
		v.State = "failed"
		if !st.NextAttempt.IsZero() {
			v.NextRetry = st.NextAttempt.Unix()
		}
	case st.SyncErr != "":
		v.State, v.Err = "unreadable", deployText(st.SyncErr, 300) // the running binary's modules can't be read; retried
	default:
		v.State = "installing" // the first attempt, or a retry in progress
	}
	return v
}

func (s *Server) handleEdge(w http.ResponseWriter, r *http.Request) {
	if s.edgeRoutes == nil {
		http.Error(w, "edge unavailable", http.StatusServiceUnavailable)
		return
	}
	ev := &edgeView{Reason: s.edgeReason, Dark: s.darkCatchAlls()}
	for _, st := range s.edgeDNSPlugins.Snapshot() {
		ev.Plugins = append(ev.Plugins, pluginView(st))
	}
	for _, rj := range s.edgeDNSPlugins.Rejected() {
		ev.Refused = append(ev.Refused, edgeRefusedView{Apex: rj.Apex, Reason: deployText(rj.Reason, 300)})
	}
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
				CatchAll: rt.CatchAll,
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
