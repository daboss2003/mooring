package web

import (
	"net/http"
	"sort"
)

// errorsAppView groups an app's erroring routes for the Errors tab.
type errorsAppView struct {
	App    string
	Routes []errorsRouteView
}

// errorsRouteView is one route's error rollup + its recent entries (for the accordion body).
type errorsRouteView struct {
	App, Service, Host, Prefix string
	RoutePath                  string // the prefix, or "/" for a whole-host route
	Count24h, CountHour        int
	Count5xx                   int
	LastAt                     int64
	LastStatus                 int
	Entries                    []errorEntryView
}

// errorEntryView is one error response as shown in the (filterable) list.
type errorEntryView struct {
	At       int64
	Method   string
	Path     string
	Status   int
	RemoteIP string
	DurMs    float64
}

// perRouteEntryCap bounds how many recent errors are rendered per route accordion (client filter
// narrows within them; the store keeps far more within the 24h TTL for the count rollups).
const perRouteEntryCap = 100

// errorsData builds the Errors-tab view model: every route that has returned a 4xx/5xx in the last
// 24h, grouped by app (alphabetical), each with its recent entries. Shared by the full page and the
// live-refresh fragment so the two can't drift.
func (s *Server) errorsData(r *http.Request) tmplData {
	d := tmplData{Title: "Errors — Mooring", Username: sessionUser(r), ServiceLogEnabled: s.cfg.Server.ServiceLogOn() && s.serviceLogs != nil}
	if s.edgeErrors != nil {
		byApp := map[string]*errorsAppView{}
		var order []string
		for _, rt := range s.edgeErrors.Routes() {
			rv := errorsRouteView{
				App: rt.App, Service: rt.Service, Host: rt.Host, Prefix: rt.Prefix, RoutePath: routeDisplayPath(rt.Prefix),
				Count24h: rt.Count24h, CountHour: rt.CountHour, Count5xx: rt.Count5xx, LastAt: rt.LastAt, LastStatus: rt.LastStatus,
			}
			for _, e := range s.edgeErrors.Errors(rt.App, rt.Host, rt.Prefix, "", perRouteEntryCap) {
				rv.Entries = append(rv.Entries, errorEntryView{At: e.At, Method: e.Method, Path: e.Path, Status: e.Status, RemoteIP: e.RemoteIP, DurMs: e.DurMs})
			}
			a := byApp[rt.App]
			if a == nil {
				a = &errorsAppView{App: rt.App}
				byApp[rt.App] = a
				order = append(order, rt.App)
			}
			a.Routes = append(a.Routes, rv)
		}
		sort.Strings(order) // apps alphabetical; routes within an app stay recency-ordered
		for _, app := range order {
			d.ErrorApps = append(d.ErrorApps, *byApp[app])
		}
	}
	return d
}

// handleErrors renders the Errors tab. Read-only; auth-gated. The body refreshes live from
// handleErrorsPartial.
func (s *Server) handleErrors(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "errors.html", s.errorsData(r))
}

// handleErrorsPartial renders just the Errors body fragment for the page's live poll.
func (s *Server) handleErrorsPartial(w http.ResponseWriter, r *http.Request) {
	s.renderPartial(w, "errorsbody", s.errorsData(r))
}

// routeDisplayPath renders a route's path prefix for display ("" = the whole host → "/").
func routeDisplayPath(prefix string) string {
	if prefix == "" {
		return "/"
	}
	return prefix
}
