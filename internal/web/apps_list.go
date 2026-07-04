package web

import "net/http"

// appsRow is one line in the Apps table: a unified view of every app Mooring knows —
// running ones (from the live snapshot) and provisioned ones not yet deployed.
type appsRow struct {
	Project     string
	DisplayName string
	Source      string
	Up, Total   int
	Degraded    bool
	Deployed    bool
}

// appsRows merges the live snapshot with the provisioned set into one ordered list
// (running apps first, in the operator's saved order; then provisioned-but-not-yet-
// deployed apps).
func (s *Server) appsRows() []appsRow {
	snap := s.snapshot()
	byProject := map[string]int{} // project -> index in out
	var out []appsRow
	for _, a := range s.orderedApps(snap) {
		byProject[a.Project] = len(out)
		out = append(out, appsRow{
			Project: a.Project, DisplayName: a.DisplayName, Source: "running",
			Up: a.UpCount(), Total: a.Total(), Degraded: a.Degraded(), Deployed: true,
		})
	}
	for _, p := range s.provisionedApps() {
		if i, ok := byProject[p.Slug]; ok {
			if p.Source != "" {
				out[i].Source = p.Source
			}
			continue
		}
		out = append(out, appsRow{
			Project: p.Slug, DisplayName: p.Slug, Source: p.Source,
			Up: p.UpCount, Total: p.Total, Deployed: p.Deployed,
		})
	}
	return out
}

// handleAppsList renders the Apps table.
func (s *Server) handleAppsList(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "apps.html", tmplData{
		Title:       "Apps — Mooring",
		CSRFToken:   CSRFToken(r.Context()),
		Username:    sessionUser(r),
		AppsRows:    s.appsRows(),
		PendingApps: s.pendingAppsList(),
	})
}
