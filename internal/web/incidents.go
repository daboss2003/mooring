package web

import (
	"net/http"

	"github.com/daboss2003/mooring/internal/selfheal"
)

// The Incidents screen is the operator's "what needs me right now" view: it pulls
// together open alerts, unhealthy apps, services the self-healer has given up on
// (circuit open), and recent denied/errored actions — so problems live in one place
// instead of scattered across pages.

type incidentsView struct {
	Alerts    []firingView
	Unhealthy []incidentApp
	Circuit   []incidentSvc
	Failures  []incidentEvent
}

type incidentApp struct {
	Project     string
	DisplayName string
	Up, Total   int
}

type incidentSvc struct{ App, Service string }

type incidentEvent struct {
	When    int64 // unix seconds; the "ts" template renders it localised
	Action  string
	Target  string
	Outcome string
	Detail  string
}

// Clear reports whether there are no incidents (the all-clear state).
func (v *incidentsView) Clear() bool {
	return len(v.Alerts) == 0 && len(v.Unhealthy) == 0 && len(v.Circuit) == 0 && len(v.Failures) == 0
}

func (s *Server) handleIncidents(w http.ResponseWriter, r *http.Request) {
	iv := &incidentsView{}

	// Open alerts (firing + not silenced), if alerting is configured.
	if s.alertStore != nil {
		if firing, err := s.alertStore.FiringStates(); err == nil {
			for _, f := range firing {
				iv.Alerts = append(iv.Alerts, firingView{
					RuleID: f.RuleID, Target: f.Target, Level: f.Level, Detail: f.Detail,
					Since: f.Since, Acked: f.Acked,
				})
			}
		}
	}

	// Unhealthy apps from the latest snapshot. Protected/managed projects (the
	// read-plane proxy) are Mooring's own infrastructure — surfaced as System tiles,
	// never as operator-actionable incidents.
	if snap := s.snapshot(); snap != nil {
		for _, a := range snap.Apps {
			if a.Degraded() && !s.cfg.IsProtectedProject(a.Project) {
				iv.Unhealthy = append(iv.Unhealthy, incidentApp{
					Project: a.Project, DisplayName: a.DisplayName, Up: a.UpCount(), Total: a.Total(),
				})
			}
		}
	}

	// Services the self-healer has latched open (it tried and gave up — needs a human).
	if s.selfHeal != nil {
		if all, err := s.selfHeal.LoadAll(); err == nil {
			for k, f := range all {
				if f.Phase == selfheal.CircuitOpen && !s.cfg.IsProtectedProject(k.App) {
					iv.Circuit = append(iv.Circuit, incidentSvc{App: k.App, Service: k.Service})
				}
			}
		}
	}

	// Recent denied / errored actions from the audit trail.
	if s.db != nil {
		rows, err := s.db.QueryContext(r.Context(),
			`SELECT ts, action, target, outcome, detail FROM events
			 WHERE outcome IN ('deny','error') ORDER BY seq DESC LIMIT 25`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var e incidentEvent
				var ts int64
				if err := rows.Scan(&ts, &e.Action, &e.Target, &e.Outcome, &e.Detail); err != nil {
					break
				}
				e.When = ts
				iv.Failures = append(iv.Failures, e)
			}
		}
	}

	s.render(w, r, "incidents.html", tmplData{
		Title:     "Incidents — Mooring",
		CSRFToken: CSRFToken(r.Context()),
		Incidents: iv,
	})
}
