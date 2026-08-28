package web

import (
	"net/http"
	"strconv"
	"time"
)

// serviceLogDisplayCap bounds how many retained lines the history page renders at once (the store
// keeps more within its TTL; the text filter + time range narrow to what's shown).
const serviceLogDisplayCap = 500

// deepLinkHalfWindow is the default ± seconds around an Errors-tab entry's timestamp when jumping to
// the service's logs (?at=<unix> with no explicit &window=).
const deepLinkHalfWindow int64 = 120

// serviceLogView backs the per-service retained-log search page.
type serviceLogView struct {
	Project, Service string
	Enabled          bool     // capture is on AND a store is wired
	Query            string   // current text filter
	Copy             string   // selected replica id ("" = all copies merged)
	Copies           []string // replica ids seen in the retained window
	Range            string   // selected preset: "15m" | "1h" | "6h" | "24h" | "all" (ignored when At>0)
	At               int64    // Errors-tab deep-link center (0 = none)
	Lines            []serviceLogLineView
	Capped           bool // hit the display cap (older matches exist — narrow the filter/range)
}

// serviceLogLineView is one retained log line for the template.
type serviceLogLineView struct {
	At   int64
	Copy string
	Text string
}

// rangePresetSeconds maps a time-range preset to a lookback in seconds (0 = no lower bound / "all").
func rangePresetSeconds(preset string) int64 {
	switch preset {
	case "15m":
		return 15 * 60
	case "1h":
		return 60 * 60
	case "6h":
		return 6 * 60 * 60
	case "24h":
		return 24 * 60 * 60
	default:
		return 0
	}
}

// handleServiceLogHistory renders one service's retained, searchable logs. Read-only, auth-gated. It
// reads ONLY the in-memory/file-backed servicelog store — never the SQLite DB. A ?at=<unix> query
// (from an Errors-tab entry) centers the window on that time; otherwise a ?range= preset applies.
func (s *Server) handleServiceLogHistory(w http.ResponseWriter, r *http.Request) {
	project := r.PathValue("project")
	service := r.PathValue("service")
	v := &serviceLogView{
		Project: project, Service: service,
		Enabled: s.cfg.Server.ServiceLogOn() && s.serviceLogs != nil,
	}
	data := tmplData{
		Title:      service + " logs — " + project,
		Username:   sessionUser(r),
		Project:    project,
		ServiceLog: v,
	}
	if !v.Enabled {
		s.render(w, r, "service_logs.html", data)
		return
	}

	q := r.URL.Query().Get("q")
	copyID := r.URL.Query().Get("copy")
	v.Query, v.Copy = q, copyID
	v.Copies = s.serviceLogs.Copies(project, service)

	var since, until int64
	if atStr := r.URL.Query().Get("at"); atStr != "" {
		if at, err := strconv.ParseInt(atStr, 10, 64); err == nil && at > 0 {
			v.At = at
			half := deepLinkHalfWindow
			if ws := r.URL.Query().Get("window"); ws != "" {
				if wsec, err := strconv.ParseInt(ws, 10, 64); err == nil && wsec > 0 && wsec <= 3600 {
					half = wsec
				}
			}
			since, until = at-half, at+half
		}
	} else {
		v.Range = r.URL.Query().Get("range")
		if v.Range == "" {
			v.Range = "1h"
		}
		if d := rangePresetSeconds(v.Range); d > 0 {
			since = time.Now().Unix() - d
		}
	}

	for _, l := range s.serviceLogs.Search(project, service, copyID, q, since, until, serviceLogDisplayCap) {
		v.Lines = append(v.Lines, serviceLogLineView{At: l.At, Copy: l.Copy, Text: l.Text})
	}
	v.Capped = len(v.Lines) >= serviceLogDisplayCap
	s.render(w, r, "service_logs.html", data)
}
