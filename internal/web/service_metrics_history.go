package web

import (
	"encoding/json"
	"net/http"
)

// serviceErrorBucketSecs buckets the error-rate history at 5 minutes over the edge-error store's 24h
// window — a readable trend without a per-second series.
const serviceErrorBucketSecs = 300

// serviceMetricPoint is one time-sample of a service's resource use, aggregated across the service's
// RUNNING replicas at that timestamp: CPU% and memory are per-replica AVERAGES (so a scaled service
// reads as "the average running copy", and the % never exceeds one replica's ceiling). Bytes are sent
// raw; the client scales the memory chart to the window's peak.
type serviceMetricPoint struct {
	T        int64   `json:"t"`
	CPU      float64 `json:"cpu"`
	MemBytes int64   `json:"memBytes"`
	MemLimit int64   `json:"memLimit"`
}

// serviceErrorPoint is one 5-minute bucket of the service's edge (4xx/5xx) errors.
type serviceErrorPoint struct {
	T        int64 `json:"t"`
	Count    int   `json:"count"`
	Count5xx int   `json:"count5xx"`
}

// handleServiceMetricsHistory returns one service's recent metric history as JSON for the per-service
// trend charts (read plane): CPU% + memory from the already-persisted container_metrics ring, and an
// error-rate series derived from the edge-error store (24h). It is a protected route (requireAuth,
// GET, no-store) and reads with ONE flat GROUP BY query — no nested per-row query, so it can never
// self-deadlock the single-conn DB. Output is oldest→newest so the client can append.
func (s *Server) handleServiceMetricsHistory(w http.ResponseWriter, r *http.Request) {
	project := r.PathValue("project")
	service := r.PathValue("service")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	out := struct {
		Points []serviceMetricPoint `json:"points"`
		Errors []serviceErrorPoint  `json:"errors"`
	}{Points: []serviceMetricPoint{}, Errors: []serviceErrorPoint{}}

	if s.db != nil {
		// GROUP BY ts collapses a scaled service's per-replica rows into one point per timestamp
		// (uses the container_metrics_proj_ts index). Newest N, then reversed to chronological. Only
		// state='running' rows are averaged: the monitor persists a zero cpu/mem row for a non-running
		// replica, and folding those into the AVG would dilute a scaled service's trend toward zero when
		// a copy is briefly down (a rolling redeploy or a crash-looping replica). A ts where every copy
		// is down simply yields no point (an honest gap), not a false dip.
		rows, err := s.db.QueryContext(r.Context(),
			`SELECT ts, AVG(cpu_pct), AVG(mem_bytes), MAX(mem_limit)
			   FROM container_metrics
			  WHERE project=? AND service=? AND state='running'
			  GROUP BY ts ORDER BY ts DESC LIMIT ?`, project, service, metricsHistoryLimit)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		var rev []serviceMetricPoint
		for rows.Next() {
			var p serviceMetricPoint
			var mem float64 // AVG() returns a float even over integer bytes
			if err := rows.Scan(&p.T, &p.CPU, &mem, &p.MemLimit); err != nil {
				rows.Close()
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			p.MemBytes = int64(mem)
			rev = append(rev, p)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		rows.Close()
		out.Points = make([]serviceMetricPoint, 0, len(rev))
		for i := len(rev) - 1; i >= 0; i-- {
			out.Points = append(out.Points, rev[i])
		}
	}

	// Error-rate history from the edge-error store (in-memory, 24h TTL; off the SQLite DB entirely).
	// All-zero when the app isn't edge-fronted or simply hasn't errored — a flat "0 errors" trend.
	if s.edgeErrors != nil {
		for _, b := range s.edgeErrors.RateBuckets(project, service, serviceErrorBucketSecs, 0) {
			out.Errors = append(out.Errors, serviceErrorPoint{T: b.T, Count: b.Count, Count5xx: b.Count5xx})
		}
	}
	_ = json.NewEncoder(w).Encode(out)
}
