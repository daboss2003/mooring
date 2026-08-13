package web

import "net/http"

// handleActivity renders the Activity tab: Mooring's own recent WARN/ERROR operational events
// (deploys, image builds/scans, backups, git-fetch failures, scale decisions, self-heal actions),
// deduped with a count + last-seen and retained ~24h. It's the in-dashboard replacement for
// `journalctl -u mooring | grep …`. Read-only; auth-gated like the Server tab.
func (s *Server) handleActivity(w http.ResponseWriter, r *http.Request) {
	d := tmplData{Title: "Activity — Mooring"}
	if s.eventLog != nil {
		d.Activity = s.eventLog.List()
	}
	s.render(w, r, "activity.html", d)
}
