package web

import "time"

// unixTS renders a unix timestamp as its UTC display string (e.g. "2026-07-04
// 12:00:05 UTC"), or an em-dash when absent. It is the text INSIDE the "ts" template
// (see templates/_layout.html), which wraps it in a <time data-ts> element that
// app.js rewrites to the viewer's own timezone on load — the strict CSP forbids inline
// JS, so localisation lives in the external app.js. The <time> element itself is built
// in the template layer (auto-escaped) rather than via template.HTML, so no code path
// bypasses html/template escaping (SEC-3). Returns a plain string.
func unixTS(ts int64) string {
	if ts <= 0 {
		return "—"
	}
	return time.Unix(ts, 0).UTC().Format("2006-01-02 15:04:05") + " UTC"
}
