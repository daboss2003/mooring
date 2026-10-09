package web

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// serviceLogDisplayCap bounds how many retained lines the history page renders at once (a display
// limit: the text filter + time range narrow within a service's whole retained history).
const serviceLogDisplayCap = 2000

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
	Range            string   // selected preset (see logRangePresets; ignored when At>0)
	Presets          []logRangePreset
	At               int64 // Errors-tab deep-link center (0 = none)
	Lines            []serviceLogLineView
	Capped           bool   // hit the display cap or the search budget (older matches may exist — narrow the filter/range)
	Window           string // the service's retention, e.g. "48 hours"
	MaxLines         string // the service's line cap, e.g. "2,000"
	Paused           bool   // capture paused for disk pressure
	ThresholdPct     int    // the disk-pressure threshold (server.disk_gc_threshold)
	DefaultWindow    string // the default policy, shown while paused
	DefaultMaxLines  string
}

// logRangePreset is one time-range choice on the log page.
type logRangePreset struct {
	Value, Label string
	secs         int64
}

// logRangePresets are the time-range choices; one is offered when the service retains at least
// that long ("all" always).
var logRangePresets = []logRangePreset{
	{"15m", "Last 15 min", 15 * 60},
	{"1h", "Last hour", 60 * 60},
	{"6h", "Last 6 hours", 6 * 60 * 60},
	{"24h", "Last 24 hours", 24 * 60 * 60},
	{"7d", "Last 7 days", 7 * 24 * 60 * 60},
	{"30d", "Last 30 days", 30 * 24 * 60 * 60},
	{"all", "All retained", 0},
}

// presetsFor returns the presets a service retaining for retain can use.
func presetsFor(retain time.Duration) []logRangePreset {
	var out []logRangePreset
	for _, p := range logRangePresets {
		if p.secs == 0 || time.Duration(p.secs)*time.Second <= retain {
			out = append(out, p)
		}
	}
	return out
}

// retainLabel renders a retention for the page: "90 minutes", "48 hours", "30 days".
func retainLabel(d time.Duration) string {
	plural := func(n int64, unit string) string {
		if n == 1 {
			return "1 " + unit
		}
		return strconv.FormatInt(n, 10) + " " + unit + "s"
	}
	switch {
	case d >= 72*time.Hour && d%(24*time.Hour) == 0:
		return plural(int64(d/(24*time.Hour)), "day")
	case d >= time.Hour && d%time.Hour == 0:
		return plural(int64(d/time.Hour), "hour")
	case d >= time.Minute:
		return plural(int64(d/time.Minute), "minute")
	}
	return plural(int64(d/time.Second), "second")
}

// groupDigits renders n with thousands separators: 200000 → "200,000".
func groupDigits(n int) string {
	s := strconv.Itoa(n)
	if n < 0 {
		return s
	}
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// serviceLogLineView is one retained log line for the template. Level is a best-effort severity
// ("error"|"warn"|"debug"|"") used only for color-coding.
type serviceLogLineView struct {
	At    int64
	Copy  string
	Text  string
	Level string
}

var (
	logErrTokens   = map[string]bool{"error": true, "err": true, "errors": true, "fatal": true, "panic": true, "critical": true, "crit": true, "alert": true, "emerg": true, "emergency": true, "exception": true, "severe": true, "failure": true}
	logWarnTokens  = map[string]bool{"warn": true, "warning": true}
	logDebugTokens = map[string]bool{"debug": true, "trace": true, "verbose": true}
	// logStatusRe matches an HTTP status code that is the VALUE OF A STATUS FIELD — status / statusCode
	// / status_code = 4xx|5xx — so a bare 3-digit number elsewhere in the line (a response time, byte
	// count, port) is NOT mistaken for a status. The key must be exactly status(code) followed by a real
	// `:`/`=` (so statusTime / statusCount don't qualify), tolerating surrounding quotes/spaces for
	// pretty-printed JSON. `[ \t]` (not `\s`) keeps this byte-identical to the JS mirror (RE2's `\s` is
	// ASCII, JS's is Unicode); \b rejects a longer digit run.
	logStatusRe = regexp.MustCompile(`status(?:_?code)?["']?[ \t]*[:=][ \t]*["']?([1-5][0-9][0-9])\b`)
)

// logLevel classifies a log line's severity for color-coding, from its level keyword or an HTTP status
// code, returning the highest severity found — "error", "warn", "debug", or "" (none/normal). Level
// keywords are matched on whole alphanumeric tokens (so "level=error"/"[ERROR]" classify but "stderr"
// does not); a status code counts only when it is a status field's value (5xx → error, 4xx → warn).
func logLevel(text string) string {
	lower := strings.ToLower(text)
	var hasErr, hasWarn, hasDebug bool

	var b strings.Builder
	classify := func() {
		if b.Len() == 0 {
			return
		}
		t := b.String()
		b.Reset()
		switch {
		case logErrTokens[t]:
			hasErr = true
		case logWarnTokens[t]:
			hasWarn = true
		case logDebugTokens[t]:
			hasDebug = true
		}
	}
	for _, r := range lower {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			classify()
		}
	}
	classify()

	for _, m := range logStatusRe.FindAllStringSubmatch(lower, -1) {
		switch m[1][0] {
		case '5':
			hasErr = true
		case '4':
			hasWarn = true
		}
	}

	switch {
	case hasErr:
		return "error"
	case hasWarn:
		return "warn"
	case hasDebug:
		return "debug"
	}
	return ""
}

// serviceLogView builds the retained-log view model from the request (q / range / copy / at). Shared
// by the full page and the live-refresh rows fragment so the two can't drift. Reads the servicelog
// store; the retention shown is the one the store applies (servicelog.Store.Policy).
func (s *Server) serviceLogView(r *http.Request) *serviceLogView {
	project := r.PathValue("project")
	service := r.PathValue("service")
	v := &serviceLogView{
		Project: project, Service: service,
		Enabled: s.cfg.Server.ServiceLogOn() && s.serviceLogs != nil,
	}
	if !v.Enabled {
		return v
	}
	pol := s.serviceLogs.Policy(project, service)
	v.Window, v.MaxLines = retainLabel(pol.Retain), groupDigits(pol.MaxLines)
	v.Presets = presetsFor(pol.Retain)
	if v.Paused = s.serviceLogs.Paused(); v.Paused {
		def := s.serviceLogs.Default()
		v.ThresholdPct = s.cfg.Server.DiskGCThresholdPct()
		v.DefaultWindow, v.DefaultMaxLines = retainLabel(def.Retain), groupDigits(def.MaxLines)
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
		// Only an offered preset applies; anything else (a stale link, a range longer than the
		// service keeps) shows everything retained.
		var secs int64
		found := false
		for _, p := range v.Presets {
			if p.Value == v.Range {
				secs, found = p.secs, true
			}
		}
		if !found {
			v.Range = "all"
		}
		if secs > 0 {
			since = time.Now().Unix() - secs
		}
	}

	// The request's context: a viewer who leaves (or a live poll that is superseded) stops the search.
	lines, more := s.serviceLogs.Search(r.Context(), project, service, copyID, q, since, until, serviceLogDisplayCap)
	for _, l := range lines {
		v.Lines = append(v.Lines, serviceLogLineView{At: l.At, Copy: l.Copy, Text: l.Text, Level: logLevel(l.Text)})
	}
	v.Capped = more
	return v
}

// handleServiceLogHistory renders one service's retained, searchable logs. Read-only, auth-gated. A
// ?at=<unix> query (from an Errors-tab entry) centers the window on that time; otherwise a ?range=
// preset applies and the list refreshes live from handleServiceLogRows.
func (s *Server) handleServiceLogHistory(w http.ResponseWriter, r *http.Request) {
	v := s.serviceLogView(r)
	s.render(w, r, "service_logs.html", tmplData{
		Title:      v.Service + " logs — " + v.Project,
		Username:   sessionUser(r),
		Project:    v.Project,
		ServiceLog: v,
	})
}

// handleServiceLogRows renders just the log-lines fragment for the page's live poll.
func (s *Server) handleServiceLogRows(w http.ResponseWriter, r *http.Request) {
	s.renderPartial(w, "servicelogrows", tmplData{ServiceLog: s.serviceLogView(r)})
}
