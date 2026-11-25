package web

import (
	"bytes"
	"cmp"
	"context"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/query"
)

// The log Patterns pages (owner only, requirePerm("admin")): the templates an app service's log
// lines (and the host's unclassified lines) fall into, from Server.patterns (nil = log patterns are
// off). The Responses and Blocks pages share secPage with them.

const (
	patPageSize      = 50     // patterns per page
	patMaxOffset     = 100000 // the deepest page a link may ask for
	patDetectionsMax = 20     // a pattern's detections on its page
	patFindTerms     = 6      // text terms of a pattern's Find events search
	patFindTermMax   = 100    // bytes of each
	patHours         = 168    // hourly bars on a pattern's page
	patBarsHeight    = 40.0   // the bars' SVG height
)

// secPage is the view of the Patterns, Responses and Blocks pages: the shell's tmplData plus this
// page's model. At most one of the models is set.
type secPage struct {
	tmplData
	Pats      *patListView
	Pat       *patDetailView
	Resp      *respView
	Blocks    *blocksView
	Off       bool   // detection is off: the page shows only that
	PatOff    bool   // detection is on but log patterns are off
	RespOff   bool   // automated response isn't running
	NoBlocks  bool   // the block list isn't available
	NoEdgeWhy string // why Mooring doesn't run the edge, when it says
	Missing   string // what was asked for isn't there or couldn't be read: this message
}

// renderSec renders a full page of these sections with status (the shell backfill of renderDetect).
func (s *Server) renderSec(w http.ResponseWriter, r *http.Request, status int, name, title string, p *secPage) {
	p.Title = title + " — Mooring"
	p.CSRFToken = CSRFToken(r.Context())
	p.Username = sessionUser(r)
	p.EdgeMode = string(s.cfg.Edge.Mode)
	p.IdleTimeoutMs = s.cfg.Session.IdleTimeout.D().Milliseconds()
	p.UpdateBanner = s.updateBanner()
	p.CanAdmin = s.canAdmin(p.Username)
	s.writeSec(w, status, name, p)
}

// writeSec executes a template into a buffer first, so an error never sends half a page.
func (s *Server) writeSec(w http.ResponseWriter, status int, name string, p *secPage) {
	var buf bytes.Buffer
	if err := s.templates.ExecuteTemplate(&buf, name, p); err != nil {
		s.log.Warn("security pages: template failed", "template", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

var (
	patStateLabels = map[string]string{
		siem.PatternLearned: "Learned", siem.PatternNew: "New",
		siem.PatternExpected: "Expected", siem.PatternIgnored: "Spikes ignored",
	}
	// patStateClass is a state's pill class (an allowlist: State is stored data).
	patStateClass  = map[string]string{siem.PatternNew: "pill-warn", siem.PatternExpected: "pill-ok"}
	patStateFilter = []string{siem.PatternNew, siem.PatternLearned, siem.PatternExpected, siem.PatternIgnored}
	// patLevels are the minimum-level filter's choices (event levels).
	patLevels = []string{siem.LvlInfo, siem.LvlWarn, siem.LvlError, siem.LvlCritical}
	patSorts  = []sevOption{{Value: "", Label: "Last seen"}, {Value: "count", Label: "Most lines in 24 hours"}, {Value: "first", Label: "Newest first"}}
	// patIDPattern is a pattern's ID: "p" + 16 lowercase hex.
	patIDPattern = regexp.MustCompile(`^p[0-9a-f]{16}$`)
	// patPlaceholder is a template's variable part.
	patPlaceholder = regexp.MustCompile(`<(?:NUM|HEX|UUID|IP|TS|HASH|B64|STR|LONG|\*)>`)
)

func patStateLabel(st string) string {
	if l := patStateLabels[st]; l != "" {
		return l
	}
	return st
}

// patForm is the list's filter as submitted.
type patForm struct {
	App, Service       string
	Host               bool
	State, Level, Sort string
	Offset             int
}

// parsePatFilter reads the list's filter. An unknown state, level, sort or offset is ignored; a
// scope that can't be searched is a message for the owner (and no query).
func parsePatFilter(p url.Values) (siem.PatternFilter, patForm, string) {
	var form patForm
	f := siem.PatternFilter{Limit: patPageSize + 1} // one more than shown: is there a next page?
	form.App = siem.Cut(strings.TrimSpace(p.Get("app")), siem.MaxShort)
	form.Service = siem.Cut(strings.TrimSpace(p.Get("service")), siem.MaxShort)
	form.Host = p.Get("host") != ""
	if st := p.Get("state"); patStateLabels[st] != "" {
		form.State, f.States = st, []string{st}
	}
	if lv := p.Get("level"); slices.Contains(patLevels, lv) {
		form.Level, f.MinLevel = lv, lv
	}
	if so := p.Get("sort"); so == "count" || so == "first" {
		form.Sort, f.Sort = so, so
	}
	if n, err := strconv.Atoi(p.Get("offset")); err == nil && n > 0 {
		form.Offset = min(n, patMaxOffset)
	}
	f.Offset = form.Offset
	switch {
	case form.Host && (form.App != "" || form.Service != ""):
		return f, form, "Pick an app or the host, not both."
	case form.Service != "" && form.App == "":
		return f, form, "A service needs its app."
	}
	f.App, f.Service, f.Host = form.App, form.Service, form.Host
	return f, form, ""
}

// params is the query string of a list link with this filter, from offset.
func (f patForm) params(offset int) url.Values {
	v := url.Values{}
	for k, x := range map[string]string{"app": f.App, "service": f.Service, "state": f.State, "level": f.Level, "sort": f.Sort} {
		if x != "" {
			v.Set(k, x)
		}
	}
	if f.Host {
		v.Set("host", "1")
	}
	if offset > 0 {
		v.Set("offset", strconv.Itoa(offset))
	}
	return v
}

// patRow is one pattern as the list and its page show it.
type patRow struct {
	ID, URL                       string
	Template                      string
	Scope, ScopeURL               string // "<app>/<service>" or "Host", and that scope's patterns
	ScopeApp, ScopeSvc            string // an app service's Scope in its two parts (the list wraps it after the slash)
	Lvl, LvlClass                 string
	State, StateLabel, StateClass string
	First, FirstISO               string
	Last, LastISO, Ago            string
	Count                         string
}

func patRowOf(p *siem.Pattern, now time.Time) patRow {
	row := patRow{
		ID: p.ID, URL: "/security/patterns/" + url.PathEscape(p.ID), Template: p.Template,
		Lvl: p.Level, LvlClass: securityLevelClass[p.Level],
		State: p.State, StateLabel: patStateLabel(p.State), StateClass: patStateClass[p.State],
		Count: groupDigits(int(max(p.Count, 0))),
	}
	if row.LvlClass == "" {
		row.LvlClass = "sec-lvl-info"
	}
	switch {
	case p.Scope == "host":
		row.Scope, row.ScopeURL = "Host", withQuery("/security/patterns", url.Values{"host": {"1"}})
	case p.App != "" && p.Service != "":
		row.ScopeApp, row.ScopeSvc = p.App, p.Service
		row.Scope, row.ScopeURL = p.App+"/"+p.Service, withQuery("/security/patterns", url.Values{"app": {p.App}, "service": {p.Service}})
	case p.App != "":
		row.Scope, row.ScopeURL = p.App, withQuery("/security/patterns", url.Values{"app": {p.App}})
	default:
		row.Scope = p.Scope
	}
	if !p.Last.IsZero() {
		row.Last, row.LastISO, row.Ago = p.Last.UTC().Format(detectTimeFmt), p.Last.UTC().Format(time.RFC3339), secAgo(now, p.Last)
	}
	if !p.First.IsZero() {
		row.First, row.FirstISO = p.First.UTC().Format(detectTimeFmt), p.First.UTC().Format(time.RFC3339)
	}
	return row
}

// patScopeLabel is a stored scope key ("app:<slug>/<service>" or "host") as the rows' Scope says
// it: "<slug>/<service>" or "Host". Anything else is shown as stored.
func patScopeLabel(scope string) string {
	if scope == "host" {
		return "Host"
	}
	if rest, ok := strings.CutPrefix(scope, "app:"); ok && rest != "" {
		return rest
	}
	return scope
}

// patStatsView is the miner's state for the page header.
type patStatsView struct {
	Enabled                               bool
	Scopes, Patterns, Lines               string
	Unmined, Dropped, Overflowed          string
	Lost                                  bool // some lines were counted only, dropped or past a template cap
	Budget                                string
	BudgetPct                             float64
	Learning                              []string // scope labels, as the rows' Scope
	LearningMore                          bool     // the service lists at most 50
	HasUnmined, HasDropped, HasOverflowed bool
}

func patStatsOf(st siem.PatternStats) patStatsView {
	pct := riskPct(st.BudgetPct) // 0–100, NaN and negatives as 0
	v := patStatsView{
		Enabled: st.Enabled, Scopes: groupDigits(st.Scopes), Patterns: groupDigits(st.Patterns),
		Lines: groupDigits(int(max(st.Lines, 0))), Unmined: groupDigits(int(max(st.Unmined, 0))),
		Dropped: groupDigits(int(max(st.Dropped, 0))), Overflowed: groupDigits(int(max(st.Overflowed, 0))),
		HasUnmined: st.Unmined > 0, HasDropped: st.Dropped > 0, HasOverflowed: st.Overflowed > 0,
		Budget: strconv.Itoa(int(pct+0.5)) + "%", BudgetPct: pct,
		LearningMore: len(st.Learning) >= 50,
	}
	for _, sc := range st.Learning {
		v.Learning = append(v.Learning, patScopeLabel(sc))
	}
	v.Lost = v.HasUnmined || v.HasDropped || v.HasOverflowed
	return v
}

// patListView backs security_patterns.html and its live-refresh fragment.
type patListView struct {
	Form                  patForm
	States, Levels, Sorts []sevOption
	Stats                 patStatsView
	Err                   string
	failed                bool // Err is a read failure (500)
	Rows                  []patRow
	Filtered              bool
	PrevURL, NextURL      string
	FirstRow, LastRow     int // the rows' positions, from 1
	PollURL               string
	PollMS                int
}

// secPatternsList builds the list for the page, or for its live refresh (always the first page,
// the only one that refreshes).
func (s *Server) secPatternsList(r *http.Request, live bool) *patListView {
	f, form, errMsg := parsePatFilter(r.URL.Query())
	if live {
		f.Offset, form.Offset = 0, 0
	}
	v := &patListView{Form: form, Stats: patStatsOf(s.patterns.PatternStats()), PollMS: detectPollMS}
	v.Filtered = form.App != "" || form.Service != "" || form.Host || form.State != "" || form.Level != ""
	v.States = []sevOption{{Value: "", Label: "Any state", Selected: form.State == ""}}
	for _, st := range patStateFilter {
		v.States = append(v.States, sevOption{Value: st, Label: patStateLabel(st), Selected: st == form.State})
	}
	v.Levels = []sevOption{{Value: "", Label: "Any level", Selected: form.Level == ""}}
	for _, lv := range patLevels {
		label := strings.ToUpper(lv[:1]) + lv[1:] + " and above"
		if lv == siem.LvlCritical {
			label = "Critical"
		}
		v.Levels = append(v.Levels, sevOption{Value: lv, Label: label, Selected: lv == form.Level})
	}
	for _, o := range patSorts {
		o.Selected = o.Value == form.Sort
		v.Sorts = append(v.Sorts, o)
	}
	if errMsg != "" {
		v.Err = errMsg
		return v
	}
	ctx, cancel := context.WithTimeout(r.Context(), detectTimeout)
	defer cancel()
	list, err := s.patterns.Patterns(ctx, f)
	if err != nil {
		s.log.Warn("security patterns: list failed", "err", err)
		v.Err, v.failed = "The patterns could not be read. Mooring's log has the details.", true
		return v
	}
	more := len(list) > patPageSize
	if more {
		list = list[:patPageSize]
	}
	now := time.Now().UTC()
	for i := range list {
		v.Rows = append(v.Rows, patRowOf(&list[i], now))
	}
	if len(v.Rows) > 0 {
		v.FirstRow, v.LastRow = form.Offset+1, form.Offset+len(v.Rows)
	}
	if more && form.Offset+patPageSize <= patMaxOffset {
		v.NextURL = withQuery("/security/patterns", form.params(form.Offset+patPageSize))
	}
	if form.Offset > 0 {
		v.PrevURL = withQuery("/security/patterns", form.params(max(form.Offset-patPageSize, 0)))
	} else {
		v.PollURL = withQuery("/security/patterns/rows", form.params(0))
	}
	return v
}

// patOff sets the page's off state when the Patterns pages can't run: detection off, or log
// patterns off. It reports whether it did.
func (s *Server) patOff(p *secPage) bool {
	switch {
	case s.patterns != nil:
		return false
	case s.detections == nil:
		p.Off = true
	default:
		p.PatOff = true
	}
	return true
}

// handleSecPatterns renders the Patterns page (GET /security/patterns).
func (s *Server) handleSecPatterns(w http.ResponseWriter, r *http.Request) {
	p := &secPage{}
	status := http.StatusOK
	if !s.patOff(p) {
		p.Pats = s.secPatternsList(r, false)
		if p.Pats.failed {
			status = http.StatusInternalServerError
		}
	}
	s.renderSec(w, r, status, "security_patterns.html", "Log patterns", p)
}

// handleSecPatternRows renders the first page's list for its live refresh.
func (s *Server) handleSecPatternRows(w http.ResponseWriter, r *http.Request) {
	p := &secPage{}
	status := http.StatusOK
	if !s.patOff(p) {
		p.Pats = s.secPatternsList(r, true)
		if p.Pats.failed {
			status = http.StatusInternalServerError
		}
	}
	s.writeSec(w, status, "secpatlist", p)
}

// patBar is one hour of a pattern's bars (SVG coordinates).
type patBar struct {
	X, Y, H string
	Title   string
}

// patDetailView backs security_pattern.html.
type patDetailView struct {
	patRow
	Sample            string
	Bars              []patBar
	Peak, Last24      string
	DetsOn            bool // the detection service is set: the pattern's detections are listed
	Dets              []detectionRow
	DetErr            string
	FindURL, FindTerm string
	Actions           []incAction
	Notice, Err       string
}

// patBars draws lines per hour, oldest first, as bars right-aligned on a patHours-wide axis ending
// at the current hour.
func patBars(hourly []uint32, now time.Time) (bars []patBar, peak, last24 int) {
	if len(hourly) > patHours {
		hourly = hourly[len(hourly)-patHours:]
	}
	for i, n := range hourly {
		peak = max(peak, int(n))
		if i >= len(hourly)-24 {
			last24 += int(n)
		}
	}
	if peak == 0 {
		return nil, 0, 0
	}
	hour := now.UTC().Truncate(time.Hour)
	offset := patHours - len(hourly)
	f := func(x float64) string { return strconv.FormatFloat(x, 'f', 2, 64) }
	for i, n := range hourly {
		if n == 0 {
			continue
		}
		h := max(float64(n)/float64(peak)*patBarsHeight, 0.6)
		start := hour.Add(-time.Duration(len(hourly)-1-i) * time.Hour)
		lines := groupDigits(int(n)) + " lines"
		if n == 1 {
			lines = "1 line"
		}
		bars = append(bars, patBar{
			X: f(float64(offset+i) + 0.1), Y: f(patBarsHeight - h), H: f(h),
			Title: start.Format("2006-01-02 15:00") + " UTC: " + lines,
		})
	}
	return bars, peak, last24
}

// patActions are the state buttons offered from st.
func patActions(st string) []incAction {
	expected := incAction{siem.PatternExpected, "Mark expected", false}
	ignore := incAction{siem.PatternIgnored, "Ignore spikes", false}
	watch := incAction{siem.PatternLearned, "Watch again", true}
	switch st {
	case siem.PatternNew:
		expected.Primary = true
		return []incAction{expected, ignore, {siem.PatternLearned, "Keep watching", false}}
	case siem.PatternLearned:
		return []incAction{expected, ignore}
	case siem.PatternExpected:
		return []incAction{watch, ignore}
	case siem.PatternIgnored:
		return []incAction{watch, expected}
	}
	watch.Primary = false
	return []incAction{expected, ignore, watch}
}

// unsearchable reports a character a Find events term can't carry: a control character, or a
// Unicode format character (category Cf: a bidi override, a zero-width space, a byte order mark),
// which is invisible in the search box and can reorder what the owner reads there.
func unsearchable(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }

// patternSearch is the Security logs search of a pattern's "Find events" link ("" when there is
// none): its scope (app:<app> svc:<service>, or src:host) and up to patFindTerms of the template's
// constant parts as quoted text, the longest first, each cut to patFindTermMax bytes. The search
// must parse back to exactly those terms and texts, so no template can widen or break it.
func patternSearch(p *siem.Pattern) string {
	type pair struct{ field, value string }
	var want []pair
	switch {
	case p.Scope == "host":
		want = []pair{{"src", siem.SrcHost}}
	case p.App != "":
		want = []pair{{"app", p.App}}
		if p.Service != "" {
			want = append(want, pair{"svc", p.Service})
		}
	default:
		return ""
	}
	for _, w := range want {
		if strings.HasSuffix(w.value, "*") { // would search as a prefix
			return ""
		}
	}
	type frag struct {
		text string
		pos  int
	}
	var frags []frag
	seen := map[string]bool{}
	for _, tok := range strings.Fields(p.Template) {
		for _, part := range patPlaceholder.Split(tok, -1) {
			part = siem.Cut(part, patFindTermMax)
			key := strings.ToLower(part)
			if utf8.RuneCountInString(part) < 2 || !utf8.ValidString(part) || strings.IndexFunc(part, unsearchable) >= 0 || seen[key] {
				continue
			}
			seen[key] = true
			frags = append(frags, frag{part, len(frags)})
		}
	}
	slices.SortStableFunc(frags, func(a, b frag) int { return cmp.Compare(len(b.text), len(a.text)) })
	frags = frags[:min(len(frags), patFindTerms)]
	slices.SortFunc(frags, func(a, b frag) int { return cmp.Compare(a.pos, b.pos) })
	parts := make([]string, 0, len(want)+len(frags))
	for _, w := range want {
		parts = append(parts, searchTerm(w.field, w.value))
	}
	for _, f := range frags {
		parts = append(parts, quoteSecurityValue(f.text, true))
	}
	search := strings.Join(parts, " ")
	q, err := query.Parse(search)
	if err != nil || len(q.Terms) != len(want) || len(q.Text) != len(frags) {
		return ""
	}
	for i, t := range q.Terms {
		if t.Field != want[i].field || t.Value != want[i].value || t.Op != query.OpEq || t.Neg {
			return ""
		}
	}
	for i, x := range q.Text {
		if x != frags[i].text {
			return ""
		}
	}
	return search
}

func patDetailOf(p *siem.Pattern, now time.Time) *patDetailView {
	v := &patDetailView{patRow: patRowOf(p, now), Sample: p.Sample, Actions: patActions(p.State)}
	var peak, last24 int
	v.Bars, peak, last24 = patBars(p.Hourly, now)
	v.Peak, v.Last24 = groupDigits(peak), groupDigits(last24)
	if search := patternSearch(p); search != "" {
		v.FindTerm = search
		if !p.First.IsZero() && !p.Last.IsZero() {
			v.FindURL = detectSearchURL([]string{search}, p.First.Add(-detectSearchPad), p.Last.Add(detectSearchPad))
		} else {
			v.FindURL = "/security?" + securityParams(search, entitySearchRange, time.Time{}, time.Time{}).Encode()
		}
	}
	return v
}

// patDoneText are the fixed notices of a pattern page's ?done= (the state it was set to).
var patDoneText = map[string]string{
	siem.PatternExpected: "Marked as expected: the pattern rules stay silent for it.",
	siem.PatternIgnored:  "Spikes ignored: the spike rule stays silent for it.",
	siem.PatternLearned:  "Watching again: the pattern rules report it again.",
}

const patDetailTmpl = "security_pattern.html"

// handleSecPattern renders one pattern (GET /security/patterns/{id}).
func (s *Server) handleSecPattern(w http.ResponseWriter, r *http.Request) {
	p := &secPage{}
	if s.patOff(p) {
		s.renderSec(w, r, http.StatusOK, patDetailTmpl, "Log pattern", p)
		return
	}
	id := r.PathValue("id")
	if !patIDPattern.MatchString(id) {
		s.renderSec(w, r, http.StatusNotFound, patDetailTmpl, "Log pattern", &secPage{Missing: "Pattern not found."})
		return
	}
	s.showPattern(w, r, http.StatusOK, id, patDoneText[r.URL.Query().Get("done")], "")
}

// showPattern renders pattern id with a notice, or with a refused change's message and status.
func (s *Server) showPattern(w http.ResponseWriter, r *http.Request, status int, id, notice, errMsg string) {
	ctx, cancel := context.WithTimeout(r.Context(), detectTimeout)
	defer cancel()
	pat, ok, err := s.patterns.Pattern(ctx, id)
	switch {
	case err != nil:
		s.log.Warn("security patterns: read failed", "id", id, "err", err)
		s.renderSec(w, r, http.StatusInternalServerError, patDetailTmpl, "Log pattern", &secPage{Missing: "The pattern could not be read. Mooring's log has the details."})
		return
	case !ok:
		s.renderSec(w, r, http.StatusNotFound, patDetailTmpl, "Log pattern", &secPage{Missing: "Pattern not found."})
		return
	}
	now := time.Now().UTC()
	v := patDetailOf(&pat, now)
	v.Notice, v.Err = notice, errMsg
	if s.detections != nil {
		v.DetsOn = true
		dets, err := s.detections.Detections(ctx, siem.DetectionFilter{Key: pat.ID, Limit: patDetectionsMax})
		if err != nil {
			s.log.Warn("security patterns: detections failed", "id", id, "err", err)
			v.DetErr = "The detections could not be read. Mooring's log has the details."
		}
		for i := range dets {
			v.Dets = append(v.Dets, detectionRowOf(&dets[i], now))
		}
	}
	s.renderSec(w, r, status, patDetailTmpl, "Log pattern", &secPage{Pat: v})
}

// handleSecPatternState marks a pattern expected, ignores its spikes, or watches it again
// (POST /security/patterns/{id}/state).
func (s *Server) handleSecPatternState(w http.ResponseWriter, r *http.Request) {
	const action = "security_pattern_state"
	if p := (&secPage{}); s.patOff(p) {
		s.renderSec(w, r, http.StatusServiceUnavailable, "security_patterns.html", "Log patterns", p)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id := r.PathValue("id")
	if !patIDPattern.MatchString(id) {
		s.detectAudit(r, action, "pattern", audit.Error, "result=not found")
		s.renderSec(w, r, http.StatusNotFound, patDetailTmpl, "Log pattern", &secPage{Missing: "Pattern not found."})
		return
	}
	target := "pattern:" + id
	state := r.PostFormValue("state")
	if patDoneText[state] == "" {
		s.detectAudit(r, action, target, audit.Error, "result=rejected")
		s.showPattern(w, r, http.StatusUnprocessableEntity, id, "", "Pick a state: expected, spikes ignored or watch again.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), detectTimeout)
	defer cancel()
	if err := s.patterns.SetPatternState(ctx, id, state, sessionUser(r)); err != nil {
		status, msg, result := s.serviceError(err, "The state was not saved", "security patterns: state", "id", id)
		s.detectAudit(r, action, target, audit.Error, "state="+state+" result="+result)
		s.showPattern(w, r, status, id, "", msg)
		return
	}
	s.detectAudit(r, action, target, audit.OK, "state="+state)
	http.Redirect(w, r, withQuery("/security/patterns/"+id, url.Values{"done": {state}}), http.StatusSeeOther)
}
