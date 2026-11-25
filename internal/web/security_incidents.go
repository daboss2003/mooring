package web

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/siem"
)

// The security Incidents pages (owner only, requirePerm("admin")): related detections of an account
// or address grouped into one incident, with a timeline and a workflow (state, assignee, notes,
// false positive), from Server.incidentSvc (nil = detection is off). The viewer-readable /incidents
// page (incidents.go) lists Mooring's alerts and is a different thing.

const (
	incPageSize = 50 // incidents per page
	incRiskyMax = 10 // entities in the Highest risk panel
)

// incPage is the view of the Incidents, incident and entity pages: the shell's tmplData plus this
// page's model. Exactly one of the models is set.
type incPage struct {
	tmplData
	List    *incListView
	One     *incDetailView
	Ent     *entityView
	Off     bool   // detection is off: the page shows only that
	Missing string // what was asked for isn't there, couldn't be read or isn't valid: this message
}

// renderInc renders a full page of these sections with status (the shell backfill of renderDetect).
func (s *Server) renderInc(w http.ResponseWriter, r *http.Request, status int, name, title string, p *incPage) {
	p.Title = title + " — Mooring"
	p.CSRFToken = CSRFToken(r.Context())
	p.Username = sessionUser(r)
	p.EdgeMode = string(s.cfg.Edge.Mode)
	p.IdleTimeoutMs = s.cfg.Session.IdleTimeout.D().Milliseconds()
	p.UpdateBanner = s.updateBanner()
	p.CanAdmin = s.canAdmin(p.Username)
	s.writeInc(w, status, name, p)
}

// writeInc executes a template into a buffer first, so an error never sends half a page.
func (s *Server) writeInc(w http.ResponseWriter, status int, name string, p *incPage) {
	var buf bytes.Buffer
	if err := s.templates.ExecuteTemplate(&buf, name, p); err != nil {
		s.log.Warn("security incidents: template failed", "template", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

// incidentOwners is who an incident can be assigned to: the owners of the live user set (a config
// reload included), the auth owner first, then the users: owners by name. Deployers and viewers
// can't open the incident pages, so they are never offered.
func (s *Server) incidentOwners() []string {
	sec := s.security()
	if sec == nil {
		return nil
	}
	var names []string
	for n, u := range sec.users {
		if u.role == config.RoleOwner {
			names = append(names, n)
		}
	}
	// s.cfg is the startup config: after a reload renames the auth owner, the new name sorts with
	// the others until a restart (the live set itself is always current).
	first := s.cfg.Auth.Username
	sort.Slice(names, func(i, j int) bool {
		if fi, fj := names[i] == first, names[j] == first; fi != fj {
			return fi
		}
		return names[i] < names[j]
	})
	return names
}

// validText reports whether s is a value a filter or form may carry: not empty, at most max bytes,
// valid UTF-8, no control characters.
func validText(s string, max int) bool {
	return s != "" && len(s) <= max && utf8.ValidString(s) && strings.IndexFunc(s, unicode.IsControl) < 0
}

var (
	incStateLabels = map[string]string{
		siem.IncidentOpen: "Open", siem.IncidentAcknowledged: "Acknowledged",
		siem.IncidentResolved: "Resolved", siem.IncidentFalsePositive: "False positive",
	}
	// incStateClass is a state's pill class (an allowlist: State is stored data).
	incStateClass = map[string]string{siem.IncidentOpen: "pill-warn", siem.IncidentResolved: "pill-ok"}
)

func incStateLabel(st string) string {
	if l := incStateLabels[st]; l != "" {
		return l
	}
	return st
}

// incRow is one incident as the lists and the detail page show it.
type incRow struct {
	ID                            int64
	URL, Title                    string
	State, StateLabel, StateClass string
	Sev, SevClass                 string
	Chain                         string
	Entities                      []entityRef
	First, FirstISO               string
	Last, LastISO, Ago            string
	Detections                    string
	DetectionsText                string // "1 detection", "3 detections"
	Assignee                      string
	AssigneeNotOwner              bool // the assignee is no longer an owner (or no longer a user)
}

func incRowOf(in *siem.Incident, owners []string, now time.Time) incRow {
	row := incRow{
		ID: in.ID, URL: "/security/incidents/" + strconv.FormatInt(in.ID, 10), Title: in.Title,
		State: in.State, StateLabel: incStateLabel(in.State), StateClass: incStateClass[in.State],
		Sev: string(in.Severity), SevClass: sevClass(in.Severity), Chain: in.Chain,
		Detections: groupDigits(in.Detections), Assignee: in.Assignee,
		AssigneeNotOwner: in.Assignee != "" && !slices.Contains(owners, in.Assignee),
	}
	row.DetectionsText = row.Detections + " detections"
	if in.Detections == 1 {
		row.DetectionsText = "1 detection"
	}
	for _, e := range in.Entities {
		row.Entities = append(row.Entities, entityRefOf(e))
	}
	if !in.Last.IsZero() {
		row.Last, row.LastISO, row.Ago = in.Last.UTC().Format(detectTimeFmt), in.Last.UTC().Format(time.RFC3339), secAgo(now, in.Last)
	}
	if !in.First.IsZero() {
		row.First, row.FirstISO = in.First.UTC().Format(detectTimeFmt), in.First.UTC().Format(time.RFC3339)
	}
	return row
}

// incListView backs security_incidents.html and its live-refresh fragment.
type incListView struct {
	Form       incForm
	States     []sevOption
	Severities []sevOption
	Assignees  []sevOption
	Err        string
	Rows       []incRow
	Filtered   bool   // a severity, assignee or single state is chosen
	Default    bool   // the default view (open and acknowledged incidents)
	AllURL     string // this filter with every state
	OlderURL   string
	NewestURL  string // on an older page: back to the newest
	PollURL    string // the first page refreshes itself
	PollMS     int
	Risky      []riskRow
	RiskyErr   string
}

// incForm is the filter form as submitted ("" = the default: open and acknowledged; "all").
type incForm struct{ State, Severity, Assignee string }

var incStateFilters = []sevOption{
	{Value: "", Label: "Open and acknowledged"}, {Value: siem.IncidentOpen, Label: "Open"},
	{Value: siem.IncidentAcknowledged, Label: "Acknowledged"}, {Value: siem.IncidentResolved, Label: "Resolved"},
	{Value: siem.IncidentFalsePositive, Label: "False positive"}, {Value: "all", Label: "All states"},
}

// parseIncFilter reads the list's filter. An unknown state, severity, assignee or cursor is
// ignored.
func parseIncFilter(p url.Values) (siem.IncidentFilter, incForm) {
	var form incForm
	f := siem.IncidentFilter{Limit: incPageSize + 1} // one more than shown: is there an older page?
	switch st := p.Get("state"); st {
	case "all":
		form.State = st
	case siem.IncidentOpen, siem.IncidentAcknowledged, siem.IncidentResolved, siem.IncidentFalsePositive:
		form.State, f.States = st, []string{st}
	default:
		f.States = []string{siem.IncidentOpen, siem.IncidentAcknowledged}
	}
	if sev := siem.Severity(p.Get("severity")); siem.SeverityRank(sev) > 0 {
		f.MinSeverity, form.Severity = sev, string(sev)
	}
	if a := p.Get("assignee"); validText(a, siem.MaxShort) {
		f.Assignee, form.Assignee = a, a
	}
	cur := parseDetectCursor(p)
	f.BeforeLast, f.Before = cur.last, cur.id
	return f, form
}

// params is the query string of a list link with this filter, from cur (zero = the newest page).
func (f incForm) params(cur detectCursor) url.Values {
	v := url.Values{}
	for k, x := range map[string]string{"state": f.State, "severity": f.Severity, "assignee": f.Assignee} {
		if x != "" {
			v.Set(k, x)
		}
	}
	if !cur.last.IsZero() {
		v.Set("before_last", cur.last.UTC().Format(time.RFC3339Nano))
		v.Set("before", strconv.FormatInt(cur.id, 10))
	}
	return v
}

// assigneeFilterOptions is the assignee select of the filter: anyone, each owner, and the current
// filter when it names someone who is no longer an owner.
func assigneeFilterOptions(owners []string, cur string) []sevOption {
	opts := []sevOption{{Value: "", Label: "Anyone", Selected: cur == ""}}
	for _, u := range owners {
		opts = append(opts, sevOption{Value: u, Label: u, Selected: u == cur})
	}
	if cur != "" && !slices.Contains(owners, cur) {
		opts = append(opts, sevOption{Value: cur, Label: cur + " (no longer an owner)", Selected: true})
	}
	return opts
}

// riskRow is one entity of the Highest risk panel.
type riskRow struct {
	Entity              entityRef
	Score               string
	Pct                 float64
	Open                string
	Updated, UpdatedISO string
	Ago                 string
}

// riskPct is a score as 0–100 (the service promises that range; a bad value can't break the meter).
func riskPct(score float64) float64 {
	switch {
	case score != score || score < 0: // NaN or negative
		return 0
	case score > 100:
		return 100
	}
	return score
}

func riskScoreText(score float64) string {
	return strconv.Itoa(int(riskPct(score) + 0.5))
}

func riskRowOf(rs siem.RiskScore, now time.Time) riskRow {
	row := riskRow{Entity: entityRefOf(rs.Entity), Score: riskScoreText(rs.Score), Pct: riskPct(rs.Score), Open: groupDigits(rs.OpenIncidents)}
	if !rs.Updated.IsZero() {
		row.Updated, row.UpdatedISO, row.Ago = rs.Updated.UTC().Format("2006-01-02 15:04"), rs.Updated.UTC().Format(time.RFC3339), secAgo(now, rs.Updated)
	}
	return row
}

// secIncidentsList builds the list for the page, or for its live refresh (always the newest page,
// the only one that refreshes).
func (s *Server) secIncidentsList(r *http.Request, live bool) *incListView {
	f, form := parseIncFilter(r.URL.Query())
	if live {
		f.BeforeLast, f.Before = time.Time{}, 0
	}
	owners := s.incidentOwners()
	v := &incListView{
		Form: form, Severities: filterSeverityOptions(form.Severity), Assignees: assigneeFilterOptions(owners, form.Assignee),
		PollMS: detectPollMS, Default: form.State == "",
		Filtered: form.Severity != "" || form.Assignee != "" || (form.State != "" && form.State != "all"),
	}
	for _, o := range incStateFilters {
		o.Selected = o.Value == form.State
		v.States = append(v.States, o)
	}
	all := form
	all.State = "all"
	v.AllURL = withQuery("/security/incidents", all.params(detectCursor{}))
	ctx, cancel := context.WithTimeout(r.Context(), detectTimeout)
	defer cancel()
	now := time.Now().UTC()
	if list, err := s.incidentSvc.Incidents(ctx, f); err != nil {
		s.log.Warn("security incidents: list failed", "err", err)
		v.Err = "The incidents could not be read. Mooring's log has the details."
	} else {
		more := len(list) > incPageSize
		if more {
			list = list[:incPageSize]
		}
		for i := range list {
			v.Rows = append(v.Rows, incRowOf(&list[i], owners, now))
		}
		// The next page starts after the last row shown, in the service's order (last active, then ID).
		if more {
			if last := list[len(list)-1]; !last.Last.IsZero() {
				v.OlderURL = withQuery("/security/incidents", form.params(detectCursor{last: last.Last, id: last.ID}))
			}
		}
		if !f.BeforeLast.IsZero() {
			v.NewestURL = withQuery("/security/incidents", form.params(detectCursor{}))
		} else {
			v.PollURL = withQuery("/security/incidents/rows", form.params(detectCursor{}))
		}
	}
	risky, err := s.incidentSvc.Risky(ctx, incRiskyMax)
	if err != nil {
		s.log.Warn("security incidents: risk scores failed", "err", err)
		v.RiskyErr = "The risk scores could not be read. Mooring's log has the details."
	}
	for _, rs := range risky {
		v.Risky = append(v.Risky, riskRowOf(rs, now))
	}
	return v
}

// handleSecIncidents renders the Incidents page (GET /security/incidents).
func (s *Server) handleSecIncidents(w http.ResponseWriter, r *http.Request) {
	p := &incPage{Off: s.incidentSvc == nil}
	if !p.Off {
		p.List = s.secIncidentsList(r, false)
	}
	s.renderInc(w, r, http.StatusOK, "security_incidents.html", "Security incidents", p)
}

// handleSecIncidentRows renders the newest page's list for its live refresh.
func (s *Server) handleSecIncidentRows(w http.ResponseWriter, r *http.Request) {
	p := &incPage{Off: s.incidentSvc == nil}
	if !p.Off {
		p.List = s.secIncidentsList(r, true)
	}
	s.writeInc(w, http.StatusOK, "secinclist", p)
}

// incDetailView backs security_incident.html.
type incDetailView struct {
	incRow
	Updated, UpdatedAgo string
	Rules               []incRuleLink
	Timeline            []timelineRow
	Actions             []incAction // the state buttons
	CanFP               bool        // the incident can be marked as a false positive
	AssignOpts          []sevOption
	Mutes               []muteRow // the mutes it made that are still in force
	ReopenUnmutes       bool      // Reopen is offered and would remove Mutes
	MaxNote             int
	Notice, Err         string
	// A rejected change comes back with what was typed: the state form's note and mute box, the
	// Add note form's text.
	StateNote string
	Mute      bool
	NoteDraft string
}

type incRuleLink struct{ ID, URL string }

type incAction struct {
	State, Label string
	Primary      bool
}

// incActions are the state changes offered from st: the next steps of an open or acknowledged
// incident (and whether it can be marked a false positive), or Reopen.
func incActions(st string) ([]incAction, bool) {
	switch st {
	case siem.IncidentOpen:
		return []incAction{{siem.IncidentAcknowledged, "Acknowledge", true}, {siem.IncidentResolved, "Resolve", false}}, true
	case siem.IncidentAcknowledged:
		return []incAction{{siem.IncidentResolved, "Resolve", true}}, true
	}
	return []incAction{{siem.IncidentOpen, "Reopen", true}}, false
}

// timelineRow is one timeline entry. Kind is one of the Timeline* kinds, or "" for an unknown one
// (shown as Raw and Text).
type timelineRow struct {
	When, ISO, Ago string
	Kind, Raw      string
	By             string // "" for Mooring
	Sev, SevClass  string
	DetectionURL   string
	Rule           string // the rule's name, or its ID
	RuleURL        string
	Text           string
	StateLabel     string
}

var timelineKinds = map[string]bool{
	siem.TimelineOpened: true, siem.TimelineDetection: true, siem.TimelineEscalated: true, siem.TimelineState: true,
	siem.TimelineAssigned: true, siem.TimelineNote: true, siem.TimelineMuted: true,
}

func timelineRowOf(ev siem.IncidentEvent, now time.Time) timelineRow {
	row := timelineRow{By: ev.Actor, Text: ev.Text, Rule: ev.RuleName}
	if timelineKinds[ev.Kind] {
		row.Kind = ev.Kind
	} else {
		row.Raw = ev.Kind
	}
	if !ev.TS.IsZero() {
		row.When, row.ISO, row.Ago = ev.TS.UTC().Format(detectTimeFmt), ev.TS.UTC().Format(time.RFC3339Nano), secAgo(now, ev.TS)
	}
	if ev.Severity != "" {
		row.Sev, row.SevClass = string(ev.Severity), sevClass(ev.Severity)
	}
	if ev.DetectionID > 0 {
		row.DetectionURL = "/security/detections/" + strconv.FormatInt(ev.DetectionID, 10)
	}
	if row.Rule == "" {
		row.Rule = ev.RuleID
	}
	if ev.RuleID != "" {
		row.RuleURL = withQuery("/security/detections", url.Values{"rule": {ev.RuleID}})
	}
	if ev.Kind == siem.TimelineState {
		row.StateLabel = incStateLabel(ev.Text)
	}
	return row
}

func incDetailOf(in *siem.Incident, owners []string, now time.Time) *incDetailView {
	v := &incDetailView{incRow: incRowOf(in, owners, now), MaxNote: siem.MaxNote}
	if !in.Updated.IsZero() {
		v.Updated, v.UpdatedAgo = in.Updated.UTC().Format(detectTimeFmt), secAgo(now, in.Updated)
	}
	for _, id := range in.Rules {
		v.Rules = append(v.Rules, incRuleLink{ID: id, URL: withQuery("/security/detections", url.Values{"rule": {id}})})
	}
	for _, ev := range in.Timeline {
		v.Timeline = append(v.Timeline, timelineRowOf(ev, now))
	}
	v.Actions, v.CanFP = incActions(in.State)
	// A former owner stays shown on the summary, not offered: the select starts at Unassigned.
	v.AssignOpts = []sevOption{{Value: "", Label: "Unassigned", Selected: in.Assignee == "" || v.AssigneeNotOwner}}
	for _, u := range owners {
		v.AssignOpts = append(v.AssignOpts, sevOption{Value: u, Label: u, Selected: u == in.Assignee})
	}
	for _, m := range in.Mutes {
		v.Mutes = append(v.Mutes, muteRowOf(m, now))
	}
	v.ReopenUnmutes = len(v.Mutes) > 0 && slices.ContainsFunc(v.Actions, func(a incAction) bool { return a.State == siem.IncidentOpen })
	return v
}

// incDoneText are the fixed notices of the incident page's ?done= (nothing from the query string is
// shown, so a crafted link can't put words on the page).
var incDoneText = map[string]string{
	"acknowledged":         "Incident acknowledged.",
	"resolved":             "Incident resolved.",
	"reopened":             "Incident reopened.",
	"false_positive":       "Marked as a false positive.",
	"false_positive_muted": "Marked as a false positive. Its rules are muted for its accounts and addresses for 30 days.",
	"assigned":             "Assignee saved.",
	"unassigned":           "Incident unassigned.",
	"note":                 "Note added.",
	"unmuted":              "Mute removed.",
}

// incidentID is the {id} of the path (0, false for anything but a positive integer).
func incidentID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}

func incTarget(id int64) string { return "incident:" + strconv.FormatInt(id, 10) }

const incDetailTmpl = "security_incident.html"

// handleSecIncident renders one incident (GET /security/incidents/{id}).
func (s *Server) handleSecIncident(w http.ResponseWriter, r *http.Request) {
	if s.incidentSvc == nil {
		s.renderInc(w, r, http.StatusOK, incDetailTmpl, "Incident", &incPage{Off: true})
		return
	}
	id, ok := incidentID(r)
	if !ok {
		s.renderInc(w, r, http.StatusNotFound, incDetailTmpl, "Incident", &incPage{Missing: "Incident not found."})
		return
	}
	s.showIncident(w, r, http.StatusOK, id, incDoneText[r.URL.Query().Get("done")], "", nil)
}

// showIncident renders incident id with a notice, or with a rejected change's message and status
// (keep puts back what was typed).
func (s *Server) showIncident(w http.ResponseWriter, r *http.Request, status int, id int64, notice, errMsg string, keep func(*incDetailView)) {
	ctx, cancel := context.WithTimeout(r.Context(), detectTimeout)
	defer cancel()
	in, ok, err := s.incidentSvc.Incident(ctx, id)
	switch {
	case err != nil:
		s.log.Warn("security incidents: read failed", "id", id, "err", err)
		s.renderInc(w, r, http.StatusInternalServerError, incDetailTmpl, "Incident", &incPage{Missing: "The incident could not be read. Mooring's log has the details."})
		return
	case !ok:
		s.renderInc(w, r, http.StatusNotFound, incDetailTmpl, "Incident", &incPage{Missing: "Incident not found."})
		return
	}
	v := incDetailOf(&in, s.incidentOwners(), time.Now().UTC())
	v.Notice, v.Err = notice, errMsg
	if keep != nil {
		keep(v)
	}
	title := in.Title
	if title == "" {
		title = "Incident " + strconv.FormatInt(in.ID, 10)
	}
	s.renderInc(w, r, status, incDetailTmpl, title, &incPage{One: v})
}

// incOffPost answers a change while detection is off.
func (s *Server) incOffPost(w http.ResponseWriter, r *http.Request) {
	s.renderInc(w, r, http.StatusServiceUnavailable, "security_incidents.html", "Security incidents", &incPage{Off: true})
}

// incPostStart is the common start of an incident change: detection on, the form parsed, the
// incident ID valid. ok false means the response is written.
func (s *Server) incPostStart(w http.ResponseWriter, r *http.Request, action string) (int64, bool) {
	if s.incidentSvc == nil {
		s.incOffPost(w, r)
		return 0, false
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return 0, false
	}
	id, ok := incidentID(r)
	if !ok {
		s.detectAudit(r, action, "incident", audit.Error, "result=not found")
		s.renderInc(w, r, http.StatusNotFound, incDetailTmpl, "Incident", &incPage{Missing: "Incident not found."})
		return 0, false
	}
	return id, true
}

// serviceError is how a page shows a change the incident service refused. Only a validation error's
// text is for the owner (siem.ErrInvalidInput); any other error is internal and stays in Mooring's
// log. what is the sentence's start ("The change was not saved").
func (s *Server) serviceError(err error, what, logMsg string, args ...any) (status int, msg, result string) {
	args = append(args, "err", err)
	if errors.Is(err, siem.ErrInvalidInput) {
		s.log.Info(logMsg+" rejected", args...)
		text := err.Error()
		if i := strings.Index(text, siem.ErrInvalidInput.Error()+": "); i >= 0 {
			text = text[i+len(siem.ErrInvalidInput.Error())+2:]
		}
		return http.StatusUnprocessableEntity, what + ": " + text, "rejected"
	}
	s.log.Warn(logMsg+" failed", args...)
	return http.StatusInternalServerError, what + ". Mooring's log has the details.", "error"
}

// incChangeDone finishes a change the service was asked for: on err, the incident page with the
// message (and what was typed); else the audit row and the redirect back with the notice.
func (s *Server) incChangeDone(w http.ResponseWriter, r *http.Request, action string, id int64, detail string, err error, done string, keep func(*incDetailView)) {
	if err != nil {
		status, msg, result := s.serviceError(err, "The change was not saved", "security incidents: "+action, "id", id)
		s.detectAudit(r, action, incTarget(id), audit.Error, strings.TrimSpace(detail+" result="+result))
		s.showIncident(w, r, status, id, "", msg, keep)
		return
	}
	s.detectAudit(r, action, incTarget(id), audit.OK, detail)
	http.Redirect(w, r, withQuery("/security/incidents/"+strconv.FormatInt(id, 10), url.Values{"done": {done}}), http.StatusSeeOther)
}

// incReject answers a change refused before the service is asked (the input), with the message.
func (s *Server) incReject(w http.ResponseWriter, r *http.Request, action string, id int64, msg string, keep func(*incDetailView)) {
	s.detectAudit(r, action, incTarget(id), audit.Error, "result=rejected")
	s.showIncident(w, r, http.StatusUnprocessableEntity, id, "", msg, keep)
}

// incNote reads a note as typed: line breaks as \n, surrounding space trimmed. A non-empty message is
// what is wrong with it.
func incNote(raw string, required bool) (string, string) {
	n := strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(raw, "\r\n", "\n"), "\r", "\n"))
	switch {
	case !utf8.ValidString(n):
		return "", "The note is not valid text."
	case strings.IndexFunc(n, func(c rune) bool { return unicode.IsControl(c) && c != '\n' && c != '\t' }) >= 0:
		return "", "The note has control characters."
	case len(n) > siem.MaxNote:
		return "", "The note is too long: at most " + groupDigits(siem.MaxNote) + " bytes."
	case required && n == "":
		return "", "The note is empty."
	}
	return n, ""
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// incStateDone are the states the state form sets, with their notices.
var incStateDone = map[string]string{
	siem.IncidentOpen: "reopened", siem.IncidentAcknowledged: "acknowledged", siem.IncidentResolved: "resolved",
}

// handleSecIncidentState moves an incident to open, acknowledged or resolved, with an optional note
// (POST /security/incidents/{id}/state). The audit row never holds the note.
func (s *Server) handleSecIncidentState(w http.ResponseWriter, r *http.Request) {
	const action = "security_incident_state"
	id, ok := s.incPostStart(w, r, action)
	if !ok {
		return
	}
	raw := r.PostFormValue("note")
	keep := func(v *incDetailView) { v.StateNote = raw }
	state := r.PostFormValue("state")
	done, ok := incStateDone[state]
	if !ok {
		s.incReject(w, r, action, id, "Pick a state: open, acknowledged or resolved.", keep)
		return
	}
	note, msg := incNote(raw, false)
	if msg != "" {
		s.incReject(w, r, action, id, msg, keep)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), detectTimeout)
	defer cancel()
	err := s.incidentSvc.SetState(ctx, id, state, sessionUser(r), note)
	s.incChangeDone(w, r, action, id, "state="+state+" note="+yesNo(note != ""), err, done, keep)
}

// handleSecIncidentFalsePositive marks an incident a false positive, optionally muting its rules for
// its entities for 30 days (POST /security/incidents/{id}/false-positive; the state form's second
// button).
func (s *Server) handleSecIncidentFalsePositive(w http.ResponseWriter, r *http.Request) {
	const action = "security_incident_false_positive"
	id, ok := s.incPostStart(w, r, action)
	if !ok {
		return
	}
	raw, mute := r.PostFormValue("note"), r.PostFormValue("mute") != ""
	keep := func(v *incDetailView) { v.StateNote, v.Mute = raw, mute }
	note, msg := incNote(raw, false)
	if msg != "" {
		s.incReject(w, r, action, id, msg, keep)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), detectTimeout)
	defer cancel()
	err := s.incidentSvc.MarkFalsePositive(ctx, id, sessionUser(r), mute, note)
	done := "false_positive"
	if mute {
		done = "false_positive_muted"
	}
	s.incChangeDone(w, r, action, id, "mute="+yesNo(mute)+" note="+yesNo(note != ""), err, done, keep)
}

// handleSecIncidentAssign assigns an incident to an owner, or unassigns it
// (POST /security/incidents/{id}/assign). The audit row never names the assignee.
func (s *Server) handleSecIncidentAssign(w http.ResponseWriter, r *http.Request) {
	const action = "security_incident_assign"
	id, ok := s.incPostStart(w, r, action)
	if !ok {
		return
	}
	assignee := r.PostFormValue("assignee")
	// A missing field is refused rather than read as "unassign".
	if !r.PostForm.Has("assignee") || (assignee != "" && !slices.Contains(s.incidentOwners(), assignee)) {
		s.incReject(w, r, action, id, "Pick an owner, or Unassigned.", nil)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), detectTimeout)
	defer cancel()
	err := s.incidentSvc.Assign(ctx, id, assignee, sessionUser(r))
	detail, done := "assignee=set", "assigned"
	if assignee == "" {
		detail, done = "assignee=none", "unassigned"
	}
	s.incChangeDone(w, r, action, id, detail, err, done, nil)
}

// handleSecIncidentNote adds a note to an incident's timeline (POST /security/incidents/{id}/note).
// The audit row never holds the text.
func (s *Server) handleSecIncidentNote(w http.ResponseWriter, r *http.Request) {
	const action = "security_incident_note"
	id, ok := s.incPostStart(w, r, action)
	if !ok {
		return
	}
	raw := r.PostFormValue("note")
	keep := func(v *incDetailView) { v.NoteDraft = raw }
	note, msg := incNote(raw, true)
	if msg != "" {
		s.incReject(w, r, action, id, msg, keep)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), detectTimeout)
	defer cancel()
	err := s.incidentSvc.AddNote(ctx, id, sessionUser(r), note)
	s.incChangeDone(w, r, action, id, "", err, "note", keep)
}
