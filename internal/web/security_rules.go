package web

import (
	"context"
	"errors"
	"math"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/siem"
)

// rulesPageView backs security_rules.html.
type rulesPageView struct {
	Notice, Err     string
	Loaded          bool // the rules were read (else only the error shows)
	Builtin, Custom ruleTable
	FeedsOn         bool // a feed source is wired
	Feeds           []feedRow
	FeedCredits     detectCredits
}

// ruleTable is one table of rules; its rows' action forms need the CSRF token.
type ruleTable struct {
	Rows []ruleRow
	CSRF string
}

type ruleRow struct {
	ID, Name, Description string
	TypeLabel             string
	Sev, SevClass         string
	MITRE                 []mitreLink
	Enabled               bool
	Condition             string
	Response              string // the rule's automated response, in words ("" for none)
	Snoozed               bool
	SnoozedUntil          string
	SnoozedISO, SnoozedIn string
	EditURL               string
	Builtin               bool
}

type feedRow struct {
	Name, Label       string
	Enabled           bool
	Version           string
	Updated, Ago      string
	Entries           string
	NextTry, NextIn   string
	LastError         string
	HasEntries, Error bool
}

// ruleTypes are the rule types in the form's order, with their labels.
var ruleTypes = []struct{ Value, Label string }{
	{siem.RuleThreshold, "Threshold: at least N events in a window"},
	{siem.RuleDistinct, "Distinct: at least N distinct values in a window"},
	{siem.RuleNewValue, "New value: a value not seen before"},
	{siem.RuleAnomaly, "Anomaly: well above the usual rate"},
	{siem.RuleTravel, "Impossible travel: locations too far apart for the time between them"},
	{siem.RuleSequence, "Sequence: N events, then a closing event"},
}

// baselineKinds are the baseline rules' kinds (Rule.Baseline): a label and what the rule learns.
// Baseline rules are built in only, so the custom form never offers the type.
var baselineKinds = map[string]struct{ Label, Learns string }{
	siem.BaselineSignIn:  {"sign-in pattern", "usual sign-in hours, countries, networks and clients"},
	siem.BaselineTraffic: {"traffic volume", "requests and errors per hour of the week"},
	siem.BaselineAdmin:   {"admin activity", "usual sudo and su hours, programs and target users"},
	siem.BaselineIP:      {"address behavior", "usual request mix"},
}

// baselineLabel is a baseline rule's type label with its kind ("Baseline: sign-in pattern").
func baselineLabel(kind string) string {
	if k, ok := baselineKinds[kind]; ok {
		return "Baseline: " + k.Label
	}
	if kind != "" {
		return "Baseline: " + kind
	}
	return "Baseline"
}

// baselineTunables are the tunables a baseline rule can have; the form shows those the rule sets.
var baselineTunables = map[string]bool{"count": true, "window": true, "factor": true, "learn": true}

func ruleTypeLabel(t string) string {
	if t == siem.RuleBaseline {
		return "Baseline"
	}
	for _, rt := range ruleTypes {
		if rt.Value == t {
			return rt.Label[:strings.IndexByte(rt.Label, ':')]
		}
	}
	return t
}

// ruleTypeFields are the type-specific fields each rule type uses. The form shows only these, and a
// save reads only these: the others are stored as zero (custom) or left as they are (built-in).
var ruleTypeFields = map[string][]string{
	siem.RuleThreshold: {"count", "window"},
	siem.RuleDistinct:  {"field", "count", "window"},
	siem.RuleNewValue:  {"field", "learn"},
	siem.RuleAnomaly:   {"count", "window", "factor", "learn"},
	siem.RuleTravel:    {"speed_kmh"},
	siem.RuleSequence:  {"then", "count", "window"},
}

// ruleTunables are the built-in rule's type-specific tunable fields (Enabled and Severity aside).
var ruleTunables = []string{"count", "window", "factor", "learn", "speed_kmh"}

func typeUses(typ, field string) bool {
	for _, f := range ruleTypeFields[typ] {
		if f == field {
			return true
		}
	}
	return false
}

// fieldKinds is, per type-specific field, the rule types that use it (the custom form's
// data-kind lists for app.js).
func fieldKinds() map[string]string {
	m := map[string]string{}
	for _, rt := range ruleTypes {
		for _, f := range ruleTypeFields[rt.Value] {
			m[f] = strings.TrimSpace(m[f] + " " + rt.Value)
		}
	}
	return m
}

// parseRuleDuration reads a rule duration: a Go duration ("90m", "36h", "1h30m") or a whole number
// of days ("7d"). Empty is zero (not set). Negative values and other units are refused.
func parseRuleDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		if days == "" || strings.Trim(days, "0123456789") != "" {
			return 0, errors.New("bad days")
		}
		n, err := strconv.ParseInt(days, 10, 64)
		if err != nil || n > int64(math.MaxInt64/int64(24*time.Hour)) {
			return 0, errors.New("too long")
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	switch {
	case err != nil:
		return 0, err
	case d < 0:
		return 0, errors.New("negative")
	}
	return d, nil
}

// fmtRuleDuration writes d the way parseRuleDuration reads it, in the largest whole unit.
func fmtRuleDuration(d time.Duration) string {
	switch {
	case d == 0:
		return ""
	case d%(24*time.Hour) == 0:
		return strconv.FormatInt(int64(d/(24*time.Hour)), 10) + "d"
	case d%time.Hour == 0:
		return strconv.FormatInt(int64(d/time.Hour), 10) + "h"
	case d%time.Minute == 0:
		return strconv.FormatInt(int64(d/time.Minute), 10) + "m"
	}
	return d.String()
}

func fmtNum(f float64) string {
	if f == 0 {
		return ""
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// ruleCondition is a rule's parameters in a few words, for the list.
func ruleCondition(r siem.Rule) string {
	var parts []string
	add := func(s string) { parts = append(parts, s) }
	in := func() string {
		if r.Window > 0 {
			return " in " + fmtRuleDuration(r.Window)
		}
		return ""
	}
	learning := func() {
		if r.Learn > 0 {
			add("after " + fmtRuleDuration(r.Learn) + " of learning")
		}
	}
	switch r.Type {
	case siem.RuleThreshold:
		add("at least " + strconv.Itoa(r.Count) + in())
	case siem.RuleDistinct:
		add("at least " + strconv.Itoa(r.Count) + " distinct " + r.Field + in())
	case siem.RuleNewValue:
		add("new " + r.Field)
		learning()
	case siem.RuleAnomaly:
		add(fmtNum(r.Factor) + "× the usual rate, at least " + strconv.Itoa(r.Count) + in())
		learning()
	case siem.RuleTravel:
		add("faster than " + fmtNum(r.SpeedKMH) + " km/h")
	case siem.RuleSequence:
		add("at least " + strconv.Itoa(r.Count) + ", then a closing event" + in())
	case siem.RuleBaseline:
		if k, ok := baselineKinds[r.Baseline]; ok {
			add(k.Learns)
		}
		learning()
	}
	if r.GroupBy != "" {
		add("per " + r.GroupBy)
	}
	return strings.Join(parts, " ")
}

func ruleRowOf(r siem.Rule, now time.Time) ruleRow {
	row := ruleRow{
		ID: r.ID, Name: r.Name, Description: r.Description, TypeLabel: ruleTypeLabel(r.Type),
		Sev: string(r.Severity), SevClass: sevClass(r.Severity), MITRE: mitreLinks(r.MITRE), Enabled: r.Enabled,
		Condition: ruleCondition(r), Response: ruleResponseText(r.Response), Builtin: r.Builtin,
		EditURL: withQuery("/security/rules/edit", url.Values{"id": {r.ID}}),
	}
	if r.Type == siem.RuleBaseline {
		row.TypeLabel = baselineLabel(r.Baseline)
	}
	if r.SnoozedUntil.After(now) {
		row.Snoozed = true
		row.SnoozedUntil, row.SnoozedISO, row.SnoozedIn = r.SnoozedUntil.UTC().Format("Jan 02 15:04"), r.SnoozedUntil.UTC().Format(time.RFC3339), secAgo(now, r.SnoozedUntil)
	}
	return row
}

// feedRows is the Enrichment feeds panel, with the credits of the feeds that are on.
func feedRows(fs []siem.FeedStatus, now time.Time) ([]feedRow, detectCredits) {
	var rows []feedRow
	var c detectCredits
	for _, f := range fs {
		row := feedRow{
			Name: f.Name, Label: listLabel(f.Name), Enabled: f.Enabled, Version: f.Version, LastError: f.LastError,
			Entries: groupDigits(f.Entries), HasEntries: f.Entries > 0, Error: f.LastError != "",
		}
		if !f.Updated.IsZero() {
			row.Updated, row.Ago = f.Updated.UTC().Format("2006-01-02 15:04"), secAgo(now, f.Updated)
		}
		if !f.NextTry.IsZero() {
			row.NextTry, row.NextIn = f.NextTry.UTC().Format("2006-01-02 15:04"), secAgo(now, f.NextTry)
		}
		switch {
		case !f.Enabled:
		case strings.HasPrefix(f.Name, "dbip"):
			c.Geo = true
		case strings.HasPrefix(f.Name, "spamhaus"):
			c.Spamhaus = true
		case f.Name == "dshield":
			c.DShield = true
		}
		rows = append(rows, row)
	}
	return rows, c
}

// ruleNotices are the fixed texts of the rules page's ?done= and ?err= (nothing from the query
// string is shown, so a crafted link can't put words on the page). %s is the rule's name.
var (
	ruleDoneText = map[string][2]string{ // [with the rule's name, without]
		"saved":     {"Saved %s.", "Saved the rule."},
		"reset":     {"Reset %s to its built-in values.", "Reset the rule to its built-in values."},
		"deleted":   {"", "Deleted the custom rule."},
		"snoozed":   {"%s is snoozed", "The rule is snoozed"},
		"unsnoozed": {"Cleared the snooze on %s.", "Cleared the snooze."},
	}
	ruleErrText = map[string]string{
		"missing":   "That rule no longer exists.",
		"read":      "The rules could not be read. Mooring's log has the details.",
		"delete":    "The rule could not be deleted. Only custom rules can be deleted; Mooring's log has the details.",
		"reset":     "The rule could not be reset. Only built-in rules can be reset; Mooring's log has the details.",
		"snooze":    "The snooze was not saved. Mooring's log has the details.",
		"snoozefor": "Pick a snooze length: 1 hour, 24 hours or 7 days.",
	}
)

func ruleNotice(done string, rule *siem.Rule, now time.Time) string {
	t, ok := ruleDoneText[done]
	if !ok {
		return ""
	}
	if rule == nil || t[0] == "" {
		if done == "snoozed" {
			return t[1] + ": its detections are recorded, not sent to the alert channels."
		}
		return t[1]
	}
	msg := strings.Replace(t[0], "%s", rule.Name, 1)
	if done == "snoozed" {
		if rule.SnoozedUntil.After(now) {
			msg += " until " + rule.SnoozedUntil.UTC().Format("2006-01-02 15:04") + " UTC"
		}
		msg += ": its detections are recorded, not sent to the alert channels."
	}
	return msg
}

func findRule(rules []siem.Rule, id string) *siem.Rule {
	for i := range rules {
		if rules[i].ID == id {
			return &rules[i]
		}
	}
	return nil
}

// handleSecurityRules renders the Rules page (GET /security/rules).
func (s *Server) handleSecurityRules(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	v := &rulesPageView{}
	if s.feeds != nil {
		v.FeedsOn = true
		v.Feeds, v.FeedCredits = feedRows(s.feeds.FeedStatus(), now)
	}
	p := &detectPage{Rules: v, Off: s.detections == nil}
	if p.Off {
		s.renderDetect(w, r, http.StatusOK, "security_rules.html", "Detection rules", p)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), detectTimeout)
	defer cancel()
	rules, err := s.detections.Rules(ctx)
	if err != nil {
		s.log.Warn("security rules: list failed", "err", err)
		v.Err = ruleErrText["read"]
	}
	v.Loaded = err == nil
	q := r.URL.Query()
	if v.Err == "" {
		v.Err = ruleErrText[q.Get("err")]
	}
	v.Notice = ruleNotice(q.Get("done"), findRule(rules, q.Get("rule")), now)
	v.Builtin.CSRF, v.Custom.CSRF = CSRFToken(r.Context()), CSRFToken(r.Context())
	for _, ru := range rules {
		if ru.Builtin {
			v.Builtin.Rows = append(v.Builtin.Rows, ruleRowOf(ru, now))
		} else {
			v.Custom.Rows = append(v.Custom.Rows, ruleRowOf(ru, now))
		}
	}
	s.renderDetect(w, r, http.StatusOK, "security_rules.html", "Detection rules", p)
}

// ruleFormView backs security_rule_edit.html: a built-in rule's tunables, or a custom rule whole.
// Values are strings as typed, so a rejected form comes back as it was.
type ruleFormView struct {
	New, Builtin bool
	ID           string // the rule's ID ("" for a new rule)
	Slug         string
	Name         string
	Description  string
	Type         string
	TypeLabel    string
	Learns       string // a baseline rule: what it learns
	Severity     string
	MITRE        string // comma list
	MITRELinks   []mitreLink
	Query, Then  string
	GroupBy      string
	Field        string
	Count        string
	Window       string
	Factor       string
	Learn        string
	Speed        string
	Enabled      bool
	Snoozed      string // "until …" for a snoozed rule
	Err          string
	Types        []sevOption // Value, Label, Selected
	Severities   []sevOption
	Kinds        map[string]string // type-specific field → the types that use it
	Show         map[string]bool   // type-specific field → shown (and enabled) as rendered
	// The automated response: shown when the rule may take one (RespActions beyond "None"), else
	// RespWhy says why it may take none. Response and RespDuration are as typed.
	RespShown     bool
	RespAfterSave bool // a new rule: a response can be set once it is saved
	RespWhy       string
	RespActions   []sevOption
	RespDurations []sevOption
	Response      string
	RespDuration  string
	respPosted    bool // the form sent the response fields
}

// ruleResponseLabels are the response actions as the rule form offers them.
var ruleResponseLabels = map[string]string{
	siem.ResponseBlock:  "Block the address at the edge",
	siem.ResponseRevoke: "Sign the Mooring account out of every session",
}

// ruleBlockLengths are the first-block lengths the rule form offers (values as fmtRuleDuration
// writes them).
var ruleBlockLengths = []blockDuration{
	{"1h", "1 hour", time.Hour}, {"4h", "4 hours", 4 * time.Hour},
	{"1d", "24 hours", 24 * time.Hour}, {"7d", "7 days", 7 * 24 * time.Hour},
}

// ruleResponseText is a rule's response in words, for the rules list ("" for none).
func ruleResponseText(rr siem.RuleResponse) string {
	switch rr.Action {
	case "":
		return ""
	case siem.ResponseBlock:
		if d := durText(rr.Duration); d != "" {
			return "block the address for " + d
		}
		return "block the address"
	case siem.ResponseRevoke:
		return "sign the account out"
	}
	return rr.Action
}

// ruleResponseForm fills the form's Response section from what the detection service says rule
// may do (siem.RuleResponder): the actions it may take, or why it may take none. stored, the action
// the rule has now, stays offered, so a save never drops it unasked.
func (s *Server) ruleResponseForm(f *ruleFormView, rule siem.Rule, stored string) {
	rr, ok := s.detections.(siem.RuleResponder)
	if !ok {
		return
	}
	if f.New {
		// Intentional: a new rule's form offers no response. Which responses a rule may take depends
		// on its saved search and type; the form says a response can be set after the rule is saved.
		f.RespAfterSave = true
		return
	}
	actions, why := rr.RuleResponses(rule)
	f.RespWhy = why
	f.RespActions = []sevOption{{Value: "", Label: "None", Selected: f.Response == ""}}
	offer := func(a, suffix string) {
		label := ruleResponseLabels[a]
		if label == "" || slices.ContainsFunc(f.RespActions, func(o sevOption) bool { return o.Value == a }) {
			return
		}
		f.RespActions = append(f.RespActions, sevOption{Value: a, Label: label + suffix, Selected: a == f.Response})
	}
	for _, a := range actions {
		offer(a, "")
	}
	if stored != "" {
		offer(stored, " (not available for this rule)")
	}
	f.RespShown = len(f.RespActions) > 1
	cur := f.RespDuration
	if cur == "" {
		cur = "1h"
	}
	d, err := parseRuleDuration(cur)
	f.RespDurations = nil
	found := false
	for _, l := range ruleBlockLengths {
		sel := err == nil && d == l.d
		found = found || sel
		f.RespDurations = append(f.RespDurations, sevOption{Value: l.Value, Label: l.Label, Selected: sel})
	}
	if !found {
		// A length set before (or typed) that isn't one of the offered ones stays as it is.
		f.RespDurations = append([]sevOption{{Value: cur, Label: cur, Selected: true}}, f.RespDurations...)
	}
}

// ruleResponseFromForm sets rule's response from the form. A response the form didn't send is
// kept as cur has it. A non-empty message is a problem with the input.
func ruleResponseFromForm(f *ruleFormView, rule *siem.Rule, cur *siem.Rule) string {
	if !f.respPosted {
		if cur != nil {
			rule.Response = cur.Response
		}
		return ""
	}
	switch {
	case f.Response == "":
		rule.Response = siem.RuleResponse{}
	case !slices.ContainsFunc(f.RespActions, func(o sevOption) bool { return o.Value == f.Response }):
		return "Pick a response this rule can take."
	case f.Response == siem.ResponseBlock:
		d, err := parseRuleDuration(f.RespDuration)
		if err != nil || d <= 0 {
			return "Block length must be a duration such as 1h, 24h or 7d."
		}
		rule.Response = siem.RuleResponse{Action: siem.ResponseBlock, Duration: d}
	default:
		rule.Response = siem.RuleResponse{Action: f.Response}
	}
	return ""
}

func ruleSeverityOptions(cur string) []sevOption {
	labels := map[siem.Severity]string{
		siem.SevLow: "Low: Detections page only", siem.SevMedium: "Medium: Detections page only",
		siem.SevHigh: "High: also a warning alert", siem.SevCritical: "Critical: also a critical alert",
	}
	var opts []sevOption
	for _, s := range detectSeverities {
		opts = append(opts, sevOption{Value: string(s), Label: labels[s], Selected: cur == string(s)})
	}
	return opts
}

// finish fills the form's option lists and which type-specific fields show.
func (f *ruleFormView) finish(cur *siem.Rule) {
	f.Types = nil
	f.Severities = ruleSeverityOptions(f.Severity)
	f.Kinds = fieldKinds()
	f.Show = map[string]bool{}
	f.TypeLabel = ruleTypeLabel(f.Type)
	for _, rt := range ruleTypes {
		f.Types = append(f.Types, sevOption{Value: rt.Value, Label: rt.Label, Selected: rt.Value == f.Type})
	}
	for _, field := range []string{"field", "then", "count", "window", "factor", "learn", "speed_kmh"} {
		f.Show[field] = typeUses(f.Type, field)
	}
	if f.Builtin && cur != nil {
		// A built-in rule also shows a tunable it already sets, in case the pack uses one this form
		// doesn't expect for its type.
		set := map[string]bool{"count": cur.Count != 0, "window": cur.Window != 0, "factor": cur.Factor != 0, "learn": cur.Learn != 0, "speed_kmh": cur.SpeedKMH != 0}
		for _, field := range ruleTunables {
			f.Show[field] = f.Show[field] || set[field]
			if cur.Type == siem.RuleBaseline {
				f.Show[field] = set[field] && baselineTunables[field]
			}
		}
		f.Show["field"], f.Show["then"] = false, false
		if cur.Type == siem.RuleBaseline {
			f.TypeLabel = baselineLabel(cur.Baseline)
			if l := baselineKinds[cur.Baseline].Learns; l != "" {
				f.Learns = strings.ToUpper(l[:1]) + l[1:]
			}
		}
	}
}

func ruleFormOf(r siem.Rule, now time.Time) *ruleFormView {
	f := &ruleFormView{
		Builtin: r.Builtin, ID: r.ID, Name: r.Name, Description: r.Description, Type: r.Type, Severity: string(r.Severity),
		MITRE: strings.Join(r.MITRE, ", "), MITRELinks: mitreLinks(r.MITRE), Query: r.Query, Then: r.Then, GroupBy: r.GroupBy, Field: r.Field,
		Window: fmtRuleDuration(r.Window), Factor: fmtNum(r.Factor), Learn: fmtRuleDuration(r.Learn), Speed: fmtNum(r.SpeedKMH),
		Enabled: r.Enabled, Response: r.Response.Action, RespDuration: fmtRuleDuration(r.Response.Duration),
	}
	if r.Count != 0 {
		f.Count = strconv.Itoa(r.Count)
	}
	if r.SnoozedUntil.After(now) {
		f.Snoozed = r.SnoozedUntil.UTC().Format("2006-01-02 15:04") + " UTC (" + secAgo(now, r.SnoozedUntil) + ")"
	}
	f.finish(&r)
	return f
}

// handleSecurityRuleEdit renders the rule form: GET /security/rules/edit?id=… for a rule,
// GET /security/rules/new for a new custom rule.
func (s *Server) handleSecurityRuleEdit(w http.ResponseWriter, r *http.Request) {
	const page = "security_rule_edit.html"
	if s.detections == nil {
		s.renderDetect(w, r, http.StatusOK, page, "Edit rule", &detectPage{Off: true})
		return
	}
	if r.URL.Path == "/security/rules/new" {
		f := &ruleFormView{New: true, Type: siem.RuleThreshold, Severity: string(siem.SevMedium), Enabled: true}
		f.finish(nil)
		s.ruleResponseForm(f, siem.Rule{Type: f.Type, Severity: siem.SevMedium, Enabled: true}, "")
		s.renderDetect(w, r, http.StatusOK, page, "New custom rule", &detectPage{Edit: f})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), detectTimeout)
	defer cancel()
	rules, err := s.detections.Rules(ctx)
	if err != nil {
		s.log.Warn("security rules: read for edit failed", "err", err)
		s.renderDetect(w, r, http.StatusInternalServerError, page, "Edit rule", &detectPage{Missing: ruleErrText["read"]})
		return
	}
	cur := findRule(rules, r.URL.Query().Get("id"))
	if cur == nil {
		s.renderDetect(w, r, http.StatusNotFound, page, "Edit rule", &detectPage{Missing: "Rule not found."})
		return
	}
	f := ruleFormOf(*cur, time.Now().UTC())
	s.ruleResponseForm(f, *cur, cur.Response.Action)
	s.renderDetect(w, r, http.StatusOK, page, "Edit "+cur.Name, &detectPage{Edit: f})
}

// ruleFormFromPost is the submitted form, as typed, for a new rule (cur nil) or cur.
func ruleFormFromPost(r *http.Request, cur *siem.Rule, now time.Time) *ruleFormView {
	v := func(k string) string { return strings.TrimSpace(r.PostFormValue(k)) }
	var f *ruleFormView
	if cur != nil && cur.Builtin {
		// Only the tunables come from the form; the rest is shown as the rule has it.
		f = ruleFormOf(*cur, now)
	} else {
		f = &ruleFormView{
			Name: v("name"), Description: v("description"), Type: v("type"), MITRE: v("mitre"),
			Query: v("query"), Then: v("then"), GroupBy: v("group_by"), Field: v("field"),
		}
		if cur != nil {
			f.ID = cur.ID
			if cur.SnoozedUntil.After(now) {
				f.Snoozed = cur.SnoozedUntil.UTC().Format("2006-01-02 15:04") + " UTC (" + secAgo(now, cur.SnoozedUntil) + ")"
			}
		} else {
			f.New, f.Slug = true, v("slug")
		}
	}
	f.Severity, f.Enabled = v("severity"), r.PostFormValue("enabled") != ""
	switch {
	case r.PostForm.Has("response"):
		f.respPosted, f.Response, f.RespDuration = true, v("response"), v("response_duration")
	case cur != nil:
		f.Response, f.RespDuration = cur.Response.Action, fmtRuleDuration(cur.Response.Duration)
	}
	for field, dst := range map[string]*string{"count": &f.Count, "window": &f.Window, "factor": &f.Factor, "learn": &f.Learn, "speed_kmh": &f.Speed} {
		if r.PostForm.Has(field) {
			*dst = v(field)
		}
	}
	f.finish(cur)
	return f
}

// ruleFromForm builds the rule to save from the form. A non-empty message is a problem with the
// input (the number and duration fields; SaveRule checks the rest).
func ruleFromForm(f *ruleFormView, cur *siem.Rule) (siem.Rule, string) {
	var rule siem.Rule
	switch {
	case cur != nil && cur.Builtin:
		rule = *cur
	default:
		rule = siem.Rule{
			ID: f.ID, Name: f.Name, Description: f.Description, Type: f.Type, Query: f.Query, GroupBy: f.GroupBy,
		}
		if cur == nil {
			rule.ID = "custom." + f.Slug
		} else {
			rule.SnoozedUntil = cur.SnoozedUntil
		}
		for _, m := range strings.FieldsFunc(f.MITRE, func(c rune) bool { return c == ',' || c == ' ' || c == '\t' || c == '\n' || c == '\r' }) {
			rule.MITRE = append(rule.MITRE, strings.ToUpper(m))
		}
		if typeUses(f.Type, "field") {
			rule.Field = f.Field
		}
		if typeUses(f.Type, "then") {
			rule.Then = f.Then
		}
		if rule.Type == siem.RuleBaseline {
			return rule, "Baseline rules are built in. Pick another type for a custom rule."
		}
	}
	rule.Severity, rule.Enabled = siem.Severity(f.Severity), f.Enabled
	use := func(field string) bool { return f.Show[field] }
	if use("count") {
		n, err := strconv.Atoi(f.Count)
		if f.Count == "" {
			n, err = 0, nil
		}
		if err != nil || n < 0 {
			return rule, "Count must be a whole number, 0 or more."
		}
		rule.Count = n
	}
	for _, d := range []struct {
		field, label string
		dst          *time.Duration
		in           string
	}{{"window", "Window", &rule.Window, f.Window}, {"learn", "Learning period", &rule.Learn, f.Learn}} {
		if !use(d.field) {
			continue
		}
		x, err := parseRuleDuration(d.in)
		if err != nil {
			return rule, d.label + " must be a duration such as 10m, 24h or 7d."
		}
		*d.dst = x
	}
	for _, n := range []struct {
		field, label string
		dst          *float64
		in           string
	}{{"factor", "Factor", &rule.Factor, f.Factor}, {"speed_kmh", "Speed", &rule.SpeedKMH, f.Speed}} {
		if !use(n.field) {
			continue
		}
		x := 0.0
		if n.in != "" {
			var err error
			x, err = strconv.ParseFloat(n.in, 64)
			if err != nil || x < 0 || math.IsInf(x, 0) || math.IsNaN(x) {
				return rule, n.label + " must be a number, 0 or more."
			}
		}
		*n.dst = x
	}
	return rule, ""
}

// detectAudit records a rule change. Detail never holds the rule's search or a validation message
// (which can quote it).
func (s *Server) detectAudit(r *http.Request, action, target string, outcome audit.Outcome, detail string) {
	_ = s.audit.Log(r.Context(), audit.Event{
		Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), UA: r.UserAgent(), Action: action,
		Target: siem.Cut(target, 200), Outcome: outcome, Level: audit.Security, Detail: detail,
	})
}

// detectOffPost answers a rule change while detection is off.
func (s *Server) detectOffPost(w http.ResponseWriter, r *http.Request) {
	s.renderDetect(w, r, http.StatusServiceUnavailable, "security_rules.html", "Detection rules", &detectPage{Off: true, Rules: &rulesPageView{}})
}

func ruleKind(builtin bool) string {
	if builtin {
		return "rule=builtin"
	}
	return "rule=custom"
}

// handleSecurityRuleSave saves the rule form (POST /security/rules/save). A rejected form is shown
// again with the message and the input as typed.
func (s *Server) handleSecurityRuleSave(w http.ResponseWriter, r *http.Request) {
	const action = "security_rule_save"
	if s.detections == nil {
		s.detectOffPost(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), detectTimeout)
	defer cancel()
	now := time.Now().UTC()
	id := strings.TrimSpace(r.PostFormValue("id"))
	rules, err := s.detections.Rules(ctx)
	if err != nil {
		s.log.Warn("security rules: read for save failed", "err", err)
		s.detectAudit(r, action, id, audit.Error, "result=read failed")
		http.Redirect(w, r, "/security/rules?err=read", http.StatusSeeOther)
		return
	}
	var cur *siem.Rule
	if id != "" {
		if cur = findRule(rules, id); cur == nil {
			s.detectAudit(r, action, id, audit.Error, "result=not found")
			http.Redirect(w, r, "/security/rules?err=missing", http.StatusSeeOther)
			return
		}
	}
	f := ruleFormFromPost(r, cur, now)
	rule, msg := ruleFromForm(f, cur)
	// The response offered is the one the rule may take as it will be saved.
	stored := ""
	if cur != nil {
		stored = cur.Response.Action
	}
	s.ruleResponseForm(f, rule, stored)
	if msg == "" {
		msg = ruleResponseFromForm(f, &rule, cur)
	}
	detail := ruleKind(rule.Builtin)
	if cur == nil {
		detail += " new=true"
		if findRule(rules, rule.ID) != nil {
			msg = "A rule with the ID " + rule.ID + " already exists. Pick another ID, or edit that rule."
		}
	}
	status, result := http.StatusUnprocessableEntity, "rejected"
	if msg == "" {
		if err := s.detections.SaveRule(ctx, rule); err != nil {
			// Only a validation error's text is for the owner (siem.ErrInvalidRule); any other error
			// is internal and stays in Mooring's log.
			if errors.Is(err, siem.ErrInvalidRule) {
				s.log.Info("security rules: save rejected", "rule", rule.ID, "err", err)
				msg = "The rule was not saved: " + strings.TrimPrefix(err.Error(), siem.ErrInvalidRule.Error()+": ")
			} else {
				s.log.Warn("security rules: save failed", "rule", rule.ID, "err", err)
				msg, status, result = "The rule could not be saved; see the server log.", http.StatusInternalServerError, "error"
			}
		}
	}
	if msg != "" {
		s.detectAudit(r, action, rule.ID, audit.Error, detail+" result="+result)
		f.Err = msg
		s.renderDetect(w, r, status, "security_rule_edit.html", "Edit rule", &detectPage{Edit: f})
		return
	}
	s.detectAudit(r, action, rule.ID, audit.OK, detail)
	http.Redirect(w, r, withQuery("/security/rules", url.Values{"done": {"saved"}, "rule": {rule.ID}}), http.StatusSeeOther)
}

// ruleSnoozeFor are the snooze lengths offered ("clear" ends a snooze).
var ruleSnoozeFor = map[string]time.Duration{"1h": time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "clear": 0}

// handleSecurityRuleSnooze snoozes a rule for 1 h, 24 h or 7 d, or clears its snooze
// (POST /security/rules/snooze). A snoozed rule's detections are recorded, not sent.
func (s *Server) handleSecurityRuleSnooze(w http.ResponseWriter, r *http.Request) {
	const action = "security_rule_snooze"
	if s.detections == nil {
		s.detectOffPost(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, length := strings.TrimSpace(r.PostFormValue("id")), r.PostFormValue("for")
	d, ok := ruleSnoozeFor[length]
	if !ok {
		s.detectAudit(r, action, id, audit.Error, "result=bad length")
		http.Redirect(w, r, "/security/rules?err=snoozefor", http.StatusSeeOther)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), detectTimeout)
	defer cancel()
	rules, err := s.detections.Rules(ctx)
	if err != nil {
		s.log.Warn("security rules: read for snooze failed", "err", err)
		s.detectAudit(r, action, id, audit.Error, "result=read failed")
		http.Redirect(w, r, "/security/rules?err=read", http.StatusSeeOther)
		return
	}
	cur := findRule(rules, id)
	if cur == nil {
		s.detectAudit(r, action, id, audit.Error, "result=not found")
		http.Redirect(w, r, "/security/rules?err=missing", http.StatusSeeOther)
		return
	}
	rule := *cur
	detail, done := "clear", "unsnoozed"
	rule.SnoozedUntil = time.Time{}
	if d > 0 {
		rule.SnoozedUntil = time.Now().UTC().Add(d).Truncate(time.Second)
		detail, done = "for="+length+" until="+rule.SnoozedUntil.Format(time.RFC3339), "snoozed"
	}
	if err := s.detections.SaveRule(ctx, rule); err != nil {
		s.log.Warn("security rules: snooze failed", "rule", id, "err", err)
		s.detectAudit(r, action, id, audit.Error, detail+" result=error")
		http.Redirect(w, r, "/security/rules?err=snooze", http.StatusSeeOther)
		return
	}
	s.detectAudit(r, action, id, audit.OK, detail)
	http.Redirect(w, r, withQuery("/security/rules", url.Values{"done": {done}, "rule": {id}}), http.StatusSeeOther)
}

// handleSecurityRuleDelete deletes a custom rule (POST /security/rules/delete); the service refuses
// a built-in one.
func (s *Server) handleSecurityRuleDelete(w http.ResponseWriter, r *http.Request) {
	s.ruleChange(w, r, "security_rule_delete", "delete", "deleted", s.detectionsDelete)
}

// handleSecurityRuleReset puts a built-in rule back to the pack's values
// (POST /security/rules/reset); the service refuses a custom one.
func (s *Server) handleSecurityRuleReset(w http.ResponseWriter, r *http.Request) {
	s.ruleChange(w, r, "security_rule_reset", "reset", "reset", s.detectionsReset)
}

func (s *Server) detectionsDelete(ctx context.Context, id string) error {
	return s.detections.DeleteRule(ctx, id)
}

func (s *Server) detectionsReset(ctx context.Context, id string) error {
	return s.detections.ResetRule(ctx, id)
}

// ruleChange runs one delete or reset of the rule in the form's id, audits it and redirects back.
func (s *Server) ruleChange(w http.ResponseWriter, r *http.Request, action, errCode, done string, change func(context.Context, string) error) {
	if s.detections == nil {
		s.detectOffPost(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id := strings.TrimSpace(r.PostFormValue("id"))
	ctx, cancel := context.WithTimeout(r.Context(), detectTimeout)
	defer cancel()
	if err := change(ctx, id); err != nil {
		s.log.Info("security rules: "+errCode+" refused", "rule", id, "err", err)
		s.detectAudit(r, action, id, audit.Error, "result=refused")
		http.Redirect(w, r, "/security/rules?err="+errCode, http.StatusSeeOther)
		return
	}
	s.detectAudit(r, action, id, audit.OK, "")
	q := url.Values{"done": {done}}
	if done != "deleted" {
		q.Set("rule", id)
	}
	http.Redirect(w, r, withQuery("/security/rules", q), http.StatusSeeOther)
}
