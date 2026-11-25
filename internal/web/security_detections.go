package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/query"
)

// The Detections and Rules pages (owner only, requirePerm("admin")): what the detection rules found
// and the rules themselves, from Server.detections (nil = detection is off).

const (
	detectPageSize  = 50               // detections per page
	detectPollMS    = 30000            // live refresh of the first page
	detectTimeout   = 10 * time.Second // one page's calls to the detection service
	detectSearchPad = time.Minute      // a search link covers its events ± this
	detectTimeFmt   = "2006-01-02 15:04:05"
)

// detectPage is the view of the Detections and Rules pages: the shell's tmplData plus this page's
// model. Exactly one of the models is set.
type detectPage struct {
	tmplData
	Det     *detectionsView
	One     *detectionView
	Rules   *rulesPageView
	Edit    *ruleFormView
	Off     bool   // detection is off: the page shows only that (and, on Rules, the feeds)
	Missing string // the detection or rule asked for isn't there (or couldn't be read): this message
}

// renderDetect renders a full page of these sections with status.
func (s *Server) renderDetect(w http.ResponseWriter, r *http.Request, status int, name, title string, p *detectPage) {
	// Intentional: the same shell backfill as render (handlers.go), which only takes tmplData; these
	// pages carry their own model beside it.
	p.Title = title + " — Mooring"
	p.CSRFToken = CSRFToken(r.Context())
	p.Username = sessionUser(r)
	p.EdgeMode = string(s.cfg.Edge.Mode)
	p.IdleTimeoutMs = s.cfg.Session.IdleTimeout.D().Milliseconds()
	p.UpdateBanner = s.updateBanner()
	p.CanAdmin = s.canAdmin(p.Username)
	s.writeDetect(w, status, name, p)
}

// writeDetect executes a template into a buffer first, so an error never sends half a page.
func (s *Server) writeDetect(w http.ResponseWriter, status int, name string, p *detectPage) {
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

// detectionsView backs security_detections.html and its live-refresh fragment.
type detectionsView struct {
	Form       detectForm
	Severities []sevOption
	RuleOpts   []ruleOption
	Err        string
	Rows       []detectionRow
	Filtered   bool
	OlderURL   string
	NewestURL  string // on an older page: back to the newest
	PollURL    string // the first page refreshes itself
	PollMS     int
	Credits    detectCredits
}

type sevOption struct {
	Value, Label string
	Selected     bool
}

type ruleOption struct {
	ID, Label string
	Selected  bool
}

// detectForm is the filter form as submitted: the inputs echoed back and the parsed bounds.
type detectForm struct {
	Severity, Rule, App string
	From, To            string // datetime-local values (UTC)
	from, to            time.Time
}

// detectCursor is where an older page starts: the last row of the page before it (the service's
// keyset, DetectionFilter.BeforeLast/Before). The zero cursor is the newest page.
type detectCursor struct {
	last time.Time
	id   int64
}

// parseDetectCursor reads an older-events link's before_last (RFC 3339, nanoseconds kept) and
// before (the row's ID). Both must be valid: anything else is the newest page.
func parseDetectCursor(p url.Values) detectCursor {
	last, err := time.Parse(time.RFC3339Nano, p.Get("before_last"))
	if err != nil || last.IsZero() {
		return detectCursor{}
	}
	id, err := strconv.ParseInt(p.Get("before"), 10, 64)
	if err != nil || id <= 0 {
		return detectCursor{}
	}
	return detectCursor{last: last.UTC(), id: id}
}

// params is the query string of a list link with this filter, from cur (zero = the newest page).
func (f detectForm) params(cur detectCursor) url.Values {
	v := url.Values{}
	set := func(k, x string) {
		if x != "" {
			v.Set(k, x)
		}
	}
	set("severity", f.Severity)
	set("rule", f.Rule)
	set("app", f.App)
	if !f.from.IsZero() {
		v.Set("from", f.from.UTC().Format(time.RFC3339Nano))
	}
	if !f.to.IsZero() {
		v.Set("to", f.to.UTC().Format(time.RFC3339Nano))
	}
	if !cur.last.IsZero() {
		v.Set("before_last", cur.last.UTC().Format(time.RFC3339Nano))
		v.Set("before", strconv.FormatInt(cur.id, 10))
	}
	return v
}

// withQuery is path plus v's query string, without a bare "?".
func withQuery(path string, v url.Values) string {
	if len(v) == 0 {
		return path
	}
	return path + "?" + v.Encode()
}

// detectionRow is one detection as the list and the detail page show it.
type detectionRow struct {
	ID                 int64
	URL                string
	Last, LastISO, Ago string
	First, FirstISO    string
	Sev, SevClass      string
	RuleID, RuleName   string
	Ops                bool // an app's own /ops alert, not a rule over security events
	MITRE              []mitreLink
	Key                string
	Geo                *geoView
	Where              string // app/service
	App, Service       string
	Count              string
	Summary            string
	Snoozed            bool
	Muted              bool // a false-positive mute for this rule and key
}

type mitreLink struct{ ID, URL string }

// geoView is what enrichment knows about a detection's IP, as display strings.
type geoView struct {
	Place string // "Lagos, NG"
	ASN   string // "AS64500 Example Net"
	Lists []string
}

// detectCredits says which data-licence credits a page needs: DB-IP for geolocation and ASN data,
// Spamhaus for its DROP list, the SANS Internet Storm Center for DShield's block list.
type detectCredits struct{ Geo, Spamhaus, DShield bool }

func (c *detectCredits) add(g *siem.Geo) {
	if g == nil {
		return
	}
	if g.Country != "" || g.City != "" || g.ASN != 0 || g.Org != "" || g.Lat != 0 || g.Lon != 0 {
		c.Geo = true
	}
	for _, l := range g.Lists {
		if strings.HasPrefix(l, "spamhaus") {
			c.Spamhaus = true
		}
		if l == "dshield" {
			c.DShield = true
		}
	}
}

// Credits is the credit line the search results need: each row's event JSON shows its geo and lists.
func (v *securityView) Credits() detectCredits {
	var c detectCredits
	for i := range v.Rows {
		if !strings.Contains(v.Rows[i].JSON, `"geo"`) {
			continue
		}
		var e struct {
			Geo *siem.Geo `json:"geo"`
		}
		if json.Unmarshal([]byte(v.Rows[i].JSON), &e) == nil {
			c.add(e.Geo)
		}
	}
	return c
}

// detectSevClass is a severity's badge class (an allowlist: Severity is stored data).
var detectSevClass = map[siem.Severity]string{
	siem.SevLow: "sec-lvl-info", siem.SevMedium: "sec-lvl-warn", siem.SevHigh: "sec-lvl-error", siem.SevCritical: "sec-lvl-critical",
}

func sevClass(s siem.Severity) string {
	if c := detectSevClass[s]; c != "" {
		return c
	}
	return "sec-lvl-info"
}

var detectSeverities = []siem.Severity{siem.SevLow, siem.SevMedium, siem.SevHigh, siem.SevCritical}

// filterSeverityOptions is the minimum-severity select of the list's filter.
func filterSeverityOptions(cur string) []sevOption {
	opts := []sevOption{{Value: "", Label: "Any severity", Selected: cur == ""}}
	for _, s := range detectSeverities {
		label := strings.ToUpper(string(s[:1])) + string(s[1:]) + " and above"
		if s == siem.SevCritical {
			label = "Critical"
		}
		opts = append(opts, sevOption{Value: string(s), Label: label, Selected: cur == string(s)})
	}
	return opts
}

// mitreTechnique is an ATT&CK technique ID (T1110) or sub-technique (T1110.003); only those get a
// link, since custom rules' IDs are typed by the operator.
var mitreTechnique = regexp.MustCompile(`^T[0-9]{4}(\.[0-9]{3})?$`)

func mitreLinks(ids []string) []mitreLink {
	out := make([]mitreLink, 0, len(ids))
	for _, id := range ids {
		l := mitreLink{ID: id}
		if mitreTechnique.MatchString(id) {
			l.URL = "https://attack.mitre.org/techniques/" + strings.Replace(id, ".", "/", 1) + "/"
		}
		out = append(out, l)
	}
	return out
}

// listLabels names the threat-intel lists and feeds for the page.
var listLabels = map[string]string{
	"dbip-city":     "DB-IP City Lite",
	"dbip-asn":      "DB-IP ASN Lite",
	"spamhaus-drop": "Spamhaus DROP",
	"tor-exits":     "Tor exit",
	"tor-exit":      "Tor exit", // the list tag on events; "tor-exits" is the feed
	"dshield":       "DShield",
}

func listLabel(name string) string {
	if l := listLabels[name]; l != "" {
		return l
	}
	return name
}

func geoViewOf(g *siem.Geo) *geoView {
	if g == nil {
		return nil
	}
	v := &geoView{}
	switch {
	case g.City != "" && g.Country != "":
		v.Place = g.City + ", " + g.Country
	case g.Country != "":
		v.Place = g.Country
	default:
		v.Place = g.City
	}
	switch {
	case g.ASN != 0 && g.Org != "":
		v.ASN = "AS" + strconv.FormatUint(uint64(g.ASN), 10) + " " + g.Org
	case g.ASN != 0:
		v.ASN = "AS" + strconv.FormatUint(uint64(g.ASN), 10)
	default:
		v.ASN = g.Org
	}
	for _, l := range g.Lists {
		v.Lists = append(v.Lists, listLabel(l))
	}
	if v.Place == "" && v.ASN == "" && len(v.Lists) == 0 {
		return nil
	}
	return v
}

func detectionRowOf(d *siem.Detection, now time.Time) detectionRow {
	row := detectionRow{
		ID: d.ID, URL: "/security/detections/" + strconv.FormatInt(d.ID, 10),
		Sev: string(d.Severity), SevClass: sevClass(d.Severity),
		RuleID: d.RuleID, RuleName: d.RuleName, Ops: d.Source == siem.DetectionOps,
		MITRE: mitreLinks(d.MITRE), Key: d.Key, Geo: geoViewOf(d.Geo),
		App: d.App, Service: d.Service, Count: groupDigits(d.Count), Summary: d.Summary, Snoozed: d.Snoozed, Muted: d.Muted,
	}
	if row.RuleName == "" {
		row.RuleName = d.RuleID
	}
	if !d.Last.IsZero() {
		row.Last, row.LastISO, row.Ago = d.Last.UTC().Format(detectTimeFmt), d.Last.UTC().Format(time.RFC3339), secAgo(now, d.Last)
	}
	if !d.First.IsZero() {
		row.First, row.FirstISO = d.First.UTC().Format(detectTimeFmt), d.First.UTC().Format(time.RFC3339)
	}
	switch {
	case d.App != "" && d.Service != "":
		row.Where = d.App + "/" + d.Service
	case d.App != "":
		row.Where = d.App
	default:
		row.Where = d.Service
	}
	return row
}

// parseDetectionFilter reads the list's filter. An unknown severity or a bad page cursor is ignored;
// a bad time is a message for the owner (and no query).
func parseDetectionFilter(p url.Values) (siem.DetectionFilter, detectForm, string) {
	var form detectForm
	f := siem.DetectionFilter{Limit: detectPageSize + 1} // one more than shown: is there an older page?
	if sev := siem.Severity(p.Get("severity")); siem.SeverityRank(sev) > 0 {
		f.MinSeverity, form.Severity = sev, string(sev)
	}
	form.Rule = siem.Cut(strings.TrimSpace(p.Get("rule")), siem.MaxShort)
	form.App = siem.Cut(strings.TrimSpace(p.Get("app")), siem.MaxShort)
	f.RuleID, f.App = form.Rule, form.App
	cur := parseDetectCursor(p)
	f.BeforeLast, f.Before = cur.last, cur.id
	var err error
	if form.from, err = parseSecurityTime(p.Get("from")); err != nil {
		form.From, form.To = siem.Cut(p.Get("from"), 64), siem.Cut(p.Get("to"), 64)
		return f, form, "From is not a valid date and time."
	}
	if form.to, err = parseSecurityTime(p.Get("to")); err != nil {
		form.From, form.To = securityInputValue(form.from), siem.Cut(p.Get("to"), 64)
		return f, form, "To is not a valid date and time."
	}
	form.From, form.To = securityInputValue(form.from), securityInputValue(form.to)
	if !form.from.IsZero() && !form.to.IsZero() && !form.from.Before(form.to) {
		return f, form, "From must be before To."
	}
	f.From, f.To = form.from, form.to
	return f, form, ""
}

// detectionsList builds the list for the page, or for its live refresh (live: no filter form, so
// no rule options, and always the newest page, the only one that refreshes).
func (s *Server) detectionsList(r *http.Request, live bool) *detectionsView {
	ds := s.detections
	f, form, errMsg := parseDetectionFilter(r.URL.Query())
	if live {
		f.BeforeLast, f.Before = time.Time{}, 0
	}
	v := &detectionsView{Form: form, Severities: filterSeverityOptions(form.Severity), PollMS: detectPollMS}
	v.Filtered = form.Severity != "" || form.Rule != "" || form.App != "" || !form.from.IsZero() || !form.to.IsZero()
	ctx, cancel := context.WithTimeout(r.Context(), detectTimeout)
	defer cancel()
	if !live {
		v.RuleOpts = s.ruleOptions(ctx, form.Rule)
	}
	if errMsg != "" {
		v.Err = errMsg
		return v
	}
	list, err := ds.Detections(ctx, f)
	if err != nil {
		s.log.Warn("security detections: list failed", "err", err)
		v.Err = "The detections could not be read. Mooring's log has the details."
		return v
	}
	more := len(list) > detectPageSize
	if more {
		list = list[:detectPageSize]
	}
	now := time.Now().UTC()
	for i := range list {
		v.Rows = append(v.Rows, detectionRowOf(&list[i], now))
		v.Credits.add(list[i].Geo)
	}
	// The next page starts after the last row shown, in the service's order (last seen, then ID).
	// A row without a last-seen time can't be a cursor (a zero BeforeLast is the newest page).
	if more {
		if last := list[len(list)-1]; !last.Last.IsZero() {
			v.OlderURL = withQuery("/security/detections", form.params(detectCursor{last: last.Last, id: last.ID}))
		}
	}
	if !f.BeforeLast.IsZero() {
		v.NewestURL = withQuery("/security/detections", form.params(detectCursor{}))
	} else {
		v.PollURL = withQuery("/security/detections/rows", form.params(detectCursor{}))
	}
	return v
}

// ruleOptions is the rule select of the filter: every rule, plus the current filter when it is not
// one of them (an app /ops alert's rule ID, or a rule since deleted).
func (s *Server) ruleOptions(ctx context.Context, cur string) []ruleOption {
	opts := []ruleOption{{ID: "", Label: "Any rule", Selected: cur == ""}}
	found := cur == ""
	rules, err := s.detections.Rules(ctx)
	if err != nil {
		s.log.Warn("security detections: rules for the filter", "err", err)
	}
	for _, ru := range rules {
		opts = append(opts, ruleOption{ID: ru.ID, Label: ru.Name, Selected: ru.ID == cur})
		found = found || ru.ID == cur
	}
	if !found {
		opts = append(opts, ruleOption{ID: cur, Label: cur, Selected: true})
	}
	return opts
}

// handleDetections renders the Detections page (GET /security/detections).
func (s *Server) handleDetections(w http.ResponseWriter, r *http.Request) {
	p := &detectPage{Off: s.detections == nil}
	if !p.Off {
		p.Det = s.detectionsList(r, false)
	}
	s.renderDetect(w, r, http.StatusOK, "security_detections.html", "Detections", p)
}

// handleDetectionRows renders the newest page's list for its live refresh.
func (s *Server) handleDetectionRows(w http.ResponseWriter, r *http.Request) {
	p := &detectPage{Off: s.detections == nil}
	if !p.Off {
		p.Det = s.detectionsList(r, true)
	}
	s.writeDetect(w, http.StatusOK, "secdetlist", p)
}

// detectionView backs security_detection.html.
type detectionView struct {
	detectionRow
	Source      string
	RuleURL     string // the rule's edit page, when the rule exists
	MoreURL     string // more detections of this rule
	RelatedURL  string // a search for this key's events over the detection's span
	RelatedTerm string
	PatternURL  string // a log-pattern detection: its pattern's page (instead of RelatedURL)
	Evidence    []evidenceRow
	Browsers    bool // an evidence row is marked browser or browser-like agent
	Credits     detectCredits
	Responses   []respRow // automated responses about it
	RespErr     string
}

// patternRulePrefix starts the IDs of the log-pattern rules, whose detections are keyed by pattern ID.
const patternRulePrefix = "pattern."

type evidenceRow struct {
	When, ISO, Ago       string
	Kind, IP, Actor, App string
	SearchURL            string
	// Agent marks a request that doesn't count toward an automatic block: "browser" (it carried
	// browser fetch metadata) or "browser-like agent" (a browser's or mail client's User-Agent).
	Agent string
}

// detectSearchURL is a Security logs search link for terms within [from, to).
func detectSearchURL(terms []string, from, to time.Time) string {
	return "/security?" + securityParams(strings.Join(terms, " "), securityDefaultRange, from, to).Encode()
}

// searchTerm is field:value in the search syntax (quoted when needed); "" for an empty value.
func searchTerm(field, value string) string {
	if value == "" {
		return ""
	}
	return field + ":" + quoteSecurityValue(value, false)
}

func evidenceTerms(ev siem.Evidence) []string {
	var terms []string
	for _, t := range []string{searchTerm("kind", ev.Kind), searchTerm("ip", ev.IP), searchTerm("actor", ev.Actor), searchTerm("app", ev.App)} {
		if t != "" {
			terms = append(terms, t)
		}
	}
	return terms
}

// groupSearchField is the search field of a rule's GroupBy ("" when its key can't be searched).
func groupSearchField(groupBy string) string {
	switch {
	case groupBy == "ip", groupBy == "actor", groupBy == "app", groupBy == "kind", groupBy == "geo.cc", groupBy == "geo.asn":
		return groupBy
	case strings.HasPrefix(groupBy, "f.") && len(groupBy) > 2:
		return groupBy
	}
	return ""
}

// relatedEither are the built-in rules whose key is the value of one of two fields (the detection
// engine's pack keys an event lacking the first by the second), with the events that name exactly one
// of them: host account changes name the user, or the group for the group programs.
var relatedEither = map[string]struct{ first, second, events string }{
	"host.user_change": {"f.user", "f.group", "kind:" + siem.KindUserChange},
}

// relatedSearch is the search of a detection's "Find related events" link ("" for none): the events
// of its key, or the rule's own events when the key isn't a value to search for (a rule without a
// group-by, a rollup's "*") or its search isn't one the search page accepts.
func relatedSearch(ru siem.Rule, key string) string {
	var tries []string
	// fields are the ones a key search may use: one that parses into a term on any other field
	// (a custom f.<key> holding ':', '~', '<', '>' or "!=" reads as a shorter field) would search
	// the wrong thing and find nothing, so it falls back to the rule's own events.
	fields := map[string]bool{}
	if field := groupSearchField(ru.GroupBy); field != "" && searchableKey(field, key) {
		fields[field] = true
		pair, either := relatedEither[ru.ID]
		switch {
		case either && ru.Builtin && ru.GroupBy == pair.first:
			// Intentional: the search has no OR. An event of these names one field at most, so
			// "-first!=K -second!=K" among them finds the key's events whichever field holds it (and
			// the ones naming neither).
			v := quoteSecurityValue(key, false)
			fields[pair.second], fields["kind"] = true, true
			tries = append(tries, pair.events+" -"+pair.first+"!="+v+" -"+pair.second+"!="+v)
		case field == "f.host" && strings.HasPrefix(key, "*."):
			// Intentional: a catch-all route's key ("*.<apex>": the traffic baseline counts every label
			// under it as one). No event's host starts with "*.", and the search has no suffix match:
			// f.host~.<apex> would also find hosts under other apexes (x.<apex>munity,
			// a.<apex>.evil.org), so the rule's own events are searched instead.
		case field == "f.host":
			// Intentional: the key is the Host header lowercased without its port or trailing dot, and
			// the search compares without regard to case, so a prefix finds it stored with a port or a
			// dot. It also finds longer names that start with the key (example.co finds example.com):
			// the search can't say "this name, with or without a port" in one term.
			tries = append(tries, field+":"+quoteSecurityValue(key+"*", false))
		case strings.HasPrefix(field, "f.") && len(key) > siem.MaxShort-utf8.UTFMax:
			// The engine cuts an F value to MaxShort bytes for its key; the stored value can be longer.
			tries = append(tries, field+":"+quoteSecurityValue(key+"*", false))
		default:
			tries = append(tries, searchTerm(field, key))
		}
	}
	keyTries := len(tries)
	if ru.Query != "" {
		tries = append(tries, ru.Query)
	}
	for i, s := range tries {
		q, err := query.Parse(s)
		if err != nil {
			continue
		}
		if i < keyTries && !termsOn(q, fields) {
			continue
		}
		return s
	}
	return ""
}

// termsOn reports whether every term of q is on one of fields.
func termsOn(q query.Query, fields map[string]bool) bool {
	for _, t := range q.Terms {
		if !fields[t.Field] {
			return false
		}
	}
	return len(q.Terms) > 0
}

// searchableKey reports whether key is a value of field to search for: not empty, not a pattern of
// only '*' (it would match every value: a rollup's key), an address or prefix for ip.
func searchableKey(field, key string) bool {
	if strings.Trim(key, "*") == "" {
		return false
	}
	if field == "ip" {
		if _, err := netip.ParseAddr(key); err == nil {
			return true
		}
		_, err := netip.ParsePrefix(key)
		return err == nil
	}
	return true
}

// handleDetection renders one detection (GET /security/detections/{id}).
func (s *Server) handleDetection(w http.ResponseWriter, r *http.Request) {
	const page, title = "security_detection.html", "Detection"
	if s.detections == nil {
		s.renderDetect(w, r, http.StatusOK, page, title, &detectPage{Off: true})
		return
	}
	notFound := func() {
		s.renderDetect(w, r, http.StatusNotFound, page, title, &detectPage{Missing: "Detection not found."})
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		notFound()
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), detectTimeout)
	defer cancel()
	d, ok, err := s.detections.Detection(ctx, id)
	if err != nil {
		s.log.Warn("security detections: read failed", "id", id, "err", err)
		s.renderDetect(w, r, http.StatusInternalServerError, page, title, &detectPage{Missing: "The detection could not be read. Mooring's log has the details."})
		return
	}
	if !ok {
		notFound()
		return
	}
	now := time.Now().UTC()
	v := &detectionView{detectionRow: detectionRowOf(&d, now), Source: "Rule over security events"}
	if v.Ops {
		v.Source = "App /ops alert"
	}
	v.Credits.add(d.Geo)
	if d.RuleID != "" {
		v.MoreURL = withQuery("/security/detections", url.Values{"rule": {d.RuleID}})
	}
	// A log-pattern detection is keyed by its pattern's ID: it links the pattern's page (when the
	// Patterns pages run) and never a search for the ID, which matches no event.
	isPattern := strings.HasPrefix(d.RuleID, patternRulePrefix) && patIDPattern.MatchString(d.Key)
	if isPattern && s.patterns != nil {
		v.PatternURL = "/security/patterns/" + d.Key
	}
	if !v.Ops {
		rules, err := s.detections.Rules(ctx)
		if err != nil {
			s.log.Warn("security detections: rules for a detection", "err", err)
		}
		for _, ru := range rules {
			if ru.ID != d.RuleID {
				continue
			}
			v.RuleURL = withQuery("/security/rules/edit", url.Values{"id": {ru.ID}})
			if isPattern {
				continue
			}
			if search := relatedSearch(ru, d.Key); search != "" && !d.First.IsZero() && !d.Last.IsZero() {
				v.RelatedTerm = search
				v.RelatedURL = detectSearchURL([]string{search}, d.First.Add(-detectSearchPad), d.Last.Add(detectSearchPad))
			}
		}
	}
	for i, ev := range d.Evidence {
		if i == siem.MaxEvidence {
			break
		}
		row := evidenceRow{Kind: ev.Kind, IP: ev.IP, Actor: ev.Actor, App: ev.App}
		switch {
		case ev.Browser:
			row.Agent = "browser"
		case ev.BrowserAgent:
			row.Agent = "browser-like agent"
		}
		v.Browsers = v.Browsers || row.Agent != ""
		if !ev.TS.IsZero() {
			row.When, row.ISO, row.Ago = ev.TS.UTC().Format(detectTimeFmt), ev.TS.UTC().Format(time.RFC3339Nano), secAgo(now, ev.TS)
			if terms := evidenceTerms(ev); len(terms) > 0 {
				row.SearchURL = detectSearchURL(terms, ev.TS.Add(-detectSearchPad), ev.TS.Add(detectSearchPad))
			}
		}
		v.Evidence = append(v.Evidence, row)
	}
	v.Responses, v.RespErr = s.detectionResponses(ctx, d.ID)
	s.renderDetect(w, r, http.StatusOK, page, v.RuleName, &detectPage{One: v})
}
