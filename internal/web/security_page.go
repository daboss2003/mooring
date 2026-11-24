package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/query"
	"github.com/daboss2003/mooring/internal/siem/store"
)

// SecurityLogs is what the Security logs page reads (docs/security-logs.md). nil in Deps = security
// logs are off.
type SecurityLogs interface {
	Search(ctx context.Context, q query.Query, limit int) (store.Result, error)
	Export(ctx context.Context, q query.Query, w io.Writer, maxEvents int) (int, error)
	Status() siem.Status
	// SearchValue is value as redaction stores it (hashed or not); field is "actor" or an F key as
	// typed after "f." (the full key: redaction classifies its parents too).
	SearchValue(field, value string) string
	// SearchText is free search text as redaction stores message text (emails and phone numbers
	// hashed).
	SearchText(text string) string
	// SecretField reports whether redaction stores field's values as [redacted]; field is an F key as
	// typed after "f.", or "actor".
	SecretField(field string) bool
}

const (
	securityPageSize          = 200              // events per results page
	securityExportMax         = 100000           // events per export
	securityQueryMax          = 2 << 10          // bytes of the search string (query.Parse's own limit)
	securitySearchTimeout     = 20 * time.Second // under the server's 60s write timeout
	securityExportTimeout     = 10 * time.Minute // write deadline and context of one export
	securityExportConcurrency = 1                // exports at once: the store runs two searches or exports, so one stays for searches
	securityMsgCut            = 300              // bytes of the one-line message in a results row
	securityDefaultRange      = "24h"
)

// securityRange is one time-range preset of the search form.
type securityRange struct {
	Value, Label string
	d            time.Duration
}

var securityRanges = []securityRange{
	{"15m", "Last 15 minutes", 15 * time.Minute},
	{"1h", "Last hour", time.Hour},
	{"6h", "Last 6 hours", 6 * time.Hour},
	{"24h", "Last 24 hours", 24 * time.Hour},
	{"7d", "Last 7 days", 7 * 24 * time.Hour},
	{"14d", "Last 14 days", 14 * 24 * time.Hour},
}

// securityView backs security.html and its status fragment.
type securityView struct {
	On       bool // a SecurityLogs is wired
	Status   *securityStatusView
	Presets  []securityRange
	Q        string // the search: as typed, or with personal data as its hash once mapped
	Range    string
	From, To string // the from/to inputs (datetime-local form, UTC), "" when not set
	Err      string
	Searched bool
	Window   string
	Scanned  string
	Capped   bool
	Rows     []securityRow
	PageSize int
	OlderURL string
	Export   string
	// ReplaceURL is this search's URL with personal data hashed, for app.js to put in the address
	// bar ("" when the search held none).
	ReplaceURL string
}

type securityStatusView struct {
	Enabled       bool
	Sources       []securitySourceRow
	Queue         string // "12 / 10,000"
	QueueHigh     bool   // at least 90% full
	Disk          string
	Segments      string
	Oldest        string
	OldestAgo     string
	ArchiveOn     bool
	LastArchived  string
	ArchiveBehind string
	ArchiveErr    string
	Problem       string // what is wrong, as a clause ("host:auth is not collecting"); "" when nothing is
}

type securitySourceRow struct {
	Name            string
	OK              bool
	Err             string
	Events, Dropped string
	HasDropped      bool
	LastSeen, Ago   string
}

type securityRow struct {
	When, ISO, Ago string
	Src, Where     string
	Lvl, LvlClass  string
	Kind           string
	Out, OutClass  string
	Actor, IP      string
	Msg            string
	JSON           string
}

// canAdmin reports whether username's role may do admin actions (the owner), from the live users
// (render's tmplData.CanAdmin).
func (s *Server) canAdmin(username string) bool {
	sec := s.security()
	if sec == nil {
		return false
	}
	role, ok := sec.role(username)
	return ok && role.Can("admin")
}

func (s *Server) parseSecurityQuery(q string) (query.Query, error) {
	if s.secParse != nil { // test seam
		return s.secParse(q)
	}
	return query.Parse(q)
}

// handleSecurity renders the Security logs page: pipeline status, the search form and one page of
// results. Owner only (requirePerm("admin")).
func (s *Server) handleSecurity(w http.ResponseWriter, r *http.Request) {
	v := &securityView{On: s.securityLogs != nil, Presets: securityRanges, Range: securityDefaultRange, PageSize: securityPageSize}
	if !v.On {
		s.renderSecurityPage(w, r, v)
		return
	}
	sl := s.securityLogs
	now := time.Now().UTC()
	v.Status = securityStatusOf(sl.Status(), now)
	form, q, errMsg := s.securityQueryFrom(r, sl, now)
	v.Q, v.Range, v.From, v.To = form.q, form.rng, form.fromIn, form.toIn
	if form.rewritten {
		v.ReplaceURL = "/security?" + securityParams(form.q, form.rng, form.from, form.to).Encode()
	}
	if errMsg != "" {
		v.Err = errMsg
		s.renderSecurityPage(w, r, v)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), securitySearchTimeout)
	defer cancel()
	res, err := sl.Search(ctx, q, securityPageSize)
	if form.asked {
		outcome, detail := audit.OK, securityAuditDetail(form.rng, q)
		if err != nil {
			outcome, detail = audit.Error, "result="+searchFailure(err)+" "+detail
		}
		// Intentional: unlike an export, a search is not refused when its audit record can't be written
		// (audit.Log logs that failure): it shows the owner only what this page already may.
		_ = s.audit.Log(r.Context(), audit.Event{
			Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), UA: r.UserAgent(), Action: "security_logs_search",
			Target: "security_logs", Outcome: outcome, Level: audit.Info, Detail: detail,
		})
	}
	if err != nil {
		switch searchFailure(err) {
		case "busy":
			v.Err = securityBusy
		case "time limit":
			v.Err = "The search took too long. Narrow the range or add terms."
		default:
			s.log.Warn("security logs: search failed", "err", err)
			v.Err = "The search failed. Mooring's log has the details."
		}
		s.renderSecurityPage(w, r, v)
		return
	}
	v.Searched = true
	v.Window = securityWindowText(q.From, q.To)
	v.Scanned = groupDigits(int(res.Scanned))
	v.Capped = res.Capped
	for i := range res.Events {
		v.Rows = append(v.Rows, securityRowOf(&res.Events[i], now))
	}
	if res.More && !res.Before.IsZero() {
		// The next page keeps this page's start and ends where it stopped, so the window doesn't
		// slide with the clock.
		v.OlderURL = "/security?" + securityParams(form.q, form.rng, q.From, res.Before).Encode()
	}
	v.Export = "/security/export?" + securityParams(form.q, form.rng, form.from, form.to).Encode()
	s.renderSecurityPage(w, r, v)
}

func (s *Server) renderSecurityPage(w http.ResponseWriter, r *http.Request, v *securityView) {
	s.render(w, r, "security.html", tmplData{Title: "Security logs — Mooring", CSRFToken: CSRFToken(r.Context()), Security: v})
}

// handleSecurityStatus renders the status panel for the page's live refresh.
func (s *Server) handleSecurityStatus(w http.ResponseWriter, r *http.Request) {
	v := &securityView{On: s.securityLogs != nil}
	if v.On {
		v.Status = securityStatusOf(s.securityLogs.Status(), time.Now().UTC())
	}
	s.renderPartial(w, "securitystatus", tmplData{Security: v})
}

// handleSecurityExport streams every event the search matches (oldest first, at most
// securityExportMax) as an NDJSON download. The export is audited before the first byte; one that
// stops early or reaches the cap ends with an "incomplete" line and a second audit event.
func (s *Server) handleSecurityExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		// The mux routes HEAD to a GET pattern; a HEAD must not run (and audit) a whole export.
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	sl := s.securityLogs
	if sl == nil {
		http.Error(w, "security logs are off", http.StatusNotFound)
		return
	}
	now := time.Now().UTC()
	form, q, errMsg := s.securityQueryFrom(r, sl, now)
	if errMsg != "" {
		http.Error(w, errMsg, http.StatusBadRequest)
		return
	}
	select {
	case s.securityExports <- struct{}{}:
		defer func() { <-s.securityExports }()
	default:
		http.Error(w, "Another security-log export is running. Try again when it finishes.", http.StatusServiceUnavailable)
		return
	}
	to := q.To
	if to.IsZero() {
		to = now
	}
	user := sessionUser(r)
	event := func(action string, outcome audit.Outcome, detail string) audit.Event {
		return audit.Event{
			Actor: user, IP: ClientIP(r.Context()).String(), UA: r.UserAgent(), Action: action,
			Target: "security_logs", Outcome: outcome, Level: audit.Security, Detail: detail,
		}
	}
	// The audit event is written just before the first byte goes out, so a refusal by the store
	// (busy) leaves no "ok" record of an export that never ran.
	ew := &exportWriter{w: w, audit: func() error {
		return s.audit.Log(r.Context(), event("security_logs_export", audit.OK, securityAuditDetail(form.rng, q)))
	}}
	h := w.Header()
	h.Set("Content-Type", "application/x-ndjson")
	h.Set("Content-Disposition", `attachment; filename="security-logs-`+q.From.UTC().Format("20060102T150405Z")+"-"+to.UTC().Format("20060102T150405Z")+`.ndjson"`)
	h.Set("Cache-Control", "no-store")
	// A large export can outlast the server's 60s write timeout; give it a longer, still bounded one,
	// with room after the export's own limit for the closing line.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(securityExportTimeout + 30*time.Second))
	ctx, cancel := context.WithTimeout(r.Context(), securityExportTimeout)
	defer cancel()
	n, err := sl.Export(ctx, q, ew, securityExportMax)
	if ew.n == 0 && errors.Is(err, store.ErrBusy) {
		h.Del("Content-Disposition")
		http.Error(w, securityBusy, http.StatusServiceUnavailable)
		return
	}
	if aerr := ew.ensureAudit(); aerr != nil {
		// Intentional: fail closed (handleBackupDownload ignores a failed audit write): a security-log
		// export the audit log can't record doesn't happen. The audit precedes the first byte, so
		// nothing has been sent.
		h.Del("Content-Disposition")
		http.Error(w, "The export was refused: its audit record could not be written.", http.StatusInternalServerError)
		return
	}
	reason := exportIncompleteReason(n, err)
	if reason == "" {
		s.log.Info("security logs: exported", "actor", user, "events", n)
		return
	}
	// The file says it is incomplete in its last line, so a partial download never passes as whole.
	line, _ := json.Marshal(struct {
		Export string `json:"export"`
		Reason string `json:"reason"`
		Events int    `json:"events"`
	}{"incomplete", reason, n})
	_, werr := ew.Write(append(line, '\n'))
	_ = s.audit.Log(r.Context(), event("security_logs_export_incomplete", audit.Error,
		siem.Cut(fmt.Sprintf("reason=%s events=%d ", reason, n)+securityAuditDetail(form.rng, q), 2048)))
	s.log.Warn("security logs: export incomplete", "actor", user, "events", n, "reason", reason, "err", err, "closing_line_err", werr)
}

// securityBusy is shown when the store's search slots are all taken.
const securityBusy = "Other security-log searches or an export are running. Try again in a moment."

// searchFailure names why a search failed, for its audit record and message.
func searchFailure(err error) string {
	switch {
	case errors.Is(err, store.ErrBusy):
		return "busy"
	case errors.Is(err, context.DeadlineExceeded):
		return "time limit"
	}
	return "error"
}

// exportIncompleteReason says why an export that wrote n events is not the whole match, "" when it
// is: the cap was reached, its time ran out, the store's scan budget stopped it, or an error did.
func exportIncompleteReason(n int, err error) string {
	switch {
	case err == nil && n >= securityExportMax:
		return "cap reached"
	case err == nil:
		return ""
	case errors.Is(err, store.ErrSegmentRemoved):
		return "segment removed"
	case errors.Is(err, store.ErrBudget):
		return "scan budget"
	case errors.Is(err, context.DeadlineExceeded):
		return "time limit"
	}
	return "error"
}

// securityAuditDetail is the audit Detail of a search or export: the query as searched (personal
// data as its hash) and the window, never results.
func securityAuditDetail(rng string, q query.Query) string {
	return siem.Cut(fmt.Sprintf("q=%s range=%s from=%s to=%s", strconv.Quote(encodeSecurityQuery(q)), rng,
		q.From.Format(time.RFC3339), securityToText(q.To)), 2048)
}

// securityForm is the search form as submitted, normalized.
type securityForm struct {
	q, rng        string    // q is as typed until it is rewritten (see rewritten)
	rewritten     bool      // q had personal data hashed or a secret term removed: the address bar changes too
	asked         bool      // the request carries search parameters (not a plain page load)
	fromIn, toIn  string    // the from/to inputs echoed back (datetime-local form)
	from, to      time.Time // as typed (zero = not set), before the range fills in from
	rangeDuration time.Duration
}

// securityQueryFrom reads q/range/from/to, parses the search, sets its window and maps personal
// data to its stored hash. A non-empty message is a problem with the input, shown to the owner.
func (s *Server) securityQueryFrom(r *http.Request, sl SecurityLogs, now time.Time) (securityForm, query.Query, string) {
	p := r.URL.Query()
	f := securityForm{q: p.Get("q"), rng: securityDefaultRange}
	f.asked = p.Has("q") || p.Has("range") || p.Has("from") || p.Has("to")
	for _, pr := range securityRanges {
		if pr.Value == securityDefaultRange {
			f.rangeDuration = pr.d
		}
	}
	for _, pr := range securityRanges {
		if pr.Value == p.Get("range") {
			f.rng, f.rangeDuration = pr.Value, pr.d
		}
	}
	var err error
	if f.from, err = parseSecurityTime(p.Get("from")); err != nil {
		return f, query.Query{}, "From is not a valid date and time."
	}
	if f.to, err = parseSecurityTime(p.Get("to")); err != nil {
		return f, query.Query{}, "To is not a valid date and time."
	}
	f.fromIn, f.toIn = securityInputValue(f.from), securityInputValue(f.to)
	if len(f.q) > securityQueryMax {
		return f, query.Query{}, "The search is too long (over " + groupDigits(securityQueryMax) + " bytes)."
	}
	from := f.from
	switch {
	case !from.IsZero():
	case !f.to.IsZero():
		from = f.to.Add(-f.rangeDuration)
	default:
		from = now.Add(-f.rangeDuration)
	}
	if !f.to.IsZero() && !from.Before(f.to) {
		return f, query.Query{}, "From must be before To."
	}
	q, err := s.parseSecurityQuery(f.q)
	if err != nil {
		return f, query.Query{}, "The search could not be read: " + err.Error()
	}
	q.From, q.To = from, f.to
	// A secret field's values are stored [redacted], so a term on one can never match; its typed value
	// must not reach the audit log or the address bar either. Presence (f.password:*) is a search.
	var secret []string
	kept := make([]query.Term, 0, len(q.Terms))
	for _, t := range q.Terms {
		if key, ok := redactedKey(t.Field); ok && t.Value != "*" && sl.SecretField(key) {
			if !slices.Contains(secret, t.Field) {
				secret = append(secret, t.Field)
			}
			continue
		}
		kept = append(kept, t)
	}
	q.Terms = kept
	sv := storedValue(sl)
	q.MapValues(func(field, value string) (string, bool) {
		v, changed := sv(field, value)
		f.rewritten = f.rewritten || changed
		return v, changed
	})
	// Free text matches message text, which is stored with its emails and phone numbers hashed.
	text := make([]string, len(q.Text))
	for i, t := range q.Text {
		text[i] = sl.SearchText(t)
		f.rewritten = f.rewritten || text[i] != t
	}
	q.Text = text
	if f.rewritten = f.rewritten || len(secret) > 0; f.rewritten {
		// From here the search box, its links and the address bar carry the rewritten search, so a
		// clear value stays only in what the owner typed. It searches the same: hashes aren't hashed
		// again.
		f.q = encodeSecurityQuery(q)
	}
	if len(secret) > 0 {
		return f, query.Query{}, strings.Join(secret, ", ") + ": secret fields are stored redacted; their values can't be searched."
	}
	return f, q, ""
}

// redactedKey is the name redaction knows a term's field by: "actor", or the F key after "f.".
func redactedKey(field string) (string, bool) {
	switch {
	case field == "actor":
		return field, true
	case strings.HasPrefix(field, "f."):
		return field[2:], true
	}
	return "", false
}

// storedValue rewrites the value of an actor or f.<key> term to the form redaction stores it in,
// so personal data typed in clear text matches its keyed hash. Redaction classifies an F key whole
// (a parent counts: phone.number is personal data), so it gets the full key. Other fields are never
// redacted.
func storedValue(sl SecurityLogs) func(field, value string) (string, bool) {
	return func(field, value string) (string, bool) {
		name, ok := redactedKey(field)
		if !ok {
			return value, false
		}
		// Already a stored hash, or a prefix pattern (f.email:* = has an email): not a value to hash.
		if isPIIHash(value) || strings.HasSuffix(value, "*") {
			return value, false
		}
		v := sl.SearchValue(name, value)
		return v, v != value
	}
}

// isPIIHash reports whether v is already a stored personal-data hash: "h:" + 16 lowercase hex.
func isPIIHash(v string) bool {
	if len(v) != 18 || !strings.HasPrefix(v, "h:") {
		return false
	}
	for _, c := range v[2:] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// encodeSecurityQuery writes a parsed search back in the search syntax, terms first and then text;
// query.Parse reads the result back to the same terms and text.
func encodeSecurityQuery(q query.Query) string {
	parts := make([]string, 0, len(q.Terms)+len(q.Text))
	for _, t := range q.Terms {
		p := t.Field + string(t.Op) + quoteSecurityValue(t.Value, false)
		if t.Neg {
			p = "-" + p
		}
		parts = append(parts, p)
	}
	for _, x := range q.Text {
		parts = append(parts, quoteSecurityValue(x, true))
	}
	return strings.Join(parts, " ")
}

// quoteSecurityValue quotes s the way query.Parse unquotes it (only \" and \\ are escapes). A term
// value stays bare unless it holds a space, a quote or a backslash; text is always quoted, since a
// bare word with an operator character or a leading '-' would read as a term.
func quoteSecurityValue(s string, always bool) string {
	if !always && s != "" && !strings.ContainsAny(s, `"\`) && strings.IndexFunc(s, unicode.IsSpace) < 0 {
		return s
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// securityTimeLayouts are the from/to forms accepted: datetime-local (minutes, seconds, fractions;
// UTC) and RFC 3339 (the older-events link).
var securityTimeLayouts = []string{time.RFC3339Nano, "2006-01-02T15:04:05", "2006-01-02T15:04"}

func parseSecurityTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	for _, l := range securityTimeLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, errors.New("bad time")
}

func securityInputValue(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02T15:04:05")
}

// securityParams is the query string of a search link.
func securityParams(q, rng string, from, to time.Time) url.Values {
	v := url.Values{}
	if q != "" {
		v.Set("q", q)
	}
	v.Set("range", rng)
	if !from.IsZero() {
		v.Set("from", from.UTC().Format(time.RFC3339Nano))
	}
	if !to.IsZero() {
		v.Set("to", to.UTC().Format(time.RFC3339Nano))
	}
	return v
}

func securityToText(to time.Time) string {
	if to.IsZero() {
		return "now"
	}
	return to.UTC().Format(time.RFC3339Nano)
}

func securityWindowText(from, to time.Time) string {
	end := "now"
	if !to.IsZero() {
		end = to.UTC().Format("2006-01-02 15:04:05")
	}
	return "From " + from.UTC().Format("2006-01-02 15:04:05") + " to " + end + " (UTC)"
}

// securityLevelClass is the badge class of an event level (an allowlist: Lvl is source data).
var securityLevelClass = map[string]string{
	siem.LvlDebug: "sec-lvl-debug", siem.LvlInfo: "sec-lvl-info", siem.LvlWarn: "sec-lvl-warn",
	siem.LvlError: "sec-lvl-error", siem.LvlCritical: "sec-lvl-critical",
}

func securityRowOf(e *siem.Event, now time.Time) securityRow {
	row := securityRow{
		When: e.TS.UTC().Format("Jan 02 15:04:05"), ISO: e.TS.UTC().Format(time.RFC3339Nano), Ago: secAgo(now, e.TS),
		Src: e.Src, Lvl: e.Lvl, LvlClass: securityLevelClass[e.Lvl], Kind: e.Kind, Out: e.Out,
		Actor: e.Actor, IP: e.IP,
		Msg: siem.Cut(strings.Join(strings.Fields(e.Msg), " "), securityMsgCut),
	}
	if row.LvlClass == "" {
		row.LvlClass = "sec-lvl-info"
	}
	switch e.Out {
	case siem.OutSuccess:
		row.OutClass = "pill-ok"
	case siem.OutFailure:
		row.OutClass = "pill-down"
	}
	switch {
	case e.App != "" && e.Svc != "":
		row.Where = e.App + "/" + e.Svc
	case e.App != "":
		row.Where = e.App
	default:
		row.Where = e.Svc
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	// Intentional: no JSON HTML-escaping (<): html/template escapes the text, and the owner reads
	// the event's real characters.
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(e); err != nil {
		row.JSON = "This event can't be shown as JSON: " + err.Error()
	} else {
		row.JSON = strings.TrimSuffix(b.String(), "\n")
	}
	return row
}

func securityStatusOf(st siem.Status, now time.Time) *securityStatusView {
	v := &securityStatusView{
		Enabled:   st.Enabled,
		Queue:     groupDigits(st.Queue) + " / " + groupDigits(st.QueueCap),
		QueueHigh: st.QueueCap > 0 && st.Queue*10 >= st.QueueCap*9,
		Disk:      humanBytes(uint64(max(st.DiskBytes, 0))),
		Segments:  groupDigits(st.Segments),
		ArchiveOn: st.ArchiveOn, ArchiveErr: st.ArchiveErr,
		ArchiveBehind: groupDigits(st.ArchiveBehind),
	}
	if !st.Oldest.IsZero() {
		v.Oldest, v.OldestAgo = st.Oldest.UTC().Format("2006-01-02 15:04"), secAgo(now, st.Oldest)
	}
	if !st.LastArchived.IsZero() {
		v.LastArchived = st.LastArchived.UTC().Format("2006-01-02 15:04") + " UTC (" + secAgo(now, st.LastArchived) + ")"
	}
	var down []string
	for _, src := range st.Sources {
		row := securitySourceRow{
			Name: src.Name, OK: src.OK, Err: src.Err,
			Events: groupDigits(int(src.Events)), Dropped: groupDigits(int(src.Dropped)), HasDropped: src.Dropped > 0,
		}
		if !src.LastSeen.IsZero() {
			row.LastSeen, row.Ago = src.LastSeen.UTC().Format("2006-01-02 15:04:05"), secAgo(now, src.LastSeen)
		}
		if !src.OK {
			down = append(down, src.Name)
		}
		v.Sources = append(v.Sources, row)
	}
	var problems []string
	switch {
	case len(down) == 1:
		problems = append(problems, down[0]+" is not collecting")
	case len(down) > 1:
		problems = append(problems, strings.Join(down, ", ")+" are not collecting")
	}
	if st.ArchiveErr != "" {
		problems = append(problems, "the last S3 archive upload failed")
	}
	v.Problem = strings.Join(problems, "; ")
	return v
}

// secAgo is t relative to now: "just now", "42s ago", "5m ago", "3h ago", "3d ago", "in 5m".
func secAgo(now, t time.Time) string {
	if t.IsZero() {
		return ""
	}
	d := now.Sub(t)
	future := d < 0
	if future {
		d = -d
	}
	var s string
	switch {
	case d < 10*time.Second:
		return "just now"
	case d < time.Minute:
		s = strconv.Itoa(int(d/time.Second)) + "s"
	case d < time.Hour:
		s = strconv.Itoa(int(d/time.Minute)) + "m"
	case d < 48*time.Hour:
		s = strconv.Itoa(int(d/time.Hour)) + "h"
	default:
		s = strconv.Itoa(int(d/(24*time.Hour))) + "d"
	}
	if future {
		return "in " + s
	}
	return s + " ago"
}

// exportWriter writes an export to the client: it runs audit once before the first byte (a failed
// audit fails the write, so nothing is sent) and counts the bytes sent.
type exportWriter struct {
	w        io.Writer
	n        int64
	audit    func() error
	audited  bool
	auditErr error
}

func (e *exportWriter) ensureAudit() error {
	if !e.audited {
		e.audited = true
		e.auditErr = e.audit()
	}
	return e.auditErr
}

func (e *exportWriter) Write(p []byte) (int, error) {
	if err := e.ensureAudit(); err != nil {
		return 0, err
	}
	n, err := e.w.Write(p)
	e.n += int64(n)
	return n, err
}
