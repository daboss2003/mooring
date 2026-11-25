package web

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/blocklist"
	"github.com/daboss2003/mooring/internal/siem"
)

// The Responses page (owner only, requirePerm("admin")): automated response's mode and pause, the
// recommendations waiting for the owner and the history, from Server.responses (nil = automated
// response isn't running). accountRevoker is the dashboard's side of a session revoke.

const (
	respPageSize   = 50 // history rows per page
	respPendingMax = 50 // recommendations listed, and an incident's or a detection's responses
)

var (
	respStateLabels = map[string]string{
		siem.ResponseRecommended: "Recommended", siem.ResponseApplied: "Applied", siem.ResponseRefused: "Refused",
		siem.ResponseFailed: "Failed", siem.ResponseDismissed: "Dismissed", siem.ResponseExpired: "Expired",
	}
	// respStateClass is a state's pill class (an allowlist: State is stored data).
	respStateClass = map[string]string{
		siem.ResponseRecommended: "pill-warn", siem.ResponseApplied: "pill-ok",
		siem.ResponseRefused: "pill-down", siem.ResponseFailed: "pill-down",
	}
	respStateFilter = []string{siem.ResponseRecommended, siem.ResponseApplied, siem.ResponseRefused,
		siem.ResponseFailed, siem.ResponseDismissed, siem.ResponseExpired}
	respModeLabels = map[string]string{
		siem.ResponseModeOff: "Off", siem.ResponseModeRecommend: "Recommend", siem.ResponseModeEnforce: "Enforce",
	}
	// respReasonCode is a reason or refusal code as stored: fixed words.
	respReasonCode = regexp.MustCompile(`^[a-z0-9_]{1,40}$`)
)

// refusalWords are the block list's refusal codes in words, as the end of "The block was refused: …".
var refusalWords = map[string]string{
	blocklist.RefuseInvalid:    "it is not an IP address or CIDR range",
	blocklist.RefuseWidth:      "the range is wider than a block allows (manual: /24 for IPv4, /48 for IPv6; automatic: one IPv4 address or an IPv6 /64)",
	blocklist.RefuseNoEdge:     "Mooring doesn't run the edge on this host",
	blocklist.RefuseOldCaddy:   "the running Caddy is older than 2.11 and can't refuse 0-RTT requests",
	blocklist.RefuseAllowlist:  "it overlaps ip_allowlist",
	blocklist.RefuseTokenCIDR:  "it overlaps the allowed addresses of an API token",
	blocklist.RefuseProxy:      "it overlaps a trusted proxy",
	blocklist.RefuseCDN:        "it overlaps a CDN's address ranges",
	blocklist.RefuseLocal:      "it is a loopback, private, link-local, shared, multicast or unspecified address, or this server's own",
	blocklist.RefuseNeverBlock: "it overlaps security_logs.blocking.never_block",
	blocklist.RefuseSession:    "it covers the address of a signed-in dashboard session",
	blocklist.RefuseSelf:       "it covers your own address",
	blocklist.RefuseExempt:     "an owner unblocked it, or its incident was a false positive, recently",
	blocklist.RefuseFull:       "the block list holds as many blocks of this kind as it may",
	blocklist.RefuseDuration:   "the length is outside the allowed range",
	// The responder's own codes (internal/siem/respond).
	"hourly_cap":      "the hourly cap of automatic actions was reached",
	"cooldown":        "automated response signed this account out less than an hour ago",
	"no_revoker":      "dashboard sign-outs are not available",
	"unknown_account": "no Mooring user is stored as that account",
	"interrupted":     "Mooring stopped before it was handled",
	"invalid_target":  "the account name is not valid",
	"refused":         "the block list refused it",
	"error":           "it failed; Mooring's log has the details",
}

// reasonWords is a stored reason or refusal code in words: a known block refusal, else the code
// itself with spaces (codes are fixed words); "" for a value that isn't a code.
func reasonWords(code string) string {
	if w := refusalWords[code]; w != "" {
		return w
	}
	if !respReasonCode.MatchString(code) {
		return ""
	}
	return strings.ReplaceAll(code, "_", " ")
}

// capFirst is s with its first letter in upper case, for a reason shown on its own (the words are
// written to finish a sentence such as "The block was refused: …").
func capFirst(s string) string {
	r, n := utf8.DecodeRuneInString(s)
	if n == 0 || !unicode.IsLower(r) {
		return s
	}
	return string(unicode.ToUpper(r)) + s[n:]
}

// safeCode is code for an audit Detail: the code when it is one, else "other".
func safeCode(code string) string {
	if respReasonCode.MatchString(code) {
		return code
	}
	return "other"
}

// refusedMessage is a refused block in words, with the list's own detail (safe to show).
func refusedMessage(re *blocklist.RefusedError) string {
	msg := "The block was refused"
	if w := reasonWords(re.Code); w != "" {
		msg += ": " + w
	}
	if d := strings.TrimSpace(siem.Cut(re.Detail, 200)); d != "" {
		msg += " (" + d + ")"
	}
	return msg + "."
}

// durText is a duration in words: "90 minutes", "4 hours", "7 days".
func durText(d time.Duration) string {
	plural := func(n int64, unit string) string {
		if n == 1 {
			return "1 " + unit
		}
		return strconv.FormatInt(n, 10) + " " + unit + "s"
	}
	switch {
	case d <= 0:
		return ""
	case d >= 48*time.Hour && d%(24*time.Hour) == 0:
		return plural(int64(d/(24*time.Hour)), "day")
	case d%time.Hour == 0:
		return plural(int64(d/time.Hour), "hour")
	case d%time.Minute == 0:
		return plural(int64(d/time.Minute), "minute")
	}
	return d.String()
}

// respRow is one response as the Responses, incident and detection pages show it.
type respRow struct {
	ID                            int64
	Anchor, URL                   string // the row's anchor, and a link to it on the Responses page
	Action, Target, What          string // What: "Block 203.0.113.7/32 for 1 hour", "Sign out alice"
	Block                         bool
	State, StateLabel, StateClass string
	Reason                        string // refused or failed: why, in words, shown on its own
	Automatic                     bool
	RuleID, RuleURL               string
	DetectionURL                  string
	IncidentURL                   string
	IncidentID                    int64
	Summary                       string
	Created, CreatedISO, Ago      string
	By                            string
	Live                          *blockLive // block: the address's block now (nil when unknown)
	Confirm                       string     // Apply's confirmation question
}

func respRowOf(rs *siem.Response, now time.Time) respRow {
	id := strconv.FormatInt(rs.ID, 10)
	row := respRow{
		ID: rs.ID, Anchor: "resp-" + id,
		URL:    withQuery("/security/responses", url.Values{"before": {strconv.FormatInt(rs.ID+1, 10)}}) + "#resp-" + id,
		Action: rs.Action, Target: rs.Target, Block: rs.Action == siem.ResponseBlock,
		State: rs.State, StateLabel: respStateLabels[rs.State], StateClass: respStateClass[rs.State],
		Automatic: rs.Automatic, RuleID: rs.RuleID, Summary: rs.Summary, By: rs.By, IncidentID: rs.IncidentID,
	}
	if row.StateLabel == "" {
		row.StateLabel = rs.State
	}
	if rs.State == siem.ResponseRefused || rs.State == siem.ResponseFailed {
		if row.Reason = capFirst(reasonWords(rs.Reason)); row.Reason == "" {
			// A value that is no code is shown as stored (the page escapes it).
			row.Reason = strings.TrimSpace(siem.Cut(rs.Reason, 80))
		}
	}
	switch rs.Action {
	case siem.ResponseBlock:
		row.What = "Block " + rs.Target
		if d := durText(rs.Duration); d != "" {
			row.What += " for " + d
		}
		row.Confirm = row.What + "?"
	case siem.ResponseRevoke:
		row.What = "Sign out " + rs.Target
		row.Confirm = "Sign " + rs.Target + " out of every dashboard session?"
	default:
		row.What = strings.TrimSpace(rs.Action + " " + rs.Target)
		row.Confirm = "Apply this response?"
	}
	if rs.RuleID != "" {
		row.RuleURL = withQuery("/security/detections", url.Values{"rule": {rs.RuleID}})
	}
	if rs.DetectionID > 0 {
		row.DetectionURL = "/security/detections/" + strconv.FormatInt(rs.DetectionID, 10)
	}
	if rs.IncidentID > 0 {
		row.IncidentURL = "/security/incidents/" + strconv.FormatInt(rs.IncidentID, 10)
	}
	if !rs.Created.IsZero() {
		row.Created, row.CreatedISO, row.Ago = rs.Created.UTC().Format(detectTimeFmt), rs.Created.UTC().Format(time.RFC3339), secAgo(now, rs.Created)
	}
	return row
}

// blockLive is an address's block as the edge has it now.
type blockLive struct {
	Label, Class string
	Text         string // until when, why it is suspended, who removed it
	CoveredBy    string // the address has no block of its own: the block in force that covers it
}

var blockStateLabels = map[string]string{
	blocklist.StateActive: "Blocked", blocklist.StateSuspended: "Suspended",
	blocklist.StateExpired: "Expired", blocklist.StateRemoved: "Removed",
}

func blockLiveOf(b blocklist.Block, found bool, now time.Time) *blockLive {
	if !found {
		return &blockLive{Label: "Not blocked"}
	}
	v := &blockLive{Label: blockStateLabels[b.State]}
	if v.Label == "" {
		v.Label = b.State
	}
	switch b.State {
	case blocklist.StateActive:
		v.Class = "pill-warn"
		if !b.Until.IsZero() {
			v.Text = "until " + b.Until.UTC().Format("2006-01-02 15:04") + " UTC (" + secAgo(now, b.Until) + ")"
		}
	case blocklist.StateSuspended:
		v.Text = "not applied: " + reasonWords(b.SuspendedWhy)
	case blocklist.StateRemoved:
		if b.RemovedBy != "" {
			v.Text = "by " + b.RemovedBy
		}
	}
	return v
}

// inForce reports whether b is a block in force (active, or suspended while a protected address
// covers it).
func inForce(b blocklist.Block, found bool) bool {
	return found && (b.State == blocklist.StateActive || b.State == blocklist.StateSuspended)
}

// blockLookup answers what the edge does with a prefix now, for one page: the prefix's own block
// (Get is an exact lookup), else an active block that overlaps it — a wider range covering the
// address, or a narrower block inside an IPv6 /64. The overlap is asked of the block list
// (blockCoverer); a list without it has its active blocks read once, when first needed.
type blockLookup struct {
	s      *Server
	now    time.Time
	seen   map[netip.Prefix]*blockLive
	active []blocklist.Block
	listed bool
}

func (s *Server) newBlockLookup() *blockLookup {
	return &blockLookup{s: s, now: time.Now().UTC(), seen: map[netip.Prefix]*blockLive{}}
}

// blockCoverer is the block list's in-memory lookup of the active block overlapping a prefix
// (*blocklist.Blocker has it). It is not part of blocklist.Service.
type blockCoverer interface {
	Covering(p netip.Prefix) (blocklist.Block, bool)
}

// covering is the active block other than p's own that overlaps p: the widest one that contains
// it, else the widest one inside it.
func (l *blockLookup) covering(ctx context.Context, p netip.Prefix) (blocklist.Block, bool, error) {
	// One address the edge doesn't refuse has no covering block. A range is looked up in the list:
	// one of its addresses says nothing about the others.
	if p.IsSingleIP() && !l.s.blocks.Blocked(p.Addr()) {
		return blocklist.Block{}, false, nil
	}
	if c, ok := l.s.blocks.(blockCoverer); ok {
		b, found := c.Covering(p)
		return b, found && b.State == blocklist.StateActive && b.Prefix.IsValid() && b.Prefix != p && b.Prefix.Overlaps(p), nil
	}
	// Intentional: a block list without Covering is scanned through List, which returns the newest
	// blockListMax blocks only. Mooring's own list has Covering; this path serves other
	// implementations of blocklist.Service.
	if !l.listed {
		list, err := l.s.blocks.List(ctx, blocklist.Filter{States: []string{blocklist.StateActive}, Limit: blockListMax})
		if err != nil {
			return blocklist.Block{}, false, err
		}
		l.active, l.listed = list, true
	}
	var best blocklist.Block
	found := false
	for _, b := range l.active {
		if b.State != blocklist.StateActive || !b.Prefix.IsValid() || b.Prefix == p || !b.Prefix.Overlaps(p) {
			continue
		}
		// The widest overlapping block: one that contains p is wider than any inside it.
		if !found || b.Prefix.Bits() < best.Prefix.Bits() {
			best, found = b, true
		}
	}
	return best, found, nil
}

// state is p's own block (found: one is recorded) and, when none is in force, the active block
// covering it (covered).
func (l *blockLookup) state(ctx context.Context, p netip.Prefix) (own blocklist.Block, found bool, cover blocklist.Block, covered bool, err error) {
	own, found, err = l.s.blocks.Get(ctx, p)
	if err != nil || inForce(own, found) {
		return own, found, cover, false, err
	}
	cover, covered, err = l.covering(ctx, p)
	return own, found, cover, covered, err
}

// partlyCovered reports whether cover is narrower than p: it blocks some of p's addresses (one
// address inside an IPv6 /64), not all of them.
func partlyCovered(p netip.Prefix, cover blocklist.Block) bool {
	return cover.Prefix.Bits() > p.Bits()
}

// coveredLive is the live state of a prefix p another block (cover) covers. A cover narrower than
// p blocks part of it: the cover's own time is left out, it is not p's.
func coveredLive(p netip.Prefix, cover blocklist.Block, now time.Time) *blockLive {
	if partlyCovered(p, cover) {
		return &blockLive{Label: "Partly blocked", Class: "pill-warn", CoveredBy: cover.Prefix.String()}
	}
	v := blockLiveOf(cover, true, now)
	v.CoveredBy = cover.Prefix.String()
	return v
}

// live is p's live state for a response row (nil when it can't be read).
func (l *blockLookup) live(ctx context.Context, p netip.Prefix) (*blockLive, error) {
	if v, ok := l.seen[p]; ok {
		return v, nil
	}
	own, found, cover, covered, err := l.state(ctx, p)
	if err != nil {
		return nil, err
	}
	v := blockLiveOf(own, found, l.now)
	if covered {
		v = coveredLive(p, cover, l.now)
	}
	l.seen[p] = v
	return v, nil
}

// blockLives fills the live block state of the rows' block responses, one lookup per address
// (look carries the ones already looked up across a page's tables; nil for a single table).
func (s *Server) blockLives(ctx context.Context, look *blockLookup, rows []respRow) {
	if s.blocks == nil {
		return
	}
	if look == nil {
		look = s.newBlockLookup()
	}
	for i := range rows {
		if !rows[i].Block {
			continue
		}
		p, err := netip.ParsePrefix(rows[i].Target)
		if err != nil {
			continue
		}
		live, err := look.live(ctx, p.Masked())
		if err != nil {
			s.log.Warn("security responses: block state failed", "err", err)
			return
		}
		rows[i].Live = live
	}
}

// respStatusView is the responder's state for the page header.
type respStatusView struct {
	Mode, ModeLabel           string
	ConfigOff                 bool // the configured mode is off
	Paused, PausedLabel       string
	PausedBy, PausedAt        string
	Effective, EffectiveLabel string
	Blocks, MaxBlocks         string
	Revokes, MaxRevokes       string
	BlocksFull, RevokesFull   bool
	Revoker                   bool
	Pauses                    []pauseOpt
}

// pauseOpt is one pause button.
type pauseOpt struct {
	Level, Label, Confirm string
	Primary               bool
}

func modeLabel(m string) string {
	if l := respModeLabels[m]; l != "" {
		return l
	}
	return m
}

func respStatusOf(st siem.ResponseStatus, now time.Time) *respStatusView {
	v := &respStatusView{
		Mode: st.Mode, ModeLabel: modeLabel(st.Mode), ConfigOff: st.Mode == siem.ResponseModeOff || st.Mode == "",
		Paused: st.Paused, PausedLabel: modeLabel(st.Paused), PausedBy: st.PausedBy,
		Effective: st.Effective, EffectiveLabel: modeLabel(st.Effective),
		Blocks: groupDigits(st.BlocksThisHour), MaxBlocks: groupDigits(st.MaxBlocksPerHour),
		Revokes: groupDigits(st.RevokesThisHour), MaxRevokes: groupDigits(st.MaxRevokesPerHour),
		BlocksFull:  st.MaxBlocksPerHour > 0 && st.BlocksThisHour >= st.MaxBlocksPerHour,
		RevokesFull: st.MaxRevokesPerHour > 0 && st.RevokesThisHour >= st.MaxRevokesPerHour,
		Revoker:     st.Revoker,
	}
	if v.Effective == "" {
		v.Effective, v.EffectiveLabel = siem.ResponseModeOff, modeLabel(siem.ResponseModeOff)
	}
	if !st.PausedAt.IsZero() {
		v.PausedAt = st.PausedAt.UTC().Format("2006-01-02 15:04") + " UTC (" + secAgo(now, st.PausedAt) + ")"
	}
	offConfirm := "Pause all responses? Every automatic block is removed now."
	switch {
	case st.Paused != "":
		v.Pauses = append(v.Pauses, pauseOpt{Level: "", Label: "Lift the pause", Primary: true})
		if st.Paused == siem.ResponseModeRecommend {
			v.Pauses = append(v.Pauses, pauseOpt{Level: siem.ResponseModeOff, Label: "Pause all responses", Confirm: offConfirm})
		}
	case st.Mode == siem.ResponseModeEnforce:
		v.Pauses = append(v.Pauses,
			pauseOpt{Level: siem.ResponseModeRecommend, Label: "Pause to recommend only"},
			pauseOpt{Level: siem.ResponseModeOff, Label: "Pause all responses", Confirm: offConfirm})
	case st.Mode == siem.ResponseModeRecommend:
		v.Pauses = append(v.Pauses, pauseOpt{Level: siem.ResponseModeOff, Label: "Pause all responses", Confirm: offConfirm})
	}
	return v
}

// respForm is the history's filter as submitted.
type respForm struct{ State, Action string }

// parseRespFilter reads the history's filter; an unknown state, action or cursor is ignored.
func parseRespFilter(p url.Values) (siem.ResponseFilter, respForm) {
	var form respForm
	f := siem.ResponseFilter{Limit: respPageSize + 1} // one more than shown: is there an older page?
	if st := p.Get("state"); respStateLabels[st] != "" {
		form.State, f.States = st, []string{st}
	}
	if a := p.Get("action"); a == siem.ResponseBlock || a == siem.ResponseRevoke {
		form.Action, f.Action = a, a
	}
	if b, err := strconv.ParseInt(p.Get("before"), 10, 64); err == nil && b > 0 {
		f.Before = b
	}
	return f, form
}

func (f respForm) params(before int64) url.Values {
	v := url.Values{}
	if f.State != "" {
		v.Set("state", f.State)
	}
	if f.Action != "" {
		v.Set("action", f.Action)
	}
	if before > 0 {
		v.Set("before", strconv.FormatInt(before, 10))
	}
	return v
}

// respView backs security_responses.html.
type respView struct {
	Status              *respStatusView
	StatusErr           string
	Pending             []respRow
	PendingMore         bool
	PendingErr          string
	PendingURL          string // every recommendation, in the history
	Form                respForm
	States, Actions     []sevOption
	Rows                []respRow
	HistErr             string
	Filtered            bool
	OlderURL, NewestURL string
	Notice, Err         string
}

// respDoneText are the fixed notices of the Responses page's ?done=.
var respDoneText = map[string]string{
	"applied":            "Response applied.",
	"dismissed":          "Recommendation dismissed.",
	"unpaused":           "Pause lifted: responses follow security_logs.response.mode again.",
	"paused_recommend":   "Paused: responses are recorded as recommendations only.",
	"paused_off":         "Paused: no responses are made, and every automatic block was removed.",
	"paused_off_pending": "Responses are paused. The automatic blocks couldn't be removed yet; Mooring keeps trying.",
}

const respTmpl = "security_responses.html"

// handleSecResponses renders the Responses page (GET /security/responses).
func (s *Server) handleSecResponses(w http.ResponseWriter, r *http.Request) {
	s.showResponses(w, r, http.StatusOK, respDoneText[r.URL.Query().Get("done")], "")
}

// respOff sets the page's off state when the responder isn't running. It reports whether it did.
func (s *Server) respOff(p *secPage) bool {
	switch {
	case s.responses != nil:
		return false
	case s.detections == nil:
		p.Off = true
	default:
		p.RespOff = true
	}
	return true
}

// showResponses renders the Responses page (its filters from the URL) with a notice, or with a
// refused change's message and status.
func (s *Server) showResponses(w http.ResponseWriter, r *http.Request, status int, notice, errMsg string) {
	p := &secPage{}
	if s.respOff(p) {
		if status == http.StatusOK && r.Method != http.MethodGet {
			status = http.StatusServiceUnavailable
		}
		s.renderSec(w, r, status, respTmpl, "Responses", p)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), detectTimeout)
	defer cancel()
	now := time.Now().UTC()
	f, form := parseRespFilter(r.URL.Query())
	v := &respView{Form: form, Notice: notice, Err: errMsg,
		Filtered:   form.State != "" || form.Action != "",
		PendingURL: withQuery("/security/responses", url.Values{"state": {siem.ResponseRecommended}})}
	v.States = []sevOption{{Value: "", Label: "Any state", Selected: form.State == ""}}
	for _, st := range respStateFilter {
		v.States = append(v.States, sevOption{Value: st, Label: respStateLabels[st], Selected: st == form.State})
	}
	v.Actions = []sevOption{{Value: "", Label: "Any action", Selected: form.Action == ""},
		{Value: siem.ResponseBlock, Label: "Block", Selected: form.Action == siem.ResponseBlock},
		{Value: siem.ResponseRevoke, Label: "Sign out", Selected: form.Action == siem.ResponseRevoke}}
	failed := false
	if st, err := s.responses.Status(ctx); err != nil {
		s.log.Warn("security responses: status failed", "err", err)
		v.StatusErr, failed = "The response state could not be read. Mooring's log has the details.", true
	} else {
		v.Status = respStatusOf(st, now)
	}
	pending, err := s.responses.Responses(ctx, siem.ResponseFilter{States: []string{siem.ResponseRecommended}, Limit: respPendingMax + 1})
	if err != nil {
		s.log.Warn("security responses: recommendations failed", "err", err)
		v.PendingErr, failed = "The recommendations could not be read. Mooring's log has the details.", true
	}
	if len(pending) > respPendingMax {
		pending, v.PendingMore = pending[:respPendingMax], true
	}
	for i := range pending {
		v.Pending = append(v.Pending, respRowOf(&pending[i], now))
	}
	hist, err := s.responses.Responses(ctx, f)
	if err != nil {
		s.log.Warn("security responses: history failed", "err", err)
		v.HistErr, failed = "The responses could not be read. Mooring's log has the details.", true
	}
	more := len(hist) > respPageSize
	if more {
		hist = hist[:respPageSize]
	}
	for i := range hist {
		v.Rows = append(v.Rows, respRowOf(&hist[i], now))
	}
	if more && len(hist) > 0 {
		v.OlderURL = withQuery("/security/responses", form.params(hist[len(hist)-1].ID))
	}
	if f.Before > 0 {
		v.NewestURL = withQuery("/security/responses", form.params(0))
	}
	look := s.newBlockLookup()
	s.blockLives(ctx, look, v.Pending)
	s.blockLives(ctx, look, v.Rows)
	if failed && status == http.StatusOK {
		status = http.StatusInternalServerError
	}
	s.renderSec(w, r, status, respTmpl, "Responses", &secPage{Resp: v})
}

// responseError is how the page shows a change the responder refused. A block the list refused is
// told in words; so is a refusal or failure this attempt recorded on the response (wasPending: it
// was a recommendation before), by its reason code; a validation error's text is the owner's
// (siem.ErrInvalidInput). Anything else is internal and stays in Mooring's log. what is the
// sentence's start ("The response was not applied").
func (s *Server) responseError(ctx context.Context, id int64, err error, what string, wasPending bool) (status int, msg, result string) {
	var re *blocklist.RefusedError
	if errors.As(err, &re) {
		s.log.Info("security responses: block refused", "id", id, "code", re.Code)
		return http.StatusUnprocessableEntity, refusedMessage(re), "refused code=" + safeCode(re.Code)
	}
	if wasPending {
		// The responder records why on the response and returns its own text; the recorded code says
		// it in the page's words.
		if rs, ok, rerr := s.responses.Response(ctx, id); rerr == nil && ok && (rs.State == siem.ResponseRefused || rs.State == siem.ResponseFailed) {
			s.log.Info("security responses: not applied", "id", id, "state", rs.State, "reason", rs.Reason, "err", err)
			msg := what
			if w := reasonWords(rs.Reason); w != "" {
				msg += ": " + w
			}
			word := "refused"
			if rs.State == siem.ResponseFailed {
				word = "failed"
			}
			return http.StatusUnprocessableEntity, msg + ".", word + " code=" + safeCode(rs.Reason)
		}
	}
	if errors.Is(err, siem.ErrInvalidInput) {
		return s.serviceError(err, what, "security responses: change", "id", id)
	}
	s.log.Warn("security responses: change failed", "id", id, "err", err)
	return http.StatusInternalServerError, what + ". Mooring's log has the details.", "error"
}

// handleSecResponseApply applies a recommendation now (POST /security/responses/{id}/apply).
func (s *Server) handleSecResponseApply(w http.ResponseWriter, r *http.Request) {
	s.respChange(w, r, "security_response_apply", "applied", "The response was not applied", func(ctx context.Context, id int64, actor string) error {
		return s.responses.Apply(ctx, id, actor)
	})
}

// handleSecResponseDismiss dismisses a recommendation (POST /security/responses/{id}/dismiss).
func (s *Server) handleSecResponseDismiss(w http.ResponseWriter, r *http.Request) {
	s.respChange(w, r, "security_response_dismiss", "dismissed", "The recommendation was not dismissed", func(ctx context.Context, id int64, actor string) error {
		return s.responses.Dismiss(ctx, id, actor)
	})
}

// respChange runs one Apply or Dismiss of the response in the path, audits it and redirects back.
// The audit Detail names the action, never the target.
func (s *Server) respChange(w http.ResponseWriter, r *http.Request, action, done, what string, change func(context.Context, int64, string) error) {
	if s.responses == nil {
		s.showResponses(w, r, http.StatusServiceUnavailable, "", "")
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	id, ok := incidentID(r)
	if !ok {
		s.detectAudit(r, action, "response", audit.Error, "result=not found")
		s.showResponses(w, r, http.StatusNotFound, "", "Response not found.")
		return
	}
	target := "response:" + strconv.FormatInt(id, 10)
	// A long write (an edge block, a sign-out) finishes even if the browser goes away.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), detectTimeout)
	defer cancel()
	detail := ""
	rs, found, err := s.responses.Response(ctx, id)
	if err == nil && !found {
		s.detectAudit(r, action, target, audit.Error, "result=not found")
		s.showResponses(w, r, http.StatusNotFound, "", "Response not found.")
		return
	}
	if err == nil && (rs.Action == siem.ResponseBlock || rs.Action == siem.ResponseRevoke) {
		detail = "action=" + rs.Action
	}
	// A read failure counts as pending: the refusal check after the change reads again.
	wasPending := err != nil || rs.State == siem.ResponseRecommended
	if err := change(ctx, id, sessionUser(r)); err != nil {
		status, msg, result := s.responseError(ctx, id, err, what, wasPending)
		s.detectAudit(r, action, target, audit.Error, strings.TrimSpace(detail+" result="+result))
		s.showResponses(w, r, status, "", msg)
		return
	}
	s.detectAudit(r, action, target, audit.OK, detail)
	http.Redirect(w, r, withQuery("/security/responses", url.Values{"done": {done}}), http.StatusSeeOther)
}

// pauseLevels are the pause levels the form sets, with their audit words and notices.
var pauseLevels = map[string][2]string{
	"":                         {"none", "unpaused"},
	siem.ResponseModeRecommend: {"recommend", "paused_recommend"},
	siem.ResponseModeOff:       {"off", "paused_off"},
}

// handleSecResponsePause lowers what responses do, or lifts the pause (POST /security/responses/pause).
func (s *Server) handleSecResponsePause(w http.ResponseWriter, r *http.Request) {
	const action = "security_response_pause"
	if s.responses == nil {
		s.showResponses(w, r, http.StatusServiceUnavailable, "", "")
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	level := r.PostFormValue("level")
	lv, ok := pauseLevels[level]
	// A missing field is refused rather than read as "lift the pause".
	if !ok || !r.PostForm.Has("level") {
		s.detectAudit(r, action, "responses", audit.Error, "result=rejected")
		s.showResponses(w, r, http.StatusUnprocessableEntity, "", "Pick a pause: recommend only, all responses, or lift the pause.")
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), detectTimeout)
	defer cancel()
	err := s.responses.SetPause(ctx, level, sessionUser(r))
	if errors.Is(err, siem.ErrBlocksNotLifted) {
		// The pause is stored and in force; only the removal of the automatic blocks is still to
		// come (the responder retries it).
		s.log.Warn("security responses: paused, the automatic blocks are not removed yet", "err", err)
		s.detectAudit(r, action, "responses", audit.OK, "level="+lv[0]+" result=ok lift=error")
		http.Redirect(w, r, withQuery("/security/responses", url.Values{"done": {"paused_off_pending"}}), http.StatusSeeOther)
		return
	}
	if err != nil {
		status, msg, result := s.serviceError(err, "The pause was not changed", "security responses: pause")
		s.detectAudit(r, action, "responses", audit.Error, "level="+lv[0]+" result="+result)
		s.showResponses(w, r, status, "", msg)
		return
	}
	s.detectAudit(r, action, "responses", audit.OK, "level="+lv[0])
	http.Redirect(w, r, withQuery("/security/responses", url.Values{"done": {lv[1]}}), http.StatusSeeOther)
}

// incidentResponses are the responses about incident id, newest first ("" error message, or what
// to show when they can't be read). nil, "" when automated response isn't running.
func (s *Server) incidentResponses(ctx context.Context, id int64) ([]respRow, string) {
	if s.responses == nil {
		return nil, ""
	}
	list, err := s.responses.Responses(ctx, siem.ResponseFilter{IncidentID: id, Limit: respPendingMax})
	if err != nil {
		s.log.Warn("security incidents: responses failed", "id", id, "err", err)
		return nil, "The responses could not be read. Mooring's log has the details."
	}
	now := time.Now().UTC()
	rows := make([]respRow, 0, len(list))
	for i := range list {
		rows = append(rows, respRowOf(&list[i], now))
	}
	s.blockLives(ctx, nil, rows)
	return rows, ""
}

// detectionResponses are the responses about detection id, newest first.
func (s *Server) detectionResponses(ctx context.Context, id int64) ([]respRow, string) {
	if s.responses == nil {
		return nil, ""
	}
	list, err := s.responses.Responses(ctx, siem.ResponseFilter{DetectionID: id, Limit: respPendingMax})
	if err != nil {
		s.log.Warn("security detections: responses failed", "id", id, "err", err)
		return nil, "The responses could not be read. Mooring's log has the details."
	}
	now := time.Now().UTC()
	var rows []respRow
	for i := range list {
		// The rows are checked too: a service that doesn't filter by detection must not put another
		// detection's responses here.
		if list[i].DetectionID == id {
			rows = append(rows, respRowOf(&list[i], now))
		}
	}
	s.blockLives(ctx, nil, rows)
	return rows, ""
}

// accountRevoker is the dashboard's siem.AccountRevoker.
type accountRevoker struct{ s *Server }

// AccountRevoker signs Mooring accounts out of every session for automated response (the
// responder's SetRevoker).
func (s *Server) AccountRevoker() siem.AccountRevoker { return accountRevoker{s} }

// Revoke ends every session of the Mooring users stored as actor among the live users (the auth
// owner and users:, a reload included); the responder audits it. Several users can be stored as
// one actor (see mooringUsers): all are signed out, and the returned name lists them.
func (a accountRevoker) Revoke(ctx context.Context, actor string) (string, int64, error) {
	users := a.s.mooringUsers(actor)
	if len(users) == 0 {
		return "", 0, siem.ErrUnknownAccount
	}
	var total int64
	var errs []error
	for _, user := range users {
		// A failure for one user doesn't keep the others signed in.
		n, err := a.s.sessions.DeleteAllForUser(ctx, user)
		total += n
		if err != nil {
			errs = append(errs, err)
		}
	}
	return strings.Join(users, ", "), total, errors.Join(errs...)
}

// mooringUsers are the live usernames stored as actor, sorted: the username itself, and every
// username whose stored form is actor. Redaction stores a username that is personal data (an
// email) as a keyed hash of its lower-cased form, so usernames differing only in case share one
// actor and can't be told apart from an event.
func (s *Server) mooringUsers(actor string) []string {
	sec := s.security()
	if actor == "" || sec == nil {
		return nil
	}
	sl := s.securityLogs
	var names []string
	for n := range sec.users {
		if n == actor || (sl != nil && sl.SearchValue("actor", n) == actor) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names
}
