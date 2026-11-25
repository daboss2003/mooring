package web

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/blocklist"
	"github.com/daboss2003/mooring/internal/siem"
)

// The Blocks page (owner only, requirePerm("admin")): the managed edge's block list, from
// Server.blocks (nil = Mooring doesn't run the edge). It works with security logs off. The Guard*
// and SessionPeers methods are the dashboard's side of the list's never-block guard.

const (
	blockListMax     = 1000 // blocks listed (the list's own limit)
	blockRefusalsMax = 50   // recent refusals listed
	blockReasonMax   = 300  // bytes of a manual block's reason
	blockPrefixMax   = 64   // bytes of a typed address or range
)

// GuardAllowlist is the live ip_allowlist (a SIGHUP reload included), for the block list's guard.
func (s *Server) GuardAllowlist() []netip.Prefix {
	if sec := s.security(); sec != nil {
		return slices.Clone(sec.allowlist)
	}
	return nil
}

// GuardTokenCIDRs is the union of the active API tokens' allowed CIDRs as the IP gate has it
// (computed at start and on a reload), for the block list's guard.
func (s *Server) GuardTokenCIDRs() []netip.Prefix {
	if sec := s.security(); sec != nil {
		return slices.Clone(sec.tokenCIDRUnion)
	}
	return nil
}

// SessionPeers are the addresses the signed-in dashboard sessions signed in from, for the block
// list's guard; nil when they can't be read.
func (s *Server) SessionPeers(ctx context.Context) []netip.Addr {
	peers, err := s.sessions.ActivePeers(ctx)
	if err != nil {
		// Intentional: no addresses rather than a refusal of every block: a dashboard sign-in comes
		// from inside ip_allowlist (or loopback), which the guard protects on its own.
		s.log.Warn("block list: dashboard session addresses could not be read", "err", err)
		return nil
	}
	return peers
}

// parseBlockPrefix reads a typed address or CIDR range as the block list keeps it: a bare address
// as a /32 or /128, IPv4-mapped IPv6 as IPv4, host bits cleared. No zones.
func parseBlockPrefix(s string) (netip.Prefix, bool) {
	if s == "" || len(s) > blockPrefixMax {
		return netip.Prefix{}, false
	}
	if a, err := netip.ParseAddr(s); err == nil {
		if a.Zone() != "" {
			return netip.Prefix{}, false
		}
		a = a.Unmap()
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return netip.Prefix{}, false
	}
	if a := p.Addr(); a.Is4In6() {
		if p.Bits() < 96 {
			return netip.Prefix{}, false
		}
		p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
	}
	return p.Masked(), true
}

// entityBlockPrefix is the block list's prefix for an address entity's key: an IPv4 address, an
// IPv6 address as its /64, or the prefix the key already is.
func entityBlockPrefix(key string) (netip.Prefix, bool) {
	if a, err := netip.ParseAddr(key); err == nil && a.Zone() == "" {
		if a = a.Unmap(); a.Is6() {
			return netip.PrefixFrom(a, 64).Masked(), true
		}
		return netip.PrefixFrom(a, 32), true
	}
	if p, err := netip.ParsePrefix(key); err == nil {
		return parseBlockPrefix(p.String())
	}
	return netip.Prefix{}, false
}

// blockDuration is one manual block length the form offers.
type blockDuration struct {
	Value, Label string
	d            time.Duration
}

var blockDurations = []blockDuration{
	{"1h", "1 hour", time.Hour}, {"24h", "24 hours", 24 * time.Hour},
	{"7d", "7 days", 7 * 24 * time.Hour}, {"30d", "30 days", 30 * 24 * time.Hour},
}

// manualDurations are the lengths a manual block may have: the offered ones up to the configured
// longest, and the longest itself.
func (s *Server) manualDurations() []blockDuration {
	longest := s.cfg.SecurityLogs.Blocking.ManualMaxDurationOrDefault()
	var out []blockDuration
	for _, d := range blockDurations {
		if d.d <= longest {
			out = append(out, d)
		}
	}
	if !slices.ContainsFunc(out, func(d blockDuration) bool { return d.d == longest }) {
		out = append(out, blockDuration{Value: fmtRuleDuration(longest), Label: durText(longest) + " (the longest)", d: longest})
	}
	return out
}

func durationOptions(ds []blockDuration, cur string) []sevOption {
	opts := make([]sevOption, 0, len(ds))
	for _, d := range ds {
		opts = append(opts, sevOption{Value: d.Value, Label: d.Label, Selected: d.Value == cur})
	}
	return opts
}

// entityBlockDuration is the length of an address page's Block button: 24 hours, or the longest
// manual block when that is shorter.
func (s *Server) entityBlockDuration() blockDuration {
	ds := s.manualDurations()
	for _, d := range ds {
		if d.Value == "24h" {
			return d
		}
	}
	return ds[len(ds)-1]
}

// blocksStatusView is the list's state for the page header.
type blocksStatusView struct {
	Automatic                   bool
	AutomaticWhy                string
	L4                          bool
	L4Why                       string // why L4 listeners aren't filtered although blocking.l4 is on ("" otherwise)
	ActiveAuto, MaxAuto         string
	ActiveManual, MaxManual     string
	AutoFull, ManualFull        bool
	Applied                     bool
	ApplyErr                    string
	LastApplied, LastAppliedAgo string
}

func blocksStatusOf(st blocklist.Status, now time.Time) blocksStatusView {
	v := blocksStatusView{
		Automatic: st.Automatic, L4: st.L4, L4Why: st.L4Why, Applied: st.Applied, ApplyErr: st.ApplyErr,
		ActiveAuto: groupDigits(st.ActiveAuto), MaxAuto: groupDigits(st.MaxAuto),
		ActiveManual: groupDigits(st.ActiveManual), MaxManual: groupDigits(st.MaxManual),
		AutoFull:   st.MaxAuto > 0 && st.ActiveAuto >= st.MaxAuto,
		ManualFull: st.MaxManual > 0 && st.ActiveManual >= st.MaxManual,
	}
	if !st.Automatic {
		v.AutomaticWhy = st.AutomaticWhy
		if w := refusalWords[st.AutomaticWhy]; w != "" {
			v.AutomaticWhy = w
		}
	}
	if !st.LastApplied.IsZero() {
		v.LastApplied, v.LastAppliedAgo = st.LastApplied.UTC().Format("2006-01-02 15:04:05"), secAgo(now, st.LastApplied)
	}
	return v
}

// blockRow is one block in force.
type blockRow struct {
	Prefix                        string
	Auto                          bool
	RuleID, RuleURL               string
	Reason, By                    string
	State, StateLabel, StateClass string
	SuspendedWhy                  string
	Until, UntilISO, UntilIn      string
	Created                       string
	Hits                          string
	IncidentURL                   string
	IncidentID                    int64
	DetectionURL                  string
}

func blockRowOf(b *blocklist.Block, now time.Time) blockRow {
	row := blockRow{
		Prefix: b.Prefix.String(), Auto: b.Source == blocklist.SourceAuto, RuleID: b.RuleID, Reason: b.Reason, By: b.By,
		State: b.State, StateLabel: blockStateLabels[b.State], Hits: groupDigits(b.Hits), IncidentID: b.IncidentID,
	}
	switch b.State {
	case blocklist.StateActive:
		row.StateClass = "pill-warn"
	case blocklist.StateSuspended:
		row.SuspendedWhy = reasonWords(b.SuspendedWhy)
	}
	if row.StateLabel == "" {
		row.StateLabel = b.State
	}
	if b.RuleID != "" {
		row.RuleURL = withQuery("/security/detections", url.Values{"rule": {b.RuleID}})
	}
	if b.IncidentID > 0 {
		row.IncidentURL = "/security/incidents/" + strconv.FormatInt(b.IncidentID, 10)
	}
	if b.DetectionID > 0 {
		row.DetectionURL = "/security/detections/" + strconv.FormatInt(b.DetectionID, 10)
	}
	if !b.Until.IsZero() {
		row.Until, row.UntilISO, row.UntilIn = b.Until.UTC().Format("2006-01-02 15:04"), b.Until.UTC().Format(time.RFC3339), secAgo(now, b.Until)
	}
	if !b.Created.IsZero() {
		row.Created = b.Created.UTC().Format("2006-01-02 15:04")
	}
	return row
}

// refusalRow is one coalesced refusal.
type refusalRow struct {
	Prefix, Code, Words string
	Auto                bool
	RuleID              string
	Detail              string
	Count               string
	Last, LastISO, Ago  string
}

// l4Row is a listener Mooring's block list doesn't filter.
type l4Row struct {
	App, Listen, Service, Why string
}

// blockForm is the manual block form as typed.
type blockForm struct{ Prefix, Duration, Reason string }

// blocksView backs security_blocks.html.
type blocksView struct {
	Status        blocksStatusView
	Source        string // the list's source filter: "", "auto", "manual"
	Sources       []sevOption
	Rows          []blockRow
	RowsErr       string
	Capped        bool // the list shows its first blockListMax
	Refusals      []refusalRow
	RefusalsErr   string
	NotFiltered   []l4Row
	L4Err         string
	Form          blockForm
	Durations     []sevOption
	MaxReason     int
	ResponsesOn   bool
	Notice, Err   string
	ManualLongest string
}

// blocksDoneText are the fixed notices of the Blocks page's ?done=.
var blocksDoneText = map[string]string{
	"added":   "Block placed. The edge takes the change within about a minute.",
	"removed": "Block removed. Automatic blocks of it are paused for 24 hours.",
}

const blocksTmpl = "security_blocks.html"

// blocksOff sets the page's state when the block list isn't available. It reports whether it did.
func (s *Server) blocksOff(p *secPage) bool {
	if s.blocks != nil {
		return false
	}
	p.NoBlocks, p.NoEdgeWhy = true, s.edgeReason
	return true
}

// handleSecBlocks renders the Blocks page (GET /security/blocks).
func (s *Server) handleSecBlocks(w http.ResponseWriter, r *http.Request) {
	s.showBlocks(w, r, http.StatusOK, blocksDoneText[r.URL.Query().Get("done")], "", nil)
}

// showBlocks renders the Blocks page with a notice, or with a refused change's message and status
// (form puts back what was typed).
func (s *Server) showBlocks(w http.ResponseWriter, r *http.Request, status int, notice, errMsg string, form *blockForm) {
	p := &secPage{}
	if s.blocksOff(p) {
		if status == http.StatusOK && r.Method != http.MethodGet {
			status = http.StatusServiceUnavailable
		}
		s.renderSec(w, r, status, blocksTmpl, "Blocked addresses", p)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), detectTimeout)
	defer cancel()
	now := time.Now().UTC()
	v := &blocksView{
		Status: blocksStatusOf(s.blocks.Status(), now), MaxReason: blockReasonMax, ResponsesOn: s.responses != nil,
		Notice: notice, Err: errMsg, Form: blockForm{Duration: "24h"},
	}
	ds := s.manualDurations()
	v.ManualLongest = durText(ds[len(ds)-1].d)
	if form != nil {
		v.Form = *form
	}
	v.Durations = durationOptions(ds, v.Form.Duration)
	if src := r.URL.Query().Get("source"); src == blocklist.SourceAuto || src == blocklist.SourceManual {
		v.Source = src
	}
	v.Sources = []sevOption{{Value: "", Label: "Automatic and manual", Selected: v.Source == ""},
		{Value: blocklist.SourceAuto, Label: "Automatic", Selected: v.Source == blocklist.SourceAuto},
		{Value: blocklist.SourceManual, Label: "Manual", Selected: v.Source == blocklist.SourceManual}}
	failed := false
	list, err := s.blocks.List(ctx, blocklist.Filter{States: []string{blocklist.StateActive, blocklist.StateSuspended}, Source: v.Source, Limit: blockListMax})
	if err != nil {
		s.log.Warn("security blocks: list failed", "err", err)
		v.RowsErr, failed = "The blocks could not be read. Mooring's log has the details.", true
	}
	v.Capped = len(list) >= blockListMax
	for i := range list {
		v.Rows = append(v.Rows, blockRowOf(&list[i], now))
	}
	refs, err := s.blocks.Refusals(ctx, blockRefusalsMax)
	if err != nil {
		s.log.Warn("security blocks: refusals failed", "err", err)
		v.RefusalsErr, failed = "The refusals could not be read. Mooring's log has the details.", true
	}
	for _, rf := range refs {
		row := refusalRow{Prefix: rf.Prefix, Code: rf.Code, Words: capFirst(reasonWords(rf.Code)), Auto: rf.Source == blocklist.SourceAuto,
			RuleID: rf.RuleID, Detail: siem.Cut(rf.Detail, 200), Count: groupDigits(rf.Count)}
		if !rf.Last.IsZero() {
			row.Last, row.LastISO, row.Ago = rf.Last.UTC().Format(detectTimeFmt), rf.Last.UTC().Format(time.RFC3339), secAgo(now, rf.Last)
		}
		v.Refusals = append(v.Refusals, row)
	}
	if s.l4Routes != nil {
		routes, err := s.l4Routes.List()
		if err != nil {
			s.log.Warn("security blocks: L4 routes failed", "err", err)
			v.L4Err = "The L4 routes could not be read. Mooring's log has the details."
		}
		for _, rt := range routes {
			row := l4Row{App: rt.AppID, Listen: strconv.Itoa(rt.Listen) + "/" + rt.Protocol, Service: rt.Service}
			switch {
			case rt.Kernel():
				row.Why = "forward: kernel (Docker forwards it)"
			case !v.Status.L4:
				row.Why = "L4 blocking is off"
				if v.Status.L4Why != "" {
					row.Why = v.Status.L4Why
				}
			default:
				continue // nginx refuses blocked IPv4 clients on it
			}
			v.NotFiltered = append(v.NotFiltered, row)
		}
	}
	if failed && status == http.StatusOK {
		status = http.StatusInternalServerError
	}
	s.renderSec(w, r, status, blocksTmpl, "Blocked addresses", &secPage{Blocks: v})
}

// blockBack is where a block change goes back to: the Blocks page, or (back=entity) the address's
// entity page.
func blockBack(r *http.Request) (siem.Entity, bool) {
	if r.PostFormValue("back") != "entity" {
		return siem.Entity{}, false
	}
	return parseEntity(siem.EntityAddress, r.PostFormValue("key"), "")
}

// blockFail answers a refused block change: on the entity page it came from, or the Blocks page.
func (s *Server) blockFail(w http.ResponseWriter, r *http.Request, status int, msg string, form *blockForm) {
	if en, ok := blockBack(r); ok && s.incidentSvc != nil {
		s.showEntity(w, r, status, en, "", msg)
		return
	}
	s.showBlocks(w, r, status, "", msg, form)
}

// handleSecBlockAdd places a manual block (POST /security/blocks/add). The request carries the
// owner's own address, which the list refuses to block. The audit Detail is fixed words and the
// checked prefix, never the reason.
func (s *Server) handleSecBlockAdd(w http.ResponseWriter, r *http.Request) {
	const action = "security_block_add"
	if s.blocks == nil {
		s.showBlocks(w, r, http.StatusServiceUnavailable, "", "", nil)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	form := &blockForm{
		Prefix:   siem.Cut(strings.TrimSpace(r.PostFormValue("prefix")), blockPrefixMax+1),
		Duration: r.PostFormValue("duration"),
		Reason:   strings.TrimSpace(r.PostFormValue("reason")),
	}
	prefix, ok := parseBlockPrefix(form.Prefix)
	if !ok {
		s.detectAudit(r, action, "blocklist", audit.Error, "source=manual result=refused code="+blocklist.RefuseInvalid)
		s.blockFail(w, r, http.StatusUnprocessableEntity, "That is not an IP address or CIDR range, such as 203.0.113.7 or 203.0.113.0/24.", form)
		return
	}
	detail := "source=manual prefix=" + prefix.String()
	ds := s.manualDurations()
	i := slices.IndexFunc(ds, func(d blockDuration) bool { return d.Value == form.Duration })
	if i < 0 {
		s.detectAudit(r, action, "blocklist", audit.Error, detail+" result=rejected")
		s.blockFail(w, r, http.StatusUnprocessableEntity, "Pick a block length.", form)
		return
	}
	detail += " duration=" + ds[i].Value
	switch {
	case len(form.Reason) > blockReasonMax:
		s.detectAudit(r, action, "blocklist", audit.Error, detail+" result=rejected")
		s.blockFail(w, r, http.StatusUnprocessableEntity, "The reason is too long: at most "+strconv.Itoa(blockReasonMax)+" bytes.", form)
		return
	case !utf8.ValidString(form.Reason) || strings.IndexFunc(form.Reason, unicode.IsControl) >= 0:
		s.detectAudit(r, action, "blocklist", audit.Error, detail+" result=rejected")
		s.blockFail(w, r, http.StatusUnprocessableEntity, "The reason has characters a reason can't have.", form)
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), detectTimeout)
	defer cancel()
	_, err := s.blocks.Block(ctx, blocklist.Request{
		Prefix: prefix.String(), Source: blocklist.SourceManual, Duration: ds[i].d, Reason: form.Reason,
		By: sessionUser(r), Self: ClientIP(r.Context()).String(),
	})
	if err != nil {
		var re *blocklist.RefusedError
		if errors.As(err, &re) {
			s.log.Info("security blocks: manual block refused", "code", re.Code)
			s.detectAudit(r, action, "blocklist", audit.Error, detail+" result=refused code="+safeCode(re.Code))
			s.blockFail(w, r, http.StatusUnprocessableEntity, refusedMessage(re), form)
			return
		}
		s.log.Warn("security blocks: manual block failed", "err", err)
		s.detectAudit(r, action, "blocklist", audit.Error, detail+" result=error")
		s.blockFail(w, r, http.StatusInternalServerError, "The block was not placed. Mooring's log has the details.", form)
		return
	}
	s.detectAudit(r, action, "blocklist", audit.OK, detail)
	if en, ok := blockBack(r); ok {
		http.Redirect(w, r, entityURL(en, url.Values{"done": {"blocked"}}), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, withQuery("/security/blocks", url.Values{"done": {"added"}}), http.StatusSeeOther)
}

// handleSecBlockRemove lifts the block in force for a prefix (POST /security/blocks/remove); the
// list then exempts it from automatic blocks for 24 hours.
func (s *Server) handleSecBlockRemove(w http.ResponseWriter, r *http.Request) {
	const action = "security_block_remove"
	if s.blocks == nil {
		s.showBlocks(w, r, http.StatusServiceUnavailable, "", "", nil)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	prefix, ok := parseBlockPrefix(strings.TrimSpace(r.PostFormValue("prefix")))
	if !ok {
		s.detectAudit(r, action, "blocklist", audit.Error, "result=rejected")
		s.blockFail(w, r, http.StatusUnprocessableEntity, "That is not a valid block.", nil)
		return
	}
	detail := "prefix=" + prefix.String()
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), detectTimeout)
	defer cancel()
	if err := s.blocks.Unblock(ctx, prefix, sessionUser(r)); err != nil {
		if errors.Is(err, blocklist.ErrNotFound) {
			s.detectAudit(r, action, "blocklist", audit.Error, detail+" result=not found")
			s.blockFail(w, r, http.StatusNotFound, "That address has no block in force.", nil)
			return
		}
		s.log.Warn("security blocks: unblock failed", "err", err)
		s.detectAudit(r, action, "blocklist", audit.Error, detail+" result=error")
		s.blockFail(w, r, http.StatusInternalServerError, "The block was not removed. Mooring's log has the details.", nil)
		return
	}
	s.detectAudit(r, action, "blocklist", audit.OK, detail)
	if en, ok := blockBack(r); ok {
		http.Redirect(w, r, entityURL(en, url.Values{"done": {"unblocked"}}), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, withQuery("/security/blocks", url.Values{"done": {"removed"}}), http.StatusSeeOther)
}

// entityBlockView is an address entity's block, for its page.
type entityBlockView struct {
	Prefix    string // the block list's prefix for the address
	Shown     string // Prefix as the page says it: a single address without its /32 or /128
	WholeNet  bool   // the key is one IPv6 address and Prefix is its whole /64: the page says so
	Live      *blockLive
	Blocked   bool   // a block of its own is in force (active or suspended): Unblock
	CoveredBy string // no block of its own in force, but this active block overlaps it
	Partly    bool   // CoveredBy is narrower than Prefix (one address inside an IPv6 /64): Block stays; else neither button
	Auto      bool
	Duration  blockDuration
	Err       string
}

// entityBlock is an address entity's block state (nil when the block list isn't available or the
// key isn't an address).
func (s *Server) entityBlock(ctx context.Context, en siem.Entity) *entityBlockView {
	if s.blocks == nil || en.Kind != siem.EntityAddress {
		return nil
	}
	p, ok := entityBlockPrefix(en.Key)
	if !ok {
		return nil
	}
	v := &entityBlockView{Prefix: p.String(), Shown: shownPrefix(p), Duration: s.entityBlockDuration()}
	if a, err := netip.ParseAddr(en.Key); err == nil {
		v.WholeNet = a.Unmap().Is6() && !p.IsSingleIP()
	}
	look := s.newBlockLookup()
	b, found, cover, covered, err := look.state(ctx, p)
	if err != nil {
		s.log.Warn("security entities: block state failed", "err", err)
		v.Err = "The block state could not be read. Mooring's log has the details."
		return v
	}
	if covered {
		// Intentional: no Block and no Unblock when the covering block contains the address. It is
		// already refused, and removing the covering block unblocks more than this address: that is
		// done on the Blocks page. A narrower block inside an IPv6 /64 blocks only part of it, so
		// Block (of the whole /64) stays.
		v.Live, v.CoveredBy, v.Partly = coveredLive(p, cover, look.now), cover.Prefix.String(), partlyCovered(p, cover)
		v.Auto = !v.Partly && cover.Source == blocklist.SourceAuto
		return v
	}
	v.Live = blockLiveOf(b, found, look.now)
	v.Blocked = inForce(b, found)
	v.Auto = found && b.Source == blocklist.SourceAuto
	if v.Blocked && b.Prefix.IsValid() {
		v.Prefix, v.Shown = b.Prefix.String(), shownPrefix(b.Prefix)
	}
	return v
}

// shownPrefix is a block's prefix as a page says it: a single address without its /32 or /128.
func shownPrefix(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}
