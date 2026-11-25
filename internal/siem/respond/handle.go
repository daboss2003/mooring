package respond

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/blocklist"
	"github.com/daboss2003/mooring/internal/siem"
)

// outcome is what handling a request (or a page change) recorded, and what follows from it once
// mu is released: the event, the incident's timeline entry, the audit record and the alerts.
type outcome struct {
	x siem.Response // as recorded (ID 0: nothing recorded)
	// actorForm: a revoke's account as the event stored it (the username, or its keyed hash when the
	// username is personal data), which the siem.response event names instead of the username.
	actorForm string
	actor     string // who acted ("" Mooring)
	ruleName  string
	severity  siem.Severity
	auto      bool  // an automatic action of Mooring's: audited
	sessions  int64 // an applied revoke's sessions
	alerts    []alert.Outbox
}

const maxRuleName = 80

// handle applies one of the engine's requests (the worker).
func (r *Responder) handle(req siem.ResponseRequest) {
	req, ok := checkRequest(req)
	if !ok {
		r.logLimited("bad-request", "security response: malformed request dropped", "action", siem.Cut(req.Action, 32))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), actionTimeout)
	defer cancel()
	r.follow(r.decide(ctx, req))
}

// decide decides and records one checked request, holding mu.
func (r *Responder) decide(ctx context.Context, req siem.ResponseRequest) outcome {
	r.mu.Lock()
	defer r.mu.Unlock()
	eff := r.effective()
	switch {
	case eff == siem.ResponseModeOff:
		return outcome{}
	case req.Action == siem.ResponseRevoke && !validActor(req.Target):
		// Recorded with the target made printable; the revoker is never asked.
		out := outcome{ruleName: req.RuleName, severity: req.Severity, auto: req.Automatic && eff == siem.ResponseModeEnforce}
		return r.record(ctx, out, r.base(req, plain(req.Target, siem.MaxShort)), siem.ResponseRefused, reasonInvalidTarget)
	case req.Action == siem.ResponseBlock && r.stillBlocked(ctx, req.Target):
		// Intentional: nothing is recorded, counted, audited or emitted. The rule engine asks again for
		// as long as its detection keeps firing (it doesn't know what became of its last request), and
		// the block it asks for is in force.
		r.skip("the address is still blocked", req)
		return outcome{}
	case eff == siem.ResponseModeRecommend || !req.Automatic:
		return r.recommend(ctx, req)
	case req.Action == siem.ResponseBlock:
		return r.autoBlock(ctx, req)
	}
	return r.autoRevoke(ctx, req)
}

// skip counts a request that needs no record (Skipped).
func (r *Responder) skip(why string, req siem.ResponseRequest) {
	n := r.skipped.Add(1)
	r.log.Debug("security response: request skipped: "+why, "action", req.Action, "rule", req.RuleID, "skipped_total", n)
}

// stillBlocked reports whether a block request's address has a block in force (active, or suspended
// while a protected address covers it) with blockAhead or more to go. A request within the block's
// last blockAhead is handled: the block list lengthens the block, so the address stays blocked.
// Intentional: when the block list can't say, the request is handled as any other (the block list
// then decides).
func (r *Responder) stillBlocked(ctx context.Context, target string) bool {
	if r.o.Blocks == nil {
		return false
	}
	t, ok := blockTarget(target)
	if !ok {
		return false
	}
	p, err := netip.ParsePrefix(t)
	if err != nil {
		return false
	}
	gctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	b, found, err := r.o.Blocks.Get(gctx, p)
	if err != nil {
		r.logLimited("get", "security response: block list lookup failed", "err", err)
		return false
	}
	if !found || (b.State != blocklist.StateActive && b.State != blocklist.StateSuspended) {
		return false
	}
	return b.Until.Sub(r.now()) >= blockAhead
}

// validActor reports whether a revoke's target can be passed to the revoker: plain text of at most
// siem.MaxShort bytes on one line, without space around it. It is passed exactly as the event
// stored it, so it is checked, never rewritten.
func validActor(target string) bool {
	return target != "" && plain(target, siem.MaxShort) == target
}

// checkRequest bounds a request's text; false for one that can't be acted on or recorded (an
// unknown action, a revoke of nobody). A revoke whose target isn't a valid actor is recorded as
// refused (decide).
func checkRequest(req siem.ResponseRequest) (siem.ResponseRequest, bool) {
	switch req.Action {
	case siem.ResponseBlock:
		req.Duration = max(req.Duration, 0)
	case siem.ResponseRevoke:
		req.Duration = 0
		if plain(req.Target, siem.MaxShort) == "" {
			return req, false
		}
	default:
		return req, false
	}
	req.RuleID = clean(req.RuleID, siem.MaxShort)
	req.RuleName = clean(req.RuleName, maxRuleName)
	req.Summary = clean(req.Summary, MaxSummary)
	req.DetectionID, req.IncidentID = max(req.DetectionID, 0), max(req.IncidentID, 0)
	if siem.SeverityRank(req.Severity) == 0 {
		req.Severity = ""
	}
	return req, true
}

// blockTarget is a request's block target as the canonical prefix the block list takes for an
// automatic block: a single IPv4 address (/32), or an IPv6 /64 (a bare IPv6 address is its /64).
func blockTarget(s string) (string, bool) {
	var p netip.Prefix
	if strings.Contains(s, "/") {
		var err error
		if p, err = netip.ParsePrefix(s); err != nil {
			return "", false
		}
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			return "", false
		}
		if a = a.Unmap(); a.Is4() {
			p = netip.PrefixFrom(a, 32)
		} else {
			p = netip.PrefixFrom(a, 64)
		}
	}
	if a := p.Addr(); a.Is4In6() {
		if p.Bits() < 96 {
			return "", false
		}
		p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
	}
	p = p.Masked()
	if (p.Addr().Is4() && p.Bits() == 32) || (p.Addr().Is6() && p.Bits() == 64) {
		return p.String(), true
	}
	return "", false
}

func (r *Responder) base(req siem.ResponseRequest, target string) siem.Response {
	now := r.now()
	return siem.Response{Action: req.Action, Target: target, Automatic: req.Automatic, RuleID: req.RuleID,
		DetectionID: req.DetectionID, IncidentID: req.IncidentID, Summary: req.Summary, Duration: req.Duration,
		Created: now, Updated: now}
}

// record records x with its final state at once (mu held); a refusal already recorded for the
// same reason within refusalWindow is not recorded again (repeatRefusal).
func (r *Responder) record(ctx context.Context, out outcome, x siem.Response, state, reason string) outcome {
	x.State, x.Reason = state, reason
	if state == siem.ResponseRefused && r.repeatRefusal(ctx, x, 0) {
		return out
	}
	if err := r.insert(ctx, &x); err != nil {
		r.logLimited("record", "security response: response not recorded", "err", err)
		return out
	}
	out.x = x
	return out
}

// recommend records a request as a recommendation (mu held).
func (r *Responder) recommend(ctx context.Context, req siem.ResponseRequest) outcome {
	out := outcome{ruleName: req.RuleName, severity: req.Severity}
	target := req.Target
	if req.Action == siem.ResponseBlock {
		t, ok := blockTarget(req.Target)
		if !ok {
			return r.record(ctx, out, r.base(req, clean(req.Target, 64)), siem.ResponseRefused, blocklist.RefuseInvalid)
		}
		target = t
	}
	x, fresh, err := r.upsertRecommendation(ctx, r.base(req, target))
	if err != nil {
		r.logLimited("record", "security response: recommendation not recorded", "err", err)
		return out
	}
	// Only a new recommendation is an event and a timeline entry (see upsertRecommendation).
	if fresh {
		out.x = x
	}
	return out
}

// autoBlock places an automatic block, within the hourly cap (mu held). The response is recorded
// before the block is placed, so the block names it.
func (r *Responder) autoBlock(ctx context.Context, req siem.ResponseRequest) outcome {
	out := outcome{ruleName: req.RuleName, severity: req.Severity, auto: true}
	now := r.now()
	target, ok := blockTarget(req.Target)
	x := r.base(req, target)
	switch {
	case !ok:
		x.Target = clean(req.Target, 64)
		return r.record(ctx, out, x, siem.ResponseRefused, blocklist.RefuseInvalid)
	case r.o.Blocks == nil:
		return r.record(ctx, out, x, siem.ResponseRefused, blocklist.RefuseNoEdge)
	}
	// Intentional: when the cap can't be counted, nothing is placed (fail closed).
	n, err := r.countApplied(ctx, siem.ResponseBlock, now.Add(-capWindow))
	if err != nil {
		r.logLimited("count", "security response: hourly cap not counted, block not placed", "err", err)
		return r.record(ctx, out, x, siem.ResponseFailed, reasonError)
	}
	if n >= r.maxBlocks {
		out.alerts = r.capAlert(out.alerts, siem.ResponseBlock, r.maxBlocks, now)
		return r.record(ctx, out, x, siem.ResponseRefused, reasonCap)
	}
	x.State, x.Reason = siem.ResponseFailed, reasonInterrupted
	if err := r.insert(ctx, &x); err != nil {
		r.logLimited("record", "security response: response not recorded, block not placed", "err", err)
		return out
	}
	b, err := r.o.Blocks.Block(ctx, blocklist.Request{Prefix: target, Source: blocklist.SourceAuto, Duration: req.Duration,
		RuleID: req.RuleID, Reason: req.Summary, DetectionID: req.DetectionID, IncidentID: req.IncidentID, ResponseID: x.ID})
	r.blockOutcome(&x, b, err)
	if r.dropRepeat(ctx, x) {
		return out
	}
	x.Updated = r.now()
	if err := r.settle(ctx, x); err != nil {
		r.logLimited("record", "security response: response outcome not recorded", "err", err)
	}
	out.x = x
	return out
}

// repeatRefusal reports whether the refusal x repeats the newest response of its action and target
// created within refusalWindow (not counting row except, x's own): that one is a refusal for the
// same reason. Such a repeat is not recorded, so an address or an account that is refused over and
// over (a protected address that keeps firing, an account inside its cooldown) records one refusal
// an hour per reason. A response of another kind in between (applied, another reason) starts over.
// Intentional: when the responses can't be read, the refusal is recorded.
func (r *Responder) repeatRefusal(ctx context.Context, x siem.Response, except int64) bool {
	now := r.now()
	prev, found, err := r.newest(ctx, x.Action, x.Target, now.Add(-refusalWindow), now, except)
	if err != nil {
		r.logLimited("count", "security response: earlier refusals not read", "err", err)
		return false
	}
	if !found || prev.State != siem.ResponseRefused || prev.Reason != x.Reason {
		return false
	}
	r.skip("refused for the same reason within the hour", siem.ResponseRequest{Action: x.Action, RuleID: x.RuleID})
	return true
}

// dropRepeat removes x's row, recorded before its action was tried, when the action was refused
// and the refusal is a repeat (repeatRefusal); false when x is to be recorded.
func (r *Responder) dropRepeat(ctx context.Context, x siem.Response) bool {
	if x.State != siem.ResponseRefused || !r.repeatRefusal(ctx, x, x.ID) {
		return false
	}
	if err := r.remove(ctx, x.ID); err != nil {
		r.logLimited("record", "security response: a repeated refusal's row not removed", "err", err)
		return false
	}
	return true
}

// blockOutcome sets x's state from the block list's answer; an applied block's duration is the
// list's (a repeat's is longer).
func (r *Responder) blockOutcome(x *siem.Response, b blocklist.Block, err error) {
	var re *blocklist.RefusedError
	switch {
	case err == nil:
		x.State, x.Reason = siem.ResponseApplied, ""
		if d := b.Until.Sub(r.now()).Round(time.Second); !b.Until.IsZero() && d > 0 {
			x.Duration = d
		}
	case errors.As(err, &re):
		x.State, x.Reason = siem.ResponseRefused, code(re.Code)
	default:
		x.State, x.Reason = siem.ResponseFailed, reasonError
		r.logLimited("block", "security response: block not placed", "err", err)
	}
}

// autoRevoke signs an account out, within its cooldown and the hourly cap (mu held).
func (r *Responder) autoRevoke(ctx context.Context, req siem.ResponseRequest) outcome {
	out := outcome{ruleName: req.RuleName, severity: req.Severity, auto: true, actorForm: req.Target}
	now := r.now()
	x := r.base(req, req.Target)
	rv := r.revoker.Load()
	if rv == nil {
		return r.record(ctx, out, x, siem.ResponseRefused, reasonNoRevoker)
	}
	recent, err := r.recentlyRevoked(ctx, req.Target, now)
	if err != nil {
		r.logLimited("count", "security response: cooldown not checked, sign-out not done", "err", err)
		return r.record(ctx, out, x, siem.ResponseFailed, reasonError)
	}
	if recent {
		return r.record(ctx, out, x, siem.ResponseRefused, reasonCooldown)
	}
	n, err := r.countApplied(ctx, siem.ResponseRevoke, now.Add(-capWindow))
	if err != nil {
		r.logLimited("count", "security response: hourly cap not counted, sign-out not done", "err", err)
		return r.record(ctx, out, x, siem.ResponseFailed, reasonError)
	}
	if n >= r.maxRevokes {
		out.alerts = r.capAlert(out.alerts, siem.ResponseRevoke, r.maxRevokes, now)
		return r.record(ctx, out, x, siem.ResponseRefused, reasonCap)
	}
	x.State, x.Reason = siem.ResponseFailed, reasonInterrupted
	if err := r.insert(ctx, &x); err != nil {
		r.logLimited("record", "security response: response not recorded, sign-out not done", "err", err)
		return out
	}
	user, sessions, err := rv.a.Revoke(ctx, req.Target)
	r.revokeOutcome(&x, user, err)
	if x.State == siem.ResponseApplied {
		out.sessions = sessions
		r.noteRevoked(req.Target, x.Target, now)
		out.alerts = append(out.alerts, revokeAlert(x, sessions, req.RuleName, ""))
	}
	if r.dropRepeat(ctx, x) {
		return out
	}
	x.Updated = r.now()
	if err := r.settle(ctx, x); err != nil {
		r.logLimited("record", "security response: response outcome not recorded", "err", err)
	}
	out.x = x
	return out
}

// revokeOutcome sets x's state from the revoker's answer; an applied revoke's target becomes the
// username.
func (r *Responder) revokeOutcome(x *siem.Response, user string, err error) {
	switch {
	case err == nil:
		x.State, x.Reason = siem.ResponseApplied, ""
		if user = plain(user, siem.MaxShort); user != "" {
			x.Target = user
		}
	case errors.Is(err, siem.ErrUnknownAccount):
		x.State, x.Reason = siem.ResponseRefused, reasonUnknown
	default:
		x.State, x.Reason = siem.ResponseFailed, reasonError
		r.logLimited("revoke", "security response: sessions not revoked", "err", err)
	}
}

// recentlyRevoked reports whether Mooring revoked actor's sessions automatically within
// RevokeCooldown (mu held).
// Intentional: an applied revoke's row names the username, which the request's actor is unless
// the username is personal data (then the actor is its keyed hash). Such an account's cooldown is
// kept in memory too (noteRevoked), so after a restart it can be signed out once more within the
// hour; the hourly cap still holds.
func (r *Responder) recentlyRevoked(ctx context.Context, actor string, now time.Time) (bool, error) {
	if m, ok := r.revoked[actor]; ok && now.Sub(m.at) < RevokeCooldown && !now.Before(m.at) {
		return true, nil
	}
	n, err := r.countApplied(ctx, siem.ResponseRevoke, now.Add(-RevokeCooldown), actor)
	return n > 0, err
}

func (r *Responder) noteRevoked(actor, user string, now time.Time) {
	if len(r.revoked) >= maxRevoked {
		for k, m := range r.revoked {
			if now.Sub(m.at) >= RevokeCooldown || len(r.revoked) >= maxRevoked {
				delete(r.revoked, k)
			}
		}
	}
	r.revoked[actor] = revokedAcct{user: user, at: now}
}

// capAlert adds the warning that an action reached its hourly cap, unless one was raised within
// capWindow (mu held).
func (r *Responder) capAlert(alerts []alert.Outbox, action string, limit int, now time.Time) []alert.Outbox {
	if t, ok := r.capWarned[action]; ok && now.Sub(t) < capWindow && !now.Before(t) {
		return alerts
	}
	r.capWarned[action] = now
	what := "blocks"
	if action == siem.ResponseRevoke {
		what = "sign-outs"
	}
	return append(alerts, alert.Outbox{RuleID: 0, Target: alertTarget, Kind: AlertKind, Level: alert.LevelWarning,
		Transition: "firing", DedupeKey: "siem-response-cap:" + action,
		Summary: fmt.Sprintf("Automatic %s reached their hourly cap (%d): more are refused until the hour has passed — see the Responses page",
			what, limit)})
}

// revokeAlert is an applied revoke's critical alert; by is the owner who applied a recommendation.
func revokeAlert(x siem.Response, sessions int64, ruleName, by string) alert.Outbox {
	text := "Mooring signed " + x.Target + " out of " + sessionsText(sessions)
	if by != "" {
		text += " (applied by " + by + ")"
	}
	if ruleName == "" {
		ruleName = x.RuleID
	}
	text += ": " + ruleName + " — " + x.Summary
	return alert.Outbox{RuleID: 0, Target: alertTarget, Kind: AlertKind, Level: alert.LevelCritical, Transition: "firing",
		DedupeKey: "siem-response:" + strconv.FormatInt(x.ID, 10), Summary: clean(text, MaxSummary)}
}

func sessionsText(n int64) string {
	if n == 1 {
		return "1 session"
	}
	return strconv.FormatInt(n, 10) + " sessions"
}

var reCode = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// code is a refusal code as recorded: a fixed word, else "refused".
func code(c string) string {
	if reCode.MatchString(c) {
		return c
	}
	return reasonRefused
}

// describe is a response in words: its timeline entry and its event's message.
func describe(x siem.Response, sessions int64) string {
	t := x.Target
	if x.Action == siem.ResponseBlock {
		switch x.State {
		case siem.ResponseRecommended:
			return "recommended blocking " + t + " for " + fmtDur(x.Duration)
		case siem.ResponseApplied:
			return "blocked " + t + " for " + fmtDur(x.Duration)
		case siem.ResponseRefused:
			return "block of " + t + " refused: " + x.Reason
		case siem.ResponseFailed:
			return "block of " + t + " failed"
		case siem.ResponseDismissed:
			return "recommendation to block " + t + " dismissed"
		case siem.ResponseExpired:
			return "recommendation to block " + t + " expired"
		}
	} else {
		switch x.State {
		case siem.ResponseRecommended:
			return "recommended signing " + t + " out"
		case siem.ResponseApplied:
			return "signed " + t + " out (" + sessionsText(sessions) + ")"
		case siem.ResponseRefused:
			return "sign-out of " + t + " refused: " + x.Reason
		case siem.ResponseFailed:
			return "sign-out of " + t + " failed"
		case siem.ResponseDismissed:
			return "recommendation to sign " + t + " out dismissed"
		case siem.ResponseExpired:
			return "recommendation to sign " + t + " out expired"
		}
	}
	return x.Action + " " + x.State
}

// follow does what follows a recorded outcome, without mu: the event, the incident's timeline
// entry, the audit record (Mooring's own actions) and the alerts, each within sideTimeout.
func (r *Responder) follow(out outcome) {
	for _, o := range out.alerts {
		r.alert(o)
	}
	x := out.x
	if x.ID == 0 {
		return
	}
	text := describe(x, out.sessions)
	r.emit(eventForm(x, out.actorForm), "", out.sessions)
	if x.IncidentID != 0 && r.o.Timeline != nil {
		ctx, cancel := context.WithTimeout(context.Background(), sideTimeout)
		err := r.o.Timeline(ctx, x.IncidentID, siem.IncidentEvent{TS: r.now().UTC(), Kind: siem.TimelineResponse,
			DetectionID: x.DetectionID, RuleID: x.RuleID, RuleName: out.ruleName, Severity: out.severity, Actor: out.actor,
			Text: text})
		cancel()
		if err != nil {
			r.logLimited("timeline", "security response: incident timeline entry not added", "incident", x.IncidentID, "err", err)
		}
	}
	if out.auto {
		r.audit(context.Background(), auditEvent(x, out.sessions))
	}
}

func (r *Responder) alert(o alert.Outbox) {
	if r.o.Alerter == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), sideTimeout)
	defer cancel()
	if err := r.o.Alerter.EnqueueInfra(ctx, o); err != nil {
		r.logLimited("alert", "security response: alert not recorded", "dedupe_key", o.DedupeKey, "err", err)
	}
}

func (r *Responder) audit(ctx context.Context, ev audit.Event) {
	if r.o.Audit == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), sideTimeout)
	defer cancel()
	if err := r.o.Audit(ctx, ev); err != nil {
		r.logLimited("audit", "security response: audit record not written", "err", err)
	}
}

// auditEvent is the audit record of an automatic action. Intentional: the action is never named
// "user_…": the mooring.user_change rule matches kind mooring.user_*, and the record comes back to
// the rules as an event.
func auditEvent(x siem.Response, sessions int64) audit.Event {
	detail := "action=" + x.Action + " target=" + word(x.Target) + " state=" + x.State
	if x.Reason != "" {
		detail += " reason=" + x.Reason
	}
	if x.RuleID != "" {
		detail += " rule=" + word(x.RuleID)
	}
	if x.State == siem.ResponseApplied {
		if x.Action == siem.ResponseBlock {
			detail += " duration=" + fmtDur(x.Duration)
		} else {
			detail += " sessions=" + strconv.FormatInt(sessions, 10)
		}
	}
	outcome := audit.OK
	switch x.State {
	case siem.ResponseRefused:
		outcome = audit.Deny
	case siem.ResponseFailed:
		outcome = audit.Error
	}
	return audit.Event{Actor: auditActor, Action: auditAction, Target: x.Target, Outcome: outcome, Level: audit.Security,
		Detail: detail}
}

// eventForm is x as its siem.response event names it: a revoke's target is the account as the
// event behind it stored it (actorForm), not the username the revoker returned.
// Intentional: events given to the pipeline's Emit are stored as they are, not redacted, and a
// username that is an email address is stored as its keyed hash everywhere else in the security
// logs. The response's row, its incident's timeline entry, the alert and the audit record (which
// the pipeline redacts on its way in) keep the username.
func eventForm(x siem.Response, actorForm string) siem.Response {
	if x.Action == siem.ResponseRevoke && actorForm != "" {
		x.Target = actorForm
	}
	return x
}

// emit hands a response to the pipeline as a siem.response event (never evaluated by the rules).
// x is in its eventForm; text "" is describe's.
func (r *Responder) emit(x siem.Response, text string, sessions int64) {
	if r.o.Emit == nil {
		return
	}
	if text == "" {
		text = describe(x, sessions)
	}
	lvl := siem.LvlInfo
	switch x.State {
	case siem.ResponseApplied, siem.ResponseRefused, siem.ResponseFailed:
		lvl = siem.LvlWarn
	}
	ev := siem.Event{TS: r.now().UTC(), Src: siem.SrcSIEM, Kind: kindResponse, Lvl: lvl, Msg: text,
		F: map[string]any{"action": x.Action, "target": x.Target, "state": x.State, "rule": x.RuleID,
			"duration_s": float64(seconds(x.Duration)), "response_id": float64(x.ID), "automatic": x.Automatic}}
	if x.Reason != "" {
		ev.F["reason"] = x.Reason
	}
	if x.DetectionID != 0 {
		ev.F["detection_id"] = float64(x.DetectionID)
	}
	if x.IncidentID != 0 {
		ev.F["incident_id"] = float64(x.IncidentID)
	}
	if x.By != "" {
		ev.F["by"] = x.By
	}
	switch x.Action {
	case siem.ResponseBlock:
		if p, err := netip.ParsePrefix(x.Target); err == nil && p.IsSingleIP() {
			ev.IP = p.Addr().String()
		}
	case siem.ResponseRevoke:
		ev.Actor = x.Target
	}
	if !r.o.Emit(ev) {
		r.logLimited("emit", "security response: event not taken by the pipeline")
	}
}
