package respond

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/daboss2003/mooring/internal/blocklist"
	"github.com/daboss2003/mooring/internal/siem"
)

// The owner-only Responses page (siem.ResponseService). The owner's own changes are audited by
// the page; this package audits only what Mooring does by itself.

// Status reports the mode, the pause and this hour's automatic actions against their caps.
func (r *Responder) Status(ctx context.Context) (siem.ResponseStatus, error) {
	since := r.now().Add(-capWindow)
	blocks, err := r.countApplied(ctx, siem.ResponseBlock, since)
	if err != nil {
		return siem.ResponseStatus{}, err
	}
	revokes, err := r.countApplied(ctx, siem.ResponseRevoke, since)
	if err != nil {
		return siem.ResponseStatus{}, err
	}
	st := siem.ResponseStatus{Mode: r.mode, Effective: r.effective(), BlocksThisHour: blocks, MaxBlocksPerHour: r.maxBlocks,
		RevokesThisHour: revokes, MaxRevokesPerHour: r.maxRevokes, Revoker: r.revoker.Load() != nil}
	if p := r.pause.Load(); p != nil {
		st.Paused, st.PausedBy, st.PausedAt = p.level, p.by, p.at
	}
	return st, nil
}

var knownStates = map[string]bool{siem.ResponseRecommended: true, siem.ResponseApplied: true, siem.ResponseRefused: true,
	siem.ResponseFailed: true, siem.ResponseDismissed: true, siem.ResponseExpired: true}

// Responses lists responses, newest first (ID descending), keyset-paged by f.Before.
func (r *Responder) Responses(ctx context.Context, f siem.ResponseFilter) ([]siem.Response, error) {
	seen := map[string]bool{}
	states := f.States[:0:0]
	for _, s := range f.States {
		if !knownStates[s] {
			return nil, invalidIn("unknown state %q (recommended, applied, refused, failed, dismissed, expired)", siem.Cut(s, 32))
		}
		if !seen[s] {
			seen[s] = true
			states = append(states, s)
		}
	}
	f.States = states
	switch {
	case f.Action != "" && f.Action != siem.ResponseBlock && f.Action != siem.ResponseRevoke:
		return nil, invalidIn("unknown action %q (block, revoke)", siem.Cut(f.Action, 32))
	case f.IncidentID < 0:
		return nil, invalidIn("no incident %d", f.IncidentID)
	case f.DetectionID < 0:
		return nil, invalidIn("no detection %d", f.DetectionID)
	case f.Before < 0:
		return nil, invalidIn("no response %d", f.Before)
	}
	limit := f.Limit
	switch {
	case limit <= 0:
		limit = 50
	case limit > 200:
		limit = 200
	}
	return r.list(ctx, f, limit)
}

// Response returns one response.
func (r *Responder) Response(ctx context.Context, id int64) (siem.Response, bool, error) {
	if id <= 0 {
		return siem.Response{}, false, nil
	}
	return r.get(ctx, id)
}

// recommendation reads a recommendation for the owner to act on (mu held); one older than
// RecommendTTL is expired now (returned as such, with the error).
func (r *Responder) recommendation(ctx context.Context, id int64) (siem.Response, error) {
	if err := r.settleOwed(ctx, id); err != nil {
		return siem.Response{}, fmt.Errorf("respond: response %d was applied already, and recording that still fails (it is not applied again): %w", id, err)
	}
	x, found, err := r.get(ctx, id)
	switch {
	case err != nil:
		return siem.Response{}, err
	case !found:
		return siem.Response{}, invalidIn("no response %d", id)
	case x.State != siem.ResponseRecommended:
		return siem.Response{}, invalidIn("response %d is not a recommendation (it is %s)", id, x.State)
	}
	if now := r.now(); now.Sub(x.Updated) >= RecommendTTL {
		x.State, x.Updated = siem.ResponseExpired, now
		if err := r.settle(ctx, x); err != nil {
			return siem.Response{}, err
		}
		return x, invalidIn("the recommendation expired")
	}
	return x, nil
}

// settleOwed writes the record of a recommendation that was applied without one (apply), if id is
// such a one (mu held): nil when nothing is owed for id any more.
func (r *Responder) settleOwed(ctx context.Context, id int64) error {
	x, owed := r.unsettled[id]
	if !owed {
		return nil
	}
	if err := r.settle(context.WithoutCancel(ctx), x); err != nil {
		return err
	}
	delete(r.unsettled, id)
	return nil
}

// Apply applies a recommended response now, as the owner's: a block is placed as a manual one by
// actor for the recommended duration, a revoke through the revoker. Neither counts toward the
// hourly caps or the revoke cooldown (those bound what Mooring does by itself). A block longer
// than the longest manual block is placed for that long. A refusal is recorded on the response and
// returned as an ErrInvalidInput error saying why; when the block list or the revoker fails
// instead, the recommendation stays open and the error is returned, so it can be applied again.
// When the action was done and recording it failed, the error says so; what follows an applied
// response (its event, timeline entry and alert) follows all the same, and the record is written
// at the next Apply or Dismiss of it or the next maintenance, without doing the action again.
func (r *Responder) Apply(ctx context.Context, id int64, actor string) error {
	if err := checkActor(actor); err != nil {
		return err
	}
	if id <= 0 {
		return invalidIn("no response %d", id)
	}
	out, err := r.applyLocked(ctx, id, actor)
	r.follow(out)
	return err
}

func (r *Responder) applyLocked(ctx context.Context, id int64, actor string) (outcome, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.apply(ctx, id, actor)
}

func (r *Responder) apply(ctx context.Context, id int64, actor string) (outcome, error) {
	out := outcome{actor: actor}
	x, err := r.recommendation(ctx, id)
	if err != nil {
		if x.ID != 0 {
			out.x = x // expired just now
		}
		return out, err
	}
	x.By = actor
	var why error
	switch x.Action {
	case siem.ResponseBlock:
		if r.o.Blocks == nil {
			x.State, x.Reason = siem.ResponseRefused, blocklist.RefuseNoEdge
			why = errors.New("block refused: Mooring doesn't run the edge")
			break
		}
		// Its own block is in force already: an earlier Apply placed it and couldn't record it (and
		// Mooring restarted since, or the retry is still owed). Only the record is missing.
		if b, ok := r.ownBlock(ctx, x); ok {
			r.blockOutcome(&x, b, nil)
			break
		}
		dur := x.Duration
		if m := r.o.ManualMaxDuration; m > 0 && dur > m {
			dur = m
		}
		b, err := r.o.Blocks.Block(ctx, blocklist.Request{Prefix: x.Target, Source: blocklist.SourceManual, Duration: dur,
			RuleID: x.RuleID, Reason: x.Summary, By: actor, DetectionID: x.DetectionID, IncidentID: x.IncidentID, ResponseID: x.ID})
		r.blockOutcome(&x, b, err)
		why = err
	default:
		out.actorForm = x.Target
		rv := r.revoker.Load()
		if rv == nil {
			x.State, x.Reason = siem.ResponseRefused, reasonNoRevoker
			why = errors.New("sign-out refused: session revokes are not available yet")
			break
		}
		user, sessions, err := rv.a.Revoke(ctx, x.Target)
		r.revokeOutcome(&x, user, err)
		why = err
		if x.State == siem.ResponseRefused {
			why = errors.New("sign-out refused: no Mooring user is stored as that account")
		}
		if x.State == siem.ResponseApplied {
			out.sessions = sessions
			out.alerts = append(out.alerts, revokeAlert(x, sessions, "", actor))
		}
	}
	// Intentional: a failure (the block list's or the revoker's own error, not a refusal) is not
	// recorded: the recommendation stays open as it was, so the owner can apply it again. A refusal
	// is final.
	if x.State == siem.ResponseFailed {
		return out, fmt.Errorf("respond: response %d not applied (it is still open): %w", id, why)
	}
	x.Updated = r.now()
	// Intentional: recorded whatever became of the request's context. The block is placed (or the
	// sessions are gone) by now; a row left "recommended" by a cancelled request could be applied a
	// second time.
	if err := r.settle(context.WithoutCancel(ctx), x); err != nil {
		if x.State != siem.ResponseApplied {
			return out, err // a refusal: nothing was done, and the recommendation is still open
		}
		// Intentional: the block is placed (or the sessions are gone) although its row still says
		// "recommended". The outcome is returned as applied, so the event and the timeline entry go
		// out with the alert, and the row is remembered as owed: until it is written (settleOwed), an
		// Apply of it does nothing a second time. Only a restart forgets that.
		r.unsettled[x.ID] = x
		out.x = x
		did := "the block WAS placed"
		if x.Action == siem.ResponseRevoke {
			did = "the account WAS signed out"
		}
		return out, fmt.Errorf("respond: response %d: %s, but recording that failed (it still shows as open; it is recorded when the database takes the write): %w",
			id, did, err)
	}
	out.x = x
	if x.State == siem.ResponseRefused {
		var re *blocklist.RefusedError
		if errors.As(why, &re) {
			return out, invalidIn("%s", re.Error())
		}
		return out, invalidIn("%v", why)
	}
	return out, nil
}

// Dismiss dismisses a recommended response.
func (r *Responder) Dismiss(ctx context.Context, id int64, actor string) error {
	if err := checkActor(actor); err != nil {
		return err
	}
	if id <= 0 {
		return invalidIn("no response %d", id)
	}
	x, err := r.dismissLocked(ctx, id, actor)
	if x.ID != 0 && (err == nil || x.State == siem.ResponseExpired) {
		r.follow(outcome{x: x, actor: actor})
	}
	return err
}

func (r *Responder) dismissLocked(ctx context.Context, id int64, actor string) (siem.Response, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	x, err := r.recommendation(ctx, id)
	if err == nil {
		x.State, x.By, x.Updated = siem.ResponseDismissed, actor, r.now()
		err = r.settle(ctx, x)
	}
	return x, err
}

// SetPause lowers what responses do until lifted: "" lifts it, siem.ResponseModeRecommend records
// recommendations only, siem.ResponseModeOff also lifts every automatic block now. When that
// fails, the pause is stored and in force all the same, the error wraps siem.ErrBlocksNotLifted,
// and the lift is tried again every few minutes (maintain). The effective mode is the lower of
// the configured one and the pause, so a pause never raises it.
func (r *Responder) SetPause(ctx context.Context, level, actor string) error {
	if err := checkActor(actor); err != nil {
		return err
	}
	switch level {
	case "", siem.ResponseModeRecommend, siem.ResponseModeOff:
	default:
		return invalidIn("unknown pause %q (recommend, off, or none)", siem.Cut(level, 32))
	}
	var p *pauseState
	if level != "" {
		p = &pauseState{level: level, by: actor, at: r.now().UTC()}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.storePause(ctx, p); err != nil {
		return err
	}
	r.pause.Store(p)
	if level == siem.ResponseModeOff {
		if r.liftAll(ctx, actor, "automated response paused") < 0 {
			return fmt.Errorf("respond: paused, but %w (tried again in a few minutes)", siem.ErrBlocksNotLifted)
		}
	}
	return nil
}

// LiftForIncident: the incident was marked a false positive. Its automatic blocks are removed and
// their addresses exempt from automatic blocks for ExemptFalsePos, and its open recommendations
// are dismissed by actor; it returns how many blocks were removed.
func (r *Responder) LiftForIncident(ctx context.Context, incidentID int64, actor string) (int, error) {
	if incidentID <= 0 {
		return 0, invalidIn("no incident %d", incidentID)
	}
	if err := checkActor(actor); err != nil {
		return 0, err
	}
	n, dismissed, err := r.liftLocked(ctx, incidentID, actor)
	for _, x := range dismissed {
		r.emit(x, "", 0)
	}
	if (n > 0 || len(dismissed) > 0) && r.o.Timeline != nil {
		text := fmt.Sprintf("false positive: lifted %d automatic %s, dismissed %d %s", n, plural(n, "block", "blocks"),
			len(dismissed), plural(len(dismissed), "recommendation", "recommendations"))
		tctx, cancel := context.WithTimeout(context.Background(), sideTimeout)
		if err := r.o.Timeline(tctx, incidentID, siem.IncidentEvent{TS: r.now().UTC(), Kind: siem.TimelineResponse,
			Actor: actor, Text: text}); err != nil {
			r.logLimited("timeline", "security response: incident timeline entry not added", "incident", incidentID, "err", err)
		}
		cancel()
	}
	return n, err
}

// liftLocked is LiftForIncident's part under mu.
func (r *Responder) liftLocked(ctx context.Context, incidentID int64, actor string) (int, []siem.Response, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	if r.o.Blocks != nil {
		var err error
		if n, err = r.o.Blocks.UnblockIncident(ctx, incidentID, actor, ExemptFalsePos); err != nil {
			return 0, nil, err
		}
	}
	// The blocks are lifted by now: the recommendations are dismissed whatever became of the
	// request's context.
	dismissed, err := r.dismissIncident(context.WithoutCancel(ctx), incidentID, actor)
	return n, dismissed, err
}

func plural(n int, one, more string) string {
	if n == 1 {
		return one
	}
	return more
}

// dismissIncident dismisses the open recommendations of an incident (mu held).
func (r *Responder) dismissIncident(ctx context.Context, incidentID int64, actor string) ([]siem.Response, error) {
	open, err := r.query(ctx, `SELECT `+respCols+` FROM security_responses WHERE incident_id = ? AND state = ?
		ORDER BY id LIMIT ?`, incidentID, siem.ResponseRecommended, maxExpire)
	if err != nil {
		return nil, err
	}
	now := r.now()
	out := make([]siem.Response, 0, len(open))
	for _, x := range open {
		x.State, x.By, x.Updated = siem.ResponseDismissed, actor, now
		if err := r.settle(ctx, x); err != nil {
			return out, err
		}
		out = append(out, x)
	}
	return out, nil
}

// ownBlock is the block in force that names response x as its own (blocklist.Block.ResponseID).
func (r *Responder) ownBlock(ctx context.Context, x siem.Response) (blocklist.Block, bool) {
	p, err := netip.ParsePrefix(x.Target)
	if err != nil {
		return blocklist.Block{}, false
	}
	b, ok, err := r.o.Blocks.Get(ctx, p)
	if err != nil || !ok || b.ResponseID != x.ID || !b.Until.After(r.now()) {
		return blocklist.Block{}, false
	}
	if b.State != blocklist.StateActive && b.State != blocklist.StateSuspended {
		return blocklist.Block{}, false
	}
	return b, true
}
