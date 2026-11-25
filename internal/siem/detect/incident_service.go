package detect

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/daboss2003/mooring/internal/siem"
)

var _ siem.IncidentService = (*Engine)(nil)

var (
	errNotRunning = errors.New("detect: the engine is not running")
	errBusy       = errors.New("detect: the engine is busy, try again")
)

const (
	reqQueue      = 16
	reqTimeout    = 10 * time.Second
	reqEmitBudget = 100 * time.Millisecond
	maxAssignee   = siem.MaxShort // a Mooring user name (the caller checks it is one)
	maxActor      = siem.MaxShort
	maxEntityList = 50 // incidents listed on an entity's page
)

// A request's progress (incReq.st): queued, taken by the engine goroutine, or given up by its
// caller. Whoever moves it out of reqQueued first decides: an abandoned request is never applied.
const (
	reqQueued int32 = iota
	reqTaken
	reqAbandoned
)

// Dashboard changes of incidents go through the engine goroutine (Engine.reqs), so its incidents
// in memory stay the ones stored. A change is written to detect.db at once; the reply says whether
// it was. Mutes are written to Mooring's database by the caller's goroutine, never the engine's.

type incOp int

const (
	opState incOp = iota + 1
	opAssign
	opNote
	opFPPairs
	opFP
	opUnmuted
)

type incReq struct {
	op           incOp
	id           int64
	state, actor string
	text         string    // the note (opState, opNote, opFP), the assignee (opAssign)
	muted        int       // opFP: pairs muted; opState: the incident's mutes lifted
	until        time.Time // opFP: when they end
	rm           siem.Mute // opUnmuted
	reply        chan incReply
	st           atomic.Int32 // reqQueued, reqTaken, reqAbandoned
}

type incReply struct {
	err   error
	pairs []siem.Mute
}

// call hands a request to the engine goroutine and waits for its reply, at most reqTimeout or
// until ctx ends. A request the engine hasn't taken by then is abandoned (never applied, and the
// error says so); one it has taken is being applied, and its reply is waited for.
func (e *Engine) call(ctx context.Context, r *incReq) incReply {
	if e.closed.Load() {
		return incReply{err: errClosed}
	}
	if !e.running.Load() {
		return incReply{err: errNotRunning}
	}
	r.reply = make(chan incReply, 1)
	t := time.NewTimer(reqTimeout)
	defer t.Stop()
	select {
	case e.reqs <- r:
	case <-e.stopped:
		return incReply{err: errClosed}
	case <-ctx.Done():
		return incReply{err: ctx.Err()}
	case <-t.C:
		return incReply{err: errBusy}
	}
	var gaveUp error
	select {
	case rep := <-r.reply:
		return rep
	case <-e.stopped:
		gaveUp = errClosed
	case <-ctx.Done():
		gaveUp = ctx.Err()
	case <-t.C:
		gaveUp = errBusy
	}
	if r.st.CompareAndSwap(reqQueued, reqAbandoned) {
		return incReply{err: gaveUp}
	}
	// Taken: serve always replies (the reply channel has room), before Run can return.
	return <-r.reply
}

// serve applies one dashboard request (engine goroutine). The reply channel has room for the
// reply, so this never blocks on the caller.
func (e *Engine) serve(r *incReq) {
	if !r.st.CompareAndSwap(reqQueued, reqTaken) {
		return // Intentional: its caller gave up waiting and was told it failed: never applied.
	}
	var rep incReply
	defer func() {
		if p := recover(); p != nil {
			n := e.panics.Add(1)
			e.logLimited("panic", "security detection: incident change panicked", "panic", fmt.Sprint(p), "panics_total", n)
			rep = incReply{err: errors.New("detect: internal error")}
		}
		r.reply <- rep
	}()
	if e.closed.Load() {
		rep.err = errClosed
		return
	}
	e.emitUntil = time.Now().Add(reqEmitBudget)
	if r.op == opUnmuted {
		rep.err = e.unmuted(r)
		return
	}
	inc, found, err := e.incident(r.id)
	switch {
	case err != nil:
		rep.err = err
		return
	case !found:
		rep.err = invalidIn("no incident %d", r.id)
		return
	}
	if r.op == opFPPairs {
		rep.pairs, rep.err = e.fpPairs(inc)
		return
	}
	rep.err = e.change(inc, r)
}

// change applies a state, assignee, note or false-positive change to inc and stores it.
func (e *Engine) change(inc *incident, r *incReq) error {
	now := e.now()
	state, assignee := inc.state, inc.assignee
	var (
		entries []siem.IncidentEvent
		changes []incChange
	)
	entry := func(kind, text string, ch string) {
		entries = append(entries, siem.IncidentEvent{TS: now, Kind: kind, Actor: r.actor, Text: text})
		changes = append(changes, incChange{change: ch, actor: r.actor, text: text})
	}
	note := func() {
		if r.text != "" {
			entry(siem.TimelineNote, r.text, changeNote)
		}
	}
	switch r.op {
	case opState:
		if r.state != state {
			state = r.state
			entry(siem.TimelineState, state, changeState)
		}
		if r.muted > 0 {
			entry(siem.TimelineMuted, fmt.Sprintf("%d rule and entity %s unmuted: no longer a false positive", r.muted,
				plural(r.muted, "pair", "pairs")), changeUnmuted)
		}
		note()
	case opAssign:
		if r.text == assignee {
			return nil
		}
		assignee = r.text
		entry(siem.TimelineAssigned, assignee, changeAssigned)
	case opNote:
		note()
	case opFP:
		if state != siem.IncidentFalsePositive {
			state = siem.IncidentFalsePositive
			entry(siem.TimelineState, state, changeState)
		}
		if r.muted > 0 {
			entry(siem.TimelineMuted, fmt.Sprintf("%d rule and entity %s muted until %s", r.muted,
				plural(r.muted, "pair", "pairs"), r.until.UTC().Format("2006-01-02 15:04 UTC")), changeMuted)
		}
		note()
	}
	if len(entries) == 0 {
		return nil
	}
	if inc.manual+len(entries) > maxManual {
		return invalidIn("incident %d has %d changes and notes, the most it takes", inc.id, maxManual)
	}
	if err := e.db.applyChange(inc.id, state, assignee, now, entries); err != nil {
		if errors.Is(err, errIncidentGone) {
			e.forgetIncidents([]int64{inc.id})
			return invalidIn("no incident %d", inc.id)
		}
		e.writeErrors.Add(1)
		return err
	}
	reopened := !activeState(inc.state) && activeState(state)
	inc.state, inc.assignee, inc.updated = state, assignee, now
	inc.manual += len(entries)
	if reopened {
		e.reopened(inc, now)
	}
	for _, ch := range changes {
		e.emitIncident(inc, ch)
	}
	return nil
}

func plural(n int, one, more string) string {
	if n == 1 {
		return one
	}
	return more
}

// reopened indexes a reopened incident under its key entity again (closed ones are dropped from
// the index), and checks whether it owes an alert.
func (e *Engine) reopened(inc *incident, now time.Time) {
	e.indexKey(inc)
	if inc.alertSev >= rankHigh && (inc.alertSev > inc.alerted || (inc.realert > 0 && inc.alertSev >= 4)) {
		e.incOwed[inc] = struct{}{}
	}
}

// fpPairs returns the (rule, entity) pairs of an incident's detections keyed by its own key entity
// that can be muted (mutable): the stored detections' and those in memory not written yet.
// Intentional (owner decision): a detection that joined with another key to complete a chain (root's
// unusual sign-in in the incident of the address that brute-forced root) isn't muted, so a real
// takeover of that account still alerts.
func (e *Engine) fpPairs(inc *incident) ([]siem.Mute, error) {
	if inc.key.key == "" {
		return nil, nil
	}
	pairs, err := e.db.mutePairs(inc.id, inc.key, maxMutePairs+1)
	if err != nil {
		return nil, err
	}
	seen := map[muteKey]bool{}
	for _, p := range pairs {
		seen[muteKey{p.RuleID, entOf(p.Entity)}] = true
	}
	for a := range e.dirty {
		if a.inc != inc && (a.s.incID == 0 || a.s.incID != inc.id) {
			continue
		}
		k, ok := keyEntity(&a.s)
		if !ok || k != inc.key || seen[muteKey{a.s.d.RuleID, k}] {
			continue
		}
		if m := (siem.Mute{RuleID: a.s.d.RuleID, Entity: k.entity()}); mutable(m) {
			seen[muteKey{a.s.d.RuleID, k}] = true
			pairs = append(pairs, m)
		}
	}
	return pairs, nil
}

// unmuted records a removed mute in its incident's timeline (when it still exists) and emits it.
func (e *Engine) unmuted(r *incReq) error {
	k := entOf(r.rm.Entity)
	text := siem.Cut("mute removed: "+clean(r.rm.RuleID, maxRuleName)+" for "+k.label(), maxSummary)
	inc, found, err := e.incident(r.id)
	if err != nil || !found {
		return err
	}
	if inc.manual < maxManual {
		ok, err := e.db.addTimeline(inc.id, []siem.IncidentEvent{{TS: e.now(), Kind: siem.TimelineMuted,
			RuleID: r.rm.RuleID, Actor: r.actor, Text: text}})
		if err != nil {
			e.writeErrors.Add(1)
			return err
		}
		if !ok {
			e.forgetIncidents([]int64{inc.id})
			return nil
		}
		inc.manual++
	}
	e.emitIncident(inc, incChange{change: changeUnmuted, actor: r.actor, text: text})
	return nil
}

// Validation of the dashboard's input.

func checkText(what, s string, lo, hi int) error {
	if len(s) < lo || len(s) > hi {
		if lo > 0 {
			return invalidIn("%s must be %d to %d bytes", what, lo, hi)
		}
		return invalidIn("%s must be at most %d bytes", what, hi)
	}
	if !utf8.ValidString(s) {
		return invalidIn("%s is not valid UTF-8", what)
	}
	for _, c := range s {
		if (unicode.IsControl(c) && c != '\n' && c != '\r' && c != '\t') || c == utf8.RuneError {
			return invalidIn("%s holds a control character", what)
		}
	}
	return nil
}

// checkName checks a user name (actor, assignee): plain text on one line.
func checkName(what, s string, hi int) error {
	if err := checkText(what, s, 0, hi); err != nil {
		return err
	}
	if strings.ContainsAny(s, "\n\r\t") {
		return invalidIn("%s must be on one line", what)
	}
	return nil
}

// validEntity checks an entity: an account (key and scope) or an address (key, no scope).
func validEntity(x siem.Entity) error {
	if x.Kind != siem.EntityAccount && x.Kind != siem.EntityAddress {
		return invalidIn("unknown entity kind %q (account, address)", siem.Cut(x.Kind, 32))
	}
	if err := checkName("the entity key", x.Key, siem.MaxShort); err != nil {
		return err
	}
	if x.Key == "" {
		return invalidIn("the entity key is empty")
	}
	if x.Kind == siem.EntityAddress && x.Scope != "" {
		return invalidIn("an address has no scope")
	}
	return checkName("the entity scope", x.Scope, siem.MaxShort+4)
}

func checkID(id int64) error {
	if id <= 0 {
		return invalidIn("no incident %d", id)
	}
	return nil
}

// Incidents lists incidents, most recently active first (Last, then ID, descending), keyset-paged
// by f.BeforeLast and f.Before. Changes of the last writeEvery may not show yet.
func (e *Engine) Incidents(ctx context.Context, f siem.IncidentFilter) ([]siem.Incident, error) {
	if e.closed.Load() {
		return nil, errClosed
	}
	for _, s := range f.States {
		if !activeState(s) && s != siem.IncidentResolved && s != siem.IncidentFalsePositive {
			return nil, invalidIn("unknown state %q (open, acknowledged, resolved, false_positive)", siem.Cut(s, 32))
		}
	}
	if f.MinSeverity != "" && siem.SeverityRank(f.MinSeverity) == 0 {
		return nil, invalidIn("unknown severity %q (low, medium, high, critical)", siem.Cut(string(f.MinSeverity), 32))
	}
	if f.Entity != nil {
		if err := validEntity(*f.Entity); err != nil {
			return nil, err
		}
	}
	if err := checkName("the assignee", f.Assignee, maxAssignee); err != nil {
		return nil, err
	}
	return e.db.listIncidents(ctx, f)
}

// Incident returns one incident with its timeline (oldest first) and the false-positive mutes it
// made that are still in force.
func (e *Engine) Incident(ctx context.Context, id int64) (siem.Incident, bool, error) {
	if e.closed.Load() {
		return siem.Incident{}, false, errClosed
	}
	if id <= 0 {
		return siem.Incident{}, false, nil
	}
	inc, ok, err := e.db.getIncident(ctx, id)
	if ok && err == nil {
		inc.Mutes = e.incidentMutes(id)
	}
	return inc, ok, err
}

// SetState moves an incident to open, acknowledged or resolved; note ("" for none) is added to
// its timeline. Setting the state it has only adds the note. It lifts the false-positive mutes the
// incident made (it is no longer a false positive), recorded in its timeline.
func (e *Engine) SetState(ctx context.Context, id int64, state, actor, note string) error {
	switch state {
	case siem.IncidentOpen, siem.IncidentAcknowledged, siem.IncidentResolved:
	case siem.IncidentFalsePositive:
		return invalidIn("an incident is marked a false positive with MarkFalsePositive")
	default:
		return invalidIn("unknown state %q (open, acknowledged, resolved)", siem.Cut(state, 32))
	}
	if err := errors.Join(checkID(id), checkName("the actor", actor, maxActor), checkText("the note", note, 0, siem.MaxNote)); err != nil {
		return err
	}
	r := &incReq{op: opState, id: id, state: state, actor: actor, text: note}
	switch {
	case e.closed.Load():
		return errClosed
	case !e.running.Load():
		return errNotRunning
	}
	if e.ms != nil {
		// Intentional (owner decision): any move away from false_positive (every state SetState
		// sets) lifts the mutes the incident made. They go first, in Mooring's database on this
		// goroutine like every mute change. When the state change then fails, the incident stays a
		// false positive without them (more alerts, never fewer); setting the state again records it.
		n, err := e.liftMutes(ctx, id)
		if err != nil {
			return err
		}
		r.muted = n
	}
	return e.call(ctx, r).err
}

// Assign sets an incident's assignee ("" unassigns). The caller checks it is a Mooring user.
func (e *Engine) Assign(ctx context.Context, id int64, assignee, actor string) error {
	if err := errors.Join(checkID(id), checkName("the assignee", assignee, maxAssignee), checkName("the actor", actor, maxActor)); err != nil {
		return err
	}
	return e.call(ctx, &incReq{op: opAssign, id: id, actor: actor, text: assignee}).err
}

// AddNote adds a note (1–MaxNote bytes) to an incident's timeline.
func (e *Engine) AddNote(ctx context.Context, id int64, actor, text string) error {
	if strings.TrimSpace(text) == "" {
		return invalidIn("the note is empty")
	}
	if err := errors.Join(checkID(id), checkName("the actor", actor, maxActor), checkText("the note", text, 1, siem.MaxNote)); err != nil {
		return err
	}
	return e.call(ctx, &incReq{op: opNote, id: id, actor: actor, text: text}).err
}

// MarkFalsePositive sets an incident's state to false_positive; with mute, every (rule, key
// entity) pair of its detections is muted for 30 days first (in Mooring's database).
func (e *Engine) MarkFalsePositive(ctx context.Context, id int64, actor string, mute bool, note string) error {
	if err := errors.Join(checkID(id), checkName("the actor", actor, maxActor), checkText("the note", note, 0, siem.MaxNote)); err != nil {
		return err
	}
	r := &incReq{op: opFP, id: id, actor: actor, text: note}
	if mute {
		if e.ms == nil {
			return ErrNoStore
		}
		rep := e.call(ctx, &incReq{op: opFPPairs, id: id})
		if rep.err != nil {
			return rep.err
		}
		if len(rep.pairs) > maxMutePairs {
			return invalidIn("incident %d has more than %d rule and entity pairs to mute; mark it a false positive without muting", id, maxMutePairs)
		}
		r.until = e.now().Add(muteFor)
		// Intentional: the mutes are stored before the state; when the state change then fails, the
		// mutes stay (marking it again stores them again, and they can be removed on the entity page).
		if len(rep.pairs) > 0 {
			if err := e.addMutes(ctx, rep.pairs, r.until, actor, id); err != nil {
				return err
			}
		}
		r.muted = len(rep.pairs)
	}
	return e.call(ctx, r).err
}

// Entity returns an entity's risk score, its incidents (most recently active first, at most 50)
// and the mutes in force for it.
func (e *Engine) Entity(ctx context.Context, x siem.Entity) (siem.RiskScore, []siem.Incident, []siem.Mute, error) {
	if e.closed.Load() {
		return siem.RiskScore{}, nil, nil, errClosed
	}
	if err := validEntity(x); err != nil {
		return siem.RiskScore{}, nil, nil, err
	}
	k := entOf(x)
	now := e.now()
	rs, err := e.db.entityRisk(ctx, k, now)
	if err != nil {
		return siem.RiskScore{}, nil, nil, err
	}
	incs, err := e.db.entityIncidents(ctx, k, maxEntityList)
	if err != nil {
		return siem.RiskScore{}, nil, nil, err
	}
	var mutes []siem.Mute
	if ms := e.mutes.Load(); ms != nil {
		for mk, m := range ms.m {
			if mk.ent == k && m.Until.After(now) {
				mutes = append(mutes, m)
			}
		}
	}
	slices.SortFunc(mutes, func(a, b siem.Mute) int { return strings.Compare(a.RuleID, b.RuleID) })
	return rs, incs, mutes, nil
}

// RemoveMute removes a mute (from Mooring's database) and records it in the timeline of the
// incident it came from.
func (e *Engine) RemoveMute(ctx context.Context, ruleID string, x siem.Entity, actor string) error {
	if err := validEntity(x); err != nil {
		return err
	}
	if err := errors.Join(checkName("the rule ID", ruleID, siem.MaxShort), checkName("the actor", actor, maxActor)); err != nil {
		return err
	}
	if ruleID == "" {
		return invalidIn("the rule ID is empty")
	}
	if e.ms == nil {
		return ErrNoStore
	}
	k := muteKey{ruleID, entOf(x)}
	e.mu.Lock()
	m, had := e.muteRows[k]
	n, err := e.ms.del(ctx, ruleID, k.ent)
	if err != nil {
		e.mu.Unlock()
		return err
	}
	if !had && n == 0 {
		e.mu.Unlock()
		return invalidIn("no mute of rule %s for that entity", siem.Cut(ruleID, 80))
	}
	delete(e.muteRows, k)
	e.rebuildMutes()
	e.mu.Unlock()
	if m.IncidentID == 0 {
		return nil
	}
	m.RuleID, m.Entity = ruleID, x
	// Intentional: the mute is gone once deleted above; failing to add the timeline entry only logs.
	if rep := e.call(ctx, &incReq{op: opUnmuted, id: m.IncidentID, actor: actor, rm: m}); rep.err != nil {
		e.logLimited("unmute", "security detection: removed mute not recorded in its incident", "err", rep.err)
	}
	return nil
}

// Risky returns the entities with the highest current risk score (limit 1–100, default 20).
func (e *Engine) Risky(ctx context.Context, limit int) ([]siem.RiskScore, error) {
	if e.closed.Load() {
		return nil, errClosed
	}
	switch {
	case limit <= 0:
		limit = 20
	case limit > 100:
		limit = 100
	}
	return e.db.risky(ctx, limit, e.now())
}
