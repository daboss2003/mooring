package detect

import (
	"context"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/query"
)

// Automated response (phase 4): the requests the engine makes for its rules' responses
// (Rule.Response, applied by internal/siem/respond), and which responses a rule may take.

const (
	minBlockDuration   = 5 * time.Minute
	maxBlockDuration   = 7 * 24 * time.Hour
	maxResponseEntries = 100 // response entries one incident's timeline takes
	// blockAskEvery: a detection asks for its block at most this often, however often it fires. The
	// responder skips a request for an address that is still blocked.
	blockAskEvery = 5 * time.Minute
	// maxSignOuts: the accounts a detection remembers having asked a sign-out for.
	maxSignOuts = 32
)

// respondCommit is called by commit, on the engine goroutine, after correlate (so a.s.d.Muted and
// the incident link are known). Every commit is a firing (fire; a rollup's and an app /ops report's
// ask nothing, see responseFor), and every firing is judged on its own: what sent the events it
// counted, the rule's snooze and the key's mute as they are now. A detection whose earlier firings
// asked for nothing asks at the first one that qualifies.
//   - A block is asked for at most every blockAskEvery per detection, and not while a request of
//     the detection still waits for its write.
//   - A sign-out is asked for once per detection and account (an address-keyed rule's detection
//     asks for each account that signs in from the address).
//
// Intentional: both memories are the activeDet's own, not stored. A detection read back from
// detect.db (after an eviction or a restart) may ask once more; the responder skips a block of an
// address still blocked, and its cooldown refuses a second sign-out of an account within the hour.
func (e *Engine) respondCommit(a *activeDet) {
	if e.opt.Responder == nil {
		return
	}
	req, ok := e.responseFor(a)
	if !ok {
		return
	}
	switch req.Action {
	case siem.ResponseBlock:
		now := e.now()
		// Intentional: a last request in the future (the clock stepped back) doesn't hold the next.
		if len(a.resp) > 0 || (!a.blockAsked.IsZero() && !now.Before(a.blockAsked) && now.Sub(a.blockAsked) < blockAskEvery) {
			return
		}
		a.blockAsked = now
	case siem.ResponseRevoke:
		if slices.Contains(a.signedOut, req.Target) {
			return
		}
		// Intentional: past maxSignOuts the oldest account is forgotten, so it may be asked for again
		// (refused by the responder's cooldown) rather than a new account never be asked for.
		if len(a.signedOut) >= maxSignOuts {
			a.signedOut = a.signedOut[:copy(a.signedOut, a.signedOut[len(a.signedOut)-maxSignOuts+1:])]
		}
		a.signedOut = append(a.signedOut, strings.Clone(req.Target))
	}
	a.resp = append(a.resp, req)
	// Intentional: while detect.db writes fail, the request goes at once, without the detection's
	// ID, rather than waiting on a write that may not come. A written detection's has its ID already.
	if e.writeBackoff > 0 || a.s.d.ID != 0 {
		e.sendResponses(a)
	}
}

// respondWritten is called by writeBatch for each written detection, once it (and its incident)
// have their IDs: its waiting requests go to Options.Responder.
func (e *Engine) respondWritten(a *activeDet) {
	e.sendResponses(a)
}

// respondUnwritten is called by writeBatch after a failed write: every request still waiting for
// its detection's write goes now, without the detection's ID, oldest detection first.
func (e *Engine) respondUnwritten() {
	var waiting []*activeDet
	for a := range e.dirty {
		if len(a.resp) > 0 {
			waiting = append(waiting, a)
		}
	}
	slices.SortFunc(waiting, func(x, y *activeDet) int { return cmpInt(int64(x.seq), int64(y.seq)) })
	for _, a := range waiting {
		e.sendResponses(a)
	}
}

// respondDropped is called by park for a detection dropped unwritten: its requests go now.
func (e *Engine) respondDropped(a *activeDet) {
	e.sendResponses(a)
}

// sendResponses sends a detection's waiting requests (once: they are cleared), with the
// detection's ID and incident ID when they are known.
func (e *Engine) sendResponses(a *activeDet) {
	waiting := a.resp
	a.resp = nil
	d := &a.s.d
	for _, req := range waiting {
		req.DetectionID, req.IncidentID = d.ID, a.s.incID
		if req.IncidentID == 0 && a.inc != nil {
			req.IncidentID = a.inc.id
		}
		req.Summary, req.At = d.Summary, e.now()
		if !e.opt.Responder.Respond(req) {
			e.logLimited("respond", "security detection: response request not taken (the responder's queue is full)",
				"rule", req.RuleID, "action", req.Action)
		}
	}
}

// responseFor is the request a detection's firing makes, if any (owner decisions):
//   - none for a rollup, an app /ops detection, a muted or snoozed one, or a rule switched off;
//   - a block only of an address the edge saw or an app's log reported. It is automatic only when
//     every source the rule's query lets through is the edge (compiled.autoBlock): a rule that also
//     counts an app's events only recommends, whichever event fired it (an app says what the
//     address is, so its events are forgeable). Addresses in Mooring's and the host's logs are never
//     blocked;
//   - unless the rule needs a listed address: no block when a browser sent any event counted in the
//     firing (a web page can make its visitors' browsers send requests anywhere), and a
//     recommendation only when one came with a browser's or a mail client's agent (sentBy). The
//     address baseline's firings say so too (baseline_ip.go);
//   - a sign-out only of a Mooring account: the key of an actor-keyed rule, or the account of the
//     last event (the successful sign-in) of an address-keyed one.
func (e *Engine) responseFor(a *activeDet) (siem.ResponseRequest, bool) {
	d := &a.s.d
	if a.s.rollup || d.Source != siem.DetectionSIEM || d.Muted || d.Snoozed || d.Key == "" || d.Key == RollupKey {
		return siem.ResponseRequest{}, false
	}
	c := e.rules.Load().byID[d.RuleID]
	if c == nil || !c.r.Enabled {
		return siem.ResponseRequest{}, false
	}
	resp := c.r.Response
	// The rule's query is checked again here (validation did at its save): a stored rule that no
	// longer validates never acts.
	if resp.Action == "" || !slices.Contains(c.respOK, resp.Action) {
		return siem.ResponseRequest{}, false
	}
	req := siem.ResponseRequest{Action: resp.Action, RuleID: d.RuleID, RuleName: d.RuleName, Severity: d.Severity}
	switch resp.Action {
	case siem.ResponseBlock:
		if a.s.entKind != siem.EntityAddress {
			return siem.ResponseRequest{}, false
		}
		switch sc := a.s.scope; {
		case sc == siem.SrcEdge:
			req.Automatic = c.autoBlock
		case sc == siem.SrcApp || strings.HasPrefix(sc, siem.SrcApp+":"):
		default:
			return siem.ResponseRequest{}, false
		}
		// Intentional: only a rule that needs the address on a threat list blocks on a browser's
		// request (the address itself is listed); any other rule, one-event ones included, could be
		// steered onto a web page's visitors.
		if !needsList(c.q) {
			switch {
			case a.byBrowser:
				return siem.ResponseRequest{}, false
			case a.byAgent:
				req.Automatic = false
			// Intentional: the address baseline records what sent the requests it counted (ipSlot), so
			// its block follows the rules above (owner decision). No other baseline kind is keyed by an
			// address today (validateBaseline); one that were would keep counts of its own without the
			// senders, so its block is a recommendation.
			case c.r.Type == siem.RuleBaseline && c.r.Baseline != siem.BaselineIP:
				req.Automatic = false
			}
		}
		req.Target, req.Duration = d.Key, resp.Duration
	case siem.ResponseRevoke:
		if a.s.scope != siem.SrcMooring {
			return siem.ResponseRequest{}, false
		}
		switch c.r.GroupBy {
		case "actor":
			if a.s.entKind == siem.EntityAccount {
				req.Target = d.Key
			}
		case "ip":
			if n := len(d.Evidence); n > 0 {
				req.Target = d.Evidence[n-1].Actor
			}
		}
		if req.Target == "" {
			return siem.ResponseRequest{}, false
		}
		req.Automatic = true
	}
	return req, true
}

// needsList reports whether q matches only events whose address is on a threat list (a positive
// list: term).
func needsList(q query.Query) bool {
	return slices.ContainsFunc(q.Terms, func(t query.Term) bool { return t.Field == "list" && !t.Neg && t.Value != "" })
}

// RuleResponses reports the response actions a rule may take, or why it may take none.
func (e *Engine) RuleResponses(r siem.Rule) (actions []string, why string) {
	return ruleResponses(r)
}

// Event sources a rule's query may match, as a set.
const (
	srcEdgeBit = 1 << iota
	srcAppBit
	srcMooringBit
	srcHostBit
)

var srcBits = []struct {
	src string
	bit int
}{{siem.SrcEdge, srcEdgeBit}, {siem.SrcApp, srcAppBit}, {siem.SrcMooring, srcMooringBit}, {siem.SrcHost, srcHostBit}}

// sources is the set of sources whose events q's src terms let through.
func sources(q query.Query) int {
	set := 0
	for _, s := range srcBits {
		if termsAccept(q, "src", &siem.Event{Src: s.src}) {
			set |= s.bit
		}
	}
	return set
}

// ruleSources is the sources a rule lets through: its query's, and for a sequence its closing
// query's too (none when either lets none through).
func ruleSources(q, then query.Query, sequence bool) int {
	srcs := sources(q)
	if sequence {
		last := sources(then)
		if srcs == 0 || last == 0 {
			return 0
		}
		srcs |= last
	}
	return srcs
}

// termsAccept reports whether every term of q on field matches ev (the other terms aside).
func termsAccept(q query.Query, field string, ev *siem.Event) bool {
	for _, t := range q.Terms {
		if t.Field == field && !(query.Query{Terms: []query.Term{t}}).Match(ev) {
			return false
		}
	}
	return true
}

// successOnly reports whether q's out terms let through successful events only: not failures,
// not events without an outcome, not any other outcome.
func successOnly(q query.Query) bool {
	accepts := func(out string) bool { return termsAccept(q, "out", &siem.Event{Out: out}) }
	return accepts(siem.OutSuccess) && !accepts(siem.OutFailure) && !accepts("") && !accepts("other")
}

const whyMooringAddr = "Mooring sign-in addresses are your allowlisted addresses; Mooring can't block them"

// responseChecks says, for each action, why the rule can't take it ("": it can), from its query
// and group-by alone:
//   - block: keyed by address (group by ip), and the query (both queries of a sequence) lets through
//     only the edge's events or an app's; with an app's, the block is a recommendation only (see
//     responseFor). Mooring's own sign-in addresses are inside ip_allowlist, and the host's reach
//     SSH and ports the edge doesn't front;
//   - revoke: keyed by account (actor) or address (ip, taking the sign-in's account); the query
//     (both queries of a sequence) lets through Mooring's events only, as an app's and the host's
//     log lines are forgeable and would count toward a Mooring account's sign-out; and the query (a
//     sequence's closing query) lets through successful events only: anyone can make sign-ins fail
//     on purpose.
func responseChecks(r siem.Rule) (blockWhy, revokeWhy string) {
	q, err := query.Parse(r.Query)
	if err != nil {
		return "The rule's query doesn't parse", "The rule's query doesn't parse"
	}
	succ, then, closing, seq := q, query.Query{}, "query", r.Type == siem.RuleSequence
	if seq {
		if then, err = query.Parse(r.Then); err != nil {
			return "The rule's closing query doesn't parse", "The rule's closing query doesn't parse"
		}
		succ, closing = then, "closing query"
	}
	srcs := ruleSources(q, then, seq)
	switch {
	case r.GroupBy != "ip":
		blockWhy = "Blocks need detections keyed by an address (group by ip)"
	case srcs == 0:
		blockWhy = "The rule's query matches no source"
	case srcs&^srcMooringBit == 0:
		blockWhy = whyMooringAddr
	case srcs&^srcHostBit == 0:
		blockWhy = "Addresses in the host's logs reach SSH and other ports the edge doesn't front; Mooring can't block them"
	case srcs&^(srcEdgeBit|srcAppBit) != 0:
		blockWhy = "Blocks need the edge's own address: this rule's query doesn't pin src:edge (or src:app, for recommendations only)"
	}
	// Intentional: the sign-in baseline rule is the one rule over several sources that may sign out.
	// Each of its firings is one sign-in compared with that account's own habit, kept per source, and
	// its detections are kept apart per source (fire), so only a Mooring sign-in makes a detection of
	// Mooring's scope, the only one responseFor signs out. A rule that counts events would count an
	// app's or the host's toward it.
	mooringOnly := srcs == srcMooringBit || (r.Type == siem.RuleBaseline && r.Baseline == siem.BaselineSignIn)
	switch {
	case r.GroupBy != "ip" && r.GroupBy != "actor":
		revokeWhy = "Sign-outs need detections keyed by an account (group by actor) or an address (group by ip)"
	case srcs&srcMooringBit == 0 || sources(succ)&srcMooringBit == 0:
		revokeWhy = "Sign-outs are for Mooring accounts: this rule doesn't match Mooring's own events"
	case !mooringOnly && seq:
		revokeWhy = "Sign-outs are for Mooring accounts: both of the rule's queries must pin src:mooring"
	case !mooringOnly:
		revokeWhy = "Sign-outs are for Mooring accounts: the rule's query must pin src:mooring"
	case !successOnly(succ):
		revokeWhy = "Sign-outs only follow successful Mooring sign-ins: the rule's " + closing + " must require out:success"
	}
	return blockWhy, revokeWhy
}

// ruleResponses is RuleResponses (see responseChecks).
func ruleResponses(r siem.Rule) (actions []string, why string) {
	if r.GroupBy != "ip" && r.GroupBy != "actor" {
		return nil, "Responses need detections keyed by an address (group by ip) or an account (group by actor)"
	}
	blockWhy, revokeWhy := responseChecks(r)
	switch {
	case blockWhy == "":
		return []string{siem.ResponseBlock}, ""
	case revokeWhy == "":
		return []string{siem.ResponseRevoke}, ""
	case r.GroupBy == "actor":
		return nil, revokeWhy
	case blockWhy == whyMooringAddr:
		return nil, whyMooringAddr + ", and sign-outs only follow successful sign-ins"
	case strings.Contains(revokeWhy, "must pin src:mooring"):
		// An address-keyed rule that also matches Mooring's events could do either: both reasons.
		return nil, blockWhy + ". " + revokeWhy
	}
	return nil, blockWhy
}

// validResponse checks a rule's response (validate): one its query and group-by allow
// (responseChecks), a block of 5m to 7d. A sign-out's duration, and that of no response, is cleared.
func validResponse(r *siem.Rule) error {
	switch r.Response.Action {
	case "":
		r.Response.Duration = 0
		return nil
	case siem.ResponseBlock:
		if err := checkRange("the block duration", r.Response.Duration, minBlockDuration, maxBlockDuration, showDur); err != nil {
			return err
		}
	case siem.ResponseRevoke:
		r.Response.Duration = 0
	default:
		return invalid("unknown response %q (block, revoke)", siem.Cut(r.Response.Action, 32))
	}
	why, revokeWhy := responseChecks(*r)
	if r.Response.Action == siem.ResponseRevoke {
		why = revokeWhy
	}
	if why != "" {
		return invalid("%s", why)
	}
	return nil
}

// NoteResponse adds a response entry (siem.TimelineResponse) to an incident's timeline, through the
// engine goroutine; the responder calls it. The entry's text is one line of at most maxSummary
// bytes; an incident takes at most maxResponseEntries of them (more are left out without an error).
func (e *Engine) NoteResponse(ctx context.Context, incidentID int64, ev siem.IncidentEvent) error {
	if incidentID <= 0 {
		return invalidIn("no incident %d", incidentID)
	}
	if oneLine(ev.Text, maxSummary) == "" {
		return invalidIn("the entry is empty")
	}
	return e.call(ctx, &incReq{op: opResponse, id: incidentID, ev: ev}).err
}

// oneLine is s without control and format characters, on one line, cut to n bytes.
// Intentional: unlike clean, '@', '<', '>' and '`' stay: a timeline entry is shown on the page only
// (never in an alert), and a username may hold an '@'.
func oneLine(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t' || r == '\r':
			b.WriteByte(' ')
		case r == utf8RuneError, unicode.IsControl(r), unicode.Is(unicode.Cf, r):
		default:
			b.WriteRune(r)
		}
		if b.Len() > n+4 {
			break
		}
	}
	return siem.Cut(strings.TrimSpace(b.String()), n)
}

// noteResponse stores a response entry (serve, engine goroutine).
func (e *Engine) noteResponse(r *incReq) error {
	now := e.now()
	ev := siem.IncidentEvent{TS: r.ev.TS.UTC(), Kind: siem.TimelineResponse, DetectionID: max(r.ev.DetectionID, 0),
		RuleID: clean(r.ev.RuleID, siem.MaxShort), RuleName: clean(r.ev.RuleName, maxRuleName),
		Actor: oneLine(r.ev.Actor, maxActor), Text: oneLine(r.ev.Text, maxSummary)}
	if ev.TS.IsZero() || ev.TS.After(now.Add(maxSkew)) {
		ev.TS = now.UTC()
	}
	if siem.SeverityRank(r.ev.Severity) > 0 {
		ev.Severity = r.ev.Severity
	}
	added, found, err := e.db.addResponseEntry(r.id, ev)
	switch {
	case err != nil:
		e.writeErrors.Add(1)
		return err
	case !found:
		e.forgetIncidents([]int64{r.id})
		return invalidIn("no incident %d", r.id)
	case !added:
		e.logLimited("response-entries", "security detection: incident has its most response entries, entry left out",
			"incident", r.id)
	}
	return nil
}

// addResponseEntry stores a response entry in an incident's timeline unless it has
// maxResponseEntries already (added false); found is false when there is no such incident.
func (d *db) addResponseEntry(id int64, ev siem.IncidentEvent) (added, found bool, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	tx, err := d.w.BeginTx(ctx, nil)
	if err != nil {
		return false, false, err
	}
	defer func() { _ = tx.Rollback() }()
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM incidents WHERE id = ?`, id).Scan(&n); err != nil || n == 0 {
		return false, false, err
	}
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM incident_timeline WHERE incident_id = ? AND kind = ?`,
		id, siem.TimelineResponse).Scan(&n); err != nil {
		return false, true, err
	}
	if n >= maxResponseEntries {
		return false, true, nil
	}
	if err := insertTimeline(ctx, tx, id, ev); err != nil {
		return false, true, err
	}
	return true, true, tx.Commit()
}
