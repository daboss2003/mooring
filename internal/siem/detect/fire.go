package detect

import (
	"container/list"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/siem"
)

// maxSummary bounds Detection.Summary and an alert's summary (bytes); maxLists bounds a reported
// detection's Geo.Lists.
const (
	maxSummary = 300
	maxLists   = 16
)

// firing is what one rule evaluation found.
type firing struct {
	count    int     // events (or distinct values) behind it
	expected float64 // anomaly: the usual count per window
	value    string  // new_value: the new value
	from, to *point  // travel
	dist     float64 // travel: km
	gap      time.Duration
	evidence []siem.Evidence
}

// activeDet is a detection that later firings of its rule and key may still update.
type activeDet struct {
	s       stored // s.rollup: the rule's rollup detection for hour
	mapKey  string // mapKey(rule ID, key); a rollup's is rollupKey(rule ID)
	groupBy string
	seq     uint64    // creation order (writes and emits keep it)
	wrote   time.Time // last write attempt
	emitted bool      // the current state was emitted as an event
	elem    *list.Element
	parkEl  *list.Element // in parkLRU
	hour    time.Time
	mixed   bool       // rollup: its events concern several apps
	keys    *rolledSet // rollup: the keys counted in it this hour (nil once its hour is over)
}

// rolledSet is the keys counted in a rule's rollup detection for an hour, as 8-byte keyed hashes
// (saved with the hour's counters, so a key is counted once across a restart too).
// Intentional: hashes, not the keys (addresses, account names: personal data), keyed with
// HMAC-SHA256 under a random secret of the rollup's own (the rule is implicit), so the saved values
// can't be matched against hashes made anywhere else. Two keys with the same 8-byte value count
// once: a rare under-count of the rollup, about n²/2⁶⁵ for n keys (under 10⁻⁹ at the 100,000 kept).
type rolledSet struct {
	secret [16]byte
	m      map[uint64]struct{}
	mac    hash.Hash
}

const rolledVersion = 1

func newRolledSet() *rolledSet {
	s := &rolledSet{m: map[uint64]struct{}{}}
	_, _ = rand.Read(s.secret[:]) // never fails (Go 1.24+)
	return s
}

func (s *rolledSet) hash(key string) uint64 {
	if s.mac == nil {
		s.mac = hmac.New(sha256.New, s.secret[:])
	}
	s.mac.Reset()
	s.mac.Write([]byte(key))
	var b [sha256.Size]byte
	return binary.LittleEndian.Uint64(s.mac.Sum(b[:0]))
}

// encode is the version, the secret, then each hash (8 bytes, little-endian).
func (s *rolledSet) encode() []byte {
	b := make([]byte, 0, 1+len(s.secret)+8*len(s.m))
	b = append(b, rolledVersion)
	b = append(b, s.secret[:]...)
	for h := range s.m {
		b = binary.LittleEndian.AppendUint64(b, h)
	}
	return b
}

// decodeRolled reads a saved set, keeping at most limit hashes of it; nil when b isn't one.
func decodeRolled(b []byte, limit int) *rolledSet {
	const head = 1 + 16
	if len(b) < head || b[0] != rolledVersion || (len(b)-head)%8 != 0 {
		return nil
	}
	s := &rolledSet{m: make(map[uint64]struct{}, min((len(b)-head)/8, max(limit, 0)))}
	copy(s.secret[:], b[1:head])
	for p := b[head:]; len(p) >= 8 && len(s.m) < limit; p = p[8:] {
		s.m[binary.LittleEndian.Uint64(p)] = struct{}{}
	}
	return s
}

// mapKey is a (rule, key) pair's key in the engine's maps (active, parked, cooldown, inflight).
func mapKey(ruleID, key string) string { return ruleID + "\x00" + key }

// rollupKey is a rule's rollup detection's key in those maps. It never equals a mapKey: a rule ID
// holds no control character (built-in and custom IDs are validated, an /ops one is cleaned), so
// a mapKey's first control character is the "\x00" after the rule ID.
func rollupKey(ruleID string) string { return ruleID + "\x01" }

// dedupeKey is a detection's alert dedupe key: "siem:<rule ID>:<key>", a rollup's
// "siem-rollup:<rule ID>"; a rule's hourly summary alert's is "siem-cap:<rule ID>". A real key
// can't produce either of the last two.
func dedupeKey(a *activeDet) string {
	if a.s.rollup {
		return "siem-rollup:" + a.s.d.RuleID
	}
	return "siem:" + a.s.d.RuleID + ":" + a.s.d.Key
}

// findActive returns the detection a firing of (ruleID, key) may update: the one in memory (active
// or parked unwritten), else the newest stored one (looked up only when one may exist).
func (e *Engine) findActive(ruleID, key string) *activeDet {
	mk := mapKey(ruleID, key)
	if el, ok := e.active[mk]; ok {
		e.actLRU.MoveToFront(el)
		return el.Value.(*activeDet)
	}
	if a := e.parked[mk]; a != nil {
		e.unpark(a)
		e.track(a)
		return a
	}
	if e.closed.Load() || !e.known.may(mk) {
		return nil
	}
	now := e.now()
	if !e.readFailAt.IsZero() && now.Sub(e.readFailAt) < readBackoff {
		return nil
	}
	s, ok, err := e.db.latest(context.Background(), ruleID, key)
	if err != nil {
		e.readFailAt = now
		e.writeErrors.Add(1)
		e.logLimited("read", "security detection: detection lookup failed", "err", err)
		return nil
	}
	if !ok {
		return nil
	}
	// The key's cooldown holds across its detections: the row's alert counts for a new one too.
	e.noteCooldown(mk, s.alerted)
	a := &activeDet{s: s, mapKey: mk, emitted: true, wrote: now}
	e.seq++
	a.seq = e.seq
	e.track(a)
	return a
}

// putActive makes a new detection the active one of its key.
func (e *Engine) putActive(a *activeDet) {
	e.seq++
	a.seq = e.seq
	e.track(a)
}

// track puts a into active (keeping its seq), retiring the key's previous one and the least
// recently used ones over maxActive.
func (e *Engine) track(a *activeDet) {
	if el, ok := e.active[a.mapKey]; ok {
		e.retire(el)
	}
	a.elem = e.actLRU.PushFront(a)
	e.active[a.mapKey] = a.elem
	for e.actLRU.Len() > maxActive {
		e.retire(e.actLRU.Back())
	}
}

// retire forgets an active detection; a later firing finds it in the database, or among the
// parked ones while it is not written yet. It never writes: a busy or failing database never
// slows an event down.
func (e *Engine) retire(el *list.Element) {
	a := el.Value.(*activeDet)
	e.actLRU.Remove(el)
	delete(e.active, a.mapKey)
	a.elem = nil
	if _, dirty := e.dirty[a]; dirty {
		e.park(a)
		return
	}
	e.known.add(a.mapKey)
}

// park keeps an unwritten detection until a flush writes it, at most maxParked of them: past that
// the oldest is dropped unwritten (only while writes keep failing).
func (e *Engine) park(a *activeDet) {
	a.parkEl = e.parkLRU.PushBack(a)
	if !a.s.rollup {
		e.parked[a.mapKey] = a
	}
	for e.parkLRU.Len() > maxParked {
		x := e.parkLRU.Front().Value.(*activeDet)
		e.unpark(x)
		delete(e.dirty, x)
		n := e.lost.Add(1)
		e.logLimited("lost", "security detection: detections dropped unwritten (detect.db writes keep failing)", "lost_total", n)
	}
}

func (e *Engine) unpark(a *activeDet) {
	if a.parkEl == nil {
		return
	}
	e.parkLRU.Remove(a.parkEl)
	a.parkEl = nil
	if e.parked[a.mapKey] == a {
		delete(e.parked, a.mapKey)
	}
}

// fire records a firing of rule c for key: a new detection, or an update of the one fired within
// the rule's window (at least an hour) before.
func (e *Engine) fire(c *compiled, key string, ev *siem.Event, f firing) {
	now := e.now()
	a := e.findActive(c.r.ID, key)
	isNew := a == nil || a.s.d.Source != siem.DetectionSIEM || ev.TS.Sub(a.s.d.Last) > max(c.r.Window, minCoalesce)
	if isNew {
		if !e.allowNew(c.r.ID) {
			base := siem.Detection{Source: siem.DetectionSIEM, RuleID: c.r.ID, RuleName: c.r.Name, Severity: c.r.Severity,
				MITRE: c.r.MITRE, App: ev.App, First: ev.TS, Last: ev.TS, Snoozed: c.r.SnoozedUntil.After(now)}
			e.rollUp(base, key, f.evidence, TargetSIEM)
			return
		}
		a = &activeDet{mapKey: mapKey(c.r.ID, key), s: stored{d: siem.Detection{Source: siem.DetectionSIEM,
			RuleID: c.r.ID, Key: strings.Clone(key), First: ev.TS, Last: ev.TS, Count: f.count}}}
		e.putActive(a)
	} else {
		a.s.d.Count = satInt(a.s.d.Count, f.count)
		if ev.TS.After(a.s.d.Last) {
			a.s.d.Last = ev.TS
		}
		if ev.TS.Before(a.s.d.First) {
			a.s.d.First = ev.TS
		}
	}
	d := &a.s.d
	a.groupBy = c.r.GroupBy
	d.RuleName, d.Severity, d.MITRE = c.r.Name, c.r.Severity, slices.Clone(c.r.MITRE)
	if ev.App != "" {
		d.App = strings.Clone(ev.App)
	}
	if ev.Geo != nil {
		d.Geo = cloneGeo(ev.Geo)
	}
	d.Evidence = appendEvidence(d.Evidence, f.evidence)
	d.Summary = summarize(c, d, f)
	d.Snoozed = c.r.SnoozedUntil.After(now)
	e.commit(a, TargetSIEM)
}

// syncHour starts the per-hour counters again when the wall-clock hour changed; a past hour's
// rollups are parked until written.
func (e *Engine) syncHour() time.Time {
	h := e.now().UTC().Truncate(time.Hour)
	if h.Equal(e.hour) {
		return h
	}
	e.hour = h
	clear(e.newRows)
	e.rolledN = 0
	for id, r := range e.rollups {
		r.keys = nil
		if _, dirty := e.dirty[r]; dirty {
			e.park(r)
		}
		delete(e.rollups, id)
	}
	return h
}

// allowNew reports whether rule may record a new detection this hour (and counts it).
func (e *Engine) allowNew(rule string) bool {
	e.syncHour()
	n, ok := e.newRows[rule]
	if !ok && len(e.newRows) >= maxRuleHours {
		return false
	}
	if n >= e.lim.newPerHour {
		return false
	}
	e.newRows[rule] = n + 1
	return true
}

// rollUp counts a firing of a rule past its new detections this hour in the rule's rollup
// detection for the hour: key RollupKey (marked rollup when stored, so a real key "*" is never
// taken for it), the count is the number of keys (each counted once).
func (e *Engine) rollUp(base siem.Detection, key string, evid []siem.Evidence, target string) {
	hour := e.syncHour()
	id := base.RuleID
	r := e.rollups[id]
	if r == nil {
		if len(e.rollups) >= maxRuleHours {
			n := e.lost.Add(1)
			e.logLimited("rollups", "security detection: too many rules over their hourly cap, firing not recorded", "lost_total", n)
			return
		}
		r = &activeDet{mapKey: rollupKey(id), hour: hour, keys: newRolledSet(),
			s: stored{rollup: true, d: siem.Detection{Source: base.Source, RuleID: id, Key: RollupKey, First: base.First,
				Last: base.Last, App: base.App, Service: base.Service}}}
		e.seq++
		r.seq = e.seq
		e.rollups[id] = r
	}
	d := &r.s.d
	if r.keys == nil {
		r.keys = newRolledSet()
	}
	h := r.keys.hash(key)
	if _, seen := r.keys.m[h]; !seen {
		// Past maxRolledKeys (all rules' rollups this hour) a key is counted at each firing (the
		// count may then be high).
		if e.rolledN < maxRolledKeys {
			r.keys.m[h] = struct{}{}
			e.rolledN++
		}
		d.Count = satInt(d.Count, 1)
	}
	if base.Last.After(d.Last) {
		d.Last = base.Last
	}
	if base.First.Before(d.First) {
		d.First = base.First
	}
	if !r.mixed && (d.App != base.App || d.Service != base.Service) {
		r.mixed, d.App, d.Service = true, "", ""
	}
	d.RuleName, d.Severity, d.MITRE, d.Snoozed = base.RuleName, base.Severity, slices.Clone(base.MITRE), base.Snoozed
	d.Evidence = appendEvidence(d.Evidence, evid)
	keys := "keys"
	if d.Count == 1 {
		keys = "key"
	}
	d.Summary = fmt.Sprintf("and %d more %s this hour (at most %d new detections per rule an hour)",
		d.Count, keys, e.lim.newPerHour)
	e.commit(r, target)
}

// commit marks a new or updated detection for writing (flush writes a new detection at its next
// run, an updated one at most every writeEvery) and alerts on it when due.
func (e *Engine) commit(a *activeDet, target string) {
	a.emitted = false
	e.dirty[a] = struct{}{}
	e.maybeAlert(a, target)
}

// alertJob is one alert for the worker. The worker only sends o; the engine goroutine reads the
// rest when the result comes back.
type alertJob struct {
	o         alert.Outbox
	mk        string     // the detection's mapKey (a rollup's rollupKey); "" for a summary alert
	rule      string     // the rule ID (its hourly cap)
	det       *activeDet // the detection it is about (never touched by the worker)
	at        time.Time  // when it was raised (engine time): the cooldown starts there
	hour      time.Time  // the wall-clock hour it counts in
	capped    bool       // a high detection's: counted in its rule's alerts this hour (given back if it fails)
	uncounted bool       // the detection was counted in this hour's summary before (counted again if it fails)
	more      int        // a summary alert's: the detections it counts
	tries     int        // the worker's
	next      time.Time  // the worker's: when to try again
}

type alertResult struct {
	job *alertJob
	ok  bool
}

// capKey is a rule's wall-clock hour (unix seconds) of high alerts. A past hour's summary that
// couldn't be queued yet is kept under its own hour, beside the current one.
type capKey struct {
	rule string
	hour int64
}

// capState is a rule's high alerts in one wall-clock hour.
type capState struct {
	hour   time.Time
	sent   int // alerts raised (queued, sent or being retried)
	more   int // detections counted for the summary (never sent on their own this hour)
	source string
	name   string
	target string
	late   bool // a previous hour's summary owed at startup (the process was killed): its text says so
}

// summaryText is a rule's summary alert message for cs.
func summaryText(cs *capState) string {
	what := "detections"
	if cs.more == 1 {
		what = "detection"
	}
	name := clean(cs.name, maxRuleName)
	if cs.late {
		h := cs.hour.UTC()
		return siem.Cut(fmt.Sprintf("%s: %d more %s in the previous hour (%s–%s UTC) — see the Detections page",
			name, cs.more, what, h.Format("2006-01-02 15:04"), h.Add(time.Hour).Format("15:04")), maxSummary)
	}
	return siem.Cut(fmt.Sprintf("%s: %d more %s this hour — see the Detections page", name, cs.more, what), maxSummary)
}

// noteCooldown records that an alert for a (rule, key) map key was raised at t (and sent), so the
// key alerts no more before t+alertCooldown.
func (e *Engine) noteCooldown(mk string, t time.Time) {
	if t.IsZero() {
		return
	}
	if old, ok := e.cooldown[mk]; ok && !old.Before(t) {
		return
	}
	e.cooldown[mk] = t
	if len(e.cooldown) > maxCooldowns {
		now := e.now()
		for k, t := range e.cooldown {
			if now.Sub(t) >= alertCooldown || len(e.cooldown) > maxCooldowns {
				delete(e.cooldown, k)
			}
		}
	}
}

// maybeAlert queues an alert for a high or critical detection that isn't snoozed, unless one for
// its rule and key was raised within alertCooldown (and sent) or is still in flight. A critical
// detection is then always alerted. A high one is not when its rule already raised
// lim.alertsPerHour high alerts this wall-clock hour: it is counted in the rule's summary alert for
// the hour instead (sendCaps).
func (e *Engine) maybeAlert(a *activeDet, target string) {
	d := &a.s.d
	if e.opt.Alerter == nil || d.Snoozed || siem.SeverityRank(d.Severity) < siem.SeverityRank(siem.SevHigh) {
		return
	}
	now := e.now()
	mk := a.mapKey
	if t, ok := e.inflight[mk]; ok && now.Sub(t) < inflightTTL && now.Sub(t) >= 0 {
		return
	}
	// Intentional: the cooldown is per rule and key on the wall clock, across detections and
	// restarts: a host-log backlog replayed after downtime can make several detections of one key
	// at once.
	// A recorded time in the future (the clock was ahead, then corrected) doesn't count: it would
	// mute the key until that time + the cooldown.
	if t, ok := e.cooldown[mk]; ok && now.Sub(t) < alertCooldown && now.Sub(t) >= 0 {
		return
	}
	if !a.s.alerted.IsZero() && now.Sub(a.s.alerted) < alertCooldown && now.Sub(a.s.alerted) >= 0 {
		return // sent before a restart (the stored detection's alerted time)
	}
	hour := now.UTC().Truncate(time.Hour)
	ck := capKey{d.RuleID, hour.Unix()}
	cs := e.caps[ck]
	crit := d.Severity == siem.SevCritical
	// Intentional (owner decisions): a critical detection is never held back by the cap; past it,
	// a high one is not sent on its own, the rule's one summary alert at the end of the hour counts
	// it.
	if !crit {
		if cs == nil {
			e.sendCaps(false) // a past hour's summaries first
			if len(e.caps) >= maxRuleHours {
				e.logLimited("caps", "security detection: too many rules alerting this hour, alert not sent", "rule", d.RuleID)
				return
			}
			cs = &capState{hour: hour, source: d.Source}
			e.caps[ck] = cs
		}
		cs.name, cs.target = d.RuleName, target
		if cs.sent >= e.lim.alertsPerHour {
			if !a.s.capHour.Equal(hour) {
				a.s.capHour = hour // stored with the detection (commit marked it for writing)
				cs.more++
			}
			return
		}
	}
	level := alert.LevelWarning
	if crit {
		level = alert.LevelCritical
	}
	j := &alertJob{mk: mk, rule: d.RuleID, det: a, at: now, hour: hour, capped: !crit,
		o: alert.Outbox{RuleID: 0, Target: target, Kind: AlertKind, Level: level, Transition: "firing",
			Summary:   siem.Cut(clean(d.RuleName, maxRuleName)+": "+d.Summary, maxSummary),
			DedupeKey: dedupeKey(a)}}
	if !e.enqueueAlert(j) {
		return
	}
	if !crit {
		cs.sent++
	}
	// Counted in this hour's summary before (no slot was free then, or it was high): now alerted
	// on its own, so the summary no longer counts it.
	if a.s.capHour.Equal(hour) {
		a.s.capHour, j.uncounted = time.Time{}, true
		if cs := e.caps[ck]; cs != nil && cs.more > 0 {
			cs.more--
		}
	}
	e.inflight[mk] = now
	if len(e.inflight) > 2*(alertQueue+maxRetrying) {
		for k, t := range e.inflight {
			if now.Sub(t) >= inflightTTL || now.Sub(t) < 0 {
				delete(e.inflight, k)
			}
		}
	}
}

// sendCaps queues the summary alert (a warning) of each rule that went past its cap in a finished
// hour (all: the current hour's too, at shutdown). A rule that is switched off, deleted or
// snoozed by then gets none; its detections stay recorded.
func (e *Engine) sendCaps(all bool) {
	now := e.now()
	hour := now.UTC().Truncate(time.Hour)
	for k, cs := range e.caps {
		current := !cs.hour.Before(hour)
		if !all && current {
			continue
		}
		queued := false
		if cs.more > 0 && e.summaryWanted(k.rule, cs.source, now) {
			j := &alertJob{rule: k.rule, hour: cs.hour, more: cs.more, o: alert.Outbox{RuleID: 0, Target: cs.target,
				Kind: AlertKind, Level: alert.LevelWarning, Transition: "firing", DedupeKey: "siem-cap:" + k.rule,
				Summary: summaryText(cs)}}
			queued = e.enqueueAlert(j)
			// A full queue: tried again at the next tick, for at most two hours.
			if !queued && !all && hour.Sub(cs.hour) < 2*time.Hour {
				continue
			}
		}
		if all && current {
			// Intentional: at shutdown the current hour's summary goes out at once, but the hour's
			// counters stay for the last save (persist), so after a restart within the hour the rule
			// has no more alerts than it had left, and the summary at the end of the hour counts only
			// what this one didn't (one not queued or not wanted now is still owed then).
			if queued {
				cs.more = 0
			}
			continue
		}
		if !queued && cs.more > 0 {
			// Not sent (not wanted, or the queue stayed full): settled, so its saved count goes at the
			// next save and a start after a kill doesn't send it late. A queued one is settled when
			// its result comes back (finishAlert).
			e.hourDirty = true
		}
		delete(e.caps, k)
	}
}

// summaryWanted reports whether a rule's summary alert goes out now (owner decision: not for a
// rule switched off, deleted or snoozed when the hour ends). An app's /ops alert has no rule here
// to switch off or snooze: its summary always goes.
func (e *Engine) summaryWanted(ruleID, source string, now time.Time) bool {
	if source != siem.DetectionSIEM {
		return true
	}
	c := e.rules.Load().byID[ruleID]
	return c != nil && c.r.Enabled && !c.r.SnoozedUntil.After(now)
}

// finishAlert takes the worker's result for an alert (engine goroutine): a sent alert starts its
// rule and key's cooldown and is recorded on the detection; a failed one leaves both as they were,
// so the key's next firing alerts again (and gives back its slot under the rule's cap).
func (e *Engine) finishAlert(r alertResult) {
	j := r.job
	if j == nil {
		return
	}
	if j.mk == "" {
		// A summary alert. One that failed while its hour's counters are still kept (sent at
		// shutdown, see sendCaps) is owed again: its count goes back for the last save.
		if cs := e.caps[capKey{j.rule, j.hour.Unix()}]; !r.ok && cs != nil {
			cs.more = satInt(cs.more, j.more)
		}
		// Intentional: the saved counters are brought up to date once the summary is settled (sent
		// or given up), at the next write tick: a start after a kill then sends no late copy of it.
		// Saving when it is queued instead could lose it to a kill before it is recorded. The outbox
		// and detect.db can't commit together, so a kill within that tick can still send it twice.
		e.hourDirty = true
		return
	}
	if t, ok := e.inflight[j.mk]; ok && t.Equal(j.at) {
		delete(e.inflight, j.mk)
	}
	if !r.ok {
		cs := e.caps[capKey{j.rule, j.hour.Unix()}]
		if cs == nil {
			return
		}
		if j.capped && cs.sent > 0 {
			cs.sent--
		}
		if j.uncounted { // never alerted on its own after all: the summary counts it again
			cs.more++
			j.det.s.capHour = j.hour
			if a := e.current(j); a != nil {
				a.s.capHour = j.hour
				e.dirty[a] = struct{}{} // stored with its next write; emitted stays as it was
			}
		}
		return
	}
	e.noteCooldown(j.mk, j.at)
	if a := e.current(j); a != nil {
		if a.s.alerted.Before(j.at) {
			a.s.alerted = j.at
			e.dirty[a] = struct{}{} // stored with its next write; emitted stays as it was
		}
	} else if id := j.det.s.d.ID; id != 0 && (len(e.alertedRows) < maxCooldowns || e.alertedRows[id] != 0) {
		// Written and gone from memory since (evicted, or a newer detection of its key took its
		// place): the time goes on its row with the next write, so a restart keeps the cooldown.
		e.alertedRows[id] = max(e.alertedRows[id], j.at.UnixNano())
	}
}

// current is the in-memory detection a job's result belongs to, nil when it is gone (a newer copy
// read back from the database counts when it is the same detection).
func (e *Engine) current(j *alertJob) *activeDet {
	a := j.det
	if a == nil {
		return nil
	}
	if a.s.rollup {
		if e.rollups[a.s.d.RuleID] == a || a.parkEl != nil {
			return a
		}
		return nil
	}
	if el, ok := e.active[a.mapKey]; ok {
		if x := el.Value.(*activeDet); x == a || (a.s.d.ID != 0 && x.s.d.ID == a.s.d.ID) {
			return x
		}
	}
	if e.parked[a.mapKey] == a {
		return a
	}
	return nil
}

// flush writes the detections that are due: new ones, and updated ones last written writeEvery
// ago or more (all of them when force), at most maxBatch per transaction. After a failed write it
// waits writeBackoff before trying again (force too: shutdown tries once).
func (e *Engine) flush(force bool) {
	e.emitUntil = time.Now().Add(emitBudget)
	now := e.now()
	if !force && e.writeBackoff > 0 && now.Sub(e.writeFailAt) < e.writeBackoff {
		return
	}
	due := make([]*activeDet, 0, len(e.dirty))
	for a := range e.dirty {
		if force || a.s.d.ID == 0 || now.Sub(a.wrote) >= writeEvery {
			due = append(due, a)
		}
	}
	slices.SortFunc(due, func(x, y *activeDet) int { return cmpInt(int64(x.seq), int64(y.seq)) })
	ok := true
	for len(due) > 0 {
		n := min(len(due), maxBatch)
		ok = e.writeBatch(due[:n])
		due = due[n:]
		if !force || !ok {
			break // the rest waits for the next run
		}
	}
	if ok && len(e.alertedRows) > 0 {
		e.markAlerted(now)
	}
}

// markAlerted stores the alert times of detections no longer in memory (see finishAlert).
func (e *Engine) markAlerted(now time.Time) {
	err := errClosed
	if !e.closed.Load() {
		err = e.db.markAlerted(context.Background(), e.alertedRows)
	}
	if err != nil {
		e.writeErrors.Add(1)
		e.writeFailAt = now
		e.writeBackoff = min(max(2*e.writeBackoff, writeBackoffMin), writeBackoffMax)
		e.logLimited("write", "security detection: alert times not stored", "count", len(e.alertedRows), "err", err)
		return
	}
	clear(e.alertedRows)
}

// writeBatch stores detections (insert or update) in one transaction, then emits each as an
// event once per change. After a failed write they stay dirty (and findable) and nothing is
// emitted: a detection is emitted only once stored, with its ID.
func (e *Engine) writeBatch(as []*activeDet) bool {
	now := e.now()
	var (
		ids []int64
		err = errClosed
	)
	if !e.closed.Load() {
		ss := make([]*stored, len(as))
		for i, a := range as {
			ss[i] = &a.s
		}
		ids, err = e.db.writeBatch(context.Background(), ss)
	}
	for _, a := range as {
		a.wrote = now
	}
	if err != nil {
		e.writeErrors.Add(1)
		e.writeFailAt = now
		e.writeBackoff = min(max(2*e.writeBackoff, writeBackoffMin), writeBackoffMax)
		e.logLimited("write", "security detection: detections not stored", "count", len(as), "err", err)
		return false
	}
	e.writeBackoff = 0
	for i, a := range as {
		if a.s.d.ID != 0 && ids[i] != a.s.d.ID {
			a.emitted = false // stored again under a new ID (its row was removed): emitted with it
		}
		a.s.d.ID = ids[i]
		delete(e.dirty, a)
		if a.parkEl != nil {
			e.unpark(a)
			if !a.s.rollup {
				e.known.add(a.mapKey)
			}
		}
		if !a.emitted {
			e.emit(a)
			a.emitted = true
		}
	}
	return true
}

// emit hands a detection to the pipeline as a siem.detection event.
func (e *Engine) emit(a *activeDet) {
	if e.opt.Emit == nil {
		return
	}
	d := &a.s.d
	ev := siem.Event{TS: e.now().UTC(), Src: siem.SrcSIEM, Kind: KindDetection, Lvl: levelOf(d.Severity),
		App: d.App, Svc: d.Service, Geo: cloneGeo(d.Geo), Msg: d.Summary,
		F: map[string]any{"rule": d.RuleID, "severity": string(d.Severity), "count": float64(d.Count),
			"detection_id": float64(d.ID)}}
	if len(d.MITRE) > 0 {
		ev.F["mitre"] = strings.Join(d.MITRE, ",")
	}
	if d.Key != "" {
		ev.F["key"] = d.Key
	}
	if !a.s.rollup {
		switch a.groupBy {
		case "ip":
			// An IPv6 key is a /64: ip is then the newest address behind the detection.
			if _, err := netip.ParseAddr(d.Key); err == nil {
				ev.IP = d.Key
			} else if n := len(d.Evidence); n > 0 {
				ev.IP = d.Evidence[n-1].IP
			}
		case "actor", "f.account":
			ev.Actor = d.Key
		}
	}
	// Intentional: a full emit lane is waited on (the pipeline drains it), within emitBudget per
	// flush, instead of dropping at once: a burst — the final flush at shutdown — would otherwise lose
	// the searchable events of detections whose rows are stored. A stalled pipeline costs at most the
	// budget, after which the rest are dropped and counted.
	for !e.opt.Emit(ev) {
		if !time.Now().Before(e.emitUntil) {
			e.emitDropped.Add(1)
			return
		}
		time.Sleep(emitRetry)
	}
}

func levelOf(s siem.Severity) string {
	switch s {
	case siem.SevMedium:
		return siem.LvlWarn
	case siem.SevHigh:
		return siem.LvlError
	case siem.SevCritical:
		return siem.LvlCritical
	}
	return siem.LvlInfo
}

func (e *Engine) enqueueAlert(j *alertJob) bool {
	if e.opt.Alerter == nil {
		return false
	}
	select {
	case e.alerts <- j:
		return true
	default:
		n := e.alertsDropped.Add(1)
		e.logLimited("alerts", "security detection: alert queue full, alert dropped", "dropped_total", n)
		return false
	}
}

// alertWorker writes queued alerts to the alert outbox, one at a time, each within alertTimeout.
// A failed write is tried again after lim.alertBackoff (alertTries attempts in all), meanwhile the
// next alerts go ahead. It is the only path from the engine to Mooring's database. Each result
// goes back to the engine goroutine (finishAlert). At shutdown it keeps going for up to
// alertTimeout on what is queued or waiting for a retry, one attempt each.
func (e *Engine) alertWorker(ctx context.Context) {
	var retry []*alertJob
	attempt := func(j *alertJob) {
		actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), e.lim.alertTimeout)
		err := e.opt.Alerter.EnqueueInfra(actx, j.o)
		cancel()
		j.tries++
		if err == nil {
			e.result(j, true)
			return
		}
		if j.tries < alertTries && j.tries-1 < len(e.lim.alertBackoff) && len(retry) < maxRetrying && ctx.Err() == nil {
			j.next = time.Now().Add(e.lim.alertBackoff[j.tries-1])
			retry = append(retry, j)
			e.logLimited("alert", "security detection: alert not recorded, will retry", "err", err)
			return
		}
		n := e.alertsFailed.Add(1)
		e.logLimited("alert-failed", "security detection: alert not recorded, given up", "dedupe_key", j.o.DedupeKey,
			"tries", j.tries, "err", err, "failed_total", n)
		e.result(j, false)
	}
	// stop spends at most one alert timeout on what is queued or waiting for a retry, one attempt each.
	stop := func(first []*alertJob) {
		deadline := time.Now().Add(e.lim.alertTimeout)
		waiting := append(first, retry...)
		retry = nil
		for time.Now().Before(deadline) {
			select {
			case j := <-e.alerts:
				attempt(j)
			default:
				if len(waiting) == 0 {
					return
				}
				attempt(waiting[0])
				waiting = waiting[1:]
			}
		}
	}
	for {
		// Intentional: shutdown is checked before anything else. A select with both the cancelled
		// context and a queued alert ready picks at random, and each queued alert taken the normal
		// way can hang for a whole alert timeout against a stalled database.
		if ctx.Err() != nil {
			stop(nil)
			return
		}
		var wake <-chan time.Time
		if len(retry) > 0 {
			next := retry[0].next
			for _, j := range retry[1:] {
				if j.next.Before(next) {
					next = j.next
				}
			}
			wake = time.After(time.Until(next))
		}
		select {
		case <-ctx.Done():
			stop(nil)
			return
		case j := <-e.alerts:
			if ctx.Err() != nil {
				stop([]*alertJob{j})
				return
			}
			attempt(j)
		case <-wake:
			now := time.Now()
			var due []*alertJob
			keep := retry[:0]
			for _, j := range retry {
				if j.next.After(now) {
					keep = append(keep, j)
				} else {
					due = append(due, j)
				}
			}
			retry = keep
			for i, j := range due {
				if ctx.Err() != nil {
					retry = append(retry, due[i:]...) // the shutdown pass at the loop's top takes them
					break
				}
				attempt(j)
			}
		}
	}
}

// result hands an alert's outcome back to the engine goroutine; it never blocks (a lost result
// only means the key's alert stops counting as in flight after inflightTTL).
func (e *Engine) result(j *alertJob, ok bool) {
	select {
	case e.results <- alertResult{job: j, ok: ok}:
	default:
	}
}

// report records an app /ops detection (siem.Reporter, on the engine goroutine).
func (e *Engine) report(r siem.Detection) {
	now := e.now()
	r.Source = siem.DetectionOps
	if r.RuleID = clean(r.RuleID, siem.MaxShort); r.RuleID == "" {
		return
	}
	if siem.SeverityRank(r.Severity) == 0 {
		r.Severity = siem.SevMedium
	}
	if r.RuleName = clean(r.RuleName, maxRuleName); r.RuleName == "" {
		r.RuleName = r.RuleID
	}
	r.Key, r.App, r.Service = clean(r.Key, siem.MaxShort), clean(r.App, siem.MaxShort), clean(r.Service, siem.MaxShort)
	r.Summary = clean(r.Summary, maxSummary)
	r.MITRE = slices.DeleteFunc(r.MITRE, func(t string) bool { return !reMITRE.MatchString(t) })
	r.MITRE = r.MITRE[:min(len(r.MITRE), maxMITRE)]
	r.Count = min(max(r.Count, 1), math.MaxInt32)
	for i := range r.Evidence {
		x := &r.Evidence[i]
		x.Kind, x.IP, x.Actor, x.App = clean(x.Kind, siem.MaxShort), clean(x.IP, siem.MaxShort),
			clean(x.Actor, siem.MaxShort), clean(x.App, siem.MaxShort)
	}
	if g := r.Geo; g != nil {
		g.Country, g.City, g.Org = clean(g.Country, 8), clean(g.City, siem.MaxShort), clean(g.Org, siem.MaxShort)
		g.Lists = g.Lists[:min(len(g.Lists), maxLists)]
		for i := range g.Lists {
			g.Lists[i] = clean(g.Lists[i], 64)
		}
	}
	if r.Last.IsZero() || !timely(r.Last, now) {
		r.Last = now
	}
	if r.First.IsZero() || r.First.After(r.Last) {
		r.First = r.Last
	}
	r.First, r.Last = r.First.UTC(), r.Last.UTC()
	r.ID = 0
	target := r.App
	if r.Service != "" {
		target += "/" + r.Service
	}
	if target == "" {
		target = "ops"
	}

	a := e.findActive(r.RuleID, r.Key)
	if isNew := a == nil || a.s.d.Source != siem.DetectionOps || r.Last.Sub(a.s.d.Last) > minCoalesce; isNew {
		if !e.allowNew(r.RuleID) {
			e.rollUp(r, r.Key, r.Evidence, target)
			return
		}
		r.Evidence = appendEvidence(nil, r.Evidence)
		a = &activeDet{mapKey: mapKey(r.RuleID, r.Key), s: stored{d: r}}
		e.putActive(a)
	} else {
		d := &a.s.d
		d.Count = satInt(d.Count, r.Count)
		if r.Last.After(d.Last) {
			d.Last = r.Last
		}
		d.RuleName, d.Severity, d.MITRE, d.Summary, d.Snoozed = r.RuleName, r.Severity, r.MITRE, r.Summary, r.Snoozed
		d.App, d.Service, d.Geo = r.App, r.Service, r.Geo
		d.Evidence = appendEvidence(d.Evidence, r.Evidence)
	}
	e.commit(a, target)
}

func satInt(a, b int) int {
	if b > 0 && a > math.MaxInt32-b {
		return math.MaxInt32
	}
	return a + b
}

func appendEvidence(have, add []siem.Evidence) []siem.Evidence {
	out := append(slices.Clone(have), add...)
	if len(out) > siem.MaxEvidence {
		out = out[len(out)-siem.MaxEvidence:]
	}
	for i := range out {
		out[i].TS = out[i].TS.UTC()
	}
	return out
}

func cloneGeo(g *siem.Geo) *siem.Geo {
	if g == nil {
		return nil
	}
	c := *g
	c.City, c.Org = strings.Clone(c.City), strings.Clone(c.Org)
	c.Lists = slices.Clone(c.Lists)
	return &c
}

// clean makes event-supplied text safe for a one-line summary that goes to chat channels: control
// and format characters are removed, and so are '<', '>', '@' and '`'.
// Intentional: without those four, a user name like "<!channel>" or "@everyone" would notify a
// Slack or Discord channel. The value is then cut to n bytes.
func clean(s string, n int) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t' || r == '\r':
			b.WriteByte(' ')
		case r == utf8RuneError, unicode.IsControl(r), unicode.Is(unicode.Cf, r), r == '<', r == '>', r == '@', r == '`':
		default:
			b.WriteRune(r)
		}
		if b.Len() > n+4 {
			break
		}
	}
	return siem.Cut(strings.TrimSpace(b.String()), n)
}

const utf8RuneError = '�'

// place is "City, CC" (or what of it is known).
func place(g *siem.Geo) string {
	if g == nil {
		return ""
	}
	city, cc := clean(g.City, 40), clean(g.Country, 8)
	switch {
	case city != "" && cc != "":
		return city + ", " + cc
	case city != "":
		return city
	}
	return cc
}

// geoLabel is " (Lagos, NG; AS37148 Example)" for an IP's location, "" when nothing is known.
func geoLabel(g *siem.Geo) string {
	if g == nil {
		return ""
	}
	var parts []string
	if p := place(g); p != "" {
		parts = append(parts, p)
	}
	if g.ASN != 0 {
		as := "AS" + strconv.FormatUint(uint64(g.ASN), 10)
		if org := clean(g.Org, 40); org != "" {
			as += " " + org
		}
		parts = append(parts, as)
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, "; ") + ")"
}

// subject names a detection's key: the address with its location, the actor, "app web", … word,
// when set, names what the key is instead ("account backdoor").
func subject(groupBy, word, key string, g *siem.Geo) string {
	k := clean(key, 80)
	if k == "" {
		return ""
	}
	switch {
	case groupBy == "":
		return ""
	case word != "":
		return word + " " + k
	case groupBy == "ip":
		return k + geoLabel(g)
	case groupBy == "actor", groupBy == "kind":
		return k
	case groupBy == "app":
		return "app " + k
	case groupBy == "geo.cc":
		return "country " + k
	case groupBy == "geo.asn":
		return "AS" + k
	}
	return strings.TrimPrefix(groupBy, "f.") + " " + k
}

// shownValue is a new_value detection's value as the summary shows it: only fields that hold no
// free text.
func shownValue(field, v string) string {
	switch field {
	case "ip", "actor", "app", "kind", "geo.cc":
		return clean(v, 64)
	case "geo.asn":
		return "AS" + clean(v, 16)
	}
	return ""
}

// fieldWord names a custom rule's Field in a summary ("country", "distinct addresses").
func fieldWord(field string, many bool) string {
	one, more := map[string][2]string{
		"ip": {"address", "distinct addresses"}, "actor": {"actor", "distinct actors"}, "app": {"app", "distinct apps"},
		"kind": {"kind", "distinct kinds"}, "geo.cc": {"country", "distinct countries"},
		"geo.asn": {"network", "distinct networks"},
	}[field], many
	switch {
	case one[0] == "" && more:
		return "distinct values of " + field
	case one[0] == "":
		return field
	case more:
		return one[1]
	}
	return one[0]
}

// summarize words a detection on one line: "<key> — <what happened>".
func summarize(c *compiled, d *siem.Detection, f firing) string {
	noun := c.info.noun
	if noun == "" {
		noun = "matching events"
	}
	field := c.info.fieldNoun
	if field == "" {
		field = fieldWord(c.r.Field, c.r.Type == siem.RuleDistinct)
	}
	span := max(c.r.Window, d.Last.Sub(d.First))
	var what string
	switch c.r.Type {
	case siem.RuleThreshold:
		what = fmt.Sprintf("%d %s in %s", d.Count, noun, fmtDur(span))
	case siem.RuleDistinct:
		what = fmt.Sprintf("%d %s in %s", d.Count, field, fmtDur(span))
	case siem.RuleNewValue:
		v := shownValue(c.r.Field, f.value)
		if v == "" {
			v = "value"
		}
		what = "new " + field + " " + v
		if d.Count > 1 {
			what = fmt.Sprintf("%d new %s values, the latest %s", d.Count, field, v)
		}
	case siem.RuleAnomaly:
		what = fmt.Sprintf("%d %s in %s, usually about %s", f.count, noun, fmtDur(c.r.Window), fmtNum(f.expected))
	case siem.RuleTravel:
		from, to := "an unknown place", "an unknown place"
		if f.from != nil && f.from.place != "" {
			from = f.from.place
		}
		if f.to != nil && f.to.place != "" {
			to = f.to.place
		}
		what = fmt.Sprintf("%s from %s and %s %s apart (%d km)", noun, from, to, fmtDur(f.gap), int(math.Round(f.dist)))
	case siem.RuleSequence:
		then := c.info.thenNoun
		if then == "" {
			then = "a closing event"
		}
		what = fmt.Sprintf("%d %s then %s", d.Count, noun, then)
	}
	s := what
	if sub := subject(c.r.GroupBy, c.info.subject, d.Key, d.Geo); sub != "" {
		s = sub + " — " + what
	}
	return siem.Cut(s, maxSummary)
}

func fmtNum(v float64) string {
	if v < 10 {
		return strconv.FormatFloat(math.Round(v*10)/10, 'f', -1, 64)
	}
	return strconv.FormatFloat(math.Round(v), 'f', -1, 64)
}

// fmtDur writes a duration as "45s", "10m", "1h30m", "7d".
func fmtDur(d time.Duration) string {
	d = d.Round(time.Second)
	if d <= 0 {
		return "0s"
	}
	if d >= 24*time.Hour && d%(24*time.Hour) == 0 {
		return strconv.FormatInt(int64(d/(24*time.Hour)), 10) + "d"
	}
	h, m, s := d/time.Hour, (d%time.Hour)/time.Minute, (d%time.Minute)/time.Second
	var b strings.Builder
	if h > 0 {
		b.WriteString(strconv.FormatInt(int64(h), 10) + "h")
	}
	if m > 0 {
		b.WriteString(strconv.FormatInt(int64(m), 10) + "m")
	}
	if s > 0 && h == 0 {
		b.WriteString(strconv.FormatInt(int64(s), 10) + "s")
	}
	if b.Len() == 0 {
		return "0s"
	}
	return b.String()
}
