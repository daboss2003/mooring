package detect

import (
	"fmt"
	"maps"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/siem"
)

// Incidents (docs/security-incidents.md): detections of one account or address (their key) within
// 24 hours are grouped in one incident, with a timeline, a workflow state and one alert. The
// engine goroutine owns every structure here; the dashboard's changes reach it through Engine.reqs
// (incident_service.go).

const (
	incJoinWindow   = 24 * time.Hour // detections of one key entity within this join one incident
	chainWindow     = 24 * time.Hour // the two steps of a known chain are at most this far apart
	maxIncEntities  = 50             // entities kept on an incident
	maxIncRules     = 20             // rule IDs listed on an incident
	maxDetEntities  = 1 + 2*siem.MaxEvidence
	maxSpanRules    = 64 // rules an incident's chain check keeps detections of
	maxSpansPerRule = 8  // detections kept per rule for the chain check (the most recently seen)
	maxTimeline     = 500
	maxManual       = 400  // state, assignee, note and mute entries one incident's timeline takes
	maxIncCache     = 2000 // incidents kept in memory (past it the flush drops idle ones)
	maxIncNew       = 2000 // incidents not written yet (writes failing); past it detections alert on their own
	maxEntIndex     = 20000
	maxEntIncs      = 8 // incidents remembered per entity (the ones a detection of it may join)
	maxRisk         = 20000
	riskHalfLife    = 72 * time.Hour
	riskCap         = 100
	riskFloor       = 1 // a score faded below this is dropped
	incAlertRetry   = time.Minute
	incQueueRetry   = 10 * time.Second
	// incNoIDAlert: an incident still not written this long after it opened (or while writes fail)
	// alerts its detections on their own: its alert needs its ID.
	incNoIDAlert   = 5 * time.Second
	chainTitleRank = 5 // above every severity: a chain's title is never replaced by a detection's

	// KindIncident is the kind of the security event each incident change is emitted as.
	KindIncident = "siem.incident"
	// IncidentAlertKind is the alert kind of an incident's alert.
	IncidentAlertKind = "security_incident"
)

// Incident changes (the "change" field of a siem.incident event).
const (
	changeOpened    = "opened"
	changeEscalated = "escalated"
	changeState     = "state"
	changeAssigned  = "assigned"
	changeNote      = "note"
	changeMuted     = "muted"
	changeUnmuted   = "unmuted"
)

// riskWeight is what a detection adds to each of its entities' risk score, by severity rank.
var riskWeight = [5]float64{0, 5, 15, 35, 60}

// incEnt is an entity as a map key.
type incEnt struct{ kind, scope, key string }

func entOf(e siem.Entity) incEnt { return incEnt{e.Kind, e.Scope, e.Key} }

func (k incEnt) entity() siem.Entity { return siem.Entity{Kind: k.kind, Key: k.key, Scope: k.scope} }

// String is "address:203.0.113.7" or "account:host:root".
func (k incEnt) String() string {
	if k.kind == siem.EntityAddress {
		return k.kind + ":" + k.key
	}
	return k.kind + ":" + k.scope + ":" + k.key
}

// label names an entity on one line: "203.0.113.7", "account root (host)".
func (k incEnt) label() string {
	if k.kind == siem.EntityAddress {
		return clean(k.key, 80)
	}
	return "account " + clean(k.key, 80) + " (" + clean(k.scope, 64) + ")"
}

func activeState(s string) bool { return s == siem.IncidentOpen || s == siem.IncidentAcknowledged }

func rankSeverity(r int) siem.Severity {
	switch r {
	case 1:
		return siem.SevLow
	case 2:
		return siem.SevMedium
	case 3:
		return siem.SevHigh
	case 4:
		return siem.SevCritical
	}
	return ""
}

const rankHigh = 3

// addressEntity is an event address as an entity: its key (ipKey: IPv6 as its /64), or false
// when it isn't an address, or is a loopback or unspecified one.
func addressEntity(ip string) (incEnt, bool) {
	k := ipKey(strings.TrimSpace(ip))
	var a netip.Addr
	if p, err := netip.ParsePrefix(k); err == nil {
		a = p.Addr()
	} else if a, err = netip.ParseAddr(k); err != nil {
		return incEnt{}, false
	}
	if a.IsLoopback() || a.IsUnspecified() {
		return incEnt{}, false
	}
	return incEnt{kind: siem.EntityAddress, key: siem.Cut(k, siem.MaxShort)}, true
}

// incKeyKind is the kind of entity a detection's key is, from its rule's group-by: an address for
// "ip", an account for "actor", "f.account", "f.target", and for "f.user" when the event has it
// (host.user_change falls back to f.group, which is no account). "" for any other group-by.
func incKeyKind(groupBy, key string, ev *siem.Event) string {
	switch groupBy {
	case "ip":
		if _, ok := addressEntity(key); ok {
			return siem.EntityAddress
		}
	case "actor", "f.account", "f.target":
		if key != "" {
			return siem.EntityAccount
		}
	case "f.user":
		if s, ok := ev.F["user"].(string); ok && s != "" && key != "" {
			return siem.EntityAccount
		}
	}
	return ""
}

// incScope is the account scope of an event's source: "mooring", "host", "app:<slug>", "edge".
func incScope(ev *siem.Event) string {
	switch ev.Src {
	case siem.SrcApp:
		if ev.App == "" {
			return "app"
		}
		return "app:" + siem.Cut(ev.App, siem.MaxShort)
	case "":
		return ""
	}
	return siem.Cut(ev.Src, 32)
}

// keyEntity is a detection's key as an entity (false: its key is no account or address).
func keyEntity(s *stored) (incEnt, bool) {
	switch s.entKind {
	case siem.EntityAddress:
		return incEnt{kind: siem.EntityAddress, key: s.d.Key}, s.d.Key != ""
	case siem.EntityAccount:
		return incEnt{kind: siem.EntityAccount, scope: s.scope, key: s.d.Key}, s.d.Key != ""
	}
	return incEnt{}, false
}

// detEntities is a detection's entities: its key, then the addresses and accounts of its evidence
// events (an evidence actor takes the detection's scope, or the evidence's app for an app scope).
// Intentional: the user name of an ssh.invalid_user event is a name the server doesn't have, so
// it is no account.
func detEntities(s *stored) []incEnt {
	out := make([]incEnt, 0, 4)
	add := func(k incEnt) {
		if k.key != "" && len(out) < maxDetEntities && !slices.Contains(out, k) {
			out = append(out, k)
		}
	}
	if k, ok := keyEntity(s); ok {
		add(k)
	}
	for _, x := range s.d.Evidence {
		if k, ok := addressEntity(x.IP); ok {
			add(k)
		}
		if x.Actor != "" && x.Kind != siem.KindSSHInvalidUser && s.scope != "" {
			scope := s.scope
			if strings.HasPrefix(scope, "app") && x.App != "" {
				scope = "app:" + siem.Cut(x.App, siem.MaxShort)
			}
			add(incEnt{kind: siem.EntityAccount, scope: scope, key: siem.Cut(x.Actor, siem.MaxShort)})
		}
	}
	return out
}

// incident is one incident in memory (the engine goroutine's).
type incident struct {
	id            int64
	seq           uint64 // creation order (new incidents are written in it)
	state         string
	sev, alertSev int // ranks: shown severity; the one its alert goes by (rules not snoozed)
	alerted       int // the highest rank an alert was recorded for
	alertedAt     time.Time
	title         string
	titleRank     int // the rank of the detection the title is from; chainTitleRank: the chain's
	chain         string
	// key is its opener's key entity (ents[0] as stored): the one that indexes it for every join.
	// keys: the other key entities of its detections, which joined it to complete a chain
	// (chainJoined), known in memory; realert: critical alerts owed for such keys.
	key              incEnt
	keys             []incEnt
	realert          int
	ents             []incEnt // at most maxIncEntities, in the order they joined
	entTimes         map[incEnt]*entSpan
	first, last      time.Time
	ndet             int
	rules            []string
	assignee         string
	created, updated time.Time
	manual           int // state, assignee, note and mute entries in its timeline

	// Detections per rule for the chain check, in the order the rules joined. Read back from
	// detect.db the first time an incident loaded from it is checked.
	spans       map[string][]incSpan
	spanRules   []string
	spansLoaded bool

	used     time.Time // last looked at (the cache keeps the most recently used)
	urgent   bool      // written at the next flush; otherwise at most every writeEvery
	wrote    time.Time
	entDirty map[incEnt]struct{}
	tl       []incTL     // timeline entries not written yet
	changes  []incChange // siem.incident events owed once it is written
	// jobs are the alerts in flight that count for it (its own, and its detections' own alerts it
	// waits on), with when each was raised: one not reported back within inflightTTL no longer counts.
	jobs    map[*alertJob]time.Time
	retryAt time.Time
	gone    bool // removed from detect.db (retention, size cap, the dashboard): never written again
}

func (inc *incident) addJob(j *alertJob, at time.Time) {
	if inc.jobs == nil {
		inc.jobs = map[*alertJob]time.Time{}
	}
	inc.jobs[j] = at
}

// busy reports whether an alert that counts for it is in flight (dropping the ones past
// inflightTTL, or raised at a time ahead of now: the clock was corrected).
func (inc *incident) busy(now time.Time) bool {
	for j, at := range inc.jobs {
		if d := now.Sub(at); d >= inflightTTL || d < 0 {
			delete(inc.jobs, j)
		}
	}
	return len(inc.jobs) > 0
}

type entSpan struct{ first, last time.Time }

// incSpan is one detection of an incident, for the chain check.
type incSpan struct {
	id          int64  // the detection's ID (0: not written yet)
	seq         uint64 // its activeDet's seq (while it is in memory)
	first, last time.Time
	snoozed     bool
	ents        []incEnt
}

// incTL is a timeline entry not written yet; det is the detection of a detection entry.
type incTL struct {
	ev  siem.IncidentEvent
	det *activeDet
}

// incChange is a siem.incident event owed once the incident is written.
type incChange struct{ change, actor, text string }

// entRef is one of an entity's incidents: inc while it is in memory, else its ID.
type entRef struct {
	inc  *incident
	id   int64
	last time.Time // the entity's latest detection in it (its last event)
}

// latestRef is the latest detection time of an entity's refs.
func latestRef(refs []*entRef) time.Time {
	var t time.Time
	for _, r := range refs {
		if r.last.After(t) {
			t = r.last
		}
	}
	return t
}

type riskEntry struct {
	score float64
	at    time.Time
}

// riskNow is r's score faded to now (half of it every riskHalfLife).
func riskNow(r riskEntry, now time.Time) float64 {
	dt := now.Sub(r.at)
	if dt <= 0 {
		return r.score
	}
	return r.score * math.Exp2(-float64(dt)/float64(riskHalfLife))
}

// riskRank orders scores by their current value whatever now is: log2(score) + at/half-life.
func riskRank(score float64, at time.Time) float64 {
	return math.Log2(max(score, 1e-9)) + float64(at.UnixNano())/float64(riskHalfLife)
}

// chainDef is a known chain: a detection of a rule in first, and one of a different rule in then
// whose detections share an entity (of kind shared, any when ""), the second within chainWindow of
// the first (ordered: then not before first). It raises the incident to critical.
type chainDef struct {
	name        string
	first, then map[string]bool
	shared      string
	ordered     bool
}

func idSet(ids ...string) map[string]bool {
	m := make(map[string]bool, len(ids))
	for _, id := range ids {
		m[id] = true
	}
	return m
}

var (
	bruteForceRules = []string{"ssh.bruteforce", "ssh.spray", "mooring.login_bruteforce", "mooring.login_spray",
		"app.auth_bruteforce", "app.auth_spray"}
	// unusualSignInRules: a successful sign-in that is out of the ordinary (place, speed, a listed or
	// Tor address, the sign-in baseline).
	unusualSignInRules = []string{"ssh.login_new_country", "mooring.login_new_country", "app.auth_new_country",
		"app.admin_new_country", "ssh.login_travel", "mooring.login_travel", "baseline.signin_unusual",
		"ssh.login_spamhaus_ip", "ssh.login_dshield_ip", "app.admin_spamhaus_ip", "app.admin_dshield_ip",
		"ssh.login_tor", "mooring.login_tor", "app.admin_tor_login"}
	// signInRules: any detection of a successful sign-in.
	signInRules = append([]string{"ssh.success_after_failures", "mooring.login_success_after_failures",
		"app.auth_success_after_failures"}, unusualSignInRules...)
	changeRules = []string{"mooring.user_change", "app.privilege_change", "host.user_change", "sudo.failures",
		"baseline.admin_unusual"}
	listedRules = []string{"ssh.login_spamhaus_ip", "ssh.login_dshield_ip", "mooring.api_token_spamhaus_ip",
		"mooring.api_token_dshield_ip", "app.admin_spamhaus_ip", "app.admin_dshield_ip", "edge.spamhaus_ip",
		"edge.dshield_ip"}

	// chains are checked in order; the first that matches names the incident.
	chains = []chainDef{
		// T1110 Brute Force → T1078 Valid Accounts.
		{name: "Brute force then sign-in", first: idSet(bruteForceRules...), then: idSet(signInRules...), ordered: true},
		// T1078 Valid Accounts → T1098 Account Manipulation / T1136 Create Account / T1548 Abuse
		// Elevation Control Mechanism.
		{name: "Account takeover", first: idSet(unusualSignInRules...), then: idSet(changeRules...),
			shared: siem.EntityAccount, ordered: true},
		// T1078 Valid Accounts from an address on a threat-intelligence list.
		{name: "Listed address with access", first: idSet(listedRules...), then: idSet(signInRules...),
			shared: siem.EntityAddress},
	}
)

// chainRules is every rule of a chain step.
var chainRules = func() map[string]bool {
	m := map[string]bool{}
	for _, ch := range chains {
		maps.Copy(m, ch.first)
		maps.Copy(m, ch.then)
	}
	return m
}()

func (c *chainDef) inOrder(a, b *incSpan) bool {
	if b.first.Sub(a.last) > chainWindow {
		return false
	}
	if c.ordered {
		return !a.first.After(b.last)
	}
	return a.first.Sub(b.last) <= chainWindow
}

func sharedEntity(a, b []incEnt, kind string) (incEnt, bool) {
	for _, x := range a {
		if (kind == "" || x.kind == kind) && slices.Contains(b, x) {
			return x, true
		}
	}
	return incEnt{}, false
}

// matchChain returns the first known chain the incident's detections make, and the entity its two
// steps share; alerting: only detections of rules that weren't snoozed count.
func (inc *incident) matchChain(alerting bool) (*chainDef, incEnt, bool) {
	for i := range chains {
		if k, ok := inc.matches(&chains[i], alerting); ok {
			return &chains[i], k, true
		}
	}
	return nil, incEnt{}, false
}

// matches reports whether the incident's detections make chain ch, and the entity its steps share.
func (inc *incident) matches(ch *chainDef, alerting bool) (incEnt, bool) {
	for _, ra := range inc.spanRules {
		if !ch.first[ra] {
			continue
		}
		for _, rb := range inc.spanRules {
			if rb == ra || !ch.then[rb] {
				continue
			}
			as, bs := inc.spans[ra], inc.spans[rb]
			for x := range as {
				sa := &as[x]
				if alerting && sa.snoozed {
					continue
				}
				for y := range bs {
					sb := &bs[y]
					if alerting && sb.snoozed {
						continue
					}
					if !ch.inOrder(sa, sb) {
						continue
					}
					if k, ok := sharedEntity(sa.ents, sb.ents, ch.shared); ok {
						return k, true
					}
				}
			}
		}
	}
	return incEnt{}, false
}

// chainWith reports whether a detection of rule (span sp) makes chain ch with one of the
// incident's detections of the chain's other step, both listing entity k.
func (inc *incident) chainWith(ch *chainDef, rule string, sp *incSpan, k incEnt) bool {
	if (ch.shared != "" && k.kind != ch.shared) || !slices.Contains(sp.ents, k) {
		return false
	}
	for _, r := range inc.spanRules {
		asThen, asFirst := ch.first[r] && ch.then[rule], ch.first[rule] && ch.then[r]
		if r == rule || (!asThen && !asFirst) {
			continue
		}
		for i := range inc.spans[r] {
			o := &inc.spans[r][i]
			if slices.Contains(o.ents, k) && ((asThen && ch.inOrder(o, sp)) || (asFirst && ch.inOrder(sp, o))) {
				return true
			}
		}
	}
	return false
}

// madeWith reports whether the incident's detections make chain ch with two steps that both list
// entity k (of the kind the chain shares).
func (inc *incident) madeWith(ch *chainDef, k incEnt) bool {
	if ch.shared != "" && k.kind != ch.shared {
		return false
	}
	for _, ra := range inc.spanRules {
		if !ch.first[ra] {
			continue
		}
		for _, rb := range inc.spanRules {
			if rb == ra || !ch.then[rb] {
				continue
			}
			for x := range inc.spans[ra] {
				sa := &inc.spans[ra][x]
				if !slices.Contains(sa.ents, k) {
					continue
				}
				for y := range inc.spans[rb] {
					if sb := &inc.spans[rb][y]; slices.Contains(sb.ents, k) && ch.inOrder(sa, sb) {
						return true
					}
				}
			}
		}
	}
	return false
}

// completes reports whether detection a (keyed by key, listing ents) is the missing step of a known
// chain in inc: inc holds a detection of the chain's other step that lists key too, in order and
// within chainWindow, and doesn't make that chain for key yet (made for another account of the same
// spray, it is made again for this one).
func (e *Engine) completes(inc *incident, a *activeDet, ents []incEnt, key incEnt) bool {
	d := &a.s.d
	e.loadSpans(inc)
	sp := incSpan{first: d.First, last: d.Last, ents: ents}
	for i := range chains {
		ch := &chains[i]
		if (ch.first[d.RuleID] || ch.then[d.RuleID]) && !inc.madeWith(ch, key) && inc.chainWith(ch, d.RuleID, &sp, key) {
			return true
		}
	}
	return false
}

// madeFor reports whether inc makes, for key, a known chain detection a's rule is a step of.
func (e *Engine) madeFor(inc *incident, a *activeDet, key incEnt) bool {
	e.loadSpans(inc)
	for i := range chains {
		ch := &chains[i]
		if (ch.first[a.s.d.RuleID] || ch.then[a.s.d.RuleID]) && inc.madeWith(ch, key) {
			return true
		}
	}
	return false
}

// edgeOnly reports whether a built-in rule is evaluated over edge events only (its query, which
// can't be tuned, starts with src:edge): the block-list rules of the edge.
func edgeOnly(rule string) bool {
	p := packByID[rule]
	return p != nil && strings.HasPrefix(p.Query, "src:edge ")
}

// addSpan records (or updates) a detection's span for the chain check.
func (inc *incident) addSpan(rule string, sp incSpan) {
	if inc.spans == nil {
		inc.spans = map[string][]incSpan{}
	}
	ss, ok := inc.spans[rule]
	if !ok {
		if len(inc.spanRules) >= maxSpanRules {
			return
		}
		inc.spanRules = append(inc.spanRules, rule)
	}
	for i := range ss {
		if (sp.id != 0 && ss[i].id == sp.id) || (sp.seq != 0 && ss[i].seq == sp.seq) {
			if sp.id == 0 {
				sp.id = ss[i].id
			}
			ss[i] = sp
			inc.spans[rule] = ss
			return
		}
	}
	ss = append(ss, sp)
	if len(ss) > maxSpansPerRule {
		oldest := 0
		for i := range ss {
			if ss[i].last.Before(ss[oldest].last) {
				oldest = i
			}
		}
		ss = slices.Delete(ss, oldest, oldest+1)
	}
	inc.spans[rule] = ss
}

// addEntity puts an entity on the incident (at most maxIncEntities) or moves its times.
func (inc *incident) addEntity(k incEnt, first, last time.Time) {
	if inc.entTimes == nil {
		inc.entTimes = map[incEnt]*entSpan{}
	}
	if inc.entDirty == nil {
		inc.entDirty = map[incEnt]struct{}{}
	}
	s := inc.entTimes[k]
	if s == nil {
		if len(inc.ents) >= maxIncEntities {
			return
		}
		inc.ents = append(inc.ents, k)
		s = &entSpan{first: first, last: last}
		inc.entTimes[k] = s
		inc.entDirty[k] = struct{}{}
		return
	}
	if first.Before(s.first) {
		s.first = first
		inc.entDirty[k] = struct{}{}
	}
	if last.After(s.last) {
		s.last = last
		inc.entDirty[k] = struct{}{}
	}
}

// detTitle is a detection as an incident title: "<rule name>: <summary>".
func detTitle(d *siem.Detection) string {
	return siem.Cut(clean(clean(d.RuleName, maxRuleName)+": "+d.Summary, maxSummary), maxSummary)
}

// correlate puts a new or updated detection in its incident (commit, engine goroutine; it runs on
// every update and is idempotent). It reports whether the detection's own alert is replaced: it is
// in an incident, or muted. A rollup, an app /ops detection and one whose key is no account or
// address join none and keep their own alerts.
func (e *Engine) correlate(a *activeDet) bool {
	d := &a.s.d
	d.Muted = false
	if a.s.rollup || d.Source != siem.DetectionSIEM {
		return false
	}
	key, ok := keyEntity(&a.s)
	if !ok {
		return false
	}
	now := e.now()
	if e.isMuted(d.RuleID, key, now) {
		d.Muted = true
		return true
	}
	if !e.lim.incidents {
		return false
	}
	ents := detEntities(&a.s)
	inc, linked, err := e.linkedIncident(a)
	if err != nil {
		// Intentional: its incident can't be read now. The detection alerts on its own rather than
		// not at all; the incident counts that alert once it is read again (carryOwn).
		return false
	}
	if linked {
		// Intentional: a detection stays in the incident it joined. While that is resolved or a
		// false positive, its updates change neither it nor any other incident, and alert nothing.
		if inc != nil && activeState(inc.state) {
			e.touchIncident(inc, a, ents, now, false)
		}
		return true
	}
	inc = e.findIncident(key, d.Last)
	// Intentional (owner decision): the one exception to the key-only rule. A detection of a chain
	// step may join another incident that lists its key, when it is the missing step of a known chain
	// there (a brute force that tried alice, then alice's unusual sign-in). Its own key's incident is
	// taken when that makes the chain too. The edge's block-list rules never take it: a carrier
	// address on a list would otherwise raise strangers' sign-ins behind it to critical.
	chained, mayRealert := false, false
	if chainRules[d.RuleID] && !edgeOnly(d.RuleID) && (inc == nil || !e.completes(inc, a, ents, key)) {
		if c, realert := e.chainJoin(key, a, ents, inc); c != nil {
			inc, chained, mayRealert = c, true, realert
		}
	}
	opened := inc == nil
	if opened {
		if len(e.incNew) >= maxIncNew {
			e.logLimited("incidents-full", "security detection: too many incidents not written yet, detection alerts on its own")
			return false
		}
		e.seq++
		inc = &incident{seq: e.seq, key: key, state: siem.IncidentOpen, created: now, first: d.First, last: d.Last,
			spansLoaded: true}
		e.incNew[inc] = struct{}{}
	}
	critBefore := inc.critAlerted(now)
	e.touchIncident(inc, a, ents, now, true)
	if chained {
		e.chainJoined(inc, a, key, critBefore && mayRealert)
	}
	if opened {
		open := incTL{ev: siem.IncidentEvent{TS: now, Kind: siem.TimelineOpened, Severity: rankSeverity(inc.sev),
			Text: inc.title}}
		inc.tl = append([]incTL{open}, inc.tl...)
		inc.changes = append([]incChange{{change: changeOpened}}, inc.changes...)
	}
	if inc.id != 0 {
		a.inc, a.s.incID = nil, inc.id
	} else {
		a.inc = inc
	}
	a.linkDirty = true
	return true
}

// linkedIncident returns the incident a detection is in (linked false: none). An incident that
// can't be read is reported linked with the error (inc nil), so the detection doesn't open another.
func (e *Engine) linkedIncident(a *activeDet) (*incident, bool, error) {
	if a.inc != nil {
		if a.inc.id == 0 {
			return a.inc, true, nil
		}
		a.s.incID, a.inc = a.inc.id, nil
	}
	if a.s.incID == 0 {
		return nil, false, nil
	}
	inc, found, err := e.incident(a.s.incID)
	if err != nil {
		e.writeErrors.Add(1)
		e.logLimited("incident-read", "security detection: incident lookup failed", "err", err)
		return nil, true, err
	}
	if !found { // removed (retention, size cap): the detection is in none now
		a.s.incID, a.linkDirty = 0, true
		return nil, false, nil
	}
	return inc, true, nil
}

// findIncident returns the open or acknowledged incident a new detection keyed by key joins: of
// the key's incidents with a detection of it within incJoinWindow before t, the one with the
// latest; nil: none.
// Intentional (owner decision): a detection joins only through its key entity. The accounts and
// addresses of its evidence are listed on its incident as context but never index one for this: a
// shared carrier address, or a user name an attacker typed, would pull unrelated detections
// together. listIdx (chainIncident) is the one exception, for chain steps only.
func (e *Engine) findIncident(key incEnt, t time.Time) *incident {
	var best incRef
	for _, r := range e.activeRefs(e.entIdx, key, t) {
		if best.inc == nil || r.last.After(best.last) {
			best = r
		}
	}
	return best.inc
}

// chainJoin returns the incident other than own that chain-step detection a (keyed by key, listing
// ents) joins to complete a known chain, nil for none, and whether that join may re-alert:
//   - first the incidents keyed by one of its own evidence addresses (entIdx, so no flood of other
//     incidents listing key can hide them): one it completes (owner decision: also when another of
//     them makes the chain for key already, as the sign-in also came from this one); else one that
//     makes the chain for key already, with no new alert (another rule seeing the same compromise),
//     and no other is looked at;
//   - only then the other incidents listing key (listIdx) it completes (chainIncident).
//
// Of several, the most recently active.
func (e *Engine) chainJoin(key incEnt, a *activeDet, ents []incEnt, own *incident) (*incident, bool) {
	var made, done *incident
	later := func(best, inc *incident) bool { return best == nil || inc.last.After(best.last) }
	for _, k := range ents {
		if k.kind != siem.EntityAddress || k == key {
			continue
		}
		for _, r := range e.activeRefs(e.entIdx, k, a.s.d.Last) {
			switch inc := r.inc; {
			case inc == own:
			case e.madeFor(inc, a, key):
				if later(made, inc) {
					made = inc
				}
			case later(done, inc) && e.completes(inc, a, ents, key):
				done = inc
			}
		}
	}
	switch {
	case done != nil:
		return done, true
	case made != nil:
		return made, false
	}
	if c := e.chainIncident(key, a, ents, own); c != nil {
		return c, true
	}
	return nil, false
}

// chainIncident returns the open or acknowledged incident other than skip that lists key from a
// detection of a chain step (listIdx) and in which detection a is the missing step of a known chain
// (completes); of several, the most recently active. An incident that makes that chain for key
// already is no candidate, so a second attacker's chain on the same account goes to that
// attacker's incident.
func (e *Engine) chainIncident(key incEnt, a *activeDet, ents []incEnt, skip *incident) *incident {
	var best *incident
	for _, r := range e.activeRefs(e.listIdx, key, a.s.d.Last) {
		if r.inc != skip && (best == nil || r.inc.last.After(best.last)) && e.completes(r.inc, a, ents, key) {
			best = r.inc
		}
	}
	return best
}

// chainJoined records key as a key entity of inc, which detection a joined to complete a chain. A
// key inc didn't have makes it alert again (critical) when realert (it had already alerted
// critical, and the join completed the chain): once per such key.
func (e *Engine) chainJoined(inc *incident, a *activeDet, key incEnt, realert bool) {
	if e.keyedBy(inc, key) {
		return
	}
	if len(inc.keys) < maxIncEntities {
		inc.keys = append(inc.keys, key)
	}
	if realert && !a.s.d.Snoozed {
		inc.realert++
		e.incOwed[inc] = struct{}{}
		e.markIncident(inc, true)
	}
}

// keyedBy reports whether one of inc's detections is keyed by k: its opener's key, a key that
// joined to complete a chain since it is in memory, or a stored detection's (a read failure counts
// as no: the alert goes out).
func (e *Engine) keyedBy(inc *incident, k incEnt) bool {
	if k == inc.key || slices.Contains(inc.keys, k) {
		return true
	}
	if inc.id == 0 || e.closed.Load() {
		return false
	}
	ok, err := e.db.incidentKeyed(inc.id, k)
	if err != nil {
		e.writeErrors.Add(1)
		e.logLimited("incident-read", "security detection: incident detections not read", "err", err)
	}
	return ok
}

// critAlerted reports whether a critical alert counts for the incident: recorded, or in flight.
func (inc *incident) critAlerted(now time.Time) bool {
	if inc.alerted >= 4 {
		return true
	}
	inc.busy(now)
	for j := range inc.jobs {
		if j.incRank >= 4 {
			return true
		}
	}
	return false
}

// incRef is one of an entity's incidents, resolved.
type incRef struct {
	inc  *incident
	last time.Time
}

// entIndex maps an entity to its incidents: at most maxEntIncs each, maxEntIndex entities. The
// engine keeps two: entIdx (key entities, for every join) and listIdx (entities listed by a
// detection of a chain step, for chain completion only).
type entIndex map[incEnt][]*entRef

// activeRefs resolves k's incidents in x that are open or acknowledged with a detection of k within
// incJoinWindow before t. Its references to closed or removed incidents are dropped on the way (a
// reopened one is indexed again).
func (e *Engine) activeRefs(x entIndex, k incEnt, t time.Time) []incRef {
	refs := x[k]
	if len(refs) == 0 {
		return nil
	}
	var out []incRef
	keep := refs[:0]
	for _, r := range refs {
		if t.Sub(r.last) > incJoinWindow {
			keep = append(keep, r)
			continue
		}
		inc, gone := e.refIncident(r)
		switch {
		case gone:
			continue
		case inc == nil: // unreadable for now
			keep = append(keep, r)
			continue
		case !activeState(inc.state):
			continue
		}
		keep = append(keep, r)
		out = append(out, incRef{inc: inc, last: r.last})
	}
	clear(refs[len(keep):])
	if len(keep) == 0 {
		delete(x, k)
	} else {
		x[k] = keep
	}
	return out
}

// refIncident resolves one of an entity's incidents (nil: unreadable, or gone: removed).
func (e *Engine) refIncident(r *entRef) (inc *incident, gone bool) {
	id := r.id
	if r.inc != nil {
		if r.inc.id == 0 {
			return r.inc, false
		}
		id = r.inc.id
		if e.incs[id] == r.inc {
			r.inc.used = e.now()
			return r.inc, false
		}
	}
	inc, found, err := e.incident(id)
	if err != nil {
		e.logLimited("incident-read", "security detection: incident lookup failed", "err", err)
		return nil, false
	}
	if !found {
		return nil, true
	}
	r.inc, r.id = inc, inc.id
	return inc, false
}

// indexEntity records that inc has a detection of key entity k at t (entIdx).
func (e *Engine) indexEntity(k incEnt, inc *incident, t time.Time) { e.indexIn(e.entIdx, k, inc, t) }

// indexIn records that inc has a detection of k at t in x. An entity keeps at most maxEntIncs
// incidents: past that, the one with its oldest latest detection is dropped.
func (e *Engine) indexIn(x entIndex, k incEnt, inc *incident, t time.Time) {
	refs := x[k]
	for _, r := range refs {
		if r.is(inc) {
			r.inc, r.id = inc, inc.id
			if t.After(r.last) {
				r.last = t
			}
			return
		}
	}
	if refs == nil && len(x) >= maxEntIndex {
		x.prune(e.now(), true)
	}
	refs = append(refs, &entRef{inc: inc, id: inc.id, last: t})
	if len(refs) > maxEntIncs {
		oldest := 0
		for i := range refs {
			if refs[i].last.Before(refs[oldest].last) {
				oldest = i
			}
		}
		refs = slices.Delete(refs, oldest, oldest+1)
	}
	x[k] = refs
}

// indexKey indexes inc under its key entity, when that is listed on it (with its latest time), and,
// when it has a detection of a chain step, under every entity it lists for chain completion.
func (e *Engine) indexKey(inc *incident) {
	if t := inc.entTimes[inc.key]; inc.key.key != "" && t != nil {
		e.indexEntity(inc.key, inc, t.last)
	}
	if slices.ContainsFunc(inc.rules, func(r string) bool { return chainRules[r] }) {
		for k, t := range inc.entTimes {
			e.indexIn(e.listIdx, k, inc, t.last)
		}
	}
}

// is reports whether r refers to inc.
func (r *entRef) is(inc *incident) bool {
	switch {
	case r.inc == inc:
		return true
	case inc.id == 0:
		return false
	case r.inc != nil:
		return r.inc.id == inc.id
	}
	return r.id == inc.id
}

// pruneIndex prunes both entity indexes (entIndex.prune).
func (e *Engine) pruneIndex(now time.Time, full bool) {
	e.entIdx.prune(now, full)
	e.listIdx.prune(now, full)
}

// prune drops the entities' incidents whose latest detection of them is too old to join anything;
// full: and, when that frees too little, the tenth of the entities seen least recently.
func (x entIndex) prune(now time.Time, full bool) {
	cut := now.Add(-incJoinWindow - maxSkew)
	for k, refs := range x {
		if keep := slices.DeleteFunc(refs, func(r *entRef) bool { return r.last.Before(cut) }); len(keep) == 0 {
			delete(x, k)
		} else {
			x[k] = keep
		}
	}
	if !full || len(x) < maxEntIndex {
		return
	}
	type kv struct {
		k incEnt
		t time.Time
	}
	all := make([]kv, 0, len(x))
	for k, refs := range x {
		all = append(all, kv{k, latestRef(refs)})
	}
	slices.SortFunc(all, func(a, b kv) int { return a.t.Compare(b.t) })
	for _, v := range all[:len(all)/10+1] {
		delete(x, v.k)
	}
}

// forget drops the references to the incidents removed (gone, by ID).
func (x entIndex) forget(gone map[int64]bool) {
	for k, refs := range x {
		keep := slices.DeleteFunc(refs, func(r *entRef) bool {
			return (r.inc != nil && r.inc.id != 0 && gone[r.inc.id]) || (r.inc == nil && gone[r.id])
		})
		if len(keep) == 0 {
			delete(x, k)
		} else {
			x[k] = keep
		}
	}
}

// unpin makes the references to incidents that left memory refer to them by ID.
func (x entIndex) unpin(left map[*incident]bool) {
	for _, refs := range x {
		for _, r := range refs {
			if r.inc != nil && left[r.inc] {
				r.id, r.inc = r.inc.id, nil
			}
		}
	}
}

// touchIncident adds a detection to an incident (joined: it just joined) or takes its update:
// times, entities, the chain check, severity, title, risk and the timeline.
func (e *Engine) touchIncident(inc *incident, a *activeDet, ents []incEnt, now time.Time, joined bool) {
	d := &a.s.d
	rank := siem.SeverityRank(d.Severity)
	if joined {
		inc.ndet = satInt(inc.ndet, 1)
		if !slices.Contains(inc.rules, d.RuleID) && len(inc.rules) < maxIncRules {
			inc.rules = append(inc.rules, d.RuleID)
		}
		inc.tl = append(inc.tl, incTL{det: a, ev: siem.IncidentEvent{TS: now, Kind: siem.TimelineDetection,
			RuleID: d.RuleID, RuleName: d.RuleName, Severity: d.Severity, Text: d.Summary}})
		inc.capTimeline()
		for _, k := range ents {
			e.addRisk(k, rank, now)
		}
	}
	if inc.first.IsZero() || d.First.Before(inc.first) {
		inc.first = d.First
	}
	if d.Last.After(inc.last) {
		inc.last = d.Last
	}
	for _, k := range ents {
		inc.addEntity(k, d.First, d.Last)
	}
	// Only the opener's key entity indexes the incident for every join (see findIncident), and only
	// when it is listed on it. The entities a detection of a chain step lists index it for chain
	// completion only (chainIncident).
	if k, ok := keyEntity(&a.s); ok && k == inc.key && inc.entTimes[k] != nil {
		e.indexEntity(k, inc, d.Last)
	}
	if chainRules[d.RuleID] {
		for _, k := range ents {
			if inc.entTimes[k] != nil {
				e.indexIn(e.listIdx, k, inc, d.Last)
			}
		}
	}
	e.loadSpans(inc)
	inc.addSpan(d.RuleID, incSpan{id: d.ID, seq: a.seq, first: d.First, last: d.Last, snoozed: d.Snoozed, ents: ents})

	opening := inc.sev == 0
	sev, alertSev := max(inc.sev, rank), inc.alertSev
	if !d.Snoozed {
		alertSev = max(alertSev, rank)
	}
	why := d.RuleName
	// A chain can only start matching through a rule of one of its steps; once the incident is
	// critical for both and named, there is nothing left for it to raise.
	if chainRules[d.RuleID] && (inc.chain == "" || sev < 4 || alertSev < 4) {
		if ch, shared, ok := inc.matchChain(false); ok {
			if inc.chain == "" {
				inc.chain = ch.name
				inc.title = siem.Cut(clean(ch.name+": "+shared.label(), maxSummary), maxSummary)
				inc.titleRank = chainTitleRank
			}
			if sev < 4 {
				sev, why = 4, "known chain "+ch.name
			}
		}
		if alertSev < 4 {
			if _, _, ok := inc.matchChain(true); ok {
				alertSev = 4
			}
		}
	}
	if rank > inc.titleRank {
		inc.title, inc.titleRank = detTitle(d), rank
	}
	if !opening && sev > inc.sev {
		text := siem.Cut(fmt.Sprintf("severity raised to %s: %s", rankSeverity(sev), clean(why, maxSummary)), maxSummary)
		inc.tl = append(inc.tl, incTL{ev: siem.IncidentEvent{TS: now, Kind: siem.TimelineEscalated,
			RuleID: d.RuleID, RuleName: d.RuleName, Severity: rankSeverity(sev), Text: text}})
		inc.changes = append(inc.changes, incChange{change: changeEscalated, text: text})
	}
	alerted := inc.alerted
	e.carryOwn(inc, a, now)
	urgent := joined || sev != inc.sev || alertSev != inc.alertSev || inc.alerted != alerted
	inc.sev, inc.alertSev = sev, alertSev
	inc.updated, inc.used = now, now
	e.markIncident(inc, urgent)
	if inc.alertSev >= rankHigh && inc.alertSev > inc.alerted {
		e.incOwed[inc] = struct{}{}
	}
}

// carryOwn counts a detection's own alert for its incident, so a detection alerts once: on its own
// (sent before it was in an incident, while its incident couldn't be read, or while the incident
// had no ID) or through the incident. One sent within alertCooldown raises the rank the incident
// has alerted; one in flight makes the incident wait for its result (settleOwn).
func (e *Engine) carryOwn(inc *incident, a *activeDet, now time.Time) {
	d := &a.s.d
	rank := siem.SeverityRank(d.Severity)
	if rank < rankHigh {
		return
	}
	if j := a.own; j != nil && j.settles == nil && now.Sub(j.at) < inflightTTL && now.Sub(j.at) >= 0 {
		// The worker never reads settles or incRank (alertJob): set here while the job is queued.
		j.settles, j.incRank = inc, rank
		inc.addJob(j, j.at)
		return
	}
	if t := a.s.alerted; !t.IsZero() && now.Sub(t) < alertCooldown && now.Sub(t) >= 0 && rank > inc.alerted {
		inc.alerted, inc.alertedAt = rank, t
	}
}

// capTimeline keeps the entries not written yet within maxTimeline, dropping the oldest detection
// entries (writes failing for long).
func (inc *incident) capTimeline() {
	for len(inc.tl) > maxTimeline {
		i := slices.IndexFunc(inc.tl, func(t incTL) bool { return t.ev.Kind == siem.TimelineDetection })
		if i < 0 {
			i = 0
		}
		inc.tl = slices.Delete(inc.tl, i, i+1)
	}
}

func (e *Engine) markIncident(inc *incident, urgent bool) {
	if inc.gone {
		return // removed from detect.db: never stored again under a new ID
	}
	e.incDirty[inc] = struct{}{}
	if urgent {
		inc.urgent = true
	}
}

// loadSpans reads back the detections of an incident loaded from detect.db for the chain check,
// once (a failure leaves the check with the detections seen since).
func (e *Engine) loadSpans(inc *incident) {
	if inc.spansLoaded {
		return
	}
	inc.spansLoaded = true
	if inc.id == 0 || e.closed.Load() {
		return
	}
	rows, err := e.db.incidentSpans(inc.id, maxSpanRules*maxSpansPerRule)
	if err != nil {
		e.writeErrors.Add(1)
		e.logLimited("incident-read", "security detection: incident detections not read", "err", err)
		return
	}
	// Oldest first, so the most recently seen of each rule are the ones kept.
	for i := len(rows) - 1; i >= 0; i-- {
		r := &rows[i]
		inc.addSpan(r.d.RuleID, incSpan{id: r.d.ID, first: r.d.First, last: r.d.Last, snoozed: r.d.Snoozed,
			ents: detEntities(r)})
	}
}

// addRisk adds a detection of severity rank to an entity's risk score.
func (e *Engine) addRisk(k incEnt, rank int, now time.Time) {
	if rank < 1 || rank > 4 {
		return
	}
	r := e.risk[k]
	cur := 0.0
	if r == nil {
		if len(e.risk) >= maxRisk {
			e.evictRisk(now, true)
		}
		r = &riskEntry{}
		e.risk[k] = r
	} else {
		cur = riskNow(*r, now)
	}
	r.score, r.at = min(cur+riskWeight[rank], riskCap), now
	e.riskDirty[k] = struct{}{}
	delete(e.riskGone, k)
}

// evictRisk drops the scores faded below riskFloor; full: and, when that frees too little, the
// lowest tenth.
func (e *Engine) evictRisk(now time.Time, full bool) {
	drop := func(k incEnt) {
		delete(e.risk, k)
		delete(e.riskDirty, k)
		e.riskGone[k] = struct{}{}
	}
	for k, r := range e.risk {
		if riskNow(*r, now) < riskFloor {
			drop(k)
		}
	}
	if !full || len(e.risk) < maxRisk {
		return
	}
	type kv struct {
		k incEnt
		s float64
	}
	all := make([]kv, 0, len(e.risk))
	for k, r := range e.risk {
		all = append(all, kv{k, riskNow(*r, now)})
	}
	slices.SortFunc(all, func(a, b kv) int { return cmpFloat(a.s, b.s) })
	for _, x := range all[:len(all)/10+1] {
		drop(x.k)
	}
}

func cmpFloat(a, b float64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// incident returns an incident by ID: the one in memory, else read from detect.db (and kept in
// memory). Engine goroutine.
func (e *Engine) incident(id int64) (*incident, bool, error) {
	if inc := e.incs[id]; inc != nil {
		inc.used = e.now()
		return inc, true, nil
	}
	if e.closed.Load() {
		return nil, false, errClosed
	}
	inc, found, err := e.db.loadIncident(id)
	if err != nil || !found {
		return nil, found, err
	}
	inc.used = e.now()
	// Intentional: no eviction here, even past maxIncCache: an incident a caller already holds
	// (found for an entity a moment ago) must stay the one in memory, or a later lookup would read
	// a second copy of it. The flush evicts (evictIncidents), so the cache only grows between ticks.
	e.incs[id] = inc
	return inc, true, nil
}

// incidentOf is the copy of inc the engine keeps: inc, or the one read back after inc left memory
// (an alert's result can come back after that); nil when it was removed (never written back), or
// can't be read now. Intentional: then the result is dropped and the incident is looked at again
// at a later flush (oweLater), so its alert may go out twice: a stale copy written back could undo
// a dashboard change made since.
func (e *Engine) incidentOf(inc *incident) *incident {
	if inc.gone {
		return nil
	}
	if inc.id == 0 || e.incs[inc.id] == inc {
		return inc
	}
	cur, found, err := e.incident(inc.id)
	switch {
	case err != nil:
		e.oweLater(inc.id)
		return nil
	case !found:
		return nil
	}
	return cur
}

// oweLater has a later flush read incident id back and raise the alert it owes then (retryOwed).
func (e *Engine) oweLater(id int64) {
	if len(e.incRetry) < maxIncNew {
		e.incRetry[id] = struct{}{}
	}
}

// retryOwed reads back the incidents oweLater named and checks the alert each owes as stored.
func (e *Engine) retryOwed() {
	for id := range e.incRetry {
		inc, found, err := e.incident(id)
		if err != nil {
			return // detect.db can't be read: the next flush tries again
		}
		delete(e.incRetry, id)
		if found && inc.alertSev >= rankHigh && (inc.alertSev > inc.alerted || inc.realert > 0) {
			e.incOwed[inc] = struct{}{}
		}
	}
}

// evictIncidents drops from memory the incidents nothing waits on (written, no alert owed) that
// can't be joined any more (closed, or no detection within the join window), then, past
// maxIncCache, the least recently used of the others nothing waits on.
func (e *Engine) evictIncidents(now time.Time) {
	idle := func(inc *incident) bool {
		_, dirty := e.incDirty[inc]
		_, owed := e.incOwed[inc]
		return !dirty && !owed && !inc.busy(now)
	}
	gone := map[*incident]bool{}
	for id, inc := range e.incs {
		if idle(inc) && (!activeState(inc.state) || now.Sub(inc.last) > incJoinWindow+maxSkew) && now.Sub(inc.used) > time.Minute {
			delete(e.incs, id)
			gone[inc] = true
		}
	}
	if len(e.incs) > maxIncCache {
		var all []*incident
		for _, inc := range e.incs {
			if idle(inc) {
				all = append(all, inc)
			}
		}
		slices.SortFunc(all, func(a, b *incident) int { return a.used.Compare(b.used) })
		for _, inc := range all[:min(len(all), len(e.incs)-maxIncCache+maxIncCache/10)] {
			delete(e.incs, inc.id)
			gone[inc] = true
		}
	}
	if len(gone) == 0 {
		return
	}
	e.entIdx.unpin(gone)
	e.listIdx.unpin(gone)
}

// incMaintain runs on the persist tick: idle incidents leave memory, faded risk scores and entities
// too old to join anything are dropped.
func (e *Engine) incMaintain() {
	now := e.now()
	e.evictIncidents(now)
	e.evictRisk(now, false)
	e.pruneIndex(now, false)
}

// raiseIncidentAlerts queues the alerts incidents owe (flush, after the write gave them IDs): one
// when an open or acknowledged incident's severity (of rules not snoozed) first reaches high or
// critical, one more each time it rises above the level alerted, and a critical one again when a
// new key completed a chain in it (realert). An incident still without an
// ID while detect.db writes fail (or incNoIDAlert after it opened) alerts its detections on their
// own instead (alertOnOwn).
func (e *Engine) raiseIncidentAlerts(now time.Time) {
	if len(e.incRetry) > 0 {
		e.retryOwed()
	}
	for inc := range e.incOwed {
		busy := inc.busy(now)
		if inc.id != 0 && e.incs[inc.id] != inc {
			// A copy that left memory (its alert result came back when detect.db couldn't be read):
			// once nothing of it is in flight, the copy read back is checked instead (oweLater).
			if !busy {
				delete(e.incOwed, inc)
				if !inc.gone {
					e.oweLater(inc.id)
				}
			}
			continue
		}
		owes := inc.alertSev > inc.alerted || (inc.realert > 0 && inc.alertSev >= 4)
		switch {
		case e.opt.Alerter == nil || inc.gone || !activeState(inc.state) || inc.alertSev < rankHigh || (!owes && !busy):
			delete(e.incOwed, inc)
		case busy || now.Before(inc.retryAt):
		case inc.id == 0:
			if e.writeBackoff > 0 || now.Sub(inc.created) >= incNoIDAlert {
				e.alertOnOwn(inc, now)
			}
		default:
			level := alert.LevelWarning
			if inc.alertSev >= 4 {
				level = alert.LevelCritical
			}
			j := &alertJob{inc: inc, incRank: inc.alertSev, realert: inc.realert, at: now, o: alert.Outbox{RuleID: 0, Target: TargetSIEM,
				Kind: IncidentAlertKind, Level: level, Transition: "firing", Summary: incidentAlertText(inc),
				DedupeKey: "siem-incident:" + strconv.FormatInt(inc.id, 10)}}
			if e.enqueueAlert(j) {
				inc.addJob(j, now)
			} else {
				inc.retryAt = now.Add(incQueueRetry)
			}
		}
	}
}

// alertOnOwn alerts on its own (a security_detection alert, like a detection in no incident) the
// most severe detection of an incident not written yet that the incident hasn't alerted for, so
// nothing high or critical is silent while detect.db writes fail. Its result counts for the
// incident (settleOwn): once the incident is written, it doesn't alert that rank again.
// Intentional: not held back by the rule's hourly cap or the key's cooldown, as the incident alert
// it stands in for isn't.
func (e *Engine) alertOnOwn(inc *incident, now time.Time) {
	var (
		best *activeDet
		rank int
	)
	for _, t := range inc.tl {
		a := t.det
		if a == nil || a.s.d.Snoozed || a.s.d.Muted {
			continue
		}
		if r := siem.SeverityRank(a.s.d.Severity); r >= rankHigh && r > inc.alerted && r > rank {
			best, rank = a, r
		}
	}
	if best == nil {
		// Its rank comes from a chain of detections already alerted: its own alert waits for its ID.
		inc.retryAt = now.Add(incQueueRetry)
		return
	}
	j := ownAlertJob(best, TargetSIEM, now)
	j.settles, j.incRank = inc, rank
	if !e.enqueueAlert(j) {
		inc.retryAt = now.Add(incQueueRetry)
		return
	}
	inc.addJob(j, now)
	best.own = j
	e.inflight[j.mk] = now
}

// settleOwn takes the result of a detection's own alert that counts for its incident (alertOnOwn,
// carryOwn): a sent one raises the rank the incident has alerted; a failed one leaves the incident
// owing its alert, tried again after incAlertRetry.
func (e *Engine) settleOwn(j *alertJob, ok bool) {
	delete(j.settles.jobs, j)
	inc := e.incidentOf(j.settles)
	if inc == nil {
		return
	}
	if !ok {
		inc.retryAt = e.now().Add(incAlertRetry)
	} else if j.incRank > inc.alerted {
		inc.alerted, inc.alertedAt = j.incRank, j.at
		e.markIncident(inc, true)
	}
	e.incOwed[inc] = struct{}{}
}

// incidentAlertText is "<title> — incident #<id>", at most maxSummary bytes.
func incidentAlertText(inc *incident) string {
	suffix := " — incident #" + strconv.FormatInt(inc.id, 10)
	return siem.Cut(inc.title, maxSummary-len(suffix)) + suffix
}

// finishIncidentAlert takes the worker's result for an incident's alert: a sent one is recorded on
// the incident (written at the next flush); a failed one is raised again after incAlertRetry. An
// incident removed meanwhile (retention, size cap) is left removed.
func (e *Engine) finishIncidentAlert(j *alertJob, ok bool) {
	delete(j.inc.jobs, j)
	inc := e.incidentOf(j.inc)
	if inc == nil {
		return
	}
	if !ok {
		inc.retryAt = e.now().Add(incAlertRetry)
		e.incOwed[inc] = struct{}{}
		return
	}
	if j.incRank > inc.alerted {
		inc.alerted, inc.alertedAt = j.incRank, j.at
		e.markIncident(inc, true)
	}
	if j.realert > 0 && inc.realert > 0 {
		inc.realert = max(inc.realert-j.realert, 0)
		e.markIncident(inc, true)
	}
}

// emitIncident hands an incident change to the pipeline as a siem.incident event.
func (e *Engine) emitIncident(inc *incident, ch incChange) {
	if e.opt.Emit == nil {
		return
	}
	msg := inc.title
	if ch.change == changeNote || ch.change == changeMuted || ch.change == changeUnmuted || ch.change == changeEscalated {
		msg = ch.text
	}
	sev := rankSeverity(inc.sev)
	ev := siem.Event{TS: e.now().UTC(), Src: siem.SrcSIEM, Kind: KindIncident, Lvl: levelOf(sev), Msg: msg,
		F: map[string]any{"incident_id": float64(inc.id), "change": ch.change, "state": inc.state,
			"severity": string(sev)}}
	if inc.chain != "" {
		ev.F["chain"] = inc.chain
	}
	if inc.assignee != "" {
		ev.F["assignee"] = inc.assignee
	}
	if ch.actor != "" {
		ev.F["actor"] = ch.actor
	}
	names := make([]string, 0, len(inc.ents))
	for _, k := range inc.ents {
		names = append(names, k.String())
		if ev.IP == "" && k.kind == siem.EntityAddress {
			if _, err := netip.ParseAddr(k.key); err == nil {
				ev.IP = k.key
			}
		}
		if ev.Actor == "" && k.kind == siem.EntityAccount {
			ev.Actor = k.key
		}
	}
	if len(names) > 0 {
		ev.F["entities"] = siem.Cut(strings.Join(names, ","), siem.MaxFieldValue)
	}
	e.emitEvent(ev)
}
