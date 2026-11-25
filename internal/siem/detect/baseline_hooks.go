package detect

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

// Phase-3 baseline rules (docs/security-detections.md "Baselines"): the engine calls these from
// applyRule, validate, summarize, New, the write tick and persist. Each kind keeps its learned
// state in a bounded table (baseline_table.go): signin and admin in baseline_habit.go, traffic in
// baseline_traffic.go, ip in baseline_ip.go. Everything runs on the engine goroutine.

// Entities kept per kind (see table: three quarters at most go to protected ones).
const (
	maxSigninAccounts    = 2000  // Mooring's and the server's (SSH) accounts
	maxAppSigninAccounts = 20000 // the apps' accounts
	maxAdminUsers        = 2000
	maxTrafficHosts      = 1000
	maxAddresses         = 50000

	blTickRows = 128  // rows saved (and deleted) per write tick at most
	blChunk    = 2000 // rows per transaction of a full save (a kind's rewrite too)
	// Bytes of a stored entity's state at most (the largest valid one, a host name's, is about
	// 8 KB): a longer row is discarded unread.
	maxBlData = 16 << 10

	blBackoffMin = 5 * time.Second // after a failed save, ticks wait this long (doubling)
	blBackoffMax = time.Minute
)

// The kinds of stored state. The sign-in baseline keeps Mooring's and the server's (SSH) accounts
// in a table of their own: an app with many accounts can't push them out.
const (
	kindSignin    = "signin"     // scopes mooring and host
	kindSigninApp = "signin_app" // scopes app:<slug> (and any other source)
	kindAdmin     = "admin"
	kindTraffic   = "traffic"
	kindIP        = "ip"
)

// blVersions is part of each kind's stored signature. Raise a kind's when what its state means
// changes (signin, signin_app: signinValues, uaFamily, hourSlot; admin: adminValues, programOf,
// hourSlot; traffic: what is counted per hour; ip: pathKinds): its rows are then discarded and
// learned again, instead of every key departing at once (every account's client "new" after
// uaFamily changed). A var so tests can raise one.
var blVersions = map[string]int{kindSignin: 1, kindSigninApp: 1, kindAdmin: 1, kindTraffic: 1, kindIP: 1}

// blKindOf is the baseline (the rules' Baseline) of each kind.
var blKindOf = map[string]string{kindSignin: siem.BaselineSignIn, kindSigninApp: siem.BaselineSignIn,
	kindAdmin: siem.BaselineAdmin, kindTraffic: siem.BaselineTraffic, kindIP: siem.BaselineIP}

// baselines is the learned per-entity state of the baseline rules.
type baselines struct {
	loc *time.Location // hours are the server's local time

	signin    *table[habit] // Mooring's and the server's accounts
	signinApp *table[habit] // the apps' accounts
	admin     *table[habit]
	traffic   *table[hostTraffic]
	ip        *table[addrMix]
	stores    []blStore

	// The time zone (zoneSig) the stored hours of each loaded kind were learned in, and loc's (as
	// of zoneLoc): checkZone resets the hours of a kind learned in another zone.
	zones   map[string]string
	zoneLoc *time.Location
	zone    string

	// The enabled baseline rules of each kind, in rule order, of the rule set set.
	set   *ruleSet
	kinds map[string][]*compiled

	// traffic: hours starting before since weren't watched whole, nor those starting before lossy
	// (events were dropped unevaluated: their counts are a lower bound); closed is the newest hour
	// (unix hours) closed, 0 before the first tick; dropped is the engine's count of events not
	// evaluated (queue full) at the last tick.
	since, lossy, lastTick time.Time
	closed                 int64
	maxGap                 time.Duration
	dropped                int64

	failAt  time.Time
	backoff time.Duration

	// App sign-in changes asked by DeleteAppBaselines and KeepAppBaselines (any goroutine), applied
	// at the next baseline step of the goroutine that owns the tables (applyDeletes).
	delMu  sync.Mutex
	delOps []appOp
	delN   atomic.Int32 // len(delOps), read without delMu
	// The key prefixes of apps deleted lately, until when their sign-ins aren't learned (the owning
	// goroutine's).
	appGone map[string]time.Time
}

// appOp is one app sign-in change: with keep nil, the app of prefix ("app:<slug>|") was deleted at
// at; else every app whose prefix isn't in keep is gone.
type appOp struct {
	prefix string
	at     time.Time
	keep   map[string]bool
}

func newBaselines(now time.Time) *baselines {
	b := &baselines{loc: time.Local, since: now, maxGap: maxTickGap, zones: map[string]string{}, appGone: map[string]time.Time{},
		signin:    newTable(kindSignin, maxSigninAccounts, (*habit).encode),
		signinApp: newTable(kindSigninApp, maxAppSigninAccounts, (*habit).encode),
		admin:     newTable(kindAdmin, maxAdminUsers, (*habit).encode),
		traffic:   newTable(kindTraffic, maxTrafficHosts, (*hostTraffic).encode),
		ip:        newTable(kindIP, maxAddresses, (*addrMix).encode)}
	b.signin.reset, b.signinApp.reset, b.admin.reset = (*habit).resetHours, (*habit).resetHours, (*habit).resetHours
	b.traffic.reset = (*hostTraffic).resetHours
	b.stores = []blStore{b.signin, b.signinApp, b.admin, b.traffic, b.ip}
	return b
}

// signinTable is the sign-in table of an account of scope (signinScope).
func (b *baselines) signinTable(scope string) *table[habit] {
	if scope == siem.SrcMooring || scope == siem.SrcHost {
		return b.signin
	}
	return b.signinApp
}

// zoneSig identifies loc by its UTC offset at noon UTC on every day of 2025 to 2035: zones with
// the same offsets (Europe/Berlin and Europe/Paris) are the same for the hours learned.
// Intentional: a fixed span of years. Years counted from the current one would change the
// signature every new year in a zone with daylight saving time (its change days move), resetting
// every learned hour; a time-zone database update that changes a zone within the span resets once.
func zoneSig(loc *time.Location) string {
	h := sha256.New()
	day0, end := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC), time.Date(2036, 1, 1, 0, 0, 0, 0, time.UTC)
	var off [4]byte
	for d := day0; d.Before(end); d = d.AddDate(0, 0, 1) {
		_, o := d.In(loc).Zone()
		binary.LittleEndian.PutUint32(off[:], uint32(int32(o)))
		h.Write(off[:])
	}
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// checkZone resets the hours of every loaded kind learned in another time zone than loc's (the
// server's zone changed, or was set after they were learned: the hours they hold are another
// zone's). What isn't per hour (countries, networks, clients, programs, target users) is kept. The
// kind is rewritten at the next full save, which records the zone. It runs before the learned state
// is used, and works out loc's zone once per loc (tests set loc after New).
func (b *baselines) checkZone() {
	if b.loc == b.zoneLoc {
		return
	}
	b.zoneLoc, b.zone = b.loc, zoneSig(b.loc)
	for _, s := range b.stores {
		if z, ok := b.zones[s.kindName()]; ok && s.timed() && z != b.zone {
			s.resetHours()
		}
	}
}

// rulesOf returns the enabled rules of a baseline kind in the rule set in force.
func (b *baselines) rulesOf(e *Engine, kind string) []*compiled {
	if b.set != e.cur || b.kinds == nil {
		b.set, b.kinds = e.cur, map[string][]*compiled{}
		if e.cur != nil {
			for _, c := range e.cur.list {
				if c.r.Type == siem.RuleBaseline && c.r.Enabled {
					b.kinds[c.r.Baseline] = append(b.kinds[c.r.Baseline], c)
				}
			}
		}
	}
	return b.kinds[kind]
}

// applyBaseline learns from ev for key and fires on a departure (from applyRule, engine goroutine).
// Rules of one kind share what is learned: each compares with it, and one of them learns (signin
// and admin: the last enabled one, after every rule compared; traffic and ip: the first).
func (e *Engine) applyBaseline(c *compiled, key string, ev *siem.Event, w uint32) {
	b := e.bl
	if b == nil || key == "" {
		return
	}
	b.checkZone()
	b.applyDeletes(e)
	rs := b.rulesOf(e, c.r.Baseline)
	if len(rs) == 0 {
		return
	}
	first, last := rs[0] == c, rs[len(rs)-1] == c
	switch c.r.Baseline {
	case siem.BaselineSignIn, siem.BaselineAdmin:
		b.habitEvent(e, c, key, ev, last)
	case siem.BaselineTraffic:
		if first {
			b.trafficEvent(e, key, ev)
		}
	case siem.BaselineIP:
		b.ipEvent(e, c, key, ev, first)
	}
}

// Bounds of the baseline rules' tunables.
const (
	maxSigninCount  = 3 // of the three departures a sign-in can count (signinReasons)
	minIPCount      = 10
	minTrafficLearn = 7 * day
	maxTrafficLearn = trafficWeeks * 7 * day
)

// validateBaseline checks a baseline rule (built-in rules only) and clears what its kind doesn't
// use.
func validateBaseline(r *siem.Rule) error {
	if !r.Builtin {
		return invalid("type baseline is for the built-in rules only; a custom rule can't use it")
	}
	count := func(lo, hi int) error { return checkRange("the count", r.Count, lo, hi, showInt) }
	learn := func(lo, hi time.Duration) error { return checkRange("the learning period", r.Learn, lo, hi, showDur) }
	factor := func() error { return checkRange("the factor", r.Factor, minFactor, maxFactor, showFloat) }
	var (
		group string
		err   error
	)
	switch r.Baseline {
	case siem.BaselineSignIn:
		group = "actor"
		err = errors.Join(count(1, maxSigninCount), learn(day, maxLearn))
		r.Window, r.Factor = 0, 0
	case siem.BaselineAdmin:
		group = "actor"
		err = learn(day, maxLearn)
		r.Count, r.Window, r.Factor = 0, 0, 0
	case siem.BaselineTraffic:
		group = "f.host"
		err = errors.Join(count(1, maxCount), factor(), learn(minTrafficLearn, maxTrafficLearn))
		r.Window = 0
	case siem.BaselineIP:
		group = "ip"
		err = errors.Join(count(minIPCount, maxCount), checkRange("the window", r.Window, minWindow, maxAnomalyWindow, showDur),
			factor(), learn(hour, maxLearn))
	default:
		return invalid("unknown baseline %q", siem.Cut(r.Baseline, 32))
	}
	if r.GroupBy != group {
		return invalid("a %s baseline groups by %s", r.Baseline, group)
	}
	r.Field, r.Then, r.SpeedKMH = "", "", 0
	return err
}

// baselineWhat is the "what happened" part of a baseline detection's summary: its latest firing's
// reasons.
func baselineWhat(c *compiled, d *siem.Detection, f firing) string {
	r := strings.Join(f.reasons, ", ")
	if r == "" {
		return "unusual activity"
	}
	switch c.r.Baseline {
	case siem.BaselineSignIn:
		return "unusual sign-in: " + r
	case siem.BaselineAdmin:
		return "unusual sudo or su: " + r
	}
	return r
}

// blKinds is each stored kind's signature (its baseline's first pack rule's matching definition,
// both traffic rules share one, and the kind's version), with zone for a kind that learns per hour.
func blKinds(zone string) map[string]blKind {
	def := map[string]string{}
	for _, p := range pack {
		if p.Type == siem.RuleBaseline {
			if _, ok := def[p.Baseline]; !ok {
				def[p.Baseline] = signature(p.Rule)
			}
		}
	}
	out := map[string]blKind{}
	for kind, bl := range blKindOf {
		k := blKind{sig: fmt.Sprintf("%s/v%d", def[bl], blVersions[kind])}
		if kind != kindIP {
			k.zone = zone
		}
		out[kind] = k
	}
	return out
}

// maxBaselineKey bounds a stored entity's key (a sign-in account's is its scope, '|', the actor).
const maxBaselineKey = 2*siem.MaxShort + 8

// loadBaselines reads the learned state back at New. A row that doesn't decode is dropped (and its
// row deleted with the next save); a kind with more rows than its cap keeps the ones saved most
// recently and is rewritten at the next full save. A kind not read back (an error) is not checked
// against the time zone, so its stored rows are never rewritten from an empty table by a reset.
func (e *Engine) loadBaselines() {
	now := e.now()
	b := newBaselines(now)
	e.bl = b
	ctx := context.Background()
	zones, err := e.db.syncBaselineKinds(ctx, blKinds(zoneSig(b.loc)))
	if err != nil {
		e.log.Error("security detection: baselines not loaded", "err", err)
		return
	}
	habitOf := func(v []byte) (habit, error) { return decodeHabit(v, signinCaps) }
	habitSettled := func(x *habit) bool { return x.settled(now) }
	var errs []error
	for _, l := range []struct {
		kind string
		load func() error
	}{
		{kindSignin, func() error { return loadKind(e, b.signin, habitOf, habitSettled) }},
		{kindSigninApp, func() error { return loadKind(e, b.signinApp, habitOf, habitSettled) }},
		{kindAdmin, func() error {
			return loadKind(e, b.admin, func(v []byte) (habit, error) { return decodeHabit(v, adminCaps) }, habitSettled)
		}},
		{kindTraffic, func() error { return loadKind(e, b.traffic, decodeTraffic, (*hostTraffic).hasHistory) }},
		{kindIP, func() error {
			return loadKind(e, b.ip, decodeIP, func(x *addrMix) bool { return x.settled(now.UnixNano()) })
		}},
	} {
		if err := l.load(); err != nil {
			errs = append(errs, err)
			continue
		}
		b.zones[l.kind] = zones[l.kind]
	}
	if err := errors.Join(errs...); err != nil {
		e.log.Error("security detection: baselines not fully loaded", "err", err)
	}
}

func loadKind[T any](e *Engine, t *table[T], dec func([]byte) (T, error), settled func(*T) bool) error {
	rows, bad, err := e.db.loadBaselineRows(context.Background(), t.kind, t.max+1)
	if err != nil {
		return err
	}
	if len(rows) > t.max {
		rows, t.resync = rows[:t.max], true
	}
	// Oldest first, so the most recently saved end up the most recently used.
	for i := len(rows) - 1; i >= 0; i-- {
		r := rows[i]
		v, err := dec(r.data)
		if err != nil || r.key == "" || len(r.key) > maxBaselineKey || t.peek(r.key) != nil {
			bad++
			t.noteGone(r.key)
			continue
		}
		x := t.add(r.key)
		x.v, x.saved = v, true
		if settled(&x.v) {
			t.protect(x)
		}
	}
	if bad > 0 {
		e.log.Warn("security detection: learned baseline entries discarded", "kind", t.kind, "count", bad)
	}
	return nil
}

// baselineTick runs on the engine's write tick: it closes the traffic baseline's finished hours
// and saves up to blTickRows changed entities.
func (e *Engine) baselineTick() {
	b := e.bl
	if b == nil || e.closed.Load() {
		return
	}
	e.syncRules()
	b.checkZone()
	b.applyDeletes(e)
	now := e.now()
	b.trafficTick(e, now)
	b.save(e, now, false)
}

// saveBaselines runs on the engine's persist tick and at shutdown: every changed entity is saved,
// and the kinds due a rewrite are rewritten.
func (e *Engine) saveBaselines() {
	if e.bl == nil || e.closed.Load() {
		return
	}
	e.bl.checkZone()
	e.bl.applyDeletes(e)
	e.bl.save(e, e.now(), true)
}

// maxAppDeletes bounds the app changes waiting for the engine goroutine, and the apps deleted
// lately whose sign-ins aren't learned (appGoneFor).
const maxAppDeletes = 1024

// appGoneFor is how long after DeleteAppBaselines a deleted app's sign-ins aren't learned: those
// still queued for the engine can't make its baselines again.
const appGoneFor = 10 * time.Minute

// DeleteAppBaselines forgets what the sign-in baseline learned of the accounts of the app slug
// (scope app:<slug>), for an app being deleted. Its saved rows are deleted before it returns (it
// waits for detect.db's write connection, at most until ctx ends or 30 s); the entries in memory
// are dropped at the next baseline step of the engine goroutine (within a second while Run runs, at
// the first one after it starts), which also deletes any row of them it saved in between. For
// appGoneFor after the call the app's sign-ins aren't learned. It never waits for the engine
// goroutine, so it works whether or not Run runs. Errors: an invalid slug (siem.ErrInvalidInput),
// the engine closed, too many changes not taken by the engine yet, or the database's. Calling it
// again is safe.
func (e *Engine) DeleteAppBaselines(ctx context.Context, slug string) error {
	if err := checkSlug(slug); err != nil {
		return err
	}
	prefix := appScope(slug) + "|"
	if err := e.queueAppOp(appOp{prefix: prefix, at: e.now()}); err != nil {
		return err
	}
	return e.db.deleteBaselinePrefix(ctx, kindSigninApp, prefix)
}

// KeepAppBaselines forgets what the sign-in baseline learned of the accounts of every app not in
// slugs (the apps that exist; none: every app's), in memory and saved, as DeleteAppBaselines does:
// serve calls it at start, for the apps deleted while detection was off. Sign-ins of other
// sources are kept. The errors are DeleteAppBaselines'.
func (e *Engine) KeepAppBaselines(ctx context.Context, slugs []string) error {
	keep := make(map[string]bool, len(slugs))
	for _, s := range slugs {
		if err := checkSlug(s); err != nil {
			return err
		}
		keep[appScope(s)+"|"] = true
	}
	if err := e.queueAppOp(appOp{keep: keep}); err != nil {
		return err
	}
	return e.db.keepBaselinePrefixes(ctx, kindSigninApp, keep)
}

func checkSlug(slug string) error {
	if slug == "" || len(slug) > siem.MaxShort {
		return invalidIn("an app slug is 1 to %d bytes", siem.MaxShort)
	}
	return nil
}

// queueAppOp hands an app sign-in change to the goroutine that owns the tables.
func (e *Engine) queueAppOp(op appOp) error {
	b := e.bl
	if e.closed.Load() || b == nil {
		return errClosed
	}
	b.delMu.Lock()
	defer b.delMu.Unlock()
	if op.keep == nil && slices.ContainsFunc(b.delOps, func(o appOp) bool { return o.keep == nil && o.prefix == op.prefix }) {
		return nil
	}
	if len(b.delOps) >= maxAppDeletes {
		return errBusy
	}
	b.delOps = append(b.delOps, op)
	b.delN.Store(int32(len(b.delOps)))
	return nil
}

// appPrefix is the "app:<slug>|" an app account's key starts with, "" for another source's.
func appPrefix(key string) string {
	if !strings.HasPrefix(key, "app:") {
		return ""
	}
	if i := strings.IndexByte(key, '|'); i >= 0 {
		return key[:i+1]
	}
	return ""
}

// applyDeletes applies the app sign-in changes asked since the last step: the entries of the apps
// gone are dropped (their saved rows, if any are left, go with the next save) and a deleted app's
// sign-ins aren't learned for appGoneFor. On the goroutine that owns the tables.
func (b *baselines) applyDeletes(e *Engine) {
	if b.delN.Load() == 0 {
		return
	}
	b.delMu.Lock()
	ops := b.delOps
	b.delOps = nil
	b.delN.Store(0)
	b.delMu.Unlock()
	for _, op := range ops {
		if op.keep == nil {
			b.markAppGone(op.prefix, op.at.Add(appGoneFor), e.now())
		}
	}
	b.signinApp.each(func(x *tent[habit]) {
		p := appPrefix(x.key)
		if p == "" {
			return
		}
		for _, op := range ops {
			if op.keep == nil && op.prefix == p || op.keep != nil && !op.keep[p] {
				b.signinApp.drop(x)
				return
			}
		}
	})
}

// markAppGone has prefix's sign-ins not learned until until; past maxAppDeletes apps, the one whose
// time ends first is let go.
func (b *baselines) markAppGone(prefix string, until, now time.Time) {
	for p, u := range b.appGone {
		if !u.After(now) {
			delete(b.appGone, p)
		}
	}
	if _, ok := b.appGone[prefix]; !ok && len(b.appGone) >= maxAppDeletes {
		first := ""
		for p, u := range b.appGone {
			if first == "" || u.Before(b.appGone[first]) {
				first = p
			}
		}
		delete(b.appGone, first)
	}
	if until.After(b.appGone[prefix]) {
		b.appGone[prefix] = until
	}
}

// appIsGone reports whether scope is an app deleted lately (appGoneFor).
func (b *baselines) appIsGone(scope string, now time.Time) bool {
	if len(b.appGone) == 0 {
		return false
	}
	until, ok := b.appGone[scope+"|"]
	if ok && !until.After(now) {
		delete(b.appGone, scope+"|")
		return false
	}
	return ok
}

// save writes what changed: on a tick at most blTickRows rows and deletions in one transaction; in
// full every change, blChunk rows per transaction, after rewriting the kinds due one. After a
// failed write the ticks wait (backoff); a full save tries anyway.
func (b *baselines) save(e *Engine, now time.Time, full bool) {
	if !full && b.backoff > 0 && now.Sub(b.failAt) < b.backoff {
		return
	}
	ctx := context.Background()
	if full {
		for _, s := range b.stores {
			if !s.needsResync() {
				continue
			}
			if err := b.rewrite(ctx, e, s, now); err != nil {
				b.saveFailed(e, now, err)
				return
			}
			b.backoff = 0
		}
	}
	limit := blTickRows
	if full {
		limit = blChunk
	}
	type took struct {
		s    blStore
		rows []blRow
		gone []string
	}
	for {
		var rows, gone []blRow
		var took1 []took
		for _, s := range b.stores {
			if !s.pending() {
				continue
			}
			t := took{s: s, rows: s.takeDirty(max(limit-len(rows), 0)), gone: s.takeGone(max(limit-len(gone), 0))}
			rows = append(rows, t.rows...)
			for _, k := range t.gone {
				gone = append(gone, blRow{kind: s.kindName(), key: k})
			}
			took1 = append(took1, t)
		}
		if len(rows) == 0 && len(gone) == 0 {
			return
		}
		if err := e.db.writeBaselines(ctx, rows, gone, now.UnixNano(), nil); err != nil {
			for _, t := range took1 {
				t.s.unsave(t.rows, t.gone)
			}
			b.saveFailed(e, now, err)
			return
		}
		b.backoff = 0
		if !full {
			return
		}
	}
}

// rewrite saves every entity of s, blChunk per transaction, and with the last of them deletes the
// kind's other rows and records the zone its hours are in: a failure part-way loses no stored
// row (the old ones are still there) and the rewrite is due again.
func (b *baselines) rewrite(ctx context.Context, e *Engine, s blStore, now time.Time) error {
	kind := s.kindName()
	stamp, err := e.db.rewriteStamp(ctx, kind, now)
	if err != nil {
		return err
	}
	zone := ""
	if s.timed() {
		zone = b.zone
	}
	keys := s.startRewrite()
	for i := 0; ; i += blChunk {
		j := min(i+blChunk, len(keys))
		var fin *blFinish
		if j == len(keys) {
			fin = &blFinish{kind: kind, zone: zone, stamp: stamp}
		}
		if err := e.db.writeBaselines(ctx, s.encodeKeys(keys[i:j]), nil, stamp, fin); err != nil {
			s.setResync()
			return err
		}
		if fin != nil {
			break
		}
	}
	if s.timed() {
		b.zones[kind] = zone
	}
	return nil
}

func (b *baselines) saveFailed(e *Engine, now time.Time, err error) {
	b.failAt, b.backoff = now, min(max(2*b.backoff, blBackoffMin), blBackoffMax)
	e.writeErrors.Add(1)
	e.logLimited("baselines", "security detection: learned baselines not saved", "err", err)
}
