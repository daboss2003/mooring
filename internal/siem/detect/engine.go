// Package detect is the security-log detection engine (docs/security-detections.md): it evaluates
// rules over every finished security event, records detections in <dir>/detect.db, emits each
// detection as a siem.detection event, and sends high and critical ones to the alert channels.
// The built-in rule pack is in pack.go; overrides and custom rules live in Mooring's database
// (table security_rules).
//
// One goroutine (Run) does all evaluation, so the state needs no locks; the pipeline hands events
// over through Subscriber, which never blocks. Every structure keyed by event values is bounded.
package detect

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"hash/maphash"
	"log/slog"
	"maps"
	"math"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/store"
)

// Alerter is the part of the alert store the engine needs.
type Alerter interface {
	EnqueueInfra(ctx context.Context, o alert.Outbox) error
}

// Options configures an Engine.
type Options struct {
	Dir     string    // <data_dir>/security-logs: the engine keeps detect.db there
	MainDB  *store.DB // Mooring's database, for the rule store only (nil: the pack, read-only)
	Alerter Alerter   // nil: no alerts
	// Emit hands a siem.detection event to the security-log pipeline; it must not block (false:
	// not taken).
	Emit func(siem.Event) bool
	// MapValue maps a clear value in a rule query to its stored form, like the search page does:
	// field is "actor" or the full "f.<key>". nil keeps values as written.
	MapValue func(field, value string) string
	Log      *slog.Logger
	Now      func() time.Time
}

// Tunables.
const (
	queueSize     = 8192
	reportQueue   = 256
	alertQueue    = 256
	maxActive     = 20000 // detections kept in memory for coalescing
	maxParked     = 20000 // detections not yet written kept outside the active ones
	maxKnown      = 200000
	maxBatch      = 2000 // detection writes per transaction
	writeTick     = time.Second
	writeEvery    = 10 * time.Second // an updated detection is written (and emitted) at most this often
	persistEvery  = 10 * time.Minute // learned state saved, and detect.db's size checked
	pruneEvery    = 24 * time.Hour
	pruneFirst    = 10 * time.Minute
	keepFor       = 400 * 24 * time.Hour
	alertCooldown = time.Hour
	alertTimeout  = 3 * time.Second
	emitBudget    = 2 * time.Second        // per flush: how long a full emit lane is waited on in all
	emitRetry     = 500 * time.Microsecond // between two tries on a full emit lane
	drainTimeout  = 3 * time.Second        // at shutdown, for the events and reports still queued
	logEvery      = time.Minute
	minCoalesce   = time.Hour

	// Per rule and wall-clock hour (owner decisions): at most newPerHour new detections (more keys
	// are counted in one rollup detection, key "*"), and at most alertsPerHour alerts for high
	// detections (more are counted in one summary alert at the end of the hour; critical ones are
	// never held back).
	newPerHour    = 50
	alertsPerHour = 5
	maxRolledKeys = 100000 // keys remembered (all rules' rollups an hour) so a rollup counts each key once; 8 bytes each saved (800 KB at most)
	maxRuleHours  = 4096   // rules with an hourly counter
	maxCooldowns  = 20000  // (rule, key) pairs with an alert sent within the hour

	maxDBBytes = 512 << 20 // detect.db's pages in use; past it the oldest detections are removed

	// Alert delivery: alertTries attempts, retried after alertBackoff[i] (about a minute in all).
	alertTries  = 3
	maxRetrying = alertQueue
	inflightTTL = 15 * time.Minute // an alert not reported back by then is no longer in flight

	writeBackoffMin = 5 * time.Second // after a failed write, flushes wait this long (doubling)
	writeBackoffMax = time.Minute
	readBackoff     = 5 * time.Second // after a failed lookup, stored detections aren't looked up

	// Intentional: events older than a day (a host-log backlog read after downtime, a replay) or
	// more than 5 minutes ahead (clock skew, a forged time) are stored and searchable but never
	// evaluated: a replay would fire every rule again, and a future time would hold windows open.
	maxAge  = 24 * time.Hour
	maxSkew = 5 * time.Minute

	// KindDetection is the kind of the security event each detection is emitted as.
	KindDetection = "siem.detection"
	// AlertKind is the alert kind of high and critical detections.
	AlertKind = "security_detection"
	// TargetSIEM is the alert target of detections by the rules (an app /ops alert's target is
	// "<app>/<service>").
	TargetSIEM = "security-logs"
	// RollupKey is the key of a rule's rollup detection (the keys over newPerHour in one hour). A
	// real key can be "*" too: the rollup is told apart by its stored rollup flag, never its key.
	RollupKey = "*"
)

var defaultAlertBackoff = []time.Duration{10 * time.Second, 40 * time.Second}

// Stats are the engine's counters since start.
type Stats struct {
	Queue          int   // events waiting
	Dropped        int64 // events not evaluated because the queue was full
	ReportsDropped int64 // app /ops detections not taken because their queue was full
	AlertsDropped  int64 // alerts not sent because the alert queue was full
	AlertsFailed   int64 // alerts given up after alertTries failed attempts
	EmitDropped    int64 // detections the pipeline didn't take as events
	Panics         int64 // evaluations that panicked (recovered)
	WriteErrors    int64 // detection database writes that failed
	Lost           int64 // detections dropped unwritten (writes kept failing)
}

// limits are the per-hour caps and the database cap; tests lower them.
type limits struct {
	newPerHour, alertsPerHour int
	dbBytes                   int64
	alertBackoff              []time.Duration
	alertTimeout              time.Duration // one outbox write, and the alert worker's shutdown pass
}

// Engine evaluates the rules. Create it with New, start Run, hand it events with Subscriber.
type Engine struct {
	opt  Options
	log  *slog.Logger
	now  func() time.Time
	db   *db
	rs   *ruleStore
	seed maphash.Seed
	lim  limits

	in      chan siem.Event
	reports chan siem.Detection
	alerts  chan *alertJob
	results chan alertResult
	running atomic.Bool
	closed  atomic.Bool

	dropped, reportsDropped, alertsDropped, alertsFailed, emitDropped, panics, writeErrors, lost atomic.Int64
	emitUntil                                                                                    time.Time // the current flush's emit budget ends (the engine goroutine's)
	lastLog                                                                                      sync.Map  // category → *atomic.Int64 (unix ns)

	// The rules in force; replaced whole by SaveRule/DeleteRule/ResetRule (under mu).
	rules  atomic.Pointer[ruleSet]
	mu     sync.Mutex
	ov     map[string]override
	custom map[string]storedCustom

	// Evaluation state: owned by the Run goroutine (or a test calling process directly).
	cur     *ruleSet
	states  map[string]*ruleState
	pending map[string]map[string]stateRow // persisted state not yet matched to a rule
	active  map[string]*list.Element       // rule ID + "\x00" + key → *activeDet
	actLRU  list.List
	seq     uint64
	dirty   map[*activeDet]struct{}
	known   keyFilter // which (rule, key) may have a stored detection to update

	// Detections not written yet that are out of active (evicted, or a past hour's rollup), oldest
	// first; parked[mapKey] is the newest of a key, so a firing still finds it.
	parked  map[string]*activeDet
	parkLRU list.List

	// Per rule, for the current wall-clock hour.
	hour    time.Time
	newRows map[string]int
	rollups map[string]*activeDet
	rolledN int // keys in the rollups' sets (activeDet.keys), at most maxRolledKeys
	caps    map[capKey]*capState
	// A summary alert was settled (sent, given up or dropped) since the last save of the hour's
	// counters: saved at the next write tick.
	hourDirty bool

	cooldown map[string]time.Time // mapKey (a rollup's rollupKey) → when the last sent alert was raised
	inflight map[string]time.Time // an alert queued or being retried → when it was raised
	// Alert times of detections that left memory before their alert was reported back: detection
	// ID → unix ns, stored by the next flush.
	alertedRows map[int64]int64

	writeFailAt  time.Time
	writeBackoff time.Duration // 0: the last write succeeded
	readFailAt   time.Time
}

// keyFilter tracks the (rule, key) pairs that may have a stored detection a firing could update,
// so a firing for a new key needs no database lookup. A hash collision only costs a lookup.
type keyFilter struct {
	seed maphash.Seed
	m    map[uint64]struct{}
	all  bool // too many to track: always look up
}

func (f *keyFilter) add(mk string) {
	if f.all {
		return
	}
	if len(f.m) >= maxKnown {
		f.all, f.m = true, nil
		return
	}
	f.m[maphash.String(f.seed, mk)] = struct{}{}
}

func (f *keyFilter) may(mk string) bool {
	if f.all {
		return true
	}
	_, ok := f.m[maphash.String(f.seed, mk)]
	return ok
}

// New opens <Dir>/detect.db, loads the rules (the pack merged with what MainDB stores) and the
// persisted state. A stored built-in setting that no longer validates falls back to the pack's
// value; a stored custom rule that doesn't is listed switched off (see buildSet).
func New(opts Options) (*Engine, error) {
	if opts.Dir == "" {
		return nil, errors.New("detect: no directory")
	}
	e := &Engine{opt: opts, log: opts.Log, now: opts.Now, seed: maphash.MakeSeed(),
		lim: limits{newPerHour: newPerHour, alertsPerHour: alertsPerHour, dbBytes: maxDBBytes,
			alertBackoff: defaultAlertBackoff, alertTimeout: alertTimeout},
		in: make(chan siem.Event, queueSize), reports: make(chan siem.Detection, reportQueue),
		alerts: make(chan *alertJob, alertQueue), results: make(chan alertResult, 2*alertQueue),
		ov: map[string]override{}, custom: map[string]storedCustom{},
		states: map[string]*ruleState{}, active: map[string]*list.Element{}, dirty: map[*activeDet]struct{}{},
		parked: map[string]*activeDet{}, newRows: map[string]int{}, rollups: map[string]*activeDet{},
		caps: map[capKey]*capState{}, cooldown: map[string]time.Time{},
		inflight: map[string]time.Time{}, alertedRows: map[int64]int64{}}
	if e.log == nil {
		e.log = slog.New(slog.DiscardHandler)
	}
	if e.now == nil {
		e.now = time.Now
	}
	d, err := openDB(opts.Dir)
	if err != nil {
		return nil, err
	}
	e.db = d
	if opts.MainDB != nil {
		e.rs = &ruleStore{db: opts.MainDB.DB}
		ov, custom, errs, err := e.rs.load(context.Background())
		if err != nil {
			_ = d.close()
			return nil, fmt.Errorf("detect: load rules: %w", err)
		}
		for _, err := range errs {
			e.log.Error("security detection: stored rule skipped", "err", err)
		}
		e.ov, e.custom = ov, custom
	}
	if err := e.rebuild(); err != nil {
		_ = d.close()
		return nil, err
	}
	e.known = keyFilter{seed: maphash.MakeSeed(), m: map[uint64]struct{}{}}
	// Only a detection whose last event is within the longest coalescing window can be updated.
	keys, err := d.recentKeys(context.Background(), e.now().Add(-maxWindow-minCoalesce-maxSkew), maxKnown)
	if err != nil {
		e.log.Error("security detection: recent detections not read", "err", err)
		e.known.all = true
	}
	for _, k := range keys {
		e.known.add(k)
	}
	// The cooldowns of the alerts raised within the hour before a restart (findActive also takes
	// a stored detection's alert time when it reads one back).
	cds, err := d.alertedSince(context.Background(), e.now().Add(-alertCooldown), maxCooldowns)
	if err != nil {
		e.log.Error("security detection: recent alerts not read", "err", err)
	}
	maps.Copy(e.cooldown, cds)
	if e.pending, err = d.loadState(context.Background()); err != nil {
		e.log.Error("security detection: learned state not loaded", "err", err)
		e.pending = nil
	}
	if err := e.loadHour(); err != nil {
		e.log.Error("security detection: hourly limits not read back", "err", err)
	}
	return e, nil
}

// loadHour reads back the per-rule counters saved for the current wall-clock hour (new detections,
// the rollup detection and the keys counted in it, high alerts and the detections owed a summary
// alert; see saveHour), so a restart within the hour keeps the hourly limits. Of the previous
// hour, exactly now's hour − 1h, it takes the summary alerts still owed (the process was killed
// before it sent them): sendCaps sends them, late, at its next run. Counters saved for any other
// hour, a later one too (the clock was ahead, then corrected), are not used; a stored count below 0
// is 0.
func (e *Engine) loadHour() error {
	ctx := context.Background()
	now := e.now()
	hour := now.UTC().Truncate(time.Hour)
	e.hour = hour
	rows, err := e.db.loadHours(ctx, hour, 2*maxRuleHours, false)
	if err != nil {
		return err
	}
	count := func(v int64) int { return int(min(max(v, 0), math.MaxInt32)) }
	valid := func(r *hourRow) bool {
		// A rule ID never holds a control character (see rollupKey).
		return r.rule != "" && len(r.rule) <= siem.MaxShort && strings.IndexFunc(r.rule, unicode.IsControl) < 0 &&
			(r.source == "" || r.source == siem.DetectionSIEM || r.source == siem.DetectionOps)
	}
	capOf := func(r *hourRow, late bool) *capState {
		return &capState{hour: r.hour, sent: count(r.sent), more: count(r.more), source: r.source, late: late,
			name: siem.Cut(r.name, siem.MaxShort), target: siem.Cut(r.target, 2*siem.MaxShort+1)}
	}
	rollupOf := map[string]*hourRow{}
	for i := range rows {
		r := &rows[i]
		if !valid(r) {
			continue
		}
		if n := count(r.newCount); n > 0 && len(e.newRows) < maxRuleHours {
			e.newRows[r.rule] = n
		}
		if r.rollupID > 0 {
			rollupOf[r.rule] = r
		}
		if r.source != "" && len(e.caps) < maxRuleHours {
			e.caps[capKey{r.rule, hour.Unix()}] = capOf(r, false)
		}
	}
	if len(rollupOf) > 0 {
		ss, err := e.db.hourRollups(ctx, hour, maxRuleHours)
		if err != nil {
			return err
		}
		for _, s := range ss {
			id := s.d.RuleID
			hr := rollupOf[id]
			if hr == nil || hr.rollupID != s.d.ID || len(e.rollups) >= maxRuleHours {
				continue
			}
			// The keys counted in it come back with it (only with it: in a new rollup they'd be
			// missing from its count). A set that doesn't decode starts empty.
			keys := decodeRolled(hr.rolled, maxRolledKeys-e.rolledN)
			if keys == nil {
				keys = newRolledSet()
			}
			e.rolledN += len(keys.m)
			r := &activeDet{s: s, mapKey: rollupKey(id), hour: hour, emitted: true, wrote: now, keys: keys}
			e.seq++
			r.seq = e.seq
			e.rollups[id] = r
		}
	}
	prev := hour.Add(-time.Hour)
	owed, err := e.db.loadHours(ctx, prev, maxRuleHours, true)
	if err != nil {
		return err
	}
	for i := range owed {
		r := &owed[i]
		if valid(r) && r.source != "" && r.more > 0 && len(e.caps) < maxRuleHours {
			e.caps[capKey{r.rule, prev.Unix()}] = capOf(r, true)
		}
	}
	return nil
}

// saveHourIfDirty saves the hour's counters when a summary alert was settled since the last save
// (the write tick).
func (e *Engine) saveHourIfDirty() {
	if e.hourDirty && !e.closed.Load() {
		e.persistHour()
	}
}

// persistHour saves the hour's counters (saveHour), logging a failure (the next save tries again).
func (e *Engine) persistHour() {
	e.hourDirty = false
	if err := e.saveHour(); err != nil {
		e.writeErrors.Add(1)
		e.logLimited("persist-hour", "security detection: hourly limits not saved", "err", err)
	}
}

// saveHour saves the current wall-clock hour's per-rule counters (see loadHour) in place of the
// ones saved before: at most one row per rule with a counter, each map bounded by maxRuleHours,
// the rollups' keys at most maxRolledKeys × 8 bytes (800 KB) in all. A previous hour's summary
// still owed (not queued yet) is saved too, so a kill before it is sent doesn't lose it.
func (e *Engine) saveHour() error {
	hour := e.now().UTC().Truncate(time.Hour)
	prev := hour.Add(-time.Hour)
	by := map[capKey]*hourRow{}
	row := func(id string, h time.Time) *hourRow {
		k := capKey{id, h.Unix()}
		r := by[k]
		if r == nil {
			r = &hourRow{rule: id, hour: h}
			by[k] = r
		}
		return r
	}
	if e.hour.Equal(hour) { // else they are a past hour's, cleared at the next firing (syncHour)
		for id, n := range e.newRows {
			row(id, hour).newCount = int64(n)
		}
		for id, r := range e.rollups {
			if r.s.d.ID != 0 { // its keys only with it (see loadHour)
				x := row(id, hour)
				x.rollupID = r.s.d.ID
				if r.keys != nil {
					x.rolled = r.keys.encode()
				}
			}
		}
	}
	for k, cs := range e.caps {
		if k.hour == hour.Unix() || (k.hour == prev.Unix() && cs.more > 0) {
			r := row(k.rule, cs.hour)
			r.sent, r.more, r.source, r.name, r.target = int64(cs.sent), int64(cs.more), cs.source, cs.name, cs.target
		}
	}
	rows := make([]hourRow, 0, len(by))
	for _, r := range by {
		rows = append(rows, *r)
	}
	return e.db.saveHours(context.Background(), rows)
}

// rebuild compiles the rules from the pack, e.ov and e.custom and puts them in force.
func (e *Engine) rebuild() error {
	rs, errs := buildSet(e.ov, e.custom, e.opt.MapValue, e.now())
	for _, err := range errs {
		e.log.Error("security detection: stored rule setting not used", "err", err)
	}
	if len(rs.list) == 0 {
		return errors.New("detect: no rule compiles")
	}
	e.rules.Store(rs)
	return nil
}

// Close closes the detection database. Call it after Run has returned.
func (e *Engine) Close() error {
	if !e.closed.CompareAndSwap(false, true) {
		return nil
	}
	return e.db.close()
}

// Stats returns the engine's counters.
func (e *Engine) Stats() Stats {
	return Stats{Queue: len(e.in), Dropped: e.dropped.Load(), ReportsDropped: e.reportsDropped.Load(),
		AlertsDropped: e.alertsDropped.Load(), AlertsFailed: e.alertsFailed.Load(), EmitDropped: e.emitDropped.Load(),
		Panics: e.panics.Load(), WriteErrors: e.writeErrors.Load(), Lost: e.lost.Load()}
}

// logLimited logs at most once per logEvery per category.
func (e *Engine) logLimited(cat, msg string, args ...any) {
	v, _ := e.lastLog.LoadOrStore(cat, new(atomic.Int64))
	last := v.(*atomic.Int64)
	now := time.Now().UnixNano()
	prev := last.Load()
	if now-prev < int64(logEvery) || !last.CompareAndSwap(prev, now) {
		return
	}
	e.log.Warn(msg, args...)
}

// timely reports whether an event's time is one the rules evaluate (see maxAge).
func timely(ts, now time.Time) bool {
	return !ts.Before(now.Add(-maxAge)) && !ts.After(now.Add(maxSkew))
}

// Subscriber returns the pipeline subscriber: it copies the event into the engine's queue, or
// drops and counts it when the queue is full. It never blocks.
func (e *Engine) Subscriber() func(siem.Event) {
	return func(ev siem.Event) {
		defer func() {
			if r := recover(); r != nil {
				e.panics.Add(1)
			}
		}()
		if ev.Src == siem.SrcSIEM || !timely(ev.TS, e.now()) {
			return
		}
		// The pipeline shares F with the other subscribers: copy it (values are immutable).
		ev.F = maps.Clone(ev.F)
		if ev.Geo != nil {
			g := *ev.Geo
			g.Lists = slices.Clone(g.Lists)
			ev.Geo = &g
		}
		select {
		case e.in <- ev:
		default:
			n := e.dropped.Add(1)
			e.logLimited("dropped", "security detection: queue full, events not evaluated", "dropped_total", n)
		}
	}
}

// Report takes a detection from a source that evaluates its own condition (the app /ops alerts):
// it is stored, emitted and alerted on by the engine goroutine. It never blocks.
func (e *Engine) Report(d siem.Detection) {
	d.MITRE = slices.Clone(d.MITRE)
	d.Evidence = slices.Clone(d.Evidence)
	if d.Geo != nil {
		g := *d.Geo
		g.Lists = slices.Clone(g.Lists)
		d.Geo = &g
	}
	select {
	case e.reports <- d:
	default:
		n := e.reportsDropped.Add(1)
		e.logLimited("reports", "security detection: report queue full, app detection dropped", "dropped_total", n)
	}
}

// Run evaluates events until ctx is done. Then it evaluates what is still queued (for at most
// drainTimeout) and raises the hour's pending summary alerts, stops the alert worker (which tries
// what is queued once more) while taking its results, and only then writes what is pending and
// saves the hour's counters and the learned state, so the alerts sent at shutdown are stored on
// their detections and counted after a restart. It runs the daily prune. Call it once.
func (e *Engine) Run(ctx context.Context) {
	if !e.running.CompareAndSwap(false, true) {
		return
	}
	// The worker outlives ctx: the alerts of the last events are raised after it is done.
	wctx, stopWorker := context.WithCancel(context.WithoutCancel(ctx))
	workerDone := make(chan struct{})
	go func() {
		defer close(workerDone)
		e.alertWorker(wctx)
	}()
	defer func() {
		stopWorker()
		<-workerDone
	}()

	write := time.NewTicker(writeTick)
	defer write.Stop()
	persist := time.NewTicker(persistEvery)
	defer persist.Stop()
	prune := time.NewTimer(pruneFirst)
	defer prune.Stop()
	for {
		select {
		case <-ctx.Done():
			e.safe(e.drain)
			e.safe(func() { e.sendCaps(true) })
			stopWorker()
			e.awaitWorker(workerDone)
			e.safe(func() { e.flush(true) })
			e.safe(e.persist)
			return
		case ev := <-e.in:
			e.safe(func() { e.process(&ev) })
		case d := <-e.reports:
			e.safe(func() { e.report(d) })
		case r := <-e.results:
			e.safe(func() { e.finishAlert(r) })
		case <-write.C:
			e.safe(func() { e.flush(false) })
			e.safe(func() { e.sendCaps(false) })
			e.safe(e.saveHourIfDirty)
		case <-persist.C:
			e.safe(e.persist)
			e.safe(e.capSize)
		case <-prune.C:
			e.safe(e.prune)
			e.safe(e.capSize)
			prune.Reset(pruneEvery)
		}
	}
}

// drain evaluates the events and reports still queued, for at most drainTimeout.
func (e *Engine) drain() {
	deadline := time.Now().Add(drainTimeout)
	for time.Now().Before(deadline) {
		select {
		case ev := <-e.in:
			e.safe(func() { e.process(&ev) })
		case d := <-e.reports:
			e.safe(func() { e.report(d) })
		default:
			return
		}
	}
}

// awaitWorker takes the alert worker's results until it has stopped (done closed), then the ones
// still waiting, so none is lost to a full results channel.
func (e *Engine) awaitWorker(done <-chan struct{}) {
	for {
		select {
		case r := <-e.results:
			e.safe(func() { e.finishAlert(r) })
		case <-done:
			for {
				select {
				case r := <-e.results:
					e.safe(func() { e.finishAlert(r) })
				default:
					return
				}
			}
		}
	}
}

// safe runs f, recovering (and counting) a panic so one bad event can't stop detection.
func (e *Engine) safe(f func()) {
	defer func() {
		if r := recover(); r != nil {
			n := e.panics.Add(1)
			e.logLimited("panic", "security detection: evaluation panicked", "panic", fmt.Sprint(r), "panics_total", n)
		}
	}()
	f()
}

// syncRules puts a new rule set in force for the evaluation: a rule whose matching definition is
// unchanged keeps its state, any other starts empty (or from its persisted state at startup).
func (e *Engine) syncRules() {
	rs := e.rules.Load()
	if rs == e.cur {
		return
	}
	next := make(map[string]*ruleState, len(rs.list))
	for _, c := range rs.list {
		if old := e.states[c.r.ID]; old != nil && old.sig == c.sig {
			next[c.r.ID] = old
			continue
		}
		st := newRuleState(c.sig)
		e.restore(c, st)
		next[c.r.ID] = st
	}
	e.states, e.cur = next, rs
}

// restore loads a rule's persisted state when its signature still matches.
func (e *Engine) restore(c *compiled, st *ruleState) {
	parts := e.pending[c.r.ID]
	if parts == nil {
		return
	}
	delete(e.pending, c.r.ID)
	if p, ok := parts[partSeen]; ok && p.sig == c.sig && c.r.Type == siem.RuleNewValue {
		if s, err := decodeSeen(p.data); err == nil {
			st.nv = s
		} else {
			e.log.Warn("security detection: learned values discarded", "rule", c.r.ID, "err", err)
		}
	}
	if p, ok := parts[partAnomaly]; ok && p.sig == c.sig && c.r.Type == siem.RuleAnomaly {
		if err := decodeAnomaly(p.data, st); err != nil {
			e.log.Warn("security detection: learned counts discarded", "rule", c.r.ID, "err", err)
		}
	}
}

// Persisted state parts.
const (
	partSeen    = "seen"
	partAnomaly = "anomaly"
)

// persist saves the current hour's per-rule counters (saveHour) and the learned state of
// new_value and anomaly rules (when it changed), and removes the saved state of rules that are gone.
func (e *Engine) persist() {
	if e.closed.Load() {
		return
	}
	e.persistHour()
	e.syncRules()
	keep := map[string]bool{}
	var rows []stateWrite
	for _, c := range e.cur.list {
		keep[c.r.ID] = true
		st := e.states[c.r.ID]
		switch {
		case st == nil:
		case c.r.Type == siem.RuleNewValue && st.nv != nil && st.nv.dirty:
			rows = append(rows, stateWrite{c.r.ID, partSeen, c.sig, st.nv.encode()})
		case c.r.Type == siem.RuleAnomaly && st.anDirty:
			rows = append(rows, stateWrite{c.r.ID, partAnomaly, c.sig, encodeAnomaly(st)})
		}
	}
	// Persisted state not yet matched to a rule (not in force yet) is kept too.
	for id := range e.pending {
		keep[id] = true
	}
	if err := e.db.saveState(context.Background(), rows, keep, e.now()); err != nil {
		e.writeErrors.Add(1)
		e.logLimited("persist", "security detection: learned state not saved", "err", err)
		return
	}
	for _, c := range e.cur.list {
		if st := e.states[c.r.ID]; st != nil {
			if st.nv != nil {
				st.nv.dirty = false
			}
			st.anDirty = false
		}
	}
}

func (e *Engine) prune() {
	if e.closed.Load() {
		return
	}
	n, err := e.db.prune(context.Background(), e.now().Add(-keepFor))
	if err != nil {
		e.writeErrors.Add(1)
		e.logLimited("prune", "security detection: prune failed", "err", err)
	} else if n > 0 {
		e.log.Info("security detection: old detections removed", "count", n)
	}
}

// capSize keeps detect.db's pages in use within lim.dbBytes: past it, the oldest low and medium
// detections are removed, then (none left) the oldest of any severity, down to nine tenths.
func (e *Engine) capSize() {
	if e.closed.Load() {
		return
	}
	n, err := e.db.trimTo(context.Background(), e.lim.dbBytes, e.lim.dbBytes/10*9)
	if err != nil {
		e.writeErrors.Add(1)
		e.logLimited("size", "security detection: size cap failed", "err", err)
	} else if n > 0 {
		e.log.Warn("security detection: detections removed to keep detect.db within its size cap",
			"count", n, "cap_bytes", e.lim.dbBytes)
	}
}

// weight is how many events e stands for: F.repeated (syslog "message repeated N times") of a
// host event, at most maxWeight, else 1.
func weight(e *siem.Event) uint32 {
	// Intentional: only the host parser sets F.repeated from syslog's own "message repeated" line;
	// in an app's or the edge's event it is whatever the line's JSON said, so it weighs 1.
	if e.Src != siem.SrcHost {
		return 1
	}
	if v, ok := e.F["repeated"].(float64); ok && v >= 1 {
		return uint32(min(v, maxWeight))
	}
	return 1
}

// process evaluates one event against every enabled rule.
func (e *Engine) process(ev *siem.Event) {
	if ev.Src == siem.SrcSIEM || !timely(ev.TS, e.now()) {
		return
	}
	e.syncRules()
	w := weight(ev)
	for _, c := range e.cur.list {
		if c.r.Enabled {
			e.applyRule(c, e.states[c.r.ID], ev, w)
		}
	}
}

// applyRule applies one rule to one event.
func (e *Engine) applyRule(c *compiled, st *ruleState, ev *siem.Event, w uint32) {
	isThen := false
	if c.r.Type == siem.RuleSequence {
		isThen = c.then.Match(ev)
		if !isThen && !c.q.Match(ev) {
			return
		}
	} else if !c.q.Match(ev) {
		return
	}
	key, ok := c.group(ev)
	if !ok {
		return
	}
	t := ev.TS.UnixNano()
	switch c.r.Type {
	case siem.RuleThreshold:
		k := st.key(key)
		k.ring.add(t, w, c.r.Window, ringCap(c.r.Count))
		k.ev.add(ev)
		if k.ring.sum >= uint64(c.r.Count) {
			e.fire(c, key, ev, firing{count: int(min(k.ring.sum, math.MaxInt32)), evidence: k.ev.list()})
			k.ring.reset()
			k.ev.reset()
		}
		st.charge(k)
	case siem.RuleDistinct:
		val, ok := c.field(ev)
		if !ok {
			return
		}
		k := st.key(key)
		if k.set == nil {
			k.set = &distinct{}
		}
		k.set.add(maphash.String(e.seed, val), t, c.r.Window)
		k.ev.add(ev)
		if n := len(k.set.m); n >= c.r.Count {
			e.fire(c, key, ev, firing{count: n, evidence: k.ev.list()})
			k.set.reset()
			k.ev.reset()
		}
		st.charge(k)
	case siem.RuleNewValue:
		val, ok := c.field(ev)
		if !ok {
			return
		}
		if st.nv == nil {
			st.nv = newSeen()
		}
		if st.nv.observe(key, val, t, c.r.Learn) {
			e.fire(c, key, ev, firing{count: 1, value: val, evidence: []siem.Evidence{evidenceOf(ev)}})
		}
	case siem.RuleAnomaly:
		// The learning period runs from the rule's first matching event, not the key's: once the
		// rule has learned, a key with no history (a host's first surge) fires at Count.
		if st.anStart == 0 || t < st.anStart {
			st.anStart = t
		}
		k := st.key(key)
		if k.an == nil {
			k.an = &anomaly{}
		}
		k.an.add(t, w, c.r.Window)
		st.anDirty = true
		k.ev.add(ev)
		n := k.an.windowCount(t, c.r.Window)
		if n >= uint64(c.r.Count) && t-st.anStart >= int64(c.r.Learn) {
			if exp := k.an.expected(t, c.r.Window); float64(n) > c.r.Factor*exp {
				e.fire(c, key, ev, firing{count: int(min(n, math.MaxInt32)), expected: exp, evidence: k.ev.list()})
				k.an.slots = [anomalySlots]slot{}
				k.ev.reset()
			}
		}
		st.charge(k)
		if !k.prot && k.an.settled() {
			st.promote(k)
		}
	case siem.RuleTravel:
		if ev.Geo == nil || (ev.Geo.Lat == 0 && ev.Geo.Lon == 0) || !validCoord(ev.Geo.Lat, ev.Geo.Lon) {
			return
		}
		k := st.key(key)
		cur := &point{t: t, lat: ev.Geo.Lat, lon: ev.Geo.Lon, place: place(ev.Geo)}
		if p := k.last; p != nil {
			dist := haversineKM(p.lat, p.lon, cur.lat, cur.lon)
			dt := time.Duration(max(absInt(t-p.t), int64(time.Second)))
			if dist > minTravelKM && dist/dt.Hours() > c.r.SpeedKMH {
				prev := *p
				e.fire(c, key, ev, firing{count: 1, from: &prev, to: cur, dist: dist, gap: time.Duration(absInt(t - p.t)),
					evidence: []siem.Evidence{evidenceOf(ev)}})
			}
		}
		k.last = cur
		st.charge(k)
	case siem.RuleSequence:
		if isThen {
			// A closing event ends the sequence for its key whether or not it fired: the preceding
			// events before it never count toward a later closing event.
			k := st.peek(key)
			if k == nil {
				return
			}
			k.ring.expire(t - int64(c.r.Window))
			if k.ring.sum >= uint64(c.r.Count) {
				evid := append(k.ev.list(), evidenceOf(ev))
				e.fire(c, key, ev, firing{count: int(min(k.ring.sum, math.MaxInt32)), evidence: evid})
			}
			k.ring.reset()
			k.ev.reset()
			st.charge(k)
			return
		}
		k := st.key(key)
		k.ring.add(t, w, c.r.Window, ringCap(c.r.Count))
		k.ev.add(ev)
		st.charge(k)
	}
}

// minTravelKM: two places closer than this never count as travel (city-level IP locations).
const minTravelKM = 500

func validCoord(lat, lon float64) bool {
	return !math.IsNaN(lat) && !math.IsNaN(lon) && lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180
}

func haversineKM(lat1, lon1, lat2, lon2 float64) float64 {
	const r = 6371.0
	rad := math.Pi / 180
	dlat, dlon := (lat2-lat1)*rad, (lon2-lon1)*rad
	a := math.Sin(dlat/2)*math.Sin(dlat/2) + math.Cos(lat1*rad)*math.Cos(lat2*rad)*math.Sin(dlon/2)*math.Sin(dlon/2)
	return 2 * r * math.Asin(math.Sqrt(min(1, a)))
}

func absInt(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}
