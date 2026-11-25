package detect

import (
	"container/list"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

// The log-pattern miner (docs/security-detections.md "Log patterns"). The pipeline hands it app
// lines and the host's unclassified lines (offer, never blocking); its own goroutine sorts each
// into its scope's templates (pattern_drain.go) under a CPU budget and counts it, and hands the
// pattern.* rules' firings to the engine goroutine (patternFire), which records them as any
// detection. The engine goroutine also closes the hours (tick) and saves what was learned
// (pattern_db.go). Everything below mu is shared by the three and taken in short holds: a batch of
// at most patBatch lines, a tick, a save's taking, a dashboard read.

// Rule IDs of the pattern rules (pack_pattern.go).
const (
	rulePatternNew      = "pattern.new"
	rulePatternNewError = "pattern.new_error"
	rulePatternSpike    = "pattern.spike"
	rulePatternChurn    = "pattern.churn"
)

const (
	patQueue       = 4096
	patQueueBytes  = 4 << 20 // bytes of the lines queued at most
	patLineCost    = 64      // bytes counted for a queued line beside its text
	patBatch       = 64      // lines between two checks of the CPU budget
	patFires       = 256
	patGrace       = 2 * time.Minute // an hour is closed this long after it ended (late lines)
	patForget      = 30 * day        // a template without a line this long is forgotten
	patOwnerForget = 400 * day       // … one the owner marked (expected, ignored), this long: a yearly job's stays
	patSweepEvery  = time.Hour       // the forgetting and the samples' expiry run this often (and when an hour closes)
	patSkew        = 2 * time.Minute // a stored time this far past the clock means the clock was set back
	maxPatMarks    = 2000            // owner's states kept apart from their templates
	patSampleAge   = time.Hour       // a template's sample is refreshed at most this often
	patRelearn     = 24 * time.Hour  // after a tokenizer change every scope learns again this long
	patChurnEvery  = 10 * time.Minute
	patLearnEvery  = 10 * time.Second // the learning scopes listed by PatternStats are this fresh
	maxPatLearning = 50

	defaultPatCPU       = 5
	maxPatCPU           = 25
	defaultPatRetention = 14 * day
	defaultPatLearn     = 7 * day
	defaultPatSettle    = 5 * minute

	rankWarn = 2 // siem.LevelRank(siem.LvlWarn)

	// Intentional: the miner sends at most patReportsPerHour new-pattern reports a rule and clock
	// hour, below the engine's newPerHour (engine.go: past it a rule's new detections of the hour
	// are rolled up into one, which the miner can't see). The owner wants every new pattern to have
	// a detection of its own, so the rest wait for the next hour, the oldest first. A report sent
	// in an hour's last patReportLate counts for the next hour too: the engine records it when it
	// takes it from the channel, which may be after the hour turned.
	patReportsPerHour = 40
	patReportLate     = time.Minute
)

// Fails to compile when patReportsPerHour isn't below the engine's cap.
const _ = uint(newPerHour - patReportsPerHour - 1)

// patTokVersion is stored with each scope: raise it when the tokenizer's output changes, and every
// scope learns again for patRelearn (an upgrade must not report every template as new). A var so
// tests can raise it.
var patTokVersion = 1

// Hour states of the miner's watched hours.
const (
	hourOff     uint8 = iota // not watched whole (not running, stalled, or the hour it started in)
	hourLearned              // watched whole: its counts are history
	hourLossy                // watched, but lines were dropped (the queue was full): not history
)

// patLimits bound the miner's state; tests lower them.
type patLimits struct {
	scopes         int
	scopeTemplates int
	templates      int
	newPerMin      int // new templates a scope may make in a minute
	newPerHour     int // … and in an hour
	leafClusters   int
	kids           int
	cache          int // fingerprint cache entries in all
}

func (l patLimits) scopeNodes() int { return 4 * l.scopeTemplates }
func (l patLimits) nodes() int      { return 4 * l.templates }
func (l patLimits) scopeCache() int { return 4 * l.scopeTemplates }

var defaultPatLimits = patLimits{scopes: 1000, scopeTemplates: 500, templates: 10000, newPerMin: 20, newPerHour: 100,
	leafClusters: 64, kids: 100, cache: 40000}

// patLine is one line handed to the miner: app, svc and msg share one allocation of their own.
type patLine struct {
	ts       int64 // unix ns
	host     bool
	lvl      uint8
	app, svc string
	msg      string
}

func (l *patLine) size() int64 { return int64(len(l.app)+len(l.svc)+len(l.msg)) + patLineCost }

type scopeKey struct {
	host     bool
	app, svc string
}

// patOp is an app change asked by DeleteAppPatterns or KeepAppPatterns: with keep nil, the app slug
// was deleted at at; else every app not in keep is gone.
type patOp struct {
	slug string
	at   time.Time
	keep map[string]bool
}

// repBudget counts a rule's new-pattern reports sent in a clock hour (unix hours).
type repBudget struct {
	hour    int64
	n, late int32 // sent in hour (with the hour before's late ones); of them in its last patReportLate
}

// room is how many more reports may be sent at now.
func (b *repBudget) room(now int64) int {
	if h := floorDiv(now, int64(time.Hour)); h != b.hour {
		n := int32(0)
		if h == b.hour+1 {
			n = b.late
		}
		b.hour, b.n, b.late = h, n, 0
	}
	return int(patReportsPerHour - b.n)
}

// sent counts a report sent at now (after room).
func (b *repBudget) sent(now int64) {
	b.n++
	if now-b.hour*int64(time.Hour) >= int64(time.Hour-patReportLate) {
		b.late++
	}
}

// pmark is a state the owner set on a template (expected, ignored), kept by the template's ID
// apart from it, so it outlives the template being forgotten for room.
type pmark struct {
	scope, state string
	at           int64 // unix ns: set, or its template last forgotten for room
}

// hourMeta is which hours were watched (hourOff, hourLearned, hourLossy), for the last patHours.
type hourMeta struct {
	closed int64 // the newest closed hour (unix hours); 0 before the first
	st     [patHours]uint8
}

func modH(h int64) int { return int(((h % patHours) + patHours) % patHours) }

func (h *hourMeta) state(hr int64) uint8 {
	if h.closed == 0 || hr > h.closed || hr <= h.closed-patHours {
		return hourOff
	}
	return h.st[modH(hr)]
}

func (h *hourMeta) set(hr int64, s uint8) {
	if hr > h.closed {
		for x := max(h.closed+1, hr-patHours+1); x < hr; x++ {
			h.st[modH(x)] = hourOff
		}
		h.closed = hr
	}
	if hr > h.closed-patHours {
		h.st[modH(hr)] = s
	}
}

// budget is the miner's CPU budget: its busy time per one-second slice of the miner's clock.
type budget struct {
	limit  time.Duration
	sec    int64
	busy   time.Duration
	hist   [60]time.Duration
	histAt [60]int64
}

func (b *budget) roll(t time.Time) {
	s := t.Unix()
	if s == b.sec {
		return
	}
	i := int(((b.sec % 60) + 60) % 60)
	b.hist[i], b.histAt[i] = b.busy, b.sec
	b.sec, b.busy = s, 0
}

// pct is the share of the budget used in the minute up to t (0–100).
func (b *budget) pct(t time.Time) float64 {
	s := t.Unix()
	var sum time.Duration
	if b.sec > s-60 && b.sec <= s {
		sum += b.busy
	}
	for i := range b.hist {
		if at := b.histAt[i]; at > s-60 && at <= s && at != b.sec {
			sum += b.hist[i]
		}
	}
	if b.limit <= 0 {
		return 0
	}
	return min(100, 100*float64(sum)/float64(60*b.limit))
}

type miner struct {
	e       *Engine
	lim     patLimits
	exclude map[string]bool
	retain  time.Duration
	loc     *time.Location   // hours of the day are the server's local time
	clock   func() time.Time // the busy time's clock (tests replace it)

	q     chan patLine
	qSize atomic.Int64
	fires chan patternFiring
	stop  chan struct{}
	done  chan struct{}
	run   atomic.Bool

	lines, unmined, dropped, overflowed, firesDropped atomic.Int64
	reportsLost                                       atomic.Int64 // new templates forgotten for room with their report unsent
	nScopes, nTemplates                               atomic.Int64
	budgetPct                                         atomic.Uint64 // math.Float64bits
	learnList                                         atomic.Pointer[[]string]

	opsMu sync.Mutex
	ops   []patOp
	opsN  atomic.Int32

	// The engine goroutine's: saving (pattern_db.go).
	failAt  time.Time
	backoff time.Duration

	mu sync.Mutex
	// Below: under mu.
	scopes     map[scopeKey]*pscope
	byName     map[string]*pscope
	byID       map[string]*ptmpl
	lru, plru  list.List         // every scope's templates (plru: the protected ones)
	wlru       list.List         // … the unprotected ones whose new report is waiting
	olru       list.List         // … the ones the owner marked
	marks      map[string]*pmark // the owner's states by template ID (maxPatMarks at most)
	marksDirty bool              // saved whole with the next save
	rep        [2]repBudget      // the reports sent this hour: pattern.new's, pattern.new_error's
	skipped    int64             // lines left uncounted over the CPU budget
	skippedAt  int64             // skipped at the last tick
	sweepAt    time.Time         // the last sweep
	ntmpl      int
	nodes      int
	ncache     int
	pending    map[*ptmpl]struct{} // templates whose new report is waiting
	dirtySet   map[*ptmpl]struct{}
	cdirtySet  map[*ptmpl]struct{}
	urgent     []*ptmpl            // states the owner set, saved first
	gone       map[string]struct{} // saved templates forgotten since the last save
	goneScopes map[string]struct{}
	resync     bool // more were forgotten than gone may hold: the next full save rewrites them all
	metaDirty  bool
	appGone    map[string]time.Time // apps deleted lately: their lines aren't mined until then
	hours      hourMeta
	since      time.Time // hours starting before since weren't watched whole
	lossy      time.Time // nor were those starting before lossy learned (lines were dropped)
	lastTick   time.Time
	droppedAt  int64 // dropped at the last tick
	learnAt    time.Time
	bud        budget
	toks       [maxPatTokens]tok
	pbuf       []byte
}

func newMiner(e *Engine) *miner {
	o := e.opt.Patterns
	cpu := o.MaxCPUPercent
	if cpu <= 0 {
		cpu = defaultPatCPU
	}
	cpu = min(cpu, maxPatCPU)
	retain := o.SampleRetention
	if retain <= 0 {
		retain = defaultPatRetention
	}
	m := &miner{e: e, lim: defaultPatLimits, exclude: map[string]bool{}, retain: retain, loc: time.Local, clock: time.Now,
		q: make(chan patLine, patQueue), fires: make(chan patternFiring, patFires), stop: make(chan struct{}),
		done: make(chan struct{}), scopes: map[scopeKey]*pscope{}, byName: map[string]*pscope{},
		byID: map[string]*ptmpl{}, pending: map[*ptmpl]struct{}{}, dirtySet: map[*ptmpl]struct{}{},
		cdirtySet: map[*ptmpl]struct{}{}, gone: map[string]struct{}{}, goneScopes: map[string]struct{}{},
		appGone: map[string]time.Time{}, marks: map[string]*pmark{}}
	m.bud.limit = time.Second * time.Duration(cpu) / 100
	for _, a := range o.ExcludeApps {
		m.exclude[a] = true
	}
	return m
}

// offer takes a line for the miner (the pipeline goroutine): an app's line with a message, or a
// host's unclassified line written by root (a journal line names its sender's uid; a file line,
// auth.log or fail2ban's, none). It never blocks: past the queue's room the line is dropped and
// counted. Only the message's first maxPatLine bytes are kept, copied, with the app and service.
func (m *miner) offer(ev *siem.Event) {
	host := false
	switch ev.Src {
	case siem.SrcApp:
		if ev.App == "" || m.exclude[ev.App] {
			return
		}
	case siem.SrcHost:
		if ev.Kind != siem.KindLog {
			return
		}
		// Intentional: a journal line of another sender than root is anyone's text (logger), and a
		// sender_uid that isn't a string is no journal's: fail closed.
		if v, ok := ev.F["sender_uid"]; ok {
			if s, _ := v.(string); s != "0" {
				return
			}
		}
		host = true
	default:
		return
	}
	if ev.Msg == "" {
		return
	}
	msg := siem.Cut(ev.Msg, maxPatLine)
	app, svc := "", ""
	if !host {
		app, svc = siem.Cut(ev.App, siem.MaxShort), siem.Cut(ev.Svc, siem.MaxShort)
	}
	size := int64(len(app)+len(svc)+len(msg)) + patLineCost
	if m.qSize.Add(size) > patQueueBytes {
		m.qSize.Add(-size)
		m.drop()
		return
	}
	var b strings.Builder
	b.Grow(len(app) + len(svc) + len(msg))
	b.WriteString(app)
	b.WriteString(svc)
	b.WriteString(msg)
	s := b.String()
	l := patLine{ts: ev.TS.UnixNano(), host: host, lvl: uint8(siem.LevelRank(ev.Lvl)), app: s[:len(app)],
		svc: s[len(app) : len(app)+len(svc)], msg: s[len(app)+len(svc):]}
	select {
	case m.q <- l:
	default:
		m.qSize.Add(-size)
		m.drop()
	}
}

func (m *miner) drop() {
	n := m.dropped.Add(1)
	m.e.logLimited("patterns-dropped", "security detection: log-pattern queue full, lines not mined", "dropped_total", n)
}

// start runs the miner's goroutine (once).
func (m *miner) start() {
	if !m.run.CompareAndSwap(false, true) {
		return
	}
	go m.loop()
}

// halt stops the goroutine and waits for it; a miner never started has nothing to stop.
func (m *miner) halt() {
	if !m.run.Load() {
		return
	}
	select {
	case <-m.stop:
	default:
		close(m.stop)
	}
	<-m.done
}

func (m *miner) loop() {
	defer close(m.done)
	batch := make([]patLine, 0, patBatch)
	for {
		select {
		case <-m.stop:
			return
		case l := <-m.q:
			batch = append(batch[:0], l)
		fill:
			for len(batch) < patBatch {
				select {
				case l := <-m.q:
					batch = append(batch, l)
				default:
					break fill
				}
			}
			pause := m.step(batch)
			clear(batch)
			if pause > 0 {
				t := time.NewTimer(pause)
				select {
				case <-m.stop:
					t.Stop()
					return
				case <-t.C:
				}
			}
		}
	}
}

// step mines a batch of lines and returns how long the goroutine pauses: past twice the budget in
// a slice, until the slice ends (lines wait in the queue meanwhile, or are dropped when it fills).
// Past the budget the batch is only counted against the templates its lines already fit (the
// fingerprint cache); the others are counted unmined.
func (m *miner) step(batch []patLine) (pause time.Duration) {
	for i := range batch {
		m.qSize.Add(-batch[i].size())
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	start := m.clock()
	m.bud.roll(start)
	over := m.bud.busy >= m.bud.limit
	func() {
		defer func() {
			if r := recover(); r != nil {
				n := m.e.panics.Add(1)
				m.e.logLimited("patterns-panic", "security detection: log-pattern mining panicked", "panic", fmt.Sprint(r), "panics_total", n)
			}
		}()
		m.applyOps()
		rs := m.loadRules()
		now := m.e.now().UnixNano()
		for i := range batch {
			m.mine(&batch[i], over, &rs, now)
		}
	}()
	end := m.clock()
	if end.After(start) {
		m.bud.busy += end.Sub(start)
	}
	m.budgetPct.Store(f64bits(m.bud.pct(end)))
	m.nScopes.Store(int64(len(m.scopes)))
	m.nTemplates.Store(int64(m.ntmpl))
	if m.bud.busy >= 2*m.bud.limit {
		return max(time.Unix(m.bud.sec+1, 0).Sub(end), 0)
	}
	return 0
}

// patRules are the pattern rules in force (nil: not in the rule set).
type patRules struct{ newRule, newErr, spike, churn *compiled }

func (m *miner) loadRules() patRules {
	rs := m.e.rules.Load()
	if rs == nil {
		return patRules{}
	}
	get := func(id string) *compiled {
		if c := rs.byID[id]; c != nil && c.r.Type == siem.RuleBaseline && c.r.Baseline == siem.BaselinePattern {
			return c
		}
		return nil
	}
	return patRules{get(rulePatternNew), get(rulePatternNewError), get(rulePatternSpike), get(rulePatternChurn)}
}

// newFor is the rule that reports a new template of level lvl.
func (r *patRules) newFor(lvl uint8) *compiled {
	if lvl >= rankWarn {
		return r.newErr
	}
	return r.newRule
}

// learnFor is the learning period of a scope for a template of level lvl (its new rule's).
func (r *patRules) learnFor(lvl uint8) int64 {
	if c := r.newFor(lvl); c != nil && c.r.Learn > 0 {
		return int64(c.r.Learn)
	}
	return int64(defaultPatLearn)
}

// learning reports whether a scope still learns at now for a template of level lvl.
func (m *miner) learning(sc *pscope, now int64, learn int64) bool {
	return now < sc.relearn || now-sc.first < learn
}

// mine sorts one line into its scope's templates and counts it.
func (m *miner) mine(l *patLine, over bool, rs *patRules, now int64) {
	sc := m.scope(l, now)
	if sc == nil {
		return
	}
	n := tokenize(l.msg, &m.toks)
	if n == 0 {
		return
	}
	toks := m.toks[:n]
	m.lines.Add(1)
	if now > sc.last {
		sc.last = now
		if now-sc.lastSave >= int64(day) {
			sc.lastSave, sc.dirty = now, true
		}
	}
	fp := fingerprint(l.msg, toks)
	t := sc.cache[fp]
	if t != nil && !t.fits(l.msg, toks) {
		t = nil
	}
	if t == nil {
		if over {
			// It may be a known template's line: the hour's counts are short (tick: a lossy hour).
			m.unmined.Add(1)
			m.skipped++
			return
		}
		if t = m.place(sc, l, toks, fp, rs, now); t == nil {
			return
		}
	}
	m.count(t, l, rs, now)
}

// scope is a line's scope, made at its first line; nil when the scope cap is reached or the app
// was deleted lately.
func (m *miner) scope(l *patLine, now int64) *pscope {
	k := scopeKey{host: l.host, app: l.app, svc: l.svc}
	if sc := m.scopes[k]; sc != nil {
		return sc
	}
	if !l.host {
		if until, ok := m.appGone[l.app]; ok {
			if now < until.UnixNano() {
				return nil
			}
			delete(m.appGone, l.app)
		}
	}
	if len(m.scopes) >= m.lim.scopes {
		m.unmined.Add(1)
		m.overflowed.Add(1)
		return nil
	}
	k.app, k.svc = strings.Clone(l.app), strings.Clone(l.svc)
	return m.addScope(k, now, patTokVersion)
}

func (m *miner) addScope(k scopeKey, first int64, tokVer int) *pscope {
	sc := &pscope{name: scopeName(k.host, k.app, k.svc), app: k.app, svc: k.svc, host: k.host, first: first,
		last: first, lastSave: first, tokVer: tokVer, cache: map[uint64]*ptmpl{}, dirty: true}
	if _, ok := m.goneScopes[sc.name]; ok {
		delete(m.goneScopes, sc.name)
		sc.saved = true
	}
	m.scopes[k] = sc
	m.byName[sc.name] = sc
	return sc
}

// place finds the template of a line not in the fingerprint cache: the most similar one of the
// leaves it can be in, else a new one; nil when the line overflowed (counted).
func (m *miner) place(sc *pscope, l *patLine, toks []tok, fp uint64, rs *patRules, now int64) *ptmpl {
	if t, s := m.bestOf(sc, l.msg, toks); t != nil && s >= patSim {
		if t.merge(l.msg, toks) {
			m.markDirty(t)
		}
		m.cachePut(sc, fp, t)
		return t
	}
	return m.create(sc, l, toks, fp, rs, now)
}

func (m *miner) cachePut(sc *pscope, fp uint64, t *ptmpl) {
	if _, ok := sc.cache[fp]; !ok {
		// Intentional: a full cache starts again empty (a map doesn't shrink); its lines find
		// their templates in the tree again. At the cap over all scopes it is the largest cache
		// that starts again, not this scope's: a busy scope would otherwise leave the others one
		// entry each (and the cap would be passed by one a scope).
		switch {
		case len(sc.cache) >= m.lim.scopeCache():
			m.resetCache(sc)
		case m.ncache >= m.lim.cache:
			big := sc
			for _, x := range m.byName {
				if len(x.cache) > len(big.cache) {
					big = x
				}
			}
			m.resetCache(big)
		}
		m.ncache++
	}
	sc.cache[fp] = t
}

func (m *miner) resetCache(sc *pscope) {
	m.ncache -= len(sc.cache)
	sc.cache = map[uint64]*ptmpl{}
}

// allowNew reports whether a scope may make a new template now (the per-minute and per-hour caps).
func (m *miner) allowNew(sc *pscope, now int64) bool {
	if mi := floorDiv(now, int64(time.Minute)); mi != sc.minAt {
		sc.minAt, sc.newMin = mi, 0
	}
	if h := floorDiv(now, int64(time.Hour)); h != sc.hourAt {
		sc.hourAt, sc.newHour = h, 0
	}
	return sc.newMin < m.lim.newPerMin && sc.newHour < m.lim.newPerHour
}

// create makes a new template of a line: learned while its scope learns, the owner's state when
// the owner had marked this template before it was forgotten for room, else new (reported by
// pattern.new or pattern.new_error once settled). nil when the line overflowed instead (a cap).
// Templates are forgotten for room only once it is known that one will be made.
func (m *miner) create(sc *pscope, l *patLine, toks []tok, fp uint64, rs *patRules, now int64) *ptmpl {
	if !m.allowNew(sc, now) {
		m.overflow(sc, rs, now, true)
		return nil
	}
	keys := lineKeys(l.msg, toks)
	if leaf := m.routeLeaf(sc, len(toks), keys); leaf != nil && len(leaf.clusters) >= m.lim.leafClusters {
		return m.fullLeaf(sc, leaf, l, toks, fp, rs, now)
	}
	strs := make([]string, len(toks))
	for i := range toks {
		strs[i] = tokText(l.msg, toks[i])
	}
	id := m.newID(sc.name, strings.Join(strs, " "))
	if id == "" {
		m.overflow(sc, rs, now, false)
		return nil
	}
	for sc.n >= m.lim.scopeTemplates && m.evict(backOf(&sc.lru, &sc.wlru, &sc.plru, &sc.olru), rs, now) {
	}
	for m.ntmpl >= m.lim.templates && m.evict(backOf(&m.lru, &m.wlru, &m.plru, &m.olru), rs, now) {
	}
	// After the forgetting: it may have pruned the leaf found above.
	leaf := m.insertLeaf(sc, len(toks), keys)
	if leaf == nil {
		m.overflow(sc, rs, now, false)
		return nil
	}
	if len(leaf.clusters) >= m.lim.leafClusters {
		return m.fullLeaf(sc, leaf, l, toks, fp, rs, now)
	}
	t := &ptmpl{id: id, sc: sc, leaf: leaf, toks: strs, text: render(strs), lvl: l.lvl, first: l.ts, last: l.ts,
		hourAt: floorDiv(l.ts, int64(time.Hour)), minAt: floorDiv(l.ts, int64(time.Minute)), state: siem.PatternLearned}
	t.npath = copy(t.path[:], keys)
	if mk := m.marks[id]; mk != nil && mk.scope == sc.name {
		t.state = mk.state
	} else if !m.learning(sc, now, rs.learnFor(l.lvl)) {
		t.state, t.fresh = siem.PatternNew, true
	}
	m.link(t)
	sc.newMin++
	sc.newHour++
	m.markDirty(t)
	m.cachePut(sc, fp, t)
	return t
}

// fullLeaf handles a line whose leaf is full: it counts for the leaf's most similar template
// (unchanged), or overflows when none shares a token with it.
func (m *miner) fullLeaf(sc *pscope, leaf *pnode, l *patLine, toks []tok, fp uint64, rs *patRules, now int64) *ptmpl {
	if t, s := best(leaf, l.msg, toks); t != nil && s > 0 {
		m.cachePut(sc, fp, t)
		return t
	}
	m.overflow(sc, rs, now, false)
	return nil
}

// link puts a template (made or read back) in its leaf, the lists and the maps.
func (m *miner) link(t *ptmpl) {
	sc := t.sc
	t.leaf.clusters = append(t.leaf.clusters, t)
	if t.fresh && !t.reported {
		t.pending = true
		m.pending[t] = struct{}{}
	}
	a, b := m.listsOf(t)
	t.el, t.gel = a.PushFront(t), b.PushFront(t)
	m.byID[t.id] = t
	sc.n++
	m.ntmpl++
	if _, ok := m.gone[t.id]; ok {
		// A saved template forgotten and back before the save: its row still exists. Left in gone,
		// the save would delete the row of the template now here.
		delete(m.gone, t.id)
		t.saved = true
	}
	if ownerState(t.state) {
		m.ownerMark(t)
	} else if t.seen >= 2 {
		m.protect(t)
	}
}

// ownerState reports whether state is one the owner sets to silence a pattern.
func ownerState(state string) bool {
	return state == siem.PatternExpected || state == siem.PatternIgnored
}

// newID is the ID of a new template, "" when every try clashes with another template's.
func (m *miner) newID(scope, text string) string {
	for n := 0; n < 16; n++ {
		if id := patternID(scope, text, n); m.byID[id] == nil {
			return id
		}
	}
	return ""
}

// overflow counts a line not sorted into a template (rate: held back by the new-template cap;
// else there was no room for its template) and fires pattern.churn for it: once the scope has
// learned, when such lines reach the rule's count, at most every patChurnEvery.
func (m *miner) overflow(sc *pscope, rs *patRules, now int64, rate bool) {
	m.unmined.Add(1)
	m.overflowed.Add(1)
	sc.overflow++
	if rate {
		sc.capHits++
	} else {
		sc.roomHits++
	}
	c := rs.churn
	if c == nil || !c.r.Enabled || sc.overflow < int64(c.r.Count) || m.learning(sc, now, max(rs.learnFor(0), rs.learnFor(rankWarn))) {
		return
	}
	if sc.churnAt != 0 && now-sc.churnAt < int64(patChurnEvery) {
		return
	}
	var why string
	switch past := fmt.Sprintf("new log patterns past the cap (%d a minute, %d an hour)", m.lim.newPerMin, m.lim.newPerHour); {
	case sc.capHits > 0 && sc.roomHits > 0:
		why = past + " and no room left for new ones"
	case sc.roomHits > 0:
		why = "no room left for new log patterns"
	default:
		why = past
	}
	what := why + "; " + linesOf(sc.overflow) + " not sorted into a pattern"
	if m.send(m.firingOf(rulePatternChurn, sc.name, sc, now, int(min(sc.overflow, 1<<31-1)), what)) {
		sc.churnAt, sc.overflow, sc.capHits, sc.roomHits = now, 0, 0, 0
	}
}

func (m *miner) firingOf(rule, key string, sc *pscope, ts int64, count int, what string) patternFiring {
	f := patternFiring{rule: rule, key: key, ts: time.Unix(0, ts).UTC(), src: siem.SrcHost, count: max(count, 1), what: what}
	if !sc.host {
		f.src, f.app, f.svc = siem.SrcApp, sc.app, sc.svc
	}
	return f
}

// linesOf is "1 line", "12 lines".
func linesOf(n int64) string {
	if n == 1 {
		return "1 line"
	}
	return fmt.Sprintf("%d lines", n)
}

// send hands a firing to the engine goroutine; false when its channel is full (counted).
func (m *miner) send(f patternFiring) bool {
	select {
	case m.fires <- f:
		return true
	default:
		n := m.firesDropped.Add(1)
		m.e.logLimited("patterns-fires", "security detection: log-pattern firings queue full, firing dropped", "dropped_total", n)
		return false
	}
}

// count counts a line of t: its counts, newest time, highest level, sample, protection, and the
// spike check.
func (m *miner) count(t *ptmpl, l *patLine, rs *patRules, now int64) {
	if t.count < 1<<62 {
		t.count++
	}
	if l.ts > t.last {
		t.last = l.ts
	}
	if l.lvl > t.lvl {
		t.lvl = l.lvl
		m.markDirty(t)
	}
	h := floorDiv(l.ts, int64(time.Hour))
	t.addHour(h)
	if h > t.seenAt {
		t.seenAt = h
		if t.seen < 1<<31 {
			t.seen++
		}
		if t.seen >= 2 && !t.prot && !t.own {
			m.protect(t)
		}
	}
	if t.addMin(floorDiv(l.ts, int64(time.Minute))) {
		m.touch(t)
	}
	if !t.cdirty && !t.dirty {
		t.cdirty = true
		m.cdirtySet[t] = struct{}{}
	}
	if t.sample == "" || now-t.sampleAt >= int64(patSampleAge) {
		t.sample, t.sampleAt = strings.Clone(siem.Cut(l.msg, siem.MaxPatternText)), now
		m.markDirty(t)
	}
	m.spike(t, rs, now)
}

func (t *ptmpl) addHour(h int64) {
	switch {
	case h > t.hourAt:
		if h-t.hourAt >= patHours {
			t.hours = [patHours]uint32{}
		} else {
			for x := t.hourAt + 1; x <= h; x++ {
				t.hours[modH(x)] = 0
			}
		}
		t.hourAt = h
	case h <= t.hourAt-patHours:
		return // older than the hours kept
	}
	i := modH(h)
	t.hours[i] = satAdd(t.hours[i], 1)
}

func (t *ptmpl) hourCount(h int64) uint32 {
	if h > t.hourAt || h <= t.hourAt-patHours {
		return 0
	}
	return t.hours[modH(h)]
}

func modM(x int64) int { return int(((x % patMins) + patMins) % patMins) }

// addMin counts a line in minute x; it reports whether x is a newer minute than any before.
func (t *ptmpl) addMin(x int64) bool {
	newer := false
	switch {
	case x > t.minAt:
		if x-t.minAt >= patMins {
			t.mins = [patMins]uint32{}
		} else {
			for y := t.minAt + 1; y <= x; y++ {
				t.mins[modM(y)] = 0
			}
		}
		t.minAt, newer = x, true
	case x <= t.minAt-patMins:
		return false
	}
	i := modM(x)
	t.mins[i] = satAdd(t.mins[i], 1)
	return newer
}

func (t *ptmpl) minCount(x int64) uint32 {
	if x > t.minAt || x <= t.minAt-patMins {
		return 0
	}
	return t.mins[modM(x)]
}

// spike fires pattern.spike for a template older than the rule's learning period whose lines in
// the last Window reach Count and are more than Factor × its usual count for that time of day; at
// most once a Window.
func (m *miner) spike(t *ptmpl, rs *patRules, now int64) {
	c := rs.spike
	if c == nil || !c.r.Enabled || t.state == siem.PatternExpected || t.state == siem.PatternIgnored {
		return
	}
	if now < t.spikeUntil || now-t.first < int64(c.r.Learn) {
		return
	}
	w := min(max(c.r.Window, time.Minute), patMins*time.Minute)
	cur := floorDiv(now, int64(time.Minute))
	var n uint64
	for x := cur - int64(w/time.Minute) + 1; x <= cur; x++ {
		n += uint64(t.minCount(x))
	}
	if n < uint64(c.r.Count) {
		return
	}
	usual, ok := m.usualOf(t, now, w)
	if !ok || float64(n) <= c.r.Factor*usual {
		return
	}
	what := fmt.Sprintf("%s: %s in %s, usually about %s", t.sc.label(), linesOf(int64(min(n, 1<<62))), fmtDur(w), fmtNum(usual))
	if m.send(m.firingOf(rulePatternSpike, t.id, t.sc, now, int(min(n, 1<<31-1)), what)) {
		t.spikeUntil = now + int64(w)
	}
}

// usualOf is a template's usual count in a window w at now's time of day: for that local hour
// and each of the hours either side of it, the middle (the higher of two) of the template's
// counts in that hour on the previous 7 days (the same wall-clock time, so a daylight saving
// change doesn't shift it), of the hours watched whole since its first line; then the highest of
// the three, scaled to w. An hour of the day with fewer than 3 such hours has no middle; false when
// none of the three has one. Worked out once per hour and window.
// Intentional: the highest of three per-hour middles, not one middle over all 21 hours: a daily job
// whose lines all fall in one hour has 7 busy hours among 14 quiet ones, and the one middle (0)
// would make it a spike every day.
func (m *miner) usualOf(t *ptmpl, now int64, w time.Duration) (float64, bool) {
	key := floorDiv(now, int64(time.Hour))<<8 | int64(w/time.Minute)
	if t.usualKey == key && t.usualKey != 0 {
		return t.usual, t.usualOK
	}
	at := time.Unix(0, now).In(m.loc)
	first := floorDiv(t.first, int64(time.Hour))
	var (
		vs   [3][7]float64
		n    [3]int
		top  float64
		have bool
	)
	for d := 1; d <= 7; d++ {
		hb := floorDiv(at.AddDate(0, 0, -d).Unix(), 3600)
		for k := range vs {
			if h := hb + int64(k) - 1; h >= first && m.hours.state(h) == hourLearned {
				vs[k][n[k]] = float64(t.hourCount(h))
				n[k]++
			}
		}
	}
	for k := range vs {
		if n[k] >= 3 {
			top, have = max(top, middle(vs[k][:n[k]], true)), true
		}
	}
	t.usualKey = key
	t.usual, t.usualOK = top*w.Hours(), have
	return t.usual, t.usualOK
}

func (m *miner) markDirty(t *ptmpl) {
	if t.dead || t.dirty {
		return
	}
	if t.cdirty {
		t.cdirty = false
		delete(m.cdirtySet, t)
	}
	t.dirty = true
	m.dirtySet[t] = struct{}{}
}

func (m *miner) clean(t *ptmpl) {
	if t.dirty {
		t.dirty = false
		delete(m.dirtySet, t)
	}
	if t.cdirty {
		t.cdirty = false
		delete(m.cdirtySet, t)
	}
}

// listsOf are the lists a template is in: its scope's and the miner's.
func (m *miner) listsOf(t *ptmpl) (*list.List, *list.List) {
	switch {
	case t.own:
		return &t.sc.olru, &m.olru
	case t.prot:
		return &t.sc.plru, &m.plru
	case t.pending:
		return &t.sc.wlru, &m.wlru
	}
	return &t.sc.lru, &m.lru
}

// unpend takes a template out of the reports waiting (sent, cancelled, or not owed): an
// unprotected one goes back to the other unprotected ones, as the most recently used.
func (m *miner) unpend(t *ptmpl) {
	if !t.pending {
		return
	}
	listed := t.el != nil && !t.own && !t.prot
	if listed {
		a, b := m.listsOf(t)
		a.Remove(t.el)
		b.Remove(t.gel)
	}
	t.pending = false
	delete(m.pending, t)
	if listed {
		a, b := m.listsOf(t)
		t.el, t.gel = a.PushFront(t), b.PushFront(t)
	}
}

// touch makes a template the most recently used of its lists.
func (m *miner) touch(t *ptmpl) {
	if t.el == nil {
		return
	}
	a, b := m.listsOf(t)
	a.MoveToFront(t.el)
	b.MoveToFront(t.gel)
}

// moveTo puts a listed template in the owner-marked lists (own), the protected ones (prot) or the
// unprotected ones (those whose new report is waiting are listed apart), as the most recently used.
func (m *miner) moveTo(t *ptmpl, own, prot bool) {
	a, b := m.listsOf(t)
	a.Remove(t.el)
	b.Remove(t.gel)
	t.own, t.prot = own, prot
	a, b = m.listsOf(t)
	t.el, t.gel = a.PushFront(t), b.PushFront(t)
}

// protect moves a template seen in two hours or more to the protected ones: forgotten for room
// only when no unprotected one is left. At most three quarters of a scope's and of all templates
// are protected; past that the least recently used protected one goes back.
func (m *miner) protect(t *ptmpl) {
	if t.prot || t.own || t.el == nil {
		return
	}
	sc := t.sc
	m.moveTo(t, false, true)
	for sc.plru.Len() > m.lim.scopeTemplates/4*3 && sc.plru.Len() > 1 {
		m.unprotect(sc.plru.Back().Value.(*ptmpl))
	}
	for m.plru.Len() > m.lim.templates/4*3 && m.plru.Len() > 1 {
		m.unprotect(m.plru.Back().Value.(*ptmpl))
	}
}

func (m *miner) unprotect(t *ptmpl) {
	if t.prot {
		m.moveTo(t, false, false)
	}
}

// ownerMark moves a template the owner marked (expected, ignored) to the owner-marked ones:
// forgotten for room only when no other template is left to forget, and never moved back by the
// protected share (the owner's decision outlasts any churn). ownerUnmark moves it back.
func (m *miner) ownerMark(t *ptmpl) {
	if !t.own && t.el != nil {
		m.moveTo(t, true, false)
	}
}

func (m *miner) ownerUnmark(t *ptmpl) {
	if !t.own || t.el == nil {
		return
	}
	m.moveTo(t, false, false)
	if t.seen >= 2 {
		m.protect(t)
	}
}

// backOf is the least recently used template of the first list that has one.
func backOf(ls ...*list.List) *ptmpl {
	for _, l := range ls {
		if el := l.Back(); el != nil {
			return el.Value.(*ptmpl)
		}
	}
	return nil
}

// evict forgets t for room (false: there was none to forget). Its owner's mark, if any, stays: the
// same template made again has the owner's state. The unprotected templates whose new report is
// waiting are forgotten after the other unprotected ones (create), and one forgotten all the same
// has its report sent here when it is due (reportEvicted).
func (m *miner) evict(t *ptmpl, rs *patRules, now int64) bool {
	if t == nil {
		return false
	}
	if t.pending && rs != nil {
		m.reportEvicted(t, rs, now)
	}
	// A mark is dropped patOwnerForget after it was set or its template was last here (sweep).
	if mk := m.marks[t.id]; mk != nil && now-mk.at >= int64(day) {
		mk.at, m.marksDirty = now, true
	}
	m.forget(t)
	return true
}

// reportEvicted sends the new report of a template about to be forgotten for room when the report is
// due (reports: the rule is on, the template has settled and has the rule's Count of lines) and
// only waits for the hour's patReportsPerHour: sent when there is room for it now, else counted
// (reportsLost) and logged. A template forgotten before it settled is owed no report.
func (m *miner) reportEvicted(t *ptmpl, rs *patRules, now int64) {
	if t.dead || !t.fresh || t.reported {
		return
	}
	c := rs.newFor(t.lvl)
	if c == nil || !c.r.Enabled || now-t.first < int64(c.r.Window) || t.count < int64(c.r.Count) {
		return
	}
	if b := &m.rep[repOf(c)]; b.room(now) > 0 && m.send(m.newFiring(c, t, now)) {
		b.sent(now)
		m.metaDirty = true
		t.reported, t.fresh = true, false
		return
	}
	n := m.reportsLost.Add(1)
	m.e.logLimited("patterns-report-lost", "security detection: a new log pattern was forgotten for room before it could be reported", "lost_total", n)
}

// newFiring is the new report of t for rule c.
func (m *miner) newFiring(c *compiled, t *ptmpl, now int64) patternFiring {
	what := fmt.Sprintf("new in %s: %s in %s (%s)", t.sc.label(), linesOf(t.count),
		fmtDur(time.Duration(max(now-t.first, 0))), levelName(t.lvl))
	return m.firingOf(c.r.ID, t.id, t.sc, max(t.last, t.first), int(min(t.count, 1<<31-1)), what)
}

// setMark keeps the owner's state of a template apart from it; past maxPatMarks the mark set
// longest ago is dropped (its template, when still here, keeps its state).
func (m *miner) setMark(id, scope, state string, at int64) {
	if mk := m.marks[id]; mk != nil {
		if mk.scope != scope || mk.state != state {
			mk.scope, mk.state, mk.at, m.marksDirty = scope, state, at, true
		}
		return
	}
	for len(m.marks) >= maxPatMarks {
		old := ""
		for x, mk := range m.marks {
			if old == "" || mk.at < m.marks[old].at || mk.at == m.marks[old].at && x < old {
				old = x
			}
		}
		delete(m.marks, old)
	}
	m.marks[id] = &pmark{scope: scope, state: state, at: at}
	m.marksDirty = true
}

func (m *miner) dropMark(id string) {
	if _, ok := m.marks[id]; ok {
		delete(m.marks, id)
		m.marksDirty = true
	}
}

// forget drops a template (its row is deleted with the next save).
func (m *miner) forget(t *ptmpl) {
	if t.dead {
		return
	}
	sc := t.sc
	m.unlink(t)
	if t.el != nil {
		a, b := m.listsOf(t)
		a.Remove(t.el)
		b.Remove(t.gel)
		t.el, t.gel = nil, nil
	}
	if m.byID[t.id] == t {
		delete(m.byID, t.id)
	}
	m.clean(t)
	if t.pending {
		t.pending = false
		delete(m.pending, t)
	}
	t.dead = true
	sc.n--
	m.ntmpl--
	if t.saved {
		m.noteGone(t.id)
	}
}

func (m *miner) noteGone(id string) {
	if m.resync {
		return
	}
	if len(m.gone) >= 2*m.lim.templates {
		// Intentional: past this many rows to delete, every template is rewritten at the next full
		// save instead (a flood of templates would otherwise grow this set without bound).
		m.resync, m.gone = true, map[string]struct{}{}
		return
	}
	m.gone[id] = struct{}{}
}

// dropScope forgets a scope and its templates.
func (m *miner) dropScope(sc *pscope) {
	for t := backOf(&sc.lru, &sc.wlru, &sc.plru, &sc.olru); t != nil; t = backOf(&sc.lru, &sc.wlru, &sc.plru, &sc.olru) {
		m.forget(t)
	}
	m.ncache -= len(sc.cache)
	sc.cache = nil
	delete(m.scopes, scopeKey{host: sc.host, app: sc.app, svc: sc.svc})
	if m.byName[sc.name] == sc {
		delete(m.byName, sc.name)
	}
	if sc.saved && len(m.goneScopes) < 2*m.lim.scopes {
		m.goneScopes[sc.name] = struct{}{}
	} else if sc.saved {
		m.resync = true
	}
}

// queueOp hands an app change to the miner (applied at its next step or tick).
func (m *miner) queueOp(op patOp) error {
	m.opsMu.Lock()
	defer m.opsMu.Unlock()
	if op.keep == nil && slices.ContainsFunc(m.ops, func(o patOp) bool { return o.keep == nil && o.slug == op.slug }) {
		return nil
	}
	if len(m.ops) >= maxAppDeletes {
		return errBusy
	}
	m.ops = append(m.ops, op)
	m.opsN.Store(int32(len(m.ops)))
	return nil
}

// applyOps applies the app changes asked since the last step (under mu): the scopes of the apps
// gone are dropped, and a deleted app's lines aren't mined for appGoneFor.
func (m *miner) applyOps() {
	if m.opsN.Load() == 0 {
		return
	}
	m.opsMu.Lock()
	ops := m.ops
	m.ops = nil
	m.opsN.Store(0)
	m.opsMu.Unlock()
	now := m.e.now()
	for _, op := range ops {
		if op.keep != nil {
			continue
		}
		for s, u := range m.appGone {
			if !u.After(now) {
				delete(m.appGone, s)
			}
		}
		if until := op.at.Add(appGoneFor); len(m.appGone) < maxAppDeletes && until.After(m.appGone[op.slug]) {
			m.appGone[op.slug] = until
		}
	}
	gone := func(app string) bool {
		for _, op := range ops {
			if op.keep == nil && op.slug == app || op.keep != nil && !op.keep[app] {
				return true
			}
		}
		return false
	}
	for _, sc := range m.byName {
		if !sc.host && gone(sc.app) {
			m.dropScope(sc)
		}
	}
	for id, mk := range m.marks {
		if host, app, _, ok := parseScope(mk.scope); ok && !host && gone(app) {
			delete(m.marks, id)
			m.marksDirty = true
		}
	}
}

// tick runs on the engine's write tick (under mu): it closes the hours that ended patGrace ago or
// more; at an hour's end, and every patSweepEvery by the clock, it sweeps (forgets what was quiet
// too long, clears the samples past the retention, has every template whose counts changed
// saved); it sends the new-template reports that are due.
func (m *miner) tick(now time.Time) {
	// Intentional: the wall clock only. A time.Now() reading also carries a monotonic one, which
	// Before, After and Sub would use: a clock set back would never show.
	now = now.Round(0)
	m.applyOps()
	rs := m.loadRules()
	if m.hours.closed >= floorDiv(now.Unix(), 3600) || !m.lastTick.IsZero() && now.Before(m.lastTick.Add(-patSkew)) {
		m.unfuture(now)
	}
	if m.lastTick.IsZero() || now.Before(m.lastTick) || now.Sub(m.lastTick) > maxTickGap {
		m.since = now
	}
	// Lines dropped at the queue, or left uncounted over the CPU budget: the hour's counts are short.
	if d := m.dropped.Load(); d != m.droppedAt || m.skipped != m.skippedAt {
		m.lossy, m.droppedAt, m.skippedAt = now, d, m.skipped
	}
	m.lastTick = now
	ns := now.UnixNano()
	closed := false
	if upTo := floorDiv(now.Add(-patGrace).Unix(), 3600) - 1; upTo > m.hours.closed {
		for h := max(m.hours.closed+1, upTo-patHours+1); h <= upTo; h++ {
			start := time.Unix(h*3600, 0)
			st := hourOff
			if !m.since.After(start) {
				st = hourLearned
				if m.lossy.After(start) {
					st = hourLossy
				}
			}
			m.hours.set(h, st)
		}
		m.metaDirty, closed = true, true
	}
	// Intentional: by the clock too, not only when an hour closes: no hour closes while the hours'
	// table is ahead of the clock, and the first tick of a run clears what expired while stopped.
	if closed || now.Before(m.sweepAt) || now.Sub(m.sweepAt) >= patSweepEvery { // a run's first tick: sweepAt is zero
		m.sweepAt = now
		m.sweep(ns)
	}
	m.reports(&rs, ns)
	end := m.clock()
	m.bud.roll(end)
	m.budgetPct.Store(f64bits(m.bud.pct(end)))
	m.nScopes.Store(int64(len(m.scopes)))
	m.nTemplates.Store(int64(m.ntmpl))
	if m.learnAt.IsZero() || now.Sub(m.learnAt) >= patLearnEvery || now.Before(m.learnAt) {
		m.learnAt = now
		learn := max(rs.learnFor(0), rs.learnFor(rankWarn))
		var names []string
		for _, sc := range m.byName {
			if m.learning(sc, ns, learn) {
				names = append(names, sc.name)
			}
		}
		slices.Sort(names)
		names = names[:min(len(names), maxPatLearning)]
		m.learnList.Store(&names)
	}
}

// unfuture puts right what a clock that ran ahead left behind (under mu; at load, and on a tick
// that finds the clock set back): times more than patSkew past now are brought to now, and when
// hours past now were closed the table of watched hours starts again. Left as they were, no hour
// would close, no scope finish learning, no template settle or lose its sample, until the clock
// caught up with them.
func (m *miner) unfuture(now time.Time) {
	ns := now.UnixNano()
	lim := ns + int64(patSkew)
	limH, limM := floorDiv(lim, int64(time.Hour)), floorDiv(lim, int64(time.Minute))
	nowH := floorDiv(now.Unix(), 3600)
	if m.hours.closed >= nowH {
		m.hours, m.metaDirty = hourMeta{}, true
	}
	for i := range m.rep {
		if m.rep[i].hour > nowH {
			m.rep[i], m.metaDirty = repBudget{}, true
		}
	}
	if m.lossy.After(now) {
		m.lossy = now
	}
	if m.sweepAt.After(now) {
		m.sweepAt = time.Time{}
	}
	for slug, until := range m.appGone {
		if end := now.Add(appGoneFor); until.After(end) {
			m.appGone[slug] = end
		}
	}
	for _, sc := range m.byName {
		changed := false
		if sc.first > lim {
			sc.first, changed = ns, true
		}
		if end := ns + int64(patRelearn); sc.relearn > end+int64(patSkew) {
			sc.relearn, changed = end, true
		}
		if sc.last > lim {
			sc.last, sc.lastSave, changed = ns, ns, true
		}
		if sc.churnAt > lim {
			sc.churnAt = 0
		}
		if changed {
			sc.dirty = true
		}
	}
	for _, t := range m.byID {
		changed := false
		if t.first > lim {
			t.first, changed = ns, true
		}
		if t.last > lim {
			t.last, changed = max(ns, t.first), true
		}
		if t.hourAt > limH {
			// Its counts are of hours that haven't been yet.
			t.hours, t.hourAt, changed = [patHours]uint32{}, nowH, true
		}
		if t.minAt > limM {
			t.mins, t.minAt = [patMins]uint32{}, floorDiv(ns, int64(time.Minute))
		}
		if t.seenAt > limH {
			t.seenAt, changed = nowH, true
		}
		if t.sampleAt > lim {
			t.sampleAt, changed = ns, true
		}
		if t.spikeUntil > lim+int64(patMins*time.Minute) {
			t.spikeUntil = 0
		}
		if changed {
			t.usualKey = 0
			m.markDirty(t)
		}
	}
	for _, mk := range m.marks {
		if mk.at > lim {
			mk.at, m.marksDirty = ns, true
		}
	}
}

// sweep forgets the templates without a line for patForget (the owner-marked ones: patOwnerForget),
// clears the samples older than the retention, has every template whose counts
// changed saved, and drops the scopes left without a template and without a line for patForget
// (they count toward the scopes' cap) and the marks patOwnerForget old whose template is gone.
func (m *miner) sweep(now int64) {
	for _, t := range m.byID {
		age := int64(patForget)
		if ownerState(t.state) {
			age = int64(patOwnerForget)
		}
		switch {
		case now-t.last > age:
			m.forget(t) // its mark, if any, goes below: it is older than the template's last line
		case t.sample != "" && now-t.sampleAt > int64(m.retain):
			t.sample, t.sampleAt = "", 0
			m.markDirty(t)
		case t.cdirty:
			m.markDirty(t)
		}
	}
	for _, sc := range m.byName {
		if sc.n == 0 && now-sc.last > int64(patForget) {
			m.dropScope(sc)
		}
	}
	for id, mk := range m.marks {
		if m.byID[id] == nil && now-mk.at > int64(patOwnerForget) {
			m.dropMark(id)
		}
	}
}

// reports sends the new-template reports that are due: a template made new whose report wasn't
// cancelled (the owner set it expected or learned; ignored silences its spikes only), Window (the
// settle time) after its first line, once it has Count lines; pattern.new_error when its level
// reached warn, else pattern.new. A rule switched off reports nothing (and never will, for these).
// At most patReportsPerHour a rule and hour are sent, the oldest templates first; the others, and a
// report the engine's channel had no room for, are tried again at a later tick (a template
// forgotten for room before that: reportEvicted).
func (m *miner) reports(rs *patRules, now int64) {
	if len(m.pending) == 0 {
		return
	}
	room := [2]int{m.rep[0].room(now), m.rep[1].room(now)}
	done := func(t *ptmpl) {
		t.reported, t.fresh = true, false
		m.unpend(t)
		m.markDirty(t)
	}
	var due []*ptmpl
	for t := range m.pending {
		if t.dead || !t.fresh || t.reported {
			m.unpend(t)
			continue
		}
		c := rs.newFor(t.lvl)
		settle, need := int64(defaultPatSettle), int64(1)
		if c != nil {
			settle, need = int64(c.r.Window), int64(c.r.Count)
		}
		if now-t.first < settle || t.count < need {
			continue
		}
		if c == nil || !c.r.Enabled {
			done(t)
		} else if room[repOf(c)] > 0 {
			due = append(due, t)
		}
	}
	slices.SortFunc(due, func(a, b *ptmpl) int {
		if c := cmpInt(a.first, b.first); c != 0 {
			return c
		}
		return strings.Compare(a.id, b.id)
	})
	for _, t := range due {
		c := rs.newFor(t.lvl)
		b := &m.rep[repOf(c)]
		if b.room(now) <= 0 {
			continue
		}
		if !m.send(m.newFiring(c, t, now)) {
			return
		}
		b.sent(now)
		m.metaDirty = true
		done(t)
	}
}

// repOf is the index of a new-pattern rule's report count in miner.rep.
func repOf(c *compiled) int {
	if c.r.ID == rulePatternNewError {
		return 1
	}
	return 0
}

// setState sets a template's state for the owner at now (under mu): true when the template exists.
// expected and ignored are kept as the template's mark too; expected and learned cancel the report
// of a new template not reported yet, ignored (which silences spikes only) doesn't.
func (m *miner) setState(id, state string, now int64) bool {
	t := m.byID[id]
	if t == nil {
		return false
	}
	if ownerState(state) {
		m.setMark(id, t.sc.name, state, now)
	} else {
		m.dropMark(id)
	}
	if t.state == state {
		return true
	}
	t.state = state
	if state != siem.PatternIgnored {
		t.fresh = false
		m.unpend(t)
	}
	if ownerState(state) {
		m.ownerMark(t)
	} else {
		m.ownerUnmark(t)
	}
	t.spikeUntil, t.usualKey = 0, 0
	if !t.dirty {
		m.markDirty(t)
		m.urgent = append(m.urgent, t)
	}
	return true
}
