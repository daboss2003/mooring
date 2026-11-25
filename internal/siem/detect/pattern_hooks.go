package detect

import (
	"container/list"
	"context"
	"errors"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

// Log patterns (phase 4, docs/security-detections.md "Log patterns"): the hooks the engine calls.
// The miner is in pattern_miner.go, its tree in pattern_drain.go, the tokenizer in
// pattern_token.go, what it saves in pattern_db.go, the rules in pack_pattern.go.

// PatternOptions configures log-pattern mining.
type PatternOptions struct {
	Enabled       bool
	MaxCPUPercent int      // the miner's share of one CPU core (1–25; 0 means 5)
	ExcludeApps   []string // app slugs whose lines are not mined
	// SampleRetention is how long a pattern's sample line is kept after it was last seen (the
	// security logs' hot_retention; 0 means 14 days).
	SampleRetention time.Duration

	// m is the miner, set by New (loadPatterns) when Enabled.
	// Intentional: held here, not in Engine, because engine.go belongs to the engine's own build;
	// e.miner() is the one place that reads it.
	m *miner
}

// patternFiring is one firing the miner hands to the engine goroutine.
type patternFiring struct {
	rule, key     string // the rule, and the pattern's ID (pattern.churn: the scope's name)
	ts            time.Time
	src, app, svc string
	count         int
	what          string // the summary's "what happened": no template or message text
}

func (e *Engine) miner() *miner { return e.opt.Patterns.m }

func f64bits(v float64) uint64 { return math.Float64bits(v) }

// offerPattern is called by the pipeline subscriber (on the pipeline goroutine) for every timely
// event, before its fields are copied; it must be cheap and never block or keep ev.
func (e *Engine) offerPattern(ev *siem.Event) {
	if m := e.miner(); m != nil {
		m.offer(ev)
	}
}

// startPatterns starts the miner (Run, once). stopPatterns stops it and takes its last firings.
func (e *Engine) startPatterns() {
	if m := e.miner(); m != nil {
		m.start()
	}
}

func (e *Engine) stopPatterns() {
	m := e.miner()
	if m == nil {
		return
	}
	m.halt()
	for {
		select {
		case f := <-m.fires:
			e.safe(func() { e.patternFire(f) })
		default:
			return
		}
	}
}

// patternFires is the miner's firings channel (nil when patterns are off).
func (e *Engine) patternFires() <-chan patternFiring {
	if m := e.miner(); m != nil {
		return m.fires
	}
	return nil
}

// patternFire handles one firing on the engine goroutine: the rule in force records it (when it is
// switched on) like any detection, keyed by the pattern's ID, with the scope's app and service.
// Pattern detections have no account or address, so they join no incident.
func (e *Engine) patternFire(f patternFiring) {
	c := e.rules.Load().byID[f.rule]
	if c == nil || !c.r.Enabled || c.r.Type != siem.RuleBaseline || c.r.Baseline != siem.BaselinePattern {
		return
	}
	ev := &siem.Event{TS: f.ts, Src: f.src, App: f.app, Svc: f.svc, Kind: siem.KindLog, Lvl: siem.LvlInfo}
	e.fire(c, f.key, ev, firing{count: f.count, reasons: []string{f.what}})
}

// patternTick runs on the engine's write tick.
func (e *Engine) patternTick() {
	m := e.miner()
	if m == nil || e.closed.Load() {
		return
	}
	m.locked(func() { m.tick(e.now()) })
	e.savePatternsNow(false)
}

// locked runs f under the miner's lock.
// Intentional: unlocked by defer, in a function of its own, wherever the engine goroutine takes the
// lock: a panic under it is recovered by the engine (safe), and a lock left held would stop the
// miner, the dashboard's reads and the next tick for good.
func (m *miner) locked(f func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	f()
}

// loadPatterns (New) and savePatterns (persist, and at shutdown) read and write what was learned.
func (e *Engine) loadPatterns() {
	if !e.opt.Patterns.Enabled {
		// Intentional: with patterns off nothing clears a sample when its retention ends, and a
		// sample is a log line: none is kept. The templates stay, for when patterns are on again.
		if err := e.db.clearPatternSamples(context.Background()); err != nil {
			e.log.Error("security detection: stored log-pattern samples not cleared", "err", err)
		}
		return
	}
	m := newMiner(e)
	e.opt.Patterns.m = m
	// Intentional: what can't be read back is learned again (its scopes start learning from now),
	// mining isn't refused.
	if err := m.load(context.Background(), e.now()); err != nil {
		e.log.Error("security detection: learned log patterns not loaded", "err", err)
	}
}

func (e *Engine) savePatterns() { e.savePatternsNow(true) }

// Bounds of the pattern rules' tunables.
const (
	maxPatSettle    = 24 * hour
	minPatSpikeLrn  = day
	maxPatSpikeLrn  = 7 * day
	maxPatWindow    = patMins * minute
	minPatLearnTime = hour
)

// validatePatternRule checks a pattern rule's tunables (validateBaseline) and returns the GroupBy
// it must have.
func validatePatternRule(r *siem.Rule) (group string, err error) {
	count := func() error { return checkRange("the count", r.Count, 1, maxCount, showInt) }
	switch r.ID {
	case rulePatternNew, rulePatternNewError:
		err = errors.Join(count(), checkRange("the settle time", r.Window, minWindow, maxPatSettle, showDur),
			checkRange("the learning period", r.Learn, minPatLearnTime, maxLearn, showDur))
		r.Factor = 0
	case rulePatternSpike:
		err = errors.Join(count(), checkRange("the window", r.Window, minWindow, maxPatWindow, showDur),
			checkRange("the factor", r.Factor, minFactor, maxFactor, showFloat),
			checkRange("the learning period", r.Learn, minPatSpikeLrn, maxPatSpikeLrn, showDur))
	case rulePatternChurn:
		err = count()
		r.Window, r.Factor, r.Learn = 0, 0, 0
	default:
		return "app", invalid("%q is not a log-pattern rule", siem.Cut(r.ID, 64))
	}
	return "app", err
}

// DeleteAppPatterns forgets an app's patterns (app delete); KeepAppPatterns forgets those of every
// app not in slugs (at start, for apps deleted while detection was off). As DeleteAppBaselines:
// the saved rows are deleted before it returns, the templates in memory at the miner's next step
// or tick (which also deletes any row of them saved in between), and the app's lines aren't mined
// for appGoneFor after a delete. It works with patterns off too (rows of an earlier run).
func (e *Engine) DeleteAppPatterns(ctx context.Context, slug string) error {
	if err := checkPatSlug(slug); err != nil {
		return err
	}
	if e.closed.Load() {
		return errClosed
	}
	if m := e.miner(); m != nil {
		if err := m.queueOp(patOp{slug: slug, at: e.now()}); err != nil {
			return err
		}
	}
	return e.db.deletePatternPrefix(ctx, appPatPrefix(slug))
}

func (e *Engine) KeepAppPatterns(ctx context.Context, slugs []string) error {
	keep := make(map[string]bool, len(slugs))
	for _, s := range slugs {
		if err := checkPatSlug(s); err != nil {
			return err
		}
		keep[s] = true
	}
	if e.closed.Load() {
		return errClosed
	}
	if m := e.miner(); m != nil {
		if err := m.queueOp(patOp{keep: keep}); err != nil {
			return err
		}
	}
	return e.db.keepPatternApps(ctx, keep)
}

func checkPatSlug(slug string) error {
	if err := checkSlug(slug); err != nil {
		return err
	}
	if strings.ContainsRune(slug, '/') {
		return invalidIn("an app slug has no '/'")
	}
	return nil
}

var _ siem.PatternService = (*Engine)(nil)

// Patterns lists patterns for the page (see siem.PatternFilter), without Sample and Hourly.
func (e *Engine) Patterns(ctx context.Context, f siem.PatternFilter) ([]siem.Pattern, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if e.closed.Load() {
		return nil, errClosed
	}
	if f.Service != "" && f.App == "" {
		return nil, invalidIn("a service filter needs its app")
	}
	if f.Host && f.App != "" {
		return nil, invalidIn("the host's patterns have no app")
	}
	for _, s := range f.States {
		if !validState(s) {
			return nil, invalidIn("unknown pattern state %q", siem.Cut(s, 32))
		}
	}
	minLvl := -1
	if f.MinLevel != "" {
		if !validLevel(f.MinLevel) {
			return nil, invalidIn("unknown level %q", siem.Cut(f.MinLevel, 32))
		}
		minLvl = siem.LevelRank(f.MinLevel)
	}
	switch f.Sort {
	case "", "last", "count", "first":
	default:
		return nil, invalidIn("unknown sort %q (last, count, first)", siem.Cut(f.Sort, 32))
	}
	limit := f.Limit
	switch {
	case limit <= 0:
		limit = 50
	case limit > 200:
		limit = 200
	}
	m := e.miner()
	if m == nil {
		return []siem.Pattern{}, nil
	}
	nowH := floorDiv(e.now().UnixNano(), int64(time.Hour))
	type ref struct {
		t   *ptmpl
		c24 uint64
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var refs []ref
	for _, sc := range m.byName {
		switch {
		case f.Host && !sc.host, f.App != "" && (sc.host || sc.app != f.App), f.Service != "" && sc.svc != f.Service:
			continue
		}
		for _, l := range []*list.List{&sc.lru, &sc.wlru, &sc.plru, &sc.olru} {
			for el := l.Front(); el != nil; el = el.Next() {
				t := el.Value.(*ptmpl)
				if len(f.States) > 0 && !slices.Contains(f.States, t.state) || minLvl >= 0 && int(t.lvl) < minLvl {
					continue
				}
				r := ref{t: t}
				if f.Sort == "count" {
					for h := nowH - 23; h <= nowH; h++ {
						r.c24 += uint64(t.hourCount(h))
					}
				}
				refs = append(refs, r)
			}
		}
	}
	slices.SortFunc(refs, func(a, b ref) int {
		var c int
		switch f.Sort {
		case "count":
			c = cmpUint(b.c24, a.c24)
		case "first":
			c = cmpInt(b.t.first, a.t.first)
		}
		if c == 0 {
			c = cmpInt(b.t.last, a.t.last)
		}
		if c == 0 {
			c = strings.Compare(a.t.id, b.t.id)
		}
		return c
	})
	out := []siem.Pattern{}
	for i := max(f.Offset, 0); i < len(refs) && len(out) < limit; i++ {
		out = append(out, patternOf(refs[i].t))
	}
	return out, nil
}

func cmpUint(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func validLevel(l string) bool {
	switch l {
	case siem.LvlDebug, siem.LvlInfo, siem.LvlWarn, siem.LvlError, siem.LvlCritical:
		return true
	}
	return false
}

// levelName is the event level of a rank.
func levelName(r uint8) string {
	for _, l := range []string{siem.LvlDebug, siem.LvlInfo, siem.LvlWarn, siem.LvlError, siem.LvlCritical} {
		if siem.LevelRank(l) == int(r) {
			return l
		}
	}
	return siem.LvlInfo
}

func patternOf(t *ptmpl) siem.Pattern {
	p := siem.Pattern{ID: t.id, Scope: t.sc.name, Template: t.text, Level: levelName(t.lvl), State: t.state,
		First: time.Unix(0, t.first).UTC(), Last: time.Unix(0, t.last).UTC(), Count: t.count}
	if !t.sc.host {
		p.App, p.Service = t.sc.app, t.sc.svc
	}
	return p
}

// Pattern returns one pattern with its sample line and its lines per hour for the last 168 hours.
func (e *Engine) Pattern(ctx context.Context, id string) (siem.Pattern, bool, error) {
	if err := ctx.Err(); err != nil {
		return siem.Pattern{}, false, err
	}
	if e.closed.Load() {
		return siem.Pattern{}, false, errClosed
	}
	m := e.miner()
	if m == nil {
		return siem.Pattern{}, false, nil
	}
	nowH := floorDiv(e.now().UnixNano(), int64(time.Hour))
	m.mu.Lock()
	defer m.mu.Unlock()
	t := m.byID[id]
	if t == nil {
		return siem.Pattern{}, false, nil
	}
	p := patternOf(t)
	p.Sample = t.sample
	p.Hourly = make([]uint32, 168)
	for i := range p.Hourly {
		p.Hourly[i] = t.hourCount(nowH - 167 + int64(i))
	}
	return p, true, nil
}

// SetPatternState sets expected, ignored or learned (watch again); actor is recorded by the
// caller's audit event. It is saved with the engine's next write tick. expected and ignored
// outlive the template being forgotten for room (the same template made again has the state);
// expected and learned cancel a new template's report not sent yet, ignored doesn't.
func (e *Engine) SetPatternState(ctx context.Context, id, state, actor string) error {
	switch state {
	case siem.PatternExpected, siem.PatternIgnored, siem.PatternLearned:
	default:
		return invalidIn("a pattern's state can be set to expected, ignored or learned, not %q", siem.Cut(state, 32))
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if e.closed.Load() {
		return errClosed
	}
	m := e.miner()
	if m == nil {
		return invalidIn("unknown pattern")
	}
	var ok bool
	now := e.now().UnixNano()
	m.locked(func() { ok = m.setState(id, state, now) })
	if !ok {
		return invalidIn("unknown pattern")
	}
	return nil
}

// PatternStats is the miner's state for the page header.
func (e *Engine) PatternStats() siem.PatternStats {
	m := e.miner()
	if m == nil {
		return siem.PatternStats{}
	}
	s := siem.PatternStats{Enabled: true, Scopes: int(m.nScopes.Load()), Patterns: int(m.nTemplates.Load()),
		Lines: m.lines.Load(), Unmined: m.unmined.Load(), Dropped: m.dropped.Load(), Overflowed: m.overflowed.Load(),
		BudgetPct: math.Float64frombits(m.budgetPct.Load())}
	if l := m.learnList.Load(); l != nil {
		s.Learning = slices.Clone(*l)
	}
	return s
}
