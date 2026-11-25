package detect

import (
	"container/list"
	"context"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

// patHarness is a harness with log-pattern mining on, hours of the day in loc (UTC when nil).
func patHarness(t testing.TB, loc *time.Location, mod ...func(*Options)) *harness {
	t.Helper()
	mods := append([]func(*Options){func(o *Options) { o.Patterns.Enabled = true }}, mod...)
	h := newHarness(t, false, mods...)
	h.patSetup(loc)
	return h
}

func (h *harness) patSetup(loc *time.Location) {
	if loc == nil {
		loc = time.UTC
	}
	m := h.e.miner()
	m.loc = loc
	// The busy time's clock stands still: only TestPatternBudget drives the CPU budget (on the real
	// clock a test mining thousands of lines at once would go over it).
	still := time.Unix(1_700_000_000, 0)
	m.clock = func() time.Time { return still }
}

// patReopen restarts the engine (saving as at shutdown) and keeps the miner's zone.
func (h *harness) patReopen(t *testing.T) {
	t.Helper()
	loc := h.e.miner().loc
	h.reopen(t)
	h.patSetup(loc)
}

func (h *harness) pm() *miner { return h.e.miner() }

// appLine is an app service's log line at ts.
func appLine(ts time.Time, app, svc, lvl, msg string) siem.Event {
	return siem.Event{TS: ts.UTC(), Src: siem.SrcApp, App: app, Svc: svc, Lvl: lvl, Kind: siem.KindLog, Msg: msg}
}

// hostLine is a host's unclassified line at ts; uid is its journal sender ("": a file line).
func hostLine(ts time.Time, uid, msg string) siem.Event {
	e := siem.Event{TS: ts.UTC(), Src: siem.SrcHost, Lvl: siem.LvlInfo, Kind: siem.KindLog, Msg: msg}
	if uid != "" {
		e.F = map[string]any{"sender_uid": uid}
	}
	return e
}

// mine offers events (clock moved to each one's time when later) and mines what was queued, as the
// miner's goroutine does, in batches of patBatch.
func (h *harness) mine(evs ...siem.Event) {
	for i := range evs {
		if evs[i].TS.After(h.clk.now()) {
			h.clk.set(evs[i].TS)
		}
		ev := evs[i]
		ev.Normalize(h.clk.now())
		h.e.offerPattern(&ev)
		if len(h.pm().q) >= patQueue-1 {
			h.drainQueue()
		}
	}
	h.drainQueue()
}

func (h *harness) drainQueue() {
	m := h.pm()
	for {
		var batch []patLine
		for len(batch) < patBatch {
			select {
			case l := <-m.q:
				batch = append(batch, l)
				continue
			default:
			}
			break
		}
		if len(batch) == 0 {
			return
		}
		m.step(batch)
	}
}

// patFire hands the miner's firings to the engine, as Run does, and returns how many there were.
func (h *harness) patFire() int {
	n := 0
	for {
		select {
		case f := <-h.pm().fires:
			h.e.patternFire(f)
			n++
		default:
			return n
		}
	}
}

// patTick runs the engine's write tick for the miner at at, and hands its firings over.
func (h *harness) patTick(at time.Time) {
	h.clk.set(at.UTC())
	h.e.patternTick()
	h.patFire()
}

// tmplOf is the template a line's text falls into in an app scope, nil for none.
func (h *harness) tmplOf(app, svc, msg string) *ptmpl {
	m := h.pm()
	m.mu.Lock()
	defer m.mu.Unlock()
	sc := m.scopes[scopeKey{app: app, svc: svc}]
	if sc == nil {
		return nil
	}
	var toks [maxPatTokens]tok
	n := tokenize(msg, &toks)
	var ls [maxLeaves]*pnode
	for _, leaf := range ls[:m.leaves(sc, msg, toks[:n], &ls)] {
		for _, t := range leaf.clusters {
			if t.fits(msg, toks[:n]) {
				return t
			}
		}
	}
	return nil
}

// learnedScope makes app/svc's scope as if its first line was mined at first.
func (h *harness) learnedScope(app, svc string, first time.Time) {
	m := h.pm()
	m.mu.Lock()
	defer m.mu.Unlock()
	k := scopeKey{app: app, svc: svc}
	if sc := m.scopes[k]; sc != nil {
		sc.first = first.UnixNano()
		return
	}
	m.addScope(k, first.UnixNano(), patTokVersion)
}

// patRule is the pack's pattern rule id with mod applied.
func patRule(id string, mod ...func(*siem.Rule)) siem.Rule {
	r := cloneRule(packByID[id].Rule)
	for _, f := range mod {
		f(&r)
	}
	return r
}

// patRules are the four pattern rules as the pack has them.
func patPack() []siem.Rule {
	return []siem.Rule{patRule(rulePatternNew), patRule(rulePatternNewError), patRule(rulePatternSpike), patRule(rulePatternChurn)}
}

func (h *harness) patterns(t *testing.T, f siem.PatternFilter) []siem.Pattern {
	t.Helper()
	ps, err := h.e.Patterns(context.Background(), f)
	if err != nil {
		t.Fatal(err)
	}
	return ps
}

// patRows is the stored templates: ID → state.
func patRows(t *testing.T, h *harness) map[string]string {
	t.Helper()
	rows, err := h.e.db.w.Query(`SELECT id, state FROM patterns`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, st string
		if err := rows.Scan(&id, &st); err != nil {
			t.Fatal(err)
		}
		out[id] = st
	}
	return out
}

func patScopeRows(t *testing.T, h *harness) map[string]bool {
	t.Helper()
	rows, err := h.e.db.w.Query(`SELECT scope FROM pattern_scopes`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out[s] = true
	}
	return out
}

// checkPatBounds fails when the miner's state is past its limits or inconsistent.
func checkPatBounds(t testing.TB, m *miner) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	total, nodes, cache := 0, 0, 0
	for k, sc := range m.scopes {
		if m.byName[sc.name] != sc || k.host != sc.host || k.app != sc.app || k.svc != sc.svc {
			t.Fatalf("scope %s: maps disagree", sc.name)
		}
		if sc.n > m.lim.scopeTemplates || sc.lru.Len()+sc.wlru.Len()+sc.plru.Len()+sc.olru.Len() != sc.n || sc.plru.Len() > max(m.lim.scopeTemplates/4*3, 1) {
			t.Fatalf("scope %s: %d templates (%d+%d+%d listed), cap %d", sc.name, sc.n, sc.lru.Len()+sc.wlru.Len(), sc.plru.Len(), sc.olru.Len(), m.lim.scopeTemplates)
		}
		for _, l := range []*list.List{&sc.lru, &sc.wlru, &sc.plru, &sc.olru} {
			for el := l.Front(); el != nil; el = el.Next() {
				tp := el.Value.(*ptmpl)
				_, waiting := m.pending[tp]
				if tp.own != (l == &sc.olru) || tp.prot != (l == &sc.plru) || tp.own != ownerState(tp.state) || tp.el != el ||
					tp.pending != waiting || (tp.pending && !tp.own && !tp.prot) != (l == &sc.wlru) {
					t.Fatalf("template %s (%s): own %v prot %v pending %v in the wrong list", tp.id, tp.state, tp.own, tp.prot, tp.pending)
				}
			}
		}
		if sc.nodes > m.lim.scopeNodes() || len(sc.cache) > m.lim.scopeCache() {
			t.Fatalf("scope %s: %d nodes, %d cached", sc.name, sc.nodes, len(sc.cache))
		}
		total += sc.n
		nodes += sc.nodes
		cache += len(sc.cache)
		n := 0
		var walk func(x *pnode)
		walk = func(x *pnode) {
			n++
			if len(x.kids) > m.lim.kids || len(x.clusters) > m.lim.leafClusters || len(x.kids)+len(x.clusters) == 0 {
				t.Fatalf("scope %s: node with %d children, %d templates", sc.name, len(x.kids), len(x.clusters))
			}
			for _, tp := range x.clusters {
				if tp.dead || tp.leaf != x || m.byID[tp.id] != tp || len(tp.toks) == 0 || len(tp.toks) > maxPatTokens ||
					len(tp.text) > siem.MaxPatternText || len(tp.sample) > siem.MaxPatternText {
					t.Fatalf("template %s: bad (dead %v, %d tokens, %d text)", tp.id, tp.dead, len(tp.toks), len(tp.text))
				}
			}
			for _, k := range x.kids {
				walk(k)
			}
		}
		for _, r := range sc.roots {
			walk(r)
		}
		if n != sc.nodes {
			t.Fatalf("scope %s: %d nodes counted, %d in the tree", sc.name, sc.nodes, n)
		}
	}
	if len(m.scopes) > m.lim.scopes || total != m.ntmpl || len(m.byID) != m.ntmpl || m.ntmpl > m.lim.templates ||
		nodes != m.nodes || m.nodes > m.lim.nodes() || cache != m.ncache || m.ncache > m.lim.cache ||
		m.lru.Len()+m.wlru.Len()+m.plru.Len()+m.olru.Len() != m.ntmpl || m.plru.Len() > max(m.lim.templates/4*3, 1) || len(m.gone) > 2*m.lim.templates ||
		len(m.marks) > maxPatMarks {
		t.Fatalf("totals: %d scopes, %d templates (%d listed, %d by ID, %d counted), %d nodes (%d counted), %d cached (%d counted)",
			len(m.scopes), total, m.lru.Len()+m.wlru.Len()+m.plru.Len()+m.olru.Len(), len(m.byID), m.ntmpl, nodes, m.nodes, cache, m.ncache)
	}
}

func idsOf(ps []siem.Pattern) []string {
	out := make([]string, len(ps))
	for i, p := range ps {
		out[i] = p.ID
	}
	return out
}

func lines(n int, f func(i int) string) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = f(i)
	}
	return out
}
