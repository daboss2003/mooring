package detect

import (
	"container/list"
	"context"
	"database/sql"
	"encoding/binary"
	"errors"
	"math"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

// What the miner learned, in detect.db (migration 0007): a row per template (patterns: its
// tokens, counts and state; its sample line apart), a row per scope (when it was first and last
// seen, until when it learns again, the tokenizer version), the states the owner set
// (pattern_marks), and the watched hours with the reports sent this hour (pattern_meta "hours").

const (
	patTickRows   = 128  // rows saved (and deleted) per write tick at most
	patChunk      = 1000 // rows per transaction of a full save
	maxPatData    = 16 << 10
	maxPatScope   = 2*siem.MaxShort + 8
	patDataVer    = 1
	patMetaVer    = 1
	patMetaHours  = "hours"
	patBackoffMin = 5 * time.Second
	patBackoffMax = time.Minute
)

type patRow struct {
	id, scope, state string
	last             int64
	data             []byte
	sample           string
	sampleNS         int64
}

type scopeRow struct {
	scope                string
	first, relearn, last int64
	tokVer               int
}

type markRow struct {
	id, scope, state string
	at               int64
}

// patWrite is one save: rows to write and delete, and (fin) the end of a rewrite at stamp.
type patWrite struct {
	pats       []patRow
	scopes     []scopeRow
	meta       []byte
	gone       []string
	goneScopes []string
	stamp      int64
	fin        bool
	marks      []markRow // with marksSet: every mark (the stored ones are replaced)
	marksSet   bool

	tmpls []*ptmpl // what it took, to put back after a failure
	scs   []*pscope
}

func (w *patWrite) empty() bool {
	return len(w.pats)+len(w.scopes)+len(w.gone)+len(w.goneScopes) == 0 && w.meta == nil && !w.fin && !w.marksSet
}

// encode: the version, the path keys, the tokens, the level, first, last, count, hours seen and
// the newest of them, flags (1: reported, 2: fresh), then the newest hour counted and each hour's
// count.
func (t *ptmpl) encode() []byte {
	b := make([]byte, 0, 64+len(t.text)+2*patHours)
	b = append(b, patDataVer, byte(t.npath))
	for _, k := range t.path[:t.npath] {
		b = binary.AppendUvarint(b, uint64(len(k)))
		b = append(b, k...)
	}
	b = binary.AppendUvarint(b, uint64(len(t.toks)))
	for _, s := range t.toks {
		b = binary.AppendUvarint(b, uint64(len(s)))
		b = append(b, s...)
	}
	b = append(b, t.lvl)
	b = binary.AppendVarint(b, t.first)
	b = binary.AppendVarint(b, t.last)
	b = binary.AppendUvarint(b, uint64(t.count))
	b = binary.AppendUvarint(b, uint64(t.seen))
	b = binary.AppendVarint(b, t.seenAt)
	var flags byte
	if t.reported {
		flags |= 1
	}
	if t.fresh {
		flags |= 2
	}
	b = append(b, flags)
	b = binary.AppendVarint(b, t.hourAt)
	for _, v := range t.hours {
		b = binary.AppendUvarint(b, uint64(v))
	}
	return b
}

func (r *reader) str(limit uint64) (string, bool) {
	n := r.uvarint()
	if r.err != nil || n == 0 || n > limit {
		return "", false
	}
	v := r.bytes(n)
	return string(v), r.err == nil
}

func decodeTemplate(b []byte) (*ptmpl, error) {
	if len(b) < 2 || b[0] != patDataVer {
		return nil, errState
	}
	t := &ptmpl{npath: int(b[1])}
	r := &reader{b: b[2:]}
	if t.npath < 1 || t.npath > patDepth {
		return nil, errState
	}
	for i := 0; i < t.npath; i++ {
		s, ok := r.str(maxTokText + 8)
		if !ok {
			return nil, errState
		}
		t.path[i] = s
	}
	n := r.uvarint()
	if r.err != nil || n == 0 || n > maxPatTokens || min(int(n), patDepth) != t.npath {
		return nil, errState
	}
	t.toks = make([]string, n)
	for i := range t.toks {
		s, ok := r.str(maxTokText + 8)
		if !ok {
			return nil, errState
		}
		t.toks[i] = s
	}
	lv := r.bytes(1)
	if r.err != nil || lv[0] > 4 {
		return nil, errState
	}
	t.lvl = lv[0]
	t.first, t.last = r.varint(), r.varint()
	count, seen := r.uvarint(), r.uvarint()
	t.seenAt = r.varint()
	fl := r.bytes(1)
	if r.err != nil || count > 1<<62 || seen > 1<<31 || t.last < t.first || fl[0] > 3 {
		return nil, errState
	}
	t.count, t.seen, t.reported, t.fresh = int64(count), uint32(seen), fl[0]&1 != 0, fl[0]&2 != 0
	t.hourAt = r.varint()
	for i := range t.hours {
		v := r.uvarint()
		if v > math.MaxUint32 {
			return nil, errState
		}
		t.hours[i] = uint32(v)
	}
	if r.err != nil || len(r.b) != 0 {
		return nil, errState
	}
	t.text = render(t.toks)
	return t, nil
}

// encodeMeta is the miner's state stored as pattern_meta "hours": the version, the newest closed
// hour, each hour's state, then per new-pattern rule the hour of its report count, the count and
// the late ones.
func (m *miner) encodeMeta() []byte {
	b := append(make([]byte, 0, 48+patHours), patMetaVer)
	b = binary.AppendVarint(b, m.hours.closed)
	b = append(b, m.hours.st[:]...)
	for _, r := range m.rep {
		b = binary.AppendVarint(b, r.hour)
		b = binary.AppendUvarint(b, uint64(r.n))
		b = binary.AppendUvarint(b, uint64(r.late))
	}
	return b
}

func decodeMeta(b []byte) (hourMeta, [2]repBudget, error) {
	var (
		h   hourMeta
		rep [2]repBudget
	)
	if len(b) == 0 || b[0] != patMetaVer {
		return h, rep, errState
	}
	r := &reader{b: b[1:]}
	h.closed = r.varint()
	st := r.bytes(patHours)
	if r.err != nil || h.closed < 0 {
		return hourMeta{}, rep, errState
	}
	for i, s := range st {
		if s > hourLossy {
			return hourMeta{}, rep, errState
		}
		h.st[i] = s
	}
	for i := range rep {
		hour, n, late := r.varint(), r.uvarint(), r.uvarint()
		if r.err != nil || hour < 0 || n > math.MaxInt32 || late > n {
			return hourMeta{}, [2]repBudget{}, errState
		}
		rep[i] = repBudget{hour: hour, n: int32(n), late: int32(late)}
	}
	if len(r.b) != 0 {
		return hourMeta{}, [2]repBudget{}, errState
	}
	return h, rep, nil
}

func (m *miner) rowOf(t *ptmpl) patRow {
	return patRow{id: t.id, scope: t.sc.name, state: t.state, last: t.last, data: t.encode(), sample: t.sample,
		sampleNS: t.sampleAt}
}

func scopeRowOf(sc *pscope) scopeRow {
	return scopeRow{scope: sc.name, first: sc.first, relearn: sc.relearn, last: sc.last, tokVer: sc.tokVer}
}

// take takes up to limit changed templates (the owner's state changes first, then the structural
// changes, then with counts the ones whose counts changed only), the changed scopes, the watched
// hours, the owner's marks when one changed, and up to limit deletions, and marks them saved (under
// mu).
func (m *miner) take(limit int, counts bool) *patWrite {
	w := &patWrite{}
	add := func(t *ptmpl) {
		if len(w.pats) >= limit || t.dead || !t.dirty && !t.cdirty {
			return
		}
		m.clean(t)
		w.pats = append(w.pats, m.rowOf(t))
		w.tmpls = append(w.tmpls, t)
		t.saved = true
	}
	for _, t := range m.urgent {
		add(t)
	}
	m.urgent = m.urgent[:0]
	for t := range m.dirtySet {
		if len(w.pats) >= limit {
			break
		}
		add(t)
	}
	if counts {
		for t := range m.cdirtySet {
			if len(w.pats) >= limit {
				break
			}
			add(t)
		}
	}
	for _, sc := range m.byName {
		if sc.dirty && len(w.scopes) < limit {
			sc.dirty, sc.saved = false, true
			w.scopes = append(w.scopes, scopeRowOf(sc))
			w.scs = append(w.scs, sc)
		}
	}
	if m.metaDirty {
		m.metaDirty = false
		w.meta = m.encodeMeta()
	}
	if m.marksDirty {
		// Intentional: all of them (maxPatMarks rows at most), replacing the stored ones, not row by
		// row: they change when the owner sets a state or an app is deleted, rarely, and a whole
		// set can't drift from the one in memory after a failed save.
		m.marksDirty, w.marksSet = false, true
		w.marks = make([]markRow, 0, len(m.marks))
		for id, mk := range m.marks {
			w.marks = append(w.marks, markRow{id: id, scope: mk.scope, state: mk.state, at: mk.at})
		}
	}
	for id := range m.gone {
		if len(w.gone) >= limit {
			break
		}
		delete(m.gone, id)
		w.gone = append(w.gone, id)
	}
	for name := range m.goneScopes {
		if len(w.goneScopes) >= limit {
			break
		}
		delete(m.goneScopes, name)
		w.goneScopes = append(w.goneScopes, name)
	}
	return w
}

// unsave puts back what a failed save took (under mu).
func (m *miner) unsave(w *patWrite) {
	for _, t := range w.tmpls {
		m.markDirty(t)
	}
	for _, sc := range w.scs {
		if m.byName[sc.name] == sc {
			sc.dirty = true
		}
	}
	if w.meta != nil {
		m.metaDirty = true
	}
	if w.marksSet {
		m.marksDirty = true
	}
	for _, id := range w.gone {
		if m.byID[id] == nil {
			m.noteGone(id)
		}
	}
	for _, name := range w.goneScopes {
		if m.byName[name] == nil && len(m.goneScopes) < 2*m.lim.scopes {
			m.goneScopes[name] = struct{}{}
		}
	}
	if w.stamp != 0 {
		m.resync = true
	}
}

// savePatternsNow saves what changed: on a tick at most patTickRows rows of templates whose
// structure, state or sample changed; in full (persist, shutdown) every change, the counts too,
// patChunk rows per transaction, after rewriting every row when that is due (resync). After a
// failed write the ticks wait (backoff); a full save tries anyway.
func (e *Engine) savePatternsNow(full bool) {
	m := e.miner()
	if m == nil || e.closed.Load() {
		return
	}
	now := e.now()
	// A failure "later than now" is one the clock was set back from: no waiting on it.
	if !full && m.backoff > 0 && !now.Before(m.failAt) && now.Sub(m.failAt) < m.backoff {
		return
	}
	ctx := context.Background()
	if full {
		var resync bool
		m.locked(func() { resync = m.resync })
		if resync {
			if err := e.rewritePatterns(ctx, m, now); err != nil {
				e.patternSaveFailed(m, now, err)
				return
			}
		}
	}
	limit := patTickRows
	if full {
		limit = patChunk
	}
	for range 16 {
		var w *patWrite
		m.locked(func() { w = m.take(limit, full) })
		if w.empty() {
			return
		}
		if err := e.db.writePatterns(ctx, w, now.UnixNano()); err != nil {
			m.locked(func() { m.unsave(w) })
			e.patternSaveFailed(m, now, err)
			return
		}
		m.backoff = 0
		if !full {
			return
		}
	}
}

func (e *Engine) patternSaveFailed(m *miner, now time.Time, err error) {
	m.failAt, m.backoff = now, min(max(2*m.backoff, patBackoffMin), patBackoffMax)
	e.writeErrors.Add(1)
	e.logLimited("patterns", "security detection: learned log patterns not saved", "err", err)
}

// rewritePatterns saves every template and scope at one stamp, patChunk per transaction, and with
// the last deletes the rows the rewrite didn't write: a failure part-way loses no stored row.
func (e *Engine) rewritePatterns(ctx context.Context, m *miner, now time.Time) error {
	stamp, err := e.db.patternStamp(ctx, now)
	if err != nil {
		return err
	}
	var ids []string
	m.locked(func() {
		m.resync = false
		clear(m.gone)
		clear(m.goneScopes)
		ids = make([]string, 0, len(m.byID))
		for _, l := range []*list.List{&m.lru, &m.wlru, &m.plru, &m.olru} {
			for el := l.Back(); el != nil; el = el.Prev() {
				ids = append(ids, el.Value.(*ptmpl).id)
			}
		}
	})
	for i := 0; ; i += patChunk {
		j := min(i+patChunk, len(ids))
		w := &patWrite{stamp: stamp}
		// Intentional: what a chunk took is put back (resync again) when taking it panics part-way,
		// so the rewrite is tried again and no row it didn't write is deleted on a half-built set.
		func() {
			m.mu.Lock()
			defer m.mu.Unlock()
			defer func() {
				if r := recover(); r != nil {
					m.unsave(w)
					panic(r)
				}
			}()
			for _, id := range ids[i:j] {
				if t := m.byID[id]; t != nil {
					m.clean(t)
					w.pats = append(w.pats, m.rowOf(t))
					w.tmpls = append(w.tmpls, t)
					t.saved = true
				}
			}
			if j == len(ids) {
				w.fin = true
				for _, sc := range m.byName {
					sc.dirty, sc.saved = false, true
					w.scopes = append(w.scopes, scopeRowOf(sc))
					w.scs = append(w.scs, sc)
				}
				m.metaDirty = false
				w.meta = m.encodeMeta()
			}
		}()
		if err := e.db.writePatterns(ctx, w, stamp); err != nil {
			m.locked(func() { m.unsave(w) })
			return err
		}
		if w.fin {
			return nil
		}
	}
}

// patternStamp is the updated_ns of a rewrite: now, or later when a row was saved at now or later
// (a clock set back), so no row the rewrite didn't write has it.
func (d *db) patternStamp(ctx context.Context, now time.Time) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	stamp := now.UnixNano()
	for _, q := range []string{`SELECT MAX(updated_ns) FROM patterns`, `SELECT MAX(updated_ns) FROM pattern_scopes`} {
		var last sql.NullInt64
		if err := d.w.QueryRowContext(ctx, q).Scan(&last); err != nil {
			return 0, err
		}
		if last.Valid && last.Int64 >= stamp && last.Int64 < math.MaxInt64 {
			stamp = last.Int64 + 1
		}
	}
	return stamp, nil
}

// writePatterns applies a save in one transaction; rows are saved at ns (w.stamp for a rewrite).
func (d *db) writePatterns(ctx context.Context, w *patWrite, ns int64) error {
	ctx, cancel := context.WithTimeout(ctx, batchTimeout)
	defer cancel()
	tx, err := d.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, id := range w.gone {
		if _, err := tx.ExecContext(ctx, `DELETE FROM patterns WHERE id = ?`, id); err != nil {
			return err
		}
	}
	for _, s := range w.goneScopes {
		if _, err := tx.ExecContext(ctx, `DELETE FROM pattern_scopes WHERE scope = ?`, s); err != nil {
			return err
		}
	}
	if len(w.pats) > 0 {
		put, err := tx.PrepareContext(ctx, `INSERT INTO patterns(id, scope, state, last_ns, data, sample, sample_ns, updated_ns)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET scope = excluded.scope, state = excluded.state,
			last_ns = excluded.last_ns, data = excluded.data, sample = excluded.sample, sample_ns = excluded.sample_ns,
			updated_ns = excluded.updated_ns`)
		if err != nil {
			return err
		}
		defer put.Close()
		for _, p := range w.pats {
			if _, err := put.ExecContext(ctx, p.id, p.scope, p.state, p.last, p.data, p.sample, p.sampleNS, ns); err != nil {
				return err
			}
		}
	}
	for _, s := range w.scopes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO pattern_scopes(scope, first_ns, relearn_ns, tokenizer, last_ns, updated_ns)
			VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(scope) DO UPDATE SET first_ns = excluded.first_ns,
			relearn_ns = excluded.relearn_ns, tokenizer = excluded.tokenizer, last_ns = excluded.last_ns,
			updated_ns = excluded.updated_ns`, s.scope, s.first, s.relearn, s.tokVer, s.last, ns); err != nil {
			return err
		}
	}
	if w.marksSet {
		if _, err := tx.ExecContext(ctx, `DELETE FROM pattern_marks`); err != nil {
			return err
		}
		if len(w.marks) > 0 {
			put, err := tx.PrepareContext(ctx, `INSERT INTO pattern_marks(id, scope, state, set_ns) VALUES (?, ?, ?, ?)`)
			if err != nil {
				return err
			}
			defer put.Close()
			for _, k := range w.marks {
				if _, err := put.ExecContext(ctx, k.id, k.scope, k.state, k.at); err != nil {
					return err
				}
			}
		}
	}
	if w.meta != nil {
		if _, err := tx.ExecContext(ctx, `INSERT INTO pattern_meta(name, data) VALUES (?, ?)
			ON CONFLICT(name) DO UPDATE SET data = excluded.data`, patMetaHours, w.meta); err != nil {
			return err
		}
	}
	if w.fin {
		if _, err := tx.ExecContext(ctx, `DELETE FROM patterns WHERE updated_ns <> ?`, w.stamp); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM pattern_scopes WHERE updated_ns <> ?`, w.stamp); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// patLoad is what loadPatternRows read.
type patLoad struct {
	scopes []scopeRow
	pats   []patRow // the most recently seen first
	marks  []markRow
	meta   []byte
}

// loadPatternRows deletes the rows longer than a valid one can be, so none is read into memory,
// and returns the scopes, at most limit templates (the most recently seen first), at most
// maxPatMarks+1 marks (the most recently set first) and the watched hours.
func (d *db) loadPatternRows(ctx context.Context, limit int) (*patLoad, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if _, err := d.w.ExecContext(ctx, `DELETE FROM patterns WHERE length(CAST(id AS BLOB)) > 17
		OR length(CAST(scope AS BLOB)) > ? OR length(CAST(state AS BLOB)) > 16 OR length(CAST(data AS BLOB)) > ?
		OR length(CAST(sample AS BLOB)) > ?`, maxPatScope, maxPatData, siem.MaxPatternText); err != nil {
		return nil, err
	}
	if _, err := d.w.ExecContext(ctx, `DELETE FROM pattern_scopes WHERE length(CAST(scope AS BLOB)) > ?`, maxPatScope); err != nil {
		return nil, err
	}
	if _, err := d.w.ExecContext(ctx, `DELETE FROM pattern_marks WHERE length(CAST(id AS BLOB)) > 17
		OR length(CAST(scope AS BLOB)) > ? OR length(CAST(state AS BLOB)) > 16`, maxPatScope); err != nil {
		return nil, err
	}
	l := &patLoad{}
	// Each query's rows are read to the end and closed before the next statement (one connection).
	if err := d.patQuery(ctx, func(rows *sql.Rows) error {
		var s scopeRow
		if err := rows.Scan(&s.scope, &s.first, &s.relearn, &s.tokVer, &s.last); err != nil {
			return err
		}
		l.scopes = append(l.scopes, s)
		return nil
	}, `SELECT scope, first_ns, relearn_ns, tokenizer, last_ns FROM pattern_scopes LIMIT ?`, 4*defaultPatLimits.scopes); err != nil {
		return nil, err
	}
	if err := d.patQuery(ctx, func(rows *sql.Rows) error {
		var p patRow
		if err := rows.Scan(&p.id, &p.scope, &p.state, &p.last, &p.data, &p.sample, &p.sampleNS); err != nil {
			return err
		}
		l.pats = append(l.pats, p)
		return nil
	}, `SELECT id, scope, state, last_ns, data, sample, sample_ns FROM patterns ORDER BY last_ns DESC LIMIT ?`, limit); err != nil {
		return nil, err
	}
	if err := d.patQuery(ctx, func(rows *sql.Rows) error {
		var k markRow
		if err := rows.Scan(&k.id, &k.scope, &k.state, &k.at); err != nil {
			return err
		}
		l.marks = append(l.marks, k)
		return nil
	}, `SELECT id, scope, state, set_ns FROM pattern_marks ORDER BY set_ns DESC LIMIT ?`, maxPatMarks+1); err != nil {
		return nil, err
	}
	err := d.w.QueryRowContext(ctx, `SELECT data FROM pattern_meta WHERE name = ?`, patMetaHours).Scan(&l.meta)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	return l, nil
}

// patQuery runs q and hands each row to scan; the rows are closed when it returns.
func (d *db) patQuery(ctx context.Context, scan func(*sql.Rows) error, q string, args ...any) error {
	rows, err := d.w.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := scan(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

// clearPatternSamples clears every stored sample line (patterns are off).
func (d *db) clearPatternSamples(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, err := d.w.ExecContext(ctx, `UPDATE patterns SET sample = '', sample_ns = 0 WHERE sample <> '' OR sample_ns <> 0`)
	return err
}

// deletePatternPrefix deletes the templates, scopes and marks of the scope names starting with prefix
// ("app:<slug>/"): the names from prefix up to prefix with its '/' raised to '0' (the next byte).
func (d *db) deletePatternPrefix(ctx context.Context, prefix string) error {
	if !strings.HasSuffix(prefix, "/") {
		return errors.New("detect: a pattern scope prefix ends in '/'")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	hi := prefix[:len(prefix)-1] + "0"
	tx, err := d.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM patterns WHERE scope >= ? AND scope < ?`, prefix, hi); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM pattern_scopes WHERE scope >= ? AND scope < ?`, prefix, hi); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM pattern_marks WHERE scope >= ? AND scope < ?`, prefix, hi); err != nil {
		return err
	}
	return tx.Commit()
}

// keepPatternApps deletes the templates, scopes and marks of every app whose slug isn't in keep; the
// host's are kept.
func (d *db) keepPatternApps(ctx context.Context, keep map[string]bool) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// "app:" up to "app;" (':' raised to the next byte): the scope names starting with "app:".
	var gone []string
	for _, q := range []string{
		`SELECT DISTINCT substr(scope, 5, instr(substr(scope, 5), '/') - 1) FROM patterns WHERE scope >= 'app:' AND scope < 'app;'`,
		`SELECT DISTINCT substr(scope, 5, instr(substr(scope, 5), '/') - 1) FROM pattern_scopes WHERE scope >= 'app:' AND scope < 'app;'`,
		`SELECT DISTINCT substr(scope, 5, instr(substr(scope, 5), '/') - 1) FROM pattern_marks WHERE scope >= 'app:' AND scope < 'app;'`,
	} {
		rows, err := d.w.QueryContext(ctx, q)
		if err != nil {
			return err
		}
		for rows.Next() {
			var slug string
			if err := rows.Scan(&slug); err != nil {
				rows.Close()
				return err
			}
			if slug != "" && !keep[slug] {
				gone = append(gone, slug)
			}
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
	}
	for _, slug := range gone {
		if err := d.deletePatternPrefix(ctx, appPatPrefix(slug)); err != nil {
			return err
		}
	}
	return nil
}

// load reads back what was learned (New). A row that doesn't decode, of a scope that isn't one, or
// past a cap is dropped (its row deleted with the next save): past the templates' cap, and past a
// scope's, the rows seen least recently, and every row is rewritten at the next full save. A scope
// whose tokenizer version differs learns again for patRelearn. A sample past the retention isn't
// kept, and times past now (a clock that ran ahead) are brought to now (unfuture).
func (m *miner) load(ctx context.Context, now time.Time) error {
	l, err := m.e.db.loadPatternRows(ctx, m.lim.templates+1)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	ns := now.UnixNano()
	if l.meta != nil {
		if h, rep, err := decodeMeta(l.meta); err == nil {
			m.hours, m.rep = h, rep
		} else {
			m.metaDirty = true
		}
	}
	scopeOf := func(name string, first int64, tokVer int) *pscope {
		if sc := m.byName[name]; sc != nil {
			return sc
		}
		host, app, svc, ok := parseScope(name)
		if !ok || len(m.scopes) >= m.lim.scopes {
			return nil
		}
		sc := m.addScope(scopeKey{host: host, app: app, svc: svc}, first, tokVer)
		sc.dirty = false
		if tokVer != patTokVersion {
			sc.relearn, sc.tokVer, sc.dirty = ns+int64(patRelearn), patTokVersion, true
		}
		return sc
	}
	bad := 0
	for _, s := range l.scopes {
		if sc := scopeOf(s.scope, s.first, s.tokVer); sc != nil {
			sc.saved = true
			if s.relearn > sc.relearn {
				sc.relearn = s.relearn
			}
			if s.last > sc.last {
				sc.last, sc.lastSave = s.last, s.last
			}
		} else {
			bad++
			if len(m.goneScopes) < 2*m.lim.scopes {
				m.goneScopes[s.scope] = struct{}{}
			}
		}
	}
	pats := l.pats
	if len(pats) > m.lim.templates {
		pats, m.resync = pats[:m.lim.templates], true
	}
	// The most recently seen first: they are the ones kept within a scope's cap.
	keep := make([]*ptmpl, len(pats))
	seen := make(map[string]struct{}, len(pats))
	kept := map[*pscope]int{}
	for i, p := range pats {
		t, err := decodeTemplate(p.data)
		var sc *pscope
		if _, dup := seen[p.id]; err == nil && !dup && validPatternID(p.id) && validState(p.state) {
			// A template of a scope with no row: the scope's start is unknown, so it learns again.
			sc = m.byName[p.scope]
			if sc == nil {
				sc = scopeOf(p.scope, t.first, 0)
			}
		}
		if sc == nil || kept[sc] >= m.lim.scopeTemplates {
			bad++
			m.noteGone(p.id)
			continue
		}
		kept[sc]++
		seen[p.id] = struct{}{}
		t.id, t.sc, t.state, t.saved = p.id, sc, p.state, true
		t.sample, t.sampleAt = p.sample, p.sampleNS
		keep[i] = t
	}
	// Then the oldest first, so the most recently seen end up the most recently used.
	for i := len(keep) - 1; i >= 0; i-- {
		t := keep[i]
		if t == nil {
			continue
		}
		sc := t.sc
		path := t.path
		leaf := m.insertLeaf(sc, len(t.toks), t.path[:t.npath])
		if leaf == nil || len(leaf.clusters) >= m.lim.leafClusters {
			if leaf != nil {
				m.prune(sc, leaf)
			}
			bad++
			m.noteGone(t.id)
			continue
		}
		t.leaf = leaf
		t.minAt = floorDiv(t.last, int64(time.Minute))
		if t.state == siem.PatternNew && !t.reported {
			t.fresh = true
		}
		if t.last > sc.last {
			sc.last = t.last
		}
		m.link(t)
		// The path changed (it went to a <*> child this time), or the sample is past the retention
		// (it expired while stopped, and isn't shown until the first sweep either): saved so.
		if t.path != path {
			m.markDirty(t)
		}
		if t.sample != "" && ns-t.sampleAt > int64(m.retain) {
			t.sample, t.sampleAt = "", 0
			m.markDirty(t)
		}
	}
	if len(l.marks) > maxPatMarks {
		l.marks, m.marksDirty = l.marks[:maxPatMarks], true
	}
	for _, k := range l.marks {
		if _, _, _, ok := parseScope(k.scope); !ok || !validPatternID(k.id) || !ownerState(k.state) || m.marks[k.id] != nil {
			m.marksDirty = true
			continue
		}
		m.marks[k.id] = &pmark{scope: k.scope, state: k.state, at: k.at}
	}
	m.unfuture(now)
	if bad > 0 {
		m.e.log.Warn("security detection: learned log patterns discarded", "count", bad)
	}
	m.nScopes.Store(int64(len(m.scopes)))
	m.nTemplates.Store(int64(m.ntmpl))
	return nil
}

func validState(s string) bool {
	switch s {
	case siem.PatternLearned, siem.PatternNew, siem.PatternExpected, siem.PatternIgnored:
		return true
	}
	return false
}
