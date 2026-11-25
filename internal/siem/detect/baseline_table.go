package detect

import "container/list"

// table is one baseline kind's learned entities (accounts, server users, host names, addresses),
// keyed by values attackers choose, so it is bounded: past max entities the least recently used is
// dropped. Entities with a learned history are protected: they are dropped only when no other is
// left, and take at most maxProt places (past that the least recently used protected one goes back
// to the others), so a flood of new keys can't push out what was learned and new keys still get a
// place. It also tracks what changed since the last save (dirty) and the saved entities dropped
// since (gone), for baselineTick and saveBaselines.
type table[T any] struct {
	kind         string
	max, maxProt int
	enc          func(*T) []byte
	// reset clears what an entity learned per hour, for a kind that learns per hour (nil for the
	// others): the server's time zone changed.
	reset     func(*T)
	m         map[string]*list.Element // key → *tent[T]
	lru, plru list.List                // most recently used first; plru the protected ones

	dirty map[string]struct{}
	dq    []string // dirty keys, oldest change first (a key no longer dirty is skipped)
	dqHd  int
	gone  map[string]struct{} // saved entities dropped since the last save (rows to delete)
	// resync: the next full save rewrites the kind (more entities were dropped than gone may hold,
	// more rows were loaded than max, or the hours were reset).
	resync bool
}

type tent[T any] struct {
	key   string
	v     T
	prot  bool
	saved bool // a row exists (it was loaded or saved): dropping it deletes the row
}

func newTable[T any](kind string, max int, enc func(*T) []byte) *table[T] {
	return &table[T]{kind: kind, max: max, maxProt: max / 4 * 3, enc: enc, m: map[string]*list.Element{},
		dirty: map[string]struct{}{}, gone: map[string]struct{}{}}
}

func (t *table[T]) len() int { return len(t.m) }

func (t *table[T]) listOf(x *tent[T]) *list.List {
	if x.prot {
		return &t.plru
	}
	return &t.lru
}

// get returns key's entity (now the most recently used), nil when there is none.
func (t *table[T]) get(key string) *tent[T] {
	el, ok := t.m[key]
	if !ok {
		return nil
	}
	x := el.Value.(*tent[T])
	t.listOf(x).MoveToFront(el)
	return x
}

// peek returns key's entity without changing the order.
func (t *table[T]) peek(key string) *tent[T] {
	if el, ok := t.m[key]; ok {
		return el.Value.(*tent[T])
	}
	return nil
}

// add creates key's entity (it must not exist), dropping the least recently used ones past max.
func (t *table[T]) add(key string) *tent[T] {
	x := &tent[T]{key: key}
	if _, ok := t.gone[key]; ok {
		// A saved entity dropped and back before the save: its row still exists. Left in gone, a
		// later save (or a later part of a full one) would delete the row of the entity now here.
		delete(t.gone, key)
		x.saved = true
	}
	t.m[key] = t.lru.PushFront(x)
	for len(t.m) > t.max {
		el := t.lru.Back()
		if el == nil || el.Value.(*tent[T]) == x {
			if el = t.plru.Back(); el == nil {
				break
			}
		}
		t.drop(el.Value.(*tent[T]))
	}
	return x
}

// protect moves an entity with a learned history to the protected ones.
func (t *table[T]) protect(x *tent[T]) {
	el, ok := t.m[x.key]
	if !ok || x.prot {
		return
	}
	t.lru.Remove(el)
	x.prot = true
	t.m[x.key] = t.plru.PushFront(x)
	for t.plru.Len() > t.maxProt && t.plru.Len() > 1 {
		b := t.plru.Back()
		y := b.Value.(*tent[T])
		t.plru.Remove(b)
		y.prot = false
		t.m[y.key] = t.lru.PushFront(y)
	}
}

// drop removes an entity (its saved row is deleted with the next save).
func (t *table[T]) drop(x *tent[T]) {
	el, ok := t.m[x.key]
	if !ok {
		return
	}
	t.listOf(x).Remove(el)
	delete(t.m, x.key)
	delete(t.dirty, x.key)
	if x.saved {
		t.noteGone(x.key)
	}
}

func (t *table[T]) noteGone(key string) {
	if t.resync {
		return
	}
	if len(t.gone) >= t.max {
		// Intentional: past max rows to delete, the kind is rewritten whole at the next full save
		// instead (a flood of keys would otherwise grow this set without bound).
		t.resync, t.gone = true, map[string]struct{}{}
		return
	}
	t.gone[key] = struct{}{}
}

// touch marks an entity changed (saved with the next tick or full save).
func (t *table[T]) touch(x *tent[T]) {
	if _, ok := t.dirty[x.key]; ok {
		return
	}
	t.dirty[x.key] = struct{}{}
	t.dq = append(t.dq, x.key)
	// The queue keeps a key of an entity dropped while dirty: rebuilt from the set when it outgrows
	// it (order then lost), so it stays O(entities).
	if live := len(t.dq) - t.dqHd; live > 2*len(t.dirty)+1024 {
		t.dq, t.dqHd = t.dq[:0], 0
		for k := range t.dirty {
			t.dq = append(t.dq, k)
		}
	}
}

// each calls f for every entity, the least recently used first; f may drop the entity it is given.
func (t *table[T]) each(f func(x *tent[T])) {
	for _, l := range []*list.List{&t.lru, &t.plru} {
		for el := l.Back(); el != nil; {
			prev := el.Prev()
			f(el.Value.(*tent[T]))
			el = prev
		}
	}
}

// blRow is one entity's saved form.
type blRow struct {
	kind, key string
	data      []byte
}

// takeDirty returns up to n changed entities, encoded, the oldest change first, and marks them
// saved (clean); n < 0: all of them.
func (t *table[T]) takeDirty(n int) []blRow {
	var out []blRow
	for t.dqHd < len(t.dq) && (n < 0 || len(out) < n) {
		k := t.dq[t.dqHd]
		t.dq[t.dqHd] = ""
		t.dqHd++
		if _, ok := t.dirty[k]; !ok {
			continue
		}
		delete(t.dirty, k)
		el, ok := t.m[k]
		if !ok {
			continue
		}
		x := el.Value.(*tent[T])
		out = append(out, blRow{kind: t.kind, key: k, data: t.enc(&x.v)})
		x.saved = true
	}
	if t.dqHd == len(t.dq) {
		t.dq, t.dqHd = t.dq[:0], 0
	} else if t.dqHd > 1024 && t.dqHd > len(t.dq)/2 {
		n := copy(t.dq, t.dq[t.dqHd:])
		t.dq, t.dqHd = t.dq[:n], 0
	}
	return out
}

// takeGone returns up to n keys of dropped saved entities (n < 0: all) and forgets them.
func (t *table[T]) takeGone(n int) []string {
	var out []string
	for k := range t.gone {
		if n >= 0 && len(out) >= n {
			break
		}
		out = append(out, k)
		delete(t.gone, k)
	}
	return out
}

// startRewrite begins a rewrite of the kind (every entity saved, the kind's other rows deleted): it
// returns every entity's key, the least recently used first, and clears what was waiting to be
// saved (the rewrite saves it).
func (t *table[T]) startRewrite() []string {
	keys := make([]string, 0, len(t.m))
	t.each(func(x *tent[T]) { keys = append(keys, x.key) })
	t.resync = false
	clear(t.gone)
	clear(t.dirty)
	t.dq, t.dqHd = t.dq[:0], 0
	return keys
}

// encodeKeys returns the entities of keys still here, encoded, and marks them saved.
func (t *table[T]) encodeKeys(keys []string) []blRow {
	out := make([]blRow, 0, len(keys))
	for _, k := range keys {
		if x := t.peek(k); x != nil {
			out = append(out, blRow{kind: t.kind, key: k, data: t.enc(&x.v)})
			x.saved = true
		}
	}
	return out
}

// setResync has the next full save rewrite the kind (the rows to delete are then its rows of no
// entity here).
func (t *table[T]) setResync() {
	t.resync = true
	clear(t.gone)
}

// resetHours clears what every entity learned per hour (the server's time zone changed) and has the
// kind rewritten; nothing for a kind that doesn't learn per hour.
func (t *table[T]) resetHours() {
	if t.reset == nil {
		return
	}
	t.each(func(x *tent[T]) { t.reset(&x.v) })
	t.setResync()
}

// unsave puts back what a failed save took: the entities still here are changed again, the
// dropped ones to delete again.
func (t *table[T]) unsave(rows []blRow, gone []string) {
	for _, r := range rows {
		if x := t.peek(r.key); x != nil {
			t.touch(x)
		}
	}
	for _, k := range gone {
		if t.peek(k) == nil {
			t.noteGone(k)
		}
	}
}

// pending reports whether anything is waiting to be saved.
func (t *table[T]) pending() bool { return len(t.dirty) > 0 || len(t.gone) > 0 || t.resync }

// blStore is what the save code needs of a table (the kinds hold different entity types).
type blStore interface {
	kindName() string
	timed() bool
	takeDirty(n int) []blRow
	takeGone(n int) []string
	unsave(rows []blRow, gone []string)
	pending() bool
	needsResync() bool
	startRewrite() []string
	encodeKeys(keys []string) []blRow
	setResync()
	resetHours()
}

func (t *table[T]) kindName() string  { return t.kind }
func (t *table[T]) timed() bool       { return t.reset != nil }
func (t *table[T]) needsResync() bool { return t.resync }
