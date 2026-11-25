package detect

import (
	"container/list"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

// Bounds of the evaluation state. Keys and values come from events, so from attackers: every
// structure is capped and the least recently used keys are evicted.
const (
	maxKeys    = 10000   // keys per rule
	maxEntries = 1 << 18 // window entries per rule, all keys together
	// Intentional: at most three quarters of a rule's keys and entries go to keys with a history
	// (an anomaly key with counts in two or more hours). Such keys are evicted only after every key
	// without one, so a flood of one-off keys can't evict a learned baseline, and new keys still
	// get a place.
	maxProtKeys       = maxKeys / 4 * 3
	maxProtEntries    = maxEntries / 4 * 3
	minRing           = 64     // a key's window holds max(2×Count, minRing) entries
	maxDistinctValues = 1000   // values per key of a distinct rule
	maxSeen           = 100000 // a new_value rule's seen (key, value) pairs, and its known keys
	maxPairsPerKey    = 1000   // a new_value rule's seen values of one key
	anomalyHours      = 168    // hourly counts kept per key: 7 days
	anomalySlots      = 61     // the current window's slots (Window/60 each, plus the partial one)
	preEvidence       = 4      // events kept per key for the evidence of its next firing
	maxWeight         = 1000   // F.repeated counts at most this much
)

// entry is one second of matching events of a key (weights summed).
type entry struct {
	t int64 // unix ns of the first event in that second
	w uint32
}

// ring is a key's matching events inside the window, oldest first, with their weights summed.
type ring struct {
	e    []entry
	head int
	sum  uint64
}

func (r *ring) len() int { return len(r.e) - r.head }

// expire drops the entries at or before cut.
func (r *ring) expire(cut int64) {
	for r.head < len(r.e) && r.e[r.head].t <= cut {
		r.sum -= uint64(r.e[r.head].w)
		r.head++
	}
	r.compact()
}

func (r *ring) compact() {
	if r.head == len(r.e) {
		r.e, r.head = r.e[:0], 0
		return
	}
	if r.head > 32 && r.head > len(r.e)/2 {
		n := copy(r.e, r.e[r.head:])
		r.e, r.head = r.e[:n], 0
	}
}

// add counts an event of weight w at t in a window of the given length, keeping at most capN
// entries. An entry within the same second as the newest one is merged into it.
func (r *ring) add(t int64, w uint32, window time.Duration, capN int) {
	ref := t
	if n := len(r.e); n > r.head && r.e[n-1].t > ref {
		ref = r.e[n-1].t
	}
	cut := ref - int64(window)
	r.expire(cut)
	if t <= cut {
		return // arrived after its window closed
	}
	if n := len(r.e); n > r.head && r.e[n-1].t/int64(time.Second) == t/int64(time.Second) {
		r.e[n-1].w = satAdd(r.e[n-1].w, w)
		r.sum += uint64(w)
		return
	}
	// Intentional: the oldest entry is dropped when the ring is full. capN ≥ Count and every
	// entry weighs at least 1, so a full ring already holds Count events and the rule fires.
	for r.len() >= capN && r.len() > 0 {
		r.sum -= uint64(r.e[r.head].w)
		r.head++
	}
	r.compact()
	r.e = append(r.e, entry{t: t, w: w})
	r.sum += uint64(w)
}

func (r *ring) reset() { r.e, r.head, r.sum = r.e[:0], 0, 0 }

func satAdd(a, b uint32) uint32 {
	if a > math.MaxUint32-b {
		return math.MaxUint32
	}
	return a + b
}

func ringCap(count int) int { return max(2*count, minRing) }

// distinct is a key's set of values seen inside the window (values as 64-bit hashes).
type distinct struct {
	m    map[uint64]int64 // value → newest time seen
	fifo []dEntry         // every time a value was seen, oldest first
	head int
}

type dEntry struct {
	t int64
	h uint64
}

func (d *distinct) cost() int { return len(d.m) + len(d.fifo) - d.head }

func (d *distinct) expire(cut int64) {
	for d.head < len(d.fifo) && d.fifo[d.head].t <= cut {
		x := d.fifo[d.head]
		d.head++
		if d.m[x.h] == x.t {
			delete(d.m, x.h)
		}
	}
	if d.head == len(d.fifo) {
		d.fifo, d.head = d.fifo[:0], 0
	} else if d.head > 32 && d.head > len(d.fifo)/2 {
		n := copy(d.fifo, d.fifo[d.head:])
		d.fifo, d.head = d.fifo[:n], 0
	}
}

func (d *distinct) add(h uint64, t int64, window time.Duration) {
	if d.m == nil {
		d.m = map[uint64]int64{}
	}
	ref := t
	if n := len(d.fifo); n > d.head && d.fifo[n-1].t > ref {
		ref = d.fifo[n-1].t
	}
	cut := ref - int64(window)
	d.expire(cut)
	if t <= cut {
		return
	}
	old, seen := d.m[h]
	switch {
	case seen && old >= t:
		return
	case !seen && len(d.m) >= maxDistinctValues:
		// Intentional: at the cap new values are not kept; the set already holds more values than
		// any distinct rule may ask for, so the rule fires.
		return
	}
	d.m[h] = t
	d.fifo = append(d.fifo, dEntry{t: t, h: h})
	// A value seen over and over adds an entry each time: rebuild from the set when the list
	// outgrows it, so it stays O(values).
	if live := len(d.fifo) - d.head; live > 2*len(d.m)+64 {
		d.fifo = d.fifo[:0]
		for h, t := range d.m {
			d.fifo = append(d.fifo, dEntry{t: t, h: h})
		}
		slices.SortFunc(d.fifo, func(a, b dEntry) int { return cmpInt(a.t, b.t) })
		d.head = 0
	}
}

func (d *distinct) reset() { clear(d.m); d.fifo, d.head = d.fifo[:0], 0 }

func cmpInt(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// anomaly is a key's hourly counts (7 days) and its count in the current window.
type anomaly struct {
	first int64 // unix ns of the key's first event
	last  int64 // the newest hour (unix hours) with a count
	hours [anomalyHours]uint32
	slotW int64 // width of a slot (ns)
	slots [anomalySlots]slot
}

type slot struct {
	idx int64
	n   uint32
}

const anomalyCost = anomalyHours + anomalySlots

func slotWidth(window time.Duration) int64 {
	return max(int64(window)/(anomalySlots-1), int64(time.Second))
}

func (a *anomaly) add(t int64, w uint32, window time.Duration) {
	if a.first == 0 || t < a.first {
		a.first = t
	}
	h := t / int64(time.Hour)
	switch {
	case h > a.last:
		if h-a.last >= anomalyHours {
			clear(a.hours[:])
		} else {
			for i := a.last + 1; i <= h; i++ {
				a.hours[i%anomalyHours] = 0
			}
		}
		a.last = h
		a.hours[h%anomalyHours] = satAdd(a.hours[h%anomalyHours], w)
	case h > a.last-anomalyHours:
		a.hours[h%anomalyHours] = satAdd(a.hours[h%anomalyHours], w)
	}
	if sw := slotWidth(window); sw != a.slotW {
		a.slots, a.slotW = [anomalySlots]slot{}, sw
	}
	idx := t / a.slotW
	s := &a.slots[idx%anomalySlots]
	switch {
	case s.idx == idx:
	case s.idx > idx:
		return // older than the slot ring
	default:
		s.idx, s.n = idx, 0
	}
	s.n = satAdd(s.n, w)
}

// windowCount is the count in (t−window, t], to slot precision.
func (a *anomaly) windowCount(t int64, window time.Duration) uint64 {
	if a.slotW == 0 {
		return 0
	}
	cut := t - int64(window)
	var n uint64
	for _, s := range a.slots {
		if s.n > 0 && (s.idx+1)*a.slotW > cut && s.idx*a.slotW <= t {
			n += uint64(s.n)
		}
	}
	return n
}

// expected is the usual count per window: the mean hourly count over the key's history before
// the current window (at most 7 days), scaled to the window; 0 for a key without such history.
func (a *anomaly) expected(t int64, window time.Duration) float64 {
	end := (t-int64(window))/int64(time.Hour) - 1 // the last whole hour before the window
	start := max(a.first/int64(time.Hour), a.last-anomalyHours+1)
	end = min(end, a.last)
	if end < start {
		return 0
	}
	var sum uint64
	for i := start; i <= end; i++ {
		sum += uint64(a.hours[i%anomalyHours])
	}
	return float64(sum) / float64(end-start+1) * window.Hours()
}

// settled reports whether a key has a history worth keeping: counts in at least two hours.
func (a *anomaly) settled() bool {
	n := 0
	for _, c := range a.hours {
		if c > 0 {
			if n++; n >= 2 {
				return true
			}
		}
	}
	return false
}

// point is a key's last located event (travel).
type point struct {
	t        int64
	lat, lon float64
	place    string // "Lagos, NG"
}

// evidence keeps a key's most recent events for its next firing, and when it last counted an event
// a browser sent (sentBy), so a firing knows that of every event behind it, not only of the few kept.
type evidence struct {
	e    [preEvidence]siem.Evidence
	n    int
	next int
	// Unix ns of the end of the second of the newest counted event with browser fetch metadata, and
	// of the newest one with a browser's agent (0: none since the last reset).
	browserT, agentT int64
}

func (v *evidence) add(e *siem.Event) {
	x := evidenceOf(e)
	v.e[v.next] = x
	v.next = (v.next + 1) % preEvidence
	v.n = min(v.n+1, preEvidence)
	// Intentional: the last nanosecond of the event's second, not its own time. A key's window keeps
	// one entry per second under the time of the first event counted in it (ring.add), so an event
	// merged into that entry is counted until the entry leaves the window, which may be later than
	// the event's own time. The end of the second is never before the entry's time.
	const sec = int64(time.Second)
	t := e.TS.UnixNano()
	t += sec - 1 - (t%sec+sec)%sec
	switch {
	case x.Browser:
		v.browserT = max(v.browserT, t)
	case x.BrowserAgent:
		v.agentT = max(v.agentT, t)
	}
}

// sent reports whether an event counted after cut (unix ns, the start of the firing's window) was
// sent by a browser, or came with a browser's agent.
// Intentional: an event the key's window dropped early (a full ring) still counts here until it is
// older than the window: erring toward no automatic block.
func (v *evidence) sent(cut int64) (browser, agent bool) {
	return v.browserT > cut, v.agentT > cut
}

func (v *evidence) list() []siem.Evidence {
	out := make([]siem.Evidence, 0, v.n)
	for i := 0; i < v.n; i++ {
		out = append(out, v.e[(v.next-v.n+i+preEvidence)%preEvidence])
	}
	return out
}

func (v *evidence) reset() { *v = evidence{} }

// evidenceOf copies what finds an event again; strings are cloned so a kept key never holds the
// event's whole line in memory.
func evidenceOf(e *siem.Event) siem.Evidence {
	browser, agent := sentBy(e)
	return siem.Evidence{TS: e.TS, Kind: strings.Clone(e.Kind), IP: strings.Clone(e.IP),
		Actor: strings.Clone(e.Actor), App: strings.Clone(e.App), Browser: browser, BrowserAgent: agent}
}

// sentBy reports what sent an edge event's request (no other source's events say): browser when it
// carried browser fetch metadata (Sec-Fetch-Site, parsed into f.fetch_site); else agent when its
// User-Agent (f.ua) is a browser's ("Mozilla/…") or a mail client's (Office, Thunderbird), which
// fetch what a page or an email tells them to.
// Intentional: a User-Agent is whatever the client says, so agent only ever lowers a block to a
// recommendation (responseFor): a scanner claiming to be a browser is shown, not hidden.
func sentBy(e *siem.Event) (browser, agent bool) {
	if e.Src != siem.SrcEdge {
		return false, false
	}
	if v, _ := e.F["fetch_site"].(string); v != "" {
		return true, false
	}
	ua, _ := e.F["ua"].(string)
	if len(ua) >= len("Mozilla/") && strings.EqualFold(ua[:len("Mozilla/")], "Mozilla/") {
		return false, true
	}
	return false, containsFold(ua, "ms-office") || containsFold(ua, "microsoft office") || containsFold(ua, "thunderbird")
}

// containsFold reports whether s contains sub (lower-case ASCII) in any ASCII case, without
// allocating.
func containsFold(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if strings.EqualFold(s[i:i+len(sub)], sub) {
			return true
		}
	}
	return false
}

// keyState is one key's state in a rule; which part is used depends on the rule type.
type keyState struct {
	key  string
	ring ring
	set  *distinct
	an   *anomaly
	last *point
	ev   evidence
	cost int  // entries charged to the rule's budget
	prot bool // in the rule's protected keys (plru)
}

func (k *keyState) measure() int {
	n := 1 + k.ring.len()
	if k.set != nil {
		n += k.set.cost()
	}
	if k.an != nil {
		n += anomalyCost
	}
	return n
}

// ruleState is one rule's state: its keys (most recently used first) and, for new_value, the
// seen sets.
type ruleState struct {
	sig      string
	keys     map[string]*list.Element
	lru      list.List // keys without a history
	plru     list.List // keys with a history (anomaly): evicted only when lru is empty
	entries  int
	pEntries int // entries of the keys in plru
	nv       *seen
	anStart  int64 // anomaly: unix ns of the rule's first matching event (its learning starts there)
	anDirty  bool  // anomaly counts changed since the last save
}

func newRuleState(sig string) *ruleState {
	return &ruleState{sig: sig, keys: map[string]*list.Element{}}
}

func (s *ruleState) listOf(k *keyState) *list.List {
	if k.prot {
		return &s.plru
	}
	return &s.lru
}

// key returns key's state, creating it (and evicting the least recently used keys) as needed.
func (s *ruleState) key(key string) *keyState {
	if el, ok := s.keys[key]; ok {
		k := el.Value.(*keyState)
		s.listOf(k).MoveToFront(el)
		return k
	}
	k := &keyState{key: strings.Clone(key)}
	k.cost = k.measure()
	s.keys[k.key] = s.lru.PushFront(k)
	s.entries += k.cost
	s.evict(k)
	return k
}

// peek returns key's state without creating it or changing the order.
func (s *ruleState) peek(key string) *keyState {
	if el, ok := s.keys[key]; ok {
		return el.Value.(*keyState)
	}
	return nil
}

// charge updates the budget after k changed, then evicts keys over the bounds.
func (s *ruleState) charge(k *keyState) {
	c := k.measure()
	s.entries += c - k.cost
	if k.prot {
		s.pEntries += c - k.cost
	}
	k.cost = c
	s.evict(k)
}

// evict drops keys while the rule is over its bounds: the least recently used key without a
// history first, one with a history only when none is left. keep is never dropped.
func (s *ruleState) evict(keep *keyState) {
	for len(s.keys) > maxKeys || s.entries > maxEntries {
		el := backExcept(&s.lru, keep)
		if el == nil {
			el = backExcept(&s.plru, keep)
		}
		if el == nil {
			return
		}
		k := el.Value.(*keyState)
		s.listOf(k).Remove(el)
		delete(s.keys, k.key)
		s.entries -= k.cost
		if k.prot {
			s.pEntries -= k.cost
		}
		if k.an != nil {
			s.anDirty = true
		}
	}
}

func backExcept(l *list.List, keep *keyState) *list.Element {
	el := l.Back()
	if el != nil && el.Value.(*keyState) == keep {
		el = el.Prev()
	}
	return el
}

// promote moves a key with a history to the protected keys; past their bounds, the least recently
// used protected key goes back to the others.
func (s *ruleState) promote(k *keyState) {
	el, ok := s.keys[k.key]
	if !ok || k.prot {
		return
	}
	s.lru.Remove(el)
	k.prot = true
	s.keys[k.key] = s.plru.PushFront(k)
	s.pEntries += k.cost
	for (s.plru.Len() > maxProtKeys || s.pEntries > maxProtEntries) && s.plru.Len() > 1 {
		b := s.plru.Back()
		x := b.Value.(*keyState)
		s.plru.Remove(b)
		x.prot = false
		s.pEntries -= x.cost
		s.keys[x.key] = s.lru.PushFront(x)
	}
}

// seen is a new_value rule's learned values: the keys it knows and the (key, value) pairs seen,
// as 64-bit hashes with the time last seen (unix seconds); a pair also holds its key's hash.
type seen struct {
	start int64 // unix ns of the rule's first matching event
	keys  map[uint64]seenKey
	pairs map[uint64]seenPair
	dirty bool
}

type seenKey struct {
	t int64
	n int // the key's pairs
}

type seenPair struct {
	k uint64 // the key's hash
	t int64
}

func newSeen() *seen { return &seen{keys: map[uint64]seenKey{}, pairs: map[uint64]seenPair{}} }

func hash64(parts ...string) uint64 {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	var b [32]byte
	return binary.LittleEndian.Uint64(h.Sum(b[:0]))
}

// observe records value for key at t and reports whether it is new for a key already known
// (a key seen for the first time is learned without firing) once the rule has learned for learn.
func (s *seen) observe(key, value string, t int64, learn time.Duration) bool {
	if s.start == 0 || t < s.start {
		s.start = t
	}
	sec := t / int64(time.Second)
	kh, ph := hash64("k", key), hash64("p", key, value)
	k, knownKey := s.keys[kh]
	p, knownPair := s.pairs[ph]
	k.t = max(sec, k.t)
	if !knownKey || !knownPair {
		k.n++
	}
	s.keys[kh] = k
	s.pairs[ph] = seenPair{k: kh, t: max(sec, p.t)}
	s.dirty = true
	if k.n > maxPairsPerKey {
		s.trimKey(kh, ph)
	}
	if len(s.pairs) > maxSeen || len(s.keys) > maxSeen {
		s.trim()
	}
	return knownKey && !knownPair && t-s.start >= int64(learn)
}

// trimKey forgets the least recently seen values of one key (never keep, the one just seen) until
// it holds nine tenths of maxPairsPerKey.
// Intentional: the only case where values of a key still in use are forgotten (such a value fires
// as new when it comes back). A key with that many values (an attacker cycling them) would
// otherwise fill the rule's memory, and trim would then forget every other key.
func (s *seen) trimKey(kh, keep uint64) {
	type ht struct {
		h uint64
		t int64
	}
	var own []ht
	for h, p := range s.pairs {
		if p.k == kh && h != keep {
			own = append(own, ht{h, p.t})
		}
	}
	slices.SortFunc(own, func(a, b ht) int { return cmpInt(a.t, b.t) })
	drop := max(0, len(own)+1-(maxPairsPerKey-maxPairsPerKey/10))
	for _, x := range own[:drop] {
		delete(s.pairs, x.h)
	}
	k := s.keys[kh]
	k.n = len(own) + 1 - drop
	s.keys[kh] = k
}

// trim forgets the least recently seen keys, each with every pair of it, until a tenth of maxSeen
// is free.
// Intentional: a pair is forgotten only with its key (trimKey aside). Forgetting old pairs of a
// key still in use would make a value already seen for it (a user's usual country) fire as new; a
// forgotten key is learned again without firing.
func (s *seen) trim() {
	type kt struct {
		h uint64
		t int64
	}
	perKey := make(map[uint64]int, len(s.keys))
	orphans := 0
	for _, p := range s.pairs {
		if _, ok := s.keys[p.k]; ok {
			perKey[p.k]++
		} else {
			orphans++
		}
	}
	order := make([]kt, 0, len(s.keys))
	for h, k := range s.keys {
		order = append(order, kt{h, k.t})
	}
	slices.SortFunc(order, func(a, b kt) int { return cmpInt(a.t, b.t) })
	target := maxSeen - maxSeen/10
	pairs, keys := len(s.pairs)-orphans, len(s.keys)
	drop := map[uint64]struct{}{}
	for _, x := range order {
		if pairs <= target && keys <= target {
			break
		}
		drop[x.h] = struct{}{}
		pairs -= perKey[x.h]
		keys--
	}
	for h, p := range s.pairs {
		_, gone := drop[p.k]
		if _, known := s.keys[p.k]; gone || !known {
			delete(s.pairs, h)
		}
	}
	for h := range drop {
		delete(s.keys, h)
	}
}

// Persisted forms. Each starts with a version byte; a blob that doesn't decode is discarded.

const (
	seenVersion    = 2 // 2: a pair holds its key's hash
	anomalyVersion = 2 // 2: the rule's start
)

func (s *seen) encode() []byte {
	b := make([]byte, 0, 16+12*len(s.keys)+20*len(s.pairs))
	b = append(b, seenVersion)
	b = binary.AppendVarint(b, s.start)
	b = binary.AppendUvarint(b, uint64(len(s.keys)))
	for h, k := range s.keys {
		b = binary.LittleEndian.AppendUint64(b, h)
		b = binary.AppendVarint(b, k.t)
	}
	b = binary.AppendUvarint(b, uint64(len(s.pairs)))
	for h, p := range s.pairs {
		b = binary.LittleEndian.AppendUint64(b, h)
		b = binary.LittleEndian.AppendUint64(b, p.k)
		b = binary.AppendVarint(b, p.t)
	}
	return b
}

var errState = errors.New("detect: bad state")

type reader struct {
	b   []byte
	err error
}

func (r *reader) uvarint() uint64 {
	v, n := binary.Uvarint(r.b)
	if n <= 0 {
		r.err = errState
		return 0
	}
	r.b = r.b[n:]
	return v
}

func (r *reader) varint() int64 {
	v, n := binary.Varint(r.b)
	if n <= 0 {
		r.err = errState
		return 0
	}
	r.b = r.b[n:]
	return v
}

func (r *reader) u64() uint64 {
	if len(r.b) < 8 {
		r.err = errState
		return 0
	}
	v := binary.LittleEndian.Uint64(r.b)
	r.b = r.b[8:]
	return v
}

func (r *reader) bytes(n uint64) []byte {
	if uint64(len(r.b)) < n {
		r.err = errState
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func decodeSeen(b []byte) (*seen, error) {
	if len(b) == 0 || b[0] != seenVersion {
		return nil, errState
	}
	r := &reader{b: b[1:]}
	s := newSeen()
	s.start = r.varint()
	n := r.uvarint()
	if n > maxSeen {
		return nil, errState
	}
	for i := uint64(0); i < n && r.err == nil; i++ {
		h := r.u64()
		s.keys[h] = seenKey{t: r.varint()}
	}
	n = r.uvarint()
	if n > maxSeen {
		return nil, errState
	}
	for i := uint64(0); i < n && r.err == nil; i++ {
		h, k := r.u64(), r.u64()
		s.pairs[h] = seenPair{k: k, t: r.varint()}
	}
	if r.err != nil || len(r.b) != 0 {
		return nil, errState
	}
	// The per-key counts aren't stored: counted again (a pair of an unknown key counts for none).
	for _, p := range s.pairs {
		if k, ok := s.keys[p.k]; ok {
			k.n++
			s.keys[p.k] = k
		}
	}
	return s, nil
}

// encodeAnomaly writes the rule's start, then every key's first time, last hour and hourly counts.
func encodeAnomaly(st *ruleState) []byte {
	b := []byte{anomalyVersion}
	b = binary.AppendVarint(b, st.anStart)
	n := 0
	for _, l := range []*list.List{&st.lru, &st.plru} {
		for el := l.Front(); el != nil; el = el.Next() {
			if el.Value.(*keyState).an != nil {
				n++
			}
		}
	}
	b = binary.AppendUvarint(b, uint64(n))
	// Least recently used first, the unprotected keys before the protected ones, so a restore
	// rebuilds the same order.
	for _, l := range []*list.List{&st.lru, &st.plru} {
		for el := l.Back(); el != nil; el = el.Prev() {
			k := el.Value.(*keyState)
			if k.an == nil {
				continue
			}
			b = binary.AppendUvarint(b, uint64(len(k.key)))
			b = append(b, k.key...)
			b = binary.AppendVarint(b, k.an.first)
			b = binary.AppendVarint(b, k.an.last)
			for _, c := range k.an.hours {
				b = binary.AppendUvarint(b, uint64(c))
			}
		}
	}
	return b
}

func decodeAnomaly(b []byte, st *ruleState) error {
	if len(b) == 0 || b[0] != anomalyVersion {
		return errState
	}
	r := &reader{b: b[1:]}
	start := r.varint()
	n := r.uvarint()
	if n > maxKeys {
		return errState
	}
	type rec struct {
		key string
		an  *anomaly
	}
	recs := make([]rec, 0, n)
	for i := uint64(0); i < n && r.err == nil; i++ {
		l := r.uvarint()
		if l > siem.MaxShort {
			return errState
		}
		key := string(r.bytes(l))
		a := &anomaly{first: r.varint(), last: r.varint()}
		for j := range a.hours {
			c := r.uvarint()
			if c > math.MaxUint32 {
				return errState
			}
			a.hours[j] = uint32(c)
		}
		recs = append(recs, rec{key, a})
	}
	if r.err != nil || len(r.b) != 0 {
		return errState
	}
	st.anStart = start
	for _, x := range recs {
		k := st.key(x.key)
		k.an = x.an
		st.charge(k)
		if k.an.settled() {
			st.promote(k)
		}
	}
	return nil
}
