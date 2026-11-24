package store

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"container/heap"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/query"
)

// segRef is a search's view of one segment, taken under the lock; the file is read without it.
type segRef struct {
	path        string
	ord         int   // position in (hour, seq) order: capture order across segments
	first, last int64 // TS range
	size        int64 // bytes the search may read
}

// snapshot lists the segments that may hold events of q's time range, in capture order.
func (s *Store) snapshot(q query.Query) []segRef {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []segRef
	for i, g := range s.segs {
		size := g.readable()
		if size <= 0 || g.events == 0 {
			continue
		}
		if (!q.From.IsZero() && g.last < tsNS(q.From)) || (!q.To.IsZero() && g.first > tsNS(q.To)) {
			continue
		}
		out = append(out, segRef{path: filepath.Join(s.segDir, g.name), ord: i, first: g.first, last: g.last, size: size})
	}
	return out
}

// errBudget stops a read whose context ended or whose byte budget is used up.
var errBudget = errors.New("store: scan budget used up")

// budgetReader fails with errBudget once ctx has ended or the budget is spent (checked before
// each read).
type budgetReader struct {
	r    io.Reader
	ctx  context.Context
	left *int64
}

func (b *budgetReader) Read(p []byte) (int, error) {
	if b.ctx.Err() != nil || *b.left <= 0 {
		return 0, errBudget
	}
	n, err := b.r.Read(p)
	*b.left -= int64(n)
	return n, err
}

// errGone: a segment of the snapshot was removed before it could be read.
var errGone = errors.New("store: segment removed")

// readSegment calls fn with each line in the first size bytes of a segment file (n counts from
// 1) until fn returns false. It returns errBudget when the budget or ctx stopped it and errGone
// when the file was removed since the snapshot; an unreadable or damaged file yields what decoded
// and no error. The line is only valid during the call.
func readSegment(ctx context.Context, path string, size int64, budget *int64, buf []byte, fn func(n int, line []byte) bool) error {
	f, err := os.OpenFile(path, os.O_RDONLY|oNoFollow, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return errGone
	}
	if err != nil {
		return nil
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil
	}
	if ctx.Err() != nil || *budget <= 0 {
		return errBudget
	}
	zr, err := gzip.NewReader(io.LimitReader(f, size))
	if err != nil {
		return nil
	}
	zr.Multistream(false)
	sc := bufio.NewScanner(&budgetReader{r: zr, ctx: ctx, left: budget})
	sc.Buffer(buf, maxLine)
	n := 0
	for sc.Scan() {
		n++
		if !fn(n, sc.Bytes()) {
			return nil
		}
	}
	if errors.Is(sc.Err(), errBudget) {
		return errBudget
	}
	// io.ErrUnexpectedEOF is the unfinished gzip stream of the open segment's flushed part (or of a
	// segment a crash left): the end of the data. Any other error is a damaged file, whose readable
	// part was all it held.
	return nil
}

// hit is one matching event a search holds: its TS, its capture order (the index row id, or the
// segment and line) and its stored line.
type hit struct {
	ts, ord int64
	line    []byte
}

func (a hit) less(b hit) bool {
	if a.ts != b.ts {
		return a.ts < b.ts
	}
	return a.ord < b.ord
}

type hitHeap []hit

func (h hitHeap) Len() int           { return len(h) }
func (h hitHeap) Less(i, j int) bool { return h[i].less(h[j]) }
func (h hitHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *hitHeap) Push(x any)        { *h = append(*h, x.(hit)) }
func (h *hitHeap) Pop() any {
	old := *h
	x := old[len(old)-1]
	*h = old[:len(old)-1]
	return x
}

// collector keeps the newest limit+1 matches (the extra one shows whether the page ends inside a
// group of equal TS) within a byte budget, oldest on top of the heap.
type collector struct {
	k, maxBytes, bytes int
	h                  hitHeap
	evicted            bool  // a match was left out
	maxEvTS            int64 // the newest TS left out
}

func newCollector(limit, maxBytes int) *collector {
	return &collector{k: limit + 1, maxBytes: maxBytes}
}

func (c *collector) full() bool { return len(c.h) >= c.k }

func (c *collector) minTS() int64 { return c.h[0].ts }

func (c *collector) note(ts int64) {
	if !c.evicted || ts > c.maxEvTS {
		c.maxEvTS = ts
	}
	c.evicted = true
}

func (c *collector) evict() {
	y := heap.Pop(&c.h).(hit)
	c.bytes -= len(y.line)
	c.note(y.ts)
}

// offer adds a match, copying line only when it is kept.
func (c *collector) offer(ts, ord int64, line []byte) {
	x := hit{ts: ts, ord: ord}
	if c.full() && !c.h[0].less(x) {
		c.note(ts)
		return
	}
	x.line = bytes.Clone(line)
	heap.Push(&c.h, x)
	c.bytes += len(x.line)
	if len(c.h) > c.k {
		c.evict()
	}
	for c.bytes > c.maxBytes && len(c.h) > 1 {
		c.evict()
		c.k = len(c.h)
	}
}

// result turns the kept matches into a page of at most limit events, newest first. With hasCap,
// only the matches newer than capAt are known to be complete: the others are dropped and the page
// ends just above capAt, so the next page (To = Before) repeats rather than skips what wasn't fully
// examined.
func (c *collector) result(limit int, r Result, capAt int64, hasCap bool) Result {
	if hasCap {
		kept := c.h[:0]
		for _, x := range c.h {
			if x.ts > capAt {
				kept = append(kept, x)
			} else {
				c.bytes -= len(x.line)
			}
		}
		c.h = kept
		heap.Init(&c.h)
	}
	for len(c.h) > limit {
		c.evict()
	}
	list := make([]hit, len(c.h))
	for i := len(list) - 1; i >= 0; i-- {
		list[i] = heap.Pop(&c.h).(hit)
	}
	evicted := c.evicted && (!hasCap || c.maxEvTS > capAt) // a complete match was left out
	if n := len(list); evicted && n > 0 && c.maxEvTS == list[n-1].ts {
		// Intentional: the page would end inside a group of events sharing one TS, and the next page
		// (To = Before, exclusive) would skip the rest of the group, so the group moves to the next
		// page whole. A page that is one group throughout is returned as it is.
		j := n
		for j > 0 && list[j-1].ts == c.maxEvTS {
			j--
		}
		if j > 0 {
			list = list[:j]
		}
	}
	r.More = r.More || evicted || hasCap
	r.Events = make([]siem.Event, 0, len(list))
	for _, x := range list {
		var e siem.Event
		if json.Unmarshal(x.line, &e) == nil {
			r.Events = append(r.Events, e)
		}
	}
	switch n := len(r.Events); {
	case hasCap && !evicted:
		r.Before = nsTime(capAt).Add(time.Nanosecond)
	case n > 0:
		r.Before = r.Events[n-1].TS
	}
	return r
}

// searchScan answers q by reading the segments, the one that can hold the newest TS of the page
// first, until no unread segment can hold a newer match than the ones kept, or the budget runs out.
func (s *Store) searchScan(ctx context.Context, q query.Query, limit int) (Result, error) {
	refs := s.snapshot(q)
	sort.Slice(refs, func(i, j int) bool {
		if refs[i].last != refs[j].last {
			return refs[i].last > refs[j].last
		}
		return refs[i].ord > refs[j].ord
	})
	toNS := int64(math.MaxInt64)
	if !q.To.IsZero() {
		toNS = tsNS(q.To)
	}
	// eff is the newest TS a segment can hold in the page. One whose events also run past To
	// (a "wide" segment: it holds events stored with a much older TS than their capture time)
	// can hold any TS below To.
	eff := func(r segRef) int64 { return min(r.last, toNS-1) }
	// Intentional: the newest segment that lies below To is read first and whole whatever the
	// byte budget (a segment is at most half of it), so a capped page always gets past it and the
	// next page makes progress. The time budget and ctx still stop it.
	newest, hasNewest := int64(0), false
	for _, r := range refs {
		if r.last < toNS {
			newest, hasNewest = r.last, true
			break
		}
	}
	if hasNewest {
		slices.SortStableFunc(refs, func(a, b segRef) int {
			switch an, bn := a.last == newest, b.last == newest; {
			case an && !bn:
				return -1
			case bn && !an:
				return 1
			}
			return 0
		})
	}
	pf := newPrefilter(q)
	c := newCollector(limit, s.maxResultBytes)
	budget := s.searchBytes
	buf := make([]byte, 64<<10)
	var r Result
	capIdx := -1
	for i, ref := range refs {
		if c.full() && eff(ref) < c.minTS() {
			break
		}
		b, whole := &budget, int64(math.MaxInt64)
		if hasNewest && ref.last == newest {
			b = &whole
		}
		err := readSegment(ctx, ref.path, ref.size, b, buf, func(n int, line []byte) bool {
			r.Scanned++
			if !pf.pass(line) {
				return true
			}
			var e siem.Event
			if json.Unmarshal(line, &e) != nil || !q.Match(&e) {
				return true
			}
			c.offer(tsNS(e.TS), int64(ref.ord)<<32|int64(n), line)
			return true
		})
		if b == &whole {
			budget -= math.MaxInt64 - whole
		}
		if errors.Is(err, errGone) {
			continue // removed since the snapshot: its events are gone for every page
		}
		if err != nil {
			r.Capped, capIdx = true, i
			break
		}
	}
	if !r.Capped {
		return c.result(limit, r, 0, false), nil
	}
	// The matches newer than every unread segment's newest TS are complete.
	//
	// Intentional: an unread wide segment bounds nothing below To, so it is left out of the bound,
	// which comes from the other unread segments; paging still progresses. Its older events may
	// then be missing from the page (it is marked Capped). It only happens when the wide segments
	// alone don't fit the budget.
	capAt, hasCap := int64(math.MinInt64), false
	for _, u := range refs[capIdx:] {
		if u.last < toNS && u.last > capAt {
			capAt, hasCap = u.last, true
		}
	}
	return pageGuard(c.result(limit, r, capAt, hasCap), q), nil
}

// pageGuard keeps a page from asking for a next page it can't move to: More with Before not below
// To becomes More=false (the page stays Capped: the range is too large for one search's budget).
func pageGuard(r Result, q query.Query) Result {
	if r.More && !q.To.IsZero() && !r.Before.Before(q.To) {
		r.More = false
	}
	return r
}

// export streams the matches of q in capture order.
func (s *Store) export(ctx context.Context, q query.Query, w io.Writer, maxEvents int) (int, error) {
	refs := s.snapshot(q)
	pf := newPrefilter(q)
	bw := bufio.NewWriterSize(w, 64<<10)
	budget := s.exportBytes
	buf := make([]byte, 64<<10)
	n := 0
	var werr error
	for _, ref := range refs {
		err := readSegment(ctx, ref.path, ref.size, &budget, buf, func(_ int, line []byte) bool {
			if !pf.pass(line) {
				return true
			}
			var e siem.Event
			if json.Unmarshal(line, &e) != nil || !q.Match(&e) {
				return true
			}
			b, err := json.Marshal(&e)
			if err == nil {
				b = append(b, '\n')
				_, err = bw.Write(b)
			}
			if err != nil {
				werr = err
				return false
			}
			n++
			return n < maxEvents
		})
		if werr != nil {
			return n, werr
		}
		if err != nil {
			if ferr := bw.Flush(); ferr != nil {
				return n, ferr
			}
			if errors.Is(err, errGone) {
				return n, ErrSegmentRemoved
			}
			return n, ErrBudget
		}
		if n >= maxEvents {
			break
		}
	}
	return n, bw.Flush()
}
