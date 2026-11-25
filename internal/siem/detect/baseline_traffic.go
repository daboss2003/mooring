package detect

import (
	"encoding/binary"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

// The traffic baseline (traffic) counts each edge host name's requests and server errors (5xx) per
// hour and keeps, for each hour of the week, the counts of the last trafficWeeks weeks. When an
// hour has ended (trafficGrace after, so late access log lines still count), each host's counts
// are compared with the middle of the earlier weeks' counts for that hour of the week: far more is
// a surge (baseline.traffic_surge), far fewer a drop (baseline.traffic_drop). Only host names an
// edge route serves are counted (Options.KnownHost), under the name it gives (every label of a
// catch-all route as one "*.<apex>"): the Host header is the client's to choose. Only hours the
// engine watched whole are counted: not the hour it started in, nor hours it was stopped or
// stalled, the edge's routes weren't read yet or the rules were off. An hour in which events were
// dropped unevaluated is compared for a surge only (its counts are a lower bound) and not learned.

const (
	weekHours    = 7 * 24
	trafficWeeks = 4
	trafficGrace = 2 * time.Minute
	// Ticks farther apart than this (the process was stopped or stalled, or the clock jumped): the
	// hours between weren't watched whole.
	maxTickGap = 2 * time.Minute
	// A host name without a request in this many watched hours in a row is forgotten.
	trafficForget = trafficWeeks * weekHours

	ruleTrafficSurge = "baseline.traffic_surge"
	ruleTrafficDrop  = "baseline.traffic_drop"
)

type hostTraffic struct {
	from  int64  // the first hour (unix hours) counted whole
	quiet uint32 // watched hours closed without a request since the last one with a request
	slots [weekHours]tslot
	open  [3]tbucket // the hours not closed yet (not saved)
}

// tslot is one hour of the week's counts in the weeks newest−3 … newest: the week w's at w mod 4,
// mask bit w mod 4 set when it holds one.
type tslot struct {
	week int32
	mask uint8
	v    [trafficWeeks]tcount
}

type tcount struct{ req, err uint32 }

type tbucket struct {
	h        int64 // unix hours; 0: free
	req, err uint32
}

func wpos(w int32) int { return int(((w % trafficWeeks) + trafficWeeks) % trafficWeeks) }

func (s *tslot) record(week int32, c tcount) {
	switch {
	case s.mask == 0 || week >= s.week+trafficWeeks:
		s.mask, s.week = 0, week
	case week > s.week:
		for w := s.week + 1; w <= week; w++ {
			s.mask &^= 1 << wpos(w)
		}
		s.week = week
	case week <= s.week-trafficWeeks:
		return // older than the weeks kept
	}
	s.v[wpos(week)] = c
	s.mask |= 1 << wpos(week)
}

// prior returns the counts of the weeks before week (at most trafficWeeks back) that hold one.
func (s *tslot) prior(week int32) []tcount {
	var out []tcount
	for i := int32(0); i < trafficWeeks; i++ {
		w := s.week - i
		if s.mask&(1<<wpos(w)) != 0 && w < week && w >= week-trafficWeeks {
			out = append(out, s.v[wpos(w)])
		}
	}
	return out
}

func (x *hostTraffic) hasHistory() bool {
	for i := range x.slots {
		if x.slots[i].mask != 0 {
			return true
		}
	}
	return false
}

// count adds a request in hour h (closed: the newest hour already closed, 0 for none).
func (x *hostTraffic) count(h, closed int64, isErr bool) {
	free := -1
	for i := range x.open {
		b := &x.open[i]
		if b.h == h {
			b.req = satAdd(b.req, 1)
			if isErr {
				b.err = satAdd(b.err, 1)
			}
			return
		}
		if free < 0 && (b.h == 0 || b.h <= closed) {
			free = i
		}
	}
	if free < 0 {
		return // three later hours already open (a clock far ahead): not counted
	}
	x.open[free] = tbucket{h: h, req: 1}
	if isErr {
		x.open[free].err = 1
	}
}

// take returns hour h's counts and frees the buckets of h and before.
func (x *hostTraffic) take(h int64) tcount {
	var c tcount
	for i := range x.open {
		b := &x.open[i]
		if b.h == h {
			c = tcount{req: b.req, err: b.err}
		}
		if b.h != 0 && b.h <= h {
			*b = tbucket{}
		}
	}
	return c
}

// resetHours forgets the counts of every hour of the week (the server's time zone changed).
func (x *hostTraffic) resetHours() { x.slots = [weekHours]tslot{} }

// middle is the median of vs, but of an even count the lower of the two middle values, or with
// upper the higher one (never their mean): a drop compares with the lower, a surge with the
// higher, so one unusual week of two (a spike) doesn't make an ordinary hour a departure.
func middle(vs []float64, upper bool) float64 {
	if len(vs) == 0 {
		return 0
	}
	s := slices.Clone(vs)
	slices.Sort(s)
	n := len(s)
	if n%2 == 0 && !upper {
		return s[n/2-1]
	}
	return s[n/2]
}

// weeksFor is how many earlier weeks of an hour of the week a traffic rule needs: learn ÷ 7 days,
// rounded up, 1 to trafficWeeks.
func weeksFor(learn time.Duration) int {
	w := int((learn + 7*day - 1) / (7 * day))
	return min(max(w, 1), trafficWeeks)
}

// hourSpan is "10:00–11:00 Tue": the hour from start, its local start and end in loc ("09:30–10:30
// Tue" in a zone half an hour off UTC: the hours counted are UTC's).
func hourSpan(start time.Time, loc *time.Location) string {
	l := start.In(loc)
	return l.Format("15:04") + "–" + start.Add(time.Hour).In(loc).Format("15:04") + " " + l.Format("Mon")
}

// trafficEvent counts an edge request for host (the first enabled traffic rule does), under the
// name KnownHost gives it; nothing when the host isn't served or the routes weren't read yet.
func (b *baselines) trafficEvent(e *Engine, host string, ev *siem.Event) {
	if host == "" || e.opt.KnownHost == nil {
		return
	}
	h := floorDiv(ev.TS.Unix(), 3600)
	if b.closed != 0 && h <= b.closed {
		return // its hour is closed: too late
	}
	key, known, ready := e.opt.KnownHost(host)
	if !known || !ready || key == "" || len(key) > maxBaselineKey {
		return
	}
	x := b.traffic.get(key)
	if x == nil {
		x = b.traffic.add(key)
		x.v.from = h + 1 // the hour it was first seen in is counted from then on only
		b.traffic.touch(x)
	}
	st, _ := ev.F["status"].(float64)
	x.v.count(h, b.closed, st >= 500)
}

func floorDiv(a, b int64) int64 {
	q := a / b
	if a%b != 0 && (a < 0) != (b < 0) {
		q--
	}
	return q
}

// trafficTick closes the hours that ended trafficGrace ago or more (write tick).
func (b *baselines) trafficTick(e *Engine, now time.Time) {
	rules := b.rulesOf(e, siem.BaselineTraffic)
	ready := false
	if e.opt.KnownHost != nil {
		_, _, ready = e.opt.KnownHost("") // ready is the same for any host
	}
	// The hours not closed yet aren't watched whole when: this is the first tick, the last was too
	// long ago (stopped, stalled, a clock jump), the rules are off, or the routes weren't read yet
	// (requests weren't counted). They are watched but some of their events may be lost when
	// events were dropped unevaluated since the last tick (the engine's queue was full).
	if b.lastTick.IsZero() || now.Before(b.lastTick) || now.Sub(b.lastTick) > b.maxGap || len(rules) == 0 || !ready {
		b.since = now
	}
	if dropped := e.dropped.Load(); dropped != b.dropped {
		b.lossy, b.dropped = now, dropped
	}
	b.lastTick = now
	upTo := floorDiv(now.Add(-trafficGrace).Unix(), 3600) - 1
	if b.closed == 0 {
		b.closed = upTo
		return
	}
	if upTo <= b.closed {
		return
	}
	// Buckets hold at most three hours: earlier ones are long gone (and weren't watched).
	for h := max(b.closed+1, upTo-2); h <= upTo; h++ {
		b.closeHour(e, h, rules, ready)
	}
	b.closed = upTo
}

func (b *baselines) closeHour(e *Engine, h int64, rules []*compiled, ready bool) {
	start := time.Unix(h*3600, 0).UTC()
	watched := len(rules) > 0 && !b.since.After(start)
	whole := watched && !b.lossy.After(start) // and no event of it dropped unevaluated
	slot, week := slotOf(start, b.loc), int32(weekOf(start, b.loc))
	var hosts []*tent[hostTraffic]
	b.traffic.each(func(x *tent[hostTraffic]) { hosts = append(hosts, x) })
	for _, x := range hosts {
		c := x.v.take(h)
		if !ready {
			// Until the edge's routes were read no host is known to be gone: none is forgotten (nor
			// its saved row deleted), and nothing was counted.
			continue
		}
		// A host name no route serves any more, or now counted under another name (a catch-all
		// route serves it), is forgotten.
		if key, known, _ := e.opt.KnownHost(x.key); !known || key != x.key {
			b.traffic.drop(x)
			continue
		}
		q := x.v.quiet
		if c.req > 0 {
			x.v.quiet = 0
		} else if whole {
			x.v.quiet = min(q+1, trafficForget)
		}
		if x.v.quiet >= trafficForget {
			b.traffic.drop(x) // no request for trafficForget watched hours
			continue
		}
		if !watched || h < x.v.from {
			if x.v.quiet != q {
				b.traffic.touch(x)
			}
			continue
		}
		for _, r := range rules {
			// Intentional: with events dropped unevaluated the hour's counts are a lower bound: a
			// surge in them is one (the floods that fill the queue among them), a drop may not be.
			if whole || r.r.ID != ruleTrafficDrop {
				b.trafficCheck(e, r, x, slot, week, c, start)
			}
		}
		if !whole {
			if x.v.quiet != q {
				b.traffic.touch(x)
			}
			continue // not learned
		}
		x.v.slots[slot].record(week, c)
		b.traffic.touch(x)
		b.traffic.protect(x)
	}
}

func (b *baselines) trafficCheck(e *Engine, c *compiled, x *tent[hostTraffic], slot int, week int32, n tcount,
	start time.Time) {
	prior := x.v.slots[slot].prior(week)
	if len(prior) < weeksFor(c.r.Learn) {
		return
	}
	reqs, errs := make([]float64, len(prior)), make([]float64, len(prior))
	for i, p := range prior {
		reqs[i], errs[i] = float64(p.req), float64(p.err)
	}
	drop := c.r.ID == ruleTrafficDrop
	ureq, uerr := middle(reqs, !drop), middle(errs, true)
	var parts []string
	if drop {
		if ureq >= float64(c.r.Count) && float64(n.req) <= ureq/c.r.Factor {
			parts = append(parts, fmt.Sprintf("%d requests (usually about %s)", n.req, fmtNum(ureq)))
		}
	} else {
		if n.req >= uint32(c.r.Count) && float64(n.req) >= c.r.Factor*ureq {
			parts = append(parts, fmt.Sprintf("%d requests (usually about %s)", n.req, fmtNum(ureq)))
		}
		if n.err >= uint32(minErrors(c.r.Count)) && float64(n.err) >= c.r.Factor*uerr {
			parts = append(parts, fmt.Sprintf("%d server errors (usually about %s)", n.err, fmtNum(uerr)))
		}
	}
	if len(parts) == 0 {
		return
	}
	reason := strings.Join(parts, " and ") + " in the hour " + hourSpan(start, b.loc)
	ev := &siem.Event{TS: start.Add(time.Hour - time.Second), Src: siem.SrcEdge, Kind: siem.KindHTTPRequest,
		F: map[string]any{"host": x.key}}
	e.fire(c, x.key, ev, firing{count: 1, reasons: []string{reason}})
}

// minErrors is a surge rule's minimum of server errors in an hour: a quarter of its count (its
// minimum of requests), at least 1.
func minErrors(count int) int { return max(count/4, 1) }

const trafficVersion = 1

// encode: the version, from, quiet, then per hour of the week its mask and, when set, its newest
// week and the requests and errors of each week held.
func (x *hostTraffic) encode() []byte {
	b := make([]byte, 0, 24+weekHours*3)
	b = append(b, trafficVersion)
	b = binary.AppendVarint(b, x.from)
	b = binary.AppendUvarint(b, uint64(x.quiet))
	for i := range x.slots {
		s := &x.slots[i]
		b = append(b, s.mask)
		if s.mask == 0 {
			continue
		}
		b = binary.AppendVarint(b, int64(s.week))
		for p := range trafficWeeks {
			if s.mask&(1<<p) != 0 {
				b = binary.AppendUvarint(b, uint64(s.v[p].req))
				b = binary.AppendUvarint(b, uint64(s.v[p].err))
			}
		}
	}
	return b
}

func decodeTraffic(b []byte) (hostTraffic, error) {
	var x hostTraffic
	if len(b) == 0 || b[0] != trafficVersion {
		return x, errState
	}
	r := &reader{b: b[1:]}
	x.from = r.varint()
	q := r.uvarint()
	if q > trafficForget {
		return x, errState
	}
	x.quiet = uint32(q)
	for i := range x.slots {
		m := r.bytes(1)
		if r.err != nil {
			return x, errState
		}
		s := &x.slots[i]
		if s.mask = m[0]; s.mask == 0 {
			continue
		}
		if s.mask >= 1<<trafficWeeks {
			return x, errState
		}
		w := r.varint()
		if w < 0 || w > 1<<31-1 {
			return x, errState
		}
		s.week = int32(w)
		for p := range trafficWeeks {
			if s.mask&(1<<p) != 0 {
				req, errs := r.uvarint(), r.uvarint()
				if req > 1<<32-1 || errs > req {
					return x, errState
				}
				s.v[p] = tcount{req: uint32(req), err: uint32(errs)}
			}
		}
	}
	if r.err != nil || len(r.b) != 0 {
		return x, errState
	}
	return x, nil
}
