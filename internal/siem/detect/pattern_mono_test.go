// Clock readings as time.Now() gives them carry a monotonic part, which hides a wall-clock step from
// Before/After/Sub: these tests replay the clock-set-back cases with such readings.
package detect

import (
	"testing"
	"time"
	"unsafe"
)

type rawTime struct {
	wall uint64
	ext  int64
	loc  *time.Location
}

const (
	scrUnixToInternal int64 = (1969*365 + 1969/4 - 1969/100 + 1969/400) * 86400
	scrWallToInternal int64 = (1884*365 + 1884/4 - 1884/100 + 1884/400) * 86400
)

// monoTime is what time.Now() returns when the wall clock reads wall and mono has passed on the
// monotonic clock since base (a time.Now() reading).
func monoTime(t *testing.T, base, wall time.Time, mono time.Duration) time.Time {
	x := base.Add(mono)
	r := (*rawTime)(unsafe.Pointer(&x))
	if r.wall>>63 == 0 {
		t.Fatal("base has no monotonic reading")
	}
	sec := uint64(wall.Unix() + scrUnixToInternal - scrWallToInternal)
	r.wall = 1<<63 | sec<<30 | uint64(wall.Nanosecond())
	if x.Unix() != wall.Unix() || x.Sub(base) != mono {
		t.Fatalf("monoTime: wall %v (want %v) mono %v (want %v)", x.Unix(), wall.Unix(), x.Sub(base), mono)
	}
	return x
}

type monoClk struct {
	t    *testing.T
	h    *harness
	base time.Time
	mono time.Duration
	cur  time.Time
}

func newMonoClk(t *testing.T, h *harness) *monoClk {
	c := &monoClk{t: t, h: h, base: time.Now()}
	c.cur = c.base
	h.e.now = func() time.Time { return c.cur }
	return c
}

// set: the wall clock reads wall; a minute has passed for real.
func (c *monoClk) set(wall time.Time) {
	c.mono += time.Minute
	c.cur = monoTime(c.t, c.base, wall, c.mono)
	c.h.clk.set(wall)
}

func (c *monoClk) tick(wall time.Time) {
	c.set(wall)
	c.h.e.patternTick()
	c.h.patFire()
}

// The repo's TestPatternClockSetBackWithinTheHour, with readings as time.Now() gives them.
func TestPatternMonoClockBackWithinHourMonotonic(t *testing.T) {
	h := patHarness(t, nil)
	h.learnedScope("shop", "web", t0.Add(-8*day))
	c := newMonoClk(t, h)
	for at := t0.Add(30 * time.Minute); !at.After(t0.Add(40 * time.Minute)); at = at.Add(time.Minute) {
		c.tick(at)
	}
	c.set(t0.Add(40 * time.Minute))
	h.mine(appLine(t0.Add(40*time.Minute), "shop", "web", "", "made half an hour ahead"))
	tp := h.tmplOf("shop", "web", "made half an hour ahead")
	if tp == nil {
		t.Fatal("no template")
	}
	c.tick(t0.Add(10 * time.Minute))
	if got := time.Unix(0, tp.first).UTC(); got.After(t0.Add(10*time.Minute + patSkew)) {
		t.Errorf("the template's first line is still at %v (clock reads %v)", got, t0.Add(10*time.Minute))
	}
	c.tick(t0.Add(16 * time.Minute))
	if ds := h.detections(t, rulePatternNew); len(ds) != 1 {
		t.Errorf("new reports 6 minutes after the clock was set back: %d", len(ds))
	}
}

// The repo's TestPatternClockSetBack "running" mode, with readings as time.Now() gives them: the
// first tick of the run is on the clock that is ahead.
func TestPatternMonoClockBackRunningMonotonic(t *testing.T) {
	h := patHarness(t, nil)
	c := newMonoClk(t, h)
	future := t0.Add(400 * day)
	for at := future; !at.After(future.Add(3 * time.Hour)); at = at.Add(time.Minute) {
		c.tick(at)
	}
	if h.pm().hours.closed < floorDiv(future.Unix(), 3600) {
		t.Fatal("setup: no hour closed on the wrong clock")
	}
	end := t0.Add(2*day + 3*time.Hour)
	for at := t0; at.Before(end); at = at.Add(time.Minute) {
		c.tick(at)
	}
	m := h.pm()
	m.mu.Lock()
	st := m.hours.state(floorDiv(t0.Add(5*time.Hour).Unix(), 3600))
	since := m.since
	m.mu.Unlock()
	if st != hourLearned {
		t.Errorf("an hour watched whole after the clock was set back is %d (since=%v, clock=%v)", st, since.UTC(), end)
	}
}

// Started on the right clock; the clock runs ahead 400 days for 3 hours and is corrected.
func TestPatternMonoClockAheadMidRunMonotonic(t *testing.T) {
	h := patHarness(t, nil)
	c := newMonoClk(t, h)
	for at := t0.Add(-6 * time.Hour); at.Before(t0); at = at.Add(time.Minute) {
		c.tick(at)
	}
	future := t0.Add(400 * day)
	for at := future; !at.After(future.Add(3 * time.Hour)); at = at.Add(time.Minute) {
		c.tick(at)
	}
	c.tick(t0.Add(3 * time.Hour)) // corrected: 3 real hours later
	m := h.pm()
	m.mu.Lock()
	// The hour t0+1h..t0+2h passed while the clock was ahead: its lines were counted elsewhere.
	st := m.hours.state(floorDiv(t0.Add(time.Hour).Unix(), 3600))
	m.mu.Unlock()
	t.Logf("state of an hour that passed on the wrong clock: %d (0 off, 1 learned)", st)
	if st == hourLearned {
		t.Errorf("an hour whose lines were counted on the wrong clock is history")
	}
}

// The traffic baseline's tick, with readings as time.Now() gives them: after the clock is set
// back, the hours not closed yet aren't watched whole (since starts again at the new time).
func TestTrafficClockSetBackMonotonic(t *testing.T) {
	h := newHarness(t, false, func(o *Options) { o.KnownHost = served(func(string) bool { return true }) })
	h.only(t, trafficRules()...)
	c := newMonoClk(t, h)
	tick := func(wall time.Time) {
		c.set(wall)
		h.e.baselineTick()
	}
	tick(t0.Add(30 * time.Minute))
	tick(t0.Add(31 * time.Minute))
	first := h.e.bl.since
	tick(t0.Add(10 * time.Minute)) // set back 21 minutes
	if got := h.e.bl.since; !got.Equal(t0.Add(10*time.Minute)) || !first.Equal(t0.Add(30*time.Minute)) {
		t.Errorf("since after the clock was set back = %v (first %v), want %v", got, first, t0.Add(10*time.Minute))
	}
}
