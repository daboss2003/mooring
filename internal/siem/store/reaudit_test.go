package store

import (
	"bufio"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/query"
)

// indexedHour appends n classified events in one capture hour and flushes them.
func indexedHour(t *testing.T, s *Store, c *clock, n, size int) {
	t.Helper()
	var b []siem.Event
	for i := 0; i < n; i++ {
		e := mkev(c, "auth.login", siem.LvlInfo, i)
		e.Msg = strings.Repeat("r", size)
		b = append(b, e)
	}
	mustAppend(t, s, b...)
	mustFlush(t, s)
}

// Removing a segment deletes its index rows in chunks and lets go of the lock between them, so an
// Append (here, run between two chunks from the same goroutine) is never held up by a removal. A
// removal that still held the lock would deadlock here.
func TestRemovalReleasesTheLockBetweenChunks(t *testing.T) {
	c := newClock(h10)
	s := openStore(t, storeDir(t), c, nil)
	indexedHour(t, s, c, 3000, 50)
	c.add(time.Hour)
	mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, 1))
	if err := s.SealDue(); err != nil {
		t.Fatal(err)
	}
	old := segNames(s)[0]
	if err := s.MarkArchived(old, "k", c.now()); err != nil {
		t.Fatal(err)
	}
	s.deleteChunk = 100
	appends := 0
	s.betweenSteps = func() {
		appends++
		if err := s.Append([]siem.Event{mkev(c, "auth.login", siem.LvlInfo, 10000+appends)}); err != nil {
			t.Errorf("Append between chunks: %v", err)
		}
	}
	s.opt.MaxDiskBytes = 1
	done := make(chan error, 1)
	start := time.Now()
	go func() { done <- s.Prune() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("Prune did not return: the lock was held between chunks")
	}
	s.betweenSteps = nil
	if appends < 25 {
		t.Errorf("only %d pauses while removing 3000 rows in chunks of 100", appends)
	}
	if k := countRows(t, s, `events WHERE segment = ?`, old); k != 0 {
		t.Errorf("%d rows left", k)
	}
	if k := countRows(t, s, `row_gc`); k != 0 {
		t.Errorf("%d segments left queued for row removal", k)
	}
	t.Logf("removal with %d pauses took %v", appends, time.Since(start))
}

// A crash in the middle of removing a segment's rows: the next Prune finishes the job.
func TestRowRemovalResumesAfterACrash(t *testing.T) {
	c := newClock(h10)
	dir := storeDir(t)
	s := openStore(t, dir, c, nil)
	indexedHour(t, s, c, 500, 50)
	c.add(time.Hour)
	mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, 1))
	if err := s.SealDue(); err != nil {
		t.Fatal(err)
	}
	old := segNames(s)[0]
	if err := s.MarkArchived(old, "k", c.now()); err != nil {
		t.Fatal(err)
	}
	s.deleteChunk = 100
	calls := 0
	s.betweenSteps = func() {
		if calls++; calls == 2 {
			abandon(s) // crash after two chunks
		}
	}
	s.opt.MaxDiskBytes = 1
	_ = s.Prune()
	s2 := openStore(t, dir, c, nil)
	if k := countRows(t, s2, `events WHERE segment = ?`, old); k == 0 || k == 500 {
		t.Fatalf("%d rows left after the crash; want a partial removal", k)
	}
	if err := s2.Prune(); err != nil {
		t.Fatal(err)
	}
	if k := countRows(t, s2, `events WHERE segment = ?`, old); k != 0 {
		t.Errorf("%d rows left after the next Prune", k)
	}
	if k := countRows(t, s2, `row_gc`); k != 0 {
		t.Errorf("%d segments still queued", k)
	}
}

// Free pages go back to the file system in bounded steps with the lock released between them; a
// step that runs out of time keeps what it did, and the next Prune carries on.
func TestVacuumInBoundedSteps(t *testing.T) {
	c := newClock(h10)
	s := openStore(t, storeDir(t), c, nil)
	indexedHour(t, s, c, 4000, 1000)
	c.add(time.Hour)
	mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, 1))
	if err := s.SealDue(); err != nil {
		t.Fatal(err)
	}
	if err := s.MarkArchived(segNames(s)[0], "k", c.now()); err != nil {
		t.Fatal(err)
	}
	s.vacuumStep, s.vacuumBudget = 50, 0 // one step per Prune
	free := func() int {
		var n int
		if err := s.db.QueryRow(`PRAGMA freelist_count`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	s.opt.MaxDiskBytes = 1
	if err := s.Prune(); err != nil { // removes the hour and its ~4 MB of rows
		t.Fatal(err)
	}
	s.opt.MaxDiskBytes = 1 << 30
	f1 := free()
	if f1 < 200 {
		t.Fatalf("free pages after the removal: %d", f1)
	}
	if err := s.Prune(); err != nil {
		t.Fatal(err)
	}
	f2 := free()
	if f2 >= f1 || f2 == 0 {
		t.Fatalf("one bounded vacuum step: %d → %d free pages", f1, f2)
	}
	for i := 0; i < 3; i++ {
		if err := s.Prune(); err != nil {
			t.Fatal(err)
		}
	}
	f3 := free()
	if f3 >= f2 {
		t.Fatalf("progress not kept across Prunes: %d → %d", f2, f3)
	}
	// With time to spare one vacuum finishes the job, letting go of the lock between steps (an
	// Append runs in each pause; one that held the lock would deadlock here).
	steps := 0
	s.betweenSteps = func() {
		steps++
		if err := s.Append([]siem.Event{mkev(c, "auth.login", siem.LvlInfo, 20000+steps)}); err != nil {
			t.Errorf("Append between vacuum steps: %v", err)
		}
	}
	s.vacuumBudget = time.Minute
	done := make(chan error, 1)
	go func() { done <- s.Prune() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("vacuum held the lock between steps")
	}
	s.betweenSteps = nil
	if free() != 0 {
		t.Errorf("%d free pages left", free())
	}
	if steps < f3/50-2 {
		t.Errorf("%d pauses for about %d steps", steps, f3/50)
	}
}

// The disk cap judges the database by its live pages, so it removes only what is needed even when
// the free pages haven't been returned to the file system yet.
func TestDiskCapIgnoresPagesNotYetVacuumed(t *testing.T) {
	c := newClock(h10)
	s := openStore(t, storeDir(t), c, nil)
	names := bigHours(t, s, c, 4)
	s.vacuumStep, s.vacuumBudget = 1, 0 // the vacuum barely moves
	s.mu.Lock()
	used := s.segBytesLocked() + s.dbLiveBytes()
	s.mu.Unlock()
	s.opt.MaxDiskBytes = used - 100<<10
	if err := s.Prune(); err != nil {
		t.Fatal(err)
	}
	if got := segNames(s); strings.Join(got, " ") != strings.Join(names[1:], " ") {
		t.Fatalf("after a cap 100 KiB under the live size: %q", got)
	}
	if err := s.Prune(); err != nil {
		t.Fatal(err)
	}
	if got := segNames(s); len(got) != len(names)-1 {
		t.Fatalf("a second Prune removed more: %q", got)
	}
}

// Paging past segments whose time range reaches back (a line timestamped yesterday in a busy hour)
// reaches every event, and a page that says More always moves Before below To.
func TestCappedPagingPastBackdatedSegments(t *testing.T) {
	for _, budget := range []int64{2, 1} { // ×maxRaw: the wide segments fit, or they don't
		c := newClock(h10)
		s := openStore(t, storeDir(t), c, nil)
		s.maxRaw = 64 << 10
		mk := func(i int, ts time.Time) siem.Event {
			e := mkev(c, siem.KindLog, siem.LvlInfo, i)
			e.Msg = fmt.Sprintf("event %d %s", i, strings.Repeat("x", 300))
			e.TS = ts
			return e
		}
		n := 0
		var normal []string
		for h := 0; h < 2; h++ {
			for i := 0; i < 150; i++ {
				mustAppend(t, s, mk(n, c.now()))
				normal = append(normal, fmt.Sprintf("event %d ", n))
				n++
				c.add(20 * time.Second)
			}
			c.set(h10.Add(time.Duration(h+1) * time.Hour))
		}
		for seg := 0; seg < 2; seg++ {
			mustAppend(t, s, mk(n, h10.Add(-24*time.Hour)))
			n++
			for i := 0; i < 400; i++ {
				mustAppend(t, s, mk(n, c.now()))
				normal = append(normal, fmt.Sprintf("event %d ", n))
				n++
				c.add(time.Second)
			}
		}
		mustFlush(t, s)
		c.set(h10.Add(3 * time.Hour))
		if err := s.SealDue(); err != nil {
			t.Fatal(err)
		}
		s.searchBytes = budget * s.maxRaw
		q := query.Query{Text: []string{"event"}}
		seen := map[string]int{}
		for p := 0; ; p++ {
			if p > 200 {
				t.Fatalf("budget %d: paging does not end", budget)
			}
			r, err := s.Search(bg, q, 1000)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range r.Events {
				seen[e.Msg]++
			}
			if !r.More {
				break
			}
			if !q.To.IsZero() && !r.Before.Before(q.To) {
				t.Fatalf("budget %d: page %d says More with Before %v not below To %v", budget, p, r.Before, q.To)
			}
			q.To = r.Before
		}
		for m, k := range seen {
			if k != 1 {
				t.Errorf("budget %d: %.12q returned %d times", budget, m, k)
			}
		}
		if budget == 2 && len(seen) != n {
			t.Errorf("budget %d: %d of %d events reachable", budget, len(seen), n)
		}
		// Every event stored at its capture time is reachable even when the back-dated segments
		// don't fit the budget.
		got := map[string]bool{}
		for m := range seen {
			got[m[:strings.Index(m, " x")+1]] = true
		}
		for _, m := range normal {
			if !got[m] {
				t.Fatalf("budget %d: %q never returned", budget, m)
			}
		}
	}
}

// The clock steps forward 60 days (real time: hours) and events keep coming: segments captured
// before the step are aged by the time that really passed, so none is removed early. With no
// archive the same holds.
func TestClockJumpLatchHoldsThroughNewEvents(t *testing.T) {
	withJumpLatch(t)
	for _, archive := range []bool{true, false} {
		c := newClock(h10)
		dir := storeDir(t)
		s := openStore(t, dir, c, func(o *Options) { o.ArchiveConfigured = archive })
		for h := 0; h < 3; h++ {
			mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, h))
			c.add(time.Hour)
		}
		if err := s.SealDue(); err != nil {
			t.Fatal(err)
		}
		before := segNames(s)
		c.add(60 * 24 * time.Hour)
		mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, 99)) // the next event, at the new time
		if err := s.Prune(); err != nil {
			t.Fatal(err)
		}
		for _, n := range before {
			if segByName(s, n) == nil {
				t.Fatalf("archive=%v: %s removed after a clock step and one event", archive, n)
			}
		}
		// A step shorter than the old guard's 42 days is caught too.
		c.add(20 * 24 * time.Hour)
		mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, 100))
		if err := s.Prune(); err != nil {
			t.Fatal(err)
		}
		if segByName(s, before[0]) == nil {
			t.Fatalf("archive=%v: removed after a second, 20-day step", archive)
		}
		// The latch survives a restart.
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		s2 := openStore(t, dir, c, func(o *Options) { o.ArchiveConfigured = archive })
		if err := s2.Prune(); err != nil {
			t.Fatal(err)
		}
		if segByName(s2, before[0]) == nil {
			t.Fatalf("archive=%v: removed after a restart", archive)
		}
		// As real time passes (events every few hours), the pre-step segments age out on time and
		// the latch is released.
		for d := time.Duration(0); d < 23*24*time.Hour; d += 4 * time.Hour {
			c.add(4 * time.Hour)
			mustAppend(t, s2, mkev(c, "auth.login", siem.LvlInfo, 200))
			if err := s2.Prune(); err != nil {
				t.Fatal(err)
			}
		}
		for _, n := range before {
			if segByName(s2, n) != nil {
				t.Errorf("archive=%v: %s kept past its real retention", archive, n)
			}
		}
		s2.mu.Lock()
		latched := s2.latchAt != 0
		s2.mu.Unlock()
		if latched {
			t.Errorf("archive=%v: latch not released once the pre-step segments were gone", archive)
		}
	}
}

// The clock coming back releases the latch; normal aging resumes.
func TestClockJumpLatchReleasedWhenTheClockComesBack(t *testing.T) {
	withJumpLatch(t)
	c := newClock(h10)
	s := openStore(t, storeDir(t), c, nil)
	mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, 1))
	c.add(10 * 365 * 24 * time.Hour)
	if err := s.Prune(); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	latched := s.latchAt != 0
	s.mu.Unlock()
	if !latched {
		t.Fatal("no latch after a 10-year step")
	}
	c.set(h10.Add(2 * time.Hour))
	if err := s.Prune(); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	latched = s.latchAt != 0
	s.mu.Unlock()
	if latched {
		t.Error("latch kept after the clock came back")
	}
}

// Recovery re-indexes a segment it seals from what is in the file: events that reached the file
// without a Flush are indexed, and the index agrees with a scan.
func TestRecoveryReindexesSealedSegments(t *testing.T) {
	c := newClock(h10)
	dir := storeDir(t)
	s := openStore(t, dir, c, nil)
	mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, -1))
	mustFlush(t, s)
	var evs []siem.Event
	for i := 0; i < 20000; i++ {
		e := mkev(c, "auth.login", siem.LvlInfo, i)
		e.TS = h10.Add(time.Duration(i+1) * time.Millisecond)
		if i%3 == 0 {
			e.Kind = siem.KindLog // not indexed
		}
		e.Msg = fmt.Sprintf("event %d %x", i, uint64(i)*0x9E3779B97F4A7C15)
		evs = append(evs, e)
	}
	mustAppend(t, s, evs...) // no Flush: some deflate blocks reach the file anyway
	abandon(s)
	s2 := openStore(t, dir, c, nil)
	g := segByName(s2, segNames(s2)[0])
	if g.events < 1000 {
		t.Fatalf("only %d events reached the file", g.events)
	}
	pq, _ := query.Parse("kind:auth.login")
	var idx, scan int
	for _, fn := range []searchFn{s2.searchIndex, s2.searchScan} {
		q := pq
		n := 0
		for {
			r, err := fn(bg, q, maxLimit)
			if err != nil {
				t.Fatal(err)
			}
			n += len(r.Events)
			if !r.More {
				break
			}
			q.To = r.Before
		}
		if idx == 0 {
			idx = n
		} else {
			scan = n
		}
	}
	if idx != scan || idx < 600 {
		t.Fatalf("after recovery: index %d, scan %d auth.login events (segment holds %d events)", idx, scan, g.events)
	}
	if k := countRows(t, s2, `events`); k != scan {
		t.Errorf("%d index rows for %d events", k, scan)
	}
}

// Index rows waiting for a retry are dropped with the segment the cap removes; they are never
// inserted for a segment that no longer exists.
func TestRemovedSegmentsRetryRowsAreDropped(t *testing.T) {
	c := newClock(h10)
	s := openStore(t, storeDir(t), c, nil)
	for i := 0; i < 5; i++ {
		mustAppend(t, s, mkev(c, "auth.login", siem.LvlWarn, i))
	}
	c.add(time.Hour)
	mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, 100))
	if _, err := s.db.Exec(`CREATE TRIGGER zz_fail BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT, 'injected'); END`); err != nil {
		t.Fatal(err)
	}
	name := segNames(s)[0]
	c.add(time.Hour)
	s.opt.MaxDiskBytes = 1
	_ = s.Prune() // seals 10 and 11 (their inserts fail), then the cap removes 10
	if segByName(s, name) != nil {
		t.Fatal("segment not removed")
	}
	if _, err := s.db.Exec(`DROP TRIGGER zz_fail`); err != nil {
		t.Fatal(err)
	}
	s.opt.MaxDiskBytes = 1 << 30
	mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, 101))
	mustFlush(t, s)
	if k := countRows(t, s, `events WHERE segment = ?`, name); k != 0 {
		t.Fatalf("%d index rows inserted for the removed segment", k)
	}
	// The kept segment's rows were retried.
	if k := countRows(t, s, `events WHERE segment = ?`, segNames(s)[0]); k != 1 {
		t.Errorf("kept segment has %d rows, want 1", k)
	}
}

type hookWriter struct {
	n    int
	hook func()
	sb   strings.Builder
}

func (w *hookWriter) Write(p []byte) (int, error) {
	w.n++
	if w.n == 1 && w.hook != nil {
		w.hook()
	}
	return w.sb.Write(p)
}

// A segment removed while an export runs stops the export with ErrSegmentRemoved, after the
// events it already wrote.
func TestExportStopsWhenASegmentIsRemoved(t *testing.T) {
	c := newClock(h10)
	s := openStore(t, storeDir(t), c, nil)
	total := 0
	for h := 0; h < 3; h++ {
		var b []siem.Event
		for i := 0; i < 300; i++ {
			e := mkev(c, "auth.login", siem.LvlInfo, total)
			e.Msg = fmt.Sprintf("event %d %s", total, strings.Repeat("y", 1000))
			b = append(b, e)
			total++
		}
		mustAppend(t, s, b...)
		mustFlush(t, s)
		c.add(time.Hour)
	}
	if err := s.SealDue(); err != nil {
		t.Fatal(err)
	}
	for _, n := range segNames(s) {
		if err := s.MarkArchived(n, "k/"+n, c.now()); err != nil {
			t.Fatal(err)
		}
	}
	w := &hookWriter{hook: func() {
		s.opt.MaxDiskBytes = 1
		_ = s.Prune()
	}}
	n, err := s.Export(bg, query.Query{Text: []string{"event"}}, w, 0)
	if !errors.Is(err, ErrSegmentRemoved) || n == 0 || n >= total {
		t.Fatalf("Export = %d, %v; want a partial count and ErrSegmentRemoved", n, err)
	}
	lines := 0
	sc := bufio.NewScanner(strings.NewReader(w.sb.String()))
	sc.Buffer(make([]byte, 64<<10), maxLine)
	for sc.Scan() {
		lines++
	}
	if lines != n {
		t.Errorf("%d lines written, Export said %d", lines, n)
	}
}

// A page that can't move past To within its budget (here the time budget ends inside the newest
// segment below To) doesn't ask for a next page it can't reach: More is false, the page Capped.
func TestPageNeverAsksForANextPageItCantReach(t *testing.T) {
	c := newClock(h10)
	s := openStore(t, storeDir(t), c, nil)
	for i := 0; i < 50; i++ {
		mustAppend(t, s, mkev(c, siem.KindLog, siem.LvlInfo, i))
		c.add(time.Second)
	}
	mustFlush(t, s)
	g := segByName(s, segNames(s)[0])
	q := query.Query{Text: []string{"event"}, To: nsTime(g.last).Add(time.Nanosecond)}
	s.searchTime = time.Nanosecond
	r, err := s.Search(bg, q, 10)
	if err != nil {
		t.Fatal(err)
	}
	if !r.Capped || (r.More && !r.Before.Before(q.To)) {
		t.Fatalf("Capped %v More %v Before %v To %v", r.Capped, r.More, r.Before, q.To)
	}
}
