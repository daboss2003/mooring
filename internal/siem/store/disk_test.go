package store

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

// bigHours appends n capture hours of heavily indexed events (each hour's index rows run to
// megabytes, far more than its compressed segment), then one event in the current hour, and seals
// the finished hours.
func bigHours(t *testing.T, s *Store, c *clock, n int) []string {
	t.Helper()
	for h := 0; h < n; h++ {
		var b []siem.Event
		for i := 0; i < 1500; i++ {
			e := mkev(c, "auth.login", siem.LvlInfo, i)
			e.Msg = strings.Repeat("a", 2000)
			b = append(b, e)
		}
		mustAppend(t, s, b...)
		mustFlush(t, s)
		c.add(time.Hour)
	}
	mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, 9))
	mustFlush(t, s)
	if err := s.SealDue(); err != nil {
		t.Fatal(err)
	}
	return segNames(s)
}

// The disk cap measures again after each removal (with the freed database pages returned and the
// WAL truncated), so a cap a little under the current size removes one segment, not all of them,
// and later Prunes don't keep removing because the WAL stayed at its peak.
func TestDiskCapRemovesOnlyWhatIsNeeded(t *testing.T) {
	for _, archived := range []bool{true, false} {
		c := newClock(h10)
		s := openStore(t, storeDir(t), c, nil)
		names := bigHours(t, s, c, 4)
		if archived {
			for _, n := range names[:4] {
				if err := s.MarkArchived(n, "k/"+n, c.now()); err != nil {
					t.Fatal(err)
				}
			}
		}
		if w := fileSize(s.dbPath + "-wal"); w > walSizeLimit {
			t.Errorf("WAL at %d bytes, over journal_size_limit", w)
		}
		s.mu.Lock()
		s.reclaimLocked()
		s.mu.Unlock()
		if w := fileSize(s.dbPath + "-wal"); w != 0 {
			t.Fatalf("reclaim left the WAL at %d bytes", w)
		}
		s.opt.MaxDiskBytes = s.DiskBytes() - 100<<10
		if err := s.Prune(); err != nil {
			t.Fatal(err)
		}
		got := segNames(s)
		if strings.Join(got, " ") != strings.Join(names[1:], " ") {
			t.Fatalf("archived=%v: after a cap 100 KiB under the size: %q (from %q)", archived, got, names)
		}
		if d := s.DiskBytes(); d > s.opt.MaxDiskBytes {
			t.Errorf("archived=%v: still %d bytes over the cap", archived, d-s.opt.MaxDiskBytes)
		}
		if w := fileSize(s.dbPath + "-wal"); w > walSizeLimit {
			t.Errorf("archived=%v: WAL left at %d bytes", archived, w)
		}
		// The removed segment's index rows went with it (they are recent: only that removes them).
		if k := countRows(t, s, `events WHERE segment = ?`, names[0]); k != 0 {
			t.Errorf("archived=%v: %d index rows kept for the removed segment", archived, k)
		}
		// Later hours add little: nothing more is removed.
		for h := 0; h < 3; h++ {
			c.add(time.Hour)
			mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, 100+h))
			mustFlush(t, s)
			if err := s.Prune(); err != nil {
				t.Fatal(err)
			}
		}
		if got := segNames(s); len(got) != len(names)-1+3 || got[0] != names[1] {
			t.Errorf("archived=%v: later Prunes kept removing: %q", archived, got)
		}
	}
}

// A cap the store can't get under (smaller than the database and the open segment) never removes
// the newest sealed segment that isn't archived.
func TestDiskCapKeepsTheNewestUnarchivedSegment(t *testing.T) {
	c := newClock(h10)
	s := openStore(t, storeDir(t), c, nil)
	names := bigHours(t, s, c, 3)
	s.opt.MaxDiskBytes = 1
	if err := s.Prune(); err != nil {
		t.Fatal(err)
	}
	if got := segNames(s); strings.Join(got, " ") != names[2]+" "+names[3] {
		t.Fatalf("after an impossible cap: %q (from %q)", got, names)
	}
	// Archived segments can all go: the archive holds them.
	if err := s.MarkArchived(names[2], "k", c.now()); err != nil {
		t.Fatal(err)
	}
	if err := s.Prune(); err != nil {
		t.Fatal(err)
	}
	if got := segNames(s); len(got) != 1 || got[0] != names[3] {
		t.Fatalf("archived newest segment kept: %q", got)
	}
}

// diskFake is a DiskUsage that returns a scripted sequence of used percentages (the last one
// repeats) and counts its calls.
type diskFake struct {
	mu    sync.Mutex
	pcts  []float64
	calls int
}

func (d *diskFake) set(p ...float64) {
	d.mu.Lock()
	d.pcts, d.calls = p, 0
	d.mu.Unlock()
}

func (d *diskFake) usage() (uint64, uint64, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	p := d.pcts[min(d.calls, len(d.pcts)-1)]
	d.calls++
	return uint64(p * 1000), 100_000, true
}

func (d *diskFake) n() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.calls
}

func TestDiskPressure(t *testing.T) {
	c := newClock(h10)
	fake := &diskFake{pcts: []float64{50}}
	s := openStore(t, storeDir(t), c, func(o *Options) {
		o.DiskUsage, o.DiskThresholdPct = fake.usage, 90
	})
	for i := 0; i < 4; i++ {
		mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, i))
		c.add(time.Hour)
	}
	mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, 9))
	if err := s.SealDue(); err != nil {
		t.Fatal(err)
	}
	names := segNames(s) // hours 10-13 sealed, 14 open
	for _, n := range names[1:3] {
		if err := s.MarkArchived(n, "k/"+n, c.now()); err != nil {
			t.Fatal(err)
		}
	}
	// At the threshold: the archived segments go (oldest first, sampling again after each) until
	// the disk is below it, and the Append goes through.
	fake.set(95, 50)
	c.add(diskCheckEvery)
	mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, 10))
	if got := segNames(s); strings.Join(got, " ") != strings.Join([]string{names[0], names[2], names[3], names[4]}, " ") {
		t.Fatalf("after pressure with one removal enough: %q", got)
	}
	// Still above with nothing archived left: Append refuses, unarchived segments are kept.
	fake.set(95)
	c.add(diskCheckEvery)
	err := s.Append([]siem.Event{mkev(c, "auth.login", siem.LvlInfo, 11)})
	if !errors.Is(err, ErrDiskPressure) {
		t.Fatalf("Append under pressure = %v", err)
	}
	var ae *AppendError
	if errors.As(err, &ae) {
		t.Errorf("a refused batch reported a partial write: %+v", ae)
	}
	if got := segNames(s); strings.Join(got, " ") != strings.Join([]string{names[0], names[3], names[4]}, " ") {
		t.Fatalf("unarchived segments removed under pressure: %q", got)
	}
	// The disk is sampled at most every diskCheckEvery, not per Append.
	calls := fake.n()
	fake.set(50)
	for i := 0; i < 5; i++ {
		if err := s.Append([]siem.Event{mkev(c, "auth.login", siem.LvlInfo, 20+i)}); !errors.Is(err, ErrDiskPressure) {
			t.Fatalf("Append within the check interval = %v", err)
		}
	}
	if fake.n() != 0 || calls == 0 {
		t.Errorf("disk sampled %d times within the interval", fake.n())
	}
	c.add(diskCheckEvery)
	mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, 30))
	// Prune samples every time and removes archived segments under pressure even without appends.
	if err := s.MarkArchived(names[0], "k/0", c.now()); err != nil {
		t.Fatal(err)
	}
	fake.set(95, 50)
	if err := s.Prune(); err != nil {
		t.Fatal(err)
	}
	if got := segNames(s); got[0] != names[3] {
		t.Errorf("Prune under pressure: %q", got)
	}
}

func TestDiskPressureUnknownReadingKeepsState(t *testing.T) {
	c := newClock(h10)
	var mu sync.Mutex
	ok, used := true, uint64(95)
	s := openStore(t, storeDir(t), c, func(o *Options) {
		o.DiskUsage = func() (uint64, uint64, bool) { mu.Lock(); defer mu.Unlock(); return used, 100, ok }
		o.DiskThresholdPct = 90
	})
	if err := s.Append([]siem.Event{mkev(c, "auth.login", siem.LvlInfo, 1)}); !errors.Is(err, ErrDiskPressure) {
		t.Fatalf("first Append at 95%% = %v", err)
	}
	mu.Lock()
	ok = false
	mu.Unlock()
	c.add(diskCheckEvery)
	if err := s.Append([]siem.Event{mkev(c, "auth.login", siem.LvlInfo, 2)}); !errors.Is(err, ErrDiskPressure) {
		t.Fatalf("Append with an unknown reading = %v, want the pressure kept", err)
	}
	mu.Lock()
	ok, used = true, 10
	mu.Unlock()
	c.add(diskCheckEvery)
	mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, 3))
	// Without DiskUsage (or a threshold) there is no check.
	s2 := openStore(t, storeDir(t), c, func(o *Options) { o.DiskThresholdPct = 90 })
	mustAppend(t, s2, mkev(c, "auth.login", siem.LvlInfo, 4))
}
