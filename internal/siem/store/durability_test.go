package store

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/query"
)

// Index rows are written at Flush, after the segment bytes are synced: a crash before the Flush
// leaves neither the bytes nor the rows, so the index and a scan agree afterwards.
func TestCrashBeforeFlushLeavesNoIndexOnlyEvents(t *testing.T) {
	c := newClock(h10.Add(10 * time.Minute))
	dir := storeDir(t)
	s := openStore(t, dir, c, nil)
	for i := 0; i < 5; i++ {
		mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, i))
	}
	mustFlush(t, s)
	for i := 5; i < 10; i++ {
		mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, i))
	}
	pq, _ := query.Parse("kind:auth.login")
	// Before the Flush the index, like a scan, shows only what was flushed.
	if r, err := s.searchIndex(bg, pq, 100); err != nil || len(r.Events) != 5 {
		t.Fatalf("index before Flush: %d events (%v)", len(r.Events), err)
	}
	abandon(s)
	s2 := openStore(t, dir, c, nil)
	idx, err := s2.searchIndex(bg, pq, 100)
	if err != nil {
		t.Fatal(err)
	}
	scan, err := s2.searchScan(bg, pq, 100)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(msgs(idx.Events), ",") != strings.Join(msgs(scan.Events), ",") || len(idx.Events) != 5 {
		t.Fatalf("after a crash: index %q, scan %q", msgs(idx.Events), msgs(scan.Events))
	}
	// A clean Close indexes what it made durable.
	mustAppend(t, s2, mkev(c, "auth.login", siem.LvlInfo, 20))
	if err := s2.Close(); err != nil {
		t.Fatal(err)
	}
	s3 := openStore(t, dir, c, nil)
	if r, _ := s3.searchIndex(bg, pq, 100); len(r.Events) != 6 {
		t.Errorf("after Close and reopen the index has %d events, want 6", len(r.Events))
	}
}

// Sealing (a size-cap roll inside Append) indexes the sealed segment's rows too.
func TestSealIndexesPendingRows(t *testing.T) {
	c := newClock(h10)
	s := openStore(t, storeDir(t), c, nil)
	s.maxEvents = 3
	var b []siem.Event
	for i := 0; i < 7; i++ {
		b = append(b, mkev(c, "auth.login", siem.LvlInfo, i))
	}
	mustAppend(t, s, b...)
	if n := countRows(t, s, `events`); n != 6 {
		t.Errorf("%d rows indexed before Flush, want the 6 of the two sealed segments", n)
	}
	mustFlush(t, s)
	if n := countRows(t, s, `events`); n != 7 {
		t.Errorf("%d rows after Flush", n)
	}
}

// The highest seq of each hour is kept in the database: a segment removed at the disk cap and a
// restart within the same hour don't hand its name (and archive key) to a new segment.
func TestSeqNotReusedAfterRemovalAndRestart(t *testing.T) {
	c := newClock(h10.Add(10 * time.Minute))
	dir := storeDir(t)
	s := openStore(t, dir, c, nil)
	s.maxEvents = 2
	mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, 0), mkev(c, "auth.login", siem.LvlInfo, 1))
	mustFlush(t, s)
	if err := s.SealDue(); err != nil {
		t.Fatal(err)
	}
	first := segNames(s)
	if len(first) != 1 {
		t.Fatalf("segments %q", first)
	}
	if err := s.MarkArchived(first[0], "k", c.now()); err != nil {
		t.Fatal(err)
	}
	s.opt.MaxDiskBytes = 1
	if err := s.Prune(); err != nil {
		t.Fatal(err)
	}
	if segByName(s, first[0]) != nil {
		t.Fatal("archived segment not removed at the cap")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2 := openStore(t, dir, c, nil)
	mustAppend(t, s2, mkev(c, "auth.login", siem.LvlInfo, 9))
	for _, n := range segNames(s2) {
		if n == first[0] {
			t.Fatalf("name %s reused after its segment was removed", n)
		}
	}
}

// failWriterAfter passes the first n bytes through, then fails every write.
type failWriterAfter struct {
	w io.Writer
	n int
}

func (f *failWriterAfter) Write(p []byte) (int, error) {
	if f.n <= 0 {
		return 0, errors.New("disk on fire")
	}
	if len(p) > f.n {
		k, _ := f.w.Write(p[:f.n])
		f.n = 0
		return k, errors.New("disk on fire")
	}
	f.n -= len(p)
	return f.w.Write(p)
}

func randomEvents(c *clock, n int) []siem.Event {
	var out []siem.Event
	for i := 0; i < n; i++ {
		b := make([]byte, 2048)
		_, _ = rand.Read(b)
		e := mkev(c, "auth.login", siem.LvlInfo, i)
		e.Msg = fmt.Sprintf("event %d %s", i, hex.EncodeToString(b))
		out = append(out, e)
	}
	return out
}

// exactlyOnce checks every event of evs is stored once.
func exactlyOnce(t *testing.T, s *Store, evs []siem.Event) {
	t.Helper()
	mustFlush(t, s)
	r, err := s.searchScan(bg, query.Query{}, maxLimit)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, e := range r.Events {
		seen[strings.Fields(e.Msg)[1]]++
	}
	for i := range evs {
		if k := seen[fmt.Sprint(i)]; k != 1 {
			t.Errorf("event %d stored %d times", i, k)
		}
	}
	// And the index agrees with the segments.
	pq, _ := query.Parse("kind:auth.login")
	idx, _ := s.searchIndex(bg, pq, maxLimit)
	if len(idx.Events) != len(r.Events) {
		t.Errorf("index has %d events, segments %d", len(idx.Events), len(r.Events))
	}
}

func TestAppendReportsPartialWriteOnWriteError(t *testing.T) {
	c := newClock(h10)
	s := openStore(t, storeDir(t), c, nil)
	s.wrapFile = func(w io.Writer) io.Writer {
		s.wrapFile = nil // the first segment's disk fails, later ones work
		return &failWriterAfter{w: w, n: 40 << 10}
	}
	evs := randomEvents(c, 40)
	err := s.Append(evs)
	var ae *AppendError
	if !errors.As(err, &ae) || ae.Written <= 0 || ae.Written >= len(evs) {
		t.Fatalf("Append over a failing disk = %v (%+v)", err, ae)
	}
	mustAppend(t, s, evs[ae.Written:]...)
	exactlyOnce(t, s, evs)
	// The events this call reported as not written are retried, not recorded as lost.
	mustFlush(t, s)
	if r := searchAll(t, s, "kind:siem.dropped"); len(r.Events) != 0 {
		t.Errorf("retried events recorded as lost: %+v", r.Events)
	}
	// The broken segment was sealed as it is on disk.
	segs, _ := s.Unarchived()
	if len(segs) != 1 || segs[0].Events != ae.Written || segs[0].SHA256 != fileSHA(t, segs[0].Path) {
		t.Errorf("broken segment = %+v, Written %d", segs, ae.Written)
	}
}

func TestAppendReportsPartialWriteWhenNoSegmentCanBeCreated(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	c := newClock(h10)
	dir := storeDir(t)
	s := openStore(t, dir, c, nil)
	s.maxEvents = 3
	evs := randomEvents(c, 6)
	mustAppend(t, s, evs[0])
	segDir := filepath.Join(dir, "segments")
	if err := os.Chmod(segDir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(segDir, 0o700)
	// Two more fit the open segment; the roll to a new one fails.
	err := s.Append(evs[1:])
	var ae *AppendError
	if !errors.As(err, &ae) || ae.Written != 2 {
		t.Fatalf("Append = %v (%+v), want 2 written", err, ae)
	}
	// Nothing at all stored: a plain error.
	err = s.Append(evs[1+ae.Written:])
	if err == nil || errors.As(err, &ae) {
		t.Fatalf("Append with nowhere to write = %v, want a plain error", err)
	}
	if err := os.Chmod(segDir, 0o700); err != nil {
		t.Fatal(err)
	}
	mustAppend(t, s, evs[3:]...)
	exactlyOnce(t, s, evs)
}

// A clock that jumps far ahead doesn't make every segment look past its retention.
func TestForwardClockJumpSkipsAgePruning(t *testing.T) {
	withJumpLatch(t)
	c := newClock(h10)
	s := openStore(t, storeDir(t), c, nil)
	mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, 1))
	c.add(time.Hour)
	mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, 2))
	if err := s.SealDue(); err != nil {
		t.Fatal(err)
	}
	c.add(10 * 365 * 24 * time.Hour)
	if err := s.Prune(); err != nil {
		t.Fatal(err)
	}
	if n := s.Segments(); n != 2 {
		t.Fatalf("a forward clock jump removed segments: %d left", n)
	}
	// Within the bound the retention applies as usual: hour 10 is past retention + 7 days, 11 not.
	c.set(h10.Add(time.Hour + 21*24*time.Hour + 30*time.Minute))
	if err := s.Prune(); err != nil {
		t.Fatal(err)
	}
	if segByName(s, "2026112310-box1-1.ndjson.gz") != nil || segByName(s, "2026112311-box1-1.ndjson.gz") == nil {
		t.Fatalf("after 21 days: %q", segNames(s))
	}
}

func TestSegmentsCarryBoxAndChain(t *testing.T) {
	c := newClock(h10)
	dir := storeDir(t)
	s := openStore(t, dir, c, nil)
	s.maxEvents = 1
	for i := 0; i < 3; i++ {
		mustAppend(t, s, mkev(c, "auth.login", siem.LvlInfo, i))
	}
	c.add(time.Hour)
	if err := s.SealDue(); err != nil {
		t.Fatal(err)
	}
	segs, _ := s.Unarchived()
	if len(segs) != 3 {
		t.Fatalf("%d segments", len(segs))
	}
	for i, g := range segs {
		if g.Box != "box1" || g.Chain != int64(i+1) {
			t.Errorf("segment %d: Box %q Chain %d", i, g.Box, g.Chain)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// A file another box name wrote (the host was renamed) keeps its own box after recovery.
	other := filepath.Join(dir, "segments", "2026112309-old-host-4.ndjson.gz")
	if err := os.WriteFile(other, mustRead(t, segs[0].Path), 0o600); err != nil {
		t.Fatal(err)
	}
	s2 := openStore(t, dir, c, nil)
	segs, _ = s2.Unarchived()
	if len(segs) != 4 {
		t.Fatalf("%d segments after recovery", len(segs))
	}
	for i, g := range segs[:3] {
		if g.Box != "box1" || g.Chain != int64(i+1) {
			t.Errorf("after reopen, segment %d: Box %q Chain %d", i, g.Box, g.Chain)
		}
	}
	if g := segs[3]; g.Name != filepath.Base(other) || g.Box != "old-host" || g.Seq != 4 || g.Chain != 4 {
		t.Errorf("recovered segment = %+v", g)
	}
}

// Index rows are written indexChunk per transaction (each well inside dbTimeout). When one
// transaction fails, only the rows not yet written are kept and retried at the next Flush: none is
// lost or written twice.
func TestIndexInsertRetriesOnlyWhatFailed(t *testing.T) {
	c := newClock(h10)
	s := openStore(t, storeDir(t), c, nil)
	n := indexChunk*2 + 10
	var evs []siem.Event
	for i := 0; i < n; i++ {
		e := mkev(c, "auth.login", siem.LvlInfo, i)
		e.TS = h10.Add(time.Duration(i) * time.Millisecond)
		evs = append(evs, e)
	}
	// The second chunk's transaction fails.
	failTS := tsNS(evs[indexChunk+5].TS)
	if _, err := s.db.Exec(fmt.Sprintf(`CREATE TRIGGER boom BEFORE INSERT ON events WHEN NEW.ts = %d BEGIN SELECT RAISE(ABORT, 'boom'); END`, failTS)); err != nil {
		t.Fatal(err)
	}
	mustAppend(t, s, evs...)
	if err := s.Flush(); err == nil {
		t.Fatal("Flush with a failing index insert reported no error")
	}
	if k := countRows(t, s, `events`); k != indexChunk {
		t.Fatalf("%d rows written before the failure, want the first chunk (%d)", k, indexChunk)
	}
	if _, err := s.db.Exec(`DROP TRIGGER boom`); err != nil {
		t.Fatal(err)
	}
	mustFlush(t, s)
	if k := countRows(t, s, `events`); k != n {
		t.Fatalf("%d rows after the retry, want %d", k, n)
	}
	if k := countRows(t, s, `(SELECT ts FROM events GROUP BY ts HAVING COUNT(*) > 1)`); k != 0 {
		t.Fatalf("%d events indexed twice", k)
	}
	// Removing the segment removes all its rows, more than one delete batch.
	if n <= s.deleteChunk {
		t.Fatalf("test needs more than %d rows", s.deleteChunk)
	}
	c.add(time.Hour)
	if err := s.SealDue(); err != nil {
		t.Fatal(err)
	}
	segs, _ := s.Unarchived()
	if err := s.MarkArchived(segs[0].Name, "k", c.now()); err != nil {
		t.Fatal(err)
	}
	s.opt.MaxDiskBytes = 1
	if err := s.Prune(); err != nil {
		t.Fatal(err)
	}
	if k := countRows(t, s, `events WHERE segment = ?`, segs[0].Name); k != 0 {
		t.Fatalf("%d index rows left after removing their segment", k)
	}
}
