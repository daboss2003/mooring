package store

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

// seg is one segment file and its manifest row. Fields change only under Store.mu.
type seg struct {
	name                 string
	hour                 time.Time // UTC capture hour
	seq                  int
	box                  string
	events               int
	bytes                int64 // file size once sealed (see size)
	sha, prev            string
	first, last          int64 // oldest and newest Event.TS, unix ns
	capFirst, capLast    int64 // capture times of the first and last event, unix ns
	chain                int64 // position in the seal order, 0 while open
	sealedAt, archivedAt int64
	key                  string
	open                 bool
	w                    *segWriter // set while this process writes the segment
	flushed              int64      // bytes of the open file a reader may decode (gzip-flushed and synced)
	pending              []indexRow // index rows of events not yet flushed; written once their bytes are durable
}

// size is the file's current size.
func (g *seg) size() int64 {
	if g.w != nil {
		return g.w.cw.n
	}
	return g.bytes
}

// readable is how much of the file a search may read: all of a sealed one, the flushed part of
// one being written.
func (g *seg) readable() int64 {
	if g.w != nil {
		return g.flushed
	}
	return g.bytes
}

// segWriter is the open gzip stream of a segment being written.
type segWriter struct {
	f      *os.File
	cw     *countWriter
	gz     *gzip.Writer
	raw    int64 // uncompressed bytes written
	dirty  bool  // written since the last flush
	broken bool  // a write failed: the file is sealed as it is on disk
	retry  int   // trailing events the caller reports as not written (it retries them): not a loss
}

// countWriter counts and hashes what reaches the file.
type countWriter struct {
	w io.Writer
	n int64
	h hash.Hash
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	c.h.Write(p[:n])
	return n, err
}

// finish ends the gzip stream and makes the file durable. The writer is unusable afterwards.
func (w *segWriter) finish() error {
	var errs []error
	if !w.broken {
		if err := w.gz.Close(); err != nil {
			w.broken = true
			errs = append(errs, err)
		}
	}
	if err := w.f.Sync(); err != nil {
		w.broken = true
		errs = append(errs, err)
	}
	if err := w.f.Close(); err != nil {
		w.broken = true
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

const segSuffix = ".ndjson.gz"

var segNameRe = regexp.MustCompile(`^([0-9]{10})-(.+)-([1-9][0-9]{0,8})\.ndjson\.gz$`)

func segName(hour time.Time, box string, seq int) string {
	return hour.UTC().Format("2006010215") + "-" + box + "-" + strconv.Itoa(seq) + segSuffix
}

// parseSegName parses a segment file name; ok=false for anything else.
func parseSegName(name string) (hour time.Time, box string, seq int, ok bool) {
	m := segNameRe.FindStringSubmatch(name)
	if m == nil || !siem.SafeName(m[2]) {
		return time.Time{}, "", 0, false
	}
	hour, err := time.ParseInLocation("2006010215", m[1], time.UTC)
	if err != nil {
		return time.Time{}, "", 0, false
	}
	seq, err = strconv.Atoi(m[3])
	if err != nil {
		return time.Time{}, "", 0, false
	}
	return hour, m[2], seq, true
}

func segLess(a, b *seg) bool {
	if !a.hour.Equal(b.hour) {
		return a.hour.Before(b.hour)
	}
	if a.seq != b.seq {
		return a.seq < b.seq
	}
	return a.name < b.name
}

func (s *Store) insertSegLocked(g *seg) {
	i := sort.Search(len(s.segs), func(i int) bool { return segLess(g, s.segs[i]) })
	s.segs = slices.Insert(s.segs, i, g)
}

func (s *Store) dropSegLocked(g *seg) {
	if i := slices.Index(s.segs, g); i >= 0 {
		s.segs = slices.Delete(s.segs, i, i+1)
	}
}

func (s *Store) noteSeqLocked(hour time.Time, box string, seq int) {
	k := strconv.FormatInt(hour.Unix(), 10) + "/" + box
	if seq > s.maxSeq[k] {
		s.maxSeq[k] = seq
	}
}

// Timestamps are stored as unix nanoseconds, clamped to the range int64 can hold (1678–2262).
var (
	minTS = time.Unix(0, math.MinInt64)
	maxTS = time.Unix(0, math.MaxInt64)
)

func tsNS(t time.Time) int64 {
	switch {
	case t.Before(minTS):
		return math.MinInt64
	case t.After(maxTS):
		return math.MaxInt64
	}
	return t.UnixNano()
}

func nsTime(ns int64) time.Time { return time.Unix(0, ns).UTC() }

// classified events are indexed in security.db.
func classified(e *siem.Event) bool {
	return (e.Kind != siem.KindLog && e.Kind != siem.KindHTTPRequest) || siem.LevelRank(e.Lvl) >= siem.LevelRank(siem.LvlWarn)
}

// marshalLine is e's stored line: its JSON and '\n'. A float that JSON can't hold (NaN, ±Inf) is
// dropped; an event larger than maxLine is refused.
func marshalLine(e *siem.Event) ([]byte, error) {
	b, err := json.Marshal(e)
	if err != nil {
		c := sanitize(e)
		if b, err = json.Marshal(&c); err != nil {
			return nil, err
		}
	}
	if len(b)+1 > maxLine {
		return nil, fmt.Errorf("event of %d bytes is larger than %d", len(b), maxLine)
	}
	return append(b, '\n'), nil
}

func finite(f float64) bool { return !math.IsNaN(f) && !math.IsInf(f, 0) }

func sanitize(e *siem.Event) siem.Event {
	c := *e
	if len(e.F) > 0 {
		c.F = make(map[string]any, len(e.F))
		for k, v := range e.F {
			switch x := v.(type) {
			case float64:
				if finite(x) {
					c.F[k] = x
				}
			case string, bool:
				c.F[k] = x
			}
		}
	}
	if e.Geo != nil {
		g := *e.Geo
		if !finite(g.Lat) || !finite(g.Lon) {
			g.Lat, g.Lon = 0, 0
		}
		c.Geo = &g
	}
	return c
}

// currentLocked is the segment Append writes for hour, or nil. Caller holds s.mu.
func (s *Store) currentLocked(hour time.Time) *seg {
	for i := len(s.segs) - 1; i >= 0; i-- {
		g := s.segs[i]
		if g.w != nil && !g.w.broken && g.hour.Equal(hour) && g.box == s.opt.Box {
			return g
		}
	}
	return nil
}

// newSegLocked creates the next segment of hour: the file (0600, never through a symlink, never
// over an existing file) and its open manifest row. Caller holds s.mu.
func (s *Store) newSegLocked(hour time.Time, capNS int64) (*seg, error) {
	box := s.opt.Box
	seq := s.maxSeq[strconv.FormatInt(hour.Unix(), 10)+"/"+box] + 1
	for tries := 0; tries < 64; tries, seq = tries+1, seq+1 {
		name := segName(hour, box, seq)
		path := filepath.Join(s.segDir, name)
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|oNoFollow, 0o600)
		if errors.Is(err, fs.ErrExist) {
			s.noteSeqLocked(hour, box, seq)
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("store: create segment: %w", err)
		}
		s.noteSeqLocked(hour, box, seq)
		err = s.tx(func(ctx context.Context, tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, `INSERT INTO segments(name, hour, seq, box, path, cap_first, cap_last, state)
				VALUES (?, ?, ?, ?, ?, ?, ?, 'open')`, name, hour.Unix(), seq, box, path, capNS, capNS); err != nil {
				return err
			}
			return upsertSeq(ctx, tx, hour, box, seq)
		})
		if err != nil {
			_ = f.Close()
			_ = os.Remove(path)
			return nil, fmt.Errorf("store: record segment %s: %w", name, err)
		}
		_ = syncDir(s.segDir)
		var fw io.Writer = f
		if s.wrapFile != nil {
			fw = s.wrapFile(f)
		}
		cw := &countWriter{w: fw, h: sha256.New()}
		gz, _ := gzip.NewWriterLevel(cw, gzip.DefaultCompression)
		g := &seg{name: name, hour: hour, seq: seq, box: box, open: true, capFirst: capNS, capLast: capNS,
			w: &segWriter{f: f, cw: cw, gz: gz}}
		s.insertSegLocked(g)
		return g, nil
	}
	return nil, errors.New("store: no free segment name")
}

// upsertSeq records seq as used for (hour, box), keeping the highest.
func upsertSeq(ctx context.Context, tx *sql.Tx, hour time.Time, box string, seq int) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO seqs(hour, box, seq) VALUES (?, ?, ?)
		ON CONFLICT(hour, box) DO UPDATE SET seq = MAX(seq, excluded.seq)`, hour.Unix(), box, seq)
	return err
}

// Append writes events (already normalized and redacted) to the current hour's segment and
// indexes the classified ones. Events taken become durable and searchable at the next Flush (or
// when their segment is sealed); their index rows are written then, after the segment's bytes are
// synced, so a crash never leaves an indexed event that isn't in a segment.
//
// The result says how much of evs was taken: nil, all of it; *AppendError{Written: n}, evs[:n]
// and not evs[n:] (retry only evs[n:], or the first n are stored twice); any other error, none
// (ErrDiskPressure: the filesystem is at the disk-pressure threshold). An event that can never be
// stored (over 1 MiB as JSON) is dropped with a warning and counts as taken.
//
// Intentional: the segment is chosen by the capture time (Options.Now), not by an event's TS, so a
// source that lies about its timestamps can't scatter events into old hours. Each segment records
// its TS range, which is what search uses.
func (s *Store) Append(evs []siem.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() {
		return errClosed
	}
	s.noteTimeLocked(s.now())
	if s.pressureLocked(false) {
		return ErrDiskPressure
	}
	if s.closed.Load() { // the pressure check lets go of the lock while it removes segments
		return errClosed
	}
	n, err := s.appendLocked(evs)
	s.appendLostLocked()
	switch {
	case err == nil:
		return nil
	case n == 0:
		return err
	}
	return &AppendError{Written: n, Err: err}
}

// appendLocked writes evs and returns how many of them were taken (see Append). Caller holds s.mu.
func (s *Store) appendLocked(evs []siem.Event) (int, error) {
	if len(evs) == 0 {
		return 0, nil
	}
	now := s.now()
	hour, capNS := now.Truncate(time.Hour), now.UnixNano()
	g := s.currentLocked(hour)
	var (
		inG    []int // indexes in evs of the events this call wrote to g
		before int   // g's events before this call wrote to it
	)
	if g != nil {
		before = g.events
	}
	for i := range evs {
		e := &evs[i]
		line, err := marshalLine(e)
		if err != nil {
			if !s.dropWarned.Swap(true) {
				s.opt.Log.Warn("siem store: dropping an event that can't be stored", "kind", e.Kind, "src", e.Src, "err", err)
			}
			continue
		}
		if g != nil && g.events > 0 && (g.w.raw+int64(len(line)) > s.maxRaw || g.events >= s.maxEvents) {
			// A failed seal leaves the segment open in the manifest; SealDue retries it. The events
			// in it are durable either way.
			if err := s.sealLocked(g); err != nil {
				s.opt.Log.Error("siem store: cannot seal a full segment", "segment", g.name, "err", err)
			}
			g = nil
		}
		if g == nil {
			if g, err = s.newSegLocked(hour, capNS); err != nil {
				return i, err
			}
			inG, before = nil, 0
		}
		if _, err := g.w.gz.Write(line); err != nil {
			g.w.broken, g.w.retry = true, len(inG)
			werr := fmt.Errorf("store: write %s: %w", g.name, err)
			if serr := s.sealLocked(g); serr != nil {
				werr = errors.Join(werr, serr)
			}
			// The segment was sealed as it is on disk: the events of this call that decode from it
			// were stored, the rest were not.
			stored := min(max(g.events-before, 0), len(inG))
			if stored == len(inG) {
				return i, werr
			}
			return inG[stored], werr
		}
		ts := tsNS(e.TS)
		if g.events == 0 || ts < g.first {
			g.first = ts
		}
		if g.events == 0 || ts > g.last {
			g.last = ts
		}
		g.events++
		g.capLast = capNS
		g.w.raw += int64(len(line))
		g.w.dirty = true
		inG = append(inG, i)
		if classified(e) {
			g.pending = append(g.pending, newIndexRow(e, ts, g.name, g.events, line[:len(line)-1]))
			s.pendingBytes += len(line)
		}
	}
	if s.pendingBytes > pendingCap {
		if err := s.flushLocked(); err != nil {
			s.opt.Log.Error("siem store: flush", "err", err)
		}
	}
	return len(evs), nil
}

// Flush makes everything appended so far durable and visible to Search.
func (s *Store) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() {
		return errClosed
	}
	err := s.flushLocked()
	s.appendLostLocked()
	return err
}

// flushLocked syncs every open segment, then indexes the events that are now durable. Caller
// holds s.mu.
func (s *Store) flushLocked() error {
	var (
		errs []error
		rows []indexRow
	)
	for _, g := range slices.Clone(s.segs) {
		if g.w == nil {
			continue
		}
		if g.w.dirty {
			err := g.w.gz.Flush()
			if err == nil {
				err = g.w.f.Sync()
			}
			if err != nil {
				g.w.broken = true
				errs = append(errs, fmt.Errorf("store: flush %s: %w", g.name, err))
				if err := s.sealLocked(g); err != nil {
					errs = append(errs, err)
				}
				continue
			}
			g.w.dirty = false
			g.flushed = g.w.cw.n
		}
		rows = append(rows, s.takePendingLocked(g)...)
	}
	if err := s.indexLocked(rows); err != nil {
		errs = append(errs, fmt.Errorf("store: index: %w", err))
	}
	return errors.Join(errs...)
}

// takePendingLocked hands over g's pending index rows. Caller holds s.mu.
func (s *Store) takePendingLocked(g *seg) []indexRow {
	rows := g.pending
	g.pending = nil
	for _, r := range rows {
		s.pendingBytes -= len(r.json) + 1
	}
	return rows
}

// SealDue seals the open segments of hours that are over (and the current one when it outgrows
// its size cap), recording each one's SHA256 and PrevSHA256.
func (s *Store) SealDue() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() {
		return errClosed
	}
	s.noteTimeLocked(s.now())
	err := s.sealDueLocked()
	s.appendLostLocked()
	return err
}

// sealDueLocked is SealDue. Caller holds s.mu.
func (s *Store) sealDueLocked() error {
	hour := s.now().Truncate(time.Hour)
	var errs []error
	for _, g := range slices.Clone(s.segs) {
		if !g.open {
			continue
		}
		// g.w == nil: a seal whose manifest update failed earlier; this retries it.
		if g.w == nil || !g.hour.Equal(hour) || g.w.raw >= s.maxRaw || g.events >= s.maxEvents {
			errs = append(errs, s.sealLocked(g))
		}
	}
	return errors.Join(errs...)
}

// sealLocked finishes g's file, indexes the events in it and records it in the hash chain.
// Caller holds s.mu.
func (s *Store) sealLocked(g *seg) error {
	path := filepath.Join(s.segDir, g.name)
	if w := g.w; w != nil {
		g.w = nil
		ferr := w.finish()
		rows := s.takePendingLocked(g)
		if g.events == 0 {
			// Nothing reached it (its first write failed).
			_ = os.Remove(path)
			s.dropSegLocked(g)
			_, err := s.exec(`DELETE FROM segments WHERE name = ?`, g.name)
			return errors.Join(ferr, err)
		}
		if ferr != nil || w.broken {
			// The file is sealed as it is on disk: count what in it still decodes, and index only
			// the events that reached it.
			st, err := scanFile(path)
			if err != nil {
				s.dropSegLocked(g)
				s.loseLocked(g.name, g.events, "segment unreadable")
				g.events = 0
				_, derr := s.exec(`DELETE FROM segments WHERE name = ?`, g.name)
				return errors.Join(fmt.Errorf("store: seal %s: %w", g.name, err), derr)
			}
			if lost := g.events - w.retry - st.events; lost > 0 {
				s.loseLocked(g.name, lost, "write error") // events earlier calls were told were stored
			}
			rows = slices.DeleteFunc(rows, func(r indexRow) bool { return r.ord > st.events })
			g.events, g.first, g.last, g.bytes, g.sha = st.events, st.first, st.last, st.size, st.sha
		} else {
			g.bytes, g.sha = w.cw.n, hex.EncodeToString(w.cw.h.Sum(nil))
		}
		g.flushed = g.bytes
		_ = syncDir(s.segDir)
		if err := s.indexLocked(rows); err != nil {
			s.opt.Log.Error("siem store: cannot index a sealed segment; retrying at the next flush", "segment", g.name, "err", err)
		}
	}
	return s.recordSealLocked(g)
}

// recordSealLocked links g into the hash chain and marks it sealed. Caller holds s.mu.
func (s *Store) recordSealLocked(g *seg) error {
	sealedAt := s.now().UnixNano()
	var (
		n    int64
		prev string
	)
	err := s.tx(func(ctx context.Context, tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, `SELECT n, sha256 FROM chain WHERE id = 1`).Scan(&n, &prev); err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO segments(name, hour, seq, box, path, events, bytes, sha256, prev_sha256,
				first_ts, last_ts, cap_first, cap_last, chain, sealed_at, state)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'sealed')
			ON CONFLICT(name) DO UPDATE SET events = excluded.events, bytes = excluded.bytes, sha256 = excluded.sha256,
				prev_sha256 = excluded.prev_sha256, first_ts = excluded.first_ts, last_ts = excluded.last_ts,
				cap_first = excluded.cap_first, cap_last = excluded.cap_last, chain = excluded.chain,
				sealed_at = excluded.sealed_at, state = 'sealed'`,
			g.name, g.hour.Unix(), g.seq, g.box, filepath.Join(s.segDir, g.name), g.events, g.bytes, g.sha, prev,
			g.first, g.last, g.capFirst, g.capLast, n+1, sealedAt); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO chain(id, n, sha256) VALUES (1, ?, ?)
			ON CONFLICT(id) DO UPDATE SET n = excluded.n, sha256 = excluded.sha256`, n+1, g.sha)
		return err
	})
	if err != nil {
		return fmt.Errorf("store: seal %s: %w", g.name, err)
	}
	g.open, g.prev, g.chain, g.sealedAt = false, prev, n+1, sealedAt
	return nil
}

// fileStats is what scanFile learns from a segment file.
type fileStats struct {
	events      int
	first, last int64
	size        int64
	sha         string
	mtime       time.Time
}

// scanFile hashes a segment file and counts the events in it that still decode (a truncated or
// damaged gzip stream ends the count, not the hash).
func scanFile(path string) (fileStats, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|oNoFollow, 0)
	if err != nil {
		return fileStats{}, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return fileStats{}, err
	}
	if !fi.Mode().IsRegular() {
		return fileStats{}, fmt.Errorf("%s is not a regular file", path)
	}
	st := fileStats{mtime: fi.ModTime()}
	hw := &countWriter{w: io.Discard, h: sha256.New()}
	tee := io.TeeReader(f, hw)
	if zr, err := gzip.NewReader(tee); err == nil {
		zr.Multistream(false)
		sc := bufio.NewScanner(zr)
		sc.Buffer(make([]byte, 64<<10), maxLine)
		for sc.Scan() {
			var e struct {
				TS time.Time `json:"ts"`
			}
			if json.Unmarshal(sc.Bytes(), &e) != nil {
				continue
			}
			ts := tsNS(e.TS)
			if st.events == 0 || ts < st.first {
				st.first = ts
			}
			if st.events == 0 || ts > st.last {
				st.last = ts
			}
			st.events++
		}
	}
	if _, err := io.Copy(io.Discard, tee); err != nil {
		return fileStats{}, err
	}
	st.size, st.sha = hw.n, hex.EncodeToString(hw.h.Sum(nil))
	return st, nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// loseLocked logs count events of segment name that are gone before they were archived (or,
// without an archive, before their retention ended) and queues a siem.dropped event for them.
// Caller holds s.mu.
func (s *Store) loseLocked(name string, count int, reason string) {
	s.opt.Log.Warn("siem store: security-log events lost", "segment", name, "events", count, "reason", reason)
	now := s.now()
	e := siem.Event{
		TS: now, Src: siem.SrcSIEM, Kind: siem.KindDropped, Lvl: siem.LvlWarn,
		F:   map[string]any{"source": "store", "segment": name, "count": float64(count), "reason": reason},
		Msg: fmt.Sprintf("security-log segment %s: %d events lost: %s", name, count, reason),
	}
	e.Normalize(now)
	s.lost = append(s.lost, e)
}

// appendLostLocked appends the queued siem.dropped events. Caller holds s.mu.
func (s *Store) appendLostLocked() {
	if len(s.lost) == 0 || s.closed.Load() {
		return
	}
	evs := s.lost
	s.lost = nil
	if _, err := s.appendLocked(evs); err != nil {
		s.opt.Log.Error("siem store: cannot record lost segments", "err", err)
	}
}

func (s *Store) segment(g *seg) Segment {
	out := Segment{
		Name: g.name, Box: g.box, Chain: g.chain, Path: filepath.Join(s.segDir, g.name), Hour: g.hour,
		Seq: g.seq, Events: g.events, Bytes: g.size(), SHA256: g.sha, PrevSHA256: g.prev, Key: g.key,
	}
	if g.events > 0 {
		out.First, out.Last = nsTime(g.first), nsTime(g.last)
	}
	if g.archivedAt != 0 {
		out.ArchivedAt = nsTime(g.archivedAt)
	}
	return out
}

// Unarchived lists sealed segments not yet archived, oldest first (in seal order, the order of
// the hash chain).
func (s *Store) Unarchived() ([]Segment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() {
		return nil, errClosed
	}
	var gs []*seg
	for _, g := range s.segs {
		if !g.open && g.archivedAt == 0 {
			gs = append(gs, g)
		}
	}
	sort.Slice(gs, func(i, j int) bool { return gs[i].chain < gs[j].chain })
	out := make([]Segment, len(gs))
	for i, g := range gs {
		out[i] = s.segment(g)
	}
	return out, nil
}

// Boxes lists every box name this store has written segments under (the current one included),
// oldest first. A box stays listed after its segments are removed (the archive prunes objects
// stored under a previous host name with it). Only names siem.SafeName accepts are returned.
func (s *Store) Boxes() ([]string, error) {
	if s.closed.Load() {
		return nil, errClosed
	}
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `SELECT name FROM boxes ORDER BY first_seen, name`)
	if err != nil {
		return nil, fmt.Errorf("store: boxes: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("store: boxes: %w", err)
		}
		if siem.SafeName(name) {
			out = append(out, name)
		}
	}
	return out, rows.Err()
}

// MarkArchived records that segment name was uploaded as key at at.
func (s *Store) MarkArchived(name, key string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() {
		return errClosed
	}
	var g *seg
	for _, x := range s.segs {
		if x.name == name {
			g = x
			break
		}
	}
	if g == nil {
		// Intentional: not an error. Prune can remove a segment at the disk cap while its upload
		// runs; the upload stands and there is nothing left to record.
		return nil
	}
	if g.open {
		return fmt.Errorf("store: segment %s is not sealed", name)
	}
	if key == "" || len(key) > 1024 {
		return fmt.Errorf("store: bad archive key for %s", name)
	}
	if at.IsZero() {
		at = s.now()
	}
	if _, err := s.exec(`UPDATE segments SET archived_at = ?, archive_key = ? WHERE name = ?`, tsNS(at), key, name); err != nil {
		return fmt.Errorf("store: mark %s archived: %w", name, err)
	}
	g.archivedAt, g.key = tsNS(at), key
	return nil
}
