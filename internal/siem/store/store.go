// Package store keeps security-log events on this host: hourly gzip NDJSON segments for every
// event, and a separate SQLite database (security.db, its own connections) indexing the classified
// ones (every kind except log and http.request, and anything at warn or above) plus the segment
// manifest with its hash chain. It never touches Mooring's main database.
//
// Layout under Options.Dir (0700): security.db (+ -wal/-shm, 0600), segments/ (0700) with one
// <YYYYMMDDHH>-<box>-<seq>.ndjson.gz file (0600) per capture hour and size cap, tmp/ (0700) for
// other packages' temporary files, and .lock, which keeps a second process from opening the store.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/query"
)

// Options configures a Store.
type Options struct {
	Dir          string        // <data_dir>/security-logs (created 0700)
	Box          string        // this host's name, safe for a file name (siem.SafeName)
	HotRetention time.Duration // segments older than this are removed (archived or not, see Prune)
	MaxDiskBytes int64         // segments + database
	Log          *slog.Logger
	Now          func() time.Time
	// ArchiveConfigured reports that an off-host archive uploads the sealed segments. When false,
	// Prune removes segments at HotRetention whether or not they were archived.
	ArchiveConfigured bool
	// DiskUsage reports the used and total bytes of the filesystem Dir is on (ok=false: unknown,
	// the previous state is kept). At or above DiskThresholdPct percent, archived segments are
	// removed (oldest first) and, if that isn't enough, Append refuses events with ErrDiskPressure.
	// nil, or a threshold ≤ 0, disables the check. It is sampled at most every 5 seconds.
	DiskUsage        func() (used, total uint64, ok bool)
	DiskThresholdPct float64
}

// Segment is one hour's file of events.
type Segment struct {
	Name       string // <YYYYMMDDHH>-<box>-<seq>.ndjson.gz
	Box        string // the box that wrote it (part of Name); the archive key uses it, never the archiver's own
	Chain      int64  // position in the seal order (1, 2, ...); 0 while open — the archive's seal `n`
	Path       string
	Hour       time.Time // the UTC hour its events were captured in
	Seq        int
	Events     int
	Bytes      int64
	SHA256     string    // of the file's bytes, hex; set when sealed
	PrevSHA256 string    // SHA256 of the segment sealed before it ("" for the first): the hash chain
	First      time.Time // the oldest event TS in it
	Last       time.Time // the newest event TS in it
	ArchivedAt time.Time // zero until uploaded
	Key        string    // the archive object key once uploaded
}

// Result is one page of search results, newest first.
type Result struct {
	Events  []siem.Event
	Scanned int64 // events examined
	Capped  bool  // the scan budget ran out before the whole range was examined
	More    bool  // older matches may exist: search again with To = Before
	// Before is where the next page starts (search again with To = Before): the TS of the oldest
	// event returned or, when the scan was capped, 1ns after the newest TS it could not finish
	// examining (so the next page repeats that part rather than skipping it).
	Before time.Time
}

// Errors.
var (
	// ErrBusy: the maximum number of searches and exports is running and none ended in time.
	ErrBusy = errors.New("store: too many searches running, try again")
	// ErrBudget: an export stopped at its scan budget before the whole range was examined.
	ErrBudget = errors.New("store: export stopped at its scan budget; narrow the time range")
	// ErrDiskPressure: Append refused events because the filesystem is at the disk-pressure threshold.
	ErrDiskPressure = errors.New("store: disk at the pressure threshold; events not stored")
	// ErrSegmentRemoved: an export stopped because a segment it was about to read was removed
	// (retention, disk cap or disk pressure) while it ran; what it wrote before is complete up to there.
	ErrSegmentRemoved = errors.New("store: export stopped: a segment was removed while it ran")

	errClosed = errors.New("store: closed")
)

// Limits.
const (
	segMaxRaw    = 256 << 20 // uncompressed bytes in one segment
	segMaxEvents = 2_000_000 // events in one segment
	maxLine      = 1 << 20   // bytes of one stored event line; longer events are dropped

	searchBudget   = 512 << 20 // decompressed bytes one search may read
	searchTimeout  = 10 * time.Second
	exportBudget   = 4 << 30
	exportTimeout  = 10 * time.Minute
	maxSearches    = 2 // searches and exports running at once
	busyWait       = 2 * time.Second
	defaultLimit   = 100
	maxLimit       = 1000
	maxResultBytes = 32 << 20 // event bytes one search holds
	defaultExport  = 1_000_000

	unarchivedGrace = 7 * 24 * time.Hour // how much longer an unarchived segment is kept
	dbTimeout       = 10 * time.Second   // one write statement or transaction
	diskCheckEvery  = 5 * time.Second    // how often Append samples DiskUsage
	walSizeLimit    = 4 << 20            // journal_size_limit: the WAL is cut back to this after a checkpoint
	pendingCap      = 32 << 20           // bytes of index rows held for the next Flush before Append flushes itself

	defaultHotRetention = 14 * 24 * time.Hour
	defaultMaxDiskBytes = 10 << 30
)

// Store is the on-host store. Safe for concurrent use.
type Store struct {
	opt                 Options
	dir, segDir, tmpDir string
	dbPath              string
	db                  *sql.DB  // read-write, one connection; Append, seals, Prune and DB()
	rdb                 *sql.DB  // read-only connections for searches, so a search never holds up Append
	lock                *os.File // flock on .lock
	sem                 chan struct{}
	closed              atomic.Bool
	mu                  sync.Mutex                // the writer side: segs, maxSeq and every DB write
	segs                []*seg                    // every segment on disk, ordered by (hour, seq, name)
	maxSeq              map[string]int            // highest seq ever seen per hour and box, so a name is never reused
	lost                []siem.Event              // siem.dropped events waiting to be appended; guarded by mu
	maxRaw              int64                     // segMaxRaw (tests lower these)
	maxEvents           int                       // segMaxEvents
	searchBytes         int64                     // searchBudget
	exportBytes         int64                     // exportBudget
	searchTime          time.Duration             // searchTimeout
	exportTime          time.Duration             // exportTimeout
	busyWait            time.Duration             // busyWait
	maxResultBytes      int                       // maxResultBytes
	dropWarned          atomic.Bool               // an oversized event was logged once
	pendingBytes        int                       // index rows waiting in open segments for their Flush; guarded by mu
	retryRows           []indexRow                // index rows whose insert failed, retried at the next Flush; guarded by mu
	pressure            bool                      // at or above DiskThresholdPct at the last sample; guarded by mu
	diskCheckedAt       time.Time                 // when DiskUsage was last sampled; guarded by mu
	capWarned           bool                      // the disk cap couldn't be met; guarded by mu
	lastSeen            int64                     // the clock at the store's last look (unix ns); guarded by mu
	latchAt, jumpedTo   int64                     // the clock-step latch (see noteTimeLocked); guarded by mu
	deleteChunk         int                       // index rows one DELETE removes (tests lower these)
	vacuumStep          int                       // pages one incremental_vacuum statement frees
	vacuumBudget        time.Duration             // how long one vacuum may run
	betweenSteps        func()                    // tests: called with the lock let go between steps of a long job
	wrapFile            func(io.Writer) io.Writer // tests: wraps a new segment's file to inject write errors
}

// Open opens (creating) the store.
func Open(opt Options) (*Store, error) {
	if opt.Dir == "" {
		return nil, errors.New("store: no directory")
	}
	if !siem.SafeName(opt.Box) {
		return nil, fmt.Errorf("store: box name %q is not usable in a file name", opt.Box)
	}
	if opt.HotRetention <= 0 {
		opt.HotRetention = defaultHotRetention
	}
	if opt.MaxDiskBytes <= 0 {
		opt.MaxDiskBytes = defaultMaxDiskBytes
	}
	if opt.Log == nil {
		opt.Log = slog.Default()
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	s := &Store{
		opt: opt, dir: opt.Dir, segDir: filepath.Join(opt.Dir, "segments"), tmpDir: filepath.Join(opt.Dir, "tmp"),
		dbPath: filepath.Join(opt.Dir, "security.db"), sem: make(chan struct{}, maxSearches),
		maxSeq: map[string]int{}, maxRaw: segMaxRaw, maxEvents: segMaxEvents,
		searchBytes: searchBudget, exportBytes: exportBudget, searchTime: searchTimeout,
		exportTime: exportTimeout, busyWait: busyWait, maxResultBytes: maxResultBytes,
		deleteChunk: 2000, vacuumStep: 2000, vacuumBudget: 2 * time.Second,
	}
	if err := ensureDir(filepath.Dir(opt.Dir), false); err != nil {
		return nil, err
	}
	for _, d := range []string{s.dir, s.segDir, s.tmpDir} {
		if err := ensureDir(d, true); err != nil {
			return nil, err
		}
	}
	lock, err := lockDir(s.dir)
	if err != nil {
		return nil, err
	}
	s.lock = lock
	if err := s.openDB(); err != nil {
		_ = lock.Close()
		return nil, err
	}
	s.mu.Lock()
	err = s.loadClockLocked()
	if err == nil {
		err = s.recoverLocked()
	}
	if err == nil {
		s.noteTimeLocked(s.now())
		s.appendLostLocked()
	}
	s.mu.Unlock()
	if err != nil {
		_ = s.rdb.Close()
		_ = s.db.Close()
		_ = lock.Close()
		return nil, err
	}
	s.cleanTmp()
	return s, nil
}

// ensureDir makes sure dir is a real directory (never a symlink); own=true creates it 0700 and
// tightens an existing one to 0700, own=false only creates missing parents.
func ensureDir(dir string, own bool) error {
	if !own {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("store: mkdir %s: %w", dir, err)
		}
		return nil
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("store: mkdir %s: %w", dir, err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("store: %s is not a directory (a symlink is refused)", dir)
	}
	if fi.Mode().Perm() != 0o700 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("store: chmod %s: %w", dir, err)
		}
	}
	return nil
}

// cleanTmp removes what a previous run left in tmp/ (nothing else uses it before Open returns).
func (s *Store) cleanTmp() {
	ents, err := os.ReadDir(s.tmpDir)
	if err != nil {
		return
	}
	for _, e := range ents {
		if !e.IsDir() {
			_ = os.Remove(filepath.Join(s.tmpDir, e.Name()))
		}
	}
}

// TempDir is a private (0700) directory on the store's file system for other packages' temporary
// files, such as an encrypted copy of a segment being uploaded. Open empties it.
func (s *Store) TempDir() string { return s.tmpDir }

func (s *Store) now() time.Time { return s.opt.Now().UTC() }

// DiskBytes is the store's current size on disk; Segments the number of segment files; Oldest the
// capture time of the oldest event kept.
func (s *Store) DiskBytes() int64 {
	s.mu.Lock()
	n := s.segBytesLocked()
	s.mu.Unlock()
	return n + s.dbBytes()
}

func (s *Store) Segments() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.segs)
}

func (s *Store) Oldest() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	var oldest int64
	for _, g := range s.segs {
		if g.capFirst != 0 && (oldest == 0 || g.capFirst < oldest) {
			oldest = g.capFirst
		}
	}
	if oldest == 0 {
		return time.Time{}
	}
	return time.Unix(0, oldest).UTC()
}

func (s *Store) DB() *sql.DB { return s.db } // the security database, for later phases' tables

// segBytesLocked is the size of every segment file. Caller holds s.mu.
func (s *Store) segBytesLocked() int64 {
	var n int64
	for _, g := range s.segs {
		n += g.size()
	}
	return n
}

func (s *Store) dbBytes() int64 {
	var n int64
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if fi, err := os.Lstat(s.dbPath + suffix); err == nil {
			n += fi.Size()
		}
	}
	return n
}

// Close flushes the open segments and closes the database. It seals nothing: the next Open seals
// the segments that were open. A second Close does nothing.
func (s *Store) Close() error {
	s.mu.Lock()
	if s.closed.Swap(true) {
		s.mu.Unlock()
		return nil
	}
	var errs []error
	for _, g := range s.segs {
		if g.w == nil {
			continue
		}
		// Intentional: the gzip stream is finished (its trailer written) although the segment stays
		// open in the manifest, and its pending index rows are not written: the next Open seals it
		// as found and indexes it from the file. A finished stream decodes without the
		// truncated-tail error a crash leaves.
		if err := g.w.finish(); err != nil {
			errs = append(errs, fmt.Errorf("store: close %s: %w", g.name, err))
		}
		g.w, g.pending = nil, nil
	}
	if err := s.indexLocked(nil); err != nil { // rows of sealed segments still waiting for a retry
		errs = append(errs, fmt.Errorf("store: index: %w", err))
	}
	if err := s.persistClockLocked(); err != nil {
		errs = append(errs, fmt.Errorf("store: close: %w", err))
	}
	s.mu.Unlock()
	errs = append(errs, s.rdb.Close(), s.db.Close(), s.lock.Close())
	return errors.Join(errs...)
}

// acquire takes a search slot, waiting up to busyWait. The returned func releases it.
func (s *Store) acquire(ctx context.Context) (func(), error) {
	if s.closed.Load() {
		return nil, errClosed
	}
	t := time.NewTimer(s.busyWait)
	defer t.Stop()
	select {
	case s.sem <- struct{}{}:
		return func() { <-s.sem }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.C:
		return nil, ErrBusy
	}
}

// Search returns up to limit events matching q, newest first, within a scan budget. limit ≤ 0 is
// 100 and at most 1000 are returned. A query the index can answer completely (only src, app, svc,
// kind, out, lvl, actor and ip terms, no text, and restricted to classified events by a kind other
// than log/http.request or lvl ≥ warn) is answered from security.db; any other query scans the
// segments overlapping its time range, newest first. A page never ends inside a group of events
// sharing one TS unless the whole page is that group. Two searches or exports run at once; a third
// waits up to 2 seconds for one to end, then returns ErrBusy.
func (s *Store) Search(ctx context.Context, q query.Query, limit int) (Result, error) {
	if limit <= 0 {
		limit = defaultLimit
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	release, err := s.acquire(ctx)
	if err != nil {
		return Result{}, err
	}
	defer release()
	sctx, cancel := context.WithTimeout(ctx, s.searchTime)
	defer cancel()
	var r Result
	if indexable(q) {
		r, err = s.searchIndex(sctx, q, limit)
	} else {
		r, err = s.searchScan(sctx, q, limit)
	}
	if ctx.Err() != nil {
		return Result{}, ctx.Err()
	}
	return r, err
}

// Export writes every event matching q (oldest first, at most maxEvents) to w as NDJSON and
// returns how many it wrote. Events come in capture order (the order they were stored), which is
// TS order except where a source's own timestamp disagrees. maxEvents ≤ 0 is 1,000,000. An export
// that reaches its scan budget (4 GiB decompressed or 10 minutes) returns what it wrote and
// ErrBudget.
func (s *Store) Export(ctx context.Context, q query.Query, w io.Writer, maxEvents int) (int, error) {
	if maxEvents <= 0 {
		maxEvents = defaultExport
	}
	release, err := s.acquire(ctx)
	if err != nil {
		return 0, err
	}
	defer release()
	ectx, cancel := context.WithTimeout(ctx, s.exportTime)
	defer cancel()
	n, err := s.export(ectx, q, w, maxEvents)
	if ctx.Err() != nil {
		return n, ctx.Err()
	}
	return n, err
}

// AppendError is Append's error when only some of a batch was stored: the first Written events are
// in the store (segment, and the index after the next Flush), the rest are not. A caller retrying must retry only evs[Written:],
// or it stores duplicates.
type AppendError struct {
	Written int
	Err     error
}

func (e *AppendError) Error() string { return e.Err.Error() }
func (e *AppendError) Unwrap() error { return e.Err }
