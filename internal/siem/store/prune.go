package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"time"
)

// Prune removes segments past HotRetention, then the oldest archived ones while over
// MaxDiskBytes; an unarchived segment goes only past HotRetention + 7 days or, over the disk cap,
// when nothing archived is left (each such loss is logged and recorded as a KindDropped event).
// Open segments are never removed. A segment's index rows go with it. Prune first seals what
// SealDue would, so calling Prune periodically is enough when no archiver runs.
//
// The disk cap counts the segments and the database's live pages (free pages waiting to be
// returned to the file system don't count). It never removes the newest sealed segment that isn't
// archived, so a cap smaller than the database and the open segment can't empty the store. Long
// jobs (removing a large segment's index rows, returning free pages) run in bounded steps and let
// go of the lock between them, so Append and searches aren't held up. Prune also applies the
// disk-pressure check (see Options.DiskUsage) and the clock-step latch (see noteTimeLocked).
func (s *Store) Prune() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed.Load() {
		return errClosed
	}
	now := s.now()
	s.noteTimeLocked(now)
	errs := []error{s.sealDueLocked(), s.resumeRowGCLocked()}
	if s.closed.Load() {
		return errClosed
	}
	for _, g := range slices.Clone(s.segs) {
		if g.open || slices.Index(s.segs, g) < 0 {
			continue
		}
		ageCut := s.ageNowLocked(g, now).Add(-s.opt.HotRetention)
		end := g.hour.Add(time.Hour)
		switch {
		// Intentional: with no archive configured nothing will ever upload a segment, so its
		// archived state is ignored and the retention alone decides.
		case g.archivedAt != 0 || !s.opt.ArchiveConfigured:
			if !end.After(ageCut) {
				errs = append(errs, s.removeLocked(g, ""))
			}
		default:
			if !end.After(ageCut.Add(-unarchivedGrace)) {
				errs = append(errs, s.removeLocked(g, "not archived within the retention + 7 days"))
			}
		}
		if s.closed.Load() {
			return errClosed
		}
	}
	if s.latchAt == 0 {
		// The seq records of hours long gone (not while the clock is in doubt).
		cut := now.Add(-s.opt.HotRetention - unarchivedGrace - 24*time.Hour)
		if _, err := s.exec(`DELETE FROM seqs WHERE hour < ? AND NOT EXISTS (SELECT 1 FROM segments WHERE segments.hour = seqs.hour)`,
			cut.Unix()); err != nil {
			errs = append(errs, fmt.Errorf("store: prune seqs: %w", err))
		}
	}
	s.releaseLatchIfDoneLocked()
	errs = append(errs, s.enforceCapLocked())
	if s.closed.Load() {
		return errClosed
	}
	s.pressureLocked(true)
	if s.closed.Load() {
		return errClosed
	}
	errs = append(errs, s.vacuumLocked(), s.persistClockLocked())
	s.appendLostLocked()
	return errors.Join(errs...)
}

// defaultJumpAfter: a forward step of the clock larger than this between two of the store's
// observations of it (Append, SealDue, Prune, Open) is taken as a clock step, or a stop that long.
const defaultJumpAfter = 6 * time.Hour

var jumpAfter = defaultJumpAfter // tests change it

// noteTimeLocked records now as the store's view of the clock. A forward step larger than
// jumpAfter sets the latch: latchAt is the time before the step, jumpedTo when it was seen. While
// latched, segments captured up to latchAt are aged by latchAt + (now − jumpedTo), the time that
// passed since the step, instead of by now, so a clock that steps ahead never makes them look
// expired; a further step while latched moves jumpedTo by its size. A backward step larger than
// jumpAfter (the clock put right) releases the latch, and so does Prune once no segment from
// before the step is left. Mistaking a stop of the service for a step only keeps those segments
// longer by that long. Caller holds s.mu.
func (s *Store) noteTimeLocked(now time.Time) {
	n := now.UnixNano()
	switch d := n - s.lastSeen; {
	case s.lastSeen == 0:
	case d > int64(jumpAfter):
		if s.latchAt == 0 {
			s.latchAt, s.jumpedTo = s.lastSeen, n
		} else {
			s.jumpedTo += d
		}
		s.opt.Log.Warn("siem store: the clock stepped forward (or the store was stopped that long); segments captured before are aged by the time passed since",
			"step", time.Duration(d), "before", nsTime(s.lastSeen))
		if err := s.persistClockLocked(); err != nil {
			s.opt.Log.Error("siem store: cannot record the clock step", "err", err)
		}
	case d < -int64(jumpAfter) && s.latchAt != 0:
		s.latchAt, s.jumpedTo = 0, 0
		s.opt.Log.Info("siem store: the clock stepped back; segments are aged by the clock again", "step", time.Duration(-d))
		if err := s.persistClockLocked(); err != nil {
			s.opt.Log.Error("siem store: cannot record the clock step", "err", err)
		}
	}
	s.lastSeen = n
}

// ageNowLocked is the time g's age is measured against (see noteTimeLocked). Caller holds s.mu.
func (s *Store) ageNowLocked(g *seg, now time.Time) time.Time {
	if s.latchAt != 0 && g.hour.UnixNano() <= s.latchAt {
		return nsTime(s.latchAt + (now.UnixNano() - s.jumpedTo))
	}
	return now
}

// releaseLatchIfDoneLocked releases the latch once no segment captured before the step is left.
// Caller holds s.mu.
func (s *Store) releaseLatchIfDoneLocked() {
	if s.latchAt == 0 {
		return
	}
	for _, g := range s.segs {
		if g.hour.UnixNano() <= s.latchAt {
			return
		}
	}
	s.latchAt, s.jumpedTo = 0, 0
	s.opt.Log.Info("siem store: every segment from before the clock step is gone; segments are aged by the clock again")
	if err := s.persistClockLocked(); err != nil {
		s.opt.Log.Error("siem store: cannot record the clock latch", "err", err)
	}
}

func (s *Store) persistClockLocked() error {
	_, err := s.exec(`INSERT INTO clock(id, last_seen, latch_at, jumped_to) VALUES (1, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET last_seen = excluded.last_seen, latch_at = excluded.latch_at, jumped_to = excluded.jumped_to`,
		s.lastSeen, s.latchAt, s.jumpedTo)
	return err
}

func (s *Store) loadClockLocked() error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	err := s.db.QueryRowContext(ctx, `SELECT last_seen, latch_at, jumped_to FROM clock WHERE id = 1`).Scan(&s.lastSeen, &s.latchAt, &s.jumpedTo)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	return err
}

// dbLiveBytes is the size of the database's pages in use (free pages not counted).
func (s *Store) dbLiveBytes() int64 {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	var pages, free, size int64
	if s.db.QueryRowContext(ctx, `PRAGMA page_count`).Scan(&pages) != nil ||
		s.db.QueryRowContext(ctx, `PRAGMA freelist_count`).Scan(&free) != nil ||
		s.db.QueryRowContext(ctx, `PRAGMA page_size`).Scan(&size) != nil {
		return s.dbBytes()
	}
	return (pages - free) * size
}

// enforceCapLocked removes segments while the segments and the database's live pages are over
// MaxDiskBytes, measuring after each removal. Caller holds s.mu (released between steps).
func (s *Store) enforceCapLocked() error {
	for s.segBytesLocked()+s.dbLiveBytes() > s.opt.MaxDiskBytes {
		g, reason := s.capVictimLocked()
		if g == nil {
			if !s.capWarned {
				s.capWarned = true
				s.opt.Log.Warn("siem store: over its disk cap with only the newest hour left; raise security_logs.hot_max_disk_mb",
					"bytes", s.segBytesLocked()+s.dbLiveBytes(), "cap", s.opt.MaxDiskBytes)
			}
			return nil
		}
		if err := s.removeLocked(g, reason); err != nil {
			return err
		}
		if s.closed.Load() {
			return errClosed
		}
	}
	s.capWarned = false
	return nil
}

func fileSize(p string) int64 {
	fi, err := os.Lstat(p)
	if err != nil {
		return 0
	}
	return fi.Size()
}

// capVictimLocked is the next segment to remove over the disk cap: the oldest archived one, else
// the oldest unarchived one but the newest (a loss). Caller holds s.mu.
func (s *Store) capVictimLocked() (*seg, string) {
	var newest *seg // the newest sealed segment not archived: kept, so an impossible cap can't empty the store
	for _, g := range s.segs {
		if !g.open && g.archivedAt != 0 {
			return g, ""
		}
		if !g.open {
			newest = g
		}
	}
	for _, g := range s.segs {
		if !g.open && g != newest {
			return g, "disk cap"
		}
	}
	return nil, ""
}

// removeLocked deletes a sealed segment: its file, its manifest row (queuing its index rows in
// row_gc, in the same transaction) and then its index rows, in batches with the lock let go
// between them. Index rows still waiting for a retry go with it. A non-empty lostReason records
// the removal as a loss. A segment already removed (while the lock was let go) is left alone.
// Caller holds s.mu (released between steps).
func (s *Store) removeLocked(g *seg, lostReason string) error {
	if slices.Index(s.segs, g) < 0 {
		return nil
	}
	if err := os.Remove(filepath.Join(s.segDir, g.name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("store: remove %s: %w", g.name, err)
	}
	s.dropSegLocked(g)
	s.retryRows = slices.DeleteFunc(s.retryRows, func(r indexRow) bool { return r.segment == g.name })
	if lostReason != "" {
		s.loseLocked(g.name, g.events, lostReason)
	}
	err := s.tx(func(ctx context.Context, tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM segments WHERE name = ?`, g.name); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO row_gc(segment) VALUES (?)`, g.name)
		return err
	})
	if err != nil {
		return fmt.Errorf("store: remove %s: %w", g.name, err)
	}
	return s.gcRowsLocked(g.name)
}

// gcRowsLocked deletes the index rows of segment name, deleteChunk per statement with the lock
// let go between statements, then its row_gc entry.
//
// Intentional: index rows are removed with their segment rather than by their own TS, so a search
// answers the same from the index as from a scan of the segments. Caller holds s.mu (released
// between steps).
func (s *Store) gcRowsLocked(name string) error {
	for {
		res, err := s.exec(`DELETE FROM events WHERE id IN (SELECT id FROM events WHERE segment = ? LIMIT ?)`, name, s.deleteChunk)
		if err != nil {
			return fmt.Errorf("store: remove the index rows of %s: %w", name, err)
		}
		if n, err := res.RowsAffected(); err != nil || n < int64(s.deleteChunk) {
			break
		}
		if err := s.pauseLocked(); err != nil {
			return err
		}
	}
	if _, err := s.exec(`DELETE FROM row_gc WHERE segment = ?`, name); err != nil {
		return fmt.Errorf("store: remove the index rows of %s: %w", name, err)
	}
	return nil
}

// resumeRowGCLocked finishes removing the index rows of segments a previous run removed (a crash
// in the middle). Caller holds s.mu (released between steps).
func (s *Store) resumeRowGCLocked() error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	rows, err := s.db.QueryContext(ctx, `SELECT segment FROM row_gc`)
	if err != nil {
		cancel()
		return fmt.Errorf("store: read row_gc: %w", err)
	}
	var names []string
	for rows.Next() {
		var n string
		if rows.Scan(&n) == nil {
			names = append(names, n)
		}
	}
	err = rows.Err()
	rows.Close()
	cancel()
	if err != nil {
		return fmt.Errorf("store: read row_gc: %w", err)
	}
	for _, n := range names {
		if err := s.gcRowsLocked(n); err != nil {
			return err
		}
	}
	return nil
}

// pauseLocked lets go of s.mu between two steps of a long job, so a waiting Append or search runs.
// Caller holds s.mu; anything it read under the lock may have changed when this returns.
func (s *Store) pauseLocked() error {
	s.mu.Unlock()
	if s.betweenSteps != nil {
		s.betweenSteps()
	}
	runtime.Gosched()
	s.mu.Lock()
	if s.closed.Load() {
		return errClosed
	}
	return nil
}

// vacuumLocked returns the database's free pages to the file system, vacuumStep pages per
// statement and each keeping its work, for at most vacuumBudget (at least one step), letting go of
// the lock between steps; the next call carries on. Then it truncates the WAL. Caller holds s.mu
// (released between steps).
func (s *Store) vacuumLocked() error {
	deadline := time.Now().Add(s.vacuumBudget)
	for {
		var free int64
		if err := s.db.QueryRow(`PRAGMA freelist_count`).Scan(&free); err != nil {
			return fmt.Errorf("store: vacuum: %w", err)
		}
		if free == 0 {
			break
		}
		// Intentional: the step is formatted into the statement because a PRAGMA takes no bound
		// parameters; it is this package's own integer, never input.
		if _, err := s.exec(fmt.Sprintf(`PRAGMA incremental_vacuum(%d)`, s.vacuumStep)); err != nil {
			return fmt.Errorf("store: vacuum: %w", err)
		}
		if !time.Now().Before(deadline) {
			break
		}
		if err := s.pauseLocked(); err != nil {
			return err
		}
	}
	s.checkpointLocked()
	return nil
}

// checkpointLocked truncates the WAL, waiting at most 250ms for a search reading an older snapshot
// (it is then left for the next call). Caller holds s.mu.
func (s *Store) checkpointLocked() {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, `PRAGMA busy_timeout = 250`); err != nil {
		return
	}
	defer conn.ExecContext(ctx, `PRAGMA busy_timeout = 5000`)
	var busy, frames, done int
	_ = conn.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &frames, &done)
}

// pressureLocked reports whether the filesystem is at or above DiskThresholdPct, sampling it at
// most every diskCheckEvery (force: now). At or above it, archived segments are removed, oldest
// first and sampling again after each, until it is below; unarchived segments are kept (they have
// no other copy), and Append refuses events while the pressure lasts. Caller holds s.mu (released
// between steps).
func (s *Store) pressureLocked(force bool) bool {
	if s.opt.DiskUsage == nil || s.opt.DiskThresholdPct <= 0 {
		return false
	}
	now := s.now()
	if d := now.Sub(s.diskCheckedAt); !force && !s.diskCheckedAt.IsZero() && d >= 0 && d < diskCheckEvery {
		return s.pressure
	}
	s.diskCheckedAt = now
	over := s.overThresholdLocked()
	for over && !s.closed.Load() {
		var g *seg
		for _, x := range s.segs {
			if !x.open && x.archivedAt != 0 {
				g = x
				break
			}
		}
		if g == nil {
			break
		}
		if err := s.removeLocked(g, ""); err != nil {
			s.opt.Log.Error("siem store: cannot remove an archived segment under disk pressure", "segment", g.name, "err", err)
			break
		}
		if err := s.vacuumLocked(); err != nil {
			break
		}
		over = s.overThresholdLocked()
	}
	switch {
	case over && !s.pressure:
		s.opt.Log.Warn("siem store: disk usage at or above the threshold; refusing new security-log events",
			"threshold_pct", s.opt.DiskThresholdPct)
	case !over && s.pressure:
		s.opt.Log.Info("siem store: disk usage below the threshold; storing security-log events again")
	}
	s.pressure = over
	return over
}

// overThresholdLocked samples DiskUsage; an unknown reading keeps the current state.
func (s *Store) overThresholdLocked() bool {
	used, total, ok := s.opt.DiskUsage()
	if !ok || total == 0 {
		return s.pressure
	}
	return float64(used)/float64(total)*100 >= s.opt.DiskThresholdPct
}
