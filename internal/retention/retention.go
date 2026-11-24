// Package retention bounds Mooring's own audit/events table so it can never
// become the disk-wedge that kills the write plane (plan §16.1). It is read-plane
// (it only prunes its own rows) and runs precisely when the box is small.
//
// The cardinal invariant: a level=security audit row is NEVER silently dropped.
// Every security row that is about to be pruned is first appended to a rotated
// NDJSON archive; if that append fails, the whole pass aborts WITHOUT deleting
// anything (fail-closed) — losing audit evidence is never acceptable.
package retention

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/daboss2003/mooring/internal/store"
)

// Config is the live, SIGHUP-reloadable retention policy (plan §16.1 Tier-1).
type Config struct {
	Interval        time.Duration
	EventsMaxAge    time.Duration
	EventsMaxRows   int
	ArchiveMaxBytes int64
}

// batchSize bounds each DELETE so retention never holds a long write lock on a
// small box (plan §16.1: bounded "DELETE … WHERE …" batches).
const batchSize = 500

// Runner prunes the events table on a ticker. Construct with New; drive with Run.
type Runner struct {
	db          *store.DB
	log         *slog.Logger
	archivePath string
	cfg         atomic.Pointer[Config]
}

// New builds a Runner. archiveDir is where the security-row NDJSON archive lives
// (Mooring's own data dir); cfg is the initial (reloadable) policy.
func New(db *store.DB, log *slog.Logger, archiveDir string, cfg Config) *Runner {
	r := &Runner{db: db, log: log, archivePath: filepath.Join(archiveDir, "events-archive.ndjson")}
	r.cfg.Store(&cfg)
	return r
}

// SetConfig hot-swaps the policy (called from the SIGHUP path). Cheap + atomic.
func (r *Runner) SetConfig(cfg Config) { r.cfg.Store(&cfg) }

func (r *Runner) config() Config { return *r.cfg.Load() }

// Run executes one pass shortly after start, then every Interval, until ctx is
// cancelled. A pass error is logged and paged (security level) but never panics.
func (r *Runner) Run(ctx context.Context) {
	// A short initial delay lets boot settle before the first (bounded) pass.
	select {
	case <-ctx.Done():
		return
	case <-time.After(30 * time.Second):
	}
	r.runPass(ctx)
	t := time.NewTicker(r.config().Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.runPass(ctx)
			// Honor a reloaded interval for the next tick.
			t.Reset(r.config().Interval)
		}
	}
}

func (r *Runner) runPass(ctx context.Context) {
	deleted, err := r.Pass(ctx)
	if err != nil {
		// A retention failure is itself a security-relevant event: it means the
		// audit table may grow unbounded OR (worse) we could not preserve a
		// security row. Page it; never proceed past the failure.
		r.log.Error("retention pass failed (audit growth / archive integrity at risk)", "err", err)
		return
	}
	if deleted > 0 {
		r.log.Info("retention pass complete", "events_pruned", deleted)
	}
}

// Pass runs one full retention pass over the events table and returns the number
// of rows pruned. Exported for tests + on-demand invocation.
func (r *Runner) Pass(ctx context.Context) (int, error) {
	cfg := r.config()
	total := 0

	// 1) Age-based prune: rows older than EventsMaxAge, batch by batch.
	cutoff := time.Now().Add(-cfg.EventsMaxAge).Unix()
	for {
		n, err := r.pruneBatch(ctx,
			`SELECT seq, ts, actor, ip, action, target, outcome, level, detail, user_agent
			   FROM events WHERE ts < ? ORDER BY seq LIMIT ?`,
			[]any{cutoff, batchSize},
			func(lastSeq int64) (string, []any) {
				// Exactly the just-read batch: ts<cutoff AND seq<=lastSeq (new rows
				// get a higher seq, so none can sneak in between read and delete).
				return `DELETE FROM events WHERE ts < ? AND seq <= ?`, []any{cutoff, lastSeq}
			})
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			break
		}
	}

	// 2) Hard row cap: trim the oldest rows beyond EventsMaxRows, one batch at a
	// time, re-counting each round so we never over-delete.
	for {
		var count int
		if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events`).Scan(&count); err != nil {
			return total, fmt.Errorf("retention: count events: %w", err)
		}
		excess := count - cfg.EventsMaxRows
		if excess <= 0 {
			break
		}
		lim := excess
		if lim > batchSize {
			lim = batchSize
		}
		n, err := r.pruneBatch(ctx,
			`SELECT seq, ts, actor, ip, action, target, outcome, level, detail, user_agent
			   FROM events ORDER BY seq LIMIT ?`,
			[]any{lim},
			func(lastSeq int64) (string, []any) {
				// The oldest `lim` rows are exactly those with seq<=lastSeq.
				return `DELETE FROM events WHERE seq <= ?`, []any{lastSeq}
			})
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			break // nothing matched (shouldn't happen, but never spin)
		}
	}

	if total > 0 {
		// Bound the WAL after a pruning pass (cheap; full VACUUM is M18/§16.1).
		_, _ = r.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`)
	}
	return total, nil
}

// eventRow is the archived shape of one audit row.
type eventRow struct {
	Seq     int64  `json:"seq"`
	TS      int64  `json:"ts"`
	Actor   string `json:"actor"`
	IP      string `json:"ip"`
	Action  string `json:"action"`
	Target  string `json:"target"`
	Outcome string `json:"outcome"`
	Level   string `json:"level"`
	Detail  string `json:"detail"`
	UA      string `json:"ua,omitempty"`
}

// pruneBatch reads ONE batch via selectSQL, archives the security rows in it
// (fail-closed), then deletes exactly that batch via delSQL(lastSeq). It returns
// the number of rows deleted (0 when the batch is empty). The caller loops.
func (r *Runner) pruneBatch(ctx context.Context, selectSQL string, selectArgs []any, delSQL func(lastSeq int64) (string, []any)) (int, error) {
	rows, err := r.db.QueryContext(ctx, selectSQL, selectArgs...)
	if err != nil {
		return 0, fmt.Errorf("retention: select batch: %w", err)
	}
	var batch []eventRow
	var lastSeq int64
	for rows.Next() {
		var e eventRow
		if err := rows.Scan(&e.Seq, &e.TS, &e.Actor, &e.IP, &e.Action, &e.Target, &e.Outcome, &e.Level, &e.Detail, &e.UA); err != nil {
			rows.Close()
			return 0, fmt.Errorf("retention: scan: %w", err)
		}
		batch = append(batch, e)
		lastSeq = e.Seq
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, fmt.Errorf("retention: rows: %w", err)
	}
	rows.Close()
	if len(batch) == 0 {
		return 0, nil
	}

	// Archive every security row in this batch BEFORE deleting anything. A
	// failure here aborts the pass with nothing deleted (fail-closed).
	if err := r.archiveSecurity(batch); err != nil {
		return 0, err
	}

	sql, args := delSQL(lastSeq)
	res, err := r.db.ExecContext(ctx, sql, args...)
	if err != nil {
		return 0, fmt.Errorf("retention: delete batch: %w", err)
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// archiveSecurity appends the level=security rows in batch to the NDJSON archive
// (0600), rotating first if the file would exceed the size budget. It fsyncs so a
// crash can't lose a row we are about to delete. Any error means "do not delete".
func (r *Runner) archiveSecurity(batch []eventRow) error {
	var sec []eventRow
	for _, e := range batch {
		if e.Level == "security" {
			sec = append(sec, e)
		}
	}
	if len(sec) == 0 {
		return nil
	}
	if err := r.maybeRotate(); err != nil {
		return err
	}
	f, err := os.OpenFile(r.archivePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("retention: open archive: %w", err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	for i := range sec {
		if err := enc.Encode(&sec[i]); err != nil {
			return fmt.Errorf("retention: write archive: %w", err)
		}
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("retention: fsync archive: %w", err)
	}
	return nil
}

// maybeRotate renames the archive to a single ".1" backup once it exceeds the
// size budget (bounded disk use; the previous ".1" is overwritten).
func (r *Runner) maybeRotate() error {
	cfg := r.config()
	fi, err := os.Stat(r.archivePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("retention: stat archive: %w", err)
	}
	if fi.Size() < cfg.ArchiveMaxBytes {
		return nil
	}
	if err := os.Rename(r.archivePath, r.archivePath+".1"); err != nil {
		return fmt.Errorf("retention: rotate archive: %w", err)
	}
	return nil
}
