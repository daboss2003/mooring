// Package cronstore persists the last-run time + outcome of each app's scheduled tasks, so the
// scheduler knows when a task is next due and a restart doesn't re-fire everything.
package cronstore

import (
	"context"
	"database/sql"
	"errors"

	"github.com/daboss2003/mooring/internal/store"
)

// Store records scheduled-task runs.
type Store struct{ db *store.DB }

// New builds a Store.
func New(db *store.DB) *Store { return &Store{db: db} }

// Run is one task's last-run bookkeeping.
type Run struct {
	LastRun int64
	LastOK  bool
}

// Get returns the last run for (slug, task); zero value (LastRun=0) if never run.
func (s *Store) Get(ctx context.Context, slug, task string) (Run, error) {
	var r Run
	var ok int
	err := s.db.QueryRowContext(ctx,
		`SELECT last_run, last_ok FROM scheduled_task_runs WHERE slug=? AND task=?`, slug, task).
		Scan(&r.LastRun, &ok)
	if errors.Is(err, sql.ErrNoRows) {
		return Run{}, nil
	}
	if err != nil {
		return Run{}, err
	}
	r.LastOK = ok != 0
	return r, nil
}

// Record upserts the last-run time + outcome for a task.
func (s *Store) Record(ctx context.Context, slug, task string, at int64, ok bool) error {
	okI := 0
	if ok {
		okI = 1
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO scheduled_task_runs(slug, task, last_run, last_ok) VALUES(?,?,?,?)
		 ON CONFLICT(slug, task) DO UPDATE SET last_run=excluded.last_run, last_ok=excluded.last_ok`,
		slug, task, at, okI)
	return err
}

// DeleteApp removes all scheduled-task rows for a slug (app teardown).
func (s *Store) DeleteApp(ctx context.Context, slug string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM scheduled_task_runs WHERE slug=?`, slug); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM scheduled_task_history WHERE slug=?`, slug)
	return err
}

// --- per-run history (the operator-facing run log) ---

// HistoryRow is one recorded scheduled-task run. While a run is in flight, Finished is false and
// FinishedAt/OK are zero. Log is populated only by GetRun (the listing queries omit it).
type HistoryRow struct {
	ID         int64
	Slug       string // the app that owns the task
	Task       string
	Service    string
	StartedAt  int64
	FinishedAt int64 // 0 while running
	Finished   bool
	OK         bool
	ExitCode   int
	Detail     string
	Log        string
}

// Running reports whether the run is still in flight.
func (r HistoryRow) Running() bool { return !r.Finished }

const (
	maxCronLogBytes = 64 << 10
	maxCronDetail   = 500
)

// StartRun records the start of a task run (a "running" row) and returns its id.
func (s *Store) StartRun(ctx context.Context, slug, task, service string, at int64) (int64, error) {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO scheduled_task_history(slug, task, service, started_at) VALUES(?,?,?,?)`,
		slug, task, service, at)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// FinishRun records the outcome of a run started with StartRun. The log is bounded (tail kept, where
// the error usually is) so a chatty task can't bloat the DB.
func (s *Store) FinishRun(ctx context.Context, id, at int64, ok bool, exitCode int, detail, log string) error {
	if id == 0 {
		return nil
	}
	if len(log) > maxCronLogBytes {
		log = log[len(log)-maxCronLogBytes:]
	}
	if len(detail) > maxCronDetail {
		detail = detail[:maxCronDetail]
	}
	okI := 0
	if ok {
		okI = 1
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE scheduled_task_history SET finished_at=?, ok=?, exit_code=?, detail=?, log=? WHERE id=?`,
		at, okI, exitCode, detail, log, id)
	return err
}

// History returns one page of run history (newest first), for one app (slug != "") or all apps
// (slug == ""). It fetches limit+1 in a single query so the caller can page without a COUNT (no
// nested query — the single-conn DB forbids that). The (large) log column is NOT fetched here.
func (s *Store) History(ctx context.Context, slug string, limit, offset int) (out []HistoryRow, hasMore bool, err error) {
	if limit <= 0 {
		limit = 20
	}
	if offset < 0 {
		offset = 0
	}
	const cols = `id, slug, task, service, started_at, finished_at, ok, exit_code, detail`
	var rows *sql.Rows
	if slug == "" {
		rows, err = s.db.QueryContext(ctx, `SELECT `+cols+` FROM scheduled_task_history ORDER BY started_at DESC, id DESC LIMIT ? OFFSET ?`, limit+1, offset)
	} else {
		rows, err = s.db.QueryContext(ctx, `SELECT `+cols+` FROM scheduled_task_history WHERE slug=? ORDER BY started_at DESC, id DESC LIMIT ? OFFSET ?`, slug, limit+1, offset)
	}
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	for rows.Next() {
		r, serr := scanHistory(rows)
		if serr != nil {
			return nil, false, serr
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	if len(out) > limit {
		hasMore = true
		out = out[:limit]
	}
	return out, hasMore, nil
}

// Running returns every in-flight run (finished_at IS NULL), oldest first.
func (s *Store) Running(ctx context.Context) ([]HistoryRow, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, slug, task, service, started_at, finished_at, ok, exit_code, detail FROM scheduled_task_history WHERE finished_at IS NULL ORDER BY started_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HistoryRow
	for rows.Next() {
		r, serr := scanHistory(rows)
		if serr != nil {
			return nil, serr
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// GetRun returns one run WITH its captured log (for the log view); ok=false if the id is unknown.
func (s *Store) GetRun(ctx context.Context, id int64) (HistoryRow, bool, error) {
	var r HistoryRow
	var fin, ok sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT id, slug, task, service, started_at, finished_at, ok, exit_code, detail, log FROM scheduled_task_history WHERE id=?`, id).
		Scan(&r.ID, &r.Slug, &r.Task, &r.Service, &r.StartedAt, &fin, &ok, &r.ExitCode, &r.Detail, &r.Log)
	if errors.Is(err, sql.ErrNoRows) {
		return HistoryRow{}, false, nil
	}
	if err != nil {
		return HistoryRow{}, false, err
	}
	if fin.Valid {
		r.Finished, r.FinishedAt = true, fin.Int64
	}
	if ok.Valid {
		r.OK = ok.Int64 != 0
	}
	return r, true, nil
}

// scanHistory scans the common (log-less) column set into a HistoryRow.
func scanHistory(rows *sql.Rows) (HistoryRow, error) {
	var r HistoryRow
	var fin, ok sql.NullInt64
	if err := rows.Scan(&r.ID, &r.Slug, &r.Task, &r.Service, &r.StartedAt, &fin, &ok, &r.ExitCode, &r.Detail); err != nil {
		return HistoryRow{}, err
	}
	if fin.Valid {
		r.Finished, r.FinishedAt = true, fin.Int64
	}
	if ok.Valid {
		r.OK = ok.Int64 != 0
	}
	return r, nil
}

// PruneHistory deletes FINISHED runs whose start is older than olderThan (unix seconds). In-flight
// runs are never pruned. The TTL is the operator-facing retention (default 7 days).
func (s *Store) PruneHistory(ctx context.Context, olderThan int64) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM scheduled_task_history WHERE finished_at IS NOT NULL AND started_at < ?`, olderThan)
	return err
}

// ReconcileRunningOnBoot marks any run still flagged running as finished+interrupted. A one-shot cron
// container cannot survive a Mooring restart, so a leftover "running" row is a phantom — clearing it
// on boot keeps the "running now" view honest.
func (s *Store) ReconcileRunningOnBoot(ctx context.Context, at int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE scheduled_task_history SET finished_at=?, ok=0, exit_code=-1, detail='interrupted — Mooring restarted mid-run' WHERE finished_at IS NULL`, at)
	return err
}
