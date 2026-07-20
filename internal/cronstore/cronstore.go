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
	_, err := s.db.ExecContext(ctx, `DELETE FROM scheduled_task_runs WHERE slug=?`, slug)
	return err
}
