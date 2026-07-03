package imagescan

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/daboss2003/mooring/internal/store"
)

// Store persists the latest per-app scan result.
type Store struct{ db *store.DB }

// NewStore builds a Store over the shared single-conn DB.
func NewStore(db *store.DB) *Store { return &Store{db: db} }

// AppScan is one app's latest scan: aggregate counts + the per-target detail.
type AppScan struct {
	Project   string
	ScannedAt int64
	Critical  int
	High      int
	Medium    int
	Low       int
	Reports   []Report
	Error     string
}

// Total counts all findings; Actionable is High+Critical present.
func (a AppScan) Total() int       { return a.Critical + a.High + a.Medium + a.Low }
func (a AppScan) Actionable() bool { return a.Critical > 0 || a.High > 0 }

// Save upserts an app's scan result.
func (s *Store) Save(ctx context.Context, a AppScan) error {
	blob, _ := json.Marshal(a.Reports)
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO image_scans(project, scanned_at, critical, high, medium, low, report_json, error)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(project) DO UPDATE SET
		   scanned_at=excluded.scanned_at, critical=excluded.critical, high=excluded.high,
		   medium=excluded.medium, low=excluded.low, report_json=excluded.report_json, error=excluded.error`,
		a.Project, a.ScannedAt, a.Critical, a.High, a.Medium, a.Low, blob, a.Error)
	return err
}

// Get returns one app's scan (ok=false if never scanned).
func (s *Store) Get(ctx context.Context, project string) (AppScan, bool, error) {
	var a AppScan
	var blob []byte
	err := s.db.QueryRowContext(ctx,
		`SELECT project, scanned_at, critical, high, medium, low, report_json, error FROM image_scans WHERE project=?`, project).
		Scan(&a.Project, &a.ScannedAt, &a.Critical, &a.High, &a.Medium, &a.Low, &blob, &a.Error)
	if errors.Is(err, sql.ErrNoRows) {
		return AppScan{}, false, nil
	}
	if err != nil {
		return AppScan{}, false, err
	}
	_ = json.Unmarshal(blob, &a.Reports)
	return a, true, nil
}

// List returns every app's scan, newest-first. It selects all columns in ONE query
// and never issues a per-row nested query while the rows are open (the single-conn
// SQLite self-deadlock rule).
func (s *Store) List(ctx context.Context) ([]AppScan, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT project, scanned_at, critical, high, medium, low, report_json, error
		   FROM image_scans ORDER BY (critical*1000 + high) DESC, scanned_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AppScan
	for rows.Next() {
		var a AppScan
		var blob []byte
		if err := rows.Scan(&a.Project, &a.ScannedAt, &a.Critical, &a.High, &a.Medium, &a.Low, &blob, &a.Error); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(blob, &a.Reports)
		out = append(out, a)
	}
	return out, rows.Err()
}

// Delete removes an app's scan row (app teardown).
func (s *Store) Delete(ctx context.Context, project string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM image_scans WHERE project=?`, project)
	return err
}
