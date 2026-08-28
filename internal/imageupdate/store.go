// Package imageupdate detects when a newer image is available for a PULL-IMAGE app
// service (a service that runs `image: postgres:16` rather than a git build). It is the
// image-side analog of the git poller's "update available": the git poller tells you a
// connected repo has new commits to deploy; this tells you a pinned image tag now resolves
// to a newer digest in its registry, so a redeploy would pull it. Like the git poller it is
// ADVISORY only — Mooring never auto-pulls (it never auto-deploys); it surfaces the update
// and, optionally, alerts.
//
// Feasibility note: the registry digest is NOT reachable over Mooring's read plane (the
// socket-proxy denies IMAGES + DISTRIBUTION on purpose), so the check runs on the write-plane
// `docker` CLI — the same binary that deploys — using metadata-only commands (no layer pull).
package imageupdate

import (
	"context"
	"database/sql"
	"errors"

	"github.com/daboss2003/mooring/internal/store"
)

// Store persists the latest per-service image-update state (current state, no history).
type Store struct{ db *store.DB }

// NewStore builds a Store over the shared single-conn DB.
func NewStore(db *store.DB) *Store { return &Store{db: db} }

// Row is one service's image-update state.
type Row struct {
	Project         string
	Service         string
	ImageRef        string
	DeployedDigest  string
	LatestDigest    string
	UpdateAvailable bool
	CheckedAt       int64
	Error           string
}

// Save upserts one service's state.
func (s *Store) Save(ctx context.Context, r Row) error {
	upd := 0
	if r.UpdateAvailable {
		upd = 1
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO image_service_updates(project, service, image_ref, deployed_digest, latest_digest, update_available, checked_at, error)
		 VALUES(?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(project, service) DO UPDATE SET
		   image_ref=excluded.image_ref, deployed_digest=excluded.deployed_digest,
		   latest_digest=excluded.latest_digest, update_available=excluded.update_available,
		   checked_at=excluded.checked_at, error=excluded.error`,
		r.Project, r.Service, r.ImageRef, r.DeployedDigest, r.LatestDigest, upd, r.CheckedAt, r.Error)
	return err
}

// List returns every service's state, updates-available first then by app/service. It selects
// all columns in ONE query and never issues a per-row nested query while the rows are open (the
// single-conn SQLite self-deadlock rule).
func (s *Store) List(ctx context.Context) ([]Row, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT project, service, image_ref, deployed_digest, latest_digest, update_available, checked_at, error
		   FROM image_service_updates
		  ORDER BY update_available DESC, project ASC, service ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Row
	for rows.Next() {
		var r Row
		var upd int
		var checked sql.NullInt64
		if err := rows.Scan(&r.Project, &r.Service, &r.ImageRef, &r.DeployedDigest, &r.LatestDigest, &upd, &checked, &r.Error); err != nil {
			return nil, err
		}
		r.UpdateAvailable = upd != 0
		r.CheckedAt = checked.Int64
		out = append(out, r)
	}
	return out, rows.Err()
}

// Get returns one service's state (ok=false if never checked).
func (s *Store) Get(ctx context.Context, project, service string) (Row, bool, error) {
	var r Row
	var upd int
	var checked sql.NullInt64
	err := s.db.QueryRowContext(ctx,
		`SELECT project, service, image_ref, deployed_digest, latest_digest, update_available, checked_at, error
		   FROM image_service_updates WHERE project=? AND service=?`, project, service).
		Scan(&r.Project, &r.Service, &r.ImageRef, &r.DeployedDigest, &r.LatestDigest, &upd, &checked, &r.Error)
	if errors.Is(err, sql.ErrNoRows) {
		return Row{}, false, nil
	}
	if err != nil {
		return Row{}, false, err
	}
	r.UpdateAvailable = upd != 0
	r.CheckedAt = checked.Int64
	return r, true, nil
}

// Delete removes an app's rows (app teardown).
func (s *Store) Delete(ctx context.Context, project string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM image_service_updates WHERE project=?`, project)
	return err
}

// PruneExcept removes rows for services that no longer exist in the live set (an app dropped a
// pull-image service, or switched it to a build). keep maps project → set of live service names.
// It reads all (project, service) keys in one query, then deletes the stale ones after the rows are
// closed — never a nested query while iterating (the single-conn rule).
func (s *Store) PruneExcept(ctx context.Context, keep map[string]map[string]bool) error {
	rows, err := s.db.QueryContext(ctx, `SELECT project, service FROM image_service_updates`)
	if err != nil {
		return err
	}
	type key struct{ project, service string }
	var stale []key
	for rows.Next() {
		var k key
		if err := rows.Scan(&k.project, &k.service); err != nil {
			rows.Close()
			return err
		}
		if !keep[k.project][k.service] {
			stale = append(stale, k)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, k := range stale {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM image_service_updates WHERE project=? AND service=?`, k.project, k.service); err != nil {
			return err
		}
	}
	return nil
}
