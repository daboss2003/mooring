package edge

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/store"
)

// RouteStore persists the declarative app_routes set (Layer 1). The edge config is
// re-rendered as a WHOLE document from this set on every apply (never stored as
// text — SBD-7).
type RouteStore struct{ db *store.DB }

// NewRouteStore builds a RouteStore.
func NewRouteStore(db *store.DB) *RouteStore { return &RouteStore{db: db} }

// ReplaceProject atomically replaces all of one project's routes with the given set
// — the deploy-time op so a repo's mooring.yaml is the source of truth for its edge
// routes. Each route is validated first; a cross-app hostname collision trips the
// UNIQUE(hostname, path_prefix) constraint and fails the whole transaction (nothing
// changes), so a deploy can't hijack another app's hostname. Callers should only
// invoke this when the definition DECLARES routes, so an app whose routes are managed
// in the dashboard (none in mooring.yaml) is never silently wiped.
func (s *RouteStore) ReplaceProject(ctx context.Context, project string, routes []Route) error {
	for i := range routes {
		routes[i].AppID = project
		routes[i].Hostname = strings.ToLower(strings.TrimSpace(routes[i].Hostname))
		routes[i].Upstream = strings.TrimSpace(routes[i].Upstream)
		if routes[i].UpstreamScheme == "" {
			routes[i].UpstreamScheme = "http"
		}
		if err := ValidateRoute(routes[i]); err != nil {
			return err
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Checked inside the transaction so a concurrent claim can't slip between check and insert.
	for _, r := range routes {
		if owner, taken, err := pathOwner(ctx, tx, r.Hostname, r.PathPrefix, project); err != nil {
			return err
		} else if taken {
			return fmt.Errorf("hostname %q path %q is already in use by app %q", r.Hostname, displayPrefix(r.PathPrefix), owner)
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM app_routes WHERE app_id = ?`, project); err != nil {
		return err
	}
	now := time.Now().Unix()
	for _, r := range routes {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO app_routes(app_id, hostname, upstream, upstream_scheme, path_prefix, redirect_http, hsts, security_headers, enabled, tls_ca, created_at)
			 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			r.AppID, r.Hostname, r.Upstream, r.UpstreamScheme, r.PathPrefix,
			b2i(r.RedirectHTTP), b2i(r.HSTS), b2i(r.SecurityHeaders), b2i(r.Enabled), r.CA, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Save validates + upserts a route by id (0 = insert). ValidateRoute rejects
// wildcards, control-plane upstreams, and loopback targets before it can persist.
func (s *RouteStore) Save(ctx context.Context, r Route) error {
	r.Hostname = strings.ToLower(strings.TrimSpace(r.Hostname))
	r.Upstream = strings.TrimSpace(r.Upstream)
	if r.UpstreamScheme == "" {
		r.UpstreamScheme = "http"
	}
	if err := ValidateRoute(r); err != nil {
		return err
	}
	if owner, taken, err := pathOwner(ctx, s.db, r.Hostname, r.PathPrefix, r.AppID); err != nil {
		return err
	} else if taken {
		return fmt.Errorf("hostname %q path %q is already in use by app %q", r.Hostname, displayPrefix(r.PathPrefix), owner)
	}
	if r.id == 0 {
		_, err := s.db.ExecContext(ctx,
			`INSERT INTO app_routes(app_id, hostname, upstream, upstream_scheme, path_prefix, redirect_http, hsts, security_headers, enabled, tls_ca, created_at)
			 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			r.AppID, r.Hostname, r.Upstream, r.UpstreamScheme, r.PathPrefix,
			b2i(r.RedirectHTTP), b2i(r.HSTS), b2i(r.SecurityHeaders), b2i(r.Enabled), r.CA, time.Now().Unix())
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE app_routes SET app_id=?, hostname=?, upstream=?, upstream_scheme=?, path_prefix=?, redirect_http=?, hsts=?, security_headers=?, enabled=?, tls_ca=? WHERE id=?`,
		r.AppID, r.Hostname, r.Upstream, r.UpstreamScheme, r.PathPrefix,
		b2i(r.RedirectHTTP), b2i(r.HSTS), b2i(r.SecurityHeaders), b2i(r.Enabled), r.CA, r.id)
	return err
}

// HostnameOwner reports which OTHER app already claims hostname at an equivalent path prefix,
// so a caller can reject a collision with a clear "already taken" message. Different apps may
// share a hostname on different prefixes; equivalent spellings of one prefix ("" and "/",
// "/api" and "/api/") are the same claim, since the edge matches them identically. Matching is
// case-insensitive on the hostname; exceptProject (the app being deployed) is excluded.
func (s *RouteStore) HostnameOwner(ctx context.Context, hostname, pathPrefix, exceptProject string) (string, bool, error) {
	return pathOwner(ctx, s.db, hostname, pathPrefix, exceptProject)
}

type queryRower interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func pathOwner(ctx context.Context, q queryRower, hostname, pathPrefix, exceptProject string) (string, bool, error) {
	var owner string
	err := q.QueryRowContext(ctx,
		`SELECT app_id FROM app_routes WHERE hostname = ? AND rtrim(path_prefix, '/') = ? AND app_id <> ? LIMIT 1`,
		strings.ToLower(strings.TrimSpace(hostname)), strings.TrimRight(pathPrefix, "/"), exceptProject).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return owner, true, nil
}

func displayPrefix(p string) string {
	if p == "" {
		return "/"
	}
	return p
}

// List returns all routes (for rendering + the UI).
func (s *RouteStore) List() ([]Route, error) {
	rows, err := s.db.Query(
		`SELECT id, app_id, hostname, upstream, upstream_scheme, path_prefix, redirect_http, hsts, security_headers, enabled, tls_ca FROM app_routes ORDER BY hostname, path_prefix`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Route
	for rows.Next() {
		var r Route
		var redir, hsts, sec, en int
		if err := rows.Scan(&r.id, &r.AppID, &r.Hostname, &r.Upstream, &r.UpstreamScheme, &r.PathPrefix, &redir, &hsts, &sec, &en, &r.CA); err != nil {
			return nil, err
		}
		r.RedirectHTTP, r.HSTS, r.SecurityHeaders, r.Enabled = redir == 1, hsts == 1, sec == 1, en == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

// ID returns a route's row id (for the UI).
func (r Route) ID() int64 { return r.id }

// Delete removes a route by id.
func (s *RouteStore) Delete(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM app_routes WHERE id=?`, id)
	return err
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
