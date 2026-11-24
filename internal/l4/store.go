package l4

import (
	"context"
	"fmt"
	"time"

	"github.com/daboss2003/mooring/internal/store"
)

// RouteStore persists the L4 routes an app declares (mooring.yaml edge.l4_routes),
// keyed by project. The L4 LB config is rendered from the union of all projects'
// routes — never stored as nginx text. A listener (listen+protocol) is globally
// unique (DB constraint), so two apps can't claim the same public port.
type RouteStore struct{ db *store.DB }

// NewRouteStore builds a store over the shared DB.
func NewRouteStore(db *store.DB) *RouteStore { return &RouteStore{db: db} }

// ReplaceProject atomically replaces all of one project's L4 routes with the given
// set (the deploy-time op: an app's mooring.yaml is the source of truth for its
// routes). Every route is validated first; a cross-project listener collision trips
// the UNIQUE(listen, protocol) constraint and fails the whole transaction (nothing
// is changed) so the deploy is blocked with a clear error rather than hijacking a
// port another app owns.
func (s *RouteStore) ReplaceProject(ctx context.Context, project string, routes []Route) error {
	if project == "" {
		return fmt.Errorf("l4 store: empty project")
	}
	for _, r := range routes {
		if err := ValidateRoute(r); err != nil {
			return err
		}
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM app_l4_routes WHERE app_id = ?`, project); err != nil {
		return err
	}
	now := time.Now().Unix()
	for _, r := range routes {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO app_l4_routes(app_id, listen, protocol, service, port, lb, forward, created_at)
			 VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
			project, r.Listen, r.Protocol, r.Service, r.Port, r.LB, r.Forward, now); err != nil {
			return fmt.Errorf("l4 route %d/%s: %w (a listener may be claimed by another app)", r.Listen, r.Protocol, err)
		}
	}
	return tx.Commit()
}

// HostPort is one host port an app publishes itself (a service ports[] entry). Protocol "" means tcp.
type HostPort struct {
	Port     int
	Protocol string
}

// CheckProject reports whether project could take routes and publish hostPorts without colliding with
// another project's L4 routes: a listen+protocol another app owns, or one of this app's own published
// host ports on another app's L4 listener. The project's own rows never conflict. It never writes; the
// deploy calls it before anything starts (ReplaceProject's UNIQUE constraint stays the backstop).
func (s *RouteStore) CheckProject(ctx context.Context, project string, routes []Route, hostPorts []HostPort) error {
	if project == "" {
		return fmt.Errorf("l4 store: empty project")
	}
	for _, r := range routes {
		if err := ValidateRoute(r); err != nil {
			return err
		}
	}
	owners, err := s.otherOwners(ctx, project)
	if err != nil {
		return err
	}
	for _, r := range routes {
		if owner, ok := owners[listenerKey(r.Listen, r.Protocol)]; ok {
			return fmt.Errorf("l4 route %d/%s is already in use by app %q — pick a different listen port", r.Listen, r.Protocol, owner)
		}
	}
	for _, hp := range hostPorts {
		proto := hp.Protocol
		if proto == "" {
			proto = "tcp"
		}
		if owner, ok := owners[listenerKey(hp.Port, proto)]; ok {
			return fmt.Errorf("published host port %d/%s is already in use by an l4_route of app %q — pick a different one", hp.Port, proto, owner)
		}
	}
	return nil
}

func listenerKey(port int, protocol string) string { return fmt.Sprintf("%d/%s", port, protocol) }

// otherOwners maps each listener ("port/protocol") that another project's L4 route holds to that project.
// All rows are read and the cursor closed before the caller does anything else (single DB connection).
func (s *RouteStore) otherOwners(ctx context.Context, project string) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT app_id, listen, protocol FROM app_l4_routes WHERE app_id <> ?`, project)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var app, proto string
		var listen int
		if err := rows.Scan(&app, &listen, &proto); err != nil {
			return nil, err
		}
		out[listenerKey(listen, proto)] = app
	}
	return out, rows.Err()
}

// List returns every project's L4 routes (the input to a render), ordered
// deterministically. AppID is returned so the reconciler can scope replica discovery
// to the owning project; Pool is left empty for the reconciler to populate.
func (s *RouteStore) List() ([]Route, error) {
	rows, err := s.db.Query(
		`SELECT app_id, listen, protocol, service, port, lb, forward FROM app_l4_routes ORDER BY listen, protocol`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Route
	for rows.Next() {
		var r Route
		if err := rows.Scan(&r.AppID, &r.Listen, &r.Protocol, &r.Service, &r.Port, &r.LB, &r.Forward); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
