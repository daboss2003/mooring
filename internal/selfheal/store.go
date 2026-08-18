package selfheal

import (
	"context"
	"database/sql"
	"errors"

	"github.com/daboss2003/mooring/internal/store"
)

// Store persists the per-(app,service) FSM and the expected_down leases. Alert and
// FSM state are recovered from SQLite on restart so a bounce neither re-fires
// remediation nor loses an open circuit.
type Store struct{ db *store.DB }

// NewStore builds a Store.
func NewStore(db *store.DB) *Store { return &Store{db: db} }

// Key identifies one supervised service.
type Key struct{ App, Service string }

// LoadAll returns every persisted FSM, keyed by (app,service).
func (s *Store) LoadAll() (map[Key]FSM, error) {
	rows, err := s.db.Query(`SELECT app, service, phase, unhealthy_streak, healthy_streak, attempts,
		last_rung, backoff_until, window_start, oom_strikes, degraded_since, open FROM supervisor_state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[Key]FSM{}
	for rows.Next() {
		var k Key
		var f FSM
		var lastRung string
		var open int
		if err := rows.Scan(&k.App, &k.Service, &f.Phase, &f.UnhealthyStreak, &f.HealthyStreak,
			&f.Attempts, &lastRung, &f.BackoffUntil, &f.WindowStart, &f.OOMStrikes, &f.DegradedSince, &open); err != nil {
			return nil, err
		}
		f.LastRung = Rung(lastRung)
		f.Open = open == 1
		out[k] = f
	}
	return out, rows.Err()
}

// Save upserts one FSM.
func (s *Store) Save(ctx context.Context, k Key, f FSM, now int64) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO supervisor_state
		(app, service, phase, unhealthy_streak, healthy_streak, attempts, last_rung, backoff_until, window_start, oom_strikes, degraded_since, open, updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(app, service) DO UPDATE SET
			phase=excluded.phase, unhealthy_streak=excluded.unhealthy_streak, healthy_streak=excluded.healthy_streak,
			attempts=excluded.attempts, last_rung=excluded.last_rung, backoff_until=excluded.backoff_until,
			window_start=excluded.window_start, oom_strikes=excluded.oom_strikes, degraded_since=excluded.degraded_since,
			open=excluded.open, updated_at=excluded.updated_at`,
		k.App, k.Service, string(f.Phase), f.UnhealthyStreak, f.HealthyStreak, f.Attempts, string(f.LastRung),
		f.BackoffUntil, f.WindowStart, f.OOMStrikes, f.DegradedSince, b2i(f.Open), now)
	return err
}

// Delete drops an FSM (a service that no longer exists in any app).
func (s *Store) Delete(ctx context.Context, k Key) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM supervisor_state WHERE app=? AND service=?`, k.App, k.Service)
	return err
}

// DeleteApp removes ALL self-healing state for an app: the per-service FSM rows, the
// tuned policy, and any expected-down lease. Used by the app-delete teardown.
func (s *Store) DeleteApp(ctx context.Context, app string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM supervisor_state WHERE app=?`, app); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM app_selfheal WHERE project=?`, app); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM expected_down WHERE app=?`, app); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM service_held WHERE app=?`, app)
	return err
}

// ClearCircuit resets a latched CIRCUIT_OPEN service to HEALTHY so the supervisor
// will act on it again (the operator's "I fixed the underlying problem" button).
func (s *Store) ClearCircuit(ctx context.Context, k Key, now int64) error {
	return s.Save(ctx, k, FSM{Phase: Healthy}, now)
}

// --- operator holds (a service deliberately kept down / auto-restart paused) ---

// SetHeld marks a service as operator-held: while held, the supervisor suspends remediation and
// the auto-scaler skips it, so a manually-stopped service is never auto-restarted. Durable —
// survives a reboot (unlike an expected_down lease) — until ClearHeld/ClearHeldApp releases it.
func (s *Store) SetHeld(ctx context.Context, k Key, actor string, now int64) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO service_held(app, service, held_by, held_at) VALUES(?,?,?,?)
		 ON CONFLICT(app, service) DO UPDATE SET held_by=excluded.held_by, held_at=excluded.held_at`,
		k.App, k.Service, actor, now)
	return err
}

// ClearHeld releases one service's hold (an explicit start/resume).
func (s *Store) ClearHeld(ctx context.Context, k Key) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM service_held WHERE app=? AND service=?`, k.App, k.Service)
	return err
}

// ClearHeldApp releases every hold for an app (an app-level start/redeploy, or teardown).
func (s *Store) ClearHeldApp(ctx context.Context, app string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM service_held WHERE app=?`, app)
	return err
}

// ActiveHeld returns the set of currently-held services. Read once per tick by both the
// supervisor and the auto-scaler (the table is tiny and indexed by its primary key).
func (s *Store) ActiveHeld() (map[Key]bool, error) {
	rows, err := s.db.Query(`SELECT app, service FROM service_held`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[Key]bool{}
	for rows.Next() {
		var k Key
		if err := rows.Scan(&k.App, &k.Service); err != nil {
			return nil, err
		}
		out[k] = true
	}
	return out, rows.Err()
}

// --- expected_down leases ---

// AcquireExpectedDown opens/extends a bounded lease for an app (the write plane
// holds it while it intentionally touches the app). until is the auto-expiry.
func (s *Store) AcquireExpectedDown(ctx context.Context, app string, until int64) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO expected_down(app, until, reason) VALUES(?,?,?)
		 ON CONFLICT(app) DO UPDATE SET until=excluded.until, reason=excluded.reason`,
		app, until, "write-plane action")
	return err
}

// ReleaseExpectedDown clears an app's lease (the action finished).
func (s *Store) ReleaseExpectedDown(ctx context.Context, app string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM expected_down WHERE app=?`, app)
	return err
}

// ActiveExpectedDown returns the set of apps with a non-expired lease.
func (s *Store) ActiveExpectedDown(now int64) (map[string]bool, error) {
	rows, err := s.db.Query(`SELECT app FROM expected_down WHERE until > ?`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var app string
		if err := rows.Scan(&app); err != nil {
			return nil, err
		}
		out[app] = true
	}
	return out, rows.Err()
}

// ClearAllExpectedDown wipes every lease — called fail-closed on boot, so a deploy
// that crashed without releasing its lease can't suppress a crash-loop alert forever.
func (s *Store) ClearAllExpectedDown(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM expected_down`)
	return err
}

// --- per-app self-healing policy (mooring.yaml spec.self_healing) ---

// SavePolicy upserts one app's tuned self-healing policy. The whole-app policy is
// the mooring.yaml source of truth; the supervisor reads it per tick via PolicyFor
// and falls back to the built-in default for an app with no row.
func (s *Store) SavePolicy(ctx context.Context, project string, p Policy, now int64) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO app_selfheal
		(project, sustain_ticks, attempt_cap, stabilize_ticks, oom_strike_cap,
		 window_seconds, backoff_base_secs, backoff_max_secs, redeploy_enabled, updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(project) DO UPDATE SET
			sustain_ticks=excluded.sustain_ticks, attempt_cap=excluded.attempt_cap,
			stabilize_ticks=excluded.stabilize_ticks, oom_strike_cap=excluded.oom_strike_cap,
			window_seconds=excluded.window_seconds, backoff_base_secs=excluded.backoff_base_secs,
			backoff_max_secs=excluded.backoff_max_secs, redeploy_enabled=excluded.redeploy_enabled,
			updated_at=excluded.updated_at`,
		project, p.SustainTicks, p.AttemptCap, p.StabilizeTicks, p.OOMStrikeCap,
		p.WindowSeconds, p.BackoffBaseSecs, p.BackoffMaxSecs, b2i(p.RedeployEnabled), now)
	return err
}

// PolicyFor returns an app's tuned policy. ok=false (and the built-in default should
// be used) when the app has no row.
func (s *Store) PolicyFor(project string) (Policy, bool, error) {
	var p Policy
	var redeploy int
	err := s.db.QueryRow(`SELECT sustain_ticks, attempt_cap, stabilize_ticks, oom_strike_cap,
		window_seconds, backoff_base_secs, backoff_max_secs, redeploy_enabled
		FROM app_selfheal WHERE project = ?`, project).Scan(
		&p.SustainTicks, &p.AttemptCap, &p.StabilizeTicks, &p.OOMStrikeCap,
		&p.WindowSeconds, &p.BackoffBaseSecs, &p.BackoffMaxSecs, &redeploy)
	if errors.Is(err, sql.ErrNoRows) {
		return Policy{}, false, nil
	}
	if err != nil {
		return Policy{}, false, err
	}
	p.RedeployEnabled = redeploy == 1
	return p, true, nil
}

// DeletePolicy drops an app's tuned policy (reverting it to the built-in default).
func (s *Store) DeletePolicy(ctx context.Context, project string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM app_selfheal WHERE project=?`, project)
	return err
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
