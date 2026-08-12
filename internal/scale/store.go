package scale

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/daboss2003/mooring/internal/store"
)

// Store persists scaling policies (operator opt-in + thresholds) and controller
// state (desired replicas + hysteresis timers, recovered on restart).
type Store struct{ db *store.DB }

// NewStore builds a Store.
func NewStore(db *store.DB) *Store { return &Store{db: db} }

// Key identifies one scaled service.
type Key struct{ App, Service string }

// PolicyRow is a stored policy plus its per-replica reservations + enabled flag.
type PolicyRow struct {
	Policy
	Enabled       bool
	PerReplicaMem uint64
	PerReplicaCPU uint64
	Metrics       []MetricSpec // custom scaling signals (source + thresholds); mirrored into Policy.Signals
}

// MetricSpec is a custom scaling signal's full spec: how to SOURCE it (Source/Select, used by the
// watcher to read the value) plus its thresholds (Up/Down, used by the controller). Persisted with
// the policy as JSON.
type MetricSpec struct {
	Name   string  `json:"name"`
	Source string  `json:"source"` // "ops" (Phase 1)
	Select string  `json:"select,omitempty"`
	Up     float64 `json:"up"`
	Down   float64 `json:"down"`
}

// syncSignals mirrors the custom metrics' thresholds into Policy.Signals — what the controller's
// Decide reads. Called after load/convert so Valid() and Decide see the signals.
func (pr *PolicyRow) syncSignals() {
	pr.Policy.Signals = nil
	for _, m := range pr.Metrics {
		pr.Policy.Signals = append(pr.Policy.Signals, SignalPolicy{Name: m.Name, Up: m.Up, Down: m.Down})
	}
}

// marshalSignals returns the JSON for the signals column ("" when there are none, to keep existing
// CPU/mem-only policies clean).
func marshalSignals(specs []MetricSpec) (string, error) {
	if len(specs) == 0 {
		return "", nil
	}
	b, err := json.Marshal(specs)
	return string(b), err
}

// unmarshalSignals parses the signals column into pr.Metrics and mirrors thresholds into
// Policy.Signals. An empty/whitespace column means no custom signals.
func (pr *PolicyRow) unmarshalSignals(raw string) error {
	if raw != "" {
		if err := json.Unmarshal([]byte(raw), &pr.Metrics); err != nil {
			return err
		}
	}
	pr.syncSignals()
	return nil
}

// SavePolicy validates + upserts a policy. A policy must pass Policy.Valid() and
// carry non-zero per-replica reservations before it can be enabled.
// DeleteApp removes ALL scaling policies and controller state for every service of an
// app. Used by the app-delete teardown.
func (s *Store) DeleteApp(ctx context.Context, app string) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM scaling_policy WHERE app=?`, app); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM scaling_state WHERE app=?`, app)
	return err
}

func (s *Store) SavePolicy(ctx context.Context, k Key, pr PolicyRow) error {
	pr.syncSignals() // so Valid() sees the custom signals
	if ok, why := pr.Policy.Valid(); !ok {
		return errors.New("scaling policy invalid: " + why)
	}
	if pr.Enabled && (pr.PerReplicaMem == 0 || pr.PerReplicaCPU == 0) {
		return errors.New("scaling requires non-zero per-replica memory and cpu reservations")
	}
	sigJSON, err := marshalSignals(pr.Metrics)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO scaling_policy
		(app, service, enabled, min_replicas, max_replicas, up_cpu_pct, up_mem_pct, down_cpu_pct, down_mem_pct, breach_for_secs, cooldown_up, cooldown_down, per_replica_mem, per_replica_cpu, signals_json)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(app,service) DO UPDATE SET
			enabled=excluded.enabled, min_replicas=excluded.min_replicas, max_replicas=excluded.max_replicas,
			up_cpu_pct=excluded.up_cpu_pct, up_mem_pct=excluded.up_mem_pct, down_cpu_pct=excluded.down_cpu_pct,
			down_mem_pct=excluded.down_mem_pct, breach_for_secs=excluded.breach_for_secs,
			cooldown_up=excluded.cooldown_up, cooldown_down=excluded.cooldown_down,
			per_replica_mem=excluded.per_replica_mem, per_replica_cpu=excluded.per_replica_cpu,
			signals_json=excluded.signals_json`,
		k.App, k.Service, b2i(pr.Enabled), pr.Min, pr.Max, pr.UpCPUPct, pr.UpMemPct, pr.DownCPUPct, pr.DownMemPct,
		pr.BreachForSecs, pr.CooldownUpSecs, pr.CooldownDownSecs, int64(pr.PerReplicaMem), int64(pr.PerReplicaCPU), sigJSON)
	return err
}

// EnabledPolicies returns every enabled policy keyed by (app,service).
func (s *Store) EnabledPolicies() (map[Key]PolicyRow, error) {
	rows, err := s.db.Query(`SELECT app, service, min_replicas, max_replicas, up_cpu_pct, up_mem_pct,
		down_cpu_pct, down_mem_pct, breach_for_secs, cooldown_up, cooldown_down, per_replica_mem, per_replica_cpu, signals_json
		FROM scaling_policy WHERE enabled=1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[Key]PolicyRow{}
	for rows.Next() {
		var k Key
		var pr PolicyRow
		var mem, cpu int64
		var sig string
		if err := rows.Scan(&k.App, &k.Service, &pr.Min, &pr.Max, &pr.UpCPUPct, &pr.UpMemPct,
			&pr.DownCPUPct, &pr.DownMemPct, &pr.BreachForSecs, &pr.CooldownUpSecs, &pr.CooldownDownSecs, &mem, &cpu, &sig); err != nil {
			return nil, err
		}
		pr.Enabled = true
		pr.PerReplicaMem, pr.PerReplicaCPU = uint64(mem), uint64(cpu)
		if err := pr.unmarshalSignals(sig); err != nil {
			return nil, err
		}
		out[k] = pr
	}
	return out, rows.Err()
}

// PolicyFor returns the policy for one service (enabled flag included), or ok=false.
func (s *Store) PolicyFor(k Key) (PolicyRow, bool, error) {
	var pr PolicyRow
	var mem, cpu int64
	var en int
	var sig string
	err := s.db.QueryRow(`SELECT enabled, min_replicas, max_replicas, up_cpu_pct, up_mem_pct, down_cpu_pct,
		down_mem_pct, breach_for_secs, cooldown_up, cooldown_down, per_replica_mem, per_replica_cpu, signals_json
		FROM scaling_policy WHERE app=? AND service=?`, k.App, k.Service).
		Scan(&en, &pr.Min, &pr.Max, &pr.UpCPUPct, &pr.UpMemPct, &pr.DownCPUPct, &pr.DownMemPct,
			&pr.BreachForSecs, &pr.CooldownUpSecs, &pr.CooldownDownSecs, &mem, &cpu, &sig)
	if errors.Is(err, sql.ErrNoRows) {
		return PolicyRow{}, false, nil
	}
	if err != nil {
		return PolicyRow{}, false, err
	}
	pr.Enabled = en == 1
	pr.PerReplicaMem, pr.PerReplicaCPU = uint64(mem), uint64(cpu)
	if err := pr.unmarshalSignals(sig); err != nil {
		return PolicyRow{}, false, err
	}
	return pr, true, nil
}

// LoadStates returns all persisted controller states.
func (s *Store) LoadStates() (map[Key]State, error) {
	rows, err := s.db.Query(`SELECT app, service, replicas, breach_since, last_change FROM scaling_state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[Key]State{}
	for rows.Next() {
		var k Key
		var st State
		if err := rows.Scan(&k.App, &k.Service, &st.Replicas, &st.BreachSince, &st.LastChange); err != nil {
			return nil, err
		}
		out[k] = st
	}
	return out, rows.Err()
}

// SaveState upserts one controller state.
func (s *Store) SaveState(ctx context.Context, k Key, st State, now int64) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO scaling_state(app, service, replicas, breach_since, last_change, updated_at)
		VALUES(?,?,?,?,?,?)
		ON CONFLICT(app,service) DO UPDATE SET replicas=excluded.replicas, breach_since=excluded.breach_since,
			last_change=excluded.last_change, updated_at=excluded.updated_at`,
		k.App, k.Service, st.Replicas, st.BreachSince, st.LastChange, now)
	return err
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
