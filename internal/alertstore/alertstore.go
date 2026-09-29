// Package alertstore persists the alert engine's channels (AES-256-GCM encrypted
// config), rules, per-(rule,target) state, and the outbox (plan §8/§9). Channel
// secrets are never stored or returned in plaintext except to the notifier at
// send time.
package alertstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/secret"
	"github.com/daboss2003/mooring/internal/store"
)

// Store persists alerting state.
type Store struct {
	db     *store.DB
	cipher *secret.Cipher
}

// New builds a Store.
func New(db *store.DB, cipher *secret.Cipher) *Store { return &Store{db: db, cipher: cipher} }

// --- channels ---

// ChannelMeta is a channel without its (encrypted) config.
type ChannelMeta struct {
	ID      int64
	Name    string
	Kind    string
	Enabled bool
}

// SaveChannel validates + encrypts a channel config and upserts by name.
func (s *Store) SaveChannel(ctx context.Context, name, kind string, configJSON []byte) error {
	if name == "" {
		return errors.New("alertstore: channel name required")
	}
	if !alert.ValidChannelKind(kind) {
		return errors.New("alertstore: unknown channel kind")
	}
	if _, err := alert.BuildChannel(kind, configJSON); err != nil {
		return err
	}
	enc, err := s.cipher.Seal(configJSON)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO alert_channels(name, kind, config_enc, enabled, created_at) VALUES(?, ?, ?, 1, ?)
		 ON CONFLICT(name) DO UPDATE SET kind=excluded.kind, config_enc=excluded.config_enc`,
		name, kind, enc, time.Now().Unix())
	return err
}

// ListChannels returns channel metadata (no config).
func (s *Store) ListChannels() ([]ChannelMeta, error) {
	rows, err := s.db.Query(`SELECT id, name, kind, enabled FROM alert_channels ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ChannelMeta
	for rows.Next() {
		var c ChannelMeta
		var en int
		if err := rows.Scan(&c.ID, &c.Name, &c.Kind, &en); err != nil {
			return nil, err
		}
		c.Enabled = en == 1
		out = append(out, c)
	}
	return out, rows.Err()
}

// NtfyManagedInfo is the display-safe subset of a Mooring-hosted ntfy channel — the
// subscribe URL, topic, and the read-only USERNAME+PASSWORD the operator signs into the
// ntfy app/web UI with. The publisher's write token is never returned.
type NtfyManagedInfo struct {
	Name     string
	BaseURL  string
	Topic    string
	Username string
	Password string
}

// ManagedNtfy returns the configured Mooring-hosted ntfy channel's subscribe info, or
// ok=false if none is configured. Decrypts the channel config but exposes only the
// read-only subscriber credentials (the operator must see them to subscribe), never the
// publisher write token.
func (s *Store) ManagedNtfy() (NtfyManagedInfo, bool, error) {
	var name string
	var enc []byte
	err := s.db.QueryRow(`SELECT name, config_enc FROM alert_channels WHERE kind='ntfy_managed' ORDER BY id LIMIT 1`).Scan(&name, &enc)
	if errors.Is(err, sql.ErrNoRows) {
		return NtfyManagedInfo{}, false, nil
	}
	if err != nil {
		return NtfyManagedInfo{}, false, err
	}
	pt, err := s.cipher.Open(enc)
	if err != nil {
		return NtfyManagedInfo{}, false, err
	}
	var cfg struct {
		BaseURL string `json:"base_url"`
		Topic   string `json:"topic"`
		SubUser string `json:"sub_user"`
		SubPass string `json:"sub_pass"`
	}
	if err := json.Unmarshal(pt, &cfg); err != nil {
		return NtfyManagedInfo{}, false, err
	}
	return NtfyManagedInfo{Name: name, BaseURL: cfg.BaseURL, Topic: cfg.Topic, Username: cfg.SubUser, Password: cfg.SubPass}, true, nil
}

// ChannelKind returns a channel's kind by id (for delete-time teardown decisions).
func (s *Store) ChannelKind(id int64) (string, error) {
	var kind string
	err := s.db.QueryRow(`SELECT kind FROM alert_channels WHERE id=?`, id).Scan(&kind)
	return kind, err
}

func (s *Store) channel(id int64) (alert.Channel, error) {
	var kind string
	var enc []byte
	if err := s.db.QueryRow(`SELECT kind, config_enc FROM alert_channels WHERE id=? AND enabled=1`, id).Scan(&kind, &enc); err != nil {
		return nil, err
	}
	pt, err := s.cipher.Open(enc)
	if err != nil {
		return nil, err
	}
	return alert.BuildChannel(kind, pt)
}

// ChannelByID builds a single channel (for the "send test" button).
func (s *Store) ChannelByID(id int64) (alert.Channel, error) { return s.channel(id) }

// AllChannels builds every enabled channel. Used for Mooring-originated infra
// alerts (plan §8.4), which are never deferred and route to all channels. A channel
// that fails to build is skipped (a broken channel can't block the others).
func (s *Store) AllChannels() ([]alert.Channel, error) {
	rows, err := s.db.Query(`SELECT id FROM alert_channels WHERE enabled=1 ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var out []alert.Channel
	for _, id := range ids {
		if ch, err := s.channel(id); err == nil {
			out = append(out, ch)
		}
	}
	return out, nil
}

// EnqueueInfra appends a Mooring-originated infra notification (rule_id=0 sentinel,
// never deferred). It is deduped against pending rows so a re-paged condition each
// tick can't pile up — at most one un-sent row per (dedupe_key, transition).
func (s *Store) EnqueueInfra(ctx context.Context, o alert.Outbox) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO alert_outbox(rule_id, target, kind, level, transition, summary, dedupe_key, created_at)
		 SELECT 0, ?, ?, ?, ?, ?, ?, ?
		 WHERE NOT EXISTS (SELECT 1 FROM alert_outbox WHERE dedupe_key=? AND transition=? AND sent_at=0)`,
		o.Target, o.Kind, o.Level, o.Transition, o.Summary, o.DedupeKey, time.Now().Unix(),
		o.DedupeKey, o.Transition)
	return err
}

// ChannelsForRule returns the channels a rule routes to (its channel_id, or all
// enabled channels when channel_id is NULL/0).
// OpenInfraAlerts returns, for every dedupe key of the given infra alert kind whose most recent outbox
// row is a "firing" transition, that row's target. A restarted process uses it to re-adopt the alerts it
// raised before the restart, so their "resolved" is still sent. (Rows past the outbox retention are
// gone, and with them any memory of the alert.)
func (s *Store) OpenInfraAlerts(ctx context.Context, kind string) (map[string]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT dedupe_key, target, transition FROM alert_outbox WHERE rule_id=0 AND kind=? AND dedupe_key<>'' ORDER BY id`, kind)
	if err != nil {
		return nil, err
	}
	type last struct{ target, transition string }
	latest := map[string]last{}
	for rows.Next() {
		var key, target, transition string
		if err := rows.Scan(&key, &target, &transition); err != nil {
			rows.Close()
			return nil, err
		}
		latest[key] = last{target, transition} // ordered by id: the last row per key wins
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	out := map[string]string{}
	for key, l := range latest {
		if l.transition == "firing" {
			out[key] = l.target
		}
	}
	return out, nil
}

func (s *Store) ChannelsForRule(channelID int64) ([]alert.Channel, error) {
	if channelID != 0 {
		c, err := s.channel(channelID)
		if err != nil {
			return nil, err
		}
		return []alert.Channel{c}, nil
	}
	rows, err := s.db.Query(`SELECT id FROM alert_channels WHERE enabled=1`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	var out []alert.Channel
	for _, id := range ids {
		if c, err := s.channel(id); err == nil {
			out = append(out, c)
		}
	}
	return out, nil
}

func (s *Store) DeleteChannel(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM alert_channels WHERE id=?`, id)
	return err
}

// --- rules ---

func (s *Store) SaveRule(ctx context.Context, r alert.Rule) error {
	if !alert.ValidKind(r.Kind) {
		return errors.New("alertstore: unknown rule kind")
	}
	if r.Level != alert.LevelWarning && r.Level != alert.LevelCritical {
		r.Level = alert.LevelWarning
	}
	if r.ForSeconds < 0 {
		r.ForSeconds = 0
	}
	var chID any
	if r.ChannelID != 0 {
		chID = r.ChannelID
	}
	if r.ID == 0 {
		_, err := s.db.ExecContext(ctx,
			`INSERT INTO alert_rules(name, kind, scope, threshold, for_seconds, level, defer_when_self_managed, channel_id, enabled, created_at)
			 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			r.Name, r.Kind, r.Scope, r.Threshold, r.ForSeconds, r.Level, b2i(r.DeferWhenSelfManaged), chID, b2i(r.Enabled), time.Now().Unix())
		return err
	}
	_, err := s.db.ExecContext(ctx,
		`UPDATE alert_rules SET name=?, kind=?, scope=?, threshold=?, for_seconds=?, level=?, defer_when_self_managed=?, channel_id=?, enabled=? WHERE id=?`,
		r.Name, r.Kind, r.Scope, r.Threshold, r.ForSeconds, r.Level, b2i(r.DeferWhenSelfManaged), chID, b2i(r.Enabled), r.ID)
	return err
}

func (s *Store) ListRules() ([]alert.Rule, error) {
	rows, err := s.db.Query(
		`SELECT id, name, kind, scope, threshold, for_seconds, level, defer_when_self_managed, COALESCE(channel_id,0), enabled FROM alert_rules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []alert.Rule
	for rows.Next() {
		var r alert.Rule
		var deferSM, en int
		if err := rows.Scan(&r.ID, &r.Name, &r.Kind, &r.Scope, &r.Threshold, &r.ForSeconds, &r.Level, &deferSM, &r.ChannelID, &en); err != nil {
			return nil, err
		}
		r.DeferWhenSelfManaged = deferSM == 1
		r.Enabled = en == 1
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) DeleteRule(ctx context.Context, id int64) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM alert_rules WHERE id=?`, id); err != nil {
		return err
	}
	_, _ = s.db.ExecContext(ctx, `DELETE FROM alert_state WHERE rule_id=?`, id)
	return nil
}

// DeleteApp removes everything alerting holds for one app: rules scoped to the app
// (and their live state/outbox), plus any per-target state/outbox for the app's
// containers under GLOBAL rules (target is "<slug>" or "<slug>/<service>"). Global
// channels and all-app rules are left untouched. Used by the app-delete teardown.
// Each statement runs on its own; the subqueries resolve before the rules are dropped.
func (s *Store) DeleteApp(ctx context.Context, slug string) error {
	like := slug + "/%"
	stmts := []struct {
		sql  string
		args []any
	}{
		{`DELETE FROM alert_state WHERE rule_id IN (SELECT id FROM alert_rules WHERE scope=?)`, []any{slug}},
		{`DELETE FROM alert_outbox WHERE rule_id IN (SELECT id FROM alert_rules WHERE scope=?)`, []any{slug}},
		{`DELETE FROM alert_state WHERE target=? OR target LIKE ?`, []any{slug, like}},
		{`DELETE FROM alert_outbox WHERE target=? OR target LIKE ?`, []any{slug, like}},
		{`DELETE FROM alert_rules WHERE scope=?`, []any{slug}},
	}
	for _, st := range stmts {
		if _, err := s.db.ExecContext(ctx, st.sql, st.args...); err != nil {
			return err
		}
	}
	return nil
}

// RuleByID returns one rule (the notifier needs its channel routing).
func (s *Store) RuleByID(id int64) (alert.Rule, bool) {
	var r alert.Rule
	var deferSM, en int
	err := s.db.QueryRow(
		`SELECT id, name, kind, scope, threshold, for_seconds, level, defer_when_self_managed, COALESCE(channel_id,0), enabled FROM alert_rules WHERE id=?`, id).
		Scan(&r.ID, &r.Name, &r.Kind, &r.Scope, &r.Threshold, &r.ForSeconds, &r.Level, &deferSM, &r.ChannelID, &en)
	if err != nil {
		return alert.Rule{}, false
	}
	r.DeferWhenSelfManaged = deferSM == 1
	r.Enabled = en == 1
	return r, true
}

// --- state ---

func (s *Store) LoadStates() ([]alert.State, error) {
	rows, err := s.db.Query(`SELECT rule_id, target, phase, since, level, detail, acked, silenced_until FROM alert_state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []alert.State
	for rows.Next() {
		var st alert.State
		var phase string
		var acked int
		if err := rows.Scan(&st.RuleID, &st.Target, &phase, &st.Since, &st.Level, &st.Detail, &acked, &st.SilencedUntil); err != nil {
			return nil, err
		}
		st.Phase = alert.Phase(phase)
		st.Acked = acked == 1
		out = append(out, st)
	}
	return out, rows.Err()
}

// SaveStates upserts the state set and prunes ok rows to keep the table bounded.
func (s *Store) SaveStates(ctx context.Context, states []alert.State) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, st := range states {
		if st.Phase == alert.PhaseOK {
			_, _ = tx.ExecContext(ctx, `DELETE FROM alert_state WHERE rule_id=? AND target=?`, st.RuleID, st.Target)
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO alert_state(rule_id, target, phase, since, level, detail, acked, silenced_until, updated_at)
			 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(rule_id, target) DO UPDATE SET
			   phase=excluded.phase, since=excluded.since, level=excluded.level, detail=excluded.detail,
			   acked=excluded.acked, silenced_until=excluded.silenced_until, updated_at=excluded.updated_at`,
			st.RuleID, st.Target, string(st.Phase), st.Since, st.Level, st.Detail, b2i(st.Acked), st.SilencedUntil, time.Now().Unix()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// FiringStates returns the currently-open (firing) states for the UI.
func (s *Store) FiringStates() ([]alert.State, error) {
	all, err := s.LoadStates()
	if err != nil {
		return nil, err
	}
	var out []alert.State
	for _, st := range all {
		if st.Phase == alert.PhaseFiring {
			out = append(out, st)
		}
	}
	return out, nil
}

func (s *Store) Ack(ctx context.Context, ruleID int64, target string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE alert_state SET acked=1 WHERE rule_id=? AND target=?`, ruleID, target)
	return err
}

func (s *Store) Silence(ctx context.Context, ruleID int64, target string, until int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE alert_state SET silenced_until=? WHERE rule_id=? AND target=?`, until, ruleID, target)
	return err
}

// IsSilenced reports whether a (rule,target) is silenced at now.
func (s *Store) IsSilenced(ruleID int64, target string, now int64) bool {
	var until int64
	err := s.db.QueryRow(`SELECT silenced_until FROM alert_state WHERE rule_id=? AND target=?`, ruleID, target).Scan(&until)
	return err == nil && until > now
}

// --- outbox (evaluator writes, notifier drains) ---

// OutboxRow is one pending notification.
type OutboxRow struct {
	ID         int64
	RuleID     int64
	Target     string
	Kind       string
	Level      string
	Transition string
	Summary    string
	DedupeKey  string
	Attempts   int
}

// EnqueueOutbox appends notifications the evaluator produced (it never sends).
func (s *Store) EnqueueOutbox(ctx context.Context, items []alert.Outbox) error {
	if len(items) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	for _, o := range items {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO alert_outbox(rule_id, target, kind, level, transition, summary, dedupe_key, created_at)
			 VALUES(?, ?, ?, ?, ?, ?, ?, ?)`,
			o.RuleID, o.Target, o.Kind, o.Level, o.Transition, o.Summary, o.DedupeKey, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// PendingOutbox returns unsent rows, oldest first.
func (s *Store) PendingOutbox(limit int) ([]OutboxRow, error) {
	rows, err := s.db.Query(
		`SELECT id, rule_id, target, kind, level, transition, summary, dedupe_key, attempts
		 FROM alert_outbox WHERE sent_at=0 ORDER BY id LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OutboxRow
	for rows.Next() {
		var o OutboxRow
		if err := rows.Scan(&o.ID, &o.RuleID, &o.Target, &o.Kind, &o.Level, &o.Transition, &o.Summary, &o.DedupeKey, &o.Attempts); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// MarkSent finalizes an outbox row: ok → sent; otherwise bump attempts, and after
// maxAttempts mark sent anyway so a permanently-failing channel can't wedge the
// queue (a separate infra alert would surface a broken channel).
func (s *Store) MarkSent(ctx context.Context, id int64, ok bool, maxAttempts int) {
	if ok {
		_, _ = s.db.ExecContext(ctx, `UPDATE alert_outbox SET sent_at=? WHERE id=?`, time.Now().Unix(), id)
		return
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE alert_outbox SET attempts=attempts+1 WHERE id=?`, id)
	_, _ = s.db.ExecContext(ctx, `UPDATE alert_outbox SET sent_at=? WHERE id=? AND attempts>=?`, time.Now().Unix(), id, maxAttempts)
}

// PruneOutbox drops sent rows older than the cutoff (bounded growth).
func (s *Store) PruneOutbox(ctx context.Context, olderThan int64) {
	_, _ = s.db.ExecContext(ctx, `DELETE FROM alert_outbox WHERE sent_at>0 AND sent_at<?`, olderThan)
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
