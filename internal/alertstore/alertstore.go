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
	"fmt"
	"sync/atomic"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/secret"
	"github.com/daboss2003/mooring/internal/store"
)

// Outbox retention. Quiet hours hold a row less than a day and a critical is retried for a day, so no row
// they keep reaches the unsent limit.
const (
	outboxSentRetention = 7 * 24 * time.Hour // delivered and closed rows (OpenInfraAlerts reads them)
	outboxUnsentMaxAge  = 48 * time.Hour     // rows never sent: alerting disabled, or no channel worked
	outboxPruneEvery    = 10 * time.Minute   // how often EnqueueInfra prunes
	pruneTimeout        = 30 * time.Second   // EnqueueInfra's prune, after its insert
)

// Delivery retries (owner decision): a message that isn't critical is tried warningAttempts times in all,
// each on the next drain; a critical message is retried with a backoff from criticalBackoff, doubling, at
// most criticalBackoffMax apart, until its rows are criticalRetryFor old. Then the rows are given up.
const (
	warningAttempts    = 3
	criticalBackoff    = 15   // seconds
	criticalBackoffMax = 3600 // seconds
	criticalRetryFor   = 24 * time.Hour
)

// Store persists alerting state.
type Store struct {
	db        *store.DB
	cipher    *secret.Cipher
	nextPrune atomic.Int64 // unix sec before which EnqueueInfra doesn't prune again

	beforePrune func(ctx context.Context) // tests: called first in PruneOutbox, with its context
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

// BuiltChannel is an enabled channel ready to send, with its id (the notifier retries only the channels
// that failed).
type BuiltChannel struct {
	ID int64
	alert.Channel
}

// AllChannels builds every enabled channel. Used for Mooring-originated infra
// alerts (plan §8.4), which are never deferred and route to all channels. A channel
// that fails to build is skipped (a broken channel can't block the others).
func (s *Store) AllChannels() ([]BuiltChannel, error) {
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
	var out []BuiltChannel
	for _, id := range ids {
		if ch, err := s.channel(id); err == nil {
			out = append(out, BuiltChannel{ID: id, Channel: ch})
		}
	}
	return out, nil
}

// EnqueueInfra appends a Mooring-originated infra notification (rule_id=0 sentinel,
// never deferred). A condition re-raised each tick can't pile up: the row is skipped when
// the NEWEST row for its dedupe key — sent or not — is unsent with the same transition, level,
// kind and summary. Only the newest row counts: quiet hours hold warnings unsent for hours, so a
// re-fire queued behind a held or already-sent "resolved" must still be recorded, and a held
// warning must never swallow a critical raised under the same key (self-heal and disk GC use one
// key for both). A new summary or kind is a new state (a task that failed again, for another
// reason): it is recorded, so the message that combines the held rows reports the newest and
// counts every one.
//
// It also prunes the outbox (at most every outboxPruneEvery): producers enqueue whether or not
// alerting is enabled, and with alerting disabled nothing else would drop the rows.
func (s *Store) EnqueueInfra(ctx context.Context, o alert.Outbox) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO alert_outbox(rule_id, target, kind, level, transition, summary, dedupe_key, created_at)
		 SELECT 0, ?, ?, ?, ?, ?, ?, ?
		 WHERE NOT EXISTS (
		   SELECT 1 FROM (SELECT transition, level, kind, summary, sent_at FROM alert_outbox
		                   WHERE rule_id=0 AND dedupe_key=? ORDER BY id DESC LIMIT 1) AS newest
		    WHERE newest.sent_at=0 AND newest.transition=? AND newest.level=? AND newest.kind=? AND newest.summary=?)`,
		o.Target, o.Kind, o.Level, o.Transition, o.Summary, o.DedupeKey, time.Now().Unix(),
		o.DedupeKey, o.Transition, o.Level, o.Kind, o.Summary)
	// Intentional: the prune runs after the insert, on a bounded context of its own (maybePrune): run
	// first on the caller's, a slow prune spent the caller's deadline (the detection engine gives an
	// alert 3 seconds) and the alert was not recorded. The error returned is the insert's.
	s.maybePrune(ctx)
	return err
}

// CloseInfraAlert ends the infra alert open under o.DedupeKey without notifying anyone: the operator
// cleared it, or what it is about went away (a removed app). It records o — a "resolved" row — already
// closed, so the key's next episode starts after it (InfraResolveLevel, OpenInfraAlerts, the rows a
// message combines), and closes the key's unsent rows undelivered. It does nothing when the key's newest
// row isn't a "firing" one: no alert is open.
func (s *Store) CloseInfraAlert(ctx context.Context, o alert.Outbox) error {
	if o.DedupeKey == "" {
		return errors.New("alertstore: CloseInfraAlert needs a dedupe key")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var transition string
	err = tx.QueryRowContext(ctx, `SELECT transition FROM alert_outbox WHERE rule_id=0 AND dedupe_key=? ORDER BY id DESC LIMIT 1`,
		o.DedupeKey).Scan(&transition)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && transition != "firing") {
		return nil
	}
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	if _, err := tx.ExecContext(ctx, `UPDATE alert_outbox SET sent_at=? WHERE rule_id=0 AND dedupe_key=? AND sent_at=0`,
		now, o.DedupeKey); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO alert_outbox(rule_id, target, kind, level, transition, summary, dedupe_key, created_at, sent_at)
		 VALUES(0, ?, ?, ?, 'resolved', ?, ?, ?, ?)`,
		o.Target, o.Kind, o.Level, o.Summary, o.DedupeKey, now, now); err != nil {
		return err
	}
	return tx.Commit()
}

// maybePrune prunes the outbox when outboxPruneEvery has passed since the last time, within
// pruneTimeout of its own: the caller's context only passes on its values.
func (s *Store) maybePrune(ctx context.Context) {
	now := time.Now()
	next := s.nextPrune.Load()
	if now.Unix() < next || !s.nextPrune.CompareAndSwap(next, now.Add(outboxPruneEvery).Unix()) {
		return
	}
	pctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), pruneTimeout)
	defer cancel()
	s.PruneOutbox(pctx, now)
}

// InfraResolveLevel returns the level a "resolved" row for the infra alert under dedupeKey should carry:
// the highest level among the key's "firing" rows, delivered or not, since its last "resolved" row (a
// CloseInfraAlert row too). ok is false when no such firing row is recorded (never raised, or pruned).
func (s *Store) InfraResolveLevel(ctx context.Context, dedupeKey string) (level string, ok bool) {
	var n, crit int
	err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(MAX(level='critical'),0) FROM alert_outbox
		  WHERE rule_id=0 AND dedupe_key=? AND transition='firing'
		    AND id > COALESCE((SELECT MAX(id) FROM alert_outbox
		                        WHERE rule_id=0 AND dedupe_key=? AND transition='resolved'), 0)`,
		dedupeKey, dedupeKey).Scan(&n, &crit)
	if err != nil || n == 0 {
		return "", false
	}
	if crit == 1 {
		return alert.LevelCritical, true
	}
	return alert.LevelWarning, true
}

// InfraFiringRecorded reports whether a "firing" row of the infra alert under dedupeKey may be recorded in
// the key's current episode: since its last "resolved" row (a CloseInfraAlert row too). since is when the
// caller knows the episode began at the earliest (unix sec, wall clock; 0 = unknown). false is a positive
// answer: no such row is recorded and none can have been pruned, because the episode began inside the
// outbox retention — after since, or after the last "resolved" row was recorded, whichever is later. A read
// error is returned with true.
func (s *Store) InfraFiringRecorded(ctx context.Context, dedupeKey string, since int64) (bool, error) {
	var n int
	var resolvedAt int64
	err := s.db.QueryRowContext(ctx,
		`SELECT (SELECT COUNT(*) FROM alert_outbox
		          WHERE rule_id=0 AND dedupe_key=? AND transition='firing'
		            AND id > COALESCE((SELECT MAX(id) FROM alert_outbox
		                                WHERE rule_id=0 AND dedupe_key=? AND transition='resolved'), 0)),
		        COALESCE((SELECT created_at FROM alert_outbox WHERE rule_id=0 AND dedupe_key=? AND transition='resolved'
		                   ORDER BY id DESC LIMIT 1), 0)`,
		dedupeKey, dedupeKey, dedupeKey).Scan(&n, &resolvedAt)
	if err != nil {
		return true, err
	}
	if n > 0 {
		return true, nil
	}
	// A row of the episode was raised after since and after the last resolve, so it was closed after them
	// too; the prune deletes only rows closed before the retention.
	return max(since, resolvedAt) < time.Now().Add(-outboxSentRetention).Unix(), nil
}

// OpenInfraAlerts returns, for every dedupe key of the given infra alert kind whose most recent outbox
// row of that kind, delivered or not, is a "firing" transition, that row's target. A restarted process
// uses it to re-adopt the alerts it raised before the restart, so their "resolved" is still sent. (Rows
// past the outbox retention are gone, and with them any memory of the alert. A row left unsent for 48
// hours is closed, not deleted, so it outlives the rows raised before it.)
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

// ChannelsForRule returns the channels a rule routes to (its channel_id, or all
// enabled channels when channel_id is NULL/0).
func (s *Store) ChannelsForRule(channelID int64) ([]BuiltChannel, error) {
	if channelID != 0 {
		c, err := s.channel(channelID)
		if err != nil {
			return nil, err
		}
		return []BuiltChannel{{ID: channelID, Channel: c}}, nil
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
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var out []BuiltChannel
	for _, id := range ids {
		if c, err := s.channel(id); err == nil {
			out = append(out, BuiltChannel{ID: id, Channel: c})
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

// SaveStates upserts the state set and prunes ok rows to keep the table bounded. The states come from a
// LoadStates done before evaluating, so an existing row keeps what the operator set since: its silence
// (only Silence changes it) and, within the same phase, its ack. A new phase takes the state's ack, which
// the evaluator clears when an episode ends. An ok row whose silence hasn't ended is kept, at ok with no
// ack, so a firing inside the silence is still silenced (EnqueueOutbox); the first save after the silence
// ends deletes it. An ok state never creates a row.
func (s *Store) SaveStates(ctx context.Context, states []alert.State) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	for _, st := range states {
		if st.Phase == alert.PhaseOK {
			// The row's own silenced_until decides, not the state's: a silence set or lifted since the load counts.
			if _, err := tx.ExecContext(ctx,
				`UPDATE alert_state SET phase=?, since=?, level=?, detail=?, acked=0, updated_at=?
				  WHERE rule_id=? AND target=? AND silenced_until>?`,
				string(st.Phase), st.Since, st.Level, st.Detail, now, st.RuleID, st.Target, now); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM alert_state WHERE rule_id=? AND target=? AND silenced_until<=?`,
				st.RuleID, st.Target, now); err != nil {
				return err
			}
			continue
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO alert_state(rule_id, target, phase, since, level, detail, acked, silenced_until, updated_at)
			 VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(rule_id, target) DO UPDATE SET
			   phase=excluded.phase, since=excluded.since, level=excluded.level, detail=excluded.detail,
			   acked=CASE WHEN alert_state.phase=excluded.phase AND alert_state.since=excluded.since
			              THEN MAX(alert_state.acked, excluded.acked) ELSE excluded.acked END,
			   updated_at=excluded.updated_at`,
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

// Silence silences a rule's alert on one target until the unix time until. It also closes the alert's
// unsent outbox rows undelivered (quiet hours may be holding them), and EnqueueOutbox records any row the
// alert raises while silenced already closed: the silence is applied when a row is raised, not when it
// would be sent, by which time the state that holds silenced_until may be gone. Mooring's own alerts
// (rule 0) have no silence.
func (s *Store) Silence(ctx context.Context, ruleID int64, target string, until int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE alert_state SET silenced_until=? WHERE rule_id=? AND target=?`, until, ruleID, target); err != nil {
		return err
	}
	if now := time.Now().Unix(); ruleID > 0 && until > now {
		if _, err := tx.ExecContext(ctx, `UPDATE alert_outbox SET sent_at=? WHERE rule_id=? AND target=? AND sent_at=0`,
			now, ruleID, target); err != nil {
			return err
		}
	}
	return tx.Commit()
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
	CreatedAt  int64 // unix sec
}

// AlertKey names the alert the row belongs to (see alertWhere): rows with the same key are one alert.
func (r OutboxRow) AlertKey() string {
	switch {
	case r.RuleID != 0:
		return fmt.Sprintf("rule:%d:%s", r.RuleID, r.Target)
	case r.DedupeKey != "":
		return "infra:" + r.DedupeKey
	}
	return fmt.Sprintf("row:%d", r.ID)
}

// alertWhere returns the SQL predicate, and its args, selecting every row of r's alert. A rule's alert is
// one (rule, target) — the key of its alert_state row; its dedupe key also names the rule's kind, which an
// edit can change mid-alert. A Mooring infra alert (rule_id 0) is one dedupe key. An infra row without a
// dedupe key is an alert of its own (no producer sends one today).
func alertWhere(r OutboxRow) (string, []any) {
	switch {
	case r.RuleID != 0:
		return "rule_id=? AND target=?", []any{r.RuleID, r.Target}
	case r.DedupeKey != "":
		return "rule_id=0 AND dedupe_key=?", []any{r.DedupeKey}
	}
	return "id=?", []any{r.ID}
}

// EnqueueOutbox appends notifications the evaluator produced (it never sends). A row raised while its
// (rule, target) state is silenced is recorded already closed (see Silence).
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
			`INSERT INTO alert_outbox(rule_id, target, kind, level, transition, summary, dedupe_key, created_at, sent_at)
			 SELECT ?, ?, ?, ?, ?, ?, ?, ?,
			        CASE WHEN EXISTS (SELECT 1 FROM alert_state WHERE rule_id=? AND target=? AND silenced_until>?) THEN ? ELSE 0 END`,
			o.RuleID, o.Target, o.Kind, o.Level, o.Transition, o.Summary, o.DedupeKey, now,
			o.RuleID, o.Target, now, now); err != nil {
			return err
		}
	}
	return tx.Commit()
}

const outboxColumns = `id, rule_id, target, kind, level, transition, summary, dedupe_key, attempts, created_at`

// PendingOutbox returns unsent rows, oldest first.
func (s *Store) PendingOutbox(limit int) ([]OutboxRow, error) {
	return s.queryOutbox(`SELECT `+outboxColumns+` FROM alert_outbox WHERE sent_at=0 ORDER BY id LIMIT ?`, limit)
}

// PendingAlerts returns, for each alert with unsent rows due at now, its oldest such row, oldest first: the
// notifier's batch, one entry per alert however many rows it has. A row is due unless a failed delivery
// set it to back off (next_try_at). criticalOnly limits it to alerts with an unsent, due critical row
// (their oldest one): the quiet-hours batch, during which every other alert is held. The level is filtered
// before the LIMIT, so any number of held rows can't keep a critical alert out of the batch. The grouping
// is alertWhere's alert identity.
//
// Intentional: criticalOnly looks at unsent rows only. An alert whose message is critical only because of
// a given-up critical row (PendingAlert combines it) is held through quiet hours like a warning (owner
// decision): a critical that already failed for 24 hours doesn't page again at night.
func (s *Store) PendingAlerts(limit int, criticalOnly bool, now time.Time) ([]OutboxRow, error) {
	level := ""
	if criticalOnly {
		level = alert.LevelCritical
	}
	return s.queryOutbox(`SELECT `+outboxColumns+` FROM alert_outbox WHERE id IN (
		  SELECT MIN(id) FROM alert_outbox WHERE sent_at=0 AND next_try_at<=? AND (?='' OR level=?)
		   GROUP BY rule_id, CASE WHEN rule_id<>0 THEN 't:'||target
		                          WHEN dedupe_key<>'' THEN 'k:'||dedupe_key
		                          ELSE 'i:'||id END)
		ORDER BY id LIMIT ?`, now.Unix(), level, level, limit)
}

func (s *Store) queryOutbox(query string, args ...any) ([]OutboxRow, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OutboxRow
	for rows.Next() {
		var o OutboxRow
		if err := rows.Scan(&o.ID, &o.RuleID, &o.Target, &o.Kind, &o.Level, &o.Transition, &o.Summary, &o.DedupeKey, &o.Attempts, &o.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// PendingAlert is what the notifier sends for one alert: every undelivered row of the alert combined
// into one message. The rule, in full:
//   - The rows combined are the alert's unsent rows plus the rows given up (closed after their
//     deliveries kept failing) since the alert's last row closed otherwise — delivered, or dropped on
//     purpose (silenced, the alert closed by CloseInfraAlert, 48 hours unsent) — before its oldest
//     unsent row. A given-up critical is reported with the next message, and nothing the operator
//     already got or chose not to get is reported again.
//   - The message reports the newest of them, at critical level when any of them is critical.
//   - A delivered message closes every unsent row it combined, never a row raised after it was read.
//   - A failed delivery counts an attempt against every unsent row the message combined (in the
//     quiet-hours pass only against its critical rows: held warnings keep theirs). A message that isn't
//     critical is tried warningAttempts times; a critical one backs off and is retried until its rows
//     are criticalRetryFor old. Then the rows are given up: closed, and reported again by the alert's
//     next message.
type PendingAlert struct {
	Latest   OutboxRow // the newest combined row: the state the message reports
	Level    string    // critical when any combined row is critical, else Latest's level
	Count    int       // rows combined
	Fired    int       // of them "firing"
	Resolved int       // of them "resolved"
	Since    int64     // created_at of the oldest combined row (unix sec)
	First    string    // transition of the oldest combined row

	newestUnsent int64 // the newest unsent row combined: a delivery closes the unsent rows up to it
	criticalOnly bool  // read for the quiet-hours pass
}

// PendingAlert returns the combination of every undelivered row of row's alert (see PendingAlert and
// alertWhere). criticalOnly: it is read for the quiet-hours pass, in which a failure counts only against
// the critical rows. ok is false when the alert has no unsent row any more.
func (s *Store) PendingAlert(row OutboxRow, criticalOnly bool) (PendingAlert, bool, error) {
	where, args := alertWhere(row)
	qargs := append(append(append([]any{}, args...), args...), args...)
	p := PendingAlert{criticalOnly: criticalOnly}
	var latestID, firstID int64
	var crit int
	err := s.db.QueryRow(
		`SELECT COUNT(*), COALESCE(MIN(created_at),0), COALESCE(MAX(id),0), COALESCE(MIN(id),0),
		        COALESCE(MAX(CASE WHEN sent_at=0 THEN id END),0),
		        COALESCE(SUM(transition='firing'),0), COALESCE(SUM(transition='resolved'),0),
		        COALESCE(MAX(level='critical'),0)
		   FROM alert_outbox
		  WHERE `+where+` AND (sent_at=0 OR given_up=1)
		    AND id > COALESCE((SELECT MAX(id) FROM alert_outbox WHERE `+where+` AND sent_at>0 AND given_up=0
		                         AND id < (SELECT MIN(id) FROM alert_outbox WHERE `+where+` AND sent_at=0)), 0)`, qargs...).
		Scan(&p.Count, &p.Since, &latestID, &firstID, &p.newestUnsent, &p.Fired, &p.Resolved, &crit)
	if err != nil {
		return PendingAlert{}, false, err
	}
	if p.newestUnsent == 0 {
		return PendingAlert{}, false, nil
	}
	ends, err := s.queryOutbox(`SELECT `+outboxColumns+` FROM alert_outbox WHERE id IN (?, ?) ORDER BY id`, firstID, latestID)
	if err != nil {
		return PendingAlert{}, false, err
	}
	if len(ends) == 0 || ends[len(ends)-1].ID != latestID { // pruned in between
		return PendingAlert{}, false, nil
	}
	p.First = ends[0].Transition
	p.Latest, p.Level = ends[len(ends)-1], ends[len(ends)-1].Level
	if crit == 1 {
		p.Level = alert.LevelCritical
	}
	return p, true, nil
}

// FinishAlert records the outcome of one delivery of p at now. delivered (or dropped on purpose: silenced,
// rule deleted) closes every unsent row p combined. Otherwise one failed attempt is counted against them
// (see PendingAlert): a critical message's rows back off 15 seconds, doubling, at most an hour, and are
// given up once criticalRetryFor old; any other message's rows are tried again by the next drain and
// given up after warningAttempts attempts. Giving up means a permanently failing channel can't wedge the
// queue. It returns the write's error; the rows are then left as they were (unsent, and due again).
func (s *Store) FinishAlert(ctx context.Context, p PendingAlert, delivered bool, now time.Time) error {
	where, args := alertWhere(p.Latest)
	ts := now.Unix()
	if delivered {
		_, err := s.db.ExecContext(ctx, `UPDATE alert_outbox SET sent_at=? WHERE sent_at=0 AND id<=? AND `+where,
			append([]any{ts, p.newestUnsent}, args...)...)
		return err
	}
	only := ""
	if p.criticalOnly {
		only = " AND level='critical'"
	}
	crit := b2i(p.Level == alert.LevelCritical)
	// Every SET expression reads the row's values from before the update (attempts is the count before
	// this failure).
	giveUp := `((?=0 AND attempts+1>=?) OR (?=1 AND created_at<=?))`
	giveUpArgs := []any{crit, warningAttempts, crit, now.Add(-criticalRetryFor).Unix()}
	q := `UPDATE alert_outbox SET attempts=attempts+1,
	        next_try_at=CASE WHEN ?=1 THEN ? + MIN(?, ? << MIN(attempts, 20)) ELSE 0 END,
	        given_up=CASE WHEN ` + giveUp + ` THEN 1 ELSE 0 END,
	        sent_at=CASE WHEN ` + giveUp + ` THEN ? ELSE 0 END
	      WHERE sent_at=0 AND id<=? AND ` + where + only
	qargs := []any{crit, ts, criticalBackoffMax, criticalBackoff}
	qargs = append(qargs, giveUpArgs...)
	qargs = append(qargs, giveUpArgs...)
	qargs = append(qargs, ts, p.newestUnsent)
	_, err := s.db.ExecContext(ctx, q, append(qargs, args...)...)
	return err
}

// PruneOutbox bounds the outbox: rows closed more than 7 days ago are deleted, and rows still unsent 48
// hours after they were raised are closed. The notifier calls it each cycle and EnqueueInfra every 10
// minutes, so it also runs with alerting disabled.
func (s *Store) PruneOutbox(ctx context.Context, now time.Time) {
	if s.beforePrune != nil {
		s.beforePrune(ctx)
	}
	_, _ = s.db.ExecContext(ctx, `DELETE FROM alert_outbox WHERE sent_at>0 AND sent_at<?`, now.Add(-outboxSentRetention).Unix())
	// Intentional: closed unsent, not given up. A row this old was raised while alerting was disabled or no
	// channel worked (quiet hours hold a row less than a day, a critical is retried for a day), and
	// replaying it when alerting comes back would report long-gone states. Closed rather than deleted, so
	// it outlives the rows raised before it: deleting a never-sent "resolved" while the sent "firing"
	// before it is kept would make the alert look open again (OpenInfraAlerts, InfraResolveLevel).
	_, _ = s.db.ExecContext(ctx, `UPDATE alert_outbox SET sent_at=? WHERE sent_at=0 AND created_at<?`,
		now.Unix(), now.Add(-outboxUnsentMaxAge).Unix())
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
