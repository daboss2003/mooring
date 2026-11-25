package detect

import (
	"cmp"
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

// False-positive mutes: a rule's detections for one entity (its key as an account or address) are
// recorded marked muted, but alert nothing and join no incident, until the mute ends. They are
// stored in Mooring's database (table security_mutes) like the rule settings, and put in force as
// an immutable set (Engine.mutes) the engine reads without a lock.

const (
	muteFor      = 30 * 24 * time.Hour
	maxMutes     = 10000 // mutes in force
	maxMutePairs = 1000  // pairs one false positive mutes
)

type muteKey struct {
	rule string
	ent  incEnt
}

// muteSet is the mutes in force; never modified once built.
type muteSet struct {
	m map[muteKey]siem.Mute
}

// isMuted reports whether rule's detections for k are muted at now.
func (e *Engine) isMuted(rule string, k incEnt, now time.Time) bool {
	ms := e.mutes.Load()
	if ms == nil {
		return false
	}
	m, ok := ms.m[muteKey{rule, k}]
	return ok && m.Until.After(now)
}

// rebuildMutes puts e.muteRows in force, without the ones that ended (under mu, or before Run).
func (e *Engine) rebuildMutes() {
	now := e.now()
	ms := &muteSet{m: make(map[muteKey]siem.Mute, len(e.muteRows))}
	for k, m := range e.muteRows {
		if m.Until.After(now) {
			ms.m[k] = m
		}
	}
	e.mutes.Store(ms)
}

// muteStore keeps the mutes in Mooring's database.
type muteStore struct {
	db *sql.DB
}

// load removes the mutes that ended and reads the others (at most 2×maxMutes).
func (s *muteStore) load(ctx context.Context, now time.Time) (map[muteKey]siem.Mute, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM security_mutes WHERE until_at <= ?`, now.Unix()); err != nil {
		return nil, err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT rule_id, kind, scope, key, until_at, by_user, incident_id, created_at
		FROM security_mutes LIMIT ?`, 2*maxMutes)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[muteKey]siem.Mute{}
	for rows.Next() {
		var (
			m              siem.Mute
			until, created int64
		)
		if err := rows.Scan(&m.RuleID, &m.Entity.Kind, &m.Entity.Scope, &m.Entity.Key, &until, &m.By, &m.IncidentID,
			&created); err != nil {
			return nil, err
		}
		m.Until, m.Created = time.Unix(until, 0).UTC(), time.Unix(created, 0).UTC()
		if validEntity(m.Entity) != nil || m.RuleID == "" {
			continue
		}
		out[muteKey{m.RuleID, entOf(m.Entity)}] = m
	}
	return out, rows.Err()
}

// put stores mutes (replacing a stored one of the same rule and entity) and removes the ones that
// ended, in one transaction.
func (s *muteStore) put(ctx context.Context, ms []siem.Mute, now time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM security_mutes WHERE until_at <= ?`, now.Unix()); err != nil {
		return err
	}
	for _, m := range ms {
		if _, err := tx.ExecContext(ctx, `INSERT INTO security_mutes(rule_id, kind, scope, key, until_at, by_user,
			incident_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(rule_id, kind, scope, key) DO UPDATE SET until_at = excluded.until_at, by_user = excluded.by_user,
			incident_id = excluded.incident_id, created_at = excluded.created_at`,
			m.RuleID, m.Entity.Kind, m.Entity.Scope, m.Entity.Key, m.Until.Unix(), m.By, m.IncidentID, m.Created.Unix()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// del removes one mute and reports how many rows it removed.
func (s *muteStore) del(ctx context.Context, rule string, k incEnt) (int64, error) {
	return s.exec(ctx, `DELETE FROM security_mutes WHERE rule_id = ? AND kind = ? AND scope = ? AND key = ?`,
		rule, k.kind, k.scope, k.key)
}

func (s *muteStore) exec(ctx context.Context, q string, args ...any) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	res, err := s.db.ExecContext(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// liftMutes removes the mutes incident id made, from Mooring's database and from the set in
// force, and returns how many of them were in force.
func (e *Engine) liftMutes(ctx context.Context, id int64) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := e.ms.exec(ctx, `DELETE FROM security_mutes WHERE incident_id = ?`, id); err != nil {
		return 0, err
	}
	now, n := e.now(), 0
	for k, m := range e.muteRows {
		if m.IncidentID == id {
			if m.Until.After(now) {
				n++
			}
			delete(e.muteRows, k)
		}
	}
	e.rebuildMutes()
	return n, nil
}

// incidentMutes returns the mutes in force that incident id made, by rule then entity.
func (e *Engine) incidentMutes(id int64) []siem.Mute {
	ms := e.mutes.Load()
	if ms == nil {
		return nil
	}
	now := e.now()
	var out []siem.Mute
	for _, m := range ms.m {
		if m.IncidentID == id && m.Until.After(now) {
			out = append(out, m)
		}
	}
	slices.SortFunc(out, func(a, b siem.Mute) int {
		return cmp.Or(strings.Compare(a.RuleID, b.RuleID), strings.Compare(entOf(a.Entity).String(), entOf(b.Entity).String()))
	})
	return out
}

// DeleteAppMutes removes the false-positive mutes of an app's accounts (scope "app:<slug>"), from
// Mooring's database and from the set in force: the app is being deleted. Its incidents and
// detections stay, as security records.
func (e *Engine) DeleteAppMutes(ctx context.Context, slug string) error {
	if slug == "" {
		return invalidIn("the app is empty")
	}
	if err := checkName("the app", slug, siem.MaxShort); err != nil {
		return err
	}
	if e.ms == nil {
		return nil // no Mooring database: no mutes
	}
	scope := "app:" + slug
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, err := e.ms.exec(ctx, `DELETE FROM security_mutes WHERE kind = ? AND scope = ?`, siem.EntityAccount, scope); err != nil {
		return err
	}
	for k := range e.muteRows {
		if k.ent.kind == siem.EntityAccount && k.ent.scope == scope {
			delete(e.muteRows, k)
		}
	}
	e.rebuildMutes()
	return nil
}

// addMutes mutes each (rule, entity) pair of pairs until until, for a false positive of incident
// id marked by actor, and puts them in force.
func (e *Engine) addMutes(ctx context.Context, pairs []siem.Mute, until time.Time, actor string, id int64) error {
	if e.ms == nil {
		return ErrNoStore
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.now()
	live := 0
	for _, m := range e.muteRows {
		if m.Until.After(now) {
			live++
		}
	}
	rows := make([]siem.Mute, 0, len(pairs))
	added := 0
	for _, p := range pairs {
		k := muteKey{p.RuleID, entOf(p.Entity)}
		if old, ok := e.muteRows[k]; !ok || !old.Until.After(now) {
			added++
		}
		rows = append(rows, siem.Mute{RuleID: p.RuleID, Entity: p.Entity, Until: until.UTC().Truncate(time.Second),
			By: actor, IncidentID: id, Created: now.UTC().Truncate(time.Second)})
	}
	if live+added > maxMutes {
		return invalidIn("at most %d mutes can be in force (%d are); remove some on the entity pages", maxMutes, live)
	}
	if err := e.ms.put(ctx, rows, now); err != nil {
		return err
	}
	for k, m := range e.muteRows {
		if !m.Until.After(now) {
			delete(e.muteRows, k)
		}
	}
	for _, m := range rows {
		e.muteRows[muteKey{m.RuleID, entOf(m.Entity)}] = m
	}
	e.rebuildMutes()
	return nil
}

// KeepAppMutes removes the false-positive mutes of the accounts of every app not in slugs (scope
// "app:<slug>"), from Mooring's database and from the set in force: serve calls it at start with
// the apps that exist, for an app deleted while detection was off. slugs is the complete list: an
// empty one removes the mutes of every app. Other scopes ("app" with no slug among them) stay.
func (e *Engine) KeepAppMutes(ctx context.Context, slugs []string) error {
	if e.ms == nil {
		return nil // no Mooring database: no mutes
	}
	keep := make(map[string]bool, len(slugs))
	for _, s := range slugs {
		keep["app:"+s] = true
	}
	gone := func(scope string) bool { return strings.HasPrefix(scope, "app:") && !keep[scope] }
	e.mu.Lock()
	defer e.mu.Unlock()
	scopes, err := e.ms.appScopes(ctx)
	if err != nil {
		return err
	}
	var drop []string
	for _, s := range scopes {
		if gone(s) {
			drop = append(drop, s)
		}
	}
	if err := e.ms.delScopes(ctx, drop); err != nil {
		return err
	}
	for k := range e.muteRows {
		if k.ent.kind == siem.EntityAccount && gone(k.ent.scope) {
			delete(e.muteRows, k)
		}
	}
	e.rebuildMutes()
	return nil
}

// appScopes returns the app scopes ("app:<slug>") of the stored account mutes.
func (s *muteStore) appScopes(ctx context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT scope FROM security_mutes WHERE kind = ? AND substr(scope, 1, 4) = 'app:'`,
		siem.EntityAccount)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var sc string
		if err := rows.Scan(&sc); err != nil {
			return nil, err
		}
		out = append(out, sc)
	}
	return out, rows.Err()
}

// delScopes removes the account mutes of the given scopes, in one transaction.
func (s *muteStore) delScopes(ctx context.Context, scopes []string) error {
	if len(scopes) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, sc := range scopes {
		if _, err := tx.ExecContext(ctx, `DELETE FROM security_mutes WHERE kind = ? AND scope = ?`, siem.EntityAccount, sc); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// invalidIn is a validation error of the IncidentService (it wraps siem.ErrInvalidInput).
func invalidIn(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{siem.ErrInvalidInput}, a...)...)
}
