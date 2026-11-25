package detect

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

// The incident tables of detect.db (migration 0005). Engine-goroutine reads and writes use the
// write connection; the dashboard reads use the read-only pool.

const incCols = `id, state, severity, sev_rank, alert_rank, alerted_rank, alerted_ns, title, chain, entities, rules,
	first_ns, last_ns, detections, assignee, created_ns, updated_ns`

// activeSQL selects the IDs of open and acknowledged incidents.
const activeSQL = `SELECT id FROM incidents WHERE state IN ('open', 'acknowledged')`

// manualKinds are the timeline entries the dashboard adds (counted against maxManual).
const manualKinds = `('state', 'assigned', 'note', 'muted')`

var errIncidentGone = errors.New("detect: incident removed")

func prefixed(cols, p string) string {
	parts := strings.Split(cols, ",")
	for i, c := range parts {
		parts[i] = p + strings.TrimSpace(c)
	}
	return strings.Join(parts, ", ")
}

func timeNS(ns int64) time.Time {
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns).UTC()
}

func scanIncident(sc interface{ Scan(...any) error }) (*incident, error) {
	var (
		inc                      incident
		sev, ents, rules         string
		alertedNS, first, last   int64
		created, updated, ndet64 int64
	)
	if err := sc.Scan(&inc.id, &inc.state, &sev, &inc.sev, &inc.alertSev, &inc.alerted, &alertedNS, &inc.title,
		&inc.chain, &ents, &rules, &first, &last, &ndet64, &inc.assignee, &created, &updated); err != nil {
		return nil, err
	}
	inc.sev = min(max(inc.sev, 0), 4)
	if inc.alertSev == realertRank {
		inc.realert = 1
	}
	inc.alertSev, inc.alerted = min(max(inc.alertSev, 0), 4), min(max(inc.alerted, 0), 4)
	inc.alertedAt, inc.first, inc.last = timeNS(alertedNS), timeNS(first), timeNS(last)
	inc.created, inc.updated = timeNS(created), timeNS(updated)
	inc.ndet = int(min(max(ndet64, 0), 1<<31-1))
	inc.titleRank = inc.sev
	if inc.chain != "" {
		inc.titleRank = chainTitleRank
	}
	if ents != "" {
		var es []siem.Entity
		if json.Unmarshal([]byte(ents), &es) == nil {
			// The engine's own entities are kept whatever their text (a key can hold a control
			// character an app logged); public() lists only those the dashboard can name.
			for i, x := range es {
				if !entityShape(x) {
					continue
				}
				k := entOf(x)
				if i == 0 {
					inc.key = k // the first is the key entity (it opened the incident)
				}
				if len(inc.ents) < maxIncEntities && !slices.Contains(inc.ents, k) {
					inc.ents = append(inc.ents, k)
				}
			}
		}
	}
	if rules != "" {
		inc.rules = strings.Split(rules, ",")
		inc.rules = inc.rules[:min(len(inc.rules), maxIncRules)]
	}
	return &inc, nil
}

// entityShape reports whether x is an entity the engine can have made: an account or an address
// with a key, within the lengths it keeps (its text isn't checked: see validEntity).
func entityShape(x siem.Entity) bool {
	switch x.Kind {
	case siem.EntityAccount:
	case siem.EntityAddress:
		if x.Scope != "" {
			return false
		}
	default:
		return false
	}
	return x.Key != "" && len(x.Key) <= siem.MaxShort && len(x.Scope) <= siem.MaxShort+4
}

// public is the incident as the dashboard sees it (without its timeline): the entities it can name
// (validEntity) only.
func (inc *incident) public() siem.Incident {
	out := siem.Incident{ID: inc.id, State: inc.state, Severity: rankSeverity(inc.sev), Title: inc.title,
		Chain: inc.chain, First: inc.first, Last: inc.last, Detections: inc.ndet, Rules: slices.Clone(inc.rules),
		Assignee: inc.assignee, Updated: inc.updated, Entities: make([]siem.Entity, 0, len(inc.ents))}
	for _, k := range inc.ents {
		if x := k.entity(); validEntity(x) == nil {
			out.Entities = append(out.Entities, x)
		}
	}
	return out
}

// incRow is an incident's row as written.
type incRow struct {
	id                          int64
	state, severity             string
	sevRank, alertRank, alerted int
	alertedNS                   int64
	title, chain, ents, rules   string
	first, last                 int64
	detections                  int
	assignee                    string
	created, updated            int64
}

// realertRank is the alert_rank stored for a critical incident owing a re-alert (chainJoined).
// Intentional: stored in the rank column (one above critical) rather than a column of its own, so
// the startup read of incidents owing an alert (alert_rank > alerted_rank) takes it too.
const realertRank = 5

func (inc *incident) row() incRow {
	es := make([]siem.Entity, 0, len(inc.ents))
	for _, k := range inc.ents {
		es = append(es, k.entity())
	}
	b, _ := json.Marshal(es)
	alertRank := inc.alertSev
	if inc.realert > 0 && alertRank == 4 {
		alertRank = realertRank
	}
	return incRow{id: inc.id, state: inc.state, severity: string(rankSeverity(inc.sev)), sevRank: inc.sev,
		alertRank: alertRank, alerted: inc.alerted, alertedNS: nanos(inc.alertedAt), title: inc.title,
		chain: inc.chain, ents: string(b), rules: strings.Join(inc.rules, ","), first: nanos(inc.first),
		last: nanos(inc.last), detections: inc.ndet, assignee: inc.assignee, created: nanos(inc.created),
		updated: nanos(inc.updated)}
}

// incEntRow is one incident_entities row; inc indexes incBatch.incs.
type incEntRow struct {
	inc         int
	k           incEnt
	first, last int64
}

// incTLRow is one timeline row; inc indexes incBatch.incs, det the batch's detections (-1: detID).
type incTLRow struct {
	inc   int
	det   int
	detID int64
	ev    siem.IncidentEvent
}

type riskRow struct {
	k     incEnt
	score float64
	at    time.Time
}

// incBatch is what a detection write stores of incidents in the same transaction.
type incBatch struct {
	incs    []incRow
	detInc  []int // per detection: the index in incs of its incident (-1: its stored incID)
	ents    []incEntRow
	tl      []incTLRow
	risk    []riskRow
	riskDel []incEnt
}

// writeIncidents is the first part of a write: it inserts or updates the batch's incidents and
// returns their IDs.
func writeIncidents(ctx context.Context, tx *sql.Tx, b *incBatch) ([]int64, error) {
	ids := make([]int64, len(b.incs))
	for i, r := range b.incs {
		if r.id != 0 {
			res, err := tx.ExecContext(ctx, `UPDATE incidents SET state = ?, severity = ?, sev_rank = ?, alert_rank = ?,
				alerted_rank = MAX(alerted_rank, ?), alerted_ns = MAX(alerted_ns, ?), title = ?, chain = ?, entities = ?,
				rules = ?, first_ns = ?, last_ns = ?, detections = ?, assignee = ?, updated_ns = ? WHERE id = ?`,
				r.state, r.severity, r.sevRank, r.alertRank, r.alerted, r.alertedNS, r.title, r.chain, r.ents, r.rules,
				r.first, r.last, r.detections, r.assignee, r.updated, r.id)
			if err != nil {
				return nil, err
			}
			if n, err := res.RowsAffected(); err != nil {
				return nil, err
			} else if n > 0 {
				ids[i] = r.id
				continue
			}
			// Removed (retention) while still in memory: stored again under a new ID.
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO incidents(state, severity, sev_rank, alert_rank, alerted_rank,
			alerted_ns, title, chain, entities, rules, first_ns, last_ns, detections, assignee, created_ns, updated_ns)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			r.state, r.severity, r.sevRank, r.alertRank, r.alerted, r.alertedNS, r.title, r.chain, r.ents, r.rules,
			r.first, r.last, r.detections, r.assignee, r.created, r.updated)
		if err != nil {
			return nil, err
		}
		if ids[i], err = res.LastInsertId(); err != nil {
			return nil, err
		}
	}
	return ids, nil
}

// writeIncidentRest is the last part of a write: entities, timeline entries (trimmed), risk.
func writeIncidentRest(ctx context.Context, tx *sql.Tx, b *incBatch, incIDs, detIDs []int64) error {
	for _, r := range b.ents {
		if _, err := tx.ExecContext(ctx, `INSERT INTO incident_entities(incident_id, kind, scope, key, first_ns, last_ns)
			VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(incident_id, kind, scope, key) DO UPDATE SET
			first_ns = MIN(first_ns, excluded.first_ns), last_ns = MAX(last_ns, excluded.last_ns)`,
			incIDs[r.inc], r.k.kind, r.k.scope, r.k.key, r.first, r.last); err != nil {
			return err
		}
	}
	trim := map[int64]bool{}
	for _, t := range b.tl {
		id := incIDs[t.inc]
		det := t.detID
		if t.det >= 0 {
			det = detIDs[t.det]
		}
		t.ev.DetectionID = det
		if err := insertTimeline(ctx, tx, id, t.ev); err != nil {
			return err
		}
		trim[id] = true
	}
	for id := range trim {
		if err := trimTimeline(ctx, tx, id); err != nil {
			return err
		}
	}
	for _, r := range b.risk {
		if _, err := tx.ExecContext(ctx, `INSERT INTO entity_risk(kind, scope, key, score, updated_ns, rank)
			VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(kind, scope, key) DO UPDATE SET score = excluded.score,
			updated_ns = excluded.updated_ns, rank = excluded.rank`,
			r.k.kind, r.k.scope, r.k.key, r.score, r.at.UnixNano(), riskRank(r.score, r.at)); err != nil {
			return err
		}
	}
	for _, k := range b.riskDel {
		if _, err := tx.ExecContext(ctx, `DELETE FROM entity_risk WHERE kind = ? AND scope = ? AND key = ?`,
			k.kind, k.scope, k.key); err != nil {
			return err
		}
	}
	return nil
}

func insertTimeline(ctx context.Context, tx *sql.Tx, id int64, ev siem.IncidentEvent) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO incident_timeline(incident_id, ts_ns, kind, detection_id, rule_id,
		rule_name, severity, actor, text) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, id, nanos(ev.TS), ev.Kind, ev.DetectionID,
		ev.RuleID, ev.RuleName, string(ev.Severity), ev.Actor, ev.Text)
	return err
}

// trimTimeline keeps an incident's timeline within maxTimeline entries by removing its oldest
// detection entries (never another kind).
func trimTimeline(ctx context.Context, tx *sql.Tx, id int64) error {
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM incident_timeline WHERE incident_id = ?`, id).Scan(&n); err != nil {
		return err
	}
	if n <= maxTimeline {
		return nil
	}
	_, err := tx.ExecContext(ctx, `DELETE FROM incident_timeline WHERE id IN (SELECT id FROM incident_timeline
		WHERE incident_id = ? AND kind = 'detection' ORDER BY id LIMIT ?)`, id, n-maxTimeline)
	return err
}

// applyChange stores a dashboard change of an incident: its state, assignee and updated time, and
// the timeline entries, in one transaction.
func (d *db) applyChange(id int64, state, assignee string, updated time.Time, entries []siem.IncidentEvent) error {
	ctx, cancel := context.WithTimeout(context.Background(), batchTimeout)
	defer cancel()
	tx, err := d.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.ExecContext(ctx, `UPDATE incidents SET state = ?, assignee = ?, updated_ns = ? WHERE id = ?`,
		state, assignee, nanos(updated), id)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return errIncidentGone
	}
	for _, ev := range entries {
		if err := insertTimeline(ctx, tx, id, ev); err != nil {
			return err
		}
	}
	if len(entries) > 0 {
		if err := trimTimeline(ctx, tx, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// addTimeline stores timeline entries of an incident (false: it is gone).
func (d *db) addTimeline(id int64, entries []siem.IncidentEvent) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), batchTimeout)
	defer cancel()
	tx, err := d.w.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM incidents WHERE id = ?`, id).Scan(&n); err != nil || n == 0 {
		return false, err
	}
	for _, ev := range entries {
		if err := insertTimeline(ctx, tx, id, ev); err != nil {
			return false, err
		}
	}
	if err := trimTimeline(ctx, tx, id); err != nil {
		return false, err
	}
	return true, tx.Commit()
}

// loadIncident reads one incident with its entities' times and the count of dashboard entries in
// its timeline (engine goroutine).
func (d *db) loadIncident(id int64) (*incident, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	inc, err := scanIncident(d.w.QueryRowContext(ctx, `SELECT `+incCols+` FROM incidents WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	byID := map[int64]*incident{id: inc}
	if err := d.incidentEntities(ctx, `incident_id = ?`, []any{id}, byID); err != nil {
		return nil, false, err
	}
	if err := d.w.QueryRowContext(ctx, `SELECT COUNT(*) FROM incident_timeline WHERE incident_id = ? AND kind IN `+
		manualKinds, id).Scan(&inc.manual); err != nil {
		return nil, false, err
	}
	return inc, true, nil
}

// incidentEntities reads the incident_entities rows matching where into the incidents of byID: the
// entities listed on an incident get their times.
func (d *db) incidentEntities(ctx context.Context, where string, args []any, byID map[int64]*incident) error {
	rows, err := d.w.QueryContext(ctx, `SELECT incident_id, kind, scope, key, first_ns, last_ns FROM incident_entities
		WHERE `+where, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id          int64
			k           incEnt
			first, last int64
		)
		if err := rows.Scan(&id, &k.kind, &k.scope, &k.key, &first, &last); err != nil {
			return err
		}
		inc := byID[id]
		if inc == nil || !slices.Contains(inc.ents, k) {
			continue
		}
		if inc.entTimes == nil {
			inc.entTimes = map[incEnt]*entSpan{}
		}
		inc.entTimes[k] = &entSpan{first: timeNS(first), last: timeNS(last)}
	}
	return rows.Err()
}

// activeIncidents reads the open and acknowledged incidents that can still be joined (an entity
// seen at or after since) or owe an alert, the most recently active first, at most limit, with
// their entities' times and their dashboard entry counts.
func (d *db) activeIncidents(since time.Time, limit int) ([]*incident, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	sel := `SELECT id FROM incidents WHERE state IN ('open', 'acknowledged') AND (last_ns >= ? OR
		(alert_rank >= 3 AND alert_rank > alerted_rank)) ORDER BY last_ns DESC LIMIT ?`
	args := []any{since.UnixNano(), limit}
	rows, err := d.w.QueryContext(ctx, `SELECT `+incCols+` FROM incidents WHERE id IN (`+sel+`)`, args...)
	if err != nil {
		return nil, err
	}
	var out []*incident
	byID := map[int64]*incident{}
	for rows.Next() {
		inc, err := scanIncident(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, inc)
		byID[inc.id] = inc
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	if len(out) == 0 {
		return nil, nil
	}
	if err := d.incidentEntities(ctx, `incident_id IN (`+sel+`)`, args, byID); err != nil {
		return nil, err
	}
	rows, err = d.w.QueryContext(ctx, `SELECT incident_id, COUNT(*) FROM incident_timeline WHERE kind IN `+manualKinds+
		` AND incident_id IN (`+sel+`) GROUP BY incident_id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		if inc := byID[id]; inc != nil {
			inc.manual = n
		}
	}
	return out, rows.Err()
}

// loadRisk reads the stored risk scores, the highest first, at most limit.
func (d *db) loadRisk(limit int) (map[incEnt]*riskEntry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rows, err := d.w.QueryContext(ctx, `SELECT kind, scope, key, score, updated_ns FROM entity_risk ORDER BY rank DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[incEnt]*riskEntry{}
	for rows.Next() {
		var (
			k  incEnt
			s  float64
			at int64
		)
		if err := rows.Scan(&k.kind, &k.scope, &k.key, &s, &at); err != nil {
			return nil, err
		}
		if s > 0 && s <= riskCap {
			out[k] = &riskEntry{score: s, at: time.Unix(0, at).UTC()}
		}
	}
	return out, rows.Err()
}

// The queries of an incident's detections. Intentional: "incident_id > 0 AND" repeats the partial
// index's condition (detections_incident ... WHERE incident_id > 0): SQLite uses a partial index
// only when the query's WHERE implies it literally, and without it each one scans every detection.
const (
	spansSQL = `SELECT ` + detCols + ` FROM detections WHERE incident_id > 0 AND incident_id = ?
		ORDER BY last_ns DESC LIMIT ?`
	// An address's scope column is its events' source, not part of the entity: blanked, so one
	// (rule, address) pair seen from two sources counts once.
	mutePairsSQL = `SELECT DISTINCT rule_id, ent_kind, CASE WHEN ent_kind = 'address' THEN '' ELSE scope END, key FROM detections
		WHERE incident_id > 0 AND incident_id = ? AND ent_kind = ? AND key = ? AND (ent_kind = 'address' OR scope = ?)
		LIMIT ?`
	keyedSQL = `SELECT EXISTS(SELECT 1 FROM detections WHERE incident_id > 0 AND incident_id = ? AND ent_kind = ?
		AND key = ? AND (ent_kind = 'address' OR scope = ?))`
	unlinkSQL     = `UPDATE detections SET incident_id = 0 WHERE incident_id > 0 AND incident_id IN `
	deleteDetsSQL = `DELETE FROM detections WHERE incident_id > 0 AND incident_id IN `
)

// incidentSpans reads an incident's detections, the most recently seen first, at most limit.
func (d *db) incidentSpans(id int64, limit int) ([]stored, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	rows, err := d.w.QueryContext(ctx, spansSQL, id, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []stored
	for rows.Next() {
		s, err := scanDetection(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// incidentKeyed reports whether one of an incident's stored detections is keyed by k (an
// address's scope column is its events' source, not part of the entity).
func (d *db) incidentKeyed(id int64, k incEnt) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	var n int
	err := d.w.QueryRowContext(ctx, keyedSQL, id, k.kind, k.key, k.scope).Scan(&n)
	return n != 0, err
}

// mutePairs returns the distinct (rule, entity) pairs of an incident's detections keyed by key, at
// most limit, without the ones a mute couldn't be kept for (mutable).
func (d *db) mutePairs(id int64, key incEnt, limit int) ([]siem.Mute, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	rows, err := d.w.QueryContext(ctx, mutePairsSQL, id, key.kind, key.key, key.scope, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []siem.Mute
	for rows.Next() {
		var rule, kind, scope, key string
		if err := rows.Scan(&rule, &kind, &scope, &key); err != nil {
			return nil, err
		}
		if kind == siem.EntityAddress {
			scope = ""
		}
		if m := (siem.Mute{RuleID: rule, Entity: siem.Entity{Kind: kind, Key: key, Scope: scope}}); mutable(m) {
			out = append(out, m)
		}
	}
	return out, rows.Err()
}

// mutable reports whether a (rule, entity) pair can be muted: the stored mute must be one the
// entity page can list and remove, and the next start read back (validEntity). A key holding a
// control character or invalid UTF-8 (an app's logged user name) isn't.
func mutable(m siem.Mute) bool {
	return m.RuleID != "" && validEntity(m.Entity) == nil && checkName("", m.RuleID, siem.MaxShort) == nil
}

// listIncidents returns incidents for the page, most recently active first, keyset-paged.
func (d *db) listIncidents(ctx context.Context, f siem.IncidentFilter) ([]siem.Incident, error) {
	var (
		where []string
		args  []any
	)
	q := `SELECT ` + prefixed(incCols, "i.") + ` FROM incidents i`
	if f.Entity != nil {
		q += ` JOIN incident_entities ie ON ie.incident_id = i.id AND ie.kind = ? AND ie.scope = ? AND ie.key = ?`
		args = append(args, f.Entity.Kind, f.Entity.Scope, f.Entity.Key)
	}
	if len(f.States) > 0 {
		where = append(where, "i.state IN (?"+strings.Repeat(", ?", len(f.States)-1)+")")
		for _, s := range f.States {
			args = append(args, s)
		}
	}
	if r := siem.SeverityRank(f.MinSeverity); r > 0 {
		where, args = append(where, "i.sev_rank >= ?"), append(args, r)
	}
	if f.Assignee != "" {
		where, args = append(where, "i.assignee = ?"), append(args, f.Assignee)
	}
	if !f.BeforeLast.IsZero() {
		where, args = append(where, "(i.last_ns, i.id) < (?, ?)"), append(args, f.BeforeLast.UnixNano(), f.Before)
	}
	if len(where) > 0 {
		q += ` WHERE ` + strings.Join(where, " AND ")
	}
	limit := f.Limit
	switch {
	case limit <= 0:
		limit = 50
	case limit > 200:
		limit = 200
	}
	q += ` ORDER BY i.last_ns DESC, i.id DESC LIMIT ?`
	args = append(args, limit)
	return d.queryIncidents(ctx, q, args...)
}

func (d *db) queryIncidents(ctx context.Context, q string, args ...any) ([]siem.Incident, error) {
	rows, err := d.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []siem.Incident{}
	for rows.Next() {
		inc, err := scanIncident(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, inc.public())
	}
	return out, rows.Err()
}

// getIncident returns one incident with its timeline (the newest maxTimeline entries, oldest first).
func (d *db) getIncident(ctx context.Context, id int64) (siem.Incident, bool, error) {
	inc, err := scanIncident(d.r.QueryRowContext(ctx, `SELECT `+incCols+` FROM incidents WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return siem.Incident{}, false, nil
	}
	if err != nil {
		return siem.Incident{}, false, err
	}
	out := inc.public()
	rows, err := d.r.QueryContext(ctx, `SELECT ts_ns, kind, detection_id, rule_id, rule_name, severity, actor, text
		FROM incident_timeline WHERE incident_id = ? ORDER BY id DESC LIMIT ?`, id, maxTimeline)
	if err != nil {
		return siem.Incident{}, false, err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			ev  siem.IncidentEvent
			ts  int64
			sev string
		)
		if err := rows.Scan(&ts, &ev.Kind, &ev.DetectionID, &ev.RuleID, &ev.RuleName, &sev, &ev.Actor, &ev.Text); err != nil {
			return siem.Incident{}, false, err
		}
		ev.TS, ev.Severity = timeNS(ts), siem.Severity(sev)
		out.Timeline = append(out.Timeline, ev)
	}
	if err := rows.Err(); err != nil {
		return siem.Incident{}, false, err
	}
	for i, j := 0, len(out.Timeline)-1; i < j; i, j = i+1, j-1 {
		out.Timeline[i], out.Timeline[j] = out.Timeline[j], out.Timeline[i]
	}
	return out, true, nil
}

// entityIncidents returns an entity's incidents, most recently active first, at most limit.
func (d *db) entityIncidents(ctx context.Context, k incEnt, limit int) ([]siem.Incident, error) {
	return d.queryIncidents(ctx, `SELECT `+prefixed(incCols, "i.")+` FROM incidents i JOIN incident_entities ie
		ON ie.incident_id = i.id WHERE ie.kind = ? AND ie.scope = ? AND ie.key = ?
		ORDER BY i.last_ns DESC, i.id DESC LIMIT ?`, k.kind, k.scope, k.key, limit)
}

const openCountSQL = `(SELECT COUNT(*) FROM incident_entities ie WHERE ie.kind = r.kind AND ie.scope = r.scope
	AND ie.key = r.key AND ie.incident_id IN (` + activeSQL + `))`

// entityRisk returns an entity's risk score at now and its open and acknowledged incidents.
func (d *db) entityRisk(ctx context.Context, k incEnt, now time.Time) (siem.RiskScore, error) {
	out := siem.RiskScore{Entity: k.entity()}
	var (
		s  float64
		at int64
	)
	err := d.r.QueryRowContext(ctx, `SELECT score, updated_ns FROM entity_risk WHERE kind = ? AND scope = ? AND key = ?`,
		k.kind, k.scope, k.key).Scan(&s, &at)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return out, err
	default:
		out.Updated = time.Unix(0, at).UTC()
		out.Score = roundScore(riskNow(riskEntry{score: s, at: out.Updated}, now))
	}
	err = d.r.QueryRowContext(ctx, `SELECT COUNT(*) FROM incident_entities WHERE kind = ? AND scope = ? AND key = ?
		AND incident_id IN (`+activeSQL+`)`, k.kind, k.scope, k.key).Scan(&out.OpenIncidents)
	return out, err
}

// risky returns the entities with the highest current risk score, at most limit.
func (d *db) risky(ctx context.Context, limit int, now time.Time) ([]siem.RiskScore, error) {
	rows, err := d.r.QueryContext(ctx, `SELECT r.kind, r.scope, r.key, r.score, r.updated_ns, `+openCountSQL+`
		FROM entity_risk r ORDER BY r.rank DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []siem.RiskScore{}
	for rows.Next() {
		var (
			k  incEnt
			s  float64
			at int64
			rs siem.RiskScore
		)
		if err := rows.Scan(&k.kind, &k.scope, &k.key, &s, &at, &rs.OpenIncidents); err != nil {
			return nil, err
		}
		rs.Entity, rs.Updated = k.entity(), time.Unix(0, at).UTC()
		if rs.Score = roundScore(riskNow(riskEntry{score: s, at: rs.Updated}, now)); rs.Score < riskFloor {
			continue
		}
		out = append(out, rs)
	}
	return out, rows.Err()
}

// roundScore keeps one decimal.
func roundScore(s float64) float64 { return float64(int64(s*10+0.5)) / 10 }

// deleteIncidents removes incidents with their entities and timeline in one transaction, and
// unlinks their detections still stored (withDets: removes them too). It returns how many
// detections it removed.
func (d *db) deleteIncidents(ctx context.Context, ids []int64, withDets bool) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	in := "(?" + strings.Repeat(", ?", len(ids)-1) + ")"
	args := make([]any, len(ids))
	for i, id := range ids {
		args[i] = id
	}
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	tx, err := d.w.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback() }()
	dets := unlinkSQL + in
	if withDets {
		dets = deleteDetsSQL + in
	}
	var n int64
	for _, q := range []string{
		`DELETE FROM incident_timeline WHERE incident_id IN ` + in,
		`DELETE FROM incident_entities WHERE incident_id IN ` + in,
		dets,
		`DELETE FROM incidents WHERE id IN ` + in,
	} {
		res, err := tx.ExecContext(ctx, q, args...)
		if err != nil {
			return 0, err
		}
		if q == dets && withDets {
			if n, err = res.RowsAffected(); err != nil {
				return 0, err
			}
		}
	}
	return n, tx.Commit()
}

// incidentIDs returns the IDs q selects (q takes args).
func (d *db) incidentIDs(ctx context.Context, q string, args ...any) ([]int64, error) {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	rows, err := d.w.QueryContext(ctx, q, args...)
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
	return ids, rows.Err()
}

// pruneIncidents removes the incidents (any state) whose last detection's last event is before
// cutoff, in chunks, within pruneBudget; it returns their IDs.
func (d *db) pruneIncidents(ctx context.Context, cutoff time.Time) ([]int64, error) {
	deadline := time.Now().Add(pruneBudget)
	var all []int64
	for time.Now().Before(deadline) {
		ids, err := d.incidentIDs(ctx, `SELECT id FROM incidents WHERE last_ns < ? LIMIT ?`, cutoff.UnixNano(), pruneChunk)
		if err != nil {
			return all, err
		}
		if _, err := d.deleteIncidents(ctx, ids, false); err != nil {
			return all, err
		}
		all = append(all, ids...)
		if len(ids) < pruneChunk {
			break
		}
	}
	return all, nil
}
