package respond

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

// The responses in mooring.db (security_responses, security_response_pause). Every statement runs
// within dbTimeout; rows are read whole before the next statement (one shared connection).

const (
	dbTimeout  = 5 * time.Second
	maxExpire  = 1000 // recommendations expired per maintenance
	pruneChunk = 1000 // rows a prune statement removes
	maxPrune   = 100  // prune statements per maintenance
)

const respCols = `id, action, target, state, reason, automatic, rule_id, detection_id, incident_id, summary,
	duration_s, by_user, created_at, updated_at`

type scanner interface{ Scan(...any) error }

func scanResponse(sc scanner) (siem.Response, error) {
	var (
		x                 siem.Response
		auto              int
		dur, created, upd int64
	)
	if err := sc.Scan(&x.ID, &x.Action, &x.Target, &x.State, &x.Reason, &auto, &x.RuleID, &x.DetectionID,
		&x.IncidentID, &x.Summary, &dur, &x.By, &created, &upd); err != nil {
		return siem.Response{}, err
	}
	x.Automatic = auto != 0
	x.Duration = time.Duration(dur) * time.Second
	x.Created, x.Updated = time.Unix(created, 0).UTC(), time.Unix(upd, 0).UTC()
	return x, nil
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

func seconds(d time.Duration) int64 { return int64(d / time.Second) }

// insert records x (its ID is set).
func (r *Responder) insert(ctx context.Context, x *siem.Response) error {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	res, err := r.o.DB.ExecContext(ctx, `INSERT INTO security_responses(action, target, state, reason, automatic,
		rule_id, detection_id, incident_id, summary, duration_s, by_user, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`, x.Action, x.Target, x.State, x.Reason, btoi(x.Automatic),
		x.RuleID, x.DetectionID, x.IncidentID, x.Summary, seconds(x.Duration), x.By, x.Created.Unix(), x.Updated.Unix())
	if err != nil {
		return err
	}
	x.ID, err = res.LastInsertId()
	return err
}

// settle records a response's outcome: its state, reason, target, duration, who and when.
func (r *Responder) settle(ctx context.Context, x siem.Response) error {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	_, err := r.o.DB.ExecContext(ctx, `UPDATE security_responses SET state = ?, reason = ?, target = ?, duration_s = ?,
		by_user = ?, updated_at = ? WHERE id = ?`, x.State, x.Reason, x.Target, seconds(x.Duration), x.By, x.Updated.Unix(), x.ID)
	return err
}

// remove deletes one response's row.
func (r *Responder) remove(ctx context.Context, id int64) error {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	_, err := r.o.DB.ExecContext(ctx, `DELETE FROM security_responses WHERE id = ?`, id)
	return err
}

// newest returns the newest response of action and target created after since and not after now,
// other than row except.
func (r *Responder) newest(ctx context.Context, action, target string, since, now time.Time, except int64) (siem.Response, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	x, err := scanResponse(r.o.DB.QueryRowContext(ctx, `SELECT `+respCols+` FROM security_responses
		WHERE created_at > ? AND created_at <= ? AND action = ? AND target = ? AND id != ? ORDER BY id DESC LIMIT 1`,
		since.Unix(), now.Unix(), action, target, except))
	if errors.Is(err, sql.ErrNoRows) {
		return siem.Response{}, false, nil
	}
	return x, err == nil, err
}

func (r *Responder) get(ctx context.Context, id int64) (siem.Response, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	x, err := scanResponse(r.o.DB.QueryRowContext(ctx, `SELECT `+respCols+` FROM security_responses WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return siem.Response{}, false, nil
	}
	return x, err == nil, err
}

// upsertRecommendation records x as a recommendation: the open one for its action, target and
// incident takes x's request (rule, detection, summary, duration) when there is one, else x is
// added. It returns the row as stored and whether it was added: fresh is false for a waiting
// recommendation that only took a newer request, and x.ID is 0 (nothing stored) for one the owner
// dismissed within dismissQuiet — a detection that keeps firing asks every few minutes, and must
// neither fill the timeline nor bring back what the owner just dismissed.
// Intentional: one open recommendation per incident, not per target: a row that moved to the
// latest incident asking would be missed when the earlier incident is marked a false positive
// (LiftForIncident dismisses an incident's own recommendations).
func (r *Responder) upsertRecommendation(ctx context.Context, x siem.Response) (got siem.Response, fresh bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	tx, err := r.o.DB.BeginTx(ctx, nil)
	if err != nil {
		return siem.Response{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	var id int64
	err = tx.QueryRowContext(ctx, `SELECT id FROM security_responses WHERE action = ? AND target = ? AND state = ?
		AND incident_id = ? ORDER BY id DESC LIMIT 1`, x.Action, x.Target, siem.ResponseRecommended, x.IncidentID).Scan(&id)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		var dismissed int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_responses WHERE action = ? AND target = ? AND state = ?
			AND incident_id = ? AND updated_at > ?`, x.Action, x.Target, siem.ResponseDismissed, x.IncidentID,
			x.Updated.Add(-dismissQuiet).Unix()).Scan(&dismissed); err != nil {
			return siem.Response{}, false, err
		}
		if dismissed > 0 {
			return siem.Response{}, false, nil
		}
		fresh = true
		res, err := tx.ExecContext(ctx, `INSERT INTO security_responses(action, target, state, reason, automatic,
			rule_id, detection_id, incident_id, summary, duration_s, by_user, created_at, updated_at)
			VALUES (?, ?, ?, '', ?, ?, ?, ?, ?, ?, '', ?, ?)`, x.Action, x.Target, siem.ResponseRecommended,
			btoi(x.Automatic), x.RuleID, x.DetectionID, x.IncidentID, x.Summary, seconds(x.Duration), x.Created.Unix(),
			x.Updated.Unix())
		if err != nil {
			return siem.Response{}, false, err
		}
		if id, err = res.LastInsertId(); err != nil {
			return siem.Response{}, false, err
		}
	case err != nil:
		return siem.Response{}, false, err
	default:
		if _, err := tx.ExecContext(ctx, `UPDATE security_responses SET automatic = ?, rule_id = ?, detection_id = ?,
			summary = ?, duration_s = ?, updated_at = ? WHERE id = ?`, btoi(x.Automatic), x.RuleID,
			x.DetectionID, x.Summary, seconds(x.Duration), x.Updated.Unix(), id); err != nil {
			return siem.Response{}, false, err
		}
	}
	got, err = scanResponse(tx.QueryRowContext(ctx, `SELECT `+respCols+` FROM security_responses WHERE id = ?`, id))
	if err != nil {
		return siem.Response{}, false, err
	}
	return got, fresh, tx.Commit()
}

// countApplied counts the automatic actions Mooring applied (by_user ”) after since; targets,
// when given, narrows it to those. Intentional: by created_at (indexed), which is when such a row
// was applied: Mooring records an automatic action as it applies it, and an applied row is never
// changed afterwards.
func (r *Responder) countApplied(ctx context.Context, action string, since time.Time, targets ...string) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	q := `SELECT COUNT(*) FROM security_responses WHERE created_at > ? AND action = ? AND state = ? AND automatic = 1
		AND by_user = ''`
	args := []any{since.Unix(), action, siem.ResponseApplied}
	if len(targets) > 0 {
		q += ` AND target IN (?` + strings.Repeat(`, ?`, len(targets)-1) + `)`
		for _, t := range targets {
			args = append(args, t)
		}
	}
	var n int
	err := r.o.DB.QueryRowContext(ctx, q, args...).Scan(&n)
	return n, err
}

// list returns responses for the page (f already checked), newest first.
func (r *Responder) list(ctx context.Context, f siem.ResponseFilter, limit int) ([]siem.Response, error) {
	var (
		where []string
		args  []any
	)
	if f.Before > 0 {
		where, args = append(where, `id < ?`), append(args, f.Before)
	}
	if len(f.States) > 0 {
		where = append(where, `state IN (?`+strings.Repeat(`, ?`, len(f.States)-1)+`)`)
		for _, s := range f.States {
			args = append(args, s)
		}
	}
	if f.Action != "" {
		where, args = append(where, `action = ?`), append(args, f.Action)
	}
	if f.IncidentID > 0 {
		where, args = append(where, `incident_id = ?`), append(args, f.IncidentID)
	}
	if f.DetectionID > 0 {
		where, args = append(where, `detection_id = ?`), append(args, f.DetectionID)
	}
	q := `SELECT ` + respCols + ` FROM security_responses`
	if len(where) > 0 {
		q += ` WHERE ` + strings.Join(where, ` AND `)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	return r.query(ctx, q, args...)
}

func (r *Responder) query(ctx context.Context, q string, args ...any) ([]siem.Response, error) {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	rows, err := r.o.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []siem.Response
	for rows.Next() {
		x, err := scanResponse(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

// expire marks the recommendations nobody acted on within RecommendTTL expired (mu held), at most
// maxExpire per run, and returns them as they are now.
func (r *Responder) expire(ctx context.Context) ([]siem.Response, error) {
	now := r.now()
	old, err := r.query(ctx, `SELECT `+respCols+` FROM security_responses WHERE state = ? AND updated_at < ?
		ORDER BY id LIMIT ?`, siem.ResponseRecommended, now.Add(-RecommendTTL).Unix(), maxExpire)
	if err != nil || len(old) == 0 {
		return nil, err
	}
	out := make([]siem.Response, 0, len(old))
	for _, x := range old {
		x.State, x.Updated = siem.ResponseExpired, now
		if err := r.settle(ctx, x); err != nil {
			return out, err
		}
		out = append(out, x)
	}
	return out, nil
}

// prune removes the responses created more than Retention ago (a recommendation still open is
// expired first), in chunks.
func (r *Responder) prune(ctx context.Context) {
	cutoff := r.now().Add(-Retention).Unix()
	for range maxPrune {
		dctx, cancel := context.WithTimeout(ctx, dbTimeout)
		res, err := r.o.DB.ExecContext(dctx, `DELETE FROM security_responses WHERE id IN (SELECT id FROM security_responses
			WHERE created_at < ? AND state != ? ORDER BY id LIMIT ?)`, cutoff, siem.ResponseRecommended, pruneChunk)
		cancel()
		if err != nil {
			r.logLimited("prune", "security response: old responses not removed", "err", err)
			return
		}
		if n, err := res.RowsAffected(); err != nil || n < pruneChunk {
			return
		}
	}
}

// loadPause reads the dashboard's pause (an unknown level is ignored).
func (r *Responder) loadPause(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	var (
		p  pauseState
		at int64
	)
	err := r.o.DB.QueryRowContext(ctx, `SELECT level, by_user, at FROM security_response_pause WHERE id = 1`).Scan(&p.level, &p.by, &at)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil
	case err != nil:
		return err
	}
	switch p.level {
	case siem.ResponseModeRecommend, siem.ResponseModeOff:
		p.at = time.Unix(at, 0).UTC()
		r.pause.Store(&p)
	default:
		r.log.Error("security response: stored pause ignored", "level", siem.Cut(p.level, 32))
	}
	return nil
}

// storePause stores the pause (nil: lifted).
func (r *Responder) storePause(ctx context.Context, p *pauseState) error {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	if p == nil {
		_, err := r.o.DB.ExecContext(ctx, `DELETE FROM security_response_pause`)
		return err
	}
	_, err := r.o.DB.ExecContext(ctx, `INSERT INTO security_response_pause(id, level, by_user, at) VALUES (1, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET level = excluded.level, by_user = excluded.by_user, at = excluded.at`,
		p.level, p.by, p.at.Unix())
	return err
}

// loadCapWarned takes each action's latest cap refusal within capWindow as its last cap warning,
// so a restart doesn't warn again within the hour.
func (r *Responder) loadCapWarned(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	for _, action := range []string{siem.ResponseBlock, siem.ResponseRevoke} {
		var at sql.NullInt64
		if err := r.o.DB.QueryRowContext(ctx, `SELECT MAX(created_at) FROM security_responses WHERE created_at > ?
			AND action = ? AND state = ? AND reason = ?`, r.now().Add(-capWindow).Unix(), action, siem.ResponseRefused,
			reasonCap).Scan(&at); err != nil {
			return err
		}
		if at.Valid {
			r.capWarned[action] = time.Unix(at.Int64, 0)
		}
	}
	return nil
}
