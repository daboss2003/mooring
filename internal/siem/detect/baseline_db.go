package detect

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"strings"
	"time"
)

// The baseline rules' learned state in detect.db (migration 0006): one row per kind and entity, and
// per kind the signature of the definition it was learned under and the time zone of its hours.

// blKind is what baseline_kinds records of a kind: the signature of the definition its rows were
// learned under (a change discards them) and, for a kind that learns per hour, the server's time
// zone (zoneSig) its hours were learned in ("" for the others).
type blKind struct{ sig, zone string }

// syncBaselineKinds discards the rows of every kind whose stored signature differs from kinds' (its
// definition changed) and records it with kinds' zone, and discards the rows of kinds not in kinds.
// It returns the zone stored for each kind.
func (d *db) syncBaselineKinds(ctx context.Context, kinds map[string]blKind) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	rows, err := d.w.QueryContext(ctx, `SELECT kind, sig, zone FROM baseline_kinds`)
	if err != nil {
		return nil, err
	}
	have := map[string]blKind{}
	for rows.Next() {
		var k string
		var s blKind
		if err := rows.Scan(&k, &s.sig, &s.zone); err != nil {
			rows.Close()
			return nil, err
		}
		have[k] = s
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	tx, err := d.w.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	zones := map[string]string{}
	for kind, k := range kinds {
		if s, ok := have[kind]; ok && s.sig == k.sig {
			zones[kind] = s.zone
			continue
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM baselines WHERE kind = ?`, kind); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO baseline_kinds(kind, sig, zone) VALUES (?, ?, ?)
			ON CONFLICT(kind) DO UPDATE SET sig = excluded.sig, zone = excluded.zone`, kind, k.sig, k.zone); err != nil {
			return nil, err
		}
		zones[kind] = k.zone
	}
	for kind := range have {
		if _, ok := kinds[kind]; ok {
			continue
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM baselines WHERE kind = ?`, kind); err != nil {
			return nil, err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM baseline_kinds WHERE kind = ?`, kind); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return zones, nil
}

// loadBaselineRows deletes a kind's rows whose key or state is longer than a valid one can be
// (maxBaselineKey, maxBlData), so no such value is read into memory, and returns the others, the
// most recently saved first, at most limit, with the number deleted.
func (d *db) loadBaselineRows(ctx context.Context, kind string, limit int) ([]blRow, int, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	res, err := d.w.ExecContext(ctx, `DELETE FROM baselines WHERE kind = ?
		AND (length(CAST(key AS BLOB)) > ? OR length(CAST(data AS BLOB)) > ?)`, kind, maxBaselineKey, maxBlData)
	if err != nil {
		return nil, 0, err
	}
	n, _ := res.RowsAffected()
	rows, err := d.w.QueryContext(ctx, `SELECT key, data FROM baselines WHERE kind = ? ORDER BY updated_ns DESC LIMIT ?`,
		kind, limit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []blRow
	for rows.Next() {
		r := blRow{kind: kind}
		if err := rows.Scan(&r.key, &r.data); err != nil {
			return nil, 0, err
		}
		out = append(out, r)
	}
	return out, int(n), rows.Err()
}

// deleteBaselinePrefix deletes kind's rows whose key starts with prefix, which ends in '|': the keys
// from prefix up to prefix with that '|' raised to '}' (the next byte) are exactly those.
func (d *db) deleteBaselinePrefix(ctx context.Context, kind, prefix string) error {
	if !strings.HasSuffix(prefix, "|") {
		return errors.New("detect: a baseline key prefix ends in '|'")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, err := d.w.ExecContext(ctx, `DELETE FROM baselines WHERE kind = ? AND key >= ? AND key < ?`,
		kind, prefix, prefix[:len(prefix)-1]+"}")
	return err
}

// keepBaselinePrefixes deletes kind's rows of app accounts ("app:<slug>|…") whose prefix isn't in
// keep; the rows of other sources are kept.
func (d *db) keepBaselinePrefixes(ctx context.Context, kind string, keep map[string]bool) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// "app:" up to "app;" (':' raised to the next byte): the keys starting with "app:".
	rows, err := d.w.QueryContext(ctx, `SELECT DISTINCT substr(key, 1, instr(key, '|')) FROM baselines
		WHERE kind = ? AND key >= 'app:' AND key < 'app;'`, kind)
	if err != nil {
		return err
	}
	var gone []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			rows.Close()
			return err
		}
		if p != "" && !keep[p] {
			gone = append(gone, p)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, p := range gone {
		if err := d.deleteBaselinePrefix(ctx, kind, p); err != nil {
			return err
		}
	}
	return nil
}

// blFinish ends a kind's rewrite: its rows the rewrite didn't write (updated_ns other than stamp)
// are deleted and its zone recorded.
type blFinish struct {
	kind, zone string
	stamp      int64
}

// rewriteStamp is the updated_ns of a kind's rewrite: now, or later when a row of the kind was
// saved at now or later (a clock set back), so no row the rewrite didn't write has it.
func (d *db) rewriteStamp(ctx context.Context, kind string, now time.Time) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var last sql.NullInt64
	if err := d.w.QueryRowContext(ctx, `SELECT MAX(updated_ns) FROM baselines WHERE kind = ?`, kind).Scan(&last); err != nil {
		return 0, err
	}
	stamp := now.UnixNano()
	if last.Valid && last.Int64 >= stamp && last.Int64 < math.MaxInt64 {
		stamp = last.Int64 + 1
	}
	return stamp, nil
}

// writeBaselines deletes the rows of gone (kind and key) and saves rows (updated at ns), in one
// transaction; with fin, it ends that kind's rewrite in the same transaction.
func (d *db) writeBaselines(ctx context.Context, rows, gone []blRow, ns int64, fin *blFinish) error {
	ctx, cancel := context.WithTimeout(ctx, batchTimeout)
	defer cancel()
	tx, err := d.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if len(gone) > 0 {
		del, err := tx.PrepareContext(ctx, `DELETE FROM baselines WHERE kind = ? AND key = ?`)
		if err != nil {
			return err
		}
		defer del.Close()
		for _, g := range gone {
			if _, err := del.ExecContext(ctx, g.kind, g.key); err != nil {
				return err
			}
		}
	}
	if len(rows) > 0 {
		put, err := tx.PrepareContext(ctx, `INSERT INTO baselines(kind, key, data, updated_ns) VALUES (?, ?, ?, ?)
			ON CONFLICT(kind, key) DO UPDATE SET data = excluded.data, updated_ns = excluded.updated_ns`)
		if err != nil {
			return err
		}
		defer put.Close()
		for _, r := range rows {
			if _, err := put.ExecContext(ctx, r.kind, r.key, r.data, ns); err != nil {
				return err
			}
		}
	}
	if fin != nil {
		if _, err := tx.ExecContext(ctx, `DELETE FROM baselines WHERE kind = ? AND updated_ns <> ?`, fin.kind, fin.stamp); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE baseline_kinds SET zone = ? WHERE kind = ?`, fin.zone, fin.kind); err != nil {
			return err
		}
	}
	return tx.Commit()
}
