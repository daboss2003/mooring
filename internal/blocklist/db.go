package blocklist

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
)

const (
	dbTimeout = 10 * time.Second
	// maxLoad bounds the blocks in force read at Open: both caps at their largest, twice.
	maxLoad = 2 * (10000 + MaxManual)
	// maxListScan bounds a page query filtered in Go (active and suspended are told apart in memory).
	maxListScan = maxLoad
	// pruneAfter: a row is deleted this long after its block expired or was lifted (and its
	// exemption ended); refusals this long after the last one.
	pruneAfter    = 30 * 24 * time.Hour
	maxRefusals   = 5000
	maxDetail     = 300
	maxShortField = 128
)

const blockCols = `prefix, source, rule_id, detection_id, incident_id, response_id, reason, by_user,
	created_at, until_at, removed_at, removed_by, exempt_until, hits, auto_step, auto_at, suspended_why`

func unixTime(s int64) time.Time {
	if s == 0 {
		return time.Time{}
	}
	return time.Unix(s, 0).UTC()
}

func unixOf(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

type scanner interface{ Scan(dest ...any) error }

// scanBlock reads one edge_blocks row (blockCols); text is the stored prefix, Prefix its parse (the
// zero Prefix when it doesn't parse). State is not set; SuspendedWhy is the stored one.
func scanBlock(s scanner) (blk Block, text string, err error) {
	var created, until, removed, exempt, step, autoAt int64
	if err = s.Scan(&text, &blk.Source, &blk.RuleID, &blk.DetectionID, &blk.IncidentID, &blk.ResponseID, &blk.Reason,
		&blk.By, &created, &until, &removed, &blk.RemovedBy, &exempt, &blk.Hits, &step, &autoAt, &blk.SuspendedWhy); err != nil {
		return Block{}, "", err
	}
	blk.Created, blk.Until, blk.RemovedAt, blk.ExemptUntil = unixTime(created), unixTime(until), unixTime(removed), unixTime(exempt)
	blk.autoStep, blk.autoAt = time.Duration(max(step, 0))*time.Second, unixTime(autoAt)
	blk.Prefix, _ = netip.ParsePrefix(text)
	return blk, text, nil
}

// maxFor is the longest block of source.
func (b *Blocker) maxFor(source string) time.Duration {
	if source == SourceAuto {
		return b.maxAutoDur
	}
	return b.manualMaxDur
}

// loadInForce reads the blocks in force, each active or suspended as last saved. A row that isn't a
// canonical prefix its source may block is never published. A block ending later than now plus the longest block of its source (a clock that
// stepped back, a hand-edited row) is cut to that, in memory and in the database.
func (b *Blocker) loadInForce(ctx context.Context, now time.Time) (map[netip.Prefix]Block, error) {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	rows, err := b.db.QueryContext(ctx, `SELECT `+blockCols+` FROM edge_blocks
		WHERE removed_at = 0 AND until_at > ? ORDER BY created_at DESC, prefix LIMIT ?`, now.Unix(), maxLoad)
	if err != nil {
		return nil, fmt.Errorf("blocklist: load: %w", err)
	}
	out := map[netip.Prefix]Block{}
	type clamp struct {
		text  string
		until int64
	}
	var clamps []clamp
	skipped := 0
	for rows.Next() {
		blk, text, err := scanBlock(rows)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("blocklist: load: %w", err)
		}
		p := blk.Prefix
		if !p.IsValid() || canon(p) != p || p.String() != text || (blk.Source != SourceAuto && blk.Source != SourceManual) || !widthOK(p, blk.Source) {
			skipped++
			continue
		}
		if limit := now.Add(b.maxFor(blk.Source)).Truncate(time.Second); blk.Until.After(limit) {
			blk.Until = limit
			clamps = append(clamps, clamp{text, limit.Unix()})
		}
		blk.State = StateActive
		if blk.SuspendedWhy != "" {
			blk.State = StateSuspended
		}
		out[p] = blk
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("blocklist: load: %w", err)
	}
	rows.Close()
	for _, c := range clamps {
		if _, err := b.db.ExecContext(ctx, `UPDATE edge_blocks SET until_at = ? WHERE prefix = ?`, c.until, c.text); err != nil {
			return nil, fmt.Errorf("blocklist: clamp: %w", err)
		}
	}
	if skipped > 0 {
		b.log.Warn("blocklist: blocks in the database that aren't valid were not loaded", "count", skipped)
	}
	if len(clamps) > 0 {
		b.log.Warn("blocklist: blocks ending past the longest block were cut to it (the clock may have stepped back)", "count", len(clamps))
	}
	return out, nil
}

// getRow reads the row of p, in force or not.
func (b *Blocker) getRow(ctx context.Context, p netip.Prefix) (Block, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	blk, _, err := scanBlock(b.db.QueryRowContext(ctx, `SELECT `+blockCols+` FROM edge_blocks WHERE prefix = ?`, p.String()))
	if errors.Is(err, sql.ErrNoRows) {
		return Block{}, false, nil
	}
	if err != nil {
		return Block{}, false, fmt.Errorf("blocklist: read: %w", err)
	}
	return blk, true, nil
}

// putBlock writes a newly placed block over the prefix's row (its exemption is kept).
func (b *Blocker) putBlock(ctx context.Context, blk Block) error {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	_, err := b.db.ExecContext(ctx, `INSERT INTO edge_blocks(`+blockCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,0,'',0,?,?,?,'')
		ON CONFLICT(prefix) DO UPDATE SET source = excluded.source, rule_id = excluded.rule_id,
			detection_id = excluded.detection_id, incident_id = excluded.incident_id, response_id = excluded.response_id,
			reason = excluded.reason, by_user = excluded.by_user, created_at = excluded.created_at,
			until_at = excluded.until_at, removed_at = 0, removed_by = '', hits = excluded.hits,
			auto_step = excluded.auto_step, auto_at = excluded.auto_at, suspended_why = ''`,
		blk.Prefix.String(), blk.Source, blk.RuleID, blk.DetectionID, blk.IncidentID, blk.ResponseID, blk.Reason, blk.By,
		unixOf(blk.Created), unixOf(blk.Until), blk.Hits, int64(blk.autoStep/time.Second), unixOf(blk.autoAt))
	if err != nil {
		return fmt.Errorf("blocklist: write: %w", err)
	}
	return nil
}

// extendBlock writes an extended block in force (its new end, and its owner when a manual request
// took over an automatic block).
func (b *Blocker) extendBlock(ctx context.Context, blk Block) error {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	_, err := b.db.ExecContext(ctx, `UPDATE edge_blocks SET until_at = ?, source = ?, by_user = ?, reason = ? WHERE prefix = ?`,
		unixOf(blk.Until), blk.Source, blk.By, blk.Reason, blk.Prefix.String())
	if err != nil {
		return fmt.Errorf("blocklist: write: %w", err)
	}
	return nil
}

// removeRows lifts the blocks in force of prefixes, exempting each until exempt (zero: no new
// exemption), in one transaction. reset also clears each prefix's repeat history.
func (b *Blocker) removeRows(ctx context.Context, prefixes []netip.Prefix, by string, now, exempt time.Time, reset bool) error {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	tx, err := b.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("blocklist: remove: %w", err)
	}
	defer tx.Rollback()
	q := `UPDATE edge_blocks SET removed_at = ?, removed_by = ?, exempt_until = MAX(exempt_until, ?), suspended_why = ''`
	if reset {
		q += resetHistory
	}
	q += ` WHERE prefix = ? AND removed_at = 0`
	for _, p := range prefixes {
		if _, err := tx.ExecContext(ctx, q, now.Unix(), by, unixOf(exempt), p.String()); err != nil {
			return fmt.Errorf("blocklist: remove: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("blocklist: remove: %w", err)
	}
	return nil
}

// resetHistory is the SET list that clears a prefix's repeat history: its next automatic block is the
// first step again.
const resetHistory = `, hits = 0, auto_step = 0, auto_at = 0`

// exemptIncident exempts every automatic block ever placed for incident id until exempt, in force or
// not, and clears its repeat history: an address of a false positive isn't blocked again
// automatically while it lasts, and not for longer after it.
func (b *Blocker) exemptIncident(ctx context.Context, id int64, exempt time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	_, err := b.db.ExecContext(ctx, `UPDATE edge_blocks SET exempt_until = MAX(exempt_until, ?)`+resetHistory+` WHERE incident_id = ? AND source = ?`,
		unixOf(exempt), id, SourceAuto)
	if err != nil {
		return fmt.Errorf("blocklist: exempt: %w", err)
	}
	return nil
}

// exemptUntil is when the exemption covering p ends: its own row's, or that of a range containing it
// (an owner unblocked the range). The zero Time when none is running at now.
func (b *Blocker) exemptUntil(ctx context.Context, p netip.Prefix, now time.Time) (time.Time, error) {
	widest := ManualIPv4Bits
	if p.Addr().Is6() {
		widest = ManualIPv6Bits
	}
	args := []any{now.Unix()}
	marks := make([]string, 0, p.Bits()-widest+1)
	for bits := p.Bits(); bits >= widest; bits-- {
		args = append(args, netip.PrefixFrom(p.Addr(), bits).Masked().String())
		marks = append(marks, "?")
	}
	if len(marks) == 0 {
		return time.Time{}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	var until int64
	// Only placeholders are joined into the statement; the prefixes are bound.
	err := b.db.QueryRowContext(ctx, `SELECT COALESCE(MAX(exempt_until), 0) FROM edge_blocks
		WHERE exempt_until > ? AND prefix IN (`+strings.Join(marks, ",")+`)`, args...).Scan(&until)
	if err != nil {
		return time.Time{}, fmt.Errorf("blocklist: read: %w", err)
	}
	return unixTime(until), nil
}

// putSuspended saves whether the block in force of p is suspended (why: the code; "": it isn't).
func (b *Blocker) putSuspended(ctx context.Context, p netip.Prefix, why string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dbTimeout)
	defer cancel()
	_, err := b.db.ExecContext(ctx, `UPDATE edge_blocks SET suspended_why = ? WHERE prefix = ? AND removed_at = 0`, why, p.String())
	return err
}

// putRefusal records a refusal, coalesced per (prefix, code).
func (b *Blocker) putRefusal(ctx context.Context, rf Refusal) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dbTimeout)
	defer cancel()
	_, err := b.db.ExecContext(ctx, `INSERT INTO edge_block_refusals(prefix, code, source, rule_id, detail, count, first_at, last_at)
		VALUES (?,?,?,?,?,1,?,?)
		ON CONFLICT(prefix, code) DO UPDATE SET count = count + 1, last_at = excluded.last_at,
			source = excluded.source, rule_id = excluded.rule_id, detail = excluded.detail`,
		rf.Prefix, rf.Code, rf.Source, rf.RuleID, rf.Detail, rf.First.Unix(), rf.Last.Unix())
	return err
}

// stateAt is a row's state at now: removed, expired, or in force (active or suspended, as memory
// has it).
func (b *Blocker) stateAt(blk Block, now time.Time) (string, string) {
	switch {
	case !blk.RemovedAt.IsZero():
		return StateRemoved, ""
	case !blk.Until.After(now):
		return StateExpired, ""
	}
	b.mu.Lock()
	cur, ok := b.inForce[blk.Prefix]
	b.mu.Unlock()
	if ok && cur.State == StateSuspended {
		return StateSuspended, cur.SuspendedWhy
	}
	return StateActive, ""
}

// List returns the blocks f selects, newest first.
func (b *Blocker) List(ctx context.Context, f Filter) ([]Block, error) {
	limit := f.Limit
	switch {
	case limit <= 0:
		limit = 100
	case limit > 1000:
		limit = 1000
	}
	want := map[string]bool{}
	for _, s := range f.States {
		switch s {
		case StateActive, StateSuspended, StateExpired, StateRemoved:
			want[s] = true
		default:
			return nil, fmt.Errorf("blocklist: unknown state %q", s)
		}
	}
	now := b.now()
	var conds, states []string
	var args []any
	if len(want) > 0 {
		if want[StateActive] || want[StateSuspended] {
			states = append(states, `(removed_at = 0 AND until_at > ?)`)
			args = append(args, now.Unix())
		}
		if want[StateExpired] {
			states = append(states, `(removed_at = 0 AND until_at <= ?)`)
			args = append(args, now.Unix())
		}
		if want[StateRemoved] {
			states = append(states, `removed_at > 0`)
		}
		conds = append(conds, "("+strings.Join(states, " OR ")+")")
	}
	if f.Source != "" {
		conds = append(conds, `source = ?`)
		args = append(args, f.Source)
	}
	if f.IncidentID != 0 {
		conds = append(conds, `incident_id = ?`)
		args = append(args, f.IncidentID)
	}
	q := `SELECT ` + blockCols + ` FROM edge_blocks`
	if len(conds) > 0 {
		q += ` WHERE ` + strings.Join(conds, " AND ")
	}
	// Active and suspended are told apart in memory: when only one of them is asked for, the query
	// reads every block in force and the page is cut after filtering.
	scan := limit
	if len(want) > 0 && want[StateActive] != want[StateSuspended] {
		scan = maxListScan
	}
	q += ` ORDER BY created_at DESC, prefix LIMIT ?`
	args = append(args, scan)

	qctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	rows, err := b.db.QueryContext(qctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("blocklist: list: %w", err)
	}
	var all []Block
	for rows.Next() {
		blk, _, err := scanBlock(rows)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("blocklist: list: %w", err)
		}
		if blk.Prefix.IsValid() {
			all = append(all, blk)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, fmt.Errorf("blocklist: list: %w", err)
	}
	out := make([]Block, 0, min(len(all), limit))
	for _, blk := range all {
		blk.State, blk.SuspendedWhy = b.stateAt(blk, now)
		if len(want) > 0 && !want[blk.State] {
			continue
		}
		out = append(out, blk)
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

// Get returns the row of prefix, in force or not.
func (b *Blocker) Get(ctx context.Context, prefix netip.Prefix) (Block, bool, error) {
	p := canon(prefix)
	if !p.IsValid() {
		return Block{}, false, nil
	}
	blk, ok, err := b.getRow(ctx, p)
	if err != nil || !ok {
		return Block{}, false, err
	}
	blk.State, blk.SuspendedWhy = b.stateAt(blk, b.now())
	return blk, true, nil
}

// Refusals returns the latest refusals, most recent first (limit 1–1000, default 100).
func (b *Blocker) Refusals(ctx context.Context, limit int) ([]Refusal, error) {
	switch {
	case limit <= 0:
		limit = 100
	case limit > 1000:
		limit = 1000
	}
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	rows, err := b.db.QueryContext(ctx, `SELECT prefix, code, detail, source, rule_id, count, first_at, last_at
		FROM edge_block_refusals ORDER BY last_at DESC, prefix, code LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("blocklist: refusals: %w", err)
	}
	defer rows.Close()
	var out []Refusal
	for rows.Next() {
		var rf Refusal
		var first, lastAt int64
		if err := rows.Scan(&rf.Prefix, &rf.Code, &rf.Detail, &rf.Source, &rf.RuleID, &rf.Count, &first, &lastAt); err != nil {
			return nil, fmt.Errorf("blocklist: refusals: %w", err)
		}
		rf.First, rf.Last = unixTime(first), unixTime(lastAt)
		out = append(out, rf)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("blocklist: refusals: %w", err)
	}
	return out, nil
}

// prune deletes rows pruneAfter past their block's end (or lifting) and exemption, refusals
// pruneAfter past the last one, and the oldest refusals past maxRefusals.
func (b *Blocker) prune(ctx context.Context, now time.Time) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dbTimeout)
	defer cancel()
	cut := now.Add(-pruneAfter).Unix()
	stmts := []struct {
		q    string
		args []any
	}{
		{`DELETE FROM edge_blocks WHERE ((removed_at > 0 AND removed_at < ?) OR (removed_at = 0 AND until_at < ?)) AND exempt_until < ?`,
			[]any{cut, cut, now.Unix()}},
		{`DELETE FROM edge_block_refusals WHERE last_at < ?`, []any{cut}},
		{`DELETE FROM edge_block_refusals WHERE rowid IN (SELECT rowid FROM edge_block_refusals ORDER BY last_at DESC LIMIT -1 OFFSET ?)`,
			[]any{maxRefusals}},
	}
	for _, s := range stmts {
		if _, err := b.db.ExecContext(ctx, s.q, s.args...); err != nil {
			b.log.Warn("blocklist: prune failed", "err", err)
			return
		}
	}
}
