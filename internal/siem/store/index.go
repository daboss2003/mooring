package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/netip"
	"strings"

	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/query"
)

// indexRow is one classified event's row in the events table.
type indexRow struct {
	ts                                  int64
	src, app, svc, kind, out, actor, ip string
	lvl                                 int
	segment, json                       string
	ord                                 int // the event's position in its segment (1, 2, ...)
}

// canonIP is an IP column value: the address in canonical form (IPv4-mapped IPv6 unmapped) when it
// parses, else the value lowercased. query.Match compares parsed addresses the same way.
func canonIP(v string) string {
	if a, err := netip.ParseAddr(v); err == nil {
		return a.Unmap().String()
	}
	return strings.ToLower(v)
}

func newIndexRow(e *siem.Event, ts int64, segment string, ord int, line []byte) indexRow {
	return indexRow{
		ts: ts, src: strings.ToLower(e.Src), app: strings.ToLower(e.App), svc: strings.ToLower(e.Svc),
		kind: strings.ToLower(e.Kind), out: strings.ToLower(e.Out), actor: strings.ToLower(e.Actor),
		ip: canonIP(e.IP), lvl: siem.LevelRank(e.Lvl), segment: segment, json: string(line), ord: ord,
	}
}

// indexLocked inserts rows of durable events, with any whose insert failed before, in one
// transaction. On failure they are kept for the next call unless that would hold more than
// pendingCap bytes. Caller holds s.mu.
func (s *Store) indexLocked(rows []indexRow) error {
	rows = append(s.retryRows, rows...)
	s.retryRows = nil
	if len(rows) == 0 {
		return nil
	}
	done, err := s.insertRows(rows)
	if err == nil {
		return nil
	}
	rows = rows[done:] // the chunks before the failure are written
	n := 0
	for _, r := range rows {
		n += len(r.json)
	}
	if n <= pendingCap {
		s.retryRows = rows
	} else {
		s.opt.Log.Error("siem store: dropping index rows that can't be written; those events are found by a scan only", "rows", len(rows), "err", err)
	}
	return err
}

// indexChunk is how many index rows one transaction writes, so each stays well inside dbTimeout.
const indexChunk = 1000

// insertRows writes index rows, indexChunk per transaction, and returns how many were written
// (always whole chunks from the start of rows). Caller holds s.mu.
func (s *Store) insertRows(rows []indexRow) (int, error) {
	done := 0
	for done < len(rows) {
		chunk := rows[done:min(done+indexChunk, len(rows))]
		err := s.tx(func(ctx context.Context, tx *sql.Tx) error {
			st, err := tx.PrepareContext(ctx, `INSERT INTO events(ts, src, app, svc, kind, out, lvl, actor, ip, segment, json)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
			if err != nil {
				return err
			}
			defer st.Close()
			for _, r := range chunk {
				if _, err := st.ExecContext(ctx, r.ts, r.src, r.app, r.svc, r.kind, r.out, r.lvl, r.actor, r.ip, r.segment, r.json); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return done, err
		}
		done += len(chunk)
	}
	return done, nil
}

// indexColumns are the string fields the events table holds, by query field.
var indexColumns = map[string]string{"src": "src", "app": "app", "svc": "svc", "kind": "kind", "out": "out", "actor": "actor"}

// indexable reports whether the events table holds every event q can match: q has no text, every
// term is on a field the table holds, and a term restricts it to classified events (a kind other
// than log and http.request, or a level of warn or above).
func indexable(q query.Query) bool {
	if len(q.Text) > 0 || len(q.Terms) == 0 {
		return false
	}
	restricted := false
	for _, t := range q.Terms {
		if _, ok := indexColumns[t.Field]; !ok && t.Field != "ip" && t.Field != "lvl" {
			return false
		}
		if !t.Neg && classifiedOnly(t) {
			restricted = true
		}
	}
	return restricted
}

// classifiedOnly reports whether every event matching t is classified. Kinds compare lowercased,
// as query.Match does, so kind:LOG never counts as restricting.
func classifiedOnly(t query.Term) bool {
	switch t.Field {
	case "kind":
		if t.Op != query.OpEq {
			return false
		}
		v := strings.ToLower(t.Value)
		if p, ok := strings.CutSuffix(v, "*"); ok {
			return !strings.HasPrefix(siem.KindLog, p) && !strings.HasPrefix(siem.KindHTTPRequest, p)
		}
		return v != siem.KindLog && v != siem.KindHTTPRequest
	case "lvl":
		r := siem.LevelRank(strings.ToLower(t.Value))
		warn := siem.LevelRank(siem.LvlWarn)
		switch t.Op {
		case query.OpEq, query.OpGe:
			return r >= warn
		case query.OpGt:
			return r+1 >= warn
		}
	}
	return false
}

// sqlWhere narrows the events table to rows that may match q. Every condition is a fixed
// fragment with '?' placeholders, and each selects a superset of the matches; query.Match decides
// on the rows returned.
func sqlWhere(q query.Query) (string, []any) {
	conds := []string{"1 = 1"}
	var args []any
	add := func(c string, a ...any) {
		conds = append(conds, c)
		args = append(args, a...)
	}
	if !q.From.IsZero() {
		add("ts >= ?", tsNS(q.From))
	}
	if !q.To.IsZero() {
		add("ts < ?", tsNS(q.To))
	}
	for _, t := range q.Terms {
		v := strings.ToLower(t.Value)
		if col, ok := indexColumns[t.Field]; ok && v != "" {
			p, prefix := strings.CutSuffix(v, "*")
			// A missing field is '' in the table. ':' and '!=' need the field present; a negated term
			// also matches events without it.
			eq, ne := t.Op == query.OpEq, t.Op == query.OpNe
			switch {
			case t.Op == query.OpContains && !t.Neg:
				add("instr("+col+", ?) > 0", v)
			case t.Op == query.OpContains:
				add("instr("+col+", ?) = 0", v)
			case eq && !t.Neg && prefix:
				add(col+" != '' AND instr("+col+", ?) = 1", p)
			case eq && !t.Neg:
				add(col+" = ?", v)
			case ne && !t.Neg && prefix:
				add(col+" != '' AND instr("+col+", ?) != 1", p)
			case ne && !t.Neg:
				add(col+" != '' AND "+col+" != ?", v)
			case eq && prefix:
				add("("+col+" = '' OR instr("+col+", ?) != 1)", p)
			case eq:
				add(col+" != ?", v)
			case ne && prefix:
				add("("+col+" = '' OR instr("+col+", ?) = 1)", p)
			case ne:
				add("("+col+" = '' OR "+col+" = ?)", v)
			}
			continue
		}
		switch t.Field {
		case "ip":
			if t.Op == query.OpEq && !t.Neg && !strings.ContainsAny(t.Value, "/*") {
				if a, err := netip.ParseAddr(t.Value); err == nil {
					add("ip = ?", a.Unmap().String())
				}
			}
		case "lvl":
			if t.Neg || t.Op == query.OpContains {
				continue
			}
			op := map[query.Op]string{query.OpEq: "=", query.OpNe: "!=", query.OpGt: ">", query.OpGe: ">=", query.OpLt: "<", query.OpLe: "<="}[t.Op]
			if op != "" {
				add("lvl "+op+" ?", siem.LevelRank(v))
			}
		}
	}
	return strings.Join(conds, " AND "), args
}

// indexHit is one candidate row.
type indexHit struct {
	id, ts int64
	json   []byte
}

const indexBatch = 256

// indexBatch runs one page query on the read pool and reads every row before closing them.
func (s *Store) indexBatch(ctx context.Context, sqlText string, args []any) ([]indexHit, error) {
	rows, err := s.rdb.QueryContext(ctx, sqlText, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []indexHit
	for rows.Next() {
		var h indexHit
		if err := rows.Scan(&h.id, &h.ts, &h.json); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// searchIndex answers q from the events table: candidate rows newest first in batches (keyset on
// ts, id), each checked with query.Match. Rows of the first TS are examined whatever the budget,
// so every page makes progress.
func (s *Store) searchIndex(ctx context.Context, q query.Query, limit int) (Result, error) {
	where, args := sqlWhere(q)
	c := newCollector(limit, s.maxResultBytes)
	budget := s.searchBytes
	var (
		r                     Result
		curTS, curID, firstTS int64
		capAt                 int64 // when capped: the matches newer than this are complete
		started               bool
	)
	for !c.full() && !r.Capped {
		text := `SELECT id, ts, json FROM events WHERE ` + where
		a := append([]any(nil), args...)
		if started {
			text += ` AND ts <= ? AND (ts < ? OR id < ?)`
			a = append(a, curTS, curTS, curID)
		}
		text += ` ORDER BY ts DESC, id DESC LIMIT ?`
		a = append(a, indexBatch)
		batch, err := s.indexBatch(ctx, text, a)
		if err != nil {
			if ctx.Err() == nil {
				return Result{}, err
			}
			if !started {
				// Nothing examined: the same page again.
				return Result{Capped: true, More: true, Before: q.To}, nil
			}
			r.Capped, capAt = true, curTS
			break
		}
		for _, h := range batch {
			if !started {
				firstTS, started = h.ts, true
			} else if h.ts != firstTS && (budget <= 0 || ctx.Err() != nil) {
				r.Capped, capAt = true, h.ts
				break
			}
			r.Scanned++
			budget -= int64(len(h.json))
			var e siem.Event
			if json.Unmarshal(h.json, &e) == nil && q.Match(&e) {
				c.offer(h.ts, h.id, h.json)
			}
			curTS, curID = h.ts, h.id
			if c.full() {
				break
			}
		}
		if len(batch) < indexBatch {
			break
		}
	}
	return pageGuard(c.result(limit, r, capAt, r.Capped), q), nil
}
