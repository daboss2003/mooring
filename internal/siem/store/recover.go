package store

import (
	"bufio"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

// recoverLocked loads the manifest and reconciles it with the segment files: a segment a previous
// run left open, or a file without a row, is sealed as it is on disk (its gzip stream may be
// truncated; the hash is of the bytes there); a row whose file is gone is removed, and recorded as
// lost when it wasn't archived. Index rows of a vanished segment are kept (Prune removes them past
// the retention). Caller holds s.mu.
func (s *Store) recoverLocked() error {
	known, err := s.loadManifest()
	if err != nil {
		return err
	}
	if err := s.loadSeqsLocked(); err != nil {
		return err
	}
	ents, err := os.ReadDir(s.segDir)
	if err != nil {
		return fmt.Errorf("store: read %s: %w", s.segDir, err)
	}
	files := map[string]os.DirEntry{}
	for _, e := range ents {
		if _, _, _, ok := parseSegName(e.Name()); !ok {
			continue
		}
		if !e.Type().IsRegular() {
			s.opt.Log.Warn("siem store: ignoring a segment name that is not a regular file", "name", e.Name())
			continue
		}
		files[e.Name()] = e
	}
	var toSeal []*seg
	inManifest := map[string]bool{}
	for _, g := range known {
		inManifest[g.name] = true
		hour, box, seq, ok := parseSegName(g.name)
		if !ok || !hour.Equal(g.hour) || box != g.box || seq != g.seq {
			s.opt.Log.Warn("siem store: removing a manifest row with a malformed name", "name", g.name)
			if _, err := s.exec(`DELETE FROM segments WHERE name = ?`, g.name); err != nil {
				return fmt.Errorf("store: %w", err)
			}
			continue
		}
		s.noteSeqLocked(g.hour, g.box, g.seq)
		e, onDisk := files[g.name]
		switch {
		case !onDisk:
			// Its index rows go too (queued; the next Prune removes them), so the index never
			// answers events no segment holds.
			if err := s.tx(func(ctx context.Context, tx *sql.Tx) error {
				if _, err := tx.ExecContext(ctx, `DELETE FROM segments WHERE name = ?`, g.name); err != nil {
					return err
				}
				_, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO row_gc(segment) VALUES (?)`, g.name)
				return err
			}); err != nil {
				return fmt.Errorf("store: %w", err)
			}
			if g.archivedAt == 0 {
				s.loseLocked(g.name, g.events, "segment file missing")
			} else {
				s.opt.Log.Warn("siem store: archived segment file missing", "segment", g.name, "key", g.key)
			}
		case g.open:
			toSeal = append(toSeal, g)
		default:
			if fi, err := e.Info(); err == nil && fi.Size() != g.bytes {
				s.opt.Log.Warn("siem store: sealed segment changed size on disk", "segment", g.name, "sealed_bytes", g.bytes, "bytes", fi.Size())
			}
			s.insertSegLocked(g)
		}
	}
	for name := range files {
		if inManifest[name] {
			continue
		}
		hour, box, seq, _ := parseSegName(name)
		s.noteSeqLocked(hour, box, seq)
		toSeal = append(toSeal, &seg{name: name, hour: hour, seq: seq, box: box, open: true})
	}
	sort.Slice(toSeal, func(i, j int) bool { return segLess(toSeal[i], toSeal[j]) })
	for _, g := range toSeal {
		path := filepath.Join(s.segDir, g.name)
		st, err := scanFile(path)
		if err != nil {
			s.opt.Log.Warn("siem store: cannot read a segment left open", "segment", g.name, "err", err)
			continue
		}
		if st.size == 0 {
			_ = os.Remove(path)
			if _, err := s.exec(`DELETE FROM segments WHERE name = ?`, g.name); err != nil {
				return fmt.Errorf("store: %w", err)
			}
			continue
		}
		g.events, g.first, g.last, g.bytes, g.sha, g.flushed = st.events, st.first, st.last, st.size, st.sha, st.size
		if g.capFirst == 0 {
			g.capFirst = g.hour.UnixNano()
		}
		g.capLast = min(max(st.mtime.UnixNano(), g.capFirst), g.hour.Add(time.Hour).UnixNano()-1)
		if err := s.recordSealLocked(g); err != nil {
			return err
		}
		s.insertSegLocked(g)
		// Events can reach the file without the Flush that indexes them (a full deflate block is
		// written as it fills): the index is rebuilt from what the file holds.
		if err := s.reindexLocked(g); err != nil {
			s.opt.Log.Error("siem store: cannot index a recovered segment; a scan still finds its events", "segment", g.name, "err", err)
		}
		s.opt.Log.Info("siem store: sealed a segment left open by the previous run", "segment", g.name, "events", g.events)
	}
	// Keep what recovery learned (files no row knew of) in seqs too, and record every box seen
	// (this one included) with its earliest hour.
	firstSeen := map[string]int64{s.opt.Box: s.now().Unix()}
	return s.tx(func(ctx context.Context, tx *sql.Tx) error {
		for k, seq := range s.maxSeq {
			hour, box, _ := strings.Cut(k, "/")
			h, err := strconv.ParseInt(hour, 10, 64)
			if err != nil || !siem.SafeName(box) {
				continue
			}
			if err := upsertSeq(ctx, tx, time.Unix(h, 0), box, seq); err != nil {
				return err
			}
			if f, ok := firstSeen[box]; !ok || h < f {
				firstSeen[box] = h
			}
		}
		for box, f := range firstSeen {
			if _, err := tx.ExecContext(ctx, `INSERT INTO boxes(name, first_seen) VALUES (?, ?)
				ON CONFLICT(name) DO UPDATE SET first_seen = MIN(first_seen, excluded.first_seen)`, box, f); err != nil {
				return err
			}
		}
		return nil
	})
}

// loadSeqsLocked reads the highest seq used per hour and box. Caller holds s.mu.
func (s *Store) loadSeqsLocked() error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `SELECT hour, box, seq FROM seqs`)
	if err != nil {
		return fmt.Errorf("store: read seqs: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			hour int64
			box  string
			seq  int
		)
		if err := rows.Scan(&hour, &box, &seq); err != nil {
			return fmt.Errorf("store: read seqs: %w", err)
		}
		s.noteSeqLocked(time.Unix(hour, 0), box, seq)
	}
	return rows.Err()
}

// loadManifest reads every segment row (one query, every column, rows closed before returning).
func (s *Store) loadManifest() ([]*seg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	rows, err := s.db.QueryContext(ctx, `SELECT name, hour, seq, box, events, bytes, sha256, prev_sha256, first_ts,
		last_ts, cap_first, cap_last, chain, sealed_at, archived_at, archive_key, state FROM segments`)
	if err != nil {
		return nil, fmt.Errorf("store: read manifest: %w", err)
	}
	defer rows.Close()
	var out []*seg
	for rows.Next() {
		g := &seg{}
		var (
			hour  int64
			state string
		)
		if err := rows.Scan(&g.name, &hour, &g.seq, &g.box, &g.events, &g.bytes, &g.sha, &g.prev, &g.first,
			&g.last, &g.capFirst, &g.capLast, &g.chain, &g.sealedAt, &g.archivedAt, &g.key, &state); err != nil {
			return nil, fmt.Errorf("store: read manifest: %w", err)
		}
		g.hour, g.open = time.Unix(hour, 0).UTC(), state == "open"
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: read manifest: %w", err)
	}
	return out, nil
}

// reindexLocked replaces g's index rows with the classified events its file holds, indexChunk
// rows at a time. Caller holds s.mu (released between steps).
func (s *Store) reindexLocked(g *seg) error {
	if err := s.gcRowsLocked(g.name); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(s.segDir, g.name), os.O_RDONLY|oNoFollow, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", g.name)
	}
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil // nothing in it decodes
	}
	zr.Multistream(false)
	sc := bufio.NewScanner(zr)
	sc.Buffer(make([]byte, 64<<10), maxLine)
	var (
		batch []indexRow
		ord   int
	)
	for sc.Scan() {
		var e siem.Event
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			continue
		}
		ord++
		if !classified(&e) {
			continue
		}
		batch = append(batch, newIndexRow(&e, tsNS(e.TS), g.name, ord, sc.Bytes()))
		if len(batch) == indexChunk {
			if _, err := s.insertRows(batch); err != nil {
				return err
			}
			batch = batch[:0]
		}
	}
	// A truncated or damaged stream ends the file's events, not the re-index.
	_, err = s.insertRows(batch)
	return err
}
