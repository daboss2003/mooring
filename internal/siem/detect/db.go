package detect

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/siem"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// dbFile is the engine's own database in the security-log directory. It is separate from
// security.db so neither file's migrations or write connection depend on the other.
const dbFile = "detect.db"

const (
	dbTimeout    = 2 * time.Second  // one statement of the evaluation goroutine
	batchTimeout = 10 * time.Second // one batch of detection writes
	readers      = 2                // read-only connections for the dashboard
	walSizeCap   = 4 << 20
	pruneChunk   = 1000
	pruneBudget  = 5 * time.Second
)

type db struct {
	w     *sql.DB // the one write connection
	r     *sql.DB // read-only pool
	chunk int     // rows the size cap removes per statement (tests lower it)
}

// openDB opens <dir>/detect.db (created 0600, symlinks refused) and applies the migrations.
func openDB(dir string) (*db, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("detect: %w", err)
	}
	path := filepath.Join(dir, dbFile)
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		if fi, err := os.Lstat(path + suffix); err == nil && !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("detect: %s%s is not a regular file (a symlink is refused)", path, suffix)
		}
	}
	// SQLite creates -wal and -shm with the database file's mode.
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|oNoFollow, 0o600)
	if err != nil {
		return nil, fmt.Errorf("detect: create %s: %w", path, err)
	}
	if fi, err := f.Stat(); err == nil && fi.Mode().Perm() != 0o600 {
		_ = f.Chmod(0o600)
	}
	_ = f.Close()
	w, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)"+
		"&_pragma=synchronous(NORMAL)&_pragma=journal_size_limit("+fmt.Sprint(walSizeCap)+")")
	if err != nil {
		return nil, fmt.Errorf("detect: open %s: %w", path, err)
	}
	// One connection: writes are serialized and the SQLite rule applies (never a statement while
	// rows or a transaction are open).
	w.SetMaxOpenConns(1)
	if err := w.Ping(); err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("detect: open %s: %w", path, err)
	}
	if err := migrate(w); err != nil {
		_ = w.Close()
		return nil, err
	}
	r, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=query_only(ON)")
	if err != nil {
		_ = w.Close()
		return nil, fmt.Errorf("detect: open %s: %w", path, err)
	}
	r.SetMaxOpenConns(readers)
	return &db{w: w, r: r, chunk: pruneChunk}, nil
}

func (d *db) close() error {
	return errors.Join(d.r.Close(), d.w.Close())
}

type migration struct {
	version int
	name    string
	sql     string
}

func loadMigrations() ([]migration, error) {
	entries, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return nil, err
	}
	var ms []migration
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		var ver int
		if _, err := fmt.Sscanf(e.Name(), "%04d_", &ver); err != nil {
			return nil, fmt.Errorf("detect: bad migration filename %q: %w", e.Name(), err)
		}
		b, err := migrationFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			return nil, err
		}
		ms = append(ms, migration{version: ver, name: e.Name(), sql: string(b)})
	}
	sort.Slice(ms, func(i, j int) bool { return ms[i].version < ms[j].version })
	return ms, nil
}

// migrate applies the embedded migrations in order, each in its own transaction; a database that
// knows a higher version than this binary is refused.
func migrate(w *sql.DB) error {
	if _, err := w.Exec(`CREATE TABLE IF NOT EXISTS schema_version (
		version    INTEGER PRIMARY KEY,
		name       TEXT NOT NULL,
		applied_at INTEGER NOT NULL DEFAULT (unixepoch())
	)`); err != nil {
		return fmt.Errorf("detect: create schema_version: %w", err)
	}
	var current int
	if err := w.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&current); err != nil {
		return fmt.Errorf("detect: read schema version: %w", err)
	}
	ms, err := loadMigrations()
	if err != nil {
		return err
	}
	for i, m := range ms {
		if m.version != i+1 {
			return fmt.Errorf("detect: migrations not contiguous: expected version %d, got %d (%s)", i+1, m.version, m.name)
		}
	}
	if current > len(ms) {
		return fmt.Errorf("detect: detection database schema version %d is newer than this binary's %d (downgrade refused)", current, len(ms))
	}
	for _, m := range ms[current:] {
		tx, err := w.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(m.sql); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("detect: migration %s: %w", m.name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_version(version, name) VALUES (?, ?)`, m.version, m.name); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("detect: record migration %s: %w", m.name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("detect: commit migration %s: %w", m.name, err)
		}
	}
	return nil
}

// stored is a detection row plus the engine's bookkeeping.
type stored struct {
	d       siem.Detection
	alerted time.Time // when an alert was last handed to the alert queue (zero: never)
	rollup  bool      // the rule's rollup detection for an hour (key RollupKey, never a real key's)
	capHour time.Time // the hour it is counted in its rule's summary alert for (zero: none)
	incID   int64     // its incident (0: none, or one not written yet: activeDet.inc)
	entKind string    // the kind of entity its key is (siem.EntityAccount, siem.EntityAddress, "": neither)
	scope   string    // the account scope of its events ("mooring", "host", "app:<slug>", "edge")
}

const detCols = `id, source, rule_id, rule_name, severity, mitre, key, app, service, first_ns, last_ns, count,
	summary, geo, evidence, snoozed, alerted_ns, rollup, cap_hour, incident_id, ent_kind, scope, muted`

func scanDetection(sc interface{ Scan(...any) error }) (stored, error) {
	var (
		s                             stored
		sev, mitre, geo, evid         string
		first, last, alerted, capHour int64
		snoozed, rollup, muted        int
	)
	if err := sc.Scan(&s.d.ID, &s.d.Source, &s.d.RuleID, &s.d.RuleName, &sev, &mitre, &s.d.Key, &s.d.App,
		&s.d.Service, &first, &last, &s.d.Count, &s.d.Summary, &geo, &evid, &snoozed, &alerted, &rollup, &capHour,
		&s.incID, &s.entKind, &s.scope, &muted); err != nil {
		return stored{}, err
	}
	s.d.Muted = muted != 0
	if s.entKind != siem.EntityAccount && s.entKind != siem.EntityAddress {
		s.entKind = ""
	}
	if capHour > 0 {
		s.capHour = time.Unix(capHour, 0).UTC()
	}
	s.d.Severity = siem.Severity(sev)
	if mitre != "" {
		s.d.MITRE = strings.Split(mitre, ",")
	}
	s.d.First, s.d.Last = time.Unix(0, first).UTC(), time.Unix(0, last).UTC()
	s.d.Snoozed = snoozed != 0
	s.rollup = rollup != 0
	if alerted != 0 {
		s.alerted = time.Unix(0, alerted)
	}
	if geo != "" {
		var g siem.Geo
		if json.Unmarshal([]byte(geo), &g) == nil {
			s.d.Geo = &g
		}
	}
	if evid != "" {
		var ev []siem.Evidence
		if json.Unmarshal([]byte(evid), &ev) == nil {
			if len(ev) > siem.MaxEvidence {
				ev = ev[len(ev)-siem.MaxEvidence:]
			}
			s.d.Evidence = ev
		}
	}
	return s, nil
}

func encodeGeo(g *siem.Geo) string {
	if g == nil {
		return ""
	}
	b, err := json.Marshal(g)
	if err != nil {
		return ""
	}
	return string(b)
}

func encodeEvidence(ev []siem.Evidence) string {
	if len(ev) == 0 {
		return ""
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return ""
	}
	return string(b)
}

func nanos(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

const (
	insertSQL = `INSERT INTO detections(source, rule_id, rule_name, severity, sev_rank, mitre, key, app, service,
		first_ns, last_ns, count, summary, geo, evidence, snoozed, alerted_ns, rollup, cap_hour, incident_id, ent_kind,
		scope, muted) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	// alerted_ns never goes back: a copy read before markAlerted recorded an alert keeps it.
	updateSQL = `UPDATE detections SET rule_name = ?, severity = ?, sev_rank = ?, mitre = ?, app = ?, service = ?,
		first_ns = ?, last_ns = ?, count = ?, summary = ?, geo = ?, evidence = ?, snoozed = ?,
		alerted_ns = MAX(alerted_ns, ?), cap_hour = ?, incident_id = ?, ent_kind = ?, scope = ?, muted = ? WHERE id = ?`
)

func unixSec(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

// writeBatch inserts the detections without an ID and updates the others, in one transaction
// with what b holds of incidents (inserted or updated first, so a detection can name a new one, and
// their entities, timeline entries and risk scores after), and returns every detection's ID and
// every incident's (in order). A detection whose row is gone (the size cap removed it while it was
// still being updated) is inserted again: its ID is then a new one. b may be nil.
func (d *db) writeBatch(ctx context.Context, ss []*stored, b *incBatch) ([]int64, []int64, error) {
	ctx, cancel := context.WithTimeout(ctx, batchTimeout)
	defer cancel()
	if b == nil {
		b = &incBatch{}
	}
	tx, err := d.w.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = tx.Rollback() }()
	incIDs, err := writeIncidents(ctx, tx, b)
	if err != nil {
		return nil, nil, err
	}
	ins, err := tx.PrepareContext(ctx, insertSQL)
	if err != nil {
		return nil, nil, err
	}
	defer ins.Close()
	upd, err := tx.PrepareContext(ctx, updateSQL)
	if err != nil {
		return nil, nil, err
	}
	defer upd.Close()
	ids := make([]int64, len(ss))
	for i, s := range ss {
		mitre, geo, evid := strings.Join(s.d.MITRE, ","), encodeGeo(s.d.Geo), encodeEvidence(s.d.Evidence)
		incID := s.incID
		if i < len(b.detInc) && b.detInc[i] >= 0 {
			incID = incIDs[b.detInc[i]]
		}
		if s.d.ID != 0 {
			res, err := upd.ExecContext(ctx, s.d.RuleName, string(s.d.Severity), siem.SeverityRank(s.d.Severity),
				mitre, s.d.App, s.d.Service, nanos(s.d.First), nanos(s.d.Last), s.d.Count, s.d.Summary, geo, evid,
				boolInt(s.d.Snoozed), nanos(s.alerted), unixSec(s.capHour), incID, s.entKind, s.scope, boolInt(s.d.Muted),
				s.d.ID)
			if err != nil {
				return nil, nil, err
			}
			n, err := res.RowsAffected()
			if err != nil {
				return nil, nil, err
			}
			if n > 0 {
				ids[i] = s.d.ID
				continue
			}
		}
		res, err := ins.ExecContext(ctx, s.d.Source, s.d.RuleID, s.d.RuleName, string(s.d.Severity),
			siem.SeverityRank(s.d.Severity), mitre, s.d.Key, s.d.App, s.d.Service, nanos(s.d.First), nanos(s.d.Last),
			s.d.Count, s.d.Summary, geo, evid, boolInt(s.d.Snoozed), nanos(s.alerted), boolInt(s.rollup), unixSec(s.capHour),
			incID, s.entKind, s.scope, boolInt(s.d.Muted))
		if err != nil {
			return nil, nil, err
		}
		if ids[i], err = res.LastInsertId(); err != nil {
			return nil, nil, err
		}
	}
	if err := writeIncidentRest(ctx, tx, b, incIDs, ids); err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}
	return ids, incIDs, nil
}

// recentKeys returns mapKey(rule ID, key) of the detections (rollups aside) whose last event is at
// or after since, at most limit+1 of them (more than limit: the caller stops tracking).
func (d *db) recentKeys(ctx context.Context, since time.Time, limit int) ([]string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	rows, err := d.w.QueryContext(ctx, `SELECT rule_id, key FROM detections WHERE last_ns >= ? AND rollup = 0 LIMIT ?`,
		since.UnixNano(), limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id, key string
		if err := rows.Scan(&id, &key); err != nil {
			return nil, err
		}
		out = append(out, mapKey(id, key))
	}
	return out, rows.Err()
}

// alertedSince returns, per rule and key (mapKey, or rollupKey for a rollup), the newest time an
// alert was raised at or after since, for at most limit of them (the newest).
func (d *db) alertedSince(ctx context.Context, since time.Time, limit int) (map[string]time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	rows, err := d.w.QueryContext(ctx, `SELECT rule_id, key, rollup, MAX(alerted_ns) AS at FROM detections
		WHERE alerted_ns > 0 AND alerted_ns >= ? GROUP BY rule_id, key, rollup ORDER BY at DESC LIMIT ?`,
		since.UnixNano(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var (
			id, key string
			rollup  int
			at      int64
		)
		if err := rows.Scan(&id, &key, &rollup, &at); err != nil {
			return nil, err
		}
		mk := mapKey(id, key)
		if rollup != 0 {
			mk = rollupKey(id)
		}
		out[mk] = time.Unix(0, at)
	}
	return out, rows.Err()
}

// markAlerted records alert times (unix ns) on rows by ID, never moving one back, in one
// transaction. A row that is gone is skipped.
func (d *db) markAlerted(ctx context.Context, at map[int64]int64) error {
	ctx, cancel := context.WithTimeout(ctx, batchTimeout)
	defer cancel()
	tx, err := d.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for id, ns := range at {
		if _, err := tx.ExecContext(ctx, `UPDATE detections SET alerted_ns = ? WHERE id = ? AND alerted_ns < ?`,
			ns, id, ns); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// latest returns the newest stored detection of a rule for a key (never a rollup).
func (d *db) latest(ctx context.Context, ruleID, key string) (stored, bool, error) {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	s, err := scanDetection(d.w.QueryRowContext(ctx, `SELECT `+detCols+` FROM detections
		WHERE rule_id = ? AND key = ? AND rollup = 0 ORDER BY id DESC LIMIT 1`, ruleID, key))
	if errors.Is(err, sql.ErrNoRows) {
		return stored{}, false, nil
	}
	if err != nil {
		return stored{}, false, err
	}
	return s, true, nil
}

// list returns detections for the page, most recently seen first (last_ns, then id, descending),
// paged by that pair.
func (d *db) list(ctx context.Context, f siem.DetectionFilter) ([]siem.Detection, error) {
	var (
		where []string
		args  []any
	)
	if !f.BeforeLast.IsZero() {
		where, args = append(where, "(last_ns, id) < (?, ?)"), append(args, f.BeforeLast.UnixNano(), f.Before)
	}
	if f.RuleID != "" {
		where, args = append(where, "rule_id = ?"), append(args, f.RuleID)
	}
	if r := siem.SeverityRank(f.MinSeverity); r > 0 {
		where, args = append(where, "sev_rank >= ?"), append(args, r)
	}
	if f.App != "" {
		where, args = append(where, "app = ?"), append(args, f.App)
	}
	if !f.From.IsZero() {
		where, args = append(where, "last_ns >= ?"), append(args, f.From.UnixNano())
	}
	if !f.To.IsZero() {
		where, args = append(where, "last_ns < ?"), append(args, f.To.UnixNano())
	}
	limit := f.Limit
	switch {
	case limit <= 0:
		limit = 50
	case limit > 200:
		limit = 200
	}
	q := `SELECT ` + detCols + ` FROM detections`
	if len(where) > 0 {
		q += ` WHERE ` + strings.Join(where, " AND ")
	}
	q += ` ORDER BY last_ns DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := d.r.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []siem.Detection{}
	for rows.Next() {
		s, err := scanDetection(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s.d)
	}
	return out, rows.Err()
}

func (d *db) get(ctx context.Context, id int64) (siem.Detection, bool, error) {
	s, err := scanDetection(d.r.QueryRowContext(ctx, `SELECT `+detCols+` FROM detections WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return siem.Detection{}, false, nil
	}
	if err != nil {
		return siem.Detection{}, false, err
	}
	return s.d, true, nil
}

// prune deletes detections whose last event is before cutoff, in chunks, within pruneBudget.
func (d *db) prune(ctx context.Context, cutoff time.Time) (int64, error) {
	deadline := time.Now().Add(pruneBudget)
	var total int64
	for time.Now().Before(deadline) {
		cctx, cancel := context.WithTimeout(ctx, dbTimeout)
		res, err := d.w.ExecContext(cctx, `DELETE FROM detections WHERE id IN
			(SELECT id FROM detections WHERE last_ns < ? LIMIT ?)`, cutoff.UnixNano(), pruneChunk)
		cancel()
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
		if n < pruneChunk {
			break
		}
	}
	return total, nil
}

// used is the size of detect.db's pages in use (bytes): the file without its free pages.
func (d *db) used(ctx context.Context) (int64, error) {
	ctx, cancel := context.WithTimeout(ctx, dbTimeout)
	defer cancel()
	var pages, free, size int64
	if err := d.w.QueryRowContext(ctx, `SELECT page_count, freelist_count, page_size
		FROM pragma_page_count(), pragma_freelist_count(), pragma_page_size()`).Scan(&pages, &free, &size); err != nil {
		return 0, err
	}
	return (pages - free) * size, nil
}

// trimTo removes detections while the pages in use are above limit, until they are at most
// target: of the detections in no open or acknowledged incident, the oldest low and medium ones
// first, then the oldest of any severity; then the oldest resolved and false-positive incidents
// (with their entities and timeline; their detections go in the passes before, unlinked); and only
// when nothing else is left, the oldest open and acknowledged incidents whole, with their
// detections. It stops after pruneBudget and returns how many detections and incidents it removed,
// and the incidents' IDs.
func (d *db) trimTo(ctx context.Context, limit, target int64) (int64, []int64, error) {
	used, err := d.used(ctx)
	if err != nil || used <= limit {
		return 0, nil, err
	}
	var gone []int64
	deadline := time.Now().Add(pruneBudget)
	var total int64
	del := func(q string) func() (int64, error) {
		return func() (int64, error) {
			cctx, cancel := context.WithTimeout(ctx, dbTimeout)
			defer cancel()
			res, err := d.w.ExecContext(cctx, q, d.chunk)
			if err != nil {
				return 0, err
			}
			return res.RowsAffected()
		}
	}
	incidents := func(where string, n int, withDets bool) func() (int64, error) {
		return func() (int64, error) {
			ids, err := d.incidentIDs(ctx, `SELECT id FROM incidents WHERE `+where+` ORDER BY last_ns, id LIMIT ?`, n)
			if err != nil {
				return 0, err
			}
			dets, err := d.deleteIncidents(ctx, ids, withDets)
			if err != nil {
				return 0, err
			}
			gone = append(gone, ids...)
			return dets + int64(len(ids)), nil
		}
	}
	notActive := `incident_id NOT IN (` + activeSQL + `)`
	passes := []func() (int64, error){
		del(`DELETE FROM detections WHERE id IN (SELECT id FROM detections WHERE sev_rank <= 2 AND ` + notActive +
			` ORDER BY last_ns, id LIMIT ?)`),
		del(`DELETE FROM detections WHERE id IN (SELECT id FROM detections WHERE ` + notActive + ` ORDER BY last_ns, id LIMIT ?)`),
		incidents(`id NOT IN (`+activeSQL+`)`, d.chunk, false),
		// Intentional (owner decision): an open or acknowledged incident is never closed on its own,
		// and its records are the last to go, but the cap holds: once only they are left, the oldest
		// of them are removed whole (with their detections, entities and timeline), a few at a time,
		// so incidents left open for months can't grow detect.db without a bound.
		incidents(`state IN ('open', 'acknowledged')`, max(d.chunk/10, 1), true),
	}
	for used > target && time.Now().Before(deadline) {
		var n int64
		for _, pass := range passes {
			if n, err = pass(); err != nil {
				return total, gone, err
			}
			if n > 0 {
				break
			}
		}
		if n == 0 {
			break // nothing left to remove: the rest is learned state
		}
		total += n
		if used, err = d.used(ctx); err != nil {
			return total, gone, err
		}
	}
	return total, gone, nil
}

type stateRow struct {
	sig  string
	data []byte
}

// loadState reads every persisted rule state: rule ID → part → row.
func (d *db) loadState(ctx context.Context) (map[string]map[string]stateRow, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	rows, err := d.w.QueryContext(ctx, `SELECT rule_id, part, sig, data FROM rule_state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]map[string]stateRow{}
	for rows.Next() {
		var id, part, sig string
		var data []byte
		if err := rows.Scan(&id, &part, &sig, &data); err != nil {
			return nil, err
		}
		if out[id] == nil {
			out[id] = map[string]stateRow{}
		}
		out[id][part] = stateRow{sig: sig, data: data}
	}
	return out, rows.Err()
}

type stateWrite struct {
	rule, part, sig string
	data            []byte
}

// saveState writes the given state rows and removes the rows of rules not in keep, in one
// transaction.
func (d *db) saveState(ctx context.Context, rows []stateWrite, keep map[string]bool, now time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// The rule IDs stored, read before the transaction (no statement while rows are open).
	ids, err := d.stateRuleIDs(ctx)
	if err != nil {
		return err
	}
	tx, err := d.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	for _, r := range rows {
		if _, err := tx.ExecContext(ctx, `INSERT INTO rule_state(rule_id, part, sig, data, updated_ns) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(rule_id, part) DO UPDATE SET sig = excluded.sig, data = excluded.data, updated_ns = excluded.updated_ns`,
			r.rule, r.part, r.sig, r.data, now.UnixNano()); err != nil {
			return err
		}
	}
	for _, id := range ids {
		if !keep[id] {
			if _, err := tx.ExecContext(ctx, `DELETE FROM rule_state WHERE rule_id = ?`, id); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// hourRow is one rule's counters for a wall-clock hour (table rule_hours, see Engine.saveHour).
type hourRow struct {
	rule                 string
	hour                 time.Time
	newCount, sent, more int64
	rollupID             int64
	rolled               []byte // the rollup's keys (rolledSet.encode)
	source, name, target string
}

// saveHours replaces the saved hourly counters with rows, in one transaction.
func (d *db) saveHours(ctx context.Context, rows []hourRow) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	tx, err := d.w.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DELETE FROM rule_hours`); err != nil {
		return err
	}
	ins, err := tx.PrepareContext(ctx, `INSERT INTO rule_hours(rule_id, hour, new_count, rollup_id, rolled, sent, more,
		source, name, target) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer ins.Close()
	for _, r := range rows {
		rolled := r.rolled
		if rolled == nil {
			rolled = []byte{}
		}
		if _, err := ins.ExecContext(ctx, r.rule, r.hour.Unix(), r.newCount, r.rollupID, rolled, r.sent, r.more,
			r.source, r.name, r.target); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// loadHours returns the counters saved for hour, at most limit rows; owedOnly: only the rows with a
// summary alert owed (more > 0), without their rollup keys.
func (d *db) loadHours(ctx context.Context, hour time.Time, limit int, owedOnly bool) ([]hourRow, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	q := `SELECT rule_id, new_count, rollup_id, rolled, sent, more, source, name, target FROM rule_hours WHERE hour = ? LIMIT ?`
	if owedOnly {
		q = `SELECT rule_id, new_count, rollup_id, x'', sent, more, source, name, target FROM rule_hours
			WHERE hour = ? AND more > 0 LIMIT ?`
	}
	rows, err := d.w.QueryContext(ctx, q, hour.Unix(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []hourRow
	for rows.Next() {
		r := hourRow{hour: hour}
		if err := rows.Scan(&r.rule, &r.newCount, &r.rollupID, &r.rolled, &r.sent, &r.more, &r.source, &r.name,
			&r.target); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// hourRollups returns the rollup detections the counters saved for hour name, at most limit.
func (d *db) hourRollups(ctx context.Context, hour time.Time, limit int) ([]stored, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	rows, err := d.w.QueryContext(ctx, `SELECT `+detCols+` FROM detections WHERE rollup = 1 AND id IN
		(SELECT rollup_id FROM rule_hours WHERE hour = ? AND rollup_id > 0) LIMIT ?`, hour.Unix(), limit)
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

func (d *db) stateRuleIDs(ctx context.Context) ([]string, error) {
	rows, err := d.w.QueryContext(ctx, `SELECT DISTINCT rule_id FROM rule_state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
