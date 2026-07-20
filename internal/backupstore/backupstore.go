// Package backupstore manages Mooring's own-state backups: a consistent snapshot of
// the SQLite database (via VACUUM INTO), AES-256-GCM-encrypted with the master key
// (the chunked, tamper-evident stream from internal/backup), written under the data
// dir and recorded in a catalog. This is the "recover Mooring onto a fresh box"
// backup — it carries every app's config, definitions, edge routes, and (already-
// encrypted) secrets. App-internal data volumes are a separate snapshot type.
package backupstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/daboss2003/mooring/internal/backup"
	"github.com/daboss2003/mooring/internal/store"
)

var idRe = regexp.MustCompile(`^[a-f0-9]{24}$`)

// Record is one catalogued backup.
type Record struct {
	ID        string
	CreatedAt int64
	SizeBytes int64
	File      string
	SHA256    string
	Kind      string // "mooring-state" | "postgres" | "mysql" | "volume"
	Note      string
	Project   string // app slug ("" for mooring-state)
	Target    string // service (db dump) or volume name ("" for mooring-state)
	Location  string // "local" | "s3" | "local+s3"
}

// Store creates, lists, and deletes encrypted state backups.
type Store struct {
	db  *store.DB
	dir string
	key []byte // 32-byte master key (AES-256)
}

// New builds a Store. dir is where archives are written (created 0700 on first use).
func New(db *store.DB, dir string, key []byte) *Store {
	return &Store{db: db, dir: dir, key: key}
}

// Available reports whether backups can be taken (a valid key is configured).
func (s *Store) Available() bool { return s != nil && len(s.key) == 32 && s.db != nil }

// Create takes a consistent snapshot of the DB, encrypts it, and records it. The
// plaintext snapshot exists only transiently (0600, in the 0700 backups dir) and is
// removed as soon as it's encrypted.
func (s *Store) Create(ctx context.Context, now time.Time) (Record, error) {
	if !s.Available() {
		return Record{}, errors.New("backupstore: not available (no master key)")
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return Record{}, fmt.Errorf("backupstore: mkdir: %w", err)
	}
	_ = os.Chmod(s.dir, 0o700) // tighten a pre-existing, looser dir (MkdirAll won't)
	id, err := randHex(12)
	if err != nil {
		return Record{}, err
	}
	tmp := filepath.Join(s.dir, "."+id+".snapshot")
	final := filepath.Join(s.dir, id+".mbk")
	// Register cleanup BEFORE the snapshot, so a VACUUM that fails mid-write (disk full,
	// I/O error, cancellation) can't leave a partial PLAINTEXT copy of the DB behind.
	defer os.Remove(tmp)
	// VACUUM INTO writes a consistent copy of the live DB (committed WAL included) to a
	// NEW file. The path is server-generated (not user input); bind it as a parameter.
	if _, err := s.db.ExecContext(ctx, "VACUUM INTO ?", tmp); err != nil {
		return Record{}, fmt.Errorf("backupstore: snapshot: %w", err)
	}
	// The transient snapshot is a full plaintext copy of the DB. VACUUM INTO honors the
	// process umask (often 0022 → 0644), so force owner-only before we read it.
	if err := os.Chmod(tmp, 0o600); err != nil {
		return Record{}, fmt.Errorf("backupstore: secure snapshot: %w", err)
	}

	in, err := os.Open(tmp)
	if err != nil {
		return Record{}, err
	}
	defer in.Close()
	out, err := os.OpenFile(final, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return Record{}, err
	}
	if err := backup.Encrypt(out, in, s.key, 0); err != nil {
		out.Close()
		os.Remove(final)
		return Record{}, fmt.Errorf("backupstore: encrypt: %w", err)
	}
	if err := out.Close(); err != nil {
		os.Remove(final)
		return Record{}, err
	}
	size, sum, err := fileSizeSHA(final)
	if err != nil {
		os.Remove(final)
		return Record{}, err
	}
	rec := Record{ID: id, CreatedAt: now.Unix(), SizeBytes: size, File: id + ".mbk", SHA256: sum, Kind: "mooring-state", Location: "local"}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO backups(id, created_at, size_bytes, file, sha256, kind, note) VALUES(?, ?, ?, ?, ?, ?, '')`,
		rec.ID, rec.CreatedAt, rec.SizeBytes, rec.File, rec.SHA256, rec.Kind); err != nil {
		os.Remove(final)
		return Record{}, err
	}
	return rec, nil
}

const backupCols = `id, created_at, size_bytes, file, sha256, kind, note, project, target, location`

func scanRecord(sc interface{ Scan(...any) error }) (Record, error) {
	var r Record
	err := sc.Scan(&r.ID, &r.CreatedAt, &r.SizeBytes, &r.File, &r.SHA256, &r.Kind, &r.Note, &r.Project, &r.Target, &r.Location)
	return r, err
}

// List returns catalogued backups, newest first.
func (s *Store) List(ctx context.Context) ([]Record, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+backupCols+` FROM backups ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Record
	for rows.Next() {
		r, err := scanRecord(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Get returns one record by id (ok=false if absent/malformed).
func (s *Store) Get(ctx context.Context, id string) (Record, bool, error) {
	if !idRe.MatchString(id) {
		return Record{}, false, nil
	}
	r, err := scanRecord(s.db.QueryRowContext(ctx, `SELECT `+backupCols+` FROM backups WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Record{}, false, nil
	}
	if err != nil {
		return Record{}, false, err
	}
	return r, true, nil
}

// Dir returns the backups directory (0700). The app-data backup engine writes its
// externally-produced .mbk here (see appbackup.LocalFile) and then calls Catalog.
func (s *Store) Dir() string { return s.dir }

// NewID allocates a fresh 24-hex backup id.
func (s *Store) NewID() (string, error) { return randHex(12) }

// Catalog records an already-produced+encrypted backup file (an app-data snapshot from the
// appbackup engine). The file must already exist under Dir() as <rec.ID>.mbk; rec carries the
// size/sha the engine computed while streaming. For a volume backup it also updates
// backup_inventory so the prune denylist knows the volume is backed up.
func (s *Store) Catalog(ctx context.Context, rec Record) error {
	if !s.Available() {
		return errors.New("backupstore: not available")
	}
	if !idRe.MatchString(rec.ID) {
		return fmt.Errorf("backupstore: bad backup id %q", rec.ID)
	}
	if rec.Location == "" {
		rec.Location = "local"
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO backups(`+backupCols+`) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		rec.ID, rec.CreatedAt, rec.SizeBytes, rec.File, rec.SHA256, rec.Kind, rec.Note, rec.Project, rec.Target, rec.Location); err != nil {
		return err
	}
	if rec.Kind == "volume" && rec.Target != "" {
		if _, err := s.db.ExecContext(ctx,
			`INSERT INTO backup_inventory(volume, backup_id, updated_at) VALUES(?,?,?)
			 ON CONFLICT(volume) DO UPDATE SET backup_id=excluded.backup_id, updated_at=excluded.updated_at`,
			rec.Target, rec.ID, rec.CreatedAt); err != nil {
			return err
		}
	}
	return nil
}

// BackedUpVolumes returns the set of docker volumes that have a recorded backup (feeds
// backup.LiveState.BackedUpVolumes so PruneVolumeSafe won't drop an un-backed-up sole volume).
func (s *Store) BackedUpVolumes(ctx context.Context) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT volume FROM backup_inventory`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out[v] = true
	}
	return out, rows.Err()
}

// FilePath returns the absolute path of a record's archive, confined to the backups
// dir (the stored file name is always a generated <id>.mbk, never user input).
func (s *Store) FilePath(r Record) string { return filepath.Join(s.dir, filepath.Base(r.File)) }

// Delete removes the archive file and the catalog row, and keeps backup_inventory truthful.
// NOTE: for a volume snapshot that was also uploaded off-box (Location contains "s3"), the
// REMOTE object is not removed here (this store has no uploader) — scheduled retention prunes
// S3 copies; a manual delete of an app-data backup leaves its S3 copy for now.
func (s *Store) Delete(ctx context.Context, id string) error {
	rec, ok, err := s.Get(ctx, id)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	_ = os.Remove(s.FilePath(rec))
	if _, err := s.db.ExecContext(ctx, `DELETE FROM backups WHERE id=?`, id); err != nil {
		return err
	}
	// If this was a volume snapshot, repoint backup_inventory for that volume to the newest
	// SURVIVING snapshot (or drop the row if none remain) — so BackedUpVolumes, which feeds the
	// prune denylist, never claims a volume is backed up after its last snapshot was deleted.
	if rec.Kind == "volume" && rec.Target != "" {
		var newID string
		var newAt int64
		e := s.db.QueryRowContext(ctx,
			`SELECT id, created_at FROM backups WHERE kind='volume' AND project=? AND target=? ORDER BY created_at DESC, id DESC LIMIT 1`,
			rec.Project, rec.Target).Scan(&newID, &newAt)
		if errors.Is(e, sql.ErrNoRows) {
			_, _ = s.db.ExecContext(ctx, `DELETE FROM backup_inventory WHERE volume=?`, rec.Target)
		} else if e == nil {
			_, _ = s.db.ExecContext(ctx, `UPDATE backup_inventory SET backup_id=?, updated_at=? WHERE volume=?`, newID, newAt, rec.Target)
		}
	}
	return nil
}

func fileSizeSHA(path string) (int64, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
