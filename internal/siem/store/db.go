package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"strings"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// openDB opens security.db (creating it 0600, refusing symlinks) and runs the pending migrations,
// then opens the read-only pool searches use.
func (s *Store) openDB() error {
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		if fi, err := os.Lstat(s.dbPath + suffix); err == nil && !fi.Mode().IsRegular() {
			return fmt.Errorf("store: %s%s is not a regular file (a symlink is refused)", s.dbPath, suffix)
		}
	}
	// SQLite creates the -wal and -shm files with the database file's mode, so creating the file
	// 0600 here keeps all three private without changing the process umask.
	f, err := os.OpenFile(s.dbPath, os.O_RDWR|os.O_CREATE|oNoFollow, 0o600)
	if err != nil {
		return fmt.Errorf("store: create %s: %w", s.dbPath, err)
	}
	fi, err := f.Stat()
	if err == nil && fi.Mode().Perm() != 0o600 {
		err = f.Chmod(0o600)
	}
	_ = f.Close()
	if err != nil {
		return fmt.Errorf("store: %s: %w", s.dbPath, err)
	}
	// auto_vacuum must be set before the first table exists; modernc applies the pragmas in name
	// order after busy_timeout, so it runs before journal_mode.
	// journal_size_limit cuts the WAL back after a checkpoint, so DiskBytes doesn't keep counting
	// its high-water size.
	db, err := sql.Open("sqlite", "file:"+s.dbPath+"?_pragma=busy_timeout(5000)&_pragma=auto_vacuum(INCREMENTAL)"+
		"&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)"+
		"&_pragma=journal_size_limit("+strconv.Itoa(walSizeLimit)+")")
	if err != nil {
		return fmt.Errorf("store: open %s: %w", s.dbPath, err)
	}
	// One connection: writes are serialized, and the SQLite rule applies (never a statement while
	// rows or a transaction are open).
	db.SetMaxOpenConns(1)
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return fmt.Errorf("store: open %s: %w", s.dbPath, err)
	}
	if err := migrate(db); err != nil {
		_ = db.Close()
		return err
	}
	rdb, err := sql.Open("sqlite", "file:"+s.dbPath+"?_pragma=busy_timeout(5000)&_pragma=query_only(ON)")
	if err != nil {
		_ = db.Close()
		return fmt.Errorf("store: open %s: %w", s.dbPath, err)
	}
	rdb.SetMaxOpenConns(maxSearches)
	s.db, s.rdb = db, rdb
	return nil
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
			return nil, fmt.Errorf("store: bad migration filename %q: %w", e.Name(), err)
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

// migrate applies the embedded migrations, each in its own transaction. They must be numbered
// 1..N without gaps, and a database that knows a higher version than this binary is refused.
func migrate(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (
		version    INTEGER PRIMARY KEY,
		name       TEXT NOT NULL,
		applied_at INTEGER NOT NULL DEFAULT (unixepoch())
	)`); err != nil {
		return fmt.Errorf("store: create schema_version: %w", err)
	}
	var current int
	if err := db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&current); err != nil {
		return fmt.Errorf("store: read schema version: %w", err)
	}
	ms, err := loadMigrations()
	if err != nil {
		return err
	}
	for i, m := range ms {
		if m.version != i+1 {
			return fmt.Errorf("store: migrations not contiguous: expected version %d, got %d (%s)", i+1, m.version, m.name)
		}
	}
	if current > len(ms) {
		return fmt.Errorf("store: security database schema version %d is newer than this binary's %d (downgrade refused)", current, len(ms))
	}
	for _, m := range ms[current:] {
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(m.sql); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store: migration %s: %w", m.name, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_version(version, name) VALUES (?, ?)`, m.version, m.name); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("store: record migration %s: %w", m.name, err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("store: commit migration %s: %w", m.name, err)
		}
	}
	return nil
}

// tx runs fn in a write transaction bounded by dbTimeout. Inside fn use only tx.
func (s *Store) tx(fn func(ctx context.Context, tx *sql.Tx) error) error {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(ctx, tx); err != nil {
		return errors.Join(err, tx.Rollback())
	}
	return tx.Commit()
}

// exec runs one write statement bounded by dbTimeout.
func (s *Store) exec(query string, args ...any) (sql.Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dbTimeout)
	defer cancel()
	return s.db.ExecContext(ctx, query, args...)
}
