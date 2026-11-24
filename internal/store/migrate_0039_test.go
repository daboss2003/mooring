package store

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// openAtVersion builds a database migrated only up to version v, as an older release left it.
func openAtVersion(t *testing.T, path string, v int) {
	t.Helper()
	sqldb, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer sqldb.Close()
	if _, err := sqldb.Exec(`CREATE TABLE schema_meta (version INTEGER PRIMARY KEY, name TEXT NOT NULL,
		applied_at INTEGER NOT NULL DEFAULT (unixepoch()))`); err != nil {
		t.Fatal(err)
	}
	ms, err := loadMigrations()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		if m.version > v {
			break
		}
		if _, err := sqldb.Exec(m.sql); err != nil {
			t.Fatalf("migration %s: %v", m.name, err)
		}
		if _, err := sqldb.Exec(`INSERT INTO schema_meta(version, name) VALUES(?, ?)`, m.version, m.name); err != nil {
			t.Fatal(err)
		}
	}
}

func hasEventsUserAgent(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('events') WHERE name = 'user_agent'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

func TestMigration0039FreshDB(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "fresh.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if !hasEventsUserAgent(t, db.DB) {
		t.Fatal("events.user_agent missing on a fresh database")
	}
	// A row written without the column gets ''.
	if _, err := db.Exec(`INSERT INTO events(ts, action) VALUES(1, 'x')`); err != nil {
		t.Fatal(err)
	}
	var ua string
	if err := db.QueryRow(`SELECT user_agent FROM events WHERE action = 'x'`).Scan(&ua); err != nil || ua != "" {
		t.Fatalf("default user_agent = %q, %v", ua, err)
	}
}

// An existing database at version 38 with events in it upgrades: the old rows keep their data
// and read an empty user_agent.
func TestMigration0039ExistingDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	openAtVersion(t, path, 38)

	old, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	if hasEventsUserAgent(t, old) {
		t.Fatal("test setup: a version-38 database must not have user_agent yet")
	}
	if _, err := old.Exec(`INSERT INTO events(ts, actor, ip, action, target, outcome, level, detail)
		VALUES(100, 'operator', '203.0.113.7', 'login', '', 'ok', 'security', '')`); err != nil {
		t.Fatal(err)
	}
	old.Close()

	db, err := Open(path)
	if err != nil {
		t.Fatalf("upgrade from 38: %v", err)
	}
	defer db.Close()
	if !hasEventsUserAgent(t, db.DB) {
		t.Fatal("events.user_agent missing after the upgrade")
	}
	var actor, ip, ua string
	if err := db.QueryRow(`SELECT actor, ip, user_agent FROM events WHERE action = 'login'`).Scan(&actor, &ip, &ua); err != nil {
		t.Fatal(err)
	}
	if actor != "operator" || ip != "203.0.113.7" || ua != "" {
		t.Errorf("old row after upgrade: actor=%q ip=%q ua=%q", actor, ip, ua)
	}
	var v int
	if err := db.QueryRow(`SELECT MAX(version) FROM schema_meta`).Scan(&v); err != nil || v < 39 {
		t.Errorf("schema version after upgrade = %d, %v", v, err)
	}
}
