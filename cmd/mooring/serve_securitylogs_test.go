package main

import (
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/edgeerr"
	"github.com/daboss2003/mooring/internal/edgemetrics"
	"github.com/daboss2003/mooring/internal/servicelog"
	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/query"
	"github.com/daboss2003/mooring/internal/store"
)

func serveSecLogsConfig(t *testing.T) *config.Config {
	t.Helper()
	off := false
	cfg := &config.Config{DataDir: t.TempDir(), EncryptionKey: base64.StdEncoding.EncodeToString(make([]byte, 32))}
	cfg.SecurityLogs.HostLogs.Enabled = &off // never read this machine's auth logs in a test
	return cfg
}

func serveQuietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// waitFor searches until q finds want events or the deadline passes (the pipeline flushes every 2 s).
func waitSecLogs(t *testing.T, s *securityLogs, q string, want int) []siem.Event {
	t.Helper()
	pq, err := query.Parse(q)
	if err != nil {
		t.Fatal(err)
	}
	src := s.webSource()
	deadline := time.Now().Add(15 * time.Second)
	for {
		res, err := src.Search(context.Background(), pq, 100)
		if err == nil && len(res.Events) >= want {
			return res.Events
		}
		if time.Now().After(deadline) {
			t.Fatalf("search %q: %d events (err %v), want %d", q, len(res.Events), err, want)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// The serve wiring end to end: an app line, an edge line and an audit event reach the store,
// redacted, and are searchable; the web source maps a clear personal-data value to its hash.
func TestSecurityLogsWiringEndToEnd(t *testing.T) {
	cfg := serveSecLogsConfig(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := openSecurityLogs(ctx, cfg, nil, serveQuietLog())
	if !s.running() {
		t.Fatalf("security logs didn't start: %q", s.failed)
	}
	defer s.close()

	s.appLine(servicelog.Line{At: time.Now().Unix(), App: "shop", Svc: "api", Copy: "abc123",
		Text: `{"level":40,"event":"auth.login","outcome":"failure","reason":"bad_password","actor_id":"u_9","account":"Alice@Example.com","ip":"203.0.113.7","password":"hunter2"}`})
	s.appLine(servicelog.Line{At: time.Now().Unix(), App: "shop", Svc: "api", Copy: "abc123",
		Text: `{"level":40,"event":"auth.lockout","outcome":"failure","account":"Bob@Example.com","ip":"203.0.113.8"}`})
	s.edgeLine([]byte(`{"level":"info","ts":` + strings.TrimSuffix(strings.TrimSuffix(time.Now().Format("1136239445.000"), "0"), ".") +
		`,"logger":"http.log.access.mooring_access","msg":"handled request","request":{"remote_ip":"10.0.0.2","client_ip":"198.51.100.4","method":"GET","host":"shop.example.com","uri":"/login?token=abc","headers":{"User-Agent":["curl/8"]}},"status":401,"duration":0.01,"size":10}`))
	if sink := s.auditSink(); sink != nil {
		sink(time.Now(), audit.Event{Actor: "owner", IP: "203.0.113.9", Action: "login", Outcome: audit.Deny, Level: audit.Security, Detail: "invalid password"})
	} else {
		t.Fatal("no audit sink while running")
	}

	app := waitSecLogs(t, s, "kind:auth.login", 1)[0]
	if app.Src != siem.SrcApp || app.App != "shop" || app.IP != "203.0.113.7" || app.Out != siem.OutFailure {
		t.Errorf("app event = %+v", app)
	}
	if v, _ := app.F["password"].(string); v != "[redacted]" {
		t.Errorf("password stored as %q", v)
	}
	acct, _ := app.F["account"].(string)
	if !strings.HasPrefix(acct, "h:") {
		t.Errorf("account stored as %q, want a hash", acct)
	}
	if got := s.webSource().SearchValue("account", "alice@example.com"); got != acct {
		t.Errorf("SearchValue(account) = %q, stored %q", got, acct)
	}
	if app.Actor != "u_9" {
		t.Errorf("actor = %q, want actor_id", app.Actor)
	}
	// Without actor_id the account is the actor, stored hashed and found by its clear value.
	lock := waitSecLogs(t, s, "kind:auth.lockout", 1)[0]
	if want := s.webSource().SearchValue("actor", "bob@example.com"); !strings.HasPrefix(lock.Actor, "h:") || lock.Actor != want {
		t.Errorf("lockout actor = %q, SearchValue(actor) = %q", lock.Actor, want)
	}
	edge := waitSecLogs(t, s, "src:edge", 1)[0]
	if edge.IP != "198.51.100.4" || edge.Kind != siem.KindHTTPRequest {
		t.Errorf("edge event = %+v (want the client_ip, not the proxy)", edge)
	}
	if q, _ := edge.F["query"].(string); strings.Contains(q, "abc") {
		t.Errorf("edge query kept the token: %q", q)
	}
	moor := waitSecLogs(t, s, "kind:mooring.login", 1)[0]
	if moor.Src != siem.SrcMooring || moor.Out != siem.OutFailure || moor.IP != "203.0.113.9" {
		t.Errorf("audit event = %+v", moor)
	}
	st := s.webSource().Status()
	if !st.Enabled || st.ArchiveOn || st.QueueCap == 0 {
		t.Errorf("status = %+v", st)
	}
	// The page refuses searches on secret fields: the adapter answers from the redactor.
	if src := s.webSource(); !src.SecretField("password") || src.SecretField("org_id") {
		t.Errorf("SecretField(password)=%v SecretField(org_id)=%v", src.SecretField("password"), src.SecretField("org_id"))
	}
}

// On but unable to start (a bad key): Mooring runs on, the page source reports why, nothing panics.
func TestSecurityLogsFailedStartIsReported(t *testing.T) {
	cfg := serveSecLogsConfig(t)
	cfg.EncryptionKey = base64.StdEncoding.EncodeToString(make([]byte, 8)) // too short for DeriveKey
	s := openSecurityLogs(context.Background(), cfg, nil, serveQuietLog())
	if s == nil || s.running() || s.failed == "" {
		t.Fatalf("want a failed (non-nil, not running) value, got %+v", s)
	}
	src := s.webSource()
	if src == nil {
		t.Fatal("the page must show the failure, not \"off\"")
	}
	st := src.Status()
	if !st.Enabled || len(st.Sources) != 1 || st.Sources[0].OK || !strings.Contains(st.Sources[0].Err, "not started") {
		t.Errorf("status = %+v", st)
	}
	if _, err := src.Search(context.Background(), query.Query{}, 10); err == nil {
		t.Error("search must fail while not running")
	}
	s.appLine(servicelog.Line{Text: "x"})
	s.edgeLine([]byte("x"))
	if s.auditSink() != nil {
		t.Error("no audit sink while not running")
	}
	s.close()
}

// Off: nil everywhere, every method safe.
func TestSecurityLogsOff(t *testing.T) {
	cfg := serveSecLogsConfig(t)
	off := false
	cfg.SecurityLogs.Enabled = &off
	s := openSecurityLogs(context.Background(), cfg, nil, serveQuietLog())
	if s != nil {
		t.Fatalf("off must be nil, got %+v", s)
	}
	if s.webSource() != nil || s.auditSink() != nil || s.running() {
		t.Error("off must expose nothing")
	}
	s.appLine(servicelog.Line{})
	s.edgeLine(nil)
	s.followCLIAudit(nil, serveQuietLog())
	s.close()
	if _, err := os.Stat(filepath.Join(cfg.DataDir, "security-logs")); !os.IsNotExist(err) {
		t.Errorf("off must create nothing: %v", err)
	}
}

// CLI-written audit rows (actor cli:…) are copied from the main database from the saved position;
// rows written by serve itself (they reach the sink directly) are not copied twice.
func TestFollowCLIAuditCopiesOnlyCLIRows(t *testing.T) {
	cfg := serveSecLogsConfig(t)
	db, err := store.Open(filepath.Join(t.TempDir(), "mooring.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ins := func(actor, action string) {
		if _, err := db.Exec(`INSERT INTO events(ts, actor, ip, action, target, outcome, level, detail) VALUES(?, ?, 'local', ?, '', 'ok', 'security', '')`,
			time.Now().Unix(), actor, action); err != nil {
			t.Fatal(err)
		}
	}
	ins("cli:root", "api_token_mint")
	ins("owner", "env_set_secret")
	ins("cli:alice", "secret_import")
	// A web login attempt whose username starts with "cli:" (not ip local): it reached the sink already.
	if _, err := db.Exec(`INSERT INTO events(ts, actor, ip, action, target, outcome, level, detail) VALUES(?, 'CLI:bob', '203.0.113.5', 'login', '', 'deny', 'security', '')`, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := openSecurityLogs(ctx, cfg, nil, serveQuietLog())
	if !s.running() {
		t.Fatalf("not running: %q", s.failed)
	}
	defer s.close()
	// A saved position of 0: everything after it is examined (the first run without one starts at
	// the newest row instead).
	if err := writeSeqFile(filepath.Join(s.dir, "cli-audit.seq"), 0); err != nil {
		t.Fatal(err)
	}
	s.followCLIAudit(db, serveQuietLog())
	waitSecLogs(t, s, "src:mooring", 2)
	evs := waitSecLogs(t, s, "src:mooring", 2)
	got := map[string]bool{}
	for _, e := range evs {
		got[e.Kind] = true
	}
	if !got["mooring.api_token_mint"] || !got["mooring.secret_import"] || got["mooring.env_set_secret"] || len(evs) != 2 {
		t.Errorf("copied %v (%d events), want exactly the two cli: rows", got, len(evs))
	}
	if pos, ok := readSeqFile(filepath.Join(s.dir, "cli-audit.seq")); !ok || pos != 4 {
		t.Errorf("saved position = %d (%v), want 4", pos, ok)
	}
}

func TestSecurityLogBox(t *testing.T) {
	b := securityLogBox()
	if !siem.SafeName(b) || len(b) > 64 || strings.Contains(b, ".") {
		t.Errorf("box %q", b)
	}
}

// The access log can be on for security logs alone: with route_error_log_enabled false the route
// error log records nothing, while security logs still get every line.
func TestEdgeAccessLineHonoursRouteErrorLogOff(t *testing.T) {
	line := []byte(`{"level":"error","ts":1795430081.1,"logger":"http.log.access.mooring_access","msg":"handled request","request":{"remote_ip":"198.51.100.4","method":"GET","host":"shop.example.com","uri":"/x"},"status":502,"duration":0.01}`)
	for _, on := range []bool{false, true} {
		idx := edgemetrics.NewHostIndex()
		idx.Set([]edgemetrics.Route{{Host: "shop.example.com", Key: edgemetrics.Key{App: "shop", Service: "web"}}})
		errStore := edgeerr.New(filepath.Join(t.TempDir(), "edge-errors.jsonl"))
		var sec int
		h := edgeAccessLine(func([]byte) { sec++ }, edgemetrics.NewCollector(edgemetrics.New(30*time.Second), idx),
			edgeerr.NewCollector(errStore, idx, nil), on)
		h(line)
		got := len(errStore.Errors("shop", "shop.example.com", "", "", 10))
		if sec != 1 {
			t.Errorf("route errors %v: security logs got %d lines, want 1", on, sec)
		}
		if want := map[bool]int{false: 0, true: 1}[on]; got != want {
			t.Errorf("route errors %v: %d route-error entries, want %d", on, got, want)
		}
	}
}

// A web login attempt whose username starts with "cli:" reached security logs through the sink
// already: the CLI poll must not copy it again (only rows with ip "local" are the CLI's). A saved
// position past the newest row (a restored database) restarts from the newest row.
func TestFollowCLIAuditSkipsWebRowsAndRecoversFromARestore(t *testing.T) {
	cfg := serveSecLogsConfig(t)
	db, err := store.Open(filepath.Join(t.TempDir(), "mooring.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ins := func(actor, ip, action string) {
		if _, err := db.Exec(`INSERT INTO events(ts, actor, ip, action, target, outcome, level, detail) VALUES(?, ?, ?, ?, '', 'deny', 'security', '')`,
			time.Now().Unix(), actor, ip, action); err != nil {
			t.Fatal(err)
		}
	}
	ins("CLI:attacker", "203.0.113.5", "login") // a web login attempt
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := openSecurityLogs(ctx, cfg, nil, serveQuietLog())
	if !s.running() {
		t.Fatalf("not running: %q", s.failed)
	}
	defer s.close()
	// A position far past the newest row, as after restoring an older database.
	if err := writeSeqFile(filepath.Join(s.dir, "cli-audit.seq"), 1000); err != nil {
		t.Fatal(err)
	}
	s.followCLIAudit(db, serveQuietLog())
	deadline := time.Now().Add(10 * time.Second)
	for {
		if pos, ok := readSeqFile(filepath.Join(s.dir, "cli-audit.seq")); ok && pos == 1 {
			break
		}
		if time.Now().After(deadline) {
			pos, _ := readSeqFile(filepath.Join(s.dir, "cli-audit.seq"))
			t.Fatalf("position after a restore = %d, want the newest row (1)", pos)
		}
		time.Sleep(100 * time.Millisecond)
	}
	pq, _ := query.Parse("src:mooring")
	time.Sleep(3 * time.Second) // a pipeline flush
	if res, _ := s.webSource().Search(context.Background(), pq, 10); len(res.Events) != 0 {
		t.Errorf("copied %d rows; the web login must not be copied", len(res.Events))
	}
}

// With both captures off the cursor file is removed; with either on it is kept.
func TestRemoveStaleLogCursors(t *testing.T) {
	dir := t.TempDir()
	f := logCursorsFile(dir)
	if err := os.WriteFile(f, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	removeStaleLogCursors(dir, true)
	if _, err := os.Stat(f); err != nil {
		t.Fatalf("removed while capturing: %v", err)
	}
	removeStaleLogCursors(dir, false)
	if _, err := os.Stat(f); !os.IsNotExist(err) {
		t.Fatalf("kept with both captures off: %v", err)
	}
	removeStaleLogCursors(dir, false) // already gone: no panic
}
