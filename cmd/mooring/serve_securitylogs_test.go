package main

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/alertstore"
	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/docker"
	"github.com/daboss2003/mooring/internal/edge"
	"github.com/daboss2003/mooring/internal/edgeerr"
	"github.com/daboss2003/mooring/internal/edgemetrics"
	"github.com/daboss2003/mooring/internal/gitstore"
	"github.com/daboss2003/mooring/internal/provstore"
	"github.com/daboss2003/mooring/internal/secret"
	"github.com/daboss2003/mooring/internal/servicelog"
	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/query"
	"github.com/daboss2003/mooring/internal/siem/redact"
	"github.com/daboss2003/mooring/internal/store"
)

func serveSecLogsConfig(t *testing.T) *config.Config {
	t.Helper()
	off := false
	cfg := &config.Config{DataDir: t.TempDir(), EncryptionKey: base64.StdEncoding.EncodeToString(make([]byte, 32))}
	cfg.SecurityLogs.HostLogs.Enabled = &off // never read this machine's auth logs in a test
	// Nor download the enrichment feeds from the internet.
	cfg.SecurityLogs.Feeds.GeoIP, cfg.SecurityLogs.Feeds.Spamhaus, cfg.SecurityLogs.Feeds.Tor = &off, &off, &off
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
	s := openSecurityLogs(ctx, cfg, nil, nil, serveQuietLog())
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
	s := openSecurityLogs(context.Background(), cfg, nil, nil, serveQuietLog())
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
	s := openSecurityLogs(context.Background(), cfg, nil, nil, serveQuietLog())
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
	s := openSecurityLogs(ctx, cfg, nil, nil, serveQuietLog())
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
	s := openSecurityLogs(ctx, cfg, nil, nil, serveQuietLog())
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

// Detection wired end to end: audit events from the web server's sink reach the engine through the
// pipeline's subscriber, a pack rule fires, the detection is listed through the dashboard's
// service, and its siem.detection event comes back through Emit into the store (searchable).
// With detection off, the dashboard and the ops alerts see "off" (untyped nils).
func TestDetectionWiringEndToEnd(t *testing.T) {
	cfg := serveSecLogsConfig(t)
	db, err := store.Open(filepath.Join(t.TempDir(), "mooring.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := openSecurityLogs(ctx, cfg, nil, db, serveQuietLog())
	if !s.running() || s.detections() == nil || s.detectionReporter() == nil || s.feedStatus() == nil {
		t.Fatalf("running=%v detections=%v reporter=%v feeds=%v (failed %q)", s.running(), s.detections() != nil, s.detectionReporter() != nil, s.feedStatus() != nil, s.failed)
	}
	defer s.close()
	// The pack rule's rule set comes from the main DB (empty: the pack's defaults).
	sink := s.auditSink()
	for i := 0; i < 12; i++ {
		sink(time.Now(), audit.Event{Actor: "owner", IP: "203.0.113.50", Action: "login", Outcome: audit.Deny, Level: audit.Security, Detail: "invalid password"})
	}
	deadline := time.Now().Add(20 * time.Second)
	var got []siem.Detection
	for {
		got, err = s.detections().Detections(context.Background(), siem.DetectionFilter{RuleID: "mooring.login_bruteforce"})
		if err == nil && len(got) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no mooring.login_bruteforce detection (err %v)", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	if got[0].Key != "203.0.113.50" || got[0].Severity != siem.SevHigh {
		t.Errorf("detection = %+v", got[0])
	}
	ev := waitSecLogs(t, s, "kind:siem.detection", 1)[0]
	if ev.Src != siem.SrcSIEM || ev.IP != "203.0.113.50" {
		t.Errorf("siem.detection event = %+v", ev)
	}

	off := false
	cfg2 := serveSecLogsConfig(t)
	cfg2.SecurityLogs.Detection.Enabled = &off
	s2 := openSecurityLogs(ctx, cfg2, nil, db, serveQuietLog())
	defer s2.close()
	if !s2.running() || s2.detections() != nil || s2.detectionReporter() != nil {
		t.Errorf("detection off: running=%v detections=%v reporter=%v", s2.running(), s2.detections(), s2.detectionReporter())
	}
}

// Enrichment feeds that can't start (here: their directory is blocked by a file) don't stop security
// logs, but they raise a security_feeds_not_running alert; the next start that works resolves it.
func TestFeedsStartFailureAlerts(t *testing.T) {
	cfg := serveSecLogsConfig(t)
	db, err := store.Open(filepath.Join(t.TempDir(), "mooring.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	cipher, err := secret.NewCipher(make([]byte, 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	alerts := alertstore.New(db, cipher)
	feedsDir := filepath.Join(cfg.DataDir, "security-logs", "feeds")
	if err := os.MkdirAll(filepath.Dir(feedsDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(feedsDir, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := openSecurityLogs(context.Background(), cfg, alerts, db, serveQuietLog())
	if !s.running() || s.feedStatus() != nil {
		t.Fatalf("running=%v feeds=%v (failed %q): security logs must run without the feeds", s.running(), s.feedStatus() != nil, s.failed)
	}
	s.close()
	open, err := alerts.OpenInfraAlerts(context.Background(), kindFeedsNotRunning)
	if err != nil || len(open) != 1 {
		t.Fatalf("open feeds alerts = %v, %v; want one", open, err)
	}

	if err := os.Remove(feedsDir); err != nil {
		t.Fatal(err)
	}
	s2 := openSecurityLogs(context.Background(), cfg, alerts, db, serveQuietLog())
	defer s2.close()
	if s2.feedStatus() == nil {
		t.Fatal("feeds didn't start once the directory was free")
	}
	if open, err := alerts.OpenInfraAlerts(context.Background(), kindFeedsNotRunning); err != nil || len(open) != 0 {
		t.Fatalf("after a good start: open = %v, %v; want resolved", open, err)
	}
}

// serveAlerts is a main database with an alert store on it.
func serveAlerts(t *testing.T) (*store.DB, *alertstore.Store) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "mooring.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	cipher, err := secret.NewCipher(make([]byte, 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	return db, alertstore.New(db, cipher)
}

func openInfra(t *testing.T, alerts *alertstore.Store, kind string) int {
	t.Helper()
	open, err := alerts.OpenInfraAlerts(context.Background(), kind)
	if err != nil {
		t.Fatal(err)
	}
	return len(open)
}

// blockDetection makes detection unable to start: its database path is a directory.
func blockDetection(t *testing.T, cfg *config.Config) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(cfg.DataDir, "security-logs", "detect.db"), 0o700); err != nil {
		t.Fatal(err)
	}
}

// blockFeeds makes the enrichment feeds unable to start: their directory is a file.
func blockFeeds(t *testing.T, cfg *config.Config) {
	t.Helper()
	feedsDir := filepath.Join(cfg.DataDir, "security-logs", "feeds")
	if err := os.MkdirAll(filepath.Dir(feedsDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(feedsDir, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Events still in the pipeline when close begins are evaluated: close drains the source lanes into
// the engine while it still runs, then stops it, and the engine's last detections are stored through
// the pipeline, which stops last. A restart on the same data dir finds the detection and its
// siem.detection event.
func TestDetectionEvaluatesEventsQueuedAtClose(t *testing.T) {
	cfg := serveSecLogsConfig(t)
	db, err := store.Open(filepath.Join(t.TempDir(), "mooring.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := openSecurityLogs(context.Background(), cfg, nil, db, serveQuietLog())
	if !s.running() || s.detections() == nil {
		t.Fatalf("running=%v detections=%v (failed %q)", s.running(), s.detections() != nil, s.failed)
	}
	sink := s.auditSink()
	for i := 0; i < 12; i++ {
		sink(time.Now(), audit.Event{Actor: "owner", IP: "203.0.113.60", Action: "login", Outcome: audit.Deny, Level: audit.Security, Detail: "invalid password"})
	}
	// At once: the pipeline hands a batch to its subscribers only after a second, so all twelve are
	// still in it.
	s.close()

	s2 := openSecurityLogs(context.Background(), cfg, nil, db, serveQuietLog())
	if !s2.running() || s2.detections() == nil {
		t.Fatalf("restart: running=%v detections=%v (failed %q)", s2.running(), s2.detections() != nil, s2.failed)
	}
	defer s2.close()
	got, err := s2.detections().Detections(context.Background(), siem.DetectionFilter{RuleID: "mooring.login_bruteforce"})
	if err != nil || len(got) != 1 || got[0].Key != "203.0.113.60" {
		t.Fatalf("detections after close = %+v (err %v): the events queued at close weren't evaluated", got, err)
	}
	ev := waitSecLogs(t, s2, "kind:siem.detection", 1)[0]
	if ev.Src != siem.SrcSIEM || ev.IP != "203.0.113.60" {
		t.Errorf("siem.detection event = %+v", ev)
	}
}

// A security_detection_not_running alert is resolved when security logs start with detection
// turned off, not only by a start that works.
func TestDetectionOffResolvesNotRunningAlert(t *testing.T) {
	cfg := serveSecLogsConfig(t)
	db, alerts := serveAlerts(t)
	blockDetection(t, cfg)
	s := openSecurityLogs(context.Background(), cfg, alerts, db, serveQuietLog())
	if !s.running() || s.detections() != nil {
		t.Fatalf("running=%v detections=%v: security logs must run without detection", s.running(), s.detections() != nil)
	}
	s.close()
	if n := openInfra(t, alerts, kindDetectionNotRunning); n != 1 {
		t.Fatalf("%d open detection alerts after a failed start, want 1", n)
	}

	off := false
	cfg.SecurityLogs.Detection.Enabled = &off
	s2 := openSecurityLogs(context.Background(), cfg, alerts, db, serveQuietLog())
	defer s2.close()
	if !s2.running() {
		t.Fatalf("not running: %q", s2.failed)
	}
	if n := openInfra(t, alerts, kindDetectionNotRunning); n != 0 {
		t.Errorf("%d open detection alerts with detection turned off, want it resolved", n)
	}
}

// Security logs switched off resolve every "didn't start" alert (security logs, detection, feeds):
// nothing that was failing runs any more.
func TestSecurityLogsOffResolvesNotRunningAlerts(t *testing.T) {
	cfg := serveSecLogsConfig(t)
	db, alerts := serveAlerts(t)
	blockDetection(t, cfg)
	blockFeeds(t, cfg)
	s := openSecurityLogs(context.Background(), cfg, alerts, db, serveQuietLog())
	if !s.running() || s.detections() != nil || s.feedStatus() != nil {
		t.Fatalf("running=%v detections=%v feeds=%v", s.running(), s.detections() != nil, s.feedStatus() != nil)
	}
	s.close()
	key := cfg.EncryptionKey
	cfg.EncryptionKey = base64.StdEncoding.EncodeToString(make([]byte, 8)) // security logs can't start
	if s2 := openSecurityLogs(context.Background(), cfg, alerts, db, serveQuietLog()); s2.running() {
		t.Fatal("started with a bad key")
	}
	cfg.EncryptionKey = key
	kinds := []string{kindSecLogsNotRunning, kindDetectionNotRunning, kindFeedsNotRunning}
	for _, k := range kinds {
		if n := openInfra(t, alerts, k); n != 1 {
			t.Fatalf("%s: %d open alerts after the failed starts, want 1", k, n)
		}
	}

	off := false
	cfg.SecurityLogs.Enabled = &off
	if s3 := openSecurityLogs(context.Background(), cfg, alerts, db, serveQuietLog()); s3 != nil {
		t.Fatalf("off must be nil, got %+v", s3)
	}
	for _, k := range kinds {
		if n := openInfra(t, alerts, k); n != 0 {
			t.Errorf("%s: %d open alerts with security logs off, want it resolved", k, n)
		}
	}
}

// detectMapValue maps a clear value in a rule query the way the event was stored: the FULL f.<key>
// is classified (a personal-data parent like "phone" makes phone.number hashed), an actor that looks
// like an email is hashed, and a prefix pattern or a non-personal field is left as written.
func TestDetectMapValueFullKey(t *testing.T) {
	red, err := redact.New(make([]byte, 32), redact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	mv := detectMapValue(red)
	if got := mv("f.phone.number", "8012345678"); !strings.HasPrefix(got, "h:") || got != red.SearchValue("phone.number", "8012345678") {
		t.Errorf("f.phone.number → %q, want the stored hash", got)
	}
	if got := mv("actor", "bob@example.com"); !strings.HasPrefix(got, "h:") {
		t.Errorf("actor email → %q, want a hash", got)
	}
	for field, v := range map[string]string{"f.email": "bob*", "f.org_id": "acme", "kind": "ssh.login"} {
		if got := mv(field, v); got != v {
			t.Errorf("%s:%s → %q, want it unchanged", field, v, got)
		}
	}
}

// The traffic baseline learns only hosts an edge route serves: exact names (any case), and for a
// catch-all `*.<apex>` route every single label under the apex; disabled routes don't count, and
// before the first refresh nothing is known.
func TestKnownHosts(t *testing.T) {
	var kh knownHosts
	if _, known, ready := kh.lookup("shop.example.com"); known || ready {
		t.Fatalf("before any refresh: known=%v ready=%v, want false, false", known, ready)
	}
	kh.refresh(func() ([]edge.Route, error) {
		return []edge.Route{
			{Hostname: "Shop.Example.com", Enabled: true},
			{Hostname: "*.tenants.example.com", Enabled: true, CatchAll: true},
			{Hostname: "old.example.com", Enabled: false},
		}, nil
	})
	for host, want := range map[string]bool{
		"shop.example.com": true, "acme.tenants.example.com": true, "a.b.tenants.example.com": false,
		"tenants.example.com": false, "old.example.com": false, "evil.example.net": false,
	} {
		if _, got, _ := kh.lookup(host); got != want {
			t.Errorf("lookup(%q) known = %v, want %v", host, got, want)
		}
	}
	// Every label a catch-all serves is counted under one key; an exact host under itself.
	for host, want := range map[string]string{"acme.tenants.example.com": "*.tenants.example.com", "zz.tenants.example.com": "*.tenants.example.com", "*.tenants.example.com": "*.tenants.example.com", "shop.example.com": "shop.example.com"} {
		if key, known, ready := kh.lookup(host); key != want || !known || !ready {
			t.Errorf("lookup(%q) = %q, %v, %v; want %q, true, true", host, key, known, ready, want)
		}
	}
	if _, known, ready := kh.lookup("evil.example.net"); known || !ready {
		t.Errorf("unknown host after a refresh: known=%v ready=%v", known, ready)
	}
	// A failed refresh keeps what was known.
	kh.refresh(func() ([]edge.Route, error) { return nil, errors.New("db busy") })
	if _, known, _ := kh.lookup("shop.example.com"); !known {
		t.Error("a failed refresh dropped the known hosts")
	}
}

// The apps a start-up cleanup keeps are the ones the app delete page counts: the connected repos,
// the stored definitions, the provisioned apps and every Compose project with a container (running
// or stopped) together; a read error of any means no list at all (a cleanup on a partial list
// would delete live apps' mutes and baselines).
func TestExistingApps(t *testing.T) {
	src := appSources{
		repos: func() ([]gitstore.Config, error) {
			return []gitstore.Config{{Project: "shop"}, {Project: "blog"}}, nil
		},
		defs: func(context.Context) (map[string]*definition.Definition, map[string]error, error) {
			return map[string]*definition.Definition{"shop": nil, "api": nil}, map[string]error{"broken": errors.New("bad hmac")}, nil
		},
		// A wizard-provisioned app has a registry row and no repo.
		provisioned: func() ([]provstore.App, error) { return []provstore.App{{Slug: "wizard"}, {Slug: "shop"}}, nil },
		// An app with containers and no rows; a stopped container counts; a non-Compose one doesn't.
		containers: func(context.Context) ([]docker.Container, error) {
			return []docker.Container{
				{Labels: map[string]string{docker.LabelProject: "running-only"}, State: "running"},
				{Labels: map[string]string{docker.LabelProject: "stopped-only"}, State: "exited"},
				{Labels: map[string]string{}},
			}, nil
		},
	}
	got, ok := existingApps(context.Background(), src)
	if want := "api,blog,broken,running-only,shop,stopped-only,wizard"; !ok || strings.Join(got, ",") != want {
		t.Fatalf("existingApps = %q, %v; want %s (an unverifiable definition, a provisioned app without a repo and an app with only containers still exist)", got, ok, want)
	}
	busy := errors.New("db busy")
	for name, broken := range map[string]func(*appSources){
		"repo": func(s *appSources) { s.repos = func() ([]gitstore.Config, error) { return nil, busy } },
		"definition": func(s *appSources) {
			s.defs = func(context.Context) (map[string]*definition.Definition, map[string]error, error) {
				return nil, nil, busy
			}
		},
		"provision registry": func(s *appSources) { s.provisioned = func() ([]provstore.App, error) { return nil, busy } },
		"container": func(s *appSources) {
			s.containers = func(context.Context) ([]docker.Container, error) { return nil, busy }
		},
	} {
		s := src
		broken(&s)
		if _, ok := existingApps(context.Background(), s); ok {
			t.Errorf("a %s read error still gave a list", name)
		}
	}
}

// The start-up cleanup runs in the background: it waits (retrying) until the app list can be read
// — the socket-proxy may still be starting — then prunes once; if the list never reads it gives up
// and removes nothing. Either way it ends with the security logs.
func TestPruneDeletedAppsAtStart(t *testing.T) {
	oldRetry, oldWait := pruneAppsRetry, pruneAppsWait
	pruneAppsRetry, pruneAppsWait = 5*time.Millisecond, 2*time.Second
	defer func() { pruneAppsRetry, pruneAppsWait = oldRetry, oldWait }()

	cfg := serveSecLogsConfig(t)
	db, err := store.Open(filepath.Join(t.TempDir(), "mooring.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	until := time.Now().Add(24 * time.Hour).Unix()
	for _, scope := range []string{"app:shop", "app:gone"} {
		if _, err := db.Exec(`INSERT INTO security_mutes(rule_id, kind, scope, key, until_at, created_at) VALUES('app.auth_bruteforce', 'account', ?, 'alice', ?, ?)`,
			scope, until, time.Now().Unix()); err != nil {
			t.Fatal(err)
		}
	}
	scopes := func() string {
		var n []string
		rows, err := db.Query(`SELECT scope FROM security_mutes ORDER BY scope`)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var sc string
			_ = rows.Scan(&sc)
			n = append(n, sc)
		}
		rows.Close()
		return strings.Join(n, ",")
	}

	s := openSecurityLogs(context.Background(), cfg, nil, db, serveQuietLog())
	if s.det == nil {
		t.Fatalf("detection didn't start: %q", s.failed)
	}
	var calls atomic.Int32
	s.pruneDeletedAppsAtStart(func(context.Context) ([]string, bool) {
		if calls.Add(1) < 3 {
			return nil, false // the socket-proxy isn't up yet
		}
		return []string{"shop"}, true
	})
	deadline := time.Now().Add(2 * time.Second)
	for scopes() != "app:shop" && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := scopes(); got != "app:shop" {
		t.Fatalf("after the list read on the 3rd try, mutes left = %q, want app:shop", got)
	}
	time.Sleep(30 * time.Millisecond)
	if n := calls.Load(); n != 3 {
		t.Errorf("list read %d times, want 3 (once it reads, the cleanup is done)", n)
	}
	s.close()

	// A list that never reads: nothing removed, the worker gives up, close doesn't hang.
	if _, err := db.Exec(`INSERT INTO security_mutes(rule_id, kind, scope, key, until_at, created_at) VALUES('app.auth_bruteforce', 'account', 'app:gone', 'alice', ?, ?)`,
		until, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	pruneAppsWait = 50 * time.Millisecond
	s2 := openSecurityLogs(context.Background(), cfg, nil, db, serveQuietLog())
	var tries atomic.Int32
	s2.pruneDeletedAppsAtStart(func(context.Context) ([]string, bool) { tries.Add(1); return nil, false })
	time.Sleep(200 * time.Millisecond)
	if got := scopes(); got != "app:gone,app:shop" {
		t.Errorf("an unreadable list still removed mutes: left %q", got)
	}
	n := tries.Load()
	time.Sleep(50 * time.Millisecond)
	if tries.Load() != n || n < 2 {
		t.Errorf("tries = %d then %d: want at least 2, and none after giving up", n, tries.Load())
	}
	s2.close()

	// Security logs off: nothing starts, no panic.
	var off *securityLogs
	off.pruneDeletedAppsAtStart(func(context.Context) ([]string, bool) { t.Error("listed with security logs off"); return nil, false })
}

// At start the saved mutes (and sign-in baselines) of apps that no longer exist are removed: an app
// deleted while detection was off left them behind. Existing apps' and other scopes' are kept.
func TestPruneDeletedApps(t *testing.T) {
	cfg := serveSecLogsConfig(t)
	db, err := store.Open(filepath.Join(t.TempDir(), "mooring.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	until := time.Now().Add(24 * time.Hour).Unix()
	for _, scope := range []string{"app:shop", "app:gone", "mooring"} {
		if _, err := db.Exec(`INSERT INTO security_mutes(rule_id, kind, scope, key, until_at, created_at) VALUES('app.auth_bruteforce', 'account', ?, 'alice', ?, ?)`,
			scope, until, time.Now().Unix()); err != nil {
			t.Fatal(err)
		}
	}
	s := openSecurityLogs(context.Background(), cfg, nil, db, serveQuietLog())
	defer s.close()
	if s.det == nil {
		t.Fatalf("detection didn't start: %q", s.failed)
	}
	s.pruneDeletedApps(context.Background(), []string{"shop"})
	rows, err := db.Query(`SELECT scope FROM security_mutes ORDER BY scope`)
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for rows.Next() {
		var sc string
		_ = rows.Scan(&sc)
		left = append(left, sc)
	}
	rows.Close()
	if strings.Join(left, ",") != "app:shop,mooring" {
		t.Fatalf("mutes left = %q, want app:shop,mooring", left)
	}
	// Security logs off (s nil) or detection off: nothing to do, no panic.
	var off *securityLogs
	off.pruneDeletedApps(context.Background(), nil)
}
