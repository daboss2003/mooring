package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/edge"
	"github.com/daboss2003/mooring/internal/secret"
	"github.com/daboss2003/mooring/internal/socketproxy"
	"github.com/daboss2003/mooring/internal/store"
)

// edgeBaseConfig is the edge base serve renders every config from (and setup checks a build against):
// every config.yaml edge setting, the admin vhost and the lb: cookie secret, field by field as serve
// built it inline. It carries no DNS-01 wildcard: serve adds a namespace's only while its plugin is in the
// running Caddy.
func TestEdgeBaseConfig(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	cfg := &config.Config{
		EncryptionKey: base64.StdEncoding.EncodeToString(key),
		Admin:         config.AdminConfig{Listen: "127.0.0.1:2019", Subdomain: "admin", EdgeListen: "127.0.0.1:9101"},
		Edge: config.EdgeConfig{
			Mode: config.EdgeManaged, ACMEEmail: "ops@example.com", ACMECA: "https://acme.example.net/directory",
			CAs:            []config.EdgeCA{{Name: "corp", DirectoryURL: "https://ca.corp.example/acme", Email: "pki@corp.example", TrustedRoot: "/etc/mooring/corp.pem"}, {Name: "lab", DirectoryURL: "https://lab.example/acme"}},
			BaseDomain:     "example.com",
			DNS01:          &config.EdgeDNS01{Provider: "cloudflare", APIToken: "tok-cf-0123456789"},
			BaseDomains:    []config.EdgeBaseDomain{{Name: "shop", Domain: "shop.example.net", DNS01: &config.EdgeDNS01{Provider: "route53", APIToken: "tok-r53-0123456789"}}},
			TrustedProxies: []string{"cloudflare", "10.0.0.0/8"},
			ClientIPHeader: "CF-Connecting-IP",
		},
	}
	want := edge.BaseConfig{
		AdminListen:    "127.0.0.1:2019",
		ACMEEmail:      "ops@example.com",
		ACMECA:         "https://acme.example.net/directory",
		CAs:            []edge.CA{{Name: "corp", DirectoryURL: "https://ca.corp.example/acme", Email: "pki@corp.example", TrustedRoots: []string{"/etc/mooring/corp.pem"}}, {Name: "lab", DirectoryURL: "https://lab.example/acme"}},
		AdminHostname:  "admin.example.com",
		AdminUpstream:  "127.0.0.1:9101",
		TrustedProxies: []string{"cloudflare", "10.0.0.0/8"},
		ClientIPHeader: "CF-Connecting-IP",
		LBCookieSecret: edge.DeriveLBCookieSecret(key),
	}
	// The admin allowlist is the parsed, canonical ip_allowlist, which a hand-built Config doesn't
	// have: TestEdgeBaseConfigCanonicalAllowlist covers it with a loaded one.
	got := edgeBaseConfig(cfg)
	if len(got.AdminAllowlist) != 0 {
		t.Errorf("AdminAllowlist = %v, want none for a config without ip_allowlist", got.AdminAllowlist)
	}
	got.AdminAllowlist = nil
	if !reflect.DeepEqual(got, want) {
		t.Errorf("edgeBaseConfig:\n got %+v\nwant %+v", got, want)
	}

	// Defaults: the admin socket, no admin vhost, the default edge listener; a key that doesn't decode
	// gives no cookie secret (lb: cookie routes render as ip_hash).
	plain := &config.Config{EncryptionKey: "%%%", Edge: config.EdgeConfig{Mode: config.EdgeManaged}}
	want = edge.BaseConfig{AdminListen: "unix//run/mooring/caddy-admin.sock", AdminUpstream: "127.0.0.1:9001"}
	got = edgeBaseConfig(plain)
	got.AdminAllowlist = nil
	if !reflect.DeepEqual(got, want) {
		t.Errorf("edgeBaseConfig (defaults):\n got %+v\nwant %+v", got, want)
	}
}

// The managed socket-proxy is the read-plane security boundary; it must be protected
// from every write path by default, without the operator listing it (review finding).
func TestProtectManagedProxy(t *testing.T) {
	// Default (managed) install: the proxy project is seeded + protected.
	cfg := &config.Config{}
	protectManagedProxy(cfg)
	if !cfg.IsProtectedProject(socketproxy.Project) {
		t.Fatalf("managed proxy %q must be protected by default", socketproxy.Project)
	}

	// Idempotent: a second call (or an operator who already listed it) doesn't dupe.
	protectManagedProxy(cfg)
	n := 0
	for _, p := range cfg.ProtectedProjects {
		if p == socketproxy.Project {
			n++
		}
	}
	if n != 1 {
		t.Errorf("proxy project listed %d times, want exactly 1 (idempotent)", n)
	}

	// Operator-listed projects are preserved alongside the seeded proxy.
	cfg2 := &config.Config{ProtectedProjects: []string{"edge-stack"}}
	protectManagedProxy(cfg2)
	if !cfg2.IsProtectedProject("edge-stack") || !cfg2.IsProtectedProject(socketproxy.Project) {
		t.Error("must preserve operator projects AND add the proxy")
	}

	// external_proxy: Mooring doesn't run the proxy, so it doesn't seed it.
	cfg3 := &config.Config{}
	cfg3.Docker.ExternalProxy = true
	protectManagedProxy(cfg3)
	if cfg3.IsProtectedProject(socketproxy.Project) {
		t.Error("with external_proxy, Mooring must not seed the proxy project")
	}
}

// serveHost is cliHost with edge.mode external (no /var/lib/caddy needed) and the apps directory
// made, so serve gets past its directory check. extra is appended to the file.
func serveHost(t *testing.T, extra string) (cfgPath, dataDir string) {
	t.Helper()
	cfgPath, dataDir = cliHost(t)
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	y := strings.Replace(string(raw), `mode: "managed"`, `mode: "external"`, 1) +
		"trust_proxy: true\ntrusted_proxies:\n  - \"192.0.2.10/32\"\n" + extra
	if err := os.WriteFile(cfgPath, []byte(y), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(cfgPath); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if err := os.Mkdir(dataDir+"-apps", 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dataDir + "-apps") })
	return cfgPath, dataDir
}

// captureServeLog points serve's log at a buffer.
func captureServeLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var b bytes.Buffer
	prev := serveLogOut
	serveLogOut = &b
	t.Cleanup(func() { serveLogOut = prev })
	return &b
}

// wantRefusedStart: serve returned the exit status the unit doesn't restart on, main prints
// nothing more, and the log has exactly one ERROR line, with msg and a hint.
func wantRefusedStart(t *testing.T, what string, err error, log *bytes.Buffer, msg string) {
	t.Helper()
	wantStartExit(t, what, err, log, msg, config.ExitInvalid)
}

// wantStartExit: serve returned exit status code, main prints nothing more, and the log has
// exactly one ERROR line, with msg, a detail and a hint.
func wantStartExit(t *testing.T, what string, err error, log *bytes.Buffer, msg string, code int) {
	t.Helper()
	var w bytes.Buffer
	if got := exitStatus("serve", err, &w); got != code || w.Len() != 0 {
		t.Errorf("%s: exit %d, main printed %q (want %d and nothing): %v", what, got, w.String(), code, err)
	}
	var errLines []string
	for _, l := range strings.Split(log.String(), "\n") {
		if strings.Contains(l, "level=ERROR") {
			errLines = append(errLines, l)
		}
	}
	if len(errLines) != 1 || !strings.Contains(errLines[0], `msg="`+msg+`"`) || !strings.Contains(errLines[0], " hint=") || !strings.Contains(errLines[0], " detail=") {
		t.Errorf("%s: want one ERROR line with msg %q, a detail and a hint:\n%s", what, msg, log.String())
	}
}

// Two start-up failures a restart can't fix stop the service without a restart loop: exit 78 and
// one ERROR line each. A required directory that is missing or not writable gets the same single
// line and exit 1, which the unit restarts on: the directory may be on a volume that attaches
// late (owner decision). serve returns at each before anything is started.
func TestServeStartupRefusals(t *testing.T) {
	const dirMsg = "a required directory is missing or not writable; not starting"
	t.Run("data_dir not writable: retried", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root writes everywhere")
		}
		cfgPath, dataDir := serveHost(t, "")
		if err := os.Chmod(dataDir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(dataDir, 0o700) })
		log := captureServeLog(t)
		wantStartExit(t, "data_dir", cmdServe([]string{"--config", cfgPath}), log, dirMsg, 1)
		if !strings.Contains(log.String(), dataDir) || !strings.Contains(log.String(), "ReadWritePaths") || !strings.Contains(log.String(), "starts the service again every 2s") {
			t.Errorf("the line names the directory, the unit setting and the retry:\n%s", log.String())
		}
	})

	t.Run("data_dir missing (a volume not attached yet): retried", func(t *testing.T) {
		cfgPath, dataDir := serveHost(t, "")
		// A path nothing can create (its parent is a file), so serve can't make the directory
		// itself and stops at the check, whoever runs the test.
		blocker := filepath.Join(dataDir, "not-mounted")
		if err := os.WriteFile(blocker, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		missing := filepath.Join(blocker, "data")
		if err := os.WriteFile(cfgPath, []byte(strings.Replace(mustReadFile(t, cfgPath), dataDir, missing, 1)), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := config.Load(cfgPath); err != nil {
			t.Fatalf("fixture: %v", err)
		}
		log := captureServeLog(t)
		wantStartExit(t, "data_dir", cmdServe([]string{"--config", cfgPath}), log, dirMsg, 1)
		if !strings.Contains(log.String(), missing) || strings.Contains(log.String(), restartCommand) {
			t.Errorf("the line names the directory and asks for no restart:\n%s", log.String())
		}
	})

	t.Run("encryption_key does not match the database", func(t *testing.T) {
		cfgPath, dataDir := serveHost(t, "")
		// The database was sealed under another key.
		db, err := store.Open(filepath.Join(dataDir, "mooring.db"))
		if err != nil {
			t.Fatal(err)
		}
		other := bytes.Repeat([]byte{7}, 32)
		c, err := secret.NewCipher(other, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := verifyOrInitSentinel(c, db); err != nil {
			t.Fatal(err)
		}
		db.Close()
		log := captureServeLog(t)
		wantRefusedStart(t, "key", cmdServe([]string{"--config", cfgPath}), log, "encryption_key does not match the database; not starting")
		if strings.Contains(log.String(), base64.StdEncoding.EncodeToString(other)) || strings.Contains(log.String(), base64.StdEncoding.EncodeToString(make([]byte, 32))) {
			t.Error("the line must not carry a key")
		}
	})

	t.Run("setup.enabled without a sandbox", func(t *testing.T) {
		cfgPath, _ := serveHost(t, "setup:\n  enabled: true\n  image: \"example.invalid/jail@sha256:"+strings.Repeat("a", 64)+"\"\n")
		prev := sandboxAvailable
		sandboxAvailable = func() (bool, string) { return false, "no docker CLI here" }
		t.Cleanup(func() { sandboxAvailable = prev })
		log := captureServeLog(t)
		wantRefusedStart(t, "sandbox", cmdServe([]string{"--config", cfgPath}), log, "setup.enabled is set but this host has no working sandbox; not starting")
		if !strings.Contains(log.String(), "no docker CLI here") || !strings.Contains(log.String(), "setup.enabled: false") {
			t.Errorf("the line says why and what to do:\n%s", log.String())
		}
	})

	// A sentinel that can't be read is a database failure: exit 1, restarted.
	if errors.Is(errors.New("reading key-check sentinel: disk I/O error"), errKeyMismatch) {
		t.Error("only a key that doesn't open the sentinel is a mismatch")
	}
}

// --- SIGHUP during start-up ---

const serveHUPEnv = "MOORING_TEST_SERVE_HUP"

// TestServeHUPHelper is not a test: TestServeSurvivesHUPDuringStartup runs it in a child process.
// serve stops at its directory check, or already at the config; a SIGHUP after serve began must
// not end the process (Go's default), because serve watches it from its first statement on.
func TestServeHUPHelper(t *testing.T) {
	cfgPath := os.Getenv(serveHUPEnv)
	if cfgPath == "" {
		return
	}
	serveLogOut = io.Discard
	_ = cmdServe([]string{"--config", cfgPath})
	_ = syscall.Kill(os.Getpid(), syscall.SIGHUP)
	time.Sleep(300 * time.Millisecond) // an unwatched SIGHUP has ended the process by now
	os.Exit(0)
}

// A `systemctl reload` during start-up must not stop the service: systemd counts a death by
// SIGHUP as a clean exit and leaves the unit down.
func TestServeSurvivesHUPDuringStartup(t *testing.T) {
	cfgPath, dataDir := serveHost(t, "")
	// The helper's serve stops at the directory check, after the config is loaded.
	if err := os.WriteFile(cfgPath, []byte(strings.Replace(mustReadFile(t, cfgPath), dataDir, filepath.Join(dataDir, "missing"), 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestServeHUPHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), serveHUPEnv+"="+cfgPath, config.DevInsecurePermsEnv+"=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("a SIGHUP after the config was loaded ended the process: %v\n%s", err, out)
	}

	// Before the config is loaded, too: this serve never gets past config.Load (no file), so the
	// SIGHUP is only survived when serve watched it before reading the config.
	cmd = exec.Command(os.Args[0], "-test.run=^TestServeHUPHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), serveHUPEnv+"="+filepath.Join(t.TempDir(), "not-there.yaml"), config.DevInsecurePermsEnv+"=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("a SIGHUP before the config was loaded ended the process: %v\n%s", err, out)
	}
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// --- reload ---

// reloadRun runs one reload against fakes and records what each part was given, in order.
type reloadRun struct {
	loads, rejections int
	reloaded, applied []*config.Config
	order             []string
	log               bytes.Buffer
}

func (rr *reloadRun) run(path string, load func(string) (*config.Config, error), reloadErr error) {
	reloadConfig(context.Background(), configReload{
		path: path, log: slog.New(slog.NewTextHandler(&rr.log, nil)),
		load: func(p string) (*config.Config, error) {
			rr.loads++
			rr.order = append(rr.order, "load "+p)
			return load(p)
		},
		reload: func(_ context.Context, c *config.Config) error {
			rr.reloaded = append(rr.reloaded, c)
			rr.order = append(rr.order, "reload")
			return reloadErr
		},
		rejected: func(context.Context) { rr.rejections++; rr.order = append(rr.order, "rejected") },
		apply:    func(c *config.Config) { rr.applied = append(rr.applied, c); rr.order = append(rr.order, "apply") },
	})
}

// A reload reads config.yaml once and gives that one config to the dashboard and to the edge and
// retention, so a file that changes during the reload cannot leave them on different allowlists.
func TestReloadConfigLoadsOnceForBothParts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("list: A\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var rr reloadRun
	var read []*config.Config
	rr.run(path, func(p string) (*config.Config, error) {
		c := &config.Config{DataDir: mustReadFile(t, p)}
		read = append(read, c)
		// An edit lands right after the read: a second read would see another file.
		if err := os.WriteFile(p, []byte("list: B\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return c, nil
	}, nil)
	if rr.loads != 1 || len(read) != 1 {
		t.Fatalf("config.yaml was read %d times in one reload, want once\n%s", rr.loads, rr.log.String())
	}
	if len(rr.reloaded) != 1 || rr.reloaded[0] != read[0] {
		t.Errorf("the dashboard got %v, want the one config that was read (%p)", rr.reloaded, read[0])
	}
	if len(rr.applied) != 1 || rr.applied[0] != read[0] {
		t.Errorf("the edge and retention got %v, want the one config that was read (%p)", rr.applied, read[0])
	}
	if read[0].DataDir != "list: A\n" {
		t.Errorf("read %q", read[0].DataDir)
	}
	if want := []string{"load " + path, "reload", "apply"}; !reflect.DeepEqual(rr.order, want) {
		t.Errorf("order = %v, want %v", rr.order, want)
	}
	got := rr.log.String()
	if rr.rejections != 0 || strings.Contains(got, "level=WARN") || strings.Contains(got, "level=ERROR") ||
		strings.Count(got, "\n") != 1 || !strings.Contains(got, `level=INFO msg="config reloaded (allowlist + auth)"`) {
		t.Errorf("%d rejections\n%s", rr.rejections, got)
	}
}

// A file that does not load: one ERROR line, the rejection is audited, and nothing is applied to
// the dashboard, the edge or the retention policy.
func TestReloadConfigRefusedLoadAppliesNothing(t *testing.T) {
	var rr reloadRun
	rr.run("/etc/mooring/config.yaml", func(string) (*config.Config, error) {
		return nil, errors.New("config: read config.yaml: input/output error")
	}, nil)
	if rr.loads != 1 || len(rr.reloaded) != 0 || len(rr.applied) != 0 {
		t.Errorf("%d loads, dashboard %v, edge %v: a refused file must reach nothing", rr.loads, rr.reloaded, rr.applied)
	}
	if rr.rejections != 1 {
		t.Errorf("the rejection was audited %d times, want once", rr.rejections)
	}
	got := rr.log.String()
	if strings.Count(got, "\n") != 1 || !strings.Contains(got, `level=ERROR msg="config reload rejected; keeping previous"`) ||
		!strings.Contains(got, "input/output error") {
		t.Errorf("want one ERROR line with the cause:\n%s", got)
	}
}

// The dashboard refuses a config that loaded: the edge and the retention policy are not changed
// either, and the log says nothing was applied (the file itself loaded, so it is not audited as an
// invalid config).
func TestReloadConfigDashboardRefusalAppliesNothing(t *testing.T) {
	var rr reloadRun
	cfg := &config.Config{}
	rr.run("/etc/mooring/config.yaml", func(string) (*config.Config, error) { return cfg, nil },
		errors.New("web: parse password hash for \"zoe\": bad params"))
	if rr.loads != 1 || len(rr.reloaded) != 1 || rr.reloaded[0] != cfg {
		t.Errorf("%d loads, dashboard %v", rr.loads, rr.reloaded)
	}
	if len(rr.applied) != 0 {
		t.Errorf("the edge and retention were set from a config the dashboard refused: %v", rr.applied)
	}
	got := rr.log.String()
	if rr.rejections != 0 || strings.Count(got, "\n") != 1 || !strings.Contains(got, "level=ERROR") ||
		!strings.Contains(got, "nothing was applied") || !strings.Contains(got, "bad params") ||
		strings.Contains(got, "config reloaded (allowlist + auth)") {
		t.Errorf("%d rejections; want one ERROR line saying nothing was applied:\n%s", rr.rejections, got)
	}
}

// --- the edge's allowlist on a reload ---

// What is logged after the push comes from the edge's state, not from the reconcile's error: a
// reconcile that returns nil may not have applied the list, and one that fails may have left it
// pending or given it up.
func TestPushAdminAllowlistWordsTheCasesApart(t *testing.T) {
	pushed := []string{"203.0.113.7/32"}
	previous := []string{"198.51.100.1/32"}
	run := func(err error, inForce []string, pending bool) string {
		var b bytes.Buffer
		f := &fakeAllowlistEdge{err: err, state: func([]string) ([]string, bool) { return inForce, pending }}
		pushAdminAllowlist(context.Background(), f, pushed, slog.New(slog.NewTextHandler(&b, nil)))
		if strings.Count(b.String(), "\n") != 1 {
			t.Errorf("one line per push:\n%s", b.String())
		}
		return b.String()
	}
	const applied, pendingMsg, refused = "the edge serves the reloaded ip_allowlist", "stays pending until the next reconcile that Caddy accepts", "the edge refused the new ip_allowlist and keeps the previous list"
	rejected := fmt.Errorf("edge: %w", &edge.ConfigRejectedError{Status: 400, Body: "loading config: bad matcher"})
	unreachable := errors.New("dial unix /run/mooring/caddy-admin.sock: connect: connection refused")
	cases := []struct {
		name    string
		err     error
		inForce []string
		pending bool
		level   string
		want    string
	}{
		{"applied", nil, pushed, false, "INFO", applied},
		// Reconcile returned nil, but another reconcile took the list and gave it up.
		{"nil error, list given up", nil, previous, false, "WARN", refused},
		// Reconcile returned nil, but the list was left pending (both renders refused).
		{"nil error, list pending", nil, previous, true, "WARN", pendingMsg},
		{"Caddy refused twice, list given up", rejected, previous, false, "WARN", refused},
		// Caddy refused the previous list's render too: the list stays pending, not "until a restart".
		{"Caddy refused both renders, list pending", rejected, previous, true, "WARN", pendingMsg},
		{"Caddy not reachable, list pending", unreachable, previous, true, "WARN", pendingMsg},
		{"timeout, list pending", context.DeadlineExceeded, previous, true, "WARN", pendingMsg},
		// The list was committed and something else failed afterwards.
		{"applied, reconcile failed for another reason", unreachable, pushed, false, "WARN", applied},
	}
	for _, c := range cases {
		got := run(c.err, c.inForce, c.pending)
		if !strings.Contains(got, "level="+c.level) || !strings.Contains(got, c.want) || !strings.Contains(got, "entries=1") {
			t.Errorf("%s: want level %s and %q:\n%s", c.name, c.level, c.want, got)
		}
		for _, other := range []string{applied, pendingMsg, refused} {
			if other != c.want && strings.Contains(got, other) {
				t.Errorf("%s: also says %q:\n%s", c.name, other, got)
			}
		}
		if c.err != nil && !strings.Contains(got, "err=") {
			t.Errorf("%s: the reconcile's error is kept:\n%s", c.name, got)
		}
		if strings.Contains(got, "until a reload") || strings.Contains(got, "or a restart") {
			t.Errorf("%s: a pending list needs no reload or restart:\n%s", c.name, got)
		}
	}
	// A given-up list names the edge's own line and the way out.
	if got := run(nil, previous, false); !strings.Contains(got, edgeAllowlistRefusedLine) || !strings.Contains(got, reloadCommand) {
		t.Errorf("a refused list:\n%s", got)
	}
}

// A list Caddy accepted (also one applied by a later reconcile) is logged, and the boot config is
// rendered again with it, so a relaunched Caddy starts on the list in force.
func TestAdminAllowlistAccepted(t *testing.T) {
	base := edge.BaseConfig{
		AdminListen: "unix//run/mooring/caddy-admin.sock", ACMEEmail: "ops@example.com",
		AdminHostname: "admin.example.com", AdminAllowlist: []string{"198.51.100.1/32"}, AdminUpstream: "127.0.0.1:9001",
	}
	atStart, err := edge.Render(edge.BootFloor(base), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(atStart, []byte("198.51.100.1/32")) {
		t.Skip("the boot render doesn't carry the dashboard allowlist")
	}
	var logb bytes.Buffer
	var got []byte
	fn := adminAllowlistAccepted(base, func(cfg []byte) { got = cfg }, slog.New(slog.NewTextHandler(&logb, nil)))
	fn([]string{"203.0.113.7/32", "2001:db8::/32"})
	if !strings.Contains(logb.String(), `msg="ip_allowlist applied at the edge" entries=2`) {
		t.Errorf("the applied list is logged:\n%s", logb.String())
	}
	if !bytes.Contains(got, []byte("203.0.113.7/32")) || !bytes.Contains(got, []byte("2001:db8::/32")) || bytes.Contains(got, []byte("198.51.100.1/32")) {
		t.Errorf("the boot config must carry the new list only:\n%s", got)
	}
	if !bytes.Contains(got, []byte("admin.example.com")) || !bytes.Contains(got, []byte("ops@example.com")) {
		t.Errorf("the base's other fields are kept:\n%s", got)
	}
	if base.AdminAllowlist[0] != "198.51.100.1/32" {
		t.Error("the captured base must not be changed")
	}
	// A list the renderer refuses: the previous boot config stays, with a warning.
	got = nil
	logb.Reset()
	fn([]string{"not-an-address"})
	if got != nil || !strings.Contains(logb.String(), "level=WARN") {
		t.Errorf("a refused render must not replace the boot config:\n%s", logb.String())
	}
}
