package web

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/alertstore"
	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/dockerexec"
	"github.com/daboss2003/mooring/internal/edge"
	"github.com/daboss2003/mooring/internal/secret"
	"github.com/daboss2003/mooring/internal/store"
)

func catchAllNamespace() config.EdgeBaseDomain {
	return config.EdgeBaseDomain{Name: "shop", Domain: "shop.example.com",
		DNS01: &config.EdgeDNS01{Provider: "cloudflare", APIToken: "tok"}, CatchAll: true}
}

// catchAllTestServer is a Server with a consented, dns01-backed shop.example.com namespace, a route store
// and an alert store.
func catchAllTestServer(t *testing.T) *Server {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	cipher, err := secret.NewCipher(make([]byte, 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	return &Server{
		cfg:        &config.Config{Edge: config.EdgeConfig{BaseDomains: []config.EdgeBaseDomain{catchAllNamespace()}}},
		db:         db,
		edgeRoutes: edge.NewRouteStore(db),
		alertStore: alertstore.New(db, cipher),
		log:        quietWebLog(),
	}
}

// catchAllRouteDef is an EXPANDED definition with the shop namespace's catch-all.
func catchAllRouteDef() *definition.Definition {
	d := &definition.Definition{}
	d.Spec.Edge.Routes = []definition.Route{{Hostname: "*.shop.example.com", Service: "web", Port: 8080}}
	return d
}

func storeCatchAll(t *testing.T, s *Server, project string) {
	t.Helper()
	if err := s.edgeRoutes.ReplaceProject(context.Background(), project, []edge.Route{
		{Hostname: "*.shop.example.com", Upstream: "web:8080", Enabled: true, CatchAll: true},
	}); err != nil {
		t.Fatal(err)
	}
}

// withoutSystemCaddy runs fn with an empty PATH, so a plugin installer never reads a real caddy binary.
func withoutSystemCaddy(t *testing.T, fn func()) {
	t.Helper()
	old := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir())
	defer t.Setenv("PATH", old)
	fn()
}

// failDNSPlugin drives provider's plugin state to "install failed" (KnownMissing) through one failed
// install attempt.
func failDNSPlugin(t *testing.T, p *edge.DNSPlugins, provider, msg string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	inst := &edge.DNSPluginInstaller{DataDir: t.TempDir(), Providers: []string{provider}, State: p, MinBackoff: time.Hour, Log: quietWebLog(),
		Install: func(context.Context, edge.InstallOptions) (string, error) {
			cancel() // Run returns once this failure is recorded instead of waiting to retry
			return "", errors.New(msg)
		}}
	withoutSystemCaddy(t, func() { inst.Run(ctx) })
	if m, _ := p.KnownMissing(provider); !m {
		t.Fatalf("%s should be known missing after a failed install", provider)
	}
}

// installDNSPlugin drives provider's plugin state to "installed" the way serve does: one successful
// install lands a build on disk, then the edge relaunches on it and Sync reads its modules.
func installDNSPlugin(t *testing.T, p *edge.DNSPlugins, provider string) {
	t.Helper()
	inst := &edge.DNSPluginInstaller{DataDir: t.TempDir(), Providers: []string{provider}, State: p, Log: quietWebLog(),
		Install: func(_ context.Context, opt edge.InstallOptions) (string, error) {
			bin := edge.OwnedCaddyPath(opt.DataDir)
			script := "#!/bin/sh\ncase \"$1\" in\n  version) echo 'v2.11.2 h1:x' ;;\n  list-modules) echo 'dns.providers." + provider + "' ;;\nesac\n"
			if err := os.MkdirAll(filepath.Dir(bin), 0o700); err != nil {
				return "", err
			}
			return bin, os.WriteFile(bin, []byte(script), 0o700)
		}}
	withoutSystemCaddy(t, func() {
		inst.Run(context.Background())
		inst.Sync(context.Background(), inst.Launched()) // the relaunch onto the new build
	})
	if !p.OK(provider) {
		t.Fatalf("%s should be installed", provider)
	}
}

func catchAllOutbox(t *testing.T, s *Server) []string {
	t.Helper()
	rows, err := s.db.Query(`SELECT transition, level, target, summary FROM alert_outbox WHERE kind=? AND dedupe_key=? ORDER BY id`,
		catchAllDarkKind, "catchall:shop.example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var transition, level, target, summary string
		if err := rows.Scan(&transition, &level, &target, &summary); err != nil {
			t.Fatal(err)
		}
		if level != alert.LevelCritical || target != "shop.example.com" {
			t.Errorf("alert row level=%q target=%q, want critical shop.example.com", level, target)
		}
		out = append(out, transition+": "+summary)
	}
	return out
}

// A deploy that ADDS a catch-all while its namespace's DNS plugin is known missing is refused — even
// when another app holds a catch-all row (only this app's own stored catch-all counts as existing).
func TestCatchAllGateRefusesNewWhenPluginKnownMissing(t *testing.T) {
	s := catchAllTestServer(t)
	p := edge.NewDNSPlugins([]string{"cloudflare"})
	failDNSPlugin(t, p, "cloudflare", "edge: download a Caddy plugin build: dial tcp: no route to host")
	s.edgeDNSPlugins = p

	warns, err := s.catchAllWildcardCheck("shop", catchAllRouteDef())
	if err == nil {
		t.Fatalf("a new catch-all with a known-missing plugin must be refused (warns %v)", warns)
	}
	for _, want := range []string{"refusing a new catch-all on namespace shop.example.com", "the DNS plugin for cloudflare isn't available", "no route to host", "Deploy again once the Edge page shows the wildcard active"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q missing %q", err, want)
		}
	}

	storeCatchAll(t, s, "other")
	if _, err := s.catchAllWildcardCheck("shop", catchAllRouteDef()); err == nil {
		t.Error("another app's catch-all must not make this app's catch-all count as existing")
	}
}

// A deploy that KEEPS an existing catch-all goes ahead with a deploy-log warning, whether the plugin is
// known missing or still installing.
func TestCatchAllGateWarnsExisting(t *testing.T) {
	s := catchAllTestServer(t)
	storeCatchAll(t, s, "shop")
	p := edge.NewDNSPlugins([]string{"cloudflare"})
	s.edgeDNSPlugins = p

	warns, err := s.catchAllWildcardCheck("shop", catchAllRouteDef())
	if err != nil || len(warns) != 1 || !strings.Contains(warns[0], "(the DNS plugin for cloudflare is installing)") {
		t.Fatalf("existing catch-all while installing: warns=%v err=%v", warns, err)
	}

	failDNSPlugin(t, p, "cloudflare", "dial tcp: no route to host")
	warns, err = s.catchAllWildcardCheck("shop", catchAllRouteDef())
	if err != nil {
		t.Fatalf("an existing catch-all must not be refused: %v", err)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "⚠ catch-all *.shop.example.com has no wildcard certificate yet (the DNS plugin for cloudflare isn't available: dial tcp: no route to host)") ||
		!strings.Contains(warns[0], "fail TLS until it is issued") {
		t.Fatalf("existing catch-all warning = %v", warns)
	}
}

// Nothing is refused or warned when the plugin is installed, when there is no plugin state, or for a
// route that isn't a catch-all. A new catch-all during the first install is allowed with a warning.
func TestCatchAllGateSilentWhenPluginOKOrUntracked(t *testing.T) {
	s := catchAllTestServer(t)
	if warns, err := s.catchAllWildcardCheck("shop", catchAllRouteDef()); err != nil || len(warns) != 0 {
		t.Fatalf("nil plugin state: warns=%v err=%v", warns, err)
	}

	p := edge.NewDNSPlugins([]string{"cloudflare"})
	s.edgeDNSPlugins = p
	if warns, err := s.catchAllWildcardCheck("shop", catchAllRouteDef()); err != nil || len(warns) != 1 {
		t.Fatalf("a new catch-all during the first install is allowed with a warning: warns=%v err=%v", warns, err)
	}

	installDNSPlugin(t, p, "cloudflare")
	if warns, err := s.catchAllWildcardCheck("shop", catchAllRouteDef()); err != nil || len(warns) != 0 {
		t.Fatalf("installed plugin: warns=%v err=%v", warns, err)
	}

	failed := edge.NewDNSPlugins([]string{"cloudflare"})
	failDNSPlugin(t, failed, "cloudflare", "boom")
	s.edgeDNSPlugins = failed
	d := &definition.Definition{}
	d.Spec.Edge.Routes = []definition.Route{{Hostname: "app.shop.example.com", Service: "web", Port: 8080}}
	if warns, err := s.catchAllWildcardCheck("shop", d); err != nil || len(warns) != 0 {
		t.Fatalf("an exact route is not gated: warns=%v err=%v", warns, err)
	}
}

// applyRoutes enforces refuse-new on every ingest path, reading "existing" from the routes stored before
// it replaces them: a new catch-all is refused (nothing stored), an existing one is re-applied.
func TestApplyRoutesCatchAllRefusesNewWhenPluginMissing(t *testing.T) {
	s := catchAllTestServer(t)
	ctx := context.Background()
	failed := edge.NewDNSPlugins([]string{"cloudflare"})
	failDNSPlugin(t, failed, "cloudflare", "dial tcp: no route to host")
	s.edgeDNSPlugins = failed

	err := s.applyRoutes(ctx, "shop", catchAllRouteDef())
	if err == nil || !strings.Contains(err.Error(), "refusing a new catch-all on namespace shop.example.com") {
		t.Fatalf("applyRoutes must refuse a new catch-all: %v", err)
	}
	if routes, _ := s.edgeRoutes.List(); len(routes) != 0 {
		t.Fatalf("a refused catch-all must not be stored: %+v", routes)
	}

	s.edgeDNSPlugins = nil
	if err := s.applyRoutes(ctx, "shop", catchAllRouteDef()); err != nil {
		t.Fatalf("apply with no plugin state: %v", err)
	}
	s.edgeDNSPlugins = failed
	if err := s.applyRoutes(ctx, "shop", catchAllRouteDef()); err != nil {
		t.Fatalf("an existing catch-all must be re-applied while its plugin is missing: %v", err)
	}
	if routes, _ := s.edgeRoutes.List(); len(routes) != 1 || !routes[0].CatchAll {
		t.Fatalf("existing catch-all not kept: %+v", routes)
	}
}

// A known-missing plugin fires exactly one CRITICAL alert (no probe), which resolves once the plugin is
// installed and the probe finds the wildcard certificate.
func TestCheckCatchAllsAlertsKnownMissingThenResolves(t *testing.T) {
	s := catchAllTestServer(t)
	ctx := context.Background()
	storeCatchAll(t, s, "shop")
	p := edge.NewDNSPlugins([]string{"cloudflare"})
	failDNSPlugin(t, p, "cloudflare", "dial tcp: no route to host")
	s.edgeDNSPlugins = p
	var probes atomic.Int32
	s.catchAllProbe = func(_ context.Context, apex string) error {
		probes.Add(1)
		if apex != "shop.example.com" {
			t.Errorf("probed apex %q", apex)
		}
		return nil
	}

	s.checkCatchAlls(ctx)
	// Delivered, as the dispatcher would mark it: the outbox's own pending-row dedupe no longer applies,
	// so only the open-alert check keeps the next check from firing again.
	if _, err := s.db.Exec(`UPDATE alert_outbox SET sent_at=1`); err != nil {
		t.Fatal(err)
	}
	s.checkCatchAlls(ctx)
	rows := catchAllOutbox(t, s)
	if len(rows) != 1 || !strings.HasPrefix(rows[0], "firing: catch-all on *.shop.example.com is serving no certificate: the DNS plugin for cloudflare isn't available: dial tcp: no route to host") {
		t.Fatalf("want exactly one firing alert, got %v", rows)
	}
	if probes.Load() != 0 {
		t.Errorf("a known-missing plugin must not be probed (probes=%d)", probes.Load())
	}
	if dark := s.darkCatchAlls(); len(dark) != 1 || dark[0].Apex != "shop.example.com" || !strings.Contains(dark[0].Cause, "isn't available") {
		t.Fatalf("dark state = %+v", dark)
	}

	installDNSPlugin(t, p, "cloudflare")
	s.checkCatchAlls(ctx)
	rows = catchAllOutbox(t, s)
	if len(rows) != 2 || rows[1] != "resolved: catch-all on *.shop.example.com serves its wildcard certificate again" {
		t.Fatalf("want firing then resolved, got %v", rows)
	}
	if probes.Load() != 1 || len(s.darkCatchAlls()) != 0 {
		t.Fatalf("after recovery: probes=%d dark=%+v", probes.Load(), s.darkCatchAlls())
	}
	s.checkCatchAlls(ctx)
	if rows := catchAllOutbox(t, s); len(rows) != 2 {
		t.Fatalf("a healthy catch-all must not notify again: %v", rows)
	}
}

// With the plugin installed, the catch-all is dark only after catchAllProbeFailures failed probes in a
// row; a passing probe resets the count.
func TestCheckCatchAllsProbeFailuresBeforeDark(t *testing.T) {
	s := catchAllTestServer(t)
	ctx := context.Background()
	storeCatchAll(t, s, "shop")
	p := edge.NewDNSPlugins([]string{"cloudflare"})
	installDNSPlugin(t, p, "cloudflare")
	s.edgeDNSPlugins = p
	var probeErr atomic.Pointer[error]
	setProbe := func(err error) { probeErr.Store(&err) }
	s.catchAllProbe = func(context.Context, string) error { return *probeErr.Load() }
	noCert := errors.New("no certificate served for *.shop.example.com (EOF)")

	setProbe(noCert)
	s.checkCatchAlls(ctx)
	s.checkCatchAlls(ctx)
	if rows := catchAllOutbox(t, s); len(rows) != 0 || len(s.darkCatchAlls()) != 0 {
		t.Fatalf("two failed probes must not mark the catch-all dark: rows=%v dark=%+v", rows, s.darkCatchAlls())
	}
	setProbe(nil)
	s.checkCatchAlls(ctx) // resets the count
	setProbe(noCert)
	s.checkCatchAlls(ctx)
	s.checkCatchAlls(ctx)
	if rows := catchAllOutbox(t, s); len(rows) != 0 {
		t.Fatalf("a passing probe must reset the failure count: %v", rows)
	}
	s.checkCatchAlls(ctx)
	rows := catchAllOutbox(t, s)
	if len(rows) != 1 || !strings.Contains(rows[0], "no certificate served for *.shop.example.com (EOF) (ACME DNS-01 issuance may be failing") {
		t.Fatalf("the third failed probe in a row must fire: %v", rows)
	}
	if dark := s.darkCatchAlls(); len(dark) != 1 || !strings.Contains(dark[0].Cause, "api_token") {
		t.Fatalf("dark state = %+v", dark)
	}

	setProbe(nil)
	s.checkCatchAlls(ctx)
	if rows := catchAllOutbox(t, s); len(rows) != 2 || !strings.HasPrefix(rows[1], "resolved:") {
		t.Fatalf("a passing probe must resolve: %v", rows)
	}
}

// An open alert stays open while the plugin is (re)installing — no verdict yet, no probe — and resolves
// when the catch-all is removed. Without an alert store the check still runs.
func TestCheckCatchAllsInstallingKeepsAlertRemovedResolves(t *testing.T) {
	s := catchAllTestServer(t)
	ctx := context.Background()
	storeCatchAll(t, s, "shop")
	failed := edge.NewDNSPlugins([]string{"cloudflare"})
	failDNSPlugin(t, failed, "cloudflare", "boom")
	s.edgeDNSPlugins = failed
	s.catchAllProbe = func(context.Context, string) error { t.Error("an installing plugin must not be probed"); return nil }
	s.checkCatchAlls(ctx)

	s.edgeDNSPlugins = edge.NewDNSPlugins([]string{"cloudflare"}) // a fresh process: first install running
	s.checkCatchAlls(ctx)
	if rows := catchAllOutbox(t, s); len(rows) != 1 {
		t.Fatalf("an installing plugin must keep the alert open: %v", rows)
	}
	if len(s.darkCatchAlls()) != 0 {
		t.Fatalf("an installing plugin is not dark: %+v", s.darkCatchAlls())
	}

	if err := s.edgeRoutes.ReplaceProject(ctx, "shop", nil); err != nil {
		t.Fatal(err)
	}
	s.checkCatchAlls(ctx)
	if rows := catchAllOutbox(t, s); len(rows) != 2 || !strings.HasPrefix(rows[1], "resolved: catch-all on *.shop.example.com is no longer served") {
		t.Fatalf("a removed catch-all must resolve its alert: %v", rows)
	}

	storeCatchAll(t, s, "shop")
	s.edgeDNSPlugins = failed
	s.alertStore = nil
	s.checkCatchAlls(ctx)
	if len(s.darkCatchAlls()) != 1 {
		t.Fatalf("dark state without an alert store = %+v", s.darkCatchAlls())
	}
}

// The Edge page shows a banner per dark catch-all and the DNS-01 plugins table (escaped).
func TestEdgePageShowsDarkCatchAllAndPlugins(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, _ := e.authed(t)
	e.srv.cfg.Edge.BaseDomains = []config.EdgeBaseDomain{catchAllNamespace()}
	storeCatchAll(t, e.srv, "shop")

	p := edge.NewDNSPlugins([]string{"cloudflare", "route53", "nosuch"})
	failDNSPlugin(t, p, "cloudflare", "dial tcp: no route to host <x>")
	withoutSystemCaddy(t, func() {
		(&edge.DNSPluginInstaller{DataDir: t.TempDir(), Providers: []string{"nosuch"}, State: p}).Check(context.Background())
	})
	e.srv.edgeDNSPlugins = p
	e.srv.checkCatchAlls(context.Background())

	resp := e.req(t, "GET", "/edge", "127.0.0.1:1", nil, []*http.Cookie{sess}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /edge = %d", resp.StatusCode)
	}
	page := readBody(resp)
	for _, want := range []string{
		`<div class="error" role="alert">Catch-all <code>*.shop.example.com</code> serves no certificate`,
		"the DNS plugin for cloudflare isn&#39;t available",
		"<h2>DNS-01 plugins</h2>",
		"install failed — next retry <time data-ts=",
		"1 attempt(s)",
		"not installable (no retry)",
		"unknown DNS provider",
		`<td class="mono">route53</td>`,
		"<td>installing</td>",
		"dial tcp: no route to host &lt;x&gt;",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("edge page missing %q", want)
		}
	}
	if strings.Contains(page, "<x>") {
		t.Error("plugin error text must be escaped")
	}

	// Without plugin state the table is not shown.
	e.srv.edgeDNSPlugins = nil
	if page := readBody(e.req(t, "GET", "/edge", "127.0.0.1:1", nil, []*http.Cookie{sess}, nil)); strings.Contains(page, "DNS-01 plugins") {
		t.Error("no plugin state: the DNS-01 plugins table must be hidden")
	}
}

// The git deploy runs the gate right after the subdomains are expanded, before anything is generated or
// built: a NEW catch-all with a known-missing plugin blocks the deploy; with the catch-all already stored,
// the warning is streamed and the deploy carries on (to the disabled write plane here).
func TestDeployRepoAppCatchAllPluginGate(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), false, "disabled for test")
	e.srv.cfg.Edge.BaseDomains = []config.EdgeBaseDomain{catchAllNamespace()}
	slug := "shop"
	yaml := repoMooringYAML + "  edge:\n    base_domain: shop\n    routes:\n      - subdomain: \"*\"\n        service: web\n        port: 80\n"
	sha := gitObjStoreFixture(t, e.srv.gitObjectDir(slug), yaml)
	cfg := configureRepo(t, e, slug, sha)
	p := edge.NewDNSPlugins([]string{"cloudflare"})
	failDNSPlugin(t, p, "cloudflare", "dial tcp: no route to host")
	e.srv.edgeDNSPlugins = p

	_, err := e.srv.deployRepoApp(context.Background(), cfg, sha, "manual", "operator", false, false, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "refusing a new catch-all on namespace shop.example.com") {
		t.Fatalf("a new catch-all with a known-missing plugin must block the deploy, got %v", err)
	}
	if got, _, _ := e.srv.gitStore.Get(slug); got.UpdateState != "update_blocked" {
		t.Errorf("state = %q, want update_blocked", got.UpdateState)
	}
	if _, serr := os.Stat(filepath.Join(e.srv.appRunDir(slug), "docker-compose.yml")); serr == nil {
		t.Error("the refusal must come before the compose is generated")
	}

	storeCatchAll(t, e.srv, slug)
	cfg = configureRepo(t, e, slug, sha)
	var lines []string
	_, err = e.srv.deployRepoApp(context.Background(), cfg, sha, "manual", "operator", false, false, func(l string) { lines = append(lines, l) })
	if err == nil || strings.Contains(err.Error(), "refusing") {
		t.Fatalf("an existing catch-all must not be refused (the disabled write plane fails later), got %v", err)
	}
	if !strings.Contains(strings.Join(lines, "\n"), "⚠ catch-all *.shop.example.com has no wildcard certificate yet (the DNS plugin for cloudflare isn't available: dial tcp: no route to host)") {
		t.Errorf("deploy log missing the catch-all warning:\n%s", strings.Join(lines, "\n"))
	}
}

// A namespace whose wildcard config Caddy refused is off on its own, even with its plugin installed: a new
// catch-all on it is refused, an existing one is warned, the watch raises the alert without probing, and
// the Edge page lists the refusal. Another namespace's refusal doesn't touch it.
func TestCatchAllRefusedNamespace(t *testing.T) {
	s := catchAllTestServer(t)
	p := edge.NewDNSPlugins([]string{"cloudflare"})
	installDNSPlugin(t, p, "cloudflare")
	s.edgeDNSPlugins = p

	p.RejectNamespace("other.example.com", "not this one")
	if warns, err := s.catchAllWildcardCheck("shop", catchAllRouteDef()); err != nil || len(warns) != 0 {
		t.Fatalf("another namespace's refusal must not gate shop: warns=%v err=%v", warns, err)
	}

	p.RejectNamespace("shop.example.com", `dns.providers.cloudflare: API token '[redacted]' appears invalid`)
	_, err := s.catchAllWildcardCheck("shop", catchAllRouteDef())
	if err == nil || !strings.Contains(err.Error(), "Caddy refused the namespace's DNS-01 config: dns.providers.cloudflare: API token '[redacted]' appears invalid") {
		t.Fatalf("a new catch-all on a refused namespace must be refused with Caddy's error, got %v", err)
	}

	storeCatchAll(t, s, "shop")
	warns, err := s.catchAllWildcardCheck("shop", catchAllRouteDef())
	if err != nil || len(warns) != 1 || !strings.Contains(warns[0], "Caddy refused the namespace's DNS-01 config") {
		t.Fatalf("an existing catch-all is warned, not refused: warns=%v err=%v", warns, err)
	}

	var probes atomic.Int32
	s.catchAllProbe = func(context.Context, string) error { probes.Add(1); return nil }
	s.checkCatchAlls(context.Background())
	rows := catchAllOutbox(t, s)
	if len(rows) != 1 || !strings.Contains(rows[0], "firing: catch-all on *.shop.example.com is serving no certificate: Caddy refused the namespace's DNS-01 config") {
		t.Fatalf("want one firing alert for the refused namespace, got %v", rows)
	}
	if probes.Load() != 0 {
		t.Errorf("a refused namespace must not be probed (probes=%d)", probes.Load())
	}
}

// The Edge page lists each namespace Caddy refused, with its (escaped) error.
func TestEdgePageShowsRefusedNamespaces(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, _ := e.authed(t)
	p := edge.NewDNSPlugins([]string{"cloudflare"})
	p.RejectNamespace("staging.example.com", "json: unknown field \"api_token\" <x>")
	e.srv.edgeDNSPlugins = p
	page := readBody(e.req(t, "GET", "/edge", "127.0.0.1:1", nil, []*http.Cookie{sess}, nil))
	for _, want := range []string{"<h3>Wildcards refused by Caddy</h3>", `<td class="mono">*.staging.example.com</td>`, "unknown field &#34;api_token&#34; &lt;x&gt;"} {
		if !strings.Contains(page, want) {
			t.Errorf("edge page missing %q", want)
		}
	}
}

// A provider whose running binary can't be read shows that state, unless an install failure is the
// cause to show.
func TestPluginViewUnreadable(t *testing.T) {
	v := pluginView(edge.ProviderStatus{Provider: "cloudflare", OnDisk: true, SyncErr: "can't read the modules of the running Caddy: signal: killed"})
	if v.State != "unreadable" || !strings.Contains(v.Err, "signal: killed") {
		t.Errorf("view = %+v", v)
	}
	if v := pluginView(edge.ProviderStatus{Provider: "cloudflare", Err: "download failed", SyncErr: "x"}); v.State != "failed" || v.Err != "download failed" {
		t.Errorf("an install failure wins: %+v", v)
	}
}
