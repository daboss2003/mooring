package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/yamldiag"
	"gopkg.in/yaml.v3"
)

// corpusBase is validYAML's base block as testdata/accept_reject_corpus.json abbreviates it.
const corpusBase = `
bind_addr: "127.0.0.1:9000"
encryption_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
ip_allowlist:
  - "203.0.113.10/32"
auth:
  username: "operator"
  password_hash: "@HASH@"
edge:
  mode: "managed"
  acme_email: "ops@example.com"
  acme_ca: "https://acme.example/directory"
`

// The loader is the root-of-trust gate: readable errors must not move one file across the
// accept/refuse line. The corpus is every input this package's tests gave Parse at 1c6271d (the
// last commit before diagnostics) plus files the strict decode refuses, with the verdict that
// commit's Parse gave. Never regenerate it from the current code.
func TestParseAcceptRejectUnchanged(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "accept_reject_corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus []struct {
		YAML   string `json:"yaml"`
		Accept bool   `json:"accept"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus) < 300 {
		t.Fatalf("corpus has %d files", len(corpus))
	}
	hash, err := validHash()
	if err != nil {
		t.Fatal(err)
	}
	accepted := 0
	for _, c := range corpus {
		y := strings.ReplaceAll(strings.ReplaceAll(c.YAML, "@BASE@", corpusBase), "@HASH@", hash)
		cfg, err := Parse([]byte(y))
		if (err == nil) != c.Accept {
			t.Errorf("accept = %v, was %v before diagnostics (err: %v):\n%s", err == nil, c.Accept, err, c.YAML)
			continue
		}
		if err == nil {
			accepted++
			if cfg == nil {
				t.Errorf("accepted with a nil config:\n%s", c.YAML)
			}
			continue
		}
		if cfg != nil {
			t.Errorf("refused, but a config was returned:\n%s", c.YAML)
		}
		var d *yamldiag.Diagnostics
		if !errors.As(err, &d) || d.Cause == nil {
			t.Errorf("the refusal is not a Diagnostics with a cause (%T %v):\n%s", err, err, c.YAML)
			continue
		}
		if cause := d.Cause.Error(); !strings.HasPrefix(cause, "config: parse: ") && !strings.HasPrefix(cause, "config: refusing to boot:\n  - ") {
			t.Errorf("cause %q is not the refusal of before", cause)
		}
	}
	if accepted < 100 {
		t.Errorf("only %d accepted files: the corpus no longer exercises acceptance", accepted)
	}
}

func problemsOf(t *testing.T, overrides string) []yamldiag.Problem {
	t.Helper()
	c := &Config{}
	if err := yamlStrict([]byte(validYAML(t, overrides)), c); err != nil {
		t.Fatal(err)
	}
	applyDefaults(c)
	return c.Problems()
}

// Every validation problem names the key it is about, so its line can be shown.
func TestProblemsCarryKeyPaths(t *testing.T) {
	for _, tc := range []struct {
		ov, path, msg string
	}{
		{"encryption_key_previous: \"c2hvcnQ=\"\n", "encryption_key_previous", "must be 32 bytes"},
		{"trust_proxy: true\n", "trust_proxy", "trusted_proxies is empty"},
		{"trusted_proxies: [\"192.0.2.1\"]\n", "trusted_proxies", "trust_proxy is off"},
		{"trust_proxy: true\ntrusted_proxies: [\"192.0.2.1\", \"10.0.0.0/8\"]\n", "trusted_proxies[1]", "too broad"},
		{"trust_proxy: true\ntrusted_proxies: [\"nope\", \"203.0.113.10\"]\n", "trusted_proxies[1]", "overlaps ip_allowlist"},
		{"users:\n  - username: bob\n    role: viewer\n", "users[0].password_hash", "password_hash required"},
		{"users:\n  - username: operator\n    role: boss\n", "users[0].username", "duplicate username"},
		{"users:\n  - username: operator\n    role: boss\n", "users[0].role", "must be owner, deployer, or viewer"},
		{"  dns01:\n    provider: cloudflare\n", "edge.dns01", "requires edge.base_domain"},
		{"  dns01:\n    provider: cloudflare\n", "edge.dns01.api_token", "api_token is required"},
		{"  catch_all: true\n", "edge.catch_all", "requires edge.dns01"},
		{"  cas:\n    - name: ok\n      directory_url: https://x/d\n    - name: ok\n      directory_url: http://x/d\n", "edge.cas[1].name", "duplicate CA name"},
		{"  cas:\n    - name: ok\n      directory_url: https://x/d\n    - name: ok\n      directory_url: http://x/d\n", "edge.cas[1].directory_url", "must be an https"},
		{"  base_domains:\n    - name: a\n      domain: a.example.com\n    - name: b\n      domain: A.example.com\n", "edge.base_domains[1].domain", "lowercase FQDN"},
		{"  base_domains:\n    - name: a\n      domain: a.example.com\n      catch_all: true\n", "edge.base_domains[0].catch_all", "catch_all requires dns01"},
		{"  trusted_proxies: [cloudflare, \"0.0.0.0/0\"]\n", "edge.trusted_proxies[1]", "trusts every address"},
		{"  client_ip_header: X-Real-IP\n", "edge.client_ip_header", "edge.trusted_proxies is empty"},
		{"admin:\n  listen: \"0.0.0.0:2019\"\n", "admin.listen", "never routable"},
		{"admin:\n  subdomain: admin\n", "admin.subdomain", "needs edge.base_domain"},
		{"admin:\n  hostname: \"not a host\"\n", "admin.hostname", "is not a valid FQDN"},
		{"  base_domain: apps.example.com\nadmin:\n  subdomain: admin\n  edge_listen: \"127.0.0.1:9000\"\n", "admin.edge_listen", "must differ from bind_addr"},
		{"cookie:\n  base_path: /x\n", "cookie.base_path", "forbids a base_path"},
		{"cookie:\n  prefix: __Secure-\n", "cookie.prefix", "requires cookie.base_path"},
		{"docker:\n  proxy_addr: \"10.0.0.1:2375\"\n", "docker.proxy_addr", "loopback host:port"},
		{"compose_validation:\n  mode: loose\n", "compose_validation.mode", "strict or review"},
		{"setup:\n  enabled: true\n  image: busybox\n", "setup.image", "digest-pinned"},
		{"retention:\n  events_max_rows: 5\n", "retention.events_max_rows", ">= 1000"},
		{"server:\n  file_roots:\n    - name: logs\n      path: /var/log\n    - name: x\n      path: rel\n", "server.file_roots[1].path", "must be absolute"},
		{"server:\n  start_gate:\n    max_wait: 5s\n", "server.start_gate.max_wait", "between 1m and 2h"},
		{"server:\n  service_log_max_lines: 5\n", "server.service_log_max_lines", "must be between"},
		{"backups:\n  enabled: true\n  s3:\n    bucket: b\n    region: r\n    endpoint: e\n", "backups.s3", "requires access_key_id"},
		{"backups:\n  enabled: true\n  s3:\n    region: r\n    endpoint: e\n    access_key_id: a\n    secret_access_key: s\n", "backups.s3.bucket", "bucket is required"},
		{"security_logs:\n  response:\n    mode: block\n", "security_logs.response.mode", "use off, recommend or enforce"},
		{"security_logs:\n  blocking:\n    never_block: [\"10.0.0.0/8\", nope]\n", "security_logs.blocking.never_block[1]", "must be an IP address or a CIDR"},
		{"security_logs:\n  pii:\n    drop_fields: [ok, \"bad name\"]\n", "security_logs.pii.drop_fields[1]", "use letters"},
		{"security_logs:\n  host_logs:\n    auth_log: rel/auth.log\n", "security_logs.host_logs.auth_log", "absolute path"},
	} {
		ps := problemsOf(t, tc.ov)
		if !slices.ContainsFunc(ps, func(p yamldiag.Problem) bool {
			return p.Path == tc.path && p.Kind == yamldiag.KindSemantic && strings.Contains(p.Msg, tc.msg)
		}) {
			t.Errorf("%q: no problem at %q saying %q; got %+v", tc.ov, tc.path, tc.msg, ps)
		}
	}
	// The whole-file problems of the base block's own keys.
	c := &Config{BindAddr: "0.0.0.0:9000", Edge: EdgeConfig{Mode: "sideways"}, IPAllowlist: []string{"10.0.0.1", "nope"}}
	applyDefaults(c)
	var paths []string
	for _, p := range c.Problems() {
		if p.Path == "" || strings.ContainsAny(p.Path, " :") {
			t.Errorf("problem %q has no usable key path (%q)", p.Msg, p.Path)
		}
		paths = append(paths, p.Path)
	}
	sort.Strings(paths)
	if want := []string{"auth.password_hash", "auth.username", "bind_addr", "edge.mode", "encryption_key", "ip_allowlist[1]"}; !reflect.DeepEqual(paths, want) {
		t.Errorf("paths = %v, want %v", paths, want)
	}
}

// Validate keeps its multi-line shape, in check order, and is the cause of Parse's refusal. Its
// text is value-free like every validation message: it says what is expected, not what was found.
func TestValidateText(t *testing.T) {
	y := validYAML(t, "cookie:\n  prefix: none\nretention:\n  interval: 10s\n  events_max_rows: 5\n")
	c := &Config{}
	if err := yamlStrict([]byte(y), c); err != nil {
		t.Fatal(err)
	}
	applyDefaults(c)
	want := "config: refusing to boot:\n" +
		"  - cookie.prefix: must be __Host- or __Secure-\n" +
		"  - retention.interval: must be >= 1m\n" +
		"  - retention.events_max_rows: must be >= 1000"
	if err := c.Validate(); err == nil || err.Error() != want {
		t.Errorf("Validate() = %v\nwant %s", err, want)
	}
	_, err := Parse([]byte(y))
	var d *yamldiag.Diagnostics
	if !errors.As(err, &d) || d.Cause == nil || d.Cause.Error() != want {
		t.Errorf("Parse's refusal doesn't wrap Validate's error: %v", err)
	}
	ok := &Config{}
	if err := yamlStrict([]byte(validYAML(t, "")), ok); err != nil {
		t.Fatal(err)
	}
	applyDefaults(ok)
	if err := ok.Validate(); err != nil || len(ok.Problems()) != 0 {
		t.Errorf("a valid config: Validate() = %v, Problems() = %v", err, ok.Problems())
	}
}

// The server block's validators report every problem, not only their first.
func TestServerValidatorsReportAll(t *testing.T) {
	ps := problemsOf(t, "server:\n  deb_cache_dir: rel\n  build_concurrency: fast\n"+
		"  service_log_max_retain: 1m\n  service_log_max_lines: 5\n  service_log_max_disk_mb: 1\n"+
		"  file_roots:\n    - name: BAD\n      path: rel\n    - name: ok\n      path: /a\n    - name: ok\n      path: /b\n"+
		"  start_gate:\n    cpu_busy_pct: 5\n    cpu_settle_pct: 5000\n    max_settle: 1s\n    max_wait: 5s\n    service_settle: 1s\n    rollout_budget: 1s\n    deploy_wait: 2h\n")
	var got []string
	for _, p := range ps {
		got = append(got, p.Path)
	}
	want := []string{
		"server.file_roots[0].name", "server.file_roots[0].path", "server.file_roots[2].name",
		"server.deb_cache_dir", "server.build_concurrency",
		"server.service_log_max_retain", "server.service_log_max_lines", "server.service_log_max_disk_mb",
		"server.start_gate.settle_grace", "server.start_gate.cpu_busy_pct", "server.start_gate.cpu_settle_pct",
		"server.start_gate.max_settle", "server.start_gate.max_wait", "server.start_gate.deploy_wait",
		"server.start_gate.service_settle", "server.start_gate.rollout_budget",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("paths:\n got %v\nwant %v", got, want)
	}
}

// Problems can run again on a loaded config without doubling what it derives.
func TestProblemsRepeatable(t *testing.T) {
	cfg, err := Parse([]byte(validYAML(t, "trust_proxy: true\ntrusted_proxies: [\"192.0.2.1\"]\nbackups:\n  s3:\n    bucket: b\n")))
	if err != nil {
		t.Fatal(err)
	}
	allow, proxies, warns := len(cfg.Allowlist()), len(cfg.TrustedProxyPrefixes()), len(cfg.LoadWarnings)
	if allow != 1 || proxies != 1 {
		t.Fatalf("allowlist %d, proxies %d", allow, proxies)
	}
	if ps := cfg.Problems(); len(ps) != 0 {
		t.Fatalf("problems on a loaded config: %v", ps)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Allowlist()) != allow || len(cfg.TrustedProxyPrefixes()) != proxies || len(cfg.LoadWarnings) != warns {
		t.Errorf("after re-validating: allowlist %d, proxies %d, warnings %d (were %d, %d, %d)",
			len(cfg.Allowlist()), len(cfg.TrustedProxyPrefixes()), len(cfg.LoadWarnings), allow, proxies, warns)
	}
}

func TestAllowlistStringsCanonical(t *testing.T) {
	y := strings.ReplaceAll(validYAML(t, ""), "  - \"203.0.113.10/32\"\n",
		"  - \"198.51.100.7\"\n  - \"2001:db8::1\"\n  - \"203.0.113.77/24\"\n  - \"::ffff:192.0.2.9\"\n  - \" 192.0.2.200 \"\n  - \"::ffff:10.1.2.3/104\"\n")
	cfg, err := Parse([]byte(y))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"198.51.100.7/32", "2001:db8::1/128", "203.0.113.0/24", "192.0.2.9/32", "192.0.2.200/32", "10.0.0.0/8"}
	if got := cfg.AllowlistStrings(); !reflect.DeepEqual(got, want) {
		t.Errorf("AllowlistStrings = %v, want %v", got, want)
	}
	if got := (&Config{}).AllowlistStrings(); got == nil || len(got) != 0 {
		t.Errorf("no allowlist: %#v", got)
	}
}

func TestCertHostnames(t *testing.T) {
	names := func(ov string) []CertName {
		t.Helper()
		cfg, err := Parse([]byte(validYAML(t, ov)))
		if err != nil {
			t.Fatal(err)
		}
		return cfg.CertHostnames()
	}
	if got := names(""); len(got) != 0 {
		t.Errorf("no dashboard hostname, no dns01: %v", got)
	}
	if got, want := names("admin:\n  hostname: admin.example.com\n"), []CertName{{"admin.example.com", "the dashboard (admin.hostname)"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	// Without dns01 a base domain asks for no certificate of its own.
	if got, want := names("  base_domain: apps.example.com\n  base_domains:\n    - name: stg\n      domain: stg.example.com\nadmin:\n  subdomain: admin\n"),
		[]CertName{{"admin.apps.example.com", "the dashboard (admin.subdomain)"}}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	full := "  base_domain: apps.example.com\n  dns01:\n    provider: cloudflare\n    api_token: tok\n" +
		"  base_domains:\n    - name: stg\n      domain: stg.example.com\n      dns01:\n        provider: route53\n        api_token: tok2\n" +
		"    - name: plain\n      domain: plain.example.com\n" +
		"admin:\n  subdomain: admin\n"
	want := []CertName{
		{"admin.apps.example.com", "the dashboard (admin.subdomain)"},
		{"*.apps.example.com", "edge.base_domain (DNS-01 wildcard)"},
		{"*.stg.example.com", "base domain stg (DNS-01 wildcard)"},
	}
	if got := names(full); !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	// edge.mode external: Mooring runs no edge, so it requests nothing.
	ext := &Config{Edge: EdgeConfig{Mode: EdgeExternal, BaseDomain: "apps.example.com", DNS01: &EdgeDNS01{Provider: "cloudflare", APIToken: "t"}},
		Admin: AdminConfig{Hostname: "admin.example.com"}}
	if got := ext.CertHostnames(); got != nil {
		t.Errorf("external mode: %v", got)
	}
}

func TestRepeatedLabel(t *testing.T) {
	for _, tc := range []struct {
		sub, host, base, want string
	}{
		{"dns", "", "dns.example.com", "dns.dns.example.com"},
		{"DNS", "", "dns.Example.com", "dns.dns.example.com"},
		{"admin", "", "dns.example.com", ""},
		{"dns", "", "", ""},
		{"", "", "dns.example.com", ""},
		{"dns", "panel.example.com", "dns.example.com", ""}, // admin.hostname wins: the subdomain isn't used
		{"example", "", "dns.example.com", ""},              // only the first label counts
	} {
		c := &Config{Admin: AdminConfig{Subdomain: tc.sub, Hostname: tc.host}, Edge: EdgeConfig{BaseDomain: tc.base}}
		host, ok := c.RepeatedLabel()
		if host != tc.want || ok != (tc.want != "") {
			t.Errorf("subdomain %q under %q (hostname %q): %q %v, want %q", tc.sub, tc.base, tc.host, host, ok, tc.want)
		}
	}
}

// The reload set is exactly what a reload re-reads today: web.Server.Reload (internal/web/server.go)
// builds a new secState from ip_allowlist, trust_proxy, trusted_proxies, auth and users (and serve
// pushes ip_allowlist to the edge), and the SIGHUP handler in cmd/mooring/cmd_serve.go swaps the
// retention policy. Add a key here only together with the code that re-reads it on a reload:
// telling an operator "reload" for a key that needs a restart leaves the old value running.
func TestApplyModeReloadSet(t *testing.T) {
	wantReload := []string{"auth", "ip_allowlist", "retention", "trust_proxy", "trusted_proxies", "users"}
	var got []string
	typ := reflect.TypeOf(Config{})
	for i := 0; i < typ.NumField(); i++ {
		k := yamlKey(typ.Field(i))
		if k == "" {
			continue
		}
		if ApplyMode(k) == ApplyReload {
			got = append(got, k)
		} else if ApplyMode(k) != ApplyRestart {
			t.Errorf("ApplyMode(%q) = %q", k, ApplyMode(k))
		}
	}
	sort.Strings(got)
	if !reflect.DeepEqual(got, wantReload) {
		t.Errorf("reload keys = %v, want %v", got, wantReload)
	}
	for k := range reloadKeys {
		if !slices.Contains(got, k) {
			t.Errorf("reload key %q is not a config.yaml key", k)
		}
	}
	for path, want := range map[string]string{
		"auth.totp_secret": ApplyReload, "users[1].role": ApplyReload, "retention.interval": ApplyReload, "ip_allowlist[0]": ApplyReload,
		"edge.base_domains": ApplyRestart, "edge.trusted_proxies": ApplyRestart, "admin.hostname": ApplyRestart,
		"encryption_key": ApplyRestart, "bind_addr": ApplyRestart, "alerting.enabled": ApplyRestart,
		"security_logs.response.mode": ApplyRestart, "session.idle_timeout": ApplyRestart,
		"": ApplyRestart, "no_such_key": ApplyRestart, "authx": ApplyRestart, "retention_extra.x": ApplyRestart,
	} {
		if got := ApplyMode(path); got != want {
			t.Errorf("ApplyMode(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestDiffApply(t *testing.T) {
	load := func(ov string) *Config {
		t.Helper()
		cfg, err := Parse([]byte(validYAML(t, ov)))
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}
	old := load("")
	if reload, restart := DiffApply(old, load("")); reload != nil || restart != nil {
		t.Errorf("no change: %v %v", reload, restart)
	}
	updated := load("  base_domain: apps.example.com\n  l4_enabled: true\n" +
		"users:\n  - username: bob\n    password_hash: \"" + old.Auth.PasswordHash + "\"\n    role: viewer\n" +
		"retention:\n  events_max_rows: 5000\n" +
		"server:\n  disk_gc_enabled: false\n  start_gate:\n    max_wait: 5m\n" +
		"security_logs:\n  response:\n    mode: recommend\n" +
		"alerting:\n  enabled: true\n" +
		"session:\n  idle_timeout: 30m\n" +
		"admin:\n  subdomain: admin\n" +
		"trust_proxy: true\ntrusted_proxies: [\"192.0.2.1\"]\n")
	updated.IPAllowlist = append(updated.IPAllowlist, "198.51.100.7")
	reload, restart := DiffApply(old, updated)
	if want := []string{"ip_allowlist", "retention", "trust_proxy", "trusted_proxies", "users"}; !reflect.DeepEqual(reload, want) {
		t.Errorf("reload = %v, want %v", reload, want)
	}
	if want := []string{"admin", "alerting.enabled", "edge.base_domain", "edge.l4_enabled", "security_logs.response", "server.disk_gc_enabled", "server.start_gate", "session"}; !reflect.DeepEqual(restart, want) {
		t.Errorf("restart = %v, want %v", restart, want)
	}
	// Symmetric, and only what the file says counts: derived state and load warnings are not keys.
	if r2, s2 := DiffApply(updated, old); !reflect.DeepEqual(r2, reload) || !reflect.DeepEqual(s2, restart) {
		t.Errorf("reversed: %v %v", r2, s2)
	}
	same := load("")
	same.LoadWarnings = append(same.LoadWarnings, "x")
	same.parsedAllowlist = nil
	if reload, restart := DiffApply(old, same); reload != nil || restart != nil {
		t.Errorf("derived state reported as a change: %v %v", reload, restart)
	}
	if reload, restart := DiffApply(nil, nil); reload != nil || restart != nil {
		t.Errorf("nil configs: %v %v", reload, restart)
	}
}

// yamldiagReady reports whether internal/yamldiag explains files yet (it was a contract stub while
// this package's diagnostics were written); the tests below need its real positions and messages.
func yamldiagReady() bool {
	d := yamldiag.Explain([]byte("a: 1\n  b: 2\n"), reflect.TypeOf(Config{}), errors.New("yaml: line 2: mapping values are not allowed in this context"), yamldiag.Options{File: "probe.yaml"})
	return d != nil && len(d.Problems) > 0
}

func diagnosticsOf(t *testing.T, y string) *yamldiag.Diagnostics {
	t.Helper()
	cfg, err := Parse([]byte(y))
	var d *yamldiag.Diagnostics
	if cfg != nil || !errors.As(err, &d) {
		t.Fatalf("Parse = %v, %v; want a refusal with diagnostics", cfg, err)
	}
	if e := err.Error(); e == "" || strings.ContainsAny(e, "\r\n") {
		t.Errorf("Error() must be one non-empty line: %q", e)
	}
	return d
}

// The one-line forms callers log and wrap.
func TestRefusalErrorShapes(t *testing.T) {
	if !yamldiagReady() {
		t.Skip("internal/yamldiag is still the contract stub")
	}
	// One validation problem (validYAML starts with an empty line: retention is on line 13).
	d := diagnosticsOf(t, validYAML(t, "retention:\n  interval: 10s\n"))
	if got, want := d.Error(), "config.yaml:14:13: retention.interval: must be >= 1m"; got != want {
		t.Errorf("one problem:\n got %q\nwant %q", got, want)
	}
	// Several: the first in file order, and how many more.
	d = diagnosticsOf(t, validYAML(t, "retention:\n  interval: 10s\n  events_max_rows: 5\ncookie:\n  prefix: none\n"))
	if got, want := d.Error(), "config.yaml:14:13: retention.interval: must be >= 1m; 2 more problems"; got != want {
		t.Errorf("three problems:\n got %q\nwant %q", got, want)
	}
	if len(d.Problems) != 3 {
		t.Errorf("problems: %+v", d.Problems)
	}
	// A problem about a key the file doesn't have is placed at its nearest parent.
	d = diagnosticsOf(t, strings.Replace(validYAML(t, ""), "  acme_email: \"ops@example.com\"\n", "", 1))
	if got, want := d.Error(), "config.yaml:9:1: edge.acme_email: required in managed mode (ACME contact); fail-closed"; got != want {
		t.Errorf("missing key:\n got %q\nwant %q", got, want)
	}
	// A file the strict decode refuses.
	d = diagnosticsOf(t, validYAML(t, "edgee:\n  mode: managed\n"))
	if got, want := d.Error(), `config.yaml:13:1: unknown key on this line (hint: did you mean edge?)`; got != want {
		t.Errorf("unknown key:\n got %q\nwant %q", got, want)
	}
	if d.Cause == nil || !strings.HasPrefix(d.Cause.Error(), "config: parse: yaml: ") {
		t.Errorf("cause = %v", d.Cause)
	}
	// A file with no settings says so (the decoder's own word for it is "EOF").
	for _, y := range []string{"", "# only a comment\n", "\n\n"} {
		d = diagnosticsOf(t, y)
		if got, want := d.Error(), "config.yaml: the file is empty (hint: it has no settings, only blank lines or comments)"; got != want {
			t.Errorf("empty file %q:\n got %q\nwant %q", y, got, want)
		}
		if d.Cause == nil || d.Cause.Error() != "config: parse: EOF" {
			t.Errorf("empty file %q: cause = %v", y, d.Cause)
		}
	}
}

// Owner decision: a quoted boolean stays refused, with a message that says what to change.
func TestQuotedBooleanRefusedWithClearMessage(t *testing.T) {
	for _, ov := range []string{"trust_proxy: \"true\"\n", "trust_proxy: 'false'\n", "server:\n  disk_gc_enabled: \"false\"\n", "backups:\n  enabled: \"true\"\n"} {
		if _, err := Parse([]byte(validYAML(t, ov))); err == nil {
			t.Fatalf("%q was accepted", ov)
		}
	}
	if !yamldiagReady() {
		t.Skip("internal/yamldiag is still the contract stub")
	}
	d := diagnosticsOf(t, validYAML(t, "server:\n  disk_gc_enabled: \"false\"\n"))
	if len(d.Problems) != 1 {
		t.Fatalf("problems: %+v", d.Problems)
	}
	p := d.Problems[0]
	if p.Kind != yamldiag.KindType || p.Path != "server.disk_gc_enabled" || p.Line != 14 ||
		!strings.Contains(p.Msg, "must be true or false without quotes") || p.Hint == "" {
		t.Errorf("problem: %+v", p)
	}
}

// Load names the file by its path; Parse says config.yaml.
func TestLoadNamesTheFile(t *testing.T) {
	t.Setenv(DevInsecurePermsEnv, "1")
	path := filepath.Join(t.TempDir(), "mooring-config.yaml")
	if err := os.WriteFile(path, []byte(validYAML(t, "retention:\n  interval: 10s\n")), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	var d *yamldiag.Diagnostics
	if cfg != nil || !errors.As(err, &d) {
		t.Fatalf("Load = %v, %v", cfg, err)
	}
	if d.File != path {
		t.Errorf("File = %q, want %q", d.File, path)
	}
	if _, err := ParseNamed([]byte("nope: 1\n"), "/etc/mooring/config.yaml"); !errors.As(err, &d) || d.File != "/etc/mooring/config.yaml" {
		t.Errorf("ParseNamed: %v", err)
	}
	_, err = Parse([]byte("nope: 1\n"))
	if !errors.As(err, &d) || d.File != "config.yaml" {
		t.Errorf("Parse: %v", err)
	}
	if yamldiagReady() && !strings.HasPrefix(err.Error(), "config.yaml:1:1: ") {
		t.Errorf("Parse error %q", err)
	}
	// A file that can't be read or has the wrong mode is refused before it is parsed, as before.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || errors.As(err, &d) || !strings.Contains(err.Error(), "must not be world-accessible") {
		t.Errorf("world-readable file: %v", err)
	}
}

// Abuse: config.yaml holds the master key, password hashes and tokens, and a refusal reaches the
// journal. No form of the refusal shows a secret value, wherever the problem is.
func TestRefusalNeverShowsSecrets(t *testing.T) {
	if !yamldiagReady() {
		t.Skip("internal/yamldiag is still the contract stub")
	}
	secrets := []string{"S3CR3T-KEY-PREV", "S3CR3T-TOKEN", "S3CR3T-NS-TOKEN", "S3CR3T-HASH", "S3CR3T-TOTP", "S3CR3T-S3-ID",
		"S3CR3T-S3-KEY", "S3CR3T-GH", "S3CR3T-DEADMAN", "S3CR3T-ARCHIVE-KEY", "S3CR3T-OWNER-TOTP", "S3CR3T-BUCKET"}
	body := "encryption_key_previous: \"S3CR3T-KEY-PREV\"\n" +
		"users:\n  - username: bob\n    password_hash: \"S3CR3T-HASH\"\n    totp_secret: \"S3CR3T-TOTP\"\n    role: viewer\n" +
		"github:\n  client_id: \"S3CR3T-GH\"\n  client_secret: \"S3CR3T-GH\"\n" +
		"alerting:\n  dead_mans_url: \"https://hc.example/S3CR3T-DEADMAN\"\n" +
		"backups:\n  enabled: true\n  s3:\n    bucket: \"S3CR3T-BUCKET\"\n    access_key_id: \"S3CR3T-S3-ID\"\n    secret_access_key: \"S3CR3T-S3-KEY\"\n" +
		"security_logs:\n  archive:\n    s3:\n      bucket: b\n      secret_access_key: \"S3CR3T-ARCHIVE-KEY\"\n"
	edgeSecrets := "  base_domain: apps.example.com\n  dns01:\n    provider: \"Bad Provider\"\n    api_token: \"S3CR3T-TOKEN\"\n" +
		"  base_domains:\n    - name: stg\n      domain: stg.example.com\n      dns01:\n        provider: \"Bad Provider\"\n        api_token: \"S3CR3T-NS-TOKEN\"\n"
	withTOTP := func(y string) string {
		return strings.Replace(y, "  username: \"operator\"\n", "  username: \"operator\"\n  totp_secret: \"S3CR3T-OWNER-TOTP\"\n", 1)
	}
	for name, y := range map[string]string{
		// Validation problems on and next to every secret line.
		"validation": withTOTP(validYAML(t, edgeSecrets+body)),
		// The same file with an unknown key, a quoted boolean, a bad indent and a tab after the secrets.
		"unknown key":    withTOTP(validYAML(t, edgeSecrets+body+"sekret_extra: 1\n")),
		"quoted boolean": withTOTP(validYAML(t, edgeSecrets+body+"trust_proxy: \"true\"\n")),
		"indentation":    withTOTP(validYAML(t, edgeSecrets+body+"session:\n  idle_timeout: 5m\n   absolute_timeout: 1h\n")),
		"tab":            withTOTP(validYAML(t, edgeSecrets+body+"session:\n\tidle_timeout: 5m\n")),
		// The problem is ON a secret line.
		"secret line indent":  withTOTP(validYAML(t, edgeSecrets+"github:\n  client_id: x\n   client_secret: \"S3CR3T-GH\"\n")),
		"secret wrong type":   withTOTP(validYAML(t, edgeSecrets+"alerting:\n  dead_mans_url: [\"S3CR3T-DEADMAN\"]\n")),
		"secret under a typo": withTOTP(validYAML(t, edgeSecrets+"githubb:\n  client_secret: \"S3CR3T-GH\"\n")),
		"duplicate secret":    withTOTP(validYAML(t, edgeSecrets+"encryption_key_previous: \"S3CR3T-KEY-PREV\"\nencryption_key_previous: \"S3CR3T-KEY-PREV\"\n")),
	} {
		d := diagnosticsOf(t, y)
		if len(d.Problems) == 0 {
			t.Errorf("%s: nothing explained (%v)", name, d)
		}
		shown := d.Error() + "\n" + d.Terminal() + "\n" + string(d.JSON())
		for _, s := range secrets {
			if strings.Contains(shown, s) {
				t.Errorf("%s: the refusal shows %s:\n%s", name, s, shown)
			}
		}
	}
	// Owner decision 2026-11-25: no key is "safe" — a number or a duration is masked like any other
	// value, and the key, the line and the message are what is shown.
	d := diagnosticsOf(t, validYAML(t, "retention:\n  interval: 10s\n"))
	if out := d.Terminal(); strings.Contains(out, "10s") || !strings.Contains(out, "config.yaml:14:13: retention.interval: must be >= 1m\n  13 | retention:\n  14 |   interval: …\n") {
		t.Errorf("a refused duration:\n%s", out)
	}
}

// A mistyped duration is reported at its own line and column: the duration type decodes itself, so
// its error has to carry them for the diagnostics to place it. The message names the key and never
// the value.
func TestInvalidDurationHasItsLine(t *testing.T) {
	yml := validYAML(t, "retention:\n  interval: ten-ZQXpasted\n")
	_, err := ParseNamed([]byte(yml), "config.yaml")
	if err == nil {
		t.Fatal("an invalid duration was accepted")
	}
	line := strings.Count(yml[:strings.Index(yml, "interval: ten")], "\n") + 1
	want := "config.yaml:" + strconv.Itoa(line) + ":13: retention.interval is not a valid duration: use a number and a unit like 30s, 5m, 12h or 30d"
	if got := err.Error(); got != want {
		t.Errorf("error = %q\n want %q", got, want)
	}
	var d *yamldiag.Diagnostics
	if !errors.As(err, &d) || len(d.Problems) != 1 || d.Problems[0].Excerpt != "  interval: …" || d.Problems[0].Path != "retention.interval" {
		t.Fatalf("problems: %+v", d)
	}
	if shown := d.Error() + d.Terminal() + string(d.JSON()); strings.Contains(shown, "ZQX") {
		t.Errorf("the value is shown:\n%s", shown)
	}
	// The decoder's own text is value-free too (it is the cause, and what a wrapper may print).
	if cause := d.Cause.Error(); strings.Contains(cause, "ZQX") || !strings.Contains(cause, "line "+strconv.Itoa(line)+", column 13: not a valid duration") {
		t.Errorf("cause = %q", cause)
	}
	var dur Duration
	if err := yaml.Unmarshal([]byte("ZQXpasted"), &dur); err == nil || strings.Contains(err.Error(), "ZQX") {
		t.Errorf("Duration.UnmarshalYAML: %v", err)
	}
}
