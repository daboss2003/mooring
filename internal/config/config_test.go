package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/crypto"
)

// validBase builds a minimal YAML config with a real key + password hash, then
// lets each test mutate one field to assert the fail-closed boot check fires.
func validYAML(t *testing.T, overrides string) string {
	t.Helper()
	hash, err := crypto.HashPassword([]byte("a-strong-password"), crypto.DefaultArgon2Params)
	if err != nil {
		t.Fatal(err)
	}
	// 32-byte key, base64
	key := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" // 32 zero bytes
	base := `
bind_addr: "127.0.0.1:9000"
encryption_key: "` + key + `"
ip_allowlist:
  - "203.0.113.10/32"
auth:
  username: "operator"
  password_hash: "` + hash + `"
edge:
  mode: "managed"
  acme_email: "ops@example.com"
  acme_ca: "https://acme.example/directory"
`
	return base + overrides
}

func mustReject(t *testing.T, yaml, wantSubstr string) {
	t.Helper()
	_, err := Parse([]byte(yaml))
	if err == nil {
		t.Fatalf("expected rejection containing %q, but config was accepted", wantSubstr)
	}
	if !strings.Contains(err.Error(), wantSubstr) {
		t.Fatalf("error %q does not mention %q", err.Error(), wantSubstr)
	}
}

func TestEdgeCAsValidatedAndParsed(t *testing.T) {
	// A valid private CA parses + is queryable by name.
	cfg, err := Parse([]byte(validYAML(t, "  cas:\n    - name: internal\n      directory_url: \"https://ca.lan/acme/acme/directory\"\n      email: \"pki@lan\"\n")))
	if err != nil {
		t.Fatalf("valid edge.cas rejected: %v", err)
	}
	ca, ok := cfg.EdgeCAByName("internal")
	if !ok || ca.DirectoryURL != "https://ca.lan/acme/acme/directory" || ca.Email != "pki@lan" {
		t.Errorf("EdgeCAByName wrong: %+v ok=%v", ca, ok)
	}
	if cfg.HasEdgeCA("nope") {
		t.Error("HasEdgeCA should be false for an undefined CA")
	}
	// Bad name, non-https URL, and duplicate names are rejected.
	mustReject(t, validYAML(t, "  cas:\n    - name: \"Bad Name\"\n      directory_url: \"https://x/d\"\n"), "name")
	mustReject(t, validYAML(t, "  cas:\n    - name: internal\n      directory_url: \"http://insecure/d\"\n"), "directory_url")
	mustReject(t, validYAML(t, "  cas:\n    - name: a\n      directory_url: \"https://x/d\"\n    - name: a\n      directory_url: \"https://y/d\"\n"), "duplicate")
	mustReject(t, validYAML(t, "  cas:\n    - name: internal\n      directory_url: \"https://x/d\"\n      trusted_root: \"/no/such/file.pem\"\n"), "trusted_root")
}

func TestEdgeBaseDomainsValidatedAndResolved(t *testing.T) {
	ov := "  base_domain: \"prod.example.com\"\n" +
		"  base_domains:\n" +
		"    - name: staging\n      domain: \"staging.example.com\"\n" +
		"    - name: edge\n      domain: \"edge.example.com\"\n      dns01:\n        provider: cloudflare\n        api_token: \"tok\"\n"
	cfg, err := Parse([]byte(validYAML(t, ov)))
	if err != nil {
		t.Fatalf("valid edge.base_domains rejected: %v", err)
	}
	// The empty name is the DEFAULT namespace — the scalar edge.base_domain.
	if bd, ok := cfg.BaseDomainByName(""); !ok || bd.Domain != "prod.example.com" {
		t.Errorf("default namespace resolve = %+v ok=%v, want prod.example.com", bd, ok)
	}
	if bd, ok := cfg.BaseDomainByName("staging"); !ok || bd.Domain != "staging.example.com" {
		t.Errorf("staging resolve = %+v ok=%v", bd, ok)
	}
	// A named namespace carries its own dns01.
	if bd, ok := cfg.BaseDomainByName("edge"); !ok || bd.DNS01 == nil || bd.DNS01.Provider != "cloudflare" {
		t.Errorf("edge namespace dns01 not carried: %+v ok=%v", bd, ok)
	}
	if !cfg.HasBaseDomain("staging") || cfg.HasBaseDomain("ghost") {
		t.Error("HasBaseDomain wrong")
	}
	// With no base_domain scalar set, the default namespace does not resolve.
	bare, err := Parse([]byte(validYAML(t, "")))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := bare.BaseDomainByName(""); ok {
		t.Error("default namespace must be unresolved when edge.base_domain is empty")
	}

	// Rejections: bad name, invalid domain, duplicate name, duplicate/nested domain, nesting the
	// default scalar, and dns01 missing its token.
	mustReject(t, validYAML(t, "  base_domains:\n    - name: \"Bad Name\"\n      domain: \"x.example.com\"\n"), "name")
	mustReject(t, validYAML(t, "  base_domains:\n    - name: ok\n      domain: \"not a domain\"\n"), "domain")
	mustReject(t, validYAML(t, "  base_domains:\n    - name: a\n      domain: \"a.example.com\"\n    - name: a\n      domain: \"b.example.com\"\n"), "duplicate name")
	mustReject(t, validYAML(t, "  base_domains:\n    - name: a\n      domain: \"dup.example.com\"\n    - name: b\n      domain: \"dup.example.com\"\n"), "duplicates")
	mustReject(t, validYAML(t, "  base_domains:\n    - name: a\n      domain: \"example.com\"\n    - name: b\n      domain: \"sub.example.com\"\n"), "nests")
	mustReject(t, validYAML(t, "  base_domain: \"example.com\"\n  base_domains:\n    - name: b\n      domain: \"sub.example.com\"\n"), "nests")
	mustReject(t, validYAML(t, "  base_domains:\n    - name: a\n      domain: \"a.example.com\"\n      dns01:\n        provider: cloudflare\n"), "api_token")
}

// Hardening from the Phase-1 adversarial review.
func TestEdgeBaseDomainsHardening(t *testing.T) {
	// (1) An uppercase apex is rejected at validation — consistent with the scalar base_domain,
	// instead of being silently lowercased.
	mustReject(t, validYAML(t, "  base_domains:\n    - name: a\n      domain: \"Staging.Example.com\"\n"), "lowercase FQDN")

	// (2) BaseDomainByName normalizes (trim + lowercase) whatever is stored, so every expansion
	// site produces a well-formed, case-consistent apex.
	c := &Config{Edge: EdgeConfig{BaseDomains: []EdgeBaseDomain{{Name: "s", Domain: "  Staging.Example.COM  "}}}}
	if bd, ok := c.BaseDomainByName("s"); !ok || bd.Domain != "staging.example.com" {
		t.Errorf("BaseDomainByName should normalize the apex, got %q ok=%v", bd.Domain, ok)
	}

	// (3) Admin must not sit on a NAMED namespace apex (apex-HSTS hazard), not just the scalar.
	mustReject(t, validYAML(t, "  base_domains:\n    - name: staging\n      domain: \"staging.example.com\"\nadmin:\n  hostname: \"staging.example.com\"\n"), "apex")
}

// NamespaceForHost maps an expanded (literal) hostname back to the namespace it belongs to —
// used by preview pinning to recover a base app's namespace from its stored hostnames.
func TestNamespaceForHost(t *testing.T) {
	c := &Config{Edge: EdgeConfig{
		BaseDomain:  "prod.example.com",
		BaseDomains: []EdgeBaseDomain{{Name: "staging", Domain: "staging.example.com"}},
	}}
	cases := []struct {
		host, name string
		ok         bool
	}{
		{"api.prod.example.com", "", true},           // default namespace
		{"api.staging.example.com", "staging", true}, // named namespace
		{"prod.example.com", "", false},              // an apex is NOT one-label-under itself
		{"a.b.staging.example.com", "", false},       // two labels below → not covered
		{"api.other.com", "", false},                 // off every namespace
	}
	for _, tc := range cases {
		if name, ok := c.NamespaceForHost(tc.host); ok != tc.ok || name != tc.name {
			t.Errorf("NamespaceForHost(%q) = (%q,%v), want (%q,%v)", tc.host, name, ok, tc.name, tc.ok)
		}
	}
}

func TestServerTabConfigValidated(t *testing.T) {
	// A valid server block parses.
	cfg, err := Parse([]byte(validYAML(t, "server:\n  deb_cache_dir: \"/root/dl\"\n  file_roots:\n    - name: logs\n      path: \"/var/log/app\"\n")))
	if err != nil {
		t.Fatalf("valid server config rejected: %v", err)
	}
	if cfg.Server.DebCacheDir != "/root/dl" || len(cfg.Server.FileRoots) != 1 || cfg.Server.FileRoots[0].Name != "logs" {
		t.Errorf("server config not parsed: %+v", cfg.Server)
	}
	// Bad root name, relative paths, and duplicate names are rejected.
	mustReject(t, validYAML(t, "server:\n  file_roots:\n    - name: \"Bad Name\"\n      path: \"/x\"\n"), "file_roots")
	mustReject(t, validYAML(t, "server:\n  file_roots:\n    - name: logs\n      path: \"relative/dir\"\n"), "absolute")
	mustReject(t, validYAML(t, "server:\n  file_roots:\n    - name: a\n      path: \"/x\"\n    - name: a\n      path: \"/y\"\n"), "duplicate")
	mustReject(t, validYAML(t, "server:\n  deb_cache_dir: \"relative\"\n"), "absolute")
}

func TestServerChecksDefaultOn(t *testing.T) {
	// Unset → both checks default ON.
	cfg, err := Parse([]byte(validYAML(t, "")))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Server.VersionCheckOn() || !cfg.Server.ImageScanOn() {
		t.Error("version check + image scan must default ON when unset")
	}
	// Explicit false → OFF.
	off, err := Parse([]byte(validYAML(t, "server:\n  version_check_enabled: false\n  image_scan_enabled: false\n")))
	if err != nil {
		t.Fatal(err)
	}
	if off.Server.VersionCheckOn() || off.Server.ImageScanOn() {
		t.Error("explicit false must disable both checks")
	}
	// Explicit true → ON.
	on, err := Parse([]byte(validYAML(t, "server:\n  version_check_enabled: true\n")))
	if err != nil {
		t.Fatal(err)
	}
	if !on.Server.VersionCheckOn() {
		t.Error("explicit true must enable")
	}
}

func TestValidConfigLoads(t *testing.T) {
	cfg, err := Parse([]byte(validYAML(t, "")))
	if err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if cfg.Edge.Mode != EdgeManaged {
		t.Errorf("default edge mode not managed")
	}
	if len(cfg.Allowlist()) != 1 {
		t.Errorf("allowlist not parsed")
	}
	if cfg.Cookie.Prefix != "__Host-" {
		t.Errorf("default cookie prefix not __Host-")
	}
	// Turnkey default (key omitted): connected-repo auto-fetch is ON (2 min) so
	// connecting a repo in the dashboard "just works" with no webhook.
	if cfg.Git.PollIntervalD() != 2*time.Minute {
		t.Errorf("git poll interval default = %v, want 2m", cfg.Git.PollIntervalD())
	}
}

// An EXPLICIT poll_interval: 0 disables polling (must not collapse into the default).
func TestGitPollZeroDisables(t *testing.T) {
	cfg, err := Parse([]byte(validYAML(t, "git:\n  poll_interval: \"0s\"\n")))
	if err != nil {
		t.Fatalf("config with git poll 0 rejected: %v", err)
	}
	if cfg.Git.PollIntervalD() != 0 {
		t.Errorf("explicit poll_interval 0 must disable polling, got %v", cfg.Git.PollIntervalD())
	}
}

func TestGitPollNegativeDisablesIsPreserved(t *testing.T) {
	cfg, err := Parse([]byte(validYAML(t, "git:\n  poll_interval: \"-1s\"\n")))
	if err != nil {
		t.Fatalf("config with negative git poll rejected: %v", err)
	}
	if cfg.Git.PollIntervalD() >= 0 {
		t.Errorf("a negative git poll_interval must be preserved (disables polling), got %v", cfg.Git.PollIntervalD())
	}
}

func TestEmptyAllowlistRefused(t *testing.T) {
	y := `
bind_addr: "127.0.0.1:9000"
encryption_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
ip_allowlist: []
auth:
  username: "operator"
  password_hash: "$argon2id$v=19$m=8192,t=2,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaA"
edge:
  mode: "managed"
  acme_email: "ops@example.com"
  acme_ca: "https://acme.example/directory"
`
	mustReject(t, y, "ip_allowlist: empty")
}

func TestNonLoopbackBindRefused(t *testing.T) {
	mustReject(t, validYAML(t, `
`)+"\nbind_addr: \"0.0.0.0:9000\"\n", "bind_addr")
}

func TestManagedRequiresACMEEmail(t *testing.T) {
	y := `
bind_addr: "127.0.0.1:9000"
encryption_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
ip_allowlist:
  - "203.0.113.10/32"
auth:
  username: "operator"
  password_hash: "` + mustHash(t) + `"
edge:
  mode: "managed"
  acme_ca: "https://acme.example/directory"
`
	mustReject(t, y, "edge.acme_email")
}

func TestBadKeyLengthRefused(t *testing.T) {
	y := `
bind_addr: "127.0.0.1:9000"
encryption_key: "c2hvcnQ="
ip_allowlist:
  - "203.0.113.10/32"
auth:
  username: "operator"
  password_hash: "` + mustHash(t) + `"
edge:
  mode: "managed"
  acme_email: "ops@example.com"
  acme_ca: "https://acme.example/directory"
`
	mustReject(t, y, "encryption_key")
}

func TestTrustedProxyTooBroadRefused(t *testing.T) {
	mustReject(t, validYAML(t, `
trust_proxy: true
trusted_proxies:
  - "10.0.0.0/8"
`), "too broad")
}

func TestTrustProxyWithoutProxiesRefused(t *testing.T) {
	mustReject(t, validYAML(t, `
trust_proxy: true
`), "trusted_proxies is empty")
}

func TestUnknownKeyRefused(t *testing.T) {
	mustReject(t, validYAML(t, `
totally_unknown_key: "smuggled"
`), "parse")
}

func TestInvalidPasswordHashRefused(t *testing.T) {
	y := `
bind_addr: "127.0.0.1:9000"
encryption_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
ip_allowlist:
  - "203.0.113.10/32"
auth:
  username: "operator"
  password_hash: "not-a-real-hash"
edge:
  mode: "managed"
  acme_email: "ops@example.com"
  acme_ca: "https://acme.example/directory"
`
	mustReject(t, y, "auth.password_hash")
}

func TestCookieSecurePrefixRequiresBasePath(t *testing.T) {
	mustReject(t, validYAML(t, `
cookie:
  prefix: "__Secure-"
`), "requires cookie.base_path")
}

func mustHash(t *testing.T) string {
	t.Helper()
	h, err := crypto.HashPassword([]byte("a-strong-password"), crypto.DefaultArgon2Params)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestTrustedProxyOverlapsAllowlistRefused(t *testing.T) {
	// validYAML's allowlist is 203.0.113.10/32; trusting the same IP must reject.
	mustReject(t, validYAML(t, `
trust_proxy: true
trusted_proxies:
  - "203.0.113.10/32"
`), "overlaps")
}

func TestParsePrefixCanonicalizes4in6(t *testing.T) {
	p, err := parsePrefix("::ffff:203.0.113.7/128")
	if err != nil {
		t.Fatal(err)
	}
	if p.Addr().Is4In6() {
		t.Errorf("4in6 prefix was not unmapped: %v", p)
	}
	if !p.Contains(netip.MustParseAddr("203.0.113.7")) {
		t.Errorf("canonicalized prefix %v does not contain the plain-v4 peer", p)
	}
	// The whole-IPv4-space 4in6 form must be flagged too broad (review #3).
	bp, err := parsePrefix("::ffff:0.0.0.0/96")
	if err != nil {
		t.Fatal(err)
	}
	if !tooBroad(bp) {
		t.Errorf("::ffff:0.0.0.0/96 (entire IPv4 space) not flagged too broad: %v", bp)
	}
}

func TestCheckPermsRejectsWorldAccess(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := checkPerms(p); err == nil {
		t.Error("checkPerms accepted a world-readable (0644) config")
	}
}

func TestCheckPermsRejectsNonRootOwnerUnlessDevHatch(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; the owner check passes trivially")
	}
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(p, 0o600)
	t.Setenv(DevInsecurePermsEnv, "") // ensure the hatch is off
	if err := checkPerms(p); err == nil {
		t.Error("checkPerms accepted a non-root-owned config (root-of-trust bypass)")
	}
	t.Setenv(DevInsecurePermsEnv, "1")
	if err := checkPerms(p); err != nil {
		t.Errorf("dev escape hatch did not relax the owner check: %v", err)
	}
}

func TestBuildCacheKeepSize(t *testing.T) {
	bp := func(b bool) *bool { return &b }
	cases := []struct {
		in   string
		want string
	}{
		{"", "5GB"},                  // unset → default
		{"2GB", "2GB"},               // valid
		{"512MB", "512MB"},           // valid
		{"10gb", "10gb"},             // case-insensitive
		{"1073741824", "1073741824"}, // raw bytes
		{"5 GB", "5GB"},              // interior space rejected → default (a working prune)
		{"lots", "5GB"},              // garbage → default
		{"5GB; rm -rf /", "5GB"},     // never trust it → default
	}
	for _, c := range cases {
		got := ServerConfig{BuildCacheKeep: c.in}.BuildCacheKeepSize()
		if got != c.want {
			t.Errorf("BuildCacheKeepSize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// Default-on semantics.
	if !(ServerConfig{}).BuildCacheGCOn() {
		t.Error("build-cache GC must be ON by default (unset)")
	}
	if (ServerConfig{BuildCacheKeepEnabled: bp(false)}).BuildCacheGCOn() {
		t.Error("explicit false must disable build-cache GC")
	}
}

func TestAdminHostnameResolved(t *testing.T) {
	// explicit hostname wins
	c := &Config{Admin: AdminConfig{Hostname: "dash.example.com"}, Edge: EdgeConfig{BaseDomain: "mooring.example.com"}}
	if got := c.AdminHostnameResolved(); got != "dash.example.com" {
		t.Errorf("hostname: got %q", got)
	}
	// subdomain expands against base_domain
	c2 := &Config{Admin: AdminConfig{Subdomain: "admin"}, Edge: EdgeConfig{BaseDomain: "mooring.example.com"}}
	if got := c2.AdminHostnameResolved(); got != "admin.mooring.example.com" {
		t.Errorf("subdomain: got %q", got)
	}
	if !c2.AdminExposed() {
		t.Error("admin.subdomain should count as exposed")
	}
	// subdomain with NO base_domain → not resolved (not exposed)
	c3 := &Config{Admin: AdminConfig{Subdomain: "admin"}}
	if c3.AdminHostnameResolved() != "" || c3.AdminExposed() {
		t.Error("subdomain without base_domain must not resolve/expose")
	}
	// nothing set → loopback only
	c4 := &Config{}
	if c4.AdminExposed() {
		t.Error("default must be loopback-only (not exposed)")
	}
	// edge listen default
	if c4.AdminEdgeListen() != "127.0.0.1:9001" {
		t.Errorf("default edge_listen: got %q", c4.AdminEdgeListen())
	}
}
