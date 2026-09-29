package edge

import (
	"encoding/json"
	"strings"
	"testing"
)

func baseCfg() BaseConfig {
	return BaseConfig{
		AdminListen: "unix//run/mooring/caddy-admin.sock",
		ACMEEmail:   "ops@example.com", ACMECA: "https://acme.example/directory",
	}
}

func mustRender(t *testing.T, base BaseConfig, routes []Route) map[string]any {
	t.Helper()
	out, err := Render(base, routes, nil)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("render produced invalid JSON: %v", err)
	}
	return doc
}

// Routes opting into a named private CA get their own TLS automation policy (that CA's
// directory + trusted roots); everything else stays on the default issuer.
func TestRenderPerCAPolicies(t *testing.T) {
	base := baseCfg()
	base.CAs = []CA{{Name: "internal", DirectoryURL: "https://ca.lan/acme/acme/directory", Email: "pki@lan", TrustedRoots: []string{"/etc/mooring/internal-ca.pem"}}}
	out, err := Render(base, []Route{
		{Hostname: "pub.example.com", Upstream: "web:8080", UpstreamScheme: "http", Enabled: true},                 // default CA
		{Hostname: "api.lan", Upstream: "api:3000", UpstreamScheme: "http", Enabled: true, CA: "internal"},         // private CA
		{Hostname: "bad.example.com", Upstream: "x:80", UpstreamScheme: "http", Enabled: true, CA: "doesnotexist"}, // unknown → default
	}, []CertHost{{Hostname: "mqtt.lan", CA: "internal"}}) // cert-only, private CA
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Apps struct {
			TLS struct {
				Automation struct {
					Policies []struct {
						Subjects []string `json:"subjects"`
						Issuers  []struct {
							CA           string   `json:"ca"`
							Email        string   `json:"email"`
							TrustedRoots []string `json:"trusted_roots_pem_files"`
						} `json:"issuers"`
					} `json:"policies"`
				} `json:"automation"`
			} `json:"tls"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	pol := doc.Apps.TLS.Automation.Policies
	caBySubject := map[string]string{}
	rootsBySubject := map[string][]string{}
	for _, p := range pol {
		for _, s := range p.Subjects {
			caBySubject[s] = p.Issuers[0].CA
			rootsBySubject[s] = p.Issuers[0].TrustedRoots
		}
	}
	if caBySubject["api.lan"] != "https://ca.lan/acme/acme/directory" {
		t.Errorf("api.lan should use the private CA, got %q", caBySubject["api.lan"])
	}
	if caBySubject["mqtt.lan"] != "https://ca.lan/acme/acme/directory" {
		t.Errorf("cert-only mqtt.lan should use the private CA, got %q", caBySubject["mqtt.lan"])
	}
	if len(rootsBySubject["api.lan"]) != 1 || rootsBySubject["api.lan"][0] != "/etc/mooring/internal-ca.pem" {
		t.Errorf("api.lan missing the private CA trusted roots: %v", rootsBySubject["api.lan"])
	}
	if caBySubject["pub.example.com"] != "https://acme.example/directory" {
		t.Errorf("pub.example.com should use the default CA, got %q", caBySubject["pub.example.com"])
	}
	if caBySubject["bad.example.com"] != "https://acme.example/directory" {
		t.Errorf("unknown CA must fall back to the default issuer, got %q", caBySubject["bad.example.com"])
	}
	// The default-CA subjects must NOT carry the private CA's trusted roots.
	if len(rootsBySubject["pub.example.com"]) != 0 {
		t.Errorf("default-CA subject should have no trusted roots, got %v", rootsBySubject["pub.example.com"])
	}
}

// With no CAs configured/referenced, the render is unchanged: one policy, default issuer.
func TestRenderSingleCABackwardCompatible(t *testing.T) {
	out, err := Render(baseCfg(), []Route{{Hostname: "app.example.com", Upstream: "web:8080", UpstreamScheme: "http", Enabled: true}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(out), `"acme"`); n != 1 {
		t.Errorf("expected exactly one issuer for the single default CA, got %d", n)
	}
}

// A valid route renders an HTTPS vhost with a pinned ACME issuer + the catch-all
// 404, and admin stays on the unix socket with enforce_origin.
func TestRenderHappyPath(t *testing.T) {
	out, err := Render(baseCfg(), []Route{
		{Hostname: "app.example.com", Upstream: "shop-web:8080", Pool: []string{"172.18.0.5:8080"}, UpstreamScheme: "http", HSTS: true, SecurityHeaders: true, Enabled: true},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if strings.Contains(s, "shop-web:8080") {
		t.Errorf("the service-name selector must never be dialed:\n%s", s)
	}
	for _, want := range []string{"app.example.com", "172.18.0.5:8080", "reverse_proxy", "acme", "https://acme.example/directory", "enforce_origin", "static_response"} {
		if !strings.Contains(s, want) {
			t.Errorf("rendered config missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "on_demand") {
		t.Error("on-demand TLS must be off by default (SBD-3)")
	}
}

// SBD-4: an upstream targeting a control-plane port (or loopback) is rejected.
func TestRenderRejectsControlPlaneUpstream(t *testing.T) {
	for _, up := range []string{"127.0.0.1:9000", "10.0.0.5:2019", "host:2375", "127.0.0.1:8080", "169.254.169.254:80"} {
		_, err := Render(baseCfg(), []Route{{Hostname: "x.example.com", Upstream: up, UpstreamScheme: "http", Enabled: true}}, nil)
		if err == nil {
			t.Errorf("upstream %q should be rejected", up)
		}
	}
}

// SBD-4: an upstream HOSTNAME that resolves to loopback (localhost family) is
// rejected at validation, not just literal loopback IPs.
func TestRenderRejectsLoopbackHostnames(t *testing.T) {
	for _, up := range []string{"localhost:8080", "foo.localhost:8080", "ip6-localhost:8080", "LOCALHOST:8080"} {
		if _, err := Render(baseCfg(), []Route{{Hostname: "x.example.com", Upstream: up, UpstreamScheme: "http", Enabled: true}}, nil); err == nil {
			t.Errorf("loopback hostname upstream %q should be rejected", up)
		}
	}
	// A normal container-name upstream is still allowed.
	if _, err := Render(baseCfg(), []Route{{Hostname: "x.example.com", Upstream: "myapp-web:8080", UpstreamScheme: "http", Enabled: true}}, nil); err != nil {
		t.Errorf("a container-name upstream should be allowed: %v", err)
	}
}

// SBD-4: a wildcard / non-FQDN hostname (catch-all) is rejected.
func TestRenderRejectsWildcardHost(t *testing.T) {
	for _, h := range []string{"*.example.com", "*", "localhost", "no-dot", "UPPER.example.com"} {
		if _, err := Render(baseCfg(), []Route{{Hostname: h, Upstream: "web:80", UpstreamScheme: "http", Enabled: true}}, nil); err == nil {
			// UPPER is lowercased then validated; ensure non-FQDN/wildcards fail.
			if h != "UPPER.example.com" {
				t.Errorf("hostname %q should be rejected", h)
			}
		}
	}
}

// M14: a scaled route renders a least-conn pool with passive health checks, and
// every pool member is validated (a control-plane member is refused).
func TestRenderScaledPool(t *testing.T) {
	out, err := Render(baseCfg(), []Route{
		{Hostname: "app.example.com", Upstream: "web:8080", Pool: []string{"172.18.0.4:8080", "172.18.0.5:8080", "172.18.0.6:8080"}, UpstreamScheme: "http", Enabled: true},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{"172.18.0.4:8080", "172.18.0.5:8080", "172.18.0.6:8080", "least_conn", "passive", "max_fails"} {
		if !strings.Contains(s, want) {
			t.Errorf("scaled pool render missing %q:\n%s", want, s)
		}
	}
	// A pool member targeting a control-plane port is refused (SBD-4 over the pool).
	if _, err := Render(baseCfg(), []Route{
		{Hostname: "x.example.com", Pool: []string{"app-web-1:8080", "127.0.0.1:9000"}, UpstreamScheme: "http", Enabled: true},
	}, nil); err == nil {
		t.Error("a pool member targeting a control-plane port must be refused")
	}
}

// A single-upstream route does NOT get LB/health-check blocks (no pool).
func TestRenderSingleNoPoolMachinery(t *testing.T) {
	out, _ := Render(baseCfg(), []Route{{Hostname: "app.example.com", Upstream: "web:8080", UpstreamScheme: "http", Enabled: true}}, nil)
	if strings.Contains(string(out), "least_conn") || strings.Contains(string(out), "load_balancing") {
		t.Error("a single upstream must not render pool load-balancing machinery")
	}
}

// SBD-1: no admin vhost unless admin.hostname is set; when set it requires the IP
// allowlist as a matcher and pins the loopback admin upstream.
func TestRenderAdminVhostGating(t *testing.T) {
	// Default: no admin vhost (the host count = app subjects only).
	doc := mustRender(t, baseCfg(), []Route{{Hostname: "app.example.com", Upstream: "web:80", UpstreamScheme: "http", Enabled: true}})
	if strings.Contains(toJSON(doc), "9000") {
		t.Error("no admin upstream should appear without admin.hostname")
	}
	// admin.hostname without an allowlist → render error (SBD-1).
	b := baseCfg()
	b.AdminHostname = "admin.example.com"
	b.AdminUpstream = "127.0.0.1:9000"
	if _, err := Render(b, nil, nil); err == nil {
		t.Error("admin vhost without an IP allowlist must be rejected")
	}
	// With an allowlist → the admin vhost renders with the remote_ip matcher.
	b.AdminAllowlist = []string{"203.0.113.0/24"}
	out, err := Render(b, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "remote_ip") || !strings.Contains(s, "203.0.113.0/24") || !strings.Contains(s, "127.0.0.1:9000") {
		t.Errorf("admin vhost not rendered with allowlist+pinned upstream:\n%s", s)
	}
}

// An empty route set renders the safe recovery floor: no TLS automation, no
// proxy, just the 404 catch-all (SBD-8 base).
func TestRenderEmptyIsSafeFloor(t *testing.T) {
	out, err := Render(baseCfg(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "reverse_proxy") {
		t.Error("an empty config must proxy to nothing")
	}
	if strings.Contains(string(out), "acme") {
		t.Error("no ACME automation without configured hostnames")
	}
}

// XFF is overwritten to the real peer on every proxied route.
func TestRenderXFFOverwrite(t *testing.T) {
	out, _ := Render(baseCfg(), []Route{{Hostname: "app.example.com", Upstream: "web:80", Pool: []string{"172.18.0.5:80"}, UpstreamScheme: "http", Enabled: true}}, nil)
	if !strings.Contains(string(out), "X-Forwarded-For") || !strings.Contains(string(out), "{http.request.remote.host}") {
		t.Errorf("reverse_proxy must overwrite XFF to the real peer:\n%s", out)
	}
}

// A route with no container to dial (no pool, a service-name upstream, or marked Unroutable) answers a
// fixed 503 with Retry-After — never a name dial — and keeps its host matcher and ACME subject so the
// certificate keeps renewing.
func TestRenderUnroutableServes503AndKeepsCert(t *testing.T) {
	for _, rt := range []Route{
		{Hostname: "app.example.com", Upstream: "web:8080", UpstreamScheme: "http", Enabled: true},
		{Hostname: "app.example.com", Upstream: "web:8080", Pool: []string{"172.18.0.5:8080"}, Unroutable: true, UpstreamScheme: "http", Enabled: true},
	} {
		out, err := Render(baseCfg(), []Route{rt}, nil)
		if err != nil {
			t.Fatal(err)
		}
		s := strings.Join(strings.Fields(string(out)), "")
		if strings.Contains(s, `"dial":`) || strings.Contains(s, "reverse_proxy") {
			t.Errorf("an unroutable route must not proxy:\n%s", out)
		}
		for _, want := range []string{`"status_code":503`, `"Retry-After":["5"]`, `"body":"503ServiceUnavailable\n"`, `"automate":["app.example.com"]`} {
			if !strings.Contains(s, want) {
				t.Errorf("missing %s in:\n%s", want, out)
			}
		}
	}
}

// The selector is validated even though it is never dialed: an unsafe upstream is a render ERROR
// (SBD-4), not a quiet 503.
func TestRenderRejectsUnsafeSelectorWithoutPool(t *testing.T) {
	for _, up := range []string{"host:2375", "localhost:8080", "127.0.0.1:9000"} {
		if _, err := Render(baseCfg(), []Route{{Hostname: "app.example.com", Upstream: up, UpstreamScheme: "http", Enabled: true}}, nil); err == nil {
			t.Errorf("upstream %q must be rejected", up)
		}
	}
}

// A pool holds container IP addresses only; a name in a pool is a render error, so no caller can
// smuggle a name dial past the "never dial a name" rule.
func TestRenderRejectsNamePoolMember(t *testing.T) {
	for _, pool := range [][]string{{"web-2:8080"}, {"172.18.0.5:8080", "db:5432"}, {"172.18.0.5"}} {
		_, err := Render(baseCfg(), []Route{{Hostname: "app.example.com", Upstream: "web:8080", Pool: pool, UpstreamScheme: "http", Enabled: true}}, nil)
		if err == nil {
			t.Errorf("pool %v must be rejected", pool)
		}
	}
}

func toJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

// A cert-only subject is issued (ACME) but gets NO proxy route — a consumer app
// (e.g. an MQTT broker) terminates TLS itself with the synced cert.
func TestRenderCertOnlySubject(t *testing.T) {
	out, err := Render(baseCfg(), []Route{
		{Hostname: "app.example.com", Upstream: "web:8080", UpstreamScheme: "http", Enabled: true},
	}, []CertHost{{Hostname: "mqtt.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	if !strings.Contains(s, "mqtt.example.com") {
		t.Errorf("cert-only host must be an ACME subject:\n%s", s)
	}
	// Caddy only OBTAINS a cert for a name in tls.certificates.automate (a cert-only
	// subject has no route for auto-HTTPS to pick up, and on-demand is off). Without
	// this the policy exists but no ACME order ever runs.
	if !strings.Contains(s, `"automate"`) {
		t.Errorf("cert-only issuance requires tls.certificates.automate:\n%s", s)
	}
	// The cert-only host appears in subjects + automate (2) but in NO proxy route; the
	// proxy host (app) appears in a route match + subjects + automate (>=3). The counts
	// prove mqtt has no route while still being set up for issuance.
	if n := strings.Count(s, "mqtt.example.com"); n != 2 {
		t.Errorf("cert-only host must appear in subjects + automate only (2), got %d:\n%s", n, s)
	}
	if n := strings.Count(s, "app.example.com"); n < 3 {
		t.Errorf("proxy host must appear in route + subjects + automate (>=3), got %d:\n%s", n, s)
	}
}
