package edge

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"regexp"
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

// A namespace catch-all (*.apex) renders AFTER every exact host and after a cert-only shadow 404,
// is the only wildcard Host matcher the edge emits, and adds NO per-name ACME subject — the
// namespace's DNS-01 wildcard covers it. A cert-only host one label under the apex keeps its HTTP
// 404 (an explicit route before the catch-all), and the default 404 stays last.
func TestRenderCatchAll(t *testing.T) {
	base := baseCfg()
	apex := "shop.example.com"
	base.Wildcards = []WildcardCert{{Domain: apex, DNS01Provider: "cloudflare", DNS01Token: "tok"}}
	routes := []Route{
		{Hostname: "admin." + apex, Upstream: "web:8080", Pool: []string{"172.18.0.5:8080"}, UpstreamScheme: "http", Enabled: true},
		{Hostname: "*." + apex, Upstream: "web:8080", Pool: []string{"172.18.0.5:8080"}, UpstreamScheme: "http", Enabled: true, CatchAll: true},
	}
	certOnly := []CertHost{{Hostname: "mqtt." + apex}} // cert-only, under the apex → must keep its 404

	out, err := Render(base, routes, certOnly)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var doc struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes []struct {
						Match []struct {
							Host []string `json:"host"`
						} `json:"match"`
						Handle []struct {
							Handler    string `json:"handler"`
							StatusCode int    `json:"status_code"`
						} `json:"handle"`
					} `json:"routes"`
				} `json:"servers"`
			} `json:"http"`
			TLS struct {
				Certificates struct {
					Automate []string `json:"automate"`
				} `json:"certificates"`
			} `json:"tls"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	rts := doc.Apps.HTTP.Servers["edge"].Routes
	idxHost := func(h string) int {
		for i, r := range rts {
			if len(r.Match) == 1 && len(r.Match[0].Host) == 1 && r.Match[0].Host[0] == h {
				return i
			}
		}
		return -1
	}
	adminIdx := idxHost("admin." + apex)
	catchIdx := idxHost("*." + apex)
	shadowIdx := idxHost("mqtt." + apex)
	if adminIdx < 0 || catchIdx < 0 || shadowIdx < 0 {
		t.Fatalf("missing a route: admin=%d catch=%d shadow=%d\n%s", adminIdx, catchIdx, shadowIdx, out)
	}
	// Ordering: exact host and the cert-only shadow both precede the catch-all.
	if !(adminIdx < catchIdx) {
		t.Errorf("exact host must render before the catch-all (admin=%d catch=%d)", adminIdx, catchIdx)
	}
	if !(shadowIdx < catchIdx) {
		t.Errorf("cert-only shadow 404 must render before the catch-all (shadow=%d catch=%d)", shadowIdx, catchIdx)
	}
	// The cert-only shadow is a 404, not a proxy.
	if h := rts[shadowIdx].Handle; len(h) != 1 || h[0].Handler != "static_response" || h[0].StatusCode != 404 {
		t.Errorf("cert-only host under a catch-all must be an explicit 404, got %+v", rts[shadowIdx].Handle)
	}
	// The catch-all itself is a reverse_proxy (routable — it has a pool).
	gotProxy := false
	for _, h := range rts[catchIdx].Handle {
		if h.Handler == "reverse_proxy" {
			gotProxy = true
		}
	}
	if !gotProxy {
		t.Errorf("catch-all route should proxy, got %+v", rts[catchIdx].Handle)
	}
	// The last route is the default 404 (no match) and nothing follows the catch-all except it.
	last := rts[len(rts)-1]
	if len(last.Match) != 0 || len(last.Handle) != 1 || last.Handle[0].StatusCode != 404 {
		t.Errorf("last route must be the default 404, got match=%v handle=%+v", last.Match, last.Handle)
	}
	if catchIdx >= len(rts)-1 {
		t.Errorf("the catch-all must come before the default 404 (catch=%d of %d)", catchIdx, len(rts))
	}
	// `*.apex` appears in automate ONCE (the DNS-01 wildcard), never as a duplicate per-name subject.
	n := 0
	for _, s := range doc.Apps.TLS.Certificates.Automate {
		if s == "*."+apex {
			n++
		}
	}
	if n != 1 {
		t.Errorf("*.%s must be automated exactly once (the wildcard), got %d: %v", apex, n, doc.Apps.TLS.Certificates.Automate)
	}

	// Control: with NO catch-all, the cert-only host gets no explicit route (it relies on the default
	// 404), so the rendering path is unchanged.
	out2, err := Render(base, routes[:1], certOnly)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out2, []byte(`"host":["mqtt.`+apex+`"]`)) {
		t.Error("without a catch-all, a cert-only host must not get an explicit route")
	}
}

// SBD-1 regression: if the admin host sits under a catch-all apex, a request to it from a
// non-allowlisted IP must NOT fall through to the catch-all tenant. The renderer emits a host-level
// 404 for the admin host, ordered before the catch-all.
func TestRenderCatchAllAdminShadow(t *testing.T) {
	base := baseCfg()
	apex := "shop.example.com"
	base.AdminHostname = "admin." + apex
	base.AdminAllowlist = []string{"10.0.0.0/8"}
	base.AdminUpstream = "127.0.0.1:9000"
	base.Wildcards = []WildcardCert{{Domain: apex, DNS01Provider: "cloudflare", DNS01Token: "tok"}}
	out, err := Render(base, []Route{
		{Hostname: "*." + apex, Upstream: "web:8080", Pool: []string{"172.18.0.5:8080"}, UpstreamScheme: "http", Enabled: true, CatchAll: true},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes []struct {
						Match []struct {
							Host     []string `json:"host"`
							RemoteIP *struct {
								Ranges []string `json:"ranges"`
							} `json:"remote_ip"`
						} `json:"match"`
						Handle []struct {
							Handler    string `json:"handler"`
							StatusCode int    `json:"status_code"`
						} `json:"handle"`
					} `json:"routes"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	rts := doc.Apps.HTTP.Servers["edge"].Routes
	adminHost := "admin." + apex
	adminGuardIdx, adminShadowIdx, catchIdx := -1, -1, -1
	for i, r := range rts {
		isCatch := len(r.Match) == 1 && len(r.Match[0].Host) == 1 && r.Match[0].Host[0] == "*."+apex
		isAdmin := len(r.Match) == 1 && len(r.Match[0].Host) == 1 && r.Match[0].Host[0] == adminHost
		switch {
		case isCatch:
			catchIdx = i
		case isAdmin && r.Match[0].RemoteIP != nil:
			adminGuardIdx = i // the IP-gated admin proxy
		case isAdmin && len(r.Handle) == 1 && r.Handle[0].Handler == "static_response" && r.Handle[0].StatusCode == 404:
			adminShadowIdx = i // the shadow 404 for a denied-IP admin request
		}
	}
	if adminGuardIdx < 0 || adminShadowIdx < 0 || catchIdx < 0 {
		t.Fatalf("missing a route: adminGuard=%d adminShadow=%d catch=%d\n%s", adminGuardIdx, adminShadowIdx, catchIdx, out)
	}
	if !(adminGuardIdx < adminShadowIdx && adminShadowIdx < catchIdx) {
		t.Errorf("order must be admin-guard < admin-shadow-404 < catch-all, got %d,%d,%d", adminGuardIdx, adminShadowIdx, catchIdx)
	}
}

// A catch-all hostname must be exactly *.<apex>; a wildcard without CatchAll, or a malformed
// catch-all hostname, is still rejected (SBD-4).
func TestRenderCatchAllValidation(t *testing.T) {
	// CatchAll set but hostname is not *.<apex>.
	for _, h := range []string{"app.example.com", "*", "*.", "*.*.example.com", "a.*.example.com"} {
		if _, err := Render(baseCfg(), []Route{{Hostname: h, Upstream: "web:80", UpstreamScheme: "http", Enabled: true, CatchAll: true}}, nil); err == nil {
			t.Errorf("CatchAll hostname %q must be rejected", h)
		}
	}
	// A wildcard hostname WITHOUT CatchAll is still rejected (the only wildcard the edge allows is a
	// marked catch-all).
	if _, err := Render(baseCfg(), []Route{{Hostname: "*.example.com", Upstream: "web:80", UpstreamScheme: "http", Enabled: true}}, nil); err == nil {
		t.Error("a *.apex hostname without CatchAll must be rejected")
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

// Routes sharing a hostname are tried longest path prefix first, so "/" stored first
// can't swallow "/socket.io" (Caddy stops at the first matching terminal route).
func TestRenderPathRoutesMostSpecificFirst(t *testing.T) {
	out, err := Render(baseCfg(), []Route{
		{Hostname: "api.example.com", PathPrefix: "/", Upstream: "api:3000", Pool: []string{"172.18.0.5:3000"}, UpstreamScheme: "http", Enabled: true},
		{Hostname: "other.example.com", Upstream: "web:80", Pool: []string{"172.18.0.9:80"}, UpstreamScheme: "http", Enabled: true},
		{Hostname: "api.example.com", PathPrefix: "/socket.io/", Upstream: "realtime:3001", Pool: []string{"172.18.0.6:3001"}, UpstreamScheme: "http", Enabled: true},
		{Hostname: "API.example.com", PathPrefix: "/v1", Upstream: "api:3000", Pool: []string{"172.18.0.5:3000"}, UpstreamScheme: "http", Enabled: true},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes []struct {
						Match []struct {
							Host []string `json:"host"`
							Path []string `json:"path"`
						} `json:"match"`
					} `json:"routes"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	var paths [][]string
	for _, srv := range doc.Apps.HTTP.Servers {
		for _, r := range srv.Routes {
			if len(r.Match) == 1 && len(r.Match[0].Host) == 1 && r.Match[0].Host[0] == "api.example.com" {
				paths = append(paths, r.Match[0].Path)
			}
		}
	}
	want := [][]string{{"/socket.io", "/socket.io/*"}, {"/v1", "/v1/*"}, {"/*"}}
	if len(paths) != len(want) {
		t.Fatalf("api.example.com routes = %v, want %v", paths, want)
	}
	for i := range want {
		if strings.Join(paths[i], ",") != strings.Join(want[i], ",") {
			t.Fatalf("api.example.com route order = %v, want %v", paths, want)
		}
	}
}

// Reordering by specificity must not change which CA issues a host's certificate: it is
// still the host's first enabled route in stored order.
func TestRenderPathOrderKeepsHostCA(t *testing.T) {
	base := baseCfg()
	base.CAs = []CA{{Name: "internal", DirectoryURL: "https://ca.lan/acme/acme/directory", Email: "pki@lan"}}
	out, err := Render(base, []Route{
		{Hostname: "api.lan", PathPrefix: "/", Upstream: "api:3000", Pool: []string{"172.18.0.5:3000"}, UpstreamScheme: "http", Enabled: true, CA: "internal"},
		{Hostname: "api.lan", PathPrefix: "/ws", Upstream: "rt:3001", Pool: []string{"172.18.0.6:3001"}, UpstreamScheme: "http", Enabled: true},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "https://ca.lan/acme/acme/directory") {
		t.Errorf("api.lan lost its private CA after route reordering:\n%s", out)
	}
}

// renderedProxy is the load-balancing part of a rendered reverse_proxy handler.
type renderedProxy struct {
	LoadBalancing *struct {
		SelectionPolicy map[string]any `json:"selection_policy"`
	} `json:"load_balancing"`
	HealthChecks *struct {
		Passive *struct {
			FailDuration string `json:"fail_duration"`
			MaxFails     int    `json:"max_fails"`
		} `json:"passive"`
	} `json:"health_checks"`
}

// renderedProxies maps "host path" (path = the route's first path matcher, "" for none) to its
// reverse_proxy handler.
func renderedProxies(t *testing.T, out []byte) map[string]renderedProxy {
	t.Helper()
	var doc struct {
		Apps struct {
			HTTP struct {
				Servers map[string]struct {
					Routes []struct {
						Match []struct {
							Host []string `json:"host"`
							Path []string `json:"path"`
						} `json:"match"`
						Handle []json.RawMessage `json:"handle"`
					} `json:"routes"`
				} `json:"servers"`
			} `json:"http"`
		} `json:"apps"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	got := map[string]renderedProxy{}
	for _, srv := range doc.Apps.HTTP.Servers {
		for _, r := range srv.Routes {
			if len(r.Match) != 1 || len(r.Match[0].Host) != 1 {
				continue
			}
			key := r.Match[0].Host[0] + " "
			if len(r.Match[0].Path) > 0 {
				key += r.Match[0].Path[0]
			}
			for _, raw := range r.Handle {
				var h struct {
					Handler string `json:"handler"`
					renderedProxy
				}
				if err := json.Unmarshal(raw, &h); err != nil {
					t.Fatal(err)
				}
				if h.Handler == "reverse_proxy" {
					got[key] = h.renderedProxy
				}
			}
		}
	}
	return got
}

// wantCookieName recomputes the per-route cookie name independently of the renderer, so a change
// to the formula (which would move every live session) fails here.
func wantCookieName(host, prefix string) string {
	sum := sha256.Sum256([]byte(host + "\x00" + prefix))
	return "mlb_" + hex.EncodeToString(sum[:])[:10]
}

// Each lb value maps onto its Caddy selection policy, and every policy keeps the passive health
// checks that take a failing copy out of the pool.
func TestRenderLBPolicies(t *testing.T) {
	base := baseCfg()
	base.LBCookieSecret = "5ec2e7c00c1e5ec2e7c00c1e5ec2e7c00c1e5ec2e7c00c1e5ec2e7c00c1e5ec2"
	cases := []struct {
		lb   string
		want map[string]any
	}{
		{"", map[string]any{"policy": "least_conn"}},
		{"least_conn", map[string]any{"policy": "least_conn"}},
		{"round_robin", map[string]any{"policy": "round_robin"}},
		{"ip_hash", map[string]any{"policy": "ip_hash"}},
		{"cookie", map[string]any{"policy": "cookie", "name": wantCookieName("app.example.com", ""), "secret": base.LBCookieSecret}},
	}
	for _, c := range cases {
		out, err := Render(base, []Route{{
			Hostname: "app.example.com", Upstream: "web:8080", Pool: []string{"172.18.0.4:8080", "172.18.0.5:8080"},
			UpstreamScheme: "http", Enabled: true, LB: c.lb,
		}}, nil)
		if err != nil {
			t.Fatalf("lb %q: %v", c.lb, err)
		}
		rp, ok := renderedProxies(t, out)["app.example.com "]
		if !ok || rp.LoadBalancing == nil {
			t.Fatalf("lb %q: no load_balancing rendered:\n%s", c.lb, out)
		}
		if !reflect.DeepEqual(rp.LoadBalancing.SelectionPolicy, c.want) {
			t.Errorf("lb %q: selection_policy = %v, want %v", c.lb, rp.LoadBalancing.SelectionPolicy, c.want)
		}
		if rp.HealthChecks == nil || rp.HealthChecks.Passive == nil || rp.HealthChecks.Passive.FailDuration != "30s" || rp.HealthChecks.Passive.MaxFails != 3 {
			t.Errorf("lb %q: passive health checks missing or changed:\n%s", c.lb, out)
		}
		if c.lb != "cookie" && strings.Contains(string(out), base.LBCookieSecret) {
			t.Errorf("lb %q: the cookie secret must appear only in a cookie policy", c.lb)
		}
	}
}

// One copy needs no balancing: no load_balancing or health_checks, whatever lb says.
func TestRenderLBSingleUpstreamHasNoPolicy(t *testing.T) {
	base := baseCfg()
	base.LBCookieSecret = "5ec2e7"
	for _, lb := range []string{"", "least_conn", "round_robin", "ip_hash", "cookie"} {
		out, err := Render(base, []Route{{
			Hostname: "app.example.com", Upstream: "web:8080", Pool: []string{"172.18.0.4:8080"},
			UpstreamScheme: "http", Enabled: true, LB: lb,
		}}, nil)
		if err != nil {
			t.Fatalf("lb %q: %v", lb, err)
		}
		if s := string(out); strings.Contains(s, "load_balancing") || strings.Contains(s, "health_checks") || strings.Contains(s, base.LBCookieSecret) {
			t.Errorf("lb %q: a single upstream must not render pool machinery:\n%s", lb, s)
		}
	}
}

// Caddy sets the cookie on path "/", so path routes sharing a hostname need their own cookie
// names or each would overwrite the other's. Equivalent spellings of a prefix and hostname case
// give the same name.
func TestRenderLBCookieNamePerRoute(t *testing.T) {
	base := baseCfg()
	base.LBCookieSecret = "5ec2e7"
	pool := []string{"172.18.0.4:8080", "172.18.0.5:8080"}
	out, err := Render(base, []Route{
		{Hostname: "app.example.com", PathPrefix: "/", Upstream: "web:8080", Pool: pool, UpstreamScheme: "http", Enabled: true, LB: "cookie"},
		{Hostname: "app.example.com", PathPrefix: "/socket.io/", Upstream: "rt:8080", Pool: pool, UpstreamScheme: "http", Enabled: true, LB: "cookie"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := renderedProxies(t, out)
	root, sock := got["app.example.com /*"], got["app.example.com /socket.io"]
	if root.LoadBalancing == nil || sock.LoadBalancing == nil {
		t.Fatalf("both path routes must render a cookie policy:\n%s", out)
	}
	rootName, _ := root.LoadBalancing.SelectionPolicy["name"].(string)
	sockName, _ := sock.LoadBalancing.SelectionPolicy["name"].(string)
	if rootName != wantCookieName("app.example.com", "") || sockName != wantCookieName("app.example.com", "/socket.io") {
		t.Errorf("cookie names = %v, %v; want %v, %v", rootName, sockName, wantCookieName("app.example.com", ""), wantCookieName("app.example.com", "/socket.io"))
	}
	if rootName == sockName {
		t.Errorf("two path routes on one host share cookie name %v", rootName)
	}
	if !regexp.MustCompile(`^mlb_[0-9a-f]{10}$`).MatchString(rootName) {
		t.Errorf("cookie name %q is not mlb_ + 10 hex", rootName)
	}
	if lbCookieName("API.Example.com ", "/api/") != lbCookieName("api.example.com", "/api") || lbCookieName("a.example.com", "/") != lbCookieName("a.example.com", "") {
		t.Error("equivalent hostname/prefix spellings must give the same cookie name")
	}
	if lbCookieName("a.example.com", "/api") == lbCookieName("b.example.com", "/api") {
		t.Error("different hostnames must give different cookie names")
	}
}

// Without a secret the cookie value would be an unkeyed hash of the copy's address, which anyone
// can reverse over the private address space. The route stays sticky by client address instead.
func TestRenderLBCookieWithoutSecretUsesIPHash(t *testing.T) {
	out, err := Render(baseCfg(), []Route{{
		Hostname: "app.example.com", Upstream: "web:8080", Pool: []string{"172.18.0.4:8080", "172.18.0.5:8080"},
		UpstreamScheme: "http", Enabled: true, LB: "cookie",
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	rp := renderedProxies(t, out)["app.example.com "]
	if rp.LoadBalancing == nil || !reflect.DeepEqual(rp.LoadBalancing.SelectionPolicy, map[string]any{"policy": "ip_hash"}) {
		t.Errorf("cookie without a secret must render ip_hash:\n%s", out)
	}
}

// ValidateRoute (and so Render) refuses an lb value outside the accepted set.
func TestValidateRouteRejectsInvalidLB(t *testing.T) {
	for _, lb := range []string{"sticky", "LEAST_CONN", "random", " cookie", "first", "uri_hash"} {
		r := Route{Hostname: "app.example.com", Upstream: "web:8080", UpstreamScheme: "http", Enabled: true, LB: lb}
		if err := ValidateRoute(r); err == nil {
			t.Errorf("lb %q must be rejected", lb)
		}
		if _, err := Render(baseCfg(), []Route{r}, nil); err == nil {
			t.Errorf("Render must refuse lb %q", lb)
		}
	}
	for _, lb := range []string{"", "least_conn", "round_robin", "ip_hash", "cookie"} {
		if err := ValidateRoute(Route{Hostname: "app.example.com", Upstream: "web:8080", UpstreamScheme: "http", Enabled: true, LB: lb}); err != nil {
			t.Errorf("lb %q must be accepted: %v", lb, err)
		}
	}
}

func TestDeriveLBCookieSecret(t *testing.T) {
	k1 := bytes.Repeat([]byte{0x11}, 32)
	k2 := bytes.Repeat([]byte{0x22}, 32)
	s1 := DeriveLBCookieSecret(k1)
	if s1 != DeriveLBCookieSecret(append([]byte(nil), k1...)) {
		t.Error("derivation must be deterministic")
	}
	if s1 == DeriveLBCookieSecret(k2) {
		t.Error("different keys must derive different secrets")
	}
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(s1) {
		t.Errorf("secret %q is not 64 hex chars", s1)
	}
	if s1 == hex.EncodeToString(k1) || s1 == string(k1) || strings.Contains(s1, hex.EncodeToString(k1)) {
		t.Error("the derived secret must not be the key")
	}
	// Domain separation: not the plain hash of the key, nor the key-HMAC of another label.
	if sum := sha256.Sum256(k1); s1 == hex.EncodeToString(sum[:]) {
		t.Error("the derived secret must be domain-separated, not sha256(key)")
	}
	if DeriveLBCookieSecret(nil) != "" {
		t.Error("an empty key must derive no secret")
	}
}
