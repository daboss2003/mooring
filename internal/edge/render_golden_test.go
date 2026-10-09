package edge

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// goldenFixture exercises every part of the render: the admin vhost, the access log, a named CA, a
// DNS-01 wildcard, single and pooled routes (cookie lb), an https upstream, a path route, an
// unroutable route and a cert-only subject.
func goldenFixture() (BaseConfig, []Route, []CertHost) {
	base := BaseConfig{
		AdminListen:    "unix//run/mooring/caddy-admin.sock",
		ACMEEmail:      "ops@example.com",
		ACMECA:         "https://acme.example/directory",
		CAs:            []CA{{Name: "internal", DirectoryURL: "https://ca.lan/acme/acme/directory", Email: "pki@lan", TrustedRoots: []string{"/etc/mooring/internal-ca.pem"}}},
		AdminHostname:  "admin.example.com",
		AdminAllowlist: []string{"203.0.113.0/24", "2001:db8::/32"},
		AdminUpstream:  "127.0.0.1:9001",
		Wildcards:      []WildcardCert{{Domain: "apps.example.com", DNS01Provider: "cloudflare", DNS01Token: "tok"}},
		AccessLog:      true,
		LBCookieSecret: "5ec2e7c00c1e5ec2e7c00c1e5ec2e7c00c1e5ec2e7c00c1e5ec2e7c00c1e5ec2",
	}
	routes := []Route{
		{AppID: "shop", Hostname: "shop.example.com", Upstream: "web:8080", Pool: []string{"172.18.0.5:8080"}, UpstreamScheme: "http", HSTS: true, SecurityHeaders: true, Enabled: true},
		{AppID: "shop", Hostname: "api.apps.example.com", Upstream: "api:3000", Pool: []string{"172.18.0.6:3000", "172.18.0.7:3000"}, UpstreamScheme: "http", Enabled: true, LB: "cookie"},
		{AppID: "shop", Hostname: "api.apps.example.com", PathPrefix: "/socket.io/", Upstream: "rt:3001", Pool: []string{"172.18.0.8:3001", "172.18.0.9:3001"}, UpstreamScheme: "http", Enabled: true, LB: "ip_hash"},
		{AppID: "vault", Hostname: "vault.lan", Upstream: "vault:8200", Pool: []string{"172.19.0.2:8200"}, UpstreamScheme: "https", Enabled: true, CA: "internal"},
		{AppID: "down", Hostname: "down.example.com", Upstream: "web:80", UpstreamScheme: "http", SecurityHeaders: true, Enabled: true},
		{AppID: "off", Hostname: "off.example.com", Upstream: "web:80", Pool: []string{"172.20.0.2:80"}, UpstreamScheme: "http", Enabled: false},
	}
	certOnly := []CertHost{{Hostname: "mqtt.example.com"}, {Hostname: "mqtt.lan", CA: "internal"}}
	return base, routes, certOnly
}

// goldenPath holds the render of goldenFixture produced by the renderer BEFORE edge trusted proxies
// existed. MOORING_UPDATE_GOLDEN=1 rewrites it; only do that for an intended change to the output.
var goldenPath = filepath.Join("testdata", "render_no_trusted_proxies.golden.json")

// Without trusted proxies the rendered document is byte-identical to the renderer's output before
// the feature, for both the route-less floor and a full document.
func TestRenderGoldenWithoutTrustedProxies(t *testing.T) {
	base, routes, certOnly := goldenFixture()
	full, err := Render(base, routes, certOnly)
	if err != nil {
		t.Fatal(err)
	}
	floor, err := Render(BootFloor(base), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := append(append(append([]byte{}, full...), '\n'), floor...)
	if os.Getenv("MOORING_UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(goldenPath), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(goldenPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (MOORING_UPDATE_GOLDEN=1 creates it): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("render without trusted proxies changed:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}
