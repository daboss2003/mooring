package edge

import (
	"strings"
	"testing"
)

// With DNS-01 + base_domain, default-CA subjects AT/UNDER base_domain are served by the ONE
// *.base wildcard (dropped from per-name issuance); off-base subjects keep their own cert.
func TestRenderDNS01Wildcard(t *testing.T) {
	base := baseCfg()
	base.BaseDomain = "mooring.example.com"
	base.DNS01Provider = "cloudflare"
	base.DNS01Token = "tok-secret"
	out, err := Render(base, []Route{
		{Hostname: "api.mooring.example.com", Upstream: "api:3000", UpstreamScheme: "http", Enabled: true},
		{Hostname: "shop.other.com", Upstream: "web:80", UpstreamScheme: "http", Enabled: true}, // off-base
	}, []CertHost{{Hostname: "mqtt.mooring.example.com"}}) // cert-only under base
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	// The wildcard subject is issued via DNS-01 with the provider + token.
	for _, want := range []string{`"*.mooring.example.com"`, `"challenges"`, `"dns"`, `"cloudflare"`, `"tok-secret"`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	// A cert-only subject under base_domain has no route, so once the wildcard covers it, it
	// disappears entirely — the clean proof that under-base subjects are not issued per-name.
	if strings.Contains(s, `"mqtt.mooring.example.com"`) {
		t.Errorf("cert-only mqtt.mooring.example.com should be covered by the wildcard, not issued individually:\n%s", s)
	}
	// The under-base ROUTE still exists (served with the wildcard cert), but is not in the TLS
	// automate/subjects list — confirm it's only present as a route Host, not a cert subject.
	if strings.Count(s, `"api.mooring.example.com"`) != 1 { // exactly once: the route Host matcher
		t.Errorf("api.mooring.example.com should appear ONCE (route Host), not also as a cert subject:\n%s", s)
	}
	// The off-base hostname keeps its own (HTTP-01) cert.
	if !strings.Contains(s, `"shop.other.com"`) {
		t.Errorf("off-base subject should keep its own cert:\n%s", s)
	}
}

// Without DNS-01, behavior is unchanged: every subject is automated individually, no wildcard.
func TestRenderNoDNS01Unchanged(t *testing.T) {
	base := baseCfg()
	base.BaseDomain = "mooring.example.com" // set, but no DNS01 provider → no wildcard
	out, _ := Render(base, []Route{
		{Hostname: "api.mooring.example.com", Upstream: "api:3000", UpstreamScheme: "http", Enabled: true},
	}, nil)
	s := string(out)
	if strings.Contains(s, "*.") || strings.Contains(s, "challenges") {
		t.Errorf("no DNS-01 configured → no wildcard/DNS challenge:\n%s", s)
	}
	if !strings.Contains(s, `"api.mooring.example.com"`) {
		t.Error("subject should be automated individually without DNS-01")
	}
}

func TestCoveredByWildcard(t *testing.T) {
	base := "mooring.example.com"
	// Covered: exactly one label below base.
	for _, h := range []string{"api.mooring.example.com", "a.mooring.example.com"} {
		if !coveredByWildcard(h, base) {
			t.Errorf("%s should be covered by *.%s", h, base)
		}
	}
	// NOT covered: the apex, a deeper (multi-label) name, and lookalikes.
	for _, h := range []string{"mooring.example.com", "a.b.mooring.example.com", "evilmooring.example.com", "notmooring.example.com", "other.com"} {
		if coveredByWildcard(h, base) {
			t.Errorf("%s must NOT be treated as covered by *.%s", h, base)
		}
	}
}

// A multi-label subject under base_domain must KEEP its own cert (the wildcard can't cover it).
func TestRenderWildcardKeepsMultiLabel(t *testing.T) {
	base := baseCfg()
	base.BaseDomain = "mooring.example.com"
	base.DNS01Provider = "cloudflare"
	base.DNS01Token = "tok"
	out, err := Render(base, nil, []CertHost{{Hostname: "mqtt.iot.mooring.example.com"}}) // two labels below
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"mqtt.iot.mooring.example.com"`) {
		t.Errorf("a 2-label subject under base must keep its own cert (wildcard can't cover it):\n%s", out)
	}
}
