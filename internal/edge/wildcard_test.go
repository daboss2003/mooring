package edge

import (
	"encoding/json"
	"strings"
	"testing"
)

// With DNS-01 + base_domain, default-CA subjects AT/UNDER base_domain are served by the ONE
// *.base wildcard (dropped from per-name issuance); off-base subjects keep their own cert.
func TestRenderDNS01Wildcard(t *testing.T) {
	base := baseCfg()
	base.Wildcards = []WildcardCert{{Domain: "mooring.example.com", DNS01Provider: "cloudflare", DNS01Token: "tok-secret"}}
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

// Without any wildcard namespace, behavior is unchanged: every subject is automated
// individually, no wildcard (a base_domain without dns01 produces no Wildcards entry).
func TestRenderNoDNS01Unchanged(t *testing.T) {
	base := baseCfg() // no Wildcards → per-name HTTP-01
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
	base.Wildcards = []WildcardCert{{Domain: "mooring.example.com", DNS01Provider: "cloudflare", DNS01Token: "tok"}}
	out, err := Render(base, nil, []CertHost{{Hostname: "mqtt.iot.mooring.example.com"}}) // two labels below
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"mqtt.iot.mooring.example.com"`) {
		t.Errorf("a 2-label subject under base must keep its own cert (wildcard can't cover it):\n%s", out)
	}
}

// Phase 2: TWO named namespaces, each with its OWN DNS provider, produce TWO wildcard subjects
// each issued via its own DNS-01 provider — and a subject under each apex is covered by the
// matching wildcard.
func TestRenderMultipleWildcards(t *testing.T) {
	base := baseCfg()
	base.Wildcards = []WildcardCert{
		{Domain: "prod.example.com", DNS01Provider: "cloudflare", DNS01Token: "tok-prod"},
		{Domain: "staging.example.com", DNS01Provider: "route53", DNS01Token: "tok-stg"},
	}
	out, err := Render(base, []Route{
		{Hostname: "api.prod.example.com", Upstream: "api:3000", UpstreamScheme: "http", Enabled: true},
		{Hostname: "api.staging.example.com", Upstream: "api:3000", UpstreamScheme: "http", Enabled: true},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	// Both wildcards present, each with its own provider + token.
	for _, want := range []string{`"*.prod.example.com"`, `"*.staging.example.com"`, `"cloudflare"`, `"tok-prod"`, `"route53"`, `"tok-stg"`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	// Each app subject is covered by its namespace's wildcard → appears ONCE (route Host only),
	// not also as an individually-issued cert subject.
	for _, h := range []string{`"api.prod.example.com"`, `"api.staging.example.com"`} {
		if strings.Count(s, h) != 1 {
			t.Errorf("%s should appear once (route Host), covered by its wildcard:\n%s", h, s)
		}
	}
}

// Each wildcard's DNS-01 policy must pair its OWN provider with its OWN token inside the SAME
// issuer — a substring check can't catch cross-wiring (cloudflare↔tok-stg), so parse and verify.
func TestRenderMultipleWildcardsPairing(t *testing.T) {
	base := baseCfg()
	base.Wildcards = []WildcardCert{
		{Domain: "prod.example.com", DNS01Provider: "cloudflare", DNS01Token: "tok-prod"},
		{Domain: "staging.example.com", DNS01Provider: "route53", DNS01Token: "tok-stg"},
	}
	out, err := Render(base, nil, []CertHost{{Hostname: "a.prod.example.com"}, {Hostname: "b.staging.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	var root any
	if err := json.Unmarshal(out, &root); err != nil {
		t.Fatal(err)
	}
	want := map[string][2]string{
		"*.prod.example.com":    {"cloudflare", "tok-prod"},
		"*.staging.example.com": {"route53", "tok-stg"},
	}
	// Recursively find every TLS policy object (has "subjects" + "issuers") and check its wildcard
	// subject's DNS-01 provider name + api_token co-occur correctly.
	var walk func(v any)
	walk = func(v any) {
		switch t2 := v.(type) {
		case map[string]any:
			subs, hasSubs := t2["subjects"].([]any)
			iss, hasIss := t2["issuers"].([]any)
			if hasSubs && hasIss && len(subs) == 1 {
				if sub, _ := subs[0].(string); strings.HasPrefix(sub, "*.") {
					exp, tracked := want[sub]
					if tracked {
						prov, _ := iss[0].(map[string]any)["challenges"].(map[string]any)["dns"].(map[string]any)["provider"].(map[string]any)
						if prov["name"] != exp[0] || prov["api_token"] != exp[1] {
							t.Errorf("%s: got provider=%v token=%v, want %s/%s (CROSS-WIRED)", sub, prov["name"], prov["api_token"], exp[0], exp[1])
						}
						delete(want, sub)
					}
				}
			}
			for _, child := range t2 {
				walk(child)
			}
		case []any:
			for _, child := range t2 {
				walk(child)
			}
		}
	}
	walk(root)
	if len(want) != 0 {
		t.Errorf("did not find DNS-01 policies for: %v", want)
	}
}
