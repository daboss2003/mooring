package definition

import "testing"

func TestValidateHostOrSubdomain(t *testing.T) {
	ok := []struct{ host, sub string }{
		{"mqtt.example.com", ""}, // literal FQDN
		{"", "mqtt"},             // subdomain label
		{"", "a"},                // single char
		{"", "api-1"},            // hyphen ok
	}
	for _, c := range ok {
		if err := validateHostOrSubdomain("x", c.host, c.sub, false); err != nil {
			t.Errorf("host=%q sub=%q rejected: %v", c.host, c.sub, err)
		}
	}
	bad := []struct{ host, sub string }{
		{"", ""},                     // neither
		{"mqtt.example.com", "mqtt"}, // both
		{"", "*"},                    // wildcard label (catch-all NOT allowed here)
		{"", "-bad"},                 // leading hyphen
		{"", "bad-"},                 // trailing hyphen
		{"", "Up"},                   // uppercase
		{"", "a.b"},                  // a dot (not a single label)
		{"", "under_score"},          // underscore
		{"*.example.com", ""},        // wildcard hostname
		{"nodot", ""},                // not an FQDN
	}
	for _, c := range bad {
		if err := validateHostOrSubdomain("x", c.host, c.sub, false); err == nil {
			t.Errorf("host=%q sub=%q should be rejected", c.host, c.sub)
		}
	}
	// The catch-all subdomain "*" is valid ONLY when allowed (an edge route); rejected otherwise
	// (e.g. a cert_binding), and a both-set / bad combination is still rejected even when allowed.
	if err := validateHostOrSubdomain("route", "", "*", true); err != nil {
		t.Errorf(`subdomain "*" must be accepted on a route: %v`, err)
	}
	if err := validateHostOrSubdomain("cert", "", "*", false); err == nil {
		t.Error(`subdomain "*" must be rejected where catch-all is not allowed`)
	}
	if err := validateHostOrSubdomain("route", "x.example.com", "*", true); err == nil {
		t.Error(`subdomain "*" with a hostname set must still be rejected`)
	}
	// The EXPANDED catch-all form is a literal *.<apex> hostname (no subdomain). Re-validation of the
	// canonical runs through the hostname branch, so a route must accept exactly *.<valid-apex>; a
	// cert_binding (allowCatchAll=false) must not; a malformed apex must not. (Regression: Findings 1/2
	// — every catch-all deploy and `mooring validate` failed here because *.apex was rejected.)
	if err := validateHostOrSubdomain("route", "*.shop.example.com", "", true); err != nil {
		t.Errorf("expanded catch-all *.apex must be accepted on a route: %v", err)
	}
	if err := validateHostOrSubdomain("cert", "*.shop.example.com", "", false); err == nil {
		t.Error("a *.apex hostname must be rejected where catch-all is not allowed (cert_binding)")
	}
	for _, h := range []string{"*.", "*.bad_apex", "*.*.example.com", "*.nodot"} {
		if err := validateHostOrSubdomain("route", h, "", true); err == nil {
			t.Errorf("malformed catch-all hostname %q must be rejected", h)
		}
	}
}
