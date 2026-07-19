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
		if err := validateHostOrSubdomain("x", c.host, c.sub); err != nil {
			t.Errorf("host=%q sub=%q rejected: %v", c.host, c.sub, err)
		}
	}
	bad := []struct{ host, sub string }{
		{"", ""},                  // neither
		{"mqtt.example.com", "mqtt"}, // both
		{"", "*"},                 // wildcard label
		{"", "-bad"},              // leading hyphen
		{"", "bad-"},              // trailing hyphen
		{"", "Up"},                // uppercase
		{"", "a.b"},               // a dot (not a single label)
		{"", "under_score"},       // underscore
		{"*.example.com", ""},     // wildcard hostname
		{"nodot", ""},             // not an FQDN
	}
	for _, c := range bad {
		if err := validateHostOrSubdomain("x", c.host, c.sub); err == nil {
			t.Errorf("host=%q sub=%q should be rejected", c.host, c.sub)
		}
	}
}
