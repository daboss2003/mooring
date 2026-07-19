package edge

import (
	"strings"
	"testing"
)

func TestDNSProviderModule(t *testing.T) {
	// Known providers map to their official caddy-dns module path (case-insensitive).
	for name, want := range map[string]string{
		"cloudflare":   "github.com/caddy-dns/cloudflare",
		"Route53":      "github.com/caddy-dns/route53",
		"digitalocean": "github.com/caddy-dns/digitalocean",
	} {
		got, ok := DNSProviderModule(name)
		if !ok || got != want {
			t.Errorf("DNSProviderModule(%q) = %q,%v; want %q,true", name, got, ok, want)
		}
		// Every mapped path is under the official org (no arbitrary module injection).
		if !strings.HasPrefix(want, "github.com/caddy-dns/") {
			t.Errorf("module %q escapes the caddy-dns org", want)
		}
	}
	// Unknown / typo'd providers are rejected (drives a clear boot warning, not a bad install).
	for _, bad := range []string{"cloudflar", "evil/../pkg", "", "nope"} {
		if _, ok := DNSProviderModule(bad); ok {
			t.Errorf("DNSProviderModule(%q) should be unknown", bad)
		}
	}
}
