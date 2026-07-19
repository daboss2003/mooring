package edge

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// caddyDNSProviders maps a short DNS-provider name (edge.dns01.provider) to its Caddy DNS
// module import path under the official github.com/caddy-dns org. Mooring installs the matching
// plugin into the caddy binary AUTOMATICALLY (via `caddy add-package`, which downloads a
// plugin-enabled caddy from Caddy's official build server and swaps the binary) — so the
// operator never runs xcaddy or builds anything. This is the set Caddy officially supports;
// keep it in sync with https://github.com/orgs/caddy-dns/repositories.
var caddyDNSProviders = map[string]string{
	"acmedns":        "github.com/caddy-dns/acmedns",
	"alidns":         "github.com/caddy-dns/alidns",
	"azure":          "github.com/caddy-dns/azure",
	"cloudflare":     "github.com/caddy-dns/cloudflare",
	"cloudns":        "github.com/caddy-dns/cloudns",
	"desec":          "github.com/caddy-dns/desec",
	"digitalocean":   "github.com/caddy-dns/digitalocean",
	"dinahosting":    "github.com/caddy-dns/dinahosting",
	"dnsimple":       "github.com/caddy-dns/dnsimple",
	"dnspod":         "github.com/caddy-dns/dnspod",
	"duckdns":        "github.com/caddy-dns/duckdns",
	"gandi":          "github.com/caddy-dns/gandi",
	"gcore":          "github.com/caddy-dns/gcore",
	"godaddy":        "github.com/caddy-dns/godaddy",
	"googleclouddns": "github.com/caddy-dns/googleclouddns",
	"hetzner":        "github.com/caddy-dns/hetzner",
	"hurricane":      "github.com/caddy-dns/hurricane",
	"ionos":          "github.com/caddy-dns/ionos",
	"leaseweb":       "github.com/caddy-dns/leaseweb",
	"linode":         "github.com/caddy-dns/linode",
	"mailinabox":     "github.com/caddy-dns/mailinabox",
	"metaname":       "github.com/caddy-dns/metaname",
	"namecheap":      "github.com/caddy-dns/namecheap",
	"namedotcom":     "github.com/caddy-dns/namedotcom",
	"netlify":        "github.com/caddy-dns/netlify",
	"njalla":         "github.com/caddy-dns/njalla",
	"ovh":            "github.com/caddy-dns/ovh",
	"porkbun":        "github.com/caddy-dns/porkbun",
	"powerdns":       "github.com/caddy-dns/powerdns",
	"route53":        "github.com/caddy-dns/route53",
	"scaleway":       "github.com/caddy-dns/scaleway",
	"tencentcloud":   "github.com/caddy-dns/tencentcloud",
	"vercel":         "github.com/caddy-dns/vercel",
	"vultr":          "github.com/caddy-dns/vultr",
}

// DNSProviderModule returns the caddy module path for a provider name, and whether it's known.
func DNSProviderModule(provider string) (string, bool) {
	m, ok := caddyDNSProviders[strings.ToLower(strings.TrimSpace(provider))]
	return m, ok
}

// KnownDNSProviders returns the sorted list of supported provider names (for error messages).
func KnownDNSProviders() []string {
	out := make([]string, 0, len(caddyDNSProviders))
	for k := range caddyDNSProviders {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// EnsureDNSProvider makes sure the caddy binary has the DNS provider module compiled in,
// installing it automatically with `caddy add-package <module>` when missing — so the operator
// never builds Caddy. add-package fetches a plugin-enabled caddy from Caddy's official build
// server and replaces the binary in place; it needs the caddy binary to be writable by this
// process and egress to caddyserver.com. Idempotent (a no-op when the module is already
// present). On any failure it returns an error and the caller proceeds with the current binary,
// so the DNS-01 config load then fails visibly (nothing is silently mis-issued).
func EnsureDNSProvider(ctx context.Context, caddyBin, provider string, log *slog.Logger) error {
	module, ok := DNSProviderModule(provider)
	if !ok {
		return fmt.Errorf("edge: unknown DNS provider %q — supported: %s", provider, strings.Join(KnownDNSProviders(), ", "))
	}
	if caddyBin == "" {
		caddyBin = "caddy"
	}
	modID := "dns.providers." + strings.ToLower(strings.TrimSpace(provider))
	if caddyHasModule(ctx, caddyBin, modID) {
		return nil // already compiled in
	}
	if log != nil {
		log.Info("edge: installing the Caddy DNS plugin for the wildcard cert (no manual build needed)", "provider", provider, "module", module)
	}
	cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	out, err := exec.CommandContext(cctx, caddyBin, "add-package", module).CombinedOutput()
	if err != nil {
		return fmt.Errorf("edge: `caddy add-package %s` failed (%v): %s", module, err, lastLine(out))
	}
	if !caddyHasModule(ctx, caddyBin, modID) {
		return fmt.Errorf("edge: installed %s but %s is still missing", module, modID)
	}
	if log != nil {
		log.Info("edge: Caddy DNS plugin installed", "provider", provider)
	}
	return nil
}

// caddyHasModule reports whether `caddy list-modules` includes moduleID (a daemon-less call).
func caddyHasModule(ctx context.Context, caddyBin, moduleID string) bool {
	out, err := exec.CommandContext(ctx, caddyBin, "list-modules").CombinedOutput()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == moduleID {
			return true
		}
	}
	return false
}

// lastLine returns the last non-empty line of b (for a compact error tail).
func lastLine(b []byte) string {
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	return strings.TrimSpace(lines[len(lines)-1])
}
