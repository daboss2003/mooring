package edge

import (
	"sort"
	"strings"
)

// caddyDNSProviders maps a short DNS-provider name (edge.dns01.provider) to its Caddy DNS
// module import path under the official github.com/caddy-dns org. Mooring installs the matching
// plugin AUTOMATICALLY as a Mooring-owned Caddy build downloaded from Caddy's official build server
// (DNSPluginInstaller / InstallPluginBuild) — so the operator never runs xcaddy or builds anything,
// and nothing depends on `caddy add-package` (absent from distro builds, leaving core Caddy, and
// unable to rewrite a packaged binary under the service sandbox anyway). This is the set Caddy
// officially supports; keep it in sync with https://github.com/orgs/caddy-dns/repositories.
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
