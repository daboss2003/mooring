package edge

import (
	"sort"
	"strings"
)

// cloudflareRanges are Cloudflare's published edge address ranges, shipped with Mooring and
// refreshed each release. Source: https://www.cloudflare.com/ips-v4 and
// https://www.cloudflare.com/ips-v6, fetched 2026-10-09 (15 IPv4 + 7 IPv6 ranges).
var cloudflareRanges = []string{
	// IPv4
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
	// IPv6
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}

// trustedProxyPreset is what an edge.trusted_proxies preset name stands for: the ranges it expands
// to, and the header its proxies set themselves (the default client IP header when it is listed).
type trustedProxyPreset struct {
	ranges         []string
	clientIPHeader string
}

// trustedProxyPresets maps preset names to presets. The config layer keeps its own copy of the
// names and headers (config.edgeTrustedProxyPresets); a config test checks the two match.
var trustedProxyPresets = map[string]trustedProxyPreset{
	// Cloudflare sets CF-Connecting-IP to the connecting address and drops any value the client sent.
	// Its X-Forwarded-For is appended to, so a client that itself connects from a Cloudflare address
	// (Workers, WARP) could choose the address read from it.
	"cloudflare": {ranges: cloudflareRanges, clientIPHeader: "CF-Connecting-IP"},
}

// TrustedProxyPreset returns a copy of the ranges a preset name expands to.
func TrustedProxyPreset(name string) ([]string, bool) {
	p, ok := trustedProxyPresets[name]
	if !ok {
		return nil, false
	}
	return append([]string(nil), p.ranges...), true
}

// DefaultClientIPHeader is the client IP header used when edge.client_ip_header is unset: the
// header of the first listed preset that has one (CF-Connecting-IP for cloudflare), else
// X-Forwarded-For.
func DefaultClientIPHeader(trustedProxies []string) string {
	for _, e := range trustedProxies {
		if p, ok := trustedProxyPresets[strings.TrimSpace(e)]; ok && p.clientIPHeader != "" {
			return p.clientIPHeader
		}
	}
	return defaultClientIPHeader
}

// TrustedProxyPresetNames returns the known preset names, sorted.
func TrustedProxyPresetNames() []string {
	names := make([]string, 0, len(trustedProxyPresets))
	for n := range trustedProxyPresets {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
