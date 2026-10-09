package edge

import (
	"net/netip"
	"reflect"
	"testing"
)

// Every shipped Cloudflare range parses as a canonical CIDR, none trusts everyone, there are no
// duplicates, and both address families are present.
func TestCloudflareRangesParse(t *testing.T) {
	var v4, v6 int
	seen := map[string]bool{}
	for _, s := range cloudflareRanges {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			t.Errorf("%q is not a CIDR: %v", s, err)
			continue
		}
		if p.Masked().String() != s {
			t.Errorf("%q is not canonical (want %s)", s, p.Masked())
		}
		if p.Bits() == 0 {
			t.Errorf("%q trusts every address", s)
		}
		if p.Addr().Is4In6() {
			t.Errorf("%q is an IPv4-mapped IPv6 range", s)
		}
		if seen[s] {
			t.Errorf("%q is listed twice", s)
		}
		seen[s] = true
		if p.Addr().Is4() {
			v4++
		} else {
			v6++
		}
	}
	if v4 == 0 || v6 == 0 {
		t.Errorf("want IPv4 and IPv6 ranges, got %d v4 and %d v6", v4, v6)
	}
}

func TestTrustedProxyPresets(t *testing.T) {
	if got := TrustedProxyPresetNames(); !reflect.DeepEqual(got, []string{"cloudflare"}) {
		t.Errorf("preset names = %v", got)
	}
	r, ok := TrustedProxyPreset("cloudflare")
	if !ok || !reflect.DeepEqual(r, cloudflareRanges) {
		t.Fatalf("cloudflare preset = %v, %v", r, ok)
	}
	r[0] = "0.0.0.0/0" // the caller's copy is its own
	if cloudflareRanges[0] == "0.0.0.0/0" {
		t.Error("TrustedProxyPreset must return a copy")
	}
	for _, name := range []string{"", "Cloudflare", "CLOUDFLARE", "fastly", "cloudflare "} {
		if _, ok := TrustedProxyPreset(name); ok {
			t.Errorf("%q must not be a preset", name)
		}
	}
}
