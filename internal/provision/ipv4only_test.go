package provision

import (
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/compose"
)

// An IPv4Only public port binds 0.0.0.0 (never [::]); a public port without it stays a bare all-interfaces
// mapping, and a loopback one stays on 127.0.0.1.
func TestGenerateIPv4OnlyPort(t *testing.T) {
	spec := sampleSpec()
	spec.Services[0].Ports = []Port{
		{Internal: 5353, Publish: true, Public: true, Protocol: "udp", Published: 53, IPv4Only: true},
		{Internal: 8853, Publish: true, Public: true, Protocol: "tcp", Published: 853, IPv4Only: true},
		{Internal: 5300, Publish: true, Public: true, Protocol: "udp"},
		{Internal: 8080, Publish: true},
	}
	out, err := Generate(spec)
	if err != nil {
		t.Fatal(err)
	}
	want := "        ports:\n" +
		"            - 0.0.0.0:53:5353/udp\n" +
		"            - 0.0.0.0:853:8853/tcp\n" +
		"            - 5300:5300/udp\n" +
		"            - 127.0.0.1:8080:8080\n"
	if !strings.Contains(string(out), want) {
		t.Fatalf("ports rendered wrong:\n%s", out)
	}
	if res := compose.ValidateBytes(out, compose.Env{}, "/srv/apps/shop", compose.Options{}); !res.OK() {
		t.Fatalf("IPv4-only compose failed §5.6: %s", res.Error())
	}
}

func TestValidateIPv4OnlyNeedsPublicPublish(t *testing.T) {
	cases := map[string]Port{
		"loopback publish":   {Internal: 5353, Publish: true, IPv4Only: true},
		"not published":      {Internal: 5353, IPv4Only: true},
		"public, no publish": {Internal: 5353, Public: true, IPv4Only: true},
	}
	for name, p := range cases {
		spec := sampleSpec()
		spec.Services[0].Ports = []Port{p}
		if err := spec.Validate(); err == nil || !strings.Contains(err.Error(), "ipv4") {
			t.Errorf("%s: IPv4Only must be refused, got %v", name, err)
		}
	}
	spec := sampleSpec()
	spec.Services[0].Ports = []Port{{Internal: 5353, Publish: true, Public: true, IPv4Only: true}}
	if err := spec.Validate(); err != nil {
		t.Errorf("a public published IPv4-only port is valid: %v", err)
	}
}
