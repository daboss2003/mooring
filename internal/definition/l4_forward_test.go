package definition

import (
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/compose"
)

// kernelDNSSpec is a resolver served with forward: kernel — DNS on 53/udp + 53/tcp and DoT passthrough on
// 853/tcp, all to one copy of the service.
const kernelDNSSpec = `  compose:
    source: generated
    services:
      coredns:
        image: coredns/coredns:1.11.1
        ports:
          - { internal: 5353 }
          - { internal: 8853 }
  edge:
    l4_routes:
      - { listen: 53,  protocol: udp, service: coredns, port: 5353, forward: kernel }
      - { listen: 53,  protocol: tcp, service: coredns, port: 5353, forward: kernel }
      - { listen: 853, protocol: tcp, service: coredns, port: 8853, tls: passthrough, forward: kernel }
`

// l4Spec builds a one-service app ("dns") with one l4_route whose flow-style fields are route, plus
// extra service fields and spec sections.
func l4Spec(route, svcExtra, specExtra string) string {
	return `  compose:
    source: generated
    services:
      dns:
        image: coredns/coredns:1.11.1
` + svcExtra + `  edge:
    l4_routes:
      - { listen: 53, protocol: udp, service: dns, port: 5353` + route + ` }
` + specExtra
}

func TestL4ForwardValues(t *testing.T) {
	for _, fwd := range []string{"", ", forward: proxy", ", forward: kernel"} {
		d, err := Parse([]byte(docWith(l4Spec(fwd, "", ""))))
		if err != nil {
			t.Fatalf("%q must be accepted: %v", fwd, err)
		}
		want := strings.TrimPrefix(fwd, ", forward: ")
		if got := d.Spec.Edge.L4Routes[0].Forward; got != want {
			t.Errorf("forward = %q, want %q", got, want)
		}
		if d.Spec.Edge.L4Routes[0].Kernel() != (want == "kernel") {
			t.Errorf("Kernel() for %q = %v", want, d.Spec.Edge.L4Routes[0].Kernel())
		}
	}
	for _, bad := range []string{"nat", "KERNEL", "direct"} {
		_, err := Parse([]byte(docWith(l4Spec(", forward: "+bad, "", ""))))
		if err == nil || !strings.Contains(err.Error(), "forward") {
			t.Errorf("forward %q must be refused, got %v", bad, err)
		}
	}
}

// A kernel route serves exactly one copy: no lb, no fixed replicas > 1, no enabled autoscaling. A
// disabled scaling entry is fine, and so is replicas: 1.
func TestL4KernelOneCopyRules(t *testing.T) {
	refused := map[string]struct{ doc, want string }{
		"lb":              {docWith(l4Spec(", forward: kernel, lb: hash_client_ip", "", "")), "remove lb"},
		"replicas 2":      {docWith(l4Spec(", forward: kernel", "        replicas: 2\n", "")), "one copy"},
		"scaling enabled": {docWith(l4Spec(", forward: kernel", "", "  scaling:\n    - {service: dns, enabled: true, min: 1, max: 3}\n")), "one copy"},
		// The existing rule stays: a service may not publish a host port an l4_route owns.
		"published on 53": {docWith(l4Spec(", forward: kernel", "        ports:\n          - { internal: 5353, publish: true, public: true, published: 53, protocol: udp }\n", "")), "owned by an edge l4_route"},
	}
	for name, tc := range refused {
		if _, err := Parse([]byte(tc.doc)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: a kernel route must be refused with %q, got %v", name, tc.want, err)
		}
	}
	accepted := map[string]string{
		"scaling disabled": docWith(l4Spec(", forward: kernel", "", "  scaling:\n    - {service: dns, enabled: false, min: 1, max: 3}\n")),
		"replicas 1":       docWith(l4Spec(", forward: kernel", "        replicas: 1\n", "")),
		"proxy with lb":    docWith(l4Spec(", forward: proxy, lb: hash_client_ip", "", "")),
		"proxy scaled":     docWith(l4Spec(", forward: proxy", "", "  scaling:\n    - {service: dns, enabled: true, min: 1, max: 3}\n")),
	}
	for name, doc := range accepted {
		if _, err := Parse([]byte(doc)); err != nil {
			t.Errorf("%s: must be accepted: %v", name, err)
		}
	}
}

func TestL4ForwardCanonicalRoundTrip(t *testing.T) {
	d, err := Parse([]byte(docWith(kernelDNSSpec)))
	if err != nil {
		t.Fatal(err)
	}
	canon, err := Canonical(d)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := Parse(canon)
	if err != nil {
		t.Fatalf("canonical does not re-parse: %v\n%s", err, canon)
	}
	for i, r := range d2.Spec.Edge.L4Routes {
		if r.Forward != "kernel" {
			t.Errorf("route %d lost forward after the round trip:\n%s", i, canon)
		}
	}
	// A route without forward stays without it, so a stored canonical is unchanged.
	plain, err := Parse([]byte(docWith(l4Spec("", "", ""))))
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := Canonical(plain); strings.Contains(string(c), "forward") {
		t.Errorf("an unset forward must not be written:\n%s", c)
	}
}

// Kernel routes publish their listen port on the target service, bound to 0.0.0.0 (IPv4 only), in
// definition order after the service's own ports.
func TestL4KernelCompose(t *testing.T) {
	d, err := Parse([]byte(docWith(kernelDNSSpec)))
	if err != nil {
		t.Fatal(err)
	}
	out, err := ComposeBytes(d)
	if err != nil {
		t.Fatal(err)
	}
	want := "        ports:\n" +
		"            - 0.0.0.0:53:5353/udp\n" +
		"            - 0.0.0.0:53:5353/tcp\n" +
		"            - 0.0.0.0:853:8853/tcp\n"
	if !strings.Contains(string(out), want) {
		t.Fatalf("kernel routes not published as expected:\n%s", out)
	}
	if strings.Count(string(out), "0.0.0.0:") != 3 || strings.Contains(string(out), "[::]") {
		t.Errorf("exactly the three IPv4 publishes expected:\n%s", out)
	}
	if res := compose.ValidateBytes(out, compose.Env{}, "/srv/apps/shop", compose.Options{}); !res.OK() {
		t.Fatalf("kernel compose failed §5.6: %s", res.Error())
	}
	// The service's own published port comes first, then the routes in definition order.
	d.Spec.Compose.Services["coredns"] = func() Service {
		s := d.Spec.Compose.Services["coredns"]
		s.Ports = append(s.Ports, Port{Internal: 9153, Publish: true})
		return s
	}()
	out, err = ComposeBytes(d)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "        ports:\n            - 127.0.0.1:9153:9153\n            - 0.0.0.0:53:5353/udp\n") {
		t.Errorf("own ports must come before the kernel publishes:\n%s", out)
	}
}

// A proxy route never publishes anything: forward: proxy renders exactly what no forward does.
func TestL4ProxyRouteAddsNoPublish(t *testing.T) {
	var outs []string
	for _, fwd := range []string{"", ", forward: proxy"} {
		d, err := Parse([]byte(docWith(l4Spec(fwd, "", ""))))
		if err != nil {
			t.Fatal(err)
		}
		out, err := ComposeBytes(d)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out), "ports") {
			t.Errorf("a proxy route must not publish a port:\n%s", out)
		}
		outs = append(outs, string(out))
	}
	if outs[0] != outs[1] {
		t.Errorf("forward: proxy must render like no forward:\n%s\n---\n%s", outs[0], outs[1])
	}
}

// existingL4App is an app with proxy l4_routes and its own published ports; existingL4Compose is its
// compose as generated at 6abdcf5, before forward existed. It must stay byte-identical so an upgrade
// recreates nothing.
const existingL4App = `  compose:
    source: generated
    services:
      coredns:
        image: coredns/coredns:1.11.1
        ports:
          - { internal: 5353 }
      web:
        image: nginx:1.27
        ports:
          - { internal: 8080, publish: true }
          - { internal: 8853, publish: true, public: true, published: 8853, protocol: tcp }
          - { internal: 5300, publish: true, public: true, protocol: udp }
  edge:
    l4_routes:
      - { listen: 53, protocol: udp, service: coredns, port: 5353, lb: hash_client_ip }
      - { listen: 53, protocol: tcp, service: coredns, port: 5353 }
      - { listen: 853, protocol: tcp, service: coredns, port: 5353, tls: passthrough }
`

const existingL4Compose = `name: shop
services:
    coredns:
        image: coredns/coredns:1.11.1
    web:
        image: nginx:1.27
        ports:
            - 127.0.0.1:8080:8080
            - 8853:8853/tcp
            - 5300:5300/udp
`

func TestL4ExistingAppComposeByteIdentical(t *testing.T) {
	d, err := Parse([]byte(docWith(existingL4App)))
	if err != nil {
		t.Fatal(err)
	}
	out, err := ComposeBytes(d)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != existingL4Compose {
		t.Fatalf("an existing app's compose changed:\n--- got\n%s--- want\n%s", out, existingL4Compose)
	}
}
