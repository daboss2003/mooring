package web

import (
	"testing"

	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/definition"
)

func TestExpandSubdomains(t *testing.T) {
	s := &Server{cfg: &config.Config{Edge: config.EdgeConfig{BaseDomain: "mooring.example.com"}}}
	def := &definition.Definition{}
	def.Spec.Edge.Routes = []definition.Route{
		{Subdomain: "api", Service: "api", Port: 3000},
		{Hostname: "shop.other.com", Service: "web"}, // literal untouched
	}
	def.Spec.Compose.Services = map[string]definition.Service{
		"emqx": {CertBindings: []definition.CertBinding{{Subdomain: "mqtt", Mount: "/etc/certs"}}},
	}
	if err := s.expandSubdomains(def); err != nil {
		t.Fatal(err)
	}
	// Route subdomain → FQDN, Subdomain cleared (so re-validation sees a plain hostname).
	if got := def.Spec.Edge.Routes[0].Hostname; got != "api.mooring.example.com" {
		t.Errorf("route host = %q, want api.mooring.example.com", got)
	}
	if def.Spec.Edge.Routes[0].Subdomain != "" {
		t.Error("route Subdomain not cleared after expansion")
	}
	if def.Spec.Edge.Routes[1].Hostname != "shop.other.com" {
		t.Error("literal hostname was altered")
	}
	// Cert binding subdomain → FQDN (mutated in the shared backing array), Subdomain cleared.
	cb := def.Spec.Compose.Services["emqx"].CertBindings[0]
	if cb.Hostname != "mqtt.mooring.example.com" || cb.Subdomain != "" {
		t.Errorf("cert binding = %+v, want mqtt.mooring.example.com + cleared subdomain", cb)
	}

	// A subdomain with NO base_domain is a clear, early error.
	s2 := &Server{cfg: &config.Config{Edge: config.EdgeConfig{}}}
	d2 := &definition.Definition{}
	d2.Spec.Edge.Routes = []definition.Route{{Subdomain: "api", Service: "api"}}
	if err := s2.expandSubdomains(d2); err == nil {
		t.Fatal("subdomain without edge.base_domain must error")
	}
}
