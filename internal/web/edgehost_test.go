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

// TestExpandSubdomainsNamespaces covers named base_domains and the precedence
// per-item base_domain > spec.edge.base_domain > default scalar base_domain.
func TestExpandSubdomainsNamespaces(t *testing.T) {
	cfg := &config.Config{Edge: config.EdgeConfig{
		BaseDomain: "prod.example.com", // the DEFAULT (unnamed) namespace
		BaseDomains: []config.EdgeBaseDomain{
			{Name: "staging", Domain: "staging.example.com"},
			{Name: "edge", Domain: "edge.example.com"},
		},
	}}
	s := &Server{cfg: cfg}

	// App-level base_domain picks the namespace for every shorthand in the app…
	def := &definition.Definition{}
	def.Spec.Edge.BaseDomain = "staging"
	def.Spec.Edge.Routes = []definition.Route{
		{Subdomain: "api", Service: "api"},                     // → api.staging.example.com (app default)
		{Subdomain: "cdn", BaseDomain: "edge", Service: "cdn"}, // per-item override → cdn.edge.example.com
	}
	def.Spec.Compose.Services = map[string]definition.Service{
		"emqx": {CertBindings: []definition.CertBinding{{Subdomain: "mqtt", Mount: "/etc/certs"}}}, // → mqtt.staging.example.com
	}
	if err := s.expandSubdomains(def); err != nil {
		t.Fatal(err)
	}
	if got := def.Spec.Edge.Routes[0].Hostname; got != "api.staging.example.com" {
		t.Errorf("app-default namespace: route host = %q, want api.staging.example.com", got)
	}
	if got := def.Spec.Edge.Routes[1].Hostname; got != "cdn.edge.example.com" {
		t.Errorf("per-item override: route host = %q, want cdn.edge.example.com", got)
	}
	if def.Spec.Edge.Routes[1].BaseDomain != "" {
		t.Error("per-item BaseDomain not cleared after expansion")
	}
	if cb := def.Spec.Compose.Services["emqx"].CertBindings[0]; cb.Hostname != "mqtt.staging.example.com" {
		t.Errorf("cert binding under app namespace = %q, want mqtt.staging.example.com", cb.Hostname)
	}
	// App-level Edge.BaseDomain is KEPT (records the namespace, read by preview pinning);
	// per-item overrides are cleared (re-validation rejects base_domain without a subdomain).
	if def.Spec.Edge.BaseDomain != "staging" {
		t.Errorf("app-level Edge.BaseDomain = %q, want it preserved as staging", def.Spec.Edge.BaseDomain)
	}

	// No app-level base_domain → falls back to the default scalar base_domain.
	d2 := &definition.Definition{}
	d2.Spec.Edge.Routes = []definition.Route{{Subdomain: "api", Service: "api"}}
	if err := s.expandSubdomains(d2); err != nil {
		t.Fatal(err)
	}
	if got := d2.Spec.Edge.Routes[0].Hostname; got != "api.prod.example.com" {
		t.Errorf("default namespace: route host = %q, want api.prod.example.com", got)
	}

	// An UNDECLARED namespace name is a hard, fail-closed error (operator must whitelist it).
	d3 := &definition.Definition{}
	d3.Spec.Edge.BaseDomain = "ghost"
	d3.Spec.Edge.Routes = []definition.Route{{Subdomain: "api", Service: "api"}}
	if err := s.expandSubdomains(d3); err == nil {
		t.Fatal("an undeclared base_domain namespace must be a fail-closed error")
	}
}
