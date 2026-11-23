package main

import (
	"encoding/base64"
	"reflect"
	"testing"

	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/edge"
	"github.com/daboss2003/mooring/internal/socketproxy"
)

// edgeBaseConfig is the edge base serve renders every config from (and setup checks a build against):
// every config.yaml edge setting, the admin vhost and the lb: cookie secret, field by field as serve
// built it inline. It carries no DNS-01 wildcard: serve adds a namespace's only while its plugin is in the
// running Caddy.
func TestEdgeBaseConfig(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	cfg := &config.Config{
		EncryptionKey: base64.StdEncoding.EncodeToString(key),
		IPAllowlist:   []string{"203.0.113.0/24", "198.51.100.7"},
		Admin:         config.AdminConfig{Listen: "127.0.0.1:2019", Subdomain: "admin", EdgeListen: "127.0.0.1:9101"},
		Edge: config.EdgeConfig{
			Mode: config.EdgeManaged, ACMEEmail: "ops@example.com", ACMECA: "https://acme.example.net/directory",
			CAs:            []config.EdgeCA{{Name: "corp", DirectoryURL: "https://ca.corp.example/acme", Email: "pki@corp.example", TrustedRoot: "/etc/mooring/corp.pem"}, {Name: "lab", DirectoryURL: "https://lab.example/acme"}},
			BaseDomain:     "example.com",
			DNS01:          &config.EdgeDNS01{Provider: "cloudflare", APIToken: "tok-cf-0123456789"},
			BaseDomains:    []config.EdgeBaseDomain{{Name: "shop", Domain: "shop.example.net", DNS01: &config.EdgeDNS01{Provider: "route53", APIToken: "tok-r53-0123456789"}}},
			TrustedProxies: []string{"cloudflare", "10.0.0.0/8"},
			ClientIPHeader: "CF-Connecting-IP",
		},
	}
	want := edge.BaseConfig{
		AdminListen:    "127.0.0.1:2019",
		ACMEEmail:      "ops@example.com",
		ACMECA:         "https://acme.example.net/directory",
		CAs:            []edge.CA{{Name: "corp", DirectoryURL: "https://ca.corp.example/acme", Email: "pki@corp.example", TrustedRoots: []string{"/etc/mooring/corp.pem"}}, {Name: "lab", DirectoryURL: "https://lab.example/acme"}},
		AdminHostname:  "admin.example.com",
		AdminAllowlist: []string{"203.0.113.0/24", "198.51.100.7"},
		AdminUpstream:  "127.0.0.1:9101",
		TrustedProxies: []string{"cloudflare", "10.0.0.0/8"},
		ClientIPHeader: "CF-Connecting-IP",
		LBCookieSecret: edge.DeriveLBCookieSecret(key),
	}
	if got := edgeBaseConfig(cfg); !reflect.DeepEqual(got, want) {
		t.Errorf("edgeBaseConfig:\n got %+v\nwant %+v", got, want)
	}

	// Defaults: the admin socket, no admin vhost, the default edge listener; a key that doesn't decode
	// gives no cookie secret (lb: cookie routes render as ip_hash).
	plain := &config.Config{EncryptionKey: "%%%", Edge: config.EdgeConfig{Mode: config.EdgeManaged}}
	want = edge.BaseConfig{AdminListen: "unix//run/mooring/caddy-admin.sock", AdminUpstream: "127.0.0.1:9001"}
	if got := edgeBaseConfig(plain); !reflect.DeepEqual(got, want) {
		t.Errorf("edgeBaseConfig (defaults):\n got %+v\nwant %+v", got, want)
	}
}

// The managed socket-proxy is the read-plane security boundary; it must be protected
// from every write path by default, without the operator listing it (review finding).
func TestProtectManagedProxy(t *testing.T) {
	// Default (managed) install: the proxy project is seeded + protected.
	cfg := &config.Config{}
	protectManagedProxy(cfg)
	if !cfg.IsProtectedProject(socketproxy.Project) {
		t.Fatalf("managed proxy %q must be protected by default", socketproxy.Project)
	}

	// Idempotent: a second call (or an operator who already listed it) doesn't dupe.
	protectManagedProxy(cfg)
	n := 0
	for _, p := range cfg.ProtectedProjects {
		if p == socketproxy.Project {
			n++
		}
	}
	if n != 1 {
		t.Errorf("proxy project listed %d times, want exactly 1 (idempotent)", n)
	}

	// Operator-listed projects are preserved alongside the seeded proxy.
	cfg2 := &config.Config{ProtectedProjects: []string{"edge-stack"}}
	protectManagedProxy(cfg2)
	if !cfg2.IsProtectedProject("edge-stack") || !cfg2.IsProtectedProject(socketproxy.Project) {
		t.Error("must preserve operator projects AND add the proxy")
	}

	// external_proxy: Mooring doesn't run the proxy, so it doesn't seed it.
	cfg3 := &config.Config{}
	cfg3.Docker.ExternalProxy = true
	protectManagedProxy(cfg3)
	if cfg3.IsProtectedProject(socketproxy.Project) {
		t.Error("with external_proxy, Mooring must not seed the proxy project")
	}
}
