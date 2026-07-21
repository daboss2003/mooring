package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/daboss2003/mooring/internal/definition"
)

func ghSig(secret, body []byte) string {
	m := hmac.New(sha256.New, secret)
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func TestVerifyGitHubSig(t *testing.T) {
	secret := []byte("s3cr3t")
	body := []byte(`{"action":"opened","number":7}`)
	if !verifyGitHubSig(secret, body, ghSig(secret, body)) {
		t.Fatal("a correct signature must verify")
	}
	// Tampered body.
	if verifyGitHubSig(secret, []byte(`{"action":"opened","number":8}`), ghSig(secret, body)) {
		t.Error("a body change must fail verification")
	}
	// Wrong secret.
	if verifyGitHubSig([]byte("other"), body, ghSig(secret, body)) {
		t.Error("a wrong secret must fail verification")
	}
	// Malformed headers fail closed.
	for _, h := range []string{"", "sha1=abcd", "sha256=nothex", "sha256=", ghSig(secret, body)[:20]} {
		if verifyGitHubSig(secret, body, h) {
			t.Errorf("malformed header %q must fail", h)
		}
	}
	// Empty secret never verifies.
	if verifyGitHubSig(nil, body, ghSig(nil, body)) {
		t.Error("an empty secret must never verify")
	}
}

func TestParsePREvent(t *testing.T) {
	ev, ok := parsePREvent([]byte(`{"action":"synchronize","number":42,"pull_request":{"head":{"ref":"feature-x"}}}`))
	if !ok || ev.Action != "synchronize" || ev.Number != 42 || ev.Ref != "feature-x" {
		t.Fatalf("parse: %+v ok=%v", ev, ok)
	}
	for _, bad := range []string{`not json`, `{}`, `{"action":"opened"}`, `{"number":5}`, `{"action":"opened","number":0}`, `{"action":"opened","number":-1}`} {
		if _, ok := parsePREvent([]byte(bad)); ok {
			t.Errorf("bad payload %q should not parse", bad)
		}
	}
}

func TestPrIsOpen(t *testing.T) {
	for _, a := range []string{"opened", "reopened", "synchronize", "ready_for_review"} {
		if !prIsOpen(a) {
			t.Errorf("%s should be open", a)
		}
	}
	for _, a := range []string{"closed", "labeled", "assigned", ""} {
		if prIsOpen(a) {
			t.Errorf("%s should NOT be open", a)
		}
	}
}

func TestPreviewSlug(t *testing.T) {
	if s, ok := previewSlug("shop", 42); !ok || s != "shop-pr42" {
		t.Fatalf("previewSlug(shop,42) = %q,%v", s, ok)
	}
	if r := previewRef(42); r != "refs/pull/42/head" {
		t.Errorf("previewRef = %q", r)
	}
	// Reject invalid numbers and oversized results.
	if _, ok := previewSlug("shop", 0); ok {
		t.Error("number 0 rejected")
	}
	if _, ok := previewSlug("this-base-slug-is-really-quite-long", 123456); ok {
		t.Error("an oversized preview slug must be rejected (never create a malformed app name)")
	}
}

// A preview's edge routes are rewritten to unique slug-derived subdomains, and any fixed
// hostname is dropped — so a preview can never collide with production.
func TestApplyPreviewPrefix(t *testing.T) {
	// Single route: subdomain becomes exactly the slug; a fixed hostname is cleared.
	def := &definition.Definition{}
	def.Spec.Edge.Routes = []definition.Route{{Hostname: "shop.example.com", Service: "web"}}
	applyPreviewPrefix(def, "shop-pr42")
	if got := def.Spec.Edge.Routes[0]; got.Subdomain != "shop-pr42" || got.Hostname != "" {
		t.Fatalf("single route rewrite: %+v", got)
	}
	// Multiple routes: indexed subdomains, all fixed hostnames cleared.
	def2 := &definition.Definition{}
	def2.Spec.Edge.Routes = []definition.Route{{Subdomain: "api", Service: "api"}, {Hostname: "web.example.com", Service: "web"}}
	applyPreviewPrefix(def2, "shop-pr7")
	if def2.Spec.Edge.Routes[0].Subdomain != "shop-pr7-0" || def2.Spec.Edge.Routes[1].Subdomain != "shop-pr7-1" {
		t.Fatalf("multi route rewrite: %+v", def2.Spec.Edge.Routes)
	}
	for _, r := range def2.Spec.Edge.Routes {
		if r.Hostname != "" {
			t.Errorf("hostname must be cleared for a preview route: %+v", r)
		}
	}
	// A fork's cert_bindings and L4 routes must be STRIPPED (they could steal a prod TLS key or
	// claim a host port).
	def3 := &definition.Definition{}
	def3.Spec.Edge.Routes = []definition.Route{{Subdomain: "web", Service: "web"}}
	def3.Spec.Edge.L4Routes = []definition.L4Route{{Service: "smtp"}}
	def3.Spec.Compose.Services = map[string]definition.Service{
		"web": {
			CertBindings: []definition.CertBinding{{Hostname: "api.example.com"}},
			Ports:        []definition.Port{{Internal: 8080, Publish: true, Public: true, Published: 8080}},
		},
	}
	applyPreviewPrefix(def3, "shop-pr5")
	if len(def3.Spec.Edge.L4Routes) != 0 {
		t.Error("a preview must strip fork-controlled L4 routes")
	}
	if len(def3.Spec.Compose.Services["web"].CertBindings) != 0 {
		t.Error("a preview must strip fork-controlled cert_bindings (TLS key exfiltration)")
	}
	if p := def3.Spec.Compose.Services["web"].Ports[0]; p.Publish || p.Public || p.Published != 0 {
		t.Errorf("a preview must strip host-port publishing, got %+v", p)
	}
}
