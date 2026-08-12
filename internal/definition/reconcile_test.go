package definition

import (
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/compose"
)

// base parses the canonical goodDef fixture into a Definition — the shared starting
// point for the definition tests in this package.
func base() *Definition {
	d, err := Parse([]byte(goodDef))
	if err != nil {
		panic(err)
	}
	return d
}

func TestValidateGeneratedHappyPath(t *testing.T) {
	d := base() // generated web service + edge route → web
	if err := Validate(d, "/run/app", compose.Env{}, nil); err != nil {
		t.Errorf("a clean generated definition should validate: %v", err)
	}
}

// A malformed mem_limit is rejected at validation (early), not deferred to docker; a
// valid size and the unset (empty) case both pass.
func TestValidateMemLimit(t *testing.T) {
	set := func(field, v string) *Definition {
		d := base()
		web := d.Spec.Compose.Services["web"]
		if field == "mem_limit" {
			web.MemLimit = v
		} else {
			web.MemReservation = v
		}
		d.Spec.Compose.Services["web"] = web
		return d
	}
	if err := Validate(set("mem_limit", "768x"), "/run/app", compose.Env{}, nil); err == nil || !strings.Contains(err.Error(), "mem_limit") {
		t.Errorf("a malformed mem_limit must be rejected, got %v", err)
	}
	if err := Validate(set("mem_reservation", "lots"), "/run/app", compose.Env{}, nil); err == nil {
		t.Error("a malformed mem_reservation must be rejected")
	}
	for _, ok := range []string{"768m", "1g", "768mb", "1073741824", ""} {
		if err := Validate(set("mem_limit", ok), "/run/app", compose.Env{}, nil); err != nil {
			t.Errorf("valid mem_limit %q rejected: %v", ok, err)
		}
	}
}

// A definition with ulimits.nofile must survive the FULL deploy round-trip:
// reconcile → Generate → §5.6 compose.ValidateBytes (i.e. `ulimits` is emitted and
// the generated compose is not rejected). This is what proves the feature works at
// deploy, not just at `mooring validate`.
func TestValidateUlimitsRoundTrip(t *testing.T) {
	d := base()
	web := d.Spec.Compose.Services["web"]
	web.Ulimits = &Ulimits{Nofile: &NofileLimit{Soft: 1048576, Hard: 1048576}}
	d.Spec.Compose.Services["web"] = web
	if err := Validate(d, "/run/app", compose.Env{}, nil); err != nil {
		t.Errorf("a definition with ulimits must pass reconcile + §5.6 re-validation: %v", err)
	}
	// And the generated compose actually carries the ulimits block.
	raw, err := ComposeBytes(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"ulimits:", "nofile:", "soft: 1048576"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("generated compose missing %q:\n%s", want, raw)
		}
	}
}

// stop_grace_period must be a valid positive duration; bad/zero/negative are rejected
// early, a valid duration and the unset case pass.
func TestValidateStopGracePeriod(t *testing.T) {
	set := func(v string) *Definition {
		d := base()
		web := d.Spec.Compose.Services["web"]
		web.StopGracePeriod = v
		d.Spec.Compose.Services["web"] = web
		return d
	}
	for _, bad := range []string{"60", "soon", "0s", "-5s"} {
		if err := Validate(set(bad), "/run/app", compose.Env{}, nil); err == nil || !strings.Contains(err.Error(), "stop_grace_period") {
			t.Errorf("stop_grace_period %q must be rejected, got %v", bad, err)
		}
	}
	for _, ok := range []string{"60s", "1m30s", "500ms", "1h", ""} {
		if err := Validate(set(ok), "/run/app", compose.Env{}, nil); err != nil {
			t.Errorf("valid stop_grace_period %q rejected: %v", ok, err)
		}
	}
}

func TestValidateGeneratedProducesSafeCompose(t *testing.T) {
	d := base()
	raw, err := ComposeBytes(d)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "privileged") || strings.Contains(string(raw), "9000:") {
		t.Error("generated compose must never contain dangerous keys")
	}
}

// A build service generates a compose `build:` directive pointing at the Mooring-
// generated Dockerfile path; it must NOT emit an image for that service.
func TestComposeBytesGeneratesBuild(t *testing.T) {
	d := base()
	web := d.Spec.Compose.Services["web"]
	web.Image = ""
	web.Build = &Build{Language: "node"}
	web.Env = nil
	d.Spec.Compose.Services["web"] = web
	raw, err := ComposeBytes(d)
	if err != nil {
		t.Fatalf("a build service must generate: %v", err)
	}
	out := string(raw)
	if !strings.Contains(out, "build:") || !strings.Contains(out, ".mooring/Dockerfile.web") {
		t.Errorf("generated compose must carry the build directive:\n%s", out)
	}
	if strings.Contains(out, "image:") {
		t.Errorf("a build service must not emit image:\n%s", out)
	}
}

const stackDef = `apiVersion: mooring/v1
kind: App
metadata: {slug: credlock}
spec:
  compose:
    source: generated
    services:
      api:
        image: ghcr.io/acme/api:1
        ports:
          - internal: 3000
        env:
          NODE_ENV: production
          DB_PASSWORD: { secret: DB_PASSWORD }
        depends_on: [emqx]
      emqx:
        image: emqx/emqx:5.8.3
        ports:
          - internal: 8883
            publish: true
            public: true
          - internal: 18083
        volumes:
          - name: emqx_data
            target: /opt/emqx/data
  secrets:
    - name: DB_PASSWORD
  edge:
    routes:
      - hostname: api.example.com
        service: api
        port: 3000
`

// A multi-service stack (the CredLock shape) parses, and Mooring GENERATES a compose
// carrying the public port publish, the named volume, the inline literal env, and the
// per-service secret reference (KEY=${NAME}).
func TestGeneratedMultiServiceStack(t *testing.T) {
	d, err := Parse([]byte(stackDef))
	if err != nil {
		t.Fatalf("multi-service stack rejected: %v", err)
	}
	if len(d.Spec.Compose.Services) != 2 {
		t.Fatalf("want 2 services, got %d", len(d.Spec.Compose.Services))
	}
	raw, err := ComposeBytes(d)
	if err != nil {
		t.Fatal(err)
	}
	out := string(raw)
	for _, want := range []string{"8883:8883", "emqx_data", "NODE_ENV=production", "DB_PASSWORD=${DB_PASSWORD}"} {
		if !strings.Contains(out, want) {
			t.Errorf("generated compose missing %q:\n%s", want, out)
		}
	}
}

func TestValidateEdgeUnknownService(t *testing.T) {
	d := base()
	d.Spec.Edge.Routes[0].Service = "ghost"
	if err := Validate(d, "/run/app", compose.Env{}, nil); err == nil {
		t.Error("an edge route to an unknown service must be rejected")
	}
}

func TestValidateEdgeBaseDomain(t *testing.T) {
	// Build a full mooring.yaml with a custom edge: block (Parse runs the schema validation
	// where the base_domain-namespace checks live — the package-level Validate above is the
	// separate compose gate).
	doc := func(edge string) []byte {
		return []byte(`apiVersion: mooring/v1
kind: App
metadata:
  slug: shop
spec:
  compose:
    source: generated
    services:
      web:
        image: ghcr.io/acme/web:1.2
        ports:
          - internal: 8080
  edge:
` + edge)
	}
	// Valid: app-level namespace NAME + a subdomain route (existence deferred to deploy).
	if _, err := Parse(doc("    base_domain: staging\n    routes:\n      - subdomain: api\n        service: web\n        port: 8080\n")); err != nil {
		t.Fatalf("app-level base_domain name + subdomain should validate: %v", err)
	}
	// Valid: per-item override + subdomain.
	if _, err := Parse(doc("    routes:\n      - subdomain: cdn\n        base_domain: edge\n        service: web\n        port: 8080\n")); err != nil {
		t.Fatalf("per-item base_domain override on a subdomain should validate: %v", err)
	}
	// Reject: an FQDN base_domain (it's a namespace NAME, not an apex the app can invent).
	if _, err := Parse(doc("    base_domain: staging.example.com\n    routes:\n      - hostname: shop.example.com\n        service: web\n        port: 8080\n")); err == nil {
		t.Error("an FQDN base_domain must be rejected (namespace NAME, not an apex)")
	}
	// Reject: per-item base_domain alongside a literal hostname (no subdomain) — meaningless.
	if _, err := Parse(doc("    routes:\n      - hostname: shop.example.com\n        base_domain: staging\n        service: web\n        port: 8080\n")); err == nil {
		t.Error("base_domain without a subdomain must be rejected")
	}
}

func TestDiffPlan(t *testing.T) {
	if p, _ := DiffPlan(nil, base()); !p.NewApp {
		t.Error("nil current must be a NewApp plan")
	}
	if p, _ := DiffPlan(base(), base()); !p.Empty() {
		t.Errorf("identical defs must be an empty (idempotent) plan, got %v", p.Changes)
	}
	d2 := base()
	d2.Spec.Scaling = []Scaling{{Service: "web", Max: 3}}
	p, _ := DiffPlan(base(), d2)
	if p.Empty() || len(p.Changes) == 0 {
		t.Error("a changed def must produce a non-empty plan")
	}
}

func TestValidateScalingMetrics(t *testing.T) {
	doc := func(metrics string) []byte {
		return []byte(`apiVersion: mooring/v1
kind: App
metadata:
  slug: shop
spec:
  compose:
    source: generated
    services:
      worker:
        image: ghcr.io/acme/worker:1
  scaling:
    - service: worker
      enabled: true
      min: 2
      max: 10
` + metrics)
	}
	// A valid queue metric parses.
	if _, err := Parse(doc("      metrics:\n        - name: queue\n          source: ops\n          select: jobs\n          up: 100\n          down: 40\n")); err != nil {
		t.Fatalf("valid queue metric rejected: %v", err)
	}
	// A valid edge latency metric parses (source:edge with a fixed selector).
	if _, err := Parse(doc("      metrics:\n        - name: latency\n          source: edge\n          select: p95_latency_ms\n          up: 800\n          down: 300\n")); err != nil {
		t.Fatalf("valid edge p95 metric rejected: %v", err)
	}
	if _, err := Parse(doc("      metrics:\n        - name: rate\n          source: edge\n          select: req_per_sec\n          up: 50\n          down: 10\n")); err != nil {
		t.Fatalf("valid edge req_per_sec metric rejected: %v", err)
	}
	// Multiple signals on ONE service are fine (the list is additive) — e.g. BOTH edge selectors at
	// once, distinguished by name. Scale-up fires if EITHER breaches (OR); scale-down needs BOTH calm.
	if _, err := Parse(doc("      metrics:\n        - name: latency\n          source: edge\n          select: p95_latency_ms\n          up: 800\n          down: 300\n        - name: rate\n          source: edge\n          select: req_per_sec\n          up: 50\n          down: 10\n")); err != nil {
		t.Fatalf("two edge metrics (p95 + req_per_sec) on one service rejected: %v", err)
	}
	// Rejections: up<=down (dead band), unknown source, edge with a bad/missing selector, duplicate name.
	if _, err := Parse(doc("      metrics:\n        - name: queue\n          source: ops\n          up: 40\n          down: 40\n")); err == nil {
		t.Error("up <= down must be rejected")
	}
	if _, err := Parse(doc("      metrics:\n        - name: queue\n          source: prometheus\n          up: 100\n          down: 40\n")); err == nil {
		t.Error("an unknown source must be rejected")
	}
	if _, err := Parse(doc("      metrics:\n        - name: latency\n          source: edge\n          select: cpu\n          up: 100\n          down: 40\n")); err == nil {
		t.Error("source:edge with an unknown selector must be rejected")
	}
	if _, err := Parse(doc("      metrics:\n        - name: latency\n          source: edge\n          up: 100\n          down: 40\n")); err == nil {
		t.Error("source:edge with no selector must be rejected")
	}
	if _, err := Parse(doc("      metrics:\n        - name: q\n          source: ops\n          up: 100\n          down: 40\n        - name: q\n          source: ops\n          up: 50\n          down: 10\n")); err == nil {
		t.Error("a duplicate metric name must be rejected")
	}
}
