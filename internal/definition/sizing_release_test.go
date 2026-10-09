package definition

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/compose"
)

// replicas / cpus / logs / release / route lb parse, survive Canonical → Parse, and reach the
// generated compose (scale, cpus).
func TestSizingAndReleaseRoundTripAndCompose(t *testing.T) {
	spec := `  compose:
    services:
      api:
        build: {language: node}
        cpus: "1.5"
        logs: {retain: 30d, max_lines: 200000}
      worker:
        build: {language: node}
        replicas: 3
        cpus: "0.25"
  edge:
    routes:
      - {hostname: api.example.com, service: api, port: 3000, path_prefix: /, lb: cookie}
  release:
    service: api
    command: [node, dist/migrate.js]
    timeout: 5m
    previews: true
`
	d, err := Parse([]byte(docWith(spec)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if w := d.Spec.Compose.Services["worker"]; w.Replicas != 3 || w.CPUs != "0.25" {
		t.Fatalf("worker = %+v", w)
	}
	if l := d.Spec.Compose.Services["api"].Logs; l == nil || l.Retain != "30d" || l.MaxLines != 200000 {
		t.Fatalf("api logs = %+v", l)
	}
	if r := d.Spec.Release; r == nil || r.Service != "api" || strings.Join(r.Command, " ") != "node dist/migrate.js" || !r.Previews || r.TimeoutD() != 5*time.Minute {
		t.Fatalf("release = %+v", r)
	}
	if lb := d.Spec.Edge.Routes[0].LB; lb != "cookie" {
		t.Fatalf("route lb = %q", lb)
	}
	canon, err := Canonical(d)
	if err != nil {
		t.Fatal(err)
	}
	d2, err := Parse(canon)
	if err != nil {
		t.Fatalf("canonical does not re-parse: %v\n%s", err, canon)
	}
	if d2.Spec.Compose.Services["worker"].Replicas != 3 || d2.Spec.Release == nil || d2.Spec.Edge.Routes[0].LB != "cookie" || d2.Spec.Compose.Services["api"].Logs == nil {
		t.Fatalf("canonical lost a field:\n%s", canon)
	}
	out, err := ComposeBytes(d)
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{"cpus: 1.5", "cpus: 0.25", "scale: 3"} {
		if !strings.Contains(s, want) {
			t.Errorf("compose missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "logs") || strings.Contains(s, "migrate") {
		t.Errorf("logs/release must not leak into the compose:\n%s", s)
	}
}

func TestSizingAndReleaseRejections(t *testing.T) {
	cases := map[string]string{
		"replicas with scaling": `  compose: {services: {web: {image: nginx:1, replicas: 2}}}
  edge: {routes: [{hostname: a.example.com, service: web, port: 80}]}
  scaling: [{service: web, enabled: true, min: 1, max: 3}]`,
		"replicas on a scheduled service": `  compose: {services: {job: {image: alpine:3, replicas: 1}}}
  scheduled_tasks: [{name: nightly, service: job, every: 24h}]`,
		"replicas over the cap":      `  compose: {services: {web: {image: nginx:1, replicas: 21}}}`,
		"negative replicas":          `  compose: {services: {web: {image: nginx:1, replicas: -1}}}`,
		"writable volume replicated": `  compose: {services: {web: {image: nginx:1, replicas: 2, volumes: [{name: data, target: /data}]}}}`,
		"published port replicated":  `  compose: {services: {web: {image: nginx:1, replicas: 2, ports: [{internal: 8080, publish: true}]}}}`,
		"cpus not a number":          `  compose: {services: {web: {image: nginx:1, cpus: "1,5"}}}`,
		"cpus zero":                  `  compose: {services: {web: {image: nginx:1, cpus: "0.00"}}}`,
		"cpus three decimals":        `  compose: {services: {web: {image: nginx:1, cpus: "0.125"}}}`,
		"logs retain bad":            `  compose: {services: {web: {image: nginx:1, logs: {retain: 1d12h}}}}`,
		"logs max_lines negative":    `  compose: {services: {web: {image: nginx:1, logs: {max_lines: -5}}}}`,
		"lb unknown": `  compose: {services: {web: {image: nginx:1}}}
  edge: {routes: [{hostname: a.example.com, service: web, port: 80, lb: sticky}]}`,
		"release unknown service": `  compose: {services: {web: {image: nginx:1}}}
  release: {service: api, command: [migrate]}`,
		"release no command": `  compose: {services: {web: {image: nginx:1}}}
  release: {service: web}`,
		"release timeout too long": `  compose: {services: {web: {image: nginx:1}}}
  release: {service: web, command: [migrate], timeout: 2h}`,
		"release timeout too short": `  compose: {services: {web: {image: nginx:1}}}
  release: {service: web, command: [migrate], timeout: 1s}`,
		"release empty argument": `  compose: {services: {web: {image: nginx:1}}}
  release: {service: web, command: [migrate, ""]}`,
	}
	for name, spec := range cases {
		_, err := Parse([]byte(docWith(spec)))
		if err == nil {
			t.Errorf("%s: accepted, want a rejection", name)
		}
		t.Logf("%s: %v", name, err)
	}
	ok := map[string]string{
		"one stateful copy":           `  compose: {services: {db: {image: postgres:16, replicas: 1}}}`,
		"read-only volume replicated": `  compose: {services: {web: {image: nginx:1, replicas: 2, volumes: [{name: assets, target: /assets, read_only: true}]}}}`,
		"internal port replicated":    `  compose: {services: {web: {image: nginx:1, replicas: 2, ports: [{internal: 8080}]}}}`,
		"whole cpus":                  `  compose: {services: {web: {image: nginx:1, cpus: "2"}}}`,
		"release default timeout": `  compose: {services: {web: {image: nginx:1}}}
  release: {service: web, command: [migrate]}`,
	}
	for name, spec := range ok {
		if _, err := Parse([]byte(docWith(spec))); err != nil {
			t.Errorf("%s: rejected: %v", name, err)
		}
	}
}

// More than one copy of a stateful image is refused when a definition is submitted (a git deploy, `mooring
// validate`), never when a stored canonical is read: the stateful image list grows between versions, and an
// upgrade must not make a stored definition unreadable.
func TestStatefulReplicasRejectedAtSubmitOnly(t *testing.T) {
	d, err := Parse([]byte(docWith(`  compose: {services: {db: {image: postgres:16, replicas: 2}}}`)))
	if err != nil {
		t.Fatalf("a stored canonical with replicas on a stateful image must still parse: %v", err)
	}
	if err := ValidateForSubmit(d); err == nil || !strings.Contains(err.Error(), "stateful image") {
		t.Errorf("ValidateForSubmit = %v, want the stateful-image refusal", err)
	}
	if err := Validate(d, "/run/app", compose.Env{}, nil); err == nil || !strings.Contains(err.Error(), "stateful image") {
		t.Errorf("Validate (mooring validate) = %v, want the stateful-image refusal", err)
	}
	s, _ := testStore(t)
	if _, err := s.SaveCanonical(context.Background(), d, "stored before an upgrade", ""); err != nil {
		t.Fatal(err)
	}
	if cur, err := s.Current("shop"); err != nil || cur == nil || cur.Spec.Compose.Services["db"].Replicas != 2 {
		t.Fatalf("the stored canonical must stay readable, got %v %v", cur, err)
	}
	one, err := Parse([]byte(docWith(`  compose: {services: {db: {image: postgres:16, replicas: 1}, web: {image: nginx:1, replicas: 3}}}`)))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateForSubmit(one); err != nil {
		t.Errorf("one stateful copy and a replicated stateless service must pass: %v", err)
	}
}
