package definition

import (
	"strings"
	"testing"
)

const optionalEnvSpec = `  secrets: [{name: DB_PASSWORD}, {name: SENTRY_DSN}]
  compose:
    services:
      web:
        image: nginx:1
        env:
          DB_PASSWORD: {secret: DB_PASSWORD}
          SENTRY_DSN: {secret: SENTRY_DSN, optional: true}
          EXPLICIT_OFF: {secret: DB_PASSWORD, optional: false}
          LOG_LEVEL: info
`

// `{secret: NAME, optional: true}` parses, survives Canonical → Parse, and a plain reference (or
// optional: false) still renders as the bare `secret: NAME` mapping.
func TestEnvOptionalSecretRoundTrip(t *testing.T) {
	d, err := Parse([]byte(docWith(optionalEnvSpec)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	env := d.Spec.Compose.Services["web"].Env
	if !env["SENTRY_DSN"].Optional || env["SENTRY_DSN"].Secret != "SENTRY_DSN" {
		t.Fatalf("SENTRY_DSN = %+v, want an optional secret ref", env["SENTRY_DSN"])
	}
	if env["DB_PASSWORD"].Optional || env["EXPLICIT_OFF"].Optional {
		t.Fatalf("a ref without optional: true must not be optional: %+v / %+v", env["DB_PASSWORD"], env["EXPLICIT_OFF"])
	}
	canon, err := Canonical(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"SENTRY_DSN:\n            secret: SENTRY_DSN\n            optional: true\n",
		"DB_PASSWORD:\n            secret: DB_PASSWORD\n",
		"EXPLICIT_OFF:\n            secret: DB_PASSWORD\n",
	} {
		if !strings.Contains(string(canon), want) {
			t.Errorf("canonical missing %q:\n%s", want, canon)
		}
	}
	if strings.Contains(string(canon), "optional: false") {
		t.Errorf("optional: false must be dropped from the canonical:\n%s", canon)
	}
	d2, err := Parse(canon)
	if err != nil {
		t.Fatalf("re-parse canonical: %v\n%s", err, canon)
	}
	if again, _ := Canonical(d2); string(again) != string(canon) {
		t.Fatalf("canonical is not a fixpoint:\n%s\n---\n%s", canon, again)
	}
	if !d2.Spec.Compose.Services["web"].Env["SENTRY_DSN"].Optional {
		t.Fatal("optional lost in the canonical round trip")
	}
}

// The generated compose carries the optional marker as ${NAME:-} and escapes literal `$`.
func TestEnvOptionalReachesCompose(t *testing.T) {
	spec := strings.Replace(optionalEnvSpec, "LOG_LEVEL: info", "PRICE: \"cost $5 or $$6\"", 1)
	d, err := Parse([]byte(docWith(spec)))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	out, err := ComposeBytes(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"SENTRY_DSN=${SENTRY_DSN:-}", "DB_PASSWORD=${DB_PASSWORD}", "PRICE=cost $$5 or $$$$6"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("compose missing %q:\n%s", want, out)
		}
	}
}

func TestEnvValueMappingRejections(t *testing.T) {
	cases := map[string]string{
		"optional without secret": `{optional: true}`,
		"optional not a bool":     `{secret: DB_PASSWORD, optional: "true"}`,
		"optional as a number":    `{secret: DB_PASSWORD, optional: 1}`,
		"unknown key":             `{secret: DB_PASSWORD, default: x}`,
		"empty secret":            `{secret: "", optional: true}`,
		"secret not a scalar":     `{secret: [DB_PASSWORD]}`,
	}
	for name, v := range cases {
		spec := "  secrets: [{name: DB_PASSWORD}]\n  compose: {services: {web: {image: nginx:1, env: {X: " + v + "}}}}\n"
		if _, err := Parse([]byte(docWith(spec))); err == nil {
			t.Errorf("%s: %s must be rejected", name, v)
		}
	}
}
