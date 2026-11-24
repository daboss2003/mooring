package redact

import (
	"testing"

	"github.com/daboss2003/mooring/internal/siem"
)

// A secret-named field is redacted whatever its value: the measure exception (numbers and bools of
// a field under a secret parent, kept when the field's own name is a measure) never applies when
// the field's own last element is itself a secret name. "pass": 1234 may be a PIN.
func TestSecretLeafNumbersAlwaysRedacted(t *testing.T) {
	r, err := New(testKey, Options{})
	if err != nil {
		t.Fatal(err)
	}
	e := siem.Event{F: map[string]any{
		"pass": 1234.0, "checks.pass": 12.0, "pin": 4321.0, "otp.code": 123456.0, "has_password": true, "checks.pass_ok": true,
		"session.duration_ms": 25.0, "token.expires_in": 3600.0, "otp.attempts": 3.0, "session.secure": true,
	}}
	r.Apply(&e)
	for _, k := range []string{"pass", "checks.pass", "pin", "otp.code"} {
		if e.F[k] != redacted {
			t.Errorf("%s = %v, want %q", k, e.F[k], redacted)
		}
	}
	// Booleans are never redacted, whatever the name (owner decision): one can't carry a secret.
	for k, want := range map[string]any{"session.duration_ms": 25.0, "token.expires_in": 3600.0, "otp.attempts": 3.0, "session.secure": true,
		"has_password": true, "checks.pass_ok": true} {
		if e.F[k] != want {
			t.Errorf("%s = %v, want %v kept", k, e.F[k], want)
		}
	}
}
