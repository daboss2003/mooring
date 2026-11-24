package web

import (
	"bytes"
	"net/url"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/redact"
)

// redactingSecurityLogs is the fake pipeline with real redaction behind SearchValue, SearchText and
// SecretField (as securityLogsSource in cmd/mooring wires it).
type redactingSecurityLogs struct {
	*fakeSecurityLogs
	red *redact.Redactor
}

func (r redactingSecurityLogs) SearchValue(field, value string) string {
	return r.red.SearchValue(field, value)
}
func (r redactingSecurityLogs) SearchText(text string) string { return r.red.SearchText(text) }
func (r redactingSecurityLogs) SecretField(field string) bool { return r.red.SecretField(field) }

func testRedactor(t *testing.T) *redact.Redactor {
	t.Helper()
	red, err := redact.New(bytes.Repeat([]byte{7}, 32), redact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return red
}

// storedForm is what redaction keeps for the F field key = value of an incoming event.
func storedForm(t *testing.T, red *redact.Redactor, key, value string) string {
	t.Helper()
	e := siem.Event{F: map[string]any{key: value}}
	red.Apply(&e)
	s, _ := e.F[key].(string)
	return s
}

// A term on f.<key> searches for the value as it was stored, and redaction classifies the full key:
// under a personal-data parent (phone.number, account.id) the stored value is a hash even when the
// last element alone is not personal data.
func TestStoredValueMatchesRedaction(t *testing.T) {
	red := testRedactor(t)
	sv := storedValue(redactingSecurityLogs{&fakeSecurityLogs{}, red})
	for _, c := range []struct {
		key, value string
		personal   bool
	}{
		{"phone.number", "8012345678", true},
		{"phone.number", "+2348012345678", true},
		{"account.id", "ACC-1029", true},
		{"user.email", "Bob@Example.com", true},
		{"email", "bob@example.com", true},
		{"status", "500", false},
		{"order.id", "A-77", false},
		{"device.model", "Pixel 8", false},
	} {
		stored := storedForm(t, red, c.key, c.value)
		if hashed := stored != c.value; hashed != c.personal {
			t.Fatalf("fixture: %s=%q is stored as %q (personal %v)", c.key, c.value, stored, c.personal)
		}
		got, changed := sv("f."+c.key, c.value)
		if got != stored || changed != c.personal {
			t.Errorf("storedValue(f.%s, %q) = %q %v, want the stored %q %v", c.key, c.value, got, changed, stored, c.personal)
		}
	}
	// A prefix pattern and an already-stored hash stay as typed.
	hash := storedForm(t, red, "phone.number", "8012345678")
	for _, v := range []string{"80123*", "*", hash} {
		if got, changed := sv("f.phone.number", v); got != v || changed {
			t.Errorf("storedValue(f.phone.number, %q) = %q %v, want it unchanged", v, got, changed)
		}
	}
}

// Through the page: the search reaches the store with the stored hash, and the clear value stays
// out of the page and the audit log.
func TestSecuritySearchHashesPersonalDataUnderAParent(t *testing.T) {
	realQueryParser(t)
	red := testRedactor(t)
	f := &fakeSecurityLogs{}
	e := securityEnv(t, nil)
	e.srv.securityLogs = redactingSecurityLogs{f, red}
	const clear = "8012345678"
	_, body := e.get(t, "/security?q="+url.QueryEscape("f.phone.number:"+clear+" f.status:500"), e.loginAs(t, "operator"))
	if len(f.searches) != 1 {
		t.Fatalf("searches = %d", len(f.searches))
	}
	terms := f.searches[0].Terms
	want := []string{"f.phone.number:" + storedForm(t, red, "phone.number", clear), "f.status:500"}
	if len(terms) != len(want) {
		t.Fatalf("terms = %+v", terms)
	}
	for i, term := range terms {
		if got := term.Field + ":" + term.Value; got != want[i] {
			t.Errorf("term %d = %q, want %q", i, got, want[i])
		}
	}
	if strings.Contains(body, clear) {
		t.Error("the page shows the clear value")
	}
	for _, r := range secAuditRows(t, e, "security_logs_search") {
		if strings.Contains(r.Detail, clear) {
			t.Errorf("audit detail keeps the clear value: %q", r.Detail)
		}
	}
}
