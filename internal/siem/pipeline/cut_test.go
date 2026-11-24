package pipeline

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/redact"
)

const victim = "john.doe.victim@example.com"

func realRedactor(t *testing.T) func(*siem.Event) {
	t.Helper()
	r, err := redact.New(bytes.Repeat([]byte{7}, 32), redact.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return r.Apply
}

// jwt is a token whose payload names victim; its header and payload alone (a cut signature) still
// reveal the email once decoded.
func jwt(padTo int) string {
	enc := base64.RawURLEncoding
	payload := `{"email":"` + victim + `","pad":"`
	payload += strings.Repeat("p", max(0, padTo-len(payload))) + `"}`
	return enc.EncodeToString([]byte(`{"alg":"HS256"}`)) + "." + enc.EncodeToString([]byte(payload)) + "." + strings.Repeat("s", 43)
}

// at returns filler that ends at offset off (words separated by spaces), followed by s.
func at(off int, s string) string {
	return strings.Repeat("w ", off/2) + strings.Repeat("w", off%2) + s
}

// A secret or personal value that straddles a bound is redacted whole before the final cut, so no
// readable prefix of it is stored.
func TestRedactionSeesValuesStraddlingTheCut(t *testing.T) {
	payloadPrefix := base64.RawURLEncoding.EncodeToString([]byte(`{"email":"`))[:10]
	// A long token redacted near the start shortens Msg: a fragment left at the redaction cut
	// (bound + slack) must not move under the bound and survive. The address starts 8 bytes before
	// that cut.
	long := "got " + jwt(2000) + " "
	shifted := long + at(siem.MaxMsg+cutSlack-8-len("user ")-len(long), "user "+victim+" x")
	cases := []struct {
		name  string
		msg   string
		field string
	}{
		// "…user john.doe.vi" — the cut used to fall inside the address, leaving no '@' to match.
		{name: "email across the Msg cut", msg: at(siem.MaxMsg-12, "user "+victim+" logged in")},
		// The cut used to fall inside the payload: header + payload prefix aren't a JWT any more.
		{name: "JWT across the Msg cut", msg: at(siem.MaxMsg-60, "got "+jwt(200)+" ok")},
		{name: "email across a field cut", field: at(siem.MaxFieldValue-16, "contact "+victim+" end")},
		{name: "fragment pulled under the bound", msg: shifted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t, 16, nil)
			h.p.redact = realRedactor(t)
			field := tc.field
			h.p.parse.app = func(at time.Time, app, svc, copy, text string) siem.Event {
				ev := siem.Event{TS: at, Src: siem.SrcApp, Msg: text}
				if field != "" {
					ev.F = map[string]any{"note": field}
				}
				return ev
			}
			h.run()
			h.p.AppLine(1, "app", "svc", "c", tc.msg)
			h.advance(time.Second)
			evs := h.st.events()
			if len(evs) != 1 {
				t.Fatalf("stored %d events", len(evs))
			}
			stored := evs[0].Msg
			if s, ok := evs[0].F["note"].(string); ok {
				stored += " " + s
			}
			for _, leak := range []string{"john.doe", "john.d", payloadPrefix} {
				if strings.Contains(stored, leak) {
					t.Errorf("stored text keeps %q", leak)
				}
			}
			if len(evs[0].Msg) > siem.MaxMsg {
				t.Errorf("Msg of %d bytes is over the bound", len(evs[0].Msg))
			}
		})
	}
}

// slackCut keeps short values whole, and drops the token it cuts through.
func TestSlackCut(t *testing.T) {
	if s := strings.Repeat("a", 100+cutSlack); slackCut(s, 100) != s {
		t.Error("a value within bound + slack is kept whole")
	}
	s := strings.Repeat("a", 150) + " " + strings.Repeat("b", cutSlack+50)
	if got := slackCut(s, 100); got != strings.Repeat("a", 150) {
		t.Errorf("the token across the slack cut must be dropped back to its separator: %d bytes", len(got))
	}
	s = strings.Repeat("c", 60) + " " + strings.Repeat("d", 3*cutSlack)
	if got := slackCut(s, 100); got != strings.Repeat("c", 60) {
		t.Errorf("a token running across the whole slack is dropped back to the separator before the bound: %d bytes", len(got))
	}
	if got := slackCut(strings.Repeat("e", 3*cutSlack), 100); got != "" {
		t.Errorf("a value that is one token past bound + slack is dropped whole: %d bytes", len(got))
	}
	s = strings.Repeat("é", 400) // 2-byte runes: cuts stay on a rune boundary
	if got := slackCut(s, 101); !strings.HasPrefix(s, got) || len(got)%2 != 0 {
		t.Errorf("cut inside a rune: %d bytes", len(got))
	}
}

// A token longer than the slack that begins before the bound is dropped whole, so a JWT's header and
// payload prefix (which decode to its claims) are never stored.
func TestLongTokenAcrossTheBoundIsDropped(t *testing.T) {
	enc := base64.RawURLEncoding
	header := enc.EncodeToString([]byte(`{"alg":"RS256","kid":"k1"}`))
	payload := enc.EncodeToString([]byte(`{"email":"` + victim + `","name":"John Doe","roles":["` + strings.Repeat("r", 900) + `"]}`))
	token := header + "." + payload + "." + strings.Repeat("s", 342) // about 1.6 KiB
	if len(token) <= cutSlack+200 {
		t.Fatalf("the token (%d bytes) must be longer than the slack", len(token))
	}
	for _, before := range []int{60, 200} {
		for _, inField := range []bool{false, true} {
			h := newHarness(t, 16, nil)
			h.p.redact = realRedactor(t)
			bound, text := siem.MaxMsg, ""
			if inField {
				bound = siem.MaxFieldValue
			}
			text = at(bound-before, "id_token "+token+" done")
			h.p.parse.app = func(ts time.Time, app, svc, copy, line string) siem.Event {
				if inField {
					return siem.Event{TS: ts, Src: siem.SrcApp, Msg: "x", F: map[string]any{"note": line}}
				}
				return siem.Event{TS: ts, Src: siem.SrcApp, Msg: line}
			}
			h.run()
			h.p.AppLine(1, "app", "svc", "c", text)
			h.advance(time.Second)
			evs := h.st.events()
			if len(evs) != 1 {
				t.Fatalf("stored %d events", len(evs))
			}
			stored := evs[0].Msg
			if s, ok := evs[0].F["note"].(string); ok {
				stored = s
			}
			if strings.Contains(stored, header) || strings.Contains(stored, payload[:24]) {
				t.Errorf("field=%v, %d bytes before the bound: the token's header or payload prefix was stored", inField, before)
			}
			if !strings.HasSuffix(stored, "id_token") {
				t.Errorf("field=%v, %d bytes before the bound: want the text up to the token kept, got ...%q", inField, before, stored[max(0, len(stored)-30):])
			}
		}
	}
}
