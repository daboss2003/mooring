package redact

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/parse"
)

func TestSecretNamesRound2(t *testing.T) {
	r := newR(t, Options{})
	for _, k := range []string{"pass", "Pass", "cookies", "cookies.connect.sid", "AWS_SECRET_ACCESS_KEY",
		"env.AWS_SECRET_ACCESS_KEY", "aws.secretAccessKey", "access_key", "signingKey", "signing_key",
		"jwt_signing_key", "encryption_key", "master_key", "kms.masterKey"} {
		e := siem.Event{F: map[string]any{k: "wJalrXUtnFEMIK7MDENG"}}
		r.Apply(&e)
		if e.F[k] != "[redacted]" {
			t.Errorf("%s: %v", k, e.F[k])
		}
	}
	for _, k := range []string{"passage", "passes", "compass", "bypass", "cookie_consent", "access_key_id", "keyboard"} {
		e := siem.Event{F: map[string]any{k: "plain"}}
		r.Apply(&e)
		if e.F[k] != "plain" {
			t.Errorf("%s must stay: %v", k, e.F[k])
		}
	}
	for in, want := range map[string]string{
		"config AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENG loaded": "config AWS_SECRET_ACCESS_KEY=[redacted] loaded",
		"cookies: sid=abc; theme=dark\nnext":                       "cookies: [redacted]\nnext",
		"pass=hunter2 user=bob":                                    "pass=[redacted] user=bob",
		`{"signingKey":"c2lnbmluZ2tleQ"}`:                          `{"signingKey":"[redacted]"}`,
	} {
		e := siem.Event{Msg: in}
		r.Apply(&e)
		if e.Msg != want {
			t.Errorf("%q\n got %q\nwant %q", in, e.Msg, want)
		}
	}
}

func TestInheritance(t *testing.T) {
	r := newR(t, Options{})
	e := siem.Event{F: map[string]any{
		"password.new": "Hunter2", "password.old": "Old1", "session.id": "s1", "cookies.connect.sid": "c1",
		"token.value": "t1", "credentials.username": "u1", "req.session.cookie.maxAge": 86400000.0,
		"auth.token.expires_in": 3600.0, "session.secure": true,
		"phone.number": "8031234567", "phone.country": "234", "email.address": "a@b.co", "account.id": "acc1",
		"account.balance": 5000.0, "device_id.vendor": "acme", "user_email.domain": "b.co", "email.verified": true,
		"location.city": "Ikeja", "gps.alt": 41.0, "coords.x": 6.5,
		"location.email": "a@b.co", "email.lat": 6.5, "email.signature": strings.Repeat("ab12", 16), "req.method": "GET",
	}}
	r.Apply(&e)
	want := map[string]any{
		"password.new": "[redacted]", "password.old": "[redacted]", "session.id": "[redacted]",
		"cookies.connect.sid": "[redacted]", "token.value": "[redacted]", "credentials.username": "[redacted]",
		"req.session.cookie.maxAge": 86400000.0, "auth.token.expires_in": 3600.0, "session.secure": true, // measures (round 3)
		"phone.number": r.Hash("8031234567"), "phone.country": r.Hash("234"), "email.address": r.Hash("a@b.co"),
		"account.id": r.Hash("acc1"), "account.balance": r.Hash("5000"), "device_id.vendor": r.Hash("acme"),
		"user_email.domain": r.Hash("b.co"), "email.verified": true,
		"email.signature": r.Hash(strings.Repeat("ab12", 16)), "req.method": "GET",
	}
	for k, v := range want {
		if e.F[k] != v {
			t.Errorf("%s: got %v want %v", k, e.F[k], v)
		}
	}
	for _, k := range []string{"location.city", "gps.alt", "coords.x", "location.email", "email.lat"} {
		if _, ok := e.F[k]; ok {
			t.Errorf("%s must be dropped (drop beats hash): %v", k, e.F[k])
		}
	}
	if !r.Hashed("phone.number") || r.Hashed("location.city") || r.Hashed("session.id") {
		t.Error("Hashed must follow inheritance")
	}
	if r.SearchValue("phone.number", "803") != r.Hash("803") || r.SearchValue("session.id", "abc") != "abc" {
		t.Error("SearchValue must follow inheritance")
	}
	// In text a key's last element decides (round 3: host:port is not a nested key).
	m := siem.Event{Msg: "user.password=x a.session=y user.phone=803 device.lat=Ikeja user.name=bob password.new=z"}
	r.Apply(&m)
	if wantMsg := "user.password=[redacted] a.session=[redacted] user.phone=" + r.Hash("803") + " device.lat=[redacted] user.name=bob password.new=z"; m.Msg != wantMsg {
		t.Errorf("text:\n got %q\nwant %q", m.Msg, wantMsg)
	}
	// KeepFields works on the element that matched; secrets can't be kept.
	k := newR(t, Options{KeepFields: []string{"phone", "location", "session"}})
	e = siem.Event{F: map[string]any{"phone.number": "803", "location.city": "Ikeja", "session.id": "s1"}}
	k.Apply(&e)
	if e.F["phone.number"] != "803" || e.F["location.city"] != "Ikeja" || e.F["session.id"] != "[redacted]" {
		t.Errorf("keep on the matching element: %v", e.F)
	}
	k = newR(t, Options{KeepFields: []string{"number"}})
	e = siem.Event{F: map[string]any{"phone.number": "803"}}
	k.Apply(&e)
	if e.F["phone.number"] != k.Hash("803") {
		t.Errorf("keep on a non-matching element changes nothing: %v", e.F)
	}
}

func TestBracketKeys(t *testing.T) {
	r := newR(t, Options{})
	e := siem.Event{
		Msg: "GET /login?password[]=Hunter2&token[0]=tok1&email[]=a@b.co&user[0][password]=z&items[0]=keep 200",
		F:   map[string]any{"password[]": "x", "token[0]": "y", "items[0]": "keep", "phone[1]": "803"},
	}
	r.Apply(&e)
	want := "GET /login?password[]=[redacted]&token[0]=[redacted]&email[]=" + r.Hash("a@b.co") + "&user[0][password]=[redacted]&items[0]=keep 200"
	if e.Msg != want {
		t.Errorf("text:\n got %q\nwant %q", e.Msg, want)
	}
	// A numeric element doesn't hide that the name is a header: its value runs to the end of the line.
	h := siem.Event{Msg: "cookie[0]: sid=abc; theme=dark\nnext"}
	r.Apply(&h)
	if h.Msg != "cookie[0]: [redacted]\nnext" {
		t.Errorf("cookie[0]: %q", h.Msg)
	}
	if e.F["password[]"] != "[redacted]" || e.F["token[0]"] != "[redacted]" || e.F["items[0]"] != "keep" || e.F["phone[1]"] != r.Hash("803") {
		t.Errorf("F: %v", e.F)
	}
}

func TestPersonalDataInKeys(t *testing.T) {
	r := newR(t, Options{})
	e := siem.Event{F: map[string]any{
		"attempts.victim@example%2Ecom": 3.0, // as parse flattens {"attempts":{"victim@example.com":3}}
		"sent.+2348031234567":           1.0,
		"otp.+2348031234567":            7.0, // otp is a secret name: the value is redacted too
		"rate.08031234567.count":        2.0,
		"counts.1795440881123":          4.0, // an epoch-ms key is not a phone
		"a.b":                           5.0,
		"x.john.doe@example.com":        6.0, // not escaped: hashed whole, never in clear
	}}
	r.Apply(&e)
	want := map[string]any{
		"attempts." + r.Hash("victim@example.com"): 3.0,
		"sent." + r.Hash("+2348031234567"):         1.0,
		"otp." + r.Hash("+2348031234567"):          "[redacted]",
		"rate." + r.Hash("08031234567") + ".count": 2.0,
		"counts.1795440881123":                     4.0,
		"a.b":                                      5.0,
	}
	for k, v := range want {
		if e.F[k] != v {
			t.Errorf("%s: got %v (F %v)", k, e.F[k], e.F)
		}
	}
	for k := range e.F {
		if strings.Contains(k, "john") || strings.Contains(k, "example") || strings.Contains(k, "victim") || strings.Contains(k, "8031234567") {
			t.Errorf("personal data left in key %q", k)
		}
	}
	if len(e.F) != 7 {
		t.Errorf("a key was lost: %v", e.F)
	}
	// End to end with parse: the structure is kept and the address is hashed as one value.
	ev := parse.AppLine(time.Now(), "a", "s", "c", `{"msg":"rate","attempts":{"John.Doe@Example.com":3,"a.b":1}}`)
	r.Apply(&ev)
	if ev.F["attempts."+r.Hash("john.doe@example.com")] != 3.0 || ev.F["attempts.a.b"] != 1.0 {
		t.Errorf("parse+redact: %v", ev.F)
	}
}

func TestPercentEncodedValues(t *testing.T) {
	r := newR(t, Options{})
	cases := map[string]string{
		"GET /graphql?variables=%7B%22password%22%3A%22Hunter2Hunter2%22%7D 200": "GET /graphql?variables={%22password%22:%22[redacted]%22} 200",
		"GET /graphql?variables=%7b%22password%22%3a%22Hunter2%22%7d 200":        "GET /graphql?variables={%22password%22:%22[redacted]%22} 200",
		"v=%7B%22email%22%3A%22a%40b.co%22%7D":                                   "v={%22email%22:%22" + r.Hash("a@b.co") + "%22}",
		"data=password%3Dhunter2&x=1":                                            "data=password%3D[redacted]&x=1",                 // written back encoded
		"q=%7B%22a%22%3A1%7D&page=2":                                             "q=%7B%22a%22%3A1%7D&page=2",                     // nothing to redact: unchanged
		"v=%257B%2522password%2522%253A%2522x%2522%257D":                         "v=%257B%2522password%2522%253A%2522x%2522%257D", // one level only
		"v=%22%3A": "v=%22%3A",
	}
	for in, want := range cases {
		e := siem.Event{Msg: in, F: map[string]any{"query": in}}
		r.Apply(&e)
		if e.Msg != want || e.F["query"] != want {
			t.Errorf("%q\n got %q\nwant %q", in, e.Msg, want)
		}
	}
}

func TestUnicodeEmails(t *testing.T) {
	r := newR(t, Options{})
	for _, addr := range []string{"jöhn@exämple.com", "δοκιμή@παράδειγμα.δοκιμή", "user@例え.テスト", "a@b.xn--p1ai", "名前@例え.jp"} {
		e := siem.Event{Msg: "login " + addr + " ok", Actor: addr}
		r.Apply(&e)
		if e.Msg != "login "+r.Hash(addr)+" ok" || e.Actor != r.Hash(addr) {
			t.Errorf("%s: msg %q actor %q", addr, e.Msg, e.Actor)
		}
	}
	if r.Hash("JÖHN@EXÄMPLE.COM") != r.Hash("jöhn@exämple.com") {
		t.Error("Unicode emails are lowercased")
	}
	for _, s := range []string{"name@host", "über@", "@ünïcode.de"} {
		e := siem.Event{Msg: s}
		r.Apply(&e)
		if e.Msg != s {
			t.Errorf("%q changed to %q", s, e.Msg)
		}
	}
}

func TestPhonesInText(t *testing.T) {
	r := newR(t, Options{})
	e := siem.Event{Msg: "otp sent to +2348031234567 and 08031234567, ref 1795440881123, port 52134, x08031234567y, +234 803 123, 0803123456, 3.08031234567, 080312345678"}
	r.Apply(&e)
	want := "otp sent to " + r.Hash("+2348031234567") + " and " + r.Hash("08031234567") + ", ref 1795440881123, port 52134, x08031234567y, +234 803 123, 0803123456, 3.08031234567, 080312345678"
	if e.Msg != want {
		t.Errorf("\n got %q\nwant %q", e.Msg, want)
	}
	// The same hash as a phone field and as an actor.
	f := siem.Event{Actor: "+2348031234567", F: map[string]any{"phone": "+2348031234567"}, Msg: "phone=+2348031234567"}
	r.Apply(&f)
	if f.Actor != r.Hash("+2348031234567") || f.F["phone"] != f.Actor || f.Msg != "phone="+f.Actor {
		t.Errorf("phone forms differ: %+v", f)
	}
	// A kept field keeps phone numbers as it keeps emails.
	k := newR(t, Options{KeepFields: []string{"contact"}})
	g := siem.Event{F: map[string]any{"contact": "+2348031234567"}}
	k.Apply(&g)
	if g.F["contact"] != "+2348031234567" {
		t.Errorf("kept: %v", g.F)
	}
}

func TestSearchText(t *testing.T) {
	r := newR(t, Options{})
	for _, x := range []string{
		"ada@example.com", "Ada@Example.com", "+2348031234567", "08031234567", "jöhn@exämple.com",
		"login failed for ada@example.com from 203.0.113.5", "password=hunter2", "token: abc",
		"GET /graphql?variables=%7B%22password%22%3A%22x%22%7D", "alice", "", "h:0123456789abcdef",
		"Bearer abcdef1234567890", "1795440881123", "/users/ada%40example.com",
	} {
		e := siem.Event{Msg: x}
		r.Apply(&e)
		if got := r.SearchText(x); got != e.Msg {
			t.Errorf("SearchText(%q) = %q, Apply stores %q", x, got, e.Msg)
		}
	}
	if r.SearchText("ada@example.com") != r.Hash("ada@example.com") || r.SearchText("alice") != "alice" {
		t.Error("pinned SearchText values")
	}
}

// abuse units: each repeated, they made the key=value scanner rescan to the end of the string
// at every separator.
var abuseUnits = []string{",signature=a", ";pwd=[redacted]", ";cookie=[redacted]", "password=[redacted]",
	`signature="a `, ",email=null", "signature=a=", "&token=", ":", "=", "a=b", `"k":"`, "x%22=", "%22%3A",
	"email=,", "a@", "+0", "08031234567", "[redacted]", "Bearer ", "eyJ.", "://u:", ".", "[", "%",
	`signature=\"a `, "signature='a ", "lat=[redacted]&", "%40", "a%40", "x%40y.", "signature="}

func abuseEvent(unit string, n int) siem.Event {
	s := strings.Repeat(unit, n/len(unit)+1)[:n]
	if unit == "signature=" {
		s = s[:n-1] + "," // one long base64 run holding every separator, ending where a value can't
	}
	return siem.Event{Msg: s, Actor: s, F: map[string]any{"path": s, "query": s, "x.signature": s, s[:min(len(s), 60)] + ".k": s}}
}

func timeApply(r *Redactor, unit string, n int) time.Duration {
	best := time.Duration(1 << 62)
	for i := 0; i < 5; i++ {
		e := abuseEvent(unit, n)
		runtime.GC()
		st := time.Now()
		r.Apply(&e)
		if d := time.Since(st); d < best {
			best = d
		}
	}
	return best
}

// TestApplyLinear compares each abuse unit with plain text of the same size: linear work costs a
// small constant factor more (the bounded key read at each separator); the quadratic scanner it
// replaced cost ~750x at 128 KiB. Relative, so a loaded machine slows both sides alike.
func TestApplyLinear(t *testing.T) {
	if testing.Short() || raceDetector {
		t.Skip("timing (not meaningful under the race detector)")
	}
	r := newR(t, Options{})
	const n = 128 << 10
	base := timeApply(r, "x/y", n)
	for _, u := range abuseUnits {
		if d := timeApply(r, u, n); d > 50*base+5*time.Millisecond {
			t.Errorf("unit %q: %v for 128 KiB, plain text %v (x%d): superlinear", u, d, base, d/max(base, 1))
		}
	}
}

func TestApplyAllocsBounded(t *testing.T) {
	r := newR(t, Options{})
	for _, u := range abuseUnits {
		a := testing.AllocsPerRun(3, func() { e := abuseEvent(u, 64<<10); r.Apply(&e) })
		if a > 400 {
			t.Errorf("unit %q: %.0f allocations for a 64 KiB event", u, a)
		}
	}
}

func BenchmarkApplyAbuse(b *testing.B) {
	r := newR(b, Options{})
	for _, u := range []string{",signature=a", ";pwd=[redacted]", ";cookie=[redacted]", "%22%3A", "x/y"} {
		b.Run(u, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				e := abuseEvent(u, 8<<10)
				r.Apply(&e)
			}
		})
	}
}

// An address glued to what follows (a@b.com2023) is still hashed, up to its top-level domain.
func TestEmailsGlued(t *testing.T) {
	r := newR(t, Options{})
	for in, want := range map[string]string{
		"contact a@b.com2023 now": "contact " + r.Hash("a@b.com") + "2023 now",
		"to a@b.co1.uk":           "to " + r.Hash("a@b.co1.uk"),
		"to a@b.co.":              "to " + r.Hash("a@b.co") + ".",
		"x a@b.c y":               "x a@b.c y",
		"x a@b..co y":             "x a@b..co y",
	} {
		e := siem.Event{Msg: in}
		r.Apply(&e)
		if e.Msg != want {
			t.Errorf("%q: got %q want %q", in, e.Msg, want)
		}
	}
}
