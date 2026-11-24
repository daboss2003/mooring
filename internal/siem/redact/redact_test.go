package redact

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/daboss2003/mooring/internal/siem"
)

var testKey = []byte("0123456789abcdef0123456789abcdef")

func newR(t testing.TB, opt Options) *Redactor {
	t.Helper()
	r, err := New(testKey, opt)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

var hashRe = regexp.MustCompile(`^h:[0-9a-f]{16}$`)

func TestNewRejectsShortKey(t *testing.T) {
	for _, k := range [][]byte{nil, {}, []byte("short"), testKey[:31]} {
		if _, err := New(k, Options{}); err == nil {
			t.Errorf("New(%d-byte key) must fail", len(k))
		}
	}
	if _, err := New(testKey, Options{}); err != nil {
		t.Errorf("32-byte key: %v", err)
	}
	// The key is copied: changing the caller's slice afterwards changes nothing.
	k := append([]byte(nil), testKey...)
	r, _ := New(k, Options{})
	before := r.Hash("x")
	k[0] ^= 0xff
	if r.Hash("x") != before {
		t.Error("Redactor must copy its key")
	}
}

func TestSecretFieldNames(t *testing.T) {
	r := newR(t, Options{})
	secret := []string{
		"password", "Password", "PASSWORD", "user.password", "passwd", "pwd", "passphrase", "secret",
		"client_secret", "clientSecret", "token", "access_token", "accessToken", "refresh_token",
		"id_token", "api_key", "api-key", "apiKey", "api_secret", "x-api-key", "X-API-KEY",
		"req.headers.authorization", "req.headers.proxy-authorization", "req.headers.cookie",
		"res.headers.set-cookie", "session", "session_id", "sessionToken", "jwt", "otp", "totp",
		"otp_code", "pin", "cvv", "cvc", "card_number", "pan", "private_key", "credentials",
		// longer names ending in a secret word
		"db_password", "new_password", "X-Amz-Security-Token", "webhook_secret", "csrf_token",
		"aws_secret_key", "stripe_api_key", "session_cookie", "aws.credentials",
		"user[password]", "a.b.c.Password",
	}
	for _, k := range secret {
		e := siem.Event{F: map[string]any{k: "hunter2-value"}}
		r.Apply(&e)
		if e.F[k] != "[redacted]" {
			t.Errorf("%s: got %v, want [redacted]", k, e.F[k])
		}
	}
	// Numbers of a secret field are redacted too (a numeric PIN or OTP; owner decision, round 3: a
	// secret leaf is always redacted). A boolean never is: it can't carry a secret (owner decision).
	e := siem.Event{F: map[string]any{"pin": 1234.0, "otp": 123456.0, "has_password": true, "password": ""}}
	r.Apply(&e)
	if e.F["pin"] != "[redacted]" || e.F["otp"] != "[redacted]" {
		t.Errorf("numeric secrets: %v", e.F)
	}
	if e.F["has_password"] != true {
		t.Errorf("a boolean is never redacted: %v", e.F["has_password"])
	}
	if e.F["password"] != "" {
		t.Errorf("empty value stays empty: %q", e.F["password"])
	}

	plain := []string{"user", "method", "spin", "span", "japan", "tokens", "token_type", "pinned",
		"keyboard", "passage", "path", "key_fp", "session_count", "max_tokens", "status", "ua"}
	for _, k := range plain {
		e := siem.Event{F: map[string]any{k: "plain value"}}
		r.Apply(&e)
		if e.F[k] != "plain value" {
			t.Errorf("%s must not be redacted: %v", k, e.F[k])
		}
	}
}

func TestSignatureOnlyWhenLong(t *testing.T) {
	r := newR(t, Options{})
	hex64 := strings.Repeat("ab12", 16)
	b64 := "dGhpcyBpcyBhIHNpZ25hdHVyZSB2YWx1ZSB0aGF0IGlzIGxvbmc_-="
	e := siem.Event{F: map[string]any{
		"signature": hex64, "webhook.signature": b64, "X-Amz-Signature": hex64,
		"doc.signature": "John Doe", "sig.signature": "abc",
	}}
	r.Apply(&e)
	for _, k := range []string{"signature", "webhook.signature", "X-Amz-Signature"} {
		if e.F[k] != "[redacted]" {
			t.Errorf("%s: %v", k, e.F[k])
		}
	}
	if e.F["doc.signature"] != "John Doe" || e.F["sig.signature"] != "abc" {
		t.Errorf("short/plain signatures kept: %v", e.F)
	}
	// In text too.
	e = siem.Event{Msg: "GET /f?X-Amz-Signature=" + hex64 + "&sig=ok signature=Jane"}
	r.Apply(&e)
	if strings.Contains(e.Msg, hex64) || !strings.Contains(e.Msg, "signature=Jane") {
		t.Errorf("text signature: %q", e.Msg)
	}
}

func TestSecretValuePatterns(t *testing.T) {
	r := newR(t, Options{})
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJcds3xfn\n-----END RSA PRIVATE KEY-----"
	cases := []struct {
		name, in, gone, want string // want: exact output when set
	}{
		{"jwt", "auth ok " + jwt + " done", jwt, "auth ok [redacted] done"},
		{"jwt in json", `{"t":"` + jwt + `"}`, "eyJ", ""},
		{"bearer", "Bearer abcdef1234567890xyz", "abcdef1234567890xyz", "Bearer [redacted]"},
		{"bearer lower", "sent bearer a1b2c3d4e5 now", "a1b2c3d4e5", "sent bearer [redacted] now"},
		{"basic", "hdr Basic dXNlcjpwYXNzd29yZA== x", "dXNlcjpwYXNzd29yZA==", "hdr Basic [redacted] x"},
		{"basic short decodes with colon", "Basic dTpw", "dTpw", "Basic [redacted]"},
		{"pem", "key " + pem + " end", "MIIEow", "key [redacted] end"},
		{"pem openssh", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----", "b3BlbnNzaC1", "[redacted]"},
		{"pem pkcs8", "x -----BEGIN PRIVATE KEY----- MIIEvQ -----END PRIVATE KEY-----", "MIIEvQ", "x [redacted]"},
		{"pem pgp", "-----BEGIN PGP PRIVATE KEY BLOCK-----\nlQOYBF\n-----END PGP PRIVATE KEY BLOCK-----", "lQOYBF", "[redacted]"},
		{"pem truncated", "key -----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIBkg", "MHcCAQEEIBkg", "key [redacted]"},
		{"aws akia", "id=AKIAIOSFODNN7EXAMPLE ok", "AKIAIOSFODNN7EXAMPLE", "id=[redacted] ok"},
		{"aws asia", "ASIAY34FZKBOKMUTVV7A", "ASIAY34FZKBOKMUTVV7A", "[redacted]"},
		{"github ghp", "GITHUB_TOKEN=ghp_" + "1234567890abcdefghijABCDEFGHIJ123456", "ghp_1234567890", ""},
		{"github gho", "x gho_16C7e42F292c6912E7710c838347Ae178B4a y", "gho_16C7e42F", "x [redacted] y"},
		{"github ghs", "ghs_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", "ghs_aBc", "[redacted]"},
		{"github ghu ghr", "ghu_aBcDeFgHiJkLmNoPqRsTuV ghr_aBcDeFgHiJkLmNoPqRsTuV", "Ghu", "[redacted] [redacted]"},
		{"github pat", "github_pat_" + "11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz", "github_pat_", "[redacted]"},
		{"slack", "hook xox" + "b-123456789012-1234567890123-abcdefghijklmnopqrstuvwx", "xoxb-", "hook [redacted]"},
		{"slack user", "xox" + "p-1234567890-abcdefghij", "xoxp-", "[redacted]"},
		{"stripe sk", "sk_" + "live_51H8abcdefghijklmnopqrstuv", "sk_" + "live_51H8", "[redacted]"},
		{"stripe rk", "rk_" + "live_51H8abcdefghijklmnopqrstuv", "rk_live_", "[redacted]"},
		{"url userinfo", "dial postgres://admin:s3cr3t@db.internal:5432/app failed", "s3cr3t", "dial postgres://admin:[redacted]@db.internal:5432/app failed"},
		{"url userinfo https", "https://x-access-token:abc123@github.com/o/r.git", "abc123", "https://x-access-token:[redacted]@github.com/o/r.git"},
		{"kv eq", "password=hunter2 user=bob", "hunter2", "password=[redacted] user=bob"},
		{"kv json", `{"password":"hunter2","user":"bob"}`, "hunter2", `{"password":"[redacted]","user":"bob"}`},
		{"kv json spaced", `{"api_key" : "abc 123", "n": 1}`, "abc 123", `{"api_key" : "[redacted]", "n": 1}`},
		{"kv json number", `{"pin":1234,"a":1}`, "1234", `{"pin":[redacted],"a":1}`},
		{"kv colon", "token: abc123 rest", "abc123", "token: [redacted] rest"},
		{"kv single quotes", "api_key = 'x y z'", "x y z", "api_key = '[redacted]'"},
		{"kv escaped json", `{\"password\":\"hunter2\",\"u\":1}`, "hunter2", `{\"password\":\"[redacted]\",\"u\":1}`},
		{"kv flag", "run --password=hunter2 --user bob", "hunter2", "run --password=[redacted] --user bob"},
		{"kv brackets", "user[password]=hunter2&x=1", "hunter2", "user[password]=[redacted]&x=1"},
		{"kv percent key", "user%5Bpassword%5D=hunter2&x=1", "hunter2", "user%5Bpassword%5D=[redacted]&x=1"},
		{"kv arrow", `{"password" => "hunter2"}`, "hunter2", `{"password" => "[redacted]"}`},
		{"query", "GET /cb?code=1&access_token=abc&state=2", "abc", "GET /cb?code=1&access_token=[redacted]&state=2"},
		{"form", "username=bob&password=p%40ss&remember=1", "p%40ss", "username=bob&password=[redacted]&remember=1"},
		{"header cookie", "Cookie: sid=abc; theme=dark\nnext", "sid=abc", "Cookie: [redacted]\nnext"},
		{"header authorization", "Authorization: Digest username=x, response=abc", "response=abc", "Authorization: [redacted]"},
		{"header x-api-key", "X-Api-Key: k123", "k123", "X-Api-Key: [redacted]"},
		{"kv unterminated quote", `password="hunter2`, "hunter2", `password="[redacted]`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := siem.Event{Msg: c.in, F: map[string]any{"text": c.in}}
			r.Apply(&e)
			for _, got := range []string{e.Msg, e.F["text"].(string)} {
				if strings.Contains(got, c.gone) {
					t.Errorf("%q still contains %q", got, c.gone)
				}
				if c.want != "" && got != c.want {
					t.Errorf("got %q\nwant %q", got, c.want)
				}
			}
		})
	}
}

func TestPlainTextUntouched(t *testing.T) {
	r := newR(t, Options{})
	for _, s := range []string{
		"Failed password for root from 203.0.113.5 port 22 ssh2",
		"pam_unix(sshd:session): session opened for user root(uid=0) by (uid=0)",
		"Accepted publickey for deploy from 198.51.100.7 port 50122 ssh2: ED25519 SHA256:AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefg",
		"GET /health 200 13:14:41",
		"basic configuration loaded",
		"bearer authentication enabled",
		"user=bob action=login status=ok",
		"pk_live_51H8abcdefghijklmnopqrstuv is publishable",
		"connected to redis://cache:6379/0",
		"ssh://git@github.com/o/r.git",
		"image@sha256:0123456789abcdef",
		"ASIA PACIFIC region",
		"",
		"x",
	} {
		e := siem.Event{Msg: s}
		r.Apply(&e)
		if e.Msg != s {
			t.Errorf("changed:\n in %q\nout %q", s, e.Msg)
		}
	}
}

func TestIPsSurvive(t *testing.T) {
	r := newR(t, Options{})
	e := siem.Event{
		IP:  "203.0.113.7",
		Msg: "client 203.0.113.7 password=x from 2001:db8::1 via 10.0.0.1:443 and [2001:db8::2]:80",
		F:   map[string]any{"ip": "198.51.100.1", "client_ip": "2001:db8::5", "remote": "192.0.2.1:5555", "xff": "203.0.113.9, 10.0.0.1"},
	}
	r.Apply(&e)
	if e.IP != "203.0.113.7" {
		t.Errorf("IP: %q", e.IP)
	}
	for _, ip := range []string{"203.0.113.7", "2001:db8::1", "10.0.0.1:443", "[2001:db8::2]:80"} {
		if !strings.Contains(e.Msg, ip) {
			t.Errorf("Msg lost %s: %q", ip, e.Msg)
		}
	}
	want := map[string]any{"ip": "198.51.100.1", "client_ip": "2001:db8::5", "remote": "192.0.2.1:5555", "xff": "203.0.113.9, 10.0.0.1"}
	if !reflect.DeepEqual(e.F, want) {
		t.Errorf("F: %v", e.F)
	}
}

func TestQueryStringsInFields(t *testing.T) {
	r := newR(t, Options{})
	e := siem.Event{F: map[string]any{
		"query":   "token=abc&page=2",
		"uri":     "/x?api_key=k1&y=2",
		"req.url": "/login?password=p1&next=/home",
		"url":     "https://h.example.com/a?client_secret=cs1&x=1#frag",
		"path":    "/reset/eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl",
	}}
	r.Apply(&e)
	want := map[string]any{
		"query":   "token=[redacted]&page=2",
		"uri":     "/x?api_key=[redacted]&y=2",
		"req.url": "/login?password=[redacted]&next=/home",
		"url":     "https://h.example.com/a?client_secret=[redacted]&x=1#frag",
		"path":    "/reset/[redacted]",
	}
	if !reflect.DeepEqual(e.F, want) {
		t.Errorf("got  %v\nwant %v", e.F, want)
	}
}

func TestHash(t *testing.T) {
	r := newR(t, Options{})
	h := r.Hash("356938035643809")
	if !hashRe.MatchString(h) {
		t.Fatalf("format: %q", h)
	}
	if r.Hash("356938035643809") != h {
		t.Error("not deterministic")
	}
	r2 := newR(t, Options{})
	if r2.Hash("356938035643809") != h {
		t.Error("same key, different Redactor: must match")
	}
	other, _ := New([]byte("fedcba9876543210fedcba9876543210"), Options{})
	if other.Hash("356938035643809") == h {
		t.Error("different key must give a different hash")
	}
	if r.Hash("  356938035643809 \n") != h {
		t.Error("trim")
	}
	if r.Hash("John.Doe@Example.COM") != r.Hash("john.doe@example.com") {
		t.Error("emails are lowercased")
	}
	if r.Hash("ABC") == r.Hash("abc") {
		t.Error("non-emails are not lowercased")
	}
	if r.Hash(h) != h {
		t.Error("an already-hashed value is not hashed again")
	}
	if r.Hash("h:0123456789ABCDEF") == "h:0123456789ABCDEF" {
		t.Error("only a lowercase-hex hash counts as already hashed")
	}
}

func TestPIIFields(t *testing.T) {
	r := newR(t, Options{})
	hashed := []string{"imei", "IMEI", "imei1", "imei2", "meid", "serial", "serial_number", "serialNumber",
		"device_id", "deviceId", "android_id", "udid", "email", "user.email", "email_address", "phone",
		"phone_number", "msisdn", "account",
		// longer names ending in a personal-data word
		"user_email", "customer.contact_phone", "device_imei", "bank_account", "account_number"}
	for _, k := range hashed {
		e := siem.Event{F: map[string]any{k: " Value-1 "}}
		r.Apply(&e)
		if e.F[k] != r.Hash("Value-1") {
			t.Errorf("%s: got %v, want %s", k, e.F[k], r.Hash("Value-1"))
		}
		if !r.Hashed(k) {
			t.Errorf("Hashed(%q) = false", k)
		}
	}
	// A numeric IMEI hashes like its string form.
	e := siem.Event{F: map[string]any{"imei": 356938035643809.0, "phone": "+2348012345678", "email": "Ada@Example.com", "email_verified": true}}
	r.Apply(&e)
	if e.F["imei"] != r.Hash("356938035643809") {
		t.Errorf("numeric imei: %v", e.F["imei"])
	}
	if e.F["email"] != r.Hash("ada@example.com") || e.F["phone"] != r.Hash("+2348012345678") {
		t.Errorf("email/phone: %v", e.F)
	}
	if e.F["email_verified"] != true {
		t.Error("bool kept")
	}
	// Already hashed stays.
	e = siem.Event{F: map[string]any{"email": "h:0123456789abcdef"}}
	r.Apply(&e)
	if e.F["email"] != "h:0123456789abcdef" {
		t.Errorf("rehashed: %v", e.F["email"])
	}
}

func TestHashed(t *testing.T) {
	r := newR(t, Options{})
	for _, f := range []string{"email", "user.email", "IMEI", "Phone-Number", "actor", "Actor", "f.device_id"} {
		if !r.Hashed(f) {
			t.Errorf("Hashed(%q) = false", f)
		}
	}
	for _, f := range []string{"password", "lat", "user", "ip", "msg", "", "location"} {
		if r.Hashed(f) {
			t.Errorf("Hashed(%q) = true", f)
		}
	}
}

func TestDropFields(t *testing.T) {
	r := newR(t, Options{})
	geo := &siem.Geo{Country: "NG", City: "Lagos", Lat: 6.45, Lon: 3.39}
	e := siem.Event{Geo: geo, F: map[string]any{
		"lat": 6.5, "lon": 3.3, "lng": 3.3, "latitude": "6.5", "longitude": "3.3", "coords": "[6.5,3.3]",
		"coordinates": "6.5,3.3", "gps": "6.5,3.3", "location": "Ikeja", "altitude": 41.0,
		"device.location.lat": 6.5, "user.geo.Latitude": 6.5, "device_location": "x", "geolocation": "y",
		"keep": "yes", "flat": "kept", "colon": "kept",
	}}
	r.Apply(&e)
	want := map[string]any{"keep": "yes", "flat": "kept", "colon": "kept"}
	if !reflect.DeepEqual(e.F, want) {
		t.Errorf("got %v", e.F)
	}
	if e.Geo != geo || !reflect.DeepEqual(*geo, siem.Geo{Country: "NG", City: "Lagos", Lat: 6.45, Lon: 3.39}) {
		t.Error("Geo must never be touched")
	}
}

func TestActor(t *testing.T) {
	r := newR(t, Options{})
	cases := []struct {
		in     string
		hashed bool
	}{
		{"Ada@Example.com", true},
		{"+2348012345678", true},
		{"+234 801 234 5678", true},
		{"+1 (555) 010-9999", true},
		{"08012345678", true},
		{"0123456789", true}, // a 10-digit bank account number hashes like a phone
		{"alice", false},
		{"12345", false},
		{"u_123", false},
		{"root", false},
		{"", false},
		{"+12", false},
	}
	for _, c := range cases {
		e := siem.Event{Actor: c.in}
		r.Apply(&e)
		want := c.in
		if c.hashed {
			want = r.Hash(c.in)
		}
		if e.Actor != want {
			t.Errorf("actor %q: got %q want %q", c.in, e.Actor, want)
		}
	}
	// An email inside a display-name actor is hashed in place.
	e := siem.Event{Actor: "Ada <ada@example.com>"}
	r.Apply(&e)
	if e.Actor != "Ada <"+r.Hash("ada@example.com")+">" {
		t.Errorf("display-name actor: %q", e.Actor)
	}
}

func TestEmailsInText(t *testing.T) {
	r := newR(t, Options{})
	e := siem.Event{
		Msg: "reset sent to John@Example.com and x.y+z@mail.example.org.",
		F:   map[string]any{"note": "contact a@b.co please", "path": "/users/ada%40example.com/edit"},
	}
	r.Apply(&e)
	want := "reset sent to " + r.Hash("john@example.com") + " and " + r.Hash("x.y+z@mail.example.org") + "."
	if e.Msg != want {
		t.Errorf("Msg: %q\nwant %q", e.Msg, want)
	}
	if e.F["note"] != "contact "+r.Hash("a@b.co")+" please" {
		t.Errorf("note: %v", e.F["note"])
	}
	if e.F["path"] != "/users/"+r.Hash("ada@example.com")+"/edit" {
		t.Errorf("percent-encoded email: %v", e.F["path"])
	}
}

func TestPersonalDataInText(t *testing.T) {
	r := newR(t, Options{})
	e := siem.Event{Msg: "GET /u?email=Ada%40Example.com&imei=356938035643809&lat=6.5&lon=3.3&page=2",
		F: map[string]any{"devices": `[{"imei":"356938035643809","latitude":6.5}]`}}
	r.Apply(&e)
	want := "GET /u?email=" + r.Hash("ada@example.com") + "&imei=" + r.Hash("356938035643809") + "&lat=[redacted]&lon=[redacted]&page=2"
	if e.Msg != want {
		t.Errorf("Msg: %q\nwant %q", e.Msg, want)
	}
	if e.F["devices"] != `[{"imei":"`+r.Hash("356938035643809")+`","latitude":[redacted]}]` {
		t.Errorf("array text: %v", e.F["devices"])
	}
}

func TestOptions(t *testing.T) {
	r := newR(t, Options{
		HashFields: []string{"Customer-Ref", " bvn ", ""},
		DropFields: []string{"fingerprint", "email"},
		KeepFields: []string{"Serial", "lat", "password", "microphone"},
	})
	e := siem.Event{F: map[string]any{
		"customer_ref": "C-1", "req.bvn": "22222222222", "fingerprint": "fp", "email": "a@b.co",
		"serial": "SN1", "lat": 6.5, "password": "p", "microphone": "on", "phone": "+2348012345678",
	}}
	r.Apply(&e)
	want := map[string]any{
		"customer_ref": r.Hash("C-1"), "req.bvn": r.Hash("22222222222"),
		"serial": "SN1", "lat": 6.5, "password": "[redacted]", "microphone": "on", "phone": r.Hash("+2348012345678"),
	}
	if !reflect.DeepEqual(e.F, want) {
		t.Errorf("got  %v\nwant %v", e.F, want)
	}
	if !r.Hashed("customer_ref") || !r.Hashed("x.BVN") || r.Hashed("serial") || r.Hashed("email") {
		t.Error("Hashed must follow the options")
	}
	// A kept field keeps an email address in its value; Msg still hashes it.
	r = newR(t, Options{KeepFields: []string{"email"}})
	e = siem.Event{Msg: "to a@b.co", F: map[string]any{"email": "a@b.co", "user_email": "c@d.co"}}
	r.Apply(&e)
	if e.F["email"] != "a@b.co" || e.Msg != "to "+r.Hash("a@b.co") {
		t.Errorf("keep email: %v %q", e.F, e.Msg)
	}
	if e.F["user_email"] != r.Hash("c@d.co") {
		t.Errorf("user_email value still hashed by the address rule: %v", e.F["user_email"])
	}
	// HashFields wins over the built-in drop list.
	r = newR(t, Options{HashFields: []string{"location"}})
	e = siem.Event{F: map[string]any{"location": "Ikeja"}}
	r.Apply(&e)
	if e.F["location"] != r.Hash("Ikeja") {
		t.Errorf("hash beats built-in drop: %v", e.F)
	}
}

func TestSearchValueMatchesApply(t *testing.T) {
	r := newR(t, Options{HashFields: []string{"customer_ref"}, DropFields: []string{"fp"}, KeepFields: []string{"serial"}})
	values := []string{
		"Ada@Example.com", " ada@example.com ", "+2348012345678", "+234 801 234 5678", "08012345678",
		"0123456789", "356938035643809", "alice", "u_123", "12345", "", "  ", "h:0123456789abcdef",
		"Ada <ada@example.com>", "contact a@b.co please", "token=abc&page=2", "/users/ada%40example.com",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJl", "Bearer abcdef1234567890", "[redacted]",
		strings.Repeat("ab12", 16), "6.5", "Lagos", "C-1", "SN1",
	}
	fields := []string{"email", "user.email", "user_email", "imei", "device.phone", "account", "note",
		"msg", "query", "path", "customer_ref", "serial", "signature", "password", "req.headers.authorization",
		"token", "lat", "location", "fp"}
	for _, v := range values {
		e := siem.Event{Actor: v}
		r.Apply(&e)
		want := e.Actor
		if want == "[redacted]" && v != "[redacted]" {
			want = v
		}
		if got := r.SearchValue("actor", v); got != want {
			t.Errorf("actor %q: SearchValue %q, stored %q", v, got, e.Actor)
		}
		for _, f := range fields {
			e := siem.Event{F: map[string]any{f: v}}
			r.Apply(&e)
			stored, kept := e.F[f].(string)
			last := f[strings.LastIndexByte(f, '.')+1:]
			for _, name := range []string{f, last} {
				got := r.SearchValue(name, v)
				switch {
				case !kept, stored == "[redacted]" && v != "[redacted]":
					// Secrets and dropped fields are never stored: the input comes back.
					if got != v {
						t.Errorf("%s=%q: SearchValue %q, want the input (stored %q kept=%v)", name, v, got, stored, kept)
					}
				case got != stored:
					t.Errorf("%s=%q: SearchValue %q, stored %q", name, v, got, stored)
				}
			}
		}
	}
	// Pinned examples.
	for _, c := range []struct{ field, in, want string }{
		{"actor", "Ada@Example.com", r.Hash("ada@example.com")},
		{"Actor", "+2348012345678", r.Hash("+2348012345678")},
		{"actor", "alice", "alice"},
		{"email", "A@B.co", r.Hash("a@b.co")},
		{"imei", "356938035643809", r.Hash("356938035643809")},
		{"email", "h:0123456789abcdef", "h:0123456789abcdef"},
		{"note", "mail a@b.co", "mail " + r.Hash("a@b.co")},
		{"serial", "SN1", "SN1"},
		{"customer_ref", "C-1", r.Hash("C-1")},
		{"password", "hunter2", "hunter2"},
		{"lat", "6.5", "6.5"},
		{"method", "GET", "GET"},
	} {
		if got := r.SearchValue(c.field, c.in); got != c.want {
			t.Errorf("SearchValue(%q, %q) = %q want %q", c.field, c.in, got, c.want)
		}
	}
}

func TestKeyCarryingSecretDropped(t *testing.T) {
	r := newR(t, Options{})
	e := siem.Event{F: map[string]any{"AKIAIOSFODNN7EXAMPLE": "x", "normal_key_name_long": "y"}}
	r.Apply(&e)
	if _, ok := e.F["AKIAIOSFODNN7EXAMPLE"]; ok || e.F["normal_key_name_long"] != "y" {
		t.Errorf("F: %v", e.F)
	}
}

func TestApplyIdempotent(t *testing.T) {
	r := newR(t, Options{})
	mk := func() siem.Event {
		return siem.Event{
			Actor: "ada@example.com",
			Msg:   "password=x Bearer abcdefghij0123456789 a@b.co https://u:p@h/x?token=t&lat=1 imei=1",
			F: map[string]any{"email": "a@b.co", "token": "t", "q": "api_key=k&email=b%40c.co",
				"lat": 1.0, "n": 2.0, "note": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln"},
		}
	}
	a := mk()
	r.Apply(&a)
	b := a
	b.F = map[string]any{}
	for k, v := range a.F {
		b.F[k] = v
	}
	r.Apply(&b)
	if !reflect.DeepEqual(a, b) {
		t.Errorf("second Apply changed the event:\n%+v\n%+v", a, b)
	}
}

func TestApplyNilAndEmpty(t *testing.T) {
	r := newR(t, Options{})
	r.Apply(nil)
	e := siem.Event{}
	r.Apply(&e)
	if !reflect.DeepEqual(e, siem.Event{}) {
		t.Errorf("empty event changed: %+v", e)
	}
}

func TestConcurrentApply(t *testing.T) {
	r := newR(t, Options{HashFields: []string{"ref"}})
	want := r.Hash("a@b.co")
	var wg sync.WaitGroup
	errs := make(chan string, 16)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				e := siem.Event{Actor: "a@b.co", Msg: fmt.Sprintf("password=%d to a@b.co", i),
					F: map[string]any{"email": "A@B.co", "ref": "r", "token": "t", "lat": 1.0}}
				r.Apply(&e)
				if e.Actor != want || e.F["email"] != want || e.F["token"] != "[redacted]" ||
					e.Msg != "password=[redacted] to "+want || e.F["ref"] != r.Hash("r") || len(e.F) != 3 {
					select {
					case errs <- fmt.Sprintf("g%d i%d: %+v", g, i, e):
					default:
					}
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for s := range errs {
		t.Error(s)
	}
}

func benchEvent() siem.Event {
	return siem.Event{
		Src: siem.SrcApp, Kind: siem.KindLog, Lvl: siem.LvlInfo, IP: "203.0.113.9", Actor: "u_1842",
		Msg: "request completed",
		F: map[string]any{
			"pid": 1.0, "hostname": "api-7d9f", "req.id": 1842.0, "req.method": "POST",
			"req.url": "/v1/loans/apply?ref=abc&page=2", "req.headers.host": "api.example.com",
			"req.headers.user-agent":    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36",
			"req.headers.authorization": "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln",
			"req.headers.content-type":  "application/json", "req.remoteAddress": "::ffff:172.18.0.3",
			"req.remotePort": 41234.0, "res.statusCode": 200.0, "res.headers.content-length": "512",
			"responseTime": 12.0, "device.imei": "356938035643809",
		},
	}
}

func BenchmarkApplyAppJSON(b *testing.B) {
	r := newR(b, Options{})
	proto := benchEvent()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		e := proto
		e.F = make(map[string]any, len(proto.F))
		for k, v := range proto.F {
			e.F[k] = v
		}
		r.Apply(&e)
	}
}

func BenchmarkApplyEdge(b *testing.B) {
	r := newR(b, Options{})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		e := siem.Event{Msg: "GET api.example.com/v1/loans 200", F: map[string]any{
			"method": "GET", "host": "api.example.com", "path": "/v1/loans", "query": "page=2&size=20",
			"proto": "HTTP/2.0", "status": 200.0, "dur_ms": 3.2, "size": 512.0, "bytes_read": 0.0,
			"ua": "okhttp/4.12.0", "sni": "api.example.com",
		}}
		r.Apply(&e)
	}
}

func BenchmarkApplyPlainText(b *testing.B) {
	r := newR(b, Options{})
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		e := siem.Event{Msg: "2026-11-23T13:14:41Z worker processed job 8812 in 31ms (queue=default, attempts=1)"}
		r.Apply(&e)
	}
}
