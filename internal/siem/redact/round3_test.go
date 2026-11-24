package redact

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/parse"
)

const victim = "victim@example.com"

func TestAddressInsideKeyElement(t *testing.T) {
	r := newR(t, Options{})
	h := r.Hash(victim)
	for line, key := range map[string]string{
		`{"limits":{"login:victim@example.com":5}}`: "limits.login:" + h,
		`{"limits":{"victim@example.com:login":5}}`: "limits." + h + ":login",
		`{"limits":{"<victim@example.com>":5}}`:     "limits.<" + h + ">",
		`{"limits":{"user/victim@example.com":5}}`:  "limits.user/" + h,
		`{"limits":{"rl_victim@example.com":5}}`:    "limits." + r.Hash("rl_victim@example.com"),
		`{"limits":{"a.b victim@example.com":5}}`:   "limits.a%2Eb " + h,
		`{"otp":{"to +234 803 123 4567":1}}`:        "otp.to " + r.Hash("+234 803 123 4567"),
	} {
		ev := parse.AppLine(time.Now(), "a", "s", "c", line)
		r.Apply(&ev)
		if len(ev.F) != 1 {
			t.Errorf("%s: F %v", line, ev.F)
			continue
		}
		for k := range ev.F {
			if k != key {
				t.Errorf("%s:\n got key %q\nwant     %q", line, k, key)
			}
		}
	}
	// Underscore is part of an address's local part.
	e := siem.Event{Msg: "mail john_doe@example.com"}
	r.Apply(&e)
	if e.Msg != "mail "+r.Hash("john_doe@example.com") {
		t.Errorf("underscore: %q", e.Msg)
	}
}

func TestPhonesWithSeparators(t *testing.T) {
	r := newR(t, Options{})
	for _, p := range []string{"+234 803 123 4567", "+234-803-123-4567", "+234.803.123.4567", "0803 123 4567",
		"0803-123-4567", "(0803) 123 4567", "+44 20 7946 0958", "+1 555 010 9999", "+2348031234567", "08031234567",
		"01234567890"} { // Intentional: a UK geographic number has this shape, so a padded id like it hashes too
		for _, in := range []string{"otp sent to " + p + ".", "phone: " + p, `{"phone":"` + p + `"}`} {
			e := siem.Event{Msg: in}
			r.Apply(&e)
			if strings.Contains(e.Msg, p) || !strings.Contains(e.Msg, r.Hash(p)) {
				t.Errorf("%q -> %q (want %s)", in, e.Msg, r.Hash(p))
			}
			if !strings.Contains(e.Msg, r.SearchText(p)) {
				t.Errorf("%q: SearchText(%q) not in %q", in, p, e.Msg)
			}
		}
	}
	e := siem.Event{Msg: "call +234 803 123 4567 890 now"}
	r.Apply(&e)
	if e.Msg != "call "+r.Hash("+234 803 123 4567")+" 890 now" {
		t.Errorf("longest valid number: %q", e.Msg)
	}
	for _, s := range []string{"2026-11-23", "v0.12.3", "10.0.0.1:443", "port 08080", "ts 1763899140123",
		"delta +1234567 bytes", "order 00012345678 shipped", "took 0.0123456789 s", "offset +0100",
		"2026-11-23T13:14:41+01:00", "+234 803", "id 0123e4567-e89b-12d3", "sha 0803123456789abcdef",
		"0.0.0.0", "(0) 1", "0803 1", "a+2348031234567", "1+08031234567", "08031234567.5", "+2348031234567890123"} {
		e := siem.Event{Msg: s}
		r.Apply(&e)
		if e.Msg != s {
			t.Errorf("%q changed to %q", s, e.Msg)
		}
	}
}

func TestTextKeysUseLastElement(t *testing.T) {
	r := newR(t, Options{})
	for _, s := range []string{
		"dial tcp account.example.com:443: i/o timeout",
		"GET https://session.example.com:8443/health 200",
		"proxy location.internal:3128 refused",
		"upstream token.actions.githubusercontent.com:443 ok",
		"password.new=x phone.number=803",
	} {
		e := siem.Event{Msg: s}
		r.Apply(&e)
		if e.Msg != s {
			t.Errorf("%q changed to %q", s, e.Msg)
		}
	}
	e := siem.Event{Msg: "user.password=x a.session=y user.phone=803 device.lat=6.5"}
	r.Apply(&e)
	if want := "user.password=[redacted] a.session=[redacted] user.phone=" + r.Hash("803") + " device.lat=[redacted]"; e.Msg != want {
		t.Errorf("\n got %q\nwant %q", e.Msg, want)
	}
	// F keys keep inheritance.
	f := siem.Event{F: map[string]any{"password.new": "x", "phone.number": "803"}}
	r.Apply(&f)
	if f.F["password.new"] != "[redacted]" || f.F["phone.number"] != r.Hash("803") {
		t.Errorf("F: %v", f.F)
	}
}

func TestShortSignatureThenSecret(t *testing.T) {
	r := newR(t, Options{})
	for in, want := range map[string]string{
		"x signature=password=Hunter2Hunter2":    "x signature=password=[redacted]",
		"x signature=abc=token=Hunter2Hunter2 y": "x signature=abc=token=[redacted] y",
	} {
		e := siem.Event{Msg: in}
		r.Apply(&e)
		if e.Msg != want {
			t.Errorf("%q\n got %q\nwant %q", in, e.Msg, want)
		}
		again := e
		r.Apply(&again)
		if again.Msg != e.Msg {
			t.Errorf("%q: second Apply %q", in, again.Msg)
		}
	}
}

func TestHashedValueTrimmed(t *testing.T) {
	r := newR(t, Options{})
	h, ph := r.Hash(victim), r.Hash("+2348031234567")
	for in, want := range map[string]string{
		"sending otp to email: victim@example.com.": "sending otp to email: " + h + ".",
		"email=<victim@example.com>":                "email=<" + h + ">",
		"email: victim@example.com)":                "email: " + h + ")",
		"email=victim@example.com;":                 "email=" + h + ";",
		"user=victim@example.com.":                  "user=" + h + ".",
		"phone=+2348031234567.":                     "phone=" + ph + ".",
		"phone: (+2348031234567)":                   "phone: (" + ph + ")",
	} {
		e := siem.Event{Msg: in}
		r.Apply(&e)
		if e.Msg != want {
			t.Errorf("%q\n got %q\nwant %q", in, e.Msg, want)
		}
	}
	if r.SearchText(victim) != h || r.SearchValue("email", victim) != h {
		t.Error("search forms")
	}
}

func TestURLUserPartAddresses(t *testing.T) {
	r := newR(t, Options{})
	for _, s := range []string{"smtp://victim%40example.com:pw@smtp.example.org:587", "imap://victim@example.com@mail.example.org"} {
		e := siem.Event{Msg: s}
		r.Apply(&e)
		if strings.Contains(e.Msg, "victim") || strings.Contains(e.Msg, ":pw@") {
			t.Errorf("%q -> %q", s, e.Msg)
		}
		again := e
		r.Apply(&again)
		if again.Msg != e.Msg {
			t.Errorf("%q: second Apply %q -> %q", s, e.Msg, again.Msg)
		}
	}
	e := siem.Event{Msg: "ssh://git@github.com/o/r.git"}
	r.Apply(&e)
	if e.Msg != "ssh://git@github.com/o/r.git" {
		t.Errorf("a URL's plain user stays: %q", e.Msg)
	}
}

func TestRound3Nits(t *testing.T) {
	r := newR(t, Options{})
	if isEmail("admin@") || isEmail("@x.co") || !isEmail("a@b.co") {
		t.Error("isEmail needs a local part and a domain")
	}
	e := siem.Event{Actor: "admin@", F: map[string]any{"by.bob@": 1.0}}
	r.Apply(&e)
	if e.Actor != "admin@" || e.F["by.bob@"] != 1.0 {
		t.Errorf("not addresses: %+v", e)
	}
	for in, want := range map[string]string{
		"sent Bearer Bearer abcdef1234567890abcdef0123":        "sent Bearer Bearer [redacted]",
		"key AKIAIOSFODNN7EXAMPLEsk_" + "live_abcdefghijkl":    "key [redacted][redacted]",
		"x AKIAIOSFODNN7EXAMPLEghp_" + "abcdefghijABCDEFGHIJ1": "x [redacted][redacted]",
	} {
		e := siem.Event{Msg: in}
		r.Apply(&e)
		if e.Msg != want {
			t.Errorf("%q\n got %q\nwant %q", in, e.Msg, want)
		}
		again := e
		r.Apply(&again)
		if again.Msg != e.Msg {
			t.Errorf("%q: second Apply %q", in, again.Msg)
		}
	}
}

func TestMeasuresUnderSecretParents(t *testing.T) {
	r := newR(t, Options{})
	kept := map[string]any{
		"session.duration_ms": 1234.0, "token.expires_in": 3600.0, "otp.attempts": 2.0,
		"session.secure": true, "req.session.cookie.maxAge": 86400000.0, "token.exp": 1.7e9, "session.count": 3.0,
		"session.created_at": 1.7e9, "token.ttl": 60.0, "cookies.size": 2.0, "session.ok": true, "token.valid": false,
		"auth.token.status": 200.0, "session.elapsedMs": 5.0,
	}
	redactedNums := map[string]any{
		"otp.code": 123456.0, "session.pin": 1234.0, "session.value": 5.0, "pin": 1234.0, "otp_code": 123456.0,
		"token.id": 7.0, "session.user_id": 42.0, "password": 1234.0, "otp": 123456.0,
		"session.pin_attempts_left": 3.0, "otp.attempts.code": 1.0, // a measure parent doesn't make the leaf one
		"checks.pass": 12.0, "pass": 1234.0, // a secret leaf is redacted even when it is also a measure name
	}
	f := map[string]any{"token.expires_in_text": "3600", "session.duration": "1s"}
	for k, v := range kept {
		f[k] = v
	}
	for k, v := range redactedNums {
		f[k] = v
	}
	e := siem.Event{F: f}
	r.Apply(&e)
	for k, v := range kept {
		if e.F[k] != v {
			t.Errorf("%s: %v must be kept (a measure)", k, e.F[k])
		}
	}
	for k := range redactedNums {
		if e.F[k] != "[redacted]" {
			t.Errorf("%s: %v must be redacted", k, e.F[k])
		}
	}
	if e.F["token.expires_in_text"] != "[redacted]" || e.F["session.duration"] != "[redacted]" {
		t.Errorf("a string under a secret parent is redacted whatever its name: %v", e.F)
	}
}

func TestSecretFieldMatchesApply(t *testing.T) {
	r := newR(t, Options{KeepFields: []string{"session"}, HashFields: []string{"ref"}})
	val := strings.Repeat("Ab1", 12) // long enough to be a signature
	fields := []string{"password", "user.password", "session.id", "signature", "x.signature", "email", "lat",
		"method", "cookies.connect.sid", "token.expires_in", "pass", "checks.pass", "ref", "path", "req.headers.authorization",
		"AWS_SECRET_ACCESS_KEY", "token[0]", "password[]", "device.imei", "location.city", "a.b.c", "otp_code", "Password"}
	for _, f := range fields {
		e := siem.Event{F: map[string]any{f: val}}
		r.Apply(&e)
		if got, want := r.SecretField(f), e.F[f] == "[redacted]"; got != want {
			t.Errorf("SecretField(%q) = %v, Apply stored %v", f, got, e.F[f])
		}
	}
	if r.SecretField("actor") || r.SecretField("Actor") {
		t.Error("actor is not a secret field")
	}
}

func TestRound3Idempotent(t *testing.T) {
	r := newR(t, Options{})
	for _, s := range []string{":email=Bearer Bearer password=", "victim@example.comsignature=password=@://",
		"email=Bearer Bearer signature=", "phone: +234 803 123 4567 and 0803-123-4567", "email: <a@b.co>.",
		"smtp://victim%40example.com:pw@h", "imap://a@b.co@c.d", "x signature=password=y"} {
		e := siem.Event{Msg: s, F: map[string]any{"note": s}}
		r.Apply(&e)
		again := e
		again.F = map[string]any{"note": e.F["note"]}
		r.Apply(&again)
		if !reflect.DeepEqual(again, e) {
			t.Errorf("%q: first %q second %q", s, e.Msg, again.Msg)
		}
	}
}

func TestRound3EdgeCases(t *testing.T) {
	r := newR(t, Options{})
	// A key renamed by hashKey is checked for credentials like any key: decoding an element
	// can bare one.
	k := `x%22AKIAIOSFODNN7EXAMPLE%22+2348031234567`
	e := siem.Event{F: map[string]any{k: 1.0, "keep": 2.0}}
	r.Apply(&e)
	if !reflect.DeepEqual(e.F, map[string]any{"keep": 2.0}) {
		t.Errorf("renamed key with a credential: %v", e.F)
	}
	// An address after text that only looks like a hash ("h:" + more than 16 hex) is hashed.
	e = siem.Event{Msg: "x h:abcdefabcdefabcdefabcdefvictim@example.com"}
	r.Apply(&e)
	if strings.Contains(e.Msg, "victim") {
		t.Errorf("address after hash-like text: %q", e.Msg)
	}
	// An address continuing right after a hash already written starts after the hash.
	e = siem.Event{Msg: "x h:0123456789abcdef.victim@example.com"}
	r.Apply(&e)
	if e.Msg != "x h:0123456789abcdef"+r.Hash(".victim@example.com") {
		t.Errorf("address after a written hash: %q", e.Msg)
	}
	// An encoded space, quote or ':' ends a local part: only the address after it is hashed.
	for _, sep := range []string{"%20", "%22", "%3A", "%3a", "%09"} {
		e = siem.Event{Msg: "to x" + sep + "victim@example.com"}
		r.Apply(&e)
		if e.Msg != "to x"+sep+r.Hash(victim) {
			t.Errorf("%s before an address: %q", sep, e.Msg)
		}
	}
	// A value that starts with a hash-looking text is stepped over, not the pair after it.
	e = siem.Event{Msg: "phone=h:0123456789abcdef,password=hunter2 x"}
	r.Apply(&e)
	if e.Msg != "phone=h:0123456789abcdef,password=[redacted] x" {
		t.Errorf("pair after a hash: %q", e.Msg)
	}
	// The span decoded from an encoded token doesn't move when a pass redacts its '='.
	for _, s := range []string{"%3AAKIAIOSFODNN7EXAMPLE%22token:password=", "%7D%3AAKIAIOSFODNN7EXAMPLE%7Btoken:=h:"} {
		e := siem.Event{Msg: s}
		r.Apply(&e)
		again := e
		r.Apply(&again)
		if again.Msg != e.Msg || strings.Contains(e.Msg, "AKIAIOSFODNN7EXAMPLE") {
			t.Errorf("%q: first %q second %q", s, e.Msg, again.Msg)
		}
	}
}
