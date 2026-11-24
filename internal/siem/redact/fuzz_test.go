package redact

import (
	"reflect"
	"testing"

	"github.com/daboss2003/mooring/internal/siem"
)

func FuzzRedact(f *testing.F) {
	for _, s := range []string{
		"password=hunter2 user=bob", `{"password":"x","email":"a@b.co"}`, "Bearer abcdef1234567890",
		"-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln", "postgres://u:p@h/db", "AKIAIOSFODNN7EXAMPLE",
		"ghp_" + "1234567890abcdefghijABCDEFGHIJ123456", "xox" + "b-123456789012-abcdefghij", "sk_" + "live_abcdefghijkl",
		"?token=a&lat=1&email=a%40b.co", `{\"pin\":\"1\"}`, "Cookie: a=b; c=d", "a=", ":", `"="`, "\x00=\xff",
		"user%5Bpassword%5D=x", "h:0123456789abcdef", "+2348012345678",
		"GET /g?variables=%7B%22password%22%3A%22x%22%7D", "v=%7B%22email%22%3A%22a%40b.co%22%7D&x=%3D",
		"jöhn@exämple.com", "a@b.xn--p1ai", "otp 08031234567.", "password[]=x&token[0]=y", "a%40b@c.co",
		"cookies: a=b", ",signature=a,signature=" + "abcdefabcdefabcdefabcdefabcdefabcdef", "pwd=[redacted]x=1",
		"attempts.victim@example%2Ecom", "x.+2348031234567", "Bearer Bearer abc", "eyJ.eyJa.b.c",
		"phone: +234 803 123 4567", "(0803) 123-4567.", "login:victim@example%2Ecom", "imap://a@b.co@c.d",
		"smtp://a%40b.co:pw@h", "x signature=password=y", "email: <a@b.co>.", "AKIAIOSFODNN7EXAMPLEsk_" + "live_abcdefghijkl",
		"%3AAKIAIOSFODNN7EXAMPLE%22token:password=", "session.example.com:8443",
	} {
		f.Add(s, "password", s)
		f.Add(s, "note", s)
	}
	r, err := New(testKey, Options{HashFields: []string{"ref"}, DropFields: []string{"fp"}, KeepFields: []string{"serial"}})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, msg, key, val string) {
		e := siem.Event{Msg: msg, Actor: val, IP: "203.0.113.1",
			F: map[string]any{key: val, "q": msg, "n": 1.5, "b": true}}
		r.Apply(&e)
		if e.IP != "203.0.113.1" {
			t.Fatalf("IP changed: %q", e.IP)
		}
		for k, v := range e.F {
			// A key is kept or has its addresses/phone numbers hashed (hashKey), never invented.
			if k != key && k != r.hashKey(key) && k != "q" && k != "n" && k != "b" {
				t.Fatalf("new key %q", k)
			}
			switch tv := v.(type) {
			case string:
				if tokens(tv) != tv {
					t.Fatalf("F[%q] still holds a credential: %q", k, tv)
				}
			case float64, bool:
			default:
				t.Fatalf("F[%q] has type %T", k, v)
			}
		}
		for _, s := range []string{e.Msg, e.Actor} {
			if tokens(s) != s {
				t.Fatalf("still holds a credential: %q", s)
			}
			// Growth is bounded: each replacement is at most len("[redacted]") or a hash for at
			// least one input byte.
			if len(s) > 18*(len(msg)+len(val))+18 {
				t.Fatalf("output grew to %d bytes", len(s))
			}
		}
		// Idempotent: a second pass changes nothing.
		again := e
		again.F = map[string]any{}
		for k, v := range e.F {
			again.F[k] = v
		}
		r.Apply(&again)
		if !reflect.DeepEqual(again, e) {
			t.Fatalf("second Apply changed the event:\n%#v\n%#v", e, again)
		}
	})
}
