package query

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

var t0 = time.Date(2026, 11, 23, 10, 30, 0, 0, time.UTC)

func sample() *siem.Event {
	return &siem.Event{
		V: 1, TS: t0, Src: "app", App: "Web", Svc: "api", Copy: "abc123", Lvl: "warn",
		Kind: "auth.login_failed", Out: "failure", Actor: "h:0123456789abcdef", IP: "10.1.2.3",
		Geo: &siem.Geo{Country: "NG", City: "Lagos", ASN: 37148, Org: "Globacom", Lists: []string{"tor", "firehol_level1"}},
		F: map[string]any{
			"status": 401.0, "code": "500", "path": "/a b", "ok": true, "user.name": "Alice", "empty": "",
		},
		Msg: "Login FAILED for user Ärger",
	}
}

func TestParseTerms(t *testing.T) {
	cases := []struct {
		in    string
		terms []Term
		text  []string
	}{
		{`kind:auth.login`, []Term{{Field: "kind", Op: OpEq, Value: "auth.login"}}, nil},
		{`-ip:10.0.0.0/8`, []Term{{Field: "ip", Op: OpEq, Value: "10.0.0.0/8", Neg: true}}, nil},
		{`f.path:"/a b"`, []Term{{Field: "f.path", Op: OpEq, Value: "/a b"}}, nil},
		{`f.q:"say \"hi\" \\ ok"`, []Term{{Field: "f.q", Op: OpEq, Value: `say "hi" \ ok`}}, nil},
		{`"quoted \"text\""`, nil, []string{`quoted "text"`}},
		{`lvl>=warn f.n>5 f.n<=5 f.n<1 f.n>=2 app!=web actor~bob`, []Term{
			{Field: "lvl", Op: OpGe, Value: "warn"}, {Field: "f.n", Op: OpGt, Value: "5"},
			{Field: "f.n", Op: OpLe, Value: "5"}, {Field: "f.n", Op: OpLt, Value: "1"},
			{Field: "f.n", Op: OpGe, Value: "2"}, {Field: "app", Op: OpNe, Value: "web"},
			{Field: "actor", Op: OpContains, Value: "bob"},
		}, nil},
		{`KIND:x`, []Term{{Field: "kind", Op: OpEq, Value: "x"}}, nil},
		{`F.statusCode:500`, []Term{{Field: "f.statusCode", Op: OpEq, Value: "500"}}, nil},
		{"  hello \t world\n", nil, []string{"hello", "world"}},
		{`a=b foo!bar x"y`, nil, []string{"a=b", "foo!bar", `x"y`}},
		{`actor:h:00ff app:x"y`, []Term{{Field: "actor", Op: OpEq, Value: "h:00ff"}, {Field: "app", Op: OpEq, Value: `x"y`}}, nil},
		{`ip:2001:db8::/32 -app!=web`, []Term{{Field: "ip", Op: OpEq, Value: "2001:db8::/32"}, {Field: "app", Op: OpNe, Value: "web", Neg: true}}, nil},
		{`geo.cc:ng geo.asn>=AS100 list:tor geo.org~x geo.city:y copy:z src:host out:success svc:a`, []Term{
			{Field: "geo.cc", Op: OpEq, Value: "ng"}, {Field: "geo.asn", Op: OpGe, Value: "AS100"},
			{Field: "list", Op: OpEq, Value: "tor"}, {Field: "geo.org", Op: OpContains, Value: "x"},
			{Field: "geo.city", Op: OpEq, Value: "y"}, {Field: "copy", Op: OpEq, Value: "z"},
			{Field: "src", Op: OpEq, Value: "host"}, {Field: "out", Op: OpEq, Value: "success"},
			{Field: "svc", Op: OpEq, Value: "a"},
		}, nil},
		{`"" login`, nil, []string{"login"}},
		{``, nil, nil},
	}
	for _, c := range cases {
		q, err := Parse(c.in)
		if err != nil {
			t.Fatalf("Parse(%q): %v", c.in, err)
		}
		if !reflect.DeepEqual(q.Terms, c.terms) || !reflect.DeepEqual(q.Text, c.text) {
			t.Errorf("Parse(%q) = terms %+v text %q; want %+v %q", c.in, q.Terms, q.Text, c.terms, c.text)
		}
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct{ in, want string }{
		{`foo:bar`, `unknown field "foo"`},
		{`http://x`, `unknown field "http"`},
		{`app:`, "empty value"},
		{`app:""`, "empty value"},
		{`:x`, "missing field name"},
		{`>5`, "missing field name"},
		{`-word`, "only a field term can be negated"},
		{`-"two words"`, "only a field term can be negated"},
		{`-`, "nothing to negate"},
		{`"unterminated`, "unterminated quote"},
		{`app:"x`, "unterminated quote"},
		{`app:"x"y`, "after the closing quote"},
		{`"x"y`, "after the closing quote"},
		{`lvl>=loud`, `unknown level "loud"`},
		{`lvl:verbose`, `unknown level`},
		{`app>5`, `">" is not supported for app`},
		{`kind<=x`, `"<=" is not supported for kind`},
		{`ip>1`, `">" is not supported for ip`},
		{`ip:10.0.0.0/99`, "not an IP prefix"},
		{`geo.asn:abc`, "not an AS number"},
		{`geo.asn>-1`, "not an AS number"},
		{`f.:x`, "empty field name"},
		{`f.` + strings.Repeat("k", siem.MaxFieldKey+1) + `:x`, "field name longer than"},
		{strings.Repeat("a ", maxTerms+1), "more than 32 terms"},
		{strings.Repeat("a", maxLen+1), "longer than 2048 bytes"},
		{"app:\xff", "not valid UTF-8"},
	}
	for _, c := range cases {
		_, err := Parse(c.in)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("Parse(%.40q) error = %v; want it to contain %q", c.in, err, c.want)
		}
	}
	// The error names the offending term.
	if _, err := Parse(`kind:ok bogus:1`); err == nil || !strings.Contains(err.Error(), `"bogus:1"`) {
		t.Errorf("error %v does not name the term", err)
	}
	// Exactly the limits parse.
	if _, err := Parse(strings.TrimSpace(strings.Repeat("a ", maxTerms))); err != nil {
		t.Errorf("%d terms: %v", maxTerms, err)
	}
	if _, err := Parse(strings.Repeat("a", maxLen)); err != nil {
		t.Errorf("%d bytes: %v", maxLen, err)
	}
}

func TestMatch(t *testing.T) {
	noApp := sample()
	noApp.App = ""
	noGeo := sample()
	noGeo.Geo = nil
	mapped := sample()
	mapped.IP = "::ffff:10.1.2.3"
	v6 := sample()
	v6.IP = "2001:db8::1"
	kelvin := sample()
	kelvin.App = "Kelvin" // KELVIN SIGN lowercases to ASCII 'k'
	big := sample()
	big.F = map[string]any{"n": 1e21}
	badIP := sample()
	badIP.IP = "unknown"

	cases := []struct {
		q    string
		e    *siem.Event
		want bool
	}{
		{`src:app`, nil, true}, {`src:APP`, nil, true}, {`src:edge`, nil, false},
		{`app:web`, nil, true}, {`app:we*`, nil, true}, {`app:WE*`, nil, true}, {`app:x*`, nil, false},
		{`app:*`, nil, true}, {`app:*`, noApp, false}, {`app:web`, noApp, false},
		{`-app:web`, nil, false}, {`-app:x`, nil, true}, {`-app:web`, noApp, true},
		{`app!=web`, nil, false}, {`app!=x`, nil, true}, {`app!=x`, noApp, false}, {`-app!=x`, noApp, true},
		{`-app!=web`, nil, true},
		{`app:kelvin`, kelvin, true},
		{`svc~p`, nil, true}, {`svc~P`, nil, true}, {`svc~z`, nil, false}, {`-svc~z`, nil, true},
		{`app~e`, noApp, false}, {`-app~e`, noApp, true},
		{`copy:abc123`, nil, true}, {`copy:abc`, nil, false},
		{`kind:auth.*`, nil, true}, {`kind:auth.login_failed`, nil, true}, {`kind:auth`, nil, false},
		{`kind~login`, nil, true}, {`out:failure`, nil, true}, {`out:success`, nil, false},
		{`actor:h:0123456789abcdef`, nil, true}, {`actor:h:0000000000000000`, nil, false},
		{`ip:10.1.2.3`, nil, true}, {`ip:10.0.0.0/8`, nil, true}, {`ip:10.1.2.3/32`, nil, true},
		{`ip:192.168.0.0/16`, nil, false}, {`ip!=10.0.0.0/8`, nil, false}, {`ip!=192.168.0.0/16`, nil, true},
		{`-ip:10.0.0.0/8`, nil, false}, {`-ip:192.168.0.0/16`, nil, true},
		{`ip:10.1.*`, nil, true}, {`ip~1.2`, nil, true},
		{`ip:10.0.0.0/8`, mapped, true}, {`ip:10.1.2.3`, mapped, true},
		{`ip:2001:db8::/32`, v6, true}, {`ip:2001:DB8::1`, v6, true}, {`ip:10.0.0.0/8`, v6, false},
		{`ip:10.0.0.0/8`, badIP, false}, {`ip!=10.0.0.0/8`, badIP, true},
		{`lvl:warn`, nil, true}, {`lvl>=warn`, nil, true}, {`lvl>warn`, nil, false}, {`lvl<error`, nil, true},
		{`lvl<=info`, nil, false}, {`lvl!=warn`, nil, false}, {`lvl~ar`, nil, true}, {`LVL>=WARN`, nil, true},
		{`-lvl>=error`, nil, true},
		{`geo.cc:ng`, nil, true}, {`geo.city:lagos`, nil, true}, {`geo.org~glo`, nil, true},
		{`geo.asn:37148`, nil, true}, {`geo.asn:AS37148`, nil, true}, {`geo.asn>30000`, nil, true},
		{`geo.asn<30000`, nil, false}, {`geo.asn~714`, nil, true},
		{`geo.cc:ng`, noGeo, false}, {`-geo.cc:ng`, noGeo, true}, {`geo.asn>1`, noGeo, false}, {`list:tor`, noGeo, false},
		{`list:tor`, nil, true}, {`list:fire*`, nil, true}, {`list:spamhaus`, nil, false},
		{`list!=tor`, nil, false}, {`list!=spamhaus`, nil, true}, {`list~level`, nil, true},
		{`f.status:401`, nil, true}, {`f.status:401.0`, nil, true}, {`f.status>=400`, nil, true},
		{`f.status<400`, nil, false}, {`f.status:40*`, nil, true}, {`f.status!=401`, nil, false},
		{`f.code:500`, nil, true}, {`f.code>499`, nil, true}, {`f.code:5e2`, nil, true}, {`f.code<=499`, nil, false},
		{`f.path:"/a b"`, nil, true}, {`f.path:"/A B"`, nil, true}, {`f.path~"a b"`, nil, true},
		{`f.path>"/a"`, nil, true}, {`f.path<"/a"`, nil, false}, {`f.status>abc`, nil, false},
		{`f.path>5`, nil, false}, {`-f.path>5`, nil, true},
		{`f.ok:true`, nil, true}, {`f.ok:TRUE`, nil, true}, {`f.ok:false`, nil, false},
		{`f.missing:x`, nil, false}, {`-f.missing:x`, nil, true}, {`f.missing!=x`, nil, false},
		{`f.user.name:alice`, nil, true}, {`f.User.name:alice`, nil, false},
		{`f.empty:*`, nil, true}, {`f.n:1e21`, big, true}, {`f.n>1e20`, big, true},
		{`login`, nil, true}, {`"login failed"`, nil, true}, {`nope`, nil, false}, {`LOGIN`, nil, true},
		{`login user`, nil, true}, {`login nope`, nil, false}, {`ärger`, nil, true}, {`ÄRGER`, nil, true},
		{`kind:auth.* lvl>=warn ip:10.0.0.0/8 -app:api login`, nil, true},
		{`kind:auth.* lvl>=error`, nil, false},
		{``, nil, true},
	}
	for _, c := range cases {
		q, err := Parse(c.q)
		if err != nil {
			t.Fatalf("Parse(%q): %v", c.q, err)
		}
		e := c.e
		if e == nil {
			e = sample()
		}
		if got := q.Match(e); got != c.want {
			t.Errorf("Match(%q) on %s = %v; want %v", c.q, describe(e), got, c.want)
		}
	}
	if (Query{}).Match(nil) {
		t.Error("Match(nil) = true")
	}
	// A hand-built term on a field Parse would refuse never matches (and never panics).
	if (Query{Terms: []Term{{Field: "nope", Op: OpEq, Value: "x"}}}).Match(sample()) {
		t.Error("unknown field matched")
	}
}

func describe(e *siem.Event) string {
	return "event(app=" + e.App + " ip=" + e.IP + ")"
}

func TestMatchTimeBounds(t *testing.T) {
	e := sample()
	cases := []struct {
		from, to time.Time
		want     bool
	}{
		{time.Time{}, time.Time{}, true},
		{t0, time.Time{}, true}, // From is inclusive
		{t0.Add(time.Nanosecond), time.Time{}, false},
		{time.Time{}, t0, false}, // To is exclusive
		{time.Time{}, t0.Add(time.Nanosecond), true},
		{t0.Add(-time.Hour), t0.Add(time.Hour), true},
	}
	for _, c := range cases {
		q := Query{From: c.from, To: c.to}
		if got := q.Match(e); got != c.want {
			t.Errorf("From %v To %v: %v, want %v", c.from, c.to, got, c.want)
		}
	}
}

func TestMapValues(t *testing.T) {
	q, err := Parse(`actor:alice@example.com f.email:bob@example.com app:web hello`)
	if err != nil {
		t.Fatal(err)
	}
	orig := q
	var seen []string
	q.MapValues(func(field, value string) (string, bool) {
		seen = append(seen, field+"="+value)
		if field == "actor" || field == "f.email" {
			return "h:" + strings.ToUpper(value[:3]), true
		}
		return "ignored", false
	})
	want := []Term{
		{Field: "actor", Op: OpEq, Value: "h:ALI"},
		{Field: "f.email", Op: OpEq, Value: "h:BOB"},
		{Field: "app", Op: OpEq, Value: "web"},
	}
	if !reflect.DeepEqual(q.Terms, want) {
		t.Errorf("terms after MapValues = %+v", q.Terms)
	}
	if !reflect.DeepEqual(seen, []string{"actor=alice@example.com", "f.email=bob@example.com", "app=web"}) {
		t.Errorf("fn saw %q", seen)
	}
	if !reflect.DeepEqual(q.Text, []string{"hello"}) {
		t.Errorf("text changed: %q", q.Text)
	}
	// A copy taken before the call is not rewritten through the shared slice.
	if orig.Terms[0].Value != "alice@example.com" {
		t.Errorf("MapValues rewrote an earlier copy: %+v", orig.Terms[0])
	}
	var nilQ *Query
	nilQ.MapValues(func(string, string) (string, bool) { return "", true })
	q.MapValues(nil)
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{
		`kind:auth.* lvl>=warn -ip:10.0.0.0/8 "quoted text" f.path:"/a b"`,
		`f.n>=1e3 geo.asn<AS5 list~x -app!=y actor:h:00`, `"\"`, `-"`, `a:"\\"`, `ip:::1`, `\xff`,
		`f.` + strings.Repeat("a", 70) + `:1`, strings.Repeat(`"a" `, 40),
	} {
		f.Add(s)
	}
	e := sample()
	f.Fuzz(func(t *testing.T, s string) {
		q, err := Parse(s)
		if err != nil {
			return
		}
		if len(s) > maxLen || len(q.Terms)+len(q.Text) > maxTerms {
			t.Fatalf("accepted %d bytes / %d terms", len(s), len(q.Terms)+len(q.Text))
		}
		for _, tm := range q.Terms {
			if tm.Value == "" || !knownField(tm.Field) {
				t.Fatalf("bad term %+v", tm)
			}
		}
		_ = q.Match(e)
		_ = q.Match(&siem.Event{})
	})
}
