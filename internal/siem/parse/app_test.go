package parse

import (
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

var at = time.Date(2026, 11, 23, 12, 14, 41, 0, time.UTC)

func app(text string) siem.Event { return AppLine(at, "shop", "api", "3f2a1b", text) }

func TestAppLinePinoRequest(t *testing.T) {
	ms := at.Add(-1500 * time.Millisecond).UnixMilli()
	line := fmt.Sprintf(`{"level":30,"time":%d,"pid":1,"hostname":"api-7d9f","req":{"id":42,"method":"POST","url":"/v1/loans?page=2","headers":{"host":"api.example.com","x-forwarded-for":"203.0.113.9, 10.0.0.1","authorization":"Bearer x"},"remoteAddress":"::ffff:172.18.0.3","remotePort":41234},"res":{"statusCode":201},"responseTime":12.5,"msg":"request completed"}`, ms)
	e := app(line)
	if e.Src != siem.SrcApp || e.App != "shop" || e.Svc != "api" || e.Copy != "3f2a1b" {
		t.Errorf("identity: %+v", e)
	}
	if !e.TS.Equal(time.UnixMilli(ms)) {
		t.Errorf("TS %v", e.TS)
	}
	if e.Lvl != siem.LvlInfo || e.Kind != siem.KindLog || e.Msg != "request completed" {
		t.Errorf("lvl/kind/msg: %q %q %q", e.Lvl, e.Kind, e.Msg)
	}
	// The socket peer is the edge (a private address); the edge's X-Forwarded-For names the client.
	if e.IP != "203.0.113.9" {
		t.Errorf("IP %q", e.IP)
	}
	want := map[string]any{
		"pid": 1.0, "hostname": "api-7d9f", "req.id": 42.0, "req.method": "POST", "req.url": "/v1/loans?page=2",
		"req.headers.host": "api.example.com", "req.headers.x-forwarded-for": "203.0.113.9, 10.0.0.1",
		"req.headers.authorization": "Bearer x", "req.remoteAddress": "::ffff:172.18.0.3", "req.remotePort": 41234.0,
		"res.statusCode": 201.0, "responseTime": 12.5,
	}
	if !reflect.DeepEqual(e.F, want) {
		t.Errorf("F\n got %v\nwant %v", e.F, want)
	}
}

func TestAppLinePinoLevels(t *testing.T) {
	for n, want := range map[float64]string{10: siem.LvlDebug, 20: siem.LvlDebug, 30: siem.LvlInfo, 35: siem.LvlInfo,
		40: siem.LvlWarn, 50: siem.LvlError, 60: siem.LvlCritical, 70: siem.LvlCritical, 0: siem.LvlDebug} {
		e := app(fmt.Sprintf(`{"level":%v,"msg":"m"}`, n))
		if e.Lvl != want {
			t.Errorf("level %v: %q want %q", n, e.Lvl, want)
		}
		if _, ok := e.F["level"]; ok {
			t.Errorf("level %v left in F", n)
		}
	}
}

func TestAppLineStringLevels(t *testing.T) {
	cases := map[string]string{
		"trace": siem.LvlDebug, "debug": siem.LvlDebug, "DEBUG": siem.LvlDebug, "info": siem.LvlInfo,
		"notice": siem.LvlInfo, "INFO": siem.LvlInfo, "warn": siem.LvlWarn, "warning": siem.LvlWarn,
		"WARNING": siem.LvlWarn, "error": siem.LvlError, "err": siem.LvlError, "ERROR": siem.LvlError,
		"fatal": siem.LvlCritical, "panic": siem.LvlCritical, "critical": siem.LvlCritical,
		"crit": siem.LvlCritical, "alert": siem.LvlCritical, "emerg": siem.LvlCritical,
	}
	for _, key := range []string{"level", "lvl", "severity"} {
		for in, want := range cases {
			e := app(fmt.Sprintf(`{%q:%q}`, key, in))
			if e.Lvl != want {
				t.Errorf("%s=%s: %q want %q", key, in, e.Lvl, want)
			}
			if len(e.F) != 0 {
				t.Errorf("%s=%s: F %v", key, in, e.F)
			}
		}
	}
	// ECS log.level, nested or dotted.
	if e := app(`{"log":{"level":"error"},"message":"x"}`); e.Lvl != siem.LvlError || len(e.F) != 0 {
		t.Errorf("nested log.level: %+v", e)
	}
	if e := app(`{"log.level":"warn"}`); e.Lvl != siem.LvlWarn {
		t.Errorf("dotted log.level: %+v", e)
	}
	// An unknown level is not a level: default info, field kept.
	if e := app(`{"level":"verbose-ish"}`); e.Lvl != siem.LvlInfo || e.F["level"] != "verbose-ish" {
		t.Errorf("unknown level: %+v", e)
	}
	// A numeric level only counts under "level".
	if e := app(`{"severity":50}`); e.Lvl != siem.LvlInfo || e.F["severity"] != 50.0 {
		t.Errorf("numeric severity: %+v", e)
	}
}

func TestAppLineTime(t *testing.T) {
	src := at.Add(-90 * time.Minute)
	cases := []struct{ name, line string }{
		{"pino ms", fmt.Sprintf(`{"time":%d}`, src.UnixMilli())},
		{"zap ts s float", fmt.Sprintf(`{"ts":%d.0}`, src.Unix())},
		{"epoch us", fmt.Sprintf(`{"ts":%d}`, src.UnixMicro())},
		{"epoch ns", fmt.Sprintf(`{"timestamp":%d}`, src.UnixNano())},
		{"epoch string", fmt.Sprintf(`{"timestamp":"%d"}`, src.UnixMilli())},
		{"rfc3339", `{"timestamp":"` + src.In(time.FixedZone("WAT", 3600)).Format(time.RFC3339) + `"}`},
		{"rfc3339nano", `{"@timestamp":"` + src.Format(time.RFC3339Nano) + `"}`},
		{"logrus time string", `{"time":"` + src.Format(time.RFC3339) + `"}`},
	}
	for _, c := range cases {
		e := app(c.line)
		if !e.TS.Equal(src) {
			t.Errorf("%s: TS %v want %v", c.name, e.TS, src)
		}
		if len(e.F) != 0 {
			t.Errorf("%s: time field left in F: %v", c.name, e.F)
		}
	}
	// Outside ±24h of capture: capture time, field kept.
	for _, d := range []time.Duration{25 * time.Hour, -25 * time.Hour, 24*time.Hour + time.Second} {
		e := app(fmt.Sprintf(`{"time":%d}`, at.Add(d).UnixMilli()))
		if !e.TS.Equal(at) {
			t.Errorf("%v off: TS %v want capture %v", d, e.TS, at)
		}
		if _, ok := e.F["time"]; !ok {
			t.Errorf("%v off: time field must stay in F", d)
		}
	}
	// Exactly 24h is still inside.
	if e := app(fmt.Sprintf(`{"time":%d}`, at.Add(-24*time.Hour).UnixMilli())); !e.TS.Equal(at.Add(-24 * time.Hour)) {
		t.Errorf("24h boundary: %v", e.TS)
	}
	// First found wins: "time" before "timestamp".
	e := app(fmt.Sprintf(`{"time":%d,"timestamp":"%s"}`, src.UnixMilli(), at.Add(-time.Hour).Format(time.RFC3339)))
	if !e.TS.Equal(src) || e.F["timestamp"] == nil {
		t.Errorf("first found: %v %v", e.TS, e.F)
	}
	// Garbage time: capture time.
	if e := app(`{"time":"yesterday"}`); !e.TS.Equal(at) || e.F["time"] != "yesterday" {
		t.Errorf("garbage time: %+v", e)
	}
}

func TestAppLineMsgKeys(t *testing.T) {
	cases := map[string]string{
		`{"msg":"a","message":"b"}`:                 "a",
		`{"message":"b","@message":"c"}`:            "b",
		`{"@message":"c","error":{"message":"d"}}`:  "c",
		`{"error":{"message":"d","code":"E1"}}`:     "d",
		`{"msg":42,"message":"b"}`:                  "b",
		`{"other":"x"}`:                             "",
		`{"event":"user logged in","level":"info"}`: "user logged in", // structlog
	}
	for line, want := range cases {
		if e := app(line); e.Msg != want {
			t.Errorf("%s: Msg %q want %q", line, e.Msg, want)
		}
	}
	e := app(`{"msg":"a","message":"b"}`)
	if !reflect.DeepEqual(e.F, map[string]any{"message": "b"}) {
		t.Errorf("only the used key is lifted: %v", e.F)
	}
}

func TestAppLineIP(t *testing.T) {
	cases := []struct{ line, ip string }{
		{`{"ip":"203.0.113.5"}`, "203.0.113.5"},
		{`{"client_ip":"203.0.113.5"}`, "203.0.113.5"},
		{`{"clientIp":"2001:db8::1"}`, "2001:db8::1"},
		{`{"remote_ip":"203.0.113.5:5555"}`, "203.0.113.5"},
		{`{"remoteAddress":"[2001:db8::2]:443"}`, "2001:db8::2"},
		{`{"req":{"remoteAddress":"::ffff:198.51.100.4"}}`, "198.51.100.4"},
		{`{"req":{"ip":"198.51.100.4"}}`, "198.51.100.4"},
		{`{"request":{"ip":"198.51.100.4"}}`, "198.51.100.4"},
		{`{"x-forwarded-for":"198.51.100.4, 10.0.0.1"}`, "198.51.100.4"},
		{`{"req":{"headers":{"x-forwarded-for":" 198.51.100.4 ,10.0.0.1"}}}`, "198.51.100.4"},
		{`{"ip":"not-an-ip","client_ip":"203.0.113.5"}`, "203.0.113.5"},
		{`{"ip":"999.1.1.1"}`, ""},
		{`{"ip":"0.0.0.0"}`, ""},
		{`{"ip":12345}`, ""},
		// A private socket peer loses to the forwarded client; a public one wins.
		{`{"remoteAddress":"10.0.0.2","x-forwarded-for":"203.0.113.7"}`, "203.0.113.7"},
		{`{"ip":"198.51.100.1","x-forwarded-for":"203.0.113.7"}`, "198.51.100.1"},
		{`{"ip":"10.0.0.2"}`, "10.0.0.2"},
		{`{"ip":"fe80::1%eth0"}`, "fe80::1"},
	}
	for _, c := range cases {
		if e := app(c.line); e.IP != c.ip {
			t.Errorf("%s: IP %q want %q", c.line, e.IP, c.ip)
		}
	}
	e := app(`{"ip":"999.1.1.1","client_ip":"203.0.113.5"}`)
	if e.F["ip"] != "999.1.1.1" || e.F["client_ip"] != nil {
		t.Errorf("only the used IP field is lifted: %v", e.F)
	}
}

func TestAppLineActor(t *testing.T) {
	for _, k := range []string{"actor_id", "actorId", "user_id", "userId", "uid", "account", "username", "user", "sub"} {
		e := app(fmt.Sprintf(`{%q:"u-1","z":1}`, k))
		if e.Actor != "u-1" {
			t.Errorf("%s: actor %q", k, e.Actor)
		}
		if _, ok := e.F[k]; ok {
			t.Errorf("%s left in F", k)
		}
	}
	// First found, strings only.
	if e := app(`{"user_id":7,"username":"ada","sub":"s"}`); e.Actor != "ada" || e.F["user_id"] != 7.0 || e.F["sub"] != "s" {
		t.Errorf("first string: %+v", e)
	}
	if e := app(`{"user":{"id":"x"}}`); e.Actor != "" || e.F["user.id"] != "x" {
		t.Errorf("object user: %+v", e)
	}
}

func TestAppLineKindAndOutcome(t *testing.T) {
	cases := []struct {
		line, kind, out string
		keep            string // field that must stay in F
	}{
		{`{"event":"auth.login","outcome":"success"}`, "auth.login", siem.OutSuccess, ""},
		{`{"event":"auth.login_failed"}`, "auth.login_failed", siem.OutFailure, ""},
		{`{"event":"auth.login.failed"}`, "auth.login.failed", siem.OutFailure, ""},
		{`{"event":"apikey.access_denied"}`, "apikey.access_denied", siem.OutFailure, ""},
		{`{"event":"auth.login_failed","outcome":"ok"}`, "auth.login_failed", siem.OutSuccess, ""},
		{`{"event":"role.changed","outcome":"FAILED"}`, "role.changed", siem.OutFailure, ""},
		{`{"evt":"admin.login"}`, "admin.login", "", ""},
		{`{"event_type":"apikey.created"}`, "apikey.created", "", ""},
		{`{"event":"a.b.c.d"}`, "a.b.c.d", "", ""},
		{`{"event":"a.b.c.d.e"}`, siem.KindLog, "", "event"},
		{`{"event":"login"}`, siem.KindLog, "", "event"},
		{`{"event":"Auth.Login"}`, siem.KindLog, "", "event"},
		{`{"event":"auth..login"}`, siem.KindLog, "", "event"},
		{`{"event":"9auth.login"}`, siem.KindLog, "", "event"},
		{`{"event":"auth.login "}`, siem.KindLog, "", "event"},
		// An app can't spoof Mooring's own or the host's kinds.
		{`{"event":"mooring.login","outcome":"success"}`, siem.KindLog, siem.OutSuccess, "event"},
		{`{"event":"siem.dropped"}`, siem.KindLog, "", "event"},
		{`{"event":"ssh.login"}`, siem.KindLog, "", "event"},
		{`{"event":"sudo.command"}`, siem.KindLog, "", "event"},
		{`{"event":"su.session"}`, siem.KindLog, "", "event"},
		{`{"event":"fail2ban.ban"}`, siem.KindLog, "", "event"},
		{`{"event":"host.user_change"}`, siem.KindLog, "", "event"},
		{`{"event":"http.request"}`, siem.KindLog, "", "event"},
		{`{"event":"http.login_failed"}`, siem.KindLog, "", "event"}, // a refused kind sets no outcome either
		{`{"event":"https.cert_renewed"}`, "https.cert_renewed", "", ""},
		{`{"evt":"mooring.env_set_secret"}`, siem.KindLog, "", "evt"},
		{`{"event":"subscription.created"}`, "subscription.created", "", ""},
		{`{"event":"sudoers.changed"}`, "sudoers.changed", "", ""},
		{`{"event":"mooringx.y"}`, "mooringx.y", "", ""},
		// A bad event name doesn't stop an alias that is good.
		{`{"event":"mooring.login","event_type":"auth.login"}`, "auth.login", "", "event"},
	}
	for _, c := range cases {
		e := app(c.line)
		if e.Kind != c.kind || e.Out != c.out {
			t.Errorf("%s: kind %q out %q, want %q %q", c.line, e.Kind, e.Out, c.kind, c.out)
		}
		if c.keep != "" && e.F[c.keep] == nil {
			t.Errorf("%s: %s must stay in F (%v)", c.line, c.keep, e.F)
		}
	}
	for in, want := range map[string]string{"success": siem.OutSuccess, "ok": siem.OutSuccess, "succeeded": siem.OutSuccess,
		"failure": siem.OutFailure, "fail": siem.OutFailure, "failed": siem.OutFailure, "denied": siem.OutFailure,
		"error": siem.OutFailure, "maybe": ""} {
		e := app(fmt.Sprintf(`{"outcome":%q}`, in))
		if e.Out != want {
			t.Errorf("outcome %s: %q", in, e.Out)
		}
		if (want == "") != (e.F["outcome"] != nil) {
			t.Errorf("outcome %s: F %v", in, e.F)
		}
	}
}

func TestAppLineHTTPStatusLevel(t *testing.T) {
	cases := map[string]string{
		`{"res":{"statusCode":503},"msg":"x"}`:              siem.LvlError,
		`{"res":{"statusCode":500}}`:                        siem.LvlError,
		`{"res":{"statusCode":404}}`:                        siem.LvlWarn,
		`{"res":{"statusCode":200}}`:                        siem.LvlInfo,
		`{"level":30,"res":{"statusCode":503}}`:             siem.LvlInfo,
		`{"level":"debug","res":{"statusCode":404}}`:        siem.LvlDebug,
		`{"res":{"statusCode":"503"}}`:                      siem.LvlInfo,
		`{"req":{"method":"GET"},"res":{"statusCode":401}}`: siem.LvlWarn,
	}
	for line, want := range cases {
		if e := app(line); e.Lvl != want {
			t.Errorf("%s: %q want %q", line, e.Lvl, want)
		}
	}
}

func TestAppLineFlatten(t *testing.T) {
	e := app(`{"a":{"b":{"c":"deep"},"n":null,"t":true,"f":1.5e3},"arr":[1,"two",{"x":"<y>"}],"empty":{},"":"nokey","z":{"":"x"}}`)
	want := map[string]any{"a.b.c": "deep", "a.t": true, "a.f": 1500.0, "arr": `[1,"two",{"x":"<y>"}]`}
	if !reflect.DeepEqual(e.F, want) {
		t.Errorf("got  %v\nwant %v", e.F, want)
	}
	// Dotted keys colliding with nested ones: deterministic (sorted, first written wins).
	for i := 0; i < 20; i++ {
		e := app(`{"a.b":"dotted","a":{"b":"nested"}}`)
		if e.F["a.b"] != "nested" {
			t.Fatalf("collision: %v", e.F)
		}
	}
	// A huge array is skipped.
	big := `{"arr":[` + strings.Repeat(`"xxxxxxxx",`, 600) + `"x"],"k":1}`
	if e := app(big); e.F["arr"] != nil || e.F["k"] != 1.0 {
		t.Errorf("huge array: %v", len(fmt.Sprint(e.F["arr"])))
	}
	// A key holding an address keeps its dots as %2E (and % as %25), so redaction can hash the
	// address as one element of the flattened name.
	e = app(`{"attempts":{"John.Doe@Example.com":3,"a.b":1,"x@y":2,"50%.off@shop.example":4}}`)
	if e.F["attempts.John%2EDoe@Example%2Ecom"] != 3.0 || e.F["attempts.a.b"] != 1.0 || e.F["attempts.x@y"] != 2.0 ||
		e.F["attempts.50%25%2Eoff@shop%2Eexample"] != 4.0 {
		t.Errorf("escaped address keys: %v", e.F)
	}
	e = app(`{"a@b.co":{"n":1}}`)
	if e.F["a@b%2Eco.n"] != 1.0 {
		t.Errorf("address as a parent: %v", e.F)
	}
	// Prototype-pollution-shaped keys are plain data.
	e = app(`{"__proto__":{"admin":true},"constructor":{"prototype":{"x":1}}}`)
	if e.F["__proto__.admin"] != true || e.F["constructor.prototype.x"] != 1.0 {
		t.Errorf("proto keys: %v", e.F)
	}
}

func TestAppLineHostileJSON(t *testing.T) {
	deep := func(n int) string { return strings.Repeat(`{"a":`, n) + `1` + strings.Repeat(`}`, n) }
	if e := app(deep(6)); e.F["a.a.a.a.a.a"] != 1.0 {
		t.Errorf("depth 6 must parse: %v", e.F)
	}
	deepArr := `{"a":` + strings.Repeat("[", 6) + "1" + strings.Repeat("]", 6) + `}`
	keys := func(n int) string {
		var b strings.Builder
		b.WriteString("{")
		for i := 0; i < n; i++ {
			if i > 0 {
				b.WriteString(",")
			}
			fmt.Fprintf(&b, `"k%d":%d`, i, i)
		}
		b.WriteString("}")
		return b.String()
	}
	if e := app(keys(256)); len(e.F) != 256 {
		t.Errorf("256 keys must parse: %d", len(e.F))
	}
	for name, line := range map[string]string{
		"depth 7":        deep(7),
		"depth 5000":     deep(5000),
		"array depth 7":  deepArr,
		"257 keys":       keys(257),
		"invalid":        `{not json`,
		"trailing":       `{"a":1} trailing`,
		"two objects":    `{"a":1}{"b":2}`,
		"huge number":    `{"n":1e400,"msg":"x"}`,
		"raw NUL":        "{\"msg\":\"a\x00b\"}",
		"top-level list": `[{"a":1}]`,
	} {
		e := app(line)
		if e.Kind != siem.KindLog || e.F != nil || e.Msg != line {
			t.Errorf("%s: must fall back to plain text, got F=%v msg=%.40q", name, e.F, e.Msg)
		}
	}
	// Large finite numbers and escapes survive; invalid UTF-8 doesn't panic.
	e := app(`{"n":1.7e308,"neg":-1e308,"s":"a\u0000b\ud800","msg":"é"}`)
	if e.F["n"] != 1.7e308 || e.F["neg"] != -1e308 || e.Msg != "é" {
		t.Errorf("numbers/escapes: %v %q", e.F, e.Msg)
	}
	e = app("{\"msg\":\"bad \xff\xfe utf8\",\"k\xff\":\"v\"}")
	if !strings.HasPrefix(e.Msg, "bad ") {
		t.Errorf("invalid utf8: %q", e.Msg)
	}
	// An 8 KiB line of valid JSON still parses.
	long := `{"msg":"` + strings.Repeat("x", 8<<10-12) + `"}`
	if e := app(long); len(e.Msg) != 8<<10-12 || e.F != nil {
		t.Errorf("8 KiB: msg %d F %v", len(e.Msg), e.F)
	}
	for _, line := range []string{deep(5000), keys(257), long} {
		checkEvent(t, app(line))
	}
}

func TestAppLinePlainText(t *testing.T) {
	cases := map[string]string{
		"ERROR something broke":           siem.LvlError,
		"error: connect ECONNREFUSED":     siem.LvlError,
		"[WARN] disk almost full":         siem.LvlWarn,
		"WARNING: deprecated":             siem.LvlWarn,
		"warn something":                  siem.LvlWarn,
		"FATAL boom":                      siem.LvlCritical,
		"panic: runtime error: index out": siem.LvlCritical,
		"PANIC":                           siem.LvlCritical,
		"DEBUG cache miss":                siem.LvlDebug,
		"[debug] x":                       siem.LvlDebug,
		"INFO: started":                   siem.LvlInfo,
		"CRITICAL:root:db down":           siem.LvlCritical,
		"  ERROR  indented":               siem.LvlError,
		"Errors found: 3":                 siem.LvlInfo,
		"something ERROR later":           siem.LvlInfo,
		"listening on :3000":              siem.LvlInfo,
		"time=2026-11-23T12:00:00Z level=ERROR msg=\"db down\"": siem.LvlError,
		"level=warn msg=slow": siem.LvlWarn,
		"lvl=debug x":         siem.LvlDebug,
		"xlevel=error":        siem.LvlInfo,
		"":                    siem.LvlInfo,
		"{":                   siem.LvlInfo,
	}
	for text, want := range cases {
		e := app(text)
		if e.Lvl != want || e.Kind != siem.KindLog || e.Msg != text || e.F != nil {
			t.Errorf("%q: lvl %q kind %q msg %q F %v (want %q)", text, e.Lvl, e.Kind, e.Msg, e.F, want)
		}
		if !e.TS.Equal(at) {
			t.Errorf("%q: TS %v", text, e.TS)
		}
	}
	if e := app("hello\r\n"); e.Msg != "hello" {
		t.Errorf("trailing CRLF: %q", e.Msg)
	}
	if e := app(`  {"msg":"indented json"}`); e.Msg != "indented json" {
		t.Errorf("leading spaces before {: %q", e.Msg)
	}
}

// checkEvent asserts the invariants every parser output keeps.
func checkEvent(t *testing.T, e siem.Event) {
	t.Helper()
	switch e.Src {
	case siem.SrcApp, siem.SrcEdge, siem.SrcMooring, siem.SrcHost:
	default:
		t.Fatalf("Src %q", e.Src)
	}
	switch e.Lvl {
	case siem.LvlDebug, siem.LvlInfo, siem.LvlWarn, siem.LvlError, siem.LvlCritical:
	default:
		t.Fatalf("Lvl %q", e.Lvl)
	}
	if e.Kind == "" {
		t.Fatal("empty Kind")
	}
	if e.Out != "" && e.Out != siem.OutSuccess && e.Out != siem.OutFailure {
		t.Fatalf("Out %q", e.Out)
	}
	if e.IP != "" && parseIP(e.IP) != e.IP {
		t.Fatalf("IP %q not canonical", e.IP)
	}
	for k, v := range e.F {
		switch tv := v.(type) {
		case string, bool:
		case float64:
			if math.IsNaN(tv) || math.IsInf(tv, 0) {
				t.Fatalf("F[%q] = %v", k, tv)
			}
		default:
			t.Fatalf("F[%q] has type %T", k, v)
		}
	}
	if e.F != nil && len(e.F) == 0 {
		t.Fatal("F empty but not nil")
	}
}
