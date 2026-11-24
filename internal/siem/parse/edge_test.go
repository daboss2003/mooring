package parse

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/siem"
)

func caddyLine(ts float64, extra string) []byte {
	return []byte(fmt.Sprintf(`{"level":"info","ts":%f,"logger":"http.log.access.log0","msg":"handled request","request":{"remote_ip":"172.18.0.1","remote_port":"51234","client_ip":"203.0.113.50","proto":"HTTP/2.0","method":"POST","host":"api.example.com","uri":"/v1/login?token=abc&next=%%2F","headers":{"User-Agent":["okhttp/4.12.0","second"],"Cookie":["REDACTED"],"Authorization":["REDACTED"],"X-Forwarded-For":["1.2.3.4"],"Accept":["*/*"]},"tls":{"resumed":false,"version":772,"cipher_suite":4865,"proto":"h2","server_name":"api.example.com"}},"bytes_read":42,"user_id":"","duration":0.0123,"size":512,"status":401,"resp_headers":{"Server":["Caddy"],"Set-Cookie":["sid=x"]}%s}`, ts, extra))
}

func TestEdgeAccess(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	ts := float64(now.Add(-2*time.Second).UnixMilli()) / 1000
	e, ok := EdgeAccess(caddyLine(ts, ""), now)
	if !ok {
		t.Fatal("must parse")
	}
	if e.Src != siem.SrcEdge || e.Kind != siem.KindHTTPRequest || e.Lvl != siem.LvlWarn {
		t.Errorf("src/kind/lvl: %q %q %q", e.Src, e.Kind, e.Lvl)
	}
	if d := e.TS.Sub(now.Add(-2 * time.Second)); d > time.Millisecond || d < -time.Millisecond {
		t.Errorf("TS %v", e.TS)
	}
	if e.IP != "203.0.113.50" {
		t.Errorf("IP must be client_ip: %q", e.IP)
	}
	if e.Msg != "POST api.example.com/v1/login 401" {
		t.Errorf("Msg %q", e.Msg)
	}
	want := map[string]any{
		"method": "POST", "host": "api.example.com", "path": "/v1/login", "query": "token=abc&next=%2F",
		"proto": "HTTP/2.0", "status": 401.0, "dur_ms": 12.3, "size": 512.0, "bytes_read": 42.0,
		"ua": "okhttp/4.12.0", "sni": "api.example.com",
	}
	if !reflect.DeepEqual(e.F, want) {
		t.Errorf("F\n got %v\nwant %v", e.F, want)
	}
	// No request header other than the User-Agent is ever kept.
	for k, v := range e.F {
		if s, ok := v.(string); ok && (strings.Contains(s, "REDACTED") || s == "1.2.3.4" || s == "*/*" || s == "sid=x") {
			t.Errorf("header leaked into F[%q] = %q", k, s)
		}
	}
	checkEvent(t, e)
}

func TestEdgeAccessVariants(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	ts := float64(now.Unix())
	cases := []struct {
		name, line string
		ip, lvl    string
		f          map[string]any // subset checked
	}{
		{"remote_ip fallback", `{"logger":"http.log.access","ts":%v,"status":200,"request":{"remote_ip":"198.51.100.2","method":"GET","host":"h","uri":"/"}}`,
			"198.51.100.2", siem.LvlInfo, map[string]any{"path": "/", "status": 200.0}},
		{"invalid client_ip", `{"logger":"http.log.access.x","ts":%v,"status":500,"request":{"client_ip":"nope","remote_ip":"198.51.100.2","host":"h","uri":"/a?"}}`,
			"198.51.100.2", siem.LvlError, map[string]any{"path": "/a"}},
		{"no ip", `{"logger":"http.log.access","ts":%v,"status":302,"request":{"client_ip":"","remote_ip":"x"}}`,
			"", siem.LvlInfo, nil},
		{"user_id", `{"logger":"http.log.access","ts":%v,"status":200,"user_id":"ops","request":{"host":"h","uri":"/"}}`,
			"", siem.LvlInfo, map[string]any{"user_id": "ops"}},
		{"ipv6 mapped", `{"logger":"http.log.access","ts":%v,"status":200,"request":{"client_ip":"::ffff:203.0.113.8"}}`,
			"203.0.113.8", siem.LvlInfo, nil},
		{"string ts tolerated", `{"logger":"http.log.access","ts":"2026-11-23T12:00:00Z","status":200,"request":{"host":"h"}}`,
			"", siem.LvlInfo, map[string]any{"host": "h"}},
		{"wrong types", `{"logger":"http.log.access","ts":%v,"status":"200","duration":"1s","request":{"host":["h"],"headers":{"User-Agent":"not-a-list"}}}`,
			"", siem.LvlInfo, map[string]any{"status": 0.0}},
	}
	for _, c := range cases {
		line := c.line
		if strings.Contains(line, "%v") {
			line = fmt.Sprintf(line, ts)
		}
		e, ok := EdgeAccess([]byte(line), now)
		if !ok {
			t.Errorf("%s: must parse", c.name)
			continue
		}
		if e.IP != c.ip || e.Lvl != c.lvl {
			t.Errorf("%s: ip %q lvl %q", c.name, e.IP, e.Lvl)
		}
		for k, v := range c.f {
			if e.F[k] != v {
				t.Errorf("%s: F[%s] = %v want %v", c.name, k, e.F[k], v)
			}
		}
		checkEvent(t, e)
	}
	for name, line := range map[string]string{
		"other logger": `{"logger":"tls.obtain","ts":1,"msg":"certificate obtained"}`,
		"admin":        `{"level":"info","ts":1,"logger":"admin.api","msg":"received request"}`,
		"no logger":    `{"status":200,"request":{"host":"h"}}`,
		"longer name":  `{"logger":"http.log.accessx"}`,
		"malformed":    `{"logger":"http.log.access"`,
		"not json":     `http.log.access GET /`,
		"empty":        ``,
		"array":        `["http.log.access"]`,
		"logger type":  `{"logger":["http.log.access"]}`,
	} {
		if _, ok := EdgeAccess([]byte(line), now); ok {
			t.Errorf("%s: must not parse", name)
		}
	}
	// ±24h: a timestamp further off than a day uses now.
	for _, d := range []time.Duration{-25 * time.Hour, 25 * time.Hour} {
		e, _ := EdgeAccess([]byte(fmt.Sprintf(`{"logger":"http.log.access","ts":%v,"status":200}`, float64(now.Add(d).Unix()))), now)
		if !e.TS.Equal(now) {
			t.Errorf("%v: TS %v want now", d, e.TS)
		}
	}
	for _, v := range []string{"0", "-5", "1e300", "1.7e308"} {
		e, ok := EdgeAccess([]byte(`{"logger":"http.log.access","ts":`+v+`,"status":1e308,"duration":1e306,"size":-1e308}`), now)
		if !ok || !e.TS.Equal(now) {
			t.Errorf("ts %s: ok=%v %v", v, ok, e.TS)
		}
		checkEvent(t, e)
	}
}

func TestAudit(t *testing.T) {
	ts := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		ev       audit.Event
		lvl, out string
	}{
		{audit.Event{Action: "login", Actor: "owner", IP: "203.0.113.1", Outcome: audit.OK, Level: audit.Security, Detail: "password+totp", UA: "Mozilla/5.0", Target: "session"}, siem.LvlInfo, siem.OutSuccess},
		{audit.Event{Action: "login", Actor: "owner", Outcome: audit.Deny, Level: audit.Security}, siem.LvlWarn, siem.OutFailure},
		{audit.Event{Action: "deploy", Outcome: audit.Error, Level: audit.Info}, siem.LvlError, siem.OutFailure},
		{audit.Event{Action: "deploy", Outcome: audit.Error, Level: audit.Security}, siem.LvlError, siem.OutFailure},
		{audit.Event{Action: "env_set_secret", Outcome: audit.Deny, Level: audit.Info}, siem.LvlInfo, siem.OutFailure},
		{audit.Event{Action: "config_reload"}, siem.LvlInfo, siem.OutSuccess}, // unset outcome = ok, as audit.Log records it
	}
	for _, c := range cases {
		e := Audit(ts, c.ev)
		if e.Src != siem.SrcMooring || e.Kind != "mooring."+c.ev.Action || !e.TS.Equal(ts) {
			t.Errorf("%+v: %+v", c.ev, e)
		}
		if e.Lvl != c.lvl || e.Out != c.out {
			t.Errorf("%+v: lvl %q out %q, want %q %q", c.ev, e.Lvl, e.Out, c.lvl, c.out)
		}
		if e.Actor != c.ev.Actor || e.IP != c.ev.IP || e.Msg != c.ev.Detail {
			t.Errorf("%+v: actor/ip/msg %+v", c.ev, e)
		}
		checkEvent(t, e)
	}
	e := Audit(ts, cases[0].ev)
	if !reflect.DeepEqual(e.F, map[string]any{"target": "session", "ua": "Mozilla/5.0"}) {
		t.Errorf("F %v", e.F)
	}
	if e := Audit(ts, cases[1].ev); e.F != nil {
		t.Errorf("no target/ua → no F: %v", e.F)
	}
}
