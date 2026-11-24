package parse

import (
	"strings"
	"testing"
	"time"
)

func FuzzAppLine(f *testing.F) {
	for _, s := range []string{
		`{"level":30,"time":1795440881123,"msg":"request completed","req":{"method":"GET","url":"/x","remoteAddress":"::ffff:10.0.0.1"},"res":{"statusCode":500}}`,
		`{"level":"error","ts":1795440881.5,"msg":"x","user_id":"u1","ip":"[::1]:80","event":"auth.login_failed"}`,
		`{"a":{"b":{"c":{"d":{"e":{"f":1}}}}}}`, `{"a":[1,[2,[3]]]}`, `{"n":1e400}`, `{"":{"":""}}`,
		"ERROR boom", "panic: x", "level=warn msg=y", "{", "", `{"event":"mooring.login"}`, "{\"msg\":\"\xff\"}",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, text string) {
		e := AppLine(at, "a", "s", "c", text)
		checkEvent(t, e)
		if len(e.F) > maxJSONKeys {
			t.Fatalf("%d fields", len(e.F))
		}
		for _, p := range reservedKinds {
			if strings.HasPrefix(e.Kind, p) {
				t.Fatalf("app produced reserved kind %q", e.Kind)
			}
		}
		if e.Kind != "log" && !validKind(e.Kind) {
			t.Fatalf("kind %q", e.Kind)
		}
		if d := e.TS.Sub(at); d > window || d < -window {
			t.Fatalf("TS %v outside the window", e.TS)
		}
	})
}

func FuzzEdgeAccess(f *testing.F) {
	f.Add(caddyLine(1795440881.5, ""))
	f.Add([]byte(`{"logger":"http.log.access","ts":1e300,"status":1e308,"duration":1e306,"request":{"client_ip":"::ffff:1.2.3.4"}}`))
	f.Add([]byte(`{"logger":"http.log.access.x","request":{"headers":{"User-Agent":[""]},"uri":"?"}}`))
	allowed := map[string]bool{"method": true, "host": true, "path": true, "query": true, "proto": true, "status": true,
		"dur_ms": true, "size": true, "bytes_read": true, "ua": true, "sni": true, "user_id": true}
	now := time.Unix(1795440881, 0)
	f.Fuzz(func(t *testing.T, raw []byte) {
		e, ok := EdgeAccess(raw, now)
		if !ok {
			return
		}
		checkEvent(t, e)
		for k := range e.F {
			if !allowed[k] {
				t.Fatalf("unexpected field %q", k)
			}
		}
		if d := e.TS.Sub(now); d > window || d < -window {
			t.Fatalf("TS %v outside the window", e.TS)
		}
	})
}

func FuzzAuthLog(f *testing.F) {
	for _, s := range []string{
		"Nov 23 13:14:41 web1 sshd[1234]: Accepted publickey for deploy from 203.0.113.5 port 52134 ssh2: ED25519 SHA256:x",
		"2026-11-23T13:14:42.000001+00:00 web1 sshd-session[2001]: Failed password for invalid user a from 1.2.3.4 port 1 ssh2",
		"Nov 23 13:20:01 web1 sudo:   alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/sh",
		"Nov 23 13:25:00 web1 su: pam_unix(su:auth): authentication failure; logname=a uid=1 euid=0 tty=x ruser=a rhost=  user=root",
		"Nov 23 13:25:00 web1 useradd[1]: new user: name=x, UID=1",
		"Nov 23 13:14:41 web1 sshd[1]: message repeated 2 times: [ Connection closed by 1.2.3.4 port 1 [preauth]]",
		"Dec 31 23:59:59 h p: m", "", "x",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		e, ok := AuthLog(line, hostNow, wat)
		if ok {
			checkEvent(t, e)
			if e.TS.After(hostNow.Add(window)) {
				t.Fatalf("TS %v in the future", e.TS)
			}
		}
		if e2, ok := Fail2Ban(line, hostNow, wat); ok {
			checkEvent(t, e2)
		}
	})
}

func FuzzJournal(f *testing.F) {
	f.Add(journalLine("sshd", "Failed password for root from 1.2.3.4 port 1 ssh2"))
	f.Add([]byte(`{"SYSLOG_IDENTIFIER":"sudo","MESSAGE":[97,32,58,32,84,84,89,61,120],"__REALTIME_TIMESTAMP":"1"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if e, ok := Journal(raw); ok {
			checkEvent(t, e)
		}
	})
}
