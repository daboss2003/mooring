package detect

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/alert"
	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/parse"
)

var reBuiltinID = regexp.MustCompile(`^[a-z0-9]+\.[a-z0-9_]+$`)

func TestPackRulesAreValid(t *testing.T) {
	if len(pack) < 15 {
		t.Fatalf("%d built-in rules, want at least 15", len(pack))
	}
	seen := map[string]bool{}
	for _, p := range pack {
		r := cloneRule(p.Rule)
		if seen[r.ID] || !reBuiltinID.MatchString(r.ID) || strings.HasPrefix(r.ID, CustomPrefix) {
			t.Errorf("%s: duplicate or bad ID", r.ID)
		}
		seen[r.ID] = true
		if !r.Enabled || !r.Builtin || len(r.MITRE) == 0 || r.Description == "" {
			t.Errorf("%s: enabled %v builtin %v mitre %v", r.ID, r.Enabled, r.Builtin, r.MITRE)
		}
		before, _ := json.Marshal(r)
		if err := validate(&r, t0); err != nil {
			t.Errorf("%s: %v", r.ID, err)
			continue
		}
		if after, _ := json.Marshal(r); string(after) != string(before) {
			t.Errorf("%s: validation changed it:\n%s\n%s", r.ID, before, after)
		}
		if _, err := compile(r, p.info, nil); err != nil {
			t.Errorf("%s: %v", r.ID, err)
		}
		if p.info.noun == "" && r.Type != siem.RuleDistinct {
			t.Errorf("%s: no noun for its summary", r.ID)
		}
	}
}

// Every built-in rule is in the docs table, with its default threshold.
func TestPackIsDocumented(t *testing.T) {
	b, err := os.ReadFile("../../../docs/security-detections.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	for _, p := range pack {
		row := ""
		for _, l := range strings.Split(doc, "\n") {
			if strings.HasPrefix(l, "| `"+p.ID+"` |") {
				row = l // the first table: the rules
				break
			}
		}
		if row == "" {
			t.Errorf("%s: no row in docs/security-detections.md", p.ID)
			continue
		}
		if !strings.Contains(row, "| "+string(p.Severity)+" |") {
			t.Errorf("%s: row lacks severity %s: %s", p.ID, p.Severity, row)
		}
		for _, m := range p.MITRE {
			if !strings.Contains(row, "["+m+"](https://attack.mitre.org/techniques/"+strings.ReplaceAll(m, ".", "/")+"/)") {
				t.Errorf("%s: row lacks the link for %s: %s", p.ID, m, row)
			}
		}
		if p.Count > 0 && !strings.Contains(row, fmt.Sprint(p.Count)) {
			t.Errorf("%s: row lacks count %d: %s", p.ID, p.Count, row)
		}
		if p.Window > 0 && !strings.Contains(row, fmtDur(p.Window)) {
			t.Errorf("%s: row lacks window %s: %s", p.ID, fmtDur(p.Window), row)
		}
	}
}

// The docs' query table shows every built-in rule's query and closing query as the pack has them.
func TestPackQueriesDocumented(t *testing.T) {
	b, err := os.ReadFile("../../../docs/security-detections.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	_, queries, ok := strings.Cut(doc, "| ID | Query | Closing query (`then`) |")
	if !ok {
		t.Fatal("no query table")
	}
	for _, p := range pack {
		then := ""
		if p.Then != "" {
			then = "`" + p.Then + "`"
		}
		if row := "| `" + p.ID + "` | `" + p.Query + "` | " + then + " |"; !strings.Contains(queries, row+"\n") {
			t.Errorf("%s: no query row %s", p.ID, row)
		}
	}
}

// host feeds auth.log lines (RFC 3339 syslog time at t0+at) through the real parser.
func (h *harness) host(t *testing.T, at time.Duration, prog, msg string, g *siem.Geo) {
	t.Helper()
	line := t0.Add(at).Format(time.RFC3339) + " web1 " + prog + ": " + msg
	e, ok := parse.AuthLog(line, t0.Add(at), time.UTC)
	if !ok {
		t.Fatalf("parse %q", line)
	}
	if e.IP != "" {
		e.Geo = g
	}
	h.feed(e)
}

// app feeds a backend JSON line through the real parser.
func (h *harness) app(t *testing.T, at time.Duration, fields map[string]any, g *siem.Geo) {
	t.Helper()
	fields["time"] = t0.Add(at).UnixMilli()
	b, _ := json.Marshal(fields)
	e := parse.AppLine(t0.Add(at), "shop", "api", "abc123", string(b))
	e.Geo = g
	h.feed(e)
}

func (h *harness) mooring(at time.Duration, ev audit.Event, g *siem.Geo) {
	e := parse.Audit(t0.Add(at), ev)
	e.Geo = g
	h.feed(e)
}

func ruleIDs(ds []siem.Detection) map[string]int {
	m := map[string]int{}
	for _, d := range ds {
		m[d.RuleID]++
	}
	return m
}

var lagos = &siem.Geo{Country: "NG", City: "Lagos", Lat: 6.45, Lon: 3.39, ASN: 37148, Org: "Example"}

func TestPackSSHBruteForceThenSuccess(t *testing.T) {
	h := newHarness(t, false)
	for i := range 10 {
		h.host(t, time.Duration(i)*time.Second, "sshd[1234]", "Failed password for root from 203.0.113.7 port 52144 ssh2", lagos)
	}
	h.host(t, 11*time.Second, "sshd[1234]", "message repeated 4 times: [ Failed password for root from 203.0.113.7 port 52144 ssh2]", lagos)
	if got := ruleIDs(h.all(t)); got["ssh.bruteforce"] != 0 {
		t.Fatalf("14 failures fired: %v", got)
	}
	h.host(t, 12*time.Second, "sshd[1234]", "message repeated 6 times: [ Failed password for root from 203.0.113.7 port 52144 ssh2]", lagos)
	ds := h.detections(t, "ssh.bruteforce")
	if len(ds) != 1 || ds[0].Summary != "203.0.113.7 (Lagos, NG; AS37148 Example) — 20 failed SSH logins in 10m" {
		t.Fatalf("20 failures: %+v", ds)
	}
	if a := h.alerts(); len(a) != 0 {
		t.Fatalf("medium brute force alerted: %+v", a)
	}
	h.host(t, time.Minute, "sshd[1300]", "Accepted password for root from 203.0.113.7 port 52200 ssh2", lagos)
	ds = h.detections(t, "ssh.success_after_failures")
	if len(ds) != 1 || ds[0].Severity != siem.SevCritical ||
		ds[0].Summary != "203.0.113.7 (Lagos, NG; AS37148 Example) — 20 failed SSH logins then a successful login" {
		t.Fatalf("success after failures: %+v", ds)
	}
	a := h.alerts()
	if len(a) != 1 || a[0].Level != alert.LevelCritical || a[0].DedupeKey != "siem:ssh.success_after_failures:203.0.113.7" ||
		a[0].Summary != "SSH login after failed attempts: "+ds[0].Summary {
		t.Fatalf("critical alert: %+v", a)
	}
}

// An attempt for an unknown user name yields three events; only the ssh.login failure counts.
func TestPackSSHInvalidUserCountedOnce(t *testing.T) {
	h := newHarness(t, false)
	attempt := func(i int, user string) {
		at, port := time.Duration(i)*time.Second, 40000+i
		h.host(t, at, "sshd[99]", fmt.Sprintf("Invalid user %s from 198.51.100.4 port %d", user, port), nil)
		h.host(t, at, "sshd[99]", fmt.Sprintf("Failed password for invalid user %s from 198.51.100.4 port %d ssh2", user, port), nil)
		h.host(t, at, "sshd[99]", fmt.Sprintf("Connection closed by invalid user %s 198.51.100.4 port %d [preauth]", user, port), nil)
	}
	for i := range 19 {
		attempt(i, fmt.Sprint("u", i%9)) // 9 distinct names
	}
	if got := ruleIDs(h.all(t)); len(got) != 0 {
		t.Fatalf("19 attempts, 9 names: %v", got)
	}
	attempt(19, "u9") // the 20th attempt, the 10th name
	got := ruleIDs(h.all(t))
	if got["ssh.bruteforce"] != 1 || got["ssh.spray"] != 1 || len(got) != 2 {
		t.Fatalf("20 attempts, 10 names: %v", got)
	}
}

// A failed su or sudo yields the PAM line and su's/sudo's own line; one attempt counts once.
func TestPackSuSudoCountedOnce(t *testing.T) {
	h := newHarness(t, false)
	failedSu := func(at time.Duration) {
		h.host(t, at, "su[200]", "pam_unix(su:auth): authentication failure; logname=alice uid=1000 euid=0 tty=/dev/pts/0 ruser=alice rhost=  user=root", nil)
		h.host(t, at, "su[200]", "FAILED SU (to root) alice on pts/0", nil)
	}
	failedSudo := func(at time.Duration) {
		h.host(t, at, "sudo", "pam_unix(sudo:auth): authentication failure; logname=alice uid=1000 euid=0 tty=/dev/pts/0 ruser=alice rhost=  user=alice", nil)
		h.host(t, at, "sudo", "   alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id", nil)
	}
	failedSu(0)
	failedSudo(time.Minute)
	h.host(t, 2*time.Minute, "sudo", "   alice : a password is required ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/true", nil)
	h.host(t, 2*time.Minute, "sudo", "   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/ls", nil)
	if got := ruleIDs(h.all(t)); len(got) != 0 {
		t.Fatalf("2 failed attempts: %v", got)
	}
	failedSu(3 * time.Minute)
	ds := h.detections(t, "sudo.failures")
	if len(ds) != 1 || ds[0].Key != "alice" || ds[0].Count != 3 {
		t.Fatalf("3 failed attempts: %+v", ds)
	}
}

func TestPackAppSprayAndTakeover(t *testing.T) {
	h := newHarness(t, false)
	for i := range 9 {
		h.app(t, time.Duration(i)*time.Second, map[string]any{"level": 40, "event": "auth.login", "outcome": "failure",
			"reason": "bad_password", "account": fmt.Sprintf("user%d@example.com", i), "ip": "198.51.100.9", "msg": "login failed"}, nil)
	}
	if got := ruleIDs(h.all(t)); len(got) != 0 {
		t.Fatalf("9 accounts: %v", got)
	}
	h.app(t, 10*time.Second, map[string]any{"event": "admin.login", "outcome": "failure", "account": "ops@example.com",
		"ip": "198.51.100.9"}, nil)
	if got := ruleIDs(h.all(t)); got["app.auth_spray"] != 1 || len(got) != 1 {
		t.Fatalf("10 accounts (auth + admin): %v", got)
	}

	// One account: 10 failures, then a success.
	for i := range 10 {
		h.app(t, time.Minute+time.Duration(i)*time.Second, map[string]any{"event": "auth.login", "outcome": "failure",
			"actor_id": "u-42", "account": "victim@example.com", "ip": fmt.Sprint("203.0.113.", i)}, nil)
	}
	h.app(t, 2*time.Minute, map[string]any{"event": "auth.login", "outcome": "success", "actor_id": "u-42",
		"account": "victim@example.com", "ip": "203.0.113.99"}, nil)
	ds := h.detections(t, "app.auth_success_after_failures")
	if len(ds) != 1 || ds[0].Key != "u-42" || ds[0].App != "shop" || ds[0].Severity != siem.SevHigh {
		t.Fatalf("takeover: %+v", ds)
	}
	if a := h.alerts(); len(a) != 1 || a[0].Level != alert.LevelWarning || a[0].Target != TargetSIEM {
		t.Fatalf("alerts: %+v", a)
	}
}

func TestPackMooringSignIns(t *testing.T) {
	h := newHarness(t, false)
	fail := func(at time.Duration, user, why string) {
		h.mooring(at, audit.Event{Actor: user, IP: "203.0.113.50", Action: "login", Outcome: audit.Deny,
			Level: audit.Security, Detail: why}, lagos)
	}
	for i, u := range []string{"admin", "root", "owner", "deploy"} {
		fail(time.Duration(i)*time.Second, u, "unknown user")
	}
	if got := ruleIDs(h.all(t)); len(got) != 0 {
		t.Fatalf("4 failures: %v", got)
	}
	fail(5*time.Second, "operator", "invalid password")
	if got := ruleIDs(h.all(t)); got["mooring.login_spray"] != 1 || len(got) != 1 {
		t.Fatalf("5 user names: %v", got)
	}
	h.mooring(10*time.Second, audit.Event{Actor: "operator", IP: "203.0.113.50", Action: "login", Outcome: audit.OK,
		Level: audit.Security}, lagos)
	if got := ruleIDs(h.all(t)); got["mooring.login_success_after_failures"] != 1 {
		t.Fatalf("success after 5 failures: %v", got)
	}
	h.mooring(11*time.Second, audit.Event{Actor: "operator", IP: "203.0.113.50", Action: "login_lockout",
		Target: "peer_user", Outcome: audit.Deny, Level: audit.Security}, lagos)
	h.mooring(12*time.Second, audit.Event{Actor: "system", Action: "user_added", Target: "mallory", Outcome: audit.OK,
		Level: audit.Security, Detail: "role owner, 2FA off"}, nil)
	got := ruleIDs(h.all(t))
	if got["mooring.lockout"] != 1 || got["mooring.user_change"] != 1 {
		t.Fatalf("lockout and user change: %v", got)
	}
	if ds := h.detections(t, "mooring.user_change"); ds[0].Key != "mallory" || ds[0].Summary != "user mallory — 1 user changes in 1h" {
		t.Fatalf("user change: %+v", ds)
	}
}

// Each list fires its own rules, also for an address on several lists; Tor exits are context: only
// the sign-in rules fire on that list.
func TestPackThreatLists(t *testing.T) {
	h := newHarness(t, false)
	lists := func(l ...string) *siem.Geo { return &siem.Geo{Country: "DE", Lists: l} }
	req := func(at time.Duration, ip string, g *siem.Geo) {
		e := ev(at, siem.SrcEdge, siem.KindHTTPRequest, "", ip, "", map[string]any{"status": float64(200), "host": "x"})
		e.Geo = g
		h.feed(e)
	}
	admin := func(at time.Duration, ip string, g *siem.Geo) {
		h.app(t, at, map[string]any{"event": "admin.login", "outcome": "success", "actor_id": "staff-1", "ip": ip}, g)
	}
	req(0, "198.51.100.1", lists("tor-exit"))
	admin(time.Second, "198.51.100.1", lists("tor-exit"))
	got := ruleIDs(h.all(t))
	if got["app.admin_tor_login"] != 1 || len(got) != 1 {
		t.Fatalf("Tor only: %v", got)
	}
	req(2*time.Second, "198.51.100.2", lists("spamhaus-drop"))
	admin(3*time.Second, "198.51.100.3", lists("dshield"))
	got = ruleIDs(h.all(t))
	if got["edge.spamhaus_ip"] != 1 || got["app.admin_dshield_ip"] != 1 || len(got) != 3 {
		t.Fatalf("listed: %v", got)
	}
	// On every list at once: each list's rule fires, and Tor's.
	all := lists("spamhaus-drop", "tor-exit", "dshield")
	req(4*time.Second, "198.51.100.4", all)
	admin(5*time.Second, "198.51.100.5", all)
	got = ruleIDs(h.all(t))
	for id, n := range map[string]int{"edge.spamhaus_ip": 2, "edge.dshield_ip": 1, "app.admin_spamhaus_ip": 1,
		"app.admin_dshield_ip": 2, "app.admin_tor_login": 2} {
		if got[id] != n {
			t.Errorf("%s: %d detections, want %d (%v)", id, got[id], n, got)
		}
	}
}

func TestPackHostAccountChange(t *testing.T) {
	h := newHarness(t, false)
	h.host(t, 0, "useradd[500]", "new user: name=backdoor, UID=1001, GID=1001, home=/home/backdoor, shell=/bin/bash, from=/dev/pts/0", nil)
	h.host(t, time.Second, "usermod[501]", "add 'backdoor' to group 'sudo'", nil)
	ds := h.detections(t, "host.user_change")
	if len(ds) != 1 || ds[0].Count != 2 || ds[0].Severity != siem.SevHigh {
		t.Fatalf("user changes: %+v", ds)
	}
	if a := h.alerts(); len(a) != 1 {
		t.Fatalf("one alert for the burst: %+v", a)
	}
}

// A day of ordinary traffic fires nothing.
func TestPackQuietDay(t *testing.T) {
	h := newHarness(t, false)
	abuja := &siem.Geo{Country: "NG", City: "Abuja", Lat: 9.07, Lon: 7.40, ASN: 29465, Org: "Example ISP"}
	for hr := range 24 {
		base := time.Duration(hr) * time.Hour
		if hr%8 == 0 {
			h.host(t, base, "sshd[10]", "Accepted publickey for deploy from 203.0.113.5 port 50000 ssh2: ED25519 SHA256:abc", abuja)
			h.host(t, base+time.Minute, "sudo", "  deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl restart x", nil)
		}
		if hr == 9 {
			h.host(t, base, "sshd[11]", "Failed password for deploy from 203.0.113.5 port 50001 ssh2", abuja)
			h.host(t, base+10*time.Second, "sshd[11]", "Accepted password for deploy from 203.0.113.5 port 50001 ssh2", abuja)
			h.mooring(base, audit.Event{Actor: "operator", IP: "203.0.113.5", Action: "login", Outcome: audit.Deny,
				Level: audit.Security, Detail: "invalid password"}, abuja)
			h.mooring(base+20*time.Second, audit.Event{Actor: "operator", IP: "203.0.113.5", Action: "login",
				Outcome: audit.OK, Level: audit.Security}, abuja)
			h.mooring(base+time.Minute, audit.Event{Actor: "api:tok1", IP: "203.0.113.5", Action: "api_token_use",
				Outcome: audit.OK, Level: audit.Info}, abuja)
		}
		if hr == 14 {
			// A page with broken asset links: one visitor gets 20 404s in a minute.
			for i := range 20 {
				e := ev(base+time.Duration(i)*3*time.Second, siem.SrcEdge, siem.KindHTTPRequest, "", "198.51.100.200", "",
					map[string]any{"status": float64(404), "host": "api.example.com", "path": fmt.Sprintf("/img/%d.png", i)})
				e.Geo = abuja
				h.feed(e)
			}
		}
		for i := range 300 {
			at := base + time.Duration(i)*12*time.Second
			ip := fmt.Sprintf("198.51.%d.%d", i%7, i%200)
			status := 200
			switch {
			case i%50 == 0:
				status = 404
			case i%150 == 1:
				status = 502
			}
			e := ev(at, siem.SrcEdge, siem.KindHTTPRequest, "", ip, "", map[string]any{"status": float64(status),
				"host": "api.example.com", "path": "/v1/loans"})
			e.Geo = abuja
			h.feed(e)
			if i%10 == 0 {
				user := fmt.Sprint("u-", i%40)
				out := "success"
				if i%70 == 0 {
					out = "failure"
				}
				h.app(t, at, map[string]any{"event": "auth.login", "outcome": out, "actor_id": user,
					"account": user + "@example.com", "ip": ip}, abuja)
			}
		}
	}
	if ds := h.all(t); len(ds) != 0 {
		var ids []string
		for _, d := range ds {
			ids = append(ids, d.RuleID+": "+d.Summary)
		}
		t.Fatalf("quiet day fired %d detections:\n%s", len(ds), strings.Join(ids, "\n"))
	}
}

func TestPackEdgeScan(t *testing.T) {
	h := newHarness(t, false)
	for i := range 99 {
		h.feed(ev(time.Duration(i)*time.Second, siem.SrcEdge, siem.KindHTTPRequest, "", "203.0.113.66", "",
			map[string]any{"status": float64(404), "path": fmt.Sprint("/wp-admin/", i)}))
	}
	if ds := h.detections(t, "edge.scan"); len(ds) != 0 {
		t.Fatalf("99 404s: %+v", ds)
	}
	h.feed(ev(100*time.Second, siem.SrcEdge, siem.KindHTTPRequest, "", "203.0.113.66", "",
		map[string]any{"status": float64(404), "path": "/.env"}))
	ds := h.detections(t, "edge.scan")
	if len(ds) != 1 || ds[0].Severity != siem.SevLow {
		t.Fatalf("100 404s: %+v", ds)
	}
	if a := h.alerts(); len(a) != 0 {
		t.Fatalf("a low detection alerted: %+v", a)
	}
}

// Rule query values for personal-data fields are mapped to their stored form.
func TestRuleValuesMapped(t *testing.T) {
	var calls []string
	h := newHarness(t, false, func(o *Options) {
		o.MapValue = func(field, value string) string {
			calls = append(calls, field+"="+value)
			if field == "actor" {
				return "h:" + value
			}
			return value
		}
	})
	calls = nil // the pack's, at New
	h.only(t, siem.Rule{ID: "custom.m", Type: siem.RuleThreshold, Query: "actor:alice@example.com f.email:* f.method:password kind:x.y",
		Count: 1, Window: time.Hour})
	if strings.Join(calls, ",") != "actor=alice@example.com,f.method=password" {
		t.Fatalf("MapValue calls: %v", calls)
	}
	e := ev(0, siem.SrcApp, "x.y", "", "", "h:alice@example.com", map[string]any{"email": "h:1", "method": "password"})
	h.feed(e)
	if ds := h.all(t); len(ds) != 1 {
		t.Fatalf("mapped value didn't match: %+v", ds)
	}
}
