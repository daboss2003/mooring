package web

import (
	"html"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/query"
)

var (
	relatedLink = regexp.MustCompile(`href="([^"]+)">Find related events</a>`)
	relatedText = regexp.MustCompile(`Every event with <code>([^<]*)</code>`)
)

// The "Find related events" link of a detection finds the events of its key as they are stored, the
// way the search page reads the link (real redaction): a host key with or without a port, an
// account key that is a user or a group, a key cut to its bound; a rollup (or a rule without a
// group-by) links the rule's own events instead of searching its key.
func TestDetectionRelatedEventsLink(t *testing.T) {
	realQueryParser(t)
	red := testRedactor(t)
	sl := redactingSecurityLogs{&fakeSecurityLogs{}, red}
	now := time.Now().UTC().Truncate(time.Second)
	first, last := now.Add(-30*time.Minute), now.Add(-5*time.Minute)
	at := first.Add(time.Minute)

	longKey := strings.Repeat("p", siem.MaxShort) // the group-by value, cut to MaxShort bytes
	account := storedForm(t, red, "user", "deploy")
	rules := []siem.Rule{
		{ID: "edge.error_anomaly", Name: "Server error surge", Type: siem.RuleAnomaly, Query: "src:edge kind:http.request f.status>=500",
			GroupBy: "f.host", Count: 50, Window: 10 * time.Minute, Factor: 5, Enabled: true, Builtin: true},
		{ID: "host.user_change", Name: "Host account change", Type: siem.RuleThreshold,
			Query: "src:host kind:host.user_change -f.sender_mismatch:true", GroupBy: "f.user", Count: 1, Window: time.Hour, Enabled: true, Builtin: true},
		{ID: "ssh.bruteforce", Name: "SSH brute force", Type: siem.RuleThreshold, Query: "kind:ssh.login out:failure",
			GroupBy: "ip", Count: 10, Window: 10 * time.Minute, Enabled: true, Builtin: true},
		{ID: "custom.admin", Name: "Admin probing", Type: siem.RuleThreshold, Query: "src:edge f.path:/admin*", Count: 5, Window: time.Hour, Enabled: true},
		{ID: "custom.paths", Name: "Odd paths", Type: siem.RuleThreshold, Query: "src:edge", GroupBy: "f.path", Count: 5, Window: time.Hour, Enabled: true},
	}
	ev := func(src, kind, ip string, f map[string]any) siem.Event {
		e := siem.Event{TS: at, Src: src, Kind: kind, IP: ip, F: f}
		red.Apply(&e) // as stored
		return e
	}
	edge := func(host string) siem.Event {
		return ev("edge", "http.request", "198.51.100.7", map[string]any{"host": host, "status": float64(502), "path": "/"})
	}
	uc := func(f map[string]any) siem.Event { return ev("host", siem.KindUserChange, "", f) }
	sshFail := func(ip string) siem.Event {
		e := ev("host", "ssh.login", ip, nil)
		e.Out = siem.OutFailure
		return e
	}
	sshOK := sshFail("203.0.113.9")
	sshOK.Out = siem.OutSuccess
	path := func(p string) siem.Event {
		return ev("edge", "http.request", "198.51.100.7", map[string]any{"path": p})
	}

	for _, c := range []struct {
		name     string
		det      siem.Detection
		term     string // the search the page shows
		match    []siem.Event
		nomatch  []siem.Event
		noIPTerm bool
	}{
		{name: "host key, any port", det: siem.Detection{RuleID: "edge.error_anomaly", Key: "example.com"},
			term:    "f.host:example.com*",
			match:   []siem.Event{edge("example.com"), edge("Example.COM:8443"), edge("example.com:443"), edge("EXAMPLE.com.")},
			nomatch: []siem.Event{edge("other.com"), edge("api.example.com"), edge("example.org:443")}},
		{name: "account: user or group", det: siem.Detection{RuleID: "host.user_change", Key: account},
			term: "kind:host.user_change -f.user!=" + account + " -f.group!=" + account,
			match: []siem.Event{
				uc(map[string]any{"program": "useradd", "user": "deploy", "detail": "new user: name=deploy"}),
				uc(map[string]any{"program": "groupadd", "group": "deploy", "detail": "group added to /etc/group: name=deploy"}),
				uc(map[string]any{"program": "passwd", "user": "deploy", "sender_mismatch": true}),
			},
			nomatch: []siem.Event{
				uc(map[string]any{"program": "useradd", "user": "alice"}),
				uc(map[string]any{"program": "groupadd", "group": "dev"}),
			}},
		{name: "rollup: the rule's events, not ip:*", det: siem.Detection{RuleID: "ssh.bruteforce", Key: "*"},
			term:     "kind:ssh.login out:failure",
			match:    []siem.Event{sshFail("203.0.113.9"), sshFail("2001:db8::7")},
			nomatch:  []siem.Event{sshOK, edge("example.com")},
			noIPTerm: true},
		{name: "no group-by: the rule's events", det: siem.Detection{RuleID: "custom.admin"},
			term:    "src:edge f.path:/admin*",
			match:   []siem.Event{path("/admin/login")},
			nomatch: []siem.Event{path("/shop")}},
		{name: "key cut to MaxShort", det: siem.Detection{RuleID: "custom.paths", Key: longKey},
			term:    "f.path:" + longKey + "*",
			match:   []siem.Event{path(longKey + strings.Repeat("q", 40))},
			nomatch: []siem.Event{path(longKey[:100] + "x" + strings.Repeat("q", 200))}},
		{name: "IPv6 key is its /64", det: siem.Detection{RuleID: "ssh.bruteforce", Key: "2001:db8:1:2::/64"},
			term:    "ip:2001:db8:1:2::/64",
			match:   []siem.Event{sshFail("2001:db8:1:2::5"), sshFail("2001:db8:1:2::9")},
			nomatch: []siem.Event{sshFail("2001:db8:1:3::5")}},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := c.det
			d.ID, d.Source, d.First, d.Last, d.Severity, d.Count = 9, siem.DetectionSIEM, first, last, siem.SevMedium, 3
			e := detEnv(t, &detFakeService{rules: rules, dets: []siem.Detection{d}}, nil)
			_, body := e.get(t, "/security/detections/9", e.loginAs(t, "operator"))
			link, text := relatedLink.FindStringSubmatch(body), relatedText.FindStringSubmatch(body)
			if link == nil || text == nil {
				t.Fatalf("no related-events link on the page")
			}
			if got := html.UnescapeString(text[1]); got != c.term {
				t.Errorf("related search shown = %q, want %q", got, c.term)
			}
			req := httptest.NewRequest("GET", html.UnescapeString(link[1]), nil)
			_, q, msg := e.srv.securityQueryFrom(req, sl, now)
			if msg != "" {
				t.Fatalf("the search page refuses the link %q: %s", link[1], msg)
			}
			if !q.From.Equal(first.Add(-time.Minute)) || !q.To.Equal(last.Add(time.Minute)) {
				t.Errorf("window %v..%v, want the detection's span ± 1m", q.From, q.To)
			}
			for _, tm := range q.Terms {
				if c.noIPTerm && tm.Field == "ip" {
					t.Errorf("a rollup's link searches its key: %+v", tm)
				}
			}
			for i, x := range c.match {
				if !q.Match(&x) {
					t.Errorf("match[%d] (%s %s %v) not found by %q", i, x.Kind, x.IP, x.F, encodeSecurityQuery(q))
				}
			}
			for i, x := range c.nomatch {
				if q.Match(&x) {
					t.Errorf("nomatch[%d] (%s %s %v) found by %q", i, x.Kind, x.IP, x.F, encodeSecurityQuery(q))
				}
			}
		})
	}
}

// relatedSearch falls back to the rule's own events when the key's search is not one the search
// page accepts, and gives no link without a rule query to fall back to.
func TestRelatedSearchFallbacks(t *testing.T) {
	realQueryParser(t)
	paths := siem.Rule{ID: "custom.paths", GroupBy: "f.path", Query: "src:edge"}
	if _, err := query.Parse("f.path:\xff"); err == nil {
		t.Fatal("fixture: the parser takes invalid UTF-8")
	}
	if got := relatedSearch(paths, "\xff"); got != "src:edge" {
		t.Errorf("a key the parser refuses: %q, want the rule's query", got)
	}
	if got := relatedSearch(siem.Rule{ID: "custom.x", GroupBy: "ip"}, "not-an-ip"); got != "" {
		t.Errorf("an ip key that is no address, and no rule query: %q, want no link", got)
	}
	for _, gb := range []string{"ip", "actor", "app", "f.host", "f.user"} {
		if got := relatedSearch(siem.Rule{ID: "custom.x", GroupBy: gb, Query: "kind:x"}, "*"); got != "kind:x" {
			t.Errorf("rollup of a rule by %s: %q, want the rule's query", gb, got)
		}
	}
	if got := relatedSearch(siem.Rule{ID: "custom.x", GroupBy: "geo.cc", Query: "kind:x"}, "NG"); got != "geo.cc:NG" {
		t.Errorf("geo.cc key: %q", got)
	}
}

// A custom rule may group by an f.<key> holding characters the search treats as operators
// (`:`, `~`, `>`, `<`, `!=`). Such a key search would parse as another field (f.a:b:web1 is field f.a,
// value b:web1) and silently find nothing: the link falls back to the rule's own events instead.
func TestRelatedSearchFieldWithOperatorChars(t *testing.T) {
	for _, groupBy := range []string{"f.a:b", "f.x~y", "f.p>q", "f.p<q", "f.n!=m"} {
		ru := siem.Rule{ID: "custom.odd", GroupBy: groupBy, Query: "kind:app.event"}
		if got := relatedSearch(ru, "web1"); got != "kind:app.event" {
			t.Errorf("group by %q: link %q, want the rule's own events", groupBy, got)
		}
	}
	// An ordinary field still searches the key.
	if got := relatedSearch(siem.Rule{ID: "custom.ok", GroupBy: "f.tenant", Query: "kind:app.event"}, "web1"); got != "f.tenant:web1" {
		t.Errorf("ordinary field: link %q, want f.tenant:web1", got)
	}
}
