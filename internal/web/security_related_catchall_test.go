package web

import (
	"html"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/query"
)

// A traffic baseline counts every label under a catch-all route as one key, "*.<apex>". No event's
// host starts with "*.", and the search has no suffix match (a substring of the host would also
// find other apexes), so its "Find related events" link searches the rule's own events: they hold
// every request for the apex. An exact host still searches its host.
func TestRelatedSearchCatchAllHost(t *testing.T) {
	realQueryParser(t)
	// Why not f.host~.example.com: the substring is in names under other apexes too.
	sub, err := query.Parse("f.host~.example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, other := range []string{"x.example.community", "a.example.com.evil.org"} {
		if ev := (siem.Event{Src: siem.SrcEdge, F: map[string]any{"host": other}}); !sub.Match(&ev) {
			t.Fatalf("fixture: f.host~.example.com no longer matches %s; a safe apex search may be possible now", other)
		}
	}

	red := testRedactor(t)
	sl := redactingSecurityLogs{&fakeSecurityLogs{}, red}
	now := time.Now().UTC().Truncate(time.Second)
	first, last := now.Add(-time.Hour), now.Add(-time.Minute)
	surge := siem.Rule{ID: "baseline.traffic_surge", Name: "Traffic surge", Type: siem.RuleBaseline, Baseline: siem.BaselineTraffic,
		Severity: siem.SevHigh, Query: "src:edge kind:http.request", GroupBy: "f.host", Count: 200, Factor: 5, Learn: 14 * 24 * time.Hour,
		Enabled: true, Builtin: true}
	edge := func(host string) siem.Event {
		e := siem.Event{TS: first.Add(time.Minute), Src: siem.SrcEdge, Kind: siem.KindHTTPRequest, IP: "198.51.100.7",
			F: map[string]any{"host": host, "status": float64(200), "path": "/"}}
		red.Apply(&e)
		return e
	}
	for _, c := range []struct {
		name, key, term string
		match           []siem.Event
	}{
		{"catch-all: the rule's events", "*.example.com", "src:edge kind:http.request",
			[]siem.Event{edge("a.example.com"), edge("B.Example.COM:443"), edge("c.example.com.")}},
		{"exact host: its host", "shop.example.com", "f.host:shop.example.com*",
			[]siem.Event{edge("shop.example.com"), edge("Shop.Example.com:8443")}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := relatedSearch(surge, c.key); got != c.term {
				t.Errorf("relatedSearch(%q) = %q, want %q", c.key, got, c.term)
			}
			d := siem.Detection{ID: 9, Source: siem.DetectionSIEM, RuleID: surge.ID, RuleName: surge.Name, Severity: siem.SevHigh,
				Key: c.key, First: first, Last: last, Count: 1}
			e := detEnv(t, &detFakeService{rules: []siem.Rule{surge}, dets: []siem.Detection{d}}, nil)
			_, body := e.get(t, "/security/detections/9", e.loginAs(t, "operator"))
			link, text := relatedLink.FindStringSubmatch(body), relatedText.FindStringSubmatch(body)
			if link == nil || text == nil {
				t.Fatal("no related-events link on the page")
			}
			if got := html.UnescapeString(text[1]); got != c.term {
				t.Errorf("related search shown = %q, want %q", got, c.term)
			}
			_, q, msg := e.srv.securityQueryFrom(httptest.NewRequest("GET", html.UnescapeString(link[1]), nil), sl, now)
			if msg != "" {
				t.Fatalf("the search page refuses the link: %s", msg)
			}
			for i, x := range c.match {
				if !q.Match(&x) {
					t.Errorf("match[%d] (%v) not found by %q", i, x.F["host"], encodeSecurityQuery(q))
				}
			}
		})
	}
	// Without a rule query there is nothing to fall back to.
	noQuery := surge
	noQuery.Query = ""
	if got := relatedSearch(noQuery, "*.example.com"); got != "" {
		t.Errorf("catch-all key, no rule query: %q, want no link", got)
	}
}
