package detect

import (
	"fmt"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/parse"
)

// recommended reports whether got is one request: a block of target that is not automatic.
func recommended(got []siem.ResponseRequest, target string) bool {
	return len(got) == 1 && got[0].Action == siem.ResponseBlock && got[0].Target == target && !got[0].Automatic
}

// scanLine is a Caddy access-log line of a request from ip answered 404, with the request headers
// given (JSON, e.g. `"User-Agent":["curl/8.5.0"]`), through the real parser.
func scanLine(t *testing.T, at time.Duration, ip, headers string) siem.Event {
	t.Helper()
	ts := t0.Add(at)
	line := fmt.Sprintf(`{"level":"info","ts":%d.%03d,"logger":"http.log.access.log0","msg":"handled request",`+
		`"request":{"remote_ip":%q,"client_ip":%q,"proto":"HTTP/1.1","method":"GET","host":"shop.example.com",`+
		`"uri":"/.env","headers":{%s}},"duration":0.001,"size":0,"status":404}`,
		ts.Unix(), ts.Nanosecond()/int(time.Millisecond), ip, ip, headers)
	e, ok := parse.EdgeAccess([]byte(line), ts)
	if !ok {
		t.Fatalf("not parsed: %s", line)
	}
	return e
}

// scan feeds the pack's edge.scan rule 100 requests from ip with the headers given and returns the
// requests the firing made.
func scan(t *testing.T, ip, headers string) []siem.ResponseRequest {
	t.Helper()
	h, fr := respHarness(t, false)
	for i := range 100 {
		h.feed(scanLine(t, time.Duration(i)*10*time.Millisecond, ip, headers))
	}
	h.e.flush(false)
	if ds := h.detections(t, "edge.scan"); len(ds) != 1 {
		t.Fatalf("detections %+v", ds)
	}
	return fr.all()
}

// Owner decision (v0.33.1): any client can send Sec-Fetch-Site itself, so a scanner that adds it to
// every request is not left alone: its block is recommended (never placed automatically, as a web
// page's visitors could be the ones sending), where before nothing was asked at all.
func TestResponseScannerFakingFetchMetadata(t *testing.T) {
	got := scan(t, addrX, `"User-Agent":["curl/8.5.0"],"Sec-Fetch-Site":["cross-site"]`)
	if len(got) != 1 {
		t.Fatalf("100 scripted requests carrying Sec-Fetch-Site: %d requests, want one recommendation: %+v", len(got), got)
	}
	if r := got[0]; r.Automatic || r.Action != siem.ResponseBlock || r.Target != addrX || r.RuleID != "edge.scan" ||
		r.Duration != time.Hour {
		t.Fatalf("request %+v, want a recommended one-hour block of %s", r, addrX)
	}
	// The same scan without the header is blocked automatically.
	if got := scan(t, addrY, `"User-Agent":["curl/8.5.0"]`); len(got) != 1 || !got[0].Automatic || got[0].Target != addrY {
		t.Fatalf("the scan without the header: %+v", got)
	}
}

// A Sec-Fetch-Site value no browser sends is not browser evidence: nothing is stored for it and
// the request is judged by its User-Agent like any other.
func TestResponseMadeUpFetchSiteValue(t *testing.T) {
	for _, v := range []string{"other", "yes", "cross-site,none", "evil<script>"} {
		e := scanLine(t, 0, addrX, fmt.Sprintf(`"User-Agent":["curl/8.5.0"],"Sec-Fetch-Site":[%q]`, v))
		if got, has := e.F["fetch_site"]; has {
			t.Fatalf("Sec-Fetch-Site %q stored as f.fetch_site = %v", v, got)
		}
		if b, a := sentBy(&e); b || a {
			t.Fatalf("Sec-Fetch-Site %q: sentBy = %v, %v", v, b, a)
		}
	}
	// A script's User-Agent: an automatic block.
	got := scan(t, addrX, `"User-Agent":["curl/8.5.0"],"Sec-Fetch-Site":["made-up"]`)
	if len(got) != 1 || !got[0].Automatic || got[0].Target != addrX || got[0].RuleID != "edge.scan" {
		t.Fatalf("a made-up value with a script's agent: %+v", got)
	}
	// A browser's User-Agent: a recommendation, as without the header.
	got = scan(t, addrY, `"User-Agent":["`+chromeWin+`"],"Sec-Fetch-Site":["made-up"]`)
	if len(got) != 1 || got[0].Automatic || got[0].Target != addrY {
		t.Fatalf("a made-up value with a browser's agent: %+v", got)
	}
}

// A recommendation doesn't hold back an automatic block: a scanner that sends one burst with a faked
// browser header, then a plain one a minute later, is blocked at the second. Recommendations are
// limited among themselves, and an automatic request still holds the next automatic one.
func TestRecommendationDoesNotDelayTheAutomaticBlock(t *testing.T) {
	h, fr := respHarness(t, false)
	h.only(t, edgeRule(3))
	burst := func(at time.Duration, site string) {
		for i := range 3 {
			h.feed(edgeHit(at+time.Duration(i)*time.Second, addrX, site))
		}
		h.e.flush(false)
	}
	burst(0, "cross-site")
	burst(time.Minute, "")
	got := fr.all()
	if len(got) != 2 || got[0].Automatic || !got[1].Automatic {
		t.Fatalf("faked-header burst, then a scripted one a minute later: %+v; want a recommendation, then the automatic block", got)
	}
	burst(2*time.Minute, "cross-site") // another recommendation within 5 minutes of the first: held
	burst(3*time.Minute, "")           // another automatic request within 5 minutes of the last: held
	if got := fr.all(); len(got) != 2 {
		t.Fatalf("requests of each kind within the interval: %d, want still 2", len(got))
	}
	burst(6*time.Minute+30*time.Second, "cross-site")
	if got := fr.all(); len(got) != 3 || got[2].Automatic {
		t.Fatalf("a recommendation past the interval: %+v", got)
	}
}
