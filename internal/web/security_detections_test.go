package web

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/query"
	"github.com/daboss2003/mooring/internal/siem/store"
)

// detFakeService is a siem.DetectionService in memory. It records what the pages ask and applies
// the filter's keyset cursor and Limit the way the contract says (most recently seen first: Last,
// then ID, both descending).
type detFakeService struct {
	mu         sync.Mutex
	rules      []siem.Rule
	dets       []siem.Detection // any order: Detections sorts them
	rulesErr   error
	saveErr    error
	rulesCalls int
	filters    []siem.DetectionFilter
	saved      []siem.Rule
	deleted    []string
	reset      []string
	gets       []int64
}

func (f *detFakeService) Rules(context.Context) ([]siem.Rule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rulesCalls++
	if f.rulesErr != nil {
		return nil, f.rulesErr
	}
	return slices.Clone(f.rules), nil
}

func (f *detFakeService) SaveRule(_ context.Context, r siem.Rule) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.saved = append(f.saved, r)
	if f.saveErr != nil {
		return f.saveErr
	}
	for i := range f.rules {
		if f.rules[i].ID == r.ID {
			f.rules[i] = r
			return nil
		}
	}
	f.rules = append(f.rules, r)
	return nil
}

func (f *detFakeService) DeleteRule(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !strings.HasPrefix(id, "custom.") {
		return errors.New("only custom rules can be deleted")
	}
	f.deleted = append(f.deleted, id)
	f.rules = slices.DeleteFunc(f.rules, func(r siem.Rule) bool { return r.ID == id })
	return nil
}

func (f *detFakeService) ResetRule(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.HasPrefix(id, "custom.") {
		return errors.New("only built-in rules can be reset")
	}
	f.reset = append(f.reset, id)
	return nil
}

func (f *detFakeService) Detections(_ context.Context, fl siem.DetectionFilter) ([]siem.Detection, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.filters = append(f.filters, fl)
	all := slices.Clone(f.dets)
	slices.SortStableFunc(all, func(a, b siem.Detection) int {
		if c := b.Last.Compare(a.Last); c != 0 {
			return c
		}
		return cmp.Compare(b.ID, a.ID)
	})
	var out []siem.Detection
	for _, d := range all {
		if !fl.BeforeLast.IsZero() && !d.Last.Before(fl.BeforeLast) && !(d.Last.Equal(fl.BeforeLast) && d.ID < fl.Before) {
			continue
		}
		out = append(out, d)
		if fl.Limit > 0 && len(out) == fl.Limit {
			break
		}
	}
	return out, nil
}

func (f *detFakeService) Detection(_ context.Context, id int64) (siem.Detection, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets = append(f.gets, id)
	for _, d := range f.dets {
		if d.ID == id {
			return d, true, nil
		}
	}
	return siem.Detection{}, false, nil
}

// calls is every request that reached the service.
func (f *detFakeService) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rulesCalls + len(f.filters) + len(f.saved) + len(f.deleted) + len(f.reset) + len(f.gets)
}

func (f *detFakeService) lastSaved(t *testing.T) siem.Rule {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.saved) == 0 {
		t.Fatal("SaveRule was not called")
	}
	return f.saved[len(f.saved)-1]
}

func (f *detFakeService) savedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.saved)
}

func (f *detFakeService) lastFilter(t *testing.T) siem.DetectionFilter {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.filters) == 0 {
		t.Fatal("Detections was not called")
	}
	return f.filters[len(f.filters)-1]
}

func (f *detFakeService) filterCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.filters)
}

type detFakeFeeds []siem.FeedStatus

func (f detFakeFeeds) FeedStatus() []siem.FeedStatus { return f }

func detRules() []siem.Rule {
	return []siem.Rule{
		{ID: "ssh.bruteforce", Name: "SSH brute force", Description: "Many failed SSH logins from one IP.",
			Type: siem.RuleThreshold, Severity: siem.SevHigh, MITRE: []string{"T1110.001"},
			Query: "kind:ssh.login out:failure", GroupBy: "ip", Count: 10, Window: 10 * time.Minute, Enabled: true, Builtin: true},
		{ID: "auth.new_country", Name: "Sign-in from a new country", Type: siem.RuleNewValue, Severity: siem.SevMedium,
			MITRE: []string{"T1078"}, Query: "kind:auth.login out:success", GroupBy: "actor", Field: "geo.cc",
			Learn: 7 * 24 * time.Hour, Enabled: true, Builtin: true, SnoozedUntil: time.Now().Add(2 * time.Hour)},
		{ID: "custom.admin-probe", Name: "Admin path probing", Type: siem.RuleThreshold, Severity: siem.SevLow,
			Query: "src:edge f.path:/admin*", GroupBy: "ip", Count: 20, Window: time.Hour},
	}
}

// detEnv is securityEnv with the detection service and feed source set (nil = off).
func detEnv(t *testing.T, f *detFakeService, feeds siem.FeedStatusSource) *testEnv {
	t.Helper()
	e := securityEnv(t, nil)
	if f != nil {
		e.srv.detections = f
	}
	if feeds != nil {
		e.srv.feeds = feeds
	}
	return e
}

// detLogin signs user in and returns the session and CSRF cookies.
func (e *testEnv) detLogin(t *testing.T, user string) (sess, csrf *http.Cookie) {
	t.Helper()
	get := e.req(t, "GET", "/login", secPeer, nil, nil, nil)
	csrf = cookieByName(get, e.srv.csrfCookieName())
	if csrf == nil {
		t.Fatal("no CSRF cookie on GET /login")
	}
	form := url.Values{"username": {user}, "password": {testPassword}, "csrf_token": {csrf.Value}}
	post := e.req(t, "POST", "/login", secPeer, map[string]string{"Origin": "https://example.com"}, []*http.Cookie{csrf}, form)
	if sess = cookieByName(post, e.srv.cookieName()); sess == nil {
		t.Fatalf("login as %s failed", user)
	}
	return sess, csrf
}

// detPost posts form with the CSRF token (unless form already sets csrf_token).
func (e *testEnv) detPost(t *testing.T, path string, sess, csrf *http.Cookie, form url.Values) (*http.Response, string) {
	t.Helper()
	if !form.Has("csrf_token") {
		form.Set("csrf_token", csrf.Value)
	}
	resp := e.req(t, "POST", path, secPeer, map[string]string{"Origin": "https://example.com"}, []*http.Cookie{sess, csrf}, form)
	return resp, readBody(resp)
}

var (
	detGetPaths  = []string{"/security/detections", "/security/detections/rows", "/security/detections/1", "/security/rules", "/security/rules/edit?id=ssh.bruteforce", "/security/rules/new"}
	detPostPaths = []string{"/security/rules/save", "/security/rules/delete", "/security/rules/reset", "/security/rules/snooze"}
)

func detPostForm() url.Values {
	return url.Values{"id": {"custom.admin-probe"}, "for": {"1h"}, "name": {"x"}, "type": {"threshold"}, "severity": {"low"}, "query": {"kind:x"}}
}

func TestDetectionPagesOwnerOnly(t *testing.T) {
	f := &detFakeService{rules: detRules(), dets: []siem.Detection{{ID: 1, RuleID: "ssh.bruteforce", RuleName: "SSH brute force", Severity: siem.SevHigh}}}
	e := detEnv(t, f, detFakeFeeds{{Name: "dbip-city", Enabled: true}})
	for _, user := range []string{"dep", "vie"} {
		sess, csrf := e.detLogin(t, user)
		for _, p := range detGetPaths {
			resp, body := e.get(t, p, sess)
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("%s GET %s = %d, want 403", user, p, resp.StatusCode)
			}
			if strings.Contains(body, "SSH brute force") || strings.Contains(body, "Enrichment feeds") {
				t.Errorf("%s GET %s leaked page content", user, p)
			}
		}
		for _, p := range detPostPaths {
			if resp, _ := e.detPost(t, p, sess, csrf, detPostForm()); resp.StatusCode != http.StatusForbidden {
				t.Errorf("%s POST %s = %d, want 403", user, p, resp.StatusCode)
			}
		}
	}
	if n := f.calls(); n != 0 {
		t.Fatalf("non-owners reached the detection service %d times", n)
	}
	denied := 0
	for _, r := range secAuditRows(t, e, "rbac_deny") {
		if strings.Contains(r.Target, "/security/") {
			denied++
		}
	}
	if want := 2 * (len(detGetPaths) + len(detPostPaths)); denied != want {
		t.Errorf("rbac_deny rows for /security/ routes = %d, want %d", denied, want)
	}
	owner := e.loginAs(t, "operator")
	for _, p := range detGetPaths {
		if resp, _ := e.get(t, p, owner); resp.StatusCode != http.StatusOK {
			t.Errorf("owner GET %s = %d, want 200", p, resp.StatusCode)
		}
	}
}

func TestDetectionPostsRequireCSRF(t *testing.T) {
	f := &detFakeService{rules: detRules()}
	e := detEnv(t, f, nil)
	sess, csrf := e.detLogin(t, "operator")
	for _, p := range detPostPaths {
		for name, token := range map[string]string{"missing": "", "wrong": "not-the-token"} {
			form := detPostForm()
			form.Set("csrf_token", token)
			if token == "" {
				form.Del("csrf_token")
				// detPost adds the real token when the form has none: post by hand.
				resp := e.req(t, "POST", p, secPeer, map[string]string{"Origin": "https://example.com"}, []*http.Cookie{sess, csrf}, form)
				if resp.StatusCode != http.StatusForbidden {
					t.Errorf("POST %s with %s token = %d, want 403", p, name, resp.StatusCode)
				}
				continue
			}
			if resp, _ := e.detPost(t, p, sess, csrf, form); resp.StatusCode != http.StatusForbidden {
				t.Errorf("POST %s with %s token = %d, want 403", p, name, resp.StatusCode)
			}
		}
	}
	if len(f.saved)+len(f.deleted)+len(f.reset) != 0 {
		t.Fatalf("a POST without a valid CSRF token changed rules: saved %d, deleted %v, reset %v", len(f.saved), f.deleted, f.reset)
	}
}

// Detection off (nil service): every page says so, nothing panics, POSTs change nothing.
func TestDetectionPagesOff(t *testing.T) {
	e := detEnv(t, nil, nil)
	sess, csrf := e.detLogin(t, "operator")
	for _, p := range append(detGetPaths, "/security/detections/abc") {
		resp, body := e.get(t, p, sess)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s (off) = %d, want 200", p, resp.StatusCode)
		}
		if !strings.Contains(body, "Detection is off") {
			t.Errorf("GET %s (off) does not say detection is off", p)
		}
	}
	for _, p := range detPostPaths {
		resp, body := e.detPost(t, p, sess, csrf, detPostForm())
		if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body, "Detection is off") {
			t.Errorf("POST %s (off) = %d, want 503 with the off message", p, resp.StatusCode)
		}
	}
	if _, body := e.get(t, "/security/rules", sess); strings.Contains(body, "Enrichment feeds") {
		t.Error("feeds panel shown with no feed source")
	}
	// Feeds still show while detection is off: enrichment runs with the security logs.
	e.srv.feeds = detFakeFeeds{{Name: "tor-exits", Enabled: true, Entries: 1200}}
	if _, body := e.get(t, "/security/rules", sess); !strings.Contains(body, "Enrichment feeds") || !strings.Contains(body, "1,200") {
		t.Error("feeds panel missing on the off page")
	}
}

func detFixtures(now time.Time) []siem.Detection {
	return []siem.Detection{
		{ID: 7, Source: siem.DetectionSIEM, RuleID: "ssh.bruteforce", RuleName: "SSH brute force", Severity: siem.SevHigh,
			MITRE: []string{"T1110.001"}, Key: "203.0.113.9", App: "shop", Service: "api",
			First: now.Add(-20 * time.Minute), Last: now.Add(-3 * time.Minute), Count: 42,
			Summary: "42 failed SSH logins from 203.0.113.9 in 10m",
			Geo:     &siem.Geo{Country: "NG", City: "Lagos", ASN: 64500, Org: "Example Net", Lists: []string{"spamhaus-drop"}},
			Evidence: []siem.Evidence{
				{TS: now.Add(-4 * time.Minute), Kind: "ssh.login", IP: "203.0.113.9", Actor: "root"},
				{TS: now.Add(-3 * time.Minute), Kind: "ssh.login", IP: "2001:db8::1", Actor: "h:0123456789abcdef", App: "my app"},
			}},
		{ID: 6, Source: siem.DetectionOps, RuleID: "ops:shop/api/queue", RuleName: "Queue backlog", Severity: siem.SevCritical,
			App: "shop", Service: "api", First: now.Add(-time.Hour), Last: now.Add(-50 * time.Minute), Count: 1,
			Summary: "queue depth 900 above 500", Snoozed: true},
	}
}

func TestDetectionsList(t *testing.T) {
	now := time.Now().UTC()
	f := &detFakeService{rules: detRules(), dets: detFixtures(now)}
	e := detEnv(t, f, nil)
	sess := e.loginAs(t, "operator")
	resp, body := e.get(t, "/security/detections", sess)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /security/detections = %d", resp.StatusCode)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	for _, want := range []string{
		`href="/security/detections/7"`, `href="/security/detections/6"`, "sec-lvl-error", "sec-lvl-critical",
		"SSH brute force", "Queue backlog", `href="https://attack.mitre.org/techniques/T1110/001/"`,
		"203.0.113.9", "Lagos", "NG", "AS64500", "Example Net", "Spamhaus DROP", "shop/api", "42 failed SSH logins",
		"3m ago", `IP geolocation by <a href="https://db-ip.com"`, "Spamhaus DROP list © The Spamhaus Project",
		`data-poll-url="/security/detections/rows"`, `data-poll-interval="30000"`, "Snoozed",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("list missing %q", want)
		}
	}
	if strings.Index(body, `href="/security/detections/7"`) > strings.Index(body, `href="/security/detections/6"`) {
		t.Error("detections not in the service's order (most recently seen first)")
	}
	fl := f.lastFilter(t)
	if !fl.BeforeLast.IsZero() || fl.Before != 0 || fl.Limit != detectPageSize+1 || fl.MinSeverity != "" || fl.RuleID != "" || fl.App != "" || !fl.From.IsZero() || !fl.To.IsZero() {
		t.Errorf("filter = %+v, want the first page unfiltered with limit %d", fl, detectPageSize+1)
	}
	// The live refresh: the same list without the shell.
	resp, body = e.get(t, "/security/detections/rows", sess)
	if resp.StatusCode != http.StatusOK || strings.Contains(body, `class="sidebar"`) || !strings.Contains(body, `href="/security/detections/7"`) {
		t.Errorf("rows partial = %d, shell %v, has row %v", resp.StatusCode, strings.Contains(body, `class="sidebar"`), strings.Contains(body, `/security/detections/7`))
	}
	if !strings.Contains(body, "IP geolocation by") {
		t.Error("rows partial is missing the DB-IP credit")
	}
}

// The data-licence credits appear only with the data they credit.
func TestDetectionsCreditsFollowTheData(t *testing.T) {
	for _, c := range []struct {
		name          string
		geo           *siem.Geo
		dbip, spamhau bool
		dshield       bool
		also          string
	}{
		{"no geo", nil, false, false, false, ""},
		// The enricher's list tags are "spamhaus-drop", "tor-exit" and "dshield" (enrich.go).
		{"lists only, not Spamhaus", &siem.Geo{Lists: []string{"tor-exit"}}, false, false, false, "Tor exit"},
		{"Spamhaus list only", &siem.Geo{Lists: []string{"spamhaus-drop"}}, false, true, false, ""},
		{"DShield list only", &siem.Geo{Lists: []string{"dshield"}}, false, false, true, "DShield"},
		{"country only", &siem.Geo{Country: "DE"}, true, false, false, ""},
		{"ASN only", &siem.Geo{ASN: 64501}, true, false, false, "AS64501"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := &detFakeService{dets: []siem.Detection{{ID: 3, RuleID: "x.y", RuleName: "Rule", Severity: siem.SevLow, Key: "198.51.100.4", Geo: c.geo}}}
			e := detEnv(t, f, nil)
			sess := e.loginAs(t, "operator")
			for _, p := range []string{"/security/detections", "/security/detections/3"} {
				_, body := e.get(t, p, sess)
				if got := strings.Contains(body, "IP geolocation by"); got != c.dbip {
					t.Errorf("%s: DB-IP credit shown = %v, want %v", p, got, c.dbip)
				}
				if got := strings.Contains(body, "The Spamhaus Project"); got != c.spamhau {
					t.Errorf("%s: Spamhaus credit shown = %v, want %v", p, got, c.spamhau)
				}
				if got := strings.Contains(body, "SANS Internet Storm Center"); got != c.dshield {
					t.Errorf("%s: DShield credit shown = %v, want %v", p, got, c.dshield)
				}
				if c.also != "" && !strings.Contains(body, c.also) {
					t.Errorf("%s: missing %q", p, c.also)
				}
			}
		})
	}
}

var detRowLink = regexp.MustCompile(`href="/security/detections/([0-9]+)"`)

func detRowIDs(body string) []string {
	var ids []string
	for _, m := range detRowLink.FindAllStringSubmatch(body, -1) {
		if !slices.Contains(ids, m[1]) {
			ids = append(ids, m[1])
		}
	}
	return ids
}

// detPagingFixture is 120 detections whose IDs do not follow their last-seen order, in groups of 7
// that share one last-seen time (with nanoseconds), so that both page boundaries (rows 50 and 100)
// fall inside a group. want is their IDs most recently seen first.
func detPagingFixture(now time.Time) (dets []siem.Detection, want []string) {
	base := now.Truncate(time.Second).Add(123456789)
	for p := 0; p < 120; p++ {
		g, j := p/7, p%7
		id := int64((g*5)%18)*10 + int64(7-j) // ID desc within a group; groups out of ID order
		last := base.Add(-time.Duration(g) * 1500 * time.Millisecond)
		dets = append(dets, siem.Detection{ID: id, RuleID: "ssh.bruteforce", RuleName: "SSH brute force", Severity: siem.SevMedium, First: last, Last: last, Count: 1})
		want = append(want, strconv.FormatInt(id, 10))
	}
	// The service orders them, not the page: hand them over shuffled.
	rand.New(rand.NewPCG(1, 2)).Shuffle(len(dets), func(a, b int) { dets[a], dets[b] = dets[b], dets[a] })
	return dets, want
}

var detOlderLink = regexp.MustCompile(`href="([^"]*)">Older detections</a>`)

// Paging follows the service's order with both cursor values: every detection exactly once, ties
// on the last-seen time split across pages included.
func TestDetectionsPaging(t *testing.T) {
	now := time.Now().UTC()
	f := &detFakeService{}
	var want []string
	f.dets, want = detPagingFixture(now)
	e := detEnv(t, f, nil)
	sess := e.loginAs(t, "operator")
	link := "/security/detections?severity=medium&app=shop"
	var got []string
	for page := 1; ; page++ {
		if page > 5 {
			t.Fatal("paging does not end")
		}
		resp, body := e.get(t, link, sess)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("page %d (%s) = %d", page, link, resp.StatusCode)
		}
		ids := detRowIDs(body)
		got = append(got, ids...)
		fl := f.lastFilter(t)
		if fl.MinSeverity != siem.SevMedium || fl.App != "shop" {
			t.Errorf("page %d filter = %+v: the filters were dropped", page, fl)
		}
		if page == 1 {
			if !fl.BeforeLast.IsZero() || fl.Before != 0 || !strings.Contains(body, "data-poll-url") || strings.Contains(body, "Newest detections") {
				t.Errorf("first page: cursor %v/%d, live refresh %v, newest link %v", fl.BeforeLast, fl.Before, strings.Contains(body, "data-poll-url"), strings.Contains(body, "Newest detections"))
			}
		} else {
			if strings.Contains(body, "data-poll-url") {
				t.Errorf("page %d: an older page must not live-refresh", page)
			}
			if !strings.Contains(body, "Newest detections") {
				t.Errorf("page %d: an older page needs a link back to the newest", page)
			}
		}
		m := detOlderLink.FindStringSubmatch(body)
		if m == nil {
			if len(ids) != 20 {
				t.Errorf("last page has %d rows, want 20", len(ids))
			}
			break
		}
		if len(ids) != detectPageSize {
			t.Fatalf("page %d has %d rows and an Older link, want %d", page, len(ids), detectPageSize)
		}
		link = html.UnescapeString(m[1])
		u, err := url.Parse(link)
		if err != nil || u.Path != "/security/detections" {
			t.Fatalf("Older link %q", link)
		}
		// The cursor is the last row shown: its last-seen time, losslessly, and its ID.
		var last siem.Detection
		for _, d := range f.dets {
			if strconv.FormatInt(d.ID, 10) == ids[len(ids)-1] {
				last = d
			}
		}
		q := u.Query()
		if bl, err := time.Parse(time.RFC3339Nano, q.Get("before_last")); err != nil || !bl.Equal(last.Last) || q.Get("before") != ids[len(ids)-1] {
			t.Errorf("Older link %q: cursor before_last=%q before=%q, want %s and %d", link, q.Get("before_last"), q.Get("before"), last.Last.Format(time.RFC3339Nano), last.ID)
		}
		if q.Get("severity") != "medium" || q.Get("app") != "shop" {
			t.Errorf("Older link %q dropped the filters", link)
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("pages listed %d detections:\n got %v\nwant %v", len(got), got, want)
	}
}

// A cursor is both values, valid, or the newest page: no 500, no half cursor. The live refresh
// always reads the newest page.
func TestDetectionsCursorParsing(t *testing.T) {
	now := time.Now().UTC()
	f := &detFakeService{}
	f.dets, _ = detPagingFixture(now)
	e := detEnv(t, f, nil)
	sess := e.loginAs(t, "operator")
	at := now.Truncate(time.Second).Add(123456789)
	atQ := url.QueryEscape(at.Format(time.RFC3339Nano))
	for _, p := range []string{
		"/security/detections?before=21",                    // ID alone (no time)
		"/security/detections?before_last=" + atQ,           // time alone
		"/security/detections?before_last=garbage&before=5", // bad time
		"/security/detections?before_last=" + atQ + "&before=abc",
		"/security/detections?before_last=" + atQ + "&before=-5",
		"/security/detections?before_last=" + atQ + "&before=0",
		"/security/detections?before_last=0001-01-01T00:00:00Z&before=5", // the zero time
		"/security/detections?before_last=2026-11-24T10:00&before=5",     // not RFC 3339
		"/security/detections/rows?before_last=" + atQ + "&before=5",     // the live refresh
	} {
		resp, body := e.get(t, p, sess)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s = %d, want 200", p, resp.StatusCode)
		}
		if fl := f.lastFilter(t); !fl.BeforeLast.IsZero() || fl.Before != 0 {
			t.Errorf("%s: cursor %v/%d, want the newest page", p, fl.BeforeLast, fl.Before)
		}
		if ids := detRowIDs(body); len(ids) != detectPageSize {
			t.Errorf("%s: %d rows, want the newest %d", p, len(ids), detectPageSize)
		}
	}
	// A good cursor in another zone is the same instant.
	e.get(t, "/security/detections?before_last="+url.QueryEscape(at.In(time.FixedZone("WAT", 3600)).Format(time.RFC3339Nano))+"&before=5", sess)
	if fl := f.lastFilter(t); !fl.BeforeLast.Equal(at) || fl.Before != 5 {
		t.Errorf("cursor = %v/%d, want %v/5", fl.BeforeLast, fl.Before, at)
	}
}

func TestDetectionsFilterParsing(t *testing.T) {
	f := &detFakeService{rules: detRules()}
	e := detEnv(t, f, nil)
	sess := e.loginAs(t, "operator")

	e.get(t, "/security/detections?severity=bogus&rule=ssh.bruteforce&app=shop", sess)
	if fl := f.lastFilter(t); fl.MinSeverity != "" || fl.RuleID != "ssh.bruteforce" || fl.App != "shop" {
		t.Errorf("filter = %+v: an unknown severity is ignored, rule and app kept", fl)
	}
	_, body := e.get(t, "/security/detections?severity=high", sess)
	if fl := f.lastFilter(t); fl.MinSeverity != siem.SevHigh {
		t.Errorf("MinSeverity = %q, want high", fl.MinSeverity)
	}
	if !strings.Contains(body, `<option value="high" selected>`) {
		t.Error("the severity select does not keep the choice")
	}
	for _, p := range []string{"/security/detections?before=abc", "/security/detections?before=-5"} {
		e.get(t, p, sess)
		if fl := f.lastFilter(t); fl.Before != 0 {
			t.Errorf("%s: Before = %d, want 0", p, fl.Before)
		}
	}
	e.get(t, "/security/detections?from=2026-11-24T09:00:00&to=2026-11-24T10:30", sess)
	fl := f.lastFilter(t)
	if !fl.From.Equal(time.Date(2026, 11, 24, 9, 0, 0, 0, time.UTC)) || !fl.To.Equal(time.Date(2026, 11, 24, 10, 30, 0, 0, time.UTC)) {
		t.Errorf("From/To = %v / %v", fl.From, fl.To)
	}
	// A rule filter not in the list (an app /ops alert) stays selectable.
	_, body = e.get(t, "/security/detections?rule="+url.QueryEscape("ops:shop/api/queue"), sess)
	if !strings.Contains(body, `<option value="ops:shop/api/queue" selected>`) {
		t.Error("an unknown rule filter is not kept in the select")
	}

	n := f.filterCount()
	for p, want := range map[string]string{
		"/security/detections?from=garbage":                                   "From is not a valid date and time.",
		"/security/detections?to=2026-13-01T00:00":                            "To is not a valid date and time.",
		"/security/detections?from=2026-11-24T10:00&to=2026-11-24T09:00":      "From must be before To.",
		"/security/detections/rows?from=2026-11-24T10:00&to=2026-11-24T10:00": "From must be before To.",
	} {
		resp, body := e.get(t, p, sess)
		if resp.StatusCode != http.StatusOK || !strings.Contains(body, want) {
			t.Errorf("%s = %d, want the message %q", p, resp.StatusCode, want)
		}
	}
	if f.filterCount() != n {
		t.Error("a rejected filter still queried the service")
	}
}

func TestDetectionsEmptyState(t *testing.T) {
	e := detEnv(t, &detFakeService{}, nil)
	sess := e.loginAs(t, "operator")
	_, body := e.get(t, "/security/detections", sess)
	if !strings.Contains(body, "No detections") || !strings.Contains(body, "Review the detection rules") {
		t.Error("empty state missing its message or the link to the rules")
	}
	if strings.Contains(body, "IP geolocation by") {
		t.Error("credit shown with nothing listed")
	}
	_, body = e.get(t, "/security/detections?app=shop", sess)
	if !strings.Contains(body, "No detections match these filters.") {
		t.Error("filtered empty state missing")
	}
}

// securityLinkQuery reads a /security search link: its parsed search and window.
func securityLinkQuery(t *testing.T, href string) (query.Query, time.Time, time.Time) {
	t.Helper()
	u, err := url.Parse(html.UnescapeString(href))
	if err != nil || u.Path != "/security" {
		t.Fatalf("bad search link %q", href)
	}
	p := u.Query()
	q, err := query.Parse(p.Get("q"))
	if err != nil {
		t.Fatalf("search link %q: %v", href, err)
	}
	from, err1 := time.Parse(time.RFC3339Nano, p.Get("from"))
	to, err2 := time.Parse(time.RFC3339Nano, p.Get("to"))
	if err1 != nil || err2 != nil {
		t.Fatalf("search link %q: from/to not RFC 3339", href)
	}
	return q, from, to
}

func hasTerm(q query.Query, field, value string) bool {
	for _, tm := range q.Terms {
		if tm.Field == field && tm.Op == query.OpEq && tm.Value == value && !tm.Neg {
			return true
		}
	}
	return false
}

var detFormError = regexp.MustCompile(`<div class="error" role="alert">([^<]*)</div>`)

var detSearchLink = regexp.MustCompile(`href="(/security\?[^"]+)"`)

func TestDetectionDetail(t *testing.T) {
	realQueryParser(t)
	now := time.Now().UTC().Truncate(time.Second)
	dets := detFixtures(now)
	dets[0].Snoozed = true
	f := &detFakeService{rules: detRules(), dets: dets}
	e := detEnv(t, f, nil)
	sess := e.loginAs(t, "operator")
	resp, body := e.get(t, "/security/detections/7", sess)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET detail = %d", resp.StatusCode)
	}
	for _, want := range []string{
		"SSH brute force", "ssh.bruteforce", `href="https://attack.mitre.org/techniques/T1110/001/"`, "Lagos", "AS64500",
		"Snoozed", "42 failed SSH logins", "203.0.113.9", "2001:db8::1", "h:0123456789abcdef",
		`href="/security/rules/edit?id=ssh.bruteforce"`, `IP geolocation by <a href="https://db-ip.com"`,
		"Spamhaus DROP list © The Spamhaus Project", `href="/security/detections?rule=ssh.bruteforce"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("detail missing %q", want)
		}
	}
	links := detSearchLink.FindAllStringSubmatch(body, -1)
	if len(links) != 3 {
		t.Fatalf("search links = %d, want one for related events and one per evidence row (2)", len(links))
	}
	// Evidence rows: kind, ip, actor (and app) within ±1 minute of the event.
	for i, ev := range dets[0].Evidence {
		q, from, to := securityLinkQuery(t, links[i+1][1])
		if !hasTerm(q, "kind", ev.Kind) || !hasTerm(q, "ip", ev.IP) || !hasTerm(q, "actor", ev.Actor) {
			t.Errorf("evidence %d link terms = %+v", i, q.Terms)
		}
		if ev.App != "" && !hasTerm(q, "app", ev.App) {
			t.Errorf("evidence %d link has no app term: %+v", i, q.Terms)
		}
		if !from.Equal(ev.TS.Add(-time.Minute)) || !to.Equal(ev.TS.Add(time.Minute)) {
			t.Errorf("evidence %d window = %v..%v, want the event ±1m", i, from, to)
		}
	}
	// Related events (first, in the summary): the rule's group-by key over the detection's span.
	q, from, to := securityLinkQuery(t, links[0][1])
	if len(q.Terms) != 1 || !hasTerm(q, "ip", "203.0.113.9") {
		t.Errorf("related link terms = %+v, want ip:203.0.113.9", q.Terms)
	}
	if !from.Equal(dets[0].First.Add(-time.Minute)) || !to.Equal(dets[0].Last.Add(time.Minute)) {
		t.Errorf("related window = %v..%v", from, to)
	}

	// An ops detection: no rule to link, no evidence, no geo credit.
	_, body = e.get(t, "/security/detections/6", sess)
	if !strings.Contains(body, "Queue backlog") || strings.Contains(body, "/security/rules/edit") || strings.Contains(body, "IP geolocation by") {
		t.Error("ops detection detail wrong")
	}
	for _, p := range []string{"/security/detections/999", "/security/detections/abc", "/security/detections/0", "/security/detections/-1"} {
		resp, body := e.get(t, p, sess)
		if resp.StatusCode != http.StatusNotFound || !strings.Contains(body, "Detection not found") {
			t.Errorf("GET %s = %d, want 404 with a not-found page", p, resp.StatusCode)
		}
	}
}

func TestSecurityRulesPage(t *testing.T) {
	now := time.Now().UTC()
	f := &detFakeService{rules: detRules()}
	feeds := detFakeFeeds{
		{Name: "dbip-city", Enabled: true, Version: "2026-11", Updated: now.Add(-3 * time.Hour), Entries: 3000000, NextTry: now.Add(20 * 24 * time.Hour)},
		{Name: "spamhaus-drop", Enabled: true, LastError: "fetch: status 503", NextTry: now.Add(time.Hour)},
		{Name: "dshield", Enabled: false},
	}
	e := detEnv(t, f, feeds)
	sess := e.loginAs(t, "operator")
	resp, body := e.get(t, "/security/rules", sess)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /security/rules = %d", resp.StatusCode)
	}
	for _, want := range []string{
		"SSH brute force", "ssh.bruteforce", "Admin path probing", "custom.admin-probe", "Sign-in from a new country",
		"MITRE ATT&amp;CK®", "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.",
		`href="https://attack.mitre.org/techniques/T1078/"`, "at least 10 in 10m per ip", "new geo.cc after 7d of learning per actor",
		"Snoozed until", `href="/security/rules/new"`, `href="/security/rules/edit?id=custom.admin-probe"`,
		"Enrichment feeds", "DB-IP", "2026-11", "3,000,000", "fetch: status 503", "dshield",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("rules page missing %q", want)
		}
	}
	if got := strings.Count(body, `action="/security/rules/reset"`); got != 2 {
		t.Errorf("Reset forms = %d, want one per built-in rule (2)", got)
	}
	if got := strings.Count(body, `action="/security/rules/delete"`); got != 1 {
		t.Errorf("Delete forms = %d, want one per custom rule (1)", got)
	}
	if got := strings.Count(body, `action="/security/rules/snooze"`); got != 3 {
		t.Errorf("Snooze forms = %d, want 3", got)
	}
	if !strings.Contains(body, `name="for" value="clear"`) {
		t.Error("the snoozed rule has no Clear snooze action")
	}
	if got := strings.Count(body, `name="for" value="clear"`); got != 1 {
		t.Errorf("Clear snooze actions = %d, want 1 (only the snoozed rule)", got)
	}

	f.mu.Lock()
	f.rulesErr = errors.New("disk I/O error")
	f.mu.Unlock()
	if _, body := e.get(t, "/security/rules", sess); !strings.Contains(body, "The rules could not be read.") || strings.Contains(body, "disk I/O") ||
		strings.Contains(body, "No built-in rules") || strings.Contains(body, "No custom rules yet") {
		t.Error("a rules read error is not shown as a plain message (and only that)")
	}
}

// The feeds panel credits each data source whose feed is on, DShield included, and no other.
func TestSecurityRulesFeedCredits(t *testing.T) {
	for _, c := range []struct {
		name                    string
		feeds                   detFakeFeeds
		dbip, spamhaus, dshield bool
	}{
		{"all on", detFakeFeeds{{Name: "dbip-city", Enabled: true}, {Name: "dbip-asn", Enabled: true}, {Name: "spamhaus-drop", Enabled: true}, {Name: "tor-exits", Enabled: true}, {Name: "dshield", Enabled: true}}, true, true, true},
		{"all off", detFakeFeeds{{Name: "dbip-city"}, {Name: "dbip-asn"}, {Name: "spamhaus-drop"}, {Name: "tor-exits"}, {Name: "dshield"}}, false, false, false},
		{"DShield only", detFakeFeeds{{Name: "dbip-city"}, {Name: "spamhaus-drop"}, {Name: "dshield", Enabled: true}}, false, false, true},
		{"DB-IP ASN only", detFakeFeeds{{Name: "dbip-asn", Enabled: true}, {Name: "spamhaus-drop"}, {Name: "dshield"}}, true, false, false},
		{"Spamhaus only, failing", detFakeFeeds{{Name: "dbip-city"}, {Name: "spamhaus-drop", Enabled: true, LastError: "fetch: status 503"}}, false, true, false},
		{"Tor only", detFakeFeeds{{Name: "tor-exits", Enabled: true, Entries: 1200}}, false, false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := detEnv(t, &detFakeService{rules: detRules()}, c.feeds)
			_, body := e.get(t, "/security/rules", e.loginAs(t, "operator"))
			if !strings.Contains(body, "Enrichment feeds") {
				t.Fatal("no feeds panel")
			}
			if got := strings.Contains(body, `IP geolocation by <a href="https://db-ip.com"`); got != c.dbip {
				t.Errorf("DB-IP credit = %v, want %v", got, c.dbip)
			}
			if got := strings.Contains(body, "Spamhaus DROP list © The Spamhaus Project"); got != c.spamhaus {
				t.Errorf("Spamhaus credit = %v, want %v", got, c.spamhaus)
			}
			if got := strings.Contains(body, `DShield block list by the <a href="https://isc.sans.edu"`) && strings.Contains(body, "SANS Internet Storm Center</a> (CC BY-NC-SA)"); got != c.dshield {
				t.Errorf("DShield credit = %v, want %v", got, c.dshield)
			}
		})
	}
}

// A snooze that has ended is no snooze: the rules list, the edit form and the notice all say so.
func TestSecurityRulesPastSnoozeIsNotSnoozed(t *testing.T) {
	rules := detRules()
	past := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	rules[1].SnoozedUntil = past // built-in auth.new_country
	rules[2].SnoozedUntil = past // custom.admin-probe
	e := detEnv(t, &detFakeService{rules: rules}, nil)
	sess := e.loginAs(t, "operator")
	_, body := e.get(t, "/security/rules", sess)
	if strings.Contains(body, "Snoozed until") || strings.Contains(body, `name="for" value="clear"`) || strings.Contains(body, past.Format("Jan 02 15:04")) {
		t.Error("the rules list shows an ended snooze")
	}
	if got := strings.Count(body, `action="/security/rules/snooze"`); got != 3 {
		t.Errorf("Snooze forms = %d, want 3 (every rule can be snoozed again)", got)
	}
	for _, id := range []string{"auth.new_country", "custom.admin-probe"} {
		_, body := e.get(t, "/security/rules/edit?id="+id, sess)
		if strings.Contains(body, "Snoozed until") || strings.Contains(body, past.Format("2006-01-02 15:04")) {
			t.Errorf("%s: the edit form shows an ended snooze", id)
		}
	}
	_, body = e.get(t, "/security/rules?done=snoozed&rule=auth.new_country", sess)
	if strings.Contains(body, " until "+past.Format("2006-01-02 15:04")) {
		t.Error("the snoozed notice names an ended snooze")
	}
	// A rejected save of the custom rule re-renders it from the post.
	psess, csrf := e.detLogin(t, "operator")
	resp, body := e.detPost(t, "/security/rules/save", psess, csrf, url.Values{"id": {"custom.admin-probe"}, "name": {"Admin path probing"},
		"type": {"threshold"}, "severity": {"low"}, "query": {"src:edge"}, "count": {"abc"}, "window": {"1h"}})
	if resp.StatusCode != http.StatusUnprocessableEntity || strings.Contains(body, "Snoozed until") {
		t.Errorf("rejected save = %d, ended snooze shown %v", resp.StatusCode, strings.Contains(body, "Snoozed until"))
	}
	// The same rule snoozed into the future shows it everywhere.
	future := time.Now().UTC().Add(3 * time.Hour).Truncate(time.Second)
	rules[1].SnoozedUntil = future
	e.srv.detections = &detFakeService{rules: rules}
	if _, body = e.get(t, "/security/rules", sess); !strings.Contains(body, "Snoozed until") || strings.Count(body, `name="for" value="clear"`) != 1 {
		t.Error("a current snooze is not shown")
	}
	if _, body = e.get(t, "/security/rules/edit?id=auth.new_country", sess); !strings.Contains(body, "Snoozed until") {
		t.Error("the edit form does not show a current snooze")
	}
	if _, body = e.get(t, "/security/rules?done=snoozed&rule=auth.new_country", sess); !strings.Contains(body, " until "+future.Format("2006-01-02 15:04")) {
		t.Error("the snoozed notice does not name a current snooze")
	}
}

func TestSecurityRulesNotices(t *testing.T) {
	e := detEnv(t, &detFakeService{rules: detRules()}, nil)
	sess := e.loginAs(t, "operator")
	for p, want := range map[string]string{
		"/security/rules?done=saved&rule=ssh.bruteforce":   "Saved SSH brute force.",
		"/security/rules?done=reset&rule=ssh.bruteforce":   "Reset SSH brute force to its built-in values.",
		"/security/rules?done=deleted":                     "Deleted the custom rule.",
		"/security/rules?done=snoozed&rule=ssh.bruteforce": "SSH brute force is snoozed",
		"/security/rules?err=delete":                       "The rule could not be deleted.",
	} {
		if _, body := e.get(t, p, sess); !strings.Contains(body, want) {
			t.Errorf("%s: missing %q", p, want)
		}
	}
	// Notices are fixed texts: nothing from the query string is shown.
	_, body := e.get(t, "/security/rules?err=%3Cb%3Eevil%3C%2Fb%3E&done=saved&rule=%3Cb%3Ex", e.loginAs(t, "operator"))
	if strings.Contains(body, "evil") || strings.Contains(body, "&lt;b&gt;") {
		t.Error("the rules page reflects query-string text")
	}
}

func TestSecurityRuleEditBuiltinTunablesOnly(t *testing.T) {
	f := &detFakeService{rules: detRules()}
	e := detEnv(t, f, nil)
	sess, csrf := e.detLogin(t, "operator")
	resp, body := e.get(t, "/security/rules/edit?id=ssh.bruteforce", sess)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET edit = %d", resp.StatusCode)
	}
	for _, want := range []string{`name="count" value="10"`, `name="window" value="10m"`, `name="severity"`, `name="enabled" checked`, `name="id" value="ssh.bruteforce"`, "kind:ssh.login out:failure"} {
		if !strings.Contains(body, want) {
			t.Errorf("built-in form missing %q", want)
		}
	}
	for _, field := range []string{"query", "then", "group_by", "field", "name", "description", "type", "mitre", "slug", "factor", "learn", "speed_kmh"} {
		if strings.Contains(body, `name="`+field+`"`) {
			t.Errorf("built-in form has an input for %q", field)
		}
	}
	_, body = e.get(t, "/security/rules/edit?id=auth.new_country", sess)
	if !strings.Contains(body, `name="learn" value="7d"`) || strings.Contains(body, `name="count"`) {
		t.Error("new_value form: want learn, not count")
	}

	// A crafted POST can't change what isn't tunable, nor a tunable the type doesn't use.
	resp, _ = e.detPost(t, "/security/rules/save", sess, csrf, url.Values{
		"id": {"ssh.bruteforce"}, "severity": {"critical"}, "count": {"25"}, "window": {"2h"}, "enabled": {"on"},
		"query": {"kind:evil"}, "name": {"pwned"}, "group_by": {"app"}, "type": {"sequence"}, "factor": {"9"}, "mitre": {"T0000"},
	})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/security/rules?done=saved&rule=ssh.bruteforce" {
		t.Fatalf("save = %d → %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	got := f.lastSaved(t)
	want := detRules()[0]
	want.Severity, want.Count, want.Window = siem.SevCritical, 25, 2*time.Hour
	if got.ID != want.ID || got.Query != want.Query || got.Name != want.Name || got.GroupBy != want.GroupBy || got.Type != want.Type ||
		got.Factor != 0 || !slices.Equal(got.MITRE, want.MITRE) || got.Severity != want.Severity || got.Count != 25 || got.Window != 2*time.Hour || !got.Enabled || !got.Builtin {
		t.Errorf("saved %+v\nwant %+v", got, want)
	}
	// Unchecked = disabled.
	e.detPost(t, "/security/rules/save", sess, csrf, url.Values{"id": {"ssh.bruteforce"}, "severity": {"high"}, "count": {"10"}, "window": {"10m"}})
	if f.lastSaved(t).Enabled {
		t.Error("an unchecked Enabled box saved the rule enabled")
	}
	// A rejected built-in save comes back as the built-in form: still no inputs for fixed fields.
	f.mu.Lock()
	f.saveErr = fmt.Errorf("%w: count: at least 1", siem.ErrInvalidRule)
	f.mu.Unlock()
	resp, body = e.detPost(t, "/security/rules/save", sess, csrf, url.Values{
		"id": {"ssh.bruteforce"}, "severity": {"high"}, "count": {"0"}, "window": {"10m"}, "query": {"kind:evil"}, "name": {"pwned"},
	})
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "count: at least 1") || !strings.Contains(body, `name="count" value="0"`) {
		t.Errorf("rejected built-in save = %d, want 422 with the message and the input", resp.StatusCode)
	}
	for _, field := range []string{"query", "name", "type", "slug"} {
		if strings.Contains(body, `name="`+field+`"`) {
			t.Errorf("rejected built-in save re-rendered an input for %q", field)
		}
	}
	if strings.Contains(body, "kind:evil") || strings.Contains(body, "pwned") || !strings.Contains(body, "kind:ssh.login out:failure") {
		t.Error("rejected built-in save shows the posted fixed fields instead of the rule's")
	}
	f.mu.Lock()
	f.saveErr = nil
	f.mu.Unlock()
	rows := secAuditRows(t, e, "security_rule_save")
	if len(rows) != 3 || rows[0].Target != "ssh.bruteforce" || rows[0].Outcome != "ok" || rows[0].Level != "security" || rows[0].Actor != "operator" {
		t.Fatalf("audit rows = %+v", rows)
	}
	if strings.Contains(rows[0].Detail, "kind:") {
		t.Errorf("audit detail carries the query: %q", rows[0].Detail)
	}
}

func TestSecurityRuleSaveCustom(t *testing.T) {
	f := &detFakeService{rules: detRules()}
	e := detEnv(t, f, nil)
	sess, csrf := e.detLogin(t, "operator")
	_, body := e.get(t, "/security/rules/new", sess)
	for _, want := range []string{`name="slug"`, `name="name"`, `name="query"`, `name="then"`, `name="group_by"`, `name="field"`, `name="mitre"`, `name="speed_kmh"`, "data-kind-toggle", `name="enabled" checked`} {
		if !strings.Contains(body, want) {
			t.Errorf("new-rule form missing %q", want)
		}
	}
	resp, _ := e.detPost(t, "/security/rules/save", sess, csrf, url.Values{
		"slug": {"token-spray"}, "name": {"Token spray"}, "description": {"Many tokens from one IP."}, "type": {"distinct"},
		"severity": {"high"}, "mitre": {"t1110.003, T1078"}, "query": {"kind:api_token_use out:failure"}, "group_by": {"ip"},
		"field": {"actor"}, "count": {"5"}, "window": {"7d"}, "factor": {"3"}, "then": {"kind:x"}, "enabled": {"on"},
	})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/security/rules?done=saved&rule=custom.token-spray" {
		t.Fatalf("save = %d → %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	got := f.lastSaved(t)
	if got.ID != "custom.token-spray" || got.Name != "Token spray" || got.Description != "Many tokens from one IP." || got.Type != siem.RuleDistinct ||
		got.Severity != siem.SevHigh || !slices.Equal(got.MITRE, []string{"T1110.003", "T1078"}) || got.Query != "kind:api_token_use out:failure" ||
		got.GroupBy != "ip" || got.Field != "actor" || got.Count != 5 || got.Window != 7*24*time.Hour || got.Factor != 0 || got.Then != "" ||
		!got.Enabled || got.Builtin {
		t.Errorf("saved %+v", got)
	}
	rows := secAuditRows(t, e, "security_rule_save")
	if len(rows) != 1 || rows[0].Target != "custom.token-spray" || rows[0].Outcome != "ok" || strings.Contains(rows[0].Detail, "api_token_use") {
		t.Errorf("audit rows = %+v", rows)
	}

	// A new rule may not take an existing rule's ID.
	n := f.savedCount()
	resp, body = e.detPost(t, "/security/rules/save", sess, csrf, url.Values{"slug": {"admin-probe"}, "name": {"Dup"}, "type": {"threshold"}, "severity": {"low"}, "query": {"kind:x"}})
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "already exists") || f.savedCount() != n {
		t.Errorf("duplicate ID: %d, saved %d more", resp.StatusCode, f.savedCount()-n)
	}

	// Editing a custom rule keeps its ID and snooze; the slug field can't rename it.
	until := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	f.mu.Lock()
	f.rules[2].SnoozedUntil = until
	f.mu.Unlock()
	resp, _ = e.detPost(t, "/security/rules/save", sess, csrf, url.Values{
		"id": {"custom.admin-probe"}, "slug": {"renamed"}, "name": {"Admin probing"}, "type": {"sequence"}, "severity": {"medium"},
		"query": {"src:edge f.path:/admin*"}, "then": {"src:edge f.status:200"}, "count": {"3"}, "window": {"90m"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("edit custom = %d", resp.StatusCode)
	}
	got = f.lastSaved(t)
	if got.ID != "custom.admin-probe" || got.Name != "Admin probing" || got.Type != siem.RuleSequence || got.Then != "src:edge f.status:200" ||
		got.Window != 90*time.Minute || got.Count != 3 || got.Enabled || !got.SnoozedUntil.Equal(until) {
		t.Errorf("edited %+v", got)
	}
	_, body = e.get(t, "/security/rules/edit?id=custom.admin-probe", sess)
	if !strings.Contains(body, `value="Admin probing"`) || !strings.Contains(body, `name="then" value="src:edge f.status:200"`) || strings.Contains(body, `name="slug"`) {
		t.Error("custom edit form: want its values and no slug input")
	}
	if resp, body := e.get(t, "/security/rules/edit?id=nope.nope", sess); resp.StatusCode != http.StatusNotFound || !strings.Contains(body, "Rule not found") {
		t.Errorf("edit unknown rule = %d", resp.StatusCode)
	}
}

func TestSecurityRuleSaveErrorsKeepInput(t *testing.T) {
	f := &detFakeService{rules: detRules(), saveErr: fmt.Errorf(`%w: query: "f.<b>": unknown field`, siem.ErrInvalidRule)}
	e := detEnv(t, f, nil)
	sess, csrf := e.detLogin(t, "operator")
	form := func(over map[string]string) url.Values {
		v := url.Values{"slug": {"spray"}, "name": {"Token spray"}, "type": {"threshold"}, "severity": {"high"},
			"query": {"kind:api_token_use f.<b>:1"}, "group_by": {"ip"}, "count": {"5"}, "window": {"10m"}, "enabled": {"on"}}
		for k, x := range over {
			v.Set(k, x)
		}
		return v
	}
	resp, body := e.detPost(t, "/security/rules/save", sess, csrf, form(nil))
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("rejected save = %d, want 422", resp.StatusCode)
	}
	for _, want := range []string{"The rule was not saved: query: &#34;f.&lt;b&gt;&#34;: unknown field", `value="Token spray"`, `value="kind:api_token_use f.&lt;b&gt;:1"`, `name="slug" value="spray"`, `name="window" value="10m"`, `<option value="high" selected>`, `class="sidebar"`} {
		if !strings.Contains(body, want) {
			t.Errorf("re-rendered form missing %q", want)
		}
	}
	rows := secAuditRows(t, e, "security_rule_save")
	if len(rows) != 1 || rows[0].Outcome != "error" || rows[0].Target != "custom.spray" || strings.Contains(rows[0].Detail, "api_token_use") || strings.Contains(rows[0].Detail, "f.<b>") {
		t.Errorf("audit rows = %+v", rows)
	}

	f.saveErr = nil
	n := f.savedCount()
	for field, val := range map[string]string{"window": "1y", "count": "abc", "factor": "-2", "learn": "-1d", "speed_kmh": "fast"} {
		typ := map[string]string{"factor": "anomaly", "learn": "anomaly", "speed_kmh": "travel"}[field]
		if typ == "" {
			typ = "threshold"
		}
		resp, body := e.detPost(t, "/security/rules/save", sess, csrf, form(map[string]string{field: val, "type": typ}))
		label := map[string]string{"window": "Window", "count": "Count", "factor": "Factor", "learn": "Learning period", "speed_kmh": "Speed"}[field]
		msg := detFormError.FindStringSubmatch(body)
		if resp.StatusCode != http.StatusUnprocessableEntity || msg == nil || !strings.HasPrefix(msg[1], label) || !strings.Contains(body, `value="`+val+`"`) {
			t.Errorf("%s=%q: %d, error %q; want 422 naming %s with the input kept", field, val, resp.StatusCode, msg, label)
		}
	}
	if f.savedCount() != n {
		t.Error("a form with a bad number or duration reached SaveRule")
	}

	// Saving a rule that no longer exists.
	resp, _ = e.detPost(t, "/security/rules/save", sess, csrf, url.Values{"id": {"custom.gone"}, "name": {"x"}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/security/rules?err=missing" {
		t.Errorf("save of a missing rule = %d → %q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestSecurityRuleSnooze(t *testing.T) {
	f := &detFakeService{rules: detRules()}
	e := detEnv(t, f, nil)
	sess, csrf := e.detLogin(t, "operator")
	for _, c := range []struct {
		id, length string
		d          time.Duration // 0 = cleared
	}{
		{"ssh.bruteforce", "1h", time.Hour},
		{"ssh.bruteforce", "24h", 24 * time.Hour},
		{"custom.admin-probe", "7d", 7 * 24 * time.Hour},
		{"auth.new_country", "clear", 0},
	} {
		before := time.Now()
		resp, _ := e.detPost(t, "/security/rules/snooze", sess, csrf, url.Values{"id": {c.id}, "for": {c.length}})
		after := time.Now()
		wantLoc := "/security/rules?done=snoozed&rule=" + url.QueryEscape(c.id)
		if c.d == 0 {
			wantLoc = "/security/rules?done=unsnoozed&rule=" + url.QueryEscape(c.id)
		}
		if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != wantLoc {
			t.Errorf("%s for %s = %d → %q", c.id, c.length, resp.StatusCode, resp.Header.Get("Location"))
		}
		got := f.lastSaved(t)
		var orig siem.Rule
		for _, r := range detRules() {
			if r.ID == c.id {
				orig = r
			}
		}
		if got.ID != c.id || got.Query != orig.Query || got.Count != orig.Count || got.Builtin != orig.Builtin || got.Enabled != orig.Enabled {
			t.Errorf("snooze changed more than the snooze: %+v", got)
		}
		switch {
		case c.d == 0 && !got.SnoozedUntil.IsZero():
			t.Errorf("clear: SnoozedUntil = %v, want zero", got.SnoozedUntil)
		case c.d > 0 && (got.SnoozedUntil.Before(before.Add(c.d).Truncate(time.Second)) || got.SnoozedUntil.After(after.Add(c.d))):
			t.Errorf("%s: SnoozedUntil = %v, want now + %v", c.length, got.SnoozedUntil, c.d)
		}
	}
	n := f.savedCount()
	for _, bad := range []string{"", "2h", "forever", "-1h"} {
		resp, _ := e.detPost(t, "/security/rules/snooze", sess, csrf, url.Values{"id": {"ssh.bruteforce"}, "for": {bad}})
		if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/security/rules?err=snoozefor" {
			t.Errorf("for=%q: %d → %q", bad, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	resp, _ := e.detPost(t, "/security/rules/snooze", sess, csrf, url.Values{"id": {"no.such"}, "for": {"1h"}})
	if resp.Header.Get("Location") != "/security/rules?err=missing" {
		t.Errorf("snooze of a missing rule → %q", resp.Header.Get("Location"))
	}
	if f.savedCount() != n {
		t.Error("a bad snooze length or rule saved something")
	}
	rows := secAuditRows(t, e, "security_rule_snooze")
	if len(rows) != 9 {
		t.Fatalf("snooze audit rows = %d, want 9", len(rows))
	}
	for i, want := range []struct{ target, outcome, detail string }{
		{"ssh.bruteforce", "ok", "for=1h"}, {"ssh.bruteforce", "ok", "for=24h"}, {"custom.admin-probe", "ok", "for=7d"},
		{"auth.new_country", "ok", "clear"}, {"ssh.bruteforce", "error", "result=bad length"}, {"no.such", "error", "result=not found"},
	} {
		j := i
		if i == 5 {
			j = 8
		}
		r := rows[j]
		if r.Target != want.target || r.Outcome != want.outcome || !strings.Contains(r.Detail, want.detail) || r.Level != "security" {
			t.Errorf("audit row %d = %+v, want %+v", j, r, want)
		}
	}
}

func TestSecurityRuleDeleteReset(t *testing.T) {
	f := &detFakeService{rules: detRules()}
	e := detEnv(t, f, nil)
	sess, csrf := e.detLogin(t, "operator")
	for _, c := range []struct {
		path, id, loc, action, outcome string
	}{
		{"/security/rules/delete", "custom.admin-probe", "/security/rules?done=deleted", "security_rule_delete", "ok"},
		{"/security/rules/delete", "ssh.bruteforce", "/security/rules?err=delete", "security_rule_delete", "error"},
		{"/security/rules/reset", "ssh.bruteforce", "/security/rules?done=reset&rule=ssh.bruteforce", "security_rule_reset", "ok"},
		{"/security/rules/reset", "custom.other", "/security/rules?err=reset", "security_rule_reset", "error"},
	} {
		resp, _ := e.detPost(t, c.path, sess, csrf, url.Values{"id": {c.id}})
		if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != c.loc {
			t.Errorf("POST %s %s = %d → %q, want %q", c.path, c.id, resp.StatusCode, resp.Header.Get("Location"), c.loc)
		}
		rows := secAuditRows(t, e, c.action)
		if len(rows) == 0 {
			t.Fatalf("no %s audit row", c.action)
		}
		if r := rows[len(rows)-1]; r.Target != c.id || r.Outcome != c.outcome || r.Level != "security" || r.Actor != "operator" {
			t.Errorf("%s audit = %+v", c.action, r)
		}
	}
	if !slices.Equal(f.deleted, []string{"custom.admin-probe"}) || !slices.Equal(f.reset, []string{"ssh.bruteforce"}) {
		t.Errorf("deleted %v, reset %v", f.deleted, f.reset)
	}
	if len(secAuditRows(t, e, "security_rule_delete")) != 2 || len(secAuditRows(t, e, "security_rule_reset")) != 2 {
		t.Error("want one audit row per delete/reset attempt")
	}
}

func TestParseRuleDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"90m": 90 * time.Minute, "2h": 2 * time.Hour, "7d": 7 * 24 * time.Hour, "1d": 24 * time.Hour, "1h30m": 90 * time.Minute,
		"": 0, " 30d ": 30 * 24 * time.Hour, "0": 0, "45s": 45 * time.Second,
	} {
		got, err := parseRuleDuration(in)
		if err != nil || got != want {
			t.Errorf("parseRuleDuration(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"1y", "-5m", "-1d", "d", "1.5d", "7 d", "+3d", "1d12h", "999999999d", "10", "abc", "5m-"} {
		if got, err := parseRuleDuration(in); err == nil {
			t.Errorf("parseRuleDuration(%q) = %v, want an error", in, got)
		}
	}
	for d, want := range map[time.Duration]string{
		0: "", 7 * 24 * time.Hour: "7d", 48 * time.Hour: "2d", 36 * time.Hour: "36h", 90 * time.Minute: "90m",
		time.Hour: "1h", 90 * time.Second: "1m30s",
	} {
		if got := fmtRuleDuration(d); got != want {
			t.Errorf("fmtRuleDuration(%v) = %q, want %q", d, got, want)
		}
		if back, err := parseRuleDuration(fmtRuleDuration(d)); err != nil || back != d {
			t.Errorf("round trip of %v = %v, %v", d, back, err)
		}
	}
}

// Rule names, descriptions, queries, summaries, keys, geo strings and evidence are attacker- or
// operator-chosen text: every page escapes them.
func TestDetectionPagesEscapeHostileText(t *testing.T) {
	now := time.Now().UTC()
	rules := []siem.Rule{{
		ID: "custom.x", Name: `<script>alert("name")</script>`, Description: `<img src=x onerror=alert(1)>`,
		Type: siem.RuleThreshold, Severity: siem.SevHigh, MITRE: []string{`javascript:alert(1)`, `"><svg onload=alert(2)>`},
		Query: `kind:"<script>alert('q')</script>"`, GroupBy: "ip", Count: 1, Window: time.Minute,
	}}
	dets := []siem.Detection{{
		ID: 9, Source: siem.DetectionSIEM, RuleID: "custom.x", RuleName: `<script>alert("rn")</script>`, Severity: `<b>sev</b>`,
		MITRE: []string{`javascript:alert(3)`}, Key: `"><script>alert('k')</script>`, App: `<i>app</i>`, Service: `<u>svc</u>`,
		First: now, Last: now, Count: 1, Summary: `Failed login for <script>alert("user")</script>`,
		Geo:      &siem.Geo{Country: `<s>cc</s>`, City: `<b>town</b>`, Org: `<i>org</i>`, ASN: 1, Lists: []string{"<u>list</u>"}},
		Evidence: []siem.Evidence{{TS: now, Kind: `<svg onload=alert(4)>`, IP: "<ip>", Actor: `"><img src=y>`, App: "<a>"}},
	}}
	f := &detFakeService{rules: rules, dets: dets}
	e := detEnv(t, f, detFakeFeeds{{Name: `<script>alert("feed")</script>`, LastError: `<img src=z onerror=alert(5)>`}})
	sess := e.loginAs(t, "operator")
	for _, p := range []string{"/security/detections", "/security/detections/rows", "/security/detections/9", "/security/rules", "/security/rules/edit?id=custom.x", "/security/detections?rule=" + url.QueryEscape(`<script>alert("f")</script>`)} {
		resp, body := e.get(t, p, sess)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d", p, resp.StatusCode)
		}
		for _, bad := range []string{"<script>alert", "<img src=", "<svg onload", "<b>town", "<i>org", "<u>list", "<s>cc", "<b>sev", "<i>app", "<u>svc", `href="javascript:`, "<ip>", "<a>"} {
			if strings.Contains(body, bad) {
				t.Errorf("GET %s: unescaped %q", p, bad)
			}
		}
		// A MITRE ID that isn't a technique ID is text, never a link.
		if strings.Contains(body, "attack.mitre.org/techniques/javascript") || strings.Contains(body, "attack.mitre.org/techniques/%22") || strings.Contains(body, "ZgotmplZ") {
			t.Errorf("GET %s: a malformed MITRE ID became a link", p)
		}
	}
	// A failed save re-renders the operator's own input escaped.
	sess2, csrf := e.detLogin(t, "operator")
	f.saveErr = fmt.Errorf(`%w: <script>alert("err")</script>`, siem.ErrInvalidRule)
	_, body := e.detPost(t, "/security/rules/save", sess2, csrf, url.Values{"slug": {"y"}, "name": {`<script>alert("in")</script>`}, "type": {"threshold"}, "severity": {"low"}, "query": {`"><img src=q>`}})
	for _, bad := range []string{"<script>alert", `"><img`} {
		if strings.Contains(body, bad) {
			t.Errorf("save error page: unescaped %q", bad)
		}
	}
	if !strings.Contains(body, `&lt;script&gt;alert(&#34;err&#34;)&lt;/script&gt;`) {
		t.Error("save error page: the validation message is not shown (escaped)")
	}
}

// syncBuffer is a log destination the handlers and the test can share.
type syncBuffer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// A validation error (wrapping siem.ErrInvalidRule) is shown; any other SaveRule error is internal:
// a generic message on the page, the error in Mooring's log.
func TestSecurityRuleSaveErrorTexts(t *testing.T) {
	f := &detFakeService{rules: detRules()}
	e := detEnv(t, f, nil)
	logs := &syncBuffer{}
	e.srv.log = slog.New(slog.NewTextHandler(logs, nil))
	sess, csrf := e.detLogin(t, "operator")
	form := url.Values{"slug": {"spray"}, "name": {"Token spray"}, "type": {"threshold"}, "severity": {"high"},
		"query": {"kind:api_token_use"}, "group_by": {"ip"}, "count": {"5"}, "window": {"10m"}, "enabled": {"on"}}
	const generic = "The rule could not be saved; see the server log."

	f.mu.Lock()
	f.saveErr = fmt.Errorf("%w: count: at least 1 for a threshold rule", siem.ErrInvalidRule)
	f.mu.Unlock()
	resp, body := e.detPost(t, "/security/rules/save", sess, csrf, form)
	msg := detFormError.FindStringSubmatch(body)
	if resp.StatusCode != http.StatusUnprocessableEntity || msg == nil || msg[1] != "The rule was not saved: count: at least 1 for a threshold rule" {
		t.Errorf("validation error: %d, message %q; want 422 with the validation message", resp.StatusCode, msg)
	}

	for _, internal := range []error{
		errors.New("sql: database is locked: /var/lib/mooring/security-logs/detect.db"),
		fmt.Errorf("detect: store rule: %w", context.DeadlineExceeded),
		fmt.Errorf("detect: %w", errors.New("SQLITE_CORRUPT on page 7")),
	} {
		f.mu.Lock()
		f.saveErr = internal
		f.mu.Unlock()
		resp, body := e.detPost(t, "/security/rules/save", sess, csrf, form)
		msg := detFormError.FindStringSubmatch(body)
		if resp.StatusCode != http.StatusInternalServerError || msg == nil || msg[1] != generic {
			t.Errorf("%v: %d, message %q; want 500 with %q", internal, resp.StatusCode, msg, generic)
		}
		for _, leak := range []string{"database is locked", "detect.db", "/var/lib", "deadline", "SQLITE", "detect:"} {
			if strings.Contains(body, leak) {
				t.Errorf("%v: the page shows %q", internal, leak)
			}
		}
		if !strings.Contains(body, `value="Token spray"`) || !strings.Contains(body, `name="window" value="10m"`) {
			t.Errorf("%v: the form did not keep its input", internal)
		}
		if !strings.Contains(logs.String(), internal.Error()) {
			t.Errorf("%v: not in Mooring's log:\n%s", internal, logs.String())
		}
	}
	rows := secAuditRows(t, e, "security_rule_save")
	if len(rows) != 4 || rows[0].Detail != "rule=custom new=true result=rejected" || rows[1].Outcome != "error" || rows[1].Detail != "rule=custom new=true result=error" {
		t.Errorf("audit rows = %+v", rows)
	}
	for _, r := range rows {
		if strings.Contains(r.Detail, "database") || strings.Contains(r.Detail, "count:") {
			t.Errorf("audit detail carries the error: %q", r.Detail)
		}
	}
}

// The search results show each event's JSON, geo and lists included: the credits follow.
func TestSecuritySearchCredits(t *testing.T) {
	for _, c := range []struct {
		name          string
		geo           *siem.Geo
		dbip, spamhau bool
	}{
		{"no geo", nil, false, false},
		{"geo", &siem.Geo{Country: "NG", City: "Lagos"}, true, false},
		{"geo and Spamhaus", &siem.Geo{Country: "NG", Lists: []string{"spamhaus-drop"}}, true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeSecurityLogs{status: siem.Status{Enabled: true}, result: store.Result{Events: []siem.Event{
				{V: 1, TS: time.Now().UTC(), Src: siem.SrcHost, Lvl: siem.LvlWarn, Kind: siem.KindSSHLogin, IP: "203.0.113.9", Geo: c.geo},
				{V: 1, TS: time.Now().UTC(), Src: siem.SrcHost, Lvl: siem.LvlInfo, Kind: siem.KindSSHLogin, Msg: `"geo": {"cc": "fake"} spamhaus-drop`},
			}}}
			e := securityEnv(t, f)
			_, body := e.get(t, "/security", e.loginAs(t, "operator"))
			if got := strings.Contains(body, `IP geolocation by <a href="https://db-ip.com"`); got != c.dbip {
				t.Errorf("DB-IP credit = %v, want %v", got, c.dbip)
			}
			if got := strings.Contains(body, "Spamhaus DROP list © The Spamhaus Project"); got != c.spamhau {
				t.Errorf("Spamhaus credit = %v, want %v", got, c.spamhau)
			}
		})
	}
}

// Search, Detections and Rules share the tabs; each page marks its own.
func TestSecurityTabs(t *testing.T) {
	e := detEnv(t, &detFakeService{rules: detRules()}, nil)
	e.srv.securityLogs = &fakeSecurityLogs{}
	sess := e.loginAs(t, "operator")
	for p, active := range map[string]string{
		"/security": "Search", "/security/detections": "Detections", "/security/rules": "Rules",
		"/security/rules/new": "Rules", "/security/detections/1": "Detections",
	} {
		_, body := e.get(t, p, sess)
		for _, href := range []string{`href="/security"`, `href="/security/detections"`, `href="/security/rules"`} {
			if !strings.Contains(body, `<nav class="subnav"`) || !strings.Contains(body, href) {
				t.Errorf("%s: tabs missing %s", p, href)
			}
		}
		if want := fmt.Sprintf(`aria-current="page">%s</a>`, active); !strings.Contains(body, want) {
			t.Errorf("%s: active tab is not %s", p, active)
		}
		if strings.Count(body, `aria-current="page"`) != 1 {
			t.Errorf("%s: want exactly one active tab", p)
		}
	}
}
