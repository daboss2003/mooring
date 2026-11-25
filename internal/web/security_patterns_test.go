package web

import (
	"context"
	"errors"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/query"
)

// patFake is a siem.PatternService in memory: Patterns applies Offset and Limit to pats in their
// order (Sample and Hourly left out, as the contract says); every call is recorded.
type patFake struct {
	mu      sync.Mutex
	pats    []siem.Pattern
	stats   siem.PatternStats
	readErr error
	setErr  error
	filters []siem.PatternFilter
	gets    []string
	sets    []patSet
	statsN  int
}

type patSet struct{ ID, State, Actor string }

func (f *patFake) Patterns(_ context.Context, fl siem.PatternFilter) ([]siem.Pattern, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.filters = append(f.filters, fl)
	if f.readErr != nil {
		return nil, f.readErr
	}
	var out []siem.Pattern
	for i, p := range f.pats {
		if i < fl.Offset {
			continue
		}
		p.Sample, p.Hourly = "", nil
		out = append(out, p)
		if fl.Limit > 0 && len(out) == fl.Limit {
			break
		}
	}
	return out, nil
}

func (f *patFake) Pattern(_ context.Context, id string) (siem.Pattern, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets = append(f.gets, id)
	if f.readErr != nil {
		return siem.Pattern{}, false, f.readErr
	}
	for _, p := range f.pats {
		if p.ID == id {
			return p, true, nil
		}
	}
	return siem.Pattern{}, false, nil
}

func (f *patFake) SetPatternState(_ context.Context, id, state, actor string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sets = append(f.sets, patSet{id, state, actor})
	return f.setErr
}

func (f *patFake) PatternStats() siem.PatternStats {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statsN++
	return f.stats
}

func (f *patFake) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.filters) + len(f.gets) + len(f.sets) + f.statsN
}

func (f *patFake) lastFilter(t *testing.T) siem.PatternFilter {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.filters) == 0 {
		t.Fatal("Patterns was not called")
	}
	return f.filters[len(f.filters)-1]
}

func (f *patFake) setList() []patSet {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.sets)
}

const patWebID = "p0123456789abcdef"

func patFixtures(now time.Time) []siem.Pattern {
	hourly := make([]uint32, 168)
	hourly[0], hourly[100], hourly[167] = 3, 40, 12
	pats := []siem.Pattern{
		{ID: patWebID, Scope: "app:shop/web", App: "shop", Service: "web",
			Template: `payment failed for order <NUM> code=<STR> <script>alert(1)</script>`, Sample: `payment failed for order 991 code=E42 <img src=x onerror=alert(2)>`,
			Level: siem.LvlError, State: siem.PatternNew, First: now.Add(-2 * time.Hour), Last: now.Add(-5 * time.Minute), Count: 1234, Hourly: hourly},
		{ID: "p00000000000000aa", Scope: "host", Template: "pam_unix(cron:session): session opened for user <STR>",
			Level: siem.LvlInfo, State: siem.PatternLearned, First: now.Add(-9 * 24 * time.Hour), Last: now.Add(-time.Hour), Count: 77},
	}
	return pats
}

func newPatFake(now time.Time) *patFake {
	return &patFake{pats: patFixtures(now), stats: siem.PatternStats{
		Enabled: true, Scopes: 3, Patterns: 2, Lines: 123456, Unmined: 7, Overflowed: 2, BudgetPct: 42.4, Learning: []string{"app:shop/api", "host"},
	}}
}

// patEnv is securityEnv with detection and log patterns set (nil = off).
func patEnv(t *testing.T, f *patFake) *testEnv {
	t.Helper()
	e := detEnv(t, &detFakeService{rules: detRules()}, nil)
	if f != nil {
		e.srv.patterns = f
	}
	return e
}

var (
	patGetPaths  = []string{"/security/patterns", "/security/patterns/rows", "/security/patterns/" + patWebID}
	patPostPaths = []string{"/security/patterns/" + patWebID + "/state"}
)

func TestPatternPagesOwnerOnly(t *testing.T) {
	f := newPatFake(time.Now().UTC())
	e := patEnv(t, f)
	for _, user := range []string{"dep", "vie"} {
		sess, csrf := e.detLogin(t, user)
		for _, p := range patGetPaths {
			resp, body := e.get(t, p, sess)
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("%s GET %s = %d, want 403", user, p, resp.StatusCode)
			}
			if strings.Contains(body, "payment failed") {
				t.Errorf("%s GET %s leaked a template", user, p)
			}
		}
		for _, p := range patPostPaths {
			if resp, _ := e.detPost(t, p, sess, csrf, url.Values{"state": {"expected"}}); resp.StatusCode != http.StatusForbidden {
				t.Errorf("%s POST %s = %d, want 403", user, p, resp.StatusCode)
			}
		}
	}
	if n := f.calls(); n != 0 {
		t.Fatalf("non-owners reached the pattern service %d times", n)
	}
	owner := e.loginAs(t, "operator")
	for _, p := range patGetPaths {
		if resp, _ := e.get(t, p, owner); resp.StatusCode != http.StatusOK {
			t.Errorf("owner GET %s = %d, want 200", p, resp.StatusCode)
		}
	}
}

func TestPatternPostsRequireCSRFAndCapBody(t *testing.T) {
	f := newPatFake(time.Now().UTC())
	e := patEnv(t, f)
	sess, csrf := e.detLogin(t, "operator")
	for _, p := range patPostPaths {
		resp := e.req(t, "POST", p, secPeer, map[string]string{"Origin": "https://example.com"}, []*http.Cookie{sess, csrf}, url.Values{"state": {"expected"}})
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("POST %s without a token = %d, want 403", p, resp.StatusCode)
		}
		if resp, _ := e.detPost(t, p, sess, csrf, url.Values{"state": {"expected"}, "csrf_token": {"wrong"}}); resp.StatusCode != http.StatusForbidden {
			t.Errorf("POST %s with a wrong token = %d, want 403", p, resp.StatusCode)
		}
		// A body over the cap never reaches the service (the token rides in the header).
		resp = e.req(t, "POST", p, secPeer, map[string]string{"Origin": "https://example.com", "X-CSRF-Token": csrf.Value},
			[]*http.Cookie{sess, csrf}, url.Values{"state": {"expected"}, "pad": {strings.Repeat("x", loginBodyLimit)}})
		if resp.StatusCode < 400 {
			t.Errorf("POST %s with an oversized body = %d, want a 4xx", p, resp.StatusCode)
		}
	}
	if s := f.setList(); len(s) != 0 {
		t.Fatalf("a refused POST changed a pattern: %+v", s)
	}
}

func TestPatternPagesOff(t *testing.T) {
	// Detection off: the pages say so.
	e := detEnv(t, nil, nil)
	sess, csrf := e.detLogin(t, "operator")
	for _, p := range append(slices.Clone(patGetPaths), "/security/patterns/bogus") {
		if resp, body := e.get(t, p, sess); resp.StatusCode != http.StatusOK || !strings.Contains(body, "Detection is off") {
			t.Errorf("GET %s (detection off) = %d, off message %v", p, resp.StatusCode, strings.Contains(body, "Detection is off"))
		}
	}
	if resp, body := e.detPost(t, patPostPaths[0], sess, csrf, url.Values{"state": {"expected"}}); resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body, "Detection is off") {
		t.Errorf("POST (detection off) = %d, want 503 with the off message", resp.StatusCode)
	}
	// Detection on, log patterns off.
	e = patEnv(t, nil)
	sess, csrf = e.detLogin(t, "operator")
	for _, p := range patGetPaths {
		resp, body := e.get(t, p, sess)
		if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Log patterns are off") || !strings.Contains(body, "security_logs.detection.patterns.enabled") {
			t.Errorf("GET %s (patterns off) = %d, want the patterns-off panel", p, resp.StatusCode)
		}
	}
	if resp, body := e.detPost(t, patPostPaths[0], sess, csrf, url.Values{"state": {"expected"}}); resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body, "Log patterns are off") {
		t.Errorf("POST (patterns off) = %d, want 503", resp.StatusCode)
	}
}

func TestPatternsList(t *testing.T) {
	now := time.Now().UTC()
	f := newPatFake(now)
	e := patEnv(t, f)
	sess := e.loginAs(t, "operator")
	resp, body := e.get(t, "/security/patterns", sess)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET = %d", resp.StatusCode)
	}
	if fl := f.lastFilter(t); fl.Limit != patPageSize+1 || fl.Offset != 0 || fl.App != "" || fl.Host || len(fl.States) != 0 || fl.MinLevel != "" || fl.Sort != "" {
		t.Errorf("default filter = %+v", fl)
	}
	for _, want := range []string{
		"123,456", "42%", "7</span> counted only", "2</span> past a source", `<span class="chip">shop/api</span> <span class="chip">Host</span>`, // stats
		`href="/security/patterns/` + patWebID + `"`, "payment failed for order &lt;NUM&gt;", "&lt;script&gt;alert(1)&lt;/script&gt;",
		`href="/security/patterns?app=shop&amp;service=web"`, ">shop/<wbr>web<", `href="/security/patterns?host=1"`, ">Host<",
		"sec-lvl-error", ">New<", ">Learned<", "1,234", "5m ago",
		`data-poll-url="/security/patterns/rows"`, `data-poll-interval="30000"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("list missing %q", want)
		}
	}
	if strings.Contains(body, "<script>alert(1)") || strings.Contains(body, "onerror") {
		t.Error("a template reached the page unescaped (or the list shows samples)")
	}
	if strings.Contains(body, "app:shop/api") || strings.Contains(body, "First seen") {
		t.Error("the list shows a scope key, or still has its First seen column")
	}

	// Filters reach the service; the live fragment always reads the first page.
	_, body = e.get(t, "/security/patterns?app=shop&service=web&state=new&level=warn&sort=count&offset=50", sess)
	fl := f.lastFilter(t)
	if fl.App != "shop" || fl.Service != "web" || !slices.Equal(fl.States, []string{"new"}) || fl.MinLevel != "warn" || fl.Sort != "count" || fl.Offset != 50 || fl.Host {
		t.Errorf("filter = %+v", fl)
	}
	if strings.Contains(body, "data-poll-url") || !strings.Contains(body, `href="/security/patterns?app=shop&amp;level=warn&amp;service=web&amp;sort=count&amp;state=new"`) {
		t.Error("a later page: want no live refresh and a Previous link to the first page")
	}
	e.get(t, "/security/patterns/rows?app=shop&offset=50", sess)
	if fl := f.lastFilter(t); fl.Offset != 0 || fl.App != "shop" {
		t.Errorf("rows filter = %+v, want the first page", fl)
	}
	e.get(t, "/security/patterns?host=1&state=bogus&level=debug&sort=evil&offset=-3", sess)
	if fl := f.lastFilter(t); !fl.Host || len(fl.States) != 0 || fl.MinLevel != "" || fl.Sort != "" || fl.Offset != 0 {
		t.Errorf("unknown values: filter = %+v, want them ignored", fl)
	}

	// Paging: 60 patterns, 50 a page.
	many := make([]siem.Pattern, 60)
	for i := range many {
		many[i] = siem.Pattern{ID: fmt.Sprintf("p%016x", i), Scope: "host", Template: fmt.Sprintf("line %d", i), State: siem.PatternLearned, Last: now}
	}
	f.mu.Lock()
	f.pats = many
	f.mu.Unlock()
	_, body = e.get(t, "/security/patterns", sess)
	if !strings.Contains(body, `href="/security/patterns?offset=50">Next page`) || strings.Contains(body, "Previous page") || !strings.Contains(body, "Patterns 1 to 50") {
		t.Error("first of two pages: want Next only and the row positions")
	}
	if n := strings.Count(body, `class="sec-tpl"`); n != 50 {
		t.Errorf("first page shows %d rows, want 50", n)
	}
	_, body = e.get(t, "/security/patterns?offset=50", sess)
	if strings.Contains(body, "Next page") || !strings.Contains(body, `href="/security/patterns">Previous page`) || !strings.Contains(body, "Patterns 51 to 60") {
		t.Error("last page: want Previous only")
	}
}

func TestPatternsListStates(t *testing.T) {
	f := &patFake{stats: siem.PatternStats{Enabled: false}}
	e := patEnv(t, f)
	sess := e.loginAs(t, "operator")
	_, body := e.get(t, "/security/patterns", sess)
	if !strings.Contains(body, "No patterns yet") || !strings.Contains(body, "Log pattern mining is off on this host") {
		t.Error("empty list with mining off: want the empty state and the off notice")
	}
	_, body = e.get(t, "/security/patterns?state=new", sess)
	if !strings.Contains(body, "No patterns match these filters.") {
		t.Error("filtered empty list: want the no-match message")
	}
	// A scope that can't be asked for is a message, and no query.
	n := len(f.filters)
	for q, want := range map[string]string{"host=1&app=shop": "Pick an app or the host, not both.", "service=web": "A service needs its app."} {
		_, body = e.get(t, "/security/patterns?"+q, sess)
		if !strings.Contains(body, want) {
			t.Errorf("?%s: want %q", q, want)
		}
	}
	if len(f.filters) != n {
		t.Error("an invalid filter reached the service")
	}
	f.mu.Lock()
	f.readErr = errors.New("disk on fire at /var/lib/secret")
	f.mu.Unlock()
	for _, p := range []string{"/security/patterns", "/security/patterns/rows", "/security/patterns/" + patWebID} {
		resp, body := e.get(t, p, sess)
		if resp.StatusCode != http.StatusInternalServerError || strings.Contains(body, "disk on fire") || !strings.Contains(body, "log has the details") {
			t.Errorf("GET %s on a read error = %d, want 500 with a generic message", p, resp.StatusCode)
		}
	}
}

func TestPatternDetail(t *testing.T) {
	now := time.Now().UTC()
	f := newPatFake(now)
	det := &detFakeService{rules: detRules(), dets: []siem.Detection{
		{ID: 77, RuleID: "pattern.new", RuleName: "New log pattern", Severity: siem.SevLow, Key: patWebID, Last: now, Count: 1, Summary: "A new template in shop/web"},
	}}
	e := patEnv(t, f)
	e.srv.detections = det
	sess := e.loginAs(t, "operator")
	resp, body := e.get(t, "/security/patterns/"+patWebID, sess)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET = %d", resp.StatusCode)
	}
	if fl := det.lastFilter(t); fl.Key != patWebID {
		t.Errorf("detections filter = %+v, want Key %s", fl, patWebID)
	}
	for _, want := range []string{
		"payment failed for order &lt;NUM&gt; code=&lt;STR&gt; &lt;script&gt;", "&lt;img src=x onerror=alert(2)&gt;", // template and sample, escaped
		`href="/security/detections/77"`, "New log pattern", "A new template in shop/web",
		"At most 40 lines in one hour; 12 in the last 24 hours.",
		`name="state" value="expected"`, `name="state" value="ignored"`, `name="state" value="learned"`, "Keep watching",
		`action="/security/patterns/` + patWebID + `/state"`, "Find events",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("detail missing %q", want)
		}
	}
	if strings.Contains(body, "<img src=x") || strings.Contains(body, "<script>alert") {
		t.Error("log text reached the page unescaped")
	}
	if n := strings.Count(body, `width="0.8"`); n != 3 {
		t.Errorf("bars = %d, want 3 (one per hour with lines)", n)
	}
	for id, code := range map[string]int{"p0000000000000000": http.StatusNotFound, "P0123456789ABCDEF": http.StatusNotFound, "x": http.StatusNotFound} {
		if resp, body := e.get(t, "/security/patterns/"+id, sess); resp.StatusCode != code || !strings.Contains(body, "Pattern not found.") {
			t.Errorf("GET %s = %d, want %d", id, resp.StatusCode, code)
		}
	}
	f.mu.Lock()
	gets := slices.Clone(f.gets)
	f.mu.Unlock()
	if slices.Contains(gets, "P0123456789ABCDEF") || slices.Contains(gets, "x") {
		t.Errorf("a malformed ID reached the service: %v", gets)
	}
}

// patFindHref is the Find events link's search, as the browser would send it.
var patFindHref = regexp.MustCompile(`href="(/security\?[^"]*)">Find events`)

func TestPatternFindEventsQuoting(t *testing.T) {
	realQueryParser(t)
	p := siem.Pattern{ID: patWebID, Scope: "app:shop/web", App: "shop", Service: "web",
		Template: `GET /api?q="x" <NUM> user:<STR> <b>bold</b> a\b ok -flag :`}
	want := `app:shop svc:web "GET" "/api?q=\"x\"" "user:" "<b>bold</b>" "a\\b" "-flag"`
	got := patternSearch(&p)
	if got != want {
		t.Fatalf("search =\n %s\nwant\n %s", got, want)
	}
	q, err := query.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(q.Text, []string{"GET", `/api?q="x"`, "user:", "<b>bold</b>", `a\b`, "-flag"}) || len(q.Terms) != 2 {
		t.Errorf("parsed back to terms %+v, text %q", q.Terms, q.Text)
	}
	// The host's patterns search the host's events.
	host := siem.Pattern{Scope: "host", Template: "session opened for user <STR> by (uid=<NUM>)"}
	if got, want := patternSearch(&host), `src:host "session" "opened" "for" "user" "by" "(uid="`; got != want {
		t.Errorf("host search = %q, want %q", got, want)
	}
	// No link for a scope that would search as a prefix, or none.
	for _, bad := range []siem.Pattern{{App: "shop*", Template: "x y"}, {Scope: "weird", Template: "x y"}} {
		if got := patternSearch(&bad); got != "" {
			t.Errorf("search for %+v = %q, want none", bad, got)
		}
	}

	// On the page: the link carries exactly that search.
	f := newPatFake(time.Now().UTC())
	f.pats[0].Template = p.Template
	e := patEnv(t, f)
	sess := e.loginAs(t, "operator")
	_, body := e.get(t, "/security/patterns/"+patWebID, sess)
	m := patFindHref.FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no Find events link")
	}
	u, err := url.Parse(html.UnescapeString(m[1]))
	if err != nil {
		t.Fatal(err)
	}
	if u.Query().Get("q") != want || u.Query().Get("from") == "" || u.Query().Get("to") == "" {
		t.Errorf("link query = %v", u.Query())
	}
	if strings.Contains(body, "<b>bold</b>") {
		t.Error("the template's HTML reached the page unescaped")
	}
}

func TestPatternStateChange(t *testing.T) {
	f := newPatFake(time.Now().UTC())
	e := patEnv(t, f)
	sess, csrf := e.detLogin(t, "operator")
	path := "/security/patterns/" + patWebID + "/state"
	for _, st := range []string{siem.PatternExpected, siem.PatternIgnored, siem.PatternLearned} {
		resp, _ := e.detPost(t, path, sess, csrf, url.Values{"state": {st}})
		if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || loc != "/security/patterns/"+patWebID+"?done="+st {
			t.Errorf("state %s = %d → %q", st, resp.StatusCode, loc)
		}
	}
	if got := f.setList(); !slices.Equal(got, []patSet{{patWebID, "expected", "operator"}, {patWebID, "ignored", "operator"}, {patWebID, "learned", "operator"}}) {
		t.Errorf("SetPatternState calls = %+v", got)
	}
	_, body := e.get(t, "/security/patterns/"+patWebID+"?done=expected", sess)
	if !strings.Contains(body, "Marked as expected: the pattern rules stay silent for it.") {
		t.Error("done notice missing")
	}
	// Refused before the service: a state the form doesn't offer, a malformed ID.
	if resp, body := e.detPost(t, path, sess, csrf, url.Values{"state": {"new"}}); resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "Pick a state") {
		t.Errorf("state new = %d, want 422", resp.StatusCode)
	}
	if resp, _ := e.detPost(t, "/security/patterns/nope/state", sess, csrf, url.Values{"state": {"expected"}}); resp.StatusCode != http.StatusNotFound {
		t.Errorf("bad ID = %d, want 404", resp.StatusCode)
	}
	if n := len(f.setList()); n != 3 {
		t.Errorf("a refused change reached the service (%d calls)", n)
	}
	// The service's validation text is shown; anything else is generic.
	f.mu.Lock()
	f.setErr = fmt.Errorf("%w: unknown pattern", siem.ErrInvalidInput)
	f.mu.Unlock()
	if resp, body := e.detPost(t, path, sess, csrf, url.Values{"state": {"expected"}}); resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "The state was not saved: unknown pattern") {
		t.Errorf("invalid input = %d", resp.StatusCode)
	}
	f.mu.Lock()
	f.setErr = errors.New("sqlite: database is locked at /var/lib/x")
	f.mu.Unlock()
	if resp, body := e.detPost(t, path, sess, csrf, url.Values{"state": {"expected"}}); resp.StatusCode != http.StatusInternalServerError || strings.Contains(body, "sqlite") {
		t.Errorf("internal error = %d (or leaked)", resp.StatusCode)
	}
	rows := secAuditRows(t, e, "security_pattern_state")
	var details []string
	for _, r := range rows {
		details = append(details, r.Outcome+" "+r.Target+" "+r.Detail)
		if r.Actor != "operator" || r.Level != "security" {
			t.Errorf("audit row %+v", r)
		}
	}
	want := []string{
		"ok pattern:" + patWebID + " state=expected", "ok pattern:" + patWebID + " state=ignored", "ok pattern:" + patWebID + " state=learned",
		"error pattern:" + patWebID + " result=rejected", "error pattern result=not found",
		"error pattern:" + patWebID + " state=expected result=rejected", "error pattern:" + patWebID + " state=expected result=error",
	}
	if !slices.Equal(details, want) {
		t.Errorf("audit =\n%q\nwant\n%q", details, want)
	}
}

func TestPatternActions(t *testing.T) {
	for st, want := range map[string][]string{
		siem.PatternNew:      {"expected*", "ignored", "learned"},
		siem.PatternLearned:  {"expected", "ignored"},
		siem.PatternExpected: {"learned*", "ignored"},
		siem.PatternIgnored:  {"learned*", "expected"},
		"bogus":              {"expected", "ignored", "learned"},
	} {
		var got []string
		for _, a := range patActions(st) {
			s := a.State
			if a.Primary {
				s += "*"
			}
			got = append(got, s)
		}
		if !slices.Equal(got, want) {
			t.Errorf("actions(%s) = %v, want %v", st, got, want)
		}
	}
}
