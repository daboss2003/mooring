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

	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/siem"
)

// incFake is a siem.IncidentService in memory. Incidents applies the filter the way the contract
// says (most recently active first: Last, then ID, both descending; keyset cursor; Limit); every
// change is recorded, and fails with writeErr when set.
type incFake struct {
	mu       sync.Mutex
	incs     []siem.Incident // any order; Incident returns one with its Timeline
	risky    []siem.RiskScore
	risk     siem.RiskScore // Entity's score
	entIncs  []siem.Incident
	mutes    []siem.Mute
	readErr  error // Incidents, Incident, Entity
	riskyErr error
	writeErr error // every change
	filters  []siem.IncidentFilter
	gets     []int64
	ents     []siem.Entity
	riskyN   []int
	changes  []incChange
}

type incChange struct {
	Method   string // SetState, Assign, AddNote, MarkFalsePositive, RemoveMute
	ID       int64
	State    string
	Actor    string
	Text     string // the note
	Assignee string
	Mute     bool
	RuleID   string
	Entity   siem.Entity
}

func (f *incFake) Incidents(_ context.Context, fl siem.IncidentFilter) ([]siem.Incident, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.filters = append(f.filters, fl)
	if f.readErr != nil {
		return nil, f.readErr
	}
	all := slices.Clone(f.incs)
	slices.SortStableFunc(all, func(a, b siem.Incident) int {
		if c := b.Last.Compare(a.Last); c != 0 {
			return c
		}
		return cmp.Compare(b.ID, a.ID)
	})
	var out []siem.Incident
	for _, in := range all {
		if len(fl.States) > 0 && !slices.Contains(fl.States, in.State) {
			continue
		}
		if fl.MinSeverity != "" && siem.SeverityRank(in.Severity) < siem.SeverityRank(fl.MinSeverity) {
			continue
		}
		if fl.Assignee != "" && in.Assignee != fl.Assignee {
			continue
		}
		if !fl.BeforeLast.IsZero() && !in.Last.Before(fl.BeforeLast) && !(in.Last.Equal(fl.BeforeLast) && in.ID < fl.Before) {
			continue
		}
		in.Timeline, in.Mutes = nil, nil // filled by Incident only
		out = append(out, in)
		if fl.Limit > 0 && len(out) == fl.Limit {
			break
		}
	}
	return out, nil
}

func (f *incFake) Incident(_ context.Context, id int64) (siem.Incident, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets = append(f.gets, id)
	if f.readErr != nil {
		return siem.Incident{}, false, f.readErr
	}
	for _, in := range f.incs {
		if in.ID == id {
			return in, true, nil
		}
	}
	return siem.Incident{}, false, nil
}

func (f *incFake) change(c incChange) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.changes = append(f.changes, c)
	return f.writeErr
}

func (f *incFake) SetState(_ context.Context, id int64, state, actor, note string) error {
	return f.change(incChange{Method: "SetState", ID: id, State: state, Actor: actor, Text: note})
}

func (f *incFake) Assign(_ context.Context, id int64, assignee, actor string) error {
	return f.change(incChange{Method: "Assign", ID: id, Assignee: assignee, Actor: actor})
}

func (f *incFake) AddNote(_ context.Context, id int64, actor, text string) error {
	return f.change(incChange{Method: "AddNote", ID: id, Actor: actor, Text: text})
}

func (f *incFake) MarkFalsePositive(_ context.Context, id int64, actor string, mute bool, note string) error {
	return f.change(incChange{Method: "MarkFalsePositive", ID: id, Actor: actor, Mute: mute, Text: note})
}

func (f *incFake) Entity(_ context.Context, e siem.Entity) (siem.RiskScore, []siem.Incident, []siem.Mute, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ents = append(f.ents, e)
	if f.readErr != nil {
		return siem.RiskScore{}, nil, nil, f.readErr
	}
	rs := f.risk
	rs.Entity = e
	return rs, slices.Clone(f.entIncs), slices.Clone(f.mutes), nil
}

func (f *incFake) RemoveMute(_ context.Context, ruleID string, e siem.Entity, actor string) error {
	return f.change(incChange{Method: "RemoveMute", RuleID: ruleID, Entity: e, Actor: actor})
}

func (f *incFake) Risky(_ context.Context, limit int) ([]siem.RiskScore, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.riskyN = append(f.riskyN, limit)
	if f.riskyErr != nil {
		return nil, f.riskyErr
	}
	return slices.Clone(f.risky), nil
}

// calls is every request that reached the service.
func (f *incFake) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.filters) + len(f.gets) + len(f.ents) + len(f.riskyN) + len(f.changes)
}

func (f *incFake) changeList() []incChange {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.changes)
}

func (f *incFake) lastChange(t *testing.T) incChange {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.changes) == 0 {
		t.Fatal("no change reached the incident service")
	}
	return f.changes[len(f.changes)-1]
}

func (f *incFake) lastFilter(t *testing.T) siem.IncidentFilter {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.filters) == 0 {
		t.Fatal("Incidents was not called")
	}
	return f.filters[len(f.filters)-1]
}

func (f *incFake) lastEntity(t *testing.T) siem.Entity {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.ents) == 0 {
		t.Fatal("Entity was not called")
	}
	return f.ents[len(f.ents)-1]
}

func (f *incFake) set(fn func(f *incFake)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

// incEnv is securityEnv (the auth owner "operator", the deployer "dep", the viewer "vie") with two
// more owners from users:, "zed" then "ann", and extra (the test password), and the incident
// service set (nil = detection off).
func incEnv(t *testing.T, f *incFake, extra ...config.UserConfig) *testEnv {
	t.Helper()
	e := securityEnv(t, nil)
	hash := e.srv.cfg.ExtraUsers[0].PasswordHash
	users := append([]config.UserConfig{{Username: "zed", Role: config.RoleOwner}, {Username: "ann", Role: config.RoleOwner}}, extra...)
	for i := range users {
		users[i].PasswordHash = hash
	}
	e.srv.cfg.ExtraUsers = append(e.srv.cfg.ExtraUsers, users...)
	sec, err := buildSecState(e.srv.cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.srv.sec.Store(sec)
	if f != nil {
		e.srv.incidentSvc = f
	}
	return e
}

var (
	accAlice  = siem.Entity{Kind: siem.EntityAccount, Key: "alice", Scope: "mooring"}
	addrScan  = siem.Entity{Kind: siem.EntityAddress, Key: "203.0.113.9"}
	addrOther = siem.Entity{Kind: siem.EntityAddress, Key: "198.51.100.7"}
)

func incFixtures(now time.Time) []siem.Incident {
	return []siem.Incident{
		{ID: 12, State: siem.IncidentOpen, Severity: siem.SevCritical, Title: "Brute force, then a sign-in for alice",
			Chain: "Brute force then sign-in", Entities: []siem.Entity{accAlice, addrScan},
			First: now.Add(-2 * time.Hour), Last: now.Add(-5 * time.Minute), Detections: 3,
			Rules: []string{"ssh.bruteforce", "auth.new_country"}, Assignee: "ann", Updated: now.Add(-4 * time.Minute),
			Timeline: []siem.IncidentEvent{
				{TS: now.Add(-2 * time.Hour), Kind: siem.TimelineOpened, Text: "Opened by SSH brute force"},
				{TS: now.Add(-110 * time.Minute), Kind: siem.TimelineDetection, DetectionID: 101, RuleID: "ssh.bruteforce", RuleName: "SSH brute force",
					Severity: siem.SevHigh, Text: "42 failed SSH logins from 203.0.113.9"},
				{TS: now.Add(-100 * time.Minute), Kind: siem.TimelineEscalated, Severity: siem.SevCritical, Text: "Known chain: Brute force then sign-in"},
				{TS: now.Add(-90 * time.Minute), Kind: siem.TimelineState, Actor: "operator", Text: siem.IncidentAcknowledged},
				{TS: now.Add(-80 * time.Minute), Kind: siem.TimelineAssigned, Actor: "operator", Text: "ann"},
				{TS: now.Add(-70 * time.Minute), Kind: siem.TimelineNote, Actor: "dep", Text: "Checked the VPN log.\nNot us."},
				{TS: now.Add(-60 * time.Minute), Kind: siem.TimelineState, Actor: "dep", Text: siem.IncidentOpen},
				{TS: now.Add(-50 * time.Minute), Kind: siem.TimelineMuted, Actor: "dep", RuleID: "auth.new_country", RuleName: "Sign-in from a new country", Text: "for 30 days"},
			}},
		{ID: 9, State: siem.IncidentAcknowledged, Severity: siem.SevMedium, Title: "Port scan from 198.51.100.7",
			Entities: []siem.Entity{addrOther}, First: now.Add(-3 * time.Hour), Last: now.Add(-time.Hour), Detections: 1,
			Rules: []string{"edge.scan"}, Assignee: "dep", Updated: now.Add(-time.Hour)}, // a user, not an owner
		{ID: 4, State: siem.IncidentResolved, Severity: siem.SevHigh, Title: "Resolved incident", Entities: []siem.Entity{addrScan},
			First: now.Add(-5 * time.Hour), Last: now.Add(-3 * time.Hour), Detections: 2, Assignee: "bob", Updated: now.Add(-3 * time.Hour)}, // no longer a user
		{ID: 3, State: siem.IncidentFalsePositive, Severity: siem.SevLow, Title: "False alarm", Entities: []siem.Entity{addrOther},
			First: now.Add(-6 * time.Hour), Last: now.Add(-4 * time.Hour), Detections: 1, Updated: now.Add(-4 * time.Hour)},
	}
}

func incRisky(now time.Time) []siem.RiskScore {
	return []siem.RiskScore{
		{Entity: addrScan, Score: 87.4, Updated: now.Add(-5 * time.Minute), OpenIncidents: 2},
		{Entity: accAlice, Score: 12.2, Updated: now.Add(-time.Hour), OpenIncidents: 1},
	}
}

func newIncFake(now time.Time) *incFake {
	return &incFake{incs: incFixtures(now), risky: incRisky(now)}
}

var (
	incGetPaths  = []string{"/security/incidents", "/security/incidents/rows", "/security/incidents/12", "/security/entities?kind=address&key=203.0.113.9"}
	incPostPaths = []string{"/security/incidents/12/state", "/security/incidents/12/assign", "/security/incidents/12/note", "/security/incidents/12/false-positive", "/security/mutes/remove"}
)

func incPostForm() url.Values {
	return url.Values{"state": {"acknowledged"}, "assignee": {"dep"}, "note": {"x"}, "rule": {"ssh.bruteforce"}, "kind": {"address"}, "key": {"203.0.113.9"}}
}

func TestIncidentPagesOwnerOnly(t *testing.T) {
	f := newIncFake(time.Now().UTC())
	e := incEnv(t, f)
	for _, user := range []string{"dep", "vie"} {
		sess, csrf := e.detLogin(t, user)
		for _, p := range incGetPaths {
			resp, body := e.get(t, p, sess)
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("%s GET %s = %d, want 403", user, p, resp.StatusCode)
			}
			if strings.Contains(body, "Brute force") || strings.Contains(body, "Highest risk") || strings.Contains(body, "203.0.113.9") {
				t.Errorf("%s GET %s leaked page content", user, p)
			}
		}
		for _, p := range incPostPaths {
			if resp, _ := e.detPost(t, p, sess, csrf, incPostForm()); resp.StatusCode != http.StatusForbidden {
				t.Errorf("%s POST %s = %d, want 403", user, p, resp.StatusCode)
			}
		}
	}
	if n := f.calls(); n != 0 {
		t.Fatalf("non-owners reached the incident service %d times", n)
	}
	denied := 0
	for _, r := range secAuditRows(t, e, "rbac_deny") {
		if strings.Contains(r.Target, "/security/") {
			denied++
		}
	}
	if want := 2 * (len(incGetPaths) + len(incPostPaths)); denied != want {
		t.Errorf("rbac_deny rows for /security/ routes = %d, want %d", denied, want)
	}
	owner := e.loginAs(t, "operator")
	for _, p := range incGetPaths {
		if resp, _ := e.get(t, p, owner); resp.StatusCode != http.StatusOK {
			t.Errorf("owner GET %s = %d, want 200", p, resp.StatusCode)
		}
	}
}

func TestIncidentPostsRequireCSRF(t *testing.T) {
	f := newIncFake(time.Now().UTC())
	e := incEnv(t, f)
	sess, csrf := e.detLogin(t, "operator")
	for _, p := range incPostPaths {
		form := incPostForm()
		resp := e.req(t, "POST", p, secPeer, map[string]string{"Origin": "https://example.com"}, []*http.Cookie{sess, csrf}, form)
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("POST %s without a token = %d, want 403", p, resp.StatusCode)
		}
		form = incPostForm()
		form.Set("csrf_token", "not-the-token")
		if resp, _ := e.detPost(t, p, sess, csrf, form); resp.StatusCode != http.StatusForbidden {
			t.Errorf("POST %s with a wrong token = %d, want 403", p, resp.StatusCode)
		}
	}
	if c := f.changeList(); len(c) != 0 {
		t.Fatalf("a POST without a valid CSRF token changed something: %+v", c)
	}
}

// Detection off (nil service): every page says so, POSTs change nothing.
func TestIncidentPagesOff(t *testing.T) {
	e := incEnv(t, nil)
	sess, csrf := e.detLogin(t, "operator")
	for _, p := range append(slices.Clone(incGetPaths), "/security/incidents/abc", "/security/entities?kind=bogus") {
		resp, body := e.get(t, p, sess)
		if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Detection is off") {
			t.Errorf("GET %s (off) = %d, off message %v; want 200 with it", p, resp.StatusCode, strings.Contains(body, "Detection is off"))
		}
	}
	for _, p := range incPostPaths {
		resp, body := e.detPost(t, p, sess, csrf, incPostForm())
		if resp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(body, "Detection is off") {
			t.Errorf("POST %s (off) = %d, want 503 with the off message", p, resp.StatusCode)
		}
	}
}

var incRowLink = regexp.MustCompile(`href="/security/incidents/([0-9]+)"`)

func incRowIDs(body string) []string {
	var ids []string
	for _, m := range incRowLink.FindAllStringSubmatch(body, -1) {
		if !slices.Contains(ids, m[1]) {
			ids = append(ids, m[1])
		}
	}
	return ids
}

// entityHref is an entity link as it appears in a page's HTML.
func entityHref(en siem.Entity) string {
	v := url.Values{"kind": {en.Kind}, "key": {en.Key}}
	if en.Scope != "" {
		v.Set("scope", en.Scope)
	}
	return `href="` + html.EscapeString("/security/entities?"+v.Encode()) + `"`
}

func TestIncidentsList(t *testing.T) {
	now := time.Now().UTC()
	f := newIncFake(now)
	e := incEnv(t, f)
	sess := e.loginAs(t, "operator")
	resp, body := e.get(t, "/security/incidents", sess)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /security/incidents = %d", resp.StatusCode)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	// The default view: open and acknowledged, most recently active first.
	fl := f.lastFilter(t)
	if !slices.Equal(fl.States, []string{siem.IncidentOpen, siem.IncidentAcknowledged}) || fl.MinSeverity != "" || fl.Assignee != "" ||
		fl.Entity != nil || !fl.BeforeLast.IsZero() || fl.Before != 0 || fl.Limit != incPageSize+1 {
		t.Errorf("filter = %+v, want open+acknowledged, first page, limit %d", fl, incPageSize+1)
	}
	if ids := incRowIDs(body); !slices.Equal(ids, []string{"12", "9"}) {
		t.Errorf("rows = %v, want [12 9]", ids)
	}
	for _, want := range []string{
		"Brute force, then a sign-in for alice", "Port scan from 198.51.100.7", "sec-lvl-critical", "sec-lvl-warn",
		">Open<", ">Acknowledged<", "Brute force then sign-in", entityHref(accAlice), entityHref(addrScan), entityHref(addrOther),
		"Mooring user", ">ann<", "dep (no longer an owner)", "5m ago", "#12 · 3 detections", "#9 · 1 detection ·",
		`data-poll-url="/security/incidents/rows"`, `data-poll-interval="30000"`,
		"Highest risk", ">87<", ">12<", `href="/security/incidents?state=all"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("list missing %q", want)
		}
	}
	f.set(func(f *incFake) {
		if len(f.riskyN) == 0 || f.riskyN[len(f.riskyN)-1] != 10 {
			t.Errorf("Risky limit = %v, want 10", f.riskyN)
		}
	})
	if strings.Index(body, entityHref(addrScan)) > strings.LastIndex(body, ">87<") {
		t.Error("the risk panel does not show the riskiest entity with its score")
	}
	// The live refresh: the same list and risk panel without the shell.
	resp, body = e.get(t, "/security/incidents/rows", sess)
	if resp.StatusCode != http.StatusOK || strings.Contains(body, `class="sidebar"`) || !slices.Equal(incRowIDs(body), []string{"12", "9"}) || !strings.Contains(body, "Highest risk") {
		t.Errorf("rows partial = %d, shell %v, rows %v", resp.StatusCode, strings.Contains(body, `class="sidebar"`), incRowIDs(body))
	}

	// A risk panel failure is shown, and the list still is.
	f.set(func(f *incFake) { f.riskyErr = errors.New("detect: risk table locked") })
	_, body = e.get(t, "/security/incidents", sess)
	if !strings.Contains(body, "The risk scores could not be read.") || strings.Contains(body, "risk table locked") || len(incRowIDs(body)) != 2 {
		t.Error("a Risky error: want the generic message and the list")
	}
	f.set(func(f *incFake) { f.riskyErr, f.readErr = nil, errors.New("detect: incidents table locked") })
	_, body = e.get(t, "/security/incidents", sess)
	if !strings.Contains(body, "The incidents could not be read. Mooring&#39;s log has the details.") || strings.Contains(body, "table locked") {
		t.Error("an Incidents error: want the generic message only")
	}
}

func TestIncidentsFilters(t *testing.T) {
	now := time.Now().UTC()
	f := newIncFake(now)
	e := incEnv(t, f)
	sess := e.loginAs(t, "operator")
	for _, c := range []struct {
		query  string
		states []string
		ids    []string
	}{
		{"state=all", nil, []string{"12", "9", "4", "3"}},
		{"state=resolved", []string{siem.IncidentResolved}, []string{"4"}},
		{"state=false_positive", []string{siem.IncidentFalsePositive}, []string{"3"}},
		{"state=open", []string{siem.IncidentOpen}, []string{"12"}},
		{"state=bogus", []string{siem.IncidentOpen, siem.IncidentAcknowledged}, []string{"12", "9"}},
	} {
		_, body := e.get(t, "/security/incidents?"+c.query, sess)
		if fl := f.lastFilter(t); !slices.Equal(fl.States, c.states) {
			t.Errorf("%s: States = %v, want %v", c.query, fl.States, c.states)
		}
		if ids := incRowIDs(body); !slices.Equal(ids, c.ids) {
			t.Errorf("%s: rows %v, want %v", c.query, ids, c.ids)
		}
	}
	_, body := e.get(t, "/security/incidents?state=all&severity=high&assignee=ann", sess)
	fl := f.lastFilter(t)
	if fl.States != nil || fl.MinSeverity != siem.SevHigh || fl.Assignee != "ann" {
		t.Errorf("filter = %+v", fl)
	}
	for _, want := range []string{`<option value="all" selected>`, `<option value="high" selected>`, `<option value="ann" selected>ann</option>`} {
		if !strings.Contains(body, want) {
			t.Errorf("the filter form does not keep %q", want)
		}
	}
	// The assignee select lists the owners, the auth owner first (TestIncidentAssignOwnersOnly).
	if got, want := selectValues(t, body, `<label for="inc-assignee">`), []string{"", "operator", "ann", "zed"}; !slices.Equal(got, want) {
		t.Errorf("assignee filter options = %q, want %q", got, want)
	}
	// A former owner stays selectable for the filter; bad values are ignored.
	_, body = e.get(t, "/security/incidents?assignee=bob", sess)
	if fl := f.lastFilter(t); fl.Assignee != "bob" || !strings.Contains(body, `<option value="bob" selected>bob (no longer an owner)</option>`) {
		t.Errorf("former-owner filter: Assignee %q", fl.Assignee)
	}
	for _, bad := range []string{"severity=bogus", "assignee=" + url.QueryEscape("a\x00b"), "assignee=" + strings.Repeat("x", siem.MaxShort+1)} {
		e.get(t, "/security/incidents?"+bad, sess)
		if fl := f.lastFilter(t); fl.MinSeverity != "" || fl.Assignee != "" {
			t.Errorf("%s: filter %+v, want it ignored", bad, fl)
		}
	}
}

func incPagingFixture(now time.Time) (incs []siem.Incident, want []string) {
	base := now.Truncate(time.Second).Add(123456789)
	for p := 0; p < 120; p++ {
		g, j := p/7, p%7
		id := int64((g*5)%18)*10 + int64(7-j)
		last := base.Add(-time.Duration(g) * 1500 * time.Millisecond)
		incs = append(incs, siem.Incident{ID: id, State: siem.IncidentOpen, Severity: siem.SevMedium, Title: "Incident " + strconv.FormatInt(id, 10),
			Entities: []siem.Entity{addrScan}, First: last, Last: last, Detections: 1})
		want = append(want, strconv.FormatInt(id, 10))
	}
	rand.New(rand.NewPCG(3, 4)).Shuffle(len(incs), func(a, b int) { incs[a], incs[b] = incs[b], incs[a] })
	return incs, want
}

var incOlderLink = regexp.MustCompile(`href="([^"]*)">Older incidents</a>`)

func TestIncidentsPaging(t *testing.T) {
	now := time.Now().UTC()
	f := &incFake{}
	var want []string
	f.incs, want = incPagingFixture(now)
	e := incEnv(t, f)
	sess := e.loginAs(t, "operator")
	link := "/security/incidents?severity=medium&assignee=dep&state=open"
	for i := range f.incs {
		f.incs[i].Assignee = "dep"
	}
	var got []string
	for page := 1; ; page++ {
		if page > 5 {
			t.Fatal("paging does not end")
		}
		resp, body := e.get(t, link, sess)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("page %d (%s) = %d", page, link, resp.StatusCode)
		}
		ids := incRowIDs(body)
		got = append(got, ids...)
		fl := f.lastFilter(t)
		if fl.MinSeverity != siem.SevMedium || fl.Assignee != "dep" || !slices.Equal(fl.States, []string{siem.IncidentOpen}) {
			t.Errorf("page %d filter = %+v: the filters were dropped", page, fl)
		}
		if page == 1 {
			if !strings.Contains(body, "data-poll-url") || strings.Contains(body, "Newest incidents") {
				t.Errorf("first page: live refresh %v, newest link %v", strings.Contains(body, "data-poll-url"), strings.Contains(body, "Newest incidents"))
			}
		} else if strings.Contains(body, "data-poll-url") || !strings.Contains(body, "Newest incidents") {
			t.Errorf("page %d: an older page must not live-refresh and needs a link to the newest", page)
		}
		m := incOlderLink.FindStringSubmatch(body)
		if m == nil {
			if len(ids) != 20 {
				t.Errorf("last page has %d rows, want 20", len(ids))
			}
			break
		}
		if len(ids) != incPageSize {
			t.Fatalf("page %d has %d rows and an Older link, want %d", page, len(ids), incPageSize)
		}
		link = html.UnescapeString(m[1])
		u, err := url.Parse(link)
		if err != nil || u.Path != "/security/incidents" {
			t.Fatalf("Older link %q", link)
		}
		var last siem.Incident
		for _, in := range f.incs {
			if strconv.FormatInt(in.ID, 10) == ids[len(ids)-1] {
				last = in
			}
		}
		q := u.Query()
		if bl, err := time.Parse(time.RFC3339Nano, q.Get("before_last")); err != nil || !bl.Equal(last.Last) || q.Get("before") != ids[len(ids)-1] {
			t.Errorf("Older link %q: cursor %q/%q, want %s/%d", link, q.Get("before_last"), q.Get("before"), last.Last.Format(time.RFC3339Nano), last.ID)
		}
		if q.Get("severity") != "medium" || q.Get("assignee") != "dep" || q.Get("state") != "open" {
			t.Errorf("Older link %q dropped the filters", link)
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("pages listed %d incidents:\n got %v\nwant %v", len(got), got, want)
	}
	// The live refresh always reads the newest page.
	e.get(t, "/security/incidents/rows?before_last="+url.QueryEscape(now.Format(time.RFC3339Nano))+"&before=5", sess)
	if fl := f.lastFilter(t); !fl.BeforeLast.IsZero() || fl.Before != 0 {
		t.Errorf("rows cursor = %v/%d, want the newest page", fl.BeforeLast, fl.Before)
	}
}

func TestIncidentsEmptyState(t *testing.T) {
	e := incEnv(t, &incFake{})
	sess := e.loginAs(t, "operator")
	_, body := e.get(t, "/security/incidents", sess)
	for _, want := range []string{"No open incidents", `href="/security/detections"`, "No entity has a risk score yet."} {
		if !strings.Contains(body, want) {
			t.Errorf("empty state missing %q", want)
		}
	}
	_, body = e.get(t, "/security/incidents?severity=critical", sess)
	if !strings.Contains(body, "No incidents match these filters.") {
		t.Error("filtered empty state missing")
	}
}

var incTimelineOrder = []string{
	"Opened by SSH brute force", "42 failed SSH logins from 203.0.113.9", "Known chain: Brute force then sign-in",
	"Checked the VPN log.", "Sign-in from a new country",
}

func TestIncidentDetail(t *testing.T) {
	now := time.Now().UTC()
	f := newIncFake(now)
	e := incEnv(t, f)
	sess := e.loginAs(t, "operator")
	resp, body := e.get(t, "/security/incidents/12", sess)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET detail = %d", resp.StatusCode)
	}
	for _, want := range []string{
		`<h1 class="sec-title">Brute force, then a sign-in for alice</h1>`, "sec-lvl-critical", ">Open<", "Brute force then sign-in",
		entityHref(accAlice), entityHref(addrScan), "Mooring user",
		`href="/security/detections/101"`, "SSH brute force", `href="/security/detections?rule=ssh.bruteforce"`,
		`href="/security/detections?rule=auth.new_country"`, "<div class=\"sec-note\">Checked the VPN log.\nNot us.</div>",
		// The state form: the next steps for an open incident, plus false positive with the mute option.
		`action="/security/incidents/12/state"`, `name="state" value="acknowledged"`, `name="state" value="resolved"`,
		`formaction="/security/incidents/12/false-positive"`, `name="mute"`, `name="note"`,
		`action="/security/incidents/12/assign"`, `<option value="ann" selected>`, `<option value="">Unassigned</option>`,
		`action="/security/incidents/12/note"`, `maxlength="4096"`, "State set to", "Acknowledged", "Assigned to",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("detail missing %q", want)
		}
	}
	last := -1
	for _, s := range incTimelineOrder {
		i := strings.Index(body, s)
		if i < last {
			t.Errorf("timeline out of order at %q", s)
		}
		last = i
	}
	if strings.Contains(body, `name="state" value="open"`) {
		t.Error("an open incident offers Reopen")
	}
	if got, want := selectValues(t, body, `action="/security/incidents/12/assign"`), []string{"", "operator", "ann", "zed"}; !slices.Equal(got, want) {
		t.Errorf("assignee options = %q, want %q", got, want)
	}

	// An acknowledged incident assigned to a user who is not an owner.
	_, body = e.get(t, "/security/incidents/9", sess)
	if !strings.Contains(body, "dep (no longer an owner)") || !strings.Contains(body, `name="state" value="resolved"`) || strings.Contains(body, `name="state" value="acknowledged"`) {
		t.Error("acknowledged incident: want the former assignee marked, Resolve and no Acknowledge")
	}
	if strings.Contains(body, `<option value="dep"`) {
		t.Error("a user who is not an owner is offered as an assignee")
	}
	// Closed incidents can only be reopened.
	for _, id := range []string{"4", "3"} {
		_, body = e.get(t, "/security/incidents/"+id, sess)
		if !strings.Contains(body, `name="state" value="open"`) || strings.Contains(body, `value="resolved"`) || strings.Contains(body, "false-positive") || strings.Contains(body, `name="mute"`) {
			t.Errorf("incident %s: want only Reopen", id)
		}
	}
	for _, p := range []string{"/security/incidents/999", "/security/incidents/abc", "/security/incidents/0", "/security/incidents/-1"} {
		resp, body := e.get(t, p, sess)
		if resp.StatusCode != http.StatusNotFound || !strings.Contains(body, "Incident not found") {
			t.Errorf("GET %s = %d, want 404 with a not-found page", p, resp.StatusCode)
		}
	}
	f.set(func(f *incFake) { f.readErr = errors.New("detect: SQLITE_BUSY") })
	resp, body = e.get(t, "/security/incidents/12", sess)
	if resp.StatusCode != http.StatusInternalServerError || !strings.Contains(body, "The incident could not be read. Mooring&#39;s log has the details.") || strings.Contains(body, "SQLITE") {
		t.Errorf("read error = %d, want 500 with the generic message", resp.StatusCode)
	}
}

// noLeak checks an audit row's detail holds none of the private strings.
func noLeak(t *testing.T, r secAuditRow, private ...string) {
	t.Helper()
	for _, p := range private {
		if p != "" && strings.Contains(r.Detail, p) {
			t.Errorf("audit detail %q carries %q", r.Detail, p)
		}
	}
}

func TestIncidentStateChange(t *testing.T) {
	f := newIncFake(time.Now().UTC())
	e := incEnv(t, f)
	sess, csrf := e.detLogin(t, "operator")
	for _, c := range []struct {
		state, note, wantNote, done, notice string
	}{
		{siem.IncidentAcknowledged, "Looking into it\r\nsecond line", "Looking into it\nsecond line", "acknowledged", "Incident acknowledged."},
		{siem.IncidentResolved, "", "", "resolved", "Incident resolved."},
		{siem.IncidentOpen, "  ", "", "reopened", "Incident reopened."},
	} {
		resp, _ := e.detPost(t, "/security/incidents/12/state", sess, csrf, url.Values{"state": {c.state}, "note": {c.note}})
		if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || loc != "/security/incidents/12?done="+c.done {
			t.Errorf("state %s = %d → %q", c.state, resp.StatusCode, loc)
		}
		got := f.lastChange(t)
		if want := (incChange{Method: "SetState", ID: 12, State: c.state, Actor: "operator", Text: c.wantNote}); got != want {
			t.Errorf("state %s: call %+v, want %+v", c.state, got, want)
		}
		_, body := e.get(t, "/security/incidents/12?done="+c.done, sess)
		if !strings.Contains(body, c.notice) {
			t.Errorf("after %s: notice %q missing", c.state, c.notice)
		}
	}
	n := len(f.changeList())
	for _, bad := range []url.Values{{"state": {siem.IncidentFalsePositive}}, {"state": {"bogus"}}, {}, {"state": {"resolved"}, "note": {strings.Repeat("n", siem.MaxNote+1)}}} {
		resp, body := e.detPost(t, "/security/incidents/12/state", sess, csrf, bad)
		if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, `class="error" role="alert"`) {
			t.Errorf("state %v = %d, want 422 with a message", bad, resp.StatusCode)
		}
	}
	for _, p := range []string{"/security/incidents/abc/state", "/security/incidents/0/state"} {
		if resp, _ := e.detPost(t, p, sess, csrf, url.Values{"state": {"resolved"}}); resp.StatusCode != http.StatusNotFound {
			t.Errorf("POST %s = %d, want 404", p, resp.StatusCode)
		}
	}
	if len(f.changeList()) != n {
		t.Error("a rejected state change reached the service")
	}
	rows := secAuditRows(t, e, "security_incident_state")
	if len(rows) != 9 {
		t.Fatalf("audit rows = %d, want 9: %+v", len(rows), rows)
	}
	for i, r := range rows {
		wantOutcome := "ok"
		if i >= 3 {
			wantOutcome = "error"
		}
		wantTarget := "incident:12"
		if i >= 7 {
			wantTarget = "incident"
		}
		if r.Target != wantTarget || r.Outcome != wantOutcome || r.Level != "security" || r.Actor != "operator" {
			t.Errorf("audit row %d = %+v, want target %s outcome %s", i, r, wantTarget, wantOutcome)
		}
		noLeak(t, r, "Looking", "second line", "nnnn")
	}
	if !strings.Contains(rows[0].Detail, "state=acknowledged") || !strings.Contains(rows[0].Detail, "note=yes") || !strings.Contains(rows[1].Detail, "note=no") {
		t.Errorf("audit details = %q, %q", rows[0].Detail, rows[1].Detail)
	}
}

func TestIncidentAssign(t *testing.T) {
	f := newIncFake(time.Now().UTC())
	e := incEnv(t, f)
	sess, csrf := e.detLogin(t, "operator")
	for _, c := range []struct{ assignee, done string }{{"ann", "assigned"}, {"operator", "assigned"}, {"", "unassigned"}} {
		resp, _ := e.detPost(t, "/security/incidents/12/assign", sess, csrf, url.Values{"assignee": {c.assignee}})
		if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || loc != "/security/incidents/12?done="+c.done {
			t.Errorf("assign %q = %d → %q", c.assignee, resp.StatusCode, loc)
		}
		if got, want := f.lastChange(t), (incChange{Method: "Assign", ID: 12, Assignee: c.assignee, Actor: "operator"}); got != want {
			t.Errorf("assign %q: call %+v, want %+v", c.assignee, got, want)
		}
	}
	n := len(f.changeList())
	for _, bad := range []url.Values{{"assignee": {"mallory"}}, {"assignee": {"bob"}}, {"assignee": {"Ann"}}, {"assignee": {"dep"}}, {"assignee": {"vie"}}, {}} {
		resp, body := e.detPost(t, "/security/incidents/12/assign", sess, csrf, bad)
		if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "Pick an owner, or Unassigned.") {
			t.Errorf("assign %v = %d, want 422 with the message", bad, resp.StatusCode)
		}
	}
	if len(f.changeList()) != n {
		t.Error("an assignee who is not an owner reached the service")
	}
	rows := secAuditRows(t, e, "security_incident_assign")
	if len(rows) != 9 {
		t.Fatalf("audit rows = %d, want 9", len(rows))
	}
	for i, r := range rows {
		if r.Target != "incident:12" || (i < 3) != (r.Outcome == "ok") || r.Level != "security" {
			t.Errorf("audit row %d = %+v", i, r)
		}
		noLeak(t, r, "ann", "dep", "vie", "mallory", "bob", "Ann")
	}
	if rows[0].Detail != "assignee=set" || rows[2].Detail != "assignee=none" {
		t.Errorf("audit details %q, %q", rows[0].Detail, rows[2].Detail)
	}
}

func TestIncidentNote(t *testing.T) {
	f := newIncFake(time.Now().UTC())
	e := incEnv(t, f)
	sess, csrf := e.detLogin(t, "operator")
	resp, _ := e.detPost(t, "/security/incidents/12/note", sess, csrf, url.Values{"note": {"Blocked at the firewall.\r\nWatching for 24 h."}})
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || loc != "/security/incidents/12?done=note" {
		t.Errorf("note = %d → %q", resp.StatusCode, loc)
	}
	if got, want := f.lastChange(t), (incChange{Method: "AddNote", ID: 12, Actor: "operator", Text: "Blocked at the firewall.\nWatching for 24 h."}); got != want {
		t.Errorf("note call %+v, want %+v", got, want)
	}
	full := strings.Repeat("é", siem.MaxNote/2) // exactly MaxNote bytes
	if resp, _ := e.detPost(t, "/security/incidents/12/note", sess, csrf, url.Values{"note": {full}}); resp.StatusCode != http.StatusSeeOther {
		t.Errorf("a note of MaxNote bytes = %d, want 303", resp.StatusCode)
	}
	n := len(f.changeList())
	for _, c := range []struct{ note, msg string }{
		{"", "The note is empty."}, {" \r\n\t", "The note is empty."},
		{full + "x", "The note is too long: at most 4,096 bytes."}, {"bad \xff byte", "The note is not valid text."},
	} {
		resp, body := e.detPost(t, "/security/incidents/12/note", sess, csrf, url.Values{"note": {c.note}})
		if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, c.msg) {
			t.Errorf("note %.20q = %d, want 422 with %q", c.note, resp.StatusCode, c.msg)
		}
	}
	// A rejected note is kept in the box.
	_, body := e.detPost(t, "/security/incidents/12/note", sess, csrf, url.Values{"note": {full + "kept"}})
	if !strings.Contains(body, "kept</textarea>") {
		t.Error("a rejected note is not kept in the form")
	}
	if len(f.changeList()) != n {
		t.Error("a rejected note reached the service")
	}
	rows := secAuditRows(t, e, "security_incident_note")
	if len(rows) != 7 {
		t.Fatalf("audit rows = %d, want 7", len(rows))
	}
	for i, r := range rows {
		if r.Target != "incident:12" || (i < 2) != (r.Outcome == "ok") {
			t.Errorf("audit row %d = %+v", i, r)
		}
		noLeak(t, r, "firewall", "Watching", "éé", "bad", "kept")
	}
}

func TestIncidentFalsePositive(t *testing.T) {
	f := newIncFake(time.Now().UTC())
	e := incEnv(t, f)
	sess, csrf := e.detLogin(t, "operator")
	for _, c := range []struct {
		form url.Values
		want incChange
		done string
	}{
		{url.Values{"mute": {"on"}, "note": {"Our own scanner."}, "state": {"acknowledged"}},
			incChange{Method: "MarkFalsePositive", ID: 12, Actor: "operator", Mute: true, Text: "Our own scanner."}, "false_positive_muted"},
		{url.Values{"note": {""}}, incChange{Method: "MarkFalsePositive", ID: 12, Actor: "operator"}, "false_positive"},
	} {
		resp, _ := e.detPost(t, "/security/incidents/12/false-positive", sess, csrf, c.form)
		if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || loc != "/security/incidents/12?done="+c.done {
			t.Errorf("false positive %v = %d → %q", c.form, resp.StatusCode, loc)
		}
		if got := f.lastChange(t); got != c.want {
			t.Errorf("call %+v, want %+v", got, c.want)
		}
	}
	_, body := e.get(t, "/security/incidents/12?done=false_positive_muted", sess)
	if !strings.Contains(body, "Marked as a false positive. Its rules are muted for its accounts and addresses for 30 days.") {
		t.Error("false-positive notice missing")
	}
	n := len(f.changeList())
	resp, _ := e.detPost(t, "/security/incidents/12/false-positive", sess, csrf, url.Values{"note": {strings.Repeat("n", siem.MaxNote+1)}})
	if resp.StatusCode != http.StatusUnprocessableEntity || len(f.changeList()) != n {
		t.Errorf("a too-long note = %d, want 422 and no call", resp.StatusCode)
	}
	rows := secAuditRows(t, e, "security_incident_false_positive")
	if len(rows) != 3 || rows[0].Detail != "mute=yes note=yes" || rows[1].Detail != "mute=no note=no" || rows[2].Outcome != "error" {
		t.Errorf("audit rows = %+v", rows)
	}
	for _, r := range rows {
		noLeak(t, r, "scanner", "nnnn")
	}
}

// A validation error (siem.ErrInvalidInput) is shown with the typed input kept; any other error is
// a generic message on the page and the error in Mooring's log.
func TestIncidentActionErrors(t *testing.T) {
	f := newIncFake(time.Now().UTC())
	e := incEnv(t, f)
	logs := &syncBuffer{}
	e.srv.log = slog.New(slog.NewTextHandler(logs, nil))
	sess, csrf := e.detLogin(t, "operator")
	posts := []struct {
		path, action string
		form         url.Values
	}{
		{"/security/incidents/12/state", "security_incident_state", url.Values{"state": {"resolved"}, "note": {"typed state note"}}},
		{"/security/incidents/12/false-positive", "security_incident_false_positive", url.Values{"mute": {"on"}, "note": {"typed fp note"}}},
		{"/security/incidents/12/assign", "security_incident_assign", url.Values{"assignee": {"ann"}}},
		{"/security/incidents/12/note", "security_incident_note", url.Values{"note": {"typed note"}}},
	}
	f.set(func(f *incFake) {
		f.writeErr = fmt.Errorf(`%w: incident 12 is <b>resolved</b>; reopen it first`, siem.ErrInvalidInput)
	})
	for _, p := range posts {
		resp, body := e.detPost(t, p.path, sess, csrf, p.form)
		msg := detFormError.FindStringSubmatch(body)
		if resp.StatusCode != http.StatusUnprocessableEntity || msg == nil || msg[1] != "The change was not saved: incident 12 is &lt;b&gt;resolved&lt;/b&gt;; reopen it first" {
			t.Errorf("%s validation error = %d, message %q", p.path, resp.StatusCode, msg)
		}
		if note := p.form.Get("note"); note != "" && !strings.Contains(body, ">"+note+"</textarea>") {
			t.Errorf("%s: the typed note is not kept", p.path)
		}
	}
	for _, internal := range []error{
		errors.New("detect: incident queue full: /var/lib/mooring/security-logs/detect.db"),
		fmt.Errorf("detect: %w", context.DeadlineExceeded),
	} {
		f.set(func(f *incFake) { f.writeErr = internal })
		for _, p := range posts {
			resp, body := e.detPost(t, p.path, sess, csrf, p.form)
			msg := detFormError.FindStringSubmatch(body)
			if resp.StatusCode != http.StatusInternalServerError || msg == nil || msg[1] != "The change was not saved. Mooring&#39;s log has the details." {
				t.Errorf("%s %v = %d, message %q", p.path, internal, resp.StatusCode, msg)
			}
			for _, leak := range []string{"queue full", "detect.db", "deadline", "detect:"} {
				if strings.Contains(body, leak) {
					t.Errorf("%s: the page shows %q", p.path, leak)
				}
			}
			if !strings.Contains(logs.String(), internal.Error()) {
				t.Errorf("%v not in Mooring's log", internal)
			}
		}
	}
	for _, p := range posts {
		rows := secAuditRows(t, e, p.action)
		if len(rows) != 3 {
			t.Errorf("%s audit rows = %d, want 3", p.action, len(rows))
		}
		for _, r := range rows {
			if r.Outcome != "error" || r.Target != "incident:12" || strings.Contains(r.Detail, "resolved</b>") || strings.Contains(r.Detail, "queue") {
				t.Errorf("%s audit = %+v", p.action, r)
			}
			noLeak(t, r, "typed", "ann")
		}
	}
	// The change failed and the incident is gone: a not-found page.
	f.set(func(f *incFake) {
		f.writeErr = fmt.Errorf("%w: no such incident", siem.ErrInvalidInput)
	})
	resp, body := e.detPost(t, "/security/incidents/77/state", sess, csrf, url.Values{"state": {"resolved"}})
	if resp.StatusCode != http.StatusNotFound || !strings.Contains(body, "Incident not found") {
		t.Errorf("change of a missing incident = %d", resp.StatusCode)
	}
}

func TestEntityPage(t *testing.T) {
	realQueryParser(t)
	now := time.Now().UTC()
	f := newIncFake(now)
	f.risk = siem.RiskScore{Score: 87.4, Updated: now.Add(-5 * time.Minute), OpenIncidents: 2}
	f.entIncs = f.incs[:1]
	f.mutes = []siem.Mute{{RuleID: "ssh.bruteforce", Entity: addrScan, Until: now.Add(29 * 24 * time.Hour), By: "operator", IncidentID: 12, Created: now.Add(-24 * time.Hour)}}
	e := incEnv(t, f)
	sess := e.loginAs(t, "operator")
	resp, body := e.get(t, "/security/entities?kind=address&key=203.0.113.9", sess)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET entity = %d", resp.StatusCode)
	}
	if got := f.lastEntity(t); got != addrScan {
		t.Errorf("Entity(%+v), want %+v", got, addrScan)
	}
	for _, want := range []string{
		`<h1 class="sec-title">203.0.113.9</h1>`, ">87<", "rises with each detection", "fades", `href="/security/incidents/12"`,
		"Brute force, then a sign-in for alice", "ssh.bruteforce", `href="/security/detections?rule=ssh.bruteforce"`, ">operator<",
		`action="/security/mutes/remove"`, `name="rule" value="ssh.bruteforce"`, `name="kind" value="address"`, `name="key" value="203.0.113.9"`,
		"Find in Security logs",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("entity page missing %q", want)
		}
	}
	links := detSearchLink.FindAllStringSubmatch(body, -1)
	if len(links) != 1 {
		t.Fatalf("search links = %d, want 1", len(links))
	}
	u, _ := url.Parse(html.UnescapeString(links[0][1]))
	if u.Query().Get("q") != "ip:203.0.113.9" || u.Query().Get("range") != "14d" {
		t.Errorf("search link %q, want ip:203.0.113.9 over 14d", links[0][1])
	}

	// An account: its scope is kept, the search is on actor; a /64 address searches the prefix.
	f.set(func(f *incFake) { f.mutes, f.entIncs = nil, nil })
	_, body = e.get(t, "/security/entities?kind=account&key=alice&scope=mooring", sess)
	if got := f.lastEntity(t); got != accAlice {
		t.Errorf("Entity(%+v), want %+v", got, accAlice)
	}
	if links := detSearchLink.FindAllStringSubmatch(body, -1); len(links) != 1 || !strings.Contains(html.UnescapeString(links[0][1]), "q=actor%3Aalice") {
		t.Errorf("account search link = %v", links)
	}
	for _, want := range []string{`<h1 class="sec-title">alice</h1>`, "Mooring user", "No incidents for this account.", "No mutes for this account."} {
		if !strings.Contains(body, want) {
			t.Errorf("account page missing %q", want)
		}
	}
	_, body = e.get(t, "/security/entities?kind=address&key="+url.QueryEscape("2001:db8:1:2::/64"), sess)
	if got := f.lastEntity(t); got.Key != "2001:db8:1:2::/64" {
		t.Errorf("Entity key %q", got.Key)
	}
	if links := detSearchLink.FindAllStringSubmatch(body, -1); len(links) != 1 || !strings.Contains(html.UnescapeString(links[0][1]), url.QueryEscape("ip:2001:db8:1:2::/64")) {
		t.Errorf("prefix search link = %v", links)
	}

	var n int
	f.set(func(f *incFake) { n = len(f.ents) })
	for _, q := range []string{
		"", "kind=bogus&key=x", "kind=account", "kind=account&key=", "kind=address&key=not-an-ip",
		"kind=address&key=203.0.113.9&scope=mooring", "kind=account&key=alice&scope=" + url.QueryEscape("evil scope"),
		"kind=account&key=alice&scope=app:", "kind=account&key=alice&scope=app:" + strings.Repeat("a", 80),
		"kind=account&key=" + strings.Repeat("k", siem.MaxShort+1), "kind=account&key=" + url.QueryEscape("a\nb"),
		"kind=account&key=" + url.QueryEscape("bad\xff"),
	} {
		resp, body := e.get(t, "/security/entities?"+q, sess)
		if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "That is not a valid account or address.") {
			t.Errorf("entity %q = %d, want 400 with the message", q, resp.StatusCode)
		}
	}
	f.set(func(f *incFake) {
		if len(f.ents) != n {
			t.Error("a bad entity reached the service")
		}
	})
	for _, scope := range []string{"host", "app:shop", ""} {
		if resp, _ := e.get(t, "/security/entities?kind=account&key=root&scope="+scope, sess); resp.StatusCode != http.StatusOK {
			t.Errorf("account scope %q = %d, want 200", scope, resp.StatusCode)
		}
	}
	f.set(func(f *incFake) { f.readErr = fmt.Errorf("%w: unknown scope", siem.ErrInvalidInput) })
	if resp, body := e.get(t, "/security/entities?kind=account&key=root&scope=host", sess); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "unknown scope") {
		t.Errorf("an invalid-input read = %d, want 400 with the message", resp.StatusCode)
	}
	f.set(func(f *incFake) { f.readErr = errors.New("detect: SQLITE_BUSY") })
	if resp, body := e.get(t, "/security/entities?kind=account&key=root&scope=host", sess); resp.StatusCode != http.StatusInternalServerError || strings.Contains(body, "SQLITE") ||
		!strings.Contains(body, "could not be read") {
		t.Errorf("a read error = %d, want 500 with the generic message", resp.StatusCode)
	}
}

func TestMuteRemove(t *testing.T) {
	now := time.Now().UTC()
	f := newIncFake(now)
	e := incEnv(t, f)
	logs := &syncBuffer{}
	e.srv.log = slog.New(slog.NewTextHandler(logs, nil))
	sess, csrf := e.detLogin(t, "operator")
	resp, _ := e.detPost(t, "/security/mutes/remove", sess, csrf, url.Values{"rule": {"ssh.bruteforce"}, "kind": {"address"}, "key": {"203.0.113.9"}})
	wantLoc := "/security/entities?done=unmuted&key=203.0.113.9&kind=address"
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || loc != wantLoc {
		t.Errorf("remove = %d → %q, want %q", resp.StatusCode, loc, wantLoc)
	}
	if got, want := f.lastChange(t), (incChange{Method: "RemoveMute", RuleID: "ssh.bruteforce", Entity: addrScan, Actor: "operator"}); got != want {
		t.Errorf("call %+v, want %+v", got, want)
	}
	if _, body := e.get(t, wantLoc, sess); !strings.Contains(body, "Mute removed.") {
		t.Error("the entity page does not confirm the removal")
	}
	resp, _ = e.detPost(t, "/security/mutes/remove", sess, csrf, url.Values{"rule": {"auth.new_country"}, "kind": {"account"}, "key": {"alice"}, "scope": {"mooring"}})
	if loc := resp.Header.Get("Location"); loc != "/security/entities?done=unmuted&key=alice&kind=account&scope=mooring" {
		t.Errorf("account remove → %q", loc)
	}
	n := len(f.changeList())
	for _, bad := range []url.Values{
		{"rule": {"ssh.bruteforce"}, "kind": {"bogus"}, "key": {"x"}},
		{"rule": {"ssh.bruteforce"}, "kind": {"address"}, "key": {"nope"}},
		{"rule": {""}, "kind": {"address"}, "key": {"203.0.113.9"}},
		{"rule": {"a\x00b"}, "kind": {"address"}, "key": {"203.0.113.9"}},
		{"rule": {strings.Repeat("r", siem.MaxShort+1)}, "kind": {"address"}, "key": {"203.0.113.9"}},
	} {
		if resp, _ := e.detPost(t, "/security/mutes/remove", sess, csrf, bad); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("remove %v = %d, want 400", bad, resp.StatusCode)
		}
	}
	if len(f.changeList()) != n {
		t.Error("a bad mute removal reached the service")
	}
	f.set(func(f *incFake) { f.writeErr = fmt.Errorf("%w: no such mute", siem.ErrInvalidInput) })
	resp, body := e.detPost(t, "/security/mutes/remove", sess, csrf, url.Values{"rule": {"ssh.bruteforce"}, "kind": {"address"}, "key": {"203.0.113.9"}})
	if msg := detFormError.FindStringSubmatch(body); resp.StatusCode != http.StatusUnprocessableEntity || msg == nil || msg[1] != "The mute was not removed: no such mute" {
		t.Errorf("invalid removal = %d, message %q", resp.StatusCode, msg)
	}
	f.set(func(f *incFake) { f.writeErr = errors.New("detect: mutes table locked") })
	resp, body = e.detPost(t, "/security/mutes/remove", sess, csrf, url.Values{"rule": {"ssh.bruteforce"}, "kind": {"address"}, "key": {"203.0.113.9"}})
	if msg := detFormError.FindStringSubmatch(body); resp.StatusCode != http.StatusInternalServerError || msg == nil || msg[1] != "The mute was not removed. Mooring&#39;s log has the details." || strings.Contains(body, "locked") {
		t.Errorf("failed removal = %d, message %q", resp.StatusCode, msg)
	}
	if !strings.Contains(logs.String(), "mutes table locked") {
		t.Error("the error is not in Mooring's log")
	}
	rows := secAuditRows(t, e, "security_mute_remove")
	if len(rows) != 9 {
		t.Fatalf("audit rows = %d, want 9", len(rows))
	}
	for i, r := range rows {
		if (i < 2) != (r.Outcome == "ok") || r.Level != "security" {
			t.Errorf("audit row %d = %+v", i, r)
		}
		noLeak(t, r, "203.0.113.9", "alice", "nope")
	}
	if rows[0].Target != "mute:ssh.bruteforce" || rows[1].Target != "mute:auth.new_country" || rows[0].Detail != "kind=address" {
		t.Errorf("audit rows 0/1 = %+v / %+v", rows[0], rows[1])
	}
	for _, r := range rows[2:7] {
		if r.Target != "mute:ssh.bruteforce" && r.Target != "mute" {
			t.Errorf("rejected removal audit target %q", r.Target)
		}
	}
}

// Titles, chain names, entity keys, assignee names, note text, rule names and mutes are attacker-
// or operator-chosen text: every page escapes them, and no page reflects its notice codes.
func TestIncidentPagesEscapeHostileText(t *testing.T) {
	now := time.Now().UTC()
	hostile := siem.Entity{Kind: siem.EntityAccount, Key: `"><script>alert('k')</script>`, Scope: "app:<b>scope</b>"}
	inc := siem.Incident{
		ID: 5, State: siem.IncidentOpen, Severity: `<b>sev</b>`, Title: `<script>alert("t")</script>`, Chain: `<img src=x onerror=alert(1)>`,
		Entities: []siem.Entity{hostile, {Kind: `<i>kind</i>`, Key: `<u>key</u>`}}, First: now, Last: now, Detections: 1,
		Rules: []string{`<svg onload=alert(2)>`}, Assignee: `<svg onload=alert(3)>`, Updated: now,
		Timeline: []siem.IncidentEvent{
			{TS: now, Kind: siem.TimelineNote, Actor: `<s>actor</s>`, Text: `<script>alert("note")</script>`},
			{TS: now, Kind: siem.TimelineDetection, DetectionID: 1, RuleName: `<i>rule</i>`, Severity: `<b>sev</b>`, Text: `<img src=y>`},
			{TS: now, Kind: `<b>kind</b>`, Text: `<u>text</u>`},
			{TS: now, Kind: siem.TimelineAssigned, Text: `<svg onload=alert(4)>`},
		},
		Mutes: []siem.Mute{{RuleID: `<u>r</u>`, Entity: hostile, By: `<s>by</s>`, IncidentID: 5, Until: now.Add(time.Hour)}},
	}
	f := &incFake{incs: []siem.Incident{inc}, entIncs: []siem.Incident{inc},
		risky: []siem.RiskScore{{Entity: hostile, Score: 50}},
		mutes: []siem.Mute{{RuleID: `<u>r</u>`, Entity: addrScan, By: `<s>by</s>`, IncidentID: 5, Until: now.Add(time.Hour)}}}
	e := incEnv(t, f)
	sess := e.loginAs(t, "operator")
	for _, p := range []string{
		"/security/incidents", "/security/incidents/rows", "/security/incidents/5", "/security/entities?kind=address&key=203.0.113.9",
		"/security/incidents?assignee=" + url.QueryEscape(`<script>alert("f")</script>`),
		"/security/incidents/5?done=" + url.QueryEscape("<b>x</b>"), "/security/entities?kind=address&key=203.0.113.9&done=" + url.QueryEscape("<b>x</b>"),
	} {
		resp, body := e.get(t, p, sess)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d", p, resp.StatusCode)
		}
		for _, bad := range []string{"<script>alert", "<img src=", "<svg onload", "<b>sev", "<i>rule", "<u>r<", "<s>by", "<s>actor", "<b>kind", "<u>text", "<i>kind", "<u>key", "<b>scope", "<b>x", "&lt;b&gt;x", "ZgotmplZ"} {
			if strings.Contains(body, bad) {
				t.Errorf("GET %s: unescaped %q", p, bad)
			}
		}
	}
}

// A detection muted by a false positive says so, next to snoozed.
func TestDetectionsMutedMarker(t *testing.T) {
	now := time.Now().UTC()
	dets := detFixtures(now)
	dets[0].Muted = true
	e := detEnv(t, &detFakeService{rules: detRules(), dets: dets}, nil)
	sess := e.loginAs(t, "operator")
	const marker = `>Muted</span>`
	for _, p := range []string{"/security/detections", "/security/detections/rows", "/security/detections/7"} {
		if _, body := e.get(t, p, sess); strings.Count(body, marker) != 1 {
			t.Errorf("%s: muted markers = %d, want 1", p, strings.Count(body, marker))
		}
	}
	if _, body := e.get(t, "/security/detections/6", sess); strings.Contains(body, marker) {
		t.Error("an unmuted detection shows the muted marker")
	}
}

func baselineRules() []siem.Rule {
	return []siem.Rule{
		{ID: "baseline.signin", Name: "Unusual sign-in", Type: siem.RuleBaseline, Baseline: siem.BaselineSignIn, Severity: siem.SevMedium,
			Query: "kind:auth.login out:success", GroupBy: "actor", Learn: 14 * 24 * time.Hour, Enabled: true, Builtin: true},
		{ID: "baseline.traffic", Name: "Traffic surge or drop", Type: siem.RuleBaseline, Baseline: siem.BaselineTraffic, Severity: siem.SevHigh,
			Query: "src:edge", GroupBy: "f.host", Count: 100, Window: time.Hour, Factor: 3, Learn: 21 * 24 * time.Hour, SpeedKMH: 900, Enabled: true, Builtin: true},
		{ID: "baseline.admin", Name: "Unusual admin activity", Type: siem.RuleBaseline, Baseline: siem.BaselineAdmin, Severity: siem.SevHigh,
			GroupBy: "actor", Learn: 14 * 24 * time.Hour, Builtin: true},
		{ID: "baseline.ip", Name: "Address behavior change", Type: siem.RuleBaseline, Baseline: siem.BaselineIP, Severity: siem.SevLow,
			GroupBy: "ip", Factor: 4, Learn: 7 * 24 * time.Hour, Enabled: true, Builtin: true},
	}
}

func TestSecurityRulesBaseline(t *testing.T) {
	f := &detFakeService{rules: append(detRules(), baselineRules()...)}
	e := detEnv(t, f, nil)
	sess, csrf := e.detLogin(t, "operator")
	_, body := e.get(t, "/security/rules", sess)
	for _, want := range []string{
		"Baseline: sign-in pattern", "Baseline: traffic volume", "Baseline: admin activity", "Baseline: address behavior",
		"usual sign-in hours, countries, networks and clients after 14d of learning per actor",
		"requests and errors per hour of the week", "after 21d of learning per f.host",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("rules page missing %q", want)
		}
	}
	for id, shown := range map[string][]string{
		"baseline.signin":  {"learn"},
		"baseline.traffic": {"count", "window", "factor", "learn"},
		"baseline.admin":   {"learn"},
		"baseline.ip":      {"factor", "learn"},
	} {
		_, body := e.get(t, "/security/rules/edit?id="+id, sess)
		for _, field := range []string{"count", "window", "factor", "learn"} {
			if got := strings.Contains(body, `name="`+field+`"`); got != slices.Contains(shown, field) {
				t.Errorf("%s: input %s shown = %v, want %v", id, field, got, !got)
			}
		}
		for _, field := range []string{"speed_kmh", "query", "then", "group_by", "field", "type", "name", "slug", "mitre"} {
			if strings.Contains(body, `name="`+field+`"`) {
				t.Errorf("%s: the form has an input for %s", id, field)
			}
		}
		for _, want := range []string{`name="enabled"`, `name="severity"`, "Learns"} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: the form is missing %q", id, want)
			}
		}
	}
	// A save takes the shown tunables only.
	resp, _ := e.detPost(t, "/security/rules/save", sess, csrf, url.Values{
		"id": {"baseline.traffic"}, "severity": {"critical"}, "count": {"200"}, "window": {"2h"}, "factor": {"4"}, "learn": {"28d"},
		"speed_kmh": {"5"}, "query": {"kind:evil"}, "type": {"threshold"}, "enabled": {"on"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("baseline save = %d", resp.StatusCode)
	}
	got := f.lastSaved(t)
	if got.Type != siem.RuleBaseline || got.Baseline != siem.BaselineTraffic || got.Query != "src:edge" || got.SpeedKMH != 900 ||
		got.Count != 200 || got.Window != 2*time.Hour || got.Factor != 4 || got.Learn != 28*24*time.Hour || got.Severity != siem.SevCritical {
		t.Errorf("saved %+v", got)
	}
	// The custom form never offers the baseline type, and a crafted one is refused.
	_, body = e.get(t, "/security/rules/new", sess)
	if strings.Contains(body, `value="baseline"`) {
		t.Error("the custom-rule form offers the baseline type")
	}
	n := f.savedCount()
	resp, body = e.detPost(t, "/security/rules/save", sess, csrf, url.Values{"slug": {"mine"}, "name": {"Mine"}, "type": {"baseline"}, "severity": {"low"}, "query": {"kind:x"}})
	if resp.StatusCode != http.StatusUnprocessableEntity || f.savedCount() != n || !strings.Contains(body, "Baseline rules are built in") {
		t.Errorf("custom baseline = %d, saved %d more", resp.StatusCode, f.savedCount()-n)
	}
	if strings.Contains(body, `value="baseline"`) {
		t.Error("the re-rendered custom form offers the baseline type")
	}
}

// The Incidents tab sits between Detections and Rules and marks its pages.
func TestSecurityIncidentsTab(t *testing.T) {
	e := incEnv(t, newIncFake(time.Now().UTC()))
	e.srv.detections = &detFakeService{rules: detRules()}
	sess := e.loginAs(t, "operator")
	for _, p := range []string{"/security/incidents", "/security/incidents/12", "/security/entities?kind=address&key=203.0.113.9", "/security/detections", "/security/rules"} {
		_, body := e.get(t, p, sess)
		start := strings.Index(body, `<nav class="subnav"`)
		end := strings.Index(body[max(start, 0):], `</nav>`)
		if start < 0 || end < 0 {
			t.Fatalf("%s: no tabs", p)
		}
		nav := body[start : start+end]
		i, j, k, l := strings.Index(nav, `href="/security"`), strings.Index(nav, `href="/security/detections"`), strings.Index(nav, `href="/security/incidents"`), strings.Index(nav, `href="/security/rules"`)
		if i < 0 || j < i || k < j || l < k {
			t.Errorf("%s: tabs out of order (Search %d, Detections %d, Incidents %d, Rules %d)", p, i, j, k, l)
		}
		active := strings.Contains(body, `aria-current="page">Incidents</a>`)
		if want := strings.Contains(p, "/incidents") || strings.Contains(p, "/entities"); active != want {
			t.Errorf("%s: Incidents tab active = %v, want %v", p, active, want)
		}
		if strings.Count(body, `aria-current="page"`) != 1 {
			t.Errorf("%s: want exactly one active tab", p)
		}
	}
}
