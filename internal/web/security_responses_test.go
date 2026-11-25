package web

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/blocklist"
	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/siem"
)

// respFake is a siem.ResponseService in memory. Responses applies the filter the way the contract
// says (newest first by ID, keyset Before, Limit); every change is recorded.
type respFake struct {
	mu        sync.Mutex
	status    siem.ResponseStatus
	statusErr error
	resps     []siem.Response
	readErr   error
	changeErr error                       // Apply, Dismiss, SetPause
	onApply   func(f *respFake, id int64) // runs inside Apply (the lock held)
	lifted    int
	liftErr   error
	filters   []siem.ResponseFilter
	gets      []int64
	changes   []respChangeRec
	// ignoreDetection: Responses ignores ResponseFilter.DetectionID (a service without the filter).
	ignoreDetection bool
}

type respChangeRec struct {
	Method string // Apply, Dismiss, SetPause, LiftForIncident
	ID     int64
	Level  string
	Actor  string
}

func (f *respFake) Status(context.Context) (siem.ResponseStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status, f.statusErr
}

func (f *respFake) Responses(_ context.Context, fl siem.ResponseFilter) ([]siem.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.filters = append(f.filters, fl)
	if f.readErr != nil {
		return nil, f.readErr
	}
	all := slices.Clone(f.resps)
	slices.SortFunc(all, func(a, b siem.Response) int { return cmp.Compare(b.ID, a.ID) })
	var out []siem.Response
	for _, r := range all {
		if (len(fl.States) > 0 && !slices.Contains(fl.States, r.State)) || (fl.Action != "" && r.Action != fl.Action) ||
			(fl.IncidentID != 0 && r.IncidentID != fl.IncidentID) || (fl.Before > 0 && r.ID >= fl.Before) ||
			(fl.DetectionID != 0 && !f.ignoreDetection && r.DetectionID != fl.DetectionID) {
			continue
		}
		out = append(out, r)
		if fl.Limit > 0 && len(out) == fl.Limit {
			break
		}
	}
	return out, nil
}

func (f *respFake) Response(_ context.Context, id int64) (siem.Response, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets = append(f.gets, id)
	if f.readErr != nil {
		return siem.Response{}, false, f.readErr
	}
	for _, r := range f.resps {
		if r.ID == id {
			return r, true, nil
		}
	}
	return siem.Response{}, false, nil
}

func (f *respFake) change(c respChangeRec) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.changes = append(f.changes, c)
	if c.Method == "Apply" && f.onApply != nil {
		f.onApply(f, c.ID)
	}
	return f.changeErr
}

func (f *respFake) Apply(_ context.Context, id int64, actor string) error {
	return f.change(respChangeRec{Method: "Apply", ID: id, Actor: actor})
}

func (f *respFake) Dismiss(_ context.Context, id int64, actor string) error {
	return f.change(respChangeRec{Method: "Dismiss", ID: id, Actor: actor})
}

func (f *respFake) SetPause(_ context.Context, level, actor string) error {
	return f.change(respChangeRec{Method: "SetPause", Level: level, Actor: actor})
}

func (f *respFake) LiftForIncident(_ context.Context, id int64, actor string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.changes = append(f.changes, respChangeRec{Method: "LiftForIncident", ID: id, Actor: actor})
	return f.lifted, f.liftErr
}

func (f *respFake) changeList() []respChangeRec {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.changes)
}

func (f *respFake) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.filters) + len(f.gets) + len(f.changes)
}

func (f *respFake) lastFilter(t *testing.T) siem.ResponseFilter {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.filters) == 0 {
		t.Fatal("Responses was not called")
	}
	return f.filters[len(f.filters)-1]
}

// blockFake is a blocklist.Service in memory; every call is recorded.
type blockFake struct {
	mu         sync.Mutex
	status     blocklist.Status
	list       []blocklist.Block
	byPrefix   map[netip.Prefix]blocklist.Block // Get
	refusals   []blocklist.Refusal
	listErr    error
	getErr     error
	refErr     error
	blockErr   error
	unblockErr error
	reqs       []blocklist.Request
	unblocks   []string // "prefix by"
	gets       []netip.Prefix
	lists      []blocklist.Filter
}

func (f *blockFake) Block(_ context.Context, r blocklist.Request) (blocklist.Block, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reqs = append(f.reqs, r)
	if f.blockErr != nil {
		return blocklist.Block{}, f.blockErr
	}
	return blocklist.Block{Prefix: netip.MustParsePrefix(r.Prefix), Source: r.Source, State: blocklist.StateActive}, nil
}

func (f *blockFake) Unblock(_ context.Context, p netip.Prefix, by string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unblocks = append(f.unblocks, p.String()+" "+by)
	return f.unblockErr
}

func (f *blockFake) UnblockIncident(context.Context, int64, string, time.Duration) (int, error) {
	return 0, errors.New("not used by the dashboard")
}

func (f *blockFake) LiftAutomatic(context.Context, string, string) (int, error) {
	return 0, errors.New("not used by the dashboard")
}

func (f *blockFake) List(_ context.Context, fl blocklist.Filter) ([]blocklist.Block, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lists = append(f.lists, fl)
	if f.listErr != nil {
		return nil, f.listErr
	}
	var out []blocklist.Block
	for _, b := range f.list {
		if (len(fl.States) == 0 || slices.Contains(fl.States, b.State)) && (fl.Source == "" || fl.Source == b.Source) {
			out = append(out, b)
		}
	}
	return out, nil
}

func (f *blockFake) Get(_ context.Context, p netip.Prefix) (blocklist.Block, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets = append(f.gets, p)
	if f.getErr != nil {
		return blocklist.Block{}, false, f.getErr
	}
	b, ok := f.byPrefix[p]
	return b, ok, nil
}

func (f *blockFake) Refusals(_ context.Context, limit int) ([]blocklist.Refusal, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.refErr != nil {
		return nil, f.refErr
	}
	return slices.Clone(f.refusals[:min(limit, len(f.refusals))]), nil
}

// Blocked is true for an address inside an active block of the list.
func (f *blockFake) Blocked(a netip.Addr) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, b := range f.list {
		if b.State == blocklist.StateActive && b.Prefix.Contains(a) {
			return true
		}
	}
	return false
}

func (f *blockFake) Status() blocklist.Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status
}

func (f *blockFake) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.reqs) + len(f.unblocks) + len(f.gets) + len(f.lists)
}

func (f *blockFake) reqList() []blocklist.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.reqs)
}

func (f *blockFake) unblockList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.unblocks)
}

func respFixtures(now time.Time) []siem.Response {
	return []siem.Response{
		{ID: 31, Action: siem.ResponseBlock, Target: "203.0.113.9/32", State: siem.ResponseRecommended, Automatic: false, RuleID: "app.bruteforce",
			DetectionID: 501, IncidentID: 12, Summary: "40 failed sign-ins <b>from</b> 203.0.113.9", Duration: time.Hour, Created: now.Add(-10 * time.Minute)},
		{ID: 30, Action: siem.ResponseRevoke, Target: "alice", State: siem.ResponseRecommended, RuleID: "mooring.login_new_country",
			DetectionID: 500, IncidentID: 12, Summary: "alice signed in from a new country", Created: now.Add(-20 * time.Minute)},
		{ID: 29, Action: siem.ResponseBlock, Target: "198.51.100.7/32", State: siem.ResponseApplied, Automatic: true, RuleID: "edge.scan",
			DetectionID: 499, Duration: 4 * time.Hour, Created: now.Add(-time.Hour), By: ""},
		{ID: 28, Action: siem.ResponseBlock, Target: "192.0.2.1/32", State: siem.ResponseRefused, Reason: blocklist.RefuseAllowlist, Automatic: true,
			RuleID: "edge.scan", DetectionID: 498, Created: now.Add(-2 * time.Hour)},
		{ID: 27, Action: siem.ResponseRevoke, Target: "bob", State: siem.ResponseFailed, Reason: "no_revoker", RuleID: "mooring.login_tor",
			Created: now.Add(-3 * time.Hour)},
		{ID: 26, Action: siem.ResponseBlock, Target: "203.0.113.50/32", State: siem.ResponseDismissed, By: "operator", RuleID: "app.bruteforce",
			Created: now.Add(-4 * time.Hour)},
	}
}

func newRespFake(now time.Time) *respFake {
	return &respFake{resps: respFixtures(now), status: siem.ResponseStatus{
		Mode: siem.ResponseModeEnforce, Effective: siem.ResponseModeEnforce, BlocksThisHour: 3, MaxBlocksPerHour: 60,
		RevokesThisHour: 3, MaxRevokesPerHour: 3, Revoker: true,
	}}
}

func newBlockFake(now time.Time) *blockFake {
	return &blockFake{
		status: blocklist.Status{EdgeOwned: true, Automatic: true, ActiveAuto: 1, MaxAuto: 1000, ActiveManual: 1, MaxManual: 1000, Applied: true, LastApplied: now.Add(-time.Minute)},
		list: []blocklist.Block{
			{Prefix: netip.MustParsePrefix("198.51.100.7/32"), Source: blocklist.SourceAuto, RuleID: "edge.scan", Reason: "Scanning <i>paths</i>", State: blocklist.StateActive,
				Until: now.Add(3 * time.Hour), Hits: 2, IncidentID: 9, Created: now.Add(-time.Hour)},
			{Prefix: netip.MustParsePrefix("203.0.113.0/24"), Source: blocklist.SourceManual, By: "operator", Reason: "Credential stuffing", State: blocklist.StateSuspended,
				SuspendedWhy: blocklist.RefuseSession, Until: now.Add(48 * time.Hour), Hits: 1},
		},
		byPrefix: map[netip.Prefix]blocklist.Block{
			netip.MustParsePrefix("198.51.100.7/32"): {Prefix: netip.MustParsePrefix("198.51.100.7/32"), Source: blocklist.SourceAuto, State: blocklist.StateActive, Until: now.Add(3 * time.Hour)},
		},
		refusals: []blocklist.Refusal{{Prefix: "192.0.2.1/32", Code: blocklist.RefuseAllowlist, Detail: "in 192.0.2.0/24", Source: blocklist.SourceAuto, RuleID: "edge.scan", Count: 4, Last: now.Add(-time.Hour)}},
	}
}

// respEnv is detEnv with the responder and the block list set (nil = off).
func respEnv(t *testing.T, f *respFake, b *blockFake) *testEnv {
	t.Helper()
	e := detEnv(t, &detFakeService{rules: detRules()}, nil)
	if f != nil {
		e.srv.responses = f
	}
	if b != nil {
		e.srv.blocks = b
	}
	return e
}

var (
	respGetPaths  = []string{"/security/responses", "/security/blocks"}
	respPostPaths = []string{"/security/responses/pause", "/security/responses/31/apply", "/security/responses/31/dismiss", "/security/blocks/add", "/security/blocks/remove"}
)

func respPostForm() url.Values {
	return url.Values{"level": {"off"}, "prefix": {"203.0.113.7"}, "duration": {"24h"}}
}

func TestResponsePagesOwnerOnly(t *testing.T) {
	now := time.Now().UTC()
	f, b := newRespFake(now), newBlockFake(now)
	e := respEnv(t, f, b)
	for _, user := range []string{"dep", "vie"} {
		sess, csrf := e.detLogin(t, user)
		for _, p := range respGetPaths {
			resp, body := e.get(t, p, sess)
			if resp.StatusCode != http.StatusForbidden || strings.Contains(body, "203.0.113") {
				t.Errorf("%s GET %s = %d, want 403 and no data", user, p, resp.StatusCode)
			}
		}
		for _, p := range respPostPaths {
			if resp, _ := e.detPost(t, p, sess, csrf, respPostForm()); resp.StatusCode != http.StatusForbidden {
				t.Errorf("%s POST %s = %d, want 403", user, p, resp.StatusCode)
			}
		}
	}
	if f.calls() != 0 || b.calls() != 0 {
		t.Fatalf("non-owners reached the services (responses %d, blocks %d)", f.calls(), b.calls())
	}
	owner := e.loginAs(t, "operator")
	for _, p := range respGetPaths {
		if resp, _ := e.get(t, p, owner); resp.StatusCode != http.StatusOK {
			t.Errorf("owner GET %s = %d, want 200", p, resp.StatusCode)
		}
	}
}

func TestResponsePostsRequireCSRFAndCapBody(t *testing.T) {
	now := time.Now().UTC()
	f, b := newRespFake(now), newBlockFake(now)
	e := respEnv(t, f, b)
	sess, csrf := e.detLogin(t, "operator")
	for _, p := range respPostPaths {
		resp := e.req(t, "POST", p, secPeer, map[string]string{"Origin": "https://example.com"}, []*http.Cookie{sess, csrf}, respPostForm())
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("POST %s without a token = %d, want 403", p, resp.StatusCode)
		}
		form := respPostForm()
		form.Set("csrf_token", "not-the-token")
		if resp, _ := e.detPost(t, p, sess, csrf, form); resp.StatusCode != http.StatusForbidden {
			t.Errorf("POST %s with a wrong token = %d, want 403", p, resp.StatusCode)
		}
		form = respPostForm()
		form.Set("pad", strings.Repeat("x", loginBodyLimit))
		resp = e.req(t, "POST", p, secPeer, map[string]string{"Origin": "https://example.com", "X-CSRF-Token": csrf.Value}, []*http.Cookie{sess, csrf}, form)
		if resp.StatusCode < 400 {
			t.Errorf("POST %s with an oversized body = %d, want a 4xx", p, resp.StatusCode)
		}
	}
	if c := f.changeList(); len(c) != 0 {
		t.Errorf("a refused POST changed a response: %+v", c)
	}
	if len(b.reqList()) != 0 || len(b.unblockList()) != 0 {
		t.Error("a refused POST changed the block list")
	}
}

func TestResponsePagesOff(t *testing.T) {
	e := detEnv(t, nil, nil) // detection off
	sess, csrf := e.detLogin(t, "operator")
	if resp, body := e.get(t, "/security/responses", sess); resp.StatusCode != http.StatusOK || !strings.Contains(body, "Detection is off") {
		t.Errorf("responses (detection off) = %d", resp.StatusCode)
	}
	e = respEnv(t, nil, nil) // detection on, no responder, no block list
	sess, csrf = e.detLogin(t, "operator")
	resp, body := e.get(t, "/security/responses", sess)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Automated response is not running") || !strings.Contains(body, "security_logs.response.mode") {
		t.Errorf("responses off = %d, want the not-running panel", resp.StatusCode)
	}
	e.srv.edgeReason = "edge.mode is external"
	resp, body = e.get(t, "/security/blocks", sess)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "The block list is not available") || !strings.Contains(body, "edge.mode is external") {
		t.Errorf("blocks off = %d, want the unavailable panel with the edge's reason", resp.StatusCode)
	}
	for _, p := range respPostPaths {
		resp, body := e.detPost(t, p, sess, csrf, respPostForm())
		if resp.StatusCode != http.StatusServiceUnavailable || (!strings.Contains(body, "Automated response is not running") && !strings.Contains(body, "The block list is not available")) {
			t.Errorf("POST %s (off) = %d, want 503 with the off panel", p, resp.StatusCode)
		}
	}
	// The incident, detection and entity pages work without them.
	e.srv.incidentSvc = newIncFake(time.Now().UTC())
	for _, p := range []string{"/security/incidents/12", "/security/entities?kind=address&key=203.0.113.9"} {
		if resp, body := e.get(t, p, sess); resp.StatusCode != http.StatusOK || strings.Contains(body, ">Responses</h2>") || strings.Contains(body, "Edge block") {
			t.Errorf("GET %s without responses/blocks = %d (or shows their panels)", p, resp.StatusCode)
		}
	}
}

func TestResponsesPage(t *testing.T) {
	now := time.Now().UTC()
	f, b := newRespFake(now), newBlockFake(now)
	e := respEnv(t, f, b)
	sess := e.loginAs(t, "operator")
	resp, body := e.get(t, "/security/responses", sess)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET = %d", resp.StatusCode)
	}
	for _, want := range []string{
		">Enforce<", "Automatic responses are applied within the hourly caps", "3<small> / 60", "3<small> / 3", "Cap reached: further sign-outs",
		`name="level" value="recommend"`, `name="level" value="off"`, "Every automatic block is removed now.", ">Pause to recommend only<",
		// recommended
		"Block 203.0.113.9/32 for 1 hour", "Sign out alice", `action="/security/responses/31/apply"`, `action="/security/responses/30/dismiss"`,
		"Sign alice out of every dashboard session?", "40 failed sign-ins &lt;b&gt;from&lt;/b&gt;",
		// history
		"Block 198.51.100.7/32 for 4 hours", ">Applied<", ">Refused<", ">It overlaps ip_allowlist<", ">Dashboard sign-outs are not available<", "by operator",
		`href="/security/detections/499"`, `href="/security/incidents/12"`, `id="resp-29"`, `href="/security/responses?before=30#resp-29"`,
		// the block now, from the list
		">Blocked<", ">Not blocked<", "Blocked addresses", "<th>Block state</th><th>From</th><th></th>", "<th>Block state</th><th>From</th></tr>",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
	if strings.Contains(body, "Block now") {
		t.Error("a column is still headed Block now")
	}
	if strings.Contains(body, "<b>from</b>") {
		t.Error("a summary reached the page unescaped")
	}
	b.mu.Lock()
	gets := slices.Clone(b.gets)
	b.mu.Unlock()
	// One lookup per block address (203.0.113.9 shows in both lists), none for sign-outs.
	if len(gets) != 4 || !slices.Contains(gets, netip.MustParsePrefix("198.51.100.7/32")) {
		t.Errorf("Get calls = %v", gets)
	}

	// Filters and keyset paging.
	e.get(t, "/security/responses?state=applied&action=block&before=30", sess)
	if fl := f.lastFilter(t); !slices.Equal(fl.States, []string{"applied"}) || fl.Action != "block" || fl.Before != 30 || fl.Limit != respPageSize+1 {
		t.Errorf("history filter = %+v", fl)
	}
	e.get(t, "/security/responses?state=bogus&action=lock&before=-1", sess)
	if fl := f.lastFilter(t); len(fl.States) != 0 || fl.Action != "" || fl.Before != 0 {
		t.Errorf("unknown values: filter = %+v, want them ignored", fl)
	}
	many := make([]siem.Response, 0, 60)
	for i := 1; i <= 60; i++ {
		many = append(many, siem.Response{ID: int64(i), Action: siem.ResponseRevoke, Target: "u", State: siem.ResponseApplied, Created: now})
	}
	f.mu.Lock()
	f.resps = many
	f.mu.Unlock()
	_, body = e.get(t, "/security/responses?action=revoke", sess)
	if !strings.Contains(body, `href="/security/responses?action=revoke&amp;before=11">Older responses`) || strings.Contains(body, "Newest responses") {
		t.Error("first page: want an Older link from the last row shown")
	}
	_, body = e.get(t, "/security/responses?action=revoke&before=11", sess)
	if !strings.Contains(body, `href="/security/responses?action=revoke">Newest responses`) || strings.Contains(body, "Older responses") {
		t.Error("last page: want a Newest link only")
	}
}

func TestResponsesStatusStates(t *testing.T) {
	now := time.Now().UTC()
	for _, c := range []struct {
		name  string
		st    siem.ResponseStatus
		want  []string
		never []string
	}{
		{"configured off", siem.ResponseStatus{Mode: "off", Effective: "off", Revoker: true},
			[]string{"Automated response is off", "set <code>security_logs.response.mode</code> to <code>recommend</code> or <code>enforce</code>", "restart Mooring"},
			[]string{`name="level"`}},
		{"paused off", siem.ResponseStatus{Mode: "enforce", Paused: "off", PausedBy: "ann", PausedAt: now.Add(-time.Hour), Effective: "off"},
			[]string{"Paused by ann on", "Lift the pause to go back to <strong>Enforce</strong>", `name="level" value=""`, "Not available", "Sign-out responses are refused"},
			[]string{`name="level" value="off"`, `name="level" value="recommend"`}},
		{"paused recommend", siem.ResponseStatus{Mode: "enforce", Paused: "recommend", PausedBy: "ann", Effective: "recommend", Revoker: true},
			[]string{"recorded as recommendations", "Paused to recommend only by ann", `name="level" value=""`, `name="level" value="off"`},
			[]string{`name="level" value="recommend"`}},
		{"recommend", siem.ResponseStatus{Mode: "recommend", Effective: "recommend", Revoker: true},
			[]string{"recorded as recommendations", `name="level" value="off"`},
			[]string{`name="level" value="recommend"`, `name="level" value=""`}},
	} {
		f := &respFake{status: c.st}
		e := respEnv(t, f, nil)
		sess := e.loginAs(t, "operator")
		_, body := e.get(t, "/security/responses", sess)
		for _, w := range c.want {
			if !strings.Contains(body, w) {
				t.Errorf("%s: missing %q", c.name, w)
			}
		}
		for _, w := range c.never {
			if strings.Contains(body, w) {
				t.Errorf("%s: has %q", c.name, w)
			}
		}
		if !strings.Contains(body, "No recommendations are waiting.") || !strings.Contains(body, "No responses") {
			t.Errorf("%s: want the empty states", c.name)
		}
	}
	// Read errors: a generic message and a 500.
	f := &respFake{statusErr: errors.New("db at /var/lib/x"), readErr: errors.New("db at /var/lib/x")}
	e := respEnv(t, f, nil)
	sess := e.loginAs(t, "operator")
	resp, body := e.get(t, "/security/responses", sess)
	if resp.StatusCode != http.StatusInternalServerError || strings.Contains(body, "/var/lib/x") || strings.Count(body, "log has the details") != 3 {
		t.Errorf("read errors = %d", resp.StatusCode)
	}
}

func TestResponseApplyDismiss(t *testing.T) {
	now := time.Now().UTC()
	f := newRespFake(now)
	e := respEnv(t, f, newBlockFake(now))
	sess, csrf := e.detLogin(t, "operator")
	for _, c := range []struct{ path, done string }{
		{"/security/responses/31/apply", "applied"}, {"/security/responses/30/dismiss", "dismissed"},
	} {
		resp, _ := e.detPost(t, c.path, sess, csrf, url.Values{})
		if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || loc != "/security/responses?done="+c.done {
			t.Errorf("POST %s = %d → %q", c.path, resp.StatusCode, loc)
		}
	}
	if got := f.changeList(); !slices.Equal(got, []respChangeRec{{Method: "Apply", ID: 31, Actor: "operator"}, {Method: "Dismiss", ID: 30, Actor: "operator"}}) {
		t.Errorf("calls = %+v", got)
	}
	if _, body := e.get(t, "/security/responses?done=applied", sess); !strings.Contains(body, "Response applied.") {
		t.Error("done notice missing")
	}
	// Not found: no call.
	n := len(f.changeList())
	for _, p := range []string{"/security/responses/999/apply", "/security/responses/x/apply", "/security/responses/0/dismiss"} {
		if resp, body := e.detPost(t, p, sess, csrf, url.Values{}); resp.StatusCode != http.StatusNotFound || !strings.Contains(body, "Response not found.") {
			t.Errorf("POST %s = %d, want 404", p, resp.StatusCode)
		}
	}
	if len(f.changeList()) != n {
		t.Error("an unknown response reached Apply/Dismiss")
	}
	// A block the list refused, told in words.
	f.mu.Lock()
	f.changeErr = fmt.Errorf("apply: %w", &blocklist.RefusedError{Code: blocklist.RefuseAllowlist, Detail: "in 203.0.113.0/24"})
	f.mu.Unlock()
	resp, body := e.detPost(t, "/security/responses/31/apply", sess, csrf, url.Values{})
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "The block was refused: it overlaps ip_allowlist (in 203.0.113.0/24).") {
		t.Errorf("refused block = %d", resp.StatusCode)
	}
	// A refusal the responder recorded on the response (a cap, no revoker …): its reason code.
	f.mu.Lock()
	f.changeErr = errors.New("revoke refused: internal text /var/lib/x")
	f.onApply = func(f *respFake, id int64) {
		for i := range f.resps {
			if f.resps[i].ID == id {
				f.resps[i].State, f.resps[i].Reason = siem.ResponseRefused, "revoke_cap"
			}
		}
	}
	f.mu.Unlock()
	resp, body = e.detPost(t, "/security/responses/30/apply", sess, csrf, url.Values{})
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "The response was not applied: revoke cap.") || strings.Contains(body, "/var/lib/x") {
		t.Errorf("recorded refusal = %d", resp.StatusCode)
	}
	// As the responder answers a block the list refused: its own text as invalid input, the code
	// recorded on the response. The page tells the code in words.
	f.mu.Lock()
	f.resps = respFixtures(now)
	f.changeErr = fmt.Errorf("%w: block refused: allowlist: in 203.0.113.0/24", siem.ErrInvalidInput)
	f.onApply = func(f *respFake, id int64) {
		for i := range f.resps {
			if f.resps[i].ID == id {
				f.resps[i].State, f.resps[i].Reason = siem.ResponseRefused, blocklist.RefuseAllowlist
			}
		}
	}
	f.mu.Unlock()
	resp, body = e.detPost(t, "/security/responses/31/apply", sess, csrf, url.Values{})
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "The response was not applied: it overlaps ip_allowlist.") || strings.Contains(body, "block refused: allowlist") {
		t.Errorf("responder refusal = %d", resp.StatusCode)
	}
	// A failure it recorded: the code in words, audited as failed.
	f.mu.Lock()
	f.resps = respFixtures(now)
	f.changeErr = errors.New("respond: response 30: revoke: db locked")
	f.onApply = func(f *respFake, id int64) {
		for i := range f.resps {
			if f.resps[i].ID == id {
				f.resps[i].State, f.resps[i].Reason = siem.ResponseFailed, "error"
			}
		}
	}
	f.mu.Unlock()
	resp, body = e.detPost(t, "/security/responses/30/apply", sess, csrf, url.Values{})
	if resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "The response was not applied: it failed;") || strings.Contains(body, "db locked") {
		t.Errorf("recorded failure = %d", resp.StatusCode)
	}
	// Validation text is shown (a response that wasn't a recommendation); anything else is generic.
	f.mu.Lock()
	f.onApply = nil
	f.resps = respFixtures(now)
	f.changeErr = fmt.Errorf("%w: not a recommendation", siem.ErrInvalidInput)
	f.mu.Unlock()
	if resp, body := e.detPost(t, "/security/responses/29/apply", sess, csrf, url.Values{}); resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "The response was not applied: not a recommendation") {
		t.Errorf("invalid input = %d", resp.StatusCode)
	}
	f.mu.Lock()
	f.changeErr = errors.New("sqlite busy at /var/lib/x")
	f.mu.Unlock()
	if resp, body := e.detPost(t, "/security/responses/26/dismiss", sess, csrf, url.Values{}); resp.StatusCode != http.StatusInternalServerError || strings.Contains(body, "/var/lib/x") || !strings.Contains(body, "The recommendation was not dismissed. Mooring") {
		t.Errorf("internal error = %d", resp.StatusCode)
	}
	var got []string
	for _, a := range []string{"security_response_apply", "security_response_dismiss"} {
		for _, r := range secAuditRows(t, e, a) {
			got = append(got, a+" "+r.Outcome+" "+r.Target+" "+r.Detail)
			if strings.Contains(r.Detail, "203.0.113") || strings.Contains(r.Detail, "alice") {
				t.Errorf("audit detail names the target: %+v", r)
			}
		}
	}
	want := []string{
		"security_response_apply ok response:31 action=block",
		"security_response_apply error response:999 result=not found",
		"security_response_apply error response result=not found",
		"security_response_apply error response:31 action=block result=refused code=allowlist",
		"security_response_apply error response:30 action=revoke result=refused code=revoke_cap",
		"security_response_apply error response:31 action=block result=refused code=allowlist",
		"security_response_apply error response:30 action=revoke result=failed code=error",
		"security_response_apply error response:29 action=block result=rejected",
		"security_response_dismiss ok response:30 action=revoke",
		"security_response_dismiss error response result=not found",
		"security_response_dismiss error response:26 action=block result=error",
	}
	if !slices.Equal(got, want) {
		t.Errorf("audit =\n%q\nwant\n%q", got, want)
	}
}

func TestResponsePause(t *testing.T) {
	f := newRespFake(time.Now().UTC())
	e := respEnv(t, f, nil)
	sess, csrf := e.detLogin(t, "operator")
	for level, done := range map[string]string{"": "unpaused", "recommend": "paused_recommend", "off": "paused_off"} {
		resp, _ := e.detPost(t, "/security/responses/pause", sess, csrf, url.Values{"level": {level}})
		if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || loc != "/security/responses?done="+done {
			t.Errorf("pause %q = %d → %q", level, resp.StatusCode, loc)
		}
		if c := f.changeList(); c[len(c)-1] != (respChangeRec{Method: "SetPause", Level: level, Actor: "operator"}) {
			t.Errorf("pause %q: call %+v", level, c[len(c)-1])
		}
	}
	n := len(f.changeList())
	for _, form := range []url.Values{{}, {"level": {"enforce"}}, {"level": {"OFF"}}} {
		if resp, body := e.detPost(t, "/security/responses/pause", sess, csrf, form); resp.StatusCode != http.StatusUnprocessableEntity || !strings.Contains(body, "Pick a pause") {
			t.Errorf("pause %v = %d, want 422", form, resp.StatusCode)
		}
	}
	if len(f.changeList()) != n {
		t.Error("a refused pause reached SetPause")
	}
	_, body := e.get(t, "/security/responses?done=paused_off", sess)
	if !strings.Contains(body, "every automatic block was removed") {
		t.Error("pause notice missing")
	}
	details := map[string]bool{}
	for _, r := range secAuditRows(t, e, "security_response_pause") {
		details[r.Outcome+" "+r.Detail] = true
	}
	for _, d := range []string{"ok level=none", "ok level=recommend", "ok level=off", "error result=rejected"} {
		if !details[d] {
			t.Errorf("no audit row %q (have %v)", d, details)
		}
	}
}

// Marking an incident a false positive lifts its automatic blocks; a lift that fails is told and
// never undoes the marking.
func TestIncidentFalsePositiveLiftsBlocks(t *testing.T) {
	now := time.Now().UTC()
	inc, f := newIncFake(now), newRespFake(now)
	e := incEnv(t, inc)
	e.srv.responses = f
	sess, csrf := e.detLogin(t, "operator")
	f.mu.Lock()
	f.lifted = 2
	f.mu.Unlock()
	resp, _ := e.detPost(t, "/security/incidents/12/false-positive", sess, csrf, url.Values{"mute": {"on"}})
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || loc != "/security/incidents/12?done=false_positive_muted&lifted=2" {
		t.Errorf("false positive = %d → %q", resp.StatusCode, loc)
	}
	if c := f.changeList(); len(c) != 1 || c[0] != (respChangeRec{Method: "LiftForIncident", ID: 12, Actor: "operator"}) {
		t.Errorf("responder calls = %+v", c)
	}
	_, body := e.get(t, "/security/incidents/12?done=false_positive_muted&lifted=2", sess)
	if !strings.Contains(body, "2 automatic blocks were lifted; their addresses are exempt from automatic blocks for 30 days.") {
		t.Error("lifted notice missing")
	}
	_, body = e.get(t, "/security/incidents/12?done=note&lifted=2", sess)
	if strings.Contains(body, "automatic blocks were lifted") {
		t.Error("a lift count shown on another notice")
	}
	// No automatic block: the plain notice.
	f.mu.Lock()
	f.lifted = 0
	f.mu.Unlock()
	resp, _ = e.detPost(t, "/security/incidents/12/false-positive", sess, csrf, url.Values{})
	if loc := resp.Header.Get("Location"); loc != "/security/incidents/12?done=false_positive" {
		t.Errorf("no blocks → %q", loc)
	}
	// The lift fails: still marked, and told.
	f.mu.Lock()
	f.liftErr = errors.New("edge down")
	f.mu.Unlock()
	resp, _ = e.detPost(t, "/security/incidents/12/false-positive", sess, csrf, url.Values{})
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusSeeOther || loc != "/security/incidents/12?done=false_positive&lift=failed" {
		t.Errorf("failed lift = %d → %q", resp.StatusCode, loc)
	}
	if got := inc.changeList(); len(got) != 3 || got[2].Method != "MarkFalsePositive" {
		t.Errorf("incident calls = %+v", got)
	}
	_, body = e.get(t, "/security/incidents/12?done=false_positive&lift=failed", sess)
	if !strings.Contains(body, "Its automatic blocks could not be lifted") {
		t.Error("failed-lift notice missing")
	}
	// The marking fails: nothing is lifted.
	inc.set(func(i *incFake) { i.writeErr = errors.New("db") })
	n := len(f.changeList())
	e.detPost(t, "/security/incidents/12/false-positive", sess, csrf, url.Values{})
	if len(f.changeList()) != n {
		t.Error("blocks were lifted for a false positive that wasn't recorded")
	}
	var details []string
	for _, r := range secAuditRows(t, e, "security_incident_false_positive") {
		details = append(details, r.Detail)
	}
	if want := []string{"mute=yes note=no lifted=2", "mute=no note=no", "mute=no note=no lift=error", "mute=no note=no result=error"}; !slices.Equal(details, want) {
		t.Errorf("audit details = %q, want %q", details, want)
	}
}

func TestIncidentPageResponses(t *testing.T) {
	now := time.Now().UTC()
	inc, f := newIncFake(now), newRespFake(now)
	inc.incs[0].Timeline = append(inc.incs[0].Timeline, siem.IncidentEvent{TS: now, Kind: siem.TimelineResponse, Text: "Blocked 203.0.113.9 for 1 hour <i>auto</i>"})
	e := incEnv(t, inc)
	e.srv.responses = f
	sess := e.loginAs(t, "operator")
	_, body := e.get(t, "/security/incidents/12", sess)
	if fl := f.lastFilter(t); fl.IncidentID != 12 {
		t.Errorf("responses filter = %+v, want IncidentID 12", fl)
	}
	for _, want := range []string{">Responses</h2>", "Block 203.0.113.9/32 for 1 hour", "Sign out alice", ">Recommended<",
		`href="/security/responses?before=32#resp-31"`, "Automated response</strong>", "Blocked 203.0.113.9 for 1 hour &lt;i&gt;auto&lt;/i&gt;"} {
		if !strings.Contains(body, want) {
			t.Errorf("incident page missing %q", want)
		}
	}
	// None about it: no panel.
	_, body = e.get(t, "/security/incidents/9", sess)
	if strings.Contains(body, ">Responses</h2>") {
		t.Error("a Responses panel for an incident with none")
	}
}

func TestDetectionPagePatternAndResponses(t *testing.T) {
	now := time.Now().UTC()
	det := &detFakeService{
		rules: append(detRules(), siem.Rule{ID: "pattern.new", Name: "New log pattern", Type: siem.RuleBaseline, Baseline: siem.BaselinePattern, GroupBy: "app", Query: "src:app", Builtin: true}),
		dets: []siem.Detection{
			{ID: 499, RuleID: "edge.scan", RuleName: "Scan", Severity: siem.SevMedium, Key: "198.51.100.7", First: now.Add(-time.Hour), Last: now},
			{ID: 7, RuleID: "pattern.new", RuleName: "New log pattern", Severity: siem.SevLow, Key: patWebID, App: "shop", First: now.Add(-time.Hour), Last: now},
			{ID: 8, RuleID: "pattern.new", RuleName: "New log pattern", Severity: siem.SevLow, Key: "not-a-pattern-id", First: now.Add(-time.Hour), Last: now},
		}}
	f := newRespFake(now)
	e := detEnv(t, det, nil)
	e.srv.responses = f
	e.srv.patterns = newPatFake(now)
	sess := e.loginAs(t, "operator")
	_, body := e.get(t, "/security/detections/7", sess)
	if !strings.Contains(body, `href="/security/patterns/`+patWebID+`"`) || !strings.Contains(body, "View the log pattern") || strings.Contains(body, "Find related events") {
		t.Error("a pattern detection: want its pattern's link instead of the related search")
	}
	if _, body := e.get(t, "/security/detections/8", sess); strings.Contains(body, "View the log pattern") {
		t.Error("a key that is no pattern ID got a pattern link")
	}
	_, body = e.get(t, "/security/detections/499", sess)
	if !strings.Contains(body, ">Responses</h2>") || !strings.Contains(body, "Block 198.51.100.7/32 for 4 hours") || strings.Contains(body, "Sign out alice") {
		t.Error("detection page: want only its own responses")
	}
	if fl := f.lastFilter(t); fl.DetectionID != 499 {
		t.Errorf("responses filter = %+v", fl)
	}
}

func TestAccountRevoker(t *testing.T) {
	sl := &fakeSecurityLogs{}
	e := securityEnv(t, sl)
	hash := e.srv.cfg.ExtraUsers[0].PasswordHash
	e.srv.cfg.ExtraUsers = append(e.srv.cfg.ExtraUsers, config.UserConfig{Username: "ann@example.com", PasswordHash: hash, Role: config.RoleOwner})
	sec, err := buildSecState(e.srv.cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.srv.sec.Store(sec)
	for _, u := range []string{"operator", "operator", "ann@example.com", "dep"} {
		e.loginAs(t, u)
	}
	count := func(user string) int {
		var n int
		if err := e.srv.db.QueryRow(`SELECT COUNT(*) FROM sessions WHERE username = ?`, user).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	rv := e.srv.AccountRevoker()
	ctx := context.Background()
	if user, n, err := rv.Revoke(ctx, "operator"); err != nil || user != "operator" || n != 2 || count("operator") != 0 || count("dep") != 1 {
		t.Errorf("Revoke(operator) = %q %d %v", user, n, err)
	}
	// An email username is stored as its keyed hash.
	if user, n, err := rv.Revoke(ctx, hashOf("ann@example.com")); err != nil || user != "ann@example.com" || n != 1 || count("ann@example.com") != 0 {
		t.Errorf("Revoke(hash) = %q %d %v", user, n, err)
	}
	for _, actor := range []string{"", "mallory", hashOf("mallory@example.com"), "OPERATOR"} {
		if _, _, err := rv.Revoke(ctx, actor); !errors.Is(err, siem.ErrUnknownAccount) {
			t.Errorf("Revoke(%q) = %v, want ErrUnknownAccount", actor, err)
		}
	}
	if count("dep") != 1 {
		t.Error("an unknown actor ended another user's session")
	}
	// Without security logs there is no hash to match.
	e.srv.securityLogs = nil
	if _, _, err := rv.Revoke(ctx, hashOf("ann@example.com")); !errors.Is(err, siem.ErrUnknownAccount) {
		t.Errorf("hash without security logs = %v", err)
	}
	// A user added by a reload is found (the live users).
	e.srv.cfg.ExtraUsers = append(e.srv.cfg.ExtraUsers, config.UserConfig{Username: "zoe", PasswordHash: hash, Role: config.RoleViewer})
	sec, _ = buildSecState(e.srv.cfg)
	e.srv.sec.Store(sec)
	if user, _, err := rv.Revoke(ctx, "zoe"); err != nil || user != "zoe" {
		t.Errorf("Revoke(zoe) after a reload = %q %v", user, err)
	}
}
