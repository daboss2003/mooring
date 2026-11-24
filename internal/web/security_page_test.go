package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/crypto"
	"github.com/daboss2003/mooring/internal/session"
	"github.com/daboss2003/mooring/internal/siem"
	"github.com/daboss2003/mooring/internal/siem/query"
	"github.com/daboss2003/mooring/internal/siem/store"
)

// fakeSecurityLogs records what the Security logs page asks of the pipeline.
type fakeSecurityLogs struct {
	mu              sync.Mutex
	status          siem.Status
	result          store.Result
	searchErr       error
	searches        []query.Query
	limits          []int
	exports         []query.Query
	exportMax       []int
	exportOut       string
	exportErr       error
	exportCount     int           // when > 0, the count Export reports (else the lines it wrote)
	afterFirstWrite func()        // runs after Export wrote its first line, before the rest
	entered         chan struct{} // when set, Export signals here on entry
	block           chan struct{} // when set, Export waits for it to close
	asked           []string      // the field names SearchValue was asked about
	secretAsked     []string      // the fields SecretField was asked about
}

func (f *fakeSecurityLogs) Search(ctx context.Context, q query.Query, limit int) (store.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.searches = append(f.searches, q)
	f.limits = append(f.limits, limit)
	return f.result, f.searchErr
}

func (f *fakeSecurityLogs) Export(ctx context.Context, q query.Query, w io.Writer, maxEvents int) (int, error) {
	f.mu.Lock()
	f.exports = append(f.exports, q)
	f.exportMax = append(f.exportMax, maxEvents)
	afterFirst, entered, block, out, err, count := f.afterFirstWrite, f.entered, f.block, f.exportOut, f.exportErr, f.exportCount
	f.mu.Unlock()
	if entered != nil {
		entered <- struct{}{}
	}
	if block != nil {
		<-block
	}
	// The first line, then the hook, then the rest.
	first, rest := out, ""
	if i := strings.IndexByte(out, '\n'); i >= 0 {
		first, rest = out[:i+1], out[i+1:]
	}
	for i, part := range []string{first, rest} {
		if part == "" {
			continue
		}
		if _, werr := io.WriteString(w, part); werr != nil {
			return 0, werr
		}
		if i == 0 && afterFirst != nil {
			afterFirst()
		}
	}
	if count == 0 {
		count = strings.Count(out, "\n")
	}
	return count, err
}

func (f *fakeSecurityLogs) Status() siem.Status { return f.status }

var (
	fakeEmailText = regexp.MustCompile(`[^\s"]+@[^\s"]+`)
	fakePhoneText = regexp.MustCompile(`\+[0-9]{7,15}`)
)

// SecretField stands in for redaction's secret names: a key ending in password, token or api_key.
func (f *fakeSecurityLogs) SecretField(field string) bool {
	f.mu.Lock()
	f.secretAsked = append(f.secretAsked, field)
	f.mu.Unlock()
	k := strings.ToLower(field)
	return strings.HasSuffix(k, "password") || strings.HasSuffix(k, "token") || strings.HasSuffix(k, "api_key")
}

// SearchText stands in for redaction of free text: emails and phone numbers become their hash.
func (f *fakeSecurityLogs) SearchText(text string) string {
	text = fakeEmailText.ReplaceAllStringFunc(text, hashOf)
	return fakePhoneText.ReplaceAllStringFunc(text, hashOf)
}

var fakePhone = regexp.MustCompile(`^\+?[0-9][0-9 ()-]{6,}$`)

// SearchValue stands in for redaction: email, phone and imei keys are always hashed; actor only
// when it is an email or a phone number.
func (f *fakeSecurityLogs) SearchValue(field, value string) string {
	f.mu.Lock()
	f.asked = append(f.asked, field)
	f.mu.Unlock()
	switch field {
	case "email", "phone", "imei":
		return hashOf(value)
	case "actor":
		if strings.Contains(value, "@") || fakePhone.MatchString(value) {
			return hashOf(value)
		}
	}
	return value
}

// hashOf is the fake's keyed hash: "h:" + 16 hex.
func hashOf(v string) string {
	sum := sha256.Sum256([]byte(v))
	return "h:" + hex.EncodeToString(sum[:8])
}

func (f *fakeSecurityLogs) calls() (searches, exports int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.searches), len(f.exports)
}

const secPeer = "127.0.0.1:1"

// securityEnv is a server with the owner "operator", a deployer "dep" and a viewer "vie". f nil =
// security logs off.
func securityEnv(t *testing.T, f *fakeSecurityLogs) *testEnv {
	t.Helper()
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	hash, err := crypto.HashPassword([]byte(testPassword), crypto.DefaultArgon2Params)
	if err != nil {
		t.Fatal(err)
	}
	e.srv.cfg.ExtraUsers = []config.UserConfig{
		{Username: "dep", PasswordHash: hash, Role: config.RoleDeployer},
		{Username: "vie", PasswordHash: hash, Role: config.RoleViewer},
	}
	sec, err := buildSecState(e.srv.cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.srv.sec.Store(sec)
	if f != nil {
		e.srv.securityLogs = f
	}
	return e
}

// loginAs signs user in through the real login flow and returns the session cookie.
func (e *testEnv) loginAs(t *testing.T, user string) *http.Cookie {
	t.Helper()
	get := e.req(t, "GET", "/login", secPeer, nil, nil, nil)
	csrf := cookieByName(get, e.srv.csrfCookieName())
	if csrf == nil {
		t.Fatal("no CSRF cookie on GET /login")
	}
	form := url.Values{"username": {user}, "password": {testPassword}, "csrf_token": {csrf.Value}}
	post := e.req(t, "POST", "/login", secPeer, map[string]string{"Origin": "https://example.com"}, []*http.Cookie{csrf}, form)
	sess := cookieByName(post, e.srv.cookieName())
	if sess == nil {
		t.Fatalf("login as %s failed", user)
	}
	return sess
}

func (e *testEnv) get(t *testing.T, path string, sess *http.Cookie) (*http.Response, string) {
	t.Helper()
	resp := e.req(t, "GET", path, secPeer, nil, []*http.Cookie{sess}, nil)
	return resp, readBody(resp)
}

type secAuditRow struct {
	Actor, IP, Target, Outcome, Level, Detail string
}

func secAuditRows(t *testing.T, e *testEnv, action string) []secAuditRow {
	t.Helper()
	rows, err := e.srv.db.QueryContext(context.Background(),
		`SELECT actor, ip, target, outcome, level, detail FROM events WHERE action = ? ORDER BY seq`, action)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []secAuditRow
	for rows.Next() {
		var r secAuditRow
		if err := rows.Scan(&r.Actor, &r.IP, &r.Target, &r.Outcome, &r.Level, &r.Detail); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// realQueryParser skips a test that needs internal/siem/query's real parser while that package is
// still the phase-1 contract stub (Parse returns an empty query).
func realQueryParser(t *testing.T) {
	t.Helper()
	q, err := query.Parse("kind:ssh.login")
	if err != nil || len(q.Terms) != 1 {
		t.Skip("internal/siem/query is still the contract stub")
	}
}

var securityPaths = []string{"/security", "/security/status", "/security/export"}

// Only the owner may search or export: deployer and viewer get the standard forbidden response, an
// rbac_deny audit row, and never reach the pipeline.
func TestSecurityPagesOwnerOnly(t *testing.T) {
	f := &fakeSecurityLogs{exportOut: "{}\n"}
	e := securityEnv(t, f)
	for _, user := range []string{"dep", "vie"} {
		sess := e.loginAs(t, user)
		for _, p := range securityPaths {
			resp, body := e.get(t, p, sess)
			if resp.StatusCode != http.StatusForbidden {
				t.Errorf("%s GET %s = %d, want 403", user, p, resp.StatusCode)
			}
			if strings.Contains(body, "Collection") || resp.Header.Get("Content-Disposition") != "" {
				t.Errorf("%s GET %s leaked page content", user, p)
			}
		}
	}
	if s, x := f.calls(); s != 0 || x != 0 {
		t.Fatalf("non-owners reached the pipeline: %d searches, %d exports", s, x)
	}
	denied := map[string]int{}
	for _, r := range secAuditRows(t, e, "rbac_deny") {
		if r.Level != "security" || r.Outcome != "deny" {
			t.Errorf("rbac_deny row %+v: want level security, outcome deny", r)
		}
		denied[r.Actor+" "+r.Target]++
	}
	for _, user := range []string{"dep", "vie"} {
		for _, p := range securityPaths {
			if denied[user+" GET "+p] != 1 {
				t.Errorf("want one rbac_deny for %s GET %s, got %d (all: %v)", user, p, denied[user+" GET "+p], denied)
			}
		}
	}

	owner := e.loginAs(t, "operator")
	for _, p := range securityPaths {
		if resp, _ := e.get(t, p, owner); resp.StatusCode != http.StatusOK {
			t.Errorf("owner GET %s = %d, want 200", p, resp.StatusCode)
		}
	}
	if s, x := f.calls(); s != 1 || x != 1 {
		t.Errorf("owner: %d searches, %d exports, want 1 and 1", s, x)
	}
}

// The sidebar shows the Security logs link to the owner only.
func TestSecurityNavLinkOwnerOnly(t *testing.T) {
	e := securityEnv(t, &fakeSecurityLogs{})
	for user, want := range map[string]bool{"operator": true, "dep": false, "vie": false} {
		_, body := e.get(t, "/", e.loginAs(t, user))
		if !strings.Contains(body, `class="sidebar"`) {
			t.Fatalf("%s: overview did not render the shell", user)
		}
		if got := strings.Contains(body, secNavLink); got != want {
			t.Errorf("%s: security nav link shown = %v, want %v", user, got, want)
		}
	}
	// The Security logs page itself renders the shell through the same path.
	if _, body := e.get(t, "/security", e.loginAs(t, "operator")); !strings.Contains(body, secNavLink) {
		t.Error("the Security logs page is missing the owner's nav link")
	}
}

const secNavLink = `href="/security" data-nav`

func setRole(t *testing.T, e *testEnv, user string, role config.Role) {
	t.Helper()
	for i := range e.srv.cfg.ExtraUsers {
		if e.srv.cfg.ExtraUsers[i].Username == user {
			e.srv.cfg.ExtraUsers[i].Role = role
		}
	}
	sec, err := buildSecState(e.srv.cfg)
	if err != nil {
		t.Fatal(err)
	}
	e.srv.sec.Store(sec)
}

// The link follows the live users: a reload that changes a role applies on the next page.
func TestSecurityNavFollowsLiveRoles(t *testing.T) {
	e := securityEnv(t, &fakeSecurityLogs{})
	sess := e.loginAs(t, "dep")
	shown := func() bool {
		_, body := e.get(t, "/", sess)
		return strings.Contains(body, secNavLink)
	}
	if shown() {
		t.Fatal("deployer sees the link")
	}
	setRole(t, e, "dep", config.RoleOwner)
	if !shown() {
		t.Error("promoted to owner: link not shown")
	}
	setRole(t, e, "dep", config.RoleDeployer)
	if shown() {
		t.Error("demoted again: link still shown")
	}
}

// render takes the owner flag from the request's session, never from the handler's data.
func TestRenderTakesCanAdminFromSession(t *testing.T) {
	e := securityEnv(t, nil)
	for user, want := range map[string]bool{"operator": true, "vie": false, "ghost": false} {
		r := httptest.NewRequest("GET", "/events", nil)
		r = r.WithContext(withSession(r.Context(), &session.Session{Username: user}))
		w := httptest.NewRecorder()
		e.srv.render(w, r, "events.html", tmplData{CanAdmin: !want})
		if got := strings.Contains(w.Body.String(), secNavLink); got != want {
			t.Errorf("%s: link shown = %v, want %v", user, got, want)
		}
	}
}

func TestSecurityPageOff(t *testing.T) {
	e := securityEnv(t, nil)
	owner := e.loginAs(t, "operator")
	resp, body := e.get(t, "/security", owner)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /security (off) = %d, want 200", resp.StatusCode)
	}
	for _, want := range []string{"Security logs are off", "security_logs.enabled", "/etc/mooring/config.yaml", "docs/security-logs.md"} {
		if !strings.Contains(body, want) {
			t.Errorf("off state missing %q", want)
		}
	}
	if strings.Contains(body, `name="q"`) || strings.Contains(body, `data-poll-url="/security/status"`) {
		t.Error("off state must not offer search or poll the status")
	}
	resp, body = e.get(t, "/security/status", owner)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Security logs are off") {
		t.Errorf("status partial (off) = %d %q", resp.StatusCode, body)
	}
	if resp, _ := e.get(t, "/security/export", owner); resp.StatusCode != http.StatusNotFound {
		t.Errorf("export (off) = %d, want 404", resp.StatusCode)
	}
}

func TestSecurityPageStatusAndResults(t *testing.T) {
	now := time.Now().UTC()
	f := &fakeSecurityLogs{
		status: siem.Status{
			Enabled: true,
			Sources: []siem.SourceStatus{
				{Name: "app", OK: true, Events: 1234567, LastSeen: now.Add(-5 * time.Second)},
				{Name: "host:auth", OK: false, Err: "open /var/log/auth.log: permission denied", Dropped: 3},
			},
			Queue: 12, QueueCap: 10000, DiskBytes: 5 << 20, Segments: 3,
			Oldest: now.Add(-50 * time.Hour), ArchiveOn: true, LastArchived: now.Add(-2 * time.Hour), ArchiveBehind: 2,
		},
		result: store.Result{
			Events: []siem.Event{
				{V: 1, TS: now.Add(-3 * time.Minute), Src: siem.SrcHost, Lvl: siem.LvlWarn, Kind: siem.KindSSHLogin, Out: siem.OutFailure, Actor: "root", IP: "203.0.113.9", Msg: "Failed password for root\nfrom 203.0.113.9", F: map[string]any{"method": "password"}},
				{V: 1, TS: now.Add(-time.Hour), Src: siem.SrcApp, App: "shop", Svc: "api", Lvl: siem.LvlError, Kind: "auth.login_failed", Out: siem.OutSuccess},
			},
			Scanned: 12345,
		},
	}
	e := securityEnv(t, f)
	resp, body := e.get(t, "/security", e.loginAs(t, "operator"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /security = %d", resp.StatusCode)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	for _, want := range []string{
		`data-poll-url="/security/status"`, `data-poll-interval="15000"`,
		"host:auth", "open /var/log/auth.log: permission denied", "Not collecting", "1,234,567",
		"12 / 10,000", "5.0 MiB", "3 segments", "2 behind",
		"Scanned 12,345 events", "ssh.login", "shop/api", "203.0.113.9", "sec-lvl-warn", "sec-lvl-error",
		"pill-down", "pill-ok", "Failed password for root from 203.0.113.9", // one line in the row
		"3m ago", "&#34;method&#34;: &#34;password&#34;", // full event JSON in the expandable details
		`href="/security/export?`, "host:auth is not collecting",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
	if got := strings.Count(body, `<details class="sec-ev">`); got != 2 {
		t.Errorf("rendered %d event rows, want 2", got)
	}
	if strings.Contains(body, "Show older events") || strings.Contains(body, "The search stopped early") {
		t.Error("no older link or capped notice expected")
	}
	if len(f.limits) != 1 || f.limits[0] != securityPageSize || securityPageSize != 200 {
		t.Fatalf("search limits = %v, want [200]", f.limits)
	}
	q := f.searches[0]
	if d := now.Add(-24 * time.Hour).Sub(q.From); d < -5*time.Second || d > 5*time.Second || !q.To.IsZero() {
		t.Errorf("default window = %v..%v, want the last 24h up to now", q.From, q.To)
	}
}

func TestSecurityStatusPartialEscapes(t *testing.T) {
	f := &fakeSecurityLogs{status: siem.Status{
		Enabled: true, ArchiveOn: true,
		Sources:    []siem.SourceStatus{{Name: "host:<b>x</b>", Err: `<img src=x onerror=alert(1)>`}},
		ArchiveErr: `<script>alert("s3")</script>`,
	}}
	e := securityEnv(t, f)
	resp, body := e.get(t, "/security/status", e.loginAs(t, "operator"))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status partial = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") || resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("status partial headers: %q / %q", ct, resp.Header.Get("Cache-Control"))
	}
	if strings.Contains(body, "<html") || strings.Contains(body, `class="sidebar"`) {
		t.Error("the status partial must be a fragment, not a full page")
	}
	for _, bad := range []string{"<img src=x", "<script>alert", "<b>x</b>"} {
		if strings.Contains(body, bad) {
			t.Errorf("status partial contains unescaped %q", bad)
		}
	}
	for _, want := range []string{"&lt;img src=x onerror=alert(1)&gt;", "&lt;script&gt;alert(&#34;s3&#34;)&lt;/script&gt;", "host:&lt;b&gt;x&lt;/b&gt;"} {
		if !strings.Contains(body, want) {
			t.Errorf("status partial missing escaped %q", want)
		}
	}
}

func TestSecurityQueryErrorInline(t *testing.T) {
	f := &fakeSecurityLogs{}
	e := securityEnv(t, f)
	e.srv.secParse = func(string) (query.Query, error) {
		return query.Query{}, errors.New(`unknown field "<script>alert(1)</script>"`)
	}
	owner := e.loginAs(t, "operator")
	resp, body := e.get(t, "/security?q="+url.QueryEscape(`"><script>alert(2)</script>`), owner)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("parse error = %d, want 200 with an inline error", resp.StatusCode)
	}
	if strings.Contains(body, "<script>alert") {
		t.Error("parse error or query echoed unescaped")
	}
	for _, want := range []string{`class="error"`, "unknown field &#34;&lt;script&gt;alert(1)&lt;/script&gt;&#34;", `value="&#34;&gt;&lt;script&gt;alert(2)&lt;/script&gt;"`} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
	if s, _ := f.calls(); s != 0 {
		t.Error("a query that does not parse must not be searched")
	}

	// Too long: refused before parsing.
	e.srv.secParse = nil
	_, body = e.get(t, "/security?q="+strings.Repeat("a", securityQueryMax+1), owner)
	if !strings.Contains(body, "The search is too long") {
		t.Error("an over-long query must be refused inline")
	}
	if s, _ := f.calls(); s != 0 {
		t.Error("an over-long query must not be searched")
	}
}

// With the real parser, a malformed query is an inline error too.
func TestSecurityQueryErrorInlineRealParser(t *testing.T) {
	realQueryParser(t)
	f := &fakeSecurityLogs{}
	e := securityEnv(t, f)
	resp, body := e.get(t, "/security?q="+url.QueryEscape(`nosuch:<b>`), e.loginAs(t, "operator"))
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `class="error"`) || strings.Contains(body, "<b>") {
		t.Errorf("real parse error: status %d, inline error shown = %v", resp.StatusCode, strings.Contains(body, `class="error"`))
	}
	if s, _ := f.calls(); s != 0 {
		t.Error("a query that does not parse must not be searched")
	}
}

func TestSecurityWindow(t *testing.T) {
	f := &fakeSecurityLogs{}
	e := securityEnv(t, f)
	owner := e.loginAs(t, "operator")
	at := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	now := time.Now().UTC()
	cases := []struct {
		params   string
		from, to time.Time
		relative time.Duration // from = now - relative (to unbounded)
	}{
		{params: "", relative: 24 * time.Hour},
		{params: "range=15m", relative: 15 * time.Minute},
		{params: "range=14d", relative: 14 * 24 * time.Hour},
		{params: "range=bogus", relative: 24 * time.Hour},
		{params: "from=2026-11-20T10:00&to=2026-11-21T10:00:30", from: at("2026-11-20T10:00:00Z"), to: at("2026-11-21T10:00:30Z")},
		{params: "range=6h&to=2026-11-21T10:00:00", from: at("2026-11-21T04:00:00Z"), to: at("2026-11-21T10:00:00Z")},
		{params: "to=2026-11-21T10:00:00.123456789Z", from: at("2026-11-20T10:00:00.123456789Z"), to: at("2026-11-21T10:00:00.123456789Z")},
	}
	for _, c := range cases {
		n, _ := f.calls()
		resp, body := e.get(t, "/security?"+c.params, owner)
		if resp.StatusCode != http.StatusOK || strings.Contains(body, `class="error"`) {
			t.Errorf("%q: status %d / error shown", c.params, resp.StatusCode)
			continue
		}
		q := f.searches[n]
		if c.relative != 0 {
			if d := now.Add(-c.relative).Sub(q.From); d < -10*time.Second || d > 10*time.Second || !q.To.IsZero() {
				t.Errorf("%q: window %v..%v, want now-%v..now", c.params, q.From, q.To, c.relative)
			}
			continue
		}
		if !q.From.Equal(c.from) || !q.To.Equal(c.to) {
			t.Errorf("%q: window %v..%v, want %v..%v", c.params, q.From, q.To, c.from, c.to)
		}
	}
	for _, bad := range []string{"from=2026-11-21T10:00&to=2026-11-20T10:00", "from=yesterday", "to=2026-13-01T00:00"} {
		n, _ := f.calls()
		_, body := e.get(t, "/security?"+bad, owner)
		if !strings.Contains(body, `class="error"`) {
			t.Errorf("%q: want an inline error", bad)
		}
		if m, _ := f.calls(); m != n {
			t.Errorf("%q: searched despite the error", bad)
		}
	}
}

func TestStoredValue(t *testing.T) {
	already := hashOf("carol@example.com")
	cases := []struct {
		field, value, want string
		changed            bool
		asked              string // the name SearchValue must be asked about, "" = not asked
	}{
		{"actor", "alice@example.com", hashOf("alice@example.com"), true, "actor"},
		{"actor", "+234 801 234 5678", hashOf("+234 801 234 5678"), true, "actor"},
		{"actor", "u_1029", "u_1029", false, "actor"}, // a plain user id is stored as is
		{"f.user.email", "bob@example.com", hashOf("bob@example.com"), true, "email"},
		{"f.device.imei", "356938035643809", hashOf("356938035643809"), true, "imei"},
		{"f.status", "500", "500", false, "status"},
		{"f.user.email", already, already, false, ""}, // already a stored hash: not hashed twice
		{"actor", already, already, false, ""},
		{"f.user.email", "*", "*", false, ""}, // prefix patterns are not values
		{"f.email", "h:0a*", "h:0a*", false, ""},
		{"ip", "203.0.113.9", "203.0.113.9", false, ""}, // only actor and f.<key> are redacted
		{"kind", "ssh.login", "ssh.login", false, ""},
		{"app", "alice@example.com", "alice@example.com", false, ""},
	}
	for _, c := range cases {
		f := &fakeSecurityLogs{}
		got, changed := storedValue(f)(c.field, c.value)
		if got != c.want || changed != c.changed {
			t.Errorf("storedValue(%s, %s) = %q %v, want %q %v", c.field, c.value, got, changed, c.want, c.changed)
		}
		want := []string(nil)
		if c.asked != "" {
			want = []string{c.asked}
		}
		if strings.Join(f.asked, ",") != strings.Join(want, ",") {
			t.Errorf("storedValue(%s, %s) asked SearchValue about %v, want %v", c.field, c.value, f.asked, want)
		}
	}
	for v, want := range map[string]bool{already: true, "h:0123456789abcdef": true, "h:0123456789ABCDEF": false, "h:0123": false, "x:0123456789abcdef": false, "alice": false} {
		if isPIIHash(v) != want {
			t.Errorf("isPIIHash(%q) = %v, want %v", v, !want, want)
		}
	}
}

// An owner can type personal data in clear text: the page hashes it before searching.
func TestSecuritySearchHashesTypedPersonalData(t *testing.T) {
	realQueryParser(t)
	f := &fakeSecurityLogs{}
	e := securityEnv(t, f)
	already := hashOf("carol@example.com")
	q := `actor:alice@example.com actor:"+234 801 234 5678" actor:u_1029 f.user.email:bob@example.com f.email:` + already + " ip:203.0.113.9"
	e.get(t, "/security?q="+url.QueryEscape(q), e.loginAs(t, "operator"))
	if len(f.searches) != 1 {
		t.Fatalf("searches = %d", len(f.searches))
	}
	want := []string{
		"actor:" + hashOf("alice@example.com"), "actor:" + hashOf("+234 801 234 5678"), "actor:u_1029",
		"f.user.email:" + hashOf("bob@example.com"), "f.email:" + already, "ip:203.0.113.9",
	}
	terms := f.searches[0].Terms
	if len(terms) != len(want) {
		t.Fatalf("terms = %+v", terms)
	}
	for i, term := range terms {
		if got := term.Field + ":" + term.Value; got != want[i] {
			t.Errorf("term %d = %q, want %q", i, got, want[i])
		}
	}
}

func TestSecurityOlderLink(t *testing.T) {
	before := time.Date(2026, 11, 23, 9, 14, 7, 123456789, time.UTC)
	f := &fakeSecurityLogs{result: store.Result{
		Events: []siem.Event{{V: 1, TS: before, Src: siem.SrcEdge, Lvl: siem.LvlInfo, Kind: siem.KindHTTPRequest}},
		More:   true, Before: before, Scanned: 200,
	}}
	e := securityEnv(t, f)
	owner := e.loginAs(t, "operator")
	_, body := e.get(t, "/security?q="+url.QueryEscape("src:edge f.status>=500")+"&range=7d", owner)
	m := regexp.MustCompile(`href="(/security\?[^"]*)"[^>]*>Show older events`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no older-events link when More is set")
	}
	link, err := url.Parse(html.UnescapeString(m[1]))
	if err != nil {
		t.Fatal(err)
	}
	v := link.Query()
	first := f.searches[0]
	if v.Get("q") != "src:edge f.status>=500" || v.Get("range") != "7d" || v.Get("to") != before.Format(time.RFC3339Nano) ||
		v.Get("from") != first.From.Format(time.RFC3339Nano) {
		t.Fatalf("older link params = %v", v)
	}
	e.get(t, link.String(), owner)
	next := f.searches[1]
	if !next.To.Equal(before) || !next.From.Equal(first.From) {
		t.Errorf("following the link searched %v..%v, want %v..%v", next.From, next.To, first.From, before)
	}

	f.result.More = false
	if _, body := e.get(t, "/security", owner); strings.Contains(body, "Show older events") {
		t.Error("older link shown without More")
	}
}

func TestSecurityCappedNotice(t *testing.T) {
	f := &fakeSecurityLogs{result: store.Result{Capped: true, Scanned: 500000}}
	e := securityEnv(t, f)
	owner := e.loginAs(t, "operator")
	_, body := e.get(t, "/security", owner)
	for _, want := range []string{"The search stopped early; narrow the range or add terms.", "Scanned 500,000 events"} {
		if !strings.Contains(body, want) {
			t.Errorf("capped page missing %q", want)
		}
	}
	f.result.Capped = false
	if _, body := e.get(t, "/security", owner); strings.Contains(body, "The search stopped early") {
		t.Error("capped notice shown for a complete search")
	}
}

func TestSecuritySearchFailureIsInline(t *testing.T) {
	f := &fakeSecurityLogs{searchErr: errors.New("open /var/lib/mooring/security-logs/x.ndjson.gz: <secret path>")}
	e := securityEnv(t, f)
	resp, body := e.get(t, "/security", e.loginAs(t, "operator"))
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "The search failed") {
		t.Errorf("search failure: %d, inline message shown = %v", resp.StatusCode, strings.Contains(body, "The search failed"))
	}
	if strings.Contains(body, "secret path") {
		t.Error("the store's error text must not be shown")
	}
}

// Every event field is attacker-controlled: it must be escaped in the row and in the details JSON.
func TestSecurityResultsEscapeEventContent(t *testing.T) {
	f := &fakeSecurityLogs{result: store.Result{Events: []siem.Event{{
		V: 1, TS: time.Now(), Src: "<i>src</i>", App: "<b>app</b>", Lvl: `warn" onmouseover="alert(3)`,
		Kind: `<img src=x onerror=alert(1)>`, Out: "<u>", Actor: `"><script>alert('a')</script>`, IP: "<s>",
		Msg: `<script>alert("m")</script>`,
		F:   map[string]any{"k<script>": `v</pre><script>alert(2)</script>`},
	}}}}
	e := securityEnv(t, f)
	_, body := e.get(t, "/security", e.loginAs(t, "operator"))
	for _, bad := range []string{"<script>alert", "<img src=x", `onmouseover="alert`, "</pre><script>", "<b>app</b>", "<i>src</i>", "<u>", "<s>"} {
		if strings.Contains(body, bad) {
			t.Errorf("results contain unescaped %q", bad)
		}
	}
	for _, want := range []string{
		"&lt;script&gt;alert(&#34;m&#34;)&lt;/script&gt;",          // the row's message
		"&lt;script&gt;alert(\\&#34;m\\&#34;)&lt;/script&gt;",      // the details JSON (JSON-escaped quotes)
		"&lt;/pre&gt;&lt;script&gt;alert(2)&lt;/script&gt;",        // a field value in the JSON
		"&#34;&gt;&lt;script&gt;alert(&#39;a&#39;)&lt;/script&gt;", // the actor
		`class="sec-lvl sec-lvl-info"`,                             // unknown level: allowlisted class
	} {
		if !strings.Contains(body, want) {
			t.Errorf("results missing escaped %q", want)
		}
	}
}

func TestSecurityExport(t *testing.T) {
	const out = "{\"v\":1,\"kind\":\"ssh.login\"}\n{\"v\":1,\"kind\":\"ssh.login\"}\n"
	f := &fakeSecurityLogs{exportOut: out}
	e := securityEnv(t, f)
	e.srv.secParse = func(string) (query.Query, error) {
		return query.Query{Terms: []query.Term{{Field: "kind", Op: query.OpEq, Value: "ssh.login"}}}, nil
	}
	var auditedFirst bool
	f.afterFirstWrite = func() { auditedFirst = len(secAuditRows(t, e, "security_logs_export")) == 1 }
	owner := e.loginAs(t, "operator")
	resp, body := e.get(t, "/security/export?q="+url.QueryEscape("kind:ssh.login")+"&range=6h", owner)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("export = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/x-ndjson" {
		t.Errorf("Content-Type = %q", ct)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q", cc)
	}
	cd := resp.Header.Get("Content-Disposition")
	m := regexp.MustCompile(`^attachment; filename="security-logs-(\d{8}T\d{6}Z)-(\d{8}T\d{6}Z)\.ndjson"$`).FindStringSubmatch(cd)
	if m == nil {
		t.Fatalf("Content-Disposition = %q", cd)
	}
	from, _ := time.Parse("20060102T150405Z", m[1])
	to, _ := time.Parse("20060102T150405Z", m[2])
	if d := to.Sub(from); d < 6*time.Hour-2*time.Second || d > 6*time.Hour+2*time.Second {
		t.Errorf("filename window %s..%s, want 6h", m[1], m[2])
	}
	if body != out {
		t.Errorf("body = %q, want the export stream", body)
	}
	if len(f.exportMax) != 1 || f.exportMax[0] != 100000 {
		t.Errorf("Export maxEvents = %v, want [100000]", f.exportMax)
	}
	if !auditedFirst {
		t.Error("the export audit event must be written before the first byte")
	}
	if rows := secAuditRows(t, e, "security_logs_export_incomplete"); len(rows) != 0 {
		t.Errorf("a complete export recorded as incomplete: %+v", rows)
	}
	rows := secAuditRows(t, e, "security_logs_export")
	if len(rows) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(rows))
	}
	r := rows[0]
	if r.Actor != "operator" || r.IP != "127.0.0.1" || r.Level != "security" || r.Outcome != "ok" {
		t.Errorf("audit row = %+v", r)
	}
	if !strings.Contains(r.Detail, "kind:ssh.login") || !strings.Contains(r.Detail, "range=6h") || strings.Contains(r.Detail, `"v":1`) {
		t.Errorf("audit detail = %q, want the query and range, never results", r.Detail)
	}
	if q := f.exports[0]; q.From.IsZero() || len(q.Terms) != 1 {
		t.Errorf("Export got %+v, want the parsed query with the window", q)
	}
}

// The export audit records the hashed form of typed personal data, never the clear text.
func TestSecurityExportAuditHashesPersonalData(t *testing.T) {
	realQueryParser(t)
	f := &fakeSecurityLogs{}
	e := securityEnv(t, f)
	e.get(t, "/security/export?q="+url.QueryEscape("f.user.email:alice@example.com"), e.loginAs(t, "operator"))
	rows := secAuditRows(t, e, "security_logs_export")
	if len(rows) != 1 {
		t.Fatalf("audit rows = %d", len(rows))
	}
	if strings.Contains(rows[0].Detail, "alice@example.com") || !strings.Contains(rows[0].Detail, hashOf("alice@example.com")) {
		t.Errorf("audit detail = %q, want the hash, not the email", rows[0].Detail)
	}
}

// An export the audit log can't record doesn't happen.
func TestSecurityExportFailsClosedWithoutAudit(t *testing.T) {
	f := &fakeSecurityLogs{exportOut: "{}\n"}
	e := securityEnv(t, f)
	owner := e.loginAs(t, "operator")
	if _, err := e.srv.db.ExecContext(context.Background(), `ALTER TABLE events RENAME TO events_gone`); err != nil {
		t.Fatal(err)
	}
	resp, body := e.get(t, "/security/export", owner)
	if resp.StatusCode != http.StatusInternalServerError || resp.Header.Get("Content-Disposition") != "" {
		t.Errorf("export without audit = %d (disposition %q), want 500 and no download", resp.StatusCode, resp.Header.Get("Content-Disposition"))
	}
	if strings.Contains(body, "{}") {
		t.Error("events were sent although the export's audit event could not be written")
	}
}

// An export that stops early or reaches the cap ends with a line saying so, and the audit records it.
func TestSecurityExportIncomplete(t *testing.T) {
	const two = "{\"v\":1}\n{\"v\":1}\n"
	cases := []struct {
		name, out string
		count     int
		err       error
		reason    string // "" = complete
	}{
		{name: "complete", out: two},
		{name: "cap", out: two, count: securityExportMax, reason: "cap reached"},
		{name: "budget", out: two, err: fmt.Errorf("stop: %w", store.ErrBudget), reason: "scan budget"},
		{name: "deadline", out: two, err: context.DeadlineExceeded, reason: "time limit"},
		{name: "segment removed", out: two, err: fmt.Errorf("x: %w", store.ErrSegmentRemoved), reason: "segment removed"},
		{name: "error", out: two, err: errors.New("segment gone <x>"), reason: "error"},
		{name: "error before any event", err: errors.New("disk read failed"), reason: "error"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeSecurityLogs{exportOut: c.out, exportErr: c.err, exportCount: c.count}
			e := securityEnv(t, f)
			resp, body := e.get(t, "/security/export", e.loginAs(t, "operator"))
			if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Disposition") == "" {
				t.Fatalf("export = %d (disposition %q), want a download", resp.StatusCode, resp.Header.Get("Content-Disposition"))
			}
			n := c.count
			if n == 0 {
				n = strings.Count(c.out, "\n")
			}
			incomplete := secAuditRows(t, e, "security_logs_export_incomplete")
			if c.reason == "" {
				if body != c.out || len(incomplete) != 0 {
					t.Errorf("complete export: body %q, incomplete rows %+v", body, incomplete)
				}
				return
			}
			want := c.out + fmt.Sprintf(`{"export":"incomplete","reason":%q,"events":%d}`, c.reason, n) + "\n"
			if body != want {
				t.Errorf("body = %q, want %q", body, want)
			}
			if strings.Contains(body, "segment gone") || strings.Contains(body, "disk read failed") {
				t.Error("the store's error text must not be sent")
			}
			if len(secAuditRows(t, e, "security_logs_export")) != 1 || len(incomplete) != 1 {
				t.Fatalf("audit rows: export %d, incomplete %d, want 1 and 1", len(secAuditRows(t, e, "security_logs_export")), len(incomplete))
			}
			r := incomplete[0]
			if r.Level != "security" || r.Outcome != "error" || r.Actor != "operator" ||
				!strings.Contains(r.Detail, "reason="+c.reason) || !strings.Contains(r.Detail, fmt.Sprintf("events=%d", n)) {
				t.Errorf("incomplete audit row = %+v", r)
			}
		})
	}
}

// The store's search slots are busy: an export is refused with 503 and leaves no "ok" audit row.
func TestSecurityExportBusy(t *testing.T) {
	f := &fakeSecurityLogs{exportErr: store.ErrBusy}
	e := securityEnv(t, f)
	resp, body := e.get(t, "/security/export", e.loginAs(t, "operator"))
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("Content-Disposition") != "" {
		t.Errorf("busy export = %d (disposition %q), want 503 and no download", resp.StatusCode, resp.Header.Get("Content-Disposition"))
	}
	if !strings.Contains(body, "Try again") {
		t.Errorf("busy export body = %q", body)
	}
	if rows := append(secAuditRows(t, e, "security_logs_export"), secAuditRows(t, e, "security_logs_export_incomplete")...); len(rows) != 0 {
		t.Errorf("a busy refusal was audited: %+v", rows)
	}
}

// exportWriter runs the audit once, before any byte reaches the client; a failed audit sends nothing.
func TestExportWriterAuditsBeforeFirstByte(t *testing.T) {
	audits := 0
	var sent []string
	under := writerFunc(func(p []byte) (int, error) {
		if audits != 1 {
			t.Errorf("bytes %q reached the client with %d audits done, want 1", p, audits)
		}
		sent = append(sent, string(p))
		return len(p), nil
	})
	ew := &exportWriter{w: under, audit: func() error { audits++; return nil }}
	for _, s := range []string{"a\n", "b\n"} {
		if _, err := ew.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	if audits != 1 || ew.n != 4 || strings.Join(sent, "") != "a\nb\n" {
		t.Errorf("audits %d, bytes %d, sent %q", audits, ew.n, sent)
	}

	failed := &exportWriter{w: writerFunc(func(p []byte) (int, error) {
		t.Errorf("bytes %q sent although the audit failed", p)
		return len(p), nil
	}), audit: func() error { return errors.New("db down") }}
	if _, err := failed.Write([]byte("x\n")); err == nil || failed.ensureAudit() == nil || failed.n != 0 {
		t.Errorf("failed audit: write err %v, n %d", err, failed.n)
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

// One export at a time, so an export never holds both of the store's search slots.
func TestSecurityExportConcurrencyIsOne(t *testing.T) {
	if securityExportConcurrency != 1 {
		t.Errorf("securityExportConcurrency = %d, want 1", securityExportConcurrency)
	}
}

func TestSecuritySearchBusy(t *testing.T) {
	e := securityEnv(t, &fakeSecurityLogs{searchErr: fmt.Errorf("x: %w", store.ErrBusy)})
	resp, body := e.get(t, "/security?range=1h", e.loginAs(t, "operator"))
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Other security-log searches or an export are running. Try again in a moment.") {
		t.Errorf("busy search = %d, busy message shown = %v", resp.StatusCode, strings.Contains(body, "Try again in a moment"))
	}
}

// A search that didn't run to the end is audited with outcome error and why, not as "ok".
func TestSecuritySearchAuditOutcome(t *testing.T) {
	for _, c := range []struct {
		err             error
		outcome, result string
	}{
		{nil, "ok", ""},
		{fmt.Errorf("x: %w", store.ErrBusy), "error", "result=busy"},
		{context.DeadlineExceeded, "error", "result=time limit"},
		{errors.New("disk"), "error", "result=error"},
	} {
		e := securityEnv(t, &fakeSecurityLogs{searchErr: c.err})
		e.get(t, "/security?range=1h", e.loginAs(t, "operator"))
		rows := secAuditRows(t, e, "security_logs_search")
		if len(rows) != 1 || rows[0].Outcome != c.outcome || !strings.Contains(rows[0].Detail, c.result) ||
			(c.result == "" && strings.Contains(rows[0].Detail, "result=")) || !strings.Contains(rows[0].Detail, "range=1h") {
			t.Errorf("err %v: audit rows %+v, want outcome %s with %q", c.err, rows, c.outcome, c.result)
		}
	}
}

// A term on a secret field is refused: such values are stored [redacted], so it can never match, and
// the typed value is kept out of the audit log and the address bar. Presence (f.password:*) is fine.
func TestSecuritySecretFieldRefused(t *testing.T) {
	realQueryParser(t)
	f := &fakeSecurityLogs{}
	e := securityEnv(t, f)
	owner := e.loginAs(t, "operator")
	typed := `kind:ssh.login -f.user.password:hunter2 actor:alice@example.com f.password:* f.API_KEY~sk_live_9 f.API_KEY:sk_test_2`
	_, body := e.get(t, "/security?q="+url.QueryEscape(typed)+"&range=6h", owner)
	for _, want := range []string{`class="error"`, "f.user.password, f.API_KEY: secret fields are stored redacted; their values can&#39;t be searched."} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
	for _, clear := range []string{"hunter2", "sk_live_9", "sk_test_2", "alice@example.com"} {
		if strings.Contains(body, clear) {
			t.Errorf("page still holds %q", clear)
		}
	}
	if s, _ := f.calls(); s != 0 || len(secAuditRows(t, e, "security_logs_search")) != 0 {
		t.Error("a search with a secret term ran or was audited")
	}
	wantQ := `kind:ssh.login actor:` + hashOf("alice@example.com") + ` f.password:*`
	if got := hrefOf(t, body, `data-replace-url="([^"]*)"`).Query().Get("q"); got != wantQ {
		t.Errorf("address bar q = %q, want %q", got, wantQ)
	}
	if !strings.Contains(body, `name="q" value="`+wantQ+`"`) {
		t.Errorf("search box does not show %q", wantQ)
	}
	if !reflect.DeepEqual(f.secretAsked, []string{"user.password", "actor", "API_KEY", "API_KEY"}) {
		t.Errorf("SecretField asked about %q, want the keys as typed after f. and actor", f.secretAsked)
	}

	// A secret term alone still takes its value out of the address bar.
	_, body = e.get(t, "/security?q="+url.QueryEscape("f.password:hunter2")+"&range=1h", owner)
	if strings.Contains(body, "hunter2") {
		t.Error("page holds the secret value")
	}
	if u := hrefOf(t, body, `data-replace-url="([^"]*)"`); u.Query().Has("q") || u.Query().Get("range") != "1h" {
		t.Errorf("address bar after a lone secret term = %q, want no q", u.String())
	}

	resp, xbody := e.get(t, "/security/export?q="+url.QueryEscape(typed), owner)
	if resp.StatusCode != http.StatusBadRequest || strings.Contains(xbody, "hunter2") {
		t.Errorf("export with a secret term = %d %q", resp.StatusCode, xbody)
	}
	if _, x := f.calls(); x != 0 || len(secAuditRows(t, e, "security_logs_export")) != 0 {
		t.Error("an export with a secret term ran or was audited")
	}

	// Presence of a secret field is a search.
	if _, body := e.get(t, "/security?q="+url.QueryEscape("f.password:*"), owner); strings.Contains(body, `class="error"`) {
		t.Error("f.password:* refused")
	}
	if s, _ := f.calls(); s != 1 {
		t.Errorf("searches = %d, want 1", s)
	}
}

// HEAD is not an export: refused without running one or auditing it.
func TestSecurityExportRefusesHEAD(t *testing.T) {
	f := &fakeSecurityLogs{exportOut: "{}\n"}
	e := securityEnv(t, f)
	owner := e.loginAs(t, "operator")
	resp := e.req(t, "HEAD", "/security/export", secPeer, nil, []*http.Cookie{owner}, nil)
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != "GET" {
		t.Errorf("HEAD export = %d (Allow %q), want 405 with Allow: GET", resp.StatusCode, resp.Header.Get("Allow"))
	}
	if _, x := f.calls(); x != 0 || len(secAuditRows(t, e, "security_logs_export")) != 0 {
		t.Error("HEAD ran or audited an export")
	}
}

// Free text is mapped like field values: emails and phone numbers in it are searched, shown, linked
// and audited as their hashes.
func TestSecuritySearchMapsText(t *testing.T) {
	realQueryParser(t)
	f := &fakeSecurityLogs{}
	e := securityEnv(t, f)
	owner := e.loginAs(t, "operator")
	typed := `kind:ssh.login alice@example.com "login from +2348012345678 failed"`
	_, body := e.get(t, "/security?q="+url.QueryEscape(typed)+"&range=6h", owner)
	wantText := []string{hashOf("alice@example.com"), "login from " + hashOf("+2348012345678") + " failed"}
	if got := f.searches[0].Text; !reflect.DeepEqual(got, wantText) {
		t.Errorf("searched text = %q, want %q", got, wantText)
	}
	for _, clear := range []string{"alice@example.com", "alice%40example.com", "2348012345678"} {
		if strings.Contains(body, clear) {
			t.Errorf("page still holds the clear value %q", clear)
		}
	}
	if got := hrefOf(t, body, `data-replace-url="([^"]*)"`).Query().Get("q"); !strings.Contains(got, hashOf("alice@example.com")) {
		t.Errorf("address bar q = %q, want the text hashed", got)
	}
	e.get(t, "/security/export?q="+url.QueryEscape(typed), owner)
	for _, action := range []string{"security_logs_search", "security_logs_export"} {
		rows := secAuditRows(t, e, action)
		if len(rows) != 1 || strings.Contains(rows[0].Detail, "alice@example.com") || strings.Contains(rows[0].Detail, "2348012345678") ||
			!strings.Contains(rows[0].Detail, hashOf("alice@example.com")) {
			t.Errorf("%s audit = %+v, want the text hashed", action, rows)
		}
	}
	if got := f.exports[0].Text; !reflect.DeepEqual(got, wantText) {
		t.Errorf("exported text = %q, want %q", got, wantText)
	}
}

func TestSecurityExportBadQuery(t *testing.T) {
	f := &fakeSecurityLogs{}
	e := securityEnv(t, f)
	e.srv.secParse = func(string) (query.Query, error) { return query.Query{}, errors.New("bad term <x>") }
	resp, body := e.get(t, "/security/export?q=x", e.loginAs(t, "operator"))
	if resp.StatusCode != http.StatusBadRequest || resp.Header.Get("Content-Disposition") != "" {
		t.Errorf("bad export query = %d (disposition %q)", resp.StatusCode, resp.Header.Get("Content-Disposition"))
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") || !strings.Contains(body, "bad term") {
		t.Errorf("bad export query body = %q (%s)", body, resp.Header.Get("Content-Type"))
	}
	if _, x := f.calls(); x != 0 || len(secAuditRows(t, e, "security_logs_export")) != 0 {
		t.Error("a bad query must not export or audit an export")
	}
}

func TestSecurityExportConcurrencyCap(t *testing.T) {
	f := &fakeSecurityLogs{entered: make(chan struct{}, securityExportConcurrency), block: make(chan struct{})}
	e := securityEnv(t, f)
	owner := e.loginAs(t, "operator")
	var wg sync.WaitGroup
	for i := 0; i < securityExportConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp := e.req(t, "GET", "/security/export", secPeer, nil, []*http.Cookie{owner}, nil)
			resp.Body.Close()
		}()
	}
	for i := 0; i < securityExportConcurrency; i++ {
		<-f.entered
	}
	third := make(chan int, 1)
	go func() {
		resp := e.req(t, "GET", "/security/export", secPeer, nil, []*http.Cookie{owner}, nil)
		resp.Body.Close()
		third <- resp.StatusCode
	}()
	select {
	case code := <-third:
		if code != http.StatusServiceUnavailable {
			t.Errorf("export over the concurrency cap = %d, want 503", code)
		}
	case <-f.entered:
		t.Error("an export over the concurrency cap ran")
		close(f.block)
		<-third
		wg.Wait()
		return
	}
	close(f.block)
	wg.Wait()
	if _, x := f.calls(); x != securityExportConcurrency {
		t.Errorf("exports run = %d, want %d", x, securityExportConcurrency)
	}
}

func TestSecurityAgo(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	for d, want := range map[time.Duration]string{
		3 * time.Second: "just now", 42 * time.Second: "42s ago", 5 * time.Minute: "5m ago",
		3 * time.Hour: "3h ago", 47 * time.Hour: "47h ago", 72 * time.Hour: "3d ago", -5 * time.Minute: "in 5m",
	} {
		if got := secAgo(now, now.Add(-d)); got != want {
			t.Errorf("secAgo(-%v) = %q, want %q", d, got, want)
		}
	}
	if got := secAgo(now, time.Time{}); got != "" {
		t.Errorf("secAgo(zero) = %q, want empty", got)
	}
}

// Every search the owner asks for is audited (info level) with the mapped query, never results; a
// plain page load, the status poll and a query that doesn't parse are not searches.
func TestSecuritySearchAudited(t *testing.T) {
	realQueryParser(t)
	f := &fakeSecurityLogs{result: store.Result{Events: []siem.Event{{V: 1, TS: time.Now(), Src: "host", Kind: "ssh.login", Msg: "result-text-xyz"}}}}
	e := securityEnv(t, f)
	owner := e.loginAs(t, "operator")
	e.get(t, "/security", owner)
	e.get(t, "/security/status", owner)
	e.get(t, "/security?q="+url.QueryEscape("nosuch:x"), owner)
	if rows := secAuditRows(t, e, "security_logs_search"); len(rows) != 0 {
		t.Fatalf("audited %d searches for a page load, a poll and a bad query: %+v", len(rows), rows)
	}
	e.get(t, "/security?q="+url.QueryEscape("kind:ssh.login actor:alice@example.com")+"&range=6h", owner)
	e.get(t, "/security?range=1h", owner) // the form submitted with no terms is still a search
	rows := secAuditRows(t, e, "security_logs_search")
	if len(rows) != 2 {
		t.Fatalf("audit rows = %d, want 2", len(rows))
	}
	r := rows[0]
	if r.Actor != "operator" || r.IP != "127.0.0.1" || r.Level != "info" || r.Outcome != "ok" {
		t.Errorf("search audit row = %+v", r)
	}
	for _, want := range []string{"kind:ssh.login", "actor:" + hashOf("alice@example.com"), "range=6h"} {
		if !strings.Contains(r.Detail, want) {
			t.Errorf("search audit detail %q missing %q", r.Detail, want)
		}
	}
	if strings.Contains(r.Detail, "alice@example.com") || strings.Contains(r.Detail, "result-text-xyz") {
		t.Errorf("search audit detail %q holds clear personal data or results", r.Detail)
	}
	if !strings.Contains(rows[1].Detail, "range=1h") {
		t.Errorf("second search audit detail = %q", rows[1].Detail)
	}
}

// Unlike an export, a search whose audit record can't be written still runs.
func TestSecuritySearchRunsWhenAuditFails(t *testing.T) {
	f := &fakeSecurityLogs{result: store.Result{Events: []siem.Event{{V: 1, TS: time.Now(), Src: "host", Kind: "ssh.login"}}}}
	e := securityEnv(t, f)
	owner := e.loginAs(t, "operator")
	if _, err := e.srv.db.ExecContext(context.Background(), `ALTER TABLE events RENAME TO events_gone`); err != nil {
		t.Fatal(err)
	}
	resp, body := e.get(t, "/security?range=6h", owner)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `<details class="sec-ev">`) {
		t.Errorf("search with a failing audit = %d, rows shown = %v", resp.StatusCode, strings.Contains(body, `<details class="sec-ev">`))
	}
	if s, _ := f.calls(); s != 1 {
		t.Errorf("searches = %d, want 1", s)
	}
}

// hrefOf returns the decoded URL of the first link matching pattern (one capture group: the href).
func hrefOf(t *testing.T, body, pattern string) *url.URL {
	t.Helper()
	m := regexp.MustCompile(pattern).FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no match for %s", pattern)
	}
	u, err := url.Parse(html.UnescapeString(m[1]))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// After a search, the address bar (via data-replace-url), the search box and the older/export links
// carry personal data as its hash only, and they search the same thing.
func TestSecuritySearchURLCarriesHashes(t *testing.T) {
	realQueryParser(t)
	before := time.Date(2026, 11, 23, 9, 14, 7, 0, time.UTC)
	f := &fakeSecurityLogs{exportOut: "{}\n", result: store.Result{
		Events: []siem.Event{{V: 1, TS: before, Src: siem.SrcApp, Kind: "auth.login_failed"}}, More: true, Before: before,
	}}
	e := securityEnv(t, f)
	owner := e.loginAs(t, "operator")
	typed := `kind:auth.login_failed actor:alice@example.com f.device.imei:356938035643809 "card declined"`
	_, body := e.get(t, "/security?q="+url.QueryEscape(typed)+"&range=7d", owner)
	for _, clear := range []string{"alice@example.com", "alice%40example.com", "356938035643809"} {
		if strings.Contains(body, clear) {
			t.Errorf("page still holds the clear value %q", clear)
		}
	}
	wantQ := `kind:auth.login_failed actor:` + hashOf("alice@example.com") + ` f.device.imei:` + hashOf("356938035643809") + ` "card declined"`
	if !strings.Contains(body, `name="q" value="`+strings.ReplaceAll(wantQ, `"`, "&#34;")+`"`) {
		t.Errorf("search box does not show the mapped query %q", wantQ)
	}
	replace := hrefOf(t, body, `data-replace-url="([^"]*)"`)
	older := hrefOf(t, body, `href="(/security\?[^"]*)"[^>]*>Show older events`)
	export := hrefOf(t, body, `href="(/security/export\?[^"]*)"`)
	for name, u := range map[string]*url.URL{"address bar": replace, "older link": older, "export link": export} {
		if got := u.Query().Get("q"); got != wantQ || u.Query().Get("range") != "7d" {
			t.Errorf("%s q = %q range = %q, want %q 7d", name, got, u.Query().Get("range"), wantQ)
		}
	}
	if replace.Path != "/security" {
		t.Errorf("address bar path = %q", replace.Path)
	}
	// The mapped query searches exactly what the typed one did (hashes are not hashed again).
	e.get(t, replace.String(), owner)
	e.get(t, older.String(), owner)
	e.get(t, export.String(), owner)
	first := f.searches[0]
	for i, q := range append(f.searches[1:], f.exports...) {
		if !reflect.DeepEqual(q.Terms, first.Terms) || !reflect.DeepEqual(q.Text, first.Text) {
			t.Errorf("follow-up search %d = %+v %q, want %+v %q", i, q.Terms, q.Text, first.Terms, first.Text)
		}
	}
}

// A search with no personal data keeps the query exactly as typed and leaves the address bar alone.
func TestSecuritySearchURLUntouchedWithoutPersonalData(t *testing.T) {
	realQueryParser(t)
	e := securityEnv(t, &fakeSecurityLogs{})
	typed := `KIND:ssh.login   out:failure`
	_, body := e.get(t, "/security?q="+url.QueryEscape(typed), e.loginAs(t, "operator"))
	if strings.Contains(body, "data-replace-url") {
		t.Error("address bar replaced although nothing was hashed")
	}
	if !strings.Contains(body, `name="q" value="`+typed+`"`) {
		t.Error("search box does not keep the query as typed")
	}
	if got := hrefOf(t, body, `href="(/security/export\?[^"]*)"`).Query().Get("q"); got != typed {
		t.Errorf("export link q = %q, want %q", got, typed)
	}
}

// encodeSecurityQuery writes a query that query.Parse reads back to the same terms and text.
func TestEncodeSecurityQueryRoundTrip(t *testing.T) {
	realQueryParser(t)
	for _, s := range []string{
		`kind:ssh.login out:failure`,
		`-app:web f.status>=500 lvl>=warn`,
		`f.path:"/a b" "two words" plain`,
		`ip:203.0.113.0/24 actor:h:0123456789abcdef geo.asn:13335`,
		`f.msg~"say \"hi\"" "back\\slash" -kind:auth.*`,
		`"http://x" "-dash" f.k:"tab	in" f.q:a"b`,
		`f.Weird.Key!=v app:*`,
	} {
		q, err := query.Parse(s)
		if err != nil {
			t.Fatalf("corpus %q: %v", s, err)
		}
		enc := encodeSecurityQuery(q)
		back, err := query.Parse(enc)
		if err != nil {
			t.Errorf("%q encoded as %q does not parse: %v", s, enc, err)
			continue
		}
		if !reflect.DeepEqual(back.Terms, q.Terms) || !reflect.DeepEqual(back.Text, q.Text) {
			t.Errorf("%q encoded as %q reads back as %+v %q, want %+v %q", s, enc, back.Terms, back.Text, q.Terms, q.Text)
		}
	}
}

// app.js swaps data-replace-url into the address bar (no inline script under the CSP).
func TestAppJSReplacesSearchURL(t *testing.T) {
	js, err := embeddedAssets.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`[data-replace-url]`, `history.replaceState(`} {
		if !strings.Contains(string(js), want) {
			t.Errorf("app.js missing %q", want)
		}
	}
}
