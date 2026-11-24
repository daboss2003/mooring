package web

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/apitoken"
	"github.com/daboss2003/mooring/internal/crypto"
	"github.com/daboss2003/mooring/internal/session"
	"github.com/daboss2003/mooring/internal/store"
)

type gapEvent struct {
	Actor, IP, Action, Target, Outcome, Level, Detail, UA string
}

func gapEvents(t *testing.T, db *store.DB, action string) []gapEvent {
	t.Helper()
	rows, err := db.Query(`SELECT actor, ip, action, target, outcome, level, detail, user_agent
		FROM events WHERE action = ? ORDER BY seq`, action)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []gapEvent
	for rows.Next() {
		var r gapEvent
		if err := rows.Scan(&r.Actor, &r.IP, &r.Action, &r.Target, &r.Outcome, &r.Level, &r.Detail, &r.UA); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

type capturedResp struct {
	status int
	header http.Header
	body   string
}

func capture(t *testing.T, resp *http.Response) capturedResp {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return capturedResp{resp.StatusCode, resp.Header, string(b)}
}

// invalidTOTP returns a 6-digit code that no step in the ±1 validity window accepts.
func invalidTOTP(t *testing.T, secret string) string {
	t.Helper()
	valid := map[string]bool{}
	now := time.Now()
	for _, d := range []time.Duration{-60 * time.Second, -30 * time.Second, 0, 30 * time.Second, 60 * time.Second} {
		c, err := crypto.GenerateTOTPCode(secret, now.Add(d))
		if err != nil {
			t.Fatal(err)
		}
		valid[c] = true
	}
	for i := 0; ; i++ {
		c := fmt.Sprintf("%06d", i)
		if !valid[c] {
			return c
		}
	}
}

// The audit row tells an unknown user, a wrong password, a wrong TOTP code and a replayed code
// apart; the HTTP response is identical for all four.
func TestLoginDenyDetailDistinguishesWithIdenticalResponses(t *testing.T) {
	secret, err := crypto.GenerateTOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, secret)
	get := e.req(t, "GET", "/login", "127.0.0.1:1", nil, nil, nil)
	csrf := cookieByName(get, e.srv.csrfCookieName())
	if csrf == nil {
		t.Fatal("no CSRF cookie")
	}
	const ua = "Mozilla/5.0 (test)"
	hdr := map[string]string{"Origin": "https://example.com", "User-Agent": ua}
	post := func(user, pw, code string) capturedResp {
		f := url.Values{"username": {user}, "password": {pw}, "csrf_token": {csrf.Value}}
		if code != "" {
			f.Set("totp", code)
		}
		return capture(t, e.req(t, "POST", "/login", "127.0.0.1:1", hdr, []*http.Cookie{csrf}, f))
	}

	unknown := post("intruder", testPassword, "")
	badPW := post("operator", "wrong-password", "")
	badTOTP := post("operator", testPassword, invalidTOTP(t, secret))
	code, err := crypto.GenerateTOTPCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if ok := post("operator", testPassword, code); ok.status != http.StatusSeeOther {
		t.Fatalf("login with a valid code = %d, want 303", ok.status)
	}
	replay := post("operator", testPassword, code)

	if unknown.status != http.StatusOK || !strings.Contains(unknown.body, "Invalid credentials.") {
		t.Fatalf("unknown user response = %d %q", unknown.status, unknown.body)
	}
	for name, got := range map[string]capturedResp{"wrong password": badPW, "wrong TOTP": badTOTP, "replayed TOTP": replay} {
		if !reflect.DeepEqual(got, unknown) {
			t.Errorf("%s response differs from the unknown-user response:\n got  %d %v\n want %d %v", name, got.status, got.header, unknown.status, unknown.header)
		}
	}

	var details []string
	for _, r := range gapEvents(t, e.srv.db, "login") {
		if r.Outcome != "deny" {
			continue
		}
		details = append(details, r.Detail)
		if r.Level != "security" || r.IP != "127.0.0.1" || r.UA != ua {
			t.Errorf("deny row %+v: want level security, ip 127.0.0.1, ua %q", r, ua)
		}
	}
	want := []string{"unknown user", "invalid password", "invalid TOTP code", "TOTP code already used"}
	if !reflect.DeepEqual(details, want) {
		t.Errorf("login deny details = %q, want %q", details, want)
	}
	// The success row carries the UA too.
	var okRows int
	for _, r := range gapEvents(t, e.srv.db, "login") {
		if r.Outcome == "ok" {
			okRows++
			if r.UA != ua {
				t.Errorf("login ok row UA = %q", r.UA)
			}
		}
	}
	if okRows != 1 {
		t.Errorf("login ok rows = %d, want 1", okRows)
	}
}

// Arming a lockout writes one login_lockout event, through the real login handler.
func TestLoginLockoutAuditedOnceThroughLogin(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	get := e.req(t, "GET", "/login", "127.0.0.1:1", nil, nil, nil)
	csrf := cookieByName(get, e.srv.csrfCookieName())
	hdr := map[string]string{"Origin": "https://example.com", "User-Agent": "brute/1"}
	for i := 0; i < peerMaxFailures+3; i++ {
		f := url.Values{"username": {"operator"}, "password": {"wrong"}, "csrf_token": {csrf.Value}}
		e.req(t, "POST", "/login", "127.0.0.1:1", hdr, []*http.Cookie{csrf}, f)
	}
	rows := gapEvents(t, e.srv.db, "login_lockout")
	if len(rows) != 1 {
		t.Fatalf("login_lockout rows = %d, want 1: %+v", len(rows), rows)
	}
	r := rows[0]
	if r.Actor != "operator" || r.IP != "127.0.0.1" || r.Level != "security" || r.Outcome != "deny" ||
		r.Target != "peer_user" || r.UA != "brute/1" {
		t.Errorf("login_lockout row = %+v", r)
	}
	if !strings.Contains(r.Detail, peerLockWindow.String()) || !strings.Contains(r.Detail, peerLockFor.String()) ||
		!strings.Contains(r.Detail, strconv.Itoa(peerMaxFailures)) {
		t.Errorf("login_lockout detail %q must name the threshold, window and lock duration", r.Detail)
	}
}

// Failures that land while the lock is already armed (a concurrent attempt, the app-delete
// re-auth) don't write another event; a re-arm after the lock expired does.
func TestLockoutEventOncePerArming(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	ctx := context.Background()

	for i := 0; i < peerMaxFailures+3; i++ {
		e.srv.recordFailure(ctx, "198.51.100.1", "operator")
	}
	if n := len(gapEvents(t, e.srv.db, "login_lockout")); n != 1 {
		t.Fatalf("after %d failures from one address: %d lockout events, want 1", peerMaxFailures+3, n)
	}
	if !e.srv.locked(ctx, "198.51.100.1", "operator") {
		t.Fatal("the address must be locked")
	}

	// Per-user counter: rotate addresses (4 failures each, never arming a peer lock) to 50.
	var calls int
	for p := 2; calls < userMaxFailures-(peerMaxFailures+3); p++ {
		for j := 0; j < peerMaxFailures-1 && calls < userMaxFailures-(peerMaxFailures+3); j++ {
			e.srv.recordFailure(ctx, fmt.Sprintf("198.51.100.%d", p), "operator")
			calls++
		}
	}
	userRows := func() []gapEvent {
		var out []gapEvent
		for _, r := range gapEvents(t, e.srv.db, "login_lockout") {
			if r.Target == "user" {
				out = append(out, r)
			}
		}
		return out
	}
	if got := userRows(); len(got) != 1 {
		t.Fatalf("per-user lockout events after %d failures = %d, want 1", userMaxFailures, len(got))
	}
	e.srv.recordFailure(ctx, "203.0.113.50", "operator") // lands while locked
	if got := userRows(); len(got) != 1 {
		t.Fatalf("a failure while the user is locked wrote another event (%d)", len(got))
	}
	if r := userRows()[0]; r.Actor != "operator" || !strings.Contains(r.Detail, userLockFor.String()) {
		t.Errorf("per-user lockout row = %+v", r)
	}

	// Lock expires; the next failure inside the counting window re-arms it — a new lockout.
	if _, err := e.srv.db.Exec(`UPDATE login_attempts SET locked_until = ? WHERE scope = 'user'`, time.Now().Unix()-1); err != nil {
		t.Fatal(err)
	}
	e.srv.recordFailure(ctx, "203.0.113.51", "operator")
	if got := userRows(); len(got) != 2 {
		t.Fatalf("re-arm after expiry: %d per-user lockout events, want 2", len(got))
	}
	if !e.srv.locked(ctx, "203.0.113.99", "operator") {
		t.Error("the user must be locked again after the re-arm")
	}
}

// Concurrent failures crossing the threshold arm the lock, and write the event, exactly once.
func TestLockoutEventOnceUnderConcurrency(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	ctx := context.Background()
	for i := 0; i < peerMaxFailures-1; i++ {
		e.srv.recordFailure(ctx, "198.51.100.9", "operator")
	}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.srv.recordFailure(ctx, "198.51.100.9", "operator")
		}()
	}
	wg.Wait()
	if n := len(gapEvents(t, e.srv.db, "login_lockout")); n != 1 {
		t.Fatalf("concurrent arming wrote %d lockout events, want 1", n)
	}
}

// A successful bearer request is audited once per token and address per window.
func TestAPITokenUseAuditedOncePerWindow(t *testing.T) {
	e, _, pt := buildAPIServer(t, true, seedToken{[]string{"status:read", "metrics:read"}, []string{"198.51.100.0/24"}})
	id, _, _ := apitoken.SplitBearer(pt[0])
	h := bearer(pt[0])
	h["User-Agent"] = "ci-runner/3"
	for i := 0; i < 3; i++ {
		if resp := e.req(t, "GET", "/api/v1/status", "198.51.100.5:1", h, nil, nil); resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d", resp.StatusCode)
		}
	}
	e.req(t, "GET", "/api/v1/metrics", "198.51.100.5:1", h, nil, nil)
	rows := gapEvents(t, e.srv.db, "api_token_use")
	if len(rows) != 1 {
		t.Fatalf("api_token_use rows after 4 requests from one address = %d, want 1", len(rows))
	}
	r := rows[0]
	if r.Actor != "api:"+id || r.IP != "198.51.100.5" || r.Target != "GET /api/v1/status" ||
		r.Level != "info" || r.Outcome != "ok" || r.UA != "ci-runner/3" {
		t.Errorf("api_token_use row = %+v", r)
	}
	if strings.Contains(r.Detail+r.Target+r.Actor, pt[0][len(pt[0])-20:]) {
		t.Error("the token secret reached the audit row")
	}
	// Another address of the same token is a new key.
	e.req(t, "GET", "/api/v1/status", "198.51.100.6:1", h, nil, nil)
	if n := len(gapEvents(t, e.srv.db, "api_token_use")); n != 2 {
		t.Fatalf("api_token_use rows after a second address = %d, want 2", n)
	}
	// A refused request is not a use.
	e.req(t, "GET", "/api/v1/audit", "198.51.100.7:1", h, nil, nil) // lacks audit:read → 403
	if n := len(gapEvents(t, e.srv.db, "api_token_use")); n != 2 {
		t.Fatalf("a refused request wrote api_token_use (%d rows)", n)
	}
	// Refusals carry the UA too.
	var sawUA bool
	for _, r := range gapEvents(t, e.srv.db, "api_request") {
		if r.Outcome == "deny" && r.UA == "ci-runner/3" {
			sawUA = true
		}
	}
	if !sawUA {
		t.Error("the api_request deny row has no User-Agent")
	}
}

func TestSeenWindowDedupe(t *testing.T) {
	sw := newSeenWindow(5*time.Minute, 100)
	t0 := time.Unix(1_800_000_000, 0)
	if !sw.first("k", t0) {
		t.Fatal("first sighting must record")
	}
	if sw.first("k", t0.Add(5*time.Minute-time.Second)) {
		t.Fatal("a repeat inside the window must not record")
	}
	if !sw.first("k", t0.Add(5*time.Minute)) {
		t.Fatal("a repeat once the window passed must record")
	}
	if !sw.first("other", t0) {
		t.Fatal("another key records")
	}
	// A clock stepped backwards doesn't suppress the key for the size of the step.
	if !sw.first("k", t0.Add(-time.Hour)) {
		t.Fatal("an entry from the future must not suppress")
	}
}

func (sw *seenWindow) size() int {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	return len(sw.seen)
}

func TestSeenWindowBounded(t *testing.T) {
	sw := newSeenWindow(5*time.Minute, 3)
	t0 := time.Unix(1_800_000_000, 0)
	for _, k := range []string{"a", "b", "c"} {
		sw.first(k, t0)
	}
	// Full of live keys: a new key is still recorded and the map never grows past the bound.
	if !sw.first("d", t0.Add(time.Second)) {
		t.Fatal("a new key must record even when the map is full")
	}
	if n := sw.size(); n > 3 {
		t.Fatalf("map holds %d keys, bound is 3", n)
	}
	// Expired keys are dropped before anything live is.
	sw2 := newSeenWindow(5*time.Minute, 3)
	sw2.first("old1", t0)
	sw2.first("old2", t0)
	sw2.first("live", t0.Add(4*time.Minute))
	if !sw2.first("new", t0.Add(6*time.Minute)) {
		t.Fatal("new key must record")
	}
	if n := sw2.size(); n != 2 {
		t.Fatalf("after sweeping expired keys the map holds %d, want 2 (live + new)", n)
	}
	if sw2.first("live", t0.Add(6*time.Minute)) {
		t.Fatal("the live key must survive the sweep and still be deduped")
	}
}

func TestAlertRuleDeleteAudited(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	hdr := map[string]string{"Origin": "https://example.com", "User-Agent": "browser/9"}
	f := url.Values{"name": {"cpu high"}, "kind": {"host_cpu"}, "threshold": {"90"}, "for_seconds": {"60"}, "level": {"warning"}, "enabled": {"on"}, "csrf_token": {csrf.Value}}
	if resp := e.req(t, "POST", "/alerts/rules", "127.0.0.1:1", hdr, cookies, f); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("rule save = %d", resp.StatusCode)
	}
	rules, err := e.srv.alertStore.ListRules()
	if err != nil || len(rules) != 1 {
		t.Fatalf("rules = %v, %v", rules, err)
	}
	id := strconv.FormatInt(rules[0].ID, 10)
	del := url.Values{"id": {id}, "csrf_token": {csrf.Value}}
	if resp := e.req(t, "POST", "/alerts/rules/delete", "127.0.0.1:1", hdr, cookies, del); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("rule delete = %d", resp.StatusCode)
	}
	rows := gapEvents(t, e.srv.db, "alert_rule_delete")
	if len(rows) != 1 {
		t.Fatalf("alert_rule_delete rows = %d, want 1", len(rows))
	}
	r := rows[0]
	if r.Actor != "operator" || r.IP != "127.0.0.1" || r.Target != "cpu high" || r.Outcome != "ok" ||
		r.Level != "security" || r.Detail != "id "+id || r.UA != "browser/9" {
		t.Errorf("alert_rule_delete row = %+v", r)
	}
	if save := gapEvents(t, e.srv.db, "alert_rule_save"); len(save) != 1 || save[0].UA != "browser/9" {
		t.Errorf("alert_rule_save rows = %+v", save)
	}
	// Deleting an id that doesn't exist is recorded as an error, not as a deletion.
	gone := url.Values{"id": {"999999"}, "csrf_token": {csrf.Value}}
	e.req(t, "POST", "/alerts/rules/delete", "127.0.0.1:1", hdr, cookies, gone)
	rows = gapEvents(t, e.srv.db, "alert_rule_delete")
	if len(rows) != 2 || rows[1].Outcome != "error" || rows[1].Target != "999999" {
		t.Errorf("delete of a missing rule: rows = %+v", rows)
	}
}

// rbac_deny and logout carry the request's User-Agent.
func TestRBACDenyAndLogoutCarryUA(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	h := e.srv.requirePerm("admin", func(w http.ResponseWriter, r *http.Request) {})
	r := httptest.NewRequest("POST", "/x", nil)
	r.Header.Set("User-Agent", "viewer-browser/1")
	r = r.WithContext(withSession(r.Context(), &session.Session{Username: "ghost"}))
	h(httptest.NewRecorder(), r)
	rows := gapEvents(t, e.srv.db, "rbac_deny")
	if len(rows) != 1 || rows[0].UA != "viewer-browser/1" {
		t.Fatalf("rbac_deny rows = %+v", rows)
	}

	sess, csrf := e.authed(t)
	e.req(t, "POST", "/logout", "127.0.0.1:1", map[string]string{"Origin": "https://example.com", "User-Agent": "leaving/1"},
		[]*http.Cookie{sess, csrf}, url.Values{"csrf_token": {csrf.Value}})
	out := gapEvents(t, e.srv.db, "logout")
	if len(out) != 1 || out[0].UA != "leaving/1" {
		t.Fatalf("logout rows = %+v", out)
	}
}
