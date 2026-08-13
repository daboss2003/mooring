package web

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/config"
	"github.com/daboss2003/mooring/internal/crypto"
	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/gitstore"
	"github.com/daboss2003/mooring/internal/secret"
	"github.com/daboss2003/mooring/internal/store"
)

// buildGitHubServer builds a server with "Connect with GitHub" enabled (an OAuth App
// configured) and a git store.
func buildGitHubServer(t *testing.T) *testEnv {
	t.Helper()
	hash, err := crypto.HashPassword([]byte(testPassword), crypto.DefaultArgon2Params)
	if err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	var b strings.Builder
	fmt.Fprintf(&b, "bind_addr: \"127.0.0.1:9000\"\n")
	fmt.Fprintf(&b, "encryption_key: %q\n", key)
	fmt.Fprintf(&b, "ip_allowlist:\n  - \"127.0.0.1/32\"\n")
	fmt.Fprintf(&b, "auth:\n  username: \"operator\"\n  password_hash: %q\n", hash)
	fmt.Fprintf(&b, "edge:\n  mode: \"managed\"\n  acme_email: \"ops@example.com\"\n  acme_ca: \"https://acme.example/directory\"\n")
	fmt.Fprintf(&b, "github:\n  client_id: \"cid123\"\n  client_secret: \"sek456\"\n")
	fmt.Fprintf(&b, "data_dir: %q\n", t.TempDir())
	cfg, err := config.Parse([]byte(b.String()))
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	cipher, _ := secret.NewCipher(make([]byte, 32), nil)
	srv, err := New(cfg, Deps{DB: db, GitStore: gitstore.New(db, cipher), DefStore: definition.NewStore(db, make([]byte, 32))})
	if err != nil {
		t.Fatal(err)
	}
	if !srv.githubEnabled() {
		t.Fatal("github should be enabled")
	}
	return &testEnv{srv: srv}
}

// The OAuth callback's whole CSRF defense is the state cookie. A callback with no
// matching state cookie must be rejected before any code exchange (no network call).
func TestGitHubCallbackRejectsBadState(t *testing.T) {
	e := buildGitHubServer(t)
	// No state cookie at all → reject.
	resp := e.req(t, "GET", "/github/callback?code=abc&state=anything", "127.0.0.1:1", nil, nil, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("callback with no state cookie = %d, want 404", resp.StatusCode)
	}
	// A mismatched state cookie → reject.
	ck := &http.Cookie{Name: e.srv.ghStateCookieName(), Value: "the-real-state"}
	resp = e.req(t, "GET", "/github/callback?code=abc&state=forged", "127.0.0.1:1", nil, []*http.Cookie{ck}, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("callback with mismatched state = %d, want 404", resp.StatusCode)
	}
}

// The connect-repo page surfaces the GitHub entry point when the feature is enabled.
func TestGitHubConnectButtonShown(t *testing.T) {
	e := buildGitHubServer(t)
	sess, _ := e.login(t, "127.0.0.1:1", testPassword, "")
	if sess == nil {
		t.Fatal("login failed")
	}
	resp := e.req(t, "GET", "/git/new", "127.0.0.1:1", nil, []*http.Cookie{sess}, nil)
	body := readBody(resp)
	if !strings.Contains(body, "/github/connect") || !strings.Contains(body, "Connect with GitHub") {
		t.Error("git/new should show the Connect-with-GitHub button when enabled")
	}
}

// Starting the flow (authenticated + CSRF) sets the state cookie and redirects the
// browser to GitHub's authorize endpoint.
func TestGitHubConnectStartsFlow(t *testing.T) {
	e := buildGitHubServer(t)
	sess, _ := e.login(t, "127.0.0.1:1", testPassword, "")
	get := e.req(t, "GET", "/git/new", "127.0.0.1:1", nil, []*http.Cookie{sess}, nil)
	csrf := cookieByName(get, e.srv.csrfCookieName())
	if csrf == nil {
		t.Fatal("no CSRF cookie")
	}
	resp := e.req(t, "POST", "/github/connect", "127.0.0.1:1",
		map[string]string{"Origin": "https://example.com"},
		[]*http.Cookie{sess, csrf},
		map[string][]string{"csrf_token": {csrf.Value}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("connect = %d, want 303", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "https://github.com/login/oauth/authorize") {
		t.Errorf("redirect Location = %q, want github authorize", loc)
	}
	if cookieByName(resp, e.srv.ghStateCookieName()) == nil {
		t.Error("connect must set the oauth state cookie")
	}
}

// Regression: the repo-picker page (GET /github/repos) must run withCSRFToken so its
// "Connect" form carries a valid token. Without that wrapper the rendered csrf_token
// is empty and picking a repo + Connect fails with "forbidden: csrf token mismatch".
// (The handler 303s here because no GitHub connection is stored, but the wrapper runs
// FIRST and must mint the cookie regardless.) Sending only the session cookie — no
// csrf cookie — forces withCSRFToken to issue one, which is what we assert.
func TestGitHubReposIssuesCSRFToken(t *testing.T) {
	e := buildGitHubServer(t)
	sess, _ := e.login(t, "127.0.0.1:1", testPassword, "")
	if sess == nil {
		t.Fatal("login failed")
	}
	resp := e.req(t, "GET", "/github/repos", "127.0.0.1:1", nil, []*http.Cookie{sess}, nil)
	if cookieByName(resp, e.srv.csrfCookieName()) == nil {
		t.Fatal("GET /github/repos issued no CSRF cookie — withCSRFToken missing; the picker form's csrf_token renders empty and Connect fails with a token mismatch")
	}
}
