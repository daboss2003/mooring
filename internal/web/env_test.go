package web

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/compose"
	"github.com/daboss2003/mooring/internal/envstore"
	"github.com/daboss2003/mooring/internal/monitor"
	"github.com/daboss2003/mooring/internal/secret"
)

// authedEnv logs in and returns the session + csrf cookies plus the csrf token.
func (e *testEnv) authed(t *testing.T) (sess, csrf *http.Cookie) {
	t.Helper()
	get := e.req(t, "GET", "/login", "127.0.0.1:1", nil, nil, nil)
	csrf = cookieByName(get, e.srv.csrfCookieName())
	form := url.Values{"username": {"operator"}, "password": {testPassword}, "csrf_token": {csrf.Value}}
	post := e.req(t, "POST", "/login", "127.0.0.1:1", map[string]string{"Origin": "https://example.com"}, []*http.Cookie{csrf}, form)
	sess = cookieByName(post, e.srv.cookieName())
	if sess == nil {
		t.Fatal("login failed")
	}
	return sess, csrf
}

func TestEnvSecretMaskedAndRevealed(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	hdr := map[string]string{"Origin": "https://example.com"}

	// set a secret
	resp := e.req(t, "POST", "/apps/shop/env/secret", "127.0.0.1:1", hdr, cookies,
		url.Values{"key": {"DB_PASSWORD"}, "value": {"s3cr3t-value-xyz"}, "csrf_token": {csrf.Value}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("set secret = %d, want 303", resp.StatusCode)
	}

	// the env page must MASK the secret, never show the plaintext
	page := readBody(e.req(t, "GET", "/apps/shop/env", "127.0.0.1:1", nil, cookies, nil))
	if strings.Contains(page, "s3cr3t-value-xyz") {
		t.Error("env page leaked the secret plaintext")
	}
	if !strings.Contains(page, "DB_PASSWORD") {
		t.Error("env page missing the secret key")
	}

	// reveal returns the plaintext as text/plain, no-store
	rev := e.req(t, "POST", "/apps/shop/env/reveal", "127.0.0.1:1", hdr, cookies,
		url.Values{"key": {"DB_PASSWORD"}, "csrf_token": {csrf.Value}})
	if rev.StatusCode != http.StatusOK {
		t.Fatalf("reveal = %d, want 200", rev.StatusCode)
	}
	if got := rev.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("reveal Cache-Control = %q, want no-store", got)
	}
	if body := readBody(rev); body != "s3cr3t-value-xyz" {
		t.Errorf("reveal body = %q, want the plaintext", body)
	}

	// reveal requires CSRF (a POST without the token is rejected)
	noCSRF := e.req(t, "POST", "/apps/shop/env/reveal", "127.0.0.1:1", hdr, []*http.Cookie{sess, csrf},
		url.Values{"key": {"DB_PASSWORD"}})
	if noCSRF.StatusCode != http.StatusForbidden {
		t.Errorf("reveal without CSRF = %d, want 403", noCSRF.StatusCode)
	}
}

func TestEnvLiteralsRoundTrip(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	resp := e.req(t, "POST", "/apps/shop/env", "127.0.0.1:1", map[string]string{"Origin": "https://example.com"}, cookies,
		url.Values{"literals": {"LOG_LEVEL=info\nWORKERS=4"}, "csrf_token": {csrf.Value}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("save literals = %d, want 303", resp.StatusCode)
	}
	page := readBody(e.req(t, "GET", "/apps/shop/env", "127.0.0.1:1", nil, cookies, nil))
	if !strings.Contains(page, "LOG_LEVEL=info") || !strings.Contains(page, "WORKERS=4") {
		t.Errorf("literals not persisted/rendered")
	}
}

func TestEnvBadKeyRejected(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	resp := e.req(t, "POST", "/apps/shop/env/secret", "127.0.0.1:1", map[string]string{"Origin": "https://example.com"},
		[]*http.Cookie{sess, csrf}, url.Values{"key": {"BAD KEY"}, "value": {"x"}, "csrf_token": {csrf.Value}})
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("bad key = %d, want 422", resp.StatusCode)
	}
}

// review #2: env values containing ${VAR} are expanded to a fixpoint so the
// validator sees what docker compose will render.
func TestResolveEnvValuesFixpoint(t *testing.T) {
	env := compose.Env{"IMG": "alpine:${TAG}", "TAG": "latest", "FULL": "${IMG}-${SUFFIX}", "SUFFIX": "x"}
	out := resolveEnvValues(env)
	if out["IMG"] != "alpine:latest" {
		t.Errorf("IMG = %q, want alpine:latest", out["IMG"])
	}
	if out["FULL"] != "alpine:latest-x" {
		t.Errorf("FULL = %q, want alpine:latest-x", out["FULL"])
	}
}

// review #1/#6: each render is a unique 0600 file (no cross-app collision / no
// symlink follow), and cleanup removes it.
func TestRenderEnvFileUniqueAnd0600(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.cfg.DataDir = t.TempDir()
	if _, err := e.srv.envStore.Save(context.Background(), "a.b", []envstore.Entry{{Key: "K", Value: secret.New("v"), Secret: false}}, "op"); err != nil {
		t.Fatal(err)
	}
	app := &monitor.App{Project: "a.b", WorkingDir: "/srv/a"}
	env := compose.Env{"K": "v"}
	p1, c1, err := e.srv.renderEnvFile(app, env)
	if err != nil || p1 == "" {
		t.Fatalf("render1: %v %q", err, p1)
	}
	defer c1()
	p2, c2, err := e.srv.renderEnvFile(app, env)
	if err != nil || p2 == "" {
		t.Fatalf("render2: %v %q", err, p2)
	}
	defer c2()
	if p1 == p2 {
		t.Error("two renders produced the same path (collision risk)")
	}
	fi, err := os.Stat(p1)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("env file not 0600: %v mode=%v", err, fi.Mode().Perm())
	}
	c1()
	if _, err := os.Stat(p1); !os.IsNotExist(err) {
		t.Error("cleanup did not remove the env file")
	}
}

// Compose reads its own control variables (COMPOSE_PROFILES, COMPOSE_PROJECT_NAME, …) from the
// --env-file, so an app env key must never reach it: COMPOSE_PROFILES=mooring-scheduled would start the
// scheduled services on every `up`. Ordinary keys still render.
func TestRenderEnvFileDropsComposeControlVars(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.cfg.DataDir = t.TempDir()
	if _, err := e.srv.envStore.Save(context.Background(), "shop", []envstore.Entry{{Key: "K", Value: secret.New("v"), Secret: false}}, "op"); err != nil {
		t.Fatal(err)
	}
	app := &monitor.App{Project: "shop", WorkingDir: "/srv/shop"}
	env := compose.Env{"K": "v", "COMPOSE_PROFILES": "mooring-scheduled", "COMPOSE_PROJECT_NAME": "other", "COMPOSER_HOME": "/c",
		"DOCKER_DEFAULT_PLATFORM": "linux/amd64", "COMPOSE_TOKEN": "app-secret"}
	p, c, err := e.srv.renderEnvFile(app, env)
	if err != nil || p == "" {
		t.Fatalf("render: %v %q", err, p)
	}
	defer c()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if strings.Contains(got, "COMPOSE_PROFILES") || strings.Contains(got, "COMPOSE_PROJECT_NAME") || strings.Contains(got, "DOCKER_DEFAULT_PLATFORM") {
		t.Errorf("compose control variables must be dropped:\n%s", got)
	}
	if !strings.Contains(got, "K=v\n") || !strings.Contains(got, "COMPOSER_HOME=/c\n") || !strings.Contains(got, "COMPOSE_TOKEN=app-secret\n") {
		t.Errorf("ordinary keys (incl. an app's own COMPOSE_TOKEN) must still render:\n%s", got)
	}
}

// Importing a .env file from disk parses, classifies, and stores its entries — the
// path behind the file picker (whose accept= filter was dropped so dotenv files are
// selectable). Literals end up visible on the env page.
func TestEnvImportFromFile(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	content := "APP_NAME=demo\nAPI_URL=https://api.example.com\nLOG_LEVEL=info\n"
	resp := e.reqUpload(t, "/apps/shop/env/import", "127.0.0.1:1", csrf.Value, "envfile", ".env", content, cookies)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("env import = %d, want 303", resp.StatusCode)
	}
	body := readBody(e.req(t, "GET", "/apps/shop/env", "127.0.0.1:1", nil, cookies, nil))
	for _, want := range []string{"APP_NAME", "demo", "API_URL", "LOG_LEVEL"} {
		if !strings.Contains(body, want) {
			t.Errorf("imported env not shown on page: missing %q", want)
		}
	}
}

// Pre-deploy reachability: the env editor must be usable BEFORE an app's first
// deploy (otherwise: can't set env without deploying, can't deploy sanely without
// env). The app home 404s until containers exist, so the env page's breadcrumb must
// fall back to the repository page rather than that 404.
func TestEnvReachableBeforeDeploy(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	resp := e.req(t, "GET", "/apps/newrepo/env", "127.0.0.1:1", nil, []*http.Cookie{sess, csrf}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET env pre-deploy = %d, want 200 (env must be reachable before first deploy)", resp.StatusCode)
	}
	if body := readBody(resp); !strings.Contains(body, `href="/apps/newrepo/git"`) {
		t.Errorf("env breadcrumb must fall back to the repository page pre-deploy (no 404 to the app home)")
	}
}

// review #7/#11: a protected project's env is not editable.
func TestEnvProtectedProjectBlocked(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.cfg.ProtectedProjects = []string{"edge"}
	sess, csrf := e.authed(t)
	resp := e.req(t, "POST", "/apps/edge/env/secret", "127.0.0.1:1", map[string]string{"Origin": "https://example.com"},
		[]*http.Cookie{sess, csrf}, url.Values{"key": {"X"}, "value": {"y"}, "csrf_token": {csrf.Value}})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("protected project env edit = %d, want 403", resp.StatusCode)
	}
}

// A protected project's RICH queue actions (pause/resume/retry-failed) carry a
// server-held secret — they must be refused at the handler, unconditionally, even
// before the ops-availability check, mirroring every other write path.
func TestQueueActionProtectedProjectBlocked(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.cfg.ProtectedProjects = []string{"mooring-socket-proxy"}
	sess, csrf := e.authed(t)
	resp := e.req(t, "POST", "/apps/mooring-socket-proxy/queues/default/pause", "127.0.0.1:1",
		map[string]string{"Origin": "https://example.com"},
		[]*http.Cookie{sess, csrf}, url.Values{"csrf_token": {csrf.Value}})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("protected project queue action = %d, want 403", resp.StatusCode)
	}
}
