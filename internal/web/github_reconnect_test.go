package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/github"
	"github.com/daboss2003/mooring/internal/gitstore"
)

func TestParseGitHubRepo(t *testing.T) {
	cases := []struct {
		in               string
		wantOwner, wantN string
		wantOK           bool
	}{
		{"git@github.com:daboss2003/credlock-mdm-backend.git", "daboss2003", "credlock-mdm-backend", true},
		{"https://github.com/octocat/app.git", "octocat", "app", true},
		{"https://github.com/octocat/app", "octocat", "app", true},
		{"ssh://git@github.com/octocat/app.git", "octocat", "app", true},
		{"git@gitlab.com:octocat/app.git", "", "", false},        // not github
		{"https://evil.com/github.com/x/y.git", "", "", false},   // not github host
		{"git@github.com:octocat/../secrets.git", "", "", false}, // traversal
		{"git@github.com:onlyone.git", "", "", false},            // no owner/name split
		{"", "", "", false},
	}
	for _, c := range cases {
		o, n, ok := parseGitHubRepo(c.in)
		if ok != c.wantOK || o != c.wantOwner || n != c.wantN {
			t.Errorf("parseGitHubRepo(%q) = (%q,%q,%v), want (%q,%q,%v)", c.in, o, n, ok, c.wantOwner, c.wantN, c.wantOK)
		}
	}
}

// Reconnect must (1) delete ONLY this app's own "mooring:<slug>" deploy key — never another key,
// (2) install a fresh key, and (3) update the SSH credential while PRESERVING other settings.
func TestGitHubReconnectReinstallsOnlyOwnKey(t *testing.T) {
	e := buildGitHubServer(t)

	var deleted []string
	var created bool
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/repos/octocat/app/keys":
			// This app's key (id 11) plus an UNRELATED key (id 22) that must be left alone.
			_, _ = w.Write([]byte(`[{"id":11,"title":"mooring:credlock"},{"id":22,"title":"someones-laptop"}]`))
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/repos/octocat/app/keys/"):
			deleted = append(deleted, strings.TrimPrefix(r.URL.Path, "/repos/octocat/app/keys/"))
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/repos/octocat/app/keys":
			created = true
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer mock.Close()
	e.srv.githubClient = github.New(mock.Client(), mock.URL, mock.URL)
	if err := e.srv.gitStore.SaveGitHubConn(context.Background(), "octocat", "gho_token"); err != nil {
		t.Fatal(err)
	}
	// Existing app connected via SSH, with a build policy that MUST survive the reconnect.
	if err := e.srv.gitStore.Save(context.Background(), gitstore.SaveInput{
		Project: "credlock", RepoURL: "git@github.com:octocat/app.git", Ref: "refs/heads/main",
		BuildPolicy: "on_missing", ComposePath: "docker-compose.yml",
		NewCred: strptr("OLD-DRIFTED-KEY"), CredKind: "ssh", KnownHosts: "kh",
	}); err != nil {
		t.Fatal(err)
	}

	sess, csrf := e.authed(t)
	resp := e.req(t, "POST", "/apps/credlock/git/reconnect", "127.0.0.1:1",
		map[string]string{"Origin": "https://example.com"},
		[]*http.Cookie{sess, csrf}, url.Values{"csrf_token": {csrf.Value}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("reconnect = %d, want 303", resp.StatusCode)
	}
	if len(deleted) != 1 || deleted[0] != "11" {
		t.Errorf("must delete ONLY the app's own key (id 11), got %v", deleted)
	}
	if !created {
		t.Error("a fresh deploy key must be installed")
	}
	cfg, ok, _ := e.srv.gitStore.Get("credlock")
	if !ok || cfg.CredKind != "ssh" || cfg.BuildPolicy != "on_missing" || cfg.RepoURL != "git@github.com:octocat/app.git" {
		t.Errorf("credential updated but settings must be preserved: %+v", cfg)
	}
	// The stored private key must have been replaced (no longer the drifted one).
	newKey, err := e.srv.gitStore.Creds("credlock")
	if err != nil || newKey.SSHKey == "OLD-DRIFTED-KEY" || newKey.SSHKey == "" {
		t.Fatalf("stored SSH key must be replaced with the freshly-installed key (err=%v)", err)
	}

	// A live preview inherits the base's key — rotating the base MUST re-sync it, or the preview
	// would strand on the revoked key. Enable previews, register one, reconnect again, and confirm
	// the preview now holds the base's freshly-rotated key.
	if err := e.srv.gitStore.SetPreviewEnabled(context.Background(), "credlock", true); err != nil {
		t.Skipf("previews API unavailable: %v", err)
	}
	if err := e.srv.gitStore.RegisterPreview(context.Background(), "credlock", "credlock-pr-7", "refs/heads/pr-7"); err != nil {
		t.Fatalf("register preview: %v", err)
	}
	resp2 := e.req(t, "POST", "/apps/credlock/git/reconnect", "127.0.0.1:1",
		map[string]string{"Origin": "https://example.com"},
		[]*http.Cookie{sess, csrf}, url.Values{"csrf_token": {csrf.Value}})
	if resp2.StatusCode != http.StatusSeeOther {
		t.Fatalf("second reconnect = %d, want 303", resp2.StatusCode)
	}
	base2, _ := e.srv.gitStore.Creds("credlock")
	prev, err := e.srv.gitStore.Creds("credlock-pr-7")
	if err != nil {
		t.Fatalf("preview creds: %v", err)
	}
	if prev.SSHKey != base2.SSHKey || prev.SSHKey == newKey.SSHKey {
		t.Errorf("preview must be re-synced to the base's freshly-rotated key (preview=%q base=%q oldbase=%q)",
			short(prev.SSHKey), short(base2.SSHKey), short(newKey.SSHKey))
	}
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func strptr(s string) *string { return &s }
