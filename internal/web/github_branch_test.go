package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/github"
)

// When a picked repo has more than one branch, the connect flow asks WHICH branch to deploy
// (default pre-selected) before the first fetch — instead of silently reading mooring.yaml from a
// possibly-wrong default.
func TestGitHubChooseBranchPromptsWhenMultiple(t *testing.T) {
	e := buildGitHubServer(t)
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/octocat/app/branches" {
			_, _ = w.Write([]byte(`[{"name":"main"},{"name":"develop"}]`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer mock.Close()
	e.srv.githubClient = github.New(mock.Client(), mock.URL, mock.URL)
	if err := e.srv.gitStore.SaveGitHubConn(context.Background(), "octocat", "gho_token"); err != nil {
		t.Fatal(err)
	}

	sess, csrf := e.authed(t)
	resp := e.req(t, "POST", "/github/choose-branch", "127.0.0.1:1", map[string]string{"Origin": "https://example.com"},
		[]*http.Cookie{sess, csrf}, url.Values{"csrf_token": {csrf.Value}, "full_name": {"octocat/app"}, "default_branch": {"main"}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("choose-branch = %d, want 200 (the chooser)", resp.StatusCode)
	}
	body := readBody(resp)
	if !strings.Contains(body, `name="branch"`) || !strings.Contains(body, "develop") {
		t.Errorf("the branch chooser must list the branches, got: %s", body)
	}
	if !strings.Contains(body, `action="/github/connect-repo"`) {
		t.Error("the chooser must submit the chosen branch to /github/connect-repo")
	}
	// The default branch is pre-selected.
	if !strings.Contains(body, `value="main" selected`) {
		t.Error("the repo's default branch must be pre-selected")
	}
}
