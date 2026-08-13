package web

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/gitstore"
)

// The git page split: a configured app has 4 sub-pages that each render with the sub-nav and their
// own concern; an unconfigured app's sub-pages bounce to the Overview.
func TestGitSubPagesRenderAndGate(t *testing.T) {
	e := buildGitHubServer(t)
	if err := e.srv.gitStore.Save(context.Background(), gitstore.SaveInput{
		Project: "shop", RepoURL: "git@github.com:octocat/app.git", Ref: "refs/heads/main", BuildPolicy: "never",
	}); err != nil {
		t.Fatal(err)
	}
	sess, _ := e.login(t, "127.0.0.1:1", testPassword, "")
	if sess == nil {
		t.Fatal("login failed")
	}
	get := func(path string) *http.Response {
		return e.req(t, "GET", path, "127.0.0.1:1", nil, []*http.Cookie{sess}, nil)
	}

	for _, p := range []string{"/apps/shop/git", "/apps/shop/git/history", "/apps/shop/git/connection", "/apps/shop/git/automation"} {
		resp := get(p)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s = %d, want 200", p, resp.StatusCode)
			continue
		}
		if !strings.Contains(readBody(resp), `class="subnav"`) {
			t.Errorf("%s is missing the git sub-nav", p)
		}
	}

	// Each sub-page carries only its own concern.
	if b := readBody(get("/apps/shop/git/automation")); !strings.Contains(b, "Webhook") || !strings.Contains(b, "Preview environments") {
		t.Error("automation page must show webhook + previews")
	}
	if b := readBody(get("/apps/shop/git/connection")); !strings.Contains(b, "Repository URL") {
		t.Error("connection page must show the repo form")
	}
	// The Overview must NOT still cram the webhook/previews onto it.
	if b := readBody(get("/apps/shop/git")); strings.Contains(b, "Preview environments") {
		t.Error("overview should no longer contain the preview-envs section")
	}

	// An unconfigured app's sub-pages redirect to the Overview (nothing to show yet).
	resp := get("/apps/nope/git/history")
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/apps/nope/git" {
		t.Errorf("unconfigured history = %d loc=%q, want 303 → /apps/nope/git", resp.StatusCode, resp.Header.Get("Location"))
	}
}
