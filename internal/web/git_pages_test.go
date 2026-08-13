package web

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/gitstore"
)

// A minimal valid mooring.yaml (slug "shop") for exercising the history store.
const paginationDef = `apiVersion: mooring/v1
kind: App
metadata:
  slug: shop
spec:
  compose:
    source: generated
    services:
      web:
        image: ghcr.io/acme/web:1.2
        ports:
          - internal: 8080
  edge:
    routes:
      - hostname: shop.example.com
        service: web
        port: 8080
`

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

// The deploy-history page paginates: page 1 marks the current version and links older; the last
// page links newer and marks nothing current (only the true newest row is "current").
func TestGitHistoryPagination(t *testing.T) {
	e := buildGitHubServer(t)
	ctx := context.Background()
	if err := e.srv.gitStore.Save(ctx, gitstore.SaveInput{
		Project: "shop", RepoURL: "git@github.com:octocat/app.git", Ref: "refs/heads/main", BuildPolicy: "never",
	}); err != nil {
		t.Fatal(err)
	}
	d, err := definition.Parse([]byte(paginationDef))
	if err != nil {
		t.Fatalf("parse def: %v", err)
	}
	for i := 0; i < 25; i++ { // 25 rows → a full page of 20 plus a second page of 5
		if _, err := e.srv.defStore.SaveCanonical(ctx, d, "deploy", ""); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}
	sess, _ := e.login(t, "127.0.0.1:1", testPassword, "")
	if sess == nil {
		t.Fatal("login failed")
	}
	body := func(path string) string {
		return readBody(e.req(t, "GET", path, "127.0.0.1:1", nil, []*http.Cookie{sess}, nil))
	}

	b1 := body("/apps/shop/git/history")
	if !strings.Contains(b1, "Older") {
		t.Error("page 1 should link to an older page")
	}
	if strings.Contains(b1, "Newer") {
		t.Error("page 1 should not link to a newer page")
	}
	if !strings.Contains(b1, "(current)") {
		t.Error("page 1 must mark the newest row as current")
	}

	b2 := body("/apps/shop/git/history?page=2")
	if !strings.Contains(b2, "Newer") {
		t.Error("page 2 should link back to a newer page")
	}
	if strings.Contains(b2, "Older") {
		t.Error("page 2 should not link to an older page (only 5 rows remain)")
	}
	if strings.Contains(b2, "(current)") {
		t.Error("page 2 must not mark any row current — the live version is on page 1")
	}
}
