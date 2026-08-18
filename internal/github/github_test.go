package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestGenerateDeployKeyRoundTrips(t *testing.T) {
	k, err := GenerateDeployKey("mooring:my-app")
	if err != nil {
		t.Fatal(err)
	}
	// The private half parses as an OpenSSH key.
	signer, err := ssh.ParsePrivateKey([]byte(k.PrivatePEM))
	if err != nil {
		t.Fatalf("private key not parseable: %v", err)
	}
	// The public line parses and matches the private key.
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k.PublicLine))
	if err != nil {
		t.Fatalf("public line not parseable: %v", err)
	}
	if signer.PublicKey().Type() != "ssh-ed25519" {
		t.Errorf("expected ed25519, got %s", signer.PublicKey().Type())
	}
	if string(pub.Marshal()) != string(signer.PublicKey().Marshal()) {
		t.Error("public line does not match the generated private key")
	}
	// Two keys differ.
	k2, _ := GenerateDeployKey("mooring:my-app")
	if k2.PublicLine == k.PublicLine {
		t.Error("two generated keys must differ")
	}
}

func TestAuthorizeURL(t *testing.T) {
	c := New(http.DefaultClient, "", "")
	u := c.AuthorizeURL("CID", "https://helm.example/github/callback", "st8")
	for _, want := range []string{"https://github.com/login/oauth/authorize?", "client_id=CID", "state=st8", "scope=repo", "allow_signup=false", "redirect_uri=https%3A%2F%2Fhelm.example%2Fgithub%2Fcallback"} {
		if !strings.Contains(u, want) {
			t.Errorf("authorize URL missing %q: %s", want, u)
		}
	}
}

func TestExchangeCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login/oauth/access_token" || r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = r.ParseForm()
		if r.Form.Get("code") != "thecode" || r.Form.Get("client_secret") != "sek" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"gho_TOKEN","token_type":"bearer","scope":"repo"}`))
	}))
	defer srv.Close()
	c := New(srv.Client(), srv.URL, srv.URL)
	tok, err := c.ExchangeCode(context.Background(), "cid", "sek", "thecode", "https://x/cb")
	if err != nil {
		t.Fatal(err)
	}
	if tok != "gho_TOKEN" {
		t.Errorf("token = %q", tok)
	}
	// A GitHub error body (no access_token) is an error, not a silent empty token.
	if _, err := c.ExchangeCode(context.Background(), "cid", "WRONG", "thecode", "https://x/cb"); err == nil {
		t.Error("a failed exchange must error")
	}
}

func TestViewerAndListRepos(t *testing.T) {
	var sawAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		switch {
		case r.URL.Path == "/user":
			_, _ = w.Write([]byte(`{"login":"octocat"}`))
		case r.URL.Path == "/user/repos":
			_, _ = w.Write([]byte(`[{"full_name":"octocat/app","name":"app","private":true,"default_branch":"main","ssh_url":"git@github.com:octocat/app.git","owner":{"login":"octocat"}}]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c := New(srv.Client(), srv.URL, srv.URL)

	login, err := c.Viewer(context.Background(), "gho_X")
	if err != nil || login != "octocat" {
		t.Fatalf("viewer: %q %v", login, err)
	}
	if sawAuth != "Bearer gho_X" {
		t.Errorf("auth header = %q", sawAuth)
	}
	repos, err := c.ListRepos(context.Background(), "gho_X")
	if err != nil || len(repos) != 1 {
		t.Fatalf("repos: %d %v", len(repos), err)
	}
	if repos[0].FullName != "octocat/app" || !repos[0].Private || repos[0].Owner.Login != "octocat" {
		t.Errorf("repo parse wrong: %+v", repos[0])
	}
}

func TestListBranches(t *testing.T) {
	var sawPath, sawAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawPath, sawAuth = r.URL.Path, r.Header.Get("Authorization")
		if r.URL.Path == "/repos/octocat/app/branches" {
			_, _ = w.Write([]byte(`[{"name":"main"},{"name":"develop"},{"name":"release/1.x"}]`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c := New(srv.Client(), srv.URL, srv.URL)

	branches, err := c.ListBranches(context.Background(), "gho_X", "octocat", "app")
	if err != nil {
		t.Fatalf("list branches: %v", err)
	}
	if len(branches) != 3 || branches[0].Name != "main" || branches[2].Name != "release/1.x" {
		t.Errorf("branch parse wrong: %+v", branches)
	}
	if sawPath != "/repos/octocat/app/branches" {
		t.Errorf("path = %q", sawPath)
	}
	if sawAuth != "Bearer gho_X" {
		t.Errorf("auth header = %q", sawAuth)
	}
}

func TestCreateDeployKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/repos/octocat/app/keys" && r.Method == http.MethodPost {
			w.WriteHeader(http.StatusCreated)
			return
		}
		if r.URL.Path == "/repos/octocat/dupe/keys" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := New(srv.Client(), srv.URL, srv.URL)
	if err := c.CreateDeployKey(context.Background(), "gho_X", "octocat", "app", "mooring:app", "ssh-ed25519 AAAA x"); err != nil {
		t.Fatalf("create: %v", err)
	}
	// A duplicate key (422) maps to ErrKeyExists (treat as already-installed).
	if err := c.CreateDeployKey(context.Background(), "gho_X", "octocat", "dupe", "t", "k"); err != ErrKeyExists {
		t.Errorf("duplicate key should be ErrKeyExists, got %v", err)
	}
}

func TestListAndDeleteDeployKeys(t *testing.T) {
	var deleted []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/repos/octocat/app/keys" && r.Method == http.MethodGet:
			_, _ = w.Write([]byte(`[{"id":11,"title":"mooring:app"},{"id":22,"title":"someone-else"}]`))
		case strings.HasPrefix(r.URL.Path, "/repos/octocat/app/keys/") && r.Method == http.MethodDelete:
			deleted = append(deleted, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/repos/octocat/gone/keys/99" && r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNotFound) // idempotent
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()
	c := New(srv.Client(), srv.URL, srv.URL)

	keys, err := c.ListDeployKeys(context.Background(), "gho_X", "octocat", "app")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 2 || keys[0].ID != 11 || keys[0].Title != "mooring:app" {
		t.Fatalf("unexpected keys: %+v", keys)
	}
	if err := c.DeleteDeployKey(context.Background(), "gho_X", "octocat", "app", 11); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if len(deleted) != 1 || deleted[0] != "/repos/octocat/app/keys/11" {
		t.Errorf("wrong delete target: %v", deleted)
	}
	// A 404 (already gone) is treated as success (idempotent).
	if err := c.DeleteDeployKey(context.Background(), "gho_X", "octocat", "gone", 99); err != nil {
		t.Errorf("404 delete should be idempotent success, got %v", err)
	}
}

func TestErrorsNeverLeakToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"message":"Bad credentials: gho_SECRET"}`))
	}))
	defer srv.Close()
	c := New(srv.Client(), srv.URL, srv.URL)
	_, err := c.Viewer(context.Background(), "gho_SECRET")
	if err == nil {
		t.Fatal("expected error")
	}
	if strings.Contains(err.Error(), "gho_SECRET") {
		t.Errorf("error message leaked the token: %v", err)
	}
}

// KnownHosts must pin github.com with at least the ed25519 key, parseable as a
// known_hosts line, so deploy-key fetches verify the host.
func TestKnownHostsPinned(t *testing.T) {
	if !strings.Contains(KnownHosts, "github.com ssh-ed25519 ") {
		t.Fatal("KnownHosts must pin github.com ssh-ed25519")
	}
	for _, line := range strings.Split(strings.TrimSpace(KnownHosts), "\n") {
		if _, _, _, _, _, err := ssh.ParseKnownHosts([]byte(line)); err != nil {
			t.Errorf("known_hosts line not parseable: %q (%v)", line, err)
		}
	}
}
