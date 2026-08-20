package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// After a failed manual repo-connect, the re-rendered connect form MUST still carry a valid CSRF
// token — otherwise the operator's NEXT submit fails with "invalid csrf token" (the form is rendered
// under {{with .Git}}, so its token comes from the gitView, which renderConnectError must populate).
func TestGitConnectErrorReRendersCSRFToken(t *testing.T) {
	e := buildGitHubServer(t)
	sess, csrf := e.authed(t)
	// An invalid URL fails validation → the error re-render path, with no network.
	resp := e.req(t, "POST", "/git", "127.0.0.1:1", map[string]string{"Origin": "https://example.com"},
		[]*http.Cookie{sess, csrf}, url.Values{"csrf_token": {csrf.Value}, "repo_url": {"ftp://example.com/x.git"}, "cred_kind": {""}})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("connect error re-render = %d, want 200", resp.StatusCode)
	}
	body := readBody(resp)
	if !strings.Contains(body, `value="`+csrf.Value+`"`) {
		t.Error("re-rendered connect form is missing the CSRF token — a retry would 403 with invalid csrf token")
	}
}

// A credential kind that doesn't match the URL transport (an SSH key on an https:// URL, a token on
// an ssh:// URL) is caught up front with an actionable message, instead of a confusing downstream
// "authentication failed". An SSH URL to a non-github host with no Known-hosts line is likewise
// caught before any fetch.
func TestGitConnectCredKindMismatch(t *testing.T) {
	e := buildGitHubServer(t)
	sess, csrf := e.authed(t)
	post := func(vals url.Values) string {
		vals.Set("csrf_token", csrf.Value)
		return readBody(e.req(t, "POST", "/git", "127.0.0.1:1", map[string]string{"Origin": "https://example.com"},
			[]*http.Cookie{sess, csrf}, vals))
	}
	if b := post(url.Values{"repo_url": {"https://github.com/octocat/app.git"}, "cred_kind": {"ssh"}, "cred": {"PRIVATE-KEY"}}); !strings.Contains(b, "SSH deploy key, but the repository URL is an https") {
		t.Error("ssh key + https URL must give the mismatch message")
	}
	if b := post(url.Values{"repo_url": {"git@github.com:octocat/app.git"}, "cred_kind": {"token"}, "cred": {"ghp_xxx"}}); !strings.Contains(b, "HTTPS token, but the repository URL is an ssh") {
		t.Error("token + ssh URL must give the mismatch message")
	}
	if b := post(url.Values{"repo_url": {"git@gitlab.com:octocat/app.git"}, "cred_kind": {"ssh"}, "cred": {"PRIVATE-KEY"}}); !strings.Contains(b, "needs a Known hosts line") {
		t.Error("ssh to a non-github host with no known_hosts must ask for a Known hosts line")
	}
}
