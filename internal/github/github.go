// Package github implements the optional "Connect with GitHub" flow: a standard
// OAuth web flow plus the small slice of the GitHub API Mooring needs to make
// connecting a (private) repo a one-click affair — list the operator's repos and
// install a READ-ONLY deploy key — so nobody ever pastes a key by hand.
//
// Design notes that keep this safe:
//   - The OAuth token is used ONLY to list repos and install a per-repo deploy key.
//     Day-to-day fetching uses that repo-scoped, read-only deploy key over SSH with a
//     PINNED known_hosts (see KnownHosts) — never the broad token.
//   - Every network call goes through an injected httpDoer with an explicit base URL,
//     so the whole client is unit-testable offline against an httptest server.
//   - Errors never include the token or response bodies that might echo it.
package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	// DefaultAPIBase / DefaultOAuthBase are the public GitHub endpoints (overridable
	// for GitHub Enterprise or tests).
	DefaultAPIBase   = "https://api.github.com"
	DefaultOAuthBase = "https://github.com"

	// Scope needed to list private repos and install a deploy key on them. (OAuth Apps
	// don't offer a finer grain; GitHub Apps would, at the cost of a heavier setup.)
	Scope = "repo"

	// maxRepoPages bounds the repo listing (100/page) so a huge account can't make the
	// picker unbounded.
	maxRepoPages = 5
)

// KnownHosts pins GitHub's published SSH host keys (from https://api.github.com/meta).
// Deploy-key fetches use this with StrictHostKeyChecking, so a connected repo can
// never be MITM'd into handing Mooring a malicious tree.
const KnownHosts = `github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
github.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=
github.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=`

// httpDoer is the minimal HTTP surface the client needs (the real *http.Client or a
// test double both satisfy it).
type httpDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Client talks to GitHub. Construct with New.
type Client struct {
	hc        httpDoer
	apiBase   string
	oauthBase string
}

// New builds a Client. Pass empty bases to use the public GitHub endpoints.
func New(hc httpDoer, apiBase, oauthBase string) *Client {
	if apiBase == "" {
		apiBase = DefaultAPIBase
	}
	if oauthBase == "" {
		oauthBase = DefaultOAuthBase
	}
	return &Client{hc: hc, apiBase: strings.TrimRight(apiBase, "/"), oauthBase: strings.TrimRight(oauthBase, "/")}
}

// AuthorizeURL builds the URL to send the operator's browser to. state is an
// unguessable value the caller also stores (in a cookie) and re-checks on the
// callback, defeating cross-site request forgery of the OAuth flow.
func (c *Client) AuthorizeURL(clientID, redirectURI, state string) string {
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", Scope)
	q.Set("state", state)
	q.Set("allow_signup", "false")
	return c.oauthBase + "/login/oauth/authorize?" + q.Encode()
}

// ExchangeCode swaps the OAuth callback code for an access token.
func (c *Client) ExchangeCode(ctx context.Context, clientID, clientSecret, code, redirectURI string) (string, error) {
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.oauthBase+"/login/oauth/access_token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := c.do(req, &out); err != nil {
		return "", err
	}
	if out.AccessToken == "" {
		return "", errors.New("github: token exchange returned no access token")
	}
	return out.AccessToken, nil
}

// Viewer returns the login of the user the token belongs to (a cheap call to confirm
// the token works and show "connected as …").
func (c *Client) Viewer(ctx context.Context, token string) (string, error) {
	req, err := c.authedGet(ctx, token, "/user")
	if err != nil {
		return "", err
	}
	var out struct {
		Login string `json:"login"`
	}
	if err := c.do(req, &out); err != nil {
		return "", err
	}
	return out.Login, nil
}

// Repo is one repository in the picker.
type Repo struct {
	FullName      string `json:"full_name"` // owner/name
	Name          string `json:"name"`
	Private       bool   `json:"private"`
	DefaultBranch string `json:"default_branch"`
	SSHURL        string `json:"ssh_url"`
	Owner         struct {
		Login string `json:"login"`
	} `json:"owner"`
}

// ListRepos returns repos the user can administer, most-recently-updated first,
// bounded by maxRepoPages.
func (c *Client) ListRepos(ctx context.Context, token string) ([]Repo, error) {
	var all []Repo
	for page := 1; page <= maxRepoPages; page++ {
		req, err := c.authedGet(ctx, token, "/user/repos?per_page=100&sort=updated&affiliation=owner,organization_member&page="+strconv.Itoa(page))
		if err != nil {
			return nil, err
		}
		var batch []Repo
		if err := c.do(req, &batch); err != nil {
			return nil, err
		}
		all = append(all, batch...)
		if len(batch) < 100 {
			break
		}
	}
	return all, nil
}

// CreateDeployKey installs a READ-ONLY deploy key on owner/repo. title is a human
// label; pubLine is an authorized_keys line. It is idempotent-ish: GitHub rejects a
// duplicate key with 422, which the caller can treat as already-installed.
func (c *Client) CreateDeployKey(ctx context.Context, token, owner, repo, title, pubLine string) error {
	body, _ := json.Marshal(map[string]any{"title": title, "key": pubLine, "read_only": true})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.apiBase+"/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/keys", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	c.setAuth(req, token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer drain(resp)
	if resp.StatusCode == http.StatusCreated {
		return nil
	}
	if resp.StatusCode == http.StatusUnprocessableEntity {
		return ErrKeyExists
	}
	return fmt.Errorf("github: create deploy key: unexpected status %d", resp.StatusCode)
}

// ErrKeyExists means an identical deploy key is already installed (treat as success).
var ErrKeyExists = errors.New("github: deploy key already exists")

// DeployKeyInfo is the subset of a repo deploy key the reconnect flow needs to find + remove a
// stale key by its title.
type DeployKeyInfo struct {
	ID    int64  `json:"id"`
	Title string `json:"title"`
}

// ListDeployKeys returns owner/repo's deploy keys (id + title). Used by the reconnect flow to find
// the app's own "mooring:<slug>" key so it can be replaced — it NEVER acts on a key by anything but
// an exact title match the caller controls.
func (c *Client) ListDeployKeys(ctx context.Context, token, owner, repo string) ([]DeployKeyInfo, error) {
	req, err := c.authedGet(ctx, token,
		"/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/keys?per_page=100")
	if err != nil {
		return nil, err
	}
	var keys []DeployKeyInfo
	if err := c.do(req, &keys); err != nil {
		return nil, err
	}
	return keys, nil
}

// DeleteDeployKey removes one deploy key by numeric id. The caller resolves the id from
// ListDeployKeys by an exact title match, so this can only ever remove a key it identified.
func (c *Client) DeleteDeployKey(ctx context.Context, token, owner, repo string, keyID int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		c.apiBase+"/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/keys/"+strconv.FormatInt(keyID, 10), nil)
	if err != nil {
		return err
	}
	c.setAuth(req, token)
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer drain(resp)
	// 204 = deleted; 404 = already gone (idempotent — treat as success).
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	return fmt.Errorf("github: delete deploy key: unexpected status %d", resp.StatusCode)
}

// Release is the subset of a GitHub release Mooring's update check needs.
type Release struct {
	TagName    string `json:"tag_name"`
	HTMLURL    string `json:"html_url"`
	Prerelease bool   `json:"prerelease"`
	Draft      bool   `json:"draft"`
}

// Advisory is the subset of a repository security advisory the update check needs.
// Vulnerabilities carry the affected version ranges Mooring matches its running
// version against.
type Advisory struct {
	GHSAID          string              `json:"ghsa_id"`
	Summary         string              `json:"summary"`
	Severity        string              `json:"severity"` // low|medium|high|critical
	HTMLURL         string              `json:"html_url"`
	Vulnerabilities []AdvisoryVulnRange `json:"vulnerabilities"`
}

// AdvisoryVulnRange is one affected-package range within an advisory.
type AdvisoryVulnRange struct {
	VulnerableVersionRange string `json:"vulnerable_version_range"`
	PatchedVersions        string `json:"patched_versions"`
}

// LatestRelease returns owner/repo's latest published (non-draft, non-prerelease)
// release. UNAUTHENTICATED — public data, no token, no telemetry payload.
func (c *Client) LatestRelease(ctx context.Context, owner, repo string) (Release, error) {
	var rel Release
	req, err := c.unauthGet(ctx, "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/releases/latest")
	if err != nil {
		return Release{}, err
	}
	if err := c.do(req, &rel); err != nil {
		return Release{}, err
	}
	return rel, nil
}

// SecurityAdvisories returns owner/repo's PUBLISHED security advisories (the ones a
// maintainer disclosed). UNAUTHENTICATED. Used to detect that the running Mooring
// version is itself vulnerable/compromised.
func (c *Client) SecurityAdvisories(ctx context.Context, owner, repo string) ([]Advisory, error) {
	var out []Advisory
	req, err := c.unauthGet(ctx, "/repos/"+url.PathEscape(owner)+"/"+url.PathEscape(repo)+"/security-advisories?state=published&per_page=100")
	if err != nil {
		return nil, err
	}
	if err := c.do(req, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// unauthGet builds an UNauthenticated GitHub API GET (no Authorization header) with
// the standard Accept + API-version headers.
func (c *Client) unauthGet(ctx context.Context, path string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.apiBase+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	return req, nil
}

func (c *Client) authedGet(ctx context.Context, token, path string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.apiBase+path, nil)
	if err != nil {
		return nil, err
	}
	c.setAuth(req, token)
	return req, nil
}

func (c *Client) setAuth(req *http.Request, token string) {
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
}

// do executes a request expecting a 2xx JSON body, decoding into v. Error messages
// never include the response body (which could echo the token).
func (c *Client) do(req *http.Request, v any) error {
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer drain(resp)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("github: %s %s: status %d", req.Method, req.URL.Path, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(v)
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
}
