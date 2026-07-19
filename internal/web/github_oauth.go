package web

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/git"
	"github.com/daboss2003/mooring/internal/github"
	"github.com/daboss2003/mooring/internal/gitstore"
)

// "Connect with GitHub": a standard OAuth web flow that lets the operator pick a repo
// and have Mooring install a READ-ONLY deploy key for it — no key pasting. The OAuth
// token is used only to list repos + install the key; fetching uses the repo-scoped
// deploy key over SSH with a pinned known_hosts.
//
// CSRF/cookie note: the callback is a cross-site top-level navigation back from
// github.com, so the SameSite=Strict session cookie is NOT sent on it. The callback is
// therefore authenticated by a single-use, SameSite=Lax OAuth STATE cookie that only
// an authenticated + CSRF-checked connect action could have set — the standard OAuth
// CSRF defense. Everything after the callback redirects same-site, where the session
// cookie applies again.

// githubRepoView is one row in the repo picker.
type githubRepoView struct {
	FullName      string
	Private       bool
	DefaultBranch string
}

func (s *Server) githubEnabled() bool {
	return s.githubClient != nil && s.gitStore != nil && s.cfg.GitHub.Enabled()
}

func (s *Server) ghStateCookieName() string { return s.cfg.Cookie.Prefix + "ghstate" }

// githubRedirectURI is the OAuth callback URL. The operator registers this exact URL
// on their GitHub OAuth App. Behind the managed edge it's https://<admin hostname>;
// over the loopback tunnel it's http://<host> (a secure context for the browser).
func (s *Server) githubRedirectURI(r *http.Request) string {
	host, scheme := r.Host, "http"
	if h := s.cfg.AdminHostnameResolved(); h != "" {
		host, scheme = h, "https"
	} else if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + host + "/github/callback"
}

func (s *Server) setGhState(w http.ResponseWriter, state string) {
	http.SetCookie(w, &http.Cookie{
		Name: s.ghStateCookieName(), Value: state, Path: s.cookiePath(),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: 600,
	})
}

func (s *Server) clearGhState(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: s.ghStateCookieName(), Value: "", Path: s.cookiePath(),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

// handleGitHubConnect (POST, auth+CSRF) starts the OAuth flow: mint a state, stash it
// in a Lax cookie, and redirect the browser to GitHub.
func (s *Server) handleGitHubConnect(w http.ResponseWriter, r *http.Request) {
	if !s.githubEnabled() {
		notFound(w)
		return
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	state := hex.EncodeToString(b)
	s.setGhState(w, state)
	_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "github_connect_start", Outcome: audit.OK, Level: audit.Security})
	http.Redirect(w, r, s.githubClient.AuthorizeURL(s.cfg.GitHub.ClientID, s.githubRedirectURI(r), state), http.StatusSeeOther)
}

// handleGitHubCallback (GET, auth-EXEMPT, state-cookie-gated) finishes OAuth: verify
// state, exchange the code, store the (encrypted) token, then bounce to the picker.
func (s *Server) handleGitHubCallback(w http.ResponseWriter, r *http.Request) {
	if !s.githubEnabled() {
		notFound(w)
		return
	}
	c, cerr := r.Cookie(s.ghStateCookieName())
	s.clearGhState(w) // single-use, regardless of outcome
	qstate := r.URL.Query().Get("state")
	if cerr != nil || c.Value == "" || qstate == "" || subtle.ConstantTimeCompare([]byte(c.Value), []byte(qstate)) != 1 {
		_ = s.audit.Log(r.Context(), audit.Event{IP: ClientIP(r.Context()).String(), Action: "github_callback", Outcome: audit.Deny, Level: audit.Security, Detail: "bad or missing oauth state"})
		notFound(w)
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "github authorization failed", http.StatusBadRequest)
		return
	}
	token, err := s.githubClient.ExchangeCode(r.Context(), s.cfg.GitHub.ClientID, s.cfg.GitHub.ClientSecret, code, s.githubRedirectURI(r))
	if err != nil {
		s.log.Warn("github token exchange failed", "err", err)
		http.Error(w, "github authorization failed", http.StatusBadGateway)
		return
	}
	login, err := s.githubClient.Viewer(r.Context(), token)
	if err != nil {
		http.Error(w, "github authorization failed", http.StatusBadGateway)
		return
	}
	if err := s.gitStore.SaveGitHubConn(r.Context(), login, token); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_ = s.audit.Log(r.Context(), audit.Event{Action: "github_connected", Outcome: audit.OK, Level: audit.Security, Detail: "as " + login})
	http.Redirect(w, r, "/github/repos", http.StatusSeeOther)
}

// handleGitHubRepos (GET, auth) shows the repo picker.
func (s *Server) handleGitHubRepos(w http.ResponseWriter, r *http.Request) {
	if !s.githubEnabled() {
		notFound(w)
		return
	}
	conn, ok, err := s.gitStore.GitHubConn(r.Context())
	if err != nil || !ok {
		http.Redirect(w, r, "/git/new", http.StatusSeeOther)
		return
	}
	repos, err := s.githubClient.ListRepos(r.Context(), conn.Token)
	if err != nil {
		s.log.Warn("github list repos failed", "err", err)
		http.Error(w, "could not list repositories from github", http.StatusBadGateway)
		return
	}
	out := make([]githubRepoView, 0, len(repos))
	for _, rp := range repos {
		out = append(out, githubRepoView{FullName: rp.FullName, Private: rp.Private, DefaultBranch: rp.DefaultBranch})
	}
	s.render(w, r, "github_repos.html", tmplData{
		Title:       "Connect a repository — Mooring",
		CSRFToken:   CSRFToken(r.Context()),
		GitHubLogin: conn.Login,
		GitHubRepos: out,
	})
}

// handleGitHubConnectRepo (POST, auth+CSRF) is the one-click connect for a picked repo.
// Like the manual flow, the app's slug comes from the repo's mooring file(s) — so it
// runs discovery first (over HTTPS with the OAuth token, since the per-slug deploy key
// isn't installed until the slug is known) and then: 0 files → scaffold (slug derived
// from the repo name); 1 → connect; >1 → the chooser (one app per file). The read-only
// deploy key is installed at finalize, named per the chosen slug.
func (s *Server) handleGitHubConnectRepo(w http.ResponseWriter, r *http.Request) {
	if !s.githubEnabled() {
		notFound(w)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	fullName := strings.TrimSpace(r.PostFormValue("full_name"))
	branch := strings.TrimSpace(r.PostFormValue("branch"))
	if branch == "" {
		branch = "main"
	}
	owner, name, ok := splitFullName(fullName)
	if !ok {
		http.Error(w, "invalid repository", http.StatusBadRequest)
		return
	}
	conn, ok, err := s.gitStore.GitHubConn(r.Context())
	if err != nil || !ok {
		http.Redirect(w, r, "/git/new", http.StatusSeeOther)
		return
	}

	// Discover mooring files using the OAuth token over HTTPS.
	repoURL := "https://github.com/" + owner + "/" + name + ".git"
	if !s.gitDeploy.TryAcquire() {
		http.Error(w, "a git operation is already in progress; try again shortly", http.StatusConflict)
		return
	}
	files, derr := s.discoverMooringFiles(r.Context(), repoURL, "refs/heads/"+branch, git.Creds{Token: conn.Token})
	s.gitDeploy.Release()
	if derr != nil {
		http.Error(w, "could not read the repository from github: "+derr.Error(), http.StatusBadGateway)
		return
	}

	candidates, skipped := s.buildCandidates(files)

	switch {
	case len(candidates) == 1 && len(skipped) == 0:
		c := candidates[0]
		if c.Exists {
			http.Redirect(w, r, "/apps/"+c.Slug+"/git", http.StatusSeeOther)
			return
		}
		s.finishGitHubConnect(w, r, c.Slug, owner, name, branch, c.Path)
	case len(candidates) >= 1:
		handle := s.discoFlash.put(&discoveryStash{
			github: true, ghOwner: owner, ghName: name, ghBranch: branch, candidates: candidates,
		})
		s.render(w, r, "git_choose.html", tmplData{
			Title:     "Choose a configuration",
			CSRFToken: CSRFToken(r.Context()),
			Username:  sessionUser(r),
			Discovery: &discoveryView{Handle: handle, RepoURL: fullName, Ref: "refs/heads/" + branch, Candidates: candidates, Skipped: skipped},
		})
	case len(skipped) >= 1:
		http.Error(w, "found mooring files but none has a valid metadata.slug — add one (lowercase, e.g. slug: myapp) and reconnect", http.StatusUnprocessableEntity)
	default:
		slug := deriveSlug(name)
		if slug == "" {
			http.Error(w, "this repository has no mooring.yaml and its name can't be used as an app slug — add a mooring.yaml with metadata.slug and reconnect", http.StatusUnprocessableEntity)
			return
		}
		if _, exists, _ := s.gitStore.Get(slug); exists {
			http.Redirect(w, r, "/apps/"+slug+"/git", http.StatusSeeOther)
			return
		}
		s.finishGitHubConnect(w, r, slug, owner, name, branch, "mooring.yaml")
	}
}

// finishGitHubConnect installs a fresh read-only deploy key (named per the slug) on the
// repo via the OAuth token, then saves the app with that key as its SSH credential and
// the chosen mooring file. The OAuth token is re-read from the DB here (never carried
// through the chooser). Idempotent: an already-present key (ErrKeyExists) is fine.
func (s *Server) finishGitHubConnect(w http.ResponseWriter, r *http.Request, slug, owner, name, branch, mooringFile string) {
	if s.cfg.IsProtectedProject(slug) {
		http.Error(w, "protected project", http.StatusForbidden)
		return
	}
	conn, ok, err := s.gitStore.GitHubConn(r.Context())
	if err != nil || !ok {
		http.Redirect(w, r, "/git/new", http.StatusSeeOther)
		return
	}
	key, err := github.GenerateDeployKey("mooring:" + slug)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := s.githubClient.CreateDeployKey(r.Context(), conn.Token, owner, name, "mooring:"+slug, key.PublicLine); err != nil {
		// We mint a FRESH key per connect, so a 422 (ErrKeyExists) can't mean "this exact
		// key is already installed" — it means a DIFFERENT key already holds the title
		// "mooring:<slug>" (an orphan from a deleted app, or another Mooring using the
		// same slug). Our key was NOT installed, so fail loudly instead of saving a
		// credential that can never fetch.
		if err == github.ErrKeyExists {
			http.Error(w, "a deploy key named \"mooring:"+slug+"\" already exists on this repository — remove it on GitHub (it may be left over from a deleted app, or this slug is connected from another Mooring instance), then reconnect", http.StatusConflict)
			return
		}
		s.log.Warn("github create deploy key failed", "err", err)
		http.Error(w, "could not install the deploy key on github", http.StatusBadGateway)
		return
	}
	in := gitstore.SaveInput{
		Project:     slug,
		RepoURL:     "git@github.com:" + owner + "/" + name + ".git",
		Ref:         "refs/heads/" + branch,
		MooringFile: mooringFile,
		NewCred:     &key.PrivatePEM,
		CredKind:    "ssh",
		KnownHosts:  github.KnownHosts,
	}
	if err := s.gitStore.Save(r.Context(), in); err != nil {
		http.Error(w, "repository config rejected: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "github_connect_repo", Target: slug, Outcome: audit.OK, Level: audit.Security, Detail: owner + "/" + name + " (" + mooringFile + ")"})
	http.Redirect(w, r, "/apps/"+slug+"/git", http.StatusSeeOther)
}

// deriveSlug turns a GitHub repo name into a valid app slug for the scaffold case
// (a repo with no mooring.yaml). Returns "" if it can't be made valid.
func deriveSlug(repoName string) string {
	var b strings.Builder
	prevDash := false
	for _, c := range strings.ToLower(strings.TrimSpace(repoName)) {
		switch {
		case (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'):
			b.WriteRune(c)
			prevDash = false
		case c == '-' || c == '_' || c == '.' || c == ' ':
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if !provisionSlugRe.MatchString(out) {
		return ""
	}
	return out
}

// handleGitHubDisconnect (POST, auth+CSRF) forgets the OAuth token. Existing per-repo
// deploy keys keep working.
func (s *Server) handleGitHubDisconnect(w http.ResponseWriter, r *http.Request) {
	if s.gitStore == nil {
		notFound(w)
		return
	}
	if err := s.gitStore.DeleteGitHubConn(r.Context()); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "github_disconnect", Outcome: audit.OK, Level: audit.Security})
	http.Redirect(w, r, "/git/new", http.StatusSeeOther)
}

// splitFullName splits "owner/name" with light validation (no path traversal, single
// slash). The GitHub API call path-escapes these anyway.
func splitFullName(full string) (owner, name string, ok bool) {
	parts := strings.Split(full, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	if strings.ContainsAny(full, " \t\n\\") || strings.Contains(full, "..") {
		return "", "", false
	}
	return parts[0], parts[1], true
}
