package web

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/crypto"
	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/git"
	"github.com/daboss2003/mooring/internal/github"
	"github.com/daboss2003/mooring/internal/gitstore"
)

// A repo may carry SEVERAL mooring files — the plain mooring.yaml plus named
// variants like mooring.staging.yaml / mooring.prod.yaml — and EACH becomes its
// own deployed app instance (its own slug, taken from that file's metadata.slug).
// On connect, Mooring does a throwaway discovery fetch, lists the mooring files,
// reads each one's slug, and:
//   - 0 files  → scaffold a default (the operator supplies a name);
//   - 1 file   → create the app straight away;
//   - >1 files → present a chooser (plain mooring.yaml preferred), one app per file.
// If the chosen file's slug already names an app, the operator is redirected to it
// rather than overwriting — connect-new never silently repoints an existing app.

var connectSlugRe = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}$`)

// discoveredFile is one mooring*.yaml found at the repo's connect-time commit.
type discoveredFile struct {
	Path string // root-level file name (mooring.yaml | mooring.staging.yaml | ...)
	Slug string // metadata.slug peeked from the file (may be empty/invalid)
	Name string // metadata.name peeked from the file (optional, display only)
}

// discoveryCandidate is a choosable instance in the multi-file chooser.
type discoveryCandidate struct {
	Path    string
	Slug    string
	Name    string
	Label   string // variant label: "default" for mooring.yaml, else the middle text
	Exists  bool   // an app with this slug is already connected → "Open" instead of "Create"
	Invalid bool   // not creatable (surfaced as skipped)
	Reason  string // why it was skipped (when Invalid)
}

// discoveryView drives templates/git_choose.html.
type discoveryView struct {
	Handle     string
	RepoURL    string
	Ref        string
	Candidates []discoveryCandidate
	Skipped    []discoveryCandidate
}

// discoveryStash holds everything the chooser needs to create the chosen app on the
// follow-up POST — including the decrypted credential, which therefore NEVER round-
// trips through the browser (no hidden form field, no URL). It lives server-side,
// single-use, behind an opaque short-TTL handle (mirrors tokenFlash).
type discoveryStash struct {
	repoURL    string
	ref        string
	cred       string
	credKind   string
	knownHosts string
	autoDeploy bool
	// GitHub-picker mode: finalize installs a fresh deploy key (the OAuth token is
	// re-read from the DB at finalize, never stashed) instead of saving a pasted cred.
	github     bool
	ghOwner    string
	ghName     string
	ghBranch   string
	candidates []discoveryCandidate
	exp        time.Time
}

type discoveryFlash struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]*discoveryStash
}

func newDiscoveryFlash(ttl time.Duration) *discoveryFlash {
	return &discoveryFlash{ttl: ttl, m: make(map[string]*discoveryStash)}
}

func (f *discoveryFlash) put(st *discoveryStash) string {
	handle := crypto.RandomToken(18)
	now := time.Now()
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, e := range f.m { // opportunistic sweep
		if now.After(e.exp) {
			delete(f.m, k)
		}
	}
	if len(f.m) > 256 { // flood backstop — these hold creds, keep the table small
		f.m = make(map[string]*discoveryStash)
	}
	st.exp = now.Add(f.ttl)
	f.m[handle] = st
	return handle
}

func (f *discoveryFlash) take(handle string) (*discoveryStash, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	st, ok := f.m[handle]
	if !ok {
		return nil, false
	}
	delete(f.m, handle) // single-use regardless of expiry
	if time.Now().After(st.exp) {
		return nil, false
	}
	return st, true
}

// mooringVariantLabel maps a file name to its instance label: mooring.yaml →
// "default", mooring.staging.yaml → "staging", mooring.prod.yaml → "prod".
func mooringVariantLabel(path string) string {
	s := strings.TrimSuffix(strings.TrimSuffix(path, ".yaml"), ".yml")
	s = strings.TrimPrefix(s, "mooring")
	s = strings.TrimPrefix(s, ".")
	if s == "" {
		return "default"
	}
	return s
}

// discoverMooringFiles fetches the ref into a throwaway object store and returns the
// root-level mooring*.yaml files at its tip, each with its peeked slug/name. The temp
// store is removed before returning — the real per-app fetch happens later, keyed by
// the chosen slug. Read-plane only (no checkout, nothing runs).
func (s *Server) discoverMooringFiles(ctx context.Context, repoURL, ref string, creds git.Creds) ([]discoveredFile, error) {
	dir := filepath.Join(s.cfg.DataDir, "git-discovery", crypto.RandomToken(12))
	// Create + schedule cleanup BEFORE git.Open so the scratch dir is removed even if
	// Open fails after it has already MkdirAll'd the path.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	repo, err := git.Open(dir)
	if err != nil {
		return nil, err
	}

	fctx, cancel := context.WithTimeout(ctx, gitFetchTimeout)
	defer cancel()
	sha, err := repo.Fetch(fctx, repoURL, ref, creds)
	if err != nil {
		return nil, err // already classified by the git layer
	}
	// Only the ROOT tree (not a recursive walk) — a repo with thousands of nested files
	// can't push a root-level mooring*.yaml past a cap, and an attacker can't force a
	// huge recursive listing here.
	names, err := repo.LsTreeRoot(ctx, sha)
	if err != nil {
		return nil, err
	}
	var out []discoveredFile
	for _, name := range names {
		if strings.Contains(name, "/") || !gitstore.ValidMooringFile(name) {
			continue // root-level mooring*.yaml only
		}
		if len(out) >= maxMooringFiles {
			break // bound the per-connect CatFile/parse fan-out (DoS guard)
		}
		b, cerr := repo.CatFile(ctx, sha, name)
		if cerr != nil {
			continue
		}
		slug, dispName := definition.PeekMetadata(b)
		out = append(out, discoveredFile{Path: name, Slug: slug, Name: dispName})
	}
	return out, nil
}

// maxMooringFiles bounds how many root-level mooring*.yaml files one connect will
// read+parse — a real repo has a handful; the cap stops a hostile repo from forcing
// thousands of git subprocesses + YAML parses under the shared git lock.
const maxMooringFiles = 50

// sweepDiscoveryScratch best-effort removes any leftover discovery scratch dirs at
// startup. Each is single-use and removed on its own path, but a hard crash mid-
// discovery could orphan one under DataDir/git-discovery; clear the whole tree.
func (s *Server) sweepDiscoveryScratch() {
	_ = os.RemoveAll(filepath.Join(s.cfg.DataDir, "git-discovery"))
}

// handleGitConnect is the POST target of the "connect a repository" form. It runs
// discovery and then either creates the app, redirects to an existing one, or shows
// the multi-file chooser. The slug comes from the chosen file's metadata.slug.
func (s *Server) handleGitConnect(w http.ResponseWriter, r *http.Request) {
	if s.gitStore == nil {
		http.Error(w, "gitops unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	repoURL := strings.TrimSpace(r.PostFormValue("repo_url"))
	ref := strings.TrimSpace(r.PostFormValue("git_ref"))
	if ref == "" {
		ref = "refs/heads/main"
	}
	fallbackName := strings.TrimSpace(r.PostFormValue("name")) // only used if the repo has no mooring file
	autoDeploy := r.PostFormValue("auto_deploy") == "on"
	credKind := r.PostFormValue("cred_kind")
	cred := r.PostFormValue("cred")
	knownHosts := r.PostFormValue("known_hosts")

	if err := git.ValidateRepoURL(repoURL); err != nil {
		s.renderConnectError(w, r, err.Error())
		return
	}
	if !strings.HasPrefix(ref, "refs/") {
		s.renderConnectError(w, r, "git ref must be fully-qualified (e.g. refs/heads/main)")
		return
	}
	var gc git.Creds
	switch credKind {
	case "token":
		if strings.TrimSpace(cred) != "" {
			gc.Token = cred
		}
	case "ssh":
		if strings.TrimSpace(cred) != "" {
			gc.SSHKey = cred
			gc.KnownHosts = knownHosts
		}
	default:
		credKind = "" // public repo
	}

	// The credential kind must match the URL's transport, or the fetch fails with a confusing
	// "authentication failed" — an SSH key can't authenticate an https:// URL, and an HTTPS token
	// can't authenticate an ssh:// one. And an SSH connection pins the server's host key, so it needs
	// a Known-hosts line. Catch both up front with an actionable message.
	switch scheme := git.RepoScheme(repoURL); {
	case credKind == "ssh" && scheme == "https":
		s.renderConnectError(w, r, "you chose an SSH deploy key, but the repository URL is an https:// URL. Use an SSH URL (git@github.com:org/repo.git) with the key, or switch the credential kind to an HTTPS token.")
		return
	case credKind == "token" && scheme == "ssh":
		s.renderConnectError(w, r, "you chose an HTTPS token, but the repository URL is an ssh:// URL (git@…). Use an https:// URL with the token, or switch the credential kind to an SSH deploy key.")
		return
	case credKind == "ssh" && gc.SSHKey != "" && gc.KnownHosts == "":
		// github.com's host key is pinned — fill it in for the common case; any other host needs the
		// operator to paste a Known-hosts line, or SSH host-key verification fails.
		if strings.EqualFold(git.RepoHostName(repoURL), "github.com") {
			gc.KnownHosts, knownHosts = github.KnownHosts, github.KnownHosts
		} else {
			h := git.RepoHostName(repoURL)
			s.renderConnectError(w, r, "an SSH deploy key needs a Known hosts line to verify the server. Paste the host key for "+h+" (e.g. the output of `ssh-keyscan "+h+"`) into the Known hosts field.")
			return
		}
	}

	// Serialize the discovery fetch with any in-flight deploy/fetch (shared git lock).
	if !s.gitDeploy.TryAcquire() {
		http.Error(w, "a git operation is already in progress; try again shortly", http.StatusConflict)
		return
	}
	files, derr := s.discoverMooringFiles(r.Context(), repoURL, ref, gc)
	s.gitDeploy.Release()
	if derr != nil {
		// The classified message is intentionally coarse; log the real (redacted, credential-free)
		// git stderr so the operator can see the actual cause (e.g. "Permission denied (publickey)").
		s.log.Warn("git connect: could not read repository", "repo", repoURL, "cred_kind", credKind, "err", derr.Error(), "git_stderr", git.RawStderr(derr))
		msg := "could not read the repository: " + derr.Error()
		switch credKind {
		case "ssh":
			msg += " — for a deploy key: paste the PRIVATE key (not the .pub), make sure it has no passphrase, and add its public half to the repo's Settings → Deploy keys."
		case "token":
			msg += " — the token needs read access to THIS repository (and, if your org enforces SSO, an SSO-authorized token)."
		}
		s.renderConnectError(w, r, msg)
		return
	}

	candidates, skipped := s.buildCandidates(files)

	switch {
	case len(candidates) == 1 && len(skipped) == 0:
		// Exactly one mooring file → no choice needed.
		c := candidates[0]
		if c.Exists {
			http.Redirect(w, r, "/apps/"+c.Slug+"/git", http.StatusSeeOther)
			return
		}
		s.finishConnect(w, r, c.Slug, repoURL, ref, c.Path, cred, credKind, knownHosts, autoDeploy)
	case len(candidates) >= 1:
		// Several files (or one creatable + some skipped) → let the operator choose.
		handle := s.discoFlash.put(&discoveryStash{
			repoURL: repoURL, ref: ref, cred: cred, credKind: credKind, knownHosts: knownHosts,
			autoDeploy: autoDeploy, candidates: candidates,
		})
		s.render(w, r, "git_choose.html", tmplData{
			Title:     "Choose a configuration",
			CSRFToken: CSRFToken(r.Context()),
			Username:  sessionUser(r),
			Discovery: &discoveryView{Handle: handle, RepoURL: repoURL, Ref: ref, Candidates: candidates, Skipped: skipped},
		})
	case len(skipped) >= 1:
		// Files exist but none has a usable slug.
		s.renderConnectError(w, r, "found mooring files but none has a valid metadata.slug — add one (lowercase, e.g. slug: myapp) and reconnect")
	default:
		// No mooring file at all → scaffold from the detected stack; needs a name.
		if !connectSlugRe.MatchString(fallbackName) {
			s.renderConnectError(w, r, "this repository has no mooring.yaml — enter an app name and Mooring will scaffold one from the detected stack")
			return
		}
		if _, exists, _ := s.gitStore.Get(fallbackName); exists {
			http.Redirect(w, r, "/apps/"+fallbackName+"/git", http.StatusSeeOther)
			return
		}
		s.finishConnect(w, r, fallbackName, repoURL, ref, "mooring.yaml", cred, credKind, knownHosts, autoDeploy)
	}
}

// handleGitChoose creates (or opens) the app for the file picked in the multi-file
// chooser. The chosen path is validated against the stashed candidate allow-list, and
// the credential is recovered from the server-side stash (never from the client).
func (s *Server) handleGitChoose(w http.ResponseWriter, r *http.Request) {
	if s.gitStore == nil {
		http.Error(w, "gitops unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	st, ok := s.discoFlash.take(strings.TrimSpace(r.PostFormValue("handle")))
	if !ok {
		s.renderConnectError(w, r, "that selection expired — reconnect the repository")
		return
	}
	chosen := strings.TrimSpace(r.PostFormValue("path"))
	var cand *discoveryCandidate
	for i := range st.candidates {
		if st.candidates[i].Path == chosen && !st.candidates[i].Invalid {
			cand = &st.candidates[i]
			break
		}
	}
	if cand == nil {
		http.Error(w, "unknown selection", http.StatusBadRequest)
		return
	}
	if _, exists, _ := s.gitStore.Get(cand.Slug); exists {
		http.Redirect(w, r, "/apps/"+cand.Slug+"/git", http.StatusSeeOther)
		return
	}
	if st.github {
		s.finishGitHubConnect(w, r, cand.Slug, st.ghOwner, st.ghName, st.ghBranch, cand.Path)
		return
	}
	s.finishConnect(w, r, cand.Slug, st.repoURL, st.ref, cand.Path, st.cred, st.credKind, st.knownHosts, st.autoDeploy)
}

// finishConnect persists the app's repo config, kicks an initial fetch so a staged
// commit is ready to review+deploy, and lands the operator on its git page.
func (s *Server) finishConnect(w http.ResponseWriter, r *http.Request, slug, repoURL, ref, mooringFile, cred, credKind, knownHosts string, autoDeploy bool) {
	if s.cfg.IsProtectedProject(slug) {
		http.Error(w, "protected project", http.StatusForbidden)
		return
	}
	in := gitstore.SaveInput{
		Project:     slug,
		RepoURL:     repoURL,
		Ref:         ref,
		MooringFile: mooringFile,
		AutoDeploy:  autoDeploy,
	}
	if strings.TrimSpace(cred) != "" && (credKind == "token" || credKind == "ssh") {
		in.NewCred = &cred
		in.CredKind = credKind
		in.KnownHosts = knownHosts
	}
	if err := s.gitStore.Save(r.Context(), in); err != nil {
		s.renderConnectError(w, r, "repository config rejected: "+err.Error())
		return
	}
	_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "git_connect", Target: slug, Outcome: audit.OK, Level: audit.Security, Detail: mooringFile})
	// Land on the git page; the operator clicks "Fetch now" to stage a commit (matching
	// the established flow — connect never auto-fetches).
	http.Redirect(w, r, "/apps/"+slug+"/git", http.StatusSeeOther)
}

// renderConnectError re-renders the connect form with an error banner.
func (s *Server) renderConnectError(w http.ResponseWriter, r *http.Request, msg string) {
	// The connect form (git_repo_form) is rendered under {{with .Git}}, so it reads the CSRF token
	// from the gitView, NOT the root tmplData. It MUST be set here or the re-rendered form carries an
	// empty token and the operator's next submit fails with "invalid csrf token" (requireCSRF already
	// forwarded the valid token into the context on this POST).
	token := CSRFToken(r.Context())
	s.render(w, r, "git.html", tmplData{
		Title:         "Connect a repository",
		CSRFToken:     token,
		Username:      sessionUser(r),
		GitHubEnabled: s.githubEnabled(),
		Error:         msg,
		Git:           &gitView{Configured: false, BuildPolicy: "never", Ref: "refs/heads/main", ComposePath: "docker-compose.yml", CSRFToken: token},
	})
}

// buildCandidates turns discovered files into the creatable candidates (sorted, default
// first) and the skipped ones (with a reason). A file is skipped when its metadata.slug
// is missing/invalid, or when an EARLIER file already claimed the same slug — only one
// app can hold a slug, so a duplicate isn't offered as a second "Create".
func (s *Server) buildCandidates(files []discoveredFile) (candidates, skipped []discoveryCandidate) {
	seen := map[string]bool{}
	for _, f := range files {
		c := discoveryCandidate{Path: f.Path, Slug: f.Slug, Name: f.Name, Label: mooringVariantLabel(f.Path)}
		switch {
		case !connectSlugRe.MatchString(f.Slug):
			c.Invalid, c.Reason = true, "no valid metadata.slug"
			skipped = append(skipped, c)
		case seen[f.Slug]:
			c.Invalid, c.Reason = true, "duplicate slug — give each file a distinct metadata.slug"
			skipped = append(skipped, c)
		default:
			seen[f.Slug] = true
			_, exists, _ := s.gitStore.Get(f.Slug)
			c.Exists = exists
			candidates = append(candidates, c)
		}
	}
	sortCandidates(candidates)
	return candidates, skipped
}

// sortCandidates puts the plain mooring.yaml ("default") first, then the rest
// alphabetically by label, so the chooser always offers the obvious default on top.
func sortCandidates(c []discoveryCandidate) {
	sort.SliceStable(c, func(i, j int) bool {
		di, dj := c[i].Label == "default", c[j].Label == "default"
		if di != dj {
			return di
		}
		return c[i].Label < c[j].Label
	})
}
