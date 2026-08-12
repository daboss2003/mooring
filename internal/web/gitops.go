package web

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/compose"
	"github.com/daboss2003/mooring/internal/crypto"
	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/dockerexec"
	"github.com/daboss2003/mooring/internal/git"
	"github.com/daboss2003/mooring/internal/gitstore"
	"github.com/daboss2003/mooring/internal/monitor"
)

// M6 repo-path GitOps (plan §7.6). The read plane fetches the configured ref into
// a per-app bare object store and shows a hostile-data-safe diff; the write plane
// promotes ONE reviewed commit sha: §5.6-validate the cat-file'd compose bytes,
// archive-extract the pinned tree into a Mooring-owned run dir, materialize
// config files + env, then `docker compose up`. The webhook is FETCH-ONLY: it
// never reads a ref/sha from the payload and only triggers the same gated promote.

const (
	// webhookReplayWindow bounds how stale a signed webhook timestamp may be.
	webhookReplayWindow = 5 * time.Minute
	// webhookForwardSkew is the allowed clock skew INTO the future (a CI runner
	// whose clock runs slightly ahead). A timestamp is valid for an arrival window
	// of [ts-window, ts+window+skew]; the nonce must be remembered for at least
	// that full span (window+skew) or a skewed timestamp could be replayed in the
	// sliver after the nonce is forgotten but before the timestamp expires.
	webhookForwardSkew = 60 * time.Second
	// webhookNonceTTL keeps a used nonce at least as long as any timestamp signed
	// with it can remain valid.
	webhookNonceTTL = webhookReplayWindow + webhookForwardSkew
	// gitDeployTimeout caps a webhook-triggered background fetch+deploy.
	gitDeployTimeout = 15 * time.Minute
	// gitFetchTimeout caps a single network git fetch, independent of the larger
	// deploy cap. A read-plane fetch must never hold the shared single-flight gate for
	// a deploy-sized window — a slow/hostile repo endpoint (slow-loris, tarpit) would
	// otherwise block manual deploys, webhooks, and provisioning behind it.
	gitFetchTimeout = 90 * time.Second
	// maxWebhookNonceLen bounds the nonce header so a hostile client can't bloat
	// the in-memory replay cache key.
	maxWebhookNonceLen = 128
)

// --- in-memory webhook replay (nonce) cache ---

// nonceCache remembers recently-seen (token,nonce) pairs to make each signed
// webhook single-use within the replay window. It is self-sweeping (no background
// goroutine) and capacity-capped so a flood can't grow it unbounded.
type nonceCache struct {
	mu        sync.Mutex
	ttl       time.Duration
	seen      map[string]time.Time
	lastSweep time.Time
}

func newNonceCache(ttl time.Duration) *nonceCache {
	return &nonceCache{ttl: ttl, seen: make(map[string]time.Time), lastSweep: time.Now()}
}

// seenOrAdd records key and reports whether it was already present within the TTL
// (a replay). Caller must have already verified the signature + timestamp window.
func (n *nonceCache) seenOrAdd(key string) bool {
	now := time.Now()
	n.mu.Lock()
	defer n.mu.Unlock()
	if now.Sub(n.lastSweep) > n.ttl {
		for k, t := range n.seen {
			if now.Sub(t) > n.ttl {
				delete(n.seen, k)
			}
		}
		n.lastSweep = now
	}
	if t, ok := n.seen[key]; ok && now.Sub(t) <= n.ttl {
		return true
	}
	if len(n.seen) > 100_000 { // flood backstop: window-based reset
		n.seen = make(map[string]time.Time)
	}
	n.seen[key] = now
	return false
}

// --- one-time webhook-token flash ---

// tokenFlash hands the freshly-rotated webhook token to the operator's NEXT page
// render WITHOUT ever putting the secret in a URL/redirect (which would persist
// in browser history and any full-URL access log). The redirect carries only an
// opaque, single-use, short-lived handle; the token lives server-side until the
// matching GET consumes it once. Bound to (handle, project) — a different page
// cannot pull it (review: token in redirect query param).
type tokenFlash struct {
	mu  sync.Mutex
	ttl time.Duration
	m   map[string]flashEntry
}

type flashEntry struct {
	token   string
	project string
	exp     time.Time
}

func newTokenFlash(ttl time.Duration) *tokenFlash {
	return &tokenFlash{ttl: ttl, m: make(map[string]flashEntry)}
}

// put stores token for project and returns a fresh opaque handle.
func (f *tokenFlash) put(project, token string) string {
	handle := crypto.RandomToken(18)
	now := time.Now()
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, e := range f.m { // opportunistic sweep
		if now.After(e.exp) {
			delete(f.m, k)
		}
	}
	if len(f.m) > 1024 { // flood backstop
		f.m = make(map[string]flashEntry)
	}
	f.m[handle] = flashEntry{token: token, project: project, exp: now.Add(f.ttl)}
	return handle
}

// take consumes the token for (handle, project) exactly once.
func (f *tokenFlash) take(handle, project string) (string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.m[handle]
	if !ok {
		return "", false
	}
	delete(f.m, handle) // single-use regardless of match/expiry
	if time.Now().After(e.exp) || e.project != project {
		return "", false
	}
	return e.token, true
}

// --- repo layout (Mooring-owned) ---

// gitObjectDir is the per-app bare object store. It lives UNDER DataDir (which the
// §5.6 validator marks protected): an app bind can never reach it.
func (s *Server) gitObjectDir(slug string) string {
	return filepath.Join(s.cfg.DataDir, "git", slug+".git")
}

// appsRoot is the Mooring-owned tree holding every app's run dir. It is a
// SIBLING of DataDir (outside it) so legitimate binds under a run dir don't trip
// the "DataDir is protected" §5.6 defense-in-depth check, while the DB/keys (in
// DataDir) stay unreachable. Shared by git-backed (M6) and provisioned (M8) apps.
func (s *Server) appsRoot() string { return s.cfg.DataDir + "-apps" }

// appRunDir is the per-app checkout/run directory under appsRoot.
func (s *Server) appRunDir(slug string) string {
	return filepath.Join(s.appsRoot(), slug)
}

// --- view model ---

type gitDiffView struct {
	CommitsBehind int
	Truncated     bool
	Commits       []git.CommitInfo
	Files         []git.FileChange
}

type gitView struct {
	Configured          bool
	Project             string
	RepoURL             string
	Ref                 string
	ComposePath         string
	DockerfilePath      string
	BuildPolicy         string
	AutoDeploy          bool
	CredKind            string
	HasWebhook          bool
	WebhookToken        string // shown ONCE, right after a rotate
	DeployedCommit      string
	StagedCommit        string
	UpdateState         string
	CommitsBehind       int
	LastFetchAt         int64 // unix seconds; the "ts" template renders it localised; 0 ⇒ "never"
	LastFetchError      string
	Diff                *gitDiffView
	WriteDisabledReason string
	Versions            []definition.VersionMeta // deploy/edit history; rows with a Commit are rollback targets
	PreviewEnabled      bool                     // per-PR preview environments opt-in
	CanReinstallKey     bool                     // OAuth-connected github repo → offer "reinstall deploy key" (repairs a drifted key)
}

func shortSha(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func isFullSha40(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// --- config form (GET/POST) ---

func (s *Server) handleGitNew(w http.ResponseWriter, r *http.Request) {
	if s.gitStore == nil {
		http.Error(w, "gitops unavailable", http.StatusServiceUnavailable)
		return
	}
	s.render(w, r, "git.html", tmplData{
		Title:         "Connect a repository",
		CSRFToken:     CSRFToken(r.Context()),
		Username:      sessionUser(r),
		GitHubEnabled: s.githubEnabled(),
		Git:           &gitView{Configured: false, BuildPolicy: "never", Ref: "refs/heads/main", ComposePath: "docker-compose.yml"},
	})
}

// gitViewFor returns the repo status (with diff) for an app, or nil if no repo is
// connected. It surfaces "what changed / deploy" on the app detail page, reusing the
// same data the dedicated git page shows.
func (s *Server) gitViewFor(ctx context.Context, project string) *gitView {
	if s.gitStore == nil {
		return nil
	}
	cfg, ok, err := s.gitStore.Get(project)
	if err != nil || !ok {
		return nil
	}
	gv := &gitView{
		Configured: true, Project: project,
		RepoURL: cfg.RepoURL, Ref: cfg.Ref, ComposePath: cfg.ComposePath,
		BuildPolicy: cfg.BuildPolicy, AutoDeploy: cfg.AutoDeploy, CredKind: cfg.CredKind,
		HasWebhook: cfg.HasWebhook, DeployedCommit: cfg.DeployedCommit, StagedCommit: cfg.StagedCommit,
		UpdateState: cfg.UpdateState, CommitsBehind: cfg.CommitsBehind, LastFetchError: cfg.LastFetchError,
		WriteDisabledReason: s.writeDisabledReason(),
	}
	if cfg.LastFetchAt > 0 {
		gv.LastFetchAt = cfg.LastFetchAt
	}
	gv.Diff = s.buildDiff(ctx, project, cfg)
	return gv
}

func (s *Server) handleGitGet(w http.ResponseWriter, r *http.Request) {
	if s.gitStore == nil {
		http.Error(w, "gitops unavailable", http.StatusServiceUnavailable)
		return
	}
	project := r.PathValue("project")
	cfg, ok, err := s.gitStore.Get(project)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	gv := &gitView{
		Project:             project,
		BuildPolicy:         "never",
		Ref:                 "refs/heads/main",
		ComposePath:         "docker-compose.yml",
		WriteDisabledReason: s.writeDisabledReason(),
	}
	if ok {
		gv.Configured = true
		gv.RepoURL = cfg.RepoURL
		gv.Ref = cfg.Ref
		gv.ComposePath = cfg.ComposePath
		gv.DockerfilePath = cfg.DockerfilePath
		gv.BuildPolicy = cfg.BuildPolicy
		gv.AutoDeploy = cfg.AutoDeploy
		gv.CredKind = cfg.CredKind
		gv.HasWebhook = cfg.HasWebhook
		gv.DeployedCommit = cfg.DeployedCommit
		gv.StagedCommit = cfg.StagedCommit
		gv.UpdateState = cfg.UpdateState
		gv.CommitsBehind = cfg.CommitsBehind
		gv.LastFetchError = cfg.LastFetchError
		if cfg.LastFetchAt > 0 {
			gv.LastFetchAt = cfg.LastFetchAt
		}
		// Consume the one-time rotated-token flash (opaque handle in the URL, the
		// secret only ever lived server-side).
		if h := r.URL.Query().Get("wh"); h != "" {
			if t, ok := s.webhookFlash.take(h, project); ok {
				gv.WebhookToken = t
			}
		}
		gv.Diff = s.buildDiff(r.Context(), project, cfg)
		gv.PreviewEnabled = cfg.PreviewEnabled
		// Offer the deploy-key reinstall only when the OAuth app is set up AND this app points at a
		// github.com repo (the reconnect handler re-checks the OAuth authorization). This is the
		// supported repair for a drifted OAuth deploy key.
		if s.githubEnabled() {
			if _, _, gok := parseGitHubRepo(cfg.RepoURL); gok {
				gv.CanReinstallKey = true
			}
		}
		if s.defStore != nil {
			gv.Versions, _ = s.defStore.List(project) // newest first; rows with a Commit are rollback targets
		}
	}
	s.render(w, r, "git.html", tmplData{
		Title:     "Repository — " + project,
		CSRFToken: CSRFToken(r.Context()),
		Username:  sessionUser(r),
		Project:   project,
		Git:       gv,
	})
}

// buildDiff renders the sanitized, capped pending-update preview between the
// deployed and staged commits (best-effort; nil on any read error).
func (s *Server) buildDiff(ctx context.Context, project string, cfg gitstore.Config) *gitDiffView {
	if cfg.StagedCommit == "" {
		return nil
	}
	repo, err := git.Open(s.gitObjectDir(project))
	if err != nil {
		return nil
	}
	deployed := repo.RefSha(ctx, git.DeployedRef)
	if deployed == "" {
		deployed = cfg.DeployedCommit
	}
	if deployed == cfg.StagedCommit {
		return nil
	}
	d, err := repo.Diff(ctx, deployed, cfg.StagedCommit)
	if err != nil {
		return nil
	}
	return &gitDiffView{CommitsBehind: d.CommitsBehind, Truncated: d.Truncated, Commits: d.Commits, Files: d.Files}
}

func (s *Server) handleGitSave(w http.ResponseWriter, r *http.Request) {
	if s.gitStore == nil {
		http.Error(w, "gitops unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	project := r.PathValue("project")
	if project == "" {
		project = strings.TrimSpace(r.PostFormValue("project"))
	}
	if s.cfg.IsProtectedProject(project) {
		http.Error(w, "protected project", http.StatusForbidden)
		return
	}
	in := gitstore.SaveInput{
		Project:    project,
		RepoURL:    r.PostFormValue("repo_url"),
		Ref:        strings.TrimSpace(r.PostFormValue("git_ref")),
		AutoDeploy: r.PostFormValue("auto_deploy") == "on",
		KnownHosts: r.PostFormValue("known_hosts"),
	}
	// Credential tri-state (plan §7.6): "none" clears; a provided value replaces;
	// an empty value with a token/ssh kind keeps the stored credential untouched
	// (so config edits never force re-entry of the PAT/key).
	kind := r.PostFormValue("cred_kind")
	cred := r.PostFormValue("cred")
	switch kind {
	case "none":
		empty := ""
		in.NewCred = &empty
	case "token", "ssh":
		if strings.TrimSpace(cred) != "" {
			in.NewCred = &cred
			in.CredKind = kind
		} // else keep existing
	}
	if err := s.gitStore.Save(r.Context(), in); err != nil {
		http.Error(w, "repository config rejected: "+err.Error(), http.StatusUnprocessableEntity)
		return
	}
	_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "git_save", Target: project, Outcome: audit.OK, Level: audit.Security})
	http.Redirect(w, r, "/apps/"+project+"/git", http.StatusSeeOther)
}

func (s *Server) handleGitWebhookRotate(w http.ResponseWriter, r *http.Request) {
	if s.gitStore == nil {
		http.Error(w, "gitops unavailable", http.StatusServiceUnavailable)
		return
	}
	_ = r.ParseForm()
	project := r.PathValue("project")
	if _, ok, _ := s.gitStore.Get(project); !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	token, err := s.gitStore.RotateWebhook(r.Context(), project)
	if err != nil {
		http.Error(w, "could not rotate webhook", http.StatusInternalServerError)
		return
	}
	_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "git_webhook_rotate", Target: project, Outcome: audit.OK, Level: audit.Security})
	// Hand the token to the next render via a one-time server-side flash; the
	// redirect carries only an opaque single-use handle (never the secret itself).
	handle := s.webhookFlash.put(project, token)
	http.Redirect(w, r, "/apps/"+project+"/git?wh="+handle, http.StatusSeeOther)
}

// --- fetch flow (read-plane) ---

func (s *Server) handleGitFetch(w http.ResponseWriter, r *http.Request) {
	if s.gitStore == nil {
		http.Error(w, "gitops unavailable", http.StatusServiceUnavailable)
		return
	}
	project := r.PathValue("project")
	if s.cfg.IsProtectedProject(project) {
		http.Error(w, "protected project", http.StatusForbidden)
		return
	}
	// Single-flight: serialize fetch with any in-progress deploy of any app.
	if !s.gitDeploy.TryAcquire() {
		http.Error(w, "a git operation is already in progress; try again shortly", http.StatusConflict)
		return
	}
	defer s.gitDeploy.Release()

	// Run the fetch + audit on a BACKGROUND context: a fetch is a slow network op, so if the operator
	// navigates away mid-fetch the request context cancels — which used to (a) mask the real fetch
	// error with "context canceled" and (b) drop the audit record ("audit write failed"). doFetch
	// keeps its own gitFetchTimeout bound, so background is still bounded. r stays the actor/IP source.
	bg := context.Background()
	actor, ip := sessionUser(r), ClientIP(r.Context()).String()
	_, _, err := s.doFetch(bg, project)
	outcome := audit.OK
	if err != nil {
		outcome = audit.Error
	}
	_ = s.audit.Log(bg, audit.Event{Actor: actor, IP: ip, Action: "git_fetch", Target: project, Outcome: outcome, Level: audit.Security})
	// Redirect either way; the page surfaces last_fetch_error / the new diff.
	http.Redirect(w, r, "/apps/"+project+"/git", http.StatusSeeOther)
}

// doFetch performs the read-plane fetch: fetch the configured ref into the staged
// ref, compute commits-behind, classify the FSM state, and record the result.
// Credentials never touch the URL argv and a failure records only a CLASSIFIED
// error (never raw git stderr). It mutates only refs/objects + the DB row.
func (s *Server) doFetch(ctx context.Context, project string) (gitstore.Config, string, error) {
	bg := context.Background() // DB bookkeeping must persist even if ctx is cancelled
	cfg, ok, err := s.gitStore.Get(project)
	if err != nil || !ok {
		return gitstore.Config{}, "", errors.New("repository not configured")
	}
	creds, err := s.gitStore.Creds(project)
	if err != nil {
		s.gitStore.SetFetchError(bg, project, "could not load credentials")
		return cfg, "", errors.New("could not load credentials")
	}
	repo, err := git.Open(s.gitObjectDir(project))
	if err != nil {
		return cfg, "", err
	}
	// Bound the network fetch on its own short timeout (independent of any larger
	// deploy cap) so a hung/slow repo can't hold the shared single-flight gate.
	fctx, fcancel := context.WithTimeout(ctx, gitFetchTimeout)
	stagedSha, ferr := repo.Fetch(fctx, cfg.RepoURL, cfg.Ref, creds)
	fcancel()
	if ferr != nil {
		s.gitStore.SetFetchError(bg, project, ferr.Error()) // already classified
		return cfg, "", ferr
	}
	deployed := repo.RefSha(ctx, git.DeployedRef)
	if deployed == "" {
		deployed = cfg.DeployedCommit
	}
	behind, _ := repo.CommitsBehind(ctx, deployed, stagedSha)
	state := "update_available"
	switch {
	case deployed == "":
		state = "update_available"
	case stagedSha == deployed:
		state = "up_to_date"
	default:
		if anc, _ := repo.IsAncestor(ctx, deployed, stagedSha); anc {
			state = "update_available"
		} else {
			// The deployed commit is not reachable from the fetched ref — history
			// was rewritten (e.g. a force-push). Surface it; never auto-deploy it.
			state = "history_rewritten"
		}
	}
	s.gitStore.SetFetchResult(bg, project, stagedSha, behind, state)
	cfg.StagedCommit = stagedSha
	cfg.UpdateState = state
	cfg.CommitsBehind = behind
	return cfg, stagedSha, nil
}

// --- deploy flow (write-plane, sha-pinned promote) ---

func (s *Server) handleGitDeploy(w http.ResponseWriter, r *http.Request) {
	if s.gitStore == nil || s.runner == nil {
		http.Error(w, "write plane unavailable", http.StatusServiceUnavailable)
		return
	}
	project := r.PathValue("project")
	actor := sessionUser(r)
	peer := ClientIP(r.Context()).String()
	if s.cfg.IsProtectedProject(project) {
		_ = s.audit.Log(r.Context(), audit.Event{Actor: actor, IP: peer, Action: "git_deploy", Target: project, Outcome: audit.Deny, Level: audit.Security, Detail: "protected project"})
		http.Error(w, "protected project", http.StatusForbidden)
		return
	}
	if ok, reason := s.runner.WriteAllowed(); !ok {
		http.Error(w, reason, http.StatusForbidden)
		return
	}
	cfg, ok, err := s.gitStore.Get(project)
	if err != nil || !ok {
		http.Error(w, "repository not configured", http.StatusNotFound)
		return
	}
	sha := strings.TrimSpace(r.FormValue("sha"))

	if !s.gitDeploy.TryAcquire() {
		http.Error(w, "a deploy is already in progress — it continues in the background even if you leave this page; refresh the app to see the result", http.StatusConflict)
		return
	}

	// Stream on a BACKGROUND context (not the request context) so navigating away can't
	// cancel a build mid-flight; the single-flight gate (held until the goroutine finishes)
	// blocks a duplicate restart. Progress is streamed best-effort.
	s.streamDeploy(w, fmt.Sprintf("$ deploy %s @ %s", project, shortSha(sha)), func(bg context.Context, emit func(string)) {
		if err := s.deployRepoApp(bg, cfg, sha, "manual", actor, false, emit); err != nil {
			emit(fmt.Sprintf("\n[failed: %v]", err))
			_ = s.audit.Log(bg, audit.Event{Actor: actor, IP: peer, Action: "git_deploy", Target: project + "@" + shortSha(sha), Outcome: audit.Error, Level: audit.Security, Detail: err.Error()})
			return
		}
		emit("\n[done]")
		_ = s.audit.Log(bg, audit.Event{Actor: actor, IP: peer, Action: "git_deploy", Target: project + "@" + shortSha(sha), Outcome: audit.OK, Level: audit.Security})
	})
}

// streamDeploy runs a write-plane deploy/rollback in a background goroutine and streams its
// output to the client best-effort. The CALLER must already hold the s.gitDeploy single-flight
// semaphore — streamDeploy releases it when the work finishes. The work runs on a background
// context (a client disconnect never cancels a build); auditing is the work function's job.
func (s *Server) streamDeploy(w http.ResponseWriter, opening string, run func(bg context.Context, emit func(string))) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	clearWriteDeadline(w) // deploy stream can run minutes (build + ACME) — exempt from WriteTimeout
	flusher, _ := w.(http.Flusher)

	lines := make(chan string, 512)
	go func() {
		defer s.gitDeploy.Release()
		defer close(lines)
		bg, cancel := context.WithTimeout(context.Background(), gitDeployTimeout)
		defer cancel()
		emit := func(line string) {
			select {
			case lines <- line:
			default: // client gone / slow — drop rather than block the deploy
			}
		}
		if opening != "" {
			emit(opening)
		}
		run(bg, emit)
	}()

	// Stream until the work finishes (lines closed) or the client disconnects (write error).
	// On disconnect we just stop reading — the goroutine above keeps running in the background.
	for line := range lines {
		if _, werr := fmt.Fprintln(w, line); werr != nil {
			break
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
}

// handleVersionRollback redeploys the git commit behind a chosen prior definition version — a
// one-click "roll back to this deploy". It re-runs the FULL deploy pipeline against that older
// commit (build services rebuild; pull-image services reuse their pinned image), so a rollback
// is the same sha-pinned promotion path as a forward deploy, just aimed backward. Only versions
// with a recorded commit (past git deploys) are rollback targets; a dashboard-config version has
// no commit and is rejected. Gated like a normal deploy (auth + CSRF); the version id is scoped
// to the app so a cross-app id can never resolve.
func (s *Server) handleVersionRollback(w http.ResponseWriter, r *http.Request) {
	if s.gitStore == nil || s.runner == nil || s.defStore == nil {
		http.Error(w, "write plane unavailable", http.StatusServiceUnavailable)
		return
	}
	project := r.PathValue("project")
	actor := sessionUser(r)
	peer := ClientIP(r.Context()).String()
	if s.cfg.IsProtectedProject(project) {
		_ = s.audit.Log(r.Context(), audit.Event{Actor: actor, IP: peer, Action: "version_rollback", Target: project, Outcome: audit.Deny, Level: audit.Security, Detail: "protected project"})
		http.Error(w, "protected project", http.StatusForbidden)
		return
	}
	if ok, reason := s.runner.WriteAllowed(); !ok {
		http.Error(w, reason, http.StatusForbidden)
		return
	}
	id, perr := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if perr != nil || id <= 0 {
		http.Error(w, "invalid version id", http.StatusBadRequest)
		return
	}
	cfg, ok, err := s.gitStore.Get(project)
	if err != nil || !ok {
		http.Error(w, "repository not configured", http.StatusNotFound)
		return
	}
	commit, cerr := s.defStore.CommitForVersion(project, id)
	if cerr != nil || !isFullSha40(commit) {
		http.Error(w, "this version has no recorded commit — only past git deploys can be rolled back", http.StatusBadRequest)
		return
	}

	if !s.gitDeploy.TryAcquire() {
		http.Error(w, "a deploy is already in progress — it continues in the background even if you leave this page; refresh the app to see the result", http.StatusConflict)
		return
	}

	s.streamDeploy(w, fmt.Sprintf("$ rollback %s → %s", project, shortSha(commit)), func(bg context.Context, emit func(string)) {
		if err := s.deployRepoApp(bg, cfg, commit, "rollback", actor, true, emit); err != nil {
			emit(fmt.Sprintf("\n[failed: %v]", err))
			_ = s.audit.Log(bg, audit.Event{Actor: actor, IP: peer, Action: "version_rollback", Target: project + "@" + shortSha(commit), Outcome: audit.Error, Level: audit.Security, Detail: err.Error()})
			return
		}
		emit("\n[done]")
		_ = s.audit.Log(bg, audit.Event{Actor: actor, IP: peer, Action: "version_rollback", Target: project + "@" + shortSha(commit), Outcome: audit.OK, Level: audit.Security})
	})
}

// handleVersionDelete removes one past version from the deploy history (the operator trimming
// the rollback list). It refuses the live/latest version (see defStore.DeleteVersion). This
// only frees the tiny history row — disk from superseded build images is reclaimed by the
// image-prune path, not here. Gated auth + CSRF.
func (s *Server) handleVersionDelete(w http.ResponseWriter, r *http.Request) {
	if s.defStore == nil {
		http.Error(w, "definition store unavailable", http.StatusServiceUnavailable)
		return
	}
	project := r.PathValue("project")
	actor := sessionUser(r)
	peer := ClientIP(r.Context()).String()
	if s.cfg.IsProtectedProject(project) { // consistency with every other git handler
		_ = s.audit.Log(r.Context(), audit.Event{Actor: actor, IP: peer, Action: "version_delete", Target: project, Outcome: audit.Deny, Level: audit.Security, Detail: "protected project"})
		http.Error(w, "protected project", http.StatusForbidden)
		return
	}
	id, perr := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if perr != nil || id <= 0 {
		http.Error(w, "invalid version id", http.StatusBadRequest)
		return
	}
	if err := s.defStore.DeleteVersion(r.Context(), project, id); err != nil {
		if errors.Is(err, definition.ErrNotDeletable) {
			http.Error(w, err.Error(), http.StatusBadRequest) // safe sentinel message
			return
		}
		// A raw DB error is internal — don't echo the driver string; record the failed attempt.
		_ = s.audit.Log(r.Context(), audit.Event{Actor: actor, IP: peer, Action: "version_delete", Target: project + " v" + strconv.FormatInt(id, 10), Outcome: audit.Error, Level: audit.Security, Detail: err.Error()})
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_ = s.audit.Log(r.Context(), audit.Event{
		Actor: actor, IP: peer,
		Action: "version_delete", Target: project + " v" + strconv.FormatInt(id, 10), Outcome: audit.OK, Level: audit.Security,
	})
	http.Redirect(w, r, "/apps/"+project+"/git", http.StatusSeeOther)
}

// deployRepoApp promotes ONE reviewed commit sha. The CALLER must hold the
// gitDeploy single-flight semaphore. Sequence (plan §7.6):
//  1. sha-pin: the staged ref must STILL point at exactly the reviewed sha (a
//     concurrent fetch that moved it aborts the deploy — re-review required).
//  2. §5.6-validate the cat-file'd compose bytes (the EXACT pinned bytes, not an
//     on-disk file an in-container app could have raced).
//  3. archive-extract the pinned tree into the Mooring-owned run dir (symlinks
//     rejected, paths confined).
//  4. materialize managed config files + the 0600 env-file (M5/M5b).
//  5. `docker compose up -d` under the gate + one-docker-child semaphore (M4).
//  6. pin deployed_commit (ref + DB) so gc never prunes it (rollback stays valid).
func (s *Server) deployRepoApp(ctx context.Context, cfg gitstore.Config, sha, source, actor string, rollback bool, onLine func(string)) error {
	bg := context.Background() // FSM/DB writes persist even if the client disconnects
	slug := cfg.Project
	rd := filepath.Clean(s.appRunDir(slug))
	if !filepath.IsAbs(rd) || rd == "/" || isSensitiveDir(rd) {
		return fmt.Errorf("app run directory %q is unsafe; refusing to deploy", rd)
	}
	if !isFullSha40(sha) {
		return errors.New("a full commit sha is required")
	}

	repo, err := git.Open(s.gitObjectDir(slug))
	if err != nil {
		return fmt.Errorf("open object store: %w", err)
	}

	// (1) sha-pin. A normal deploy promotes exactly the reviewed staged commit: the staged
	// ref + DB must STILL agree on `sha` (a concurrent fetch that moved it aborts — re-review
	// required). A ROLLBACK deliberately targets an OLDER commit that is (by definition) not
	// the staged one, so it skips that equality check — but STILL requires the commit object
	// to resolve, so a pruned/garbage sha can never deploy.
	if !rollback {
		stagedNow := repo.RefSha(ctx, git.StagedRef)
		if stagedNow != sha || cfg.StagedCommit != sha {
			s.gitStore.SetState(bg, slug, "update_blocked")
			return errors.New("the staged commit moved since it was reviewed; fetch and re-review before deploying")
		}
	}
	if _, err := repo.ResolveRef(ctx, sha); err != nil {
		return fmt.Errorf("commit not found: %w", err)
	}

	// (2) Mooring OWNS the compose: read the repo's mooring.yaml at the pinned
	// commit and GENERATE the compose (the repo never supplies one). With no
	// mooring.yaml, scaffold a default from the repo's detected stack. §5.6 then
	// validates the GENERATED bytes (cat-file already rejects symlinks/gitlinks).
	def, scaffolded, derr := s.loadRepoDefinition(ctx, repo, sha, slug, cfg.MooringFile)
	if derr != nil {
		s.gitStore.SetState(bg, slug, "update_blocked")
		return derr
	}
	if scaffolded {
		onLine("no mooring file in the repo — using a generated default")
	}
	// For a PREVIEW app, rewrite its edge routes to unique slug-derived subdomains BEFORE the
	// shorthand is expanded — so a preview lands on its own hostname (covered by the wildcard
	// cert) and can never collide with production, whatever the base app declared. Pin it to the
	// BASE app's edge namespace (read from the base's canonical def), never the fork PR's choice.
	if cfg.PreviewOf != "" {
		baseNamespace, nerr := s.basePreviewNamespace(cfg.PreviewOf)
		if nerr != nil {
			s.gitStore.SetState(bg, slug, "update_blocked")
			return nerr
		}
		applyPreviewPrefix(def, slug, baseNamespace)
	}
	// Resolve every `subdomain:` shorthand to a full <subdomain>.<edge.base_domain> hostname
	// IN PLACE, ONCE, before anything reads it — so compose bind mounts, cert issue/wait/sync,
	// routes, and collision checks all see the final FQDN (there is a single expansion point).
	// The DNS advisory runs first, while the subdomains are still present.
	s.adviseSubdomainDNS(ctx, def, onLine)
	if err := s.expandSubdomains(def); err != nil {
		s.gitStore.SetState(bg, slug, "update_blocked")
		return err
	}
	composeBytes, gerr := definition.ComposeBytes(def)
	if gerr != nil {
		s.gitStore.SetState(bg, slug, "update_blocked")
		return fmt.Errorf("generate compose: %w", gerr)
	}
	// Mint any `generate:` secrets that don't exist yet (idempotent — never
	// overwrites a live value), BEFORE the env is read so freshly-minted values
	// flow into validation and the deploy --env-file.
	if err := s.ensureGeneratedSecrets(ctx, slug, def, onLine); err != nil {
		s.gitStore.SetState(bg, slug, "update_blocked")
		return fmt.Errorf("generate secrets: %w", err)
	}
	env := s.repoComposeEnv(ctx, repo, sha, cfg)
	res := compose.ValidateBytes(composeBytes, env, rd, compose.Options{ProtectedPaths: s.protectedHostPaths()})
	if !res.OK() {
		if s.cfg.ComposeValidation.Mode != "review" {
			res.SortViolations()
			onLine("generated compose rejected by the §5.6 validator:")
			for _, v := range res.Violations {
				onLine("  - " + v.String())
			}
			s.gitStore.SetState(bg, slug, "update_blocked")
			return fmt.Errorf("compose validation failed (%d finding(s))", len(res.Violations))
		}
		onLine(fmt.Sprintf("WARNING (review mode): %d validator finding(s); proceeding.", len(res.Violations)))
	}

	s.gitStore.SetState(bg, slug, "deploying")

	// (3) archive-extract the pinned tree (Mooring-owned run dir).
	if err := os.MkdirAll(rd, 0o700); err != nil {
		s.gitStore.SetState(bg, slug, "update_blocked")
		return err
	}
	// The run dir is REUSED across deploys, and `git archive | tar` only adds/overwrites —
	// it never removes a file the new commit deleted. Left alone, a file dropped in this
	// commit lingers from the previous deploy and `COPY . .` bakes it into the image
	// (breaking the build when it references now-removed code). Remove exactly the
	// git-tracked files this commit deleted vs the previously-deployed one. This touches
	// ONLY git-tracked paths, so it never disturbs Mooring-owned files (.mooring/),
	// relative-bind data dirs, or named volumes — none are git-tracked (data-safe).
	if prev := repo.RefSha(ctx, git.DeployedRef); prev != "" && prev != sha {
		if n, derr := s.pruneDeletedTrackedFiles(ctx, repo, prev, sha, rd); derr != nil {
			onLine("warning: could not reconcile deleted files: " + derr.Error())
		} else if n > 0 {
			onLine(fmt.Sprintf("removed %d file(s) deleted since the last deploy", n))
		}
	}
	onLine("extracting " + shortSha(sha) + " → run dir")
	if err := repo.ArchiveTo(ctx, sha, rd); err != nil {
		s.gitStore.SetState(bg, slug, "update_blocked")
		return fmt.Errorf("checkout: %w", err)
	}

	// (4) Mooring owns the compose: write the GENERATED compose into the run dir
	// (overwriting whatever the repo shipped), then render the Dockerfile(s) for build
	// services. Then materialize config files + the 0600 env-file.
	composeAbs := filepath.Join(rd, "docker-compose.yml")
	// Symlink-safe write (temp + rename replaces a symlinked dest rather than
	// following it; ancestors checked) — never follow a planted symlink out of rd.
	if err := atomicWrite(composeAbs, composeBytes, 0o644, rd); err != nil {
		s.gitStore.SetState(bg, slug, "update_blocked")
		return fmt.Errorf("write generated compose: %w", err)
	}
	if err := s.writeGeneratedDockerfiles(ctx, repo, sha, rd, def, onLine); err != nil {
		s.gitStore.SetState(bg, slug, "update_blocked")
		return fmt.Errorf("generate Dockerfile: %w", err)
	}
	// Pre-create bind-mount source dirs (Mooring-owned, confined) so Docker doesn't
	// create a missing one as root.
	if err := materializeBindDirs(rd, defBindSources(def)); err != nil {
		s.gitStore.SetState(bg, slug, "update_blocked")
		return err
	}
	// Render managed config files + secret files into the run dir (the read-only bind
	// mounts are already in the generated compose).
	if err := s.materializeManaged(ctx, repo, sha, rd, slug, def); err != nil {
		s.gitStore.SetState(bg, slug, "update_blocked")
		return err
	}
	// Register cert_bindings so the managed edge issues each hostname's cert, then
	// sync the issued leaf into the run dir (blocks until issued). Replaces the
	// docker.sock cert-reloader: no container holds the socket.
	if err := s.registerCertBindings(ctx, slug, def, onLine); err != nil {
		s.gitStore.SetState(bg, slug, "update_blocked")
		return err
	}
	// Wait for ACME to finish issuing each cert_binding (the edge was just told to),
	// then copy the leaf in. This makes one deploy self-complete instead of failing
	// closed and forcing a manual re-deploy.
	if err := s.waitForCertBindings(ctx, def, onLine); err != nil {
		s.gitStore.SetState(bg, slug, "update_blocked")
		return err
	}
	if err := s.syncCertBindings(rd, def); err != nil {
		s.gitStore.SetState(bg, slug, "update_blocked")
		return err
	}
	app := &monitor.App{Project: slug, WorkingDir: rd, ConfigFiles: []string{composeAbs}}
	if err := s.materializeConfigFiles(app, env); err != nil {
		s.gitStore.SetState(bg, slug, "update_blocked")
		return fmt.Errorf("config-file materialization: %w", err)
	}
	envFile, cleanup, ferr := s.renderEnvFile(app, env)
	defer cleanup()
	if ferr != nil {
		s.gitStore.SetState(bg, slug, "update_blocked")
		return errors.New("could not render env file")
	}

	// Compose only diffs a service's CONFIG, not its bind-mounted file CONTENT — so a
	// changed config_file / secret / cert (same mount path) wouldn't recreate the
	// consumer. Digest each service's managed files now and compare to last deploy;
	// the changed ones get force-recreated after the up (a cert renewal lands the same
	// way). New services need no force — the up creates them.
	newDigests := s.managedDigests(rd, def)
	changed := changedServices(readDigestState(rd), newDigests)

	// (5) docker compose up under the gate + one-docker-child semaphore.
	action := []string{"up", "-d", "--remove-orphans"}
	if defHasBuild(def) {
		// The app declares build services — build the Mooring-generated Dockerfile(s).
		action = append(action, "--build")
	} else {
		// All services pull pre-built images; never build on-box.
		action = append(action, "--no-build")
	}
	depID := s.recordRepoDeployStart(bg, slug, source, actor, "git_deploy")
	onLine("$ docker compose " + strings.Join(action, " "))
	job := dockerexec.Job{Project: slug, Dir: rd, ConfigFiles: app.ConfigFiles, EnvFile: envFile, Action: action}
	// Suppress the self-healing supervisor for this app while we intentionally
	// recreate it (plan §8.5) — a deploy mid-flight must not look like a crash loop.
	defer s.leaseExpectedDown(ctx, slug)()
	declared := declaredServiceSet(def)
	runErr := s.runUpWithConflictReap(ctx, slug, declared,
		func(c context.Context, ol func(string)) error { return s.runner.Run(c, job, ol) },
		s.runner.RemoveContainers, onLine)
	code, outcome := classifyExit(runErr)
	s.recordDeployFinish(bg, depID, code, outcome)
	if runErr != nil {
		s.gitStore.SetState(bg, slug, "update_blocked")
		s.streamOOMHint(ctx, slug, declared, onLine)
		return fmt.Errorf("docker compose up failed: %w", runErr)
	}

	// Force-recreate ONLY the services whose managed file content changed, so the new
	// config/secret/cert takes effect (compose wouldn't otherwise restart them).
	if len(changed) > 0 {
		onLine("$ docker compose up -d --force-recreate " + strings.Join(changed, " ") + "  (changed config/secret/cert)")
		recreate := append([]string{"up", "-d", "--no-build", "--force-recreate", "--"}, changed...)
		rjob := dockerexec.Job{Project: slug, Dir: rd, ConfigFiles: app.ConfigFiles, EnvFile: envFile, Action: recreate}
		rerr := s.runUpWithConflictReap(ctx, slug, declared,
			func(c context.Context, ol func(string)) error { return s.runner.Run(c, rjob, ol) },
			s.runner.RemoveContainers, onLine)
		if rerr != nil {
			s.gitStore.SetState(bg, slug, "update_blocked")
			s.streamOOMHint(ctx, slug, declared, onLine)
			return fmt.Errorf("recreate of changed services failed: %w", rerr)
		}
	}
	if err := s.writeDigestState(rd, newDigests); err != nil {
		onLine("warning: could not record managed-file digests: " + err.Error())
	}

	// Apply this app's mooring.yaml routes (L7 + L4) as the source of truth and
	// reconcile the live edge / L4 LB. A persist failure (bad route or a cross-app
	// hostname/listener collision) blocks — the operator must resolve it.
	// The repo's mooring.yaml is the source of truth: record it as the canonical and
	// reconcile every projection (edge/L4 routes, scaling) from it. This also clears
	// any prior dashboard drift, since the canonical is now the freshly-deployed file.
	note := "git deploy: " + shortSha(sha)
	if rollback {
		note = "rollback to " + shortSha(sha)
	}
	if err := s.applyDefinition(ctx, slug, def, note, sha); err != nil {
		s.gitStore.SetState(bg, slug, "update_blocked")
		return fmt.Errorf("apply definition: %w", err)
	}

	// (6) pin the deployed commit (ref keeps gc from pruning it; DB drives the FSM).
	if err := repo.SetDeployedRef(bg, sha); err != nil {
		onLine("warning: could not pin deployed ref: " + err.Error())
	}
	if rollback {
		// A rollback moves the deployed commit BACKWARD while the branch tip is still ahead.
		// Record the true "behind" state (not a false up_to_date), and PAUSE auto-deploy so the
		// next webhook can't silently re-promote the commit the operator just rolled away from.
		behind, _ := repo.CommitsBehind(ctx, sha, cfg.StagedCommit)
		s.gitStore.SetDeployedBehind(bg, slug, sha, behind)
		if cfg.AutoDeploy {
			s.gitStore.SetAutoDeploy(bg, slug, false)
			onLine("auto-deploy paused (rolled back below the branch tip) — re-enable it on the repo page once resolved")
			_ = s.audit.Log(bg, audit.Event{Actor: actor, IP: "", Action: "auto_deploy_paused", Target: slug, Outcome: audit.OK, Level: audit.Security, Detail: "rollback to " + shortSha(sha)})
		}
	} else {
		s.gitStore.SetDeployed(bg, slug, sha)
	}
	onLine("deployed " + shortSha(sha))

	// Reclaim build cache so the generated multi-stage builds' single-use runtime layers
	// (a unique `COPY --from=build /app /app` per deploy) don't accumulate on the host.
	// Only when we actually built; best-effort (never fails the deploy); LRU-keeps recent
	// cache warm. The app is already up, so this only extends the deploy log briefly.
	if defHasBuild(def) && s.cfg.Server.BuildCacheGCOn() {
		keep := s.cfg.Server.BuildCacheKeepSize()
		onLine("$ docker builder prune (reclaiming build cache, keeping " + keep + " of recent)")
		pctx, pcancel := context.WithTimeout(bg, 15*time.Minute)
		if perr := s.runner.PruneBuildCache(pctx, keep, onLine); perr != nil {
			onLine("build-cache prune skipped: " + perr.Error())
		}
		pcancel()
	}
	return nil
}

// pruneDeletedTrackedFiles removes from the run dir the git-tracked files present in
// oldSha but absent from newSha — so a file deleted in a commit actually propagates (git
// archive|tar only adds/overwrites, never deletes). It removes ONLY regular files, each
// confined under rd, so it can never delete a bind-mounted data directory, a Mooring-owned
// file under .mooring/, or anything outside the run dir (none of those are git-tracked).
// Returns the number of files removed.
func (s *Server) pruneDeletedTrackedFiles(ctx context.Context, repo *git.Repo, oldSha, newSha, rd string) (int, error) {
	oldFiles, err := repo.LsFiles(ctx, oldSha)
	if err != nil {
		return 0, err
	}
	newFiles, err := repo.LsFiles(ctx, newSha)
	if err != nil {
		return 0, err
	}
	return removeDeletedTrackedFiles(oldFiles, newFiles, rd), nil
}

// removeDeletedTrackedFiles deletes from rd each path in oldFiles that is absent from
// newFiles — but ONLY regular files confined under rd. Directories (a bind-mounted data
// dir), symlinks, non-git-tracked paths (.mooring/, named volumes), and anything that
// resolves outside rd are never removed. Split out from the git lookup so it's unit
// testable. Returns the count removed.
func removeDeletedTrackedFiles(oldFiles, newFiles []string, rd string) int {
	keep := make(map[string]bool, len(newFiles))
	for _, f := range newFiles {
		keep[f] = true
	}
	removed := 0
	for _, f := range oldFiles {
		if keep[f] {
			continue
		}
		p := filepath.Join(rd, filepath.FromSlash(f))
		if !confinedUnder(p, rd) {
			continue // never delete outside the run dir
		}
		fi, statErr := os.Lstat(p)
		if statErr != nil {
			continue // already gone
		}
		if !fi.Mode().IsRegular() {
			continue // only plain files — never a directory (bind data) or a symlink
		}
		if os.Remove(p) == nil {
			removed++
		}
	}
	return removed
}

// repoComposeEnv builds the env used for BOTH §5.6 validation and the deploy
// --env-file from the repo's pinned .env (cat-file, not on-disk) overlaid by the
// env store, so validate == deploy.
func (s *Server) repoComposeEnv(ctx context.Context, repo *git.Repo, sha string, cfg gitstore.Config) compose.Env {
	env := compose.Env{}
	if b, err := repo.CatFile(ctx, sha, ".env"); err == nil {
		env = compose.ParseEnvFile(b)
	}
	if s.envStore != nil {
		if rendered, err := s.envStore.Render(cfg.Project); err == nil {
			for k, v := range rendered {
				env[k] = v // store overrides repo .env
			}
		}
	}
	return resolveEnvValues(env)
}

func (s *Server) recordRepoDeployStart(ctx context.Context, project, source, actor, action string) int64 {
	res, err := s.db.ExecContext(ctx,
		`INSERT INTO deploys(project, service, action, source, actor, started_at) VALUES(?, '', ?, ?, ?, ?)`,
		project, action, source, actor, time.Now().Unix())
	if err != nil {
		return 0
	}
	id, _ := res.LastInsertId()
	return id
}

// --- webhook (trigger-only, plan §5.7) ---

// handleWebhook is allowlist-exempt + auth-exempt but HMAC-gated, replay-protected,
// per-token rate-limited, and single-flight. It NEVER reads a ref/sha (or anything
// else) from the request body — the body is capped and ignored. A valid call
// triggers a read-plane fetch and, only when auto_deploy is on AND the fetch
// produced a clean fast-forward update, the same gated promote a human would run.
func (s *Server) handleWebhook(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	if s.gitStore == nil || token == "" {
		notFound(w) // never reveal whether the feature/token exists
		return
	}
	// Per-token rate limit (in addition to the general per-IP limiter).
	if !s.webhookRL.allow("wh:" + token) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
		return
	}
	project, hmacSecret, ok := s.gitStore.WebhookLookup(token)
	if !ok {
		s.auditWebhook(r, "", audit.Deny, "unknown token")
		notFound(w)
		return
	}
	ts := r.Header.Get("X-Mooring-Timestamp")
	nonce := r.Header.Get("X-Mooring-Nonce")
	sig := r.Header.Get("X-Mooring-Signature")
	if !verifyWebhookSig(hmacSecret, ts, nonce, sig) {
		s.auditWebhook(r, project, audit.Deny, "bad signature or stale timestamp")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	// Replay: each (token,nonce) is single-use within the window.
	if s.webhookSeen.seenOrAdd(token + ":" + nonce) {
		s.auditWebhook(r, project, audit.Deny, "replayed nonce")
		http.Error(w, "replay rejected", http.StatusConflict)
		return
	}
	// Single-flight: acquire BEFORE spawning so a webhook flood can't pile up
	// goroutines (queuing children is the OOM vector, plan §4).
	if !s.gitDeploy.TryAcquire() {
		s.auditWebhook(r, project, audit.OK, "busy; another git op in progress")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("busy\n"))
		return
	}
	if _, ok, _ := s.gitStore.Get(project); !ok {
		s.gitDeploy.Release()
		notFound(w)
		return
	}
	s.auditWebhook(r, project, audit.OK, "accepted")
	go func() {
		defer s.gitDeploy.Release()
		ctx, cancel := context.WithTimeout(context.Background(), gitDeployTimeout)
		defer cancel()
		s.fetchAndMaybeDeploy(ctx, project, "webhook")
	}()
	w.WriteHeader(http.StatusAccepted)
	_, _ = w.Write([]byte("accepted\n"))
}

// fetchAndMaybeDeploy runs the read-plane fetch and, ONLY for a repo that opted into
// auto_deploy with a clean fast-forward update, the same gated promote the manual
// deploy uses. The CALLER must already hold s.gitDeploy (the webhook handler and the
// poller both do). It is the shared core of the webhook trigger and the background
// poller, so both honor the auto_deploy flag identically.
func (s *Server) fetchAndMaybeDeploy(ctx context.Context, project, actor string) {
	_, staged, err := s.doFetch(ctx, project)
	if err != nil {
		s.log.Warn("git fetch failed", "project", project, "via", actor)
		return
	}
	// Re-read the config AFTER the fetch so a mid-fetch toggle of auto_deploy (or any
	// edit) is honored — never auto-deploy against a flag captured before the
	// (possibly slow) network fetch.
	fresh, ok, _ := s.gitStore.Get(project)
	if !ok || !fresh.AutoDeploy {
		return // fetch-only; the operator deploys manually
	}
	// Only auto-deploy a clean fast-forward update. A history rewrite or an
	// up-to-date state never auto-deploys.
	if fresh.UpdateState != "update_available" || staged == "" || fresh.StagedCommit != staged {
		return
	}
	if s.runner == nil {
		return
	}
	if ok, _ := s.runner.WriteAllowed(); !ok {
		return
	}
	if err := s.deployRepoApp(ctx, fresh, staged, actor, actor, false, func(line string) {
		s.log.Info("git auto-deploy", "project", project, "via", actor, "line", line)
	}); err != nil {
		s.log.Warn("git auto-deploy failed", "project", project, "via", actor)
	}
}

// verifyWebhookSig verifies HMAC-SHA256(secret, "<ts>.<nonce>") in constant time
// and that ts is within the replay window. The signed message is JUST the
// timestamp + nonce — the body is never part of the signature, reinforcing that
// the payload is irrelevant (trigger-only).
func verifyWebhookSig(secret []byte, tsStr, nonce, sigHex string) bool {
	if tsStr == "" || nonce == "" || sigHex == "" || len(nonce) > maxWebhookNonceLen {
		return false
	}
	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return false
	}
	now := time.Now().Unix()
	win := int64(webhookReplayWindow / time.Second)
	if ts < now-win || ts > now+int64(webhookForwardSkew/time.Second) {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(tsStr + "." + nonce))
	expected := mac.Sum(nil)
	got, err := hex.DecodeString(sigHex)
	if err != nil || len(got) != len(expected) {
		return false
	}
	return hmac.Equal(got, expected)
}

func (s *Server) auditWebhook(r *http.Request, project string, outcome audit.Outcome, detail string) {
	_ = s.audit.Log(r.Context(), audit.Event{
		Actor: "webhook", IP: ClientIP(r.Context()).String(),
		Action: "git_webhook", Target: project, Outcome: outcome, Level: audit.Security, Detail: detail,
	})
}
