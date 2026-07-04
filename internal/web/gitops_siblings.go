package web

import (
	"context"
	"net/http"
	"strings"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/git"
	"github.com/daboss2003/mooring/internal/gitstore"
)

// pendingApp is a mooring.*.yaml file found in an ALREADY-CONNECTED repo whose slug is
// not yet deployed as its own app — surfaced so the operator can add it in one click.
// The classic case: you had mooring.yaml connected and later committed a
// mooring.staging.yaml alongside it.
type pendingApp struct {
	Slug          string
	Name          string
	Path          string // repo-relative file, e.g. mooring.staging.yaml
	RepoURL       string
	Ref           string
	SourceProject string // an already-connected app in the SAME repo (its creds are reused)
}

// pendingAppsList returns the current undeployed-sibling set (nil until the first scan).
func (s *Server) pendingAppsList() []pendingApp {
	if p := s.pendingApps.Load(); p != nil {
		return *p
	}
	return nil
}

// scanPendingApps re-derives the undeployed-sibling set from the ALREADY-FETCHED object
// stores of every connected repo — no network, since the poller just fetched them. For
// each connected app it lists the root mooring.*.yaml files at the fetched tip and
// records any whose metadata.slug isn't itself a connected app. Deduped by slug.
func (s *Server) scanPendingApps(ctx context.Context, cfgs []gitstore.Config) {
	connected := make(map[string]bool, len(cfgs))
	for _, c := range cfgs {
		connected[c.Project] = true
	}
	seen := map[string]bool{}
	var pending []pendingApp
	for _, c := range cfgs {
		if ctx.Err() != nil {
			return
		}
		if s.cfg.IsProtectedProject(c.Project) {
			continue
		}
		repo, err := git.Open(s.gitObjectDir(c.Project))
		if err != nil {
			continue
		}
		sha := repo.RefSha(ctx, git.StagedRef)
		if sha == "" {
			sha = repo.RefSha(ctx, git.DeployedRef)
		}
		if sha == "" {
			continue
		}
		names, err := repo.LsTreeRoot(ctx, sha)
		if err != nil {
			continue
		}
		for _, name := range names {
			if strings.Contains(name, "/") || !gitstore.ValidMooringFile(name) {
				continue
			}
			b, cerr := repo.CatFile(ctx, sha, name)
			if cerr != nil {
				continue
			}
			slug, disp := definition.PeekMetadata(b)
			if slug == "" || connected[slug] || seen[slug] {
				continue // no slug, already an app, or a duplicate — not a new sibling
			}
			seen[slug] = true
			if disp == "" {
				disp = slug
			}
			pending = append(pending, pendingApp{
				Slug: slug, Name: disp, Path: name,
				RepoURL: c.RepoURL, Ref: c.Ref, SourceProject: c.Project,
			})
		}
	}
	s.pendingApps.Store(&pending)
}

// handleAddDefinition creates an app from a discovered-but-undeployed sibling definition
// (the "add this new mooring.*.yaml as an app" button). The slug/path are validated
// against the SERVER-computed pending set (never trusted from the client), and the git
// credential is reused from the sibling's already-connected repo. Like the connect flow
// it records the app and lands on its git page — it doesn't fetch or deploy on its own.
func (s *Server) handleAddDefinition(w http.ResponseWriter, r *http.Request) {
	if s.gitStore == nil {
		http.Error(w, "gitops unavailable", http.StatusServiceUnavailable)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	slug := strings.TrimSpace(r.PostFormValue("slug"))
	path := strings.TrimSpace(r.PostFormValue("path"))
	var pa *pendingApp
	for _, p := range s.pendingAppsList() {
		if p.Slug == slug && p.Path == path {
			pp := p
			pa = &pp
			break
		}
	}
	if pa == nil {
		s.renderConnectError(w, r, "that definition is no longer pending — refresh the Apps page and try again")
		return
	}
	// Already an app (raced with another add / an earlier connect)? Open it, don't clobber.
	if _, exists, _ := s.gitStore.Get(pa.Slug); exists {
		http.Redirect(w, r, "/apps/"+pa.Slug+"/git", http.StatusSeeOther)
		return
	}
	// Reuse the sibling repo's stored credentials (same repo as an existing app).
	creds, err := s.gitStore.Creds(pa.SourceProject)
	if err != nil {
		s.renderConnectError(w, r, "could not load the repository credentials")
		return
	}
	cred, credKind, knownHosts := "", "", ""
	switch {
	case creds.Token != "":
		cred, credKind = creds.Token, "token"
	case creds.SSHKey != "":
		cred, credKind, knownHosts = creds.SSHKey, "ssh", creds.KnownHosts
	}
	_ = s.audit.Log(r.Context(), audit.Event{Actor: sessionUser(r), IP: ClientIP(r.Context()).String(), Action: "git_add_definition", Target: pa.Slug, Outcome: audit.OK, Level: audit.Security, Detail: pa.Path})
	// Drop it from the pending set optimistically so the banner clears immediately.
	s.dropPending(pa.Slug)
	s.finishConnect(w, r, pa.Slug, pa.RepoURL, pa.Ref, pa.Path, cred, credKind, knownHosts, false)
}

// dropPending removes a slug from the pending set (after it's been added), so the
// banner updates without waiting for the next poll.
func (s *Server) dropPending(slug string) {
	cur := s.pendingAppsList()
	out := cur[:0:0]
	for _, p := range cur {
		if p.Slug != slug {
			out = append(out, p)
		}
	}
	s.pendingApps.Store(&out)
}
