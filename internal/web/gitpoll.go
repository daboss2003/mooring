package web

import (
	"context"
	"net/http"
	"time"
)

// dashActiveWindow is how long after the last focused-dashboard heartbeat the git
// poller still considers someone to be "checking" (so it keeps fetching). app.js
// pings every ~40s while the tab is visible, so this comfortably covers a missed ping.
const dashActiveWindow = 90 * time.Second

// handleDashPing is the focused-dashboard heartbeat: app.js calls it on load and
// every ~40s WHILE the tab is visible (paused when hidden). It records only "the
// operator is actively looking" so the git poller fetches on demand rather than
// around the clock.
func (s *Server) handleDashPing(w http.ResponseWriter, r *http.Request) {
	s.lastActive.Store(time.Now().UnixNano())
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

// dashActiveRecently reports whether a focused dashboard pinged within the window.
func (s *Server) dashActiveRecently() bool {
	last := s.lastActive.Load()
	return last != 0 && time.Since(time.Unix(0, last)) < dashActiveWindow
}

// RunGitPoller is the "just connect the repo and it works" loop: it FETCHES every
// connected repo so change-detection needs NO webhook setup. It is READ-PLANE ONLY —
// it never deploys; it surfaces an "update available" the operator deploys with a
// click (push-to-deploy stays an explicit opt-in via the webhook + auto_deploy, never
// this loop). A fetch never mutates a running app, and the loop is serialized through
// the same single-flight gate as deploys, so it can never pile up docker/git children.
//
// Because Mooring never auto-deploys, fetching when nobody is looking is wasted work
// — so the loop only fetches while a focused dashboard is open (the heartbeat above).
// When the operator opens/returns to the dashboard, the next tick fetches.
//
// interval <= 0 disables polling. Blocks until ctx is cancelled.
func (s *Server) RunGitPoller(ctx context.Context, interval time.Duration) {
	if s.gitStore == nil || interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if !s.dashActiveRecently() {
				continue // nobody is checking — don't spend git/network on a fetch
			}
			s.pollAllRepos(ctx)
		}
	}
}

// pollAllRepos fetches each connected, non-protected repo once. Protected projects
// (the socket-proxy, the edge) are never git-managed and are skipped defensively.
func (s *Server) pollAllRepos(ctx context.Context) {
	cfgs, err := s.gitStore.List()
	if err != nil {
		return
	}
	for _, c := range cfgs {
		if ctx.Err() != nil {
			return
		}
		if s.cfg.IsProtectedProject(c.Project) {
			continue
		}
		s.pollOneRepo(ctx, c.Project)
	}
	// After fetching, look for mooring.*.yaml files committed to a connected repo that
	// aren't deployed as their own app yet (e.g. a newly-added mooring.staging.yaml), so
	// the Apps page can offer to add them. Reads the just-fetched object stores (no network).
	s.scanPendingApps(ctx, cfgs)
}

// pollOneRepo FETCHES a single repo (never deploys), holding the single-flight gate
// for just that repo. If a deploy/fetch is already in progress anywhere, it skips this
// tick rather than queueing (queuing children is the OOM vector) — the next tick
// retries. The fetch is bounded by its own short timeout (in doFetch), so a slow or
// hostile repo endpoint can't hold the shared gate for a deploy-sized window.
func (s *Server) pollOneRepo(ctx context.Context, project string) {
	if !s.gitDeploy.TryAcquire() {
		return
	}
	defer s.gitDeploy.Release()
	if _, _, err := s.doFetch(ctx, project); err != nil {
		// err is a CLASSIFIED git error (never raw stderr / creds), so logging the reason is safe —
		// and it means the journal shows WHY (e.g. "repository or ref not found") without digging.
		s.log.Warn("git poll fetch failed", "project", project, "err", err.Error())
	}
}
