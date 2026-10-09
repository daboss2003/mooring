package web

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/git"
	"github.com/daboss2003/mooring/internal/gitstore"
)

// POST /api/v1/apps/{project}/deploy (scope deploy:write:<project>, enforced by requireToken) is the CI
// trigger: it fetches the app's tracked branch and deploys its head through the same gated, paced pipeline
// as the dashboard's Deploy button (deployRepoApp). The body is ignored — a caller can't name a commit,
// only ask for the branch head. It never deploys a force-pushed history or an app whose auto-deploy a
// rollback paused; those stay dashboard decisions.

// apiDeployPerMinute is how many deploy requests one token may make per minute.
const apiDeployPerMinute = 6

// Intentional: process-wide rather than a Server field like webhookRL — one Server runs per process and
// token ids are unique, so the key space is the same. Every fetch holds the one git/deploy gate shared by
// all apps; the limit keeps a looping CI job from monopolizing it (or the remote).
var apiDeployLimiter = newRateLimiter(apiDeployPerMinute, time.Minute)

// apiFetch is the fetch an API deploy runs (doFetch): a test seam, as a test can't reach a remote.
var apiFetch = (*Server).doFetch

// apiDeployResponse is the body of a 200 or 202 answer.
type apiDeployResponse struct {
	Status string `json:"status"`           // up_to_date | accepted | queued
	Commit string `json:"commit,omitempty"` // the branch head (not known yet when queued)
}

// apiDeployVerdict is what an API deploy does with the fetched branch head.
type apiDeployVerdict int

const (
	apiDeployGo          apiDeployVerdict = iota // deploy it
	apiDeployUpToDate                            // it is already deployed
	apiDeployRewritten                           // history was rewritten (force-push)
	apiDeployPaused                              // auto-deploy is paused after a rollback
	apiDeployFetchFailed                         // the fetch failed
	apiDeployInternal                            // an internal error (never shown to the client)
)

// apiDeployPlan is the decision for one API deploy, taken after the fetch.
type apiDeployPlan struct {
	verdict apiDeployVerdict
	cfg     gitstore.Config // the app as it stands after the fetch (apiDeployGo)
	sha     string          // the fetched branch head
	reason  string          // apiDeployFetchFailed: the classified fetch error; apiDeployInternal: for the log
}

// refusal is the answer for every verdict but apiDeployGo: HTTP status, client message, audit outcome and
// audit detail.
func (p apiDeployPlan) refusal() (status int, msg string, outcome audit.Outcome, detail string) {
	switch p.verdict {
	case apiDeployUpToDate:
		return http.StatusOK, "", audit.OK, "already deployed"
	case apiDeployRewritten:
		return http.StatusConflict, "history rewritten (force-push) — review and deploy it from the dashboard", audit.Deny, "history rewritten"
	case apiDeployPaused:
		return http.StatusConflict, "deploys are paused after a rollback — resume auto-deploy or deploy from the dashboard", audit.Deny, "auto-deploy paused after a rollback"
	case apiDeployFetchFailed:
		return http.StatusBadGateway, "git fetch failed: " + p.reason, audit.Error, "fetch failed: " + p.reason
	default:
		return http.StatusInternalServerError, "internal error", audit.Error, p.reason
	}
}

// handleAPIDeploy serves POST /api/v1/apps/{project}/deploy. Answers: 200 up_to_date, 202 accepted (the
// deploy runs in the background), 202 queued (another git operation holds the gate), 403/404/409/429/
// 502/503 errors.
func (s *Server) handleAPIDeploy(w http.ResponseWriter, r *http.Request) {
	project := r.PathValue("project")
	tokenID := TokenID(r.Context())
	actor, ip := "api:"+tokenID, ClientIP(r.Context()).String()
	// The fetch and the audit trail carry on if the client hangs up: the request is a trigger.
	ctx := context.WithoutCancel(r.Context())
	refuse := func(status int, target string, outcome audit.Outcome, detail, msg string) {
		s.auditAPIDeploy(ctx, actor, ip, target, outcome, detail)
		apiErr(w, status, msg)
	}

	if !apiDeployLimiter.allow(tokenID) {
		w.Header().Set("Retry-After", "60")
		refuse(http.StatusTooManyRequests, project, audit.Deny, "rate limited",
			"too many deploy requests for this token — at most "+strconv.Itoa(apiDeployPerMinute)+" a minute")
		return
	}
	if s.gitStore == nil || s.runner == nil {
		refuse(http.StatusServiceUnavailable, project, audit.Error, "write plane unavailable", "deploys are unavailable on this server")
		return
	}
	if s.cfg.IsProtectedProject(project) {
		refuse(http.StatusForbidden, project, audit.Deny, "protected project", "protected project")
		return
	}
	if ok, reason := s.runner.WriteAllowed(); !ok {
		refuse(http.StatusServiceUnavailable, project, audit.Error, "write plane disabled", reason)
		return
	}
	cfg, ok, err := s.gitStore.Get(project)
	switch {
	case err != nil:
		s.log.Error("api deploy: repository lookup failed", "project", project, "err", err)
		refuse(http.StatusInternalServerError, project, audit.Error, "repository lookup failed", "internal error")
		return
	case !ok && s.isProvisionedApp(project):
		refuse(http.StatusConflict, project, audit.Deny, "not a git app",
			"this app is not deployed from a git repository — deploy it from the dashboard")
		return
	case !ok:
		refuse(http.StatusNotFound, project, audit.Deny, "unknown app", "app not found")
		return
	case cfg.PreviewOf != "":
		refuse(http.StatusConflict, project, audit.Deny, "preview app", "previews deploy from pull requests")
		return
	}

	if !s.gitDeploy.TryAcquire() {
		detail := "queued; another git operation in progress"
		if !s.deployQueue.add(pendingDeploy{key: apiQueueKey(project), project: project, source: queuedFromAPI, tokenID: tokenID, ip: ip, queued: time.Now()}) {
			detail = "already queued (the waiting request now runs with this token); another git operation in progress"
		}
		s.auditAPIDeploy(ctx, actor, ip, project, audit.OK, detail)
		apiJSONStatus(w, http.StatusAccepted, apiDeployResponse{Status: "queued"})
		return
	}
	handedOff := false
	defer func() {
		if !handedOff {
			s.gitDeploy.Release()
		}
	}()
	// Intentional: extend, not clear, the server's 60s WriteTimeout — the fetch may take gitFetchTimeout,
	// and the answer after it is one small JSON object, so a bounded deadline keeps the slow-client guard.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(gitFetchTimeout + time.Minute))

	pctx, pcancel := context.WithTimeout(ctx, gitFetchTimeout+30*time.Second)
	plan := s.planAPIDeploy(pctx, project, actor)
	pcancel()
	target := project
	if plan.sha != "" {
		target = project + "@" + shortSha(plan.sha)
	}
	if plan.verdict != apiDeployGo {
		status, msg, outcome, detail := plan.refusal()
		if plan.verdict == apiDeployUpToDate {
			s.auditAPIDeploy(ctx, actor, ip, target, outcome, detail)
			apiJSONStatus(w, status, apiDeployResponse{Status: "up_to_date", Commit: plan.sha})
			return
		}
		refuse(status, target, outcome, detail, msg)
		return
	}
	s.auditAPIDeploy(ctx, actor, ip, target, audit.OK, "deploy started")
	handedOff = true
	go func() {
		defer s.gitDeploy.Release()
		defer func() {
			if rec := recover(); rec != nil { // a deploy is driven by untrusted repo content
				s.log.Error("api deploy panic recovered", "project", project, "via", actor, "panic", rec)
			}
		}()
		dctx, cancel := context.WithTimeout(context.Background(), s.repoDeployTimeout())
		defer cancel()
		s.runAPIDeploy(dctx, plan.cfg, plan.sha, actor, ip)
	}()
	apiJSONStatus(w, http.StatusAccepted, apiDeployResponse{Status: "accepted", Commit: plan.sha})
}

// runQueuedAPIDeploy runs an API deploy request that waited for the gate. It re-checks what may have
// changed while it waited — the token included — then fetches and decides by the same rules as a request
// that found the gate free. The caller already got 202 queued: the outcome goes to the audit trail and
// the log. The caller holds the gitDeploy gate.
func (s *Server) runQueuedAPIDeploy(ctx context.Context, d pendingDeploy) {
	actor := "api:" + d.tokenID
	note := func(target string, outcome audit.Outcome, detail string) {
		s.auditAPIDeploy(context.Background(), actor, d.ip, target, outcome, "queued request: "+detail)
	}
	if !s.tokenStillGrants(ctx, d.tokenID, "deploy:write:"+d.project) {
		note(d.project, audit.Deny, "the token was revoked, expired or lost the scope while the request waited")
		return
	}
	if s.gitStore == nil || s.runner == nil {
		note(d.project, audit.Error, "write plane unavailable")
		return
	}
	if ok, _ := s.runner.WriteAllowed(); !ok {
		note(d.project, audit.Error, "write plane disabled")
		return
	}
	if cfg, ok, err := s.gitStore.Get(d.project); err != nil || !ok || cfg.PreviewOf != "" {
		note(d.project, audit.Error, "the app is no longer a git app")
		return
	}
	plan := s.planAPIDeploy(ctx, d.project, actor)
	target := d.project
	if plan.sha != "" {
		target = d.project + "@" + shortSha(plan.sha)
	}
	if plan.verdict != apiDeployGo {
		_, _, outcome, detail := plan.refusal()
		note(target, outcome, detail)
		return
	}
	note(target, audit.OK, "deploy started")
	s.runAPIDeploy(ctx, plan.cfg, plan.sha, actor, d.ip)
}

// tokenStillGrants reports whether API token id is still active (not revoked, not expired) and holds
// scope. requireToken checked it when the request arrived; a queued request runs later.
func (s *Server) tokenStillGrants(ctx context.Context, id, scope string) bool {
	if s.apiTokens == nil {
		return false
	}
	rec, err := s.apiTokens.Get(ctx, id)
	return err == nil && !rec.Revoked && rec.ExpiresAt > time.Now().Unix() && rec.Allows(scope)
}

// planAPIDeploy fetches the app's tracked branch and decides what an API deploy does with its head. The
// caller holds the gitDeploy gate.
func (s *Server) planAPIDeploy(ctx context.Context, project, actor string) apiDeployPlan {
	started := time.Now().Unix()
	fetched, sha, err := apiFetch(s, ctx, project)
	if err != nil {
		s.log.Warn("git api fetch failed", "project", project, "via", actor, "err", err.Error(), "git_stderr", git.RawStderr(err))
		return apiDeployPlan{verdict: apiDeployFetchFailed, reason: s.fetchFailureReason(project, started)}
	}
	switch fetched.UpdateState {
	case "up_to_date":
		return apiDeployPlan{verdict: apiDeployUpToDate, sha: sha}
	case "history_rewritten":
		return apiDeployPlan{verdict: apiDeployRewritten, sha: sha}
	case "update_available":
	default:
		return apiDeployPlan{verdict: apiDeployInternal, sha: sha, reason: "unexpected fetch state " + fetched.UpdateState}
	}
	// Re-read after the fetch, as fetchAndMaybeDeploy does: an auto-deploy toggle made while the fetch ran
	// counts. Its staged commit is the one just fetched (the gate keeps any other fetch out), which the
	// deploy's sha pin requires.
	fresh, ok, gerr := s.gitStore.Get(project)
	if gerr != nil || !ok || fresh.StagedCommit != sha {
		return apiDeployPlan{verdict: apiDeployInternal, sha: sha, reason: "the app changed during the fetch"}
	}
	paused, perr := s.pausedAfterRollback(ctx, fresh)
	switch {
	case perr != nil:
		s.log.Error("api deploy: deploy history lookup failed", "project", project, "err", perr)
		return apiDeployPlan{verdict: apiDeployInternal, sha: sha, reason: "deploy history lookup failed"}
	case paused:
		return apiDeployPlan{verdict: apiDeployPaused, sha: sha}
	}
	return apiDeployPlan{verdict: apiDeployGo, cfg: fresh, sha: sha}
}

// runAPIDeploy deploys sha, the fetched head of cfg's branch, for an API caller and records the verdict in
// the audit trail as the dashboard's Deploy does. Progress goes to the log, as for an auto-deploy. The
// caller holds the gitDeploy gate.
func (s *Server) runAPIDeploy(ctx context.Context, cfg gitstore.Config, sha, actor, ip string) {
	project := cfg.Project
	onLine := func(line string) { s.log.Info("git api deploy", "project", project, "via", actor, "line", line) }
	// Always paced, like every automatic deploy.
	problems, err := s.deployRepoApp(ctx, cfg, sha, "api", actor, false, false, onLine)
	outcome, detail := deployVerdict(onLine, false, problems, err)
	switch {
	case err != nil:
		s.log.Warn("git api deploy failed", "project", project, "via", actor)
	case len(problems) > 0:
		s.log.Warn("git api deploy finished with problems", "project", project, "via", actor, "problems", deployProblemsText(problems))
	}
	_ = s.audit.Log(context.Background(), audit.Event{Actor: actor, IP: ip, Action: "git_deploy", Target: project + "@" + shortSha(sha), Outcome: outcome, Level: audit.Security, Detail: detail})
}

// pausedAfterRollback reports whether the app's API deploys are paused after a rollback: auto-deploy is off
// and either the live release came from a rollback, or a rollback was interrupted. The live release came from
// a rollback when the newest git-originated definition version is one: a rollback records it once its
// rollout finished (even if the edge check after it fails), a rollback that failed before that records
// nothing, and dashboard edits add versions with other notes. Turning auto-deploy back on, or a later git
// deploy whose rollout finishes, ends the pause.
//
// Intentional: a rollback made while auto-deploy was already off pauses API deploys too — the next CI run
// would otherwise re-promote the commit the operator just rolled away from.
//
// Intentional: an unfinished rollback record (the app's newest git deploy record) pauses too. Every git deploy
// holds the gitDeploy gate and so does this caller, so an unfinished record is a deploy Mooring stopped
// partway (a crash or restart) with an unknown result: it stays paused until the operator decides.
func (s *Server) pausedAfterRollback(ctx context.Context, cfg gitstore.Config) (bool, error) {
	if cfg.AutoDeploy {
		return false, nil
	}
	var source string
	var finished int64
	err := s.db.QueryRowContext(ctx,
		`SELECT source, finished_at FROM deploys WHERE project=? AND action='git_deploy' ORDER BY id DESC LIMIT 1`,
		cfg.Project).Scan(&source, &finished)
	switch {
	case err == nil && source == "rollback" && finished == 0:
		return true, nil
	case err != nil && !errors.Is(err, sql.ErrNoRows):
		return false, err
	}
	if s.defStore == nil {
		return false, nil
	}
	note, err := s.defStore.LatestNote(cfg.Project, noteGitDeploy, noteRollback)
	if err != nil {
		return false, err
	}
	return strings.HasPrefix(note, noteRollback), nil
}

// fetchFailureReason is the classified error a fetch that started at `since` recorded for the app (what
// its repository page shows), or a generic one. Raw git output and local paths never reach the client.
func (s *Server) fetchFailureReason(project string, since int64) string {
	if cfg, ok, err := s.gitStore.Get(project); err == nil && ok && cfg.LastFetchAt >= since && cfg.LastFetchError != "" {
		return cfg.LastFetchError
	}
	return "see the app's repository page"
}

// isProvisionedApp reports whether project is a legacy provisioned (non-git) app.
func (s *Server) isProvisionedApp(project string) bool {
	if s.provStore == nil {
		return false
	}
	_, ok, _ := s.provStore.Get(project)
	return ok
}

// auditAPIDeploy records one API deploy decision (token id as actor, never the secret).
func (s *Server) auditAPIDeploy(ctx context.Context, actor, ip, target string, outcome audit.Outcome, detail string) {
	_ = s.audit.Log(ctx, audit.Event{Actor: actor, IP: ip, Action: "api_deploy", Target: target, Outcome: outcome, Level: audit.Security, Detail: detail})
}
