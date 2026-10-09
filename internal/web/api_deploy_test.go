package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/apitoken"
	"github.com/daboss2003/mooring/internal/audit"
	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/dockerexec"
	"github.com/daboss2003/mooring/internal/git"
	"github.com/daboss2003/mooring/internal/gitstore"
	"github.com/daboss2003/mooring/internal/provstore"
)

// apiPeer is a CI runner's address: inside every test token's CIDR set.
const apiPeer = "198.51.100.5:1"

// apiDeployEnv is a server with a git store and a token store, the write plane armed, and a stand-in
// docker CLI that accepts every call — so an API deploy runs the real pipeline without a daemon. The
// fetch is stagedHeadFetch (a test can't reach a remote).
type apiDeployEnv struct {
	e      *testEnv
	tokens *apitoken.Store
	calls  string // the stand-in docker's call log
}

func newAPIDeployEnv(t *testing.T) *apiDeployEnv {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("shell-script docker stand-in")
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	dir := t.TempDir()
	calls := filepath.Join(dir, "calls.log")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '" + calls + "'\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	// The token CIDR is allowlisted too, so the IP gate admits it without a reload.
	e := buildServer(t, []string{"127.0.0.1/32", "198.51.100.0/24"}, false, nil, "")
	e.srv.apiTokens = apitoken.NewStore(e.srv.db)
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), true, "")
	e.srv.defStore = definition.NewStore(e.srv.db, make([]byte, 32))
	oldLimiter, oldFetch := apiDeployLimiter, apiFetch
	apiDeployLimiter = newRateLimiter(apiDeployPerMinute, time.Minute)
	apiFetch = stagedHeadFetch
	t.Cleanup(func() { apiDeployLimiter, apiFetch = oldLimiter, oldFetch })
	return &apiDeployEnv{e: e, tokens: e.srv.apiTokens, calls: calls}
}

// mint stores a token valid from apiPeer and returns its bearer and id.
func (a *apiDeployEnv) mint(t *testing.T, scopes ...string) (bearerTok, id string) {
	t.Helper()
	now := time.Now()
	m, err := apitoken.Mint(scopes, []string{"198.51.100.0/24"}, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.tokens.Insert(context.Background(), m.Record, "ci", now); err != nil {
		t.Fatal(err)
	}
	return m.Plaintext, m.Record.ID
}

// post sends POST /api/v1/apps/<project>/deploy and decodes the JSON body.
func (a *apiDeployEnv) post(t *testing.T, tok, project string) (*http.Response, map[string]string) {
	t.Helper()
	resp := a.e.req(t, "POST", "/api/v1/apps/"+project+"/deploy", apiPeer, bearer(tok), nil, nil)
	body := map[string]string{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("response is not JSON (status %d): %v", resp.StatusCode, err)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want JSON", ct)
	}
	return resp, body
}

// dockerCalls lists every stand-in docker invocation so far.
func (a *apiDeployEnv) dockerCalls() []string {
	b, _ := os.ReadFile(a.calls)
	if s := strings.TrimSpace(string(b)); s != "" {
		return strings.Split(s, "\n")
	}
	return nil
}

// waitGateFree waits until nothing holds the git/deploy gate (an accepted deploy runs in the background).
func waitGateFree(t *testing.T, s *Server) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := s.gitDeploy.Acquire(ctx); err != nil {
		t.Fatal("the git/deploy gate was never released")
	}
	s.gitDeploy.Release()
}

type deployRow struct{ source, actor, outcome string }

// deployRowsFor lists the app's git deploy records, oldest first.
func deployRowsFor(t *testing.T, s *Server, project string) []deployRow {
	t.Helper()
	rows, err := s.db.Query(`SELECT source, actor, outcome FROM deploys WHERE project=? AND action='git_deploy' ORDER BY id`, project)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []deployRow
	for rows.Next() {
		var d deployRow
		if err := rows.Scan(&d.source, &d.actor, &d.outcome); err != nil {
			t.Fatal(err)
		}
		out = append(out, d)
	}
	return out
}

// deployAudit lists the api_deploy and git_deploy audit events, oldest first.
func deployAudit(t *testing.T, s *Server) []apiEvent {
	t.Helper()
	rows, err := s.db.Query(`SELECT seq, ts, actor, ip, action, target, outcome, level, detail FROM events
		WHERE action IN ('api_deploy', 'git_deploy') ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []apiEvent
	for rows.Next() {
		var e apiEvent
		if err := rows.Scan(&e.Seq, &e.TS, &e.Actor, &e.IP, &e.Action, &e.Target, &e.Outcome, &e.Level, &e.Detail); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

// stagedHeadFetch stands in for doFetch: the remote's head is whatever the fixture left in the staged
// ref, classified against the deployed commit as doFetch does. With nothing staged it fails like an
// unreachable remote.
func stagedHeadFetch(s *Server, ctx context.Context, project string) (gitstore.Config, string, error) {
	cfg, ok, err := s.gitStore.Get(project)
	if err != nil || !ok {
		return gitstore.Config{}, "", errors.New("repository not configured")
	}
	repo, err := git.Open(s.gitObjectDir(project))
	if err != nil {
		return cfg, "", err
	}
	staged := repo.RefSha(ctx, git.StagedRef)
	if staged == "" {
		const msg = "git: network error reaching the remote"
		s.gitStore.SetFetchError(ctx, project, msg)
		return cfg, "", errors.New(msg)
	}
	deployed := repo.RefSha(ctx, git.DeployedRef)
	if deployed == "" {
		deployed = cfg.DeployedCommit
	}
	behind, _ := repo.CommitsBehind(ctx, deployed, staged)
	state := "update_available"
	switch {
	case deployed == "":
	case staged == deployed:
		state = "up_to_date"
	default:
		if anc, _ := repo.IsAncestor(ctx, deployed, staged); !anc {
			state = "history_rewritten"
		}
	}
	s.gitStore.SetFetchResult(ctx, project, staged, behind, state)
	cfg.StagedCommit, cfg.UpdateState, cfg.CommitsBehind = staged, state, behind
	return cfg, staged, nil
}

// twoCommitRepo commits the definition twice (the second commit adds a file) into a bare clone at objDir
// and stages the newer commit, as a fetch of the branch would. It returns both shas.
func twoCommitRepo(t *testing.T, objDir string) (older, newer string) {
	t.Helper()
	env := append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	run := func(dir string, args ...string) string {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	work := t.TempDir()
	run(work, "init", "-q", "-b", "main")
	for i, f := range []string{"mooring.yaml", "CHANGELOG"} {
		body := repoMooringYAML
		if i > 0 {
			body = "v2\n"
		}
		if err := os.WriteFile(filepath.Join(work, f), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		run(work, "add", "-A")
		run(work, "commit", "-q", "-m", f)
		if i == 0 {
			older = run(work, "rev-parse", "HEAD")
		}
	}
	newer = run(work, "rev-parse", "HEAD")
	if err := os.MkdirAll(filepath.Dir(objDir), 0o700); err != nil {
		t.Fatal(err)
	}
	run(work, "clone", "--bare", "-q", work, objDir)
	run(work, "--git-dir="+objDir, "update-ref", "refs/mooring/staged", newer)
	return older, newer
}

// The happy path: the branch head is fetched, the request answers 202 with the commit at once, and the
// deploy runs in the background through the real pipeline, recorded as source "api" by this token.
func TestAPIDeployAcceptedRunsTheDeploy(t *testing.T) {
	a := newAPIDeployEnv(t)
	sha := gitObjStoreFixture(t, a.e.srv.gitObjectDir("shop"), repoMooringYAML)
	configureRepo(t, a.e, "shop", sha)
	tok, id := a.mint(t, "deploy:write:shop")

	resp, body := a.post(t, tok, "shop")
	if resp.StatusCode != http.StatusAccepted || body["status"] != "accepted" || body["commit"] != sha {
		t.Fatalf("deploy = %d %v, want 202 accepted with commit %s", resp.StatusCode, body, sha)
	}
	waitGateFree(t, a.e.srv)

	rows := deployRowsFor(t, a.e.srv, "shop")
	if len(rows) != 1 || rows[0] != (deployRow{source: "api", actor: "api:" + id, outcome: "ok"}) {
		t.Fatalf("deploy records = %+v, want one ok deploy by source api, actor api:%s", rows, id)
	}
	up := false
	for _, c := range a.dockerCalls() {
		up = up || strings.Contains(c, " up ")
	}
	if !up {
		t.Errorf("the deploy never ran docker compose up: %v", a.dockerCalls())
	}
	if cfg, _, _ := a.e.srv.gitStore.Get("shop"); cfg.DeployedCommit != sha || cfg.UpdateState != "up_to_date" {
		t.Errorf("after the deploy: deployed=%q state=%q, want %s up_to_date", cfg.DeployedCommit, cfg.UpdateState, sha)
	}
	ev := deployAudit(t, a.e.srv)
	if len(ev) != 2 {
		t.Fatalf("audit = %+v, want the request and the verdict", ev)
	}
	target := "shop@" + shortSha(sha)
	if r := ev[0]; r.Action != "api_deploy" || r.Actor != "api:"+id || r.Outcome != string(audit.OK) || r.Target != target || r.Level != string(audit.Security) || r.IP != "198.51.100.5" {
		t.Errorf("request audit = %+v", r)
	}
	if v := ev[1]; v.Action != "git_deploy" || v.Actor != "api:"+id || v.Outcome != string(audit.OK) || v.Target != target {
		t.Errorf("verdict audit = %+v", v)
	}
}

// An app already running the branch head isn't redeployed: 200 up_to_date with the commit.
func TestAPIDeployUpToDate(t *testing.T) {
	a := newAPIDeployEnv(t)
	sha := gitObjStoreFixture(t, a.e.srv.gitObjectDir("shop"), repoMooringYAML)
	configureRepo(t, a.e, "shop", sha)
	a.e.srv.gitStore.SetDeployed(context.Background(), "shop", sha)
	tok, _ := a.mint(t, "deploy:write:shop")

	resp, body := a.post(t, tok, "shop")
	if resp.StatusCode != http.StatusOK || body["status"] != "up_to_date" || body["commit"] != sha {
		t.Fatalf("deploy = %d %v, want 200 up_to_date with commit %s", resp.StatusCode, body, sha)
	}
	if rows := deployRowsFor(t, a.e.srv, "shop"); len(rows) != 0 {
		t.Errorf("an up-to-date app must not be deployed, got %+v", rows)
	}
	if calls := a.dockerCalls(); len(calls) != 0 {
		t.Errorf("docker was called: %v", calls)
	}
	waitGateFree(t, a.e.srv)
}

// A force-pushed branch (the deployed commit isn't an ancestor of the head) is never deployed by the API.
func TestAPIDeployHistoryRewrittenRefused(t *testing.T) {
	a := newAPIDeployEnv(t)
	sha := gitObjStoreFixture(t, a.e.srv.gitObjectDir("shop"), repoMooringYAML)
	configureRepo(t, a.e, "shop", sha)
	a.e.srv.gitStore.SetDeployed(context.Background(), "shop", "0123456789abcdef0123456789abcdef01234567")
	tok, _ := a.mint(t, "deploy:write:shop")

	resp, body := a.post(t, tok, "shop")
	if resp.StatusCode != http.StatusConflict || body["error"] != "history rewritten (force-push) — review and deploy it from the dashboard" {
		t.Fatalf("deploy = %d %v, want 409 history rewritten", resp.StatusCode, body)
	}
	if rows := deployRowsFor(t, a.e.srv, "shop"); len(rows) != 0 {
		t.Errorf("a rewritten history must not be deployed, got %+v", rows)
	}
	waitGateFree(t, a.e.srv)
}

// A rollback pauses auto-deploy; while paused the API refuses to re-promote the commit the operator rolled
// away from. Turning auto-deploy back on ends the pause.
func TestAPIDeployPausedAfterRollback(t *testing.T) {
	a := newAPIDeployEnv(t)
	ctx := context.Background()
	older, newer := twoCommitRepo(t, a.e.srv.gitObjectDir("shop"))
	if err := a.e.srv.gitStore.Save(ctx, gitstore.SaveInput{
		Project: "shop", RepoURL: "https://nonexistent.invalid/o/r.git", Ref: "refs/heads/main",
		ComposePath: "docker-compose.yml", BuildPolicy: "never", AutoDeploy: true,
	}); err != nil {
		t.Fatal(err)
	}
	a.e.srv.gitStore.SetFetchResult(ctx, "shop", newer, 1, "update_available")
	cfg, _, _ := a.e.srv.gitStore.Get("shop")
	// The operator rolls back to the older commit (the real rollback path).
	if _, err := a.e.srv.deployRepoApp(ctx, cfg, older, "rollback", "operator", true, false, func(string) {}); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if cfg, _, _ := a.e.srv.gitStore.Get("shop"); cfg.AutoDeploy {
		t.Fatal("the rollback must pause auto-deploy")
	}
	tok, id := a.mint(t, "deploy:write:shop")

	resp, body := a.post(t, tok, "shop")
	if resp.StatusCode != http.StatusConflict || body["error"] != "deploys are paused after a rollback — resume auto-deploy or deploy from the dashboard" {
		t.Fatalf("deploy after a rollback = %d %v, want 409 paused", resp.StatusCode, body)
	}
	if rows := deployRowsFor(t, a.e.srv, "shop"); len(rows) != 1 {
		t.Fatalf("a paused app must not be deployed, records = %+v", rows)
	}
	waitGateFree(t, a.e.srv)

	a.e.srv.gitStore.SetAutoDeploy(ctx, "shop", true) // the operator resumes auto-deploy
	resp, body = a.post(t, tok, "shop")
	if resp.StatusCode != http.StatusAccepted || body["commit"] != newer {
		t.Fatalf("deploy after resuming = %d %v, want 202 accepted with %s", resp.StatusCode, body, newer)
	}
	waitGateFree(t, a.e.srv)
	rows := deployRowsFor(t, a.e.srv, "shop")
	if len(rows) != 2 || rows[1] != (deployRow{source: "api", actor: "api:" + id, outcome: "ok"}) {
		t.Fatalf("deploy records = %+v", rows)
	}
}

// API deploys pause after a rollback while auto-deploy is off: when the live release came from a rollback
// (the newest git-originated definition version), or when a rollback was interrupted (the newest git deploy
// record is an unfinished rollback).
func TestPausedAfterRollbackRule(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.defStore = definition.NewStore(e.srv.db, make([]byte, 32))
	ctx := context.Background()
	base, err := definition.Parse([]byte(repoMooringYAML))
	if err != nil {
		t.Fatal(err)
	}
	gitV, rbV := noteGitDeploy+"bbbbbbb", noteRollback+"aaaaaaa"
	for i, tc := range []struct {
		name     string
		versions []string // definition version notes, oldest first
		deploys  []string // git deploy records "<source>:<outcome>", oldest first; "" outcome = unfinished
		auto     bool
		want     bool
	}{
		{"never deployed", nil, nil, false, false},
		{"git deploys only", []string{gitV, gitV}, []string{"manual:ok", "webhook:ok"}, false, false},
		{"rolled back, auto-deploy off", []string{gitV, rbV}, []string{"manual:ok", "rollback:ok"}, false, true},
		{"rolled back, auto-deploy resumed", []string{gitV, rbV}, []string{"manual:ok", "rollback:ok"}, true, false},
		{"deployed again after the rollback", []string{rbV, gitV}, []string{"rollback:ok", "manual:ok"}, false, false},
		{"dashboard edit after the rollback", []string{rbV, "dashboard: scaling for api"}, []string{"rollback:ok"}, false, true},
		{"dashboard edit only", []string{"dashboard: scaling for api"}, nil, false, false},
		{"rollback failed before its rollout finished", []string{gitV}, []string{"manual:ok", "rollback:error"}, false, false},
		{"rollback failed at the edge check", []string{gitV, rbV}, []string{"manual:ok", "rollback:error"}, false, true},
		{"interrupted rollback", []string{gitV}, []string{"manual:ok", "rollback:"}, false, true},
		{"interrupted rollback, auto-deploy on", []string{gitV}, []string{"manual:ok", "rollback:"}, true, false},
		{"deploy finished after an interrupted rollback", []string{gitV, gitV}, []string{"rollback:", "manual:ok"}, false, false},
		{"interrupted dashboard deploy after a rollback", []string{rbV}, []string{"rollback:ok", "manual:"}, false, true},
	} {
		project := "app" + strconv.Itoa(i)
		for _, note := range tc.versions {
			d := *base
			d.Metadata.Slug = project
			if _, err := e.srv.defStore.SaveCanonical(ctx, &d, note, ""); err != nil {
				t.Fatal(err)
			}
		}
		for _, rec := range tc.deploys {
			src, outcome, _ := strings.Cut(rec, ":")
			id := e.srv.recordRepoDeployStart(ctx, project, src, "operator", "git_deploy")
			if outcome != "" {
				e.srv.recordDeployFinish(ctx, id, 0, outcome)
			}
		}
		// A lifecycle action on the app is not a git deploy.
		e.srv.recordDeployFinish(ctx, e.srv.recordDeployStart(ctx, project, "web", "restart", "operator"), 0, "ok")
		got, err := e.srv.pausedAfterRollback(ctx, gitstore.Config{Project: project, AutoDeploy: tc.auto})
		if err != nil || got != tc.want {
			t.Errorf("%s: paused = %v, %v; want %v", tc.name, got, err, tc.want)
		}
	}
}

// A rollback that failed changed nothing: it doesn't pause API deploys (auto-deploy was off already).
func TestAPIDeployNotPausedByAFailedRollback(t *testing.T) {
	a := newAPIDeployEnv(t)
	ctx := context.Background()
	sha := gitObjStoreFixture(t, a.e.srv.gitObjectDir("shop"), repoMooringYAML)
	configureRepo(t, a.e, "shop", sha) // auto-deploy off
	a.e.srv.recordDeployFinish(ctx, a.e.srv.recordRepoDeployStart(ctx, "shop", "rollback", "operator", "git_deploy"), 1, "error")
	tok, id := a.mint(t, "deploy:write:shop")

	resp, body := a.post(t, tok, "shop")
	if resp.StatusCode != http.StatusAccepted || body["status"] != "accepted" {
		t.Fatalf("deploy after a failed rollback = %d %v, want 202 accepted", resp.StatusCode, body)
	}
	waitGateFree(t, a.e.srv)
	rows := deployRowsFor(t, a.e.srv, "shop")
	if len(rows) != 2 || rows[1] != (deployRow{source: "api", actor: "api:" + id, outcome: "ok"}) {
		t.Fatalf("deploy records = %+v", rows)
	}
}

// A request that finds the app's API entry already queued takes it over: the waiting entry runs with the
// newest request's token and address, so revoking the first token doesn't drop the second, valid request.
func TestQueuedAPIDeployRunsWithTheNewestToken(t *testing.T) {
	a := newAPIDeployEnv(t)
	s := a.e.srv
	ctx := context.Background()
	sha := gitObjStoreFixture(t, s.gitObjectDir("shop"), repoMooringYAML)
	configureRepo(t, a.e, "shop", sha)
	tokA, idA := a.mint(t, "deploy:write:shop")
	tokB, idB := a.mint(t, "deploy:write:shop")

	if !s.gitDeploy.TryAcquire() {
		t.Fatal("pre-acquire")
	}
	if resp, body := a.post(t, tokA, "shop"); resp.StatusCode != http.StatusAccepted || body["status"] != "queued" {
		t.Fatalf("A while busy = %d %v, want 202 queued", resp.StatusCode, body)
	}
	resp := a.e.req(t, "POST", "/api/v1/apps/shop/deploy", "198.51.100.77:1", bearer(tokB), nil, nil)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("B while busy = %d, want 202", resp.StatusCode)
	}
	if got := s.deployQueue.keys(); len(got) != 1 || got[0] != "api:shop" {
		t.Fatalf("queue = %v, want one api:shop entry", got)
	}
	if err := a.tokens.Revoke(ctx, idA); err != nil {
		t.Fatal(err)
	}
	s.gitDeploy.Release()
	if !s.startPendingDeploy() {
		t.Fatal("the queued API deploy must start once the gate is free")
	}
	waitGateFree(t, s)

	rows := deployRowsFor(t, s, "shop")
	if len(rows) != 1 || rows[0] != (deployRow{source: "api", actor: "api:" + idB, outcome: "ok"}) {
		t.Fatalf("deploy records = %+v, want one ok deploy by api:%s", rows, idB)
	}
	ev := deployAudit(t, s)
	if last := ev[len(ev)-1]; last.Action != "git_deploy" || last.Actor != "api:"+idB || last.IP != "198.51.100.77" {
		t.Errorf("verdict audit = %+v, want actor api:%s from 198.51.100.77", last, idB)
	}
	if r := ev[1]; r.Action != "api_deploy" || r.Actor != "api:"+idB || !strings.Contains(r.Detail, "now runs with this token") {
		t.Errorf("B's request audit = %+v", r)
	}
}

// Deleting an app takes its deploy scope off every token: a token that only deployed the app is revoked,
// one with other scopes keeps them, and neither can deploy a new app connected later under the same name.
func TestAppDeleteRemovesTheDeployScopeFromTokens(t *testing.T) {
	a := newAPIDeployEnv(t)
	s := a.e.srv
	sha := gitObjStoreFixture(t, s.gitObjectDir("shop"), repoMooringYAML)
	configureRepo(t, a.e, "shop", sha)
	single, _ := a.mint(t, "deploy:write:shop")
	multi, multiID := a.mint(t, "status:read", "deploy:write:shop", "deploy:write:blog")
	_, blogID := a.mint(t, "deploy:write:blog")

	sess, csrf := a.e.authed(t)
	resp := a.e.req(t, "POST", "/apps/shop/delete", "127.0.0.1:1", map[string]string{"Origin": "https://example.com"},
		[]*http.Cookie{sess, csrf}, url.Values{"csrf_token": {csrf.Value}, "password": {testPassword}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("delete = %d, want 303", resp.StatusCode)
	}
	if _, ok, _ := s.gitStore.Get("shop"); ok {
		t.Fatal("the app was not deleted")
	}

	// A new app is connected under the same name.
	sha = gitObjStoreFixture(t, s.gitObjectDir("shop"), repoMooringYAML)
	configureRepo(t, a.e, "shop", sha)
	if resp, body := a.post(t, single, "shop"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("single-scope token after the delete = %d %v, want 401 (revoked)", resp.StatusCode, body)
	}
	if resp, body := a.post(t, multi, "shop"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("multi-scope token after the delete = %d %v, want 403 (scope removed)", resp.StatusCode, body)
	}
	if rows := deployRowsFor(t, s, "shop"); len(rows) != 0 {
		t.Errorf("the new app was deployed by an old token: %+v", rows)
	}
	if status := a.e.req(t, "GET", "/api/v1/status", apiPeer, bearer(multi), nil, nil); status.StatusCode != http.StatusOK {
		t.Errorf("the multi-scope token's other scopes = %d, want 200", status.StatusCode)
	}
	if rec, err := a.tokens.Get(context.Background(), multiID); err != nil || rec.Revoked || !rec.Allows("deploy:write:blog") {
		t.Errorf("multi-scope token after the delete: %+v %v", rec, err)
	}
	if rec, err := a.tokens.Get(context.Background(), blogID); err != nil || rec.Revoked || !rec.Allows("deploy:write:blog") {
		t.Errorf("another app's token was touched: %+v %v", rec, err)
	}
}

// Requests the API refuses before any git or docker work, each with its status and audit record.
func TestAPIDeployGuards(t *testing.T) {
	a := newAPIDeployEnv(t)
	ctx := context.Background()
	sha := gitObjStoreFixture(t, a.e.srv.gitObjectDir("shop"), repoMooringYAML)
	configureRepo(t, a.e, "shop", sha)
	// A protected project, even one configured as a git app.
	configureRepo(t, a.e, "infra", sha)
	a.e.srv.cfg.ProtectedProjects = append(a.e.srv.cfg.ProtectedProjects, "infra")
	// A PR preview of shop.
	if err := a.e.srv.gitStore.SetPreviewEnabled(ctx, "shop", true); err != nil {
		t.Fatal(err)
	}
	if err := a.e.srv.gitStore.RegisterPreview(ctx, "shop", "shop-pr7", "refs/pull/7/head"); err != nil {
		t.Fatal(err)
	}
	// A legacy provisioned app (not git).
	if err := a.e.srv.provStore.Save(ctx, provstore.App{Slug: "legacy", Source: "generated", SpecJSON: "{}"}); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		project string
		status  int
		errText string
		outcome audit.Outcome
	}{
		{"infra", http.StatusForbidden, "protected project", audit.Deny},
		{"ghost", http.StatusNotFound, "app not found", audit.Deny},
		{"shop-pr7", http.StatusConflict, "previews deploy from pull requests", audit.Deny},
		{"legacy", http.StatusConflict, "this app is not deployed from a git repository — deploy it from the dashboard", audit.Deny},
	} {
		tok, id := a.mint(t, "deploy:write:"+tc.project)
		resp, body := a.post(t, tok, tc.project)
		if resp.StatusCode != tc.status || body["error"] != tc.errText {
			t.Errorf("%s: %d %v, want %d %q", tc.project, resp.StatusCode, body, tc.status, tc.errText)
		}
		ev := deployAudit(t, a.e.srv)
		if last := ev[len(ev)-1]; last.Actor != "api:"+id || last.Outcome != string(tc.outcome) || last.Target != tc.project {
			t.Errorf("%s: audit = %+v", tc.project, last)
		}
	}
	if rows := deployRowsFor(t, a.e.srv, "shop"); len(rows) != 0 {
		t.Errorf("no guard may deploy: %+v", rows)
	}
	if calls := a.dockerCalls(); len(calls) != 0 {
		t.Errorf("docker was called: %v", calls)
	}
	waitGateFree(t, a.e.srv)

	// The write plane disabled at boot (too little RAM): 503 with the gate's reason.
	a.e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), false, "the write plane is disabled for this test")
	tok, _ := a.mint(t, "deploy:write:shop")
	resp, body := a.post(t, tok, "shop")
	if resp.StatusCode != http.StatusServiceUnavailable || body["error"] != "the write plane is disabled for this test" {
		t.Errorf("write plane disabled: %d %v, want 503", resp.StatusCode, body)
	}
}

// A token deploys only the app named in its scope; a session cookie is never accepted on the API.
func TestAPIDeployScopeAndCookie(t *testing.T) {
	a := newAPIDeployEnv(t)
	sha := gitObjStoreFixture(t, a.e.srv.gitObjectDir("other"), repoMooringYAML)
	configureRepo(t, a.e, "other", sha)
	tok, _ := a.mint(t, "deploy:write:shop", "status:read")

	if resp, _ := a.post(t, tok, "other"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("token for shop deploying other = %d, want 403", resp.StatusCode)
	}
	ok, _ := a.mint(t, "deploy:write:other")
	ck := &http.Cookie{Name: a.e.srv.cookieName(), Value: "anything"}
	resp := a.e.req(t, "POST", "/api/v1/apps/other/deploy", apiPeer, bearer(ok), []*http.Cookie{ck}, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("deploy with a session cookie = %d, want 401", resp.StatusCode)
	}
	if rows := deployRowsFor(t, a.e.srv, "other"); len(rows) != 0 {
		t.Errorf("refused requests must not deploy: %+v", rows)
	}
}

// A request that finds another git operation running is queued under api:<slug> — beside a waiting webhook
// entry for the same app, never absorbed by it — and runs the same deploy once the gate frees.
func TestAPIDeployQueuedWhenGateBusy(t *testing.T) {
	a := newAPIDeployEnv(t)
	s := a.e.srv
	sha := gitObjStoreFixture(t, s.gitObjectDir("shop"), repoMooringYAML)
	configureRepo(t, a.e, "shop", sha)
	tok, id := a.mint(t, "deploy:write:shop")
	s.deployQueue.add(pendingDeploy{key: appQueueKey("shop"), project: "shop", queued: time.Now()})

	if !s.gitDeploy.TryAcquire() {
		t.Fatal("pre-acquire")
	}
	for i := 0; i < 2; i++ {
		resp, body := a.post(t, tok, "shop")
		if resp.StatusCode != http.StatusAccepted || body["status"] != "queued" || body["commit"] != "" {
			t.Fatalf("deploy #%d while busy = %d %v, want 202 queued", i+1, resp.StatusCode, body)
		}
		if got := s.deployQueue.keys(); len(got) != 2 || got[0] != "app:shop" || got[1] != "api:shop" {
			t.Fatalf("queue after deploy #%d = %v, want [app:shop api:shop]", i+1, got)
		}
	}
	if rows := deployRowsFor(t, s, "shop"); len(rows) != 0 {
		t.Fatalf("nothing may deploy while the gate is held: %+v", rows)
	}
	// The webhook entry would fetch from a real remote; this test runs only the API entry.
	s.deployQueue.remove(appQueueKey("shop"))
	s.gitDeploy.Release()
	if !s.startPendingDeploy() {
		t.Fatal("the queued API deploy must start once the gate is free")
	}
	waitGateFree(t, s)
	rows := deployRowsFor(t, s, "shop")
	if len(rows) != 1 || rows[0] != (deployRow{source: "api", actor: "api:" + id, outcome: "ok"}) {
		t.Fatalf("deploy records = %+v, want one ok deploy by api:%s", rows, id)
	}
	ev := deployAudit(t, s)
	if last := ev[len(ev)-1]; last.Action != "git_deploy" || last.Actor != "api:"+id || last.IP != "198.51.100.5" || last.Outcome != string(audit.OK) {
		t.Errorf("verdict audit = %+v", last)
	}
}

// A queued request is decided when it runs, by the same rules as one that found the gate free.
func TestQueuedAPIDeployAppliesTheSameRules(t *testing.T) {
	a := newAPIDeployEnv(t)
	s := a.e.srv
	ctx := context.Background()
	sha := gitObjStoreFixture(t, s.gitObjectDir("shop"), repoMooringYAML)
	configureRepo(t, a.e, "shop", sha)
	_, id := a.mint(t, "deploy:write:shop")
	queued := pendingDeploy{key: apiQueueKey("shop"), project: "shop", source: queuedFromAPI, tokenID: id, ip: "198.51.100.5"}
	lastAudit := func() apiEvent {
		ev := deployAudit(t, s)
		if len(ev) == 0 {
			t.Fatal("no audit record")
		}
		return ev[len(ev)-1]
	}

	// Paused after a rollback.
	saveNote := func(note string) {
		d, err := definition.Parse([]byte(repoMooringYAML))
		if err != nil {
			t.Fatal(err)
		}
		d.Metadata.Slug = "shop"
		if _, err := s.defStore.SaveCanonical(ctx, d, note, ""); err != nil {
			t.Fatal(err)
		}
	}
	saveNote(noteRollback + "aaaaaaa")
	s.runQueuedAPIDeploy(ctx, queued)
	if r := lastAudit(); r.Outcome != string(audit.Deny) || r.Actor != "api:"+id || !strings.Contains(r.Detail, "paused after a rollback") {
		t.Errorf("paused: audit = %+v", r)
	}
	// Already deployed.
	s.gitStore.SetDeployed(ctx, "shop", sha)
	s.runQueuedAPIDeploy(ctx, queued)
	if r := lastAudit(); r.Outcome != string(audit.OK) || !strings.Contains(r.Detail, "already deployed") {
		t.Errorf("up to date: audit = %+v", r)
	}
	// The token was revoked while the request waited (the app has an update to deploy).
	s.gitStore.SetDeployed(ctx, "shop", "")
	saveNote(noteGitDeploy + "bbbbbbb")
	if err := a.tokens.Revoke(ctx, id); err != nil {
		t.Fatal(err)
	}
	s.runQueuedAPIDeploy(ctx, queued)
	if r := lastAudit(); r.Outcome != string(audit.Deny) || !strings.Contains(r.Detail, "revoked") {
		t.Errorf("revoked token: audit = %+v", r)
	}
	// The app was deleted while the request waited (with a live token).
	_, id2 := a.mint(t, "deploy:write:shop")
	queued.tokenID = id2
	if err := s.gitStore.Delete(ctx, "shop"); err != nil {
		t.Fatal(err)
	}
	s.runQueuedAPIDeploy(ctx, queued)
	if r := lastAudit(); r.Outcome != string(audit.Error) || r.Target != "shop" || !strings.Contains(r.Detail, "no longer a git app") {
		t.Errorf("deleted app: audit = %+v", r)
	}
	if rows := deployRowsFor(t, s, "shop"); len(rows) != 0 {
		t.Errorf("no deploy may have started, got %+v", rows)
	}
	if calls := a.dockerCalls(); len(calls) != 0 {
		t.Errorf("docker was called: %v", calls)
	}
}

// A failed fetch answers 502 with the classified reason (never raw git output) and frees the gate.
func TestAPIDeployFetchFailure(t *testing.T) {
	a := newAPIDeployEnv(t)
	configureRepo(t, a.e, "shop", "0123456789abcdef0123456789abcdef01234567") // nothing staged locally
	tok, _ := a.mint(t, "deploy:write:shop")
	resp, body := a.post(t, tok, "shop")
	if resp.StatusCode != http.StatusBadGateway || body["error"] != "git fetch failed: git: network error reaching the remote" {
		t.Fatalf("deploy = %d %v, want 502 with the classified reason", resp.StatusCode, body)
	}
	waitGateFree(t, a.e.srv)
}

// Each token may make apiDeployPerMinute deploy requests a minute; the next gets 429 with Retry-After.
// Other tokens are unaffected.
func TestAPIDeployRateLimitedPerToken(t *testing.T) {
	a := newAPIDeployEnv(t)
	tok, _ := a.mint(t, "deploy:write:ghost")
	for i := 0; i < apiDeployPerMinute; i++ {
		if resp, _ := a.post(t, tok, "ghost"); resp.StatusCode != http.StatusNotFound {
			t.Fatalf("request %d = %d, want 404", i+1, resp.StatusCode)
		}
	}
	resp, body := a.post(t, tok, "ghost")
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" || body["error"] == "" {
		t.Fatalf("request %d = %d (Retry-After %q) %v, want 429 with Retry-After", apiDeployPerMinute+1, resp.StatusCode, resp.Header.Get("Retry-After"), body)
	}
	other, _ := a.mint(t, "deploy:write:ghost")
	if resp, _ := a.post(t, other, "ghost"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("another token = %d, want 404 (its own limit)", resp.StatusCode)
	}
	ev := deployAudit(t, a.e.srv)
	if r := ev[apiDeployPerMinute]; r.Outcome != string(audit.Deny) || r.Detail != "rate limited" {
		t.Errorf("rate-limited audit = %+v", r)
	}
}
