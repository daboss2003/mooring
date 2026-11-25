package web

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/crypto"
	"github.com/daboss2003/mooring/internal/dockerexec"
	"github.com/daboss2003/mooring/internal/envstore"
	"github.com/daboss2003/mooring/internal/gitstore"
	"github.com/daboss2003/mooring/internal/secret"
	"github.com/daboss2003/mooring/internal/siem"
)

// A correct password tears the app down completely: every per-app store row, the run
// dir, and the git object store (repo clone) are gone.
func TestAppDeleteFullTeardown(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	hdr := map[string]string{"Origin": "https://example.com"}
	ctx := context.Background()
	slug := "shop"

	// Seed state across several subsystems + on-disk trees.
	if err := e.srv.gitStore.Save(ctx, gitstore.SaveInput{Project: slug, RepoURL: "https://github.com/o/r.git", Ref: "refs/heads/main", BuildPolicy: "never"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.envStore.Save(ctx, slug, []envstore.Entry{{Key: "API_KEY", Value: secret.New("s3cr3t"), Secret: true}}, "op"); err != nil {
		t.Fatal(err)
	}
	runDir := e.srv.appRunDir(slug)
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(runDir, "docker-compose.yml"), []byte("services: {}\n"), 0o644)
	objDir := e.srv.gitObjectDir(slug)
	if err := os.MkdirAll(objDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// Wrong password → 403, nothing deleted.
	resp := e.req(t, "POST", "/apps/"+slug+"/delete", "127.0.0.1:1", hdr, cookies,
		url.Values{"csrf_token": {csrf.Value}, "password": {"not-the-password"}})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong password = %d, want 403", resp.StatusCode)
	}
	if _, ok, _ := e.srv.gitStore.Get(slug); !ok {
		t.Fatal("a wrong password must NOT delete the app")
	}

	// Correct password → 303 home, everything gone.
	resp = e.req(t, "POST", "/apps/"+slug+"/delete", "127.0.0.1:1", hdr, cookies,
		url.Values{"csrf_token": {csrf.Value}, "password": {testPassword}})
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/" {
		t.Fatalf("delete = %d loc=%q, want 303 /", resp.StatusCode, resp.Header.Get("Location"))
	}
	if _, ok, _ := e.srv.gitStore.Get(slug); ok {
		t.Error("git config not deleted")
	}
	if cur, _, _ := e.srv.envStore.Current(slug); len(cur) != 0 {
		t.Errorf("env/secrets not deleted: %d entries remain", len(cur))
	}
	if _, err := os.Stat(runDir); !os.IsNotExist(err) {
		t.Errorf("run dir not removed: %v", err)
	}
	if _, err := os.Stat(objDir); !os.IsNotExist(err) {
		t.Errorf("git object store (repo) not removed: %v", err)
	}
}

// Protected (Mooring-managed) projects can never be deleted.
func TestAppDeleteRejectsProtected(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.cfg.ProtectedProjects = append(e.srv.cfg.ProtectedProjects, "locked")
	sess, csrf := e.authed(t)
	resp := e.req(t, "POST", "/apps/locked/delete", "127.0.0.1:1", map[string]string{"Origin": "https://example.com"},
		[]*http.Cookie{sess, csrf}, url.Values{"csrf_token": {csrf.Value}, "password": {testPassword}})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("protected delete = %d, want 403", resp.StatusCode)
	}
}

// A delete for an unknown app is a 404 (after the password check passes).
func TestAppDeleteUnknownApp(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	resp := e.req(t, "POST", "/apps/ghost/delete", "127.0.0.1:1", map[string]string{"Origin": "https://example.com"},
		[]*http.Cookie{sess, csrf}, url.Values{"csrf_token": {csrf.Value}, "password": {testPassword}})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown app delete = %d, want 404", resp.StatusCode)
	}
}

// The teardown GATE: if the shared git/deploy lock is held (a deploy/fetch in flight)
// so the containers can't be stopped, the delete ABORTS — nothing is removed and the
// app stays intact (no orphaned containers/volumes, no false "deleted").
func TestAppDeleteGateAbortsWhenLockHeld(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), false, "test") // non-nil → gate runs
	ctx := context.Background()
	slug := "shop"
	if err := e.srv.gitStore.Save(ctx, gitstore.SaveInput{Project: slug, RepoURL: "https://github.com/o/r.git", Ref: "refs/heads/main", BuildPolicy: "never"}); err != nil {
		t.Fatal(err)
	}
	// Hold the global git/deploy slot so the teardown can't acquire it.
	if err := e.srv.gitDeploy.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	defer e.srv.gitDeploy.Release()

	bounded, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
	defer cancel()
	gateErr, errs := e.srv.teardownApp(bounded, slug)
	if gateErr == nil {
		t.Fatal("expected a gate abort while the lock is held")
	}
	if len(errs) != 0 {
		t.Errorf("a gate abort must not run any destructive step, got errs=%v", errs)
	}
	if _, ok, _ := e.srv.gitStore.Get(slug); !ok {
		t.Error("the app must remain intact when the teardown gate aborts")
	}
}

// incMuteFake is the incident service with the engine's DeleteAppMutes.
type incMuteFake struct {
	*incFake
	delMu sync.Mutex
	slugs []string
	err   error
}

func (f *incMuteFake) DeleteAppMutes(_ context.Context, slug string) error {
	f.delMu.Lock()
	defer f.delMu.Unlock()
	f.slugs = append(f.slugs, slug)
	return f.err
}

func (f *incMuteFake) calledFor() []string {
	f.delMu.Lock()
	defer f.delMu.Unlock()
	return slices.Clone(f.slugs)
}

// The teardown removes the app's false-positive mutes when the incident service can (the engine); a
// failure is a teardown error like any other store's. Its incidents and detections are kept.
func TestAppDeleteRemovesAppMutes(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	ctx := context.Background()
	const slug = "shop"
	seed := func() {
		t.Helper()
		if err := e.srv.gitStore.Save(ctx, gitstore.SaveInput{Project: slug, RepoURL: "https://github.com/o/r.git", Ref: "refs/heads/main", BuildPolicy: "never"}); err != nil {
			t.Fatal(err)
		}
	}
	f := &incMuteFake{incFake: &incFake{}}
	e.srv.incidentSvc = f
	seed()
	if gateErr, errs := e.srv.teardownApp(ctx, slug); gateErr != nil || len(errs) != 0 {
		t.Fatalf("teardown = %v, %v", gateErr, errs)
	}
	if got := f.calledFor(); !slices.Equal(got, []string{slug}) {
		t.Errorf("DeleteAppMutes calls = %q, want [%s]", got, slug)
	}
	if f.calls() != 0 {
		t.Error("the teardown changed or read incidents")
	}

	// A failure is reported with the other teardown errors, and in the delete's audit row.
	f.delMu.Lock()
	f.err = errors.New("security_mutes locked")
	f.delMu.Unlock()
	seed()
	_, errs := e.srv.teardownApp(ctx, slug)
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "security mutes: security_mutes locked") {
		t.Errorf("teardown errors = %v, want the mutes failure", errs)
	}
	seed()
	sess, csrf := e.authed(t)
	resp := e.req(t, "POST", "/apps/"+slug+"/delete", "127.0.0.1:1", map[string]string{"Origin": "https://example.com"},
		[]*http.Cookie{sess, csrf}, url.Values{"csrf_token": {csrf.Value}, "password": {testPassword}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("delete = %d, want 303", resp.StatusCode)
	}
	rows := secAuditRows(t, e, "app_delete")
	if len(rows) == 0 || rows[len(rows)-1].Outcome != "error" || !strings.Contains(rows[len(rows)-1].Detail, "security mutes") {
		t.Errorf("app_delete audit = %+v, want the mutes failure", rows)
	}

	// A service without the method, or none: nothing to call, no error.
	for _, svc := range []siem.IncidentService{&incFake{}, nil} {
		e.srv.incidentSvc = svc
		seed()
		if gateErr, errs := e.srv.teardownApp(ctx, slug); gateErr != nil || len(errs) != 0 {
			t.Errorf("teardown with %T = %v, %v", svc, gateErr, errs)
		}
	}
}

// baselineDeleter is the engine's DeleteAppBaselines, to embed in an incident service fake.
type baselineDeleter struct {
	mu    sync.Mutex
	slugs []string
	err   error
}

func (b *baselineDeleter) DeleteAppBaselines(_ context.Context, slug string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.slugs = append(b.slugs, slug)
	return b.err
}

func (b *baselineDeleter) calledFor() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return slices.Clone(b.slugs)
}

// The teardown clears the app's sign-in baselines when the incident service can (the engine),
// with or without DeleteAppMutes; a failure is a teardown error like any other store's.
func TestAppDeleteRemovesAppBaselines(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	ctx := context.Background()
	const slug = "shop"
	seed := func() {
		t.Helper()
		if err := e.srv.gitStore.Save(ctx, gitstore.SaveInput{Project: slug, RepoURL: "https://github.com/o/r.git", Ref: "refs/heads/main", BuildPolicy: "never"}); err != nil {
			t.Fatal(err)
		}
	}
	mutes, bl := &incMuteFake{incFake: &incFake{}}, &baselineDeleter{}
	e.srv.incidentSvc = struct {
		*incMuteFake
		*baselineDeleter
	}{mutes, bl}
	seed()
	if gateErr, errs := e.srv.teardownApp(ctx, slug); gateErr != nil || len(errs) != 0 {
		t.Fatalf("teardown = %v, %v", gateErr, errs)
	}
	if got := bl.calledFor(); !slices.Equal(got, []string{slug}) {
		t.Errorf("DeleteAppBaselines calls = %q, want [%s]", got, slug)
	}
	if got := mutes.calledFor(); !slices.Equal(got, []string{slug}) {
		t.Errorf("DeleteAppMutes calls = %q, want [%s]", got, slug)
	}

	// A failure is reported with the other teardown errors, and in the delete's audit row.
	bl.mu.Lock()
	bl.err = errors.New("baselines table locked")
	bl.mu.Unlock()
	seed()
	_, errs := e.srv.teardownApp(ctx, slug)
	if len(errs) != 1 || !strings.Contains(errs[0].Error(), "security baselines: baselines table locked") {
		t.Errorf("teardown errors = %v, want the baselines failure", errs)
	}
	seed()
	sess, csrf := e.authed(t)
	resp := e.req(t, "POST", "/apps/"+slug+"/delete", "127.0.0.1:1", map[string]string{"Origin": "https://example.com"},
		[]*http.Cookie{sess, csrf}, url.Values{"csrf_token": {csrf.Value}, "password": {testPassword}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("delete = %d, want 303", resp.StatusCode)
	}
	rows := secAuditRows(t, e, "app_delete")
	if len(rows) == 0 || rows[len(rows)-1].Outcome != "error" || !strings.Contains(rows[len(rows)-1].Detail, "security baselines") {
		t.Errorf("app_delete audit = %+v, want the baselines failure", rows)
	}

	// A service with DeleteAppBaselines only.
	only := &baselineDeleter{}
	e.srv.incidentSvc = struct {
		*incFake
		*baselineDeleter
	}{&incFake{}, only}
	seed()
	if gateErr, errs := e.srv.teardownApp(ctx, slug); gateErr != nil || len(errs) != 0 || !slices.Equal(only.calledFor(), []string{slug}) {
		t.Errorf("baselines only: teardown %v, %v, calls %q", gateErr, errs, only.calledFor())
	}
}

// With 2FA enabled, deleting requires a TOTP code too: a correct password but no code
// is rejected and the app survives.
func TestAppDeleteRequiresTOTPWhenEnabled(t *testing.T) {
	secret, _ := crypto.GenerateTOTPSecret()
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, secret)
	peer := "127.0.0.1:1"
	get := e.req(t, "GET", "/login", peer, nil, nil, nil)
	csrf := cookieByName(get, e.srv.csrfCookieName())
	code, err := crypto.GenerateTOTPCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	post := e.req(t, "POST", "/login", peer, map[string]string{"Origin": "https://example.com"}, []*http.Cookie{csrf},
		url.Values{"username": {"operator"}, "password": {testPassword}, "totp": {code}, "csrf_token": {csrf.Value}})
	sess := cookieByName(post, e.srv.cookieName())
	if sess == nil {
		t.Fatal("login with TOTP failed")
	}
	if err := e.srv.gitStore.Save(context.Background(), gitstore.SaveInput{Project: "shop", RepoURL: "https://github.com/o/r.git", Ref: "refs/heads/main", BuildPolicy: "never"}); err != nil {
		t.Fatal(err)
	}
	// Password correct, but no TOTP code → rejected, app intact.
	resp := e.req(t, "POST", "/apps/shop/delete", peer, map[string]string{"Origin": "https://example.com"},
		[]*http.Cookie{sess, csrf}, url.Values{"csrf_token": {csrf.Value}, "password": {testPassword}})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("delete without TOTP = %d, want 403", resp.StatusCode)
	}
	if _, ok, _ := e.srv.gitStore.Get("shop"); !ok {
		t.Error("app must survive a delete that lacked the required TOTP code")
	}
}

// patternDeleter is the engine's DeleteAppPatterns beside a pattern service fake.
type patternDeleter struct {
	*incFake
	mu    sync.Mutex
	slugs []string
	err   error
}

func (p *patternDeleter) DeleteAppPatterns(_ context.Context, slug string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.slugs = append(p.slugs, slug)
	return p.err
}

// The teardown forgets the app's log patterns when the incident service can (the engine), also
// with patterns switched off; a failure is a teardown error; without the engine nothing is called.
func TestAppDeleteRemovesAppPatterns(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	ctx := context.Background()
	const slug = "shop"
	seed := func() {
		t.Helper()
		if err := e.srv.gitStore.Save(ctx, gitstore.SaveInput{Project: slug, RepoURL: "https://github.com/o/r.git", Ref: "refs/heads/main", BuildPolicy: "never"}); err != nil {
			t.Fatal(err)
		}
	}
	seed()
	if gateErr, errs := e.srv.teardownApp(ctx, slug); gateErr != nil || len(errs) != 0 {
		t.Fatalf("no engine: teardown = %v, %v", gateErr, errs)
	}
	// Patterns switched off (no pattern service): the engine is still asked.
	pd := &patternDeleter{incFake: &incFake{}}
	e.srv.incidentSvc, e.srv.patterns = pd, nil
	seed()
	if gateErr, errs := e.srv.teardownApp(ctx, slug); gateErr != nil || len(errs) != 0 || !slices.Equal(pd.slugs, []string{slug}) {
		t.Fatalf("teardown = %v, %v; DeleteAppPatterns calls %q", gateErr, errs, pd.slugs)
	}
	pd.err = errors.New("patterns table locked")
	seed()
	if _, errs := e.srv.teardownApp(ctx, slug); len(errs) != 1 || !strings.Contains(errs[0].Error(), "security log patterns: patterns table locked") {
		t.Errorf("teardown errors = %v, want the patterns failure", errs)
	}
}
