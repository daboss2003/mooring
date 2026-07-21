package gitstore

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/secret"
	"github.com/daboss2003/mooring/internal/store"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	cipher, err := secret.NewCipher(make([]byte, 32), nil)
	if err != nil {
		t.Fatal(err)
	}
	return New(db, cipher)
}

func TestSaveGetRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	tok := "ghp_exampletoken"
	if err := s.Save(ctx, SaveInput{
		Project: "shop", RepoURL: "https://github.com/o/r.git", Ref: "refs/heads/main",
		ComposePath: "docker-compose.yml", BuildPolicy: "never", AutoDeploy: true,
		NewCred: &tok, CredKind: "token",
	}); err != nil {
		t.Fatal(err)
	}
	cfg, ok, err := s.Get("shop")
	if err != nil || !ok {
		t.Fatalf("get: %v ok=%v", err, ok)
	}
	if cfg.RepoURL != "https://github.com/o/r.git" || cfg.Ref != "refs/heads/main" || !cfg.AutoDeploy || cfg.CredKind != "token" {
		t.Errorf("round-trip mismatch: %+v", cfg)
	}
	// Credentials decrypt back to the original token.
	creds, err := s.Creds("shop")
	if err != nil {
		t.Fatal(err)
	}
	if creds.Token != tok {
		t.Errorf("token = %q, want %q", creds.Token, tok)
	}
}

// MooringFile drives WHICH file in a multi-file repo is this app's definition. It
// round-trips, defaults to mooring.yaml on a fresh insert, and an empty value on a
// later Save KEEPS the stored one (the basic edit form never round-trips it).
func TestMooringFileRoundTripAndKeep(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	// Fresh insert with no file → default mooring.yaml.
	if err := s.Save(ctx, SaveInput{Project: "plain", RepoURL: "https://github.com/o/r.git", Ref: "refs/heads/main", BuildPolicy: "never"}); err != nil {
		t.Fatal(err)
	}
	if c, _, _ := s.Get("plain"); c.MooringFile != "mooring.yaml" {
		t.Errorf("default mooring file = %q, want mooring.yaml", c.MooringFile)
	}

	// Insert with a variant.
	if err := s.Save(ctx, SaveInput{Project: "stg", RepoURL: "https://github.com/o/r.git", Ref: "refs/heads/main", BuildPolicy: "never", MooringFile: "mooring.staging.yaml"}); err != nil {
		t.Fatal(err)
	}
	if c, _, _ := s.Get("stg"); c.MooringFile != "mooring.staging.yaml" {
		t.Fatalf("mooring file = %q, want mooring.staging.yaml", c.MooringFile)
	}
	// A later edit that omits the file must KEEP the stored variant.
	if err := s.Save(ctx, SaveInput{Project: "stg", RepoURL: "https://github.com/o/r2.git", Ref: "refs/heads/main", BuildPolicy: "never"}); err != nil {
		t.Fatal(err)
	}
	if c, _, _ := s.Get("stg"); c.MooringFile != "mooring.staging.yaml" {
		t.Errorf("after edit mooring file = %q, want it KEPT as mooring.staging.yaml", c.MooringFile)
	}

	// A bogus file is rejected.
	if err := s.Save(ctx, SaveInput{Project: "bad", RepoURL: "https://github.com/o/r.git", Ref: "refs/heads/main", BuildPolicy: "never", MooringFile: "../etc/passwd"}); err == nil {
		t.Error("expected rejection of a traversal mooring file path")
	}
}

func TestValidMooringFile(t *testing.T) {
	good := []string{"mooring.yaml", "mooring.yml", "mooring.staging.yaml", "mooring.prod.yml", "mooring.us-east-1.yaml"}
	bad := []string{"", "Mooring.yaml", "mooring.YAML", "compose.yaml", "dir/mooring.yaml", "../mooring.yaml", "mooring.yaml.bak", "mooring..yaml", "mooring.staging.json"}
	for _, g := range good {
		if !ValidMooringFile(g) {
			t.Errorf("ValidMooringFile(%q) = false, want true", g)
		}
	}
	for _, b := range bad {
		if ValidMooringFile(b) {
			t.Errorf("ValidMooringFile(%q) = true, want false", b)
		}
	}
}

// Regression: List() must not deadlock. The DB pool is a single connection
// (store.SetMaxOpenConns(1)); the old List() held the rows open while calling Get()
// (a nested query), self-deadlocking and stranding the connection — which froze every
// request (the "loading forever, can't navigate anywhere" hang after a fetch). With
// two+ rows on the single conn, the buggy version blocks forever; we bound it so the
// test fails fast instead of hanging CI.
func TestListNoNestedQueryDeadlock(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	for _, p := range []string{"alpha", "bravo", "charlie"} {
		if err := s.Save(ctx, SaveInput{Project: p, RepoURL: "https://github.com/o/" + p + ".git", Ref: "refs/heads/main", BuildPolicy: "never"}); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan []Config, 1)
	go func() {
		cfgs, err := s.List()
		if err != nil {
			t.Errorf("List: %v", err)
		}
		done <- cfgs
	}()
	select {
	case cfgs := <-done:
		if len(cfgs) != 3 {
			t.Fatalf("List returned %d configs, want 3", len(cfgs))
		}
		if cfgs[0].Project != "alpha" || cfgs[2].Project != "charlie" {
			t.Errorf("List order/contents wrong: %+v", cfgs)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("List() deadlocked — a nested query while its rows are open strands the single DB connection")
	}
}

func TestCredTriStateKeepAndClear(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	tok := "tok-1"
	must := func(err error) {
		if err != nil {
			t.Helper()
			t.Fatal(err)
		}
	}
	must(s.Save(ctx, SaveInput{Project: "app", RepoURL: "https://x.example/o/r.git", Ref: "refs/heads/main", BuildPolicy: "never", NewCred: &tok, CredKind: "token"}))

	// Edit with NewCred nil → keep the stored token.
	must(s.Save(ctx, SaveInput{Project: "app", RepoURL: "https://x.example/o/r2.git", Ref: "refs/heads/main", BuildPolicy: "never", NewCred: nil}))
	creds, _ := s.Creds("app")
	if creds.Token != tok {
		t.Errorf("keep: token = %q, want %q", creds.Token, tok)
	}
	cfg, _, _ := s.Get("app")
	if cfg.CredKind != "token" {
		t.Errorf("keep: cred_kind = %q, want token", cfg.CredKind)
	}

	// Clear with NewCred "" → no credential.
	empty := ""
	must(s.Save(ctx, SaveInput{Project: "app", RepoURL: "https://x.example/o/r2.git", Ref: "refs/heads/main", BuildPolicy: "never", NewCred: &empty}))
	creds, _ = s.Creds("app")
	if creds.Token != "" {
		t.Errorf("clear: token = %q, want empty", creds.Token)
	}
}

func TestSaveRejectsUnsafeURLAndSlug(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.Save(ctx, SaveInput{Project: "ok", RepoURL: "https://127.0.0.1/o/r.git", Ref: "refs/heads/main", BuildPolicy: "never"}); err == nil {
		t.Error("loopback repo URL accepted")
	}
	if err := s.Save(ctx, SaveInput{Project: "Bad Slug!", RepoURL: "https://github.com/o/r.git", Ref: "refs/heads/main", BuildPolicy: "never"}); err == nil {
		t.Error("invalid slug accepted")
	}
	if err := s.Save(ctx, SaveInput{Project: "ok", RepoURL: "https://github.com/o/r.git", Ref: "main", BuildPolicy: "never"}); err == nil {
		t.Error("non-fully-qualified ref accepted")
	}
}

func TestWebhookRotateLookup(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.Save(ctx, SaveInput{Project: "shop", RepoURL: "https://github.com/o/r.git", Ref: "refs/heads/main", BuildPolicy: "never"}); err != nil {
		t.Fatal(err)
	}
	token, err := s.RotateWebhook(ctx, "shop")
	if err != nil || token == "" {
		t.Fatalf("rotate: %v token=%q", err, token)
	}
	project, hmacSecret, ok := s.WebhookLookup(token)
	if !ok || project != "shop" || len(hmacSecret) == 0 {
		t.Fatalf("lookup: ok=%v project=%q secretlen=%d", ok, project, len(hmacSecret))
	}
	// An unknown token never resolves.
	if _, _, ok := s.WebhookLookup("bogus-token"); ok {
		t.Error("bogus token resolved")
	}
	// Rotation invalidates the old token.
	token2, _ := s.RotateWebhook(ctx, "shop")
	if token2 == token {
		t.Error("rotation produced the same token")
	}
	if _, _, ok := s.WebhookLookup(token); ok {
		t.Error("old token still resolves after rotation")
	}
	if _, _, ok := s.WebhookLookup(token2); !ok {
		t.Error("new token does not resolve")
	}
}

func TestFSMTransitions(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.Save(ctx, SaveInput{Project: "shop", RepoURL: "https://github.com/o/r.git", Ref: "refs/heads/main", BuildPolicy: "never"}); err != nil {
		t.Fatal(err)
	}
	sha := "0123456789abcdef0123456789abcdef01234567"
	s.SetFetchResult(ctx, "shop", sha, 3, "update_available")
	cfg, _, _ := s.Get("shop")
	if cfg.StagedCommit != sha || cfg.CommitsBehind != 3 || cfg.UpdateState != "update_available" {
		t.Errorf("after fetch: %+v", cfg)
	}
	s.SetDeployed(ctx, "shop", sha)
	cfg, _, _ = s.Get("shop")
	if cfg.DeployedCommit != sha || cfg.UpdateState != "up_to_date" || cfg.CommitsBehind != 0 {
		t.Errorf("after deploy: %+v", cfg)
	}
	// An invalid state is ignored (fail-safe).
	s.SetState(ctx, "shop", "garbage")
	cfg, _, _ = s.Get("shop")
	if cfg.UpdateState != "up_to_date" {
		t.Errorf("invalid state applied: %q", cfg.UpdateState)
	}
}

// RegisterPreview is fail-closed + scoped: it needs the base to exist with previews enabled,
// sets preview_of, and NEVER clobbers a real app or a preview of a different base.
func TestRegisterPreviewScoping(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	// Base app, previews OFF.
	if err := s.Save(ctx, SaveInput{Project: "shop", RepoURL: "https://github.com/o/shop.git", Ref: "refs/heads/main", BuildPolicy: "never"}); err != nil {
		t.Fatal(err)
	}
	// Refused: previews not enabled on the base.
	if err := s.RegisterPreview(ctx, "shop", "shop-pr1", "refs/pull/1/head"); err == nil {
		t.Fatal("RegisterPreview must refuse when the base has previews disabled")
	}
	// Enable previews, then it works and sets preview_of.
	if err := s.SetPreviewEnabled(ctx, "shop", true); err != nil {
		t.Fatal(err)
	}
	if err := s.RegisterPreview(ctx, "shop", "shop-pr1", "refs/pull/1/head"); err != nil {
		t.Fatalf("RegisterPreview: %v", err)
	}
	cfg, ok, _ := s.Get("shop-pr1")
	if !ok || cfg.PreviewOf != "shop" || cfg.Ref != "refs/pull/1/head" || cfg.RepoURL != "https://github.com/o/shop.git" {
		t.Fatalf("preview app wrong: %+v", cfg)
	}
	// A second base must NOT be able to hijack an existing preview slug of "shop".
	if err := s.Save(ctx, SaveInput{Project: "evil", RepoURL: "https://github.com/x/evil.git", Ref: "refs/heads/main", BuildPolicy: "never"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPreviewEnabled(ctx, "evil", true); err != nil {
		t.Fatal(err)
	}
	if err := s.RegisterPreview(ctx, "evil", "shop-pr1", "refs/pull/9/head"); err == nil {
		t.Fatal("RegisterPreview must refuse a slug already owned by a preview of a DIFFERENT base")
	}
	// And it must never clobber a REAL (non-preview) app.
	if err := s.RegisterPreview(ctx, "shop", "evil", "refs/pull/1/head"); err == nil {
		t.Fatal("RegisterPreview must refuse to overwrite a non-preview app")
	}
}

func TestStalePreviews(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.Save(ctx, SaveInput{Project: "shop", RepoURL: "https://github.com/o/shop.git", Ref: "refs/heads/main", BuildPolicy: "never"}); err != nil {
		t.Fatal(err)
	}
	_ = s.SetPreviewEnabled(ctx, "shop", true)
	_ = s.RegisterPreview(ctx, "shop", "shop-pr1", "refs/pull/1/head")
	// Not stale yet (updated_at is ~now).
	if stale, _ := s.StalePreviews(time.Now().Add(-time.Hour).Unix()); len(stale) != 0 {
		t.Fatalf("nothing should be stale yet, got %v", stale)
	}
	// Stale against a future cutoff.
	if stale, _ := s.StalePreviews(time.Now().Add(time.Hour).Unix()); len(stale) != 1 || stale[0] != "shop-pr1" {
		t.Fatalf("shop-pr1 should be stale, got %v", stale)
	}
	// A non-preview app is never returned.
	if stale, _ := s.StalePreviews(time.Now().Add(time.Hour).Unix()); len(stale) == 1 && stale[0] == "shop" {
		t.Fatal("a non-preview app must not be reaped")
	}
}
