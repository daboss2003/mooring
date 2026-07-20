package web

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/dockerexec"
	"github.com/daboss2003/mooring/internal/envstore"
	"github.com/daboss2003/mooring/internal/gitstore"
	"github.com/daboss2003/mooring/internal/secret"
)

// repoMooringYAML is a clean generated-stack definition committed into test repos —
// Mooring generates the compose from this (the repo never supplies a compose).
const repoMooringYAML = `apiVersion: mooring/v1
kind: App
metadata: {slug: app}
spec:
  compose:
    source: generated
    services:
      web:
        image: nginx:1.27
`

// gitObjStoreFixture builds a real git commit (with the given mooring.yaml) and
// clones it --bare into objDir, pointing refs/mooring/staged at it.
func gitObjStoreFixture(t *testing.T, objDir, mooringYAML string) string {
	return gitObjStoreFixtureFiles(t, objDir, map[string]string{"mooring.yaml": mooringYAML})
}

// gitObjStoreFixtureFiles commits an arbitrary file set, then clones it --bare into
// objDir — mimicking what a fetch would leave. The hardened Repo only READS this store.
func gitObjStoreFixtureFiles(t *testing.T, objDir string, files map[string]string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
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
	for name, content := range files {
		p := filepath.Join(work, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run(work, "add", "-A")
	run(work, "commit", "-q", "-m", "init")
	sha := run(work, "rev-parse", "HEAD")
	if err := os.MkdirAll(filepath.Dir(objDir), 0o700); err != nil {
		t.Fatal(err)
	}
	run(work, "clone", "--bare", "-q", work, objDir)
	run(work, "--git-dir="+objDir, "update-ref", "refs/mooring/staged", sha)
	return sha
}

func configureRepo(t *testing.T, e *testEnv, slug, sha string) gitstore.Config {
	t.Helper()
	ctx := context.Background()
	if err := e.srv.gitStore.Save(ctx, gitstore.SaveInput{
		Project: slug, RepoURL: "https://nonexistent.invalid/o/r.git",
		Ref: "refs/heads/main", ComposePath: "docker-compose.yml", BuildPolicy: "never",
	}); err != nil {
		t.Fatal(err)
	}
	e.srv.gitStore.SetFetchResult(ctx, slug, sha, 1, "update_available")
	cfg, ok, err := e.srv.gitStore.Get(slug)
	if err != nil || !ok {
		t.Fatalf("get repo cfg: %v ok=%v", err, ok)
	}
	return cfg
}

// The run dir (where app binds live) must be OUTSIDE DataDir so legitimate binds
// under it don't trip the "DataDir is protected" §5.6 defense-in-depth check; the
// object store must be INSIDE DataDir (protected — no app can bind it).
func TestGitRunDirOutsideDataDirObjectStoreInside(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	rd := e.srv.appRunDir("shop")
	od := e.srv.gitObjectDir("shop")
	if pathUnder(rd, e.srv.cfg.DataDir) {
		t.Errorf("run dir %q is under DataDir %q — binds under it would be wrongly rejected", rd, e.srv.cfg.DataDir)
	}
	if !pathUnder(od, e.srv.cfg.DataDir) {
		t.Errorf("object store %q must be under DataDir %q (protected)", od, e.srv.cfg.DataDir)
	}
}

// A deploy is sha-PINNED: if the staged ref moved since the operator reviewed it,
// the promote aborts (no surprise commit goes live).
func TestDeployRejectsMovedStagedSha(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	slug := "shop"
	sha := gitObjStoreFixture(t, e.srv.gitObjectDir(slug), repoMooringYAML)
	cfg := configureRepo(t, e, slug, sha)

	// Ask to deploy a DIFFERENT (well-formed) sha than the one staged.
	other := "0123456789abcdef0123456789abcdef01234567"
	err := e.srv.deployRepoApp(context.Background(), cfg, other, "manual", "operator", false, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "moved") {
		t.Fatalf("expected staged-moved rejection, got %v", err)
	}
}

// A ROLLBACK targets an OLDER commit that is deliberately not the staged one, so it must
// SKIP the staged-equality guard — but it still requires the commit object to resolve, so a
// pruned/bogus sha can never deploy. Contrast with TestDeployRejectsMovedStagedSha above.
func TestRollbackSkipsStagedGuardButRequiresCommit(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	slug := "shop"
	sha := gitObjStoreFixture(t, e.srv.gitObjectDir(slug), repoMooringYAML)
	cfg := configureRepo(t, e, slug, sha)

	// A well-formed sha that is NOT staged and does not exist in the object store.
	other := "0123456789abcdef0123456789abcdef01234567"

	// Normal deploy (rollback=false) of a non-staged sha: rejected by the staged-moved guard.
	if err := e.srv.deployRepoApp(context.Background(), cfg, other, "manual", "operator", false, func(string) {}); err == nil || !strings.Contains(err.Error(), "moved") {
		t.Fatalf("normal deploy of a non-staged sha must be rejected as moved, got %v", err)
	}
	// Rollback (rollback=true): skips the staged guard, so it fails LATER at commit resolution
	// (never with "moved").
	err := e.srv.deployRepoApp(context.Background(), cfg, other, "rollback", "operator", true, func(string) {})
	if err == nil || strings.Contains(err.Error(), "moved") {
		t.Fatalf("rollback must skip the staged guard (not reject as moved), got %v", err)
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("rollback of a non-existent commit should fail at commit resolution, got %v", err)
	}
}

// Mooring OWNS the compose: a repo's own docker-compose.yml is IGNORED — the deploy
// GENERATES the compose from mooring.yaml, so a dangerous repo compose never reaches
// docker. (Write plane disabled so `up` fails fast AFTER generation.)
func TestDeployIgnoresRepoComposeUsesMooringYAML(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), false, "disabled for test")
	slug := "shop"
	dangerous := "services:\n  web:\n    image: nginx\n    privileged: true\n"
	sha := gitObjStoreFixtureFiles(t, e.srv.gitObjectDir(slug), map[string]string{
		"mooring.yaml":       repoMooringYAML,
		"docker-compose.yml": dangerous,
	})
	cfg := configureRepo(t, e, slug, sha)

	err := e.srv.deployRepoApp(context.Background(), cfg, sha, "manual", "operator", false, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "up failed") {
		t.Fatalf("expected up to fail (write plane disabled) AFTER generation, got %v", err)
	}
	out, rerr := os.ReadFile(filepath.Join(e.srv.appRunDir(slug), "docker-compose.yml"))
	if rerr != nil {
		t.Fatalf("generated compose missing from run dir: %v", rerr)
	}
	if strings.Contains(string(out), "privileged") {
		t.Errorf("the repo's dangerous docker-compose.yml must be IGNORED (Mooring generates from mooring.yaml):\n%s", out)
	}
	if !strings.Contains(string(out), "nginx") {
		t.Errorf("generated compose should carry the mooring.yaml image:\n%s", out)
	}
}

// A valid sha-pinned promote with a clean compose runs steps 1–4 (sha-pin →
// §5.6 → archive-extract → materialize) and lands the pinned tree in the
// Mooring-owned run dir BEFORE `docker compose up`. We use a write-DISABLED
// runner so `up` fails fast (ErrWritePlaneDisabled) — no real docker is touched.
func TestDeployArchivesBeforeUp(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), false, "disabled for test")
	slug := "shop"
	sha := gitObjStoreFixture(t, e.srv.gitObjectDir(slug), repoMooringYAML)
	cfg := configureRepo(t, e, slug, sha)

	err := e.srv.deployRepoApp(context.Background(), cfg, sha, "manual", "operator", false, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "up failed") {
		t.Fatalf("expected up to fail (write plane disabled), got %v", err)
	}
	// The pinned tree must have been checked out AND the generated compose written
	// into the run dir before `up`.
	out, rerr := os.ReadFile(filepath.Join(e.srv.appRunDir(slug), "docker-compose.yml"))
	if rerr != nil || !strings.Contains(string(out), "image: nginx") {
		t.Errorf("generated compose not written into run dir: %v %q", rerr, out)
	}
}

// A build service in the repo's mooring.yaml: deploy GENERATES the Dockerfile into
// the run dir and the compose references it (build: + .mooring/Dockerfile.<svc>).
func TestDeployBuildServiceGeneratesDockerfile(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), false, "disabled for test")
	slug := "shop"
	yaml := "apiVersion: mooring/v1\nkind: App\nmetadata: {slug: app}\nspec:\n  compose:\n    source: generated\n    services:\n      api:\n        build: {language: go}\n"
	sha := gitObjStoreFixtureFiles(t, e.srv.gitObjectDir(slug), map[string]string{
		"mooring.yaml": yaml,
		"go.mod":       "module x\n\ngo 1.23\n",
		"main.go":      "package main\nfunc main(){}\n",
	})
	cfg := configureRepo(t, e, slug, sha)
	err := e.srv.deployRepoApp(context.Background(), cfg, sha, "manual", "operator", false, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "up failed") {
		t.Fatalf("expected up to fail (write disabled) after generation, got %v", err)
	}
	df, rerr := os.ReadFile(filepath.Join(e.srv.appRunDir(slug), ".mooring", "Dockerfile.api"))
	if rerr != nil || !strings.Contains(string(df), "golang:") {
		t.Errorf("generated Dockerfile missing/wrong: %v\n%s", rerr, df)
	}
	cmp, _ := os.ReadFile(filepath.Join(e.srv.appRunDir(slug), "docker-compose.yml"))
	if !strings.Contains(string(cmp), "build:") || !strings.Contains(string(cmp), ".mooring/Dockerfile.api") {
		t.Errorf("compose must reference the generated Dockerfile:\n%s", cmp)
	}
	// The build context must exclude .mooring/ so `COPY . .` can't bake secrets in.
	di, derr := os.ReadFile(filepath.Join(e.srv.appRunDir(slug), ".dockerignore"))
	if derr != nil || !strings.Contains(string(di), "\n.mooring\n") {
		t.Errorf("generated .dockerignore must exclude .mooring: %v\n%s", derr, di)
	}
}

// Multi-instance: when an app is connected to a VARIANT mooring file, the deploy
// reads THAT file (cfg.MooringFile), not the plain mooring.yaml. The repo here has
// both; the app points at mooring.prod.yaml, so the generated compose must carry the
// prod image (caddy), never the default's (nginx).
func TestDeployReadsConfiguredMooringVariant(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), false, "disabled for test")
	slug := "shop"
	prodYAML := "apiVersion: mooring/v1\nkind: App\nmetadata: {slug: app}\nspec:\n  compose:\n    source: generated\n    services:\n      web:\n        image: caddy:2\n"
	sha := gitObjStoreFixtureFiles(t, e.srv.gitObjectDir(slug), map[string]string{
		"mooring.yaml":      repoMooringYAML, // nginx:1.27 (the default — must be IGNORED)
		"mooring.prod.yaml": prodYAML,        // caddy:2   (this app's file)
	})
	if err := e.srv.gitStore.Save(context.Background(), gitstore.SaveInput{
		Project: slug, RepoURL: "https://nonexistent.invalid/o/r.git", Ref: "refs/heads/main",
		BuildPolicy: "never", MooringFile: "mooring.prod.yaml",
	}); err != nil {
		t.Fatal(err)
	}
	e.srv.gitStore.SetFetchResult(context.Background(), slug, sha, 1, "update_available")
	cfg, _, _ := e.srv.gitStore.Get(slug)

	_ = e.srv.deployRepoApp(context.Background(), cfg, sha, "manual", "operator", false, func(string) {})
	cmp, rerr := os.ReadFile(filepath.Join(e.srv.appRunDir(slug), "docker-compose.yml"))
	if rerr != nil {
		t.Fatalf("generated compose missing: %v", rerr)
	}
	if !strings.Contains(string(cmp), "caddy:2") {
		t.Errorf("compose must come from mooring.prod.yaml (caddy:2):\n%s", cmp)
	}
	if strings.Contains(string(cmp), "nginx") {
		t.Errorf("the default mooring.yaml (nginx) must be IGNORED when the app points at a variant:\n%s", cmp)
	}
}

// Fail-closed: an app connected to a NAMED variant whose file is missing at the commit
// must error — NOT silently scaffold a generic app and overwrite the operator's config.
func TestDeployMissingVariantFailsClosed(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), false, "disabled for test")
	slug := "shop"
	// The object store has ONLY mooring.yaml, but the app is connected to a variant.
	sha := gitObjStoreFixture(t, e.srv.gitObjectDir(slug), repoMooringYAML)
	if err := e.srv.gitStore.Save(context.Background(), gitstore.SaveInput{
		Project: slug, RepoURL: "https://nonexistent.invalid/o/r.git", Ref: "refs/heads/main",
		BuildPolicy: "never", MooringFile: "mooring.prod.yaml",
	}); err != nil {
		t.Fatal(err)
	}
	e.srv.gitStore.SetFetchResult(context.Background(), slug, sha, 1, "update_available")
	cfg, _, _ := e.srv.gitStore.Get(slug)

	err := e.srv.deployRepoApp(context.Background(), cfg, sha, "manual", "operator", false, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("expected a fail-closed 'missing' error for the absent variant, got %v", err)
	}
	if _, rerr := os.ReadFile(filepath.Join(e.srv.appRunDir(slug), "docker-compose.yml")); rerr == nil {
		t.Error("a missing variant must NOT scaffold a generic app (no compose should be generated)")
	}
}

// A repo's own .dockerignore is preserved; Mooring MERGES .mooring into it (it does
// not overwrite the operator's entries).
func TestDeployMergesRepoDockerignore(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), false, "disabled for test")
	slug := "shop"
	yaml := "apiVersion: mooring/v1\nkind: App\nmetadata: {slug: app}\nspec:\n" +
		"  compose:\n    source: generated\n    services:\n      api:\n        build: {language: go}\n"
	sha := gitObjStoreFixtureFiles(t, e.srv.gitObjectDir(slug), map[string]string{
		"mooring.yaml":  yaml,
		"go.mod":        "module x\n\ngo 1.23\n",
		"main.go":       "package main\nfunc main(){}\n",
		".dockerignore": "node_modules\n*.log\n", // the operator's own entries
	})
	cfg := configureRepo(t, e, slug, sha)
	_ = e.srv.deployRepoApp(context.Background(), cfg, sha, "manual", "operator", false, func(string) {})
	di, err := os.ReadFile(filepath.Join(e.srv.appRunDir(slug), ".dockerignore"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"node_modules", "*.log", "\n.mooring\n"} {
		if !strings.Contains(string(di), want) {
			t.Errorf("merged .dockerignore must keep the operator's entries AND add .mooring; missing %q:\n%s", want, di)
		}
	}
}

// The managed-file digest detects a config/secret/cert CONTENT change so the deploy
// can force-recreate only the affected service (compose alone wouldn't).
func TestManagedDigestChangeDetection(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	rd := t.TempDir()
	yaml := "apiVersion: mooring/v1\nkind: App\nmetadata: {slug: app}\nspec:\n" +
		"  compose: {source: generated, services: {api: {image: nginx:1, config_files: [{template: \"x\", mount: /etc/c}]}}}\n"
	def, err := definition.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	cfgP := filepath.Join(rd, ".mooring", "cfg", "api", "0")
	_ = os.MkdirAll(filepath.Dir(cfgP), 0o750)
	_ = os.WriteFile(cfgP, []byte("v1"), 0o640)

	d1 := e.srv.managedDigests(rd, def)
	if err := e.srv.writeDigestState(rd, d1); err != nil {
		t.Fatal(err)
	}
	// No change → nothing to recreate.
	if c := changedServices(readDigestState(rd), e.srv.managedDigests(rd, def)); len(c) != 0 {
		t.Errorf("no content change must yield no recreate, got %v", c)
	}
	// Content change → exactly the affected service.
	_ = os.WriteFile(cfgP, []byte("v2"), 0o640)
	c := changedServices(readDigestState(rd), e.srv.managedDigests(rd, def))
	if len(c) != 1 || c[0] != "api" {
		t.Errorf("a config content change must flag its service, got %v", c)
	}
}

// No mooring.yaml in the repo → Mooring scaffolds a default from the detected stack
// (go.mod → a go build service) and generates the Dockerfile.
func TestDeployScaffoldsWhenNoMooringYAML(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), false, "disabled for test")
	slug := "shop"
	sha := gitObjStoreFixtureFiles(t, e.srv.gitObjectDir(slug), map[string]string{
		"go.mod":  "module x\n\ngo 1.23\n",
		"main.go": "package main\nfunc main(){}\n",
	})
	cfg := configureRepo(t, e, slug, sha)
	err := e.srv.deployRepoApp(context.Background(), cfg, sha, "manual", "operator", false, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "up failed") {
		t.Fatalf("expected scaffold→generate→up-fail, got %v", err)
	}
	df, rerr := os.ReadFile(filepath.Join(e.srv.appRunDir(slug), ".mooring", "Dockerfile.app"))
	if rerr != nil || !strings.Contains(string(df), "golang:") {
		t.Errorf("scaffold should generate a go Dockerfile: %v\n%s", rerr, df)
	}
}

// A bind volume's source dir is pre-created (Mooring-owned) under the run dir before
// `up`, so Docker doesn't create a missing one as root.
func TestDeployCreatesBindDirs(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), false, "disabled for test")
	slug := "shop"
	yaml := "apiVersion: mooring/v1\nkind: App\nmetadata: {slug: app}\nspec:\n  compose:\n    source: generated\n    services:\n      web:\n        image: nginx:1.27\n        volumes:\n          - {source: appdata, target: /var/lib/app}\n"
	sha := gitObjStoreFixture(t, e.srv.gitObjectDir(slug), yaml)
	cfg := configureRepo(t, e, slug, sha)
	_ = e.srv.deployRepoApp(context.Background(), cfg, sha, "manual", "operator", false, func(string) {})
	info, err := os.Stat(filepath.Join(e.srv.appRunDir(slug), "appdata"))
	if err != nil || !info.IsDir() {
		t.Errorf("bind source dir not pre-created: %v", err)
	}
}

// materializeBindDirs must refuse a symlinked bind source (it could be swapped to
// escape the run dir) and create a normal source as a real directory.
func TestMaterializeBindDirsSymlinkSafe(t *testing.T) {
	rd := t.TempDir()
	outside := t.TempDir()
	// symlink pointing OUTSIDE rd → rejected (confinedUnder resolves it).
	if err := os.Symlink(outside, filepath.Join(rd, "evil")); err != nil {
		t.Fatal(err)
	}
	if err := materializeBindDirs(rd, []string{"evil"}); err == nil {
		t.Error("a bind source symlinked outside the run dir must be rejected")
	}
	// symlink pointing INSIDE rd → still rejected (a symlink bind source is refused).
	_ = os.MkdirAll(filepath.Join(rd, "real"), 0o750)
	if err := os.Symlink(filepath.Join(rd, "real"), filepath.Join(rd, "inlink")); err != nil {
		t.Fatal(err)
	}
	if err := materializeBindDirs(rd, []string{"inlink"}); err == nil {
		t.Error("a symlinked bind source must be rejected even when it points inside the run dir")
	}
	// a normal source is created as a real directory.
	if err := materializeBindDirs(rd, []string{"data"}); err != nil {
		t.Fatalf("a normal bind dir should be created: %v", err)
	}
	if fi, err := os.Lstat(filepath.Join(rd, "data")); err != nil || !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		t.Errorf("data must be created as a real directory: %v", err)
	}
}

// config_files (from the repo) and secret_files (from the store) are materialized into
// the run dir at the managed paths, and the generated compose carries their RO mounts.
func TestDeployMaterializesConfigAndSecretFiles(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), false, "disabled for test")
	slug := "shop"
	if _, err := e.srv.envStore.Save(context.Background(), slug,
		[]envstore.Entry{{Key: "jwt", Value: secret.New("SECRETVAL"), Secret: true}}, "op"); err != nil {
		t.Fatal(err)
	}
	yaml := "apiVersion: mooring/v1\nkind: App\nmetadata: {slug: app}\nspec:\n" +
		"  compose:\n    source: generated\n    services:\n      web:\n        image: nginx:1.27\n" +
		"        config_files:\n          - {repo: conf/app.conf, mount: /etc/app.conf}\n" +
		"        secret_files: [jwt]\n  secrets: [{name: jwt}]\n"
	sha := gitObjStoreFixtureFiles(t, e.srv.gitObjectDir(slug), map[string]string{
		"mooring.yaml":  yaml,
		"conf/app.conf": "marker-config\n",
	})
	cfg := configureRepo(t, e, slug, sha)
	err := e.srv.deployRepoApp(context.Background(), cfg, sha, "manual", "operator", false, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "up failed") {
		t.Fatalf("expected up to fail (write disabled) AFTER materialization, got %v", err)
	}
	rd := e.srv.appRunDir(slug)
	cf, rerr := os.ReadFile(filepath.Join(rd, ".mooring", "cfg", "web", "0"))
	if rerr != nil || string(cf) != "marker-config\n" {
		t.Errorf("config file not materialized: %v %q", rerr, cf)
	}
	sf := filepath.Join(rd, ".mooring", "secrets", "web", "jwt")
	sb, serr := os.ReadFile(sf)
	if serr != nil || string(sb) != "SECRETVAL" {
		t.Errorf("secret file not materialized: %v %q", serr, sb)
	}
	if fi, _ := os.Stat(sf); fi != nil && fi.Mode().Perm() != 0o644 {
		t.Errorf("secret file mode = %v, want 0644 (container-readable; confined by the 0700 run dir)", fi.Mode().Perm())
	}
	cmp, _ := os.ReadFile(filepath.Join(rd, "docker-compose.yml"))
	for _, want := range []string{"/etc/app.conf:ro", "/run/secrets/jwt:ro"} {
		if !strings.Contains(string(cmp), want) {
			t.Errorf("generated compose missing managed mount %q:\n%s", want, cmp)
		}
	}
}

// A config_file {{hm.KEY}} token resolves to a secret value at deploy; the rendered
// file is secret-bearing → 0600, and the token is gone.
func TestDeployRendersConfigFileTokens(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), false, "disabled for test")
	slug := "shop"
	if _, err := e.srv.envStore.Save(context.Background(), slug,
		[]envstore.Entry{{Key: "api_pw", Value: secret.New("S3CRET"), Secret: true}}, "op"); err != nil {
		t.Fatal(err)
	}
	yaml := `apiVersion: mooring/v1
kind: App
metadata: {slug: app}
spec:
  compose:
    source: generated
    services:
      emqx:
        image: emqx/emqx:5.8.3
        config_files:
          - template: "key = {{hm.API_KEY}}\n"
            mount: /etc/api.conf
            bindings: {API_KEY: {secret: api_pw}}
  secrets: [{name: api_pw}]
`
	sha := gitObjStoreFixture(t, e.srv.gitObjectDir(slug), yaml)
	cfg := configureRepo(t, e, slug, sha)
	err := e.srv.deployRepoApp(context.Background(), cfg, sha, "manual", "operator", false, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "up failed") {
		t.Fatalf("expected up to fail (write disabled) after rendering, got %v", err)
	}
	p := filepath.Join(e.srv.appRunDir(slug), ".mooring", "cfg", "emqx", "0")
	b, rerr := os.ReadFile(p)
	if rerr != nil || string(b) != "key = S3CRET\n" {
		t.Errorf("config token not rendered: %v %q", rerr, b)
	}
	if fi, _ := os.Stat(p); fi != nil && fi.Mode().Perm() != 0o644 {
		t.Errorf("secret-bearing config file mode = %v, want 0644 (container-readable; confined by the 0700 run dir)", fi.Mode().Perm())
	}
}

// cert_bindings: an issued edge cert is synced into the run dir (tls.crt 0644 /
// tls.key 0600) and the generated compose mounts it RO; a not-yet-issued cert blocks.
func TestDeploySyncsCertBinding(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), false, "disabled for test")
	slug := "shop"
	// a fake edge cert store with an issued leaf for mqtt.example.com
	caddyRoot := t.TempDir()
	leaf := filepath.Join(caddyRoot, "acme-v02.api.letsencrypt.org-directory", "mqtt.example.com")
	if err := os.MkdirAll(leaf, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(leaf, "mqtt.example.com.crt"), []byte("CERTPEM"), 0o600)
	_ = os.WriteFile(filepath.Join(leaf, "mqtt.example.com.key"), []byte("KEYPEM"), 0o600)
	e.srv.caddyCertRoot = caddyRoot
	yaml := "apiVersion: mooring/v1\nkind: App\nmetadata: {slug: app}\nspec:\n" +
		"  compose:\n    source: generated\n    services:\n      emqx:\n        image: emqx/emqx:5.8.3\n" +
		"        cert_bindings:\n          - {hostname: mqtt.example.com, mount: /etc/certs}\n"
	sha := gitObjStoreFixture(t, e.srv.gitObjectDir(slug), yaml)
	cfg := configureRepo(t, e, slug, sha)
	err := e.srv.deployRepoApp(context.Background(), cfg, sha, "manual", "operator", false, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "up failed") {
		t.Fatalf("expected up to fail (write disabled) AFTER cert sync, got %v", err)
	}
	rd := e.srv.appRunDir(slug)
	crt := filepath.Join(rd, ".mooring", "certs", "emqx", "mqtt.example.com", "tls.crt")
	if b, rerr := os.ReadFile(crt); rerr != nil || string(b) != "CERTPEM" {
		t.Errorf("cert not synced: %v %q", rerr, b)
	}
	keyP := filepath.Join(rd, ".mooring", "certs", "emqx", "mqtt.example.com", "tls.key")
	if fi, _ := os.Stat(keyP); fi == nil || fi.Mode().Perm() != 0o644 {
		t.Errorf("cert key must be 0644 (the cert-binding app reads it from the bind mount as a non-root user), got %v", fi)
	}
	// The cert dir is bind-mounted as a DIRECTORY, so it must be traversable (o+x) by
	// the container's non-root user — else it can't reach tls.crt/tls.key.
	if fi, _ := os.Stat(filepath.Dir(keyP)); fi == nil || fi.Mode().Perm()&0o001 == 0 {
		t.Errorf("cert dir must be traversable by others (o+x) for the dir bind mount, got %v", fi)
	}
	cmp, _ := os.ReadFile(filepath.Join(rd, "docker-compose.yml"))
	if !strings.Contains(string(cmp), "/etc/certs:ro") {
		t.Errorf("compose must mount the cert dir:\n%s", cmp)
	}
}

// A cert_binding whose cert the edge hasn't issued yet blocks the deploy (fail-closed):
// the deploy waits for ACME up to certIssueWaitTimeout, then blocks with an actionable
// timeout error rather than proceeding without the cert.
func TestDeployCertBindingBlocksUntilIssued(t *testing.T) {
	old := certIssueWaitTimeout
	certIssueWaitTimeout = 200 * time.Millisecond // don't wait the full 150s in the test
	t.Cleanup(func() { certIssueWaitTimeout = old })

	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), false, "disabled for test")
	e.srv.caddyCertRoot = t.TempDir() // empty — nothing issued
	slug := "shop"
	yaml := "apiVersion: mooring/v1\nkind: App\nmetadata: {slug: app}\nspec:\n" +
		"  compose:\n    source: generated\n    services:\n      emqx:\n        image: emqx/emqx:5.8.3\n" +
		"        cert_bindings:\n          - {hostname: mqtt.example.com, mount: /etc/certs}\n"
	sha := gitObjStoreFixture(t, e.srv.gitObjectDir(slug), yaml)
	cfg := configureRepo(t, e, slug, sha)
	err := e.srv.deployRepoApp(context.Background(), cfg, sha, "manual", "operator", false, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "did not issue the TLS cert") {
		t.Fatalf("a not-yet-issued cert_binding must block the deploy after the wait, got %v", err)
	}
}

// A deploy in progress must NOT be restartable: a second deploy request returns 409
// (the in-flight deploy runs in the background and the single-flight gate is held), so
// navigating away and re-triggering can't restart it from scratch.
func TestDeployInProgressReturns409(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), true, "") // writes allowed
	slug := "shop"
	yaml := "apiVersion: mooring/v1\nkind: App\nmetadata: {slug: app}\nspec:\n  compose:\n    source: generated\n    services:\n      web:\n        image: nginx\n"
	sha := gitObjStoreFixture(t, e.srv.gitObjectDir(slug), yaml)
	_ = configureRepo(t, e, slug, sha)
	sess, csrf := e.authed(t)
	// Simulate an in-progress background deploy holding the single-flight gate.
	if !e.srv.gitDeploy.TryAcquire() {
		t.Fatal("could not acquire the deploy gate")
	}
	defer e.srv.gitDeploy.Release()
	resp := e.req(t, "POST", "/apps/"+slug+"/git/deploy?sha="+sha, "127.0.0.1:1",
		map[string]string{"Origin": "https://example.com"},
		[]*http.Cookie{sess, csrf}, url.Values{"csrf_token": {csrf.Value}})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("deploy while one is in progress = %d, want 409 (must not restart)", resp.StatusCode)
	}
}

// A secret_files reference with no stored value blocks the deploy (fail-closed).
func TestDeploySecretFileWithoutValueBlocks(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), false, "disabled for test")
	slug := "shop"
	yaml := "apiVersion: mooring/v1\nkind: App\nmetadata: {slug: app}\nspec:\n" +
		"  compose:\n    source: generated\n    services:\n      web:\n        image: nginx:1.27\n" +
		"        secret_files: [jwt]\n  secrets: [{name: jwt}]\n"
	sha := gitObjStoreFixture(t, e.srv.gitObjectDir(slug), yaml)
	cfg := configureRepo(t, e, slug, sha)
	err := e.srv.deployRepoApp(context.Background(), cfg, sha, "manual", "operator", false, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "set it before deploying") {
		t.Fatalf("a secret_files ref with no value must block the deploy, got %v", err)
	}
}

// No mooring.yaml AND an undetectable stack → rejected with guidance (no deploy).
func TestDeployRejectsUndetectableRepoWithoutMooringYAML(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	slug := "shop"
	sha := gitObjStoreFixtureFiles(t, e.srv.gitObjectDir(slug), map[string]string{"README.md": "hi\n"})
	cfg := configureRepo(t, e, slug, sha)
	err := e.srv.deployRepoApp(context.Background(), cfg, sha, "manual", "operator", false, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "mooring.yaml") {
		t.Fatalf("an undetectable repo without mooring.yaml must be rejected with guidance, got %v", err)
	}
}

func TestVerifyWebhookSig(t *testing.T) {
	secret := []byte("super-secret-key")
	now := time.Now().Unix()
	ts := strconv.FormatInt(now, 10)
	nonce := "nonce-123"
	sign := func(s []byte, ts, nonce string) string {
		m := hmac.New(sha256.New, s)
		m.Write([]byte(ts + "." + nonce))
		return hex.EncodeToString(m.Sum(nil))
	}
	good := sign(secret, ts, nonce)

	if !verifyWebhookSig(secret, ts, nonce, good) {
		t.Error("valid signature rejected")
	}
	if verifyWebhookSig(secret, ts, nonce, "deadbeef") {
		t.Error("garbage signature accepted")
	}
	if verifyWebhookSig([]byte("wrong-key"), ts, nonce, good) {
		t.Error("signature accepted under the wrong key")
	}
	// Stale timestamp (outside the replay window).
	stale := strconv.FormatInt(now-3600, 10)
	if verifyWebhookSig(secret, stale, nonce, sign(secret, stale, nonce)) {
		t.Error("stale timestamp accepted")
	}
	// A small forward clock skew (within the allowance) is accepted.
	skewOK := strconv.FormatInt(now+int64(webhookForwardSkew/time.Second)-2, 10)
	if !verifyWebhookSig(secret, skewOK, nonce, sign(secret, skewOK, nonce)) {
		t.Error("timestamp within forward-skew allowance rejected")
	}
	// A far-future timestamp is rejected.
	future := strconv.FormatInt(now+3600, 10)
	if verifyWebhookSig(secret, future, nonce, sign(secret, future, nonce)) {
		t.Error("far-future timestamp accepted")
	}
	// Over-long nonce.
	long := strings.Repeat("x", maxWebhookNonceLen+1)
	if verifyWebhookSig(secret, ts, long, sign(secret, ts, long)) {
		t.Error("over-long nonce accepted")
	}
	// Missing fields.
	if verifyWebhookSig(secret, "", nonce, good) || verifyWebhookSig(secret, ts, "", good) || verifyWebhookSig(secret, ts, nonce, "") {
		t.Error("missing field accepted")
	}
}

func TestNonceCacheReplay(t *testing.T) {
	n := newNonceCache(time.Minute)
	if n.seenOrAdd("tok:a") {
		t.Error("first sighting reported as replay")
	}
	if !n.seenOrAdd("tok:a") {
		t.Error("second sighting not reported as replay")
	}
	if n.seenOrAdd("tok:b") {
		t.Error("distinct nonce reported as replay")
	}
}

// Webhook auth at the HTTP boundary: unknown token → 404; bad signature → 401; a
// valid signed call → 202; a replay of it → 409. To stay hermetic (no live `git
// fetch`), we hold the single-flight semaphore so the valid call takes the "busy"
// 202 path WITHOUT spawning the background fetch goroutine — the nonce is still
// recorded before TryAcquire, so the replay path is exercised identically.
func TestWebhookHTTPAuthAndReplay(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	ctx := context.Background()
	slug := "shop"
	if err := e.srv.gitStore.Save(ctx, gitstore.SaveInput{
		Project: slug, RepoURL: "https://github.com/o/r.git", Ref: "refs/heads/main",
		ComposePath: "docker-compose.yml", BuildPolicy: "never",
	}); err != nil {
		t.Fatal(err)
	}
	token, err := e.srv.gitStore.RotateWebhook(ctx, slug)
	if err != nil {
		t.Fatal(err)
	}
	_, secret, ok := e.srv.gitStore.WebhookLookup(token)
	if !ok {
		t.Fatal("webhook lookup failed")
	}

	// Use a NON-allowlisted peer (allowlist is 127.0.0.1/32): the webhook is
	// allowlist-exempt, so it must REACH the handler. A bad signature from this
	// peer returning 401 (not a bare allowlist 404) proves the exemption.
	const ciPeer = "8.8.8.8:5000"

	// Unknown token → 404 (handler-level, never reveals).
	if resp := e.req(t, "POST", "/webhook/not-a-real-token", ciPeer, nil, nil, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown token: status %d, want 404", resp.StatusCode)
	}
	// Known token, missing/bad signature → 401 (proves allowlist exemption).
	if resp := e.req(t, "POST", "/webhook/"+token, ciPeer, nil, nil, nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad signature from non-allowlisted peer: status %d, want 401", resp.StatusCode)
	}
	// A path that only LOOKS like a webhook (traversal) must NOT ride the
	// exemption: it cleans outside /webhook/, so the non-allowlisted peer is
	// denied at the allowlist (404), never reaching a non-webhook route.
	if resp := e.req(t, "GET", "/webhook/../events", ciPeer, nil, nil, nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("traversal via webhook exemption: status %d, want 404 (allowlist denied)", resp.StatusCode)
	}

	// Hold single-flight so the valid call cannot spawn a live fetch.
	if !e.srv.gitDeploy.TryAcquire() {
		t.Fatal("could not pre-acquire single-flight")
	}
	defer e.srv.gitDeploy.Release()

	// Valid signed call → 202 (busy: another git op is "in progress").
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := "abc-123"
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(ts + "." + nonce))
	sig := hex.EncodeToString(mac.Sum(nil))
	hdr := map[string]string{"X-Mooring-Timestamp": ts, "X-Mooring-Nonce": nonce, "X-Mooring-Signature": sig}
	if resp := e.req(t, "POST", "/webhook/"+token, ciPeer, hdr, nil, nil); resp.StatusCode != http.StatusAccepted {
		t.Errorf("valid webhook: status %d, want 202", resp.StatusCode)
	}

	// Replay the exact same signed call → 409 (nonce already used).
	if resp := e.req(t, "POST", "/webhook/"+token, ciPeer, hdr, nil, nil); resp.StatusCode != http.StatusConflict {
		t.Errorf("replayed webhook: status %d, want 409", resp.StatusCode)
	}
}

func TestTokenFlashSingleUseAndBound(t *testing.T) {
	f := newTokenFlash(time.Minute)
	h := f.put("shop", "secret-token")
	// Wrong project never resolves (and consumes the handle).
	if _, ok := f.take(h, "other"); ok {
		t.Error("flash resolved for the wrong project")
	}
	// And now the handle is gone (single-use, even on a mismatch).
	if _, ok := f.take(h, "shop"); ok {
		t.Error("handle survived a prior take")
	}

	// Correct project resolves exactly once.
	h2 := f.put("shop", "secret-token")
	tok, ok := f.take(h2, "shop")
	if !ok || tok != "secret-token" {
		t.Fatalf("flash take: ok=%v tok=%q", ok, tok)
	}
	if _, ok := f.take(h2, "shop"); ok {
		t.Error("flash resolved twice (must be single-use)")
	}
	// An unknown handle never resolves.
	if _, ok := f.take("nope", "shop"); ok {
		t.Error("unknown handle resolved")
	}
}

func TestIsFullSha40(t *testing.T) {
	if !isFullSha40("0123456789abcdef0123456789abcdef01234567") {
		t.Error("valid sha rejected")
	}
	for _, bad := range []string{"", "abc", "0123456789ABCDEF0123456789abcdef01234567", strings.Repeat("g", 40)} {
		if isFullSha40(bad) {
			t.Errorf("invalid sha %q accepted", bad)
		}
	}
}
