package web

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/definition"
	"github.com/daboss2003/mooring/internal/dockerexec"
	"github.com/daboss2003/mooring/internal/envstore"
	"github.com/daboss2003/mooring/internal/gitstore"
	"github.com/daboss2003/mooring/internal/secret"
)

// envRefDef is a mooring.yaml whose web service references DB_PASSWORD from env.
func envRefDef(extraEnv string) string {
	return "apiVersion: mooring/v1\nkind: App\nmetadata: {slug: app}\nspec:\n" +
		"  secrets: [{name: DB_PASSWORD}, {name: SENTRY_DSN}]\n" +
		"  compose:\n    source: generated\n    services:\n      web:\n        image: nginx:1.27\n" +
		"        env:\n          DB_PASSWORD: {secret: DB_PASSWORD}\n" + extraEnv
}

// A normal deploy with an env {secret: NAME} that has no stored value fails, naming the service,
// the env key and the secret — before the run dir is touched.
func TestDeployFailsOnMissingEnvSecret(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), false, "disabled for test")
	slug := "shop"
	sha := gitObjStoreFixture(t, e.srv.gitObjectDir(slug), envRefDef(""))
	cfg := configureRepo(t, e, slug, sha)
	_, err := e.srv.deployRepoApp(context.Background(), cfg, sha, "manual", "operator", false, false, func(string) {})
	want := `service "web" env DB_PASSWORD: secret "DB_PASSWORD" has no value`
	if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "optional: true") {
		t.Fatalf("deploy with a missing env secret = %v, want an error containing %q", err, want)
	}
	if _, serr := os.Stat(filepath.Join(e.srv.appRunDir(slug), "docker-compose.yml")); !os.IsNotExist(serr) {
		t.Errorf("the deploy wrote the run dir before failing on the missing secret: %v", serr)
	}
	if c, _, _ := e.srv.gitStore.Get(slug); c.UpdateState != "update_blocked" {
		t.Errorf("update state = %q, want update_blocked", c.UpdateState)
	}
}

// Every missing reference is listed, across services, in one error.
func TestCheckEnvSecretsListsEveryMissingRef(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	d, err := definition.Parse([]byte(envRefDef("          SENTRY: {secret: SENTRY_DSN}\n")))
	if err != nil {
		t.Fatal(err)
	}
	err = e.srv.checkEnvSecrets("shop", d, func(string) {})
	if err == nil || !strings.Contains(err.Error(), `env DB_PASSWORD: secret "DB_PASSWORD"`) || !strings.Contains(err.Error(), `env SENTRY: secret "SENTRY_DSN"`) {
		t.Fatalf("want both missing refs named, got %v", err)
	}
}

// optional: true allows a missing secret; a secret explicitly set to "" counts as set.
func TestCheckEnvSecretsOptionalAndEmptyPass(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	if _, err := e.srv.envStore.Save(context.Background(), "shop",
		[]envstore.Entry{{Key: "DB_PASSWORD", Value: secret.New(""), Secret: true}}, "op"); err != nil {
		t.Fatal(err)
	}
	d, err := definition.Parse([]byte(envRefDef("          SENTRY: {secret: SENTRY_DSN, optional: true}\n")))
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	if err := e.srv.checkEnvSecrets("shop", d, func(l string) { lines = append(lines, l) }); err != nil {
		t.Fatalf("an empty-but-set secret and an optional missing one must pass, got %v", err)
	}
	if len(lines) != 0 {
		t.Errorf("a normal deploy logs nothing for these: %v", lines)
	}
}

// A PR preview doesn't inherit the base app's pasted secrets: a missing one is a warning on the
// deploy log, and the deploy goes on.
func TestCheckEnvSecretsPreviewWarnsAndContinues(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	ctx := context.Background()
	if err := e.srv.gitStore.Save(ctx, gitstore.SaveInput{Project: "shop", RepoURL: "https://nonexistent.invalid/o/r.git",
		Ref: "refs/heads/main", ComposePath: "docker-compose.yml", BuildPolicy: "never"}); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.gitStore.SetPreviewEnabled(ctx, "shop", true); err != nil {
		t.Fatal(err)
	}
	if err := e.srv.gitStore.RegisterPreview(ctx, "shop", "shop-pr-3", "refs/pull/3/head"); err != nil {
		t.Fatal(err)
	}
	d, err := definition.Parse([]byte(envRefDef("")))
	if err != nil {
		t.Fatal(err)
	}
	var lines []string
	if err := e.srv.checkEnvSecrets("shop-pr-3", d, func(l string) { lines = append(lines, l) }); err != nil {
		t.Fatalf("a preview must not fail on a missing secret, got %v", err)
	}
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "warning: ") || !strings.Contains(lines[0], `env DB_PASSWORD: secret "DB_PASSWORD"`) {
		t.Fatalf("want one warning line naming the ref, got %v", lines)
	}
	// The base app itself is a normal deploy: it still fails.
	if err := e.srv.checkEnvSecrets("shop", d, func(string) {}); err == nil {
		t.Fatal("the base app must still fail on the missing secret")
	}
}

// generate: secrets are minted before the check, so a generated secret referenced from env is
// never reported missing on the first deploy.
func TestEnsureGeneratedSecretsMintsBeforeEnvCheck(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	src := strings.Replace(envRefDef(""), "{name: DB_PASSWORD}", "{name: DB_PASSWORD, generate: 'password:24'}", 1)
	d, err := definition.Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.srv.ensureGeneratedSecrets(context.Background(), "shop", d, func(string) {}); err != nil {
		t.Fatalf("a generated secret referenced from env must pass the check, got %v", err)
	}
	if v, ok, _ := e.srv.envStore.Reveal("shop", "DB_PASSWORD"); !ok || len(v) != 24 {
		t.Fatalf("DB_PASSWORD not minted (ok=%v len=%d)", ok, len(v))
	}
}

// A config-file {env: KEY} binding whose env value is an optional secret with no stored value
// renders "" — the same value the container's env var gets — instead of failing the deploy.
func TestConfigBindingOptionalSecretRendersEmpty(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	d, err := definition.Parse([]byte(envRefDef("          SENTRY: {secret: SENTRY_DSN, optional: true}\n")))
	if err != nil {
		t.Fatal(err)
	}
	svc := d.Spec.Compose.Services["web"]
	resolve := e.srv.configBindingResolver("shop", "web", svc, map[string]definition.Binding{
		"OPT": {Env: "SENTRY"}, "REQ": {Env: "DB_PASSWORD"},
	})
	if v, _, err := resolve("OPT"); err != nil || v != "" {
		t.Fatalf("optional missing secret via env binding = %q, %v; want \"\", nil", v, err)
	}
	if _, _, err := resolve("REQ"); err == nil || !strings.Contains(err.Error(), "has no value") {
		t.Fatalf("a required missing secret via env binding must still fail, got %v", err)
	}
}

// Only root-level mooring files are read: a repo whose only mooring file sits in a subfolder fails
// the deploy naming that file, instead of scaffolding a guessed app.
func TestDeployRejectsNestedMooringFile(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), false, "disabled for test")
	slug := "shop"
	sha := gitObjStoreFixtureFiles(t, e.srv.gitObjectDir(slug), map[string]string{
		"go.mod":              "module x\n\ngo 1.23\n",
		"main.go":             "package main\nfunc main(){}\n",
		"deploy/mooring.yaml": repoMooringYAML,
	})
	cfg := configureRepo(t, e, slug, sha)
	_, err := e.srv.deployRepoApp(context.Background(), cfg, sha, "manual", "operator", false, false, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "deploy/mooring.yaml") || !strings.Contains(err.Error(), "root") {
		t.Fatalf("a subfolder-only mooring file must fail the deploy naming it, got %v", err)
	}
}

func TestNestedMooringFile(t *testing.T) {
	cases := []struct {
		files []string
		want  string
	}{
		{[]string{"go.mod", "main.go"}, ""},
		{[]string{"mooring.staging.yaml", "README.md"}, ""}, // root-level: not nested
		{[]string{"README.md", "infra/mooring.prod.yml", "x/mooring.yaml"}, "infra/mooring.prod.yml"},
		{[]string{"a/b/mooring-old.yaml"}, "a/b/mooring-old.yaml"},
		{[]string{"docs/mooring.md", "web/nomooring.yaml", "mooringyaml/x.txt"}, ""},
	}
	for _, c := range cases {
		if got := nestedMooringFile(c.files); got != c.want {
			t.Errorf("nestedMooringFile(%v) = %q, want %q", c.files, got, c.want)
		}
	}
}
