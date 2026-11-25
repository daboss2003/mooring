package web

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/daboss2003/mooring/internal/dockerexec"
	"github.com/daboss2003/mooring/internal/gitstore"
	"github.com/daboss2003/mooring/internal/yamldiag"
)

const diagGoodYAML = "apiVersion: mooring/v1\nkind: App\nmetadata: {slug: app}\nspec:\n" +
	"  compose:\n    source: generated\n    services:\n      web:\n        image: nginx:1.27\n"

// A refused mooring file fails the deploy with ONE line that names the file the app is connected to
// and the position; the multi-line detail (the line and a caret) is there for the deploy output.
func TestDeployRefusedDefinitionNamesFileAndLine(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	slug := "shop"
	bad := strings.Replace(diagGoodYAML, "        image: nginx:1.27\n", "        image: nginx:1.27\n        restrat: always\n", 1)
	sha := gitObjStoreFixtureFiles(t, e.srv.gitObjectDir(slug), map[string]string{"mooring.staging.yaml": bad})
	ctx := context.Background()
	if err := e.srv.gitStore.Save(ctx, gitstore.SaveInput{
		Project: slug, RepoURL: "https://nonexistent.invalid/o/r.git", Ref: "refs/heads/main",
		ComposePath: "docker-compose.yml", BuildPolicy: "never", MooringFile: "mooring.staging.yaml",
	}); err != nil {
		t.Fatal(err)
	}
	e.srv.gitStore.SetFetchResult(ctx, slug, sha, 1, "update_available")
	cfg, ok, err := e.srv.gitStore.Get(slug)
	if err != nil || !ok {
		t.Fatalf("get repo cfg: %v ok=%v", err, ok)
	}
	_, derr := e.srv.deployRepoApp(ctx, cfg, sha, "manual", "operator", false, false, func(string) {})
	if derr == nil {
		t.Fatal("a refused definition must fail the deploy")
	}
	line := derr.Error()
	if strings.ContainsAny(line, "\n\r") {
		t.Errorf("the deploy error must stay one line (audit detail, logs): %q", line)
	}
	if !strings.Contains(line, "definition rejected (unknown or mistyped field): mooring.staging.yaml:10:9: ") ||
		!strings.Contains(line, "did you mean restart?") || strings.Count(line, "mooring.staging.yaml") != 1 {
		t.Errorf("deploy error = %q", line)
	}
	var d *yamldiag.Diagnostics
	if !errors.As(derr, &d) {
		t.Fatalf("the deploy error must carry the diagnostics: %T", derr)
	}
	detail := definitionDetail(derr)
	for _, want := range []string{"mooring.staging.yaml:10:9: ", "\n  10 |         restrat: always\n", "\n     |         ^\n", "hint: did you mean restart?"} {
		if !strings.Contains(detail, want) {
			t.Errorf("detail lacks %q:\n%s", want, detail)
		}
	}
	if got, _, _ := e.srv.gitStore.Get(slug); got.UpdateState != "update_blocked" {
		t.Errorf("state = %q, want update_blocked", got.UpdateState)
	}
}

// An error that is not a located refusal has no detail, and a refusal without a Diagnostics keeps
// the file-name prefix it always had.
func TestDefinitionDetailOnlyForLocatedRefusals(t *testing.T) {
	if got := definitionDetail(errors.New("commit not found")); got != "" {
		t.Errorf("a plain error has no detail: %q", got)
	}
	if got := definitionDetail(nil); got != "" {
		t.Errorf("nil: %q", got)
	}
	unlocated := &yamldiag.Diagnostics{File: "mooring.yaml", Cause: errors.New("empty definition")}
	if got := definitionDetail(unlocated); got != "" {
		t.Errorf("a refusal with no position adds nothing to its one line: %q", got)
	}
	plain := errors.New("boom")
	if got := refusedFile("mooring.prod.yaml", plain); got.Error() != "mooring.prod.yaml: boom" || !errors.Is(got, plain) {
		t.Errorf("plain refusal: %v", got)
	}
	if got := refusedFile("mooring.prod.yaml", unlocated); got != error(unlocated) {
		t.Errorf("a Diagnostics already names its file: %v", got)
	}
}

// The setup upload answers a refused file in plain text: the position, the line and a caret. The
// file is hostile text — it is never served as HTML and its control characters are dropped.
func TestSetupSyncRefusalShowsTheLine(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	sess, csrf := e.authed(t)
	cookies := []*http.Cookie{sess, csrf}
	bad := diagGoodYAML + "  setup:\n    script: \"echo hi\"\n    triger: \"<script>alert(1)</script>\t\u202e\" # x\n"
	resp := e.reqUpload(t, "/apps/shop/setup/sync", "127.0.0.1:1", csrf.Value, "definition", "mooring.staging.yaml", bad, cookies)
	body := readBody(resp)
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422: %s", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("a refusal quotes the uploaded file: it must be plain text, never sniffed (Content-Type %q)", ct)
	}
	for _, want := range []string{
		"mooring.yaml rejected:\n",
		"mooring.staging.yaml:12:5: ",
		"\n  12 |     triger: \"<script>alert(1)</script> \" # x\n",
		"\n     |     ^\n",
		"hint: did you mean trigger?",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("body lacks %q:\n%s", want, body)
		}
	}
	if _, ok, _ := e.srv.setupStore.Get("shop"); ok {
		t.Error("a refused upload must store nothing")
	}
	// Raw control characters (a terminal escape, a bell) are a refusal of their own; none is echoed.
	raw := readBody(e.reqUpload(t, "/apps/shop/setup/sync", "127.0.0.1:1", csrf.Value, "definition", "mooring.yaml",
		diagGoodYAML+"  setup:\n    script: \"echo hi\"\n    trigger: \"\x1b[31m<script>\" # \x07\n", cookies))
	if !strings.Contains(raw, "mooring.yaml:12:") || !strings.Contains(raw, "\"[31m<script>\"") {
		t.Errorf("control characters:\n%s", raw)
	}
	for _, r := range body + raw {
		if r != '\n' && (r < 0x20 || r == 0x7f || r == '\u202e') {
			t.Errorf("control character %U in the response", r)
			break
		}
	}

	// A semantic refusal: one located problem.
	sem := strings.Replace(diagGoodYAML, "image: nginx:1.27", "image: nginx:1.27\n        restart: sometimes", 1)
	body = readBody(e.reqUpload(t, "/apps/shop/setup/sync", "127.0.0.1:1", csrf.Value, "definition", "mooring.yaml", sem, cookies))
	if !strings.Contains(body, "mooring.yaml:10:18: service \"web\" restart \"sometimes\" is not allowed\n") || !strings.Contains(body, "\n     |                  ^\n") {
		t.Errorf("semantic refusal:\n%s", body)
	}

	// The upload's file name is the operator's browser's: anything that isn't a mooring file name
	// is not echoed.
	for _, name := range []string{"../../etc/passwd", "<script>.yaml", "notes.txt", "mooring.yaml;x.html"} {
		body = readBody(e.reqUpload(t, "/apps/shop/setup/sync", "127.0.0.1:1", csrf.Value, "definition", name, sem, cookies))
		if !strings.Contains(body, "\nmooring.yaml:10:18: ") || strings.Contains(body, "passwd") || strings.Contains(body, "<script>") || strings.Contains(body, "notes") {
			t.Errorf("upload named %q:\n%s", name, body)
		}
	}

	// A refusal that has no position, and one that is not the parser's, read as before.
	resp = e.reqUpload(t, "/apps/shop/setup/sync", "127.0.0.1:1", csrf.Value, "definition", "mooring.yaml", "\n", cookies)
	if body = readBody(resp); resp.StatusCode != http.StatusUnprocessableEntity || strings.TrimSpace(body) != "mooring.yaml rejected: mooring.yaml: empty definition" {
		t.Errorf("empty upload: %d %q", resp.StatusCode, body)
	}
	resp = e.reqUpload(t, "/apps/shop/setup/sync", "127.0.0.1:1", csrf.Value, "definition", "mooring.yaml", diagGoodYAML, cookies)
	if body = readBody(resp); resp.StatusCode != http.StatusUnprocessableEntity || strings.TrimSpace(body) != "the uploaded mooring.yaml has no spec.setup" {
		t.Errorf("no spec.setup: %d %q", resp.StatusCode, body)
	}
}

// A deploy whose mooring.yaml is refused puts the offending line, the caret and the hint in the
// deploy output; the error it returns stays one line. A refusal with no position adds nothing.
func TestDeployOutputShowsTheRefusedLine(t *testing.T) {
	e := buildServer(t, []string{"127.0.0.1/32"}, false, nil, "")
	e.srv.runner = dockerexec.NewRunner(dockerexec.NewSemaphore(), false, "disabled for test")
	slug := "shop"
	bad := "apiVersion: mooring/v1\nkind: App\nmetadata: {slug: shop}\nspec:\n  compose:\n    source: generated\n    servces:\n      web:\n        image: nginx:1.27\n"
	sha := gitObjStoreFixture(t, e.srv.gitObjectDir(slug), bad)
	cfg := configureRepo(t, e, slug, sha)
	var lines []string
	_, err := e.srv.deployRepoApp(context.Background(), cfg, sha, "manual", "operator", false, false, func(l string) { lines = append(lines, l) })
	if err == nil || strings.Contains(err.Error(), "\n") || !strings.Contains(err.Error(), `unknown key "servces"`) {
		t.Fatalf("deploy of a refused definition = %v; want a one-line error naming the unknown key", err)
	}
	out := strings.Join(lines, "\n")
	if !strings.Contains(out, "    servces:") || !strings.Contains(out, "^") || !strings.Contains(out, "did you mean services?") {
		t.Fatalf("deploy output:\n%s\nwant the offending line, a caret and the hint", out)
	}
}
