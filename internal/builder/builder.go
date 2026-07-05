// Package builder is Mooring's build subsystem: it turns a declarative build spec
// (from mooring.yaml's compose.services[].build) into a hardened, multi-stage
// Dockerfile. The operator never writes a Dockerfile — Mooring owns it, the same way
// it owns the compose. A registry of language builders covers the popular stacks; an
// `auto` language detects the stack from the repo; a `generic` builder wraps the
// operator's own base + commands as a best-effort fallback.
//
// Security: the operator's install/build commands are run as Dockerfile RUN steps (it
// is their build), but they are SANITIZED — no newline/CR/NUL — so a value can never
// break out of its RUN line to inject extra Dockerfile directives (e.g. USER root,
// FROM, another COPY). Every generated image runs as a non-root user by default.
package builder

import (
	"fmt"
	"regexp"
	"strings"
)

// Spec is the declarative build input (projected from the definition Build).
type Spec struct {
	Service  string            // service name (labels / Dockerfile naming)
	Language string            // auto | node | python | go | ruby | php | static | generic
	Dir      string            // repo-relative subdir to build from ("" = repo root)
	Version  string            // runtime version (e.g. "20"); builder picks a sane default
	Base     string            // generic only: the base image
	Install  string            // dependency install command (shell)
	Build    string            // build/compile command (shell)
	Start    []string          // container start (exec form) → Dockerfile CMD
	Env      map[string]string // build-time env
	Packages []string          // extra OS packages
	Output   string            // build output dir to ship (static: served dir, e.g. "dist")
	Nonroot  bool              // run the image as a non-root user (default true at the caller)
}

// src joins the build subdir (if any) with a context-relative path. With no Dir it
// returns the path unchanged, so default Dockerfiles stay byte-identical (no churn
// for existing apps); with Dir set it scopes a COPY to that subdir of the context.
func (s Spec) src(p string) string {
	if s.Dir == "" {
		return p
	}
	if p == "." {
		return s.Dir
	}
	return s.Dir + "/" + p
}

// Builder generates a Dockerfile for one language/stack. files is the build root's
// file set (same as Detect sees) so a builder can pick the dependency manager from the
// committed lockfile (e.g. pnpm-lock.yaml → pnpm); builders that don't care ignore it.
type Builder interface {
	Name() string
	Detect(files map[string]bool) bool // does this stack match the repo's top-level files?
	Dockerfile(s Spec, files map[string]bool) (string, error)
}

// registry maps an explicit language to its builder.
var registry = map[string]Builder{}

// detectOrder is the priority order for `auto` detection (most specific first).
var detectOrder []Builder

func register(b Builder) {
	registry[b.Name()] = b
	if b.Name() != "generic" {
		detectOrder = append(detectOrder, b)
	}
}

func init() {
	// Order matters for auto-detect: a repo with both go.mod and a package.json
	// (e.g. a Go service with a JS asset step) detects as Go first, etc. Static is
	// last so it only wins when nothing else matches.
	register(goBuilder{})
	register(nodeBuilder{})
	register(pythonBuilder{})
	register(rubyBuilder{})
	register(phpBuilder{})
	register(staticBuilder{})
	register(genericBuilder{})
}

// SupportedLanguages lists the first-class builders (for errors/docs).
func SupportedLanguages() []string {
	return []string{"node", "python", "go", "ruby", "php", "static", "generic"}
}

// DockerfilePath is the run_dir-relative path where Mooring writes the generated
// Dockerfile for a service (and the compose `build.dockerfile` value). Kept here so
// the compose generator and the deploy-time writer always agree. The service name is
// schema-validated ([a-z0-9][a-z0-9_-]*), so the path is traversal-free.
func DockerfilePath(service string) string {
	return ".mooring/Dockerfile." + service
}

// Resolve picks the builder for a spec: an explicit known language, `auto` detection
// from the repo's top-level files, or an error pointing the operator at `generic`.
func Resolve(s Spec, files map[string]bool) (Builder, error) {
	lang := s.Language
	if lang == "" {
		lang = "auto"
	}
	if lang == "auto" {
		for _, b := range detectOrder {
			if b.Detect(files) {
				return b, nil
			}
		}
		return nil, fmt.Errorf("could not detect the app's stack from the repo — set build.language (%s) or use build.language: generic with a base image",
			strings.Join(SupportedLanguages(), "|"))
	}
	if b, ok := registry[lang]; ok {
		return b, nil
	}
	return nil, fmt.Errorf("unsupported build language %q (one of: %s)", lang, strings.Join(SupportedLanguages(), "|"))
}

// Generate resolves a builder and renders the Dockerfile.
func Generate(s Spec, files map[string]bool) (string, error) {
	b, err := Resolve(s, files)
	if err != nil {
		return "", err
	}
	return b.Dockerfile(s, files)
}

// --- shared, security-critical helpers ---

var (
	versionRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	imageRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:@-]*$`)
	pkgRe     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.+_-]*$`)
)

// shellLine validates an operator shell command before it becomes a RUN line. It must
// be a single line — no newline/CR/NUL — so it can never inject another Dockerfile
// directive. (It IS the operator's own command, so its CONTENT is theirs to choose.)
func shellLine(what, cmd string) (string, error) {
	if strings.ContainsAny(cmd, "\n\r\x00") {
		return "", fmt.Errorf("%s must be a single line (no newline/CR/NUL)", what)
	}
	return strings.TrimSpace(cmd), nil
}

// version returns a validated version or the default.
func version(v, def string) (string, error) {
	if v == "" {
		return def, nil
	}
	if !versionRe.MatchString(v) {
		return "", fmt.Errorf("build.version %q is invalid", v)
	}
	return v, nil
}

// validImage validates a base image reference (generic builder).
func validImage(ref string) error {
	if ref == "" || len(ref) > 512 || !imageRe.MatchString(ref) {
		return fmt.Errorf("build.base %q is not a valid image reference", ref)
	}
	return nil
}

// aptOrApkPackages renders an OS-package install line for the given manager, or "".
func packageLine(manager string, pkgs []string) (string, error) {
	if len(pkgs) == 0 {
		return "", nil
	}
	for _, p := range pkgs {
		if !pkgRe.MatchString(p) {
			return "", fmt.Errorf("build.packages entry %q is invalid", p)
		}
	}
	list := strings.Join(pkgs, " ")
	switch manager {
	case "apk":
		return "RUN apk add --no-cache " + list, nil
	case "apt":
		return "RUN apt-get update && apt-get install -y --no-install-recommends " + list + " && rm -rf /var/lib/apt/lists/*", nil
	default:
		return "", fmt.Errorf("unknown package manager %q", manager)
	}
}

// envLines renders sorted, validated build-time ENV directives.
func envLines(env map[string]string) ([]string, error) {
	if len(env) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		if !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`).MatchString(k) {
			return nil, fmt.Errorf("build.env key %q is invalid", k)
		}
		keys = append(keys, k)
	}
	sortStrings(keys)
	var out []string
	for _, k := range keys {
		v := env[k]
		if strings.ContainsAny(v, "\n\r\x00") {
			return nil, fmt.Errorf("build.env value for %q must be a single line", k)
		}
		// Quote the value so spaces/specials are inert; backslash/quote escaped.
		out = append(out, fmt.Sprintf("ENV %s=%q", k, v))
	}
	return out, nil
}

// cmdLine renders an exec-form CMD from the start argv (each element JSON-quoted).
func cmdLine(start []string) (string, error) {
	if len(start) == 0 {
		return "", nil
	}
	parts := make([]string, len(start))
	for i, a := range start {
		if a == "" || strings.ContainsAny(a, "\n\r\x00") {
			return "", fmt.Errorf("build.start has an invalid argument")
		}
		parts[i] = fmt.Sprintf("%q", a)
	}
	return "CMD [" + strings.Join(parts, ", ") + "]", nil
}

// nonrootAlpine / nonrootDebian add an unprivileged user + USER directive.
func nonrootAlpine() []string {
	return []string{
		"RUN addgroup -S app && adduser -S app -G app && chown -R app:app /app",
		"USER app",
	}
}

func nonrootDebian() []string {
	return []string{
		"RUN groupadd -r app && useradd -r -g app app && chown -R app:app /app",
		"USER app",
	}
}

// join assembles non-empty lines into a Dockerfile.
func join(lines ...string) string {
	var b strings.Builder
	for _, l := range lines {
		if l == "" {
			continue
		}
		b.WriteString(l)
		b.WriteByte('\n')
	}
	return b.String()
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
