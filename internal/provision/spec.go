// Package provision is the app provisioning core (plan §7): a typed form spec
// (mooring.yaml under the hood) deterministically GENERATED into a safe compose.
// Mooring OWNS the compose — there is no raw-compose/Dockerfile paste path — so
// the dangerous compose keys (privileged, cap_add, host namespaces, host binds,
// :80/:443 publishes) SIMPLY DO NOT EXIST in its typed model (no input can produce
// them), and the generated YAML is still re-run through §5.6 as defense in depth.
package provision

import (
	"fmt"
	"regexp"
	"strings"
)

var (
	slugRe    = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}$`)
	svcRe     = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	envKeyRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	volNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	imageRe   = regexp.MustCompile(`^[A-Za-z0-9._/:@-]+$`)
)

// controlPorts are Mooring's own ports; a generated service may never publish or
// target them (plan §7 red-team).
var controlPorts = map[int]bool{9000: true, 2019: true, 2375: true}

var validRestart = map[string]bool{"": true, "no": true, "always": true, "on-failure": true, "unless-stopped": true}

// Port is one published container port. Internal is the container port; Publish
// maps it to the host. Public binds 0.0.0.0 (requires an explicit ack) — the
// default binds loopback only (plan §7: 127.0.0.1 unless "expose publicly").
type Port struct {
	Internal  int    `json:"internal"`
	Publish   bool   `json:"publish"`
	Public    bool   `json:"public"`
	Protocol  string `json:"protocol,omitempty"`  // "" (=tcp) | "tcp" | "udp"
	Published int    `json:"published,omitempty"` // host port (default = internal)
}

// Volume is a named volume XOR a run_dir-confined bind. Exactly one of Name/Source.
type Volume struct {
	Name     string `json:"name"`   // named volume
	Source   string `json:"source"` // relative bind path, confined under run_dir
	Target   string `json:"target"` // absolute path inside the container
	ReadOnly bool   `json:"read_only"`
}

// EnvVar is a generated service's env entry: a literal Value XOR a Secret reference.
// A secret renders as ${Secret} (resolved from the encrypted store's 0600 --env-file
// at deploy); a literal renders inline. Exactly one of Value/Secret.
type EnvVar struct {
	Key    string `json:"key"`
	Value  string `json:"value"`
	Secret string `json:"secret"`
}

// Service is one generated service. Only safe fields exist here by construction. A
// service is `Image` (pull) XOR `Build` (Mooring generates the Dockerfile).
type Service struct {
	Name        string   `json:"name"`
	Image       string   `json:"image"`
	Build       *Build   `json:"build,omitempty"`
	Ports       []Port   `json:"ports"`
	Volumes     []Volume `json:"volumes"`
	Env         []EnvVar `json:"env"`         // per-service env: literal XOR secret ref
	Command     []string `json:"command"`     // exec form (no shell)
	Healthcheck []string `json:"healthcheck"` // exec form, e.g. ["curl","-f","http://localhost/health"]
	Restart     string   `json:"restart"`
	DependsOn   []string `json:"depends_on"` // sibling service names
	// MemLimit/MemReservation are compose byte-size strings ("768m", "1g"); empty omits the
	// key. A limit bounds each replica (per-container OOM protection) and makes the scaler's
	// mem trigger per-service. Validated in the definition layer; allow-listed in compose.
	MemLimit       string `json:"mem_limit,omitempty"`
	MemReservation string `json:"mem_reservation,omitempty"`
	// StopGracePeriod is a compose duration ("60s", "1m30s"); empty omits the key. Widens
	// the SIGTERM→SIGKILL drain window on stop. Validated in the definition layer.
	StopGracePeriod string `json:"stop_grace_period,omitempty"`
	// Ulimits are per-container limits (currently only nofile). Validated in the
	// definition layer; allow-listed in compose (§5.6). nil omits the compose key.
	Ulimits *Ulimits `json:"ulimits,omitempty"`
	// Scheduled marks a SCHEDULED-ONLY service (referenced by a scheduled_task): the generator
	// gives it a compose profile so `up` never starts it; Mooring runs it on its interval via
	// `compose run --rm`. Not a security-relevant field (no compose privilege), just placement.
	Scheduled bool `json:"scheduled,omitempty"`
}

// Ulimits / NofileLimit mirror the definition types for compose `ulimits.nofile`.
type Ulimits struct {
	Nofile *NofileLimit `json:"nofile,omitempty"`
}

type NofileLimit struct {
	Soft int `json:"soft"`
	Hard int `json:"hard"`
}

// Build marks a service whose image Mooring BUILDS from a generated Dockerfile.
// Context is the build context (run_dir-relative; "." = the app's checkout) and
// Dockerfile is the run_dir-relative path of the Mooring-generated Dockerfile. Both
// stay under the run dir — the §5.6 validator re-confines the context at deploy time.
type Build struct {
	Context    string `json:"context"`
	Dockerfile string `json:"dockerfile"`
}

func (b Build) validate() error {
	for _, p := range []struct{ what, v string }{{"build context", b.Context}, {"build dockerfile", b.Dockerfile}} {
		v := p.v
		if v == "" {
			return fmt.Errorf("%s is required", p.what)
		}
		if strings.ContainsAny(v, "\x00\n:") || strings.HasPrefix(v, "/") || strings.HasPrefix(v, "~") {
			return fmt.Errorf("%s %q must be a relative path under the app directory (no ':')", p.what, v)
		}
		if v == ".." || strings.HasPrefix(v, "../") || strings.Contains(v, "/../") || strings.HasSuffix(v, "/..") {
			return fmt.Errorf("%s %q must not traverse outside the app directory", p.what, v)
		}
	}
	return nil
}

// Spec is the Mode-1 form, the source of truth for a generated app.
type Spec struct {
	Slug     string    `json:"slug"`
	Services []Service `json:"services"`
}

// Validate enforces every field-level safety rule BEFORE generation (the first
// defense, plan §7). It returns the first violation as an operator-facing error.
func (s Spec) Validate() error {
	if !slugRe.MatchString(s.Slug) {
		return fmt.Errorf("app id must match [a-z][a-z0-9-]{1,30} (got %q)", s.Slug)
	}
	if len(s.Services) == 0 {
		return fmt.Errorf("at least one service is required")
	}
	if len(s.Services) > 20 {
		return fmt.Errorf("too many services (max 20)")
	}
	names := map[string]bool{}
	for _, svc := range s.Services {
		if !svcRe.MatchString(svc.Name) {
			return fmt.Errorf("service name %q is invalid (use [a-z0-9][a-z0-9_-]*)", svc.Name)
		}
		if names[svc.Name] {
			return fmt.Errorf("duplicate service name %q", svc.Name)
		}
		names[svc.Name] = true
	}
	for _, svc := range s.Services {
		if err := svc.validate(names); err != nil {
			return fmt.Errorf("service %q: %w", svc.Name, err)
		}
	}
	return nil
}

func (svc Service) validate(siblings map[string]bool) error {
	if svc.Build != nil {
		if svc.Image != "" {
			return fmt.Errorf("a service sets both image and build (pick one)")
		}
		if err := svc.Build.validate(); err != nil {
			return err
		}
	} else if err := validateImageRef(svc.Image); err != nil {
		return err
	}
	if !validRestart[svc.Restart] {
		return fmt.Errorf("restart %q is not allowed", svc.Restart)
	}
	for _, p := range svc.Ports {
		if p.Internal < 1 || p.Internal > 65535 {
			return fmt.Errorf("port %d out of range", p.Internal)
		}
		if controlPorts[p.Internal] {
			return fmt.Errorf("port %d is a reserved control-plane port", p.Internal)
		}
		if p.Protocol != "" && p.Protocol != "tcp" && p.Protocol != "udp" {
			return fmt.Errorf("port %d protocol %q must be tcp or udp", p.Internal, p.Protocol)
		}
		if p.Published != 0 {
			if p.Published < 1 || p.Published > 65535 {
				return fmt.Errorf("published port %d out of range", p.Published)
			}
			if controlPorts[p.Published] {
				return fmt.Errorf("published port %d is a reserved control-plane port", p.Published)
			}
		}
	}
	for _, v := range svc.Volumes {
		if err := v.validate(); err != nil {
			return err
		}
	}
	for _, e := range svc.Env {
		if !envKeyRe.MatchString(e.Key) {
			return fmt.Errorf("env key %q is invalid", e.Key)
		}
		if e.Value != "" && e.Secret != "" {
			return fmt.Errorf("env %q sets both value and secret", e.Key)
		}
		if e.Secret != "" && !envKeyRe.MatchString(e.Secret) {
			return fmt.Errorf("env %q secret name %q is invalid", e.Key, e.Secret)
		}
		// A literal must not smuggle a compose ${...} interpolation or control chars.
		if strings.Contains(e.Value, "${") || strings.ContainsAny(e.Value, "\x00\n") {
			return fmt.Errorf("env %q literal value is unsafe", e.Key)
		}
	}
	if err := validateExec(svc.Command); err != nil {
		return fmt.Errorf("command: %w", err)
	}
	if err := validateExec(svc.Healthcheck); err != nil {
		return fmt.Errorf("healthcheck: %w", err)
	}
	for _, d := range svc.DependsOn {
		if !siblings[d] {
			return fmt.Errorf("depends_on references unknown service %q", d)
		}
		if d == svc.Name {
			return fmt.Errorf("service cannot depend on itself")
		}
	}
	return nil
}

func (v Volume) validate() error {
	hasName := v.Name != ""
	hasBind := v.Source != ""
	if hasName == hasBind {
		return fmt.Errorf("volume must set exactly one of name or source")
	}
	// ':' is the field separator in compose's short volume syntax — a path
	// component containing it would shift source/target/mode fields, so reject it
	// (a real path never needs ':').
	if v.Target == "" || !strings.HasPrefix(v.Target, "/") || strings.ContainsAny(v.Target, "\x00\n:") {
		return fmt.Errorf("volume target must be an absolute container path (no ':')")
	}
	if hasName {
		if !volNameRe.MatchString(v.Name) {
			return fmt.Errorf("volume name %q is invalid", v.Name)
		}
		return nil
	}
	// Bind source: relative, no traversal, no abs, no home, no NUL/newline. The
	// §5.6 validator re-confines it under run_dir at validate/deploy time.
	src := v.Source
	if strings.ContainsAny(src, "\x00\n:") || strings.HasPrefix(src, "/") || strings.HasPrefix(src, "~") {
		return fmt.Errorf("bind source %q must be a relative path under the app directory (no ':')", src)
	}
	if src == ".." || strings.HasPrefix(src, "../") || strings.Contains(src, "/../") || strings.HasSuffix(src, "/..") {
		return fmt.Errorf("bind source %q must not traverse outside the app directory", src)
	}
	return nil
}

// validateExec checks an exec-form argv: each element non-empty, no NUL/newline.
// An empty list is allowed (the field is omitted).
func validateExec(argv []string) error {
	for _, a := range argv {
		if a == "" {
			return fmt.Errorf("empty argument")
		}
		if strings.ContainsAny(a, "\x00\n") {
			return fmt.Errorf("argument contains a control character")
		}
	}
	return nil
}

// validateImageRef requires a non-empty, charset-safe reference WITH an explicit
// tag or digest — never a silent :latest (plan §7).
func validateImageRef(ref string) error {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return fmt.Errorf("image is required")
	}
	if len(ref) > 512 || !imageRe.MatchString(ref) {
		return fmt.Errorf("image reference %q is invalid", ref)
	}
	if i := strings.IndexByte(ref, '@'); i >= 0 {
		// digest form name@sha256:<64 hex>
		dig := ref[i+1:]
		if !strings.HasPrefix(dig, "sha256:") || len(dig) != len("sha256:")+64 {
			return fmt.Errorf("image digest %q must be sha256:<64 hex>", dig)
		}
		return nil
	}
	// Require an explicit tag in the last path component (registry host ports have
	// a ':' too, so only the component after the last '/' counts).
	last := ref
	if i := strings.LastIndexByte(ref, '/'); i >= 0 {
		last = ref[i+1:]
	}
	if !strings.Contains(last, ":") {
		return fmt.Errorf("image %q must pin an explicit tag (no silent :latest)", ref)
	}
	if strings.HasSuffix(last, ":") {
		return fmt.Errorf("image %q has an empty tag", ref)
	}
	return nil
}
