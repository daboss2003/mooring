// Package definition is the mooring.yaml definition file (plan §7.7): the
// declarative source of truth for an app's Mooring-managed surface. It is a SECOND
// front-end onto the same reconciler/§5.6 validator the dashboard drives — a new
// front door, never a new trust path. Nothing in it reaches `docker compose`
// unvalidated.
//
// Mooring OWNS the runtime: the operator declares a multi-service STACK here and
// Mooring GENERATES the compose (and, for build services, the Dockerfile). There is
// no way to supply a raw compose/Dockerfile — `compose.source` is generated-only.
// `services` is a map keyed by name; per-service `env` is a map of literals/secret
// references (compose-familiar).
package definition

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/daboss2003/mooring/internal/ops"
	"github.com/daboss2003/mooring/internal/opsclient"
	"github.com/daboss2003/mooring/internal/sandbox"
	"github.com/daboss2003/mooring/internal/secretgen"
	"gopkg.in/yaml.v3"
)

// APIVersion is the ONLY accepted envelope version — exact-match, fail-closed.
const APIVersion = "mooring/v1"

var (
	slugRe       = regexp.MustCompile(`^[a-z][a-z0-9-]{1,30}$`)
	svcRe        = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)
	secretRe     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)
	envKeyRe     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	tokenKeyRe   = regexp.MustCompile(`^[A-Za-z0-9_-]+$`) // {{hm.KEY}} binding key grammar
	hostnameRe   = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62})(\.[a-z0-9]([a-z0-9-]{0,62}))+$`)
	edgeCANameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`) // a named CA from config.yaml edge.cas
	// subdomainLabelRe is a single RFC1123 DNS label (1-63 chars, lowercase alnum + hyphen,
	// no leading/trailing hyphen). A route/cert_binding may give `subdomain: mqtt` instead
	// of a full hostname; Mooring expands it to <label>.<edge.base_domain> at deploy time.
	subdomainLabelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
)

// validateHostOrSubdomain enforces that a route/cert_binding declares EXACTLY ONE of a full
// hostname (an FQDN, no wildcards) or a subdomain label (expanded to
// <subdomain>.<edge.base_domain> at deploy time, since base_domain lives in the operator's
// config.yaml, not the app repo). `what` tags the error.
func validateHostOrSubdomain(what, hostname, subdomain string) error {
	switch {
	case hostname == "" && subdomain == "":
		return fmt.Errorf("%s needs a hostname or a subdomain", what)
	case hostname != "" && subdomain != "":
		return fmt.Errorf("%s sets both hostname and subdomain — use exactly one", what)
	case subdomain != "":
		if !subdomainLabelRe.MatchString(subdomain) {
			return fmt.Errorf("%s subdomain %q must be a single DNS label [a-z0-9-] (it becomes <subdomain>.<edge.base_domain>)", what, subdomain)
		}
	default: // hostname set
		if len(hostname) > 253 || !hostnameRe.MatchString(hostname) {
			return fmt.Errorf("%s hostname %q is invalid (FQDN, no wildcards)", what, hostname)
		}
	}
	return nil
}

// buildLanguages are the recognized build languages. "auto" (the default) detects
// the stack from the repo; "generic" wraps the operator's own base + commands.
var buildLanguages = map[string]bool{
	"auto": true, "node": true, "python": true, "go": true,
	"ruby": true, "php": true, "static": true, "generic": true,
}

var validRestart = map[string]bool{
	"": true, "no": true, "always": true, "on-failure": true, "unless-stopped": true,
}

// Definition is the whole mooring.yaml document (kind: App).
type Definition struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Spec       Spec     `yaml:"spec"`
}

// Metadata carries the immutable app slug.
type Metadata struct {
	Slug string `yaml:"slug"`
}

// Spec is the managed surface. Each field projects onto an existing artifact.
type Spec struct {
	Compose      Compose       `yaml:"compose"`
	Secrets      []Secret      `yaml:"secrets,omitempty"`
	Edge         Edge          `yaml:"edge"`
	Scaling      []Scaling     `yaml:"scaling,omitempty"` // one policy per service (auto-scale several services in one app)
	SelfHealing  *SelfHealing  `yaml:"self_healing,omitempty"`
	OpsInterface *OpsInterface `yaml:"ops_interface,omitempty"`
	Git          *Git          `yaml:"git,omitempty"`
	Setup        *Setup        `yaml:"setup,omitempty"`
}

// Compose is GENERATED-ONLY: Mooring owns the compose. `source` defaults to and may
// only be "generated". The legacy `repo_path`/`inline` sources are rejected; Path and
// Inline are retained ONLY so a stale definition gets a clear, guiding rejection.
type Compose struct {
	Source   string             `yaml:"source,omitempty"`
	Services map[string]Service `yaml:"services,omitempty"`
	Path     string             `yaml:"path,omitempty"`
	Inline   string             `yaml:"inline,omitempty"`
}

// Service is one service in the generated stack (the map key is its name). A service
// is `image` (pull) XOR `build` (Mooring generates the Dockerfile).
type Service struct {
	Image        string              `yaml:"image,omitempty"` // image XOR build
	Build        *Build              `yaml:"build,omitempty"`
	Ports        []Port              `yaml:"ports,omitempty"`
	Volumes      []Volume            `yaml:"volumes,omitempty"`
	Env          map[string]EnvValue `yaml:"env,omitempty"` // KEY: literal | {secret: NAME}
	SecretFiles  []string            `yaml:"secret_files,omitempty"`
	ConfigFiles  []ConfigFile        `yaml:"config_files,omitempty"`
	CertBindings []CertBinding       `yaml:"cert_bindings,omitempty"`
	Command      []string            `yaml:"command,omitempty"`
	Healthcheck  []string            `yaml:"healthcheck,omitempty"`
	Restart      string              `yaml:"restart,omitempty"`
	DependsOn    []string            `yaml:"depends_on,omitempty"`
	OpsInterface *OpsInterface       `yaml:"ops_interface,omitempty"` // per-service ops endpoint (§4); probed for RICH health/queues/metrics
	// MemLimit sets a cgroup memory cap per replica (e.g. "768m", "1g"). It also makes the
	// autoscaler's up_mem_pct/down_mem_pct per-service: docker reports it as the container's
	// mem limit, so the trigger measures RSS against THIS budget, not the host's total RAM.
	// MemReservation is the optional soft reservation. Both empty → unbounded (host RAM), as today.
	MemLimit       string `yaml:"mem_limit,omitempty"`
	MemReservation string `yaml:"mem_reservation,omitempty"`
	// StopGracePeriod widens the SIGTERM→SIGKILL window on stop (scale-down / redeploy)
	// from docker's 10s default, so the app can drain long in-flight requests, e.g. "60s",
	// "1m30s". Empty = docker default. Pairs with the app's graceful-shutdown hooks.
	StopGracePeriod string `yaml:"stop_grace_period,omitempty"`
	// Ulimits sets per-container resource limits (currently only `nofile`, the open
	// file-descriptor cap). Raise it for services that hold many concurrent sockets
	// beyond the docker daemon default of 1024 (e.g. an MQTT broker whose
	// max_connections is otherwise clamped to the fd limit). nil = daemon default.
	Ulimits *Ulimits `yaml:"ulimits,omitempty"`
}

// Ulimits is the per-service ulimit block. Only `nofile` (max open file
// descriptors) is supported — the knob that gates concurrent connection count.
type Ulimits struct {
	Nofile *NofileLimit `yaml:"nofile,omitempty"`
}

// NofileLimit is a soft/hard open-file-descriptor limit (compose `ulimits.nofile`).
type NofileLimit struct {
	Soft int `yaml:"soft"`
	Hard int `yaml:"hard"`
}

// EnvValue is a per-service env var: a literal value XOR a `{secret: NAME}` reference.
// A scalar is a literal; a mapping must be exactly `{ secret: NAME }`.
type EnvValue struct {
	Value  string
	Secret string
}

// MarshalYAML renders the canonical form: a `{secret: NAME}` mapping for a reference,
// else the scalar literal — so Canonical round-trips back through UnmarshalYAML.
func (e EnvValue) MarshalYAML() (any, error) {
	if e.Secret != "" {
		return map[string]string{"secret": e.Secret}, nil
	}
	return e.Value, nil
}

// UnmarshalYAML accepts a scalar literal or a `{ secret: NAME }` mapping (only).
func (e *EnvValue) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		e.Value = n.Value
		return nil
	case yaml.MappingNode:
		if len(n.Content) != 2 || n.Content[0].Value != "secret" {
			return fmt.Errorf("env value mapping must be exactly { secret: NAME }")
		}
		e.Secret = n.Content[1].Value
		if e.Secret == "" {
			return fmt.Errorf("env value { secret: } requires a name")
		}
		return nil
	default:
		return fmt.Errorf("env value must be a literal or { secret: NAME }")
	}
}

// Port is one container port. Internal is the in-container port; Publish maps it to
// the host (loopback by default, all interfaces only when Public).
type Port struct {
	Internal  int    `yaml:"internal"`
	Publish   bool   `yaml:"publish"`
	Public    bool   `yaml:"public"`
	Protocol  string `yaml:"protocol,omitempty"`  // "" (=tcp) | "tcp" | "udp"
	Published int    `yaml:"published,omitempty"` // host port (default = internal); maps host→container so a non-root container can bind a privileged host port
}

// Build is the declarative build spec — Mooring GENERATES the Dockerfile from it.
type Build struct {
	Language string            `yaml:"language,omitempty"`
	Version  string            `yaml:"version,omitempty"`
	Dir      string            `yaml:"dir,omitempty"`  // repo-relative subdir to build from (default ".")
	Base     string            `yaml:"base,omitempty"` // generic only
	Install  string            `yaml:"install,omitempty"`
	BuildCmd string            `yaml:"build,omitempty"`
	Start    []string          `yaml:"start,omitempty"`
	Env      map[string]string `yaml:"env,omitempty"`
	Packages []string          `yaml:"packages,omitempty"`
	Output   string            `yaml:"output,omitempty"` // build output dir to ship (e.g. static: "dist")
	Nonroot  *bool             `yaml:"run_as_nonroot,omitempty"`
}

// Volume is a named volume XOR a run_dir-confined bind.
type Volume struct {
	Name     string `yaml:"name"`
	Source   string `yaml:"source"`
	Target   string `yaml:"target"`
	ReadOnly bool   `yaml:"read_only"`
}

// ConfigFile is an app config file Mooring renders + bind-mounts read-only into a
// service. Content is a repo path (git cat-file @ pinned commit) XOR inline template.
// Bindings is the explicit allowlist of {{hm.KEY}} tokens the file may resolve; the
// app's own ${…} survive byte-identical.
type ConfigFile struct {
	Repo     string             `yaml:"repo,omitempty"`
	Template string             `yaml:"template,omitempty"`
	Mount    string             `yaml:"mount"`
	Bindings map[string]Binding `yaml:"bindings,omitempty"`
}

// Binding resolves one {{hm.KEY}} token in a config-file template. Exactly one form:
// a scalar literal, or a single-key mapping selecting a source —
//   - { secret: NAME }        the encrypted secret value (marks the file secret-bearing)
//   - { env: NAME }           the SAME service's env value (literal or secret-backed)
//   - { app: FIELD }          a safe app field (currently only `slug`)
//   - { cert: HOSTNAME.field } a path to a SAME-service cert binding's tls.crt|key|ca
//
// This is the superset of the legacy dashboard binding sources, so the dashboard's
// config-file editor can express the full capability with nothing lost.
type Binding struct {
	Value  string
	Secret string
	Env    string
	App    string
	Cert   string
}

var validAppFields = map[string]bool{"slug": true}

// MarshalYAML renders the canonical form: the single source mapping for a reference,
// else the scalar literal — so Canonical round-trips back through UnmarshalYAML.
func (b Binding) MarshalYAML() (any, error) {
	switch {
	case b.Secret != "":
		return map[string]string{"secret": b.Secret}, nil
	case b.Env != "":
		return map[string]string{"env": b.Env}, nil
	case b.App != "":
		return map[string]string{"app": b.App}, nil
	case b.Cert != "":
		return map[string]string{"cert": b.Cert}, nil
	default:
		return b.Value, nil
	}
}

// UnmarshalYAML accepts a scalar literal or a single-key { SOURCE: ARG } mapping.
func (b *Binding) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		b.Value = n.Value
		return nil
	case yaml.MappingNode:
		if len(n.Content) != 2 {
			return fmt.Errorf("config-file binding mapping must be exactly one of { secret|env|app|cert: ARG }")
		}
		key, val := n.Content[0].Value, n.Content[1].Value
		if val == "" {
			return fmt.Errorf("config-file binding { %s: } requires an argument", key)
		}
		switch key {
		case "secret":
			b.Secret = val
		case "env":
			b.Env = val
		case "app":
			b.App = val
		case "cert":
			b.Cert = val
		default:
			return fmt.Errorf("config-file binding source %q must be one of secret, env, app, cert", key)
		}
		return nil
	default:
		return fmt.Errorf("config-file binding must be a literal or a { secret|env|app|cert: ARG } mapping")
	}
}

// CertBinding syncs a managed edge cert into a service. The edge issues AND renews the
// leaf; Mooring copies it into the service's mount and recreates the service at deploy
// AND autonomously on renewal (a background watcher re-syncs + recreates the affected
// service when the edge renews the leaf), so a renewed cert is picked up without a
// manual redeploy.
type CertBinding struct {
	Hostname  string `yaml:"hostname"`
	Subdomain string `yaml:"subdomain,omitempty"` // XOR hostname: expands to <subdomain>.<edge.base_domain>
	Mount     string `yaml:"mount"`
	CA        string `yaml:"ca,omitempty"` // "" = default issuer; else a named CA from config.yaml edge.cas
}

// Secret declares a name (+ optional generate hint) — NEVER a value.
type Secret struct {
	Name     string `yaml:"name"`
	Generate string `yaml:"generate"`
}

// Edge is the Layer-1 route input (§6).
type Edge struct {
	Routes   []Route   `yaml:"routes,omitempty"`
	L4Routes []L4Route `yaml:"l4_routes,omitempty"`
}

// L4Route is one managed Layer-4 (TCP/UDP) listener: a fixed public port the L4 load
// balancer owns, forwarded to a service's INTERNAL replica pool. Service/Port are
// selectors (never a literal dial target). Use it for non-HTTP stream services
// (DNS 53, DoT 853, MQTTS 8883). TLS is passthrough only for now (the app terminates
// with a cert_binding); `terminate` is reserved for a later phase.
type L4Route struct {
	Listen   int    `yaml:"listen"`        // the host port the L4 LB binds
	Protocol string `yaml:"protocol"`      // tcp | udp
	Service  string `yaml:"service"`       // selector → the service whose replicas receive traffic
	Port     int    `yaml:"port"`          // the service's internal container port
	TLS      string `yaml:"tls,omitempty"` // "" | passthrough (terminate not yet supported)
	LB       string `yaml:"lb,omitempty"`  // "" (round_robin) | least_conn | hash_client_ip
}

// Route is one managed edge vhost. Upstream is a SELECTOR — "service:port".
type Route struct {
	Hostname        string `yaml:"hostname"`
	Subdomain       string `yaml:"subdomain,omitempty"` // XOR hostname: expands to <subdomain>.<edge.base_domain>
	Service         string `yaml:"service"`
	Port            int    `yaml:"port"`
	PathPrefix      string `yaml:"path_prefix"`
	HSTS            bool   `yaml:"hsts"`
	SecurityHeaders bool   `yaml:"security_headers"`
	RedirectHTTP    bool   `yaml:"redirect_http"`
	UpstreamScheme  string `yaml:"upstream_scheme,omitempty"` // "" (=http) | http | https — how the edge dials the upstream
	CA              string `yaml:"ca,omitempty"`              // "" = default issuer; else a named CA from config.yaml edge.cas
}

// Scaling is the opt-in auto-scaling policy (§8A) for one service.
type Scaling struct {
	Service            string  `yaml:"service"`
	Enabled            bool    `yaml:"enabled"`
	Min                int     `yaml:"min"`
	Max                int     `yaml:"max"`
	UpCPUPct           float64 `yaml:"up_cpu_pct"`
	DownCPUPct         float64 `yaml:"down_cpu_pct"`
	UpMemPct           float64 `yaml:"up_mem_pct"`
	DownMemPct         float64 `yaml:"down_mem_pct"`
	PerReplicaMemMiB   int     `yaml:"per_replica_mem_mib"`
	PerReplicaCPUMilli int     `yaml:"per_replica_cpu_milli"`
	BreachForSecs      int     `yaml:"breach_for_secs,omitempty"`    // sustain window before acting (default 60)
	CooldownUpSecs     int     `yaml:"cooldown_up_secs,omitempty"`   // min seconds between scale-ups (default 60)
	CooldownDownSecs   int     `yaml:"cooldown_down_secs,omitempty"` // min seconds between scale-downs (default 300; >= up)
}

// SelfHealing tunes this app's self-healing supervisor (§8.5). Mooring supervises
// every service with a conservative built-in default; this block overrides the ladder
// tunables for ONE app. Omitted fields keep the built-in default; an omitted block
// leaves the app on the default entirely. All durations are in seconds.
type SelfHealing struct {
	SustainTicks    int  `yaml:"sustain_ticks,omitempty"`     // failing ticks before the first remediation (anti-flap)
	AttemptCap      int  `yaml:"attempt_cap,omitempty"`       // remediations per window before the circuit opens
	StabilizeTicks  int  `yaml:"stabilize_ticks,omitempty"`   // healthy ticks required to declare RECOVERED
	OOMStrikeCap    int  `yaml:"oom_strike_cap,omitempty"`    // OOM-classified failures before short-circuiting the ladder
	WindowSeconds   int  `yaml:"window_seconds,omitempty"`    // attempt-window length; attempts reset after it elapses
	BackoffBaseSecs int  `yaml:"backoff_base_secs,omitempty"` // exponential backoff base between attempts
	BackoffMaxSecs  int  `yaml:"backoff_max_secs,omitempty"`  // backoff ceiling
	RedeployEnabled bool `yaml:"redeploy_enabled,omitempty"`  // rung-3 redeploy (≥1 GB host AND opt-in here)
}

// OpsInterface is the app's optional ops endpoint (§4): Mooring probes it for RICH
// health/queues. Everything here is operator config EXCEPT the shared-secret VALUE —
// that stays encrypted (set the value in the dashboard, or declare a secret and point
// `secret` at it; the value never lives in this file). base_url is the in-cluster
// endpoint (origin only, never loopback); base_path is the relative prefix.
type OpsInterface struct {
	Enabled      bool   `yaml:"enabled"`
	BaseURL      string `yaml:"base_url,omitempty"`
	SecretHeader string `yaml:"secret_header,omitempty"`
	Secret       string `yaml:"secret,omitempty"` // reference to a declared secret NAME (value resolved at deploy); never the value
	Mode         string `yaml:"mode,omitempty"`   // auto | rich | basic
	BasePath     string `yaml:"base_path,omitempty"`
	Adapter      string `yaml:"adapter,omitempty"`
}

// Git is the repo-path / auto-pull config (§7.6). AutoDeploy defaults false.
type Git struct {
	Repo       string `yaml:"repo"`
	Ref        string `yaml:"ref"`
	AutoDeploy bool   `yaml:"auto_deploy"`
}

// Setup is the per-app setup script (Mode 3), declared here and synced into the setup
// store; the portal is a read-only view + the gated Run (no literal paste).
type Setup struct {
	Script   string   `yaml:"script"`
	Trigger  string   `yaml:"trigger"`
	Produces []string `yaml:"produces,omitempty"`
}

// SourceGenerated is the only accepted compose source.
const SourceGenerated = "generated"

// ManagedConfigPath / ManagedSecretPath are the run-dir-relative paths where Mooring
// materializes a service's config file / secret file (and the compose bind source).
// Kept here so reconcile (which emits the mount) and the deploy (which writes the
// content) always agree. The service name, secret name, and index are schema-validated,
// so the path is traversal-free.
func ManagedConfigPath(service string, i int) string {
	return fmt.Sprintf(".mooring/cfg/%s/%d", service, i)
}

func ManagedSecretPath(service, name string) string {
	return fmt.Sprintf(".mooring/secrets/%s/%s", service, name)
}

// ManagedCertDir is the run-dir-relative directory a cert binding is synced into
// (tls.crt + tls.key) and bind-mounted from. service + hostname are schema-validated.
func ManagedCertDir(service, hostname string) string {
	return fmt.Sprintf(".mooring/certs/%s/%s", service, hostname)
}

func (d *Definition) validateEnvelope() error {
	if d.APIVersion != APIVersion {
		return fmt.Errorf("apiVersion must be exactly %q (got %q) — unknown versions are rejected", APIVersion, d.APIVersion)
	}
	if d.Kind != "App" {
		return fmt.Errorf("kind must be \"App\" (got %q)", d.Kind)
	}
	if !slugRe.MatchString(d.Metadata.Slug) {
		return fmt.Errorf("metadata.slug must match [a-z][a-z0-9-]{1,30} (got %q)", d.Metadata.Slug)
	}
	return d.Spec.validate()
}

func (s *Spec) validate() error {
	switch s.Compose.Source {
	case "", SourceGenerated:
		// ok — Mooring generates the compose.
	case "repo_path", "inline":
		return fmt.Errorf("compose.source %q is no longer supported — Mooring generates the compose; "+
			"declare your services (with image: or build:) under compose.services (source: generated)", s.Compose.Source)
	default:
		return fmt.Errorf("compose.source must be \"generated\" (got %q) — Mooring generates the compose", s.Compose.Source)
	}
	if s.Compose.Path != "" || s.Compose.Inline != "" {
		return fmt.Errorf("compose.path/compose.inline are no longer supported — Mooring generates the compose from compose.services")
	}
	if len(s.Compose.Services) == 0 {
		return fmt.Errorf("compose.services is required (Mooring generates the compose from your services)")
	}
	if err := s.validateServices(); err != nil {
		return err
	}
	if err := s.validateSecrets(); err != nil {
		return err
	}
	if err := s.validateEdge(); err != nil {
		return err
	}
	if err := s.validateScaling(); err != nil {
		return err
	}
	if err := s.validateSelfHealing(); err != nil {
		return err
	}
	if err := s.validateOpsInterface(); err != nil {
		return err
	}
	return s.validateSetup()
}

// validateSelfHealing checks the per-app self-healing tunables are structurally sane.
// Every field is optional (0 = "keep the built-in default"); the controller contract
// (e.g. backoff_max >= backoff_base) is re-applied with defaults filled when the
// policy is persisted at deploy.
func (s *Spec) validateSelfHealing() error {
	sh := s.SelfHealing
	if sh == nil {
		return nil
	}
	for _, f := range []struct {
		name string
		v    int
	}{
		{"sustain_ticks", sh.SustainTicks}, {"attempt_cap", sh.AttemptCap},
		{"stabilize_ticks", sh.StabilizeTicks}, {"oom_strike_cap", sh.OOMStrikeCap},
		{"window_seconds", sh.WindowSeconds}, {"backoff_base_secs", sh.BackoffBaseSecs},
		{"backoff_max_secs", sh.BackoffMaxSecs},
	} {
		if f.v < 0 {
			return fmt.Errorf("self_healing.%s must be >= 0", f.name)
		}
	}
	if sh.BackoffBaseSecs > 0 && sh.BackoffMaxSecs > 0 && sh.BackoffMaxSecs < sh.BackoffBaseSecs {
		return fmt.Errorf("self_healing.backoff_max_secs (%d) cannot be less than backoff_base_secs (%d)", sh.BackoffMaxSecs, sh.BackoffBaseSecs)
	}
	return nil
}

// validateOpsInterface checks the ops endpoint config: when enabled, base_url is a
// valid pinned origin (§4.1 — never loopback); mode is auto|rich|basic; base_path is
// relative; the secret header (if set) is a valid header name; and the `secret`
// reference (if set) names a DECLARED secret (the value is resolved at deploy — never
// stored here). The same predicates run again in ops.ConfigStore.Set at apply.
func (s *Spec) validateOpsInterface() error {
	// App-level (legacy) + each per-service ops_interface use identical predicates.
	if err := s.validateOIFields(s.OpsInterface, "ops_interface"); err != nil {
		return err
	}
	for name, svc := range s.Compose.Services {
		if err := s.validateOIFields(svc.OpsInterface, "services."+name+".ops_interface"); err != nil {
			return err
		}
	}
	return nil
}

func (s *Spec) validateOIFields(oi *OpsInterface, ctx string) error {
	if oi == nil {
		return nil
	}
	if oi.Mode != "" && oi.Mode != "auto" && oi.Mode != "rich" && oi.Mode != "basic" {
		return fmt.Errorf("%s.mode %q must be auto, rich, or basic", ctx, oi.Mode)
	}
	if oi.Enabled {
		if err := ops.ValidateBaseURL(oi.BaseURL); err != nil {
			return fmt.Errorf("%s.base_url: %w", ctx, err)
		}
	}
	if bp := strings.TrimRight(strings.TrimSpace(oi.BasePath), "/"); bp != "" && !opsclient.ValidateRelPath(bp) {
		return fmt.Errorf("%s.base_path %q must be a relative path like /ops", ctx, oi.BasePath)
	}
	if h := strings.TrimSpace(oi.SecretHeader); h != "" && !opsclient.ValidHeaderName(h) {
		return fmt.Errorf("%s.secret_header %q is invalid (e.g. X-Ops-Secret)", ctx, oi.SecretHeader)
	}
	if oi.Secret != "" {
		if !secretRe.MatchString(oi.Secret) {
			return fmt.Errorf("%s.secret references an invalid secret name %q", ctx, oi.Secret)
		}
		declared := false
		for _, sec := range s.Secrets {
			if sec.Name == oi.Secret {
				declared = true
				break
			}
		}
		if !declared {
			return fmt.Errorf("%s.secret references undeclared secret %q (add it under spec.secrets)", ctx, oi.Secret)
		}
	}
	return nil
}

// validateScaling checks each per-service scaling policy: the service exists, no
// service appears twice, and the fields are structurally sane. The full controller
// contract (dead band, breach window, cooldowns) is applied + re-validated when the
// policy is persisted at deploy.
func (s *Spec) validateScaling() error {
	declared := map[string]bool{}
	for n := range s.Compose.Services {
		declared[n] = true
	}
	seen := map[string]bool{}
	for _, sc := range s.Scaling {
		if !svcRe.MatchString(sc.Service) {
			return fmt.Errorf("scaling entry must name a valid service")
		}
		if !declared[sc.Service] {
			return fmt.Errorf("scaling targets unknown service %q", sc.Service)
		}
		if seen[sc.Service] {
			return fmt.Errorf("scaling declared twice for service %q", sc.Service)
		}
		seen[sc.Service] = true
		if sc.Min < 0 || sc.Max < 0 {
			return fmt.Errorf("scaling %q: min/max must be >= 0", sc.Service)
		}
		if sc.Max > 0 && sc.Min > sc.Max {
			return fmt.Errorf("scaling %q: min (%d) cannot exceed max (%d)", sc.Service, sc.Min, sc.Max)
		}
		for _, p := range []struct {
			name string
			v    float64
		}{{"up_cpu_pct", sc.UpCPUPct}, {"down_cpu_pct", sc.DownCPUPct}, {"up_mem_pct", sc.UpMemPct}, {"down_mem_pct", sc.DownMemPct}} {
			if p.v < 0 || p.v > 100 {
				return fmt.Errorf("scaling %q: %s must be within 0–100", sc.Service, p.name)
			}
		}
	}
	return nil
}

// serviceNames returns the stack's service names, sorted (deterministic validation).
func (s *Spec) serviceNames() []string {
	names := make([]string, 0, len(s.Compose.Services))
	for n := range s.Compose.Services {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func (s *Spec) validateServices() error {
	declaredSecrets := map[string]bool{}
	for _, sec := range s.Secrets {
		declaredSecrets[sec.Name] = true
		// A keypair generate also produces a derived public secret <NAME>_PUB,
		// so references to it (e.g. in secret_files) are legitimate.
		if secretgen.IsKeypair(sec.Generate) {
			declaredSecrets[sec.Name+secretgen.PubSuffix] = true
		}
	}
	names := map[string]bool{}
	for n := range s.Compose.Services {
		names[n] = true
	}
	for _, name := range s.serviceNames() {
		if !svcRe.MatchString(name) {
			return fmt.Errorf("service name %q is invalid", name)
		}
		svc := s.Compose.Services[name]

		hasImage := svc.Image != ""
		hasBuild := svc.Build != nil
		if hasImage == hasBuild {
			return fmt.Errorf("service %q must set exactly one of image or build", name)
		}
		if hasBuild {
			if err := validateBuild(name, svc.Build); err != nil {
				return err
			}
		}
		for _, p := range svc.Ports {
			if p.Internal < 1 || p.Internal > 65535 {
				return fmt.Errorf("service %q port %d is out of range", name, p.Internal)
			}
			if controlPort(p.Internal) {
				return fmt.Errorf("service %q port %d is a reserved control-plane port", name, p.Internal)
			}
			if p.Public && !p.Publish {
				return fmt.Errorf("service %q port %d sets public without publish", name, p.Internal)
			}
			if p.Protocol != "" && p.Protocol != "tcp" && p.Protocol != "udp" {
				return fmt.Errorf("service %q port %d protocol %q must be tcp or udp", name, p.Internal, p.Protocol)
			}
			if p.Published != 0 {
				if !p.Publish {
					return fmt.Errorf("service %q port %d sets published without publish", name, p.Internal)
				}
				if p.Published < 1 || p.Published > 65535 {
					return fmt.Errorf("service %q published port %d is out of range", name, p.Published)
				}
				if controlPort(p.Published) {
					return fmt.Errorf("service %q published port %d is a reserved control-plane port", name, p.Published)
				}
				if p.Published == 80 || p.Published == 443 {
					return fmt.Errorf("service %q published port %d is reserved for the managed edge", name, p.Published)
				}
			}
		}
		if err := validateServiceEnv(name, svc.Env, declaredSecrets); err != nil {
			return err
		}
		if err := validateUlimits(name, svc.Ulimits); err != nil {
			return err
		}
		for _, sf := range svc.SecretFiles {
			if !declaredSecrets[sf] {
				return fmt.Errorf("service %q secret_files references undeclared secret %q", name, sf)
			}
		}
		// Cert bindings first: a config-file `{ cert: HOSTNAME.field }` may only
		// reference a cert bound on the SAME service, so collect this service's cert
		// hostnames before validating its config files.
		certHosts := map[string]bool{}
		for _, cb := range svc.CertBindings {
			if err := validateCertBinding(name, cb); err != nil {
				return err
			}
			certHosts[cb.Hostname] = true
		}
		for _, cf := range svc.ConfigFiles {
			if err := validateConfigFile(name, cf, declaredSecrets, certHosts); err != nil {
				return err
			}
		}
		for _, v := range svc.Volumes {
			if err := validateVolume(name, v); err != nil {
				return err
			}
		}
		if !validRestart[svc.Restart] {
			return fmt.Errorf("service %q restart %q is not allowed", name, svc.Restart)
		}
		if err := validateExec("command", name, svc.Command); err != nil {
			return err
		}
		if err := validateExec("healthcheck", name, svc.Healthcheck); err != nil {
			return err
		}
		for _, d := range svc.DependsOn {
			if d == name {
				return fmt.Errorf("service %q cannot depend on itself", name)
			}
			if !names[d] {
				return fmt.Errorf("service %q depends_on unknown service %q", name, d)
			}
		}
	}
	return nil
}

// maxNofile caps a declared open-file limit at the usual kernel ceiling (fs.nr_open
// default, 2^30). Above this the HOST needs an fs.nr_open sysctl bump, which Mooring
// can't set (sysctls are forbidden in generated compose), so reject rather than
// silently generate a compose Docker won't honor.
const maxNofile = 1073741824 // 2^30

// validateUlimits checks a per-service ulimits block. Only `nofile` is supported,
// and it must be present with sane soft/hard values (1 ≤ soft ≤ hard ≤ maxNofile).
func validateUlimits(svc string, u *Ulimits) error {
	if u == nil {
		return nil
	}
	if u.Nofile == nil {
		return fmt.Errorf("service %q ulimits: only `nofile` is supported and must be set", svc)
	}
	n := u.Nofile
	if n.Soft < 1 || n.Hard < 1 {
		return fmt.Errorf("service %q ulimits.nofile: soft and hard must be >= 1", svc)
	}
	if n.Soft > n.Hard {
		return fmt.Errorf("service %q ulimits.nofile: soft (%d) must be <= hard (%d)", svc, n.Soft, n.Hard)
	}
	if n.Hard > maxNofile {
		return fmt.Errorf("service %q ulimits.nofile.hard (%d) exceeds max %d — raise host fs.nr_open first", svc, n.Hard, maxNofile)
	}
	return nil
}

// validateServiceEnv checks each per-service env entry: a valid KEY, a literal with no
// `${` interpolation sequence (so a literal can't smuggle a compose variable) / no
// control chars, or a `{secret: NAME}` ref to a DECLARED secret.
func validateServiceEnv(svc string, env map[string]EnvValue, declaredSecrets map[string]bool) error {
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !envKeyRe.MatchString(k) {
			return fmt.Errorf("service %q env key %q is invalid", svc, k)
		}
		v := env[k]
		if v.Secret != "" {
			if !secretRe.MatchString(v.Secret) {
				return fmt.Errorf("service %q env %q references an invalid secret name %q", svc, k, v.Secret)
			}
			if !declaredSecrets[v.Secret] {
				return fmt.Errorf("service %q env %q references undeclared secret %q", svc, k, v.Secret)
			}
			continue
		}
		if strings.ContainsAny(v.Value, "\x00\n\r") {
			return fmt.Errorf("service %q env %q value contains a control character", svc, k)
		}
		if strings.Contains(v.Value, "${") {
			return fmt.Errorf("service %q env %q literal must not contain ${...} (use a secret reference)", svc, k)
		}
	}
	return nil
}

func validateBuild(svc string, b *Build) error {
	lang := b.Language
	if lang == "" {
		lang = "auto"
	}
	if !buildLanguages[lang] {
		return fmt.Errorf("service %q build.language %q is not supported (auto|node|python|go|ruby|php|static|generic)", svc, b.Language)
	}
	if lang == "generic" && b.Base == "" {
		return fmt.Errorf("service %q build.language generic requires build.base (the base image)", svc)
	}
	if lang != "generic" && b.Base != "" {
		return fmt.Errorf("service %q build.base is only valid with language generic", svc)
	}
	if err := validateExec("build.start", svc, b.Start); err != nil {
		return err
	}
	for k := range b.Env {
		if !envKeyRe.MatchString(k) {
			return fmt.Errorf("service %q build.env key %q is invalid", svc, k)
		}
	}
	for _, p := range b.Packages {
		if p == "" || strings.ContainsAny(p, "\x00\n ") {
			return fmt.Errorf("service %q build.packages entry %q is invalid", svc, p)
		}
	}
	if b.Output != "" {
		if err := relConfined(b.Output); err != nil {
			return fmt.Errorf("service %q build.output %q: %w", svc, b.Output, err)
		}
	}
	if b.Dir != "" {
		if err := relConfined(b.Dir); err != nil {
			return fmt.Errorf("service %q build.dir %q: %w", svc, b.Dir, err)
		}
	}
	return nil
}

// certFields are the cert files a { cert: HOSTNAME.field } binding may reference.
var certFields = map[string]bool{"crt": true, "key": true, "ca": true}

func validateConfigFile(svc string, cf ConfigFile, declaredSecrets, certHosts map[string]bool) error {
	if err := mountPath(cf.Mount); err != nil {
		return fmt.Errorf("service %q config_files mount: %w", svc, err)
	}
	hasRepo := cf.Repo != ""
	hasTmpl := cf.Template != ""
	if hasRepo == hasTmpl {
		return fmt.Errorf("service %q config_files entry must set exactly one of repo or template", svc)
	}
	if hasRepo {
		if err := relConfined(cf.Repo); err != nil {
			return fmt.Errorf("service %q config_files repo %q: %w", svc, cf.Repo, err)
		}
	}
	for k, b := range cf.Bindings {
		if !tokenKeyRe.MatchString(k) {
			return fmt.Errorf("service %q config_files binding key %q is invalid", svc, k)
		}
		if err := validateBindingSource(svc, k, b, declaredSecrets, certHosts); err != nil {
			return err
		}
	}
	return nil
}

// validateBindingSource checks one config-file binding: at most one source is set
// (UnmarshalYAML already enforces single-key mappings; this guards programmatic
// construction), and the referenced secret/env/app/cert is valid. A cert source may
// only name a cert bound on the SAME service.
func validateBindingSource(svc, key string, b Binding, declaredSecrets, certHosts map[string]bool) error {
	set := 0
	for _, v := range []string{b.Secret, b.Env, b.App, b.Cert} {
		if v != "" {
			set++
		}
	}
	if set > 1 {
		return fmt.Errorf("service %q config_files binding %q must set exactly one source", svc, key)
	}
	switch {
	case b.Secret != "":
		if !secretRe.MatchString(b.Secret) {
			return fmt.Errorf("service %q config_files binding %q references an invalid secret name %q", svc, key, b.Secret)
		}
		if !declaredSecrets[b.Secret] {
			return fmt.Errorf("service %q config_files binding %q references undeclared secret %q", svc, key, b.Secret)
		}
	case b.Env != "":
		if !envKeyRe.MatchString(b.Env) {
			return fmt.Errorf("service %q config_files binding %q references an invalid env key %q", svc, key, b.Env)
		}
	case b.App != "":
		if !validAppFields[b.App] {
			return fmt.Errorf("service %q config_files binding %q references unknown app field %q (only: slug)", svc, key, b.App)
		}
	case b.Cert != "":
		// The field is the last dot-segment (crt|key|ca); the hostname (which itself
		// contains dots) is everything before it.
		i := strings.LastIndexByte(b.Cert, '.')
		if i <= 0 || i == len(b.Cert)-1 || !certFields[b.Cert[i+1:]] {
			return fmt.Errorf("service %q config_files binding %q cert source %q must be HOSTNAME.crt|key|ca", svc, key, b.Cert)
		}
		if host := b.Cert[:i]; !certHosts[host] {
			return fmt.Errorf("service %q config_files binding %q references cert for %q, which is not a cert_binding on this service", svc, key, host)
		}
	}
	return nil
}

func validateCertBinding(svc string, cb CertBinding) error {
	if err := validateHostOrSubdomain(fmt.Sprintf("service %q cert_bindings", svc), cb.Hostname, cb.Subdomain); err != nil {
		return err
	}
	if err := mountPath(cb.Mount); err != nil {
		return fmt.Errorf("service %q cert_bindings mount: %w", svc, err)
	}
	if cb.CA != "" && !edgeCANameRe.MatchString(cb.CA) {
		return fmt.Errorf("service %q cert_bindings ca %q must match [a-z][a-z0-9-]{0,30} (a CA defined in config.yaml edge.cas)", svc, cb.CA)
	}
	return nil
}

func validateVolume(svc string, v Volume) error {
	hasName := v.Name != ""
	hasBind := v.Source != ""
	if hasName == hasBind {
		return fmt.Errorf("service %q volume must set exactly one of name or source", svc)
	}
	if v.Target == "" || !strings.HasPrefix(v.Target, "/") || strings.ContainsAny(v.Target, "\x00\n:") {
		return fmt.Errorf("service %q volume target must be an absolute container path (no ':')", svc)
	}
	if hasName {
		if !svcRe.MatchString(v.Name) {
			return fmt.Errorf("service %q volume name %q is invalid", svc, v.Name)
		}
		return nil
	}
	if strings.Contains(v.Source, ":") {
		return fmt.Errorf("service %q bind source %q must not contain ':'", svc, v.Source)
	}
	if err := relConfined(v.Source); err != nil {
		return fmt.Errorf("service %q bind source %q: %w", svc, v.Source, err)
	}
	return nil
}

func (s *Spec) validateSecrets() error {
	for _, sec := range s.Secrets {
		if !secretRe.MatchString(sec.Name) {
			return fmt.Errorf("secret name %q is invalid", sec.Name)
		}
		if sec.Generate != "" {
			if err := secretgen.Validate(sec.Generate); err != nil {
				return fmt.Errorf("secret %q: %w", sec.Name, err)
			}
			// A keypair also mints a derived public secret named <NAME>_PUB; make
			// sure that companion name is itself valid (length, grammar).
			if secretgen.IsKeypair(sec.Generate) {
				if pub := sec.Name + secretgen.PubSuffix; !secretRe.MatchString(pub) {
					return fmt.Errorf("secret %q: keypair public name %q is invalid (max 64 chars incl. %s)", sec.Name, pub, secretgen.PubSuffix)
				}
			}
		}
	}
	return nil
}

func (s *Spec) validateEdge() error {
	declared := map[string]bool{}
	for n := range s.Compose.Services {
		declared[n] = true
	}
	for _, r := range s.Edge.Routes {
		id := r.Hostname
		if id == "" {
			id = r.Subdomain
		}
		if err := validateHostOrSubdomain("edge route "+id, r.Hostname, r.Subdomain); err != nil {
			return err
		}
		if !svcRe.MatchString(r.Service) {
			return fmt.Errorf("edge route %q must name a valid service (upstream is a selector, never a literal dial target)", id)
		}
		if !declared[r.Service] {
			return fmt.Errorf("edge route %q targets unknown service %q", id, r.Service)
		}
		if r.Port != 0 && controlPort(r.Port) {
			return fmt.Errorf("edge route %q port %d is a reserved control-plane port", id, r.Port)
		}
		if r.UpstreamScheme != "" && r.UpstreamScheme != "http" && r.UpstreamScheme != "https" {
			return fmt.Errorf("edge route %q upstream_scheme %q must be http or https", id, r.UpstreamScheme)
		}
		if r.CA != "" && !edgeCANameRe.MatchString(r.CA) {
			return fmt.Errorf("edge route %q ca %q must match [a-z][a-z0-9-]{0,30} (a CA defined in config.yaml edge.cas)", id, r.CA)
		}
	}
	// L4 (TCP/UDP) routes: the LB owns each listen port, replicas stay internal.
	l4Listen := map[string]bool{} // "proto:port" dedupe
	listenPorts := map[int]bool{}
	for _, r := range s.Edge.L4Routes {
		if r.Protocol != "tcp" && r.Protocol != "udp" {
			return fmt.Errorf("edge l4_route protocol %q must be tcp or udp", r.Protocol)
		}
		if r.Listen < 1 || r.Listen > 65535 {
			return fmt.Errorf("edge l4_route listen port %d is out of range", r.Listen)
		}
		if r.Listen == 80 || r.Listen == 443 {
			return fmt.Errorf("edge l4_route listen port %d is reserved for the HTTP edge", r.Listen)
		}
		if controlPort(r.Listen) {
			return fmt.Errorf("edge l4_route listen port %d is a reserved control-plane port", r.Listen)
		}
		key := fmt.Sprintf("%s:%d", r.Protocol, r.Listen)
		if l4Listen[key] {
			return fmt.Errorf("edge l4_route listen %d/%s is declared twice", r.Listen, r.Protocol)
		}
		l4Listen[key] = true
		listenPorts[r.Listen] = true
		if !svcRe.MatchString(r.Service) {
			return fmt.Errorf("edge l4_route on %d must name a valid service", r.Listen)
		}
		if !declared[r.Service] {
			return fmt.Errorf("edge l4_route on %d targets unknown service %q", r.Listen, r.Service)
		}
		if r.Port < 1 || r.Port > 65535 || controlPort(r.Port) {
			return fmt.Errorf("edge l4_route on %d has an invalid or reserved upstream port %d", r.Listen, r.Port)
		}
		switch r.TLS {
		case "", "passthrough":
		case "terminate":
			return fmt.Errorf("edge l4_route on %d: tls: terminate is not yet supported (use passthrough)", r.Listen)
		default:
			return fmt.Errorf("edge l4_route on %d: tls %q must be passthrough", r.Listen, r.TLS)
		}
		switch r.LB {
		case "", "round_robin", "least_conn", "hash_client_ip":
		default:
			return fmt.Errorf("edge l4_route on %d: lb %q must be round_robin, least_conn, or hash_client_ip", r.Listen, r.LB)
		}
	}
	// A service may not publish a host port the L4 LB already owns (collision): the
	// LB binds it and fans to internal replicas.
	for name, svc := range s.Compose.Services {
		for _, p := range svc.Ports {
			if !p.Publish {
				continue
			}
			host := p.Internal
			if p.Published != 0 {
				host = p.Published
			}
			if listenPorts[host] {
				return fmt.Errorf("service %q publishes host port %d, which is owned by an edge l4_route", name, host)
			}
		}
	}
	return nil
}

func (s *Spec) validateSetup() error {
	if s.Setup == nil {
		return nil
	}
	autoDeploy := s.Git != nil && s.Git.AutoDeploy
	ss := sandbox.ScriptSet{Script: s.Setup.Script, Trigger: s.Setup.Trigger, Produces: s.Setup.Produces}
	if err := ss.Validate(autoDeploy); err != nil {
		return fmt.Errorf("spec.setup: %w", err)
	}
	return nil
}

func mountPath(p string) error {
	if p == "" || !strings.HasPrefix(p, "/") || strings.ContainsAny(p, "\x00\n") {
		return fmt.Errorf("must be an absolute container path")
	}
	return nil
}

func relConfined(p string) error {
	if p == "" || filepath.IsAbs(p) || p == ".." ||
		strings.HasPrefix(p, "../") || strings.Contains(p, "/../") || strings.HasSuffix(p, "/..") ||
		strings.ContainsAny(p, "\x00\n") {
		return fmt.Errorf("must be a repo-relative, traversal-free path")
	}
	return nil
}

func validateExec(field, svc string, argv []string) error {
	for _, a := range argv {
		if a == "" {
			return fmt.Errorf("service %q %s has an empty argument", svc, field)
		}
		if strings.ContainsAny(a, "\x00\n") {
			return fmt.Errorf("service %q %s argument contains a control character", svc, field)
		}
	}
	return nil
}

func controlPort(p int) bool { return p == 9000 || p == 2019 || p == 2375 }
