// Package config loads and validates /etc/mooring/config.yaml — the root of
// trust (plan §5.1). Everything here is fail-closed: any precondition violation
// returns an error and the binary refuses to boot. No web route ever reads or
// writes this file; it is edited only over SSH.
package config

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/daboss2003/mooring/internal/crypto"
	"gopkg.in/yaml.v3"
)

// edgeCANameRe constrains a named edge CA so it's a safe, referenceable identifier.
var edgeCANameRe = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)

// edgeHostnameRe validates a full DNS name (FQDN, ≥2 labels, no wildcards) — same grammar
// as the definition/edge layers use, so edge.base_domain is validated identically.
var edgeHostnameRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,62})(\.[a-z0-9]([a-z0-9-]{0,62}))+$`)

// subdomainLabelRe is a single RFC1123 DNS label (same grammar as the definition layer),
// used to validate admin.subdomain.
var subdomainLabelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// DefaultPath is where the root-of-trust config lives in production.
const DefaultPath = "/etc/mooring/config.yaml"

// EdgeMode is the managed/external switch (plan §3.1). Default managed.
type EdgeMode string

const (
	EdgeManaged  EdgeMode = "managed"
	EdgeExternal EdgeMode = "external"
)

// EditorMode gates how far the Caddy editor / compose importer may soften lints.
type EditorMode string

const (
	EditorStrict EditorMode = "strict"
	EditorReview EditorMode = "review"
)

// Config is the typed root-of-trust document. Secret-bearing fields are kept as
// plain strings here (the file itself is 0600 root:root) but are never echoed:
// String() is overridden to redact them.
type Config struct {
	BindAddr string `yaml:"bind_addr"`

	EncryptionKey         string `yaml:"encryption_key"`
	EncryptionKeyPrevious string `yaml:"encryption_key_previous"`

	IPAllowlist    []string `yaml:"ip_allowlist"`
	TrustProxy     bool     `yaml:"trust_proxy"`
	TrustedProxies []string `yaml:"trusted_proxies"`

	Auth       AuthConfig    `yaml:"auth"`
	ExtraUsers []UserConfig  `yaml:"users"` // additional operators beyond the auth owner (RBAC)
	Edge       EdgeConfig    `yaml:"edge"`
	Admin      AdminConfig   `yaml:"admin"`
	Session    SessionConfig `yaml:"session"`
	Cookie     CookieConfig  `yaml:"cookie"`
	Docker     DockerConfig  `yaml:"docker"`
	Monitor    MonitorConfig `yaml:"monitor"`
	Git        GitConfig     `yaml:"git"`
	GitHub     GitHubConfig  `yaml:"github"`

	CaddyEditor       EditorBlock     `yaml:"caddy_editor"`
	ComposeValidation EditorBlock     `yaml:"compose_validation"`
	Setup             SetupConfig     `yaml:"setup"`
	Retention         RetentionConfig `yaml:"retention"`
	Alerting          AlertingConfig  `yaml:"alerting"`
	Server            ServerConfig    `yaml:"server"`
	Backups           BackupConfig    `yaml:"backups"`

	DataDir string `yaml:"data_dir"`

	// ProtectedProjects are Compose projects Mooring must never start/stop/
	// redeploy (the socket-proxy, and later the edge) — plan §3 protected set.
	ProtectedProjects []string `yaml:"protected_projects"`

	// derived, not from YAML
	parsedAllowlist []netip.Prefix
	parsedProxies   []netip.Prefix
}

// ServerConfig configures the read-only "Server" tab (host inspection + cleanup).
// Both knobs are OPT-IN and default to off/empty: with no file_roots the file
// view is disabled entirely (fail-closed), and with no deb_cache_dir the old-.deb
// cleanup is unavailable. The host monitor (CPU/memory/disk/processes) needs no
// config. Secret/state paths (the data dir, config, keys, DB) are ALWAYS denied to
// the file view regardless of what's listed here — see internal/web.
type ServerConfig struct {
	// FileRoots are directories the operator may browse READ-ONLY in the Server
	// tab (e.g. an app's log dir). Each needs a stable name (used in the URL).
	FileRoots []ServerFileRoot `yaml:"file_roots"`
	// DebCacheDir is the directory the operator downloads Mooring .deb packages
	// into; the Server tab can delete OLD ones there (never the running version),
	// behind password+TOTP re-auth. Must be absolute. It also must be within the
	// service's writable paths for the delete to succeed (see docs).
	DebCacheDir string `yaml:"deb_cache_dir"`

	// VersionCheckEnabled controls the periodic self-update check: Mooring asks the
	// GitHub API whether a newer release exists and whether the RUNNING version is
	// affected by a published security advisory (→ a persistent banner + a CRITICAL
	// alert). It is ON by default (a *bool so "unset" means on); set it to false to
	// disable — then Mooring never contacts GitHub. When on it contacts ONLY
	// api.github.com and sends no telemetry payload.
	VersionCheckEnabled *bool `yaml:"version_check_enabled"`
	// VersionCheckInterval is how often to poll (default 6h; clamped to a 1h floor).
	VersionCheckInterval Duration `yaml:"version_check_interval"`

	// ImageScanEnabled controls periodic vulnerability scanning of each deployed app's
	// images + dependencies with Trivy (High/Critical → an alert; results on the Server
	// tab). ON by default (set false to disable). It is HEAVY — Trivy downloads a
	// vulnerability database and scanning uses CPU/RAM — so a small box may want it off.
	// The scanner never gets the Docker socket: upstream images are scanned from the
	// registry, build checkouts as a filesystem.
	ImageScanEnabled *bool `yaml:"image_scan_enabled"`
	// ImageScanInterval is how often to re-scan (default 24h; clamped to a 1h floor).
	// Re-scanning unchanged images matters — new CVEs are disclosed daily.
	ImageScanInterval Duration `yaml:"image_scan_interval"`

	// DiskGCEnabled controls disk-pressure auto-reclaim: when disk usage crosses
	// DiskGCThreshold, Mooring reclaims DANGLING docker images + build cache (the superseded
	// builds that pile up as apps redeploy) and alerts. ON by default; safe because it only
	// removes unreferenced garbage — never a tagged/in-use image, a rollback (which rebuilds),
	// or any app data volume. Set false to disable.
	DiskGCEnabled *bool `yaml:"disk_gc_enabled"`
	// DiskGCThreshold is the disk-usage percent that triggers auto-reclaim (default 75,
	// clamped to [50, 95]).
	DiskGCThreshold int `yaml:"disk_gc_threshold"`

	// BuildCacheKeepEnabled controls automatic reclamation of Docker/BuildKit build cache
	// after a build-deploy. Mooring's generated multi-stage Dockerfiles emit a unique,
	// single-use runtime layer per deploy (`COPY --from=build /app /app` + the non-root
	// chown), so the cache grows without bound; Mooring runs `docker builder prune
	// --keep-storage` to cap it — evicting the least-recently-used (stale) entries while
	// keeping recent, reusable cache (e.g. the dependency-install layer) warm. ON by
	// default (a *bool: unset = on); set false to disable — then Mooring never prunes.
	BuildCacheKeepEnabled *bool `yaml:"build_cache_keep_enabled"`
	// BuildCacheKeep is how much of the most-recently-used build cache to KEEP when pruning
	// (default "5GB"). A size like "2GB"/"512MB". Smaller = less disk, colder rebuilds.
	BuildCacheKeep string `yaml:"build_cache_keep"`
}

// VersionCheckOn reports whether the self-update check is enabled (default on).
func (s ServerConfig) VersionCheckOn() bool {
	return s.VersionCheckEnabled == nil || *s.VersionCheckEnabled
}

// ImageScanOn reports whether app vulnerability scanning is enabled (default on).
func (s ServerConfig) ImageScanOn() bool {
	return s.ImageScanEnabled == nil || *s.ImageScanEnabled
}

// DiskGCOn reports whether disk-pressure auto-reclaim is enabled (default ON). When disk
// crosses the threshold Mooring reclaims DANGLING docker images + build cache (safe garbage —
// never a tagged/in-use image or any app data) and alerts. Set false to disable.
func (s ServerConfig) DiskGCOn() bool {
	return s.DiskGCEnabled == nil || *s.DiskGCEnabled
}

// DiskGCThresholdPct is the disk-usage percentage that triggers auto-reclaim (default 75,
// clamped to [50, 95] so it can neither thrash nor wait until the disk is already full).
func (s ServerConfig) DiskGCThresholdPct() int {
	t := s.DiskGCThreshold
	if t == 0 {
		t = 75
	}
	if t < 50 {
		t = 50
	}
	if t > 95 {
		t = 95
	}
	return t
}

// BackupConfig configures scheduled, encrypted app-data backups (OPT-IN, default off). When
// Enabled, the scheduler snapshots every app's data volumes on Schedule (encrypted with the
// master key), keeps Retention snapshots per target, and — if S3 is set — also uploads each
// snapshot off-box. Credentials live HERE (operator config, the root of trust), never in an
// app repo, so a repo can never name an exfil bucket or hold keys.
type BackupConfig struct {
	Enabled     bool      `yaml:"enabled"`
	Schedule    Duration  `yaml:"schedule"`     // default 24h; clamped to a 1h floor
	Retention   int       `yaml:"retention"`    // keep N most-recent per target; default 7
	HelperImage string    `yaml:"helper_image"` // image with `tar` for volume snapshots; default below
	S3          *BackupS3 `yaml:"s3,omitempty"` // optional off-box destination
}

// BackupS3 is the optional off-box object-store destination for backups (S3/MinIO/R2/B2).
type BackupS3 struct {
	Bucket          string `yaml:"bucket"`
	Endpoint        string `yaml:"endpoint"` // host[:port], e.g. s3.us-east-1.amazonaws.com
	Region          string `yaml:"region"`
	AccessKeyID     string `yaml:"access_key_id"`
	SecretAccessKey string `yaml:"secret_access_key"`
	Prefix          string `yaml:"prefix"`     // optional key prefix, e.g. "mooring/"
	PathStyle       *bool  `yaml:"path_style"` // default true (S3-compatible endpoints)
	Insecure        bool   `yaml:"insecure"`   // allow http:// (private MinIO); default https
}

const defaultBackupHelperImage = "busybox:1.36"

// BackupsOn reports whether scheduled app-data backups are enabled (default off).
func (c *Config) BackupsOn() bool { return c.Backups.Enabled }

// BackupSchedule is the interval between backup runs (default 24h, 1h floor).
func (c *Config) BackupSchedule() time.Duration {
	d := time.Duration(c.Backups.Schedule)
	if d <= 0 {
		d = 24 * time.Hour
	}
	if d < time.Hour {
		d = time.Hour
	}
	return d
}

// BackupRetention is how many snapshots to keep per target (default 7, min 1).
func (c *Config) BackupRetention() int {
	if c.Backups.Retention <= 0 {
		return 7
	}
	return c.Backups.Retention
}

// BackupHelperImage is the image (with tar) used for volume snapshots/restores.
func (c *Config) BackupHelperImage() string {
	if strings.TrimSpace(c.Backups.HelperImage) != "" {
		return c.Backups.HelperImage
	}
	return defaultBackupHelperImage
}

// BuildCacheGCOn reports whether automatic build-cache reclamation is enabled (default on).
func (s ServerConfig) BuildCacheGCOn() bool {
	return s.BuildCacheKeepEnabled == nil || *s.BuildCacheKeepEnabled
}

// buildCacheKeepRe validates a `docker builder prune --keep-storage` size ("10GB",
// "512MB", or a raw byte count) — a defensive check so a typo can't break the prune.
// No interior whitespace: docker's size parser wants "5GB", not "5 GB", so a spaced
// value is rejected here and falls back to the default (a working prune) rather than
// reaching docker and erroring.
var buildCacheKeepRe = regexp.MustCompile(`(?i)^[0-9]+(\.[0-9]+)?(b|kb|mb|gb|tb|kib|mib|gib|tib)?$`)

// BuildCacheKeepSize returns the validated keep-storage size, defaulting to "5GB" when
// unset or malformed. It is passed as a discrete argv element (never a shell string).
func (s ServerConfig) BuildCacheKeepSize() string {
	v := strings.TrimSpace(s.BuildCacheKeep)
	if v == "" || !buildCacheKeepRe.MatchString(v) {
		return "5GB"
	}
	return v
}

// ServerFileRoot is one named, browsable directory.
type ServerFileRoot struct {
	Name string `yaml:"name"` // [a-z0-9][a-z0-9-]{0,30}; used in the URL/UI
	Path string `yaml:"path"` // absolute directory path
}

// serverRootNameRe constrains a file-root name to a safe slug (URL/UI key).
var serverRootNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,30}$`)

// validateServer checks the Server-tab config shape. Existence/containment of the
// paths is enforced at use time in internal/web (fail-closed), so this only
// rejects obviously-malformed config: bad root names, duplicates, and
// non-absolute paths.
func (c *Config) validateServer() error {
	seen := map[string]bool{}
	for _, r := range c.Server.FileRoots {
		if !serverRootNameRe.MatchString(r.Name) {
			return fmt.Errorf("server.file_roots: name %q must match [a-z0-9][a-z0-9-]{0,30}", r.Name)
		}
		if seen[r.Name] {
			return fmt.Errorf("server.file_roots: duplicate name %q", r.Name)
		}
		seen[r.Name] = true
		if !filepath.IsAbs(r.Path) {
			return fmt.Errorf("server.file_roots[%s]: path %q must be absolute", r.Name, r.Path)
		}
	}
	if c.Server.DebCacheDir != "" && !filepath.IsAbs(c.Server.DebCacheDir) {
		return fmt.Errorf("server.deb_cache_dir %q must be absolute", c.Server.DebCacheDir)
	}
	return nil
}

// IsProtectedProject reports whether a compose project is in the protected set.
func (c *Config) IsProtectedProject(project string) bool {
	for _, p := range c.ProtectedProjects {
		if p == project {
			return true
		}
	}
	return false
}

// AuthConfig holds the PRIMARY operator's credentials — always an owner. Additional operators
// go in the top-level `users:` list (see UserConfig). With no `users:`, Mooring is single-user
// exactly as before.
type AuthConfig struct {
	Username     string `yaml:"username"`
	PasswordHash string `yaml:"password_hash"`
	TOTPSecret   string `yaml:"totp_secret"`
}

// Role is an operator's authorization tier. owner does everything (deploy + all Tier-1:
// keys/reveal/setup/delete/tokens/trust); deployer can deploy, roll back, and edit an app's
// env/config/scaling; viewer is read-only.
type Role string

const (
	RoleOwner    Role = "owner"
	RoleDeployer Role = "deployer"
	RoleViewer   Role = "viewer"
)

func validRole(r Role) bool { return r == RoleOwner || r == RoleDeployer || r == RoleViewer }

// Can reports whether a role is permitted a capability tier: "view" (all roles), "deploy"
// (deployer + owner), or "admin" (owner only). Fail-closed on an unknown tier.
func (r Role) Can(perm string) bool {
	switch perm {
	case "view":
		return r == RoleViewer || r == RoleDeployer || r == RoleOwner
	case "deploy":
		return r == RoleDeployer || r == RoleOwner
	case "admin":
		return r == RoleOwner
	}
	return false
}

// UserConfig is one ADDITIONAL operator (beyond the `auth:` owner). Credentials are minted the
// same way (`mooring hash-password` / `mooring gen-totp`) and pasted under `users:`.
type UserConfig struct {
	Username     string `yaml:"username"`
	PasswordHash string `yaml:"password_hash"`
	TOTPSecret   string `yaml:"totp_secret"`
	Role         Role   `yaml:"role"`
}

// User is a resolved operator identity (the auth owner + each `users:` entry).
type User struct {
	Username     string
	PasswordHash string
	TOTPSecret   string
	Role         Role
}

// Users returns every operator: the `auth:` block as an OWNER first, then the `users:` entries.
func (c *Config) Users() []User {
	out := []User{{Username: c.Auth.Username, PasswordHash: c.Auth.PasswordHash, TOTPSecret: c.Auth.TOTPSecret, Role: RoleOwner}}
	for _, u := range c.ExtraUsers {
		out = append(out, User{Username: u.Username, PasswordHash: u.PasswordHash, TOTPSecret: u.TOTPSecret, Role: u.Role})
	}
	return out
}

// EdgeConfig configures the managed edge (plan §3.1, §6).
type EdgeConfig struct {
	Mode      EdgeMode `yaml:"mode"`
	ACMEEmail string   `yaml:"acme_email"`
	ACMECA    string   `yaml:"acme_ca"`
	CAs       []EdgeCA `yaml:"cas"` // extra named issuers (private CAs) routes/cert-bindings can opt into by name
	// BaseDomain is the namespace root for the subdomain shorthand: a route or cert_binding
	// that sets `subdomain: mqtt` (instead of a full hostname) is expanded to
	// mqtt.<base_domain> at deploy time. The operator points a SINGLE wildcard DNS record
	// (*.<base_domain> → this server) and every declared subdomain resolves. "" disables the
	// shorthand (full hostnames still work). Must be a FQDN, no wildcards.
	BaseDomain string `yaml:"base_domain"`
	// DNS01, when set, issues a single *.<base_domain> WILDCARD certificate via ACME DNS-01
	// (instead of a per-subdomain HTTP-01 cert each) — one cert for every subdomain, no
	// per-name rate limits, and it works for names that aren't HTTP-reachable. It REQUIRES a
	// caddy binary with your DNS provider's module compiled in (vanilla Caddy has none —
	// build one with xcaddy). Optional; leave unset to keep per-subdomain HTTP-01.
	DNS01 *EdgeDNS01 `yaml:"dns01,omitempty"`
	// BaseDomains are ADDITIONAL, named subdomain namespaces on top of the default base_domain
	// above. Colocated apps (e.g. prod + staging on one box) each opt into one BY NAME so both
	// can keep the `subdomain:` shorthand under their own apex without a route collision. The
	// scalar base_domain stays the DEFAULT (unnamed) namespace — this is purely additive, and
	// mirrors how the scalar acme_ca coexists with the named `cas` list. Declared ONLY here in
	// the root-of-trust config; an app references a name and can never introduce an apex.
	BaseDomains      []EdgeBaseDomain `yaml:"base_domains,omitempty"`
	ApplyProbeWindow Duration         `yaml:"apply_probe_window"`
	L4Enabled        bool             `yaml:"l4_enabled"`      // own a managed L4 (TCP/UDP) load balancer (nginx-stream)
	L4NginxDigest    string           `yaml:"l4_nginx_digest"` // pinned SHA-256 of the nginx binary (optional)
}

// EdgeBaseDomain is a NAMED subdomain namespace — an additional apex the operator declares so
// colocated apps can each use the `subdomain:` shorthand under their own root. An app (or a
// single route/cert_binding) opts in by Name; unset = the default scalar edge.base_domain.
// Declared ONLY in the root-of-trust config (an app repo must never introduce an apex). Domain
// must be a bare FQDN (no wildcards). DNS01, when set, issues a *.<Domain> wildcard cert via
// ACME DNS-01 for THIS namespace (Phase 2 wires the issuance).
type EdgeBaseDomain struct {
	Name   string     `yaml:"name"`   // [a-z][a-z0-9-]{0,30}; referenced as `base_domain: <name>`
	Domain string     `yaml:"domain"` // the apex FQDN, e.g. staging.example.com
	DNS01  *EdgeDNS01 `yaml:"dns01,omitempty"`
}

// EdgeCA is an additional ACME issuer — a private/internal CA (e.g. step-ca). A
// mooring.yaml edge route or cert binding opts into it by Name; everything else keeps
// using the default edge.acme_ca. Defined ONLY here in the root-of-trust config (an app
// repo must never be able to introduce a trusted CA).
type EdgeCA struct {
	Name         string `yaml:"name"`          // [a-z][a-z0-9-]{0,30}; referenced as `ca: <name>`
	DirectoryURL string `yaml:"directory_url"` // the ACME directory URL (https)
	Email        string `yaml:"email"`         // optional ACME contact; falls back to acme_email
	TrustedRoot  string `yaml:"trusted_root"`  // optional PEM file Caddy trusts for the CA's OWN https
}

// EdgeDNS01 configures the optional *.<base_domain> wildcard cert via ACME DNS-01. Provider
// is the Caddy DNS module name (e.g. "cloudflare", "digitalocean", "route53"); APIToken is
// the provider credential (secret-bearing — redacted, and never leaves this box except to the
// DNS provider via the caddy child). The module must be compiled into the caddy binary.
type EdgeDNS01 struct {
	Provider string `yaml:"provider"`
	APIToken string `yaml:"api_token"`
}

// dnsProviderRe constrains a Caddy DNS provider module name to a safe identifier.
var dnsProviderRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,40}$`)

// EdgeCAByName returns the configured CA with the given name.
func (c *Config) EdgeCAByName(name string) (EdgeCA, bool) {
	for _, ca := range c.Edge.CAs {
		if ca.Name == name {
			return ca, true
		}
	}
	return EdgeCA{}, false
}

// HasEdgeCA reports whether a named edge CA is configured.
func (c *Config) HasEdgeCA(name string) bool { _, ok := c.EdgeCAByName(name); return ok }

// BaseDomainByName resolves a subdomain-namespace reference to its apex + optional wildcard
// dns01. The empty name "" means the DEFAULT namespace — the scalar edge.base_domain (with the
// scalar edge.dns01). A non-empty name looks up edge.base_domains. This is the single resolver
// every subdomain-expansion site uses, so named and default namespaces behave identically.
// ok=false means the namespace isn't configured (unknown name, or "" with no base_domain set).
func (c *Config) BaseDomainByName(name string) (EdgeBaseDomain, bool) {
	// Always return a normalized (trimmed, lowercased) apex so every expansion site produces a
	// well-formed, case-consistent hostname regardless of how the operator typed the config.
	if name == "" {
		if bd := strings.ToLower(strings.TrimSpace(c.Edge.BaseDomain)); bd != "" {
			return EdgeBaseDomain{Name: "", Domain: bd, DNS01: c.Edge.DNS01}, true
		}
		return EdgeBaseDomain{}, false
	}
	for _, b := range c.Edge.BaseDomains {
		if b.Name == name {
			b.Domain = strings.ToLower(strings.TrimSpace(b.Domain))
			return b, true
		}
	}
	return EdgeBaseDomain{}, false
}

// HasBaseDomain reports whether a base_domain namespace exists (a named one, or the default
// when name is "").
func (c *Config) HasBaseDomain(name string) bool { _, ok := c.BaseDomainByName(name); return ok }

// NamespaceForHost returns the NAME of the declared namespace whose apex `host` is a single-label
// subdomain of ("" = the default base_domain), and ok=false if host is under no declared apex.
// Named namespaces are checked before the default; apexes are validated disjoint, so at most one
// matches. Used to recover which namespace an already-expanded (literal) hostname belongs to.
func (c *Config) NamespaceForHost(host string) (string, bool) {
	h := strings.ToLower(strings.TrimSpace(host))
	for _, b := range c.Edge.BaseDomains {
		if oneLabelUnder(h, strings.ToLower(strings.TrimSpace(b.Domain))) {
			return b.Name, true
		}
	}
	if bd := strings.ToLower(strings.TrimSpace(c.Edge.BaseDomain)); bd != "" && oneLabelUnder(h, bd) {
		return "", true
	}
	return "", false
}

// oneLabelUnder reports whether host is EXACTLY one DNS label below apex (foo.apex, not the apex
// itself nor a.b.apex) — the same coverage rule as a *.apex wildcard.
func oneLabelUnder(host, apex string) bool {
	if apex == "" {
		return false
	}
	suffix := "." + apex
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	label := host[:len(host)-len(suffix)]
	return label != "" && !strings.Contains(label, ".")
}

// AdminConfig optionally fronts the admin UI through the edge and points at the
// Caddy admin endpoint (plan §6.1 SBD-1/SBD-2).
type AdminConfig struct {
	Hostname string `yaml:"hostname"`
	Listen   string `yaml:"listen"`
	// Subdomain is the shorthand for exposing the dashboard through the managed edge at
	// <subdomain>.<edge.base_domain> (e.g. admin → admin.mooring.example.com). Set EITHER
	// this (with edge.base_domain) or the full Hostname above. Empty = admin stays
	// loopback-only (the default; reach it over an SSH tunnel).
	Subdomain string `yaml:"subdomain"`
	// EdgeListen is a SECOND, dedicated loopback listener the managed edge proxies the
	// admin vhost to (default 127.0.0.1:9001). It is separate from bind_addr (the
	// SSH-tunnel listener) precisely so the two access paths carry different trust: the
	// edge listener REQUIRES an X-Forwarded-For from the edge and re-gates the REAL client
	// against ip_allowlist, while the tunnel keeps peer-allowlisting. Loopback-only.
	EdgeListen string `yaml:"edge_listen"`
}

// AdminHostnameResolved returns the public hostname the dashboard is exposed at through the
// managed edge, or "" when it stays loopback-only. An explicit admin.hostname wins; otherwise
// admin.subdomain is expanded against edge.base_domain.
func (c *Config) AdminHostnameResolved() string {
	if h := strings.TrimSpace(c.Admin.Hostname); h != "" {
		return h
	}
	if sub := strings.TrimSpace(c.Admin.Subdomain); sub != "" {
		if base := strings.TrimSpace(c.Edge.BaseDomain); base != "" {
			return sub + "." + base
		}
	}
	return ""
}

// AdminExposed reports whether the dashboard is fronted publicly by the managed edge.
func (c *Config) AdminExposed() bool { return c.AdminHostnameResolved() != "" }

// AdminEdgeListen is the second loopback listener the edge dials for the admin vhost.
func (c *Config) AdminEdgeListen() string {
	if l := strings.TrimSpace(c.Admin.EdgeListen); l != "" {
		return l
	}
	return "127.0.0.1:9001"
}

// DockerConfig points at the read-only docker-socket-proxy (plan §3). Mooring
// NEVER talks to the raw socket; ProxyAddr must be a loopback endpoint.
//
// By default Mooring MANAGES this proxy itself: at boot it brings up the embedded,
// Mooring-owned read-only proxy compose so the operator never runs a docker command
// (they only ever write mooring.yaml). Set external_proxy: true if you run your own
// proxy/endpoint at proxy_addr and want Mooring to leave it alone.
type DockerConfig struct {
	ProxyAddr     string `yaml:"proxy_addr"`
	ExternalProxy bool   `yaml:"external_proxy"`
	// WritePlaneMinMB overrides the §0 write-plane resource floor (checked against RAM + swap). 0 =
	// the built-in default (1000 MB). Lower it to run the write plane on a smaller box at your own
	// risk — on-box image builds still need real headroom, but pull-image deploys and lifecycle
	// actions are cheap. A negative/absurd value is ignored.
	WritePlaneMinMB int `yaml:"write_plane_min_mb"`
}

// WritePlaneFloorBytes returns the operator's write-plane floor override in bytes, or 0 to use the
// built-in default. A non-positive value means "unset".
func (d DockerConfig) WritePlaneFloorBytes() uint64 {
	if d.WritePlaneMinMB <= 0 {
		return 0
	}
	return uint64(d.WritePlaneMinMB) << 20
}

// MonitorConfig tunes the read-plane poller (plan §4 read plane).
type MonitorConfig struct {
	PollInterval     Duration `yaml:"poll_interval"`
	MetricsRetention Duration `yaml:"metrics_retention"`
}

// GitConfig tunes the connected-repo auto-fetch poller. So a repo connected in the
// dashboard "just works" with no webhook setup, Mooring fetches every connected repo
// on this cadence — READ-PLANE ONLY: the poller never deploys, it just surfaces an
// "update available" the operator then deploys with a click. (Push-to-deploy stays an
// explicit opt-in via the webhook + auto_deploy, never the background poller.)
//
// PollInterval is a pointer so an omitted key (nil → the 2 min default) is
// distinguishable from an explicit "poll_interval: 0" (disables polling). A negative
// value also disables.
type GitConfig struct {
	PollInterval *Duration `yaml:"poll_interval"`
}

// PollIntervalD returns the effective poll interval (0 when disabled / unset).
func (g GitConfig) PollIntervalD() time.Duration {
	if g.PollInterval == nil {
		return 0
	}
	return g.PollInterval.D()
}

// GitHubConfig holds the optional "Connect with GitHub" OAuth App credentials. The
// operator registers an OAuth App once in their GitHub settings and pastes the id +
// secret here (install-time, SSH — never a browser). When both are set, the dashboard
// offers one-click repo connect (pick a repo; Mooring installs a read-only deploy key
// for it — no key pasting). Empty = the feature is simply off.
type GitHubConfig struct {
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
}

// Enabled reports whether GitHub connect is configured.
func (g GitHubConfig) Enabled() bool { return g.ClientID != "" && g.ClientSecret != "" }

// SessionConfig holds idle/absolute timeouts (plan §5.3).
type SessionConfig struct {
	IdleTimeout     Duration `yaml:"idle_timeout"`
	AbsoluteTimeout Duration `yaml:"absolute_timeout"`
}

// CookieConfig selects the session cookie prefix model (plan §5.3). __Host-
// mandates Path=/ and no base path; __Secure- pairs with a base_path.
type CookieConfig struct {
	Prefix   string `yaml:"prefix"`    // "__Host-" (default) or "__Secure-"
	BasePath string `yaml:"base_path"` // required iff prefix is __Secure-
}

// EditorBlock is the strict|review knob shared by the Caddy editor and the
// compose importer.
type EditorBlock struct {
	Mode EditorMode `yaml:"mode"`
}

// SetupConfig gates the Mode-3 setup-script sandbox (plan §7/§9, OFF by default,
// hard-gated). When enabled, scripts run in a throwaway jail with the limits
// below; the binary refuses to boot if the host can't provide a working sandbox
// (plan §5.1), and a live self-test runs before EVERY execution.
type SetupConfig struct {
	Enabled bool `yaml:"enabled"`
	// Image is the digest-pinned jail base image (the throwaway container backend).
	Image string `yaml:"image"`
	// Resource limits — counted against the global one-docker-child semaphore.
	WallClock   Duration `yaml:"wall_clock"`    // hard wall-clock timeout
	CPUs        string   `yaml:"cpus"`          // docker --cpus value, e.g. "1.0"
	MemoryMB    int      `yaml:"memory_mb"`     // hard memory cap (MemorySwapMax=0)
	PidsLimit   int      `yaml:"pids_limit"`    // max processes
	ScratchMB   int      `yaml:"scratch_mb"`    // writable scratch quota
	OutputCapKB int      `yaml:"output_cap_kb"` // captured stdout/stderr cap
}

// AlertingConfig is the Tier-1 tuning for the read-and-notify alert engine (plan
// §8). Channels + rules are operator-managed in the DB; this only tunes the
// engine. Off by default (no engine goroutines run unless enabled).
type AlertingConfig struct {
	Enabled           bool     `yaml:"enabled"`
	EvalInterval      Duration `yaml:"eval_interval"`       // evaluator tick
	NotifyMinInterval Duration `yaml:"notify_min_interval"` // global rate limit between sends
	QuietStartHour    int      `yaml:"quiet_start_hour"`    // [0..23], -1 disables (suppresses WARNING; CRITICAL always pages)
	QuietEndHour      int      `yaml:"quiet_end_hour"`
	DeadMansURL       string   `yaml:"dead_mans_url"` // outbound heartbeat to an external cron-monitor
	DeadMansInterval  Duration `yaml:"dead_mans_interval"`
	// (The "open in dashboard" link in notifications is derived from admin.hostname —
	// no separate admin_url is needed.)
}

// RetentionConfig is the Tier-1 (SSH-only, SIGHUP-reloadable) audit-retention
// block (plan §16.1). It bounds the events/audit table so it can never become
// the disk-wedge that kills the write plane — while NEVER silently dropping a
// security row (those are archived to NDJSON first, fail-closed).
type RetentionConfig struct {
	Interval      Duration `yaml:"interval"`        // how often the retention pass runs
	EventsMaxAge  Duration `yaml:"events_max_age"`  // audit rows older than this are prunable
	EventsMaxRows int      `yaml:"events_max_rows"` // hard cap on audit rows (oldest trimmed)
	ArchiveMaxMB  int      `yaml:"archive_max_mb"`  // rotate the security-archive NDJSON past this
}

// String redacts the secret-bearing fields so a Config can never be logged in
// the clear (plan §5.5 / §15 lint).
func (c Config) String() string {
	return fmt.Sprintf("config.Config{BindAddr:%q, EncryptionKey:%s, Auth.Username:%q, Edge.Mode:%q}",
		c.BindAddr, redact(c.EncryptionKey), c.Auth.Username, c.Edge.Mode)
}

func redact(s string) string {
	if s == "" {
		return `""`
	}
	return `"••••"`
}

// Duration is a yaml-friendly time.Duration ("20s", "30m", "12h").
type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

// D returns the value as a time.Duration.
func (d Duration) D() time.Duration { return time.Duration(d) }

func applyDefaults(c *Config) {
	if c.BindAddr == "" {
		c.BindAddr = "127.0.0.1:9000"
	}
	if c.Edge.Mode == "" {
		c.Edge.Mode = EdgeManaged
	}
	if c.Edge.ApplyProbeWindow == 0 {
		c.Edge.ApplyProbeWindow = Duration(20 * time.Second)
	}
	if c.Session.IdleTimeout == 0 {
		// 10m: the dashboard only sends its keepalive (and live polls) WHILE focused, so a
		// focused operator never idles out, but a dashboard left unfocused/abandoned logs
		// out after 10m. Override via session.idle_timeout. The absolute cap below is the
		// hard ceiling regardless of activity.
		c.Session.IdleTimeout = Duration(10 * time.Minute)
	}
	if c.Session.AbsoluteTimeout == 0 {
		c.Session.AbsoluteTimeout = Duration(12 * time.Hour)
	}
	if c.Cookie.Prefix == "" {
		c.Cookie.Prefix = "__Host-"
	}
	if c.CaddyEditor.Mode == "" {
		c.CaddyEditor.Mode = EditorStrict
	}
	if c.ComposeValidation.Mode == "" {
		c.ComposeValidation.Mode = EditorStrict
	}
	if c.DataDir == "" {
		c.DataDir = "/var/lib/mooring"
	}
	if c.Docker.ProxyAddr == "" {
		c.Docker.ProxyAddr = "127.0.0.1:2375"
	}
	if c.Monitor.PollInterval == 0 {
		c.Monitor.PollInterval = Duration(10 * time.Second)
	}
	if c.Monitor.MetricsRetention == 0 {
		c.Monitor.MetricsRetention = Duration(7 * 24 * time.Hour)
	}
	if c.Git.PollInterval == nil {
		// Turnkey default (key omitted): connected repos are auto-FETCHED every 2 min
		// so a repo connected in the dashboard "just works" with no webhook. An
		// explicit "poll_interval: 0" (or a negative value) disables polling.
		d := Duration(2 * time.Minute)
		c.Git.PollInterval = &d
	}
	if c.Retention.Interval == 0 {
		c.Retention.Interval = Duration(6 * time.Hour)
	}
	if c.Retention.EventsMaxAge == 0 {
		c.Retention.EventsMaxAge = Duration(365 * 24 * time.Hour)
	}
	if c.Retention.EventsMaxRows == 0 {
		c.Retention.EventsMaxRows = 200_000
	}
	if c.Retention.ArchiveMaxMB == 0 {
		c.Retention.ArchiveMaxMB = 64
	}
	// Alerting engine defaults (only meaningful when alerting.enabled).
	if c.Alerting.EvalInterval == 0 {
		c.Alerting.EvalInterval = Duration(30 * time.Second)
	}
	if c.Alerting.NotifyMinInterval == 0 {
		c.Alerting.NotifyMinInterval = Duration(5 * time.Second)
	}
	if c.Alerting.QuietStartHour == 0 && c.Alerting.QuietEndHour == 0 {
		c.Alerting.QuietStartHour, c.Alerting.QuietEndHour = -1, -1 // disabled
	}
	if c.Alerting.DeadMansInterval == 0 {
		c.Alerting.DeadMansInterval = Duration(5 * time.Minute)
	}

	// Setup-sandbox defaults (only meaningful when setup.enabled).
	if c.Setup.WallClock == 0 {
		c.Setup.WallClock = Duration(5 * time.Minute)
	}
	if c.Setup.CPUs == "" {
		c.Setup.CPUs = "1.0"
	}
	if c.Setup.MemoryMB == 0 {
		c.Setup.MemoryMB = 512
	}
	if c.Setup.PidsLimit == 0 {
		c.Setup.PidsLimit = 256
	}
	if c.Setup.ScratchMB == 0 {
		c.Setup.ScratchMB = 512
	}
	if c.Setup.OutputCapKB == 0 {
		c.Setup.OutputCapKB = 256
	}
}

// Load reads, parses, and fully validates the config at path. It is the only
// entry point; a returned error means refuse-to-boot.
func Load(path string) (*Config, error) {
	if err := checkPerms(path); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	return Parse(raw)
}

// Parse decodes and validates config bytes (used by Load and by tests). Unknown
// keys are a hard error so a typo or smuggled key cannot slip through.
func Parse(raw []byte) (*Config, error) {
	c := &Config{}
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("config: parse: %w", err)
	}
	applyDefaults(c)
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// DevInsecurePermsEnv, when set to a truthy value, relaxes the config-file
// ownership/permission enforcement for LOCAL DEVELOPMENT only. It is read from
// the environment (never from the config file itself) so the file can never
// disable its own root-of-trust checks (review #6).
const DevInsecurePermsEnv = "MOORING_DEV_INSECURE_PERMS"

func devInsecurePerms() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(DevInsecurePermsEnv)))
	return v == "1" || v == "true" || v == "yes"
}

// checkPerms enforces the root-of-trust file invariants (plan §5.1; reviews
// #2/#8): no world access; no group write/exec; owned by root (uid 0); and if
// group-readable (the supported 0640 root:<service-group> deploy), the group
// must be the running process's own group. The ownership half is skipped only
// when the dev escape hatch env var is set.
func checkPerms(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("config: stat %s: %w", path, err)
	}
	perm := fi.Mode().Perm()
	if perm&0o007 != 0 {
		return fmt.Errorf("config: %s must not be world-accessible; got %#o", path, perm)
	}
	if perm&0o030 != 0 {
		return fmt.Errorf("config: %s must not be group-writable/executable (use 0600 or 0640); got %#o", path, perm)
	}
	if devInsecurePerms() {
		return nil
	}
	uid, gid, ok := fileOwner(fi)
	if !ok {
		// Non-unix or owner unknown: fail closed unless the dev hatch is set.
		return fmt.Errorf("config: cannot determine owner of %s (set %s=1 for local dev)", path, DevInsecurePermsEnv)
	}
	if uid != 0 {
		return fmt.Errorf("config: %s must be owned by root (uid 0); got uid %d (set %s=1 for local dev)", path, uid, DevInsecurePermsEnv)
	}
	// If the group can read (0640), the group must be the service's own group so
	// only the service account — not an arbitrary group — can read the master key.
	// Skip this when running as ROOT (euid 0): root reads regardless of group, and a
	// root tool (e.g. `sudo mooring doctor`) is not the service, so os.Getgid() is the
	// invoking shell's group, not the service's — comparing to it false-alarms. `serve`
	// runs non-root as the service, so it still enforces this (the real chokepoint).
	if perm&0o040 != 0 && gid != 0 && os.Geteuid() != 0 && gid != uint32(os.Getgid()) {
		return fmt.Errorf("config: %s is group-readable by gid %d, not the service group %d", path, gid, os.Getgid())
	}
	return nil
}

// Validate runs every fail-closed boot check. All violations are collected so a
// misconfigured operator sees them at once; any violation refuses boot.
func (c *Config) Validate() error {
	var errs []string
	add := func(format string, a ...any) { errs = append(errs, fmt.Sprintf(format, a...)) }

	// --- encryption key ---
	if key, err := DecodeKey(c.EncryptionKey); err != nil {
		add("encryption_key: %v", err)
	} else if len(key) != 32 {
		add("encryption_key: must be 32 bytes (AES-256) after base64-decode; got %d", len(key))
	}
	if c.EncryptionKeyPrevious != "" {
		if key, err := DecodeKey(c.EncryptionKeyPrevious); err != nil {
			add("encryption_key_previous: %v", err)
		} else if len(key) != 32 {
			add("encryption_key_previous: must be 32 bytes; got %d", len(key))
		}
	}

	// --- IP allowlist: empty = deny-all, refused at boot (plan §5.1/§5.2) ---
	if len(c.IPAllowlist) == 0 {
		add("ip_allowlist: empty (this is deny-all and would lock you out); set at least one CIDR")
	} else {
		for _, s := range c.IPAllowlist {
			p, err := parsePrefix(s)
			if err != nil {
				add("ip_allowlist: %v", err)
				continue
			}
			c.parsedAllowlist = append(c.parsedAllowlist, p)
		}
	}

	// --- trusted proxies: only validated/required when trust_proxy is on ---
	if c.TrustProxy {
		if len(c.TrustedProxies) == 0 {
			add("trust_proxy is on but trusted_proxies is empty (would trust a spoofed XFF from anyone)")
		}
		for _, s := range c.TrustedProxies {
			p, err := parsePrefix(s)
			if err != nil {
				add("trusted_proxies: %v", err)
				continue
			}
			if tooBroad(p) {
				add("trusted_proxies: %s is too broad; must be a specific proxy IP (>= /24 for IPv4, never a bridge CIDR)", s)
				continue
			}
			c.parsedProxies = append(c.parsedProxies, p)
		}
		// The edge proxy must never also be in the allowlist (review #15): a
		// trusted-proxy peer with a missing/forged XFF falls back to being treated
		// as the peer, and the allowlist must then reject it. Overlap would admit
		// edge-sourced requests that present no valid client identity.
		for _, pp := range c.parsedProxies {
			for _, ap := range c.parsedAllowlist {
				if pp.Overlaps(ap) {
					add("trusted_proxies %s overlaps ip_allowlist %s; the edge proxy must never be in the allowlist", pp, ap)
				}
			}
		}
	} else if len(c.TrustedProxies) > 0 {
		add("trusted_proxies is set but trust_proxy is off (ambiguous; enable trust_proxy or remove the list)")
	}

	// --- auth ---
	if c.Auth.Username == "" {
		add("auth.username: required")
	}
	if c.Auth.PasswordHash == "" {
		add("auth.password_hash: required (run `mooring hash-password`)")
	} else if _, _, _, err := crypto.ParseArgon2(c.Auth.PasswordHash); err != nil {
		add("auth.password_hash: %v", err)
	}
	if c.Auth.TOTPSecret != "" && !validBase32(c.Auth.TOTPSecret) {
		add("auth.totp_secret: not valid base32 (run `mooring gen-totp`)")
	}

	// --- additional users (RBAC) ---
	// Login timing-parity uses ONE dummy hash built from the owner's argon2 params, so a username
	// miss costs the same as the owner. If a real user were hashed at a DIFFERENT cost, its verify
	// latency would differ from the dummy and make that username enumerable — so require every
	// user's argon2 params (memory/time/parallelism) to match the owner's.
	ownerParams, _, _, ownerParamErr := crypto.ParseArgon2(c.Auth.PasswordHash)
	seenUser := map[string]bool{c.Auth.Username: true}
	for i, u := range c.ExtraUsers {
		if u.Username == "" {
			add("users[%d].username: required", i)
			continue
		}
		if seenUser[u.Username] {
			add("users[%d]: duplicate username %q (already the auth owner or another user)", i, u.Username)
		}
		seenUser[u.Username] = true
		if u.PasswordHash == "" {
			add("users[%d] (%s): password_hash required (run `mooring hash-password`)", i, u.Username)
		} else if p, _, _, err := crypto.ParseArgon2(u.PasswordHash); err != nil {
			add("users[%d] (%s).password_hash: %v", i, u.Username, err)
		} else if ownerParamErr == nil && (p.Memory != ownerParams.Memory || p.Time != ownerParams.Time || p.Parallelism != ownerParams.Parallelism) {
			add("users[%d] (%s).password_hash: argon2 cost (memory/time/parallelism) must match the auth owner's — hash all users with the same `mooring hash-password` settings", i, u.Username)
		}
		if u.TOTPSecret != "" && !validBase32(u.TOTPSecret) {
			add("users[%d] (%s).totp_secret: not valid base32", i, u.Username)
		}
		if !validRole(u.Role) {
			add("users[%d] (%s).role: must be owner, deployer, or viewer", i, u.Username)
		}
	}

	// --- bind address: admin UI binds loopback only (plan §3) ---
	if !isLoopbackBind(c.BindAddr) {
		add("bind_addr: must bind loopback only (127.0.0.1 / [::1]); the edge fronts the public ports, got %q", c.BindAddr)
	}

	// --- edge mode ---
	switch c.Edge.Mode {
	case EdgeManaged:
		if strings.TrimSpace(c.Edge.ACMEEmail) == "" {
			add("edge.acme_email: required in managed mode (ACME contact); fail-closed")
		}
		if strings.TrimSpace(c.Edge.ACMECA) == "" {
			add("edge.acme_ca: required in managed mode (pin a single ACME issuer)")
		}
		if bd := strings.TrimSpace(c.Edge.BaseDomain); bd != "" && (len(bd) > 253 || !edgeHostnameRe.MatchString(bd)) {
			add("edge.base_domain %q must be a valid FQDN with no wildcards (e.g. mooring.example.com)", bd)
		}
		if d := c.Edge.DNS01; d != nil {
			if strings.TrimSpace(c.Edge.BaseDomain) == "" {
				add("edge.dns01 (wildcard cert) requires edge.base_domain")
			}
			if !dnsProviderRe.MatchString(strings.TrimSpace(d.Provider)) {
				add("edge.dns01.provider %q must be a caddy DNS module name [a-z0-9._-] (e.g. cloudflare)", d.Provider)
			}
			if strings.TrimSpace(d.APIToken) == "" {
				add("edge.dns01.api_token is required for the DNS-01 wildcard cert")
			}
		}
	case EdgeExternal:
		// Stronger fail-closed boot for external mode (plan §3.1): must have a
		// specific edge proxy in trusted_proxies. NOTE: the off-loopback :9000
		// reachability probe the plan also mandates for external mode is part of
		// the managed-edge milestone (M11) and is NOT yet implemented; the
		// loopback-only bind_addr check below is the in-scope guarantee today.
		if !c.TrustProxy || len(c.parsedProxies) == 0 {
			add("edge.mode external requires trust_proxy + a specific trusted_proxies edge IP (<= /24)")
		}
	default:
		add("edge.mode: must be %q or %q, got %q", EdgeManaged, EdgeExternal, c.Edge.Mode)
	}

	// --- extra edge CAs (private issuers) ---
	seenCA := map[string]bool{}
	for i, ca := range c.Edge.CAs {
		if !edgeCANameRe.MatchString(ca.Name) {
			add("edge.cas[%d].name: must match [a-z][a-z0-9-]{0,30} (got %q)", i, ca.Name)
		}
		if seenCA[ca.Name] {
			add("edge.cas: duplicate CA name %q", ca.Name)
		}
		seenCA[ca.Name] = true
		if !strings.HasPrefix(strings.TrimSpace(ca.DirectoryURL), "https://") {
			add("edge.cas[%d] (%s): directory_url must be an https ACME directory URL", i, ca.Name)
		}
		if ca.TrustedRoot != "" {
			if b, err := os.ReadFile(ca.TrustedRoot); err != nil {
				add("edge.cas[%d] (%s): trusted_root %q is not readable: %v", i, ca.Name, ca.TrustedRoot, err)
			} else if !bytes.Contains(b, []byte("BEGIN CERTIFICATE")) {
				add("edge.cas[%d] (%s): trusted_root %q is not a PEM certificate", i, ca.Name, ca.TrustedRoot)
			}
		}
	}

	// --- extra named base_domains (additional subdomain namespaces) ---
	// Names must be unique and grammatical; domains must be disjoint apexes (no exact dupes and
	// no nesting) — overlapping apexes would make wildcard coverage and subject grouping
	// ambiguous. The default scalar base_domain participates in the disjointness check so a
	// named namespace can't shadow it.
	seenBD := map[string]bool{}
	seenBDDomain := map[string]string{} // lowercased domain -> owning namespace label (for error text)
	if bd := strings.ToLower(strings.TrimSpace(c.Edge.BaseDomain)); bd != "" {
		seenBDDomain[bd] = "edge.base_domain"
	}
	for i, b := range c.Edge.BaseDomains {
		if !edgeCANameRe.MatchString(b.Name) {
			add("edge.base_domains[%d].name: must match [a-z][a-z0-9-]{0,30} (got %q)", i, b.Name)
		}
		if seenBD[b.Name] {
			add("edge.base_domains: duplicate name %q", b.Name)
		}
		seenBD[b.Name] = true
		// Validate the raw (trimmed, NOT lowercased) domain against the lowercase-only FQDN
		// grammar — same as the scalar base_domain at line ~966 — so an uppercase apex is
		// rejected here rather than silently lowercased. The lowercased `dom` is used only for
		// the disjointness/overlap check below (and BaseDomainByName normalizes at use).
		rawDom := strings.TrimSpace(b.Domain)
		dom := strings.ToLower(rawDom)
		if rawDom == "" || len(rawDom) > 253 || !edgeHostnameRe.MatchString(rawDom) {
			add("edge.base_domains[%d] (%s): domain %q must be a valid lowercase FQDN with no wildcards (e.g. staging.example.com)", i, b.Name, b.Domain)
		} else {
			for other, owner := range seenBDDomain {
				switch {
				case dom == other:
					add("edge.base_domains[%d] (%s): domain %q duplicates %s — namespaces must be distinct", i, b.Name, b.Domain, owner)
				case strings.HasSuffix(dom, "."+other) || strings.HasSuffix(other, "."+dom):
					add("edge.base_domains[%d] (%s): domain %q nests with %s (%s) — namespaces must be disjoint apexes", i, b.Name, b.Domain, owner, other)
				}
			}
			seenBDDomain[dom] = fmt.Sprintf("edge.base_domains[%d] (%s)", i, b.Name)
		}
		if d := b.DNS01; d != nil {
			if !dnsProviderRe.MatchString(strings.TrimSpace(d.Provider)) {
				add("edge.base_domains[%d] (%s): dns01.provider %q must be a caddy DNS module name [a-z0-9._-] (e.g. cloudflare)", i, b.Name, d.Provider)
			}
			if strings.TrimSpace(d.APIToken) == "" {
				add("edge.base_domains[%d] (%s): dns01.api_token is required for the wildcard cert", i, b.Name)
			}
		}
	}

	// --- admin.listen, when set, must never be routable ---
	if c.Admin.Listen != "" && !adminListenSafe(c.Admin.Listen) {
		add("admin.listen: must be a unix socket (unix//...) or 127.0.0.1:2019, never routable; got %q", c.Admin.Listen)
	}

	// --- exposing the admin dashboard through the managed edge (fail-closed) ---
	if c.Admin.Subdomain != "" && c.Admin.Hostname != "" {
		add("admin: set admin.hostname OR admin.subdomain, not both")
	}
	if c.Admin.Subdomain != "" && !subdomainLabelRe.MatchString(c.Admin.Subdomain) {
		add("admin.subdomain %q must be a single DNS label [a-z0-9-] (it becomes <subdomain>.<edge.base_domain>)", c.Admin.Subdomain)
	}
	if c.Admin.Subdomain != "" && strings.TrimSpace(c.Edge.BaseDomain) == "" {
		add("admin.subdomain needs edge.base_domain set")
	}
	if c.AdminExposed() {
		if c.Edge.Mode != EdgeManaged {
			add("exposing the admin dashboard (admin.hostname/admin.subdomain) requires edge.mode: managed")
		}
		h := c.AdminHostnameResolved()
		if len(h) > 253 || !edgeHostnameRe.MatchString(h) {
			add("admin hostname %q is not a valid FQDN", h)
		}
		// Admin must never sit on a namespace APEX (the default base_domain OR any named
		// base_domains apex): the admin plane sends HSTS includeSubDomains, so an apex admin
		// would pin every app subdomain under that namespace, and the *.<apex> wildcard doesn't
		// even cover the apex (cert divergence). Case-insensitive.
		if h != "" && strings.EqualFold(h, strings.TrimSpace(c.Edge.BaseDomain)) {
			add("admin must be a subdomain (e.g. admin.%s), not the base_domain apex — apex HSTS would pin every app subdomain", c.Edge.BaseDomain)
		}
		for _, b := range c.Edge.BaseDomains {
			if h != "" && strings.EqualFold(h, strings.TrimSpace(b.Domain)) {
				add("admin must be a subdomain, not the %q namespace apex %q — apex HSTS would pin every app subdomain under it", b.Name, b.Domain)
			}
		}
		if !isLoopbackBind(c.AdminEdgeListen()) {
			add("admin.edge_listen %q must be loopback (127.0.0.1:PORT), never routable", c.AdminEdgeListen())
		}
		if c.AdminEdgeListen() == strings.TrimSpace(c.BindAddr) {
			add("admin.edge_listen must differ from bind_addr (%s) — they are two separate listeners", c.BindAddr)
		}
		// The IP allowlist becomes the edge's public gate for the admin vhost — a
		// catch-all would put the login on the open internet (behind password+TOTP only).
		for _, p := range c.parsedAllowlist {
			if p.Bits() == 0 {
				add("admin exposure with a catch-all ip_allowlist (%s) puts the login on the open internet — restrict ip_allowlist to your networks", p)
				break
			}
		}
	}

	// --- cookie model coherence (plan §5.3) ---
	switch c.Cookie.Prefix {
	case "__Host-":
		if c.Cookie.BasePath != "" && c.Cookie.BasePath != "/" {
			add("cookie.prefix __Host- forbids a base_path other than \"/\"")
		}
	case "__Secure-":
		if c.Cookie.BasePath == "" {
			add("cookie.prefix __Secure- requires cookie.base_path")
		}
	default:
		add("cookie.prefix: must be __Host- or __Secure-, got %q", c.Cookie.Prefix)
	}

	// --- docker proxy: must be a loopback endpoint (never the raw/remote socket) ---
	if !isLoopbackBind(c.Docker.ProxyAddr) {
		add("docker.proxy_addr: must be a loopback host:port (the read-only socket-proxy), got %q", c.Docker.ProxyAddr)
	}

	// --- editor modes ---
	if c.CaddyEditor.Mode != EditorStrict && c.CaddyEditor.Mode != EditorReview {
		add("caddy_editor.mode: must be strict or review")
	}
	if c.ComposeValidation.Mode != EditorStrict && c.ComposeValidation.Mode != EditorReview {
		add("compose_validation.mode: must be strict or review")
	}

	// --- setup sandbox (Mode 3; plan §7/§9, hard-gated) ---
	if c.Setup.Enabled {
		// A digest-pinned jail image is mandatory (no mutable :tag for the thing
		// that runs hostile scripts).
		if !strings.Contains(c.Setup.Image, "@sha256:") {
			add("setup.image: must be digest-pinned (name@sha256:...) when setup.enabled")
		}
		if c.Setup.WallClock.D() < time.Second || c.Setup.WallClock.D() > time.Hour {
			add("setup.wall_clock: must be between 1s and 1h")
		}
		if c.Setup.MemoryMB < 16 || c.Setup.MemoryMB > 8192 {
			add("setup.memory_mb: must be between 16 and 8192")
		}
		if c.Setup.PidsLimit < 1 || c.Setup.PidsLimit > 4096 {
			add("setup.pids_limit: must be between 1 and 4096")
		}
		if c.Setup.ScratchMB < 1 {
			add("setup.scratch_mb: must be >= 1")
		}
		if c.Setup.OutputCapKB < 1 {
			add("setup.output_cap_kb: must be >= 1")
		}
	}

	// --- retention (Tier-1; plan §16.1) ---
	if c.Retention.Interval.D() < time.Minute {
		add("retention.interval: must be >= 1m (got %s)", c.Retention.Interval.D())
	}
	if c.Retention.EventsMaxAge.D() < 24*time.Hour {
		add("retention.events_max_age: must be >= 24h so audit history is not lost (got %s)", c.Retention.EventsMaxAge.D())
	}
	if c.Retention.EventsMaxRows < 1000 {
		add("retention.events_max_rows: must be >= 1000 (got %d)", c.Retention.EventsMaxRows)
	}
	if c.Retention.ArchiveMaxMB < 1 {
		add("retention.archive_max_mb: must be >= 1 (got %d)", c.Retention.ArchiveMaxMB)
	}

	// --- Server tab (read-only host inspection + .deb cleanup) ---
	if err := c.validateServer(); err != nil {
		add("%v", err)
	}

	// --- Scheduled app-data backups (opt-in) ---
	if c.Backups.Enabled {
		if len(c.EncryptionKey) == 0 {
			add("backups.enabled requires encryption_key (snapshots are AES-256 encrypted)")
		}
		if s := c.Backups.S3; s != nil {
			if strings.TrimSpace(s.Bucket) == "" {
				add("backups.s3.bucket is required when backups.s3 is set")
			}
			if strings.TrimSpace(s.Region) == "" {
				add("backups.s3.region is required when backups.s3 is set")
			}
			if strings.TrimSpace(s.Endpoint) == "" {
				add("backups.s3.endpoint is required when backups.s3 is set (e.g. s3.us-east-1.amazonaws.com)")
			}
			if strings.TrimSpace(s.AccessKeyID) == "" || strings.TrimSpace(s.SecretAccessKey) == "" {
				add("backups.s3 requires access_key_id and secret_access_key")
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("config: refusing to boot:\n  - %s", strings.Join(errs, "\n  - "))
	}
	return nil
}

// Allowlist returns the parsed allowlist prefixes (valid after Validate).
func (c *Config) Allowlist() []netip.Prefix { return c.parsedAllowlist }

// TrustedProxyPrefixes returns the parsed trusted-proxy prefixes.
func (c *Config) TrustedProxyPrefixes() []netip.Prefix { return c.parsedProxies }

// DecodeKey decodes a base64 (std or raw) master key.
func DecodeKey(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty")
	}
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	b, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("not valid base64: %w", err)
	}
	return b, nil
}

// parsePrefix parses a CIDR or bare IP, canonicalizing IPv4-mapped-IPv6 forms
// (e.g. ::ffff:203.0.113.7) to plain IPv4 so stored prefixes live in the same
// family the runtime reduces peers to (review #3/#13). Without this, a 4in6 entry
// silently matches nothing and the /24 width guard misreads 128-bit widths.
func parsePrefix(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if p, err := netip.ParsePrefix(s); err == nil {
		a := p.Addr()
		if a.Is4In6() {
			// A 4in6 prefix is measured over 128 bits; the v4-relative width is
			// bits-96 (a 4in6 /128 host is a v4 /32).
			bits := p.Bits() - 96
			if bits < 0 {
				return netip.Prefix{}, fmt.Errorf("invalid IPv4-mapped CIDR %q", s)
			}
			return netip.PrefixFrom(a.Unmap(), bits).Masked(), nil
		}
		return p.Masked(), nil
	}
	// bare IP → /32 or /128
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid CIDR/IP %q", s)
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// tooBroad rejects trusted-proxy prefixes wider than /24 (IPv4) or /120 (IPv6).
// Prefixes are already canonicalized to plain v4 by parsePrefix, so the Is4 path
// sees correct 32-bit-relative widths.
func tooBroad(p netip.Prefix) bool {
	if p.Addr().Is4() {
		return p.Bits() < 24
	}
	return p.Bits() < 120
}

func isLoopbackBind(bind string) bool {
	host := bind
	if i := strings.LastIndex(bind, ":"); i >= 0 {
		host = bind[:i]
	}
	host = strings.Trim(host, "[]")
	if host == "" {
		return false
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.IsLoopback()
}

func adminListenSafe(s string) bool {
	if strings.HasPrefix(s, "unix/") {
		return true
	}
	return s == "127.0.0.1:2019" || s == "[::1]:2019"
}

func validBase32(s string) bool {
	_, err := decodeBase32(s)
	return err == nil
}
