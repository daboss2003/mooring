package config

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"strings"

	"github.com/daboss2003/mooring/internal/yamldiag"
	"gopkg.in/yaml.v3"
)

// Readable config errors, the certificate names and the reload/restart split (v0.34.0).
//
// Load and Parse keep their signatures. From v0.34.0 an error they return for a file that doesn't
// parse or validate is a *yamldiag.Diagnostics: its Error() is one line, its Terminal() the
// multi-line form with the offending line, and it unwraps to the error of before ("config: parse:
// …", "config: refusing to boot:\n  - …"). A file they accept today is still accepted, one they
// refuse is still refused: diagnostics only explain a refusal.
//
// No form of that error shows a value from the file: excerpts keep the key and mask the rest, and
// the validation messages (Problems) say what is expected, never what was found. A key is named
// only when it is a key of config.yaml, spelled right: anything else written where a key belongs is
// masked too.

// ExitInvalid is the exit status of `mooring serve` (and `mooring config check`) for a config.yaml
// that is refused: the systemd unit doesn't restart on it (RestartPreventExitStatus).
const ExitInvalid = 78

// ErrOtherGroup is wrapped by the error Load returns when the caller is neither root nor in the
// config file's group as its primary group: the file may be fine for the service, this caller just
// can't judge it. CONTRACT (v0.34.0 fix round): checkPerms wraps it; `config check` and `doctor`
// treat it as "run with sudo", not as a refused file.
var ErrOtherGroup = errors.New("the config file belongs to another group")

// ParseNamed is Parse with the file's name for its messages ("/etc/mooring/config.yaml").
func ParseNamed(raw []byte, file string) (*Config, error) {
	c := &Config{}
	if err := yamlStrict(raw, c); err != nil {
		return nil, explain(raw, file, nil, fmt.Errorf("config: parse: %w", err))
	}
	applyDefaults(c)
	if ps := c.Problems(); len(ps) > 0 {
		return nil, explain(raw, file, ps, refusal(ps))
	}
	return c, nil
}

// explain turns a refusal (cause: the strict decode's error, or the validation's with its problems)
// into the error Parse returns. The verdict is already made: this only adds positions and excerpts.
func explain(raw []byte, file string, problems []yamldiag.Problem, cause error) (err error) {
	// Intentional: RedactValues with no exception. An error about config.yaml never shows a value
	// from the file — it gives the file, line, column, key, a plain message and a hint (owner
	// decision 2026-11-25, which replaced the earlier list of keys whose values were shown).
	o := yamldiag.Options{File: file, RedactValues: true, Schema: reflect.TypeOf(Config{})}
	// Intentional: a panic while explaining is swallowed and the plain refusal returned — the config
	// is refused either way, and a bug in the explanation must not hide why. The refusal still goes
	// through the diagnostics' one-line form, which prints the decoder's text without the values it
	// quotes: the raw cause is never the error returned.
	defer func() {
		if recover() != nil {
			err = plainRefusal(file, cause, o)
		}
	}()
	var d *yamldiag.Diagnostics
	if problems == nil {
		d = explainFile(raw, reflect.TypeOf(Config{}), cause, o)
		nameDurations(d)
	} else {
		d = &yamldiag.Diagnostics{File: file}
		d.Semantic(raw, problems, cause, o)
	}
	if d == nil {
		return plainRefusal(file, cause, o)
	}
	if d.Cause == nil {
		d.Cause = cause
	}
	return d
}

// explainFile is yamldiag.Explain (a variable so a test can make it panic).
var explainFile = yamldiag.Explain

// plainRefusal is the refusal with nothing explained: its Error() is the cause's text as the
// diagnostics print it under RedactValues, and it unwraps to cause.
func plainRefusal(file string, cause error, o yamldiag.Options) (err error) {
	defer func() {
		if recover() != nil {
			err = refused{file: file, cause: cause}
		}
	}()
	d := &yamldiag.Diagnostics{File: file}
	d.Semantic(nil, nil, cause, o)
	return d
}

// refused is the last resort of plainRefusal: a fixed sentence, the cause kept for errors.Is.
type refused struct {
	file  string
	cause error
}

func (r refused) Error() string { return r.file + ": the file was refused" }
func (r refused) Unwrap() error { return r.cause }

// nameDurations puts the key in front of Duration's own message ("retention.interval is not a valid
// duration: …"): the type decodes itself and does not know where it is written.
func nameDurations(d *yamldiag.Diagnostics) {
	if d == nil {
		return
	}
	for i := range d.Problems {
		if p := &d.Problems[i]; p.Msg == invalidDurationMsg && p.Path != "" {
			p.Kind = yamldiag.KindType
			p.Msg = p.Path + " is " + invalidDurationMsg
		}
	}
}

// yamlKey is the config.yaml key of a struct field ("" when it has none).
func yamlKey(f reflect.StructField) string {
	name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
	if !f.IsExported() || name == "" || name == "-" {
		return ""
	}
	return name
}

// CertName is one hostname the managed edge requests a certificate for because of config.yaml (app
// routes add their own, which only the running service knows).
type CertName struct {
	Host string // "admin.example.com", "*.apps.example.com"
	Why  string // "the dashboard (admin.hostname)", "base domain apps (DNS-01 wildcard)"
}

// CertHostnames lists them, the dashboard's first; none with edge.mode external.
func (c *Config) CertHostnames() []CertName {
	if c.Edge.Mode == EdgeExternal {
		return nil
	}
	var out []CertName
	seen := map[string]bool{}
	add := func(host, why string) {
		if host = strings.ToLower(strings.TrimSpace(host)); host != "" && !seen[host] {
			seen[host] = true
			out = append(out, CertName{Host: host, Why: why})
		}
	}
	switch {
	case strings.TrimSpace(c.Admin.Hostname) != "":
		add(c.AdminHostnameResolved(), "the dashboard (admin.hostname)")
	case c.AdminExposed():
		add(c.AdminHostnameResolved(), "the dashboard (admin.subdomain)")
	}
	if bd, ok := c.BaseDomainByName(""); ok && bd.DNS01 != nil {
		add("*."+bd.Domain, "edge.base_domain (DNS-01 wildcard)")
	}
	for _, b := range c.Edge.BaseDomains {
		if b.DNS01 != nil {
			add("*."+b.Domain, "base domain "+b.Name+" (DNS-01 wildcard)")
		}
	}
	return out
}

// RepeatedLabel reports a dashboard hostname whose first two labels are the same
// ("dns.dns.example.com"): admin.subdomain repeats the first label of edge.base_domain, which is
// usually the base domain written where the bare apex was meant.
func (c *Config) RepeatedLabel() (host string, ok bool) {
	sub := strings.ToLower(strings.TrimSpace(c.Admin.Subdomain))
	base := strings.ToLower(strings.TrimSpace(c.Edge.BaseDomain))
	if sub == "" || base == "" || strings.TrimSpace(c.Admin.Hostname) != "" {
		return "", false
	}
	if first, _, _ := strings.Cut(base, "."); first != sub {
		return "", false
	}
	return sub + "." + base, true
}

// AllowlistStrings is ip_allowlist as canonical prefixes ("203.0.113.7/32", "2001:db8::/32"):
// masked, bare addresses as /32 or /128, IPv4-mapped IPv6 as IPv4, no surrounding spaces. It is
// what the edge's dashboard route is rendered with, so the edge and the dashboard admit the same
// addresses.
func (c *Config) AllowlistStrings() []string {
	out := make([]string, 0, len(c.parsedAllowlist))
	for _, p := range c.parsedAllowlist {
		out = append(out, netip.Prefix.String(p))
	}
	return out
}

// Apply modes.
const (
	ApplyReload  = "reload"  // `systemctl reload mooring` applies it
	ApplyRestart = "restart" // needs `systemctl restart mooring`
)

// reloadKeys are the top-level keys a reload re-reads: web.Server.Reload (ip_allowlist, trust_proxy,
// trusted_proxies, auth, users; serve then pushes ip_allowlist to the edge) and serve's SIGHUP
// handler (retention). Everything else is read once at start.
var reloadKeys = map[string]bool{
	"ip_allowlist": true, "trust_proxy": true, "trusted_proxies": true,
	"auth": true, "users": true, "retention": true,
}

// ApplyMode says how a change of the top-level or dotted key path ("ip_allowlist",
// "edge.base_domains") takes effect: ApplyReload only for what a reload really re-reads.
func ApplyMode(keyPath string) string {
	top := keyPath
	if i := strings.IndexAny(top, ".["); i >= 0 {
		top = top[:i]
	}
	if reloadKeys[strings.TrimSpace(top)] {
		return ApplyReload
	}
	return ApplyRestart
}

// diffOneLevelDown are the top-level keys DiffApply reports by sub-key ("edge.acme_email").
var diffOneLevelDown = map[string]bool{"edge": true, "server": true, "security_logs": true, "alerting": true}

// DiffApply compares two loaded configs and lists the changed top-level keys by how they take
// effect (each sorted; a key appears once). Keys under edge, server, security_logs and alerting are
// listed one level down ("edge.base_domains").
func DiffApply(old, updated *Config) (reload, restart []string) {
	if old == nil {
		old = &Config{}
	}
	if updated == nil {
		updated = &Config{}
	}
	var changed []string
	diffFields(reflect.ValueOf(*old), reflect.ValueOf(*updated), "", &changed)
	sort.Strings(changed)
	for _, k := range changed {
		if ApplyMode(k) == ApplyReload {
			reload = append(reload, k)
		} else {
			restart = append(restart, k)
		}
	}
	return reload, restart
}

func diffFields(a, b reflect.Value, prefix string, changed *[]string) {
	for i := 0; i < a.NumField(); i++ {
		key := yamlKey(a.Type().Field(i))
		if key == "" || reflect.DeepEqual(a.Field(i).Interface(), b.Field(i).Interface()) {
			continue
		}
		if prefix == "" && diffOneLevelDown[key] && a.Field(i).Kind() == reflect.Struct {
			diffFields(a.Field(i), b.Field(i), key+".", changed)
			continue
		}
		*changed = append(*changed, prefix+key)
	}
}

// yamlStrict is the strict decode of config.yaml: unknown keys are refused.
func yamlStrict(raw []byte, c *Config) error {
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	return dec.Decode(c)
}
