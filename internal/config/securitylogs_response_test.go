package config

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

func parsed(t *testing.T, overrides string) *Config {
	t.Helper()
	cfg, err := Parse([]byte(validYAML(t, overrides)))
	if err != nil {
		t.Fatalf("%q refused: %v", overrides, err)
	}
	return cfg
}

// Unset, patterns are mined, automated response is off, and the block list has its defaults.
func TestSecurityResponseDefaults(t *testing.T) {
	c := parsed(t, "")
	s := c.SecurityLogs
	if !c.SecurityPatternsOn() || s.Detection.Patterns.MaxCPUPercentOrDefault() != 5 {
		t.Errorf("patterns: on=%v cpu=%d, want on, 5", c.SecurityPatternsOn(), s.Detection.Patterns.MaxCPUPercentOrDefault())
	}
	if m := c.SecurityResponseMode(); m != "off" {
		t.Errorf("response mode = %q, want off", m)
	}
	if s.Response.MaxBlocksPerHourOrDefault() != 60 || s.Response.MaxRevokesPerHourOrDefault() != 3 || s.Response.MaxBlockDurationOrDefault() != 24*time.Hour {
		t.Errorf("response caps = %d, %d, %s", s.Response.MaxBlocksPerHourOrDefault(), s.Response.MaxRevokesPerHourOrDefault(), s.Response.MaxBlockDurationOrDefault())
	}
	if s.Blocking.MaxEntriesOrDefault() != 1000 || s.Blocking.ManualMaxDurationOrDefault() != 30*24*time.Hour || s.Blocking.L4 || len(s.Blocking.NeverBlockPrefixes()) != 0 {
		t.Errorf("blocking = %d, %s, l4 %v, never %v", s.Blocking.MaxEntriesOrDefault(), s.Blocking.ManualMaxDurationOrDefault(), s.Blocking.L4, s.Blocking.NeverBlockPrefixes())
	}
	// Detection off (or security logs off) turns patterns and responses off whatever they say.
	for _, off := range []string{
		"security_logs:\n  detection:\n    enabled: false\n  response:\n    mode: enforce\n",
		"security_logs:\n  enabled: false\n  response:\n    mode: enforce\n",
	} {
		c := parsed(t, off)
		if c.SecurityPatternsOn() || c.SecurityResponseMode() != "off" {
			t.Errorf("%q: patterns %v, mode %q; want off, off", off, c.SecurityPatternsOn(), c.SecurityResponseMode())
		}
	}
	if c := parsed(t, "security_logs:\n  detection:\n    patterns:\n      enabled: false\n"); c.SecurityPatternsOn() || !c.SecurityDetectionOn() {
		t.Error("patterns.enabled: false didn't turn only patterns off")
	}
}

func TestSecurityResponseModeValidated(t *testing.T) {
	mode := func(m string) string { return "security_logs:\n  response:\n    mode: " + m + "\n" }
	for m, want := range map[string]string{`""`: "off", "off": "off", "recommend": "recommend", "enforce": "enforce"} {
		if got := parsed(t, mode(m)).SecurityResponseMode(); got != want {
			t.Errorf("mode %s → %q, want %q", m, got, want)
		}
	}
	for _, bad := range []string{"on", "Enforce", "true", "block", `"enforce "`} {
		mustReject(t, validYAML(t, mode(bad)), "security_logs.response.mode: ")
		mustReject(t, validYAML(t, mode(bad)), "use off, recommend or enforce")
	}
	// Refused with security logs off too: a malformed block never boots.
	mustReject(t, validYAML(t, "security_logs:\n  enabled: false\n  response:\n    mode: on\n"), "security_logs.response.mode")
}

func TestSecurityNeverBlockParsed(t *testing.T) {
	list := func(entries ...string) string {
		out := "security_logs:\n  blocking:\n    never_block:\n"
		for _, e := range entries {
			out += "      - " + e + "\n"
		}
		return out
	}
	got := parsed(t, list("203.0.113.7", "198.51.100.0/24", "198.51.100.77/24", "::ffff:192.0.2.1", "2001:db8::/32", "2001:db8::1")).SecurityLogs.Blocking.NeverBlockPrefixes()
	want := []netip.Prefix{netip.MustParsePrefix("203.0.113.7/32"), netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("192.0.2.1/32"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2001:db8::1/128")}
	if !slices.Equal(got, want) {
		t.Errorf("never_block = %v, want %v", got, want)
	}
	for _, bad := range []string{`"example.com"`, `"203.0.113.300"`, `"10.0.0.0/33"`, `""`} {
		mustReject(t, validYAML(t, list("203.0.113.7", bad)), "security_logs.blocking.never_block: ")
		mustReject(t, validYAML(t, list("203.0.113.7", bad)), "is not an IP address or CIDR")
	}
	many := make([]string, 257)
	for i := range many {
		many[i] = fmt.Sprintf("10.%d.%d.1", i/256, i%256)
	}
	if _, err := Parse([]byte(validYAML(t, list(many[:256]...)))); err != nil {
		t.Errorf("256 entries refused: %v", err)
	}
	mustReject(t, validYAML(t, list(many...)), "security_logs.blocking.never_block: at most 256 entries, got 257")
}

func TestSecurityPatternExcludeAppsValidated(t *testing.T) {
	apps := func(names ...string) string {
		out := "security_logs:\n  detection:\n    patterns:\n      exclude_apps:\n"
		for _, n := range names {
			out += "      - " + n + "\n"
		}
		return out
	}
	if got := parsed(t, apps("shop", "blog-pr12", "a_b", strings.Repeat("a", 64))).SecurityLogs.Detection.Patterns.ExcludeApps; len(got) != 4 {
		t.Errorf("exclude_apps = %q", got)
	}
	for _, bad := range []string{`"Shop"`, `"-shop"`, `"shop/web"`, `""`, `"sh op"`, strings.Repeat("a", 65)} {
		mustReject(t, validYAML(t, apps("shop", bad)), "security_logs.detection.patterns.exclude_apps: ")
		mustReject(t, validYAML(t, apps("shop", bad)), "is not an app slug")
	}
	many := make([]string, 257)
	for i := range many {
		many[i] = fmt.Sprintf("app%d", i)
	}
	mustReject(t, validYAML(t, apps(many...)), "exclude_apps: at most 256 apps, got 257")
}

// Out-of-range numbers are clamped by the accessors with a load warning naming what is used; the
// block list's warnings come with security logs off too.
func TestSecurityResponseClampWarnings(t *testing.T) {
	cases := []struct {
		yaml string
		want string
		ok   func(*Config) bool
	}{
		{"security_logs:\n  detection:\n    patterns:\n      max_cpu_percent: 50\n", "security_logs.detection.patterns.max_cpu_percent 50 is out of range; using 25",
			func(c *Config) bool { return c.SecurityLogs.Detection.Patterns.MaxCPUPercentOrDefault() == 25 }},
		{"security_logs:\n  detection:\n    patterns:\n      max_cpu_percent: -3\n", "max_cpu_percent -3 is out of range; using 1",
			func(c *Config) bool { return c.SecurityLogs.Detection.Patterns.MaxCPUPercentOrDefault() == 1 }},
		{"security_logs:\n  response:\n    max_blocks_per_hour: 5000\n", "security_logs.response.max_blocks_per_hour 5000 is out of range; using 1000",
			func(c *Config) bool { return c.SecurityLogs.Response.MaxBlocksPerHourOrDefault() == 1000 }},
		{"security_logs:\n  response:\n    max_revokes_per_hour: 500\n", "security_logs.response.max_revokes_per_hour 500 is out of range; using 100",
			func(c *Config) bool { return c.SecurityLogs.Response.MaxRevokesPerHourOrDefault() == 100 }},
		{"security_logs:\n  response:\n    max_block_duration: 30m\n", "security_logs.response.max_block_duration 30m0s is out of range; using 1h",
			func(c *Config) bool { return c.SecurityLogs.Response.MaxBlockDurationOrDefault() == time.Hour }},
		{"security_logs:\n  response:\n    max_block_duration: 30d\n", "security_logs.response.max_block_duration 30d is out of range; using 7d",
			func(c *Config) bool { return c.SecurityLogs.Response.MaxBlockDurationOrDefault() == 7*24*time.Hour }},
		{"security_logs:\n  enabled: false\n  blocking:\n    max_entries: 20000\n", "security_logs.blocking.max_entries 20000 is out of range; using 10000",
			func(c *Config) bool { return c.SecurityLogs.Blocking.MaxEntriesOrDefault() == 10000 }},
		{"security_logs:\n  enabled: false\n  blocking:\n    manual_max_duration: 90d\n", "security_logs.blocking.manual_max_duration 90d is out of range; using 30d",
			func(c *Config) bool { return c.SecurityLogs.Blocking.ManualMaxDurationOrDefault() == 30*24*time.Hour }},
	}
	for _, tc := range cases {
		c := parsed(t, tc.yaml)
		if !slices.ContainsFunc(c.LoadWarnings, func(w string) bool { return strings.Contains(w, tc.want) }) {
			t.Errorf("%q: warnings %q, want one with %q", tc.yaml, c.LoadWarnings, tc.want)
		}
		if !tc.ok(c) {
			t.Errorf("%q: accessor doesn't use the clamped value", tc.yaml)
		}
	}
	// In range: no warning.
	c := parsed(t, "security_logs:\n  detection:\n    patterns:\n      max_cpu_percent: 10\n  response:\n    max_blocks_per_hour: 100\n    max_block_duration: 48h\n  blocking:\n    max_entries: 500\n    manual_max_duration: 7d\n")
	for _, w := range c.LoadWarnings {
		if strings.Contains(w, "out of range") {
			t.Errorf("in-range values warned: %q", w)
		}
	}
}

// A mode that can't act says so: detection off, or an ip_allowlist covering every address (every
// address is then protected from automatic blocks).
func TestSecurityResponseModeWarnings(t *testing.T) {
	c := parsed(t, "security_logs:\n  detection:\n    enabled: false\n  response:\n    mode: enforce\n")
	if !slices.ContainsFunc(c.LoadWarnings, func(w string) bool {
		return w == "security_logs.response.mode is enforce but detection is off: nothing is recommended or done"
	}) {
		t.Errorf("detection off: warnings %q", c.LoadWarnings)
	}
	c = parsed(t, "security_logs:\n  enabled: false\n  response:\n    mode: recommend\n")
	if !slices.Contains(c.LoadWarnings, "security_logs.response.mode is recommend but security logs are off: nothing is recommended or done") {
		t.Errorf("security logs off: warnings %q", c.LoadWarnings)
	}
	wide := strings.Replace(validYAML(t, "security_logs:\n  response:\n    mode: recommend\n"), "ip_allowlist:\n", "ip_allowlist:\n  - 0.0.0.0/0\n", 1)
	cfg, err := Parse([]byte(wide))
	if err != nil {
		t.Fatalf("a /0 allowlist refused: %v", err)
	}
	if !slices.Contains(cfg.LoadWarnings, "ip_allowlist contains 0.0.0.0/0: every address is protected, so no automatic block can be placed") {
		t.Errorf("/0 allowlist: warnings %q", cfg.LoadWarnings)
	}
	l4 := parsed(t, "security_logs:\n  blocking:\n    l4: true\n")
	if !slices.Contains(l4.LoadWarnings, "security_logs.blocking.l4 is on but edge.l4_enabled is off: L4 listeners are not filtered") {
		t.Errorf("blocking.l4 without the L4 load balancer: warnings %q", l4.LoadWarnings)
	}
	if ok := parsed(t, ""); slices.ContainsFunc(ok.LoadWarnings, func(w string) bool { return strings.Contains(w, "blocking.l4") }) {
		t.Errorf("blocking.l4 off warned: %q", ok.LoadWarnings)
	}
	// Mode off: no such warning.
	off := strings.Replace(validYAML(t, ""), "ip_allowlist:\n", "ip_allowlist:\n  - 0.0.0.0/0\n", 1)
	if cfg, err := Parse([]byte(off)); err != nil || slices.ContainsFunc(cfg.LoadWarnings, func(w string) bool { return strings.HasPrefix(w, "ip_allowlist contains") }) {
		t.Errorf("mode off warned about the allowlist (err %v): %q", err, cfg.LoadWarnings)
	}
}
