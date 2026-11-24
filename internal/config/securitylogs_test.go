package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

// securityS3 is a complete security_logs.archive.s3 block; set replaces one of its lines.
func securityS3(set map[string]string) string {
	lines := []struct{ key, val string }{
		{"bucket", `"sec-logs"`},
		{"endpoint", `"s3.eu-west-1.amazonaws.com"`},
		{"region", `"eu-west-1"`},
		{"access_key_id", `"AKIAEXAMPLE"`},
		{"secret_access_key", `"secret"`},
		{"prefix", `"mooring/"`},
	}
	out := "security_logs:\n  archive:\n    s3:\n"
	for _, l := range lines {
		v := l.val
		if nv, ok := set[l.key]; ok {
			if nv == "-" {
				continue
			}
			v = nv
		}
		out += "      " + l.key + ": " + v + "\n"
	}
	return out
}

// security_logs.archive.s3 gets the backups.s3 checks, plus a prefix that is safe as the start of an
// object key: letters, digits, '/', '-', '_', '.', not starting with '/', ending with '/', no empty,
// "." or ".." element.
func TestSecurityLogsArchiveS3Validated(t *testing.T) {
	if _, err := Parse([]byte(validYAML(t, securityS3(nil)))); err != nil {
		t.Fatalf("a complete archive.s3 refused: %v", err)
	}
	for key, want := range map[string]string{
		"bucket":            "security_logs.archive.s3.bucket is required",
		"region":            "security_logs.archive.s3.region is required",
		"endpoint":          "security_logs.archive.s3.endpoint is required",
		"access_key_id":     "security_logs.archive.s3 requires access_key_id and secret_access_key",
		"secret_access_key": "security_logs.archive.s3 requires access_key_id and secret_access_key",
	} {
		mustReject(t, validYAML(t, securityS3(map[string]string{key: "-"})), want)
		mustReject(t, validYAML(t, securityS3(map[string]string{key: `"  "`})), want)
	}
	for _, p := range []string{`""`, `"mooring/"`, `"mooring/security-logs/"`, `"a/b-c_d.e/"`, `"Prod.2026/security-logs/"`, `"a..b/"`,
		`"` + strings.Repeat("a", 128) + `/"`, `"x/` + strings.Repeat("b", 128) + `/"`} {
		if _, err := Parse([]byte(validYAML(t, securityS3(map[string]string{"prefix": p})))); err != nil {
			t.Errorf("prefix %s refused: %v", p, err)
		}
	}
	for p, want := range map[string]string{
		`"/mooring/"`:                           "must not start with '/'",
		`"mooring"`:                             `must end with '/' (use "mooring/")`,
		`"moo ring/"`:                           "only letters, digits",
		`"mooring\\x/"`:                         "only letters, digits",
		`"mooring?x/"`:                          "only letters, digits",
		`"møøring/"`:                            "only letters, digits",
		`"a//b/"`:                               `path element`,
		`"../x/"`:                               `path element`,
		`"./x/"`:                                `path element`,
		`"a/../b/"`:                             `path element`,
		`"a/./"`:                                `path element`,
		`".hidden/"`:                            `path element ".hidden"`,
		`"mooring/.git/"`:                       `path element ".git"`,
		`"a/.../"`:                              `path element "..."`,
		`"` + strings.Repeat("a", 129) + `/"`:   "longer than 128 characters",
		`"x/` + strings.Repeat("b", 129) + `/"`: "longer than 128 characters",
		`"` + strings.Repeat("a", 256) + `/"`:   "at most 256 characters",
	} {
		mustReject(t, validYAML(t, securityS3(map[string]string{"prefix": p})), "security_logs.archive.s3.prefix")
		mustReject(t, validYAML(t, securityS3(map[string]string{"prefix": p})), want)
	}
	// A malformed block refuses boot with collection off too.
	mustReject(t, validYAML(t, securityS3(map[string]string{"bucket": "-"})+"  enabled: false\n"), "security_logs.archive.s3.bucket is required")
	// The backups.s3 messages are unchanged by the shared check.
	mustReject(t, validYAML(t, "backups:\n  enabled: true\n  s3:\n    bucket: b\n    region: r\n    access_key_id: k\n    secret_access_key: s\n"),
		"backups.s3.endpoint is required when backups.s3 is set (e.g. s3.us-east-1.amazonaws.com)")
}

func TestSecurityLogsHostLogPathsValidated(t *testing.T) {
	host := func(key, val string) string { return "security_logs:\n  host_logs:\n    " + key + ": " + val + "\n" }
	for _, key := range []string{"auth_log", "fail2ban_log"} {
		for _, p := range []string{`""`, `"/var/log/auth.log"`, `"/var/log/secure"`, `"/srv/logs/fail2ban.log"`} {
			if _, err := Parse([]byte(validYAML(t, host(key, p)))); err != nil {
				t.Errorf("%s %s refused: %v", key, p, err)
			}
		}
		for p, want := range map[string]string{
			`"var/log/auth.log"`:           "must be an absolute path",
			`"./auth.log"`:                 "must be an absolute path",
			`"/var/log/../log/auth.log"`:   `not a clean path (use "/var/log/auth.log")`,
			`"/var//log/auth.log"`:         "not a clean path",
			`"/var/log/auth.log/"`:         "not a clean path",
			`"/var/log/./auth.log"`:        "not a clean path",
			`"/var/log/auth.log\nx"`:       "control character",
			`"/var/log/auth\u0000.log"`:    "control character",
			`"/var/log/auth\u007f.log"`:    "control character",
			`"/var/log/auth\u001b[2J.log"`: "control character",
		} {
			mustReject(t, validYAML(t, host(key, p)), "security_logs.host_logs."+key)
			mustReject(t, validYAML(t, host(key, p)), want)
		}
	}
}

func TestSecurityLogsPIIListsValidated(t *testing.T) {
	pii := func(key string, names ...string) string {
		out := "security_logs:\n  pii:\n    " + key + ":\n"
		for _, n := range names {
			out += "      - " + n + "\n"
		}
		return out
	}
	many := func(n int) []string {
		var out []string
		for i := range n {
			out = append(out, "f"+strings.Repeat("x", i%10)+string(rune('a'+i%26)))
		}
		return out
	}
	for _, key := range []string{"hash_fields", "drop_fields", "keep_fields"} {
		if _, err := Parse([]byte(validYAML(t, pii(key, "imei", "device_id", "user.email", "X-Device-Id", strings.Repeat("a", 64))))); err != nil {
			t.Errorf("%s: valid names refused: %v", key, err)
		}
		if _, err := Parse([]byte(validYAML(t, pii(key, many(64)...)))); err != nil {
			t.Errorf("%s: 64 names refused: %v", key, err)
		}
		mustReject(t, validYAML(t, pii(key, many(65)...)), "security_logs.pii."+key+": at most 64 names, got 65")
		for _, bad := range []string{`""`, `"a b"`, `"a*"`, `"émail"`, `"a/b"`, `"a\tb"`, strings.Repeat("a", 65)} {
			mustReject(t, validYAML(t, pii(key, "imei", bad)), "security_logs.pii."+key+": ")
			mustReject(t, validYAML(t, pii(key, "imei", bad)), "letters, digits, '_', '-' and '.'")
		}
	}
}

// securityWarnings is the security_logs load warnings of a parsed config.
func securityWarnings(t *testing.T, overrides string) []string {
	t.Helper()
	cfg, err := Parse([]byte(validYAML(t, overrides)))
	if err != nil {
		t.Fatalf("%q refused: %v", overrides, err)
	}
	var out []string
	for _, w := range cfg.LoadWarnings {
		if strings.HasPrefix(w, "security_logs") {
			out = append(out, w)
		}
	}
	if len(out) != len(cfg.LoadWarnings) {
		t.Fatalf("%q: unexpected other load warnings: %q", overrides, cfg.LoadWarnings)
	}
	return out
}

// Out-of-bounds values are clamped by the accessors, never refused: each one is a load warning that
// says what is used. Without an archive the warning says how long events stay on this host.
func TestSecurityLogsLoadWarnings(t *testing.T) {
	const noArchive14 = "security_logs: no archive.s3 configured — security logs are kept only on this host (14 days)"
	s3 := securityS3(nil)
	cases := []struct {
		name, yaml string
		want       []string
	}{
		{"defaults: on, no archive", "", []string{noArchive14}},
		{"explicitly on, no archive", "security_logs:\n  enabled: true\n", []string{noArchive14}},
		{"off: nothing, even out of bounds", "security_logs:\n  enabled: false\n  hot_retention: 1h\n  hot_max_disk_mb: 1\n", nil},
		{"on with an archive: nothing", s3, nil},
		{"hot_retention in bounds", s3 + "  hot_retention: 30d\n", nil},
		{"hot_retention at the bounds", s3 + "  hot_retention: 1d\n", nil},
		{"no archive, 30 days", "security_logs:\n  hot_retention: 30d\n",
			[]string{"security_logs: no archive.s3 configured — security logs are kept only on this host (30 days)"}},
		{"hot_retention below the minimum", s3 + "  hot_retention: 12h\n",
			[]string{"security_logs.hot_retention 12h is outside 1d–90d; using 1d"}},
		{"hot_retention below the minimum, no archive", "security_logs:\n  hot_retention: 1h\n", []string{
			"security_logs.hot_retention 1h is outside 1d–90d; using 1d",
			"security_logs: no archive.s3 configured — security logs are kept only on this host (1 day)"}},
		{"hot_retention negative", s3 + "  hot_retention: -5h\n",
			[]string{"security_logs.hot_retention -5h is outside 1d–90d; using 1d"}},
		{"hot_retention above the maximum", s3 + "  hot_retention: 200d\n", []string{
			"security_logs.hot_retention 200d is outside 1d–90d; using 90d"}},
		{"hot_retention odd unit", s3 + "  hot_retention: 90m\n",
			[]string{"security_logs.hot_retention 1h30m0s is outside 1d–90d; using 1d"}},
		{"hot_max_disk_mb below the minimum", s3 + "  hot_max_disk_mb: 100\n",
			[]string{"security_logs.hot_max_disk_mb 100 is below the minimum 256; using 256"}},
		{"hot_max_disk_mb negative", s3 + "  hot_max_disk_mb: -5\n",
			[]string{"security_logs.hot_max_disk_mb -5 is below the minimum 256; using 256"}},
		{"hot_max_disk_mb at the minimum", s3 + "  hot_max_disk_mb: 256\n", nil},
		{"archive.retention below the minimum", s3 + "    retention: 1h\n  hot_retention: 1d\n",
			[]string{"security_logs.archive.retention 1h is below the minimum 1d; using 1d"}},
		{"archive.retention negative", s3 + "    retention: -24h\n  hot_retention: 1d\n",
			[]string{"security_logs.archive.retention -1d is below the minimum 1d; using 1d"}},
		{"archive.retention ignored without an archive", "security_logs:\n  archive:\n    retention: 1h\n", []string{noArchive14}},
		{"hot longer than the archive", s3 + "    retention: 7d\n  hot_retention: 30d\n", []string{
			"security_logs.hot_retention (30d) is longer than security_logs.archive.retention (7d): events older than 7d are kept only on this host"}},
		{"hot longer than a clamped archive", s3 + "    retention: 2h\n", []string{
			"security_logs.archive.retention 2h is below the minimum 1d; using 1d",
			"security_logs.hot_retention (14d) is longer than security_logs.archive.retention (1d): events older than 1d are kept only on this host"}},
		{"hot equal to the archive", s3 + "    retention: 14d\n", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := securityWarnings(t, c.yaml)
			if strings.Join(got, "\n") != strings.Join(c.want, "\n") {
				t.Errorf("warnings\n %q\nwant\n %q", got, c.want)
			}
		})
	}
}

// The no-archive warning starts with the exported prefix doctor recognizes.
func TestSecurityLogsNoArchiveWarningPrefix(t *testing.T) {
	got := securityWarnings(t, "")
	if len(got) != 1 || !strings.HasPrefix(got[0], WarnSecurityLogsNoArchive) {
		t.Errorf("warnings %q, want one starting with %q", got, WarnSecurityLogsNoArchive)
	}
}

// The warnings report the value the accessors use.
func TestSecurityLogsWarningsMatchAccessors(t *testing.T) {
	cfg, err := Parse([]byte(validYAML(t, securityS3(nil)+"    retention: 3h\n  hot_retention: 200d\n  hot_max_disk_mb: 7\n")))
	if err != nil {
		t.Fatal(err)
	}
	s := cfg.SecurityLogs
	if s.HotRetentionOrDefault() != MaxSecurityHotRetention || s.HotMaxDiskBytes() != MinSecurityHotMaxDiskMB<<20 || s.Archive.RetentionOrDefault() != MinSecurityArchiveRetention {
		t.Fatalf("accessors: %v %d %v", s.HotRetentionOrDefault(), s.HotMaxDiskBytes(), s.Archive.RetentionOrDefault())
	}
	all := strings.Join(cfg.LoadWarnings, "\n")
	for _, want := range []string{"using 90d", "using 256", "archive.retention 3h is below the minimum 1d; using 1d"} {
		if !strings.Contains(all, want) {
			t.Errorf("warnings %q don't say %q", cfg.LoadWarnings, want)
		}
	}
}

// docBlocks returns every block of path that starts with a line equal to start and goes on with the
// lines indented under it, each line read with prefix cut off (a line without prefix ends a block).
func docBlocks(t *testing.T, path, prefix, start string) []string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var blocks, cur []string
	in := false
	for _, raw := range strings.Split(string(b), "\n") {
		l, ok := strings.CutPrefix(raw, prefix)
		if in && ok && strings.HasPrefix(l, "  ") {
			cur = append(cur, l)
			continue
		}
		if in && len(cur) > 1 {
			blocks = append(blocks, strings.Join(cur, "\n")+"\n")
		}
		in = ok && strings.TrimRight(l, " ") == start
		cur = []string{l}
	}
	if in && len(cur) > 1 {
		blocks = append(blocks, strings.Join(cur, "\n")+"\n")
	}
	if len(blocks) == 0 {
		t.Fatalf("%s: no %q block", path, start)
	}
	return blocks
}

// Every security_logs block in the config.yaml reference, the security logs page and the packaged
// example parses, and the full block of each shows the defaults the code applies.
func TestSecurityLogsDocBlocksParse(t *testing.T) {
	for _, src := range []struct{ path, prefix string }{
		{"../../docs/host-file.md", ""},
		{"../../deploy/nfpm/config.example.yaml", "# "},
		{"../../docs/security-logs.md", ""},
	} {
		t.Run(src.path, func(t *testing.T) {
			var full *Config
			fullLines := 0
			for _, block := range docBlocks(t, src.path, src.prefix, "security_logs:") {
				cfg, err := Parse([]byte(validYAML(t, block)))
				if err != nil {
					t.Fatalf("block refused: %v\n%s", err, block)
				}
				if full == nil || strings.Count(block, "\n") > fullLines {
					full, fullLines = cfg, strings.Count(block, "\n")
				}
			}
			s := full.SecurityLogs // the longest block shows every key
			if !s.On() || !s.HostLogs.On() || s.HostLogs.Journal != nil || s.HostLogs.AuthLog != "" || s.HostLogs.Fail2BanLog != "" {
				t.Errorf("enabled/host_logs not the defaults: %+v", s)
			}
			if time.Duration(s.HotRetention) != DefaultSecurityHotRetention || s.HotMaxDiskMB != DefaultSecurityHotMaxDiskMB ||
				time.Duration(s.Archive.Retention) != DefaultSecurityArchiveRetention {
				t.Errorf("retention/disk not the defaults: %v %d %v", s.HotRetention.D(), s.HotMaxDiskMB, s.Archive.Retention.D())
			}
			if len(s.PII.HashFields)+len(s.PII.DropFields)+len(s.PII.KeepFields) != 0 {
				t.Errorf("pii lists not empty: %+v", s.PII)
			}
			if !full.SecurityFeedGeoIP() || !full.SecurityFeedSpamhaus() || !full.SecurityFeedTor() || !full.SecurityDetectionOn() || full.SecurityDShieldContact() != "" {
				t.Errorf("feeds/detection not the defaults: %+v %+v", s.Feeds, s.Detection)
			}
		})
	}
}
