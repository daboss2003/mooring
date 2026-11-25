package config

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/daboss2003/mooring/internal/siem"
)

// Limits of the security_logs block checked by Validate.
const (
	maxSecurityArchivePrefix = 256 // bytes of archive.s3.prefix
	maxSecurityPIINames      = 64  // entries in each pii list
)

// securityPIINameRe is one pii field name: a field's last dotted element as an app writes it.
var securityPIINameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// securityContactRe is feeds.dshield_contact: an email address (sent in a User-Agent header, so no
// whitespace; control characters are refused separately).
var securityContactRe = regexp.MustCompile(`^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,63}$`)

// WarnSecurityLogsNoArchive starts the load warning for security logs with no archive.s3; doctor
// reports that case as its own check.
const WarnSecurityLogsNoArchive = "security_logs: no archive.s3 configured"

// validateSecurityLogs checks the security_logs block for Validate. A malformed block refuses boot
// whether or not collection is on.
func (c *Config) validateSecurityLogs(add func(string, ...any)) {
	s := c.SecurityLogs
	if s3 := s.Archive.S3; s3 != nil {
		validateS3("security_logs.archive.s3", s3, add)
		if err := validateSecurityArchivePrefix(s3.Prefix); err != nil {
			add("security_logs.archive.s3.prefix: %v", err)
		}
	}
	for _, p := range []struct{ key, path string }{
		{"security_logs.host_logs.auth_log", s.HostLogs.AuthLog},
		{"security_logs.host_logs.fail2ban_log", s.HostLogs.Fail2BanLog},
	} {
		if p.path == "" {
			continue
		}
		if err := validateHostLogPath(p.path); err != nil {
			add("%s: %v", p.key, err)
		}
	}
	for _, l := range []struct {
		key   string
		names []string
	}{
		{"security_logs.pii.hash_fields", s.PII.HashFields},
		{"security_logs.pii.drop_fields", s.PII.DropFields},
		{"security_logs.pii.keep_fields", s.PII.KeepFields},
	} {
		if len(l.names) > maxSecurityPIINames {
			add("%s: at most %d names, got %d", l.key, maxSecurityPIINames, len(l.names))
			continue
		}
		for _, n := range l.names {
			if !securityPIINameRe.MatchString(n) {
				add("%s: %q: use letters, digits, '_', '-' and '.' (at most 64 characters)", l.key, n)
			}
		}
	}
	if c := s.Feeds.DShieldContact; c != "" && !validSecurityContact(c) {
		add("security_logs.feeds.dshield_contact: %q is not an email address (\"\" turns the DShield list off)", c)
	}
	switch s.Response.Mode {
	case "", "off", "recommend", "enforce":
	default:
		add("security_logs.response.mode: %q: use off, recommend or enforce", s.Response.Mode)
	}
	if n := len(s.Blocking.NeverBlock); n > maxSecurityNeverBlock {
		add("security_logs.blocking.never_block: at most %d entries, got %d", maxSecurityNeverBlock, n)
	} else {
		for _, e := range s.Blocking.NeverBlock {
			if _, err := parsePrefix(e); err != nil {
				add("security_logs.blocking.never_block: %q is not an IP address or CIDR", e)
			}
		}
	}
	if n := len(s.Detection.Patterns.ExcludeApps); n > maxSecurityPatternExcludeApps {
		add("security_logs.detection.patterns.exclude_apps: at most %d apps, got %d", maxSecurityPatternExcludeApps, n)
	} else {
		for _, a := range s.Detection.Patterns.ExcludeApps {
			if !securityAppSlugRe.MatchString(a) {
				add("security_logs.detection.patterns.exclude_apps: %q is not an app slug", a)
			}
		}
	}
}

// securityAppSlugRe is an app slug in security_logs lists.
var securityAppSlugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// securityResponseWarnings are the load warnings of security_logs.detection.patterns,
// security_logs.response and security_logs.blocking: values the accessors clamp, a response mode
// that can't act, and an ip_allowlist that protects every address from automatic blocks.
func securityResponseWarnings(c *Config) []string {
	s := c.SecurityLogs
	var w []string
	clamped := func(key string, got, used int) {
		if got != 0 && got != used {
			w = append(w, fmt.Sprintf("security_logs.%s %d is out of range; using %d", key, got, used))
		}
	}
	clampedDur := func(key string, got, used time.Duration) {
		if got != 0 && got != used {
			w = append(w, fmt.Sprintf("security_logs.%s %s is out of range; using %s", key, fmtSecurityDuration(got), fmtSecurityDuration(used)))
		}
	}
	// The block list applies whether or not security logs are on.
	clamped("blocking.max_entries", s.Blocking.MaxEntries, s.Blocking.MaxEntriesOrDefault())
	clampedDur("blocking.manual_max_duration", time.Duration(s.Blocking.ManualMaxDuration), s.Blocking.ManualMaxDurationOrDefault())
	if s.Blocking.L4 && !c.Edge.L4Enabled {
		w = append(w, "security_logs.blocking.l4 is on but edge.l4_enabled is off: L4 listeners are not filtered")
	}
	if !s.On() {
		if m := s.Response.Mode; m == "recommend" || m == "enforce" {
			w = append(w, fmt.Sprintf("security_logs.response.mode is %s but security logs are off: nothing is recommended or done", m))
		}
		return w
	}
	clamped("detection.patterns.max_cpu_percent", s.Detection.Patterns.MaxCPUPercent, s.Detection.Patterns.MaxCPUPercentOrDefault())
	clamped("response.max_blocks_per_hour", s.Response.MaxBlocksPerHour, s.Response.MaxBlocksPerHourOrDefault())
	clamped("response.max_revokes_per_hour", s.Response.MaxRevokesPerHour, s.Response.MaxRevokesPerHourOrDefault())
	clampedDur("response.max_block_duration", time.Duration(s.Response.MaxBlockDuration), s.Response.MaxBlockDurationOrDefault())
	mode := s.Response.Mode
	if mode != "recommend" && mode != "enforce" {
		return w
	}
	if !c.SecurityDetectionOn() {
		return append(w, fmt.Sprintf("security_logs.response.mode is %s but detection is off: nothing is recommended or done", mode))
	}
	for _, e := range c.IPAllowlist {
		if p, err := parsePrefix(e); err == nil && p.Bits() == 0 {
			w = append(w, fmt.Sprintf("ip_allowlist contains %s: every address is protected, so no automatic block can be placed", p))
			break
		}
	}
	return w
}

// validSecurityContact reports whether c is usable as feeds.dshield_contact.
func validSecurityContact(c string) bool {
	if !securityContactRe.MatchString(c) {
		return false
	}
	for _, r := range c {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// validateSecurityArchivePrefix checks the object-key prefix of the security-log archive: "" or
// letters, digits, '/', '-', '_' and '.', not starting with '/', ending with '/', every element
// passing siem.SafeName (1–128 characters, not starting with '.'; `mooring security-logs fetch`
// writes objects under their key).
func validateSecurityArchivePrefix(p string) error {
	if p == "" {
		return nil
	}
	if len(p) > maxSecurityArchivePrefix {
		return fmt.Errorf("at most %d characters, got %d", maxSecurityArchivePrefix, len(p))
	}
	if strings.Trim(p, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/-_.") != "" {
		return fmt.Errorf("%q: only letters, digits, '/', '-', '_' and '.' are allowed", p)
	}
	if p[0] == '/' {
		return fmt.Errorf("%q must not start with '/'", p)
	}
	if !strings.HasSuffix(p, "/") {
		return fmt.Errorf("%q must end with '/' (use %q)", p, p+"/")
	}
	// The archiver's own rule (archive.checkPrefix), so a prefix accepted here is never refused there.
	for _, el := range strings.Split(strings.TrimSuffix(p, "/"), "/") {
		if !siem.SafeName(el) {
			return fmt.Errorf("%q has a path element %q that is empty, longer than 128 characters or starts with '.'", p, el)
		}
	}
	return nil
}

// validateHostLogPath checks a host_logs file path: absolute, clean, no control characters.
func validateHostLogPath(p string) error {
	for _, r := range p {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%q contains a control character", p)
		}
	}
	if !filepath.IsAbs(p) {
		return fmt.Errorf("%q must be an absolute path", p)
	}
	if clean := filepath.Clean(p); clean != p {
		return fmt.Errorf("%q is not a clean path (use %q)", p, clean)
	}
	return nil
}

// securityLogsWarnings are the load warnings of the security_logs block (on only): values the
// accessors clamp, no off-host archive, and events kept longer on this host than in the archive.
func securityLogsWarnings(s SecurityLogsConfig) []string {
	if !s.On() {
		return nil
	}
	var w []string
	hot := s.HotRetentionOrDefault()
	if d := time.Duration(s.HotRetention); d != 0 && d != hot {
		w = append(w, fmt.Sprintf("security_logs.hot_retention %s is outside %s–%s; using %s",
			fmtSecurityDuration(d), fmtSecurityDuration(MinSecurityHotRetention), fmtSecurityDuration(MaxSecurityHotRetention), fmtSecurityDuration(hot)))
	}
	if mb := s.HotMaxDiskMB; mb != 0 && mb < MinSecurityHotMaxDiskMB {
		w = append(w, fmt.Sprintf("security_logs.hot_max_disk_mb %d is below the minimum %d; using %d", mb, MinSecurityHotMaxDiskMB, MinSecurityHotMaxDiskMB))
	}
	if s.Archive.S3 == nil {
		kept := fmtSecurityDuration(hot)
		switch days := hot / (24 * time.Hour); {
		case hot%(24*time.Hour) != 0:
		case days == 1:
			kept = "1 day"
		default:
			kept = fmt.Sprintf("%d days", days)
		}
		return append(w, WarnSecurityLogsNoArchive+" — security logs are kept only on this host ("+kept+")")
	}
	arch := s.Archive.RetentionOrDefault()
	if d := time.Duration(s.Archive.Retention); d != 0 && d != arch {
		w = append(w, fmt.Sprintf("security_logs.archive.retention %s is below the minimum %s; using %s",
			fmtSecurityDuration(d), fmtSecurityDuration(MinSecurityArchiveRetention), fmtSecurityDuration(arch)))
	}
	if hot > arch {
		w = append(w, fmt.Sprintf("security_logs.hot_retention (%s) is longer than security_logs.archive.retention (%s): events older than %s are kept only on this host",
			fmtSecurityDuration(hot), fmtSecurityDuration(arch), fmtSecurityDuration(arch)))
	}
	return w
}

// fmtSecurityDuration writes d as config.yaml would: whole days as "14d", whole hours as "12h".
func fmtSecurityDuration(d time.Duration) string {
	switch {
	case d%(24*time.Hour) == 0:
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	}
	return d.String()
}
