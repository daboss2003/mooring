package config

import (
	"net/netip"
	"time"
)

// SecurityLogsConfig is the `security_logs:` block: Mooring's built-in security-log collection,
// detection and archive (docs/security-logs.md). ON by default (Enabled *bool, unset = on).
// Read at boot only; a change needs a restart.
type SecurityLogsConfig struct {
	Enabled *bool `yaml:"enabled"`
	// HotRetention is how long events stay on this host, searchable (default 14d, 1d–90d).
	HotRetention Duration `yaml:"hot_retention"`
	// HotMaxDiskMB caps the on-host segments and security database (default 10240, minimum 256).
	// Past it the oldest segments already archived go first.
	HotMaxDiskMB int                   `yaml:"hot_max_disk_mb"`
	Archive      SecurityLogsArchive   `yaml:"archive"`
	PII          SecurityLogsPII       `yaml:"pii"`
	HostLogs     SecurityLogsHost      `yaml:"host_logs"`
	Feeds        SecurityLogsFeeds     `yaml:"feeds"`
	Detection    SecurityLogsDetection `yaml:"detection"`
	Response     SecurityLogsResponse  `yaml:"response"`
	Blocking     SecurityLogsBlocking  `yaml:"blocking"`
}

// SecurityLogsFeeds selects the enrichment data Mooring downloads (internal/siem/feeds): GeoIP is
// DB-IP City + ASN Lite, Spamhaus the DROP lists, Tor the exit list; each *bool unset = on.
// DShieldContact "" = no DShield block list; otherwise an email address SANS ISC requires in the
// User-Agent of the download.
type SecurityLogsFeeds struct {
	GeoIP          *bool  `yaml:"geoip"`
	Spamhaus       *bool  `yaml:"spamhaus"`
	Tor            *bool  `yaml:"tor"`
	DShieldContact string `yaml:"dshield_contact"`
}

// SecurityLogsDetection is the rule engine over security events. Enabled unset = on.
type SecurityLogsDetection struct {
	Enabled  *bool                `yaml:"enabled"`
	Patterns SecurityLogsPatterns `yaml:"patterns"`
}

// SecurityLogsPatterns is log-pattern mining (needs detection). Enabled unset = on.
// MaxCPUPercent is the miner's share of one CPU core (default 5, 1–25); ExcludeApps are app slugs
// whose lines are not mined.
type SecurityLogsPatterns struct {
	Enabled       *bool    `yaml:"enabled"`
	MaxCPUPercent int      `yaml:"max_cpu_percent"`
	ExcludeApps   []string `yaml:"exclude_apps"`
}

// SecurityLogsResponse is automated response (needs detection): Mode "" or "off" (default),
// "recommend" or "enforce"; the hourly caps on automatic blocks (default 60, 1–1000) and session
// revokes (default 3, 1–100); MaxBlockDuration, the longest automatic block a repeat reaches
// (default 24h, 1h–7d).
type SecurityLogsResponse struct {
	Mode              string   `yaml:"mode"`
	MaxBlocksPerHour  int      `yaml:"max_blocks_per_hour"`
	MaxRevokesPerHour int      `yaml:"max_revokes_per_hour"`
	MaxBlockDuration  Duration `yaml:"max_block_duration"`
}

// SecurityLogsBlocking is the edge block list (automatic blocks and the owner's manual ones). It
// applies whenever Mooring runs the edge, security logs on or off. MaxEntries bounds the active
// automatic blocks (default 1000, 1–10000); ManualMaxDuration is the longest manual block (default
// 30d, 1h–30d); L4 also refuses blocked IPv4 addresses on L4 `forward: proxy` listeners; NeverBlock
// are addresses and CIDRs never blocked (in addition to the built-in protected set).
type SecurityLogsBlocking struct {
	MaxEntries        int      `yaml:"max_entries"`
	ManualMaxDuration Duration `yaml:"manual_max_duration"`
	L4                bool     `yaml:"l4"`
	NeverBlock        []string `yaml:"never_block"`
}

// SecurityLogsArchive is the off-host copy: every sealed hour, encrypted with the encryption key,
// uploaded to S3 and deleted there after Retention.
type SecurityLogsArchive struct {
	Retention Duration  `yaml:"retention"` // default 365d, minimum 1d
	S3        *BackupS3 `yaml:"s3"`        // nil: no off-host archive (a load warning says so)
}

// SecurityLogsPII adjusts the built-in personal-data field lists (redact): HashFields are stored
// as a keyed hash, DropFields are removed, KeepFields takes a name out of both built-in lists.
// Names match a field's last dotted element, case-insensitively.
type SecurityLogsPII struct {
	HashFields []string `yaml:"hash_fields"`
	DropFields []string `yaml:"drop_fields"`
	KeepFields []string `yaml:"keep_fields"`
}

// SecurityLogsHost selects the host logs read. Enabled unset = on. AuthLog "" = /var/log/auth.log,
// else /var/log/secure, whichever exists; Fail2BanLog "" = /var/log/fail2ban.log; Journal unset =
// read sshd/sudo/su from the systemd journal only when no auth log file exists.
type SecurityLogsHost struct {
	Enabled     *bool  `yaml:"enabled"`
	AuthLog     string `yaml:"auth_log"`
	Fail2BanLog string `yaml:"fail2ban_log"`
	Journal     *bool  `yaml:"journal"`
}

// Defaults and bounds of the security_logs block.
const (
	DefaultSecurityHotRetention     = 14 * 24 * time.Hour
	MinSecurityHotRetention         = 24 * time.Hour
	MaxSecurityHotRetention         = 90 * 24 * time.Hour
	DefaultSecurityHotMaxDiskMB     = 10240
	MinSecurityHotMaxDiskMB         = 256
	DefaultSecurityArchiveRetention = 365 * 24 * time.Hour
	MinSecurityArchiveRetention     = 24 * time.Hour

	DefaultSecurityPatternCPU = 5
	MinSecurityPatternCPU     = 1
	MaxSecurityPatternCPU     = 25

	DefaultSecurityMaxBlocksPerHour  = 60
	MaxSecurityMaxBlocksPerHour      = 1000
	DefaultSecurityMaxRevokesPerHour = 3
	MaxSecurityMaxRevokesPerHour     = 100
	DefaultSecurityMaxBlockDuration  = 24 * time.Hour
	MinSecurityMaxBlockDuration      = time.Hour
	MaxSecurityMaxBlockDuration      = 7 * 24 * time.Hour

	DefaultSecurityBlockMaxEntries     = 1000
	MaxSecurityBlockMaxEntries         = 10000
	DefaultSecurityManualBlockDuration = 30 * 24 * time.Hour
	MinSecurityManualBlockDuration     = time.Hour
	MaxSecurityManualBlockDuration     = 30 * 24 * time.Hour
	maxSecurityNeverBlock              = 256
	maxSecurityPatternExcludeApps      = 256
)

// On reports whether security-log collection runs (default on).
func (s SecurityLogsConfig) On() bool { return s.Enabled == nil || *s.Enabled }

// HotRetentionOrDefault is HotRetention clamped to its bounds (unset → the default).
func (s SecurityLogsConfig) HotRetentionOrDefault() time.Duration {
	d := time.Duration(s.HotRetention)
	switch {
	case d == 0:
		return DefaultSecurityHotRetention
	case d < MinSecurityHotRetention:
		return MinSecurityHotRetention
	case d > MaxSecurityHotRetention:
		return MaxSecurityHotRetention
	}
	return d
}

// HotMaxDiskBytes is HotMaxDiskMB clamped (unset → the default), in bytes.
func (s SecurityLogsConfig) HotMaxDiskBytes() int64 {
	mb := s.HotMaxDiskMB
	switch {
	case mb == 0:
		mb = DefaultSecurityHotMaxDiskMB
	case mb < MinSecurityHotMaxDiskMB:
		mb = MinSecurityHotMaxDiskMB
	}
	return int64(mb) << 20
}

// RetentionOrDefault is the archive retention clamped (unset → the default).
func (a SecurityLogsArchive) RetentionOrDefault() time.Duration {
	d := time.Duration(a.Retention)
	switch {
	case d == 0:
		return DefaultSecurityArchiveRetention
	case d < MinSecurityArchiveRetention:
		return MinSecurityArchiveRetention
	}
	return d
}

// On reports whether host logs are read (default on).
func (h SecurityLogsHost) On() bool { return h.Enabled == nil || *h.Enabled }

// securityOn reports whether security logs are on in c (a nil c is off).
func (c *Config) securityOn() bool { return c != nil && c.SecurityLogs.On() }

func unsetOn(b *bool) bool { return b == nil || *b }

// SecurityFeedGeoIP reports whether the DB-IP City and ASN Lite databases are downloaded and used
// (default on; off when security logs are off).
func (c *Config) SecurityFeedGeoIP() bool {
	return c.securityOn() && unsetOn(c.SecurityLogs.Feeds.GeoIP)
}

// SecurityFeedSpamhaus reports whether the Spamhaus DROP lists are downloaded and used (default on;
// off when security logs are off).
func (c *Config) SecurityFeedSpamhaus() bool {
	return c.securityOn() && unsetOn(c.SecurityLogs.Feeds.Spamhaus)
}

// SecurityFeedTor reports whether the Tor exit list is downloaded and used (default on; off when
// security logs are off).
func (c *Config) SecurityFeedTor() bool { return c.securityOn() && unsetOn(c.SecurityLogs.Feeds.Tor) }

// SecurityDShieldContact is the contact address sent with the DShield block list download; "" (the
// default, and always when security logs are off) means the list isn't downloaded.
func (c *Config) SecurityDShieldContact() string {
	if !c.securityOn() {
		return ""
	}
	return c.SecurityLogs.Feeds.DShieldContact
}

// SecurityDetectionOn reports whether the detection rules run (default on; off when security logs
// are off).
func (c *Config) SecurityDetectionOn() bool {
	return c.securityOn() && unsetOn(c.SecurityLogs.Detection.Enabled)
}

// clampInt is v clamped to [lo, hi], with def for 0 (unset).
func clampInt(v, def, lo, hi int) int {
	switch {
	case v == 0:
		return def
	case v < lo:
		return lo
	case v > hi:
		return hi
	}
	return v
}

// clampDur is d clamped to [lo, hi], with def for 0 (unset).
func clampDur(d, def, lo, hi time.Duration) time.Duration {
	switch {
	case d == 0:
		return def
	case d < lo:
		return lo
	case d > hi:
		return hi
	}
	return d
}

// SecurityPatternsOn reports whether log patterns are mined (default on; off when detection is off).
func (c *Config) SecurityPatternsOn() bool {
	return c.SecurityDetectionOn() && unsetOn(c.SecurityLogs.Detection.Patterns.Enabled)
}

// MaxCPUPercentOrDefault is MaxCPUPercent clamped (unset → the default).
func (p SecurityLogsPatterns) MaxCPUPercentOrDefault() int {
	return clampInt(p.MaxCPUPercent, DefaultSecurityPatternCPU, MinSecurityPatternCPU, MaxSecurityPatternCPU)
}

// SecurityResponseMode is the automated-response mode in force: siem.ResponseModeOff ("off") when
// detection is off or the mode is unset, else the configured "recommend" or "enforce" (Validate
// refuses any other value).
func (c *Config) SecurityResponseMode() string {
	if !c.SecurityDetectionOn() {
		return "off"
	}
	switch m := c.SecurityLogs.Response.Mode; m {
	case "recommend", "enforce":
		return m
	}
	return "off"
}

// MaxBlocksPerHourOrDefault is MaxBlocksPerHour clamped (unset → the default).
func (r SecurityLogsResponse) MaxBlocksPerHourOrDefault() int {
	return clampInt(r.MaxBlocksPerHour, DefaultSecurityMaxBlocksPerHour, 1, MaxSecurityMaxBlocksPerHour)
}

// MaxRevokesPerHourOrDefault is MaxRevokesPerHour clamped (unset → the default).
func (r SecurityLogsResponse) MaxRevokesPerHourOrDefault() int {
	return clampInt(r.MaxRevokesPerHour, DefaultSecurityMaxRevokesPerHour, 1, MaxSecurityMaxRevokesPerHour)
}

// MaxBlockDurationOrDefault is MaxBlockDuration clamped (unset → the default).
func (r SecurityLogsResponse) MaxBlockDurationOrDefault() time.Duration {
	return clampDur(time.Duration(r.MaxBlockDuration), DefaultSecurityMaxBlockDuration, MinSecurityMaxBlockDuration, MaxSecurityMaxBlockDuration)
}

// MaxEntriesOrDefault is MaxEntries clamped (unset → the default).
func (b SecurityLogsBlocking) MaxEntriesOrDefault() int {
	return clampInt(b.MaxEntries, DefaultSecurityBlockMaxEntries, 1, MaxSecurityBlockMaxEntries)
}

// ManualMaxDurationOrDefault is ManualMaxDuration clamped (unset → the default).
func (b SecurityLogsBlocking) ManualMaxDurationOrDefault() time.Duration {
	return clampDur(time.Duration(b.ManualMaxDuration), DefaultSecurityManualBlockDuration, MinSecurityManualBlockDuration, MaxSecurityManualBlockDuration)
}

// NeverBlockPrefixes is NeverBlock parsed (bare addresses as /32 or /128, IPv4-mapped as IPv4);
// Validate refuses an entry that doesn't parse, so none is dropped here on a loaded config.
func (b SecurityLogsBlocking) NeverBlockPrefixes() []netip.Prefix {
	out := make([]netip.Prefix, 0, len(b.NeverBlock))
	for _, s := range b.NeverBlock {
		if p, err := parsePrefix(s); err == nil {
			out = append(out, p)
		}
	}
	return out
}
