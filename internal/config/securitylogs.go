package config

import "time"

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
	Enabled *bool `yaml:"enabled"`
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
