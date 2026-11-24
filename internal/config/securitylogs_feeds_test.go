package config

import (
	"strings"
	"testing"
)

// feedSwitches is every feed/detection accessor of a parsed config, in a fixed order.
func feedSwitches(t *testing.T, overrides string) (geoip, spamhaus, tor, detection bool, contact string) {
	t.Helper()
	cfg, err := Parse([]byte(validYAML(t, overrides)))
	if err != nil {
		t.Fatalf("%q refused: %v", overrides, err)
	}
	return cfg.SecurityFeedGeoIP(), cfg.SecurityFeedSpamhaus(), cfg.SecurityFeedTor(), cfg.SecurityDetectionOn(), cfg.SecurityDShieldContact()
}

// Unset feed and detection switches are on; dshield_contact unset is off. Each switch turns off only
// its own feed.
func TestSecurityFeedsDefaults(t *testing.T) {
	cases := []struct {
		name, yaml                     string
		geoip, spamhaus, tor, detected bool
		contact                        string
	}{
		{"no block", "", true, true, true, true, ""},
		{"empty feeds", "security_logs:\n  feeds: {}\n  detection: {}\n", true, true, true, true, ""},
		{"explicitly on", "security_logs:\n  feeds:\n    geoip: true\n    spamhaus: true\n    tor: true\n  detection:\n    enabled: true\n", true, true, true, true, ""},
		{"geoip off", "security_logs:\n  feeds:\n    geoip: false\n", false, true, true, true, ""},
		{"spamhaus off", "security_logs:\n  feeds:\n    spamhaus: false\n", true, false, true, true, ""},
		{"tor off", "security_logs:\n  feeds:\n    tor: false\n", true, true, false, true, ""},
		{"detection off", "security_logs:\n  detection:\n    enabled: false\n", true, true, true, false, ""},
		{"dshield on", "security_logs:\n  feeds:\n    dshield_contact: \"soc@example.com\"\n", true, true, true, true, "soc@example.com"},
		{"security logs off: everything off", "security_logs:\n  enabled: false\n  feeds:\n    geoip: true\n    spamhaus: true\n    tor: true\n    dshield_contact: \"soc@example.com\"\n  detection:\n    enabled: true\n",
			false, false, false, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g, s, tr, d, ct := feedSwitches(t, c.yaml)
			if g != c.geoip || s != c.spamhaus || tr != c.tor || d != c.detected || ct != c.contact {
				t.Errorf("geoip %v spamhaus %v tor %v detection %v contact %q; want %v %v %v %v %q",
					g, s, tr, d, ct, c.geoip, c.spamhaus, c.tor, c.detected, c.contact)
			}
		})
	}
	// A nil *Config (no config loaded) has everything off.
	var nilCfg *Config
	if nilCfg.SecurityFeedGeoIP() || nilCfg.SecurityFeedSpamhaus() || nilCfg.SecurityFeedTor() || nilCfg.SecurityDetectionOn() || nilCfg.SecurityDShieldContact() != "" {
		t.Error("a nil config must have every feed and detection off")
	}
}

// dshield_contact is "" or an email address; anything else refuses boot, with collection off too.
func TestSecurityDShieldContactValidated(t *testing.T) {
	contact := func(v string) string { return "security_logs:\n  feeds:\n    dshield_contact: " + v + "\n" }
	for _, ok := range []string{`""`, `"soc@example.com"`, `"a.b+c_d-e@sub.example.co.uk"`, `"x@y.io"`,
		`"` + strings.Repeat("a", 64) + `@` + strings.Repeat("b", 190) + `.` + strings.Repeat("c", 63) + `"`} {
		if _, err := Parse([]byte(validYAML(t, contact(ok)))); err != nil {
			t.Errorf("dshield_contact %s refused: %v", ok, err)
		}
	}
	for _, bad := range []string{
		`"soc"`, `"soc@"`, `"@example.com"`, `"soc@example"`, `"soc@example.c"`, `"soc@@example.com"`,
		`"so c@example.com"`, `"soc@exa mple.com"`, `"soc@example.com "`, `" soc@example.com"`,
		`"soc@example.com\r\nX-Injected: 1"`, `"soc\t@example.com"`, `"soc@example.com\u007f"`, `"soc\u001b@example.com"`,
		`"soc@example.com\u0085"`,
		`"` + strings.Repeat("a", 65) + `@example.com"`,
		`"soc@` + strings.Repeat("b", 191) + `.com"`,
		`"soc@example.` + strings.Repeat("c", 64) + `"`,
	} {
		mustReject(t, validYAML(t, contact(bad)), "security_logs.feeds.dshield_contact")
		mustReject(t, validYAML(t, contact(bad)), "email address")
	}
	mustReject(t, validYAML(t, "security_logs:\n  enabled: false\n  feeds:\n    dshield_contact: \"soc\"\n"), "security_logs.feeds.dshield_contact")
}

// The new keys are known to the strict decoder; an unknown one under them refuses boot.
func TestSecurityFeedsUnknownKeyRefused(t *testing.T) {
	mustReject(t, validYAML(t, "security_logs:\n  feeds:\n    firehol: true\n"), "firehol")
	mustReject(t, validYAML(t, "security_logs:\n  detection:\n    rules: []\n"), "rules")
}
