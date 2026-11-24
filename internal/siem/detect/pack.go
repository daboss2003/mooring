package detect

import (
	"time"

	"github.com/daboss2003/mooring/internal/siem"
)

// packInfo words a built-in rule's detections ("57 failed SSH logins in 10m").
type packInfo struct {
	noun      string // what is counted, plural: "failed SSH logins"
	thenNoun  string // sequence: the closing event, "a successful login"
	fieldNoun string // distinct / new_value: what Field holds, plural / singular: "user names"
	subject   string // what the key is, when the group-by name doesn't say it: "account"
	groupAlt  string // the group-by field used when an event lacks GroupBy ("" when it has neither)
}

type packRule struct {
	siem.Rule
	info packInfo
}

// Threat-intel list names the enricher sets in Geo.Lists. A rule per list: an address can be on
// several lists (a Tor exit on Spamhaus DROP), and each list's rules fire for it. Tor exits are
// context: only the sign-in rules fire on that list.
const (
	listSpamhaus = "list:spamhaus-drop"
	listDShield  = "list:dshield"
	listTor      = "list:tor-exit"
)

// notForged leaves out host lines a non-root sender wrote as sudo, su or passwd (the journal's
// sender check sets f.sender_mismatch): their content can't be trusted. host.forged_log_line
// detects them.
const notForged = " -f.sender_mismatch:true"

// sshAttempt is a failed SSH login that tried a password (password or keyboard-interactive, any
// method but the ones that guess nothing: publickey, none, hostbased, GSSAPI).
const sshAttempt = "src:host kind:ssh.login out:failure -f.method:publickey -f.method:none -f.method:hostbased -f.method:gssapi*"

const (
	minute = time.Minute
	hour   = time.Hour
	day    = 24 * time.Hour
)

// The queries count each attempt once:
//   - SSH: an attempt for an unknown user name yields ssh.invalid_user, an ssh.login failure (one
//     per method tried: "none", then password) and ssh.disconnect. ssh.bruteforce counts the
//     password failures of existing users and one ssh.invalid_user per unknown-user connection;
//     ssh.spray counts names on ssh.invalid_user (password or key authentication). A publickey or
//     "none" failure is not an attempt: a client tries each key it has.
//   - su / sudo: a failed attempt yields the PAM line (f.reason "authentication failure") and
//     su's or sudo's own summary line; only the summary is counted.
//   - A syslog "message repeated N times" line counts N (F.repeated, host events only).
var pack = []packRule{
	// Host: SSH.
	{siem.Rule{ID: "ssh.bruteforce", Name: "SSH brute force",
		Description: "Many failed SSH password logins, or logins for unknown user names, from one address.",
		Type:        siem.RuleThreshold, Severity: siem.SevMedium, MITRE: []string{"T1110.001"},
		Query: "src:host kind:ssh.* -kind:ssh.disconnect -out:success -f.invalid:true -f.method:publickey " +
			"-f.method:none -f.method:hostbased -f.method:gssapi*" + notForged,
		GroupBy: "ip", Count: 20, Window: 10 * minute},
		packInfo{noun: "failed SSH logins"}},
	{siem.Rule{ID: "ssh.spray", Name: "SSH user name spray",
		Description: "One address tries many SSH user names that don't exist on the server.",
		Type:        siem.RuleDistinct, Severity: siem.SevMedium, MITRE: []string{"T1110.003"},
		Query: "src:host kind:ssh.invalid_user" + notForged, GroupBy: "ip", Field: "actor", Count: 10, Window: 10 * minute},
		packInfo{fieldNoun: "unknown user names"}},
	{siem.Rule{ID: "ssh.success_after_failures", Name: "SSH login after failed attempts",
		Description: "A successful SSH login from an address that failed to log in with a password several times just before.",
		Type:        siem.RuleSequence, Severity: siem.SevCritical, MITRE: []string{"T1110.001", "T1078"},
		Query: sshAttempt + notForged,
		Then:  "src:host kind:ssh.login out:success" + notForged, GroupBy: "ip", Count: 5, Window: hour},
		packInfo{noun: "failed SSH logins", thenNoun: "a successful login"}},
	{siem.Rule{ID: "ssh.login_new_country", Name: "SSH login from a new country",
		Description: "A successful SSH login for a user from a country not seen for that user before.",
		Type:        siem.RuleNewValue, Severity: siem.SevHigh, MITRE: []string{"T1078", "T1021.004"},
		Query: "src:host kind:ssh.login out:success" + notForged, GroupBy: "actor", Field: "geo.cc", Learn: 7 * day},
		packInfo{noun: "SSH logins", fieldNoun: "country"}},
	{siem.Rule{ID: "ssh.login_spamhaus_ip", Name: "SSH login from a Spamhaus DROP address",
		Description: "A successful SSH login from an address on the Spamhaus DROP list.",
		Type:        siem.RuleThreshold, Severity: siem.SevHigh, MITRE: []string{"T1078", "T1021.004"},
		Query: "src:host kind:ssh.login out:success " + listSpamhaus + notForged, GroupBy: "ip", Count: 1, Window: hour},
		packInfo{noun: "successful SSH logins from a Spamhaus DROP address"}},
	{siem.Rule{ID: "ssh.login_dshield_ip", Name: "SSH login from a DShield address",
		Description: "A successful SSH login from an address on the DShield block list.",
		Type:        siem.RuleThreshold, Severity: siem.SevHigh, MITRE: []string{"T1078", "T1021.004"},
		Query: "src:host kind:ssh.login out:success " + listDShield + notForged, GroupBy: "ip", Count: 1, Window: hour},
		packInfo{noun: "successful SSH logins from a DShield address"}},
	{siem.Rule{ID: "ssh.login_tor", Name: "SSH login over Tor",
		Description: "A successful SSH login from a Tor exit node.",
		Type:        siem.RuleThreshold, Severity: siem.SevMedium, MITRE: []string{"T1078", "T1090.003"},
		Query: "src:host kind:ssh.login out:success " + listTor + notForged, GroupBy: "ip", Count: 1, Window: hour},
		packInfo{noun: "successful SSH logins over Tor"}},
	{siem.Rule{ID: "ssh.login_travel", Name: "SSH login impossible travel",
		Description: "Two successful SSH logins of one user from places too far apart for the time between them.",
		Type:        siem.RuleTravel, Severity: siem.SevHigh, MITRE: []string{"T1078"},
		Query: "src:host kind:ssh.login out:success" + notForged, GroupBy: "actor", SpeedKMH: 1000},
		packInfo{noun: "SSH logins"}},

	// Host: privilege, accounts, Fail2Ban.
	{siem.Rule{ID: "sudo.failures", Name: "Failed sudo or su",
		Description: "A user failed sudo or su several times (wrong password, or not allowed).",
		Type:        siem.RuleThreshold, Severity: siem.SevMedium, MITRE: []string{"T1548.003"},
		Query:   `src:host kind:su* out:failure -f.reason:"authentication failure" -f.reason:"a password is required"` + notForged,
		GroupBy: "actor", Count: 3, Window: 15 * minute},
		packInfo{noun: "failed sudo or su attempts"}},
	{siem.Rule{ID: "host.user_change", Name: "Host account change",
		Description: "A user or group was added, changed or removed on the server, or a password was changed.",
		Type:        siem.RuleThreshold, Severity: siem.SevHigh, MITRE: []string{"T1136.001", "T1098"},
		Query: "src:host kind:host.user_change" + notForged, GroupBy: "f.user", Count: 1, Window: hour},
		packInfo{noun: "user or group changes", subject: "account", groupAlt: "f.group"}},
	{siem.Rule{ID: "host.forged_log_line", Name: "Forged host log line",
		Description: "A sudo, su or passwd line in the systemd journal sent by a user who could not have written it (logger -t sudo …).",
		Type:        siem.RuleThreshold, Severity: siem.SevMedium, MITRE: []string{"T1070"},
		Query: "src:host f.sender_mismatch:true", GroupBy: "f.sender_uid", Count: 1, Window: hour},
		packInfo{noun: "forged log lines", subject: "uid"}},
	{siem.Rule{ID: "fail2ban.ban_burst", Name: "Fail2Ban ban burst",
		Description: "Fail2Ban banned many addresses in one jail in a short time.",
		Type:        siem.RuleThreshold, Severity: siem.SevMedium, MITRE: []string{"T1110"},
		Query: "src:host kind:fail2ban.ban -f.restore:true", GroupBy: "f.jail", Count: 20, Window: 10 * minute},
		packInfo{noun: "bans"}},

	// Mooring's own sign-in and accounts.
	{siem.Rule{ID: "mooring.login_bruteforce", Name: "Mooring sign-in brute force",
		Description: "Many failed sign-ins to the Mooring dashboard from one address.",
		Type:        siem.RuleThreshold, Severity: siem.SevHigh, MITRE: []string{"T1110.001"},
		Query: "src:mooring kind:mooring.login out:failure", GroupBy: "ip", Count: 10, Window: 15 * minute},
		packInfo{noun: "failed sign-ins"}},
	{siem.Rule{ID: "mooring.login_spray", Name: "Mooring sign-in spray",
		Description: "Failed sign-ins to the Mooring dashboard for many user names from one address.",
		Type:        siem.RuleDistinct, Severity: siem.SevHigh, MITRE: []string{"T1110.003"},
		Query: "src:mooring kind:mooring.login out:failure", GroupBy: "ip", Field: "actor", Count: 5, Window: 30 * minute},
		packInfo{fieldNoun: "user names"}},
	{siem.Rule{ID: "mooring.login_success_after_failures", Name: "Mooring sign-in after failed attempts",
		Description: "A successful sign-in to the Mooring dashboard from an address that failed several times just before.",
		Type:        siem.RuleSequence, Severity: siem.SevCritical, MITRE: []string{"T1110.001", "T1078"},
		Query: "src:mooring kind:mooring.login out:failure", Then: "src:mooring kind:mooring.login out:success",
		GroupBy: "ip", Count: 5, Window: hour},
		packInfo{noun: "failed sign-ins", thenNoun: "a successful sign-in"}},
	{siem.Rule{ID: "mooring.login_new_country", Name: "Mooring sign-in from a new country",
		Description: "A Mooring user signed in from a country not seen for that user before.",
		Type:        siem.RuleNewValue, Severity: siem.SevHigh, MITRE: []string{"T1078"},
		Query: "src:mooring kind:mooring.login out:success", GroupBy: "actor", Field: "geo.cc", Learn: 7 * day},
		packInfo{noun: "sign-ins", fieldNoun: "country"}},
	{siem.Rule{ID: "mooring.login_tor", Name: "Mooring sign-in over Tor",
		Description: "A successful sign-in to the Mooring dashboard from a Tor exit node.",
		Type:        siem.RuleThreshold, Severity: siem.SevMedium, MITRE: []string{"T1078", "T1090.003"},
		Query: "src:mooring kind:mooring.login out:success " + listTor, GroupBy: "ip", Count: 1, Window: hour},
		packInfo{noun: "sign-ins over Tor"}},
	{siem.Rule{ID: "mooring.login_travel", Name: "Mooring sign-in impossible travel",
		Description: "Two sign-ins of one Mooring user from places too far apart for the time between them.",
		Type:        siem.RuleTravel, Severity: siem.SevHigh, MITRE: []string{"T1078"},
		Query: "src:mooring kind:mooring.login out:success", GroupBy: "actor", SpeedKMH: 1000},
		packInfo{noun: "sign-ins"}},
	{siem.Rule{ID: "mooring.lockout", Name: "Mooring account locked out",
		Description: "Too many failed sign-ins locked a Mooring user out.",
		Type:        siem.RuleThreshold, Severity: siem.SevMedium, MITRE: []string{"T1110"},
		Query: "src:mooring kind:mooring.login_lockout", GroupBy: "actor", Count: 1, Window: hour},
		packInfo{noun: "lockouts"}},
	{siem.Rule{ID: "mooring.user_change", Name: "Mooring user change",
		Description: "A Mooring user was added or removed, or their role, password or two-factor setting changed.",
		Type:        siem.RuleThreshold, Severity: siem.SevHigh, MITRE: []string{"T1098", "T1136"},
		Query: "src:mooring kind:mooring.user_*", GroupBy: "f.target", Count: 1, Window: hour},
		packInfo{noun: "user changes", subject: "user"}},
	{siem.Rule{ID: "mooring.api_token_spamhaus_ip", Name: "API token used from a Spamhaus DROP address",
		Description: "A Mooring API token was used from an address on the Spamhaus DROP list.",
		Type:        siem.RuleThreshold, Severity: siem.SevHigh, MITRE: []string{"T1550.001"},
		Query: "src:mooring kind:mooring.api_token_use " + listSpamhaus, GroupBy: "ip", Count: 1, Window: hour},
		packInfo{noun: "API token uses from a Spamhaus DROP address"}},
	{siem.Rule{ID: "mooring.api_token_dshield_ip", Name: "API token used from a DShield address",
		Description: "A Mooring API token was used from an address on the DShield block list.",
		Type:        siem.RuleThreshold, Severity: siem.SevHigh, MITRE: []string{"T1550.001"},
		Query: "src:mooring kind:mooring.api_token_use " + listDShield, GroupBy: "ip", Count: 1, Window: hour},
		packInfo{noun: "API token uses from a DShield address"}},
	{siem.Rule{ID: "mooring.api_auth_failures", Name: "Mooring API authentication failures",
		Description: "Many API requests with a missing, unknown or invalid token from one address.",
		Type:        siem.RuleThreshold, Severity: siem.SevMedium, MITRE: []string{"T1110"},
		Query: "src:mooring kind:mooring.api_request out:failure", GroupBy: "ip", Count: 10, Window: 10 * minute},
		packInfo{noun: "refused API requests"}},

	// App security events (an app's own sign-in, MFA, admin, API key and device events).
	{siem.Rule{ID: "app.auth_bruteforce", Name: "App sign-in brute force",
		Description: "Many failed sign-ins (auth.login, admin.login) to an app from one address.",
		Type:        siem.RuleThreshold, Severity: siem.SevMedium, MITRE: []string{"T1110.001"},
		Query: "src:app kind~.login out:failure", GroupBy: "ip", Count: 20, Window: 10 * minute},
		packInfo{noun: "failed sign-ins"}},
	{siem.Rule{ID: "app.auth_spray", Name: "App sign-in spray",
		Description: "Failed sign-ins to an app for many accounts from one address.",
		Type:        siem.RuleDistinct, Severity: siem.SevMedium, MITRE: []string{"T1110.003"},
		Query: "src:app kind~.login out:failure", GroupBy: "ip", Field: "actor", Count: 10, Window: 10 * minute},
		packInfo{fieldNoun: "accounts"}},
	{siem.Rule{ID: "app.auth_success_after_failures", Name: "App sign-in after failed attempts",
		Description: "A successful sign-in to an app for an account that failed many times just before.",
		Type:        siem.RuleSequence, Severity: siem.SevHigh, MITRE: []string{"T1110.001", "T1078"},
		Query: "src:app kind~.login out:failure", Then: "src:app kind~.login out:success",
		GroupBy: "actor", Count: 10, Window: hour},
		packInfo{noun: "failed sign-ins", thenNoun: "a successful sign-in"}},
	{siem.Rule{ID: "app.auth_new_country", Name: "App sign-in from a new country",
		Description: "An app account signed in from a country not seen for that account before.",
		Type:        siem.RuleNewValue, Severity: siem.SevMedium, MITRE: []string{"T1078"},
		Query: "src:app kind:auth.login out:success", GroupBy: "actor", Field: "geo.cc", Learn: 14 * day},
		packInfo{noun: "sign-ins", fieldNoun: "country"}},
	{siem.Rule{ID: "app.admin_new_country", Name: "App admin sign-in from a new country",
		Description: "An app administrator signed in from a country not seen for that account before.",
		Type:        siem.RuleNewValue, Severity: siem.SevHigh, MITRE: []string{"T1078"},
		Query: "src:app kind:admin.login out:success", GroupBy: "actor", Field: "geo.cc", Learn: 14 * day},
		packInfo{noun: "admin sign-ins", fieldNoun: "country"}},
	{siem.Rule{ID: "app.mfa_failures", Name: "App MFA failures",
		Description: "Repeated failed second-factor checks (auth.mfa_failed, admin.mfa_failed) for one account: the password was right.",
		Type:        siem.RuleThreshold, Severity: siem.SevHigh, MITRE: []string{"T1110", "T1078"},
		Query: "src:app kind~.mfa_failed", GroupBy: "actor", Count: 5, Window: 15 * minute},
		packInfo{noun: "failed second-factor checks"}},
	{siem.Rule{ID: "app.admin_spamhaus_ip", Name: "App admin sign-in from a Spamhaus DROP address",
		Description: "A successful app admin sign-in from an address on the Spamhaus DROP list.",
		Type:        siem.RuleThreshold, Severity: siem.SevHigh, MITRE: []string{"T1078"},
		Query: "src:app kind:admin.login out:success " + listSpamhaus, GroupBy: "ip", Count: 1, Window: hour},
		packInfo{noun: "admin sign-ins from a Spamhaus DROP address"}},
	{siem.Rule{ID: "app.admin_dshield_ip", Name: "App admin sign-in from a DShield address",
		Description: "A successful app admin sign-in from an address on the DShield block list.",
		Type:        siem.RuleThreshold, Severity: siem.SevHigh, MITRE: []string{"T1078"},
		Query: "src:app kind:admin.login out:success " + listDShield, GroupBy: "ip", Count: 1, Window: hour},
		packInfo{noun: "admin sign-ins from a DShield address"}},
	{siem.Rule{ID: "app.admin_tor_login", Name: "App admin sign-in over Tor",
		Description: "A successful app admin sign-in from a Tor exit node.",
		Type:        siem.RuleThreshold, Severity: siem.SevHigh, MITRE: []string{"T1078", "T1090.003"},
		Query: "src:app kind:admin.login out:success " + listTor, GroupBy: "ip", Count: 1, Window: hour},
		packInfo{noun: "admin sign-ins over Tor"}},
	{siem.Rule{ID: "app.privilege_change", Name: "App role change",
		Description: "An app user's or administrator's role changed (user.role_changed, admin.role_changed).",
		Type:        siem.RuleThreshold, Severity: siem.SevMedium, MITRE: []string{"T1098"},
		Query: "src:app kind~.role_changed", GroupBy: "actor", Count: 1, Window: hour},
		packInfo{noun: "role changes"}},
	{siem.Rule{ID: "app.apikey_created", Name: "App API key created",
		Description: "An API key was created in an app (apikey.created).",
		Type:        siem.RuleThreshold, Severity: siem.SevLow, MITRE: []string{"T1098.001"},
		Query: "src:app kind:apikey.created", GroupBy: "actor", Count: 1, Window: hour},
		packInfo{noun: "API keys created"}},
	{siem.Rule{ID: "app.device_auth_failures", Name: "App device authentication failures",
		Description: "Many device requests with a bad signature (device.auth_failed) from one address.",
		Type:        siem.RuleThreshold, Severity: siem.SevMedium, MITRE: []string{"T1110"},
		Query: "src:app kind:device.auth_failed", GroupBy: "ip", Count: 20, Window: 10 * minute},
		packInfo{noun: "failed device authentications"}},
	{siem.Rule{ID: "app.device_shell", Name: "Remote shell on a device",
		Description: "A remote shell was opened on a device (device.shell_opened).",
		Type:        siem.RuleThreshold, Severity: siem.SevMedium, MITRE: []string{"T1059"},
		Query: "src:app kind:device.shell_opened", GroupBy: "actor", Count: 1, Window: hour},
		packInfo{noun: "remote shells opened"}},

	// Edge.
	{siem.Rule{ID: "edge.scan", Name: "Web scan",
		Description: "Many requests answered 404 for one address: a scanner looking for files and paths.",
		Type:        siem.RuleThreshold, Severity: siem.SevLow, MITRE: []string{"T1595.003"},
		Query: "src:edge kind:http.request f.status:404", GroupBy: "ip", Count: 100, Window: 5 * minute},
		packInfo{noun: "requests answered 404"}},
	{siem.Rule{ID: "edge.spamhaus_ip", Name: "Requests from a Spamhaus DROP address",
		Description: "Requests through the edge from an address on the Spamhaus DROP list.",
		Type:        siem.RuleThreshold, Severity: siem.SevLow, MITRE: []string{"T1595"},
		Query: "src:edge kind:http.request " + listSpamhaus, GroupBy: "ip", Count: 1, Window: hour},
		packInfo{noun: "requests from a Spamhaus DROP address"}},
	{siem.Rule{ID: "edge.dshield_ip", Name: "Requests from a DShield address",
		Description: "Requests through the edge from an address on the DShield block list.",
		Type:        siem.RuleThreshold, Severity: siem.SevLow, MITRE: []string{"T1595"},
		Query: "src:edge kind:http.request " + listDShield, GroupBy: "ip", Count: 1, Window: hour},
		packInfo{noun: "requests from a DShield address"}},
	{siem.Rule{ID: "edge.error_anomaly", Name: "Server error surge",
		Description: "Far more 5xx responses for one host name than usual.",
		Type:        siem.RuleAnomaly, Severity: siem.SevMedium, MITRE: []string{"T1499"},
		Query: "src:edge kind:http.request f.status>=500", GroupBy: "f.host", Count: 50, Window: 10 * minute,
		Factor: 5, Learn: 3 * day},
		packInfo{noun: "server errors"}},
}

var packByID = func() map[string]*packRule {
	m := make(map[string]*packRule, len(pack))
	for i := range pack {
		pack[i].Enabled, pack[i].Builtin = true, true
		m[pack[i].ID] = &pack[i]
	}
	return m
}()

// Pack returns the built-in rules with their default settings.
func Pack() []siem.Rule {
	out := make([]siem.Rule, len(pack))
	for i, p := range pack {
		out[i] = cloneRule(p.Rule)
	}
	return out
}
