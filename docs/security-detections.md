# Security detections

Mooring evaluates detection rules over every [security log](./security-logs.md) event as it is
collected. A rule that matches records a **detection**; high and critical detections are also sent
to your [alert channels](./alerting.md). A built-in pack of rules covers SSH, sudo and su, host
account changes, Fail2Ban, Mooring's own sign-ins and API tokens, the edge, and the security events
your app writes. Each built-in rule is tagged with the MITRE ATT&CK® techniques it detects. You can
switch rules off, tune them, snooze them, and add your own. Only an **owner** can see detections
and change rules.

Detection runs whenever security logs are on. It is **on by default**.

See also: [Security logs](./security-logs.md) · [Alerts](./alerting.md) · [App Ops Interface alerts](./app-ops-interface.md#alerts)

---

## How rules are evaluated

- Every event is evaluated after redaction: the actor, emails, phone numbers and other personal data
  are keyed hashes, as stored. A rule's query is written with clear values and matches the hashes,
  as on the Security logs page (see [Search](./security-logs.md#search)).
- Windows use each event's own timestamp (`ts`). Events older than 24 hours or more than 5 minutes
  ahead of the server clock are stored and searchable but not evaluated (for example a backlog of
  host log lines read after Mooring was stopped).
- A host log line `message repeated N times: [ … ]` counts as N events (at most 1000). In app and
  edge events, an `f.repeated` field counts as one event.
- A `sudo`, `su` or `passwd` line from the systemd journal that its sender couldn't have written
  (`f.sender_mismatch: true`, see [Host log access](./security-logs.md#host-log-access)) counts for no host rule except
  `host.forged_log_line`.
- `siem.*` events (detections, dropped events, archive failures) are never evaluated.
- Rules that use a location or a threat-intelligence list (`geo.cc`, the travel rules, `list:`)
  need the enrichment feeds; without them, an event has no `geo` and those rules don't match it.

## Rule types

Every rule has a query (the events it counts, in the [search syntax](./security-logs.md#search))
and a group-by field: state is kept, and detections are recorded, per value of that field (per
address, per actor, …). An event without the group-by field is skipped.

| Type | Fires when | Parameters |
|---|---|---|
| `threshold` | At least `count` matching events for one key within `window`. | `count` 1–100000, `window` 1m–7d |
| `distinct` | At least `count` different values of `field` for one key within `window`. | `field`, `count` 1–1000, `window` 1m–7d |
| `new_value` | An event for a known key has a value of `field` not seen for that key before. A key seen for the first time is learned without firing. Values are learned for `learn` after the rule's first matching event before any fires. | `field`, `learn` 0–30d |
| `anomaly` | At least `count` matching events for one key within `window`, and more than `factor` times the key's usual count per `window`. The usual count is the key's average per hour over its last 7 days (before the current window), scaled to the window; a key without earlier events has a usual count of 0. The rule fires only once `learn` has passed since its first matching event. | `count` 1–100000, `window` 1m–24h, `factor` 1.5–1000, `learn` 0–30d |
| `travel` | Two consecutive matching events of one key come from IP locations more than 500 km apart, at a speed above `speed_kmh` for the time between them. Events without a location are skipped. | `speed_kmh` 100–20000 |
| `sequence` | At least `count` events matching the query, then one matching the closing query (`then`), for one key within `window`. A closing event starts the key's count again from zero, whether or not the rule fired. | `then`, `count` 1–1000, `window` 1m–7d |

Group-by and field names: `ip`, `actor`, `app`, `kind`, `geo.cc`, `geo.asn`, `f.<name>` (a key of
`f`), or empty for the whole rule (group-by only).

- `ip`: an IPv4 address is the key as it is. An IPv6 address counts as its /64 prefix
  (`2001:db8:1:2::/64`), and an IPv4-mapped IPv6 address as the IPv4 address.
- `f.host`: the value is lowercased, without a port or a trailing dot (`Shop.Example.com:443` is
  `shop.example.com`).

After a `threshold`, `distinct`, `anomaly` or `sequence` rule fires for a key, its count for that
key starts again from zero.

## Built-in rules

| ID | Detects | Type | Default | Severity | MITRE ATT&CK |
|---|---|---|---|---|---|
| `ssh.bruteforce` | Many failed SSH password logins, or logins for unknown user names, from one address. | `threshold` | 20 in 10m per `ip` | medium | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) |
| `ssh.spray` | One address tries many SSH user names that don't exist on the server. | `distinct` | 10 `actor` values in 10m per `ip` | medium | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) |
| `ssh.success_after_failures` | A successful SSH login from an address that failed to log in with a password several times just before. | `sequence` | 5, then 1, in 1h per `ip` | critical | [T1110.001](https://attack.mitre.org/techniques/T1110/001/), [T1078](https://attack.mitre.org/techniques/T1078/) |
| `ssh.login_new_country` | A successful SSH login for a user from a country not seen for that user before. | `new_value` | new `geo.cc` per `actor`; learns 7d | high | [T1078](https://attack.mitre.org/techniques/T1078/), [T1021.004](https://attack.mitre.org/techniques/T1021/004/) |
| `ssh.login_spamhaus_ip` | A successful SSH login from an address on the Spamhaus DROP list. | `threshold` | 1 in 1h per `ip` | high | [T1078](https://attack.mitre.org/techniques/T1078/), [T1021.004](https://attack.mitre.org/techniques/T1021/004/) |
| `ssh.login_dshield_ip` | A successful SSH login from an address on the DShield block list. | `threshold` | 1 in 1h per `ip` | high | [T1078](https://attack.mitre.org/techniques/T1078/), [T1021.004](https://attack.mitre.org/techniques/T1021/004/) |
| `ssh.login_tor` | A successful SSH login from a Tor exit node. | `threshold` | 1 in 1h per `ip` | medium | [T1078](https://attack.mitre.org/techniques/T1078/), [T1090.003](https://attack.mitre.org/techniques/T1090/003/) |
| `ssh.login_travel` | Two successful SSH logins of one user from places too far apart for the time between them. | `travel` | over 1000 km/h per `actor` | high | [T1078](https://attack.mitre.org/techniques/T1078/) |
| `sudo.failures` | A user failed sudo or su several times (wrong password, or not allowed). | `threshold` | 3 in 15m per `actor` | medium | [T1548.003](https://attack.mitre.org/techniques/T1548/003/) |
| `host.user_change` | A user or group was added, changed or removed on the server, or a password was changed. | `threshold` | 1 in 1h per `f.user` (else `f.group`; lines naming neither count together) | high | [T1136.001](https://attack.mitre.org/techniques/T1136/001/), [T1098](https://attack.mitre.org/techniques/T1098/) |
| `host.forged_log_line` | A sudo, su or passwd line in the systemd journal sent by a user who could not have written it (`logger -t sudo …`). | `threshold` | 1 in 1h per `f.sender_uid` | medium | [T1070](https://attack.mitre.org/techniques/T1070/) |
| `fail2ban.ban_burst` | Fail2Ban banned many addresses in one jail in a short time. | `threshold` | 20 in 10m per `f.jail` | medium | [T1110](https://attack.mitre.org/techniques/T1110/) |
| `mooring.login_bruteforce` | Many failed sign-ins to the Mooring dashboard from one address. | `threshold` | 10 in 15m per `ip` | high | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) |
| `mooring.login_spray` | Failed sign-ins to the Mooring dashboard for many user names from one address. | `distinct` | 5 `actor` values in 30m per `ip` | high | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) |
| `mooring.login_success_after_failures` | A successful sign-in to the Mooring dashboard from an address that failed several times just before. | `sequence` | 5, then 1, in 1h per `ip` | critical | [T1110.001](https://attack.mitre.org/techniques/T1110/001/), [T1078](https://attack.mitre.org/techniques/T1078/) |
| `mooring.login_new_country` | A Mooring user signed in from a country not seen for that user before. | `new_value` | new `geo.cc` per `actor`; learns 7d | high | [T1078](https://attack.mitre.org/techniques/T1078/) |
| `mooring.login_tor` | A successful sign-in to the Mooring dashboard from a Tor exit node. | `threshold` | 1 in 1h per `ip` | medium | [T1078](https://attack.mitre.org/techniques/T1078/), [T1090.003](https://attack.mitre.org/techniques/T1090/003/) |
| `mooring.login_travel` | Two sign-ins of one Mooring user from places too far apart for the time between them. | `travel` | over 1000 km/h per `actor` | high | [T1078](https://attack.mitre.org/techniques/T1078/) |
| `mooring.lockout` | Too many failed sign-ins locked a Mooring user out. | `threshold` | 1 in 1h per `actor` | medium | [T1110](https://attack.mitre.org/techniques/T1110/) |
| `mooring.user_change` | A Mooring user was added or removed, or their role, password or two-factor setting changed. | `threshold` | 1 in 1h per `f.target` (the user changed) | high | [T1098](https://attack.mitre.org/techniques/T1098/), [T1136](https://attack.mitre.org/techniques/T1136/) |
| `mooring.api_token_spamhaus_ip` | A Mooring API token was used from an address on the Spamhaus DROP list. | `threshold` | 1 in 1h per `ip` | high | [T1550.001](https://attack.mitre.org/techniques/T1550/001/) |
| `mooring.api_token_dshield_ip` | A Mooring API token was used from an address on the DShield block list. | `threshold` | 1 in 1h per `ip` | high | [T1550.001](https://attack.mitre.org/techniques/T1550/001/) |
| `mooring.api_auth_failures` | Many API requests with a missing, unknown or invalid token from one address. | `threshold` | 10 in 10m per `ip` | medium | [T1110](https://attack.mitre.org/techniques/T1110/) |
| `app.auth_bruteforce` | Many failed sign-ins (auth.login, admin.login) to an app from one address. | `threshold` | 20 in 10m per `ip` | medium | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) |
| `app.auth_spray` | Failed sign-ins to an app for many accounts from one address. | `distinct` | 10 `actor` values in 10m per `ip` | medium | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) |
| `app.auth_success_after_failures` | A successful sign-in to an app for an account that failed many times just before. | `sequence` | 10, then 1, in 1h per `actor` | high | [T1110.001](https://attack.mitre.org/techniques/T1110/001/), [T1078](https://attack.mitre.org/techniques/T1078/) |
| `app.auth_new_country` | An app account signed in from a country not seen for that account before. | `new_value` | new `geo.cc` per `actor`; learns 14d | medium | [T1078](https://attack.mitre.org/techniques/T1078/) |
| `app.admin_new_country` | An app administrator signed in from a country not seen for that account before. | `new_value` | new `geo.cc` per `actor`; learns 14d | high | [T1078](https://attack.mitre.org/techniques/T1078/) |
| `app.mfa_failures` | Repeated failed second-factor checks (auth.mfa_failed, admin.mfa_failed) for one account: the password was right. | `threshold` | 5 in 15m per `actor` | high | [T1110](https://attack.mitre.org/techniques/T1110/), [T1078](https://attack.mitre.org/techniques/T1078/) |
| `app.admin_spamhaus_ip` | A successful app admin sign-in from an address on the Spamhaus DROP list. | `threshold` | 1 in 1h per `ip` | high | [T1078](https://attack.mitre.org/techniques/T1078/) |
| `app.admin_dshield_ip` | A successful app admin sign-in from an address on the DShield block list. | `threshold` | 1 in 1h per `ip` | high | [T1078](https://attack.mitre.org/techniques/T1078/) |
| `app.admin_tor_login` | A successful app admin sign-in from a Tor exit node. | `threshold` | 1 in 1h per `ip` | high | [T1078](https://attack.mitre.org/techniques/T1078/), [T1090.003](https://attack.mitre.org/techniques/T1090/003/) |
| `app.privilege_change` | An app user's or administrator's role changed (user.role_changed, admin.role_changed). | `threshold` | 1 in 1h per `actor` | medium | [T1098](https://attack.mitre.org/techniques/T1098/) |
| `app.apikey_created` | An API key was created in an app (apikey.created). | `threshold` | 1 in 1h per `actor` | low | [T1098.001](https://attack.mitre.org/techniques/T1098/001/) |
| `app.device_auth_failures` | Many device requests with a bad signature (device.auth_failed) from one address. | `threshold` | 20 in 10m per `ip` | medium | [T1110](https://attack.mitre.org/techniques/T1110/) |
| `app.device_shell` | A remote shell was opened on a device (device.shell_opened). | `threshold` | 1 in 1h per `actor` | medium | [T1059](https://attack.mitre.org/techniques/T1059/) |
| `edge.scan` | Many requests answered 404 for one address: a scanner looking for files and paths. | `threshold` | 100 in 5m per `ip` | low | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) |
| `edge.spamhaus_ip` | Requests through the edge from an address on the Spamhaus DROP list. | `threshold` | 1 in 1h per `ip` | low | [T1595](https://attack.mitre.org/techniques/T1595/) |
| `edge.dshield_ip` | Requests through the edge from an address on the DShield block list. | `threshold` | 1 in 1h per `ip` | low | [T1595](https://attack.mitre.org/techniques/T1595/) |
| `edge.error_anomaly` | Far more 5xx responses for one host name than usual. | `anomaly` | 50 and 5× usual in 10m per `f.host`; learns 3d | medium | [T1499](https://attack.mitre.org/techniques/T1499/) |

All built-in rules are on by default. The `app.*` rules match the event names in
[Security events from your app](./security-logs.md#security-events-from-your-app): `auth.login`,
`admin.login`, `auth.mfa_failed`, `admin.mfa_failed`, `user.role_changed`, `admin.role_changed`,
`apikey.created`, `device.auth_failed` and `device.shell_opened`, with `outcome`, `ip` and the
account (`actor_id`, else `account`).

Each attempt is counted once:

- An SSH login that fails with a password (`f.method` `password` or `keyboard-interactive`) is one
  attempt. A failure with `publickey`, `none`, `hostbased` or GSSAPI is not counted: a client tries
  each key it has, and `none` is the first request of every login.
- An SSH attempt for a user name that doesn't exist logs `ssh.invalid_user`, `ssh.login` failures
  (`f.invalid: true`; `none`, then the password) and `ssh.disconnect`. `ssh.bruteforce` counts the
  `ssh.invalid_user` event, once per connection. `ssh.spray` counts the names on
  `ssh.invalid_user`, which is logged with key authentication too.
- A failed `su` or `sudo` logs a PAM line (`f.reason` `authentication failure`) and su's or sudo's
  own line. `sudo.failures` counts only the second. `sudo -n` without a cached password
  (`a password is required`) is not counted.

Threat-intelligence lists: each list has its own rules (`list:spamhaus-drop`, `list:dshield`), and
an address on several lists fires the rules of each. An address on the Tor exit list
(`list:tor-exit`) fires only the sign-in rules: `ssh.login_tor` and `mooring.login_tor` (medium),
and `app.admin_tor_login` (high). An address that is a Tor exit and on the Spamhaus DROP or DShield
list fires those lists' rules too.

The queries:

| ID | Query | Closing query (`then`) |
|---|---|---|
| `ssh.bruteforce` | `src:host kind:ssh.* -kind:ssh.disconnect -out:success -f.invalid:true -f.method:publickey -f.method:none -f.method:hostbased -f.method:gssapi* -f.sender_mismatch:true` |  |
| `ssh.spray` | `src:host kind:ssh.invalid_user -f.sender_mismatch:true` |  |
| `ssh.success_after_failures` | `src:host kind:ssh.login out:failure -f.method:publickey -f.method:none -f.method:hostbased -f.method:gssapi* -f.sender_mismatch:true` | `src:host kind:ssh.login out:success -f.sender_mismatch:true` |
| `ssh.login_new_country` | `src:host kind:ssh.login out:success -f.sender_mismatch:true` |  |
| `ssh.login_spamhaus_ip` | `src:host kind:ssh.login out:success list:spamhaus-drop -f.sender_mismatch:true` |  |
| `ssh.login_dshield_ip` | `src:host kind:ssh.login out:success list:dshield -f.sender_mismatch:true` |  |
| `ssh.login_tor` | `src:host kind:ssh.login out:success list:tor-exit -f.sender_mismatch:true` |  |
| `ssh.login_travel` | `src:host kind:ssh.login out:success -f.sender_mismatch:true` |  |
| `sudo.failures` | `src:host kind:su* out:failure -f.reason:"authentication failure" -f.reason:"a password is required" -f.sender_mismatch:true` |  |
| `host.user_change` | `src:host kind:host.user_change -f.sender_mismatch:true` |  |
| `host.forged_log_line` | `src:host f.sender_mismatch:true` |  |
| `fail2ban.ban_burst` | `src:host kind:fail2ban.ban -f.restore:true` |  |
| `mooring.login_bruteforce` | `src:mooring kind:mooring.login out:failure` |  |
| `mooring.login_spray` | `src:mooring kind:mooring.login out:failure` |  |
| `mooring.login_success_after_failures` | `src:mooring kind:mooring.login out:failure` | `src:mooring kind:mooring.login out:success` |
| `mooring.login_new_country` | `src:mooring kind:mooring.login out:success` |  |
| `mooring.login_tor` | `src:mooring kind:mooring.login out:success list:tor-exit` |  |
| `mooring.login_travel` | `src:mooring kind:mooring.login out:success` |  |
| `mooring.lockout` | `src:mooring kind:mooring.login_lockout` |  |
| `mooring.user_change` | `src:mooring kind:mooring.user_*` |  |
| `mooring.api_token_spamhaus_ip` | `src:mooring kind:mooring.api_token_use list:spamhaus-drop` |  |
| `mooring.api_token_dshield_ip` | `src:mooring kind:mooring.api_token_use list:dshield` |  |
| `mooring.api_auth_failures` | `src:mooring kind:mooring.api_request out:failure` |  |
| `app.auth_bruteforce` | `src:app kind~.login out:failure` |  |
| `app.auth_spray` | `src:app kind~.login out:failure` |  |
| `app.auth_success_after_failures` | `src:app kind~.login out:failure` | `src:app kind~.login out:success` |
| `app.auth_new_country` | `src:app kind:auth.login out:success` |  |
| `app.admin_new_country` | `src:app kind:admin.login out:success` |  |
| `app.mfa_failures` | `src:app kind~.mfa_failed` |  |
| `app.admin_spamhaus_ip` | `src:app kind:admin.login out:success list:spamhaus-drop` |  |
| `app.admin_dshield_ip` | `src:app kind:admin.login out:success list:dshield` |  |
| `app.admin_tor_login` | `src:app kind:admin.login out:success list:tor-exit` |  |
| `app.privilege_change` | `src:app kind~.role_changed` |  |
| `app.apikey_created` | `src:app kind:apikey.created` |  |
| `app.device_auth_failures` | `src:app kind:device.auth_failed` |  |
| `app.device_shell` | `src:app kind:device.shell_opened` |  |
| `edge.scan` | `src:edge kind:http.request f.status:404` |  |
| `edge.spamhaus_ip` | `src:edge kind:http.request list:spamhaus-drop` |  |
| `edge.dshield_ip` | `src:edge kind:http.request list:dshield` |  |
| `edge.error_anomaly` | `src:edge kind:http.request f.status>=500` |  |

## Changing a built-in rule

On a built-in rule's **Edit** page it can be switched off and on, and its severity, `count`,
`window`, `factor`, `learn` and `speed_kmh` changed (within the ranges in [Rule types](#rule-types)).
Its query, type, group-by and field can't be changed. **Reset** puts it back to the defaults above.

**Snooze** (1 hour, 24 hours or 7 days; at most 30 days) keeps a rule's detections recorded but
sends no alert for them until the snooze ends.

A stored setting of a built-in rule that is no longer valid (for example after an upgrade changed a
range) is not used: that setting has its default value, and the rule's other stored settings are
kept.

A change takes effect at once. Tuning keeps what a rule has counted and learned; changing a custom
rule's type, query, closing query, group-by or field starts it again.

## Custom rules

**New custom rule** on the Rules page creates a rule of any type with your own query.

| Field | Limits |
|---|---|
| ID | `custom.` and a slug: lowercase letters, digits and `-`, starting with a letter or digit, at most 48 characters (`custom.admin-from-new-asn`). |
| Name | Required, plain text, at most 80 bytes. |
| Description | At most 500 bytes. |
| Type and parameters | See [Rule types](#rule-types). |
| Query, closing query | The [search syntax](./security-logs.md#search): at most 2 KiB and 32 terms each. A value for a personal-data field is typed in clear (`actor:alice@example.com`) and matched against its hash. |
| Group-by, field | `ip`, `actor`, `app`, `kind`, `geo.cc`, `geo.asn`, `f.<name>`; group-by may be empty. |
| Severity | `low`, `medium`, `high` or `critical`. |
| MITRE ATT&CK | Up to 8 technique IDs (`T1110`, `T1110.001`). |

At most 100 custom rules. A rule that doesn't validate is refused with the reason.

A stored custom rule that no longer validates (for example a query field a later release renamed)
is listed on the Rules page switched off, with its description replaced by `stored rule is
invalid: <reason>`. It is not evaluated, counts toward the 100, and can be edited or deleted.

## Detections

A detection is one rule firing for one key. While the rule keeps firing for that key, the same
detection is updated: a firing within the rule's `window` (or 1 hour, when that is longer) after the
detection's last event adds its events to the count, moves its last time, and adds to its evidence
(the 10 newest events behind it). A later firing starts a new detection.

A rule records at most 50 new detections per hour of the server clock. Past that, the hour's other
keys are counted in one detection of the rule with key `*`, whose count is the number of those keys
(each counted once) and whose summary is:

```
and 37 more keys this hour (at most 50 new detections per rule an hour)
```

A key recorded in the hour keeps updating its own detection. The next hour starts again at 0. The
limit holds across a restart of Mooring within the hour: the hour's count of new detections is
kept, and the same rollup detection goes on counting, each key still once. At most 100,000 keys
are remembered for the rollups of all rules in an hour; past that a key is counted at each firing.
The rollup detection is stored as such: a detection whose key is the value `*` (for example an
actor named `*`) is a detection of its own and never updates the rollup.

Each detection has a one-line summary with the key, its location when known, and what happened:

```
203.0.113.7 (Lagos, NG; AS37148 Example) — 20 failed SSH logins in 10m
```

The summary holds no message text. Text from events (user names, host names) has control
characters and `<`, `>`, `@` and `` ` `` removed. Updates of a detection show on the page within 10
seconds.

### Severities and alerts

| Severity | Detections page | Alert level |
|---|---|---|
| `low` | yes | none |
| `medium` | yes | none |
| `high` | yes | `warning` |
| `critical` | yes | `critical` |

A high or critical detection sends a `security_detection` alert to every enabled channel (see
[Alerts](./alerting.md#host-and-edge-maintenance-alerts)):

- Target `security-logs`; for an [App Ops Interface alert](./app-ops-interface.md#alerts),
  `<app>/<service>`.
- The message is `<rule name>: <summary>`, at most 300 bytes. The dedupe key is
  `siem:<rule ID>:<key>`; for the rollup detection (key `*`, see [Detections](#detections)) it is
  `siem-rollup:<rule ID>`.
- At most one alert per rule and key per hour of the server clock, also when several detections of
  the key are made at once (a backlog of host log lines read after Mooring was stopped) and across
  a restart of Mooring. The alert is not resolved.
- A critical detection is always sent at once, within that limit.
- A rule sends at most 5 alerts for high detections per hour of the server clock (`:00` to `:59`).
  Its further high detections in that hour are not sent on their own: when the hour ends, one
  `warning` alert for the rule counts them, with the dedupe key `siem-cap:<rule ID>` and the
  message `<rule name>: <N> more detections this hour — see the Detections page`
  (`1 more detection` for one). A detection sent on its own later in the hour (an earlier alert
  failed and gave back its place) is not counted. When Mooring stops, the current hour's is sent
  at once.
- The 5 alerts and the summary's count hold across a restart of Mooring within the hour: the rule
  sends no more than 5 alerts for high detections in the hour in all, and the summary when the hour
  ends counts each detection once, without those in a summary sent when Mooring stopped. A summary
  that couldn't be recorded when Mooring stopped is counted in the one at the end of the hour.
- When Mooring was killed (not stopped) before an hour's summary was sent, and starts again in the
  next hour, the summary is sent then, once, with the same dedupe key and the message
  `<rule name>: <N> more detections in the previous hour (<YYYY-MM-DD HH:00>–<HH:00> UTC) — see the Detections page`
  (`1 more detection` for one). It counts what the last save before the kill held. None is sent for
  a rule switched off, deleted or snoozed by then, and none for an earlier hour.
- No summary alert is sent for a rule that is switched off, deleted or snoozed when the hour ends.
  Its detections stay on the Detections page.
- A `warning` is held during [quiet hours](./alerting.md#quiet-hours); a `critical` is sent at once.
- Detections of a snoozed rule are recorded and marked snoozed, and not sent.
- An alert that can't be recorded (Mooring's database busy) is tried 3 times in about a minute;
  then it is given up, and the next firing of the same rule and key sends its alert.
- At most 256 alerts wait to be recorded; when more are raised at once, the extra ones are dropped
  and the next firing of the same rule and key sends its alert.

### Detections as security events

Every new or updated detection is also written to the security logs as a `siem.detection` event,
so it is searchable, exported and archived to S3 like any other event. A detection is written as
an event once it is stored in `detect.db` (with its `detection_id`); an updated detection at most
every 10 seconds.

| Field | Value |
|---|---|
| `src`, `kind` | `siem`, `siem.detection` |
| `lvl` | `info` (low), `warn` (medium), `error` (high), `critical` (critical) |
| `ip` | The key, for a rule grouped by `ip`; for an IPv6 /64 key, the newest address behind the detection. |
| `actor` | The key, for a rule grouped by `actor`. |
| `app`, `svc` | The app (and service, for an App Ops Interface alert) the detection concerns. |
| `geo` | The location of the last event's address, when known. |
| `msg` | The summary. |
| `f` | `rule`, `severity`, `count`, `mitre` (comma-separated technique IDs), `key` (an IPv6 key is the /64, a rollup's is `*`), `detection_id` |

```
kind:siem.detection f.severity:critical
kind:siem.detection f.rule:ssh.bruteforce
```

## Dashboard pages

Both pages are for owners only. Every change on the Rules page
is recorded in Mooring's audit log.

- **Detections** (`/security/detections`): detections, most recently seen first (by their last
  event), filtered by minimum severity, rule, app and the time of the last event. A detection's page shows its summary, key, location, MITRE ATT&CK techniques,
  first and last time, count and evidence; each evidence event links to the matching events on the
  Security logs page, and **Related events** searches the rule's events for the detection's key
  (an address or /64, an account, a host name with or without a port; a roll-up or a rule without a
  group-by searches all the rule's events). The search used is shown on the Security logs page.
- **Rules** (`/security/rules`): every rule with whether it is on, its settings, **Edit** (switch it
  on or off and change its settings), **Snooze** (1 hour, 24 hours, 7 days) and **Reset** for
  built-in rules or **Delete** for custom ones, **New custom rule**, and the state of the enrichment
  feeds (GeoIP and threat-intelligence lists).

## App alerts

An app can declare its own alerts on its [App Ops Interface](./app-ops-interface.md#alerts)
metrics in `mooring.yaml`. Mooring evaluates them and records each one as a detection (source
`ops`, rule ID `ops:<app>/<service>/<alert name>`), with the same pages, events and alerts as above.
A report within an hour of the detection's last one updates it.

## Storage and retention

- `<data_dir>/security-logs/detect.db` (mode `0600`) holds the detections, what the `new_value`
  and `anomaly` rules have learned, and each rule's counts for the current hour (new detections,
  the keys counted in its rollup detection, alerts for high detections, see
  [Detections](#detections) and [Severities and alerts](#severities-and-alerts)). The rollup's
  keys are stored as 8-byte keyed hashes (HMAC-SHA256), not as the keys: at most 100,000 of them,
  800 KB, in all. Detections are kept for 400 days after their last event; older ones are removed
  once a day. Learned state and the hour's counts are saved every 10 minutes, within a second after
  a summary alert is sent or dropped, and when Mooring stops; after Mooring was killed, the counts are those
  of the last save. Counts saved in an earlier hour are not used, except a summary alert owed for
  the previous hour.
- `detect.db` holds at most 512 MiB of data (checked every 10 minutes). Past it, the detections
  with the oldest last event are removed, low and medium ones first and then any, until it holds
  at most 90% of that. The file itself doesn't shrink; the space freed is used again. A detection
  removed while it is still being updated is stored again with a new ID, and written to the
  security logs again with that `detection_id`.
- When `detect.db` can't be written (a full disk), detections are kept in memory and written when
  it can be again: at most 20,000 detections that left the in-memory set unwritten; past that the
  oldest are dropped.
- When Mooring stops, the events and app alerts still waiting are evaluated (for at most 3
  seconds), and the alerts they raise are sent (for at most 3 seconds more) and recorded on their
  detections, before the last write.
- Rule settings and custom rules are stored in Mooring's database (table `security_rules`), so the
  [Mooring-state backup](./backup-and-recovery.md) and `mooring restore` include them.

Limits:

| What | Limit |
|---|---|
| Keys per rule | 10,000; the key used least recently is dropped. |
| Keys per `anomaly` rule | 1,139 (each holds 7 days of hourly counts). Keys with counts in two or more hours take at most three quarters and are dropped only after every other key. |
| Window entries per rule (all keys) | 262,144 (events in the same second share one entry). |
| Values per key of a `distinct` rule | 1,000 |
| Learned values of a `new_value` rule | 100,000 (key and value pairs, and keys), and 1,000 values per key. A key past 1,000 values drops its own values seen least recently until it holds 900; a dropped value fires again when it comes back. When the rule is full, the keys seen least recently are dropped with all their values until a tenth is free. A dropped key is learned again without firing. |
| History of an `anomaly` key | 7 days of hourly counts. |
| Events waiting to be evaluated | 8,192; more are not evaluated (they are still stored). |
| App alerts waiting to be recorded | 256 |
| New detections per rule per hour | 50, then one detection with key `*`; also across a restart within the hour |
| Keys counted once in rollup detections | 100,000 an hour, all rules together; past that a key is counted at each firing |
| Alerts per rule per hour | 5 for high detections, then one summary alert when the hour ends; also across a restart within the hour. Critical detections are not limited (one per rule and key per hour) |

## Turning it off

```yaml
security_logs:
  detection:
    enabled: false
```

The key is read at startup: restart Mooring after a change (`sudo systemctl restart mooring`).
Turning security logs off (`security_logs.enabled: false`) also turns detection off.

---

MITRE ATT&CK® is a registered trademark of The MITRE Corporation. © 2026 The MITRE Corporation.
This work is reproduced and distributed with the permission of The MITRE Corporation.
