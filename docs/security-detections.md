# Security detections

Mooring evaluates detection rules over every [security log](./security-logs.md) event as it is
collected. A rule that matches records a **detection**; high and critical detections are also sent
to your [alert channels](./alerting.md). A built-in pack of rules covers SSH, sudo and su, host
account changes, Fail2Ban, Mooring's own sign-ins and API tokens, the edge, and the security events
your app writes. Each built-in rule is tagged with the MITRE ATT&CK® techniques it detects. You can
switch rules off, tune them, snooze them, and add your own. Only an **owner** can see detections
and change rules.

Detection runs whenever security logs are on. It is **on by default**.

See also: [Security logs](./security-logs.md) · [Security incidents](./security-incidents.md) · [Log patterns](./security-patterns.md) · [Automated response](./security-responses.md) · [Alerts](./alerting.md) · [App Ops Interface alerts](./app-ops-interface.md#alerts)

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
| `baseline` | Built-in rules only. Learns each key's usual behaviour and fires on a departure from it; see [Baselines](#baselines) and, for the `pattern.*` rules, [Log patterns](#log-patterns). | per rule, see [Baselines](#baselines) and [Log patterns](./security-patterns.md#rules) |

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
| `baseline.signin_unusual` | A successful sign-in that departs from the account's usual pattern in at least two ways: a new place (country or network), a new client, an unusual hour of the day. | `baseline` | 2 of 3 departures per `actor`; learns 14d | medium | [T1078](https://attack.mitre.org/techniques/T1078/) |
| `baseline.traffic_surge` | Far more requests or server errors for a host name in an hour than in the same hour of the week in earlier weeks. | `baseline` | 5× usual and at least 200 requests (or 50 server errors) in an hour per `f.host`; learns 14d | medium | [T1498](https://attack.mitre.org/techniques/T1498/), [T1499](https://attack.mitre.org/techniques/T1499/) |
| `baseline.traffic_drop` | Far fewer requests for a host name in an hour than in the same hour of the week in earlier weeks: an outage, or traffic blocked before it reaches the server. | `baseline` | a fifth of usual or less, usual at least 200 requests, in an hour per `f.host`; learns 14d | medium | [T1489](https://attack.mitre.org/techniques/T1489/) |
| `baseline.admin_unusual` | A server user's sudo or su with a program or target user not seen for them (root at an unusual hour is noted with it, never alone). | `baseline` | a new program or target user per `actor`; learns 14d | high | [T1548.003](https://attack.mitre.org/techniques/T1548/003/) |
| `baseline.ip_behaviour` | Most of an address's recent requests go to sign-in endpoints or admin paths, or are answered with an error, far more than its usual share. | `baseline` | 50 requests in 10m, half or more of one kind and 5× its usual share, per `ip`; learns 1d | low | [T1110](https://attack.mitre.org/techniques/T1110/), [T1595](https://attack.mitre.org/techniques/T1595/) |
| `pattern.new` | An app service's (or the host's) log lines below `warn` fall into a template not seen before, after its learning period. | `baseline` | 1 line, reported 5m after the first; learns 7d per app service | low | |
| `pattern.new_error` | An app service's (or the host's) log lines at `warn` or above fall into a template not seen before, after its learning period. | `baseline` | 1 line, reported 5m after the first; learns 7d per app service | medium | |
| `pattern.spike` | Far more lines of a known log template in a short time than usual at that time of day on the previous days. | `baseline` | 100 lines in 10m and 5× usual per template; the template is 3d old | medium | |
| `pattern.churn` | An app service's (or the host's) logs make new templates faster than the limits allow. | `baseline` | 1 line past the limits per app service | medium | |

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
| `baseline.signin_unusual` | `out:success kind~.login -kind~.login_ -f.sender_mismatch:true` |  |
| `baseline.traffic_surge` | `src:edge kind:http.request` |  |
| `baseline.traffic_drop` | `src:edge kind:http.request` |  |
| `baseline.admin_unusual` | `src:host kind:su* out:success -f.sender_mismatch:true` |  |
| `baseline.ip_behaviour` | `src:edge kind:http.request` |  |
| `pattern.new` | `-src:edge -src:mooring` |  |
| `pattern.new_error` | `-src:edge -src:mooring lvl>=warn` |  |
| `pattern.spike` | `-src:edge -src:mooring` |  |
| `pattern.churn` | `-src:edge -src:mooring` |  |

The `pattern.*` rules are evaluated on the lines the log-pattern miner takes, not on their query
(see [Log patterns](#log-patterns)); the query is what **Related events** searches.

## Baselines

The `baseline.*` rules learn what is usual for each key and fire when an event, or an hour,
departs from it. Type `baseline` is for the built-in rules only: a custom rule can't use it. Like
the other built-in rules they can be switched off, snoozed and tuned (the parameters below).

- Hours are in the server's local time zone. The sign-in and sudo/su baselines learn the hour of
  the day, weekdays (Monday to Friday) and weekend days (Saturday and Sunday) apart; the traffic
  baselines learn the hour of the week, Sunday to Saturday. `03:00 Tue` is Tuesday 03:00–04:00.
- When the server's time zone changes, what was learned per hour is cleared and learned again; the
  countries, networks, clients, programs and target users learned are kept. Zones with the same
  UTC offsets from 2025 to 2035 (`Europe/Berlin` and `Europe/Paris`) count as one zone.
- Nothing fires while a key is learning.
- What the rules have learned survives a restart (see [Storage and retention](#storage-and-retention)).
  After an upgrade that changes how a baseline reads events (for example how client families are
  named), what that baseline learned is discarded and learned again.

### Unusual sign-in

`baseline.signin_unusual` learns per account from its successful sign-ins: SSH logins, Mooring
sign-ins and an app's `auth.login` and `admin.login` events (any kind containing `.login`, except
kinds containing `.login_` such as `mooring.login_lockout`).
Accounts of different systems are learned apart: the server user `alice` (SSH), the Mooring user
`alice` and an app's account `alice` each have their own pattern, an app's accounts per app.

Each sign-in is compared with the account's pattern in three ways:

| Departure | When |
|---|---|
| new place | The address's country (`geo.cc`), its network (`geo.asn`), or both, were not seen for the account. A new country and a new network in one sign-in are one departure; the reasons name both (`new country NG, new network AS37148`). |
| new client | The client family of the event's `ua` field was not seen for the account. |
| unusual hour | The account has at least 20 sign-ins counted by hour, and the local hour before, the hour and the hour after hold together less than 1 in 50 of the sign-ins, each hour's counted as a share of its own kind of day's: weekdays' or weekend days'. While a kind of day has fewer than 20 sign-ins, its hour counts as the same hour on both kinds of day, as a share of all sign-ins: a 10:00 habit on weekdays is usual on a Saturday until the weekend has 20 sign-ins of its own. At midnight the next or previous hour can be of the other kind of day: Friday 23:00 is next to Saturday 00:00, Sunday 23:00 to Monday 00:00. An hour that a clock change repeats has the same neighbours both times. |

The rule fires when a sign-in departs in at least `count` ways, once the account has signed in
at least 3 times and its first sign-in is `learn` ago or more. A country, network or client is
compared only when the account has one learned: a sign-in without a location (no GeoIP database)
or without a `ua` field departs in none of those ways, and an account's first country, network or
client never departs. The 20 sign-ins for the hour are counted again from 0 after a time-zone
change. Every sign-in is learned, including the ones that fire. When an app is deleted, what the
rule learned of the app's accounts is deleted with it, and the app's sign-ins are not learned for
10 minutes after. After a start, what it learned of apps that no longer exist is deleted, as for
[mutes](./security-incidents.md#false-positives-and-mutes).

The client family is the User-Agent's client and system, without versions: `Chrome on Windows`,
`Firefox on Linux`, `Safari on iOS`, `okhttp on Android`, `curl`, `Python`, `Go`; any other client
is its first product name (`myapp on iOS`), or `other`. Mooring's sign-ins carry the browser's
User-Agent; SSH logins have none. An app can log a `ua` field with the User-Agent on its
`auth.login` and `admin.login` events.

```
alice — unusual sign-in: new country NG, new network AS37148 (Example ISP), unusual hour (03:00 Tue)
```

| Parameter | Default | Range |
|---|---|---|
| `count` | 2 | 1–3 departures |
| `learn` | 14d | 1d–30d |

Limits: 2,000 Mooring and SSH accounts, and 20,000 app accounts (all apps together), kept apart
so app accounts never take the places of Mooring's or the server's; per account 16 countries,
32 networks and 16 clients (past that, the one seen least recently is forgotten).

### Traffic surge and drop

`baseline.traffic_surge` and `baseline.traffic_drop` learn per host name an edge route serves
(`f.host`; requests with any other `Host` header are not counted) the requests and the server
errors (status 500 and above) in each hour. Every host name a catch-all route (`subdomain: "*"`)
serves counts as one, `*.<apex>`: `a.example.com` and `b.example.com` under a catch-all route for
`example.com` are both counted as `*.example.com`. For each hour of the week, the counts of the
last 4 weeks are kept. When an hour has ended (2 minutes after, so late access log lines still
count), its counts are compared with the median of the earlier weeks' counts for the same hour of
the week; of an even number of weeks (2 or 4), `baseline.traffic_drop` compares with the lower of
the two middle counts and `baseline.traffic_surge` with the higher:

- `baseline.traffic_surge` fires when the hour had at least `count` requests and at least
  `factor` times the usual requests, or at least `count` ÷ 4 server errors (at least 1) and at
  least `factor` times the usual server errors.
- `baseline.traffic_drop` fires when the usual requests are at least `count` and the hour had at
  most the usual requests ÷ `factor`.

An hour of the week is compared once it has counts for `learn` ÷ 7 days earlier weeks (rounded
up; 2 by default). Only hours Mooring watched whole are counted: not the hour Mooring started in
or the hour a host name was first seen in, not hours Mooring was stopped, not hours before
the edge's routes were first read after a start, and not hours both rules were switched off. In
an hour in which events were dropped before the rules saw them (the detection queue was full),
the counts are a lower bound: `baseline.traffic_surge` still compares it, `baseline.traffic_drop`
doesn't, and it is not learned. A host name is forgotten when the next hour ends after its route
is removed or a catch-all route serves it instead, and after 672 watched hours (4 weeks) in a row
without a request; until the edge's routes are read after a start, none is forgotten. A
departure in consecutive hours updates one detection. Both rules count the same requests.

Hours are counted from UTC and shown in the server's local time with their start and end:
`10:00–11:00 Tue`, or `09:30–10:30 Tue` in a zone half an hour off UTC.

```
host shop.example.com — 2400 requests (usually about 300) and 180 server errors (usually about 2) in the hour 10:00–11:00 Tue
host shop.example.com — 12 requests (usually about 900) in the hour 10:00–11:00 Tue
```

| Parameter | Default | Range |
|---|---|---|
| `count` | 200 | 1–100000 requests |
| `factor` | 5 | 1.5–1000 |
| `learn` | 14d | 7d–28d |

Limits: 1,000 host names (about 7 KB each).

### Unusual sudo or su

`baseline.admin_unusual` learns per server user from their successful `sudo` commands and `su`
sessions in the host logs (lines with `f.sender_mismatch: true` are left out): the hours of the
day, weekdays and weekend days apart, the programs (the command's first word without its
directory: `/usr/bin/systemctl restart web` is `systemctl`) and the target users. Once the user
has run sudo or su at least 3 times and the first is `learn` ago or more, a sudo or su fires when:

- its program was not seen for the user (`new program nc`);
- its target user was not seen for the user (`new target user postgres`).

When it fires and its target user is `root`, `root at an unusual hour (03:00 Tue)` is added to
the reasons if the user has at least 20 sudo and su counted by hour and the hour is unusual for
them as an unusual hour is for a sign-in (see [Unusual sign-in](#unusual-sign-in)). Root at an
unusual hour never fires alone.

A program or target user is compared only when the user has one learned. An `su` session has no
program; a sudo line whose fields can't be told apart (`f.ambiguous: true`) has neither a program
nor a target user. Every sudo and su is learned, including the ones that fire. A program or user
name with characters other than letters, digits, `.`, `_`, `+` and `-` (or longer than 32 bytes)
is not shown in the summary (`new program`).

```
server user alice — unusual sudo or su: new program nc, root at an unusual hour (03:00 Tue)
```

| Parameter | Default | Range |
|---|---|---|
| `learn` | 14d | 1d–30d |

Limits: 2,000 server users; per user 128 programs and 16 target users.

### Address behaviour change

`baseline.ip_behaviour` learns per address (an IPv6 address as its /64) the mix of its edge
requests: how many went to sign-in endpoints, to admin paths, and were answered with an error. A
request's path is split at `/`, and each part lowercased, without a trailing `.ext`:

| Kind | When |
|---|---|
| sign-in | A part contains `login`, `logon`, `signin`, `sign-in`, `sign_in` or `password`, or is `auth`, `oauth`, `oauth2`, `authorize`, `authenticate`, `token`, `tokens`, `session`, `sessions`, `mfa`, `2fa`, `otp` or `sso`. |
| admin | A part contains `admin`, or is `manager`, `console` or `actuator`. |
| error | The status is 400 or above. |

The rule fires when, in the last `window`, the address made at least `count` requests and half
or more of them were of one kind, at least `factor` times that kind's usual share. The usual share
is the kind's share of the address's requests before the window. An address fires only once its
first request is `learn` ago or more and at least `count` of its requests are before the window.
After it fires, the window's requests are added to the usual mix and the window starts again.

```
203.0.113.7 (Lagos, NG; AS37148 Example) — 41 of 50 requests in 10m to sign-in endpoints (usually 2%)
```

Many clients behind one address (a mobile carrier's, an office's) share one mix.

| Parameter | Default | Range |
|---|---|---|
| `count` | 50 | 10–100000 requests |
| `window` | 10m | 1m–24h |
| `factor` | 5 | 1.5–1000 |
| `learn` | 1d | 1h–30d |

Limits: 50,000 addresses (about 300 bytes each).

### Keys kept

Past a baseline's limit of keys, the key used least recently is dropped. Keys with a learned
history take at most three quarters of the places and are dropped only after every other key: an
account or server user with 3 events over a day or more, a host name with a counted hour, an
address with 10 requests before its window, the first an hour ago or more. A dropped key learns
again from the start.

## Log patterns

The `pattern.*` rules report on the templates that each app service's log lines, and the host's
unclassified lines, fall into: a template first seen after its source's learning period
(`pattern.new`, `pattern.new_error`), a spike of a known template (`pattern.spike`), and a source
that makes new templates faster than the limits allow (`pattern.churn`). They are baseline rules of
kind `pattern`. What is mined, the templates, the parameters and their ranges, the pattern states
and the Patterns page are in [Log patterns](./security-patterns.md).

A pattern detection's key is the pattern's ID (for `pattern.churn`, the source). Its summary holds
no template text. Pattern detections join no incident, and with the default severities send no
alert.

## Changing a built-in rule

On a built-in rule's **Edit** page it can be switched off and on, and its severity, `count`,
`window`, `factor`, `learn` and `speed_kmh` changed (within the ranges in [Rule types](#rule-types);
for the baseline rules, in [Baselines](#baselines); for the `pattern.*` rules, in
[Log patterns](./security-patterns.md#rules)).
Its query, type, group-by and field can't be changed. **Reset** puts it back to the defaults above.

**Automated response** sets what [automated response](./security-responses.md) does about the
rule's detections when `security_logs.response.mode` is `recommend` or `enforce`: nothing, block
the detection's address at the edge for a length (5m–7d), or sign the Mooring account out of every
session. The section offers only what the rule's query and group-by allow, and says why when they
allow nothing. A block is automatic only when the rule's query lets through edge events only, and
a sign-out needs a query that lets through Mooring's events only, and successful ones only. The
default responses and the conditions are in
[Which detections get a response](./security-responses.md#which-detections-get-a-response).
**Reset** puts the default response back.

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
| Automated response | Set on the rule's **Edit** page after the rule is saved; the **New custom rule** form has no response setting. A block (group-by `ip`, a query that matches only `src:edge` or `src:app` events; automatic only with `src:edge` alone) or a sign-out (group-by `actor` or `ip`, a query that matches only Mooring's events, `src:mooring`, and only `out:success`; for a `sequence` rule both queries match only Mooring's events). See [Automated response](./security-responses.md#which-detections-get-a-response). |

At most 100 custom rules. A rule that doesn't validate is refused with the reason.

A stored custom rule that no longer validates (for example a query field a later release renamed)
is listed on the Rules page switched off, with its description replaced by `stored rule is
invalid: <reason>`. It is not evaluated, counts toward the 100, and can be edited or deleted.

## Detections

A detection is one rule firing for one key. While the rule keeps firing for that key, the same
detection is updated: a firing within the rule's `window` (or 1 hour, when that is longer) after the
detection's last event adds its events to the count, moves its last time, and adds to its evidence
(the 10 newest events behind it). A later firing starts a new detection.

A rule whose query lets several sources through (for example Mooring's and the host's events)
records one detection per source for the same account name: the Mooring user `alice`, the server
user `alice` and an app's `alice` are different accounts (the
[scope](./security-incidents.md#entities)). These detections have the same key. Each source's detection has its own alert (one per hour, see
[Severities and alerts](#severities-and-alerts)); the rule's hourly alert cap covers them together. Detections keyed by an
address are not split.

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
  `siem-rollup:<rule ID>`; for an account's detection of a rule that lets several sources through
  it is `siem-acct:<rule ID>:<scope>|<key>`, and the one alert an hour is per rule, key and source.
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

### Incidents

Detections that concern the same account or address within 24 hours are grouped in one
[incident](./security-incidents.md), with a timeline, a workflow state and one
`security_incident` alert in place of the detections' own alerts. A rollup detection, an App Ops
Interface alert and a detection whose key is no account or address join no incident and keep the
alerts above. A detection muted as a [false positive](./security-incidents.md#false-positives-and-mutes)
is recorded, marked muted, and sends no alert.

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
| `f` | `rule`, `severity`, `count`, `mitre` (comma-separated technique IDs), `key` (an IPv6 key is the /64, a rollup's is `*`), `detection_id`; `incident_id` when it is part of an [incident](./security-incidents.md); `muted` (`true`) when a false-positive mute covers its rule and key |

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
  Security logs page. An evidence event of the edge is marked `browser` (the request had a
  `Sec-Fetch-Site` header) or `browser-like agent` (a browser's or mail client's User-Agent):
  see [Requests sent by a browser](./security-responses.md#requests-sent-by-a-browser).
  **Related events** searches the rule's events for the detection's key
  (an address or /64, an account, a host name with or without a port; a roll-up or a rule without a
  group-by searches all the rule's events). The search used is shown on the Security logs page.
  A log-pattern detection has **View the log pattern** instead (no link with
  `detection.patterns.enabled: false`). The
  [responses](./security-responses.md) about the detection, among the 200 newest, are listed.
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
- `detect.db` also holds the [log patterns](./security-patterns.md#storage): templates, their
  states and counts, the states an owner set, and each scope's last line time.
- `detect.db` also holds what the [baseline rules](#baselines) have learned, one row per key.
  Changed keys are saved every second (at most 128 a second), and all of them every 10 minutes
  and when Mooring stops; after Mooring was killed, a key is as it was at its last save. A row
  that can't be read is dropped. A key dropped from memory (see [Keys kept](#keys-kept)) is
  deleted with the next save.
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
| Keys of a baseline rule | 2,000 Mooring and SSH accounts, 20,000 app accounts, 1,000 host names, 2,000 server users, 50,000 addresses; see [Baselines](#baselines). |
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
