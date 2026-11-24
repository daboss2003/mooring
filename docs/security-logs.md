# Security logs

Mooring collects security-relevant events from your apps, the edge, itself and the host into one
log. Secrets and personal data are removed before anything is stored. The last 14 days are kept
and searchable on the server; with an S3 bucket configured, every hour is also uploaded encrypted
and kept there for a year. Security logs are **on by default**. Only an **owner** can search or
export them.

See also: [Command-line reference](./cli.md#mooring-security-logs-fetch--verify--decrypt) · [Alerts](./alerting.md) · [Server settings](./host-file.md#the-configyaml-reference)

---

## What is collected

| Source (`src`) | What | Kinds |
|---|---|---|
| `app` | Every line each running app service writes to stdout and stderr. A JSON line (Pino, Bunyan, zap, logrus or any other JSON object) is read field by field; any other line is kept as text. | `log`, or the app's own kind (see [Security events from your app](#security-events-from-your-app)) |
| `edge` | One event per request through the managed edge (`edge.mode: managed`). `ip` is the client address: behind [`edge.trusted_proxies`](./host-file.md#edge-trusted-proxies), the address the trusted proxy reports. | `http.request` |
| `mooring` | Mooring's own audit events: sign-ins and failed sign-ins, lockouts, API token use, user, role and config changes, deploys and other operator actions. Events written by `mooring token` and `mooring secret import` (actor `cli:<user>`) are copied within 30 seconds while Mooring runs, and on its next start otherwise. | `mooring.<action>`, for example `mooring.login` |
| `host` | `sshd`, `sudo`, `su` and user and group changes (`useradd`, `usermod`, `passwd`, `groupadd`, …) from `/var/log/auth.log`, else `/var/log/secure`, or from the systemd journal when neither file exists; Fail2Ban bans and unbans from `/var/log/fail2ban.log`. | `ssh.*`, `sudo.command`, `su.session`, `host.user_change`, `fail2ban.*`, `log` |
| `siem` | The collector's own events. | `siem.dropped`, `siem.archive_failed` |

## Event format

Every event is one JSON object (schema version 1). The same form is stored on the server, archived
to S3 and written by an export.

| Field | Meaning |
|---|---|
| `v` | Schema version: `1`. |
| `ts` | When it happened, UTC (RFC 3339): the source's own timestamp when it has one, else when Mooring read the line. |
| `src` | `app`, `edge`, `mooring`, `host` or `siem`. |
| `app`, `svc`, `copy` | The app, its service, and the short container ID of the replica (app events). |
| `lvl` | `debug`, `info`, `warn`, `error` or `critical`. |
| `kind` | What happened, in dot.case (below). `log` for a line that isn't classified. |
| `out` | `success` or `failure`, for an event with an outcome. |
| `actor` | The account or user acting. An email address or phone number is stored as a keyed hash. |
| `ip` | The client IP address. |
| `f` | The other structured fields, after redaction. Nested keys are flattened with dots (`req.method`). Values are strings, numbers or booleans. |
| `msg` | The message text, after redaction. |

Limits: `msg` 8 KiB; `f` at most 64 fields, keys up to 64 bytes, string values up to 1 KiB; `app`,
`svc`, `copy`, `kind`, `actor` and `ip` up to 256 bytes. Longer values are cut.

```json
{"v":1,"ts":"2026-11-23T08:14:03Z","src":"host","lvl":"warn","kind":"ssh.login","out":"failure","ip":"203.0.113.7","f":{"method":"password","user":"root"},"msg":"Failed password for root from 203.0.113.7 port 52144 ssh2"}
```

### Kinds

| Kind | Source | `out` | `f` |
|---|---|---|---|
| `log` | any | | Unclassified output. |
| `http.request` | `edge` | | One access log entry. |
| `ssh.login` | `host` | `success` / `failure` | `method` (`password`, `publickey`, `keyboard-interactive`), `user`, `key_fp`, `port` |
| `ssh.invalid_user` | `host` | | `user` |
| `ssh.disconnect` | `host` | | `user`, `reason` (disconnects before authentication, "Too many authentication failures") |
| `sudo.command` | `host` | `success` / `failure` | `user`, `target_user`, `command`, `tty`, `reason`; `ambiguous: true` (at `warn`, without `command`, `target_user` or the directory) when the line's fields are out of sudo's order (TTY, PWD, USER, GROUP, ENV, COMMAND), repeated or unknown, as with a directory named `/tmp/COMMAND=x` |
| `su.session` | `host` | `success` / `failure` | `user`, `target_user` |
| `host.user_change` | `host` | | `program`, `user`, `detail` |
| `fail2ban.ban`, `fail2ban.unban` | `host` | | `jail` |
| `mooring.<action>` | `mooring` | `success` / `failure` | The audit event: `target`, `ua` (the client's User-Agent). For example `mooring.login` (`msg`: `invalid password`, `invalid TOTP code`, `unknown user`, …), `mooring.login_lockout`, `mooring.api_token_use`, `mooring.api_token_mint`, `mooring.api_token_revoke_cli`, `mooring.secret_import`, `mooring.user_added`, `mooring.user_removed`, `mooring.user_role_changed`, `mooring.user_password_changed`, `mooring.user_totp_changed`, `mooring.alert_rule_delete`, `mooring.env_set_secret`, `mooring.security_logs_export`. |
| `siem.dropped` | `siem` | | `source`, `count`, `reason`: events dropped because the collector's queue was full, refused at the disk-pressure threshold (`reason` `disk`) or not stored after an error (`reason` `error`), or lost on this server. |
| `siem.archive_failed` | `siem` | | `segment`, `error` |

## Security events from your app

An app line that is a JSON object with an `event` field becomes an event of that kind:

```json
{"level":"warn","time":"2026-11-23T08:14:03.120Z","msg":"sign-in failed","event":"auth.login_failed","outcome":"failure","actor_id":"usr_8f2c","account":"acme","ip":"203.0.113.7"}
```

| Field | Becomes |
|---|---|
| `event` (or `evt`, `event_type`) | `kind`, when it is lowercase dot.case of 2 to 4 parts of letters, digits and `_`: `auth.login_failed`, `auth.lockout`, `apikey.created`, `role.changed`. A name under `mooring.`, `siem.`, `ssh.`, `sudo.`, `su.`, `fail2ban.`, `host.` or `http.` gives kind `log`. |
| `outcome` | `out`: `success` (also `ok`, `succeeded`) or `failure` (also `fail`, `failed`, `denied`, `error`). Without it, a kind ending in `_failed`, `.failed`, `_denied` or `.denied` is a failure. |
| `actor_id` | `actor`. Without it, the first of `actorId`, `user_id`, `userId`, `uid`, `account`, `username`, `user` and `sub`. |
| `ip` | `ip`. Also read from `client_ip`, `clientIp`, `remote_ip`, `remoteAddress`, `req.remoteAddress`, `req.ip` or `request.ip`; when that address is private and the line has an `X-Forwarded-For`, its first address is used. |
| `account` | With `actor_id` present, `f.account`, stored as a keyed hash. |

The level comes from `level` (a Pino or Bunyan number, or a level name), `lvl`, `severity` or
`log.level`, else from `res.statusCode` (5xx `error`, 4xx `warn`). The time comes from `time`,
`ts`, `timestamp` or `@timestamp` when it is within 24 hours of when the line was read, and the
message from `msg`, `message`, `@message` or `error.message`. Every other field goes to `f`, after
redaction. Write one event per line; don't put tokens, passwords or personal data in it beyond these
fields.

## Redaction

Every event is redacted before it is stored or archived.

**How names match.** A field name is matched element by element: each part between dots or
brackets, ignoring case, `_` and `-`. Empty and numeric elements (`password[]`, `token[0]`) are
skipped. In a field, a rule that matches any element applies to the whole field: `password.new`,
`session.id` and `cookies.connect.sid` are secrets, `phone.number` and `account.id` are hashed,
`location.city` is dropped. A secret wins over a dropped name, and a dropped name over a hashed one.
For a `key=value` pair in a message only the key's last element counts, so
`session.example.com:8443` is left as is.

**Secrets** are replaced with `[redacted]`:

- names: password, passwd, pwd, pass, passphrase, secret, client_secret, token, access_token,
  refresh_token, id_token, api_key, api_secret, x-api-key, authorization, proxy-authorization,
  cookie, cookies, set-cookie, session, session_id, session_token, jwt, otp, totp, otp_code, pin,
  cvv, cvc, card_number, pan, private_key, credentials;
- names ending in password, passwd, passphrase, secret, token, apikey, privatekey, secretkey,
  accesskey, signingkey, encryptionkey, masterkey, credentials, sessionid, authorization or cookie;
- `signature`, or a name ending in signature, when the value is 32 or more base64 or hex characters.

A number in a secret field is redacted too, unless the field's own last element is a measure and
not itself a secret name: duration, elapsed, latency, ttl, max_age, expires,
expires_in, exp, iat, nbf, age, count, total, attempts, retries, size, length, bytes, status, ok,
valid, verified, enabled, expired, secure, http_only, success, failed, limit, remaining, version,
index, or a name ending in ms, millis, seconds, secs, at, count, size, length, ttl, duration,
attempts, total or bytes (`session.duration_ms`, `token.expires_in` are kept; `pass: 1234`,
`checks.pass`, `otp.code` are redacted). A boolean (`true` / `false`) is never redacted
(`has_password: true` is kept).

In messages and text fields the following are also redacted: JSON Web Tokens, `Bearer` and `Basic`
credentials, PEM private keys, AWS access key IDs, GitHub, Slack and Stripe live keys, the password
in a URL (`scheme://user:password@host`), and the value of a `key=value`, `key: value` or
`"key":"value"` pair whose key is a secret name. A percent-encoded value holding such pairs
(`?variables=%7B%22password%22%3A%22…%22%7D`) is decoded once and redacted the same way. IP
addresses are never redacted.

**Personal data.** Hashed values are `h:` and 16 hex characters, a keyed HMAC-SHA256 whose key is
derived from `encryption_key`; the same value always gives the same hash.

- Hashed fields: imei, imei1, imei2, meid, serial, serial_number, device_id, android_id, udid,
  email, email_address, phone, phone_number, msisdn, account, and names ending in email, phone,
  phone_number, mobile_number, msisdn, imei, device_id, android_id, serial_number, account or
  account_number. Email addresses are lowercased before hashing. Punctuation around a hashed value
  (`<…>`, a trailing `.`) is kept outside the hash.
- Email addresses anywhere in text are hashed, including Unicode and `xn--` addresses. An address
  used as a URL's user (`ssh://git@host`) is kept, unless it is encoded (`%40`) or is itself a full
  address.
- Phone numbers in text are hashed: `+` and 10 to 15 digits, or a national number of `0` (not `00`)
  and 10 more digits. The digits may be grouped by single spaces, dashes or dots
  (`+234 803 123 4567`, `0803-123-4567`), and the area code may be in parentheses
  (`(0803) 123 4567`).
- The actor is hashed when it is an email address or a phone number.
- An email address or phone number in a field name is replaced by its hash; the rest of the name is
  kept (`limits.login:h:…`).
- Dropped: lat, lon, lng, latitude, longitude, coords, coordinates, gps, location, altitude, and
  names ending in latitude, longitude, coords, coordinates, gps, location or altitude. Pairs with
  these names in text get `[redacted]`. The `geo` field Mooring adds is kept.
- `pii.hash_fields` and `pii.drop_fields` add exact names. `pii.keep_fields` removes names from the
  built-in lists; a kept element stops only its own match, and a kept field keeps addresses and
  phone numbers in its value. Secrets can't be kept. Each list holds at most 64 names of letters,
  digits, `_`, `-` and `.`, up to 64 characters each.

Searching for a hashed value by its clear value finds it (any letter case for an email).

**Event kinds.** An app line's `event` value starting with `mooring.`, `siem.`, `ssh.`, `sudo.`,
`su.`, `fail2ban.`, `host.` or `http.` is stored as kind `log`, with the field kept.

## Storage on the server

Events are stored under `<data_dir>/security-logs/` (`/var/lib/mooring/security-logs/`, mode
`0700`, owned by the `mooring` user), separate from Mooring's database:

- One gzip-compressed NDJSON segment per hour, `<YYYYMMDDHH>-<box>-<seq>.ndjson.gz`, with every
  event. `<box>` is this server's name. The hour is UTC.
- `security.db`, an SQLite database that indexes the classified events (every kind except `log`
  and `http.request`, and anything at `warn` or above) and lists the segments with their hash
  chain.

- `tmp/`, temporary files of archive uploads.

A new segment starts when the hour ends, or when a segment reaches 256 MiB uncompressed or
2,000,000 events. A segment is sealed when its hour is over: its SHA-256 and the SHA-256 of the
segment sealed before it are recorded. Segments still open after a crash or an unclean stop are
sealed as found at the next start. Events are written to disk and become searchable within about a
second.

Retention and disk use:

- `hot_retention` (default `14d`): a segment is removed this long after its hour ends. With
  `archive.s3` set, a segment not yet uploaded is kept up to 7 more days, then removed and recorded
  as a `siem.dropped` event.
- `hot_max_disk_mb` (default `10240`) caps the segments and `security.db` together. Over it, the
  oldest uploaded segments are removed first, then the oldest segments not uploaded, each recorded
  as a `siem.dropped` event (`reason` `disk cap`). The newest sealed segment not uploaded is never
  removed by this limit.
- At `server.disk_gc_threshold` (default 75% of the data directory's filesystem), uploaded segments
  are removed, oldest first, until usage is below the threshold. If usage is still at or above it,
  new security-log events are not stored, and are counted as dropped (`reason` `disk`), until it
  falls below. Segments not uploaded are kept.
- `hot_max_disk_mb` counts the segments and the space `security.db` uses for stored data. Space
  freed in `security.db` is returned to the filesystem over the following minutes.
- Removing old segments and returning free space are done in small steps, so events keep being
  stored and searched meanwhile.
- If the system clock steps forward by more than 6 hours, or Mooring is stopped for longer than
  that, segments captured before are aged by the time that has passed since, so none is removed
  early. A warning is logged. This ends when the clock steps back or when those segments have aged
  out.

## S3 archive

With `archive.s3` set, every hour is sealed when it ends and uploaded within a minute. Without it,
security logs stay on the server only, and Mooring logs a `config:` warning at startup.

```yaml
security_logs:
  archive:
    retention: 365d
    s3:
      bucket: my-security-logs
      endpoint: s3.eu-west-1.amazonaws.com    # or a MinIO / R2 / B2 endpoint
      region: eu-west-1
      access_key_id: "…"
      secret_access_key: "…"
      prefix: "mooring/"                      # optional
      path_style: true                        # default true
      insecure: false                         # true allows plain http:// (a private MinIO)
```

The keys are the same as [`backups.s3`](./backup-and-recovery.md#backing-up-your-apps-data).
`bucket`, `endpoint`, `region`, `access_key_id` and `secret_access_key` are required. `prefix` is
optional: letters, digits, `/`, `-`, `_` and `.`, at most 256 characters, ending in `/`, not starting
with `/`; each element between `/` is 1–128 characters and doesn't start with `.`. Mooring refuses to
start on an incomplete or invalid block.

Each segment is uploaded as two objects:

```
<prefix>v1/YYYY/MM/DD/HH/<box>-<seq>.ndjson.gz.enc
<prefix>v1/YYYY/MM/DD/HH/<box>-<seq>.seal.json
```

- `.ndjson.gz.enc` is the segment, encrypted with `encryption_key` in Mooring's backup format
  (AES-256-GCM).
- `.seal.json` is plain JSON with no event data (see [Archive seals](#archive-seals)).

Each server that writes to the same bucket and prefix must have its own box name (the server's
hostname). Mooring never overwrites a seal that belongs to another segment: a segment whose key
already holds a different seal is not uploaded, and the `security_log_segment_changed` alert names
it.

The archive deletes this server's objects once both their hour and their last-modified time in the
bucket are older than `archive.retention` (default `365d`, minimum `1d`), once a day. After a
hostname change it also deletes the expired objects stored under the server's earlier box names.

The credentials need `s3:PutObject`, `s3:GetObject`, `s3:ListBucket` and `s3:DeleteObject` on the
bucket. To protect the archive from deletion with
the server's keys:

- Turn on versioning and S3 Object Lock with a default retention, so an object can't be
  overwritten or deleted before then, with Mooring's keys or any other. With versioning,
  Mooring's deletes after `archive.retention` leave the data as noncurrent versions.
- Add a lifecycle rule that expires objects, and noncurrent versions, a little after the retention
  you need.

Keep `encryption_key` (after a key rotation, as `encryption_key_previous`): the archive can't be
decrypted without it.

When uploads have failed for an hour, or 6 sealed segments are waiting to be uploaded, Mooring
raises the `security_log_archive_failed` alert ([Alerts](./alerting.md#host-and-edge-maintenance-alerts)).
Failed uploads are retried, with a growing wait of up to 30 minutes.

To read the archive, use `mooring security-logs decrypt`, `verify` and `fetch`: see
[the CLI reference](./cli.md#mooring-security-logs-fetch--verify--decrypt).

### Archive seals

Each `<box>-<seq>.ndjson.gz.enc` object has a `<box>-<seq>.seal.json` object next to it:

| Field | Meaning |
|---|---|
| `v` | Seal format version (`1`). |
| `name` | The segment's file name on the server. |
| `box` | The name of the server that wrote the segment. |
| `hour`, `seq` | The UTC capture hour, and the segment's number within that hour. |
| `n` | The segment's position in its server's seal order (1, 2, ...). |
| `events`, `first`, `last` | Event count, oldest and newest event time. |
| `sha256` | SHA-256 of the decrypted segment. |
| `prev_sha256` | `sha256` of the segment sealed before it on the same server (`""` for the first). |
| `enc_sha256`, `enc_bytes` | SHA-256 and size of the `.enc` object. |
| `archived_at` | Upload time. |
| `sha256_mismatch`, `actual_sha256` | Set when the segment changed on the server after it was sealed. The segment is uploaded anyway, and `actual_sha256` is the hash of what was uploaded. |
| `mac` | HMAC-SHA256 (hex) of all the other fields, keyed with HKDF-SHA256 of `encryption_key` (info `mooring siem seal v1`). A seal can't be changed without the key. |

`mooring security-logs verify <dir>` checks that:

- every object has its seal, and every seal its object;
- each seal's `mac` verifies with `encryption_key` or `encryption_key_previous`; a seal without a
  `mac` is reported as unauthenticated;
- each object decrypts with one of those keys;
- the decrypted segment's SHA-256 is the seal's `sha256`, and the object's size and SHA-256 are its
  `enc_bytes` and `enc_sha256`;
- no seal has `sha256_mismatch` set;
- each file name and its `YYYY/MM/DD/HH` directories match the seal;
- per server, the `prev_sha256` links form one chain, with `n` increasing along it: no missing
  segment, fork, restart or duplicate. Only seals whose `mac` verifies count.

Missing segments after the newest one in the directory can't be detected.

## Search

The **Security logs** page (in the sidebar, owners only) searches the events kept on the server.
Pick a range (last 15 minutes, hour, 6 hours, 24 hours, 7 days or 14 days; the default is 24
hours, or set From and To) and type a search. Results are newest first, 200 per page; **Older**
shows the next page. Every search (a submitted search or an **Older** page) is recorded in Mooring's
audit log as `security_logs_search`, with the search as run and its range and never the results; a
search that didn't finish is recorded with outcome `error` and `result=busy`, `result=time limit`
or `result=error`. A search reads
at most 512 MiB of events or runs 10 seconds; when it stops
early the page says so, and **Older** continues from where it stopped (events stored with a
timestamp much older than when they were captured can be missing from such a page when they don't
fit in one search). At most two searches or
exports run at once; another one waits up to 2 seconds, then the page asks you to try again.

A search is terms separated by spaces; every term must match.

| Term | Matches |
|---|---|
| `field:value` | The field equals the value. Strings compare without regard to case. |
| `field:value*` | The field starts with the value (`kind:auth.*`). `field:*` matches any event that has the field. |
| `field!=value` | Events that have the field with another value. |
| `field~text` | The field contains the text. |
| `field>N`, `field>=N`, `field<N`, `field<=N` | Numbers, on `f.*` fields (`f.status>=500`); levels, on `lvl` (`lvl>=warn`). |
| `ip:203.0.113.7`, `ip:10.0.0.0/8` | The address, or any address in the prefix. |
| `-term` | The term doesn't match (also events without the field): `-app:web`. |
| `word`, `"quoted text"` | The message contains it. A word with an operator character in it (`http://x`) must be quoted. A value can be quoted too: `f.path:"/a b"`. |

Fields: `src`, `app`, `svc`, `copy`, `lvl`, `kind`, `out`, `actor`, `ip`, and `f.<name>` for a key of
`f` (the exact flattened key, for example `f.req.method`). A search is at most 2 KiB and 32 terms.

Personal data is searched by its clear value: for a field stored as a hash, the page hashes the
value before it searches (`f.email:alice@example.com`, `f.device_id:356938035643809`). For
`actor`, an email address or phone number is hashed, the same way it was stored, and an email
address or phone number in free text is hashed too. A prefix pattern (`f.email:*`) is not hashed.
Fields that hold secrets (`f.password`, `f.api_key` and any other field stored as `[redacted]`)
can't be searched by value: a search with such a term is refused, and nothing is searched or
recorded. `f.password:*` (the field is present) is allowed.
After a search runs, the search box, the address bar, **Older** and **Export** carry the hashed
values, so the clear value stays only in what you typed (and in the audit log only as its hash).

Examples:

```
kind:ssh.login out:failure
src:mooring kind:mooring.login* out:failure
lvl>=warn app:shop
src:edge f.status>=500 -ip:10.0.0.0/8
kind:auth.* actor:alice@example.com
```

## Export

**Export** on the Security logs page downloads every event the search and range match as NDJSON
(the [event format](#event-format), one per line), oldest first, up to 100,000 events. Owners only.
Every export is recorded in Mooring's audit log (`security_logs_export`, with the search and range)
before the first event is sent; when the record can't be written, the export is refused. One export
runs at a time; another one, or one while the store is busy with searches, gets `503` and a "try
again" message.

An export that stops before every matching event was written ends with one more line:

```json
{"export":"incomplete","reason":"cap reached","events":100000}
```

`reason` is `cap reached` (100,000 events), `time limit` (10 minutes), `scan budget` (the store's
read limit), `segment removed` (a segment was removed while the export ran) or `error`. An export
with a term on a secret field is refused with `400`. Mooring also records
`security_logs_export_incomplete` in the audit log, with the reason and the count. An export whose
file has no such line is complete.

## Host log access

The package adds the `mooring` service user to the `adm` group once, when the host has that group,
and records it in `/etc/mooring/.adm-group-added`. Later upgrades don't add it again, so removing the
user from `adm` (`sudo gpasswd -d mooring adm`) stays in effect; `sudo mooring setup --yes` adds it
back. The service gets the group when it next starts. On Debian and Ubuntu `/var/log/auth.log` and
`/var/log/fail2ban.log` are `root:adm 0640`, and the systemd journal gives `adm` read access.

- `sudo mooring setup --yes` adds the `mooring` user to `adm` when the group exists and the user
  isn't in it (unless security logs or `host_logs` are off). Restart Mooring afterwards.
- `sudo mooring doctor` checks the `adm` group (also whether the running service has it: a group
  joined after the service started needs a restart), each host log file and the journal, and prints
  the fix for what the service can't read.
- When `host_logs.journal` is unset and the auth log exists but the service can't read it (on
  Fedora and RHEL, `/var/log/secure` is `root:root 0600`), Mooring reads `sshd`, `sudo`, `su` and
  user and group changes from the journal instead, and doesn't read the file. The Security logs
  page shows the auth log as not reading, with the reason. This is decided when Mooring starts:
  restart Mooring after making the file readable. `host_logs.journal: false` turns this off. A host
  log not read on one start (the journal replacing the auth log, or the reverse) starts from the
  newest line when it is read again.
- A host log the service can't read shows as not reading on the Security logs page, and is retried.

From the systemd journal, Mooring reads the user and group programs (`useradd`, `usermod`,
`userdel`, `groupadd`, `groupmod`, `groupdel`, `gpasswd`, `chpasswd`, `chage`) only from entries
journald records as sent by root (`_UID` 0). An `sshd` entry sent by another user (sshd's lines
after a login come from the user's own session) is kept only as a `log` event, so
`logger -t sshd …` can't add an `ssh.*` event. `sudo`, `su` and `passwd` are read whichever user
sent them, because journald records them under the user who ran them. Every journal event records
journald's sender uid in `f.sender_uid`; a `sudo.command`, `su.session` or `passwd`
`host.user_change` event has `f.sender_mismatch: true` when that uid is not root and its user name
(from `/etc/passwd`) is not the user the line names. The event is kept. A uid with no
`/etc/passwd` entry (a user known only to LDAP or SSSD) is not flagged.

Lines in `/var/log/auth.log` and `/var/log/secure` carry no sender identity: any local user can
write a line that reads like an `sshd`, `sudo` or user-change event (`logger -t sshd …`).

## Resource use

The systemd unit sets `MemoryMax=1G` and `GOMEMLIMIT=600MiB`. The cap covers Mooring and the
processes it runs: the edge's Caddy, nginx, `docker` and `docker compose`, and `journalctl`.
`sudo mooring doctor` warns when the loaded unit's `MemoryMax` is lower (the unit from an upgrade
wasn't loaded, or a drop-in lowers it): `sudo systemctl daemon-reload && sudo systemctl restart
mooring`.

The collector queues up to 8192 events. When the queue is full, new lines are dropped and counted,
and a `siem.dropped` event records how many. Mooring's own audit events have a separate queue.

## Configuration

Security logs are on by default. The block in `/etc/mooring/config.yaml`, with the defaults:

```yaml
security_logs:
  enabled: true
  hot_retention: 14d                  # kept and searchable on this server (1d–90d)
  hot_max_disk_mb: 10240              # disk for segments + security.db (minimum 256)
  archive:
    retention: 365d                   # archived hours older than this are deleted (minimum 1d)
    s3: null                          # the S3 archive (see above); null: none
  pii:
    hash_fields: []                   # more names stored as a keyed hash
    drop_fields: []                   # more names removed
    keep_fields: []                   # names taken out of the built-in lists
  host_logs:
    enabled: true                     # false: no host logs
    auth_log: ""                      # "" = /var/log/auth.log, else /var/log/secure
    fail2ban_log: ""                  # "" = /var/log/fail2ban.log
    journal: null                     # null: the journal only when there is no auth log file
```

| Key | Default | Range | Meaning |
|---|---|---|---|
| `enabled` | `true` | | `false` turns collection off. |
| `hot_retention` | `14d` | `1d`–`90d` | How long events stay on this server. |
| `hot_max_disk_mb` | `10240` | `256` and up | Disk for the segments and `security.db` together. |
| `archive.retention` | `365d` | `1d` and up | How long archived objects are kept in S3. |
| `archive.s3` | none | | The S3 archive. |
| `pii.hash_fields`, `pii.drop_fields`, `pii.keep_fields` | `[]` | 64 names each | See [Redaction](#redaction). |
| `host_logs.enabled` | `true` | | `false`: no host logs are read. |
| `host_logs.auth_log` | `""` | absolute path | The auth log; `""` reads `/var/log/auth.log`, else `/var/log/secure`. |
| `host_logs.fail2ban_log` | `""` | absolute path | The Fail2Ban log; `""` reads `/var/log/fail2ban.log`, also once it appears. |
| `host_logs.journal` | unset | `true` / `false` | Unset: read `sshd`, `sudo`, `su` and user and group changes from the journal when there is no auth log file, or when the auth log can't be read (instead of the file). `true`: read the journal as well. `false`: never. |

A value outside its range is clamped, and Mooring logs a `config:` warning at startup saying which
value it used; `sudo mooring doctor` shows the same warnings. So does a `hot_retention` longer than
`archive.retention`. An invalid `archive.s3`, path or `pii` name refuses startup.

The block is read at startup: restart Mooring after a change (`sudo systemctl restart mooring`).

To turn security logs off:

```yaml
security_logs:
  enabled: false
```

Detection rules, alerts on security events, and incidents are not part of security logs yet.
