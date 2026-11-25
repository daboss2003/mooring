# Automated response and the block list

A [detection rule](./security-detections.md) can have a **response**: block the detection's address
at the edge for a time, or sign a Mooring account out of every dashboard session. Mooring records
each response as a recommendation for an owner to apply, or applies it by itself, depending on the
mode. Blocks are kept in the edge's **block list**, where an owner can also place blocks by hand.
Only an **owner** can see responses and blocks and change them.

Automated response is **off by default**. The block list works without it, and with security logs
off.

See also: [Security detections](./security-detections.md) · [Security incidents](./security-incidents.md) · [Log patterns](./security-patterns.md) · [Alerts](./alerting.md)

---

## Turning it on

```yaml
security_logs:
  response:
    mode: recommend                   # off (default), recommend or enforce
```

The key is read at startup: restart Mooring after a change (`sudo systemctl restart mooring`).

| Mode | What happens to a rule's response |
|---|---|
| `off` | Nothing is recorded or done. At startup, every automatic block still in force is removed. |
| `recommend` | Every response is recorded as a recommendation on the Responses page. Nothing is blocked or signed out until an owner applies it. |
| `enforce` | Automatic responses are applied at once, within the [caps](#caps). Recommend-only responses (see [Blocks](#blocks) and [Requests sent by a browser](#requests-sent-by-a-browser)) are recorded as recommendations. |

Requirements:

- [Detection](./security-detections.md) is on. With detection or security logs off, the mode is
  `off`. With `mode` `recommend` or `enforce` and security logs off (`enabled: false`) or
  `detection.enabled: false`, Mooring logs a `config:` warning at startup.
- Blocks need the managed edge (`edge.mode: managed`).
- Automatic blocks need Caddy 2.11 or later (see [HTTP/3 early data and Caddy 2.11](#http3-early-data-and-caddy-211)).
- An `ip_allowlist` that contains `0.0.0.0/0` or `::/0` protects every address, so no block can be
  placed; Mooring logs a `config:` warning at startup.

### Pause

The Responses page can lower the mode until the pause is lifted. A pause never raises the configured
mode, and it is kept across a restart.

| Button | Effect |
|---|---|
| **Pause to recommend only** (mode `enforce`) | Responses are recorded as recommendations only. |
| **Pause all responses** | No response is recorded or done, and every automatic block is removed now. |
| **Lift the pause** | Back to the configured mode. |

- When the automatic blocks can't be removed, the pause is in force all the same. The page says
  `Responses are paused. The automatic blocks couldn't be removed yet; Mooring keeps trying.`, and
  the removal is tried again every 10 minutes.
- A pause is recorded in Mooring's audit log (action `security_response_pause`, detail
  `level=<level>`; `level=off result=ok lift=error` when the blocks weren't removed yet).

## Which detections get a response

A rule's response is asked for each time the rule fires for a detection: when the detection is
first recorded, and at each update. Each firing is checked by itself, as things are at that time:
the requests it counted (see [Requests sent by a browser](#requests-sent-by-a-browser)), the rule's
snooze, the mutes, and whether the rule is on and can have the response. A detection whose earlier
firings asked for nothing (the rule was snoozed, the detection was muted) asks at the first firing that qualifies.

- A block is asked for at most once every 5 minutes per detection; an automatic block and a
  recommendation are counted apart, so a recommendation never delays the automatic block.
- A block request is dropped while the address's own block, active or
  [suspended](#suspended-blocks), has 2 minutes or more to go. Nothing is recorded for it: no
  response, no count toward a [cap](#caps), no audit record, no event and no timeline entry. A
  request in the block's last 2 minutes is handled (see [Automatic blocks](#automatic-blocks)).
- A sign-out is asked for once per detection and account. A detection of a rule grouped by `ip`
  asks for each account that signs in from the address. A detection remembers the last 32 accounts
  it asked for; an account past those can be asked for again.
- A detection recorded before a restart can ask once more after it.

No response is asked for:

- a rule that is switched off, or has no response;
- a muted detection (a [false-positive mute](./security-incidents.md#false-positives-and-mutes)) or
  a detection of a snoozed rule;
- a rule's rollup detection (key `*`) and an [App Ops Interface alert](./app-ops-interface.md#alerts).

### Blocks

| The rule's query lets through | Response |
|---|---|
| Edge events only (`src:edge`): the address the edge saw | Automatic. |
| App events (`src:app`), or edge and app events: an address an app reported counts | Recommend only, in every mode, also for a detection of edge events. |
| Mooring's own events or the host logs | Never blocked. A rule over these events can't have a block response. |

- A rule can have a block response when it is grouped by `ip` and its query matches only edge
  events (`src:edge`) or only app events (`src:app`), or both. For a `sequence` rule both queries
  count: the block is automatic only when both let through edge events only.
- `baseline.ip_behaviour` has no response by default. When one is set, its block follows the same
  rules as the other rules that count edge requests (see
  [Requests sent by a browser](#requests-sent-by-a-browser)): the requests of the burst it fired
  on are the ones counted.
- The block's target is the detection's key: an IPv4 address, or the /64 of an IPv6 address.
- Mooring's sign-in addresses are inside `ip_allowlist`, which is never blocked. Addresses in the
  host logs reach SSH and other ports the edge doesn't serve.

### Requests sent by a browser

A web page or an email can make its readers' browsers and mail clients send requests to any site.
Every edge request counted toward a firing is checked, in the rule's `window` before the firing,
not only the evidence events kept with the detection:

| A counted request | Is | Block |
|---|---|---|
| Has a `Sec-Fetch-Site` header with one of the values browsers send: `cross-site`, `same-origin`, `same-site`, `none` (stored as [`f.fetch_site`](./security-logs.md#kinds)) | Sent by a browser | Recommend only, in every mode. |
| Has no such `Sec-Fetch-Site` header (none, or another value), and a User-Agent ([`f.ua`](./security-logs.md#kinds)) that starts with `Mozilla/` or contains `ms-office`, `Microsoft Office` or `Thunderbird` (in any letter case) | Sent with a browser-like agent | Recommend only, in every mode. |

- One such request among the counted ones is enough: the block is a recommendation, whatever the
  others are.
- Any client can send these headers. A scanner that sends them is not blocked automatically; its
  block waits on the Responses page for an owner to apply.
- A rule whose query needs the address on a threat-intelligence list (a positive `list:` term, as
  in `edge.spamhaus_ip` and `edge.dshield_ip`) is not affected: it blocks whatever sent the
  request.
- The detection is still recorded. Its page marks the evidence events `browser` or
  `browser-like agent`.

### Sign-outs

A sign-out ends every dashboard session of a Mooring user. The user can sign in again; the
password, two-factor setting, role and API tokens are not changed, and no account is locked.

- A rule can have a sign-out response when it is grouped by `actor` or `ip`, its query (for a
  `sequence` rule, both queries) lets through Mooring's events only (`src:mooring`), and its query
  (for a `sequence` rule, its closing query) lets through successful events only (`out:success`).
  Rules over failed sign-ins, and rules that also match app, host or edge events, can't sign
  anyone out.
- `baseline.signin_unusual` is the one rule over several sources with a sign-out response. Only
  its detections of Mooring's own events sign out: Mooring users, never SSH or app accounts.
- The account is the detection's key for a rule grouped by `actor`, and the account of the
  successful sign-in for a rule grouped by `ip`.
- A user name that is an email address is stored in the security logs as one keyed hash, whatever
  its letter case. Mooring users whose email-address names differ only in letter case are one
  account there: a sign-out ends the sessions of all of them.
- An account name that is not plain text on one line, of at most 256 bytes, is refused
  (`invalid_target`).
- A sign-out is automatic in `enforce` and a recommendation in `recommend`.
- Each applied sign-out sends a `critical` [`security_response` alert](#alerts).

### Default responses

| Rule | Response |
|---|---|
| `edge.scan` | Block for 1 hour |
| `edge.spamhaus_ip` | Block for 24 hours |
| `edge.dshield_ip` | Block for 24 hours |
| `mooring.login_success_after_failures` | Sign out the account that signed in |
| `mooring.login_new_country` | Sign out |
| `mooring.login_tor` | Sign out the account that signed in |
| `mooring.login_travel` | Sign out |
| `baseline.signin_unusual` | Sign out (Mooring users only) |

Every other built-in rule has no response. The defaults do nothing while the mode is `off`.

### Changing a rule's response

A rule's **Edit** page has an **Automated response** section when the rule can have one; otherwise
it says why not.

| Setting | Values |
|---|---|
| Response | **None**, **Block the address at the edge**, or **Sign the Mooring account out of every session**: the ones the rule can have. |
| Block length | The first block's length: 1 hour, 4 hours, 24 hours or 7 days (5m–7d). |

**Reset** puts a built-in rule's response back to its default. A custom rule's response is set on
its **Edit** page, under the same conditions, after the rule is saved: the **New custom rule** form
has no response setting. A response that the rule's query no longer allows is never applied.

## Caps

| Cap | Default | Config key |
|---|---|---|
| Automatic blocks placed in an hour | 60 | `security_logs.response.max_blocks_per_hour` |
| Automatic sign-outs in an hour | 3 | `security_logs.response.max_revokes_per_hour` |
| Automatic sign-outs of one account | 1 an hour | |
| Longest automatic block | 24h | `security_logs.response.max_block_duration` |
| Automatic blocks in force | 1,000 | `security_logs.blocking.max_entries` |
| Manual blocks in force | 1,000 | |

- An hour is the 60 minutes before the response, not the clock hour. Only responses Mooring applied
  by itself count: a recommendation an owner applies doesn't.
- Past an hourly cap the response is refused (`hourly_cap`), and a `warning` `security_response`
  alert is sent, at most once an hour per action.
- A refusal for the same reason, action and target is recorded at most once an hour (see
  [The Responses page](#the-responses-page)).
- A [repeat](#automatic-blocks) counts as a block placed.
- A second automatic sign-out of an account within the hour is refused (`cooldown`).
- When the cap can't be counted (Mooring's database busy), nothing is blocked or signed out and
  the response is recorded as failed.
- At most 256 responses wait to be handled; more are dropped and logged.
- When Mooring stops, the responses still waiting are handled for at most 2 seconds. The rest are
  recorded as failed (`interrupted`) and not applied.

## The Responses page

`/security/responses` shows the configured mode and the pause, the automatic blocks and sign-outs
of the last hour against their caps, the recommendations waiting, and the history (50 a page,
filtered by state and action). An incident's page and a detection's page list their responses.

| State | Meaning |
|---|---|
| `recommended` | Waiting for an owner. |
| `applied` | The block was placed, or the sessions were ended. |
| `refused` | Not done, with the reason. |
| `failed` | Tried and failed. Mooring's log has the details. |
| `dismissed` | An owner dismissed the recommendation. |
| `expired` | A recommendation nobody acted on for 7 days. |

- **Apply** on a block recommendation places a [manual block](#manual-blocks) in your name for the
  recommended length, at most `manual_max_duration`. The manual limits apply (the never-blocked
  addresses, your own address). **Apply** on a sign-out recommendation ends the account's sessions
  and sends the alert.
- An **Apply** that is refused sets `refused`, with the reason. An **Apply** that fails (the block
  list or the sessions couldn't be written) leaves the recommendation `recommended`: it can be
  applied again.
- An **Apply** that placed the block or signed the account out, and then couldn't record it,
  returns an error that says the action was done (`the block WAS placed`, `the account WAS signed
  out`). The event, the timeline entry and the sign-out's alert are written. The response stays
  `recommended` until the record is written: at the next **Apply** or **Dismiss** of it, or within
  10 minutes. Until then an **Apply** of it does nothing a second time. After a restart before the
  record is written, it is `recommended` again: applying a block then only records it while that
  block is still in force, and applying a sign-out signs out the sessions opened since.
- **Dismiss** sets `dismissed`. The same action for the same target and incident is not
  recommended again for 24 hours; after that a detection that still asks is recorded as a new
  recommendation.
- At most one recommendation waits per action, target and incident. A new one for the same three
  updates it (its rule, detection, summary and length) instead of adding a second. The 7 days
  count from the last update; recommendations are expired every 10 minutes.
- The **Block state** column shows the address's block at this time: `Not blocked`, `Blocked` (with
  its end), `Suspended`, `Expired` or `Removed`. An address without a block of its own that
  another block in force covers shows `Blocked`, `by <prefix>`; an IPv6 /64 with a narrower block
  inside it shows `Partly blocked`, `by <prefix>`.
- Applying and dismissing are recorded in Mooring's audit log (actions `security_response_apply`,
  `security_response_dismiss`).
- Responses are kept for 400 days.

A refusal of a response Mooring handles by itself is recorded at most once an hour for the same
action, target and reason: the response, its `siem.response` event, its timeline entry and its
audit record. It is not recorded again while the newest response for that action and target is
that refusal and is less than an hour old.

A refused or failed response gives one of these reasons, or a [block refusal](#refusals):

| Reason | Meaning |
|---|---|
| `hourly_cap` | Refused: the hourly cap of automatic actions was reached. |
| `cooldown` | Refused: automated response signed this account out less than an hour ago. |
| `unknown_account` | Refused: no Mooring user is stored as that account. |
| `invalid_target` | Refused: the account name is not valid. |
| `no_revoker` | Refused: dashboard sign-outs are not available (Mooring is still starting). |
| `refused` | Refused: the block list refused it with a code that is no fixed word. |
| `interrupted` | Failed: Mooring stopped before it was handled. Also the responses still waiting when Mooring stopped. |
| `error` | Failed. Mooring's log has the details. |

## The block list

The block list holds the addresses and ranges the edge refuses, each until a set time. It has
automatic blocks (placed by automated response) and manual blocks (placed by an owner). It is on
`/security/blocks` (**Blocked addresses**, linked from the Responses page).

### Manual blocks

**Block an address** takes:

| Field | Values |
|---|---|
| Address or range | An IPv4 address or a CIDR from /24 to /32; an IPv6 address or a CIDR from /48 to /128. An IPv4-mapped IPv6 address is the IPv4 address. |
| Length | 1 hour, 24 hours, 7 days or 30 days, up to `security_logs.blocking.manual_max_duration`. |
| Reason | Optional, at most 300 bytes, shown on the page. Don't put secrets in it. |

- An address's [entity page](./security-incidents.md#dashboard) has **Block for 24 hours** (the
  longest manual length, when `manual_max_duration` is shorter), or **Unblock** when a block of its
  own is in force, active or suspended. An IPv6 address is blocked as its whole /64 network; the
  page says so.
- An address with no block of its own that an active block of a range containing it covers shows
  `Blocked by <prefix>` and neither button: remove that block on the Blocked addresses page.
- An IPv6 /64 with no block of its own and an active narrower block inside it (one address, for
  example) shows `Partly blocked by <prefix>` and keeps the **Block** button, which blocks the
  whole /64.
- A suspended block, and one whose time ran out, covers nothing.
- A manual block of an address that has an automatic block in force takes it over: the block
  becomes manual, and is extended when the new end is later.
- Manual blocks don't need automated response, detection or security logs.
- Adding and removing a block are recorded in Mooring's audit log (actions `security_block_add`,
  `security_block_remove`).

### Automatic blocks

- An automatic block is one IPv4 address or one IPv6 /64.
- The first block lasts the rule's block length, at most `max_block_duration`.
- A repeat is an automatic block of an address whose previous automatic block was placed less than
  30 days ago. It lasts 4 times the length the previous automatic block was placed with (or the
  rule's length when that is longer), at most `max_block_duration`. With a 1 hour rule and the
  default 24h: 1h, 4h, 16h, 24h.
- An automatic request in the last 2 minutes of an automatic block is a repeat: the block is
  placed again from that time, with the next length, and counts in **Times blocked**. Its
  `siem.block` event has the action `applied`.
- Extensions and manual blocks don't count: a repeat multiplies the length the previous automatic
  block was placed with, not its extended length, and a manual block of the address leaves the
  repeat history as it is.
- An owner's **Remove** or **Unblock**, and a false-positive incident, reset the address's repeat
  history: its next automatic block is the first step again.
- An automatic request for an address with a manual block in force extends the block to the
  rule's length (at most `max_block_duration`) from that time, when that is later than its end.
  The block stays manual. A manual block is never placed again as a repeat.
- Automated response sends no request while the address's block has 2 minutes or more to go (see
  [Which detections get a response](#which-detections-get-a-response)). When the block list
  can't be read for that check, the request extends an automatic block in the same way.
- The **Times blocked** column counts the automatic blocks of the address placed within 30
  days of each other (0 for a manual block of an address without one).
- Mode `off` at startup, and **Pause all responses**, remove every automatic block. Manual blocks
  stay. The repeat history is kept.

### Addresses that are never blocked

A block, manual or automatic, that overlaps one of these is refused:

| Addresses | Refusal |
|---|---|
| Loopback, private (RFC 1918), link-local, shared (100.64.0.0/10), multicast, reserved and unspecified IPv4 ranges; every IPv6 address outside `2000::/3` | `local` |
| This server's own addresses (read every 5 minutes) | `local` |
| `ip_allowlist`, as in force (a reload included) | `allowlist` |
| The allowed CIDRs of every active API token | `token_cidr` |
| `edge.trusted_proxies` and the top-level `trusted_proxies` | `trusted_proxy` |
| Cloudflare's published ranges | `cdn` |
| `security_logs.blocking.never_block` | `never_block` |
| The address each signed-in dashboard session signed in from | `session` |
| Your own address, for a manual block | `self` |

The edge checks the list again when it renders its config, and leaves out an entry that overlaps
`ip_allowlist`, `edge.trusted_proxies`, Cloudflare's ranges or a non-public range.

A protected entry written as an IPv4-mapped IPv6 range wider than /96 protects every IPv4 address,
and an entry that is no valid range protects every address. Mooring logs each such entry once.

### Refusals

| Code | Meaning |
|---|---|
| `invalid` | Not an IP address or CIDR. |
| `width` | Manual: wider than /24 (IPv4) or /48 (IPv6). Automatic: not one IPv4 address or an IPv6 /64. |
| `duration` | The length is outside the allowed range (a manual block: 5 minutes to `manual_max_duration`). |
| `no_edge` | Mooring doesn't run the edge (`edge.mode: external`). |
| `old_caddy` | Automatic: the running Caddy is older than 2.11. |
| `exempt` | Automatic: an owner unblocked the address or a range that contains it, or its incident was a false positive, recently. |
| `full` | The blocks of that kind in force are at their cap. A block whose time ran out doesn't count. |
| `local`, `allowlist`, `token_cidr`, `trusted_proxy`, `cdn`, `never_block`, `session`, `self` | The block overlaps an address that is never blocked (above). |

The Blocked addresses page lists the 50 most recent refusals, counted per address and reason.
Refusals are kept for 30 days after the last one, at most 5,000.

### Suspended blocks

A block in force that comes to overlap a never-blocked address (an owner signs in from it, an
`ip_allowlist` entry or an API token's CIDR is added) is **suspended**: the edge doesn't apply it.
It is applied again when the overlap ends, until its time runs out. The list is checked every
minute. A suspended block is stored as such: after a restart it stays suspended until the first
check.

### When a change takes effect

- The edge takes the block list at most once a minute. A change after a quiet minute is applied at
  once; further changes within the minute are applied together when it ends.
- A block whose time ran out is removed from the edge within about 2 minutes.
- The edge reloads its config for each change of the list. WebSocket connections through the edge
  are closed by a reload and have to reconnect.
- When the edge doesn't take the list 3 times in a row, a `warning`
  [`security_blocking` alert](#alerts) is sent; it is resolved when the edge takes the list again,
  also after a restart. The attempt is repeated every minute.
- The page's **Edge** card shows **Applied**, **Pending** or **Failing**. **Failing** shows the
  last attempt's error and `Mooring retries every minute.`

## What a blocked client gets

Every HTTP and HTTPS request through the edge from a blocked address is answered:

```
HTTP/1.1 403 Forbidden
Content-Type: text/plain; charset=utf-8
Cache-Control: no-store

403 Forbidden
```

- The block applies to every app route, catch-all routes and unknown host names included. The
  response names no rule and no reason.
- The dashboard's route comes first and admits only `ip_allowlist` addresses, which are never
  blocked.
- ACME HTTP-01 challenges are answered before any route.
- Blocked requests are in the security logs (`src:edge f.status:403`). They are not counted in the
  edge metrics that drive autoscaling and are not written to the [route error log](./errors.md).

## HTTP/3 early data and Caddy 2.11

With `mode` `recommend` or `enforce`, the edge refuses HTTP/3 0-RTT (early data), as it does with
[`edge.trusted_proxies`](./edge-and-tls.md#http3-early-data): in early data the client's address
is not verified yet. HTTP/3 itself stays on. After Mooring starts, the edge serves HTTP/1.1 and
HTTP/2 only until it has applied the config with the app routes.

Refusing early data needs Caddy 2.11 or later. Mooring reads the running Caddy's version at
startup:

- 2.11 or later: automatic blocks are placed.
- Older, or the version can't be read: automatic blocks are refused (`old_caddy`) and recorded as
  refused responses; Mooring logs a warning at startup, and the Blocked addresses page says why.
  Recommendations, manual blocks and sign-outs still work.
- With `mode: off` and no `edge.trusted_proxies`, the edge doesn't refuse early data. The Blocked
  addresses page shows the automatic blocks as `Not placed`, with the reason `the edge doesn't
  refuse QUIC 0-RTT while automated response is off (security_logs.response.mode)`.
- `mooring doctor` fails its `caddy` check, naming `security_logs.response`. `sudo mooring setup`
  upgrades Caddy (see [Validation and requirements](./edge-and-tls.md#validation-and-requirements)).
  Restart Mooring afterwards.

## Behind a CDN or proxy

- Without `edge.trusted_proxies`, the edge sees the proxy's address for every request, and blocks
  match that address. Cloudflare's ranges are never blocked: an automatic block of one is refused
  (`cdn`), and a `warning` `security_blocking` alert says to set `edge.trusted_proxies`, at most
  once a day.
- With [`edge.trusted_proxies`](./edge-and-tls.md#behind-a-cdn-or-proxy), detections and blocks use
  the client address the trusted proxy reports, and the proxies' own addresses are never blocked.
- A proxy or load balancer other than Cloudflare isn't known to Mooring: list its addresses in
  `edge.trusted_proxies`, or in `security_logs.blocking.never_block`.

## L4 listeners

```yaml
security_logs:
  blocking:
    l4: true
```

With `blocking.l4: true`, the [L4 load balancer](./edge-and-tls.md#layer-4-tcpudp-load-balancing-opt-in-default-off)
refuses new TCP connections and UDP sessions from blocked IPv4 addresses on every `forward: proxy`
listener. It is off by default.

Not filtered:

- Connections that are already open.
- IPv6 clients of L4 listeners.
- `forward: kernel` listeners: Docker forwards those ports, not nginx.
- SSH and every other port the host opens itself. Use Fail2Ban or the host firewall.

`blocking.l4: true` needs the L4 load balancer (`edge.l4_enabled: true`, and nginx with the stream
module). Without it no L4 listener is filtered: Mooring logs a `config:` warning at startup when
`edge.l4_enabled` is off, and a warning with the reason when the load balancer doesn't run. The
Blocked addresses page's **L4 listeners** card shows **Not filtered** with the reason
(`edge.l4_enabled is off`, `the L4 load balancer doesn't run on this host: …`, or that Mooring
doesn't run the edge), and its **Not filtered by Mooring** list gives the same reason for every L4
listener.

The Blocked addresses page lists the L4 ports that are not filtered. When nginx refuses its config
with the block list, the listeners are served without it, and the apply counts as failed (the
`security_blocking` alert after 3 in a row).

## False positives and exemptions

- **Remove** on a block (or **Unblock** on the entity page) lifts it, exempts the address from
  automatic blocks for 24 hours, and resets its repeat history. Removing a range also exempts the
  automatic blocks of every address inside it for the 24 hours.
- Marking an [incident](./security-incidents.md#false-positives-and-mutes) a false positive, with or
  without a mute, removes the automatic blocks placed for it, exempts every address automatically
  blocked for it from automatic blocks for 30 days (also one whose block already ran out), resets
  their repeat history, and dismisses its waiting recommendations. The incident's timeline gets a
  `response` entry with the counts.
- Blocks an owner placed or took over, an applied recommendation included, are not removed by a
  false positive.
- An exemption applies to automatic blocks only (refusal `exempt`). A manual block can still be
  placed.

## Events

With security logs on, responses and block changes are written as security events, searchable,
exported and archived like any other. They are never evaluated by the rules.

| Kind | `lvl` | `f` | Other fields |
|---|---|---|---|
| `siem.response` | `warn` for applied, refused and failed; else `info` | `action` (`block`, `revoke`), `target`, `state`, `rule`, `duration_s`, `response_id`, `automatic`; `reason`, `detection_id`, `incident_id`, `by` when set | `ip` for a block of one address; `actor` for a sign-out; `msg` says what happened (`blocked 203.0.113.7/32 for 1h`) |
| `siem.block` | `info` | `action` (`applied`, `extended`, `expired`, `removed`, `suspended`, `resumed`), `prefix`, `source` (`auto`, `manual`), `until`; `rule`, `incident_id`, `why` when set | `ip` for one address; `actor`: the owner who placed or removed it |
| `siem.block_refused` | `warn` | `prefix`, `code`, `source`; `rule` when set | `ip` for one address; `actor`: the owner who asked |

```
kind:siem.response f.state:applied
kind:siem.block f.action:removed
kind:siem.block_refused f.code:cdn
```

A sign-out's `siem.response` event names the account in its stored form, in `actor`, `f.target` and
`msg`: the user name, or its keyed hash when the user name is an email address (see
[Redaction](./security-logs.md#redaction)). The Responses page, the incident's timeline, the audit
log and the alert have the user name.

When more than 100 blocks expire or are removed at once, the first 100 get an event each and one
more event counts the rest (`f.count`).

An incident's timeline gets a `response` entry for each response about it (`blocked 203.0.113.7/32
for 1h`, `recommended signing alice out`, `block of 203.0.113.7/32 refused: hourly_cap`), at most
100 per incident. A request that only updates a waiting recommendation, a request that is dropped,
and a refusal that is not recorded again within the hour get neither an event nor an entry.

## Audit log

| Action | Recorded when | Actor |
|---|---|---|
| `security_response` | Mooring applies a response by itself, or it is refused (a refusal for the same reason, action and target at most once an hour) or fails; automatic blocks are removed because the mode is `off` or paused. The detail has the action, state, reason, rule and length or session count. | `siem` |
| `security_response_apply`, `security_response_dismiss` | An owner applies or dismisses a recommendation. | the owner |
| `security_response_pause` | An owner pauses responses or lifts the pause. The detail has the level, and `result=ok lift=error` when the automatic blocks weren't removed yet. | the owner |
| `security_block_add`, `security_block_remove` | An owner places or removes a block. The detail has the prefix and length, never the reason. | the owner |

## Alerts

Both kinds go to every enabled channel (see [Alerts](./alerting.md#host-and-edge-maintenance-alerts)).
Every `security_blocking` alert has the target `blocklist`. A `security_response` alert has the
target `security-logs`, or `respond` when automated response couldn't start.

| Kind | Level | Sent when |
|---|---|---|
| `security_response` | `critical` | A Mooring account was signed out, automatically or by an owner applying a recommendation. The message names the user, the number of sessions ended, the rule and the detection's summary. |
| `security_response` | `warning` | Automatic blocks or sign-outs reached their hourly cap. At most once an hour per action. |
| `security_response` | `warning` | Automated response couldn't start. Nothing is blocked or signed out automatically until Mooring is restarted with the cause fixed. Target `respond`. Resolved by the next start at which it starts. |
| `security_blocking` | `warning` | The edge didn't take the block list 3 times in a row. Resolved by the next apply that works, also after a restart. |
| `security_blocking` | `warning` | The automatic blocks in force reached `max_entries`; new automatic blocks are refused. At most once an hour. Resolved when the automatic blocks in force are below `max_entries` again. |
| `security_blocking` | `warning` | An automatic block of a CDN address was refused. At most once a day. |
| `security_blocking` | `warning` | The block list couldn't be read at startup. No address is blocked until Mooring is restarted with the cause fixed. Resolved by the next start at which it is read. |

A placed block sends no alert.

## Configuration

```yaml
security_logs:
  response:
    mode: off                         # off, recommend or enforce
    max_blocks_per_hour: 60           # automatic blocks placed in an hour (1–1000)
    max_revokes_per_hour: 3           # automatic sign-outs in an hour (1–100)
    max_block_duration: 24h           # the longest automatic block (1h–7d)
  blocking:
    max_entries: 1000                 # automatic blocks in force (1–10000)
    manual_max_duration: 30d          # the longest manual block (1h–30d)
    l4: false                         # true: L4 forward: proxy listeners refuse blocked IPv4 addresses
    never_block: []                   # addresses and CIDRs never blocked
```

| Key | Default | Range | Meaning |
|---|---|---|---|
| `response.mode` | `off` | `off`, `recommend`, `enforce` | See [Turning it on](#turning-it-on). Any other value refuses startup. |
| `response.max_blocks_per_hour` | `60` | `1`–`1000` | Automatic blocks placed in an hour. |
| `response.max_revokes_per_hour` | `3` | `1`–`100` | Automatic sign-outs in an hour. |
| `response.max_block_duration` | `24h` | `1h`–`7d` | The longest automatic block, also for repeats. |
| `blocking.max_entries` | `1000` | `1`–`10000` | Automatic blocks in force. |
| `blocking.manual_max_duration` | `30d` | `1h`–`30d` | The longest manual block. |
| `blocking.l4` | `false` | | `true`: see [L4 listeners](#l4-listeners). With `edge.l4_enabled` off, Mooring logs a `config:` warning at startup. |
| `blocking.never_block` | `[]` | 256 entries | IP addresses and CIDRs that are never blocked. An entry that is neither refuses startup. |

A number or duration outside its range is clamped, and Mooring logs a `config:` warning at startup
saying which value it used. The `blocking` keys apply with security logs off too. Every key is read
at startup.

## Storage

- Blocks and refusals (tables `edge_blocks`, `edge_block_refusals`), responses and the pause
  (`security_responses`, `security_response_pause`) are in Mooring's database, so the
  [Mooring-state backup](./backup-and-recovery.md) and `mooring restore` include them. A restored
  block whose time has not run out is in force again.
- A block's row is kept for 30 days after the block ended and its exemption ran out. It holds the
  address's repeat history and whether the block is suspended.
- Each rule's response is stored with the rule's other settings (table `security_rules`).

## Limits

| What | Limit |
|---|---|
| Automatic blocks in force | `max_entries` (default 1,000, at most 10,000) |
| Manual blocks in force | 1,000 |
| Manual block width | /24 (IPv4), /48 (IPv6) |
| Automatic block width | One IPv4 address, or an IPv6 /64 |
| Block length | 5 minutes at least; automatic: `max_block_duration`; manual: `manual_max_duration` |
| Recommendation | Expires 7 days after its last update |
| Responses waiting to be handled | 256 |
| `response` entries in an incident's timeline | 100 |
| Blocks listed on the page | 1,000 |
