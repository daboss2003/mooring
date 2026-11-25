# Log patterns

Mooring groups the log lines of each app service, and the host's unclassified lines, into
**patterns**: templates with the variable parts masked. After a source's learning period, a template
seen for the first time is reported as new, and a sharp rise of a known one as a spike. The reports
are [detections](./security-detections.md) of the four `pattern.*` rules. Only an **owner** can see
patterns and change their state.

Log patterns run whenever [detection](./security-detections.md) is on. They are **on by default**.

See also: [Security detections](./security-detections.md) · [Security logs](./security-logs.md) · [Automated response](./security-responses.md)

---

## What is mined

| Source | Lines | Scope |
|---|---|---|
| An app service | Every [security log](./security-logs.md) event of the app (`src:app`) with a message, whatever its kind. | `app:<slug>/<service>`: one per service of each app. |
| The host | Host events of kind `log` (lines of the host logs that are no SSH, sudo, su, account or Fail2Ban event). A systemd journal line is mined only when root sent it. | `host` |

Not mined: the edge's access log, Mooring's own events, `siem.*` events, events without a message,
the apps in `exclude_apps`, and events older than 24 hours or more than 5 minutes ahead of the
server clock (see [How rules are evaluated](./security-detections.md#how-rules-are-evaluated)).

A line is the event's `msg` after [redaction](./security-logs.md#redaction): its first 1024 bytes.
Each scope has its own templates and its own learning period.

## Templates

A line is split at whitespace and control characters into at most 64 tokens (the rest of a longer
line is one `<*>`). ANSI colour sequences are skipped. The variable part of each token is replaced
by a mask:

| Mask | Replaces |
|---|---|
| `<NUM>` | A decimal number, with an optional sign, fraction, exponent and unit (`12`, `3.5ms`, `80%`, `10MiB`), or a duration such as `1h2m3.5s`. |
| `<HEX>` | `0x` and hex digits, or at least 8 hex digits. |
| `<UUID>` | A UUID. |
| `<IP>` | An IPv4 address with an optional port or prefix length, or an IPv6 address (bare, in brackets with an optional port, or with a prefix length). |
| `<TS>` | An RFC 3339 time, a date (`2026-11-25`, `2026/11/25`) with an optional time, or a clock time (`08:14`, `08:14:03.120`), with an optional zone. |
| `<HASH>` | A keyed hash written by redaction (`h:` and 16 hex digits). |
| `<B64>` | At least 20 base64 or base64url characters with an upper-case letter, a lower-case letter and a digit. |
| `<STR>` | A quoted run (`"…"` or `'…'`), spaces included. |
| `<LONG>` | Any other token longer than 32 bytes. |
| `<*>` | A position where the lines of the template differ. |

- A `key=value` token keeps `key=` and masks the value (`user_id=<NUM>`, `path=<STR>`). The key is
  letters, digits, `_`, `.` and `-`, at most 32 bytes.
- Leading brackets and trailing brackets and punctuation stay around a mask: `(12ms),` is
  `(<NUM>),`.
- A line joins the most similar template among those with the same number of tokens and the same
  first two tokens (a token with a digit counts as any), when at least half of its tokens are the
  template's. The template keeps the tokens they share and has `<*>` elsewhere. Otherwise the line
  starts a template of its own.

```
user=<STR> signed in from <IP> in <NUM>
GET <*> <NUM> <NUM>
job <UUID> failed after <NUM> attempts
```

A template's text is at most 512 bytes. Its ID is `p` and 16 hex digits, derived from the scope and
the template's first text: the same on every server and across restarts.

## Learning period

A scope learns from its first mined line for the `learn` of the new-pattern rules: 7 days by
default. `pattern.new`'s `learn` applies to templates below `warn`, `pattern.new_error`'s to
templates at `warn` or above.

- A template first seen while its scope learns has the state `learned` and is never reported as
  new.
- `pattern.churn` doesn't fire while a scope learns.
- The Patterns page lists the scopes still learning (at most 50).

## Rules

| ID | Name | Severity | Fires when |
|---|---|---|---|
| `pattern.new` | New log pattern | low | A template whose highest level is below `warn` is first seen after its scope's learning period. |
| `pattern.new_error` | New error log pattern | medium | The same, for a template whose highest level is `warn`, `error` or `critical`. |
| `pattern.spike` | Log pattern spike | medium | A known template has far more lines in a short time than usual at that time of day. |
| `pattern.churn` | Log pattern churn | medium | A scope makes new templates faster than the limits allow. |

The rules are built-in rules of type `baseline`: they can be switched off, snoozed and tuned on the
[Rules page](./security-detections.md#changing-a-built-in-rule), and **Reset** puts the defaults
back. Their queries aren't evaluated; the Detections page uses them to search for related events.

| Rule | Parameter | Default | Range | Meaning |
|---|---|---|---|---|
| `pattern.new`, `pattern.new_error` | `count` | 1 | 1–100000 | Lines the template needs before it is reported. |
| | `window` | 5m | 1m–24h | The settle time: the template is reported this long after its first line. |
| | `learn` | 7d | 1h–30d | The scope's learning period. |
| `pattern.spike` | `count` | 100 | 1–100000 | Lines of the template in the window, at least. |
| | `window` | 10m | 1m–1h | The time the lines are counted over. |
| | `factor` | 5 | 1.5–1000 | Times the usual count the lines must exceed. |
| | `learn` | 3d | 1d–7d | How old the template must be (since its first line). |
| `pattern.churn` | `count` | 1 | 1–100000 | Lines past the scope's limits, at least. |

### New patterns

A template first seen after its scope's learning period has the state `new`. It is reported once,
`window` after its first line, when it has at least `count` lines: by `pattern.new_error` when a
line of it was at `warn` or above by then, else by `pattern.new`. The settle time lets the template
take its final shape (its `<*>` positions) before the report.

```
log pattern p3f9a1c0b7d2e4a68 — new in shop/web: 3 lines in 5m (error)
```

- A template an owner sets to `expected` or `learned` (**Keep watching**) before it is reported is
  not reported. One set to `ignored` is still reported: `ignored` switches off its spikes only.
- A template that settles while its rule is switched off is not reported, also after the rule is
  switched on again.
- Every new template is reported, also the ones a deploy brings.
- Each of the two rules reports at most 40 templates per hour of the server clock, the oldest
  first. The others are reported in the following hours.
- A new template [forgotten for room](#limits) before its report: when it had settled and had
  `count` lines, and its rule is on, it is reported at that time if the hour has reports left;
  otherwise it is not reported and Mooring logs a warning. A template forgotten before it settled
  is not reported.

### Spikes

`pattern.spike` fires for a template whose first line is `learn` ago or more when its lines in the
last `window` are at least `count` and more than `factor` times its usual count.

- The usual count is the highest of three medians, scaled to the window: the median of the
  template's hourly counts at the same local hour of the day on the previous 7 days, and the same
  for the hour before it and for the hour after it. Of an even number of hours a median is the
  higher of the two middle counts.
- Only hours Mooring watched whole count: not the hour Mooring started in, not hours it was
  stopped, not hours in which lines were dropped or left unmined over the
  [CPU budget](#cpu-budget), and not hours before the template's first line.
- Each of the three medians needs at least 3 such hours. An hour of the day with fewer has no
  median; when none of the three has one, the rule doesn't fire.
- A template fires at most once per `window`.
- Hours are in the server's local time zone.

```
log pattern p3f9a1c0b7d2e4a68 — shop/web: 480 lines in 10m, usually about 12
```

### Churn

A scope makes at most 20 new templates a minute and 100 an hour. Lines that would start a template
past those limits, or past the scope's other [limits](#limits), are counted and not sorted into a
pattern. Once the scope has learned, `pattern.churn` fires when `count` such lines have
accumulated, at most once every 10 minutes per scope. Its key is the scope. The summary names the
cause:

| Lines counted since the last report | Summary |
|---|---|
| Past the new-template limits only | `new log patterns past the cap (20 a minute, 100 an hour); N lines not sorted into a pattern` |
| No room for a new template only (one of the other [limits](#limits), such as the templates of one shape) | `no room left for new log patterns; N lines not sorted into a pattern` |
| Both | `new log patterns past the cap (20 a minute, 100 an hour) and no room left for new ones; N lines not sorted into a pattern` |

```
log scope app:shop/web — new log patterns past the cap (20 a minute, 100 an hour); 37 lines not sorted into a pattern
```

## States

| State | Meaning | `pattern.new`, `pattern.new_error` | `pattern.spike` |
|---|---|---|---|
| `learned` | Seen while its scope was learning, or put back to watching by an owner. | not reported | reported |
| `new` | First seen after its scope's learning period. | reported once | reported |
| `expected` | An owner marked it normal. | not reported | not reported |
| `ignored` (shown as **Spikes ignored**) | An owner switched its spikes off. | reported once, when it was new and not reported yet | not reported |

Actions on a pattern's page:

| Action | Sets |
|---|---|
| **Mark expected** | `expected` |
| **Ignore spikes** | `ignored` |
| **Watch again** (**Keep watching** for a new pattern) | `learned` |

A state change is recorded in Mooring's audit log (action `security_pattern_state`). A state can't
be set to `new`.

The `expected` and `ignored` states an owner set are also kept apart from the templates, by
template ID: at most 2,000, the ones set longest ago dropped first. A template that was forgotten
and is made again by the same line has its owner's state again.

## Detections and alerts

- A pattern detection's key is the pattern's ID (`pattern.churn`: the scope). The detection names
  the app and service. Its page has **View the log pattern**; with `patterns.enabled: false` it
  has no pattern link.
- The summary holds the scope and the counts, never the template or a line's text. Alerts and
  `siem.detection` events carry the summary only.
- Pattern detections join no [incident](./security-incidents.md).
- With the default severities (low and medium) no alert is sent: the detections are on the
  Detections page and the pattern's page only. A rule raised to `high` or `critical` on its
  **Edit** page sends `security_detection` alerts with the limits in
  [Severities and alerts](./security-detections.md#severities-and-alerts).
- The pattern rules have no [response](./security-responses.md).

## Sample line

Each pattern keeps one sample: a redacted line of it, at most 512 bytes. It is replaced by a newer
line at most once an hour, and removed once it is older than the security logs' `hot_retention`
(checked every hour, and when Mooring starts). The sample is shown on the pattern's page only.
With `patterns.enabled: false`, every stored sample is removed when Mooring starts.

## CPU budget

Mining runs in one background worker with a CPU budget: `max_cpu_percent` of one CPU core (default
5), measured per second.

- Over the budget in a second: a line is counted only when it fits a template it was sorted into
  before. Other lines are counted as not mined; no template is made or changed.
- Over twice the budget in a second: the worker pauses until the second ends. Lines wait in a queue
  of 4,096 lines (4 MiB); when it is full, new lines are dropped and counted.
- An hour in which lines were dropped, or left unmined over the budget, is not used as a spike's
  history.

The Patterns page shows the share of the budget used in the last minute and the lines not mined,
by reason. Collection, search and the other detection rules are not affected.

## Limits

| What | Limit |
|---|---|
| Scopes | 1,000; lines of further scopes are not mined. |
| Templates per scope | 500 |
| Templates in all | 10,000 |
| New templates per scope | 20 a minute, 100 an hour |
| Templates of one shape (same token count and first two tokens) | 64; a further line counts for the most similar one, or is not sorted. |
| Tokens per line | 64 |
| Line length mined | 1,024 bytes |
| Hourly counts kept per template | 8 days |
| A template without a line | Forgotten after 30 days; one marked `expected` or `ignored`, after 400 days. |
| A scope without a template | Dropped 30 days after its last line. |
| Owner's states kept apart from the templates | 2,000 |
| New-pattern detections per rule | 40 an hour |

Past the template limits, the template used least recently is forgotten, in this order: first the
templates seen in one hour only; then, of those, the new templates not reported yet; then the
templates seen in two or more hours, which take at most three quarters of the places; last the
templates marked `expected` or `ignored`. A forgotten
template that comes back is a new template; one that was marked `expected` or `ignored` and comes
back from the same line has that state again.

## Dashboard

Both pages are for owners only.

- With `patterns.enabled: false`, the Patterns page says that log patterns are off and how to turn
  them on.
- **Patterns** (`/security/patterns`): the number of patterns and scopes, the lines mined since
  Mooring started, the CPU budget used, the lines not mined, and the scopes still learning. The
  list shows each pattern's last time, highest level, state, template, source and line count, 50 a page, filtered by app, service, state, minimum level and **Host only**, sorted by last
  seen, most lines in the last 24 hours, or newest first. The first page updates every 30 seconds.
- A pattern's page (`/security/patterns/<id>`): the template, the sample line, the state, the
  highest level, the source, the first and last time, the lines since it was first seen, the lines
  per hour for the last 7 days, the state actions, and its 20 newest detections. **Find events**
  searches the Security logs for the source (`app:<slug> svc:<service>`, or `src:host`) and up to 6
  constant parts of the template as text; lines of other patterns that share that text match too.
  A part with a control character or a Unicode format character (a zero-width space, a
  bidirectional override) is left out.

## Storage

- Templates, their states, counts and samples, each scope's start and the time of its last line
  (to the day), the states an owner set, and the hours watched are in
  `<data_dir>/security-logs/detect.db`, with the detections.
- New and changed templates and state changes are saved every second (at most 128 a second, an
  owner's state changes first). Counts are saved every 10 minutes and when Mooring stops; after
  Mooring was killed, the counts are those of the last save.
- A row that can't be read is dropped, and learned again.
- Deleting an app deletes its patterns, also with `patterns.enabled: false`, and the app's lines
  are not mined for 10 minutes after.
  After a start, the patterns of apps that no longer exist are removed, as for
  [mutes](./security-incidents.md#false-positives-and-mutes).

## Clock changes

When the server clock is set back into an hour Mooring already closed (a step of more than 2
minutes back across the start of an hour), the hours watched start again: the hourly history is
not used, and spikes need 3 watched hours again. Templates, their states and the owner's states
are kept. Stored times more than 2 minutes after the clock are set to the clock.

## Upgrades

After an upgrade that changes how lines are split or masked, every scope learns again for 24
hours. Templates, their counts and their states are kept; a template first seen in those 24 hours
is `learned`, not `new`.

## Configuration

```yaml
security_logs:
  detection:
    patterns:
      enabled: true                   # false: no log patterns
      max_cpu_percent: 5              # share of one CPU core (1–25)
      exclude_apps: []                # app slugs whose lines are not mined
```

| Key | Default | Range | Meaning |
|---|---|---|---|
| `security_logs.detection.patterns.enabled` | `true` | | `false`: lines are not mined and the `pattern.*` rules don't fire. |
| `security_logs.detection.patterns.max_cpu_percent` | `5` | `1`–`25` | The miner's share of one CPU core. A value outside the range is clamped, with a `config:` warning at startup. |
| `security_logs.detection.patterns.exclude_apps` | `[]` | 256 app slugs | Apps whose lines are not mined. A value that is no app slug refuses startup. |

- An app is excluded in `config.yaml` only. Patterns already learned for an excluded app stay until
  they are forgotten (30 days without a line; 400 days for one marked `expected` or `ignored`).
- Turning detection off (`security_logs.detection.enabled: false`) or security logs off turns log
  patterns off.
- The block is read at startup: restart Mooring after a change (`sudo systemctl restart mooring`).
