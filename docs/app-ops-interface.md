# App Ops Interface (rich per-service monitoring)

Any service can expose a small HTTP **ops endpoint**, and Mooring turns it into a rich, live view on that **service's page** — dependency health, queues, and open-ended metric cards (database, cache, routes, system, memory, …). It's opt-in, per-service, and degrades safely: if a service doesn't implement it (or the response doesn't match), the service just shows its basic Docker-derived status.

This is the self-hosted analogue of a Laravel Pulse / Horizon dashboard — but driven by a tiny JSON contract your app implements, shown inside Mooring next to the service's logs and controls.

See also: [The definition file](./definition-file.md) · [Secrets & config files](./config-files-and-secrets.md)

---

## Where it shows up

Open an app, click a **service name** in its table → the service's page. When that service exposes an ops endpoint you'll see:

- **Health** — a RICH badge plus one tile per dependency the app reports (db, cache, broker, …) with `up` / `degraded` / `down`.
- **Metric cards** — one panel per group your app returns (Database, Cache, Routes, System, Memory, anything).
- **Queues** — each queue with its state and counts.

It's **per service** — each service is probed independently, so `api`, `worker`, and `resolver` each get their own ops view.

## Enable it (per service, in `mooring.yaml`)

```yaml
spec:
  secrets:
    - name: ops_secret            # the shared secret's VALUE is set in the dashboard, never in this file
  compose:
    services:
      api:
        image: ...
        ops_interface:
          enabled: true
          base_url: http://api:8080   # in-cluster origin (never loopback)
          base_path: /ops             # optional prefix for the endpoints below
          secret_header: X-Ops-Secret # Mooring sends the secret in this header on every probe
          secret: ops_secret          # references spec.secrets[].name (value resolved from the secret store)
          mode: auto                  # auto (discover) | rich (probe directly) | basic (off)
          adapter: ops.v1
```

Set the `ops_secret` value on the app's **Environment** page (it's write-only/masked). Mooring sends it in `secret_header` on every request, so your app can require it and reject anyone else.

## What your app implements

All paths are under `base_path` (default none). Every response is treated as **untrusted**: size-capped, schema-checked, element-count-capped; any mismatch just drops that part — it never crashes Mooring.

### 1. Discovery — `GET /.well-known/ops` (for `mode: auto`)

```json
{ "opsInterfaceVersion": "1.0", "capabilities": ["health", "queues", "metrics"], "basePath": "/ops" }
```

Mooring speaks **major version 1**. List only the capabilities you implement. With `mode: rich` you can skip this and Mooring probes the endpoints directly.

### 2. Health — `GET {basePath}/health/live`  (capability `health`)

Terminus-style; each entry becomes a health tile:

```json
{
  "status": "ok",
  "details": {
    "postgres": { "status": "up", "message": "" },
    "redis":    { "status": "degraded", "message": "high latency" }
  }
}
```

`status` values map to `up` / `down` / `degraded` (anything else → `unknown`).

### 3. Metrics — `GET {basePath}/metrics`  (capability `metrics`)

**Open-ended** — you name the groups; Mooring renders each as a card. `value` may be a string or a number; `unit` and `status` (for coloring) are optional.

```json
{
  "groups": [
    { "title": "Database", "items": [
      { "label": "Connections", "value": 12, "status": "up" },
      { "label": "Slow queries (1m)", "value": 3, "unit": "/min", "status": "degraded" },
      { "label": "Pool wait p95", "value": 4.1, "unit": "ms" }
    ]},
    { "title": "Cache", "items": [
      { "label": "Hit rate", "value": 94.2, "unit": "%" },
      { "label": "Keys", "value": 18234 }
    ]},
    { "title": "Routes (p95, 5m)", "items": [
      { "label": "GET /api/users", "value": 42, "unit": "ms" },
      { "label": "POST /api/login", "value": 120, "unit": "ms", "status": "degraded" }
    ]},
    { "title": "System", "items": [
      { "label": "Memory", "value": 312, "unit": "MiB" },
      { "label": "Goroutines", "value": 84 }
    ]}
  ]
}
```

Use as many groups/items as you like — Database, Cache, Routes, System, Memory, Jobs, Exceptions, whatever your app tracks. (Per-poll counts are capped at 64 groups × 64 items; longer strings are clipped.)

### 4. Queues — `GET {basePath}/queues`  (capability `queues`)

```json
{ "queues": [ { "name": "default", "isPaused": false, "counts": { "waiting": 3, "active": 1, "failed": 0 } } ] }
```

Each response may also be wrapped in a `{ "status": ..., "data": ... }` envelope — Mooring unwraps it.

#### Queue actions (pause / resume / retry-failed)

If you also expose `POST {basePath}/queues/{queue}/{action}` for `action` ∈ `pause | resume | retry-failed`, the service page renders **pause / resume / retry-failed** buttons next to each queue. Mooring POSTs to **that service's own ops endpoint** (the same one its queues are read from) with the `secret_header`, and logs an `ops_queue_<action>` audit event. Protected/managed projects never get action buttons. Respond `2xx` on success.

## Auth

Mooring sends the configured `secret_header: <your secret>` on every request and validates TLS/SSRF on its side (it only dials the in-cluster `base_url`, never loopback). Require that header in your ops handlers so only Mooring can read them.

## Modes

- **auto** — fetch `/.well-known/ops`, use the advertised capabilities.
- **rich** — skip discovery; probe `health/live`, `queues`, and `metrics` directly (use when the app gates its ops endpoints and you don't want a descriptor).
- **basic** — ops off for this service (it shows Docker-derived status only).

## Alerts

`alerts` in an `ops_interface` block (per service or app-level) declares conditions on the values that endpoint reports. Mooring reads the values in the background and records a [detection](./security-detections.md) when a condition holds.

Example for a DNS resolver:

```yaml
ops_interface:
  enabled: true
  base_url: http://resolver:8081
  base_path: /ops
  secret_header: X-Ops-Secret
  secret: OPS_SECRET
  alerts:
    - { name: ratelimit-drops, metric: { group: Limiter, label: Ratelimit drops }, when: increases, window: 5m }
    - { name: qps-spike, metric: { queue: dns, count: qps }, when: above_usual, factor: 5, min: 200, window: 2m }
    - { name: allowlist-refusals, metric: { group: Limiter, label: Refused (allowlist) }, when: increases, value: 100, window: 5m, severity: medium }
    - { name: empty-questions, metric: { group: Limiter, label: Empty questions }, when: increases, value: 100, window: 5m, severity: medium }
```

### Keys

| Key | Value | Default |
|---|---|---|
| `name` | `[a-z0-9][a-z0-9-]{0,47}`, unique within the `ops_interface` | required |
| `metric` | `{ group, label }` or `{ queue, count }` (see below) | required |
| `when` | `increases` \| `above` \| `above_usual` | required |
| `value` | number. `increases`: the rise that fires, `>= 0`. `above`: the limit, required and not `0` | `0` (`increases`) |
| `factor` | number, `1.5`–`1000` (`above_usual` only) | `5` |
| `min` | number, `>= 0` (`above_usual` only) | `0` |
| `window` | duration, `30s`–`24h`; `above_usual` at most `23h` | `5m` (`increases`), `1m` (`above`, `above_usual`) |
| `severity` | `low` \| `medium` \| `high` \| `critical` | `high` |

An `ops_interface` has at most 16 alerts, and alerts need `enabled: true`. An app declares alerts on at most 8 `ops_interface` blocks, the app-level one and the services' together. `value` is refused on `above_usual`; `factor` and `min` are refused on `increases` and `above`. With `mode: basic` Mooring doesn't probe the endpoint, so its alerts don't run.

While the app-level `spec.ops_interface` declares alerts, the dashboard's ops settings refuse to turn the ops interface off. Remove the alerts from `mooring.yaml` and deploy first.

### Metric references

- `{ group: <title>, label: <label> }` — one item of `GET {basePath}/metrics`: the group's `title` and the item's `label`. The item's `value` must be a number or a numeric string; any other value is skipped.
- `{ queue: <name>, count: <key> }` — one count of `GET {basePath}/queues`: the queue's `name` and a key of its `counts`.

Names are matched exactly, case included. Each is 1–128 bytes, with no control characters and no leading or trailing space. A reading that doesn't include the value, and a failed probe, add nothing to the history.

### Conditions

- **`increases`** — the value rose by more than `value` over the last `window`, counted from the last reading at or before `window` ago. That reading must be at most 1 minute older than `window` (one missed reading); after a longer gap in the readings the alert can't fire until the readings reach back `window` again. The rise is added up reading by reading. A reading lower than the one before it is a counter reset (the app restarted): the rise to that reading counts from 0, so a restart is never a negative rise. The alert can't fire until the history reaches back `window`. Use it for counters.
- **`above`** — the value stayed above `value` for the whole `window`: every reading in the last `window`, and the last reading before it, is above `value`, and no two of those readings are more than 1 minute apart. A reading equal to `value` is not above it.
- **`above_usual`** — the value stayed above `max(factor × usual, min)` for the whole `window`, read the same way as `above`. `usual` is the median of the readings from the last 24 hours, leaving out the last `window`. The alert can't fire until the history reaches back one hour more than `window`. Use `min` to ignore spikes from a low usual level (a usual level of 0 makes `min` the limit).

The history covers 24 hours and is kept in memory only: it starts again when Mooring restarts, when an alert's `metric` changes, and when the container Mooring reads the values from changes.

### Polling and detections

- Mooring evaluates the alerts every 30 seconds. Each `ops_interface` with alerts is probed for this in the background, one at a time, with a 6-second timeout, the same way the service page probes it. The app-level `spec.ops_interface` is probed with the dashboard's ops settings (its base URL, secret header and secret).
- When `base_url` names a service, Mooring reads one running copy of it: the copy it read last while that copy runs, otherwise the copy the service page reads. After 3 failed probes of that copy in a row, while another copy runs, Mooring reads the running copy with the lowest address among the others. When the copy changes (a scale-down removed it, a deploy recreated it, its probes kept failing), the history of that `ops_interface`'s alerts starts again; values of two copies are never compared.
- No probe starts later than 20 seconds into a round; the `ops_interface` blocks left out are probed first in the next round. Each app gets an equal share of a round's time: the next probe is always of the app whose probes have taken the least time so far in that round.
- A failed probe adds nothing to the history and is logged at most every 15 minutes. An endpoint whose probes keep failing is tried 1, 2, 4, 8 … rounds apart, at least every 10 minutes; the first good probe ends the wait.
- Mooring evaluates at most 256 alerts across all apps, in app-name order; the `ops_interface` blocks beyond that are skipped and logged.
- An app whose stored definition can't be read (it fails its integrity check or no longer validates) is skipped and logged; the other apps' alerts keep running, and the skipped app's history is kept.
- A firing records a detection with rule ID `ops:<app>/<service>/<name>` (`-` in place of the service for the app-level `ops_interface`) and a one-line summary, for example `Limiter / Ratelimit drops rose by 1243 in 5m (now 98123)`, `queue dns qps 2140 for 2m, usual 180 (×11.9)` or `Upstream / Errors above 50 for 1m (now 75)`.
- While the condition keeps holding, Mooring records it again at most once per `window` or 15 minutes, whichever is longer. A record within an hour of the detection's last one adds 1 to that detection's count; a later one starts a new detection. When the detection engine's queue is full, a record is lost and the next one follows after the same interval.
- `severity: high` also sends a warning alert and `severity: critical` a critical alert to the alert channels; `low` and `medium` are shown on the Detections page only. See [Security detections](./security-detections.md).
- Alerts run only while detection is on.
