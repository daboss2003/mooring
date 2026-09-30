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
