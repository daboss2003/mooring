# Edge & TLS — the managed edge

Mooring is internet-facing by default. Every install owns the public ports `:80`/`:443`,
runs ACME/Let's Encrypt for you, terminates TLS, and reverse-proxies the admin UI and each of
your apps.

This document explains how that edge works, why it is built the way it is, and how to drive it
safely — including the trade-offs that were made deliberately and what backstops protect you
when a configuration mistake slips through.

> **One-line summary.** From a single required field per app — a hostname — Mooring derives a
> complete, hardened HTTPS vhost. The admin UI stays on loopback. A supervised, sandboxed child
> Caddy does the public-facing work as a separate process (co-resident in the control-plane unit
> today; a dedicated edge user/slice is planned). What Caddy
> actually runs is always Mooring's typed render of a protected base plus your routes — generated
> from `mooring.yaml`, never a config you author by hand.

**See also:** [README](../README.md) · [Security model](./security.md) ·
[App provisioning](./gitops.md) · [Configuration reference](./architecture.md) ·
[Alerting & self-healing](./alerting.md)

---

## Table of contents

- [Edge modes: `managed` vs `external`](#edge-modes-managed-vs-external)
- [How the edge is owned (process isolation)](#how-the-edge-is-owned-process-isolation)
- [Automatic HTTPS / ACME](#automatic-https--acme)
- [Per-app reverse proxy: routes & upstreams](#per-app-reverse-proxy-routes--upstreams)
- [How the edge config is rendered](#how-the-edge-config-is-rendered)
- [The secure-by-default baseline (SBD-1..8)](#the-secure-by-default-baseline-sbd-18)
- [Non-HTTP services: cert-only / shared-cert](#non-http-services-cert-only--shared-cert)
- [Recovery & escape hatches](#recovery--escape-hatches)
- [Configuration reference](#configuration-reference)

---

## Edge modes: `managed` vs `external`

There is exactly **one** config key that decides who owns the edge:

```yaml
edge:
  mode: managed   # "managed" (default) | "external" (advanced escape hatch)
```

There is **no auto-detection**. The choice is explicit and **fail-closed** — if the prerequisites
for the chosen mode are missing, Mooring refuses to come up rather than guess.

### `managed` (default — the product)

This is the path you get by doing nothing. Mooring **owns the edge**:

- It supervises a child Caddy that binds the public ports `:80`/`:443`.
- The child runs ACME/Let's Encrypt and terminates TLS.
- The child reverse-proxies the admin vhost to `127.0.0.1:9000` (behind an injected IP-allowlist
  matcher) and each app vhost to the discovered addresses of that app's running containers.
- The admin UI **still** binds loopback `127.0.0.1:9000`. Only the *child* binds public ports.

Required config:

| Key | Meaning | If missing |
|---|---|---|
| `edge.acme_email` | Contact for the ACME account | **Fail-closed.** Onboarding refuses to mark setup "complete" and prints the exact CLI line to set it. |
| `edge.acme_ca` | The single, pinned ACME issuer | No fallback issuer is ever used (see [ACME](#automatic-https--acme)). |
| `edge.apply_probe_window` | How long a deploy waits for the edge to serve its routes before failing the deploy | Defaults to `20s`. |

### `external` (narrow advanced escape hatch)

For an operator who insists on fronting Mooring with their **own** existing proxy. This is a
deliberate, narrow escape hatch — not an off-switch and not a casual setting.

- **Config-file-only, NOT UI-reachable.** You cannot click your way into `external`; you fall
  into `managed` by doing nothing. Setting `external` is always a deliberate operator act.
- In `external` mode Mooring **binds loopback only**, never opens `:80`/`:443`, and never constructs
  the edge subsystem (the unit's `CAP_NET_BIND_SERVICE` goes **unused** — drop it with a drop-in if
  you want zero caps in external mode).
- The per-app TLS controls are **hidden** — there is no managed edge to drive.
- Mooring emits paste-ready proxy snippets for your front proxy but **applies nothing**.

**Fail-closed boot is stronger here** (this is the most-abused trust seam — the XFF/trusted-proxy
boundary). Mooring refuses to start in `external` mode unless:

1. `trusted_proxies` is a **specific edge IP** — a prefix no wider than `/24`, and not a Docker
   bridge CIDR; **and**
2. a boot probe confirms `:9000` is **unreachable from a non-loopback interface**.

The emitted snippet bakes in **XFF overwrite** (not append) — an external proxy that *appends*
`X-Forwarded-For` silently breaks the IP allowlist, so Mooring forces an overwrite. "The operator
chose external" never absolves the allowlist / XFF safety checks.

### Resource behavior: a warning, not a silent mode-switch

On an undersized box the default **stays `managed`** — the edge runs inside the control plane's
memory-capped cgroup with a persistent banner: *"reduced MemoryMax — consider a larger host."* Only a box that
**genuinely cannot** host the child boots `external`, and then it shows a blocking banner:
*"edge not owned — resource gate."* Mooring never silently degrades you into `external`; choosing it
is always deliberate. (The heavier *write plane* — deploy/build — is separately gated at ≥ 1 GB RAM;
the edge itself is part of the baseline and always serves its minimum-safe config.)

---

## How the edge is owned (process isolation)

The single most load-bearing decision in the edge design: **the TLS terminator runs as a separate,
Mooring-supervised OS process — a stock Caddy binary — not embedded in-process.**

Mooring drives the child entirely through Caddy's **admin API on loopback** (preferably a unix
socket), pushing a **full-document JSON config** with a graceful, atomic `/load`. There is no
on-disk config file the proxy auto-loads — **the admin API is the single source of truth.**

### Why a separate process

| Property | What it buys you |
|---|---|
| **Blast radius** | The public-facing HTTP/TLS/ACME/x509 stack parses hostile SNI and traffic in a *separate child process* — not the address space that holds your session secrets and master key. |
| **"Single binary" survives** | Mooring stays ~12–18 MB. You patch the proxy by swapping one static file and doing a graceful reload — no rebuild of Mooring. |
| **Crash isolation** | Mooring supervises with backoff. If the child dies, the admin UI stays up to show you *why*. If Mooring dies, the child keeps serving. |

### Supervision & capabilities

> **Current isolation (be precise):** the edge is a separate **process**, but today it is **co-resident** in the control-plane systemd unit — it runs as the **same** low-privilege user and shares the unit's cgroup + `MemoryMax` (384 MB, sized to cover Mooring + Caddy + nginx + forked compose). A *dedicated edge user, slice, and per-edge `MemoryMax`* — so a public-plane traffic spike can't pressure the control plane, and the cap is held by the child alone — is a **planned hardening, not yet implemented**.

- The child runs as the **control plane's** low-privilege user (a dedicated edge user/slice is planned).
- **`CAP_NET_BIND_SERVICE` is granted by the base unit, by default** (it is the *only* allowed
  capability, and ambient so the Caddy/nginx children inherit it) — so the managed edge binds
  `:80`/`:443`/`:53` non-root out of the box, no drop-in or setup step. In `external` mode the edge
  isn't started and the cap is simply unused. Because the children are co-resident, the control-plane
  process also holds it today — granting it to the child **alone** is part of the planned per-process split.
- Mooring talks to the child over loopback `:2019` (or, preferably, a unix socket) **only**.
- A liveness poll plus crash-loop detection raises a `level=security` audit event.

### Supply-chain hardening of the child binary

The child proxy binary is **root-owned, mode `0755`, on a read-only mount, digest-pinned, and
verified before launch** (Mooring refuses to start it on a digest mismatch). Its path and data dir
are in the bind-mount **deny set**, so no deploy can overwrite them. The edge runs on **its own
Docker network** that the app network cannot reach — so an in-container ACME client cannot answer
challenges for edge hostnames or reach `:2019` — and `ProtectSystem=strict` keeps the cert/data dir
and Mooring's own config/key **out of the edge's mount namespace entirely**, so a stray
`file_server` cannot browse them.

---

## Automatic HTTPS / ACME

In `managed` mode every app vhost automatically gets: an ACME-issued certificate, an HTTP→HTTPS
redirect, a reverse-proxy with **`X-Forwarded-For` overwritten to the real TCP peer**, and an edge
header bundle (HSTS is added only *after* a certificate exists). You set a hostname; Mooring does
the rest.

The ACME behavior is deliberately conservative, because each loose default is a real outage or
abuse class:

- **A single pinned ACME CA, no silent fallback.** `edge.acme_ca` names one issuer and Mooring
  never falls back to another. A fallback would land certs at a *different* on-disk path and silently
  break shared-volume cert readers — a real outage class.
- **On-demand TLS is OFF by default.** Only hostnames present in your routes get certificates. A
  hostile SNI cannot make Mooring request arbitrary certs and burn through rate limits.
- **Resolves-to-this-box check at issuance.** Mooring validates that a hostname resolves to this
  box **at issuance time**, not merely when you added the route. A name that no longer points here
  will not silently keep trying.
- **Key custody.** Certificate private keys stay in the proxy's data dir, owned by the proxy user,
  mode `0600`. Mooring does **not** read HTTP-vhost private keys.
- **Wildcard certificates via DNS-01.** Point one wildcard DNS record (`*.example.com` → this box)
  and set `edge.dns01` with your provider and an API token, and Mooring issues a **single wildcard
  certificate** for the whole namespace — no per-hostname issuance or rate limits, and it works for
  names that aren't HTTP-reachable. Mooring **installs the matching Caddy DNS-provider module for
  you** (`caddy add-package`) — you never run `xcaddy` or build a binary. This is what gives every
  app subdomain and every [preview environment](./gitops.md#preview-environments-a-deploy-per-pull-request)
  instant HTTPS. Without `dns01`, each hostname gets its own certificate over HTTP validation.

### Subdomain namespaces (colocating apps under one apex)

Set `edge.base_domain` and a route or cert binding can use the **subdomain shorthand** — `subdomain: mqtt`
expands to `mqtt.example.com` — so you point one wildcard DNS record at the box and every declared
subdomain just resolves. To run more than one apex on the same server (say a **prod** and a **staging**
namespace side by side), add named `edge.base_domains`; each app opts into one by name and keeps the
shorthand under its own apex without route collisions. Both namespaces and the private CAs list
(`edge.cas`, for issuing off an internal CA instead of the public one) are declared **only** in the
root-of-trust `config.yaml` — an app references a name and can never introduce a new apex or issuer.

---

## Per-app reverse proxy: routes & upstreams

**Routes are declared in the app's `mooring.yaml`** — under `spec.edge.routes` — which is the single
source of truth. To add, change, or remove a public route you edit that file and deploy; there is no
"add a route" form. On deploy, Mooring reconciles the declared set onto the edge (replace-by-app, so
the file's set is exactly what's live) and renders the proxy document. The dashboard's **Edge routes**
page is **read-only**: it shows the deployed routes, not an editor.

Internally, the reconciled set is held in Mooring's database and applied idempotently. The schema is
additive:

```text
app_routes(
  id, app_id, hostname, upstream, upstream_scheme,
  path_prefix, redirect_http, hsts, security_headers, enabled, …,
  UNIQUE(hostname, path_prefix)
)
```

### Path routes on one hostname

Several routes can share a hostname with different `path_prefix` values. A request goes to the route
with the longest matching prefix, whatever order the routes are declared in:

```yaml
spec:
  edge:
    routes:
      - hostname: api.example.com
        path_prefix: /
        service: api
        port: 3000
      - hostname: api.example.com
        path_prefix: /socket.io/
        service: realtime
        port: 3001
```

`/socket.io/?EIO=4` goes to `realtime`; every other path goes to `api`. A prefix matches the path
itself and everything below it: `/v1` matches `/v1` and `/v1/users`, not `/v1beta`. `/` (or an empty
prefix) matches every path.

**Reconciliation is declarative and whole-document.** Mooring holds the desired set in SQLite,
renders the **entire** proxy JSON, and POSTs the whole document to the admin API. It never sends
incremental patches — a full re-render is far easier to keep bug-free.

### The structural backstops that keep the edge out of the control plane

- **Container addresses only.** The edge dials only IP addresses discovered from the read-only
  container list — never a hostname or a compose service name — so nothing is resolved at dial time.
  Every address is validated when the config is rendered: loopback, link-local and unspecified
  addresses and the ports `9000`/`2019`/`2375` are refused. A route whose stored upstream is unsafe
  fails the render, and the running config is kept.
- **The admin route is the only loopback target** — the admin vhost → `127.0.0.1:9000`, identity-pinned
  and **never operator- or app-editable**.
- **Caddy admin on a unix socket** (preferred) so there is no TCP `:2019` to proxy to at all, with
  `enforce_origin:true` and origins pinned to loopback.
- **Config is marshalled from typed structs.** Hostname/path/upstream are charset-validated first.
- **Optional egress filter.** A systemd cgroup egress filter (`IPAddressDeny`) ships in the unit
  **commented out** (a strict deny breaks ACME — Let's Encrypt has no fixed CIDR — and proxying to app
  containers); enable and tune it per the unit's egress block when you can pin your CA/app egress.

### Upstream addresses and unavailable routes

A route names a service and a port (`web:3000`). The Caddy that serves the edge runs on the host,
where compose service names don't resolve, so Mooring resolves each route to addresses itself, on
every reconcile (after deploys, scaling, restarts, and every 15 seconds):

- **Discovery.** Mooring lists the running containers of the route's app and service over the read
  plane and dials each one's address on the app's `<app>_default` network. One-off `compose run`
  containers are never dialed. A service with several copies gets a pool (least connections, passive
  health checks).
- **New copies take traffic once ready.** When at least one copy is ready — healthy, or running
  without a healthcheck — copies still `starting`, `unhealthy`, or not yet observed are left out of
  the pool. If no copy is ready yet, every running copy is dialed.
- **No running container → 503.** The route keeps its hostname and certificate but answers
  `503 Service Unavailable` with `Retry-After: 5`. The body is fixed and names nothing internal.
- **Discovery unavailable → last-known addresses for up to 5 minutes.** If the container list can't be
  read (the socket-proxy is down), each route keeps dialing the addresses last confirmed; after 5
  minutes it answers 503 instead, since a recreated container gets a new address.
- **https upstreams** are dialed by address too, with the certificate verified against the service
  name (TLS `server_name`), exactly as a name dial would.
- **Removing a copy** (per-copy stop) takes it out of the pool before it is removed. A scale-down, a
  self-heal restart, a lifecycle action or a certificate renewal re-points the edge right after it acts.
- **Caddy restarts.** If the Caddy child restarts, Mooring re-applies the full config as soon as its
  admin API answers.
- **Visibility.** When a route stops being served normally (last-known addresses, or 503), the change
  is logged to the Activity tab with the reason and the addresses dialed. A route that answers 503 for
  more than 60 seconds raises a warning alert (not while its app is deploying); it resolves when the
  route is served again.

### Example managed route

A typed route for an HTTP app. You never write this by hand — Mooring builds it from the
`hostname`/`service`/`port` you declare in `mooring.yaml` and a discovered upstream — but here is
what Mooring renders on your behalf:

```jsonc
// One route per app vhost, rendered from the typed route set
{
  "match": [{ "host": ["dashboard.example.com"] }],
  "handle": [{
    "handler": "reverse_proxy",
    "upstreams": [{ "dial": "10.89.0.7:8080" }],   // a discovered container address, validated at render
    "headers": {
      "request": {
        "set": { "X-Forwarded-For": ["{http.request.remote.host}"] }  // OVERWRITE, never append
      }
    }
  }]
}
// Automatic HTTPS (ACME), HTTP→HTTPS redirect, HSTS-after-cert,
// and the edge header bundle are all derived for you — not shown here.
```

---

## How the edge config is rendered

You never author Caddy config — file or portal. The edge config is **typed and generated from
`mooring.yaml` only**: you declare routes (and cert bindings) per app, and Mooring renders the
whole proxy document. What Caddy runs is always Mooring's typed render of two parts:

| Part | Source | What it contains |
|---|---|---|
| **Protected base** | Mooring code (typed structs) | The admin block (unix socket, `enforce_origin:true`); the identity-pinned admin→`:9000` route *with* its allowlist matcher; global TLS (pinned ACME CA + email, on-demand off); XFF-overwrite + header bundle; default unmatched-Host = 404/close. |
| **Routes** | `spec.edge.routes` (typed structs) | One route per app vhost. |

The config is **marshalled from typed structs**, never string-concatenated — this is the operational
meaning of SBD-7 and the SBD-8 recovery guarantee below.

**Minimum-safe protected base** (ships with every install, safe before any route exists): admin on
the unix socket; on-demand off; ACME only for route hostnames; one server on `[:443, :80]` (`:80` =
ACME + redirect only) with `routes:[]` and unmatched-Host = close/404; **no admin vhost unless you
set `admin.hostname`.** A fresh install is a public IP with HTTPS-capable Caddy that *proxies to
nothing and exposes no admin surface* until you add your first route. This base is the recovery floor
for SBD-8.

> An app's managed config file (see [App provisioning](./gitops.md)) is a **completely different
> surface** and never mixes with the edge config.

### Apply pipeline (fail-closed)

Every change to the route set re-renders the whole document and applies it:

1. **Validate and render.** Every enabled route is validated (hostname, path, upstream selector, and
   every discovered address — see [the backstops](#the-structural-backstops-that-keep-the-edge-out-of-the-control-plane)).
   An invalid route fails the render and nothing is applied.
2. **Atomic load.** The document is POSTed to the admin API's `/load`. Caddy swaps it in atomically;
   a rejected document leaves the running config in place. A render identical to the last applied one
   is not re-sent.
3. **Deploy verification.** A deploy then checks, for up to `edge.apply_probe_window` (default
   `20s`), that every route of the app is served and dials only running containers of that app's
   route service that the `docker` CLI also lists. One line per route is written to the deploy log;
   any failure fails the deploy (the new containers stay up; the app is marked `update_blocked`).

> **Pool membership changes at deploy time.** Because an app's pool membership and hostname candidacy
> can change when you deploy, the **full conflict check (including wildcard overlap) is re-run on
> every route change** — a render that would overlap a newly-pooled hostname is rejected fail-closed.

---

## The secure-by-default baseline (SBD-1..8)

Because the edge is always-on, "safe" no longer means *the operator configured it safely* — it means
*the shipped default is provably safe with zero operator action.* Each item is a hard invariant
enforced **in code** (typed structs + render-time checks) and **proven by a per-invariant automated
test on a fresh install.** These are **release-blocking** on the first edge-owning release.

| ID | Invariant | What it guarantees |
|---|---|---|
| **SBD-1** | Admin UI never reachable through the public edge by accident | Admin UI binds `127.0.0.1:9000` only. The edge serves **no admin vhost at all** unless you explicitly set `admin.hostname` (default: reach the UI via SSH tunnel / port-forward). If set, the admin vhost renders with the **IP allowlist as the first matcher, injected from typed config** (not operator text) → upstream `127.0.0.1:9000`. The allowlist cannot be omitted. |
| **SBD-2** | Caddy admin API never public | `admin.listen = unix//run/mooring/caddy-admin.sock` (preferred) or `127.0.0.1:2019`, never routable; `enforce_origin:true`, origins loopback-only. No public vhost may proxy to `:2019`. |
| **SBD-3** | On-demand TLS off; ACME bounded | Absent from the base; the renderer **force-rewrites any `ask` endpoint** to a fixed loopback validator that answers "yes" only for known route/allowlist hostnames, plus a rate limit. ACME issues only for configured app vhosts. |
| **SBD-4** | Only configured app vhosts served; control-plane ports unreachable as upstreams | Exactly the route-derived vhost set (+ optional admin vhost); **no catch-all/wildcard proxy**; no upstream targets `9000`/`2019`/`2375` or a loopback/link-local address (validated when stored **and** re-checked at render; only discovered container addresses are dialed, never names); default unmatched-Host = `404`/close, never proxy. |
| **SBD-5** | Network isolation of edge from control plane | The structural backstop — container-address-only dials validated at render + unix-socket admin + the optional egress filter (see [the backstops](#the-structural-backstops-that-keep-the-edge-out-of-the-control-plane)). |
| **SBD-6** | Egress stays controlled by always-on | Outbound calls are **host-pinned in-process** (ops prober, edge upstreams, alert notifiers reject loopback/link-local/metadata). The systemd cgroup egress filter is an **opt-in** deeper backstop (off by default — a strict deny blocks ACME). |
| **SBD-7** | Config rendering safety | Proxy config is marshalled from typed structs (never string concat), generated from the typed routes in `mooring.yaml` — there is no path by which an operator authors Caddy config. |
| **SBD-8** | The edge can never go down irrecoverably | Every apply is validate → stage → load with a retained last-known-good and an armed health-probe watchdog; on failure, **auto-revert**. The typed base config is always loadable as the recovery floor; **SSH is the ultimate recovery floor.** |

---

## Non-HTTP services: cert-only / shared-cert

The edge can be the **ACME agent for a hostname it does not serve traffic for** — for example, an
MQTT-over-TLS broker, where a separate service must terminate TLS itself on its own port. This is a
**per-route choice:**

### `cert-only` / shared-cert (recommended default)

The proxy obtains and renews the certificate for the hostname but serves **no traffic** on that
port. A separate service reads the same cert files and terminates TLS itself.

The hard rule: **never `chmod` the cert dir or keys to broaden access.** A different-uid reader, or a
container that mounts that path, could then read live TLS keys. Instead, Mooring's deploy:

- **Copies the leaf cert + key** into the service's `mount` (`tls.crt` 0644, `tls.key` 0600), under
  the consumer's `run_dir`, and **recreates the service** so it loads them (the managed-file digest
  diff force-recreates a service whose mounted cert changed);
- **Does not** rely on the stock proxy's cert-obtained event hook. That hook needs an unbundled
  plugin; assuming it exists caused a prior outage. Do **not** mount the proxy data dir into any
  monitored app container.

> **Renewal is autonomous.** A background watcher (hourly) re-syncs each app's
> `cert_bindings` from the edge and, when a leaf has actually changed, recreates the affected
> service so it loads the new cert — no manual redeploy. The recreate briefly bounces only that
> service and is suppressed from self-healing. When several services changed, they are recreated
> one at a time, each waited for like a deploy's [paced starts](./gitops.md#paced-starts); a
> deploy that starts meanwhile goes first, and the renewal is retried at the next hourly check. (The richer `cert_*` inventory/alerts described under
> *Cert lifecycle visibility* below are still planned, not yet built.)

#### `cert_bindings` — wiring a cert to a service declaratively

A `cert_bindings` entry on a service connects the cert-only pattern to an app: the edge is the ACME
agent for a `hostname`, and the cert-sync helper writes the leaf cert + key into the service's
`mount` dir as `tls.crt` (0644) and `tls.key` (0600). The app reads them straight from that path —
there are no template tokens for certs. A `cert_bindings` entry has exactly two fields:

```yaml
cert_bindings:
  - hostname: mqtt.example.com   # the FQDN the edge issues a cert for
    mount: /etc/mosquitto/certs  # the in-container dir Mooring syncs tls.crt + tls.key into
```

The deploy **waits automatically** until the cert is synced — the container never polls or waits; if
the cert can't issue, the deploy fails fast with a reason rather than spin-looping. **Renewal is
autonomous** — a background watcher re-syncs + recreates the affected service when the edge renews
the leaf (see the note above).

#### Example: cert-only binding for an MQTT-over-TLS broker

```yaml
# In the app's mooring.yaml — the edge issues the cert; the broker serves TLS itself.
spec:
  edge:
    routes:
      - hostname: mqtt.example.com   # edge issues the cert; the broker terminates TLS on its own port
        service: broker
        port: 8883
  compose:
    source: generated
    services:
      broker:
        image: eclipse-mosquitto:2
        cert_bindings:
          - hostname: mqtt.example.com
            mount: /etc/mosquitto/certs   # tls.crt + tls.key land here, synced + renewed by Mooring

# The broker's managed config file points at the synced paths:
#   listener 8883
#   certfile /etc/mosquitto/certs/tls.crt
#   keyfile  /etc/mosquitto/certs/tls.key
```

### Layer-4 (TCP/UDP) load balancing (opt-in, default off)

For a **non-HTTP** service — a database port, a game server, DNS, MQTT — Mooring can put a public
TCP or UDP port in front of it with its own managed **Layer-4 load balancer**: a supervised child
**nginx** `stream` proxy. There's no custom Mooring build — the stock binary drives it; you just
turn it on with `edge.l4_enabled: true` and have an `nginx` binary on the host (optionally pinned
with `edge.l4_nginx_digest`).

Apps declare listeners under [`spec.edge.l4_routes`](./definition-file.md#specedgel4_routes-tcpudp-load-balancing):
each route sets a public `listen` port, a `protocol` (`tcp`/`udp`), the internal `service` + `port`
to reach, and an optional method (`round_robin` default, `least_conn`, or `hash_client_ip`). The LB
owns the public port and fans traffic across the service's **live internal replicas** — discovered
from the running containers, so a scaled or self-healed service's pool stays current, and a route
with no live replica is skipped rather than blackholed. You point at a **service and port**, never a
literal address, and control-plane ports (80/443, 9000/2019/2375) are refused as listeners. For TLS
you usually keep the certificate at the app and use `cert-only` sync; L4 just moves the raw stream.

---

## Recovery & escape hatches

The edge is designed so it can **never become irrecoverable**:

- **Atomic load.** A bad `/load` leaves the previous config running — Caddy never serves a partial
  config.
- **Re-derived config.** The edge config is never stored as a document: every apply re-derives the
  protected base from code and the routes from the stored route set.
- **The protected base is always loadable.** Because it is rendered from typed structs, the
  minimum-safe base (admin allowlist + ACME, proxying nothing) is always available as the recovery
  floor — and **SSH is the ultimate recovery floor**, even if the UI itself is unreachable.

---

## Cert lifecycle visibility & ACME rate-limits

> **Status: planned, not yet implemented.** This section describes the intended cert-lifecycle
> design. The `cert_inventory` table, the `cert_*` alerts (`cert_expiring`, `cert_renew_stalled`,
> `cert_sync_stale`, `cert_anomaly`), and the local ACME-rate-limit modeling are **not built yet** —
> today the edge (Caddy) issues + renews certs, and `cert_bindings` are synced at deploy. Treat the
> below as the roadmap, not current behavior.

A single pinned CA with no fallback means anything that silently stops issuance — expiry, a stalled
renewal, a rate-limit — leaves the edge **serving but degrading invisibly**. So Mooring makes it
**loud**, reading **leaf x509 metadata only, never a private key** (a lint bans opening any `.key` in
the cert subsystem).

- **Cert inventory** (`cert_inventory` table; read-only `GET /edge/certs`): hostname, issuer,
  `NotAfter`, derived last-renew, SANs, source. Edge-HTTPS leaves are read from the Caddy admin API on
  loopback; cert-only/shared-cert leaves by parsing the synced `.crt` the cert-sync helper placed. A
  cert-scan rides the poll tick — no per-cert goroutine, no reliance on a stock-proxy event hook.
- **Proactive alerts** (never deferred — see [alerting.md](./alerting.md)): `cert_expiring`
  (WARNING ~21 d → CRITICAL ~7 d, *regardless* of whether renewal looks healthy);
  `cert_renew_stalled` (in the renewal window, serial not advancing); **`cert_sync_stale`** — the
  silent MQTT-TLS killer: the edge leaf is fresher than the consumer's synced leaf, so it re-nudges the
  cert-sync helper (the self-healing recreate path) then pages; `cert_anomaly` (issuer ≠ the pinned CA).
- **ACME rate-limit handling.** Mooring models the CA's weekly per-registered-domain and
  duplicate-cert limits **locally** from its own issuance ledger (`acme_ledger`, bucketed by eTLD+1 via
  an embedded public-suffix list — it never asks the CA). On a 429 / `rateLimited` *or* a local-window
  estimate exceeding the limit → **`cert_rate_limited`** (CRITICAL; the UI shows "retry after …", not a
  silent "still trying") with **capped, jittered, Retry-After-honoring back-off on a *monotonic*
  clock** (so a forward clock-step can't collapse the back-off and hammer the CA — see the clock-skew
  coupling in [security.md](./security.md)) plus a hard floor of one attempt per hostname per
  failed-validation window.
- **Pre-issuance batching.** Bulk-adding vhosts can trip the weekly per-domain limit and brick
  issuance for *every* hostname in that domain. The route-add path groups by registered domain, issues
  up to the safe remaining count now, and **defers the rest as `cert_pending_batch`** — the route is
  still rendered (HTTP→HTTPS works), just cert-pending, so the edge degrades **visibly and partially,
  never silently and totally**. The dry-run surfaces warn before commit, and staging rehearsals are
  ledgered under a separate bucket so they never consume the prod weekly budget.

## Configuration reference

```yaml
edge:
  mode: managed                 # "managed" (default) | "external" (config-file-only escape hatch)
  acme_email: ops@example.com   # REQUIRED in managed mode — fail-closed if empty
  acme_ca: https://acme-v02.api.letsencrypt.org/directory   # single pinned issuer, no fallback
  base_domain: example.com      # optional: enables the `subdomain:` shorthand; point *.example.com here
  dns01:                        # optional: one wildcard cert for the namespace (module auto-installed)
    provider: cloudflare
    api_token: "<dns-provider-token>"
  # base_domains: [...]         # optional: additional NAMED namespaces (prod + staging on one box)
  # cas: [...]                  # optional: extra named issuers (private/internal CAs) to opt into
  apply_probe_window: 20s       # how long a deploy waits for the edge to serve its routes (default 20s)
  l4_enabled: false             # managed L4 (TCP/UDP) load balancer via child nginx; needs nginx on host; default off

admin:
  # Optional. If unset, the admin UI is reachable only via SSH tunnel / port-forward to 127.0.0.1:9000
  # (the edge serves NO admin vhost — SBD-1). If set, the admin vhost is rendered with the IP
  # allowlist injected as the first matcher.
  hostname: ""

# In external mode ONLY — fail-closed boot requirements:
trusted_proxies:
  - 203.0.113.10/32             # MUST be a specific edge IP, prefix <= /24, not a Docker bridge CIDR
```

| Key | Default | Notes |
|---|---|---|
| `edge.mode` | `managed` | Explicit; no auto-detect. `external` is config-file-only and not UI-reachable. |
| `edge.acme_email` | *(empty)* | **Required** in `managed` mode; onboarding refuses to complete without it. |
| `edge.acme_ca` | *(your CA)* | Single pinned issuer. **No fallback** — a fallback would diverge cert paths and break shared-cert readers. |
| `edge.apply_probe_window` | `20s` | How long a deploy waits for the edge to serve every route of the app (dialing only that app's containers) before it fails the deploy. |
| `edge.base_domain` | *(unset)* | Namespace apex for the `subdomain:` shorthand; point `*.<base_domain>` DNS at the box. |
| `edge.dns01` | *(unset)* | `{provider, api_token}` → one **wildcard** cert for the namespace via DNS-01; the Caddy provider module is auto-installed. |
| `edge.base_domains` | *(none)* | Additional **named** namespaces (e.g. prod + staging on one box); an app opts into one by name. |
| `edge.cas` | *(none)* | Extra named issuers (private/internal CAs) a route or cert binding can select by name. |
| `edge.l4_enabled` | `false` | Turns on the managed Layer-4 (TCP/UDP) load balancer — a supervised child **nginx** `stream` proxy. Needs `nginx` on the host; optionally pin it with `edge.l4_nginx_digest`. |
| `admin.hostname` | *(unset)* | When unset, no admin vhost is served at all (SBD-1). |
| `trusted_proxies` | *(none)* | **Required for `external` boot:** a specific edge IP, `≤ /24`, not a bridge CIDR; boot also probes that `:9000` is unreachable from non-loopback. |