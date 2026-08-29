# Architecture

> **You don't need this page to use Mooring** — [Install it](./installation.md) and [Deploy your first app](./first-steps.md) cover everything for day-to-day use. This is an optional deep-dive for people who want to understand how it works under the hood, or who are evaluating it for security.

How Mooring is put together: the processes that make up a running install, where each one sits on the host, how data is split between them, and the small number of choke points every privileged action is forced through.

Mooring is a **single static Go binary** plus a small supporting cast of OS processes it supervises. It is a generic tool an operator points at a Docker host — not tied to any project. The overriding design constraint is stated plainly in the build plan: hosting Mooring *must never become the thing that gets the server hacked*. Almost every structural decision below is subordinate to that requirement.

---

## 1. The components

A running install is not one process — it is a small set of cooperating processes, each with a deliberately narrow job and a deliberately narrow blast radius.

| Component | What it is | Runs as | Why it is separate |
|---|---|---|---|
| **Mooring core** | The `html/template` + htmx admin UI, the poller, the reconciler, the API. One static Go binary (~12–18 MB, ~10–15 MB idle RSS). | Dedicated low-priv user, member of the `docker` group, its own `systemd` unit. | It is the control plane. It holds the operator session and (in memory) the master key. Everything else is kept *out* of this address space. |
| **Caddy edge** (child) | A stock, unmodified Caddy binary that owns `:80`/`:443`, runs ACME/Let's Encrypt, terminates TLS, and reverse-proxies each vhost. | A **separate child process** supervised by the core. **Today co-resident** in the core's unit (same low-priv user + cgroup + `MemoryMax`); `CAP_NET_BIND_SERVICE` is granted to the **unit** (so the core holds it too). A dedicated edge user/slice + child-only cap is **planned, not yet implemented**. | The public-facing HTTP/TLS/ACME/x509 stack parses hostile traffic, so it runs as a separate process from the request handlers; full user/cgroup isolation is the next hardening step. |
| **docker-socket-proxy** | A read-only proxy in front of the real Docker socket, with a deny-by-default verb allowlist (`CONTAINERS`/`INFO`/`VERSION` only). | Loopback-only, internal-only network, `read_only`, `cap_drop: ALL`. | The raw `docker.sock` is root-equivalent. It is mounted **only** into this proxy — **never** into Mooring. The core reads container state *through* this proxy. |
| **SQLite** | The embedded application database (`modernc.org/sqlite`, pure-Go, CGO-free). | A file owned by the Mooring user, opened with `umask 0077`. | Holds app state and **ciphertext only** — never the key that decrypts it (see §3). |
| **cert-sync helper** | A small helper that copies the edge's leaf cert + key to a per-consumer `0600` path, watches mtime, and signals the consumer. | Invoked by the core with **static argv only**. | Lets a non-HTTP service (e.g. an MQTT-over-TLS broker) reuse an ACME cert **without** broadening permissions on the proxy's key directory. |
| **The CLI** (`mooring`) | The same binary, invoked over SSH for key management, config validation (`validate`), `secret import`, and DB `restore`. | The operator's SSH session. | SSH is the highest trust tier. `validate` runs the *same* reconciler the dashboard does, read-only — never a bypass (see §7). Deploys themselves happen in the dashboard. |

The build plan's stack decisions behind this:

- **Go**, `CGO_ENABLED=0 -trimpath -ldflags="-s -w"` → one static binary. Node was a non-starter (~80–150 MB RSS); Rust's win is irrelevant next to the monitored workloads.
- **`go:embed`** ships templates, CSS, JS, and SQL migrations *inside* the binary. No `node_modules`, no asset pipeline, no build step at deploy time.
- **Server-rendered `html/template` + htmx + Alpine** (~30 KB JS, embedded). No SPA. The strict CSP needs no `unsafe-inline`. All operator-facing rendering uses `html/template`; `text/template` and `template.HTML` on externally-influenced content are *banned* and enforced by a custom lint rule.
- **Docker access is hybrid:** **reads** go through the read-only socket-proxy via the Docker Go SDK; **writes** shell out to `docker compose` with **static argv only** — never a shell, never string interpolation, always `--` terminators. Mooring **brings the read-only proxy up itself at boot** (from an embedded, locked-down compose) so the operator never runs a Docker command; set `docker.external_proxy: true` to run your own instead.

> **Why split the binary at all?** The "single binary" promise survives because the edge is a *swappable* stock file, not embedded code. Patch Caddy by replacing one static file and doing a graceful reload — no Mooring rebuild. Mooring stays ~12–18 MB. This is the rare case where adding a process *reduces* total risk: the blast radius of the most-attacked code (TLS termination) is moved out of the address space that holds the crown jewels.

---

## 2. Runtime placement

The placement of these processes on the host *is* a security control. Two rules dominate.

### Mooring is its own systemd unit — never a container in a managed project

Mooring does **not** run as a Compose container. It runs as its own `systemd` unit. The consequence is structural and load-bearing:

- It can never appear in a managed project's container list, so its own controls can **never target itself**.
- A stack `down` can **never** take Mooring down — because Mooring isn't in any stack.

It runs **non-root** under a dedicated low-privilege user that is a member of the `docker` group. The unit is hardened: `MemoryMax`, `OOMScoreAdjust=-100`, `ProtectSystem=strict`, `NoNewPrivileges`, `PrivateTmp`, and the full sandbox set (`RestrictAddressFamilies`, `RestrictNamespaces`, `MemoryDenyWriteExecute`, `SystemCallFilter=@system-service`, empty `CapabilityBoundingSet`, tight `ReadWritePaths`, and — critically — **network egress allow-listing** via `IPAddressDeny=any` + a narrow `IPAddressAllow`). The egress allowlist is the single highest-leverage control against unknown attacks: even a perfect SSRF or RCE in the core cannot reach cloud metadata or call home, because those destinations are physically unreachable from the cgroup.

### The admin UI binds loopback only

Mooring's admin UI binds `127.0.0.1:9000` and **never** binds a public port itself. In the default (`managed`) mode, it is the *child edge* that owns `:80`/`:443` and reverse-proxies the admin vhost back to `127.0.0.1:9000` (behind an injected IP-allowlist matcher).

### The edge is a supervised child process

The child Caddy is a separate process supervised by the core. **Today it is co-resident** in the core's systemd unit — same low-priv user, same cgroup, sharing the unit's `MemoryMax` (384 MB, sized to cover Mooring + Caddy + nginx + forked compose). One consequence holds now, one is planned:

1. **Crash isolation (now)** — Mooring supervises the child with backoff. If the child dies, the admin UI stays up to show *why*. If Mooring dies, the child keeps serving.
2. **OOM isolation (planned)** — a dedicated edge slice with its own `MemoryMax`, so a public-plane traffic spike can't pressure the control-plane cgroup, is a planned hardening; today they share one cap.

`CAP_NET_BIND_SERVICE` is granted by the **base unit, by default** (the only allowed capability, ambient so the co-resident Caddy/nginx children inherit it) — so a managed edge binds privileged ports non-root out of the box. It is unused in `external` mode. Granting it to the child **alone** — not the core — is the planned per-process split; today it is on the unit.

### Two OOM mechanisms (do not conflate them)

This trips people up, so the plan calls it out explicitly:

- **`MemoryMax`** kills *inside* the cgroup — including any forked `docker` / `docker compose` children. This is the real enforcement.
- **`OOMScoreAdjust`** only biases the *global* OOM killer. It is a hint, not a guarantee.

A **global semaphore caps concurrent `docker` children at 1** across the poller, the stats sampler, deploys, log streams, and the setup sandbox. See §4.

---

## 3. Data residency: what lives where

Mooring deliberately splits its state across three locations with three different owners and three different threat profiles. The split *is* the "two independent secret stores" property of the security model.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  /etc/mooring/config.yaml          0600 root:root   — SSH-edited ONLY         │
│  ───────────────────────────────────────────────────────────────────────────  │
│    encryption_key (master key)   ip_allowlist   bind address                   │
│    edge.mode / edge.acme_email / edge.acme_ca   argon2id admin hash            │
│    scaling.* / selfheal.* / supervisor.* tuning (caps, gates, reservations)    │
│                                                                                 │
│    No web route reads or writes ANY of this. SIGHUP hot-reloads allowlist+auth.│
└──────────────────────────────────────────────────────────────────────────────┘
        │  master key held in-memory by the core; never written back, never logged
        ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│  SQLite (umask 0077)                — app state + CIPHERTEXT only               │
│  ───────────────────────────────────────────────────────────────────────────  │
│    apps  app_routes  edge_config_versions  definition_versions  deploys        │
│    env_blobs(*_enc)  captured_secrets(*_enc)  alert_channels(*_enc)            │
│    ops_snapshot  host_metrics  container_metrics  sessions  events (audit)      │
│    (definition_versions = the history of the deployed mooring.yaml — a read    │
│     record of what was last applied, NOT an editable copy)                      │
│                                                                                 │
│    *_enc columns are AES-256-GCM under the master key. Losing the key bricks    │
│    all ciphertext — back up config and DB SEPARATELY, offsite. Logs are file    │
│    pointers, never stored in SQLite.                                            │
└──────────────────────────────────────────────────────────────────────────────┘
        │
        ▼
┌──────────────────────────────────────────────────────────────────────────────┐
│  /var/lib/mooring/apps/<slug>/     — per-app working tree (Mooring-owned)     │
│  ───────────────────────────────────────────────────────────────────────────  │
│    run_dir/        the GENERATED compose + Dockerfile(s), the 0600 --env-file,  │
│                    rendered config/secret files, synced certs, bind mounts —    │
│                    all confined HERE (canonicalize-then-Rel). Regenerated from  │
│                    the repo's mooring.yaml on every deploy.                     │
│                                                                                 │
│  The mooring.yaml ITSELF lives in your Git repo (the source of truth), never   │
│  here. /var/lib/mooring/git/<slug>.git is the bare object store of fetched     │
│  commits; the last-deployed YAML is recorded for history/rollback in the SQLite │
│  definition_versions table — a read record, not an editable file.               │
└──────────────────────────────────────────────────────────────────────────────┘
```

The split matters because of the **crown-jewels ranking** in the threat model. The master key (A1) is total compromise; it lives *only* in the root-owned config file that the web plane cannot touch. SQLite holds A4 — the encrypted store — but only as ciphertext. An attacker who exfiltrates the database without the key gets nothing usable. Edge/ACME private keys (A5) live in a *fourth* place entirely: the proxy's own data dir, owned by the proxy user, `0600`, kept out of the core's mount namespace by `ProtectSystem=strict` so a `file_server` directive can never browse them.

The `config.yaml` also holds all the **safety tuning** — the scaling caps, self-healing gates, and host-capacity reservations. This is intentional: those knobs decide whether the box can OOM itself, so they belong in the SSH-only file, never behind a web form.

### The 3-tier config split

Configuration is split across **three tiers** by *security boundary*, not by tidiness:

| Tier | Where | Holds | Source |
|---|---|---|---|
| **1 — security / identity** | `/etc/mooring/config.yaml` (`0600 root`) | master key, IP allowlist, bind, `edge.mode`, `acme_email`, the safety tuning | **SSH / root only** |
| **2 — server-wide ops** | the `kind: Host` `mooring.yaml` (the host definition) | the app registry, global defaults, server-wide alerting, cross-app ordering | the host definition file |
| **3 — one app** | the app's `mooring.yaml`, in its Git repo | that app's managed surface (services, edge routes, config files, ops) | the repo file |

Tiers 2 and 3 are *structurally incapable of expressing a Tier-1 field* — a
`master key`/`allowlist`/`bind`/`edge.mode` key anywhere in a host or app spec is an
`additionalProperties:false` hard reject. So even though they describe what gets deployed, they can
never reach the root of trust. See [host-file.md](./host-file.md) for the full host definition.

> **The honest trade-off.** This split means there is no web password reset and no web key rotation. If you lose `config.yaml`, every ciphertext column is permanently unreadable — there is no recovery path by design, because a recovery path would be an attack path. Back up the config (the key) and the database **separately and offsite**, and use `mooring verify-key` to catch a key/DB mismatch *before* the next write corrupts data.

---

## 4. The read plane and the write plane

Every Mooring capability falls into one of two planes, and the boundary between them is a **safety gate, not a performance one**.

### Read plane (always on, safe on a small VPS)

The read plane is everything that *observes*: container status via the socket-proxy, one-shot CPU/mem stats, host RAM/disk/CPU sampling, log streaming, App Ops Interface polling, git **fetch**, the alert evaluator, the self-healing *watcher* (detection only), and the scaling *controller* (decision only). None of it can write to Docker. All of it runs comfortably below 1 GB of RAM.

### Write plane (gated on ~1 GB of RAM + swap)

The write plane is everything that *changes the host*: `docker compose up/pull/build`, redeploy, on-box image builds, managed config-file materialization, and the setup-script sandbox. **These are gated on a host with roughly 1 GB of addressable memory — RAM plus swap.**

This is a safety gate because of how a small box fails. A `docker compose pull` or a sandbox run that OOMs a tiny host can cascade the *whole* host into a crash-loop — and the proxy/edge dies first, taking the dashboard offline exactly when you need it. On a box below the floor, write-plane operations are disabled **but the edge still serves** its minimum-safe base.

**Swap counts, and the floor is decimal-GB.** The floor is ~900 MiB checked against **RAM + swap**, not a strict 1 GiB against RAM alone — because a VPS sold as "1 GB" reports a little under 1 GiB and would otherwise be locked out. So a 1 GB VPS (with or without swap) can deploy; a 1 GB **+ swap** box has comfortable headroom even for on-box builds (which lean on swap). A genuinely tiny box (≤ 512 MB, no swap) stays gated — but an operator who accepts the risk can lower the floor with `docker.write_plane_min_mb`. Note that on-box image builds still want real headroom regardless; pull-image deploys and lifecycle actions are cheap.

### Three controls keep any plane from OOM-killing the control plane

1. **The §0 resource gate** — the write plane only arms on ≥ 1 GB. Builds default off even then.
2. **The global one-docker-child semaphore** — at most **one** `docker` child runs at a time, across the poller, stats, deploys, log streams, *and* the sandbox. Remediation and scale-up use a **non-blocking** `TryAcquire`: if the semaphore is held, the action **defers and re-checks next tick** — it is never queued, because queuing docker children *is* the OOM vector.
3. **Per-process memory caps in distinct cgroups/slices**, plus `GOMEMLIMIT` set under the systemd cap, swap-disabled sandboxes, and one-service-at-a-time deploys.

The self-healing supervisor and the auto-scaler **both** pass the §0 gate, the semaphore, *and* a memory-headroom floor before acting — and the host-capacity guard collapses to a single replica on a near-OOM box. Neither can manufacture an OOM. Worst case, they decline to act and page you.

### The resource gate at a glance

| Capability | Min host | Default |
|---|---|---|
| Security spine + read-only health/monitoring | small VPS ok | **on** |
| Managed edge (owns `:80`/`:443` + ACME) — **core** | any (child of the core unit) | **on** |
| Write plane (deploy/redeploy), on-box build | ≥ 1 GB | build **off** |
| Git auto-fetch (pull new commits) | small VPS ok (read plane) | **on** for repo apps |
| Git deploy/build (manual promote) | ≥ 1 GB (write plane) | **manual** |
| Self-healing supervisor (restart/recreate) | small VPS ok (watcher) | **on** (redeploy rung ≥ 1 GB) |
| Auto-scaling (replica count) | guard funds ≥ 2 replicas | **off**, opt-in |
| Setup-script execution | ≥ 1 GB | **off** |

Note the asymmetry: the **edge is part of the baseline, not gated**. On an undersized box the default stays `managed` (the edge runs in a reduced `MemoryMax` slice with a persistent banner suggesting a larger host). Only a box that *genuinely cannot* host the child boots `external` mode, with a loud blocking banner. Choosing `external` is always a deliberate operator act — never a silent automatic degrade.

---

## 5. How a `docker compose` action flows through the §5.6 chokepoint

**Everything** that reaches `docker compose` — the compose Mooring *generates* from a `mooring.yaml` (read from your Git repo, or scaffolded for a first deploy), a materialized config file, or a replayed version on rollback — passes through **one** validator. This single chokepoint is the heart of the write-path safety story.

```
   mooring.yaml ──► GENERATED compose ─┐
   scaffolded default ──────────────────┤
   materialized config files ───────────┼──►  §5.6 ALLOWLIST VALIDATOR  ──►  docker compose
   rollback (replayed version) ─────────┘    (the ONE chokepoint)          (static argv,
                      1. resolve ${VAR} / .env / extends / x-anchors  FIRST          never a shell,
                      2. reject any UNKNOWN top-level/service key                      never interpolated,
                      3. reject the dangerous set (privileged, cap_add, host           always -- terminated)
                         binds of / /var/run/docker.sock /etc /proc, *:host
                         namespaces, security_opt unconfined, devices, sysctls …)
                      4. confine every bind mount UNDER the app's run_dir
                         (canonicalize-then-Rel; reject .. / absolute / symlink escape)
                      5. EDGE-COLLISION rejections (apps may never grab the edge):
                         (a) reject any publish of host :80/:443 — every publish form
                             canonicalized (short, long-form, ranges, 0.0.0.0/[::]/* …)
                         (b) reject a bundled proxy/TLS/ACME/cert-reload sidecar —
                             detected STRUCTURALLY (port, edge data-dir by named volume,
                             socket mount), not bypassable by renaming the image
                         (c) app_routes.upstream may never target a loopback control port
                         (d) materialized config files re-run through THIS SAME validator
```

A few principles make this load-bearing:

- **Allowlist, not denylist.** Unknown keys are rejected, not ignored. A new dangerous Compose feature is denied *by default* until Mooring is taught about it.
- **Resolve interpolation first.** Validating *before* `${VAR}`/`.env` expansion is a known bypass class, so resolution always happens first and validation runs on the *final* document.
- **Render by marshalling typed structs — never string concatenation.** What Mooring hands to `docker compose` is always the product of its own typed renderer.
- **The same validation runs on rollbacks and webhooks.** There is no second, weaker path.

After validation, the action is executed by shelling out to `docker compose` with **static argv** — no `sh -c`, no string interpolation, `--` terminators — and **one service at a time**, holding the one-docker-child semaphore. The app is brought up on its **internal port only**; then Mooring (never the app, never a script) wires the edge by adding the `app_routes` row, rendering the whole proxy document, and atomically `/load`ing the vhost + ACME HTTPS.

The rule is symmetric: **apps can't define the edge, and the edge can't be routed into the control plane.** See [the edge doc](./edge-and-tls.md) for the pinned dialer and egress firewall that back this at dial time.

---

## 6. One reconciler, one source

The source of an app's structure is its **`mooring.yaml`, in its Git repo** — the single source of truth. A deploy reads that file at a pinned commit, generates the compose + Dockerfile from it, and funnels through **exactly one reconciler.** A deploy is *triggered* from the dashboard (or by a Git push, via fetch→deploy), but the dashboard doesn't author the structure — it deploys the repo file. The `mooring validate` CLI runs that *same* validator read-only, so the chokepoint is identical whether you're deploying or just checking a file in CI. This is a core design principle, not an implementation detail.

```
   Deploy (reads the repo mooring.yaml)   mooring validate (SSH / CI, read-only)
        │                                   │
        │  typed reconcile request          │  same validator, no write
        └─────────────────┬─────────────────┘
                          ▼
        ┌────────────────────────────────────────────────────┐
        │   THE ONE RECONCILER                                │
        │   parse → typed DefinitionV1 → resolve ${VAR} first │
        │   → §5.6 allowlist validator                        │
        │   → §6.2 edge conflict gate (read-and-render)       │
        │   → secret-literal lint → required-secret check     │
        │   → §0 resource gate + host-capacity guard          │
        │   → diff vs SQLite                                  │
        │   → gated write-plane apply in dependency order:    │
        │       env → render configs → cert-sync (block on    │
        │       required) → compose up → edge route re-render │
        │   → reconcile the projections (edge/L4 routes,      │
        │       scaling, self-healing, ops) FROM the file     │
        │   → auto-rollback the WHOLE app on any step failure │
        └────────────────────────────────────────────────────┘
```

A deploy and the CLI produce the *same* typed reconcile request from the *same* `mooring.yaml` and pass the *same* chokepoints: §5.6, the §6.2 edge-conflict gate, the secure-by-default baseline, the host-capacity guard, and the fail-closed posture. The **only** thing the CLI skips is the *web transport* gates (IP allowlist, session, CSRF) — because it isn't on the web; it's an SSH session that already holds the master key.

The trust model behind this is precise:

> SSH is the highest tier. An operator who can edit the root-owned config *already* holds the master key, so `mooring secret import` grants nothing new — which is exactly *why* the CLI may write secrets but **no web route ever reads the key, allowlist, or bind address.** Authority decides *who* may invoke; it never widens *what* a deploy may do. A hostile or typo'd definition is still run through the same fail-closed validation as anything else.

The `mooring.yaml` definition file is the authoring surface, and it is a front *door*, never a new trust *path*. It inherits every invariant (run_dir confinement, edge-port denial, secret-never-in-browser, marshalled-from-typed-structs, fail-closed) and adds **zero** new bytes reaching `docker compose`. Its `edge.routes` block is parsed into the typed edge model and re-marshalled — read-and-render, never run verbatim. The dashboard then shows the deployed config read-only; it never edits the file or writes structure back to your repo (Mooring's Git access is fetch-only). See [the definition-file doc](./definition-file.md) for the full field reference and the shared reconciler.

---

## 7. Host-pinned outbound and egress allow-listing

Mooring makes authenticated, secret-bearing outbound calls to apps (the App Ops Interface, §4 of the plan). Because a monitored app is assumed to be *eventually hostile*, the destination of every such call is locked down hard.

- **The destination is pinned to the operator-configured `ops_base_url`** — the app's known container endpoint. An app's descriptor may supply capability flags and a *relative* `basePath`/`state_endpoint` (`^/[A-Za-z0-9._/-]{0,128}$`), but it may **never** supply a scheme, host, port, or absolute/`//`-prefixed URL. The relative path is joined onto the pinned base; the descriptor **cannot move the outbound host.**
- The outbound client is **DNS-rebind-safe** (re-validates the resolved IP on every connection), **redirect-revalidating**, and **blocks** loopback, link-local, private, CGNAT, ULA, `169.254.169.254` (cloud metadata), and ports `2375/2019/9000`.
- The secret-bearing call is proxied **server-side** — the shared secret never reaches the browser.

This is enforced at two layers. The application client refuses bad destinations, and underneath it the systemd **egress allow-listing** (`IPAddressDeny=any` + a narrow `IPAddressAllow` for the edge, the docker-proxy, the internal app net, and the ACME endpoints) makes a forbidden destination *physically unreachable* from the cgroup. Even a perfect SSRF against an unknown 0-day cannot reach cloud metadata or exfiltrate the master key, because the network path does not exist. The plan ships a mandatory abuse test for exactly this — *"the descriptor cannot move the outbound host."* The edge gets the parallel treatment: its slice's egress is limited to the ACME CA/OCSP/CRL plus pinned app hosts, and its custom pinned dialer refuses `9000/2019/2375` and metadata on the *resolved* target.

---

## 8. Future direction: v2 Core/Agent split

Mooring v1 is single-host by design. The build plan reserves a **v2 multi-server** direction — *not to be built now*, but every v1 boundary is deliberately forward-compatible with it:

- **Core** — the UI, SQLite, and auth/allowlist.
- **Agent** — a tiny per-host process that owns *that host's* socket-proxy, `docker compose`, and edge.

Core fans the same App Ops Interface out to agents. The v1 boundaries that make this extraction *mechanical* are exactly the ones described above: loopback-only listen, SSH-secured config, SDK-reads-via-proxy + compose-exec-for-writes, and host-pinned outbound. The split also enables a "control plane off-box" deployment for very small hosts — moving the heavy parts elsewhere while a thin agent runs on the constrained box.

> **The open risk this addresses.** The single biggest residual risk in v1 is that `docker`-group / `docker.sock` access is root-equivalent — it is the reason a dashboard compromise *could* become a server compromise. v1 *shrinks* that risk with the read-only proxy, allowlist validation, systemd sandboxing, and egress allow-listing — but it does not *eliminate* it. Hard removal needs the v2 split, where the agent's socket access is isolated from the internet-facing Core.

---

## 9. Putting it together — the full picture

```
                          INTERNET  (hostile by default)
                              │  :80 / :443
                              ▼
        ┌──────────────────────────────────────────────┐
        │  CADDY EDGE  (child process; co-resident in    │   pinned dialer (live):
        │  the core unit today — own user/slice planned) │   :9000/:2019/:2375 +
        │  CAP_NET_BIND_SERVICE (on the unit, default)   │   metadata UNREACHABLE.
        │  owns ACME · terminates TLS · pinned dialer    │   cgroup egress filter =
        │                                                │   opt-in (off by default)
        └───────┬───────────────────────────┬───────────┘
                │ admin vhost (IP-allowlist  │ app vhosts → app
                │ matcher, injected)         │ internal ports only
                ▼                            ▼
        ┌────────────────┐            ┌──────────────────────┐
        │ MOORING CORE  │            │   App containers      │
        │ 127.0.0.1:9000 │ ── ops ──► │   (internal port)     │
        │ non-root       │  host-     │   assumed hostile     │
        │ docker group   │  pinned    └──────────┬───────────┘
        │ own systemd    │  outbound             │ reads
        │ unit, hardened │                       ▼
        │ egress-locked  │            ┌──────────────────────┐
        │                │ ── reads ─►│ docker-socket-proxy   │
        │ in-mem: key    │   (SDK)    │ loopback · read_only  │
        │                │            │ verb allowlist only   │
        │                │ ── writes ────────────┐ cap_drop ALL
        │                │  docker compose        │ (raw sock mounted
        │                │  static argv, ≤1 child │  ONLY here)
        └───┬────────┬───┘            └───────────┴──────────┘
            │        │                          ▲
        SQLite   /var/lib/mooring/      real /var/run/docker.sock
       (cipher-  apps/<slug>/run_dir     (root-equivalent — never
        text +   (GENERATED compose,      in Mooring's mount set)
        YAML      env, configs, certs);
        history)  git/<slug>.git (commits)
            ▲
            │ master key (in-mem only)
        /etc/mooring/config.yaml  0600 root:root  — SSH only
        key · allowlist · bind · edge.mode · acme_email · tuning
            ▲
            │ SSH (highest trust tier)
        OPERATOR ── mooring CLI (keys · validate · secret import · restore) ─► root-of-trust + the ONE validator
                 ── edits config.yaml directly ──► reload (allowlist·auth·totp·tokens) | restart (keys·bind·edge·github·alerting)
```

Read this diagram as a set of trust boundaries: internet → edge → app; edge → allowlist; app → read-only proxy; operator/SSH → privileged actions. Each arrow crosses a boundary, and at every crossing the receiving side fails closed. That is the whole architecture in one sentence — **a small number of narrow, hardened processes — the most dangerous (the raw-`docker.sock` proxy, the setup sandbox) isolated in their own user and cgroup — funnelling every privileged action through a single validating chokepoint, with the master key kept in a place the web plane can never reach.**

---

## See also

- [README](../README.md) — what Mooring is and how to install it.
- [Security model](./security.md) — the middleware pipeline, the IP-allowlist/XFF invariant, secrets at rest.
- [The managed edge](./edge-and-tls.md) — how Mooring owns Caddy, the pinned dialer, and the secure-by-default baseline.
- [App provisioning](./gitops.md) — connecting a Git repo, the generated compose, and the §5.6 chokepoint in detail.
- [The definition file](./definition-file.md) — `mooring.yaml`, the shared reconciler, and the CLI.
- [Operations](./backup-and-recovery.md) — running on a small host, backups, and recovery.