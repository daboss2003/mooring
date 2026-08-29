# Security Model

> **The paramount requirement of Mooring is that it must be extremely safe and effectively bug-free.** Hosting it must never become *the thing that gets your server hacked*. Every design choice in Mooring is subordinate to that single goal. This document is the security model in full: the request pipeline, the validation chokepoint, the secrets architecture, the secure-by-default baseline, the threat model, and the assurance program that gates every release.

This is a long page on purpose. If you operate a Mooring install, read at least [§1](#1-the-paramount-requirement) and [§5](#5-the-secure-by-default-baseline-sbd-18); if you author apps or routes in a `mooring.yaml`, also read [§3](#3-the-56-validator--one-allowlist-chokepoint); if you assess the risk of running Mooring at all, read [§6](#6-threat-model-trust-boundaries-and-attacker-classes) and [§9](#9-residual-risk-the-honest-part).

See also: the project [README](../README.md), the [edge / Caddy docs](./edge-and-tls.md), the [provisioning modes](./gitops.md), the [configuration reference](./host-file.md), and the [architecture overview](./architecture.md).

---

## 1. The paramount requirement

Mooring is a single static Go binary that gives you a CapRover-style dashboard — health, logs, start/stop/redeploy, env, git deploy, host metrics, and **managed HTTPS out of the box** — without a heavyweight PaaS's RAM appetite. Because Mooring talks to `docker` and (by default) **owns the public edge on ports 80 and 443**, a flaw in Mooring is not just a dashboard bug: it is a potential path to root on the host.

Two consequences shape everything below:

1. **Owning the edge is now core, not optional.** By default (`edge.mode: managed`) Mooring supervises a child Caddy that owns `:80/:443` and runs ACME/Let's Encrypt. **Every install is therefore internet-facing by default.** The release gate that proves the edge is safe ([§8](#8-the-assurance-program-15)) applies to *every* release, not just "advanced" ones.
2. **Safety is achieved by containment, not by assuming bug-freeness.** We assume the binary *will* eventually be exploited and design so that the exploit is survivable — systemd sandboxing, egress allow-listing, a read-only filesystem, and dropped capabilities mean that even a perfect remote-code-execution bug cannot reach cloud metadata, the master key, or `docker.sock` ([§7](#7-containment-posture-surviving-an-unknown-0-day)).

The design has been red-teamed across several passes; the fixes are folded into the model described here.

---

## 2. The request pipeline *is* the security model

Mooring's security is not a single check — it is an **ordered pipeline of layers, each of which fails closed**. The order matters. A request that is rejected at layer 1 never reaches layer 6; a forged header that would fool layer 6 is irrelevant because layer 1 already dropped the connection on the unspoofable TCP peer.

```
1 IP allowlist  →  2 trusted-proxy / XFF resolve  →  3 security headers  →  4 rate limiter
→ 5 session loader  →  6 argon2id auth  →  7 CSRF + Origin check  →  8 router  →  9 audit
```

| # | Layer | What it does | Fails closed by |
|---|-------|--------------|-----------------|
| 1 | **IP allowlist** | Runs **first**, before routing, auth, or body parsing, on the **real `net.Conn` TCP peer**. Non-allowlisted peers get a bare `404` (or a dropped connection) — no hint that Mooring exists. | Empty `ip_allowlist` means **deny-all**, never allow-all. |
| 2 | **Trusted-proxy / XFF resolve** | Decides whether to trust `X-Forwarded-For`. See the invariant below. | If the peer is not a trusted proxy, XFF is **ignored** and the peer itself is allowlisted. |
| 3 | **Security headers** | Strict CSP, HSTS, `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, `Server` stripped (see [§2.2](#22-csrf-and-headers)). | Headers are added unconditionally. |
| 4 | **Rate limiter** | Global + per-route limits; slowloris-safe timeouts; body/header caps. | A small box cannot be DoS'd into OOM. |
| 5 | **Session loader** | Loads the server-side opaque session (stored hashed). | No session → unauthenticated. |
| 6 | **argon2id auth** | Verifies credentials. The argon2id verify **always runs** (against a dummy hash for unknown users) so response timing never reveals whether a username exists. | Tuned small (`m≈8 MiB`, `t=2`, `p=1`, serialized + rate-limited) so a login can't OOM a tiny box. |
| 7 | **CSRF + Origin check** | Synchronizer + double-submit token **and** an `Origin` check on every state-changing request; `403` on mismatch. | Any mismatch → `403`. |
| 8 | **Router** | Only now does the request reach a handler. | — |
| 9 | **Audit** | Appends an immutable event row: actor, IP, target, outcome, timestamp. | — |

### 2.1 The IP allowlist + XFF invariant (the most-abused boundary)

This is, historically, the single most-abused boundary in proxy-fronted admin tools. The classic bug is `x-forwarded-for.split(",")[0]` with **no trusted-proxy check** — trusting the leftmost, attacker-supplied value. **Mooring never does that, and never enables a blanket `trustProxy`.**

The rule:

- Read the real `net.Conn` peer. **If the peer is *not* in `trusted_proxies`, ignore `X-Forwarded-For` entirely and allowlist the peer.** Only if the peer *is* a trusted proxy does Mooring take the single, **overwritten** XFF value. The managed edge **overwrites** XFF to the real client (single-hop, spoof-safe) — it never *appends*.
- **`trusted_proxies` must be the edge proxy's specific IP (`≤ /24`), not a docker-bridge CIDR**, and monitored-app containers must not share that CIDR — otherwise a hostile container could connect to `:9000` directly with a forged XFF and be admitted.
- **Belt-and-suspenders, mandatory in managed mode:** a host firewall on `:9000` (drop everything but the edge IP) **and** an edge-layer `remote_ip` allowlist. The XFF overwrite is **never the sole anchor**.
- Lockout keys on the **(real peer, username)** pair *and* a **global per-username** throttle, so rotating XFF values cannot bypass the lockout.

> A shipped unit test proves that a **forged-XFF direct connection from a bridge peer is rejected**. This test runs first in the known-attack checklist ([§8](#8-the-assurance-program-15)).

### 2.2 CSRF and headers

Every state-changing request requires a synchronizer + double-submit CSRF token **and** passes an `Origin` check (`403` on mismatch); cookies are `SameSite=Strict`. The admin plane ships a **fixed, strict CSP** with no `unsafe-inline`:

```
default-src 'self'; script-src 'self'; object-src 'none';
frame-ancestors 'none'; base-uri 'none'; form-action 'self'
```

This is possible because Mooring is server-rendered (`html/template` + htmx + Alpine, ~30 KB of embedded JS) — there is no SPA build step and no inline-script requirement. `text/template` and `template.HTML` on any externally-influenced content are **banned** and enforced by a custom lint rule.

### 2.3 Auth and sessions

`POST /login` takes username + password (+ optional TOTP). Username comparison is constant-time. There is **no public registration and no web password reset** — credentials are set over SSH (see [§4.1](#41-the-ssh-provisioned-config-root-of-trust)). Sessions are server-side opaque 256-bit ids, **stored hashed** and **rotated on login and on any privilege change**. The cookie uses the `__Host-` prefix (which mandates a subdomain deploy) or `__Secure-` + `Path=base_path`; config validation refuses an incompatible combination. Both idle and absolute timeouts apply. The dashboard's keepalive runs **only while it is focused** (the tab is visible *and* the window has focus), so a dashboard left unfocused/abandoned stops refreshing and the session **idles out** server-side after `session.idle_timeout` (default **10m**); a client watchdog polls a non-refreshing `/session/status` and redirects to the login page when that happens. An active operator is never logged out (the keepalive holds the session); the absolute timeout is the hard ceiling regardless.

### 2.4 The webhook exemption

`POST /webhook/:token` is the **one** route exempt from the IP allowlist — because CI egress IPs are unpredictable. It is not unprotected: it is HMAC-verified (timing-safe), replay-protected (a signed timestamp + nonce inside the HMAC-covered body, provider-agnostic), per-token rate-limited, and single-flight debounced. The high-entropy token is **never logged**.

Crucially, the webhook is **fetch-only and trigger-only**: it performs a `git fetch`, advances a staged ref, computes "commits behind," and sets `update_available`. It **never** reads the ref/sha/repo from the (attacker-influenced) payload, and **never** builds, re-validates, or redeploys. The actual deploy is a separate, manually-gated path. This removes the surprise-OOM vector that an auto-redeploy-on-push webhook would have. A webhook can **never** trigger setup-script execution. See [provisioning](./gitops.md) for the full auto-pull / manual-deploy model.

### 2.5 Operators, roles, and the auth epoch

Mooring supports more than one operator, all declared in the root-of-trust `config.yaml` (never a web signup). The `auth:` block is the primary **owner**; additional operators go in a `users:` list, each with a role:

| Role | Can |
|---|---|
| **owner** | Everything — deploy, roll back, edit apps, **and** all Tier-1 actions: reveal/set secrets, mint API tokens, delete apps, change trust. |
| **deployer** | Deploy, roll back, and edit an app's env / config files / scaling. **No** Tier-1 actions. |
| **viewer** | Read-only. |

Roles are enforced **server-side**, as a `requirePerm(view|deploy|admin)` gate that runs *after* authentication on every mutating route — never in the UI alone. The tier check is fail-closed: an unknown capability is denied.

**The auth epoch — one credential change logs everyone out.** Mooring persists a fingerprint over the *entire* operator set — every user's username, password hash, TOTP secret, **and role**. On both **reload and restart**, it re-derives the fingerprint and, if it changed, **revokes every live session**. So changing any operator's password, rotating a TOTP, renaming a user, **changing a role, or adding/removing an operator** immediately invalidates all outstanding sessions — closing the "demote or disable a user but their existing session keeps working" gap, through either the reload *or* the restart path.

---

## 3. The §5.6 validator — one allowlist chokepoint

**Everything** that reaches `docker compose` — the compose Mooring **generates** from a `mooring.yaml`, a setup-script's output, or a scaffolded starter — passes through **one** validator. There is exactly one chokepoint, and it is an **allowlist, not a denylist**. The dashboard deploys (and the Git fetches they act on) funnel into it, and `mooring validate` runs that very same validator read-only: a new front-end is a new *front door*, never a new *trust path*.

The validator does its work in this order, and the order is load-bearing:

### 3.1 Resolve `${VAR}` / `.env` first

Validating *before* interpolation is a known bypass — an attacker hides a dangerous value behind a variable. Mooring resolves `${VAR}`, `.env`, `extends:`, and `x-`-anchors **first**, then validates the **final** materialized document.

### 3.2 Reject unknown and dangerous keys (allowlist)

Any **unknown top-level or service key** is rejected. The known-dangerous set is rejected outright:

```
privileged, cap_add, host binds of / /var/run/docker.sock /etc /proc,
pid:host, network:host, ipc:host, uts:host, userns:host,
security_opt: unconfined, cgroup_parent, sysctls, devices, exec tmpfs, …
```

### 3.3 Confine bind mounts under `run_dir`

Bind-mount sources are confined **under the app's `run_dir`** using **canonicalize-then-`Rel`** — rejecting `..`, absolute paths, and symlink escapes. The same confinement applies to materialized [managed config files](./gitops.md), captured setup-script secrets, and repo-relative paths (which confine under the **checkout subtree**). A path that resolves onto a **protected path** — the proxy data / ACME-key dir, the edge binary, the socket-proxy, an `--env-file`, or Mooring's own config / DB / master key — is rejected. NUL is always rejected; CR/LF is rejected **regardless of any operator-declared `format`** (never trust an attacker-influenced format hint for a security decision).

### 3.4 The edge owns 80/443 — an app may never grab it

The edge-collision rejections are applied to the **final** compose:

- **(a)** Reject any service publishing host `:80` or `:443`. Every publish form is canonicalized first — short form, long form (`published:` / `target:`), ranges whose span includes 80/443, and every bind address including `0.0.0.0`, `[::]`, `::`, `*`, and host-gateway. The error is line-anchored: *"port 80/443 is owned by the Mooring edge; declare an internal port and add an app route instead."*
- **(b)** Reject a bundled competing proxy / TLS-terminator / ACME client / cert-reload sidecar — detected **structurally** (a service requesting 80/443, mounting the edge/proxy data dir by *resolved named volume*, or mounting the socket for cert-reload), plus a curated advisory image-prefix list. The structural rules are **not bypassable by renaming the image**.
- **(c)** At route time, the loopback-port deny still governs `app_routes.upstream`. The rule is symmetric: apps cannot *define* the edge, and the edge cannot be *routed into* the control plane.

### 3.5 Marshal from typed structs — never `sh -c`, never string concat

This is the cornerstone. **Configs are rendered by marshalling typed structs, never by string concatenation.** Writes to Docker shell out to `docker compose` with **static argv only** — never a shell, never string interpolation, with `--` terminators. **No external input ever reaches argv unvalidated, and there is no `sh -c` anywhere in the write path.** A custom semgrep rule fails the build on any `exec.Command` whose arguments derive from request/DB/app input without passing this validator.

> The same validation runs for rollbacks, webhooks, materialized config files, and the exact bytes of a pinned git commit (read via `git cat-file`, not a working tree). There is no "trusted" input that skips it — including input authored over SSH (see [§6.4](#64-authority-is-never-an-exemption-from-validation)).

---

## 4. The secrets model

Mooring uses **two independent secret stores**. The config file holds the master key; the SQLite database holds **only ciphertext**. A compromise of the database alone yields nothing decryptable.

### 4.1 The SSH-provisioned config (root of trust)

`/etc/mooring/config.yaml`, mode `0600 root:root`, is edited **only over SSH**. It is the root of trust. Mooring performs **fail-closed boot checks** and refuses to start on any of:

- insecure file permissions;
- **empty `ip_allowlist`** (= deny-all, intentionally — never silently allow-all);
- `trust_proxy` enabled with an empty or too-broad `trusted_proxies`;
- wrong-length keys or an invalid argon2id hash;
- in managed mode, the admin endpoint reachable off-loopback, or missing edge prerequisites;
- setup-scripts enabled with no working sandbox.

The CLI tools (run over SSH; passwords read from `/dev/tty`, **never argv**) are: `mooring hash-password`, `gen-key`, `gen-totp`, and `verify-key` (decrypts one column to catch a key/DB mismatch *before* it corrupts on the next write). `SIGHUP` hot-reloads the allowlist and auth — but **not** keys.

### 4.2 What no web route can ever do

**No web route reads or writes the master key, the IP allowlist, the auth credentials, or the bind address.** These exist *only* in the SSH-edited config. The route table is intentionally missing any endpoint that sets username/password, the master key, the bind address, the allowlist, `edge.mode`, `acme_email`, the admin bind, or the scaling/self-healing tuning. This is a deliberate, structural absence — there is no handler to attack.

### 4.3 Encryption at rest

Env blobs, git credentials, ops secrets, and webhook/channel secrets are encrypted with **AES-256-GCM** under the `encryption_key` (config-file only; never in the DB, logs, or UI). Key rotation is supported via `encryption_key_previous`.

> **Back up the config (the key) and the DB separately and offsite.** Losing the key bricks all ciphertext irrecoverably. Run `verify-key` after a restore to confirm the key and DB match.

### 4.4 The `Redacted` type

A dedicated **`Redacted` type** wraps every secret. Its `String()` and `MarshalJSON()` return `••••`. Secrets therefore **never** serialize into logs, error messages, `ps` output, temp files, or stack traces — the type makes accidental leakage a compile-shaped problem rather than a discipline problem. A semgrep rule fails the build on any secret type whose `String()`/`MarshalJSON()` isn't redacted.

### 4.5 Reveal-on-click (an honest trade-off)

Revealing a secret in the UI is a deliberate, audited action:

- It is a **`POST`**, not a GET (so the value never lands in a URL, history, or referer).
- The response is **`text/plain` with `Cache-Control: no-store`**.
- It is **audited**, bound to the current session, and **never `innerHTML`-swapped**.

**Honest trade-off:** revealing a secret *does* put its plaintext into the operator's browser, in memory, on screen. That is the inherent cost of a "reveal" feature, and Mooring states it plainly rather than pretending otherwise. The mitigations (POST, no-store, audit, no DOM injection) reduce the blast radius; they do not eliminate the fact that you asked to see the secret and it was shown to you.

### 4.6 Crown jewels (ranked)

The threat model ranks the secrets by blast radius, which is how mitigations are prioritized:

| Rank | Asset | Compromise impact |
|------|-------|-------------------|
| A1 | The master key | Total compromise (decrypts everything). |
| A2 | The admin password hash | Operator impersonation. |
| A3 | The `docker.sock` / `docker compose` write path | Root-equivalent on the host ([§9](#9-residual-risk-the-honest-part)). |
| A4 | The encrypted store (ciphertext) | Useless without A1. |
| A5 | Edge / ACME private keys | TLS impersonation for managed hostnames. |
| A6 | The operator session | The most-privileged live session — hence the strict output-encoding on all dashboard-rendered content. |

---

## 5. The secure-by-default baseline (SBD-1..8)

Because the edge is always-on, "safe" no longer means *the operator configured it safely* — it means *the shipped default is provably safe with zero operator action*. The Secure-by-Default Baseline is a finite, testable set of invariants. Each is enforced **in code** (typed structs + render-time checks) and **proven by a per-invariant automated test on a fresh install**. All eight must be 100% green before any edge-owning release ships ([§8](#8-the-assurance-program-15), Layer A).

| ID | Invariant |
|----|-----------|
| **SBD-1** | **Admin UI never reachable through the public edge by accident.** The admin UI binds `127.0.0.1:9000` only. The edge serves **no admin vhost at all** unless the operator explicitly sets `admin.hostname` (default: reach the UI via an SSH tunnel). If set, the admin vhost is rendered with the **IP allowlist as the first matcher, injected from typed config** — the allowlist cannot be omitted. |
| **SBD-2** | **Caddy admin API never public.** `admin.listen` is a unix socket (`/run/mooring/caddy-admin.sock`, preferred) or `127.0.0.1:2019`, never routable; `enforce_origin: true`, origins loopback-only. No public vhost may proxy to `:2019`. |
| **SBD-3** | **On-demand TLS off; ACME bounded.** Absent in the base config. If ever enabled via the editor, the renderer **force-rewrites the `ask` endpoint** to a fixed loopback validator that answers "yes" only for `app_routes` / allowlisted hostnames, plus a rate limit. |
| **SBD-4** | **Only configured app vhosts served; control-plane ports unreachable as upstreams.** Exactly the `app_routes`-derived vhost set (plus the optional admin vhost). **No catch-all / wildcard proxy.** No upstream targets `9000/2019/2375` or any internal port — struct-validated **and** re-checked at render **and** refused at dial. Unmatched `Host` → `404`/close, never proxy. |
| **SBD-5** | **Network isolation of the edge from the control plane** (the structural backstop — see [§5.1](#51-the-structural-runtime-controls-the-real-backstop)). |
| **SBD-6** | **Egress allow-listing unchanged by always-on.** Outbound ops calls stay host-pinned; edge egress is limited to the ACME CA / OCSP / CRL endpoints plus the pinned app hosts. |
| **SBD-7** | **Config rendering safety — the operator never authors Caddy.** Proxy config is marshalled **entirely from typed structs** (never string concat), derived from the typed route model / `mooring.yaml`. There is **no operator-supplied Caddy input path** — no raw-config editor, no file, no portal field — so what Caddy runs is *always* the product of Mooring's typed renderer. Like Docker/compose, Caddy is a Mooring-owned, invisible implementation detail (see [edge/Caddy ownership](#93-the-edge-config-is-mooring-owned)). |
| **SBD-8** | **The edge can never go down irrecoverably.** Every apply is validate → stage → load, with a retained last-known-good; on failure, the previous config keeps running (Caddy `/load` is transactional). The typed base config is always loadable as the recovery floor, and Mooring re-derives it from typed structs on restart. **SSH is the ultimate recovery floor** — the edge config is never operator-authored text that could be left in a broken state. |

**The minimum-safe base config** ships with every install, rendered from typed structs, and is safe before any route exists: admin on the unix socket; on-demand TLS off; ACME only for `app_routes` hostnames; one server on `[:443, :80]` (`:80` = ACME + redirect only) with empty routes and unmatched-`Host` = close/404; **no admin vhost unless `admin.hostname` is set**. A fresh install is therefore a public IP running an HTTPS-capable Caddy that **proxies to nothing and exposes no admin surface** until you add your first route.

### 5.1 The structural runtime controls (the real backstop)

Even though the operator never authors Caddy config (the edge is rendered entirely from typed structs), a route's *upstream* is still a hostname that Caddy resolves at *runtime* — and a struct-level check sees the literal hostname, not the `127.0.0.1:9000` it might resolve to at dial time. The edge's real safety therefore rests on **structural runtime controls**, with the render-time validation as defense-in-depth on top. These controls keep the edge from reaching the control plane:

- **Custom pinned dialer.** The edge dials every upstream through a dialer that **re-resolves and refuses, on every connection,** loopback `127.0.0.0/8` / `::1`, link-local / metadata `169.254.0.0/16`, and ports `9000/2019/2375`. Enforced on the **resolved target**, not the literal config string — so a DNS name (or a rebind) that points at a control-plane port is refused *at dial time*.
- **`app_routes.upstream` is an allowlist** of discovered app container endpoints. The admin-vhost→`:9000` route is the **only** loopback target, identity-pinned, never operator- or app-editable. Auto-scaled replica pools have every member checked the same way.
- **Egress firewall (the real backstop).** The edge slice's `IPAddressDeny` / firewall makes `9000/2019/2375` and metadata **physically unreachable** from the edge. Even a config the linter missed, an edge RCE, or an SSRF cannot reach the control plane or the socket-proxy.
- **Caddy admin on a unix socket** — so there is **no TCP `:2019`** to proxy to at all.

Full detail of the edge model lives in the [edge docs](./edge-and-tls.md).

---

## 6. Threat model, trust boundaries, and attacker classes

The threat model drives every other decision.

### 6.1 Trust boundaries

```
internet  →  edge  →  app
   edge    →  allowlist        (the XFF / trusted-proxy seam — most-abused)
 operator  →  privileged actions
   app     →  read-only socket-proxy   (a "read" proxy must never become a "write")
   app     →  docker compose / git / shell   (root-equivalent — why a dashboard compromise becomes a server compromise)
   app     →  outbound polls to app-controlled metadata   (the SSRF boundary)
   app     →  untrusted JSON / HTML into parsers / templates
   SSH config  →  process
   build / CI  →  binary
```

### 6.2 Attacker classes

| Class | Description |
|-------|-------------|
| **U** | Unauthenticated internet attacker. |
| **I** | An allowlisted-but-malicious insider (a second operator, or a stolen credential). |
| **C** | **A compromised monitored app answering Mooring's polls.** *Assume every app is eventually hostile.* This is the class that drives the SSRF design. |
| **R** | A malicious repo / compose / setup script — **RCE-by-design** is the operator's intent here, so the job is *containment*, not prevention. |
| **S** | A supply-chain attacker (the child proxy binary, an L4 plugin build, a dependency). |

### 6.3 SSRF design-against (attacker class C)

A compromised app must not be able to redirect Mooring's authenticated, secret-bearing requests at cloud metadata (`169.254.169.254`), the proxy admin API, the socket-proxy, or the admin UI. The invariant: **the app descriptor is advisory metadata only.** It may supply capability flags and a *relative* `basePath`/`state_endpoint` (`^/[A-Za-z0-9._/-]{0,128}$`) — it may **never** supply a scheme, host, port, or absolute / `//`-prefixed URL. **Every** outbound ops / alerting / health call is pinned to the operator-configured `ops_base_url` (the app's known container endpoint); the relative path is joined onto that pinned base.

Concretely, the outbound client:

- enforces a **scheme allowlist** (and for git, `{https, ssh}` only);
- is **DNS-rebind-safe** (a pinned-IP client that re-validates on every redirect);
- **blocks** loopback / link-local / private / CGNAT / ULA CIDRs + `169.254.169.254` + ports `2375/2019/9000`;
- **does not follow redirects** by default.

A mandatory abuse test — **"the descriptor cannot move the outbound host"** — runs in the assurance suite, alongside a property test that the outbound client never connects to a blocked CIDR even against a resolver that returns metadata / rebinding IPs.

### 6.4 Authority is never an exemption from validation

This is worth stating loudly because it surprises people: **having SSH access — or being the operator — does not exempt input from validation.** SSH is the highest trust tier (an operator who can edit the root-owned config already holds the master key, so `mooring secret import` over SSH grants nothing new). But **authority decides *who may invoke*; it never widens *what a deploy may do*.** A hostile or typo'd definition is still run through the *same* fail-closed §5.6 validator + edge-conflict gate no matter how it arrives — and `mooring validate` exercises that very validator read-only, so you can check a file in CI before it ever reaches the write plane. There is no "trusted path" that smuggles unvalidated bytes to `docker compose`.

---

## 7. Containment posture: surviving an unknown 0-day

The principle: **assume the binary will be exploited, and make that survivable.** Mitigation is the last line; containment is the floor.

### 7.1 Process and privilege isolation

- Mooring runs as **its own systemd unit** (not a compose container — so its controls can't target itself and a stack `down` can't take it down), **non-root**, under a dedicated low-privilege user in the `docker` group.
- The raw `docker.sock` is **never mounted into Mooring**. Reads go through a **read-only `docker-socket-proxy`** on loopback (`read_only`, `cap_drop: ALL`, a deny-by-default verb allowlist of `CONTAINERS/INFO/VERSION` only — `EXEC/POST/IMAGES/VOLUMES/…=0`). The socket is mounted *only* into the proxy.
- The public edge is a **separate child process** — the hostile-traffic-parsing TLS/ACME/x509 stack does not share the address space holding session secrets or the master key. (Today it is **co-resident** in the control-plane unit — same user + cgroup; `CAP_NET_BIND_SERVICE` is granted to the unit via the opt-in drop-in, so the core holds it too. A dedicated edge user/slice + child-only cap is a **planned** hardening.)
- Setup scripts run in a throwaway jail under a **distinct uid** (`mooring-sandbox`), with no docker.sock, no network, dropped caps, a read-only rootfs, and exactly one writable mount. The sandbox is **re-verified live before every run** (see [provisioning](./gitops.md)).

### 7.2 systemd sandboxing

The Mooring unit, the `docker compose` child, **and** the setup sandbox run with the full hardening set:

```
NoNewPrivileges        ProtectSystem=strict    ProtectHome
PrivateTmp             PrivateDevices          ProtectKernel*
RestrictAddressFamilies  RestrictNamespaces    LockPersonality
MemoryDenyWriteExecute  SystemCallFilter=@system-service
CapabilityBoundingSet=(empty)   tight ReadWritePaths
MemoryMax   OOMScoreAdjust=-100
```

`MemoryMax` kills *inside* the cgroup (including forked `docker`/`docker compose` children); `OOMScoreAdjust` only biases the *global* killer. A **global semaphore caps concurrent docker children at 1** across the poller, stats, deploys, log streams, and the sandbox — no plane can OOM-kill the control plane.

### 7.3 Network egress allow-listing — the highest-leverage control

This is the single most important control against *unknown* attacks:

```
IPAddressDeny=any
IPAddressAllow= only the edge, the docker-proxy, the internal app net, and the ACME endpoints
```

Even a **perfect SSRF or RCE** then cannot reach cloud metadata or call home — there is simply no route out. This is what makes an unknown 0-day survivable rather than catastrophic: the attacker may get code execution inside the process, but the process can't pivot anywhere useful.

### 7.4 Anomaly detection and recovery

Mooring raises anomaly alerts on spikes in auth-failures, allowlist-rejects, and outbound-to-blocked-CIDR attempts — these should be **zero**, so *any* hit is a signal of an active attack — plus restart-loops. A **rehearsed IR / key-rotation / rollback runbook** covers rotating A1 (+ re-encrypt), rotating A2, reissuing A5, rolling back to the previous signed binary, the kill-switch, and a dedicated "docker.sock suspected compromised" branch.

---

## 8. The assurance program (§15)

The Security Assurance Program runs **after** the build is feature-complete and **gates** the binary before it may own a public edge or run setup scripts. **It is recurring, not one-shot.** Because the edge is core, this gate is **universal — it applies to every release.**

It splits into two layers:

- **Layer A — the Secure-by-Default Baseline** ([§5](#5-the-secure-by-default-baseline-sbd-18), SBD-1..8). The **hard release-blocking shippability bar** on the first edge-owning release: every SBD invariant green on a fresh install, with a per-invariant test.
- **Layer B — the full program** (fuzzing, pentest cadence, CVE SLAs, parser-surface review). The **ongoing durability bar**, gating each release on its cadence.

The universal **public-edge gate** is the operationalization of the paramount requirement: a release **may not own a public edge until Layer A is green**, and **may not run setup scripts until the sandbox escape test passes**. Any diff to a blast-radius module (the exec wrapper, the SSRF client, the allowlist/XFF code, the crypto/secret store, the setup sandbox, ACME, or the edge renderer) **re-triggers the relevant gates before merge**.

### 8.1 Phase highlights

- **Phase 0 — Threat model** ([§6](#6-threat-model-trust-boundaries-and-attacker-classes)) drives everything.
- **Phase 1 — Static assurance:** `govulncheck` (zero reachable), `gosec` / `staticcheck` / `go vet` clean, `trivy` / `grype` (zero Critical/High with a fix), `gitleaks` over full history, plus the **custom rules** generic tools miss. Those custom rules are implemented in-repo as dependency-free AST gates (`internal/security`, run by plain `go test`) — banning `sh -c` / shell command construction outside the sandbox jail, non-host-pinned outbound clients (`http.Get`/`DefaultClient`/…), and `text/template` / dynamic `template.HTML` in the web layer; each has a self-test proving it still fires. See [§8.4](#84-what-is-automated-in-repo).
- **Phase 2 — Known-attack checklist** (each line is a test). Highlights:
  - **The keystone allowlist/XFF test** runs *first*: a forged `X-Forwarded-For` / `X-Real-IP` / `Forwarded` / `::ffff:` from the internet is **rejected**, and a direct-to-port connection honors no forwarded header (default deny).
  - **SSRF design-against** ([§6.3](#63-ssrf-design-against-attacker-class-c)): destination pinned, DNS-rebind-safe, redirect-revalidating, blocked CIDRs + metadata + control-plane ports, no redirect-follow.
  - **git checkout-time RCE hardening** (see [§8.2](#82-git-is-a-code-execution-surface)).
  - Command/arg injection (no shell ever, static argv, `--`), path traversal, SSTI (app content is data, never template source), JSON-bomb / deserialization caps, setup-script RCE, secret leakage, TLS/ACME abuse, webhook replay/forgery, log injection, and small-box DoS.
- **Phase 3 — Dynamic & adversarial:** an **authz test matrix** regenerated from the route table (so a new route can't slip past untested — any unexpected *allow* fails the gate; implemented in `internal/web`); a property/abuse suite of invariants under randomized input; Go native fuzzing of the health/snapshot/descriptor parsers, the XFF derivation, the relative-path grammar/resolver, and the webhook verifier (`go test -fuzz`, zero panics/OOM/hangs); DAST; and an **independent pentest** whose explicit objectives are *bypass the allowlist from the internet, pivot SSRF to cloud metadata, turn a monitored-app compromise into a docker.sock write, extract the master key, and escape the setup sandbox*. (The Caddyfile/paste-adapt fuzz surface no longer exists — the raw editor was removed.)
- **Phase 4 — Defense-in-depth for unknown attacks** ([§7](#7-containment-posture-surviving-an-unknown-0-day)).

### 8.2 Git is a code-execution surface

A connected repo is attacker-controlled, and "fetch runs nothing" is **false** — merely fetching, diffing, or checking out can execute code via `.gitattributes` `filter`/`textconv` drivers, LFS smudge, `core.fsmonitor`/`sshCommand`, hooks, and submodule `ext::`. **Every** git invocation is run config- and attribute-proof:

```
GIT_CONFIG_NOSYSTEM=1   GIT_CONFIG_GLOBAL=/dev/null   HOME=(empty)
-c core.hooksPath=/dev/null   -c core.fsmonitor=false   -c core.symlinks=false
-c protocol.ext.allow=never   -c protocol.file.allow=never
-c submodule.recurse=false    -c gc.auto=0   (neutralized filter/diff drivers)
```

File bytes are read via `git cat-file blob <sha>:<path>` (object-store, no worktree, no smudge); diffs use `--no-textconv --no-ext-diff`. **Tree entries whose git mode is `120000` (symlink) or `160000` (gitlink) are rejected** on the path. The compose-path confinement check and the read happen on the **same pinned commit's tree** (no lstat-then-reopen TOCTOU). The known-attack test verifies a repo carrying a malicious filter/textconv/LFS/hook/submodule executes **nothing** on fetch/diff/checkout — proven by a canary the filter *would* have created. See [provisioning](./gitops.md) for the deploy-side fences.

### 8.3 The edge-config abuse class is eliminated by construction

Earlier designs included a raw Caddy-config editor (a "Layer-2 overlay"), which was its own risk class needing four mandatory abuse tests. **That editor was removed:** the operator never authors Caddy config — neither via a file nor the portal — so the abuse class (an operator-supplied overlay that exposes the admin API, removes/widens the admin allowlist, routes a public vhost to a control-plane port, or enables unbounded on-demand TLS) **cannot exist** — there is no input path to carry it. The edge config is rendered entirely from typed structs (SBD-7).

The remaining edge invariants are SBD-enforced and per-invariant tested (Layer A): no admin vhost without an injected allowlist (SBD-1), the admin API never routable (SBD-2), on-demand TLS off (SBD-3), no catch-all and **no upstream to a control-plane port — struct-validated, re-checked at render, and refused at dial** (SBD-4), and the typed base as an always-loadable recovery floor (SBD-8). The pinned dialer + egress firewall ([§5.1](#51-the-structural-runtime-controls-the-real-backstop)) are the runtime backstop for a hostname that resolves to the control plane. The apply pipeline retains a last-known-good and auto-reverts a failed load; `mooring` re-derives the typed base on restart as the SSH recovery floor.

### 8.4 What is automated in-repo

The program's runnable core ships in the repo and executes with **plain `go test ./...`** — no external binary required — so the gate runs on every developer machine and in CI identically. `scripts/security-gate.sh` is the single entrypoint: it runs these in-repo gates fail-closed, smoke-fuzzes each target, and then runs each external tool (`govulncheck`, `staticcheck`, `gosec`, `gitleaks`, `trivy`) **if installed** — a missing tool is reported `SKIP`, never silently passed, and CI installs them so they become `RUN`.

| Gate | Where | What it enforces |
|------|-------|------------------|
| **Phase-1 custom static rules** | `internal/security` | no `sh -c`/shell construction outside the sandbox jail; no unguarded outbound HTTP; `html/template` only + no dynamic `template.HTML/JS/CSS/URL` in the web layer. Each detector has a self-test proving it still fires. |
| **Phase-3 authz route-posture matrix** | `internal/web` | regenerated from the route table: every route is auth-exempt-allowlisted or wrapped in `requireAuth`; every mutating verb is `requireCSRF` (except the HMAC webhook); plus a dynamic anonymous-denied sweep over every protected route. |
| **Phase-3 fuzz targets** | `internal/ops`, `internal/opsclient`, `internal/web` | the descriptor/health/queue JSON parsers (attacker class C), the relative-path grammar, the XFF derivation, path confinement, and the webhook verifier — zero panics/OOM/hangs. |
| **Layer-A SBD invariants** | `internal/edge` | SBD-1..8 asserted on a fresh install, consolidated as the shippability bar. |

What stays an external/process responsibility (driven by CI / cadence, not this repo's `go test`): `govulncheck`/`gosec`/`staticcheck`/`gitleaks`/`trivy`/`grype`, the `syft` SBOM + `cosign`/SLSA provenance on the release artifact, DAST against a deployed instance, the systemd-posture drift-check, and the independent pentest cadence.

---

### 8.5 Exit criteria

A release may own a **public edge** only when **all** hold: Layer A / SBD-1..8 green on a fresh install; Phase 1 green; zero reachable known vulns; the authz matrix + abuse suite green; fuzz targets ran the agreed duration with zero panics/OOM/hangs; **SSRF proven impossible** against metadata/private/rebinding/redirect plus the descriptor-can't-move-host test; **allowlist/XFF bypass proven impossible** for the full forged-header set; no-shell / no-unvalidated-argv enforced in CI **and** at runtime; secret-leakage tests pass; the systemd-sandbox + egress-allowlist + read-only-FS + non-root + read-only-socket-proxy posture deployed and drift-checked; the release **signed with an SBOM + provenance + reproducible build**; the independent pentest's objectives **all failed**; and the IR/rotation/rollback runbook rehearsed. **Additional gate to run setup scripts / deploy untrusted compose:** the sandbox independently passes an **escape test** (an attempted escape that *fails*) — until then that feature ships **disabled by default**.

---

## 9. Residual risk (the honest part)

No security model is complete without naming what it does *not* fully solve.

### 9.1 `docker.sock` is root-equivalent (the headline residual risk)

**Membership in the `docker` group — and access to `docker.sock` / the `docker compose` write path (asset A3) — is root-equivalent on the host.** This is *the* reason a dashboard compromise can become a *server* compromise. Mooring **shrinks** this risk but does **not eliminate** it:

- reads go through a read-only, verb-allowlisted proxy (the raw socket is never in Mooring);
- writes go through the §5.6 allowlist validator with static argv only;
- systemd sandboxing + egress allow-listing contain a compromised process.

But the write plane fundamentally *needs* to launch containers, and launching containers on a shared Docker daemon is root-adjacent by nature. **Hard removal of this risk requires the v2 Core/Agent split** (a tiny per-host agent owns the socket; the control plane runs off-box) — explicitly out of scope for v1. If this residual is unacceptable for your threat model, the honest answer is: do not run the write plane on a host whose root you cannot afford to lose, and wait for v2.

A related caveat: a host may **already** have a root-equivalent `docker.sock` consumer before Mooring is installed (an existing cert-reload or auto-update sidecar). "Minimize socket consumers" may already be violated — document the host's existing consumers as part of your trust base.

### 9.2 The always-on public edge

The edge is the highest-surface feature and now exposes **every** install on `:80/:443`. It is mitigated by the secure-by-default baseline (SBD-1..8), the structural runtime controls (pinned dialer + egress firewall + unix-socket admin), and the §15 universal gate — but it is, unavoidably, internet-facing code parsing hostile traffic. Running it in a separate process/user/cgroup is what keeps a flaw there away from the master key.

### 9.3 The edge config is Mooring-owned

There is **no raw Caddy-config editor** and no way for the operator to author Caddy config (file or portal) — the entire edge config is generated from typed structs / `mooring.yaml`, exactly as Docker/compose is (see [SBD-7](#5-the-secure-by-default-baseline-sbd-18)). This removes a whole risk class by construction. What remains is the unavoidable one: a route's *upstream hostname* is resolved by Caddy at runtime, and a hostname could in principle resolve to the control plane. That residual is contained by the structural controls of [§5.1](#51-the-structural-runtime-controls-the-real-backstop) — the pinned dialer that refuses loopback/metadata/control-plane ports *at dial time*, the unix-socket admin (no `:2019` to reach), and the egress firewall that makes the control plane physically unreachable from the edge — not by parse-time validation alone.

### 9.4 Other named residuals

- **Malicious compose / setup script** (the sharpest write-path risk) → contained by the §5.6 allowlist + the sandbox + capture-as-hostile-data.
- **Resource exhaustion on a small box** → the §0 resource gate (a safety property, not just performance).
- **Supply chain** (the child proxy binary, an L4 plugin build) → digest-pin + verify + an SBOM/scan cadence.
- **Backup footgun** → losing the key bricks all ciphertext; mitigated by `verify-key` + separate offsite backups of config (key) and DB.

---

## 10. The through-line (cross-cutting principles)

These ten principles are the spine the rest of the model hangs on:

1. **Fail closed, everywhere** — refuse to start on any precondition violation; never a silent degrade to a less-safe mode.
2. **The pipeline order *is* the security model** — allowlist-first on the unspoofable peer; belt-and-suspenders in managed mode; the XFF overwrite is never the sole anchor.
3. **Process & privilege isolation by default** — non-root; raw `docker.sock` never in Mooring; the edge is a separate process/user/cgroup; setup scripts run in a throwaway jail under a distinct uid.
4. **Two independent gates, two independent secret stores** — network + credential gates; the master key in the SSH-edited file only; SQLite holds only ciphertext; no web route touches auth/allowlist/key/bind.
5. **All external input is hostile; validation is an allowlist** — resolve `${VAR}` first; never `sh -c`; external data never reaches argv; app responses size-capped/schema-checked/escaped; outbound calls host-pinned and rebind-safe.
6. **The edge is core and secure-by-default; other capabilities are inert until enabled** — owning Caddy is the default (SBD-1..8); alerting and setup scripts are off by default with zero surface when off; the operator authors only `mooring.yaml` / the typed route model, never Caddy itself (the edge config is generated, like compose).
7. **The resource gate is a safety property** — write plane, builds, and the setup sandbox gated on ≥ 1 GB; per-plane memory caps; one-docker-child semaphore; no plane can OOM-kill the control plane.
8. **Everything privileged is audited and recoverable** — append-only events; the `Redacted` type; POST/no-store reveal; rehearsed key-rotation + one-command binary rollback.
9. **Safety by containment, not by assuming bug-freeness** — assume the binary *will* be exploited and make it survivable; §15 is a **recurring** gate.
10. **The `mooring.yaml` in your repo is the single source of truth for the app's shape; the dashboard is read-only for that** — services and edge/L4 routes are defined in the committed file and changed only by editing it and deploying. The dashboard manages the **operational** pieces, which it persists (encrypted where appropriate) and reconciles: **secret values** and **env** (the YAML declares secret names, never values), **config files** and **cert bindings** (per service; optionally seeded from the file), the **auto-scaling policy**, and **lifecycle actions** (deploy / restart / scale-now / queue pause-resume / clear self-heal circuit). Mooring's git access is **fetch-only** — it never pushes to your repo. Every path that reaches `docker compose` — dashboard deploy, CLI, or SSH — funnels through the *same* validator chokepoint; a new front-end is a new front *door*, never a new trust *path*.

---

## See also

- [README](../README.md) — what Mooring is and how to install it.
- [Configuration reference](./host-file.md#the-configyaml-reference) — every key in `config.yaml`, including `ip_allowlist`, `trusted_proxies`, and `edge.mode`.
- [Managed edge / Caddy](./edge-and-tls.md) — the typed, generated edge config and the route model.
- [Provisioning modes](./gitops.md) — the four input modes, the setup-script sandbox, and the git deploy fences.
- [Operations runbook](./architecture.md) — key rotation, backups, and the IR runbook.