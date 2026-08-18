# Running many apps on one server

A per-app definition describes one app. When you run several apps on a server, a few things belong to the **server**, not to any single app — shared alert channels, server-wide defaults, and the order apps should come up in. That's what the host file is for.

See also: [The `mooring.yaml` file](./definition-file.md) · [Installation](./installation.md)

---

## The host file

The host file (`kind: Host`) is an optional, server-level definition where you set:

- **Shared defaults** — values that apply to every app unless the app overrides them (for example, common labels or sensible resource defaults).
- **Which apps live on this server**, and the **order to deploy them** — so a database comes up before the app that depends on it.

A host file looks like this:

```yaml
apiVersion: mooring/v1
kind: Host
spec:
  # The registry of apps on this box (registering does NOT deploy — it just lists them).
  apps:
    - slug: db
      enabled: true
      source: { repo: "git@github.com:me/db.git", ref: "refs/heads/main" }
    - slug: web
      enabled: true
      source: { repo: "git@github.com:me/web.git", ref: "refs/heads/main" }
      # source can also be `{ path: /srv/app }` (a local checkout) or `{ managed: true }`.

  # Defaults projected beneath every app (the app's own value always wins). A default may
  # only TIGHTEN a posture, never silently widen one.
  defaults:
    scaling: { min: 1, max: 3 }   # a replica ceiling every app's scaling stays within
    self_healing: true            # supervise every app unless it opts out
    auto_deploy: false            # git auto-deploy off by default

  # Sequence a multi-app bring-up: deploy `web` only once `db` is healthy.
  orchestration:
    deploy_order:
      - { deploy: web, after: db }
    setup_order: [db, web]
```

Like the per-app file, the host file is the source of truth: you keep it in version control, and the dashboard reads it (it shows the deployed server settings, and is read-only for them).

## Where settings live (and what the dashboard can change)

Mooring keeps settings in three layers, by how sensitive they are:

1. **The root of trust** — your master key, the dashboard login, the IP allowlist, and the network address. These live in `config.yaml` and are set **over SSH at install**. The dashboard can **never** change them; they're set over SSH at install only.
2. **Server settings** — the host-wide defaults and coordination above.
3. **App settings** — everything about an individual app: its image, env, secrets, routes, scaling, and so on.

Layers 2 and 3 are defined in their definition files (the host file and each app's `mooring.yaml`); the dashboard reflects them read-only, except the operational things it deliberately owns — secret values, lifecycle actions, and the auto-scaling policy. Layer 1 stays SSH-only on purpose. Settings combine in order — a built-in default, then a server default, then the app's own value — with the most specific winning, and the same safety checks apply no matter which layer a value came from.

## The `config.yaml` reference

`config.yaml` (default `/etc/mooring/config.yaml`) is the **root of trust** — edited only over SSH, never by the dashboard. [Installation](./installation.md) walks through the essentials; this is the complete surface. Every block is optional except `encryption_key` and the `auth` block (and `edge.acme_email` in managed mode); sensible defaults apply to the rest.

```yaml
# --- Identity & network ---
bind_addr: "127.0.0.1:9000"          # loopback admin listener (default); the edge fronts public ports
encryption_key: "<base64 32 bytes>"  # REQUIRED — master key for encrypting secrets at rest
encryption_key_previous: ""          # set during a key rotation so old data still decrypts
data_dir: "/var/lib/mooring"         # where the database, git clones, and backups live
protected_projects: []               # compose projects Mooring must never start/stop (its own infra)

ip_allowlist: ["203.0.113.0/24"]     # CIDRs allowed to reach the dashboard (empty = only loopback/tunnel)
trust_proxy: false                   # honor X-Forwarded-For (only behind the managed edge / a trusted proxy)
trusted_proxies: []                  # in external-edge mode: the specific edge IP(s), ≤ /24

# --- Operators & roles (RBAC) ---
auth:                                 # the PRIMARY operator — always an owner
  username: "admin"
  password_hash: "<mooring hash-password>"
  totp_secret: "<mooring gen-totp>"   # optional 2FA
users:                                # ADDITIONAL operators (omit for single-user)
  - username: "deploy-bot"
    password_hash: "..."
    role: deployer                    # owner | deployer | viewer

# --- The edge (HTTPS / routing) ---  see docs/edge-and-tls.md for the full treatment
edge:
  mode: managed                       # managed (default) | external
  acme_email: "ops@example.com"       # REQUIRED in managed mode
  acme_ca: "https://acme-v02.api.letsencrypt.org/directory"
  base_domain: "example.com"          # optional: enables the `subdomain:` shorthand
  dns01: { provider: cloudflare, api_token: "..." }   # optional: one wildcard cert; module auto-installed
  base_domains: []                    # optional: additional NAMED namespaces (prod + staging on one box)
  cas: []                             # optional: private/internal ACME issuers to opt into by name
  apply_probe_window: 20s
  l4_enabled: false                   # managed TCP/UDP load balancer (child nginx); needs nginx on host
  l4_nginx_digest: ""                 # optional pinned nginx digest

# --- Exposing the dashboard through the edge (default: loopback-only) ---
admin:
  hostname: ""                        # e.g. admin.example.com — or use `subdomain` with edge.base_domain
  subdomain: ""                       # shorthand: <subdomain>.<edge.base_domain>
  edge_listen: "127.0.0.1:9001"       # internal listener the edge dials for the admin vhost

# --- Docker access (Mooring never touches the raw socket) ---
docker:
  proxy_addr: "127.0.0.1:2375"        # the read-only socket-proxy Mooring manages by default
  external_proxy: false               # true = you run your own proxy at proxy_addr

# --- Read plane & git polling ---
monitor:
  poll_interval: 10s                  # host/app metrics poll
  metrics_retention: 168h             # keep 7 days of metrics
git:
  poll_interval: 2m                   # auto-fetch connected repos (0 or negative disables)
github:                               # optional one-click "Connect with GitHub"
  client_id: ""
  client_secret: ""

# --- Sessions ---
session:
  idle_timeout: 10m                   # focused dashboard never idles out; abandoned one logs out
  absolute_timeout: 12h               # hard ceiling regardless of activity
cookie:
  prefix: "__Host-"                   # or "__Secure-" (pairs with base_path)

# --- Audit retention (never silently drops a security row) ---
retention:
  interval: 6h
  events_max_age: 8760h               # 365d (min 24h)
  events_max_rows: 200000
  archive_max_mb: 64

# --- Alerting (off by default) ---  see docs/alerting.md
alerting:
  enabled: false
  eval_interval: 30s
  notify_min_interval: 5s
  quiet_start_hour: -1                # -1 disables quiet hours (suppresses WARNING; CRITICAL always pages)
  quiet_end_hour: -1
  dead_mans_url: ""                   # outbound heartbeat to an external cron-monitor
  dead_mans_interval: 5m

# --- The Server tab (host inspection & upkeep) ---  see docs/server-tab.md
server:
  file_roots: []                      # [{name, path}] read-only browsable dirs (opt-in)
  deb_cache_dir: ""                   # absolute dir where you download .deb updates (enables cleanup)
  version_check_enabled: true         # self-update / security-advisory check (api.github.com only)
  version_check_interval: 6h
  image_scan_enabled: true            # Trivy vulnerability scanning (heavy — turn off on a tiny box)
  image_scan_interval: 24h
  disk_gc_enabled: true               # reclaim dangling images + build cache when disk is tight
  disk_gc_threshold: 75               # % disk usage that triggers it (50–95)
  build_cache_keep_enabled: true      # trim BuildKit cache after each build-deploy
  build_cache_keep: "5GB"             # how much recent cache to keep

# --- App-data backups (off by default) ---  see docs/backup-and-recovery.md
backups:
  enabled: false
  schedule: 24h                       # 1h floor
  retention: 7                        # snapshots kept per volume
  helper_image: "busybox:1.36"
  s3: null                            # optional off-box destination (bucket/endpoint/region/keys/…)

# --- Mode-3 setup-script sandbox (off by default, hard-gated) ---
setup:
  enabled: false
  image: "<digest-pinned jail image>"
  wall_clock: 5m
  cpus: "1.0"
  memory_mb: 512
  pids_limit: 256
  scratch_mb: 512
  output_cap_kb: 256

# --- Softening lints (default strict) ---
caddy_editor: { mode: strict }        # strict | review
compose_validation: { mode: strict }
```

> **Reload vs. restart.** Most of `config.yaml` — the allowlist, `auth`/`users`, alerting tuning, retention — is picked up by `systemctl reload mooring`. A few things are read only at boot and need a full `systemctl restart` (the GitHub credentials, the bind address, the encryption key). See [editing the config file](./installation.md#editing-the-config-file-reload-vs-restart).

## Acknowledging changes

If a setting that *broadens* what an app can do changes (say, opening a new route or raising a limit), Mooring surfaces it for you to acknowledge rather than applying it silently — so an unexpected change in a file you committed can't quietly take effect.
