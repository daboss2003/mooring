# `mooring.yaml` — Definition File Reference

The **definition file** (`mooring.yaml`) lives in your app's Git repo and is the **single source of truth** for the app. You describe your **stack** — one or more services, each either pulling an image or built from your repo, plus env, secrets (by reference), config files, cert bindings, edge routes, scaling, and GitOps behaviour — and **Mooring generates and owns the `docker-compose.yml` and the Dockerfile**. You never hand-write a compose file or a Dockerfile.

**To create an app you connect its repo.** There is no dashboard "New app" form; "New app" is the **connect-a-repo** flow. If the repo has no `mooring.yaml` yet, Mooring scaffolds a starter from the detected stack so the first deploy works — commit a real one when you want full control.

**The dashboard is read-only for the app's deploy-time shape.** A service's image/build, ports, volumes, depends_on, and the **edge & L4 routes** are read from this file — the dashboard *shows* them and you change them by editing `mooring.yaml` and deploying. The **operational** pieces stay editable in the dashboard (and config files, cert bindings, and scaling can also be declared here, where this file seeds them):

- **secret VALUES** (the env page; this file declares secret *names* only),
- **config files** and **cert bindings** (you can edit them in the dashboard; declaring them here is optional),
- the **auto-scaling policy** (operational tuning, set on the service page), and
- **lifecycle ACTIONS** (deploy / restart / scale-now / pause-resume the queue / clear a self-heal circuit).

Everything reaches the runtime through **one validator** — the same one whether you `mooring validate` in CI or deploy. Nothing in this file reaches `docker compose` unvalidated. Mooring's git access is **fetch-only**: it reads your repo at a pinned commit and **never pushes to it**.

> **See also:** [README](../README.md) · [Managed config files](./config-files-and-secrets.md) · [Cert bindings](./edge-and-tls.md) · [GitOps](./gitops.md) · [Managed edge & routes](./edge-and-tls.md) · [Secrets](./config-files-and-secrets.md) · [Auto-scaling](./scaling-and-self-healing.md) · [Self-healing](./scaling-and-self-healing.md) · [CLI reference](./cli.md)

---

## Table of contents

- [The envelope: `apiVersion` / `kind` / `metadata`](#the-envelope-apiversion--kind--metadata)
- [How parsing works (and what is rejected)](#how-parsing-works-and-what-is-rejected)
- [The `spec` sections](#the-spec-sections)
  - [`compose`](#speccompose)
  - [`setup`](#specsetup-an-advanced-setup-script)
  - [`secrets`](#specsecrets)
  - [`config_files`](#config_files-per-service)
  - [`secret_files`](#secret_files-per-service)
  - [`cert_bindings`](#cert_bindings-per-service)
  - [`edge.routes`](#specedgeroutes)
  - [`edge.l4_routes`](#specedgel4_routes-tcpudp-load-balancing)
  - [`scaling`](#specscaling)
  - [`self_healing`](#specself_healing)
  - [`ops_interface`](#specops_interface--servicesnameops_interface)
  - [`git`](#specgit)
- [The `{{hm.KEY}}` binding delimiter](#the-hmkey-binding-delimiter)
- [Secrets are by reference only](#secrets-are-by-reference-only)
- [How a change is applied](#how-a-change-is-applied)
- [Where your app's files live](#where-your-apps-files-live)
- [Worked example A — a multi-service stack (API + broker)](#worked-example-a--a-multi-service-stack-api--broker)
- [Worked example B — a stateless API](#worked-example-b--a-stateless-api)
- [Complete minimal example](#complete-minimal-example)
- [Field quick reference](#field-quick-reference)

---

## The envelope: `apiVersion` / `kind` / `metadata`

Every definition file is a Kubernetes-style envelope:

```yaml
apiVersion: mooring/v1     # exact-match, fail-closed
kind: App                   # an app definition (the host-level definition uses kind: Host)
metadata:
  slug: my-app              # immutable after the first deploy
spec:
  # ... the whole app — services, secrets, edge, scaling, … (see below)
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `apiVersion` | string | yes | **Must be exactly `mooring/v1`.** See the version gate below. |
| `kind` | string | yes | `App` for an app. The host-level definition (`host.yaml`) uses `kind: Host` — see [the host file](./host-file.md). |
| `metadata.slug` | string | yes | The app identity. `^[a-z][a-z0-9-]{1,30}$`. **Fixed at connect** — the slug is read from the file you connect and becomes the project/run-dir name and secret namespace key. It never changes afterwards: editing `metadata.slug` in the repo is **ignored** on later deploys (the connect-time slug always wins), so a repo can't rename or re-home an app — and can't hijack another app's slug. |
| `spec` | object | yes | The whole app: services, secrets, edge routes, scaling, self-healing, ops, and GitOps (see [The `spec` sections](#the-spec-sections)). |

> **One repo, several apps.** A repo can hold more than one mooring file — the plain `mooring.yaml` plus named variants like `mooring.staging.yaml` and `mooring.prod.yaml` — and **each file is deployed as its own app**, identified by its own `metadata.slug`. When you connect such a repo, Mooring lets you pick which file to deploy (the plain `mooring.yaml` is the default; variants are labelled by the text between `mooring.` and `.yaml`); connect again to add another. Give each variant a **distinct slug** (e.g. `myapp-staging`, `myapp-prod`). If you only ever have one `mooring.yaml`, nothing changes. See [Deploy from Git → Several apps from one repo](./gitops.md#several-apps-from-one-repo).

### The version gate is exact-match and fail-closed

`apiVersion` is matched **exactly**. There is no "best-effort parse of a future version," no minor-version tolerance, no forward-compat guessing:

- `mooring/v1` → accepted.
- `mooring/v2`, `mooring/v1beta1`, `v1`, `mooring/V1`, anything else → **hard reject at parse**.

**Why so strict (the honest trade-off):** a definition file is an input to a security-sensitive reconciler. A parser that *guesses* at an unknown schema is a parser-differential waiting to happen — the same bytes could mean different things to two versions, and that gap is where a key gets smuggled past validation. Exact-match means an old binary never half-understands a newer file, and a hand-typo never silently lands in a degraded interpretation. If you upgrade the schema, you upgrade the binary; the file says exactly which contract it speaks.

---

## How parsing works (and what is rejected)

`mooring.yaml` is the expected name. The loader also accepts `.yml` and `.toml`, but **all three normalize through one JSON intermediate** into a single typed definition before anything is validated. The format you author in is an input encoding; the typed model is what every validator and generator sees.

Hard rejections at parse time (fail-closed, every one is a stop, not a warning):

| Rejected | Why |
|---|---|
| **Unknown key**, anywhere | `DisallowUnknownFields` **plus** an independent JSON-Schema gate with `additionalProperties: false` at every level. A typo is an error, not an ignored field. |
| **YAML anchors / merge keys (`<<`)** | They are a classic way to make two parsers disagree. Banned. |
| **Duplicate keys** | A duplicate is a parser-differential vector. Hard reject. |
| **Implicitly-typed scalars that flip meaning** | Scalars are read as explicitly typed; a `yes`/`on`/`1` cannot quietly become a boolean. |
| Wrong `apiVersion` | See the version gate above. |
| A changed `metadata.slug` after connect | Ignored — the connect-time slug always wins (the app is never renamed or re-homed by an edit to the file). |

After a clean parse, `${VAR}` / `.env` interpolation is **resolved first** (validating before interpolation is a known bypass), then the typed structs fan out into the validators. **Nothing reaches `docker compose` before the validator has seen the fully-resolved bytes.**

---

## The `spec` sections

`spec` is the whole app. Each section below is read from this file and reflected (read-only) in the dashboard.

| Section | What it configures | Default if omitted |
|---|---|---|
| `compose` | your **stack** — the services Mooring generates the compose from | **required** |
| `setup` | an advanced per-app setup script | none |
| `secrets` | secret **names** (declared here; values are set out-of-band) | empty |
| `edge.routes` | public HTTPS routes (the managed edge) | empty (no public exposure) |
| `edge.l4_routes` | TCP/UDP stream listeners (the L4 load balancer) | empty |
| `scaling` | opt-in auto-scaling, one policy per service | disabled |
| `self_healing` | per-app tuning of the self-healing supervisor | built-in defaults |
| `ops_interface` | an ops endpoint Mooring probes for rich health/metrics | disabled |
| `git` | GitOps behaviour (repo, ref, auto-deploy) | `auto_deploy: false` |

Per-service, you also declare `env`, `secret_files`, `config_files`, `cert_bindings`, `volumes`, `ops_interface`, and (for built services) `build` — all under `compose.services`, below.

### `spec.compose`

Mooring **generates and owns** the compose — `source` is always `generated` (the default; the old
`repo_path`/`inline` sources are gone). You declare your services under `compose.services`, a **map
keyed by service name**.

```yaml
compose:
  source: generated          # the only value
  services:
    api:
      build: { language: auto }              # image XOR build
      ports: [{ internal: 3000 }]            # internal only — reach it via an edge route
      env:
        NODE_ENV: production                 # a literal (inline)
        DB_PASSWORD: { secret: DB_PASSWORD } # a reference (the value never touches the YAML)
      secret_files: [jwt_private_key]        # mounted as a file at /run/secrets/<name>
      depends_on: [emqx]
      healthcheck: [wget, -qO-, http://localhost:3000/health/live]   # exec form
      restart: unless-stopped
    emqx:
      image: emqx/emqx:5.8.3                 # XOR build
      ports:
        - { internal: 8883, publish: true, public: true }   # a public, non-HTTP TLS port
        - { internal: 18083 }                                # internal only
      config_files:
        - { repo: docker/emqx/emqx.conf, mount: /opt/emqx/etc/emqx.conf }
      volumes:
        - { name: emqx_data, target: /opt/emqx/data }
```

#### A service

| Field | Notes |
|---|---|
| `image` **XOR** `build` | pull a registry image, or have Mooring build it from your repo (below). Exactly one. |
| `ports` | a list of `{ internal, publish, public, protocol, published }`. `internal` is the container port; omit `publish` for internal-only (the usual case — expose it with an `edge` route). `publish: true` maps it to the host loopback; add `public: true` for all interfaces (e.g. a non-HTTP TLS port like MQTT). `protocol` is `tcp` (default) or `udp` — declare two entries to publish both on one port (e.g. DNS on 53). `published` is the **host** port (defaults to `internal`); set it to map a privileged host port to an unprivileged container port — see below. Control-plane ports (9000/2019/2375) are rejected; host ports 80/443 belong to the edge and are rejected too. |
| | **Binding privileged ports (<1024) without root:** Mooring runs containers as non-root, which can't bind ports like 53/853. Instead of running as root, let the container listen on a high port and map the privileged host port to it — Docker's (root) daemon does the privileged bind, your app stays non-root: `{ internal: 8853, published: 853, publish: true, public: true }` → clients reach `:853`, the resolver binds `8853`. |
| `env` | a **map**: `KEY: value` (a non-secret literal, rendered inline) or `KEY: { secret: NAME }` (a reference to a declared secret, resolved from the encrypted store at deploy — the value never touches the YAML). A literal containing `${…}` is rejected (use a secret reference). |
| `secret_files` | a list of declared secret names; each is written to a file and mounted at `/run/secrets/<name>` (the `*_FILE` pattern). |
| `config_files` | app config files Mooring renders and bind-mounts read-only — see [`config_files`](#specconfig_files). |
| `cert_bindings` | a managed cert synced into the service — see [`cert_bindings`](#speccert_bindings). |
| `volumes` | `{ name, target }` (a managed named volume) or `{ source, target, read_only }` (a bind under the app's directory; the directory is created for you). |
| `depends_on` / `healthcheck` / `command` / `restart` | sibling services / exec-array / exec-array / enum. |
| `mem_limit` / `mem_reservation` | optional cgroup memory cap / soft reservation per replica, as a size string (`768m`, `1g`). A limit hard-bounds each replica (per-container OOM protection) **and** makes the auto-scaler's `up_mem_pct`/`down_mem_pct` measure against *this* budget instead of the host's total RAM — i.e. a true per-service signal. Omit both to leave the container unbounded (the default). Size comfortably above measured RSS so the kernel doesn't OOM-kill it. |
| `stop_grace_period` | optional duration (`60s`, `1m30s`) the container gets between `SIGTERM` and `SIGKILL` on stop (scale-down / redeploy), widening docker's 10s default so the app can drain long in-flight requests. Pairs with the app's graceful-shutdown hooks. Omit for the default. |
| `ulimits` | optional per-container open-file limit — only `nofile: { soft, hard }` is supported. Raise it for a service holding many concurrent sockets, whose `max_connections` would otherwise be clamped by docker's default `nofile` of 1024 (e.g. an MQTT broker). `1 ≤ soft ≤ hard`; `hard` can't exceed the host kernel's `fs.nr_open` (commonly `1048576`) — higher needs a host `sysctl` (Mooring forbids in-container `sysctls`). Omit for the docker default. |

The dangerous keys (`privileged`, `cap_add`, host namespaces, host binds, host-publish) **cannot be
expressed** — no input can generate them, and the generated compose is re-checked by the validator
anyway.

#### `build:` — Mooring generates the Dockerfile

A `build:` service has no Dockerfile for you to write — you declare the build and Mooring generates a
hardened, non-root, multi-stage Dockerfile.

```yaml
build:
  language: auto         # auto (default, detect) | node | python | go | ruby | php | static | generic
  dir: services/api      # repo-relative subdir to build from (default "." — the repo root)
  version: "22"          # runtime version (a sane default is picked)
  install: npm ci        # dependency install (one line)
  build: npm run build   # build / compile (one line)
  start: [node, dist/main]   # how the container starts (exec form)
  env: { NODE_OPTIONS: "--max-old-space-size=1024" }   # build-time env
  packages: [git]        # extra OS packages
  run_as_nonroot: true   # default true
```

- `language: auto` (the default) detects the stack from the build dir's files (`package.json`,
  `go.mod`, `requirements.txt` / `pyproject.toml`, `Gemfile`, `composer.json`, `index.html`, …).
- `dir` builds from a **subdirectory** of the repo (a traversal-free, repo-relative path). Use it for a
  monorepo — e.g. a Go service in `dns-resolver/` of a Node repo: set `language: go` (or rely on
  auto-detect, which then reads `dns-resolver/`'s files) and `dir: dns-resolver`. Omit it to build the
  repo root (the default).
- For a stack Mooring doesn't recognise, use `language: generic` with your own `base:` image plus
  `install` / `build` / `start`.
- `install` / `build` run as build steps; each must be a single line (a newline is rejected so a value
  can't inject extra build steps). The build context is your repo checkout, confined to the app's
  directory.
- **Package manager** — Mooring picks it from the lockfile you committed, so you rarely set `install`:
  - **Node** (`language: node`): `pnpm-lock.yaml` → **pnpm** (provisioned via Corepack), `yarn.lock` →
    **yarn** (Yarn Berry when a `.yarnrc.yml` sits beside it — installed with `--immutable`, else
    classic v1), otherwise **npm**. It installs with a frozen lockfile and, for a Node *server*, strips
    devDependencies from the shipped image (`pnpm prune --prod` / `yarn install --production` /
    `npm prune --omit=dev`). The same detection drives a **`static`** SPA's build stage (its
    `node_modules` is discarded — only the built output dir ships).
  - **Python** (`language: python`): `poetry.lock` → **poetry**, a `Pipfile` → **pipenv**, otherwise
    **pip**. poetry/pipenv install the project's *production* dependencies into the system interpreter.
  - Go (modules), Ruby (bundler), and PHP (composer) each have one mainstream tool, so there's nothing
    to choose.
  - Set `install:` explicitly to override the default command (e.g. a workspace filter, or a manager
    with no committed lockfile). A Yarn Berry app on the **PnP** linker generally also needs a custom
    `start` (e.g. `yarn node …`); switching Berry to `nodeLinker: node-modules` avoids that.

### `spec.setup` (an advanced setup script)

A per-app setup script — **declared here**, never typed into the dashboard (the dashboard shows it
read-only and runs it behind a confirmation).

```yaml
setup:
  script: |
    #!/bin/sh
    # one-off bootstrap …
  trigger: on_first_deploy   # never (default) | on_demand | on_first_deploy | before_each_deploy
  produces: [env:NODE_COOKIE, file:certs/internal.pem]
```

- It runs **only** from an operator-initiated, confirmed deploy — never from a webhook, a fetch,
  auto-deploy, or boot.
- `trigger: on_first_deploy` / `before_each_deploy` together with `git.auto_deploy: true` is rejected.
- Its declared outputs land only in this app's own namespace.

> Bringing an existing `.env`? See [env-import.md](./env-import.md). Server-wide settings across apps
> live in the host definition: [host-file.md](./host-file.md).

### `spec.secrets`

Declares secret **names** (and an optional generate hint). **It never contains values.** This is what keeps the whole file non-secret-bearing and safe to commit to a public repo.

```yaml
secrets:
  - name: MONGODB_URI                # you provide the value out-of-band
  - name: WEBHOOK_SECRET
    generate: hex:32                 # Mooring mints this once, on first deploy
  - name: EMQX_DASHBOARD_PASSWORD
    generate: base64:24
  - name: JWT_KEY
    generate: rsa:2048              # also mints JWT_KEY_PUB (the derived public key)
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `name` | string | required | The secret's name within **this app's** namespace. |
| `generate` | string | — | Auto-mint the value on first deploy (see below). Omit it and you provide the value yourself. |

A secret you don't `generate` is set out-of-band — `mooring secret import` (from a `.env`) or the dashboard. The file holds **names only**, never values, which is what keeps it safe to commit.

#### Auto-generating a secret

Declaring `generate` is the declarative replacement for a bootstrap script's `openssl rand` / `openssl genrsa` lines: Mooring mints the value **server-side on the first deploy where it's missing**, stores it encrypted, and never displays it.

| `generate` | Produces |
|---|---|
| `hex:N` | N random bytes, hex-encoded (`N` 16–1024) |
| `base64:N` | N random bytes, base64 (`N` 16–1024) |
| `password:N` | an `N`-char password from an unambiguous alphabet (`N` 16–256) |
| `rsa:2048` \| `rsa:3072` \| `rsa:4096` | an RSA private key (PEM) **plus** the derived public key |
| `ed25519` | an Ed25519 private key (PEM) **plus** the derived public key |

- **Idempotent.** Minted only when no value exists yet; a later deploy **never rotates a live secret**. (Set the value yourself before the first deploy and Mooring won't generate one.)
- **Keypairs** mint *two* secrets: the private key under `<name>` and the public key under `<name>_PUB`. They're PEM, so consume them as files via [`secret_files`](#config_files-per-service), not as `env` values.
- **Never displayed** — like any secret, the value only ever leaves via the audited reveal endpoint.

This replaces the whole `create_random_secret` / `create_jwt_keys` section of a hand-written setup script.

### `config_files` (per service)

An app config file Mooring renders and bind-mounts **read-only** into a service — declared **on the
service** (e.g. an `emqx.conf`, an nginx snippet, a prometheus config). The content comes from a path
in your repo (read at the pinned commit) **or** an inline body. Mooring writes the file under the
app's own directory and mounts it; you never place it yourself.

```yaml
services:
  emqx:
    image: emqx/emqx:5.8.3
    config_files:
      - repo: docker/emqx/emqx.conf      # a path in your repo (read at the pinned commit), XOR template:
        mount: /opt/emqx/etc/emqx.conf   # bind-mounted read-only here
      - template: |                      # an inline body
          level = info
        mount: /etc/app/app.conf
```

The file is re-rendered on every deploy (written `0600` if it resolved a secret, else `0640`). To inject
a value, add a `bindings` allowlist and reference it with `{{hm.KEY}}`; your app's own `${…}` survive
byte-identical:

```yaml
config_files:
  - template: |
      api_key       = {{hm.API_KEY}}
      upstream      = {{hm.UP}}
      server_name   = {{hm.HOST}}
      ssl_cert      = {{hm.CRT}}
    mount: /opt/emqx/etc/app.conf
    bindings:
      API_KEY: { secret: emqx_api_password }    # a declared secret (value never in this file)
      UP:      { env: UPSTREAM }                 # this service's env value
      HOST:    { app: slug }                     # a safe app field
      CRT:     { cert: mqtt.example.com.crt }    # a same-service cert_binding's tls.crt path
```

| Field | Notes |
|---|---|
| `repo` **XOR** `template` | content from a repo path (read at the pinned commit) or an inline body |
| `mount` | absolute container path; bind-mounted **read-only** |
| `bindings` | allowlist of `{{hm.KEY}}` tokens. Each is a scalar **literal**, or exactly one of `{secret: NAME}` (a declared secret — marks the file secret-bearing), `{env: NAME}` (this service's env value), `{app: slug}`, or `{cert: HOSTNAME.crt\|key\|ca}` (the container path of a `cert_binding` **on the same service**). Unknown tokens fail closed. |

### `secret_files` (per service)

Mount declared secrets as files (the `*_FILE` pattern). Each name must be a declared `spec.secrets`
entry; Mooring writes its value `0600` under the app's directory and mounts it at
`/run/secrets/<name>`.

```yaml
services:
  api:
    image: ghcr.io/acme/api:1
    secret_files: [jwt_private_key, mongodb_uri]   # → /run/secrets/jwt_private_key, …
```

### `cert_bindings` (per service)

Sync a managed cert (issued + renewed by Mooring's edge) into a service — so a broker like EMQX can
terminate its own TLS without you running a cert-reload sidecar. Declared on the service.

```yaml
services:
  emqx:
    image: emqx/emqx:5.8.3
    cert_bindings:
      - hostname: mqtt.example.com    # a hostname Mooring's edge issues a cert for
        mount: /etc/certs             # the cert is synced into this directory
        ca: internal                  # optional: issue from a private CA (config.yaml edge.cas)
```

| Field | Notes |
|---|---|
| `hostname` | the FQDN Mooring issues/renews the cert for. **Or** use `subdomain` (below). |
| `subdomain` | **Instead of `hostname`** (exactly one): a single DNS label expanded to `<subdomain>.<edge.base_domain>` (needs `edge.base_domain` in `config.yaml`). Same [subdomain shorthand](#specedgeroutes) as edge routes. |
| `mount` | absolute container path the cert directory is mounted at. |
| `ca` | optional — name of a **private CA** (defined in `config.yaml` [`edge.cas`](#using-a-private-ca)) to issue this cert from, instead of the default `edge.acme_ca`. An undefined name fails the deploy. Omit it for the default CA. Ideal for an internal MQTT/DB host issued by your own CA. |

Mooring's edge issues and renews the certificate for `hostname`, then **at deploy** syncs the files into `mount` as `tls.crt` (0644) and `tls.key` (0600) and recreates the service so it loads them. The deploy **waits automatically** until they exist (it fails fast with a reason if the cert can't issue), so the container never has to poll. Your app reads the files straight from `mount` — there are no cert template tokens.

> **Renewal is autonomous.** The edge auto-renews the leaf (~30 days before expiry), and a background watcher re-syncs the new leaf into `mount` and **recreates the affected service** so it loads it — no manual redeploy. The recreate briefly bounces that one service; it's suppressed from self-healing while it happens. See [Cert bindings](./edge-and-tls.md).

### `spec.edge.routes`

**Layer-1 input only** to the managed edge (§6). Each entry becomes one `app_routes` row, re-rendered into the *whole* proxy document declaratively.

```yaml
edge:
  routes:
    - hostname: api.example.com
      service: api             # the service in THIS app's compose to route to — never a literal host:port
      port: 3000               # its internal container port
      path_prefix: /
      redirect_http: true
      hsts: true
```

> A cert-only hostname (the edge issues and renews the certificate but proxies no traffic) is **not** a route — declare it with [`cert_bindings`](#speccert_bindings) on the service that consumes the cert.

> **Subdomain shorthand — one DNS record for everything.** Set a namespace root once in
> `config.yaml` (`edge.base_domain: mooring.example.com` — the label is yours; use
> `myserver.example.com`, or even the bare `example.com`). Then a route or `cert_binding` can
> give **`subdomain: mqtt`** instead of a full `hostname:`, and Mooring expands it to
> `mqtt.mooring.example.com`. Point a **single wildcard DNS record** at your server
> (`*.mooring.example.com  A  <server IP>`) and every declared subdomain resolves — no per-app
> DNS. `subdomain:` and `hostname:` are mutually exclusive (use exactly one); a `subdomain`
> must be a single DNS label (`[a-z0-9-]`, no dots). Undeclared names still get **no** cert and
> **no** route, so the wildcard record exposes nothing extra.
>
> ```yaml
> edge:
>   routes:
>     - subdomain: api          # → api.<edge.base_domain>
>       service: api
>       port: 3000
> ```

#### `spec.edge.base_domain` (namespaces)

Running more than one app on a single server (e.g. **prod + staging on one box**)? Declare **named** namespaces in `config.yaml` and let each app pick one by name — so both can keep the `subdomain:` shorthand without colliding on `UNIQUE(hostname)`:

```yaml
# config.yaml  (operator, SSH-only — the root of trust)
edge:
  base_domain: prod.example.com          # the DEFAULT (unnamed) namespace — unchanged
  base_domains:                          # additional NAMED namespaces
    - name: staging
      domain: staging.example.com
      # dns01: { provider: cloudflare, api_token: … }   # optional per-namespace wildcard cert
```

```yaml
# mooring.staging.yaml  (the app)
spec:
  edge:
    base_domain: staging      # a NAME from config.yaml edge.base_domains — NOT an FQDN
    routes:
      - subdomain: api        # → api.staging.example.com  (still the shorthand, no full domain)
        service: api
        port: 3000
```

- `spec.edge.base_domain` sets the namespace for **every** `subdomain:` in the app; `""` (omitted) means the default `edge.base_domain`. A single route or `cert_binding` may override it with its own `base_domain: <name>` (only meaningful alongside a `subdomain:`).
- It is a **name the operator declared**, never an apex the app can invent — an **undeclared name fails the deploy** (fail-closed, exactly like a subdomain with no `base_domain` configured).
- Each namespace has its own `*.<domain>` wildcard DNS record; add `dns01` to a namespace and it gets its **own** wildcard cert (so `subdomain:` names under it are HTTPS with no per-name issuance). Namespaces must be **disjoint apexes** (Mooring rejects overlapping/nested domains).
- The **admin dashboard** always lives under the default `edge.base_domain` (not a named namespace).
- Omit `base_domains` entirely and the single `edge.base_domain` is your only namespace — nothing changes.

| Field | Type | Default | Notes |
|---|---|---|---|
| `hostname` | string | required *(or `subdomain`)* | The public vhost (a full FQDN). Subject to the §6.2 conflict gate: it may not shadow a managed hostname, the admin vhost, a cert-only hostname, or an auto-scaled pool. |
| `base_domain` | string | — | **(with `subdomain` only)** The namespace **name** (from `config.yaml` `edge.base_domains`) to expand this route's subdomain under; overrides `spec.edge.base_domain`. See [namespaces](#specedgebase_domain-namespaces). |
| `subdomain` | string | — | **Instead of `hostname`** (exactly one of the two): a single DNS label expanded to `<subdomain>.<edge.base_domain>`. Needs `edge.base_domain` set in `config.yaml`. See [Subdomain shorthand](#specedgeroutes) above. |
| `service` | string | required (proxy routes) | The service **in this app's compose** to route to — resolved against this app's discovered containers, never a literal host:port. Cross-project names are rejected; the pinned-dialer + egress-firewall refuse any resolution to a control-plane port (`9000/2019/2375`), loopback, or metadata. |
| `port` | int | required (proxy routes) | The service's internal container port to forward to. |
| `upstream_scheme` | `http` \| `https` | `http` | How the edge dials the upstream (use `https` only if the container itself terminates TLS). |
| `path_prefix` | string | `/` | Combined with hostname for `UNIQUE(hostname, path_prefix)`. |
| `redirect_http` | bool | `true` | HTTP→HTTPS redirect. |
| `hsts` | bool | per-edge | HSTS is only emitted **after** a cert exists. |
| `security_headers` | bool | per-edge | Emit the baseline security-header set for this vhost. |
| `ca` | string | default issuer | Name of a **private CA** to issue this route's cert from, instead of the default `edge.acme_ca`. The CA must be defined in the operator's `config.yaml` under [`edge.cas`](#using-a-private-ca) — referencing an undefined name fails the deploy. Omit it and the route uses the default CA (Let's Encrypt, typically), exactly as before. |

(Need the edge to issue a certificate for a hostname it shouldn't proxy — a broker that terminates its own TLS, say? That's a [`cert_binding`](#speccert_bindings), not a route.)

#### Using a private CA

The default issuer is `edge.acme_ca` in the operator's `config.yaml`. To issue *some* hostnames from a private/internal CA (e.g. [`step-ca`](https://smallstep.com/docs/step-ca/)) while the rest keep using the default, the operator defines named CAs in `config.yaml` (the root of trust — an app repo can never introduce a trusted CA):

```yaml
# /etc/mooring/config.yaml
edge:
  acme_ca: https://acme-v02.api.letsencrypt.org/directory   # the default
  cas:
    - name: internal
      directory_url: https://ca.lan/acme/acme/directory
      email: pki@lan                 # optional; falls back to acme_email
      trusted_root: /etc/mooring/internal-ca.pem   # optional: a PEM Caddy trusts for the CA's own HTTPS
```

Then in any app's `mooring.yaml`, point a route (or a [`cert_binding`](#cert_bindings-per-service)) at it by name with `ca: internal`. Each CA gets its own ACME issuer; everything without a `ca` keeps using the default. So you can have, say, `mqtt.lan` (a cert binding) and `api.lan` (a route) issued by your internal CA, while your public hostnames stay on Let's Encrypt — all from the same dashboard/deploy.

The `edge.routes` block is **parsed into the typed edge model and re-marshalled** (read-and-render, never run verbatim). The save fails if it shadows a managed hostname, touches `admin`/`tls.automation`/`pki`, targets `9000/2019/2375`, grabs `:80/:443`, or weakens XFF. **The definition file contributes only Layer-1 routes** — never the protected Layer-0 base. See [Managed edge & routes](./edge-and-tls.md).

### `spec.edge.l4_routes` (TCP/UDP load balancing)

The HTTP edge fronts `edge.routes`. For a **non-HTTP** stream service — DNS (53), DoT (853), MQTTS (8883) — an `l4_route` makes Mooring's L4 load balancer own the public port and fan traffic across the service's **internal** replicas. That's what lets a fixed-port service be **auto-scaled**: it stops publishing a host port (the LB owns it), so it passes scaling candidacy as an "L4 upstream" instead of being disqualified for grabbing a host port.

```yaml
spec:
  compose:
    source: generated
    services:
      coredns:
        build: { language: go, dir: dns-resolver }
        ports:
          - { internal: 5353 }            # internal-only — the L4 LB owns the public port
  edge:
    l4_routes:
      - { listen: 53,  protocol: udp, service: coredns, port: 5353, lb: hash_client_ip }
      - { listen: 53,  protocol: tcp, service: coredns, port: 5353 }
      - { listen: 853, protocol: tcp, service: coredns, port: 5353, tls: passthrough }
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `listen` | int | required | The **host** port the L4 LB binds. Not `80`/`443` (the HTTP edge's) or a control port (`9000/2019/2375`). A `listen+protocol` is globally unique — two apps can't claim it. |
| `protocol` | `tcp` \| `udp` | required | Declare two entries to serve both on one port (DNS). |
| `service` | string | required | The service whose replicas receive traffic — a selector, resolved to this app's containers, never a literal host:port. |
| `port` | int | required | The service's **internal** container port. |
| `lb` | enum | `round_robin` | `round_robin` \| `least_conn` \| `hash_client_ip` (client-IP affinity — useful for DNS/MQTT). |
| `tls` | enum | `passthrough` | `passthrough` only for now — the LB forwards raw bytes and the **app** terminates TLS (issue its cert with a [`cert_binding`](#speccert_bindings)). `terminate` is not yet supported. |

> **Prerequisites (the L4 LB is opt-in and not bundled):**
> 1. Install **nginx + its stream module** on the host yourself — on Debian/Ubuntu `sudo apt install nginx libnginx-mod-stream` (the `stream` module is a *separate* package there). Mooring's generated config already `include`s `/etc/nginx/modules-enabled/*.conf` so the module loads, but the package must be present or nginx rejects the config with `unknown directive "stream"`. Mooring does **not** ship or pull nginx; it's only needed for L4 routes.
> 2. Set `edge.l4_enabled: true` in `config.yaml`, then **restart** Mooring (`sudo systemctl restart mooring`) — edge settings are read at startup, so a reload won't pick this up ([reload vs restart](./installation.md#editing-the-config-file-reload-vs-restart)).
> 3. Binding privileged ports (53/853) needs `CAP_NET_BIND_SERVICE` — the shipped unit **already grants it** (the supervised nginx inherits it), so there's nothing to do. (Or map a privileged host port to a high container port and keep the service unprivileged.)
> 4. **If you bind `:53` (DNS): free it from `systemd-resolved` first.** On a default systemd host the `systemd-resolved` stub listener already holds `127.0.0.53:53` (and `127.0.0.54:53` on systemd ≥ 249). The supervised nginx binds the wildcard `0.0.0.0:53`, which collides with that bind → nginx fails to start (`address already in use`) and the L4 reconcile fails closed. Disable the stub listener, then keep host DNS working by pointing `resolv.conf` at the real upstreams (not the now-dead stub):
>    ```bash
>    printf '[Resolve]\nDNSStubListener=no\n' | sudo tee /etc/systemd/resolved.conf.d/no-stub.conf
>    sudo systemctl restart systemd-resolved
>    sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf   # the real upstreams — NOT stub-resolv.conf
>    ```
>    `systemd-resolved` keeps running (it's still your resolver and still maintains that `resolv.conf`) — only its `:53` listener is gone, so **don't** stop/disable the service itself. Verify before deploying: `sudo ss -ulpnH 'sport = :53'` and `sudo ss -tlpnH 'sport = :53'` print nothing, and `getent hosts github.com` still resolves.
>
> With those in place, a deploy persists the routes, renders the nginx-stream config, and reloads it. Without them (`l4_enabled` off, or non-Linux/no nginx) `l4_routes` validate but the LB simply isn't started — fail-closed, no effect on the rest of the deploy.

### `spec.scaling`

Process-level auto-scaling of a stateless service's replica count (§8A). **Opt-in.** It's a **list** — one policy per service — so you can scale several services in one app (e.g. an HTTP `api` *and* an L4 `resolver`). Each must pass scaling candidacy (HTTP edge upstream **or** L4 upstream, stateless, no fixed host port, no RW volume).

```yaml
scaling:
  - service: api               # an HTTP service behind an edge.route
    enabled: true
    min: 1
    max: 5
    up_cpu_pct: 70             # scale up above this sustained CPU %
    down_cpu_pct: 30           # scale down below this (≥20-pt gap from up)
    per_replica_mem_mib: 256   # per-replica memory reservation; feeds the host-capacity guard
  - service: resolver          # a non-HTTP service fronted by an edge.l4_route
    enabled: true
    min: 1
    max: 4
    up_cpu_pct: 65
    down_cpu_pct: 25
    per_replica_mem_mib: 96
```

A deploy persists each policy (unset thresholds default to 80/40, with a positive breach window + down-lazy cooldowns); a policy that violates the controller contract (e.g. a <20-pt dead band) blocks the deploy. Omitted services are left as-is. Scaling a **non-HTTP** service additionally needs an [`l4_route`](#specedgel4_routes-tcpudp-load-balancing) + nginx (see that section).

> **Auto-scaling is a dashboard exception.** Unlike the rest of the structure, the scaling policy is **operational tuning you can also set on the service page** (a thresholds/min/max form) so you can react without a redeploy. The policy you author here is the starting point; what's live is whatever was last set. To capture the current policy back into your repo, download the deployed definition from the app page (`GET /apps/<slug>/definition.yaml`) and commit it — Mooring never writes to your repo.

| Field (per list entry) | Type | Default | Notes |
|---|---|---|---|
| `service` | string | required | The service this policy scales — must exist, be unique across entries, and pass the **candidacy gate** (edge HTTP **or** L4 upstream, no fixed host port, no exclusive RW volume, not stateful/clustered, stateless restart contract). **Stateful services — databases, brokers — are rejected with a clear reason.** |
| `enabled` | bool | `false` | Opt-in. |
| `min` / `max` | int | `1`/`1` | Replica bounds. On a small box `effective_max` **collapses to 1** — scaling becomes a permanent safe no-op and a wanted scale-up fires `scale_refused_no_capacity` rather than queuing a docker child. |
| `up_cpu_pct` / `down_cpu_pct` | float | — | Scale up above / down below this sustained CPU %. Hysteresis is up-eager / down-lazy with a dead band between them. |
| `up_mem_pct` / `down_mem_pct` | float | — | Optional memory triggers, with the same hysteresis. The percentage is RSS ÷ the container's memory limit — so set the service's [`mem_limit`](#a-service) for a true per-service signal; without one, the kernel reports the limit as the host's total RAM and the trigger is box-relative. |
| `per_replica_mem_mib` | int | — | Per-replica memory reservation (MiB). Feeds the host-capacity guard; if a replica's real RSS exceeds it, Mooring clamps and alerts. |
| `per_replica_cpu_milli` | int | — | Optional per-replica CPU reservation (millicores). |

> Authoring `scaling` for a stateful service is not a knob you can force — it is rejected at candidacy. Brokers/DBs are precisely the `config_files` / `cert_binding` apps of §7.4, not scaling candidates. See [Auto-scaling](./scaling-and-self-healing.md).

#### Custom scaling signals (`metrics`)

CPU and memory aren't always the load that matters. A worker's real backlog is its **queue depth**; an I/O-bound API can sit at low CPU while its **latency** climbs. Add `metrics` to a scaling policy to scale on those directly — **in addition** to CPU/mem (they still apply). Each metric scales **up** when its value is at or above `up` and **permits scale-down** below `down` (`up` must be above `down` — the per-signal dead band). Scale-down stays **conjunctive**: a service scales down only when CPU **and** memory **and** every custom metric are all below their down thresholds and it's healthy, so a busy signal alone keeps capacity up.

```yaml
scaling:
  - service: api
    enabled: true
    min: 1
    max: 8
    up_cpu_pct: 80             # CPU still applies…
    down_cpu_pct: 40
    per_replica_mem_mib: 256
    metrics:
      - name: latency          # …but this API is I/O-bound — scale on p95 latency
        source: edge           # MEASURED by Mooring's edge (the app can't fake it)
        select: p95_latency_ms
        up: 800                # add a replica when p95 ≥ 800 ms
        down: 300              # allow shrinking when p95 < 300 ms
  - service: worker
    enabled: true
    min: 1
    max: 10
    up_cpu_pct: 85
    down_cpu_pct: 30
    per_replica_mem_mib: 128
    metrics:
      - name: backlog          # a queue worker — scale on jobs waiting
        source: ops            # read from the service's ops interface
        select: ""             # "" = the whole backlog (pending counters, minus lifetime totals)
        up: 100                # target ~100 queued jobs per replica
        down: 20
```

| Field | Type | Notes |
|---|---|---|
| `name` | string | Signal name (unique within the service), `[a-z0-9_-]`. |
| `source` | string | `ops` — a per-service number from the app's [ops interface](./app-ops-interface.md); or `edge` — latency / request-rate **measured by Mooring's own edge** (the app can't self-report fake numbers; it reflects real traffic). |
| `select` | string | **`source: ops`** — `""` sums the **backlog** (pending counters across every queue, **excluding** cumulative lifetime totals like `completed`/`failed` so a monotonic counter can't cause a runaway), or a **queue/counter name** to track just that. **`source: edge`** — `p95_latency_ms` (service p95 request latency) or `req_per_sec` (request rate). |
| `up` / `down` | float | Scale up at/above `up`; permit scale-down below `down`. |

**Per-replica for totals.** A service-**total** signal (queue depth, `req_per_sec`) is divided by the running replica count before comparison, so `up` is the target **per replica** — set `up: 100` and Mooring tracks toward ~100 queued jobs each. `p95_latency_ms` is an absolute service latency (adding replicas lowers it), so it's compared as-is.

**`source: edge` needs the managed edge.** The signal comes from the edge's own per-request measurements — it only produces data for a service fronted by an [`edge.route`](#specedgeroutes) on Mooring's [managed edge](./edge-and-tls.md). Turn a metric on and the edge starts measuring within one reconcile (~15 s) — no restart. On a server that **doesn't** run the managed edge, an `edge` metric is simply **ignored** (it never affects scaling). When the edge is delivering logs but a service has no recent traffic, that reads as **idle** so it still scales down; while the edge is *not yet* delivering logs (just enabled, or a capture hiccup) the metric **holds** rather than guessing — Mooring never sheds a service it can't currently measure.

> **It measures real traffic.** Like any latency- or rate-based autoscaling, an `edge` signal reflects whatever requests reach the edge — a flood of cheap requests can move p95 or the rate. The app can't *fabricate* the numbers (Mooring measures them, not the app), but they aren't a security boundary; pair sensible `up`/`down` thresholds with the CPU/mem triggers, which always apply.

> **Why this exists.** A common failure: an API that's slow because it waits on a database or an upstream sits at ~20 % CPU, so CPU-based scaling never fires while requests pile up. `source: edge` + `p95_latency_ms` scales on the symptom that actually matters.

### `spec.scheduled_tasks` (cron jobs)

Run a service's command on an interval — a nightly database cleanup, a periodic report, a cache warm. Each task points at a **declared service whose `command:` is the job**. That service becomes **scheduled-only**: Mooring generates it into the compose but gives it a profile so `up` never starts it as a long-running container. On each interval Mooring runs it as a **fresh one-shot** `docker compose run --rm` container that removes itself when the command exits — never an exec into a running container, and never a shell. The one-shot gets the app's environment, secrets, and network, so it can reach the app's database by service name.

```yaml
spec:
  compose:
    services:
      web:
        image: ghcr.io/acme/web:1.4
      cleanup:                       # a scheduled-only service (not started by `up`)
        image: ghcr.io/acme/web:1.4  # usually the app's own image, to run its code
        command: ["python", "manage.py", "cleanup"]
  scheduled_tasks:
    - name: nightly-cleanup
      service: cleanup
      every: 24h                     # interval (e.g. 24h, 15m, 1h30m); floored at 1m
      timeout: 1h                    # optional max run time; default 30m, floored at 1m, capped at 24h
```

Notes:

- The task's **command is the service's `command:`** (a fresh container runs it), so give the scheduled service the exact command you want to run.
- **`timeout`** caps a single run. It defaults to **30 minutes**; set it higher for a long batch job (e.g. `timeout: 4h`) or lower to fail fast. A task holds the single docker slot for its whole run, so a very long timeout can make a stuck task block deploys until it hits the cap — that's why it's ceilinged at 24h. When a run hits the timeout it's killed and recorded as timed-out.
- A scheduled service **can't also be an auto-scaling target** (a one-shot doesn't scale) — that's rejected at validation.
- Runs ride the same one-docker-child slot as deploys and **skip** (retry next interval) when a deploy is in progress, so a task never delays a deploy. A failed task raises an alert; the last run is remembered across restarts (a restart doesn't re-fire everything).
- **See what ran:** the dashboard's **[Scheduled tasks](./scheduled-tasks.md)** tab shows what's running right now (with live CPU/memory and the owning app), plus the recent run history with results and captured logs (kept 7 days).

### `spec.self_healing`

Per-app tuning of the self-healing supervisor (§8.5). Every service is supervised with a conservative built-in default; this block overrides the ladder tunables for **this app**. **Every field is optional** — an omitted field keeps the built-in default, and an omitted block leaves the app entirely on the default. All durations are seconds.

```yaml
self_healing:
  sustain_ticks: 3          # failing ticks before the first remediation (anti-flap)
  attempt_cap: 5            # remediations per window before the circuit opens
  window_seconds: 1800      # attempt-window length; attempts reset after it elapses
  backoff_base_secs: 30     # exponential backoff base between attempts
  backoff_max_secs: 600     # backoff ceiling (>= base)
  redeploy_enabled: false   # allow rung-3 redeploy (>=1 GB host AND this opt-in)
```

| Field | Type | Notes |
|---|---|---|
| `sustain_ticks` | int | Failing ticks before the first remediation. |
| `attempt_cap` | int | Remediations per window before the circuit latches open. |
| `stabilize_ticks` | int | Healthy ticks required to declare RECOVERED. |
| `oom_strike_cap` | int | OOM-classified failures before short-circuiting the ladder. |
| `window_seconds` | int | Attempt-window length (attempts reset after it). |
| `backoff_base_secs` / `backoff_max_secs` | int | Exponential backoff base/ceiling between attempts (`max >= base`). |
| `redeploy_enabled` | bool | Opt in to the rung-3 redeploy (still gated on host headroom). |

> Self-healing has no separate dashboard editor — `mooring.yaml` is the source of truth. The supervisor reads the policy each tick, so a redeploy re-tunes it without a restart. See [Self-healing](./scaling-and-self-healing.md).

### `spec.ops_interface` / `services.<name>.ops_interface`

An optional **ops endpoint** (§4) Mooring probes for RICH health, queues, and open-ended **metric cards** (database, cache, routes, system, …). It can be set **per service** under `services.<name>.ops_interface` (recommended — each service gets its own rich view on its page) or app-level under `spec.ops_interface`. Everything here is operator config **except the shared-secret value** — set the value in the dashboard, or declare a secret and point `secret` at it; the value **never** lives in this file.

> **Full contract + JSON examples (health, queues, metrics): [App Ops Interface](./app-ops-interface.md).**

```yaml
ops_interface:
  enabled: true
  base_url: http://web:8080          # the in-cluster endpoint (origin only; never loopback)
  base_path: /ops                    # relative prefix under base_url
  secret_header: X-Ops-Secret        # header the probe sends the shared secret in
  secret: OPS_SECRET                 # reference to a declared secret (value resolved at deploy)
  mode: rich                         # auto | rich | basic
```

| Field | Type | Notes |
|---|---|---|
| `enabled` | bool | Turn probing on. When on, `base_url` must be a valid pinned origin. |
| `base_url` | string | `scheme://host[:port]` only — **no path**, never loopback (the §4.1 SSRF pin). |
| `base_path` | string | Relative prefix (e.g. `/ops`). |
| `secret_header` | string | The header name the probe sends the secret in (e.g. `X-Ops-Secret`). |
| `secret` | string | A **reference** to a declared `spec.secrets` name; its value is resolved at deploy and never stored here. Omit to keep a dashboard-set value. |
| `mode` | enum | `auto` (default) \| `rich` \| `basic`. |
| `adapter` | string | Response adapter (default `ops.v1`). |

> **The structure is read from this file; only the shared-secret VALUE is a dashboard input.** Set the secret value on the env page (or declare a secret and point `secret` at it). The endpoint, paths, headers, and mode come from `mooring.yaml`.

### `spec.git`

The GitOps fields. **Fetch is automatic (read-plane); deploy is manual (write-plane, sha-pinned).** Mooring's git access is **fetch-only — it never pushes to your repo.** `auto_deploy` defaults to **false**.

```yaml
git:
  repo: https://github.com/acme/app.git   # optional; usually set by the connect-a-repo flow
  ref: refs/heads/main                      # fully-qualified; the webhook never reads ref/sha from its payload
  auto_deploy: false                        # default false; opt-in only auto-clicks the SAME gated promote path
```

| Field | Type | Default | Notes |
|---|---|---|---|
| `repo` | string | — | The repo URL. Normally established when you **connect the repo** in the dashboard (that flow also installs a read-only deploy key); set it here only if you author the file before connecting. |
| `ref` | string | — | A **fully-qualified** git ref. Resolved server-side; a webhook is a trigger only and never reads the ref/sha/repo from its (attacker-influenced) payload. |
| `auto_deploy` | bool | **`false`** | When `true`, a fetch auto-clicks the **same** gated promote path — fail-closed to `update_blocked` + a page on any validation/gate failure, never an unguarded build. |

A push triggers a **fetch only** (`git fetch` → advance `staged_commit` → compute commits-behind + diff → set `update_available`). The live checkout advances only on an explicit, sha-pinned Deploy. See [GitOps](./gitops.md).

---

## The `{{hm.KEY}}` binding delimiter

Managed config files (`spec.config_files`) are rendered by a **single-pass byte scanner**, not a template engine. It matches **exactly** Mooring's own namespaced delimiter and **nothing else**:

| Touched (resolved) | Left byte-identical (data) |
|---|---|
| `{{hm.KEY}}` — `KEY` is `^[A-Za-z0-9_-]+$` (no colon, no dot) | the app's `${username}`, `$VAR`, `%(name)s`, Go `{{ .Field }}`, even `{{hmFoo}}` (no dot) |

There are **no conditionals, loops, functions, shell, or exec**. A `{{hm.KEY}}` resolves **only** if `KEY` is listed in that file's `bindings` allowlist; unknown / duplicate / malformed → hard error at save **and** at render. The renderer is **fail-closed, never empty-string** — a missing binding fails the deploy, it does not blank out.

### Binding values

Each entry in a config file's `bindings` maps a `KEY` to a value. It is a scalar literal, or exactly one single-key source mapping:

| Binding value | Resolves to | Notes |
|---|---|---|
| a literal scalar | itself | a plain config value. |
| `{ secret: NAME }` | the named secret from the encrypted store | **Marks the file secret-bearing** → rendered `0600`. |
| `{ env: NAME }` | this service's `env` value for `NAME` | If that env value is itself a `{secret: …}`, the file is secret-bearing. |
| `{ app: slug }` | the app's slug | The only app field exposed today. |
| `{ cert: HOSTNAME.crt\|key\|ca }` | the **container path** of a same-service `cert_binding`'s file | e.g. `cert: mqtt.example.com.crt` → `<that binding's mount>/tls.crt`. The hostname must be a `cert_binding` on the **same service**; the deploy already blocks until the edge issues it. |

So a TLS cert reaches a config file as a **path token** (`{cert: …}`) pointing at the read-only mount from [`cert_bindings`](#speccert_bindings) — the key/crt bytes themselves are never templated into the file.

### Rendered-value hygiene

Every resolved value is scrubbed: **NUL is always rejected**, and **CR/LF is rejected in every resolved value regardless of the declared `format`** (a secret with an embedded newline must not inject a second config line). Output is **emitted, never re-scanned** — a secret whose value happens to contain `{{hm.X}}` can never trigger a second substitution pass.

> **Why the app's `${...}` is sacred:** the whole point is that an app keeps its own runtime templating (its entrypoint still expands `${clientid}` at container start). Mooring fills *only* the deploy-time blanks it owns and gets out of the way. A blanket `envsubst` would clobber the app's own placeholders — which is exactly the bug this design refuses to make.

---

## Secrets are by reference only

**The definition file is never secret-bearing.** Because of that, the file is **safe to commit to a public repo** — it carries secret *names*, never values.

The rules, all enforced:

1. **`spec.secrets` declares names.** **It never holds values.**
2. **Every reference resolves within the referencing app's own `(slug, NAME)` namespace.** This applies to a `{ secret: NAME }` env value and a `{ secret: NAME }` binding in a `config_files` entry.
3. **No cross-app reads.** A name owned by another app resolves as **missing / fail-closed, with zero disclosure** — a committed file cannot exfiltrate another app's secret by guessing its name.
4. **Values arrive only out-of-band:**
   - `mooring secret import` — reads the values from a `.env` file you pass with `--from`, **never from argv** (so a secret never lands in `ps`, shell history, or audit).
   - the dashboard secret panel.
   - the SSH-edited root-owned config.
   …into the AES-256-GCM store under the master key.
5. **The literal-secret lint runs over every value.** A pasted secret — PEM/key material, a token shape, long base64 — in a non-secret-bearing position is **hard-rejected** with a pointer to use a `{ secret: NAME }` reference (and `{{hm.KEY}}` in a template) instead.

> **The honest trade-off:** by-reference-only means the file alone cannot bootstrap a brand-new app end-to-end — you must provision the secret values out-of-band before (or interleaved with) the first deploy. That is the deliberate cost of a file you can commit publicly and that can never carry a credential, never leak across apps, and never put a plaintext secret in your git history.

---

## How a change is applied

**The repo file is the source; the dashboard reflects it.** To change app structure you edit `mooring.yaml`, push, and deploy. Mooring **fetches** your repo (read-only — it never pushes back), and an explicit, **sha-pinned Deploy** is what advances the live app. A push by itself only marks an update *available*; nothing goes live until you deploy (unless you opt into [`git.auto_deploy`](#specgit), which auto-clicks the **same** gated deploy path).

Whatever triggers it, a deploy runs the **one reconciler** — there is no second path that does more:

```
parse → typed definition
  → resolve ${VAR}/.env FIRST
  → fan out into the typed sub-structs
  → allowlist validator
  → edge conflict gate              (edge.routes re-rendered; fail-to-save on shadow/admin/TLS/PKI/:80:443/XFF)
  → secret-literal lint
  → verify required secrets provisioned
  → resource gate + host-capacity guard
  → diff vs the live state
  → gated apply, in dependency order:
        env  →  render config files  →  cert-sync (deploy waits)  →  compose up  →  edge route re-render LAST
  → on ANY step failure: auto-rollback the WHOLE app to its prior definition  (no partial apply)
```

Properties to rely on:

- **Idempotent.** A deploy with no changes produces an **empty plan = no-op**.
- **Ordered.** Env first, edge route re-render last. Cert-sync makes the deploy wait until the cert files exist.
- **All-or-nothing.** Any step failing rolls the **entire app** back to its prior definition. There is no half-applied state.
- **Checkable ahead of time.** `mooring validate` runs the **exact same validator** read-only, so you can verify a `mooring.yaml` in CI before it ever reaches the write plane — a file that validates there is one a deploy accepts.

You can **download the deployed definition** at any time from the app page (`GET /apps/<slug>/definition.yaml`). That is how you capture a dashboard-set [auto-scaling](#specscaling) policy back into your repo so the file and the live app agree — Mooring never writes to your repo for you.

### The CLI surface

The CLI is the **root of trust plus a read-plane checker** — the write plane (deploys) lives in the dashboard. Full reference: [CLI reference](./cli.md).

| Read-plane (safe anywhere) | Root-of-trust & store (over SSH) |
|---|---|
| `validate` — parse + validate a `mooring.yaml` | `gen-key` · `hash-password` · `gen-totp` · `verify-key` |
| `init` — scaffold a starter `mooring.yaml` | `secret import` — load a `.env` into the encrypted store |
| | `token mint` / `list` / `revoke` |
| | `restore` — restore the DB from a backup |

> **Trust model:** SSH is the highest tier. An operator who can edit the root-owned config already holds the master key, so `mooring secret import` grants nothing new — which is *why* the CLI may write secrets but **no web route ever reads the key, allowlist, or bind address.**

---

## Where your app's files live

You write **relative** paths (a bind `source:`, a repo path); a `config_files` `mount` is a *container*
path. **Mooring owns the location on disk** — you never need an absolute host path. Each app gets its
own directory on the server:

```
/var/lib/mooring-apps/<app>/
```

(`/var/lib/mooring` is the data dir; the app tree is the sibling `…-apps`.) Relative paths resolve
inside that directory — a bind `source: data` becomes `…/<app>/data` — and Mooring writes the
generated compose, the generated Dockerfile(s) (`.mooring/Dockerfile.<svc>`), rendered config files,
and materialized secret files there, creating the directories for you. Everything is confined to the
app's own folder; a bind or config file can't point outside it.

---

## Worked example A — a multi-service stack (API + broker)

A NestJS API **built from the repo**, plus an EMQX broker that terminates its own MQTT/TLS. Mooring
generates and owns the compose and the API's Dockerfile; the edge fronts the API over HTTPS and issues
the broker's cert.

```yaml
apiVersion: mooring/v1            # exact-match; an unknown version is rejected, never best-effort parsed
kind: App
metadata:
  slug: credlock                   # immutable after first deploy

spec:
  compose:
    source: generated              # Mooring generates & owns the compose
    services:
      api:
        build:                     # no Dockerfile to write — Mooring generates a hardened one
          language: node
          version: "22"
          install: npm ci
          build: npm run build
          start: [node, dist/main]
          env: { NODE_OPTIONS: "--max-old-space-size=1024" }
        ports: [{ internal: 3000 }]            # internal — reached via the edge route below
        env:
          NODE_ENV: production                 # a literal
          MQTT_BROKER_URL: mqtt://emqx:1883    # reach a sibling by its service name
          MONGODB_URI: { secret: MONGODB_URI } # a reference — the value stays in the store
        secret_files: [jwt_private_key]        # mounted at /run/secrets/jwt_private_key
        depends_on: [emqx]
        healthcheck: [wget, -qO-, http://localhost:3000/health/live]
        restart: unless-stopped

      emqx:
        image: emqx/emqx:5.8.3
        ports:
          - { internal: 8883, publish: true, public: true }   # public MQTT/TLS
          - { internal: 18083 }                                # dashboard — internal only
        env:
          MQTT_DOMAIN: mqtt.example.com
          EMQX_DASHBOARD_PASSWORD: { secret: EMQX_DASHBOARD_PASSWORD }
        config_files:
          - { repo: docker/emqx/emqx.conf, mount: /opt/emqx/etc/emqx.conf }
        cert_bindings:
          - { hostname: mqtt.example.com, mount: /etc/certs }   # the edge issues + renews this cert
        volumes:
          - { name: emqx_data, target: /opt/emqx/data }
        restart: unless-stopped

  secrets:                          # NAMES only — values set out-of-band (`mooring secret import` / dashboard)
    - name: MONGODB_URI
    - name: jwt_private_key
    - name: EMQX_DASHBOARD_PASSWORD

  edge:
    routes:
      - hostname: api.example.com   # Mooring terminates HTTPS and routes to api:3000
        service: api
        port: 3000
```

Notice what you did **not** write: a `docker-compose.yml`, a Dockerfile, a Caddy config, or a
cert-reload sidecar. Mooring generates the compose and the API's Dockerfile, fronts the API over
HTTPS, and issues the broker's cert — and the dangerous compose keys (`privileged`, host mounts, host
namespaces) simply cannot be expressed here.

---

## Worked example B — a stateless API

A stateless HTTP API: an edge route, an **opt-in scaling policy**, and a healthcheck driven by self-healing. Secrets are by reference, as always.

```yaml
apiVersion: mooring/v1
kind: App
metadata:
  slug: web-api                    # immutable after first deploy

spec:
  compose:
    source: generated
    services:
      api:
        build: { language: auto }            # Mooring detects the stack + generates the Dockerfile
        ports: [{ internal: 8080 }]          # internal — reached via the edge route
        env:
          LOG_LEVEL: info
          DATABASE_URL: { secret: DATABASE_URL }   # reference; the value lives only in the store
        healthcheck: [wget, -qO-, http://localhost:8080/health]
        restart: unless-stopped

  secrets:
    - name: DATABASE_URL                     # imported via `mooring secret import` or set in the dashboard
    - name: SHARED_AUTH_TOKEN                # a SHARED auth secret is fine for a stateless service (not an identity)

  # ---- a public edge route; the upstream is a SELECTOR against this app's containers
  edge:
    routes:
      - hostname: api.example.com
        service: api                         # resolved to this app's container; never a literal dial target
        port: 8080
        path_prefix: /
        redirect_http: true
        hsts: true

  # ---- opt-in auto-scaling (a list — one policy per service) ---
  scaling:
    - service: api                # must pass candidacy; gaining a host port / RW volume scales it back to 1
      enabled: true
      min: 1
      max: 4                      # effective_max collapses to 1 on a near-OOM box (safe no-op + alert)
      up_cpu_pct: 65             # scale up when sustained CPU is above this
      down_cpu_pct: 25           # scale down when it falls below this
      per_replica_mem_mib: 96    # per-replica memory reservation; feeds the host-capacity guard

  git:
    ref: refs/heads/main
    auto_deploy: false            # default; a push fetches only — deploy stays a manual, sha-pinned promote
```

This API is a legitimate scaling candidate because every C1–C7 condition holds: it is an edge HTTP upstream with a known internal port, publishes no fixed host port (replicas are internal-port-only), holds no exclusive RW volume, is not stateful, carries no deploy-time *identity* placeholder (a *shared* `SHARED_AUTH_TOKEN` is fine — a per-node cookie would not be), honors a stateless restart contract, and opted in. Compare with [example A](#worked-example-a--a-multi-service-stack-api--broker), where the broker is stateful and scaling is therefore not even authored.

> **Self-healing** is tuned with the [`spec.self_healing`](#specself_healing) block in this file (there is no separate dashboard editor; every service is supervised on a conservative default if you omit it) — see [Scaling & self-healing](./scaling-and-self-healing.md). The **App Ops Interface** is also a definition key: set `ops_interface` per service (or app-level) — see [App Ops Interface](./app-ops-interface.md).

---

## Complete minimal example

The smallest valid `mooring.yaml` — one image-based service, no public route. Drop this in your repo, connect the repo, and deploy:

```yaml
apiVersion: mooring/v1
kind: App
metadata:
  slug: hello
spec:
  compose:
    services:
      web:
        image: nginx:1.27
        ports: [{ internal: 80 }]   # internal-only; add an edge.route to expose it publicly
```

`source: generated` is the default, so you can omit it. To expose `web` over HTTPS, add an [`edge.route`](#specedgeroutes); to build from your repo instead of pulling an image, replace `image:` with a [`build:`](#build--mooring-generates-the-dockerfile) block. Run `mooring validate` (read-only, safe in CI) before you commit.

---

## Field quick reference

| Path | Type | Required | Default |
|---|---|---|---|
| `apiVersion` | string (`mooring/v1`) | yes | — |
| `kind` | string (`App`) | yes | — |
| `metadata.slug` | string (immutable) | yes | — |
| `spec.compose.source` | `generated` | no (default) | `generated` |
| `spec.compose.services.<name>.image` \| `.build` | string \| object | exactly one | — |
| `…services.<name>.build.language` | enum (auto/node/python/go/ruby/php/static/generic) | no | `auto` |
| `…services.<name>.build.dir` | string (repo-relative subdir) | no | `.` |
| `…services.<name>.build.version` / `.install` / `.build` | string (one line each) | no | — |
| `…services.<name>.build.start` | exec array | no | — |
| `…services.<name>.build.base` | string (generic only — required there) | conditional | — |
| `…services.<name>.build.packages[]` / `.env` / `.run_as_nonroot` | list / map / bool | no | `[]` / — / `true` |
| `…services.<name>.ports[]` | `{internal, publish, public, protocol, published}` | no | — |
| `…services.<name>.ports[].protocol` | `tcp` \| `udp` | no | `tcp` |
| `…services.<name>.ports[].published` | int (host port) | no | = `internal` |
| `…services.<name>.env.<KEY>` | literal \| `{secret: NAME}` | no | — |
| `…services.<name>.secret_files[]` | string (a declared secret name) | no | — |
| `…services.<name>.config_files[]` | `{repo\|template, mount, bindings}` | no | — |
| `…services.<name>.config_files[].bindings.<KEY>` | literal \| `{secret\|env\|app\|cert: ARG}` | no | — |
| `…services.<name>.cert_bindings[]` | `{hostname, mount}` | no | — |
| `…services.<name>.volumes[]` | `{name\|source, target, read_only}` | no | — |
| `…services.<name>.command` / `.healthcheck` | exec array | no | — |
| `…services.<name>.restart` | enum (`no`/`always`/`on-failure`/`unless-stopped`) | no | docker default |
| `…services.<name>.depends_on[]` | list of sibling service names | no | — |
| `…services.<name>.mem_limit` / `.mem_reservation` | size string (`768m`, `1g`) | no | unbounded |
| `…services.<name>.stop_grace_period` | duration string (`60s`, `1m30s`) | no | docker 10s |
| `…services.<name>.ulimits.nofile` | `{ soft, hard }` ints (`1 ≤ soft ≤ hard`) | no | docker default (1024) |
| `…services.<name>.ops_interface` | object (see `spec.ops_interface`) | no | — |
| `spec.secrets[].name` | string | yes (per entry) | — |
| `spec.secrets[].generate` | string (`hex:N`\|`base64:N`\|`password:N`\|`rsa:BITS`\|`ed25519`) | no | — |
| `spec.edge.routes[].hostname` | string | yes | — |
| `spec.edge.routes[].service` | string | for proxy routes | — |
| `spec.edge.routes[].port` | int | for proxy routes | — |
| `spec.edge.routes[].upstream_scheme` | `http` \| `https` | no | `http` |
| `spec.edge.routes[].path_prefix` | string | no | `/` |
| `spec.edge.routes[].redirect_http` | bool | no | `true` |
| `spec.edge.routes[].hsts` | bool | no | per-edge |
| `spec.edge.routes[].security_headers` | bool | no | per-edge |
| `spec.edge.l4_routes[]` | `{listen, protocol, service, port, lb, tls}` | no | — |
| `spec.edge.l4_routes[].protocol` | `tcp` \| `udp` | required | — |
| `spec.edge.l4_routes[].lb` | `round_robin` \| `least_conn` \| `hash_client_ip` | no | `round_robin` |
| `spec.edge.l4_routes[].tls` | `passthrough` | no | `passthrough` |
| `spec.scaling[]` | list of per-service policies | no | — |
| `spec.scaling[].service` | string | required | must exist + be unique across entries |
| `spec.scaling[].enabled` | bool | no | `false` |
| `spec.scaling[].min` / `.max` | int | no | `1` / `1` |
| `spec.scaling[].up_cpu_pct` / `.down_cpu_pct` | float | no | `80` / `40` |
| `spec.scaling[].up_mem_pct` / `.down_mem_pct` | float | no | `80` / `40` |
| `spec.scaling[].per_replica_mem_mib` | int | no | — |
| `spec.scaling[].per_replica_cpu_milli` | int | no | — |
| `spec.scaling[].breach_for_secs` | int | no | `60` |
| `spec.scaling[].cooldown_up_secs` / `.cooldown_down_secs` | int | no | `60` / `300` |
| `spec.self_healing` | object (all fields optional; 0 = keep default) | no | built-in defaults |
| `spec.self_healing.sustain_ticks` / `.attempt_cap` / `.stabilize_ticks` / `.oom_strike_cap` / `.window_seconds` | int | no | built-in |
| `spec.self_healing.backoff_base_secs` / `.backoff_max_secs` | int (`max >= base`) | no | built-in |
| `spec.self_healing.redeploy_enabled` | bool | no | `false` |
| `spec.ops_interface` / `spec.compose.services.<name>.ops_interface` | object | no | disabled |
| `spec.ops_interface.enabled` | bool | no | `false` |
| `spec.ops_interface.base_url` | string (origin only, never loopback) | when enabled | — |
| `spec.ops_interface.base_path` / `.secret_header` / `.secret` / `.adapter` | string | no | — / — / — / `ops.v1` |
| `spec.ops_interface.mode` | `auto` \| `rich` \| `basic` | no | `auto` |
| `spec.git.repo` | string (repo URL; set by connect-a-repo) | no | — |
| `spec.git.ref` | string (fully-qualified) | no | — |
| `spec.git.auto_deploy` | bool | no | **`false`** |
| `spec.setup.script` | string | with `setup` | — |
| `spec.setup.trigger` | `never` \| `on_demand` \| `on_first_deploy` \| `before_each_deploy` | no | `never` |
| `spec.setup.produces[]` | list (`env:NAME` / `file:PATH`) | no | — |

> Unknown keys anywhere are a **hard reject** (`additionalProperties: false`). When in doubt, run `mooring validate` — it is read-plane and safe on any host.

---

**Related docs:** [README](../README.md) · [Managed config files](./config-files-and-secrets.md) · [Cert bindings](./edge-and-tls.md) · [GitOps](./gitops.md) · [Managed edge & routes](./edge-and-tls.md) · [Secrets](./config-files-and-secrets.md) · [Auto-scaling](./scaling-and-self-healing.md) · [Self-healing](./scaling-and-self-healing.md) · [CLI reference](./cli.md)