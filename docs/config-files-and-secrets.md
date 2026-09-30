# Config Files & Secrets

Mooring gives an app three ways to receive configuration — env vars, file-mounted secrets, and managed config files — plus a **secret-by-reference** model that keeps plaintext credentials out of your `mooring.yaml`, your repo, your logs, and your browser. This document covers all three, how host-side templating works, and how secrets are provisioned, stored, and previewed.

> Coming from a hand-rolled `docker-entrypoint.sh` that `sed`s a config file, bootstraps a credential, and waits for a cert? The [Replacing a bespoke entrypoint](#replacing-a-bespoke-entrypoint-declaratively) section is the fast path — those three imperative jobs become a few declarative lines.

**See also:** [README](../README.md) · [Provisioning apps](./gitops.md) · [Managed edge & certs](./edge-and-tls.md) · [The `mooring.yaml` definition file](./definition-file.md)

---

## The three kinds of config input

Env vars, file-mounted secrets, and templated config files are three distinct things with different storage, rendering behavior, and hygiene rules.

> **What lives where.** **Secret VALUES** and **env** are set in the dashboard (encrypted; the YAML declares secret *names* only — you provision the actual values on the env page or with `mooring secret import` over SSH). **`config_files`** and **`cert_bindings`** are **editable in the dashboard** too (per service), and can *also* be declared in your `mooring.yaml`, which seeds them on deploy. What is read-only in the dashboard is the app's *shape* — services and edge/L4 routes — defined in `mooring.yaml`; to change those, edit the file and deploy. Mooring's git access is fetch-only — it reads `mooring.yaml`, never writes it back.

| Kind | Holds | Mooring renders it? | At rest | Mounted as |
|---|---|---|---|---|
| **env** | `KEY: value` pairs | No | Encrypted env blob | `0600 --env-file` |
| **file-mounted secret** | An opaque file (a `.pem`, a keystore, a license blob) | No — Mooring never reads its contents | Encrypted store | Read-only bind mount |
| **managed config file** | A **template** (config with `{{hm.*}}` placeholders) | **Yes — host-side, before `up`** | Encrypted *iff* secret-bearing | Read-only bind mount, `0640`/`0600` |

All three are declared **per service**, under `spec.compose.services.<svc>`. Only `spec.secrets` (secret *names*) is top-level.

### When to use each

**Use an env var when** the value is a flat `KEY: value` the app reads from the environment. It lands in an encrypted env blob and is materialized as a `0600 --env-file` at deploy time — it never gets baked into the generated compose. A literal value or a `{ secret: NAME }` reference can both live here:

```yaml
spec:
  compose:
    source: generated
    services:
      web:
        image: myorg/web:1.4
        env:
          LOG_LEVEL: info                 # literal
          DATABASE_URL: { secret: DB_URL } # reference into the encrypted store
```

**Use a file-mounted secret when** the app wants an opaque file it reads itself — a TLS keystore, a service-account JSON, a downloaded license. Declare its name in `secret_files`; Mooring materializes the stored value as a read-only mount. The name must be a declared secret:

```yaml
      web:
        image: myorg/web:1.4
        secret_files:
          - SERVICE_ACCOUNT_JSON
```

**Use a managed config file when** the app ships a *structured* config that has deploy-time placeholders Mooring should fill — a node cookie, a shared auth secret, a dashboard password — **mixed with the app's own runtime placeholders** (`${username}`, `${clientid}`, `${topic}`) that must pass through untouched. Mooring renders it host-side, before `docker compose up`, and bind-mounts the result read-only.

> A managed config file's template is encrypted at rest only when it is **secret-bearing** (at least one binding resolves a secret). A purely structural template is stored unencrypted but rendered with the same hygiene rules below.

---

## Selective host-side templating

Mooring performs **selective** templating — it touches only its own `{{hm.<KEY>}}` delimiter and copies everything else byte-for-byte. It is not a blanket `envsubst`.

### Mooring touches only `{{hm.<KEY>}}`

The renderer recognizes exactly one token: `{{hm.<KEY>}}`, where `<KEY>` matches `^[A-Za-z0-9_-]+$` (letters, digits, `_`, `-`). There is **no colon and no dot** inside the token — `{{hm.secret:NAME}}` and `{{hm.cert.x.crt}}` are **not** valid tokens.

Each `<KEY>` resolves through the file's own `bindings` allowlist (below). Everything else is data and is copied byte-identical: the app's `${...}`, `$VAR`, `%(...)s` (Python-style), Go `{{ }}`, and even a near-miss like `{{hmFoo}}` (no dot after `hm`) are all left exactly as written. Your `${username}` survives byte-for-byte.

### It is a single-pass byte scanner, not a template engine

The renderer matches the literal pattern `{{hm.<KEY>}}` and nothing more:

- No conditionals, loops, or functions.
- No shell, no `exec`, no arbitrary evaluation.
- No second pass — a resolved value is emitted and **never re-scanned**, so a secret whose plaintext happens to contain `{{hm.X}}` can't trigger a second resolution.

### The per-file `bindings` allowlist

A `{{hm.KEY}}` resolves **only if `KEY` is in that file's `bindings` map.** There is no implicit lookup against the environment or the secret store. An unknown, duplicate, or malformed token is a **hard error at save time and again at render time** — never silently substituted with an empty string. A missing secret at render time is a **hard deploy failure**, not an empty value.

A binding value is either a **literal** or a **secret reference**:

```yaml
bindings:
  PUBLIC_HOST: broker.example.com     # literal
  NODE_COOKIE: { secret: NODE_COOKIE } # reference into the encrypted store
```

Any `{ secret: NAME }` binding marks the whole file **secret-bearing** (encrypted at rest, written `0600`).

---

## Rendered-value hygiene

A resolved value — especially a secret — is treated as data that could corrupt or extend the config, so the renderer enforces:

### NUL and CR/LF are always rejected

A resolved value containing **NUL, CR, or LF is rejected** — regardless of the file's format. A secret with an embedded newline could otherwise inject a second config line inside the container (turning `password = {{hm.NODE_COOKIE}}` into a password line plus an attacker-controlled directive).

### File permissions default to least-privilege

| Condition | Mode |
|---|---|
| Default (non-secret-bearing) | `0640` |
| Secret-bearing (any `{ secret: }` binding) | `0600` |

Rendered files are **never `0644`**, and they are written atomically (`.tmp` write, `fchmod`, then `rename`), so a partially written or wrong-mode file never exists at the final path.

### The literal-secret lint

At save time, a lint scans non-secret-bearing bodies and **rejects** material that looks like a pasted credential — PEM private-key blocks, AWS/GitHub/Slack/Stripe token markers, JWTs, connection strings with inline `user:pass@`, and long high-entropy runs. The error points you at the right tool:

> bind it as a `{ secret: NAME }` binding instead of pasting it.

This catches the most common mistake (pasting a key into the template) before it can be rendered or mounted.

### Lifecycle: re-rendered every deploy, host-edits detected

- Materialization happens **before `up`, host-side**: resolve every binding → render → write atomically → record `rendered_sha256` → bind-mount read-only.
- Files are **re-rendered on every redeploy** from the current `mooring.yaml`, so there is never a stale render left over from an old deploy.
- A host hand-edit of a rendered file is **detected** by SHA mismatch and surfaced as *"host-edited, will be overwritten."* Detection only — Mooring never auto-merges a hand edit.

---

## Cert bindings (edge cert → app)

When [Mooring owns the edge](./edge-and-tls.md), it is the ACME agent for your hostnames. A **cert binding** mounts an edge-managed cert into a service so the app can read the leaf cert and key off disk.

A cert binding has exactly two fields:

```yaml
cert_bindings:
  - hostname: broker.example.com   # a hostname Mooring issues a cert for
    mount: /etc/broker/tls         # absolute directory inside the container
```

Mooring syncs the edge-issued cert into that directory as two files:

- `tls.crt` (mode `0644`) — the leaf cert (plus chain).
- `tls.key` (mode `0600`) — the private key.

The app points its config at `<mount>/tls.crt` and `<mount>/tls.key` and reads them itself. The deploy **waits automatically** until the cert is synced — the container never has to poll or wait. **Renewal is autonomous:** a background watcher re-syncs the renewed leaf and recreates the affected service (briefly bouncing it) so it picks up the new cert — no manual redeploy.

> There are no cert template tokens. A cert reaches a container only through a cert binding (files at `mount`), never through `{{hm.*}}`. There is no `name`, `required`, or `sync_dir` field — the mount directory and the automatic deploy gate are implicit.

A cert binding is **not** the same as an edge route. To serve a hostname through the managed edge, declare a route under `spec.edge.routes`. A cert binding only places the cert files where the app can read them (for an app that terminates TLS itself, mutual TLS, etc.).

---

## Replacing a bespoke entrypoint, declaratively

The classic "templated config + custom entrypoint" pattern bundles three imperative jobs into a shell script. Mooring dissolves all three into declarative config, and the container reverts to its upstream default command.

| Imperative job (old entrypoint) | Declarative replacement |
|---|---|
| Targeted `sed` to fill placeholders | A **managed config file** with `{{hm.KEY}}` bindings |
| Bootstrap a credential into a file before start | A managed config file (or `secret_files`) bound from a `{ secret: NAME }` |
| A cert-wait loop (`until [ -f cert.pem ]; …`) | A **cert binding** — the deploy waits automatically until the cert is synced |

Each job moves out of the container entrypoint and into a typed, validated, host-side step.

---

## The secret model

### Secret-by-reference is an invariant

Mooring's master rule for secrets: **they are always by reference, never by value, in any authoring surface.**

- A `mooring.yaml` declares secret **names** in `spec.secrets` (with an optional `generate` hint) — **never values.** The file is safe to commit.
- env entries, `config_files.bindings`, `secret_files`, and `cert_bindings` are all *references* — they never carry a value.
- The actual secret value arrives **only out-of-band** (see provisioning below) and lands in the encrypted store.

Declare the names once, at the top of the spec:

```yaml
spec:
  secrets:
    - name: NODE_COOKIE
      generate: hex:32         # minted on first deploy, never overwrites an existing value
    - name: DASH_PASSWORD      # provisioned out-of-band (see below)
```

### Per-`(slug, name)` namespace — no cross-app reads

Every secret reference resolves **only within the referencing app's own `(slug, name)` namespace.** A name owned by another app resolves as missing / fail-closed — there is no error that leaks the other app's secret. A `{ secret: SHARED_KEY }` reference in app A can never read app B's `SHARED_KEY`.

### Provisioning: `mooring secret import` (never argv)

Secret values are imported from a `.env` file — **never from `argv`** (so the value can't land in shell history, `ps` output, or process listings):

```bash
# Import every KEY=VALUE in the file into my-app's encrypted store.
mooring secret import --slug my-app --from ./secrets.env

# If an import would rotate an already-provisioned value, confirm it explicitly:
mooring secret import --slug my-app --from ./secrets.env --confirm-rotations
```

The values are read from the file, never passed as command arguments. A secret declared with a `generate` hint is minted on explicit operator action, with a per-type entropy floor, and never overwrites an already-provisioned value.

### The encrypted store

Secrets, env blobs, and other sensitive material are encrypted with **AES-256-GCM** under a master key. That key lives **only in the root-owned config file** — never in the database, logs, or UI.

- A dedicated redacted type makes secrets unprintable, so a secret can't accidentally serialize into a log line, an error, or a temp file.
- Key rotation is supported via a previous-key slot in the config.
- Generate the key with `mooring gen-key`; confirm the configured key matches the DB with `mooring verify-key`.
- **Back up the config (which holds the key) and the database separately and offsite.** Losing the key bricks every ciphertext — there is no recovery path. The running server writes encrypted backups under `<data_dir>/backups/`; restore one with the service stopped via `mooring restore --from <archive.mbk> --force` (same master key required; the prior DB is kept as `mooring.db.pre-restore-<ts>`).

### The masked preview

The config-file preview lets you verify a template **without leaking a secret byte to the browser.** A secret binding renders as a masked placeholder showing its source — name only, never the value:

```
‹secret:NODE_COOKIE›
```

This confirms two things at a glance:

1. The **structure** is right — the secret lands where you expect.
2. The app's own `${...}` placeholders **survived** the render untouched.

---

## Worked example: templating a broker config

Suppose your message broker ships this config template, with a mix of values Mooring should fill and values the app resolves itself at runtime.

**`broker.conf` (template):**

```ini
# --- Mooring fills these at deploy time (host-side) ---
node.cookie            = {{hm.NODE_COOKIE}}
management.password    = {{hm.DASH_PASSWORD}}
cluster.public_host    = {{hm.PUBLIC_HOST}}
listeners.ssl.certfile = /etc/broker/tls/tls.crt
listeners.ssl.keyfile  = /etc/broker/tls/tls.key

# --- The app's OWN runtime placeholders — copied byte-identical ---
default_user           = ${username}
default_pass           = ${password}
default_vhost          = ${vhost}
mqtt.client_id_prefix  = ${clientid}
log.console.level      = %(LOG_LEVEL)s
```

Note the TLS paths are **plain literals** that point at the cert binding's `mount` directory — there are no cert tokens. The `{{hm.*}}` tokens are simple keys (no colon, no dot); each one is resolved by the file's `bindings`.

### How it's declared in `mooring.yaml`

`config_files` and `cert_bindings` are nested under the service. The TLS cert is mounted into the same directory the template references. Only `spec.secrets` is top-level.

```yaml
apiVersion: mooring/v1
kind: App
metadata:
  slug: broker
spec:
  compose:
    source: generated
    services:
      broker:
        image: myorg/broker:3.13
        config_files:
          - template: |
              node.cookie            = {{hm.NODE_COOKIE}}
              management.password    = {{hm.DASH_PASSWORD}}
              cluster.public_host    = {{hm.PUBLIC_HOST}}
              listeners.ssl.certfile = /etc/broker/tls/tls.crt
              listeners.ssl.keyfile  = /etc/broker/tls/tls.key
              default_user           = ${username}
              default_pass           = ${password}
            mount: /etc/broker/broker.conf      # absolute path inside the container
            bindings:
              NODE_COOKIE:   { secret: NODE_COOKIE }
              DASH_PASSWORD: { secret: DASH_PASSWORD }
              PUBLIC_HOST:   broker.example.com  # a literal binding
        cert_bindings:
          - hostname: broker.example.com        # Mooring syncs tls.crt + tls.key here
            mount: /etc/broker/tls
  secrets:
    - name: NODE_COOKIE
      generate: hex:32                           # minted on first deploy
    - name: DASH_PASSWORD                        # provisioned via `mooring secret import`
  edge:
    routes:
      - hostname: broker.example.com
        service: broker
        port: 15672
```

Instead of an inline `template:`, you can point at a file in the app's repo:

```yaml
        config_files:
          - repo: config/broker.conf     # repo-relative, traversal-free
            mount: /etc/broker/broker.conf
            bindings:
              NODE_COOKIE: { secret: NODE_COOKIE }
```

A `config_files` entry must set **exactly one** of `template` or `repo`, and `mount` is **required** (an absolute container path).

### The masked preview you'd see

```ini
node.cookie            = ‹secret:NODE_COOKIE›
management.password    = ‹secret:DASH_PASSWORD›
cluster.public_host    = broker.example.com
listeners.ssl.certfile = /etc/broker/tls/tls.crt
listeners.ssl.keyfile  = /etc/broker/tls/tls.key

default_user           = ${username}
default_pass           = ${password}
```

Both secrets are masked (source name, no value), and every `${...}` line is byte-identical to the template — Mooring touched only its own `{{hm.*}}` tokens.

### What happens at deploy

1. Before `up`, Mooring resolves each binding from this app's namespace.
2. Each resolved value is checked for NUL and CR/LF (always rejected).
3. The cert binding for `broker.example.com` syncs `tls.crt` (`0644`) and `tls.key` (`0600`) into `/etc/broker/tls`; the deploy waits automatically until they exist.
4. `broker.conf` is rendered in a single pass, written atomically as `0600` (secret-bearing), and bind-mounted read-only.
5. `rendered_sha256` is recorded. On the next deploy the file is re-rendered; a host hand-edit in between is reported as *"host-edited, will be overwritten."*

If `NODE_COOKIE` had not been provisioned, the deploy would **fail closed** at materialization — it never renders an empty cookie.

---

## Quick reference

| You want to… | Use |
|---|---|
| Pass a flat `KEY: value` the app reads from the env | an **env** entry (literal or `{ secret: NAME }`) |
| Hand the app an opaque file Mooring shouldn't read | a **`secret_files`** entry (encrypted store → read-only mount) |
| Fill placeholders in a structured config, keeping the app's own `${...}` | a **config file** + `{{hm.KEY}}` bindings |
| Reference a credential without ever writing its value | a `{ secret: NAME }` binding + `mooring secret import` |
| Give an app an edge-issued TLS cert on disk | a **cert binding** (`tls.crt`/`tls.key` at `mount`) |
| Verify a template without leaking secrets | the **masked preview** |
