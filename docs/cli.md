# Mooring CLI Reference

The `mooring` binary is both the long-running server (the dashboard + managed edge) **and** a small set of operator commands you run over SSH on the host. This page documents every command and its real flags.

> **An app is defined by its `mooring.yaml`.** That file — in the app's Git repo — is the single source of truth for its *shape*: services, build, ports, and edge/L4 routes. You create an app by **connecting its repo**; Mooring fetches the file, generates the compose, and deploys it. The dashboard *reflects* that shape (read-only — edit the file and deploy) and is where you manage the **operational** pieces: **secret values** and **env**, **config files** and **cert bindings** (editable in the dashboard; optionally seeded from the file), the **auto-scaling policy**, and **lifecycle actions** (deploy / restart / scale-now). The CLI is deliberately small and exists for three things:
>
> 1. **The install-time root of trust** — `gen-key`, `hash-password`, `gen-totp`, `verify-key`. These credentials and keys must be generated over SSH and pasted into the root-owned config; there is no web route that reads or writes them.
> 2. **Authoring helpers** — `validate` (the same checks a deploy runs, no DB, safe in CI), `init` (scaffold a `mooring.yaml`), and `secret import` (load a `.env` into an app's encrypted store).
> 3. **Disaster recovery** — `restore` rebuilds the database from an encrypted backup with the service stopped.
>
> Backups themselves are written by the **running server** (under `<data_dir>/backups/`). There is no `mooring backup` command — the CLI only restores.

See also: [README](../README.md) · [Configuration / root of trust](./architecture.md) · [Definition file (`mooring.yaml`)](./definition-file.md) · [Managed edge](./edge-and-tls.md) · [Security model](./security.md).

---

## Table of contents

- [Conventions](#conventions)
- [How secret values enter Mooring](#how-secret-values-enter-mooring)
- [Command reference](#command-reference)
  - [`serve`](#mooring-serve)
  - [`doctor` / `setup`](#mooring-doctor--setup)
  - [`validate`](#mooring-validate)
  - [`init`](#mooring-init)
  - [`secret import`](#mooring-secret-import)
  - [`token mint` / `list` / `revoke`](#mooring-token-mint--list--revoke)
  - [`restore`](#mooring-restore)
  - [Root-of-trust: `gen-key` / `hash-password` / `gen-totp` / `verify-key`](#root-of-trust-gen-key--hash-password--gen-totp--verify-key)
  - [`version` / `help`](#mooring-version--help)
- [Exit codes](#exit-codes)

---

## Conventions

- **`mooring <command>`** — every command is a subcommand of the single static binary. The same binary systemd runs as the server is the one you invoke by hand.
- **Run over SSH on the host.** These commands are for a single operator who already has shell access. There is no remote CLI protocol, and the commands are not exposed over the network.
- **`--config PATH`** — commands that open the database or read the master key take `--config` (default `/etc/mooring/config.yaml`). They read the root-owned config the same way the server does.
- **`--from PATH`** — on `validate` it is the definition file (default `mooring.yaml`); on `secret import` it is the `.env` to read; on `restore` it is the `.mbk` archive.
- **Slugs are immutable.** An app slug must match `^[a-z][a-z0-9-]{1,30}$` and cannot change after the app first exists.

---

## How secret values enter Mooring

Secret **values** follow one inflexible rule:

> **A secret value never appears in `argv`.** Passwords are read from `/dev/tty`; secret values are read from a file you point at (`secret import --from <.env>`). There is no `--value`/`--password` flag, by design.

Anything on the command line is visible in `ps`, shell history, and process accounting. Reading from `/dev/tty` and from files keeps values out of that channel.

Other rules that hold for every value:

- **By reference in the definition.** `mooring.yaml` declares secret *names* (`spec.secrets`) and references them (`env: { KEY: { secret: NAME } }`, `secret_files: [NAME]`, or `bindings: { KEY: { secret: NAME } }` inside a config file). The definition is **never secret-bearing** and is safe to commit. Values arrive out-of-band via `secret import`, the dashboard panel, or the SSH-edited config.
- **Namespaced per app.** A reference resolves only within the referencing app's own `(slug, name)` namespace.
- **Literal lint.** `secret import` classifies each `.env` entry and applies a hard stop on values that look like pasted secret literals where a reference belongs.
- **`git add mooring.yaml` only.** Mooring owns and generates the compose; you never write or commit a `docker-compose.yml` or a `Dockerfile`. Commit `mooring.yaml` and nothing generated.

---

## Command reference

For each command: **purpose**, **usage**, **flags**, and an **example**.

---

### `mooring serve`

- **Purpose:** load the config, open the database, and run the loopback admin server (the dashboard + the managed edge supervisor + the read/write planes). This is what systemd runs.
- **Usage:** `mooring serve [--config PATH]`
- **Flags:** `--config PATH` (default `/etc/mooring/config.yaml`).
- **Notes:** fail-closed on boot — a bad config, a key/DB mismatch, or (when `setup.enabled`) a missing sandbox refuses to start. `SIGHUP` hot-reloads the IP allowlist + auth + retention policy, but **not** keys or the bind address (those require a restart).

```console
$ mooring serve --config /etc/mooring/config.yaml
mooring serving bind=127.0.0.1:9000 edge_mode=managed db=/var/lib/mooring/mooring.db
```

---

### `mooring doctor` / `setup`

- **Purpose:** check and install the host **prerequisites** the managed planes need. The running service is deliberately unprivileged (it can't install packages, edit host DNS, or grant capabilities — a compromised dashboard mustn't either), so these are run by *you* over SSH, as root, once. Linux-only.
- **Usage:**
  - `mooring doctor [--l4]` — **read-only.** Reports each prerequisite (Caddy, Docker, DNS, the state dirs + run dir, that `CAP_NET_BIND_SERVICE` is active, egress reachability, socket-proxy liveness, Docker log rotation; `--l4` adds nginx + the stream module + a `systemd-resolved :53` conflict) and prints the exact fix for anything off. Changes nothing.
  - `mooring setup [--l4] [--restart] [--yes]` — prints a **fix plan** (a dry run); `--yes` applies it (needs root, uses apt). `--l4` includes the L4 prerequisites; `--restart` restarts the mooring service at the end.
- **What `setup --yes` does:** adds the Caddy apt repo (key fetched over HTTPS) + installs `caddy`; with `--l4` installs `nginx` + `libnginx-mod-stream`; disables the **distro** caddy/nginx units (Mooring supervises its own children); and **caps Docker's container logs** — it merges `log-opts.max-size` into `/etc/docker/daemon.json` (preserving your other keys, backing up the original) and restarts Docker. (The bind capability + runtime/state dirs are already provided by the unit + postinstall — no drop-in step.)
- **What it will NOT do automatically:** rewrite host DNS / free `:53` (it prints the steps — too easy to lock yourself out). The Docker restart **bounces running containers**, so it's a labelled step in the dry-run plan you review first — run `setup` *before* deploying apps and it disrupts nothing.

```console
$ sudo mooring doctor --l4
  ✗ caddy            MISSING — managed HTTPS edge (:80/:443 + ACME)
      → sudo mooring setup --yes
  ✓ docker           found at /usr/bin/docker — container read/write plane
  ! docker logs      json-file driver has no size cap — container logs can fill the disk
      → sudo mooring setup --yes (caps it), or set log-opts.max-size by hand (snippet below)
  ✓ dns              host name resolution works
  ✓ net-bind cap     CAP_NET_BIND_SERVICE is active in the unit
  ✗ state dirs       writable-dir problem: /var/lib/caddy (missing)
      → sudo install -d -o mooring -g mooring -m0700 <dir> (and add it to ReadWritePaths)

$ sudo mooring setup --yes          # applies the plan above
```

---

### `mooring validate`

- **Purpose:** parse and validate a `mooring.yaml` through the **same §5.6/§6.2 chokepoints** a deploy runs — with **no database** and **no write plane**. Read-only and safe to run in CI.
- **Usage:** `mooring validate [--from mooring.yaml] [--run-dir DIR]`
- **Flags:**
  - `--from <path>` — the definition file (default `mooring.yaml`).
  - `--run-dir <dir>` — the app run directory bind mounts must stay under (optional; lets the binds-confinement check run as it would on the host).
- **Notes:** this is the CLI/deploy **parity** guarantee — a `mooring.yaml` that validates here is one Mooring would accept on deploy, because both run the one reconciler. Run it in CI so a bad commit fails before you ever click **Deploy**. A sibling `.env` next to the file is used to resolve `${VAR}` references during validation. Both `kind: App` and `kind: Host` files are accepted.

```console
$ mooring validate --from mooring.yaml
OK: billing-api (kind=App, compose.source=generated) is valid
```

---

### `mooring init`

- **Purpose:** scaffold a starter `mooring.yaml` with one seed service (`web`). Mooring owns the compose, so there is no compose file or Dockerfile to point at — you edit the scaffold and run `validate`.
- **Usage:** `mooring init --slug <slug> [--image nginx:1.27] [--port N] [--out mooring.yaml]`
- **Flags:**
  - `--slug <slug>` — **required**; the immutable app slug (`^[a-z][a-z0-9-]{1,30}$`).
  - `--image <image>` — image for the seed service (default `nginx:1.27`; replace it, or switch the service to a `build:` block).
  - `--port <n>` — internal container port for the seed service (optional; `0` omits it).
  - `--out <path>` — output path (default `mooring.yaml`; must be repo-relative, refuses to overwrite an existing file).
- **Notes:** the scaffold is round-tripped through the parser before it is written, so what you get always parses. Then edit `spec.compose.services` — each service's `image:`/`build:`, its `env:` (a map) and `ports:` — plus top-level `spec.secrets` and `spec.edge.routes`. (Note: `env` is per-service, under `spec.compose.services.<name>.env` — there is no top-level `spec.env`.)

```console
$ mooring init --slug billing-api --image nginx:1.27 --port 8080
wrote mooring.yaml — edit spec.compose.services (each service's image:/build:, env, ports), spec.secrets, and spec.edge.routes, then `mooring validate`
```

---

### `mooring secret import`

- **Purpose:** import a `.env` file's **values** into an app's encrypted store. Each entry is parsed, classified (biased toward secret), and run through the override-proof literal-secret hard stop before it is ingested by reference. The imported file is **not** the live file — the live `.env` re-renders from the encrypted store on the next deploy.
- **Usage:** `mooring secret import --slug <slug> --from <.env> [--confirm-rotations] [--config PATH]`
- **Flags:**
  - `--slug <slug>` — the app to import into.
  - `--from <.env>` — the `.env` to read (values come from the file, never from `argv`).
  - `--confirm-rotations` — also apply changes that would **rotate an existing live secret** or **downgrade a secret to plain** (held back behind this higher-friction confirm by default; all other adds/changes still apply).
  - `--config PATH` — config file (default `/etc/mooring/config.yaml`).
- **Notes:** the value never appears on the command line. The diff is reported as added / changed / unchanged; rotations are listed but not applied unless `--confirm-rotations` is given.

```console
$ mooring secret import --slug billing-api --from ./.env.production
imported into "billing-api": 2 added, 0 changed, 3 unchanged (2 applied)
the live .env re-renders from the encrypted store on the next deploy; the imported file is not the live file
```

---

### `mooring token mint` / `list` / `revoke`

Scoped machine-API tokens for the read-mostly `/api/v1` JSON API. Tokens are **minted only here** — the web plane never mints one. The plaintext is printed **once**; only its hash is stored.

#### `mooring token mint`

- **Purpose:** mint a scoped, CIDR-bound, expiring bearer token.
- **Usage:** `mooring token mint --scopes <csv> --cidrs <csv> --ttl <dur> [--label S] [--config PATH]`
- **Flags:**
  - `--scopes <csv>` — comma-separated scopes. Valid scopes: `status:read`, `metrics:read`, `events:read`, `audit:read`, `deploy:write:<slug>`.
  - `--cidrs <csv>` — comma-separated CIDR set the token is valid from (non-empty; a catch-all is refused).
  - `--ttl <dur>` — mandatory lifetime (e.g. `720h`); a token always expires.
  - `--label <s>` — operator note (informational).
  - `--config PATH` — config file (default `/etc/mooring/config.yaml`).
- **Notes:** after minting, the IP gate admits the new CIDRs only after a reload (`systemctl reload mooring`, or `kill -HUP <pid>`).

```console
$ mooring token mint --scopes status:read,metrics:read --cidrs 203.0.113.0/24 --ttl 720h --label ci-readonly
token minted — copy the value below, it is shown ONCE and cannot be recovered:

  hmtok_...

id:      tok_8f3c1d
scopes:  status:read metrics:read
cidrs:   203.0.113.0/24
expires: 2026-07-16T00:00:00Z
```

#### `mooring token list`

- **Purpose:** list tokens (id, state, expiry, scopes — never the secret).
- **Usage:** `mooring token list [--config PATH]`

```console
$ mooring token list
ID          STATE    EXPIRES               SCOPES
tok_8f3c1d  active   2026-07-16T00:00:00Z  status:read metrics:read
```

#### `mooring token revoke`

- **Purpose:** revoke a token by id; it is rejected at auth immediately.
- **Usage:** `mooring token revoke --id <id> [--config PATH]`

```console
$ mooring token revoke --id tok_8f3c1d
token tok_8f3c1d revoked — it is rejected at auth immediately; reload to drop it from the IP gate union
```

---

### `mooring restore`

- **Purpose:** restore Mooring's database from an encrypted `.mbk` backup archive. This **replaces** the live database, so it is a deliberate CLI step rather than a dashboard button.
- **Usage:** `mooring restore --from <archive.mbk> --force [--config PATH]`
- **Flags:**
  - `--from <archive.mbk>` — the encrypted backup to restore.
  - `--force` — confirm the replacement (without it the command refuses and tells you to stop the service first).
  - `--config PATH` — config file (default `/etc/mooring/config.yaml`).
- **How it works:** the archive is decrypted with the configured master key (the **same** key the backup was made under — back up config and DB separately so they stay in sync), inspected to confirm it is a real Mooring database, opened (which also runs migrations and refuses a downgrade from a newer binary), and only then swapped in. The previous database is kept aside as `mooring.db.pre-restore-<ts>`.
- **Notes:** **run with the service stopped.** A wrong master key, or a corrupt/tampered archive, fails the decrypt step before anything is replaced.

```console
$ systemctl stop mooring
$ mooring restore --from /var/lib/mooring/backups/2026-06-15.mbk --force
previous database kept at /var/lib/mooring/mooring.db.pre-restore-1718409600
restored /var/lib/mooring/mooring.db from /var/lib/mooring/backups/2026-06-15.mbk
start Mooring again: systemctl start mooring
```

---

### Root of trust: `gen-key` / `hash-password` / `gen-totp` / `verify-key`

These bootstrap and verify the credentials and keys in `/etc/mooring/config.yaml`. They print material you paste into the root-owned config (`0600 root:root`) — they do **not** edit the file for you. No web route reads or writes auth, the IP allowlist, the master key, or the bind address. Passwords are read from `/dev/tty`, never `argv`.

After pasting, apply the change: **`hash-password` and `gen-totp`** (login/two-factor) take effect with `sudo systemctl reload mooring`, but **`gen-key`** (the master key) is read only at startup and needs `sudo systemctl restart mooring`. See [editing the config file](./installation.md#editing-the-config-file-reload-vs-restart).

#### `mooring gen-key`

- **Purpose:** generate the AES-256-GCM master key (base64). Everything at rest — env blobs, git creds, ops secrets, channel secrets — is encrypted under it.
- **Usage:** `mooring gen-key`
- **Flags:** none.
- **Critical:** the key lives **only** in the config file. **Back up config (the key) and the DB separately and offsite** — losing the key bricks all ciphertext irrecoverably.

```console
$ mooring gen-key
encryption_key: "9f3c1d...=="
Paste this into /etc/mooring/config.yaml (0600 root:root). Back it up offsite, separately from the DB.
```

#### `mooring hash-password`

- **Purpose:** produce an **argon2id** hash for `auth.password_hash`. There is no public registration and no web password reset — this is how the admin credential is set.
- **Usage:** `mooring hash-password [--memory-mib N]`
- **Flags:** `--memory-mib <N>` — argon2id memory cost in MiB (default `8`; raise it on a larger host for more resistance). The password is read from `/dev/tty`, prompted twice; it must be at least 12 characters.

```console
$ mooring hash-password
New password: ********
Confirm password: ********
password_hash: "$argon2id$v=19$m=8192,t=2,p=1$..."
```

#### `mooring gen-totp`

- **Purpose:** generate a TOTP secret for `auth.totp_secret` (the admin's second factor on login). It prints a **scannable QR code** to the terminal — point your authenticator app at it — plus the `otpauth://` URL and raw secret as a manual fallback.
- **Usage:** `mooring gen-totp [--account operator] [--issuer Mooring]`
- **Flags:** `--account <label>` (default `operator`) and `--issuer <label>` (default `Mooring`) — labels for the `otpauth://` URL.

```console
$ mooring gen-totp
totp_secret: "JBSWY3DPEHPK3PXP"
Scan this with your authenticator app:
  <a QR code is drawn here>

Or add it manually:
otpauth://totp/Mooring:operator?secret=JBSWY3DPEHPK3PXP&issuer=Mooring&algorithm=SHA1&digits=6&period=30
```

#### `mooring verify-key`

- **Purpose:** confirm the configured `encryption_key` matches the database before a mismatch can corrupt data. It checks (or, on a fresh DB, initializes) a key-check sentinel.
- **Usage:** `mooring verify-key [--config PATH]`
- **Flags:** `--config PATH` (default `/etc/mooring/config.yaml`).
- **When to run it:** after `gen-key`/rotation, after restoring a DB or config from backup, or any time you suspect config and DB drifted apart.

```console
$ mooring verify-key
verify-key: OK — key matches the DB
```

---

### `mooring version` / `help`

- `mooring version` — print version information (`mooring <version>`).
- `mooring help` (also `-h`, `--help`) — print the usage summary.

---

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success. |
| `1` | The command returned an error — a validation rejection (`validate`, `secret import`), a key/DB mismatch (`verify-key`), a wrong/corrupt archive (`restore`), a missing required flag, an unparseable flag, or any other runtime failure. The message is printed to stderr as `mooring <command>: <error>`. |
| `2` | No command given, or an unknown command (the usage summary is printed to stderr). |
