# Mooring CLI Reference

The `mooring` binary is both the long-running server (the dashboard + managed edge) **and** a small set of operator commands you run over SSH on the host. This page documents every command and its real flags.

> **An app is defined by its `mooring.yaml`.** That file — in the app's Git repo — is the single source of truth for its *shape*: services, build, ports, and edge/L4 routes. You create an app by **connecting its repo**; Mooring fetches the file, generates the compose, and deploys it. The dashboard *reflects* that shape (read-only — edit the file and deploy) and is where you manage the **operational** pieces: **secret values** and **env**, **config files** and **cert bindings** (editable in the dashboard; optionally seeded from the file), the **auto-scaling policy**, and **lifecycle actions** (deploy / restart / scale-now). The CLI is deliberately small and exists for three things:
>
> 1. **The install-time root of trust** — `gen-key`, `hash-password`, `gen-totp`, `verify-key`. These credentials and keys must be generated over SSH and pasted into the root-owned config; there is no web route that reads or writes them. `config check` and `config edit` check and edit that file.
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
  - [`config check`](#mooring-config-check)
  - [`config edit`](#mooring-config-edit)
  - [`validate`](#mooring-validate)
  - [`init`](#mooring-init)
  - [`secret import`](#mooring-secret-import)
  - [`token mint` / `list` / `revoke`](#mooring-token-mint--list--revoke)
  - [`restore`](#mooring-restore)
  - [`security-logs fetch` / `verify` / `decrypt`](#mooring-security-logs-fetch--verify--decrypt)
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
- **Exit status at start:** `serve` logs one `ERROR` line with `detail` and `hint` and exits in these cases. The systemd unit does not restart on `78`. On `1` it starts the service again every 2 seconds, so a file or directory on a volume that attaches late is picked up. Every other start failure exits `1`.

  | Cause | Exit status | `msg` |
  |---|---|---|
  | `config.yaml` does not exist | `1` | `config.yaml not found; not starting` |
  | `config.yaml` cannot be reached for another reason than its permissions | `1` | `config.yaml can't be read; not starting` |
  | The service may not read `config.yaml` (permission denied) | `78` | `config.yaml can't be read; not starting` |
  | `config.yaml` is group-readable and its group is neither `root` nor the service's | `78` | `config.yaml belongs to another group than the service's; not starting` |
  | `config.yaml` is refused | `78` | `config.yaml is not valid; not starting` (with `file`, `line` and `problems`) |
  | `data_dir`, `<data_dir>-apps` or, with `edge.mode: managed`, `/var/lib/caddy` is missing or not writable | `1` | `a required directory is missing or not writable; not starting` |
  | `encryption_key` does not open the database | `78` | `encryption_key does not match the database; not starting` |
  | `setup.enabled: true` without a working sandbox | `78` | `setup.enabled is set but this host has no working sandbox; not starting` |

  Do what the `hint` says. After status `78`, run `sudo systemctl start mooring`. The hints: [a refused file at start, reload and upgrade](./config-editing.md#start).
- **Reload:** `systemctl reload mooring` runs `mooring config check --errors-only` first and sends `SIGHUP` only when the file is valid. A reload applies `ip_allowlist` to the dashboard and to the edge route of the dashboard hostname; the log says whether the edge took the list: `config reload: the edge serves the reloaded ip_allowlist for the dashboard hostname`, or a warning that the list is pending until the next reconcile Caddy accepts, or that the edge refused it and keeps the previous list ([`ip_allowlist` at the edge](./config-editing.md#ip_allowlist-at-the-edge)). A reload reads `config.yaml` once and applies that configuration to the dashboard, the edge's `ip_allowlist` and the retention policy; it logs `config reloaded (allowlist + auth)`. When the file does not load it logs the `ERROR` line `config reload rejected; keeping previous`, and when the dashboard refuses the configuration an `ERROR` line that starts with `config reload: the dashboard refused the config; nothing was applied`; in both cases nothing is applied. A `SIGHUP` sent during start-up is handled once start-up finishes. See [reload or restart](./config-editing.md#apply-a-change-reload-or-restart).

```console
$ mooring serve --config /etc/mooring/config.yaml
mooring serving bind=127.0.0.1:9000 edge_mode=managed db=/var/lib/mooring/mooring.db
```

---

### `mooring doctor` / `setup`

- **Purpose:** check and install the host **prerequisites** the managed planes need. The running service is deliberately unprivileged (it can't install packages, edit host DNS, or grant capabilities — a compromised dashboard mustn't either), so these are run by *you* over SSH, as root, once. Linux-only.
- **Usage:**
  - `mooring doctor [--l4] [--config PATH]` — **read-only.** Reports each prerequisite (Caddy and its DNS plugins per the Caddy checks below, Docker and the Docker installation checks below, DNS, the state dirs + run dir, that `CAP_NET_BIND_SERVICE` is active, egress reachability, socket-proxy liveness, Docker log rotation, the security-log checks below; `--l4` adds nginx + the stream module + a `systemd-resolved :53` conflict, or with `edge.mode: external` one skipped `l4` line, since the L4 load balancer runs only with `edge.mode: managed`) and prints the exact fix for anything off. Changes nothing. `--config` (default `/etc/mooring/config.yaml`) is the config the checks read.
  - `mooring setup [--l4] [--restart] [--yes] [--config PATH]` — prints a **fix plan** (a dry run); `--yes` applies it (needs root, uses apt). `--l4` includes the L4 prerequisites; `--restart` restarts the mooring service at the end. `--config` (default `/etc/mooring/config.yaml`) is the config setup reads for `edge.mode`, `data_dir`, the `dns01` providers and the settings that need Caddy 2.11.
- **Caddy checks:** `doctor` checks the Caddy the edge will run: the Mooring-owned build `<data_dir>/bin/caddy` when it exists, otherwise the system `caddy`.
  - `caddy` — missing fails (with `edge.mode: external` it is skipped: Mooring runs no Caddy). Older than 2.11 fails when `edge.trusted_proxies`, any `dns01` namespace or `catch_all` is configured, and is a warning otherwise; for the system `caddy` the fix is `sudo mooring setup --yes`, which upgrades it to Caddy's official release (with `edge.mode: external` no fix is shown: setup doesn't upgrade it). A Mooring-owned build more than 180 days old is a warning with the refresh command: `sudo rm /var/lib/mooring/bin/caddy && sudo mooring setup --yes`.
  - `caddy (system)` — only when the edge runs the Mooring-owned build and `edge.mode` isn't `external`: a warning when the system `caddy` (the fallback) is older than 2.11. Fix: `sudo mooring setup --yes`.
  - `dns plugin <provider>` — one line per configured `dns01` provider. Ok when the provider's module is present; an unknown provider fails. A missing module is a warning when `caddyserver.com` is reachable (Mooring installs it at startup, or run `sudo mooring setup --yes` now), and fails when `caddyserver.com:443` is unreachable (allow outbound HTTPS to `caddyserver.com`). See [DNS-01 and the Caddy DNS plugin](./edge-and-tls.md#dns-01-and-the-caddy-dns-plugin).
- **Docker installation checks:** the socket-proxy (read plane) and the `docker` CLI (write plane) must reach the same Docker daemon. `doctor` runs all three checks; `setup` runs `docker daemons` and `docker installs`.
  - `docker daemons` — lists the running `dockerd` processes (pid, binary, systemd unit). A daemon inside a container or a rootless daemon is not counted. More than one fails; none running is a warning.
  - `docker installs` — looks for the `docker` CLI in `/usr/bin`, `/usr/local/bin` and `/snap/bin` (symlinks to the same binary count once) and for the Docker snap (`/snap/docker`). Two installations fail, including the snap next to an apt or `/usr/local` install.
  - `daemon match` — compares the daemon ID from the socket-proxy's `GET /info` with `docker info --format '{{.ID}}'`. Different IDs fail: deploys go to one daemon while the dashboard and edge read another. A warning means one side could not be read; run `doctor` as root with the service running. With `docker.external_proxy: true`, a proxy that does not answer `/info` skips the check.
  - Neither command removes a Docker installation. A failure prints the removal commands for the snap and apt installs.
- **Security-log checks:** only while `security_logs` is on (the default); see [Security logs](./security-logs.md#host-log-access). With `host_logs.enabled: false` only `security archive` and `memory max` run. Without a loadable config the defaults apply and there is no `security archive` line.
  - `adm group` — the `mooring` user must be in `adm`: a warning otherwise, fix `sudo usermod -aG adm mooring && sudo systemctl restart mooring` (or `sudo mooring setup --yes`). `doctor` also reads the running service's groups (its `MainPID` in `/proc`): a membership added since the service started is a warning, fix `sudo systemctl restart mooring`. Skipped on a host without an `adm` group or a `mooring` user.
  - `auth log`, `fail2ban log`, `journal` — one line per host log security logs follow: whether the service can read it, from the file's owner, group and mode against the `mooring` user's groups and the unit's `SupplementaryGroups=`. A file readable only through an ACL shows as unreadable. The journal is readable through the `systemd-journal`, `adm` or `wheel` group. A missing auth log is a warning, a missing Fail2Ban log is skipped. An unreadable file's fix is the `adm` membership, or `chgrp adm` + `chmod g+r` on the file; for the auth log also `security_logs.host_logs.journal: true`.
  - `security archive` — a warning when `security_logs.archive.s3` isn't set (security logs stay on this server only); otherwise the bucket, prefix and retention. The config warning for the same case isn't repeated as a `config` line.
  - `memory max` — a warning when the loaded unit's `MemoryMax` is below the shipped unit's `1G` (the upgrade's unit isn't loaded, or a drop-in lowers it). Fix: `sudo systemctl daemon-reload && sudo systemctl restart mooring`; `systemctl cat mooring` shows an override.
- **What `setup --yes` does:**
  - **Edge mode:** the Caddy, Mooring-owned build and nginx steps below, and disabling the `caddy` and `nginx` services, are planned only for the managed edge. With `edge.mode: external` setup installs, upgrades and disables none of them, `--l4` included, and the report has a skipped `edge` line. When there is no file at `--config` (setup runs before the config is written), setup plans for `edge.mode: managed` (the default). When the file exists but doesn't load, setup also leaves them alone and the report has an `edge` warning: fix the file (`sudo mooring doctor` shows the error) and run setup again. The Docker log cap and enabling the mooring service are planned in every mode.
  - **System `caddy`:** when there is none on `PATH` (even when a Mooring-owned build exists: the package is the fallback), adds the Caddy apt repo (key fetched over HTTPS) + installs `caddy`; a failed install stops setup. When it is older than 2.11 (Ubuntu and Debian ship 2.6.2), adds the same repo and upgrades it in place to Caddy's official release, keeping a changed `/etc/caddy/Caddyfile`. If a step of the upgrade fails (apt's lock is held, the repo is unreachable, the package is held) or apt keeps the old version, setup prints a warning, keeps the current `caddy` and goes on with the other steps; run it again once apt is free, or check `apt-cache policy caddy`. When its version can't be read, an existing system `caddy` is left alone.
  - **apt:** every `apt-get` command runs with `DEBIAN_FRONTEND=noninteractive` and `NEEDRESTART_MODE=l` (needrestart lists the services that need a restart; it doesn't prompt or restart them).
  - **Mooring-owned build:** installs a Caddy build from `caddyserver.com` as `<data_dir>/bin/caddy` when a configured `dns01` provider's plugin is missing from the Caddy the edge runs, or when that Caddy is older than 2.11 and a setting needs 2.11 (`edge.trusted_proxies`, a `dns01` namespace, `catch_all`). When the same run upgrades the system `caddy`, the build for 2.11 is installed only if the system `caddy` is still older than 2.11 after the upgrade. Before it is installed, the build must run, be 2.11 or later, have each `dns01` provider's module, and accept the edge's startup config and the edge config rendered from the edge settings in `config.yaml` (`caddy validate`, run as the `mooring` user; without app routes or DNS-01 wildcards). That config includes the issuer of each `edge.cas` CA, so a `trusted_root` the `mooring` user can't read, or that isn't a PEM certificate, fails the check. No certificate is requested and no CA is contacted. If the build fails, setup prints a warning and carries on. Mooring retries a build for a `dns01` plugin at startup; the build for 2.11 alone is retried only by running `sudo mooring setup --yes` again. A build that fails the config check is not installed and the warning carries Caddy's error, with the `dns01` tokens removed: fix that setting in `config.yaml` and run `sudo mooring setup --yes` again.
  - **The running service:** at the end, setup prints what the running mooring service needs. It was running without an edge because no Caddy was installed: restart it (`sudo systemctl restart mooring`) so the edge starts. A Mooring-owned build was installed: restart it so the edge switches to the build. The running edge used the upgraded system `caddy`: Mooring restarts the edge on it within a few minutes (`sudo systemctl restart mooring` switches at once). It added the `mooring` user to `adm` while the service runs: restart it so the service gets the group. `--restart` restarts the service instead.
  - **Other steps:** with `--l4` installs `nginx` + `libnginx-mod-stream`; disables the **distro** caddy/nginx units (Mooring supervises its own children), including the unit a package installed in the same run brings; **caps Docker's container logs** — it merges `log-opts.max-size` into `/etc/docker/daemon.json` (preserving your other keys, backing up the original) and restarts Docker; adds the `mooring` user to `adm` (`usermod -aG adm mooring`) when the host has that group, the user isn't in it, and neither `security_logs.enabled` nor `security_logs.host_logs.enabled` is `false`; and enables the mooring service when it is disabled. (The bind capability + runtime/state dirs are already provided by the unit + postinstall — no drop-in step.)
- **`config.yaml` in `doctor`:** a file that is refused is a `fail` on the `config` line, with the problems (file, line, column, the line and a hint) below it; the other checks then use the defaults. Run as root on a host with a `mooring` group, a file that loads for root and that the service cannot use is also a `fail`, judged as in [`config check`](#mooring-config-check): `<path> is readable by root only (mode 0600): the service (user mooring) can't read it; the service will not start with it (what is in the file is valid)`, with the fix `sudo chown root:mooring <path> && sudo chmod 0640 <path>`, or `<path> can't be used by the service (user mooring): <reason>; the service will not start with it (what is in the file is valid)`, with the fix `the service must be able to enter <dir>: sudo chown root:mooring <dir> && sudo chmod 0750 <dir>`. A warning, not a `fail`: a file that is missing, a file the user running `doctor` cannot read, and a group-readable file whose group is not that user's primary group when `doctor` is not run as root (`can't judge <path> as this user (the file belongs to another group): run sudo mooring config check`). The other checks use the defaults in these cases too.
- **Exit status of `doctor`:** `0` when no check failed, `1` when at least one check is a `fail`. Warnings do not change it.
- **What it will NOT do automatically:** rewrite host DNS / free `:53` (it prints the steps — too easy to lock yourself out). The Docker restart **bounces running containers**, so it's a labelled step in the dry-run plan you review first — run `setup` *before* deploying apps and it disrupts nothing.

```console
$ sudo mooring doctor --l4
  ✗ caddy            MISSING — managed HTTPS edge (:80/:443 + ACME)
      → sudo mooring setup --yes
  ✓ docker           found at /usr/bin/docker — container read/write plane
  ✓ docker daemons   one Docker daemon: pid 812 /usr/bin/dockerd (docker.service)
  ✓ docker installs  one Docker installation: /usr/bin/docker
  ! docker logs      json-file driver has no size cap — container logs can fill the disk
      → sudo mooring setup --yes (caps it), or set log-opts.max-size by hand (snippet below)
  ✓ dns              host name resolution works
  ✓ net-bind cap     CAP_NET_BIND_SERVICE is active in the unit
  ✗ state dirs       writable-dir problem: /var/lib/caddy (missing)
      → sudo install -d -o mooring -g mooring -m0700 <dir> (and add it to ReadWritePaths)

$ sudo mooring setup --yes          # applies the plan above
```

---

### `mooring config check`

- **Purpose:** run the checks `mooring serve` runs on `config.yaml` at start, without starting anything. Read-only. No value from the file is printed.
- **Usage:** `mooring config check [--config PATH] [--quiet] [--errors-only] [--json]`
- **Flags:**
  - `--config PATH` — the file (default `/etc/mooring/config.yaml`).
  - `--quiet` — print nothing; the exit status is the answer. Cannot be combined with `--errors-only` or `--json` (exit `2`).
  - `--errors-only` — print nothing for a valid file; for any other file the output is the same as without the flag.
  - `--json` — print the result as one line of JSON on stdout.
- **Exit status:** `0` valid; `78` refused (an empty file, a YAML mistake, an unknown key, a wrong type, a value the validation refuses, a wrong owner, group or mode); `2` the file is missing or unreadable, the file cannot be judged as this user, or wrong arguments. `--errors-only` does not change the exit status.
- **Output:** for a valid file `OK: <file> is valid`, the warnings, the hostnames a certificate is requested for, when `config.yaml.last-good` exists and is readable (root) the settings changed since it with the command that applies each, and a note when `config.yaml.rejected-edit` exists (an edit `config edit` kept instead of installing; `rejected_edit` in the JSON). For a refused file, every problem on stderr with its line and a caret. Every value is masked and no message quotes one; a key is shown only when it is a key of `config.yaml`. With `--json`, a file that is missing, unreadable or cannot be judged as this user prints `{"ok":false,"file":…,"error":…}` on stdout (exit `2`). Formats and the JSON fields: [Checking and editing `config.yaml`](./config-editing.md#check-the-file).
- **Notes:** run it with `sudo`. Run as a user who is neither root nor has the file's group as primary group, it does not judge a group-readable file: it prints `can't judge <path> as this user (the file belongs to another group): run sudo mooring config check` and exits `2`. Run as root on a host with a `mooring` group, it refuses (exit `78`) a file that loads for root and that the service cannot use. On a host with a `mooring` user it reads the file again as that user, with the unit's group and supplementary groups, in a child process, and that read decides: a file the user reads through an ACL is not refused; a file in a directory the user cannot enter is. Without a `mooring` user, or when the child process gives no answer within 5 seconds, the file's owner, group and mode decide. The messages: `<path> is readable by root only (mode 0600): the service (user mooring) can't read it`, or `<path> belongs to group id N, not to the service's group mooring (id M): …`, followed by the fix `sudo chown root:mooring <path> && sudo chmod 0640 <path>`; for any other reason `<path> can't be used by the service (user mooring): <reason>` (for example `stat <path>: permission denied`), followed by `The service must be able to enter <dir>:` and `sudo chown root:mooring <dir> && sudo chmod 0750 <dir>` when a directory above the file is closed to the user. With `--json` the message is `problems[0].msg` and the fix is `problems[0].hint`. `systemctl reload mooring` (as the `mooring` user, with `--errors-only`) and the package upgrade (as the `mooring` user and group when it can, otherwise as root) run it before they touch the service.

```console
$ sudo mooring config check
/etc/mooring/config.yaml:3:1: unknown key on this line
  2 | encryption_key: …
  3 | …
    | ^
   hint: did you mean ip_allowlist?

/etc/mooring/config.yaml is refused: mooring will not start or reload with it.
$ echo $?
78
```

---

### `mooring config edit`

- **Purpose:** edit `config.yaml` in an editor and install the result only when it passes the checks of `config check`. Root, on a terminal.
- **Usage:** `sudo mooring config edit [--config PATH]`
- **Flags:** `--config PATH` (default `/etc/mooring/config.yaml`).
- **Exit status:** `0` installed or unchanged; `1` nothing installed (discarded, editor failed, locked, changed underneath, interrupted, or the offer to start from the example declined); `2` not root, no terminal, or wrong arguments.
- **Editor:** the first installed of `$SUDO_EDITOR`, `$VISUAL`, `$EDITOR`, `sensible-editor`, `nano`, `vi`. It runs in its own process group. Under a shell with job control, `Ctrl-Z` in the editor suspends `mooring config edit` with it and `fg` continues both; where nothing can continue the command (for example `ssh -t host 'sudo mooring config edit'`), `Ctrl-Z` does not suspend it.
- **What it does:** locks `/etc/mooring/.config.lock`, opens a private copy (`0600`) in the editor, checks it, and on a refused copy asks `(e)dit again / (x) discard`. A valid copy replaces the file with the same owner, group and mode; the previous file is kept as `config.yaml.last-good`. It then prints which changed settings need `sudo systemctl reload mooring` and which need `sudo systemctl restart mooring`. It runs neither. When `mooring serve` will not start with the installed file for its owner, group or mode, it prints a warning (`warning: mooring serve will not start with <path> as it is now, whatever is in it: …`) with the `chown` and `chmod` command; it does not change them. The editor's backup and swap files of the copy are removed with it.
- **Refusals:** a symlink, a file with several hard links, a directory not owned by root or writable by others, a second `config edit` on the same file, and a file whose content, owner, group or mode changed while it was being edited. In the last case the edit is kept as `config.yaml.rejected-edit` (`root`, `0600`); later runs do not remove it.
- **A missing file:** it offers to start from the example, looked for at `/usr/share/mooring/config.example.yaml`, then `/etc/mooring/config.example.yaml`.
- **Signals:** `SIGINT`, `SIGTERM`, `SIGHUP` and `SIGQUIT` stop the editor's process group with `SIGTERM` (killed after 3 seconds), restore the terminal, remove the copy and exit `1` without installing. When an edit was kept as `config.yaml.rejected-edit`, the message names it.
- **Details:** [Checking and editing `config.yaml`](./config-editing.md#edit-the-file).

```console
$ sudo mooring config edit
/etc/mooring/config.yaml installed; the previous file is kept as /etc/mooring/config.yaml.last-good
To apply (nothing was reloaded or restarted):
  reload  (sudo systemctl reload mooring): ip_allowlist
```

---

### `mooring validate`

- **Purpose:** parse and validate a `mooring.yaml` through the **same §5.6/§6.2 chokepoints** a deploy runs — with **no database** and **no write plane**. Read-only and safe to run in CI.
- **Usage:** `mooring validate [--from mooring.yaml] [--run-dir DIR] [--json]`
- **Flags:**
  - `--from <path>` — the definition file (default `mooring.yaml`).
  - `--run-dir <dir>` — the app run directory bind mounts must stay under (optional; lets the binds-confinement check run as it would on the host).
  - `--json` — print the result as one line of JSON on stdout: `{"ok":true,"file":…,"kind":…,"slug":…}` for a valid `kind: App` file (`"apps": N` instead of `slug` for `kind: Host`), `{"file":…,"problems":[…]}` for a refused one. The problem fields are those of [`config check --json`](./config-editing.md#a-refused-file).
- **Exit status:** `0` valid; `1` refused; `2` the file is missing or cannot be read, or a flag is wrong. With `--json` a missing or unreadable file prints `{"ok":false,"file":…,"error":…}` on stdout; without it the message is on stderr.
- **Errors:** a refused file is printed on stderr with the file, line and column, the line itself with a caret, and a hint. The messages for a value of the wrong type quote the value (`(found "3")`). Every YAML, unknown-key and type problem is listed; of the values the validation refuses, the first. See [reading the errors](./config-editing.md#reading-the-errors).
- **Notes:** this is the CLI/deploy **parity** guarantee — a `mooring.yaml` that validates here is one Mooring would accept on deploy, because both run the one reconciler. Run it in CI so a bad commit fails before you ever click **Deploy**. A sibling `.env` next to the file is used to resolve `${VAR}` references during validation. Both `kind: App` and `kind: Host` files are accepted.

```console
$ mooring validate --from mooring.yaml
OK: billing-api (kind=App, compose.source=generated) is valid

$ mooring validate --from mooring.yaml
mooring.yaml:17:9: unknown key "servce" in spec.edge.routes[0]
  16 |       - hostname: app.example.com
  17 |         servce: web
     |         ^
   hint: did you mean service?
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

  hmt_9c1e4b7a2d5f8e0b3a6c9d1e_...

id:      9c1e4b7a2d5f8e0b3a6c9d1e
scopes:  status:read metrics:read
cidrs:   203.0.113.0/24
expires: 2026-07-16T00:00:00Z
```

#### `mooring token list`

- **Purpose:** list tokens (id, state, expiry, scopes — never the secret).
- **Usage:** `mooring token list [--config PATH]`

```console
$ mooring token list
ID                        STATE    EXPIRES               SCOPES
9c1e4b7a2d5f8e0b3a6c9d1e  active   2026-07-16T00:00:00Z  status:read metrics:read
```

#### `mooring token revoke`

- **Purpose:** revoke a token by id; it is rejected at auth immediately.
- **Usage:** `mooring token revoke --id <id> [--config PATH]`

```console
$ mooring token revoke --id 9c1e4b7a2d5f8e0b3a6c9d1e
token 9c1e4b7a2d5f8e0b3a6c9d1e revoked — it is rejected at auth immediately; reload to drop it from the IP gate union
```

---

### `mooring restore`

- **Purpose:** restore Mooring's database from an encrypted `.mbk` backup archive. This **replaces** the live database, so it is a deliberate CLI step rather than a dashboard button.
- **Usage:** `mooring restore --from <archive.mbk> --force [--config PATH]`, or `mooring restore --from-s3 latest|list|<name> --force [--config PATH]`
- **Flags:**
  - `--from <archive.mbk>` — the encrypted backup to restore.
  - `--from-s3 <which>` — restore a daily Mooring-state backup from the `backups.s3` bucket (see [Daily copies in S3](./backup-and-recovery.md#daily-copies-in-s3)). `latest` is the newest; `list` prints the backups in the bucket, newest first, and changes nothing; any other value is a name from that list, or the start of one (`20261124`) that matches exactly one backup. The archive is downloaded into the data dir, restored like `--from`, and removed afterwards; the data dir needs about twice its size free, which is checked before the download. Use either `--from` or `--from-s3`.
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

```console
$ mooring restore --from-s3 list
20261124T030012Z-4f1c9a0e7b2d6c8a1e3f5b70.mbk  2026-11-24 03:00:12 UTC  46.0 MiB
20261123T030009Z-a81d2e6f0c4b9a7e3d5c1f28.mbk  2026-11-23 03:00:09 UTC  45.9 MiB
$ systemctl stop mooring
$ mooring restore --from-s3 latest --force
downloaded s3://my-bucket/mooring/mooring-state/20261124T030012Z-4f1c9a0e7b2d6c8a1e3f5b70.mbk (48230912 bytes)
previous database kept at /var/lib/mooring/mooring.db.pre-restore-1795489200
restored /var/lib/mooring/mooring.db from s3://my-bucket/mooring/mooring-state/20261124T030012Z-4f1c9a0e7b2d6c8a1e3f5b70.mbk
start Mooring again: systemctl start mooring
```

---

### `mooring security-logs fetch` / `verify` / `decrypt`

Commands for the security-log archive in S3 (`security_logs.archive.s3`, see [Security logs](./security-logs.md)). Each sealed segment (one capture hour of a host's security events, gzip NDJSON) is stored as two objects:

```
<prefix>v1/YYYY/MM/DD/HH/<box>-<seq>.ndjson.gz.enc   the segment, encrypted with encryption_key
<prefix>v1/YYYY/MM/DD/HH/<box>-<seq>.seal.json       its seal (JSON)
```

`YYYY/MM/DD/HH` is the UTC capture hour, `<box>` the name of the host that wrote the segment and `<seq>` the segment's number within that hour (at least 4 digits). Each host writing to the same bucket and prefix needs its own box name: Mooring doesn't overwrite a seal that belongs to another segment, so a segment whose key is already taken is not uploaded (it raises an alert). A seal holds `v`, `name`, `box`, `hour`, `seq`, `n` (the segment's position in its host's seal order: 1, 2, ...), `events`, `first`, `last`, `sha256` (of the decrypted segment), `prev_sha256` (the `sha256` of the segment sealed before it on the same host, `""` for the first), `enc_sha256` and `enc_bytes` (of the `.enc` object), `archived_at` and `mac`. `mac` is an HMAC-SHA256 of all the other fields, keyed from `encryption_key`, so a seal can't be edited without the key. A seal with `"sha256_mismatch": true` belongs to a segment that changed on the host after it was sealed; it is uploaded anyway, and `actual_sha256` is the hash of what was uploaded.

The three commands read the config file (`--config PATH`, default `/etc/mooring/config.yaml`). Run them as root or as the `mooring` user. Flags may come before or after the positional argument. `mooring security-logs help` prints the usage.

#### `mooring security-logs fetch`

- **Purpose:** download the archive objects of a time range, still encrypted.
- **Usage:** `mooring security-logs fetch --from <time> --to <time> -o <dir> [--config PATH]`
- **Flags:**
  - `--from <time>`, `--to <time>` — the range, as RFC 3339 (`2026-11-22T14:00:00Z`) or a UTC date (`2026-11-22`). A date as `--to` includes that whole day. Every segment whose hour overlaps the range is fetched, for every host under the prefix.
  - `-o <dir>` — where to write (created `0700` when missing). Each object is written as a `0600` file under its key without the prefix: `<dir>/v1/YYYY/MM/DD/HH/<box>-<seq>.…`.
- **Notes:** keys that don't match the layout are skipped. When any of the files to write already exists, nothing is downloaded. Fails when `security_logs.archive.s3` is not set.

```console
$ sudo mooring security-logs fetch --from 2026-11-20 --to 2026-11-22 -o ./audit
fetched 144 object(s) (72 segment(s), 10485760 bytes) to ./audit
```

#### `mooring security-logs verify`

- **Purpose:** check a directory of downloaded objects (for example one written by `fetch`).
- **Usage:** `mooring security-logs verify <dir> [--config PATH]`
- **Checks:**
  - every `.ndjson.gz.enc` object has its `.seal.json`, and every seal its object;
  - each seal's `mac` verifies with `encryption_key` or `encryption_key_previous` (a seal without a `mac` is reported as unauthenticated);
  - each object decrypts with `encryption_key` or `encryption_key_previous`;
  - the decrypted segment's SHA-256 is the seal's `sha256`, and the object's size and SHA-256 are the seal's `enc_bytes` and `enc_sha256`;
  - no seal has `sha256_mismatch` set;
  - each file name and its `YYYY/MM/DD/HH` directories match the seal's `box`, `seq` and `hour`;
  - per host, the `prev_sha256` links form one chain, with `n` increasing along it: no missing segment, fork, restart or duplicate. Only seals whose `mac` verifies are part of the chain.
- **Notes:** the directory is read recursively; symlinks are not followed and other files are ignored. When the oldest segment's predecessor is not in the directory (the range starts after the host's first segment), verify prints a `note:` line, not a problem. Missing segments after the newest one in the directory can't be detected. Each problem is printed as a `problem:` line. Exits `1` on any problem, or when the directory holds no seals.

```console
$ sudo mooring security-logs verify ./audit
note: box web-1: the chain starts at v1/2026/11/20/00/web-1-0001; the segments before it are not in this directory
checked 72 segment(s) from 1 host(s) (web-1), 2026-11-20T00:00Z to 2026-11-22T23:00Z: 72 verified
OK

$ sudo mooring security-logs verify ./audit
note: box web-1: the chain starts at v1/2026/11/20/00/web-1-0001; the segments before it are not in this directory
problem: box web-1: segment(s) missing before v1/2026/11/21/10/web-1-0001 (its prev_sha256 3f9a0c1d2e4b is not in this directory)
checked 71 segment(s) from 1 host(s) (web-1), 2026-11-20T00:00Z to 2026-11-22T23:00Z: 71 verified
mooring security-logs: 1 problem(s) found
```

#### `mooring security-logs decrypt`

- **Purpose:** decrypt one archive object to its gzip NDJSON (one event per line).
- **Usage:** `mooring security-logs decrypt <file.ndjson.gz.enc> [-o out.ndjson.gz] [--config PATH]`
- **Flags:**
  - `-o <file>` — the output file (`0600`). Default: the input path without `.enc`. `-` writes to stdout. An existing file is not overwritten.
- **Notes:** tries `encryption_key`, then `encryption_key_previous` (and prints `decrypted with encryption_key_previous` when that one worked). The whole object is authenticated before anything is written: with a wrong key, or a corrupt or tampered object, the command fails and writes nothing.

```console
$ sudo mooring security-logs decrypt ./audit/v1/2026/11/21/09/web-1-0001.ndjson.gz.enc
wrote ./audit/v1/2026/11/21/09/web-1-0001.ndjson.gz (48213 bytes, gzip NDJSON)

$ sudo mooring security-logs decrypt ./audit/v1/2026/11/21/09/web-1-0001.ndjson.gz.enc -o - | gunzip | wc -l
1342
```

---

### Root of trust: `gen-key` / `hash-password` / `gen-totp` / `verify-key`

These bootstrap and verify the credentials and keys in `/etc/mooring/config.yaml`. They print material you paste into the root-owned config (`root:mooring`, mode `0640`; edit it with `sudo mooring config edit`) — they do **not** edit the file for you. No web route reads or writes auth, the IP allowlist, the master key, or the bind address. Passwords are read from `/dev/tty`, never `argv`.

After pasting, apply the change: **`hash-password` and `gen-totp`** (login/two-factor) take effect with `sudo systemctl reload mooring`, but **`gen-key`** (the master key) is read only at startup and needs `sudo systemctl restart mooring`. See [editing the config file](./installation.md#editing-the-config-file-reload-vs-restart).

#### `mooring gen-key`

- **Purpose:** generate the AES-256-GCM master key (base64). Everything at rest — env blobs, git creds, ops secrets, channel secrets — is encrypted under it.
- **Usage:** `mooring gen-key`
- **Flags:** none.
- **Critical:** the key lives **only** in the config file. **Back up config (the key) and the DB separately and offsite** — losing the key bricks all ciphertext irrecoverably.

```console
$ mooring gen-key
encryption_key: "9f3c1d...=="
Paste this into /etc/mooring/config.yaml (root:mooring, mode 0640). Back it up offsite, separately from the DB.
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
| `1` | The command returned an error — a validation rejection (`validate`, `secret import`), a key/DB mismatch (`verify-key`), a wrong/corrupt archive (`restore`), a missing required flag, an unparseable flag, or any other runtime failure. The message is printed to stderr as `mooring <command>: <error>`. `doctor`: at least one check is a `fail`. `config edit`: nothing was installed. `serve`: `config.yaml` is missing or cannot be reached, a required directory is missing or not writable, or another start failure; the systemd unit starts the service again every 2 seconds. |
| `2` | No command given, or an unknown command (the usage summary is printed to stderr). `config check`: the file is missing or unreadable, cannot be judged as this user, or wrong arguments. `config edit`: not root, no terminal, or wrong arguments. `validate`: the file is missing or unreadable, or a flag is wrong. |
| `78` | `config check`: `config.yaml` is refused, or, run as root, the service cannot reach or read it or it belongs to another group than the service's. `serve`: `config.yaml` is refused, the service may not read it, it belongs to another group than the service's, `encryption_key` does not match the database, or `setup.enabled` is set without a working sandbox. The systemd unit does not restart on this status. |
