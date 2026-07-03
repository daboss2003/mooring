# The Server tab

The **Server** tab (under **System** in the sidebar) is a read-only window into the
host Mooring runs on — a task-manager-and-file-viewer for your box, plus a tidy-up
for old Mooring downloads. It is built to **look, not break**: everything is
read-only except one narrow, re-authenticated action (deleting an old `.deb`).

## What it shows

- **Host monitor** — live CPU, load, memory, and disk meters (the same readings the
  Overview charts use), refreshed in place every few seconds.
- **Top processes by memory** — the processes using the most resident memory, with
  PID, name, state, and RSS. This is read-only: Mooring can't signal or kill
  processes.
- **Disk usage** — how much space Mooring itself is using, broken down by its data
  directory (database, git deploy history, secrets, state) and its app working dirs
  (repo clones, generated compose/Dockerfile). It also explains where the **build
  caches** live: Mooring discards its own interrupted-deploy leftovers on boot, but
  **Docker's** build cache, dangling images, and stopped containers accumulate
  separately — check them over SSH with `docker system df` and reclaim with
  `docker system prune`. Mooring never prunes Docker for you.
- **Mooring downloads (`.deb`)** — lists the Mooring release packages you've
  downloaded so you can delete the old ones (see below).
- **Files (read-only)** — an opt-in, allow-listed file viewer (see below).

## Cleaning up old `.deb` downloads

Every time you update Mooring you download a `mooring_<version>_linux_<arch>.deb`,
and they pile up. The Server tab can delete the old ones for you — safely:

1. Tell Mooring where you keep them. In `/etc/mooring/config.yaml`:

   ```yaml
   server:
     deb_cache_dir: /root/downloads   # the folder you download .deb files into
   ```

   The directory must be **writable by the Mooring service user**. Note that a
   systemd-sandboxed install only permits writes under its declared paths, so a
   location like `~/Downloads` or `/tmp` may need to be added to the unit's
   `ReadWritePaths` (or just point `deb_cache_dir` somewhere already writable).

2. Reload Mooring (`sudo systemctl reload mooring`) and open **Server**. Under
   **Mooring downloads** you'll see every `mooring_*_linux_*.deb` in that folder,
   newest first. The **version you're running is marked "in use — kept" and can never
   be deleted.**

3. Click **delete** on an old one. Because this removes a file, it asks for your
   **password** (and your **2FA code** if enabled) — the same re-authentication used
   for deleting an app — behind the same brute-force lockout. Every delete is
   recorded in the **Audit log**.

The cleanup only ever matches files named exactly `mooring_<version>_linux_(amd64|arm64).deb`
in that one folder. It cannot see or touch anything else, including system packages.

## The read-only file viewer

The file viewer is **off by default**. To turn it on, list the directories you want
to be able to browse:

```yaml
server:
  file_roots:
    - name: app-logs          # a short slug used in the URL
      path: /var/log/myapp
    - name: uploads
      path: /srv/data/uploads
```

Then **Server → Files** lets you browse those directories and read text files inside
them. The viewer is strictly read-only — there is **no** rename, move, write, or
delete of files. Guardrails (all enforced after resolving symlinks):

- **Allow-list only** — nothing outside a declared `file_roots` path is reachable.
  With no roots configured, the viewer is disabled entirely.
- **Secrets are always denied** — Mooring's data directory (database, git object
  stores, env/secret files), its app working dirs, the config file and its directory,
  and well-known secret locations (`/etc/mooring`, SSH keys, `/etc/shadow`) are
  refused **even if you accidentally list one as a root**. A root that resolves under
  a denied path is dropped.
- **No traversal, no symlink escape** — `..`, absolute paths, and symlinks whose
  target leaves the root are rejected.
- **Bounded** — listings are capped, file reads are size-capped, and binary files are
  detected and not rendered.
- **Audited** — every file read (and every denial) is written to the Audit log.

## Staying up to date (self-update + security alerts)

Mooring can watch **itself** for updates and, critically, for **security advisories** that
affect the version you're running — so a compromised/vulnerable Mooring tells you to update
immediately instead of sitting there silently. It's **opt-in**:

```yaml
server:
  version_check_enabled: true      # off by default
  version_check_interval: 6h       # optional; default 6h, floored at 1h
```

When enabled, Mooring periodically asks the **GitHub API** (only `api.github.com`, no
telemetry payload — just public GETs) whether:

- a **newer release** exists → a banner appears on every page: *"Mooring vX.Y.Z is available."*
- the **running version is affected by a published security advisory** → a **red banner** on
  every page *and* a **CRITICAL alert** through your configured [alert channels](./alerting.md)
  (critical alerts bypass quiet hours). The alert is de-duplicated so you're not re-paged every
  tick for the same advisory.

The check runs even when nobody is watching the dashboard (a compromise must surface on an
unattended box), and it's the exact "notify me to update" behavior other PaaS tools do — with
the security-advisory layer added on top. With `version_check_enabled` off (the default),
Mooring never contacts GitHub.

## Summary of config keys

```yaml
server:
  deb_cache_dir: /root/downloads   # optional; enables old-.deb cleanup
  file_roots:                      # optional; enables the read-only file viewer
    - name: app-logs
      path: /var/log/myapp
  version_check_enabled: true      # optional; enables the self-update + security-advisory check
  version_check_interval: 6h       # optional; default 6h (floored at 1h)
```

All are optional and default to off. The host monitor, processes, and disk-usage views need no
configuration.
