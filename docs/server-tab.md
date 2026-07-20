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
  separately — Mooring reclaims those for you (see **Reclaiming disk** below).
- **Mooring downloads (`.deb`)** — lists the Mooring release packages you've
  downloaded so you can delete the old ones (see below).
- **Files (read-only)** — an opt-in, allow-listed file viewer (see below).

## Reclaiming disk

Every time an app with a build step redeploys, Docker leaves the previous build
image behind as a **dangling** (untagged) image, plus build cache. On a busy
server these are usually the main thing that fills the disk.

- **Reclaim disk now** — the button on the Server tab runs `docker image prune`
  (dangling images) + a build-cache trim, and streams the output. It only removes
  **garbage**: Docker never prunes a tagged image or one used by a container
  (running *or* stopped), and a Mooring rollback rebuilds its image — so this can
  never delete a running app, a rollback target, or any data volume.
- **Automatic reclaim** — Mooring watches disk usage and, when it crosses
  `server.disk_gc_threshold` (default **75%**), reclaims the same garbage on its
  own and sends you an alert. It's on by default; set `server.disk_gc_enabled:
  false` to turn it off, or change the threshold:

  ```yaml
  server:
    disk_gc_enabled: true     # default
    disk_gc_threshold: 75     # percent; clamped to 50–95
  ```

  If your disk stays full after a reclaim, the cause is app data or logs, not old
  deploys — the alert says as much.

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

## Staying up to date

Mooring keeps an eye on itself. Every few hours it quietly checks whether a newer version has
been released and — more importantly — whether the version you're running has a known security
problem. This is on out of the box; you don't have to set anything up.

Two things can show up:

- **A newer version is out.** You'll see a banner on every page: *"Mooring 0.5.0 is available."*
  There's no rush — update when it suits you.
- **Your version has a security hole.** This one matters, so it's loud: a red banner on every
  page, and if you've set up [alerts](./alerting.md), a high-priority message right away (it
  ignores your quiet hours). Update as soon as you can.

All it does is ask GitHub about Mooring's own releases and security advisories. Nothing about
your server or your apps ever leaves the box — it's just Mooring reading public information about
itself.

If you'd rather it didn't reach out to GitHub at all, turn it off:

```yaml
server:
  version_check_enabled: false
```

## Scanning your apps for known vulnerabilities

Mooring also scans the apps you deploy for known security vulnerabilities (the CVEs you hear
about) and warns you when something serious turns up. This is on by default too.

It re-scans once a day — not only when you deploy. That's deliberate: new vulnerabilities are
found in software all the time, so an image that looked fine last week might not be fine today.

The important part is *how* it scans, because Mooring never lets the scanner touch the Docker
socket (that's the core of how Mooring talks to Docker safely). So:

- **Off-the-shelf images** — like the database or message broker you pull from Docker Hub — are
  checked straight from the registry they came from.
- **Your own code** is checked by reading your project's dependency files (`package-lock.json`,
  `go.sum`, and the like), which is where most of an app's vulnerabilities actually live.

You'll find the results under **Server → Vulnerabilities**: how many Critical / High / Medium /
Low issues each app has, and the worst ones spelled out with the version that fixes them.
Anything **High or Critical** also sends you an alert. To clear a finding, update the flagged
package (bump a dependency, or update the base image) and redeploy.

One heads-up: scanning is a bit heavy. The first run downloads a vulnerability database (a few
hundred MB) and each scan uses some CPU and memory. On a small server you might prefer to turn
it off:

```yaml
server:
  image_scan_enabled: false
```

(There's one thing it can't see: the exact operating-system packages inside an image you build
yourself. Getting at those would mean handing the scanner the Docker socket, which would undo
Mooring's security model — so it doesn't.)

## All the Server-tab config keys

Everything on this page works with sensible defaults, so most people never touch this. But if you
want to adjust it, here are all the keys — the two checks above are **on by default**, the rest
are opt-in:

```yaml
server:
  # Self-update + security check — ON by default; set false to stop it contacting GitHub.
  version_check_enabled: false
  version_check_interval: 6h       # how often to check (default 6h)

  # App vulnerability scanning — ON by default; set false on a small server if it's too heavy.
  image_scan_enabled: false
  image_scan_interval: 24h         # how often to re-scan (default 24h)

  # Automatic Docker build-cache reclamation — ON by default. After each build-deploy Mooring
  # runs `docker builder prune --keep-storage` so the generated multi-stage builds' single-use
  # runtime layers don't fill the disk (they can pile up to tens of GB over many deploys). It
  # keeps the most-recently-used cache warm (e.g. your dependency-install layer).
  build_cache_keep_enabled: false  # set false to disable (then Mooring never prunes the cache)
  build_cache_keep: 5GB            # how much recent cache to keep (default 5GB)

  # Clean up old downloaded .deb files from the dashboard — off unless you set this.
  deb_cache_dir: /root/downloads

  # Read-only file browser — off unless you list folders here.
  file_roots:
    - name: app-logs
      path: /var/log/myapp
```

The host monitor, top processes, and disk-usage views need no configuration at all.
