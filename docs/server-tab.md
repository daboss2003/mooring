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
- **Vulnerabilities** — known CVEs in each deployed app's images and dependencies (see below).
- **Host vulnerabilities** — known CVEs in the host's OS packages and in the binaries Mooring
  runs, plus a notice when the host needs a reboot (see below).
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

3. Click **delete** on an old one. It removes just that file — no password re-prompt
   (this is a low-risk cleanup, not a destructive app action), and every delete is
   recorded in the **Audit log**. It can only ever remove a superseded
   `mooring_<version>_linux_(amd64|arm64).deb` sitting directly in that folder — never
   the running version, and never anything reached by a path or symlink trick.

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

You'll find the results in a **Vulnerabilities** section on the Server page itself: how many
Critical / High / Medium / Low issues each app has, and the worst ones spelled out with the
version that fixes them. Anything **High or Critical** also sends you an alert. To clear a
finding, update the flagged package (bump a dependency, or update the base image) and redeploy.

When a target of an app could not be scanned, the app's row shows
`one or more targets could not be scanned` in parentheses after the scan time. When Trivy ran but
its report could not be used, the text is followed by `: ` and the reason, one of the
[reasons listed for the host scan](#host-vulnerabilities), and the Mooring log has the detail
(`imagescan: target failed`).

The scanner runs the pinned Trivy image with no Docker socket, dropped capabilities, and
`no-new-privileges`, one `docker run` per scan in a container named `mooring-scan-` followed by
16 hex digits. A scan container that was stopped or whose run failed is
[removed](#host-vulnerabilities) (`docker rm -f`). The vulnerability database is cached in a
persistent volume so it isn't re-downloaded every scan. Trivy's usage telemetry and update check are turned off
(`--disable-telemetry --skip-version-check`), so a scan contacts only the image registry and the
vulnerability database mirrors (`mirror.gcr.io`, then `ghcr.io`).

One heads-up: scanning is a bit heavy. The first run downloads a vulnerability database (about
150 MB, about 2 GB once unpacked in the cache volume) and each scan uses some CPU and memory. On a small server you might prefer to turn
it off:

```yaml
server:
  image_scan_enabled: false
```

(There's one thing it can't see: the exact operating-system packages inside an image you build
yourself. Getting at those would mean handing the scanner the Docker socket, which would undo
Mooring's security model — so it doesn't.)

## Host vulnerabilities

The **Host vulnerabilities** section lists known CVEs in the host itself. The scan covers:

- **OS packages** — every package in the host's package database: `/var/lib/dpkg/status` on
  Debian and Ubuntu, the rpm database (`/var/lib/rpm` or `/usr/lib/sysimage/rpm`) on RHEL-family
  and Amazon Linux hosts. The OS is detected from `/etc/os-release` and the distribution's release
  file (`/etc/lsb-release`, `/etc/debian_version`, `/etc/<distro>-release` or, on Amazon Linux,
  `/etc/system-release`).
- **Binaries** — the Go binaries Mooring runs, each listed separately: `caddy (system)` (the
  `caddy` on `PATH`), `caddy (Mooring-owned build)` (`<data_dir>/bin/caddy`, when present; not
  scanned when Mooring runs as root, which never uses that build, or with `edge.mode: external`),
  `docker`, `dockerd`, `containerd`, `containerd-shim-runc-v2`, `runc`, `docker-proxy` (on `PATH`, else
  `/usr/libexec/docker/docker-proxy` or `/usr/lib/docker/docker-proxy`), `docker compose` and
  `docker buildx` (the CLI plugins, from `/usr/libexec/docker/cli-plugins`,
  `/usr/lib/docker/cli-plugins` or `/usr/local/lib/docker/cli-plugins`) and `mooring`. A binary that
  isn't installed is left out. Binaries under `/snap/` are not scanned.

For each target the section shows the Critical / High / Medium / Low counts with how many of each
have a fixed version, and the worst 25 findings with their fixed version (or "no fix yet"). A
target that could not be scanned shows the reason instead of counts: for example a binary that is
not world-readable, or a host without a dpkg or rpm database.

When Trivy reports the OS release as end of life (no longer supported by the distribution), the
section shows the notice "This OS release is end of life: it gets no more security fixes, so a
clean result doesn't mean it's safe." The scan only finds vulnerabilities that the distribution
has published, so an end-of-life release shows few or no findings. No alert is sent for it.

How it runs:

- One `docker run` of the pinned Trivy image per scan (`trivy rootfs`). The container is named
  `mooring-scan-` followed by 16 hex digits, a new name for every scan (visible in `docker ps`).
  The release files, the
  package database and each binary are bind-mounted read-only under `/host`, each at `/host`
  followed by its path with symlinks resolved (on Amazon Linux 2023, `/etc/system-release` is
  mounted as `/host/usr/lib/system-release`); nothing else on the host is visible to the scanner,
  and nothing on the host is changed.
- No Docker socket, all capabilities dropped, `no-new-privileges`. The vulnerability database is
  shared with the app scan (the `mooring-trivy-cache` volume).
- It runs on the app scan's schedule (`server.image_scan_interval`, default 24h; the first run is
  about 2 minutes after Mooring starts), before the app scans, one Trivy container at a time. It
  runs even when `server.image_scan_enabled` is `false`.
- Trivy's JSON report is read as a stream. Limits: 1024 MiB for the report, 4 MiB for one entry
  of it (one finding, one string), 32 MiB of kept findings, and 512 levels of nesting. A report
  over a limit fails the scan and the scanner is stopped: `docker run` gets `SIGTERM` and is
  killed when it has not exited after 10 seconds. The app scans have the same limits.
- After a scan whose `docker run` did not end by itself with exit status 0 (stopped for a report
  limit, the scan timeout or a shutdown of Mooring, or a failed run), Mooring removes the scan
  container with `docker rm -f <name>`, with a limit of 30 seconds. A removal that fails is logged
  as `WARN` `imagescan: scan container not removed; it can run until the scanner's own timeout`
  (with `container`, `err` and `docker_stderr`); the scan's failure reason is unchanged. The app
  scans do the same.

A failed scan:

- With no completed scan before it, the section shows only the failure, "No host scan has
  completed yet, so there are no results to show", and the time of the last attempt.
- After a completed scan, the section shows the failure and the earlier results, labelled
  "Results of the last scan that completed, not of the failed one", with that scan's time.
- When Trivy ran but its report could not be used, the failure is `the last host scan failed: `
  followed by one of the reasons below. For any other failure (Docker, the image pull, Trivy's
  exit status) it is `the last host scan failed; the Mooring log (journalctl -u mooring) has the
  cause`. The Mooring log has the detail in both cases (`imagescan: host scan failed`).
- A failed scan sends no `host_vulnerabilities` alert.

| Reason | Meaning |
|---|---|
| `the scanner returned no output` | Trivy wrote no report. |
| `the scan report is incomplete` | The report ends before its JSON is complete. |
| `the scan report is larger than 1024 MiB` | The report limit. |
| `one entry of the scan report is larger than 4 MiB` | The limit for one entry. |
| `the scan report has more findings than Mooring keeps (32 MiB)` | The limit for kept findings. |
| `the scan report is nested deeper than 512 levels` | The limit for nesting. |
| `the scan report is not valid JSON` | The report is not JSON. |
| `the scan report is not in the format Mooring reads` | The JSON is not a Trivy report in the expected form. |

Alerts (see [Alerts](./alerting.md#host-and-edge-maintenance-alerts)):

- `host_vulnerabilities` — a scan finds a High or Critical finding with a fixed version that no
  earlier `host_vulnerabilities` alert included since Mooring started. A finding is identified by
  its CVE ID, package and target. Level `critical` when one of the new findings is Critical,
  otherwise `warning`. The alert counts the new findings, gives the totals, names up to three of
  the new ones and says how to fix every High or Critical finding with a fixed version in the scan
  (see below). A scan with only findings that were already alerted, or with fewer findings, sends
  nothing. After a Mooring restart, findings that remain are alerted once more. Findings without a
  fixed version are listed but never alert.
- `host_reboot_required` — see **Pending reboot** below.

To clear findings, upgrade only the affected packages:

- Debian and Ubuntu: `sudo apt-get update && sudo apt-get install --only-upgrade <package>…`
- RHEL family, Fedora and Amazon Linux 2023: `sudo dnf upgrade <package>…` (`sudo yum upgrade
  <package>…` on Amazon Linux 2 and on RHEL, CentOS or Oracle Linux 7)

A full `sudo apt-get upgrade` or `sudo dnf upgrade` also upgrades Docker (`docker-ce`,
`containerd.io`, …) when an update for it is available. Upgrading Docker or the container runtime
restarts Docker and every container on the host.

The `host_vulnerabilities` alert gives this command with the names of the OS packages that have a
High or Critical finding with a fixed version in the scan, sorted, up to 20 (the rest are counted,
with "see the Server tab"). Only names made of `A-Z`, `a-z`, `0-9` and `.+_:-` that start with a letter
or digit and don't end with `-` are printed. When one of them is a Docker or container-runtime package (`docker-ce`,
`docker-ce-cli`, `docker-ce-rootless-extras`, `containerd.io`, `docker-buildx-plugin`,
`docker-compose-plugin`, `docker.io`, `containerd`, `runc`, `moby-*`), or one of Docker's binaries has
such a finding, the alert says that upgrading restarts Docker and every container on the host.

Binaries are updated by the packages that installed them, once those ship a rebuilt version;
`mooring` is updated by a Mooring release. The alert names the affected binaries.

The Mooring-owned Caddy build is refreshed by Mooring, never by a package upgrade, and only when Mooring runs the managed edge
(`edge.mode: managed`). When a host scan finds a finding with a fixed version in that build,
Mooring downloads a current build (at most one download every 20 hours, counted from the last
attempt; the time is kept in `<data_dir>/bin/caddy.refresh-attempt`, so a Mooring restart doesn't
reset it):

- The download differs from the installed build: Mooring swaps it in, keeps the previous build as
  `<data_dir>/bin/caddy.bak`, restarts the edge and sends `caddy_build_refreshed`.
- The download is the same build as the installed one (same Go build info): nothing changes and no
  alert is sent; Mooring logs it.
- The download or its check fails: the download is deleted, the installed build keeps running and
  Mooring sends `caddy_build_refresh_failed`. The check includes `caddy validate` of the config the
  edge serves.
- Caddy still refuses the edge config that held the last downloaded build back: nothing is
  downloaded, no attempt is recorded, and Mooring sends `caddy_build_refresh_failed` (`waiting for
  Caddy to accept the edge config`).

With `edge.mode: external` the owned build is neither scanned nor refreshed.

### Pending reboot

On Debian and Ubuntu, an update that needs a reboot creates `/run/reboot-required` and lists the
packages that asked for it in `/run/reboot-required.pkgs`. While the file exists, the section shows
a notice with those packages (up to 20), and after each host scan Mooring sends a
`host_reboot_required` alert (level `warning`), again when the package list changes.

To disable the host scan:

```yaml
server:
  host_scan_enabled: false
```

## Image updates

The **Image updates** section lists services that run a pinned image (for example `image: postgres:16`)
and whether a newer image is available for that tag.

For each such service, Mooring reads the image's current digest from its registry and compares it
with the pulled digest. When they differ, the service is marked **update available**; redeploying the
app pulls the newer image. Mooring sends one alert per new digest and never redeploys on its own.

The check is **on by default** and runs every 24 hours (`server.image_update_interval`).

Scope and behavior:

- Only services that run a pinned image are checked. Services built from Git use the repo poller's
  "update available" instead; a service pinned to a digest (`image: postgres@sha256:…`) is skipped.
- The registry digest is read with `docker` metadata-only commands (`docker image inspect`,
  `docker buildx imagetools inspect`). It uses the host's existing registry logins and does not pull
  image layers.
- A registry that is unreachable, or a private image the host is not logged in to, records the error
  for that service and does not alert.

To disable it:

```yaml
server:
  image_update_check_enabled: false
```

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
  image_scan_interval: 24h         # how often to re-scan (default 24h); the host scan uses it too

  # Host vulnerability scanning (OS packages + the binaries Mooring runs) — ON by default.
  host_scan_enabled: false

  # Image-update detection for pull-image services — ON by default; set false to disable.
  image_update_check_enabled: false
  image_update_interval: 24h       # how often to re-check the registry (default 24h)

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
