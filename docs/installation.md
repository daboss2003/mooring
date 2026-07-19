# Install Mooring

> **Getting started, 2 of 3** · [← Introduction](./introduction.md) · Next: [Deploy your first app →](./first-steps.md)

This is the one part you do over SSH. It takes about five minutes: put the program on your server, create your login, and start it. After this, everything happens in the dashboard.

## What you need

- A **Linux server** with `systemd` (any cheap VPS works).
- **Docker** installed, with the Compose plugin (`docker compose`).
- **Caddy** — the managed HTTPS edge supervises a child Caddy for `:80`/`:443` + automatic certificates. It isn't bundled (it's third-party, like Docker); `mooring setup` installs it for you (below), or the `.deb`/`.rpm` pulls it in if you've added Caddy's apt repo.
- **SSH access** to the server.
- **1 GB of RAM or more** if you want to deploy and build apps on the box. Monitoring and HTTPS run fine on a smaller server.

> **Why doesn't Mooring just install these itself at runtime?** Because the running service is deliberately **unprivileged** — it can't install packages, edit host DNS, or grant capabilities. That's the security model: a compromised dashboard must not be able to either. So prerequisites are a one-time, admin-run, root job — which `mooring setup` makes a single command (it runs as *you* over SSH, not as the service).

## 1. Install the program

> `apt install mooring` with nothing else only works for packages that ship in Debian/Ubuntu's own repositories (that's why `apt install python` just works). Mooring is third-party, so `apt` needs to be told where to find it once — exactly like installing Docker, Chrome, or Tailscale. Pick one:

**Quickest — install the `.deb` directly.** Download the `.deb` for your architecture from the [latest release](https://github.com/daboss2003/mooring/releases/latest), then:

```bash
sudo apt install ./mooring_<version>_linux_amd64.deb
```

`apt` pulls in any dependencies, creates the `mooring` service user, and installs the systemd unit — so you can **skip Step 4**. To update later, download the newer `.deb` and run the same command.

> **Seeing `N: Download is performed unsandboxed as root … couldn't be accessed by user '_apt' … Permission denied`?** That's a harmless *note*, not a failure. `apt`'s unprivileged sandbox user can't read files in your home directory (it's mode `0750`), so `apt` copies the `.deb` as root and the install completes anyway — confirm with `dpkg -l mooring`. To avoid the note, install from a path `_apt` can read (download into `/tmp`), or skip the sandbox with `dpkg`:
>
> ```bash
> sudo dpkg -i mooring_<version>_linux_amd64.deb && sudo apt-get install -f
> ```

**Best for updates — add the signed APT repo (once).** Then `sudo apt upgrade` keeps Mooring current automatically, and every download is signature-checked:

```bash
curl -fsSL https://daboss2003.github.io/mooring/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/mooring.gpg
echo "deb [signed-by=/usr/share/keyrings/mooring.gpg] https://daboss2003.github.io/mooring stable main" | sudo tee /etc/apt/sources.list.d/mooring.list
sudo apt update && sudo apt install mooring
```

(Fedora/RHEL: a matching `.rpm` is on each release — `sudo dnf install ./mooring_<version>_linux_amd64.rpm` (or `_linux_arm64.rpm`).)

**Any other Linux — the raw binary.** Grab the binary for your architecture from the [releases page](https://github.com/daboss2003/mooring/releases) and put it in place (update by replacing the file). With this option you also do Step 4 to create the service:

```bash
install -m0755 mooring /usr/local/bin/mooring
mooring version
```

### Host prerequisites — what's automatic, and the few things you do once

**Most host prep is automatic.** The package's systemd unit + postinstall already create the
runtime dir (`/run/mooring`) and the writable state dirs, grant the one capability the edge needs
(`CAP_NET_BIND_SERVICE`, so Caddy/nginx bind `:80`/`:443`/`:53` non-root), set a writable `HOME`
and a sane `MemoryMax`, and leave the egress filter off by default. You don't apply drop-ins or
tune the unit.

There are only a **few one-time steps you do by hand** — `mooring doctor` tells you if any are
missing (it's read-only; run it any time to verify the box):

```bash
mooring doctor              # read-only: reports anything off + the exact fix
sudo mooring setup --yes    # installs the Caddy binary — the managed edge needs it
```

> **Mooring runs its OWN supervised Caddy (and nginx for L4).** The packaged
> `caddy.service`/`nginx.service` would squat `:80`/`:443` and crash-loop Mooring's
> edge (you'd see a green `doctor` of old but a cert failure at deploy: *"the edge has
> not issued the TLS cert yet"*). `mooring setup` now **disables those distro units**
> whenever they're present — even if you installed Caddy/nginx yourself beforehand. If
> you ever add them later, run `sudo mooring setup --yes` again (or
> `sudo systemctl disable --now caddy nginx`). `mooring doctor` flags an active/enabled
> distro `caddy`/`nginx` as a **conflict** with the one-line fix.

That's everything for a normal HTTPS app. Two extras apply **only in specific cases**:

- **A non-HTTP service on a privileged port (a DNS resolver on `:53`, MQTT, …)?** Install the L4
  load balancer's nginx + stream module, and — only if you bind `:53` — free it from
  `systemd-resolved` (Mooring never rewrites host DNS for you, because getting it wrong takes the
  box's own DNS down):
  ```bash
  sudo mooring setup --l4 --yes      # nginx + the stream module
  # then, ONLY for a :53 resolver, free the port from systemd-resolved:
  printf '[Resolve]\nDNSStubListener=no\n' | sudo tee /etc/systemd/resolved.conf.d/no-stub.conf
  sudo systemctl restart systemd-resolved
  sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf   # the real upstreams — NOT stub-resolv.conf
  getent hosts github.com             # confirm host DNS still resolves
  ```

- **(Recommended) Cap Docker's container logs.** Mooring *streams* logs (it never buffers them in
  memory or its DB), but Docker's default `json-file` driver keeps every container's stdout on disk
  **forever** — on a small VPS that fills the disk. `mooring setup` caps it for you (merges a
  `max-size` into `/etc/docker/daemon.json`, preserving your other settings, then restarts Docker).
  That restart **bounces running containers**, so it's a reviewable step in the plan — run `setup`
  *before* you deploy apps and it's a no-op disruption. The equivalent by hand:
  ```json
  { "log-driver": "json-file", "log-opts": { "max-size": "10m", "max-file": "3" } }
  ```
  then `sudo systemctl restart docker` (or use the self-rotating `local`/`journald` driver).

When `mooring doctor` is all-green, the host is ready — there's nothing else to tune.

## 2. Create your login and encryption key

These commands create the secrets Mooring needs. You run them over SSH — never in a browser — so your master key and password never travel anywhere they shouldn't. They print what to paste into your config in the next step.

```bash
# A master key that encrypts your stored secrets. Back this up somewhere safe.
mooring gen-key

# Your dashboard password (you'll be prompted to type it; it's never shown or logged).
mooring hash-password

# Optional: turn on two-factor sign-in. Prints a QR code to scan with your
# authenticator app, plus the secret to paste into your config below.
mooring gen-totp
```

> **Keep your master key safe.** It's what unlocks your stored secrets. Save a copy somewhere separate from the server. If you lose it, the encrypted data can't be recovered.

## 3. Write your config file

`/etc/mooring/config.yaml` is the only file you edit by hand. It holds the essentials: your key, your login, who's allowed to reach the dashboard, and your email for HTTPS certificates. There's no command that generates it for you — it contains your master key and login, so you write it over SSH.

If you installed the `.deb`/`.rpm`/`apt` package, the directory already exists and a template is on disk — copy it and edit:

```bash
sudo cp /usr/share/mooring/config.example.yaml /etc/mooring/config.yaml
sudo nano /etc/mooring/config.yaml      # or: sudo vi /etc/mooring/config.yaml
```

Fill in the essentials (below), then lock the file down — Mooring refuses to boot if it's group/world-writable or unreadable by the service:

```bash
sudo chown root:mooring /etc/mooring/config.yaml && sudo chmod 0640 /etc/mooring/config.yaml
```

The file:

```yaml
# /etc/mooring/config.yaml
bind_addr: "127.0.0.1:9000"        # the dashboard is private — only reachable as below

encryption_key: "<paste from gen-key>"

ip_allowlist:                       # who may reach the dashboard (your IP / VPN)
  - "203.0.113.10/32"

auth:
  username: "operator"
  password_hash: "<paste from hash-password>"
  # totp_secret: "<paste from gen-totp>"   # optional two-factor

edge:
  mode: "managed"                   # Mooring runs the web server + HTTPS for you
  acme_email: "you@example.com"     # used by Let's Encrypt for your certificates

admin:
  hostname: "admin.example.com"     # the dashboard's address; point its DNS at this server

data_dir: "/var/lib/mooring"       # where Mooring keeps its data
```

Set `admin.hostname` to the address you want the dashboard on, and point that hostname's DNS at your server — Mooring serves it over HTTPS, behind your IP allowlist. If you use the [subdomain shorthand](./definition-file.md#specedgeroutes) (`edge.base_domain`), you can instead set just `admin.subdomain: admin` and it becomes `admin.<base_domain>` — covered by the same wildcard DNS record as your apps:

```yaml
edge:
  base_domain: mooring.example.com
admin:
  subdomain: admin                  # → admin.mooring.example.com (or use admin.hostname for a full name)
```

(Prefer not to expose it at all? Leave both out and reach the dashboard over an SSH tunnel instead — see the next guide.)

> **When you expose the admin dashboard, it becomes internet-reachable** — gated by your `ip_allowlist` (enforced at the edge *and* re-checked against the real client), then your password + **TOTP**. Keep `ip_allowlist` tight (never a catch-all), and enable TOTP. Mooring fronts the dashboard through the managed edge to a **dedicated internal listener** (`admin.edge_listen`, default `127.0.0.1:9001`) so your SSH-tunnel access on `bind_addr` keeps working unchanged. Exposing/unexposing needs a **restart** (listeners are fixed at boot). If you use GitHub connect, re-register your OAuth App's callback as `https://<admin hostname>/github/callback`.

#### Optional: one wildcard certificate for all subdomains (ACME DNS-01)

By default each declared subdomain gets its own certificate via HTTP-01. If you run many
subdomains (or want a name that isn't HTTP-reachable), you can instead issue **one
`*.<base_domain>` wildcard** via ACME **DNS-01** — no per-name rate limits, one cert for
everything under `base_domain`:

```yaml
edge:
  base_domain: mooring.example.com
  dns01:
    provider: cloudflare            # your DNS provider (cloudflare, route53, digitalocean, …)
    api_token: "<dns-api-token>"    # secret — a token scoped to edit this zone
```

**Mooring installs the right Caddy plugin for you** — you don't build anything. DNS-01 needs
your provider's DNS module compiled into Caddy, so on startup Mooring runs `caddy add-package`
(Caddy's official mechanism: it downloads a plugin-enabled binary and swaps it in) for the
`provider` you named. It supports every provider in the [caddy-dns](https://github.com/orgs/caddy-dns/repositories)
family — Cloudflare, Route 53, DigitalOcean, Google Cloud DNS, Azure, Hetzner, Vultr, Linode,
Namecheap, and more. (If the auto-install can't run — e.g. the box can't reach `caddyserver.com`
or the `caddy` binary isn't writable by the service — Mooring logs a clear warning and the edge
still comes up; the wildcard just won't issue until the plugin is present. Nothing is ever
mis-issued.)

With `dns01` set, subjects at/under `base_domain` are served by the one wildcard; hostnames
outside it keep their own HTTP-01 cert. The `api_token` is stored only in the root-only
`config.yaml` (never logged or shown in the dashboard) and passed solely to the supervised Caddy.

Mooring validates this file at startup. If a required value is missing or the file permissions are too open, it stops with a clear message explaining what to fix.

> Everything *else* about your apps lives in the dashboard (or an optional per-app file). This config is just the foundation.

## 4. Start it

> ### Installed via `.deb` / `.rpm` / `apt`? Almost everyone — do this and skip the rest of this section.
>
> The package's postinstall **already** created the `mooring` service user, the data directories (`/var/lib/mooring`, `/var/lib/mooring-apps`, `/var/lib/caddy`), `/etc/mooring`, and the systemd unit. **Do _not_ run the manual commands below** — they're for the raw-binary install only, and running them produces harmless-but-confusing errors like `user 'mooring' already exists` and `cannot stat 'config.yaml'`. Once your config from Step 3 is in place, just start it:
>
> ```bash
> sudo systemctl enable --now mooring
> sudo systemctl status mooring     # → "active (running)"
> ```
>
> Then jump to the verification at the end. (Run everything with `sudo` — a plain `systemctl enable` will hang on a polkit password prompt.)

**Only if you installed the raw binary** (Step 1's last option — no package, so nothing was set up for you) do you create the service account, directories, and unit by hand. Run these with `sudo`, from a checkout of the repo so `deploy/systemd/mooring.service` exists:

```bash
sudo groupadd --system mooring
sudo useradd --system --no-create-home --shell /usr/sbin/nologin --gid mooring mooring
sudo usermod -aG docker mooring
sudo install -d -o root    -g mooring -m0750 /etc/mooring
sudo install -d -o mooring -g mooring -m0700 /var/lib/mooring
sudo install -d -o mooring -g mooring -m0700 /var/lib/mooring-apps   # per-app run dirs
sudo install -d -o mooring -g mooring -m0700 /var/lib/caddy          # edge data/cert store
sudo install -m0644 deploy/systemd/mooring.service /etc/systemd/system/mooring.service
# (write /etc/mooring/config.yaml per Step 3, then:)
sudo chown root:mooring /etc/mooring/config.yaml && sudo chmod 0640 /etc/mooring/config.yaml
sudo systemctl daemon-reload && sudo systemctl enable --now mooring
sudo systemctl status mooring
```

That's it. **You won't run any Docker commands** — Mooring sets up everything it needs to talk to Docker (a locked-down, read-only connection) and runs your HTTPS edge itself. From here on, it's all in the dashboard.

### Editing the config file (reload vs restart)

`/etc/mooring/config.yaml` is read at **startup**. After you hand-edit it, Mooring won't notice the change on its own — you have to tell it to pick it up, and **how depends on what you changed**:

| You changed… | Apply with |
|---|---|
| Who can reach the dashboard (`ip_allowlist`, `trust_proxy`, `trusted_proxies`), your login (`auth.username`, `auth.password_hash`, `auth.totp_secret`), or log retention (`retention.*`) | **`sudo systemctl reload mooring`** — hot-applied, no downtime |
| **Anything else** — the master `encryption_key`, `bind_addr`, `edge.*` (incl. `base_domain`, `dns01`, `l4_enabled`), `admin.*` (incl. `subdomain`, `edge_listen`), `github.*`, `alerting.*`, `session.*`, `cookie.*`, `docker.*`, `protected_projects`, … | **`sudo systemctl restart mooring`** |

The rule of thumb: only the **allowlist + login + retention** are hot-reloadable; **everything else is read once at boot and needs a restart**. A reload that touches a restart-only setting will *silently do nothing* — so when in doubt, `restart` (it briefly drops the dashboard connection; your apps keep running).

> **Reload is safe:** it validates the new file first and **keeps the old config if the edit is invalid**. One side effect to know: enabling/rotating two-factor (`auth.totp_secret`) on reload **logs you out**, so you re-authenticate with the new factor.

(Most *app* settings — env, routes, scaling, self-healing, ops — aren't in this file at all; you manage them in the dashboard, which applies them live. This file is just the bootstrap essentials.)

## 5. You're ready

Mooring is now running and serving HTTPS. Nothing is published yet — that happens when you add an app and give it a domain.

> **Next: [Deploy your first app →](./first-steps.md)**

---

*Want the security and hardening details of the service file (memory caps, sandboxing, network egress lock-down)? See [How it works & why it's safe](./architecture.md). Running your own Docker connection instead of the built-in one? Set `docker.external_proxy: true` — see [the CLI reference](./cli.md).*
