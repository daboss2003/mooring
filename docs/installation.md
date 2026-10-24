# Install Mooring

> **Getting started, 2 of 3** · [← Introduction](./introduction.md) · Next: [Deploy your first app →](./first-steps.md)

This guide takes a fresh Linux server to a running Mooring you can sign in to. Do the steps in
order: each one ends with a **Check**, so you know it worked before you move on. It's all over SSH
and takes about 15 minutes. After this, you work in the dashboard.

The commands are for **Ubuntu 22.04 / 24.04 and Debian 12**. On another distribution, follow the
same steps and use [the raw binary](#other-linux-install-the-raw-binary) in Step 3.

## Before you start

You need:

| | |
|---|---|
| A Linux server with `systemd` | any VPS; **1 GB of RAM or more** if apps are built on the box |
| SSH access with `sudo` | every command below runs over SSH |
| A domain whose DNS you control | for the dashboard (optional) and for your apps |
| Your own public IP address | only if you'll put the dashboard on a hostname (`curl -s https://ifconfig.me`) |

> **Why can't Mooring install all of this itself?** The running service is deliberately
> **unprivileged**: it can't install packages, edit host DNS or grant capabilities, so a
> compromised dashboard can't either. Everything that needs root is a one-time step you run here.

## Step 1. Open ports 80 and 443

Mooring's edge serves HTTPS on **443** and needs **80** to get certificates from Let's Encrypt.

- **Cloud firewall** (AWS security group, Lightsail networking, Hetzner/DigitalOcean firewall):
  allow inbound **TCP 22, 80 and 443**.
- **`ufw` on the server** (only if you use it; allow SSH first, or you lock yourself out):

  ```bash
  sudo ufw allow OpenSSH
  sudo ufw allow 80/tcp
  sudo ufw allow 443/tcp
  sudo ufw enable
  ```

**Check:** `sudo ufw status` lists 22, 80 and 443 (or your cloud console shows the three rules).

## Step 2. Install Docker

Install Docker **before** Mooring: the Mooring package adds its service user to the `docker` group,
and it can only do that if the group already exists.

If these already print versions (Compose `v2.x`), skip to Step 3:

```bash
docker --version
docker compose version     # note the space: the v2 Compose plugin, not docker-compose
docker buildx version
```

Otherwise install the engine with the Compose and Buildx plugins from Docker's own repository
(Mooring needs all three: it builds images with BuildKit):

```bash
# 1. Docker's signing key
sudo apt update
sudo apt install -y ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# 2. Docker's repository
sudo tee /etc/apt/sources.list.d/docker.sources >/dev/null <<EOF
Types: deb
URIs: https://download.docker.com/linux/ubuntu
Suites: $(. /etc/os-release && echo "${UBUNTU_CODENAME:-$VERSION_CODENAME}")
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/docker.asc
EOF
sudo apt update

# 3. The engine and the two plugins
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

On **Debian**, replace both `ubuntu` above with `debian`. Other distributions:
<https://docs.docker.com/engine/install/>.

**Check:** the three commands at the top of this step print versions, and `docker compose
version` says `v2.x`.

## Step 3. Install Mooring

Add Mooring's signed APT repository once, then install. `sudo apt upgrade` then keeps Mooring up to
date, and every download is signature-checked:

```bash
curl -fsSL https://daboss2003.github.io/mooring/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/mooring.gpg
echo "deb [signed-by=/usr/share/keyrings/mooring.gpg] https://daboss2003.github.io/mooring stable main" | sudo tee /etc/apt/sources.list.d/mooring.list
sudo apt update && sudo apt install -y mooring
```

<details>
<summary>Or install the <code>.deb</code> file directly (no repository)</summary>

```bash
cd /tmp       # a folder apt's sandbox can read (a home dir gives a harmless "unsandboxed" note)
ARCH=$(dpkg --print-architecture)
TAG=$(curl -fsSL https://api.github.com/repos/daboss2003/mooring/releases/latest | grep -oP '"tag_name":\s*"\K[^"]+')
curl -fsSLO "https://github.com/daboss2003/mooring/releases/download/${TAG}/mooring_${TAG#v}_linux_${ARCH}.deb"
sudo apt install -y "./mooring_${TAG#v}_linux_${ARCH}.deb"
```

Fedora / RHEL: the same release has `mooring_<version>_linux_<arch>.rpm`
(`sudo dnf install ./mooring_<version>_linux_amd64.rpm`).
</details>

The package creates the `mooring` service user, its folders (`/etc/mooring`, `/var/lib/mooring`,
`/var/lib/mooring-apps`, `/var/lib/caddy`), a config template, and the systemd service. It does
**not** start the service: that happens in Step 8, once the config exists.

**Check:** `mooring version` prints a version, and `systemctl list-unit-files mooring.service`
shows the service (disabled for now).

## Step 4. Install Caddy, the HTTPS edge

Mooring runs its own copy of [Caddy](https://caddyserver.com) for ports 80/443 and certificates. It
must be **Caddy's official build, version 2.11 or later**. Ubuntu's and Debian's own `caddy`
package is too old (Ubuntu ships 2.6.2) and can't take the DNS plugins wildcard certificates need,
so don't use `apt install caddy` on its own.

1. See whether a Caddy is already there:

   ```bash
   caddy version 2>/dev/null || echo "no caddy"
   ```

   | It prints | Do this |
   |---|---|
   | `no caddy` | go on to 2 |
   | `v2.11…` or later (official builds start with `v`) | go on to 2 |
   | `2.6.2`, anything without a leading `v`, or below `v2.11` | remove it first: `sudo apt-get remove -y caddy` |

2. Let Mooring install the official Caddy and prepare the host. Without `--yes` it only prints what
   it would do; read it, then apply:

   ```bash
   sudo mooring setup          # the plan
   sudo mooring setup --yes    # apply it
   ```

   This installs Caddy from Caddy's official repository, turns off the separate `caddy` service
   that package brings (Mooring supervises its own Caddy, and the packaged service would take
   ports 80/443), and caps Docker's container logs so they can't fill the disk. Capping the logs
   restarts Docker, which is why you do this before deploying any app.

**Check:**

```bash
caddy version              # v2.11 or later
systemctl is-enabled caddy # disabled (or "not-found")
```

When `edge.dns01` is set for a namespace, Mooring installs a Caddy build with that DNS provider's
plugin as `/var/lib/mooring/bin/caddy` and runs the edge from it. The Caddy package you installed
stays as the fallback. This needs outbound HTTPS to `caddyserver.com`. See
[DNS-01 and the Caddy DNS plugin](./edge-and-tls.md#dns-01-and-the-caddy-dns-plugin).

## Step 5. Create your master key and password

Run these and keep the output for Step 6. Run them over SSH only, never in a browser.

```bash
mooring gen-key            # the master key that encrypts your stored secrets
mooring hash-password      # asks for your dashboard password, prints its hash
mooring gen-totp           # optional, recommended: two-factor sign-in (shows a QR code to scan)
```

> **Back up the master key now**, somewhere off this server. It's what decrypts your stored
> secrets: lose it and they can't be recovered.

## Step 6. Write the config file

`/etc/mooring/config.yaml` is the only file you edit by hand. Start from the template:

```bash
sudo cp /usr/share/mooring/config.example.yaml /etc/mooring/config.yaml
sudo nano /etc/mooring/config.yaml
```

Make it look like this, pasting in your values from Step 5:

```yaml
# /etc/mooring/config.yaml
bind_addr: "127.0.0.1:9000"          # the dashboard listens on this server only

encryption_key: "<from mooring gen-key>"

ip_allowlist:                         # who may open the dashboard
  - "127.0.0.1/32"                    # needed for the SSH tunnel (Step 9)
  - "::1/128"
  # - "203.0.113.10/32"               # your own IP, only if you add admin.hostname below

auth:
  username: "operator"
  password_hash: "<from mooring hash-password>"
  # totp_secret: "<from mooring gen-totp>"

edge:
  mode: "managed"                     # Mooring runs the HTTPS edge for you
  acme_email: "you@example.com"       # Let's Encrypt's contact for your certificates
  acme_ca: "https://acme-v02.api.letsencrypt.org/directory"

data_dir: "/var/lib/mooring"
```

| Setting | What to put | Required |
|---|---|---|
| `bind_addr` | keep `127.0.0.1:9000`. It must be loopback: the edge, or your SSH tunnel, is the only way in | yes |
| `encryption_key` | the output of `mooring gen-key` | yes |
| `ip_allowlist` | keep both loopback lines: requests through an SSH tunnel come from `127.0.0.1`, and anything not listed gets a plain 404, even the tunnel. Add your own IP only if you put the dashboard on a hostname | yes, at least one entry |
| `auth.username` / `auth.password_hash` | your login, the hash from `mooring hash-password` | yes |
| `auth.totp_secret` | the secret from `mooring gen-totp` | no, but strongly recommended |
| `edge.mode` | `managed` | yes |
| `edge.acme_email` | an email address you read | yes |
| `edge.acme_ca` | Let's Encrypt's directory, exactly as above. (Testing? `https://acme-staging-v02.api.letsencrypt.org/directory` issues untrusted test certificates without Let's Encrypt's rate limits) | yes, Mooring won't start without it |
| `data_dir` | keep `/var/lib/mooring` | yes |

Want the dashboard on its own address instead of the SSH tunnel? Add `admin.hostname` now or
later: see [Put the dashboard on its own hostname](#optional-put-the-dashboard-on-its-own-hostname).

Then lock the file down. Mooring refuses to start if anyone but root can write it, or if it's
readable by anyone outside the `mooring` group:

```bash
sudo chown root:mooring /etc/mooring/config.yaml
sudo chmod 0640 /etc/mooring/config.yaml
```

**Check:** `sudo ls -l /etc/mooring/config.yaml` shows `-rw-r----- 1 root mooring`.

## Step 7. Point DNS at the server

Skip this for now if you'll use the SSH tunnel and have no app yet: come back when you give an app
a domain.

At your DNS provider, add an **A** record (and **AAAA** if the server has IPv6) pointing at the
server's public IP for:

- the dashboard's hostname, if you set `admin.hostname` (e.g. `admin.example.com`);
- each app hostname, or one wildcard record `*.<base_domain>` if you use
  [`edge.base_domain`](./edge-and-tls.md#subdomain-namespaces-colocating-apps-under-one-apex).

**Using Cloudflare?** Set every record to **DNS only** (the grey cloud), not proxied. Mooring issues
and serves its own certificates, and Cloudflare's free certificate doesn't cover names two levels
deep, such as `shop.app.example.com`.

**Check:** `dig +short admin.example.com` prints the server's IP. Mooring requests a hostname's
certificate only once the name resolves to this server.

## Step 8. Start Mooring

```bash
sudo systemctl enable --now mooring
sudo systemctl status mooring --no-pager     # → active (running)
sudo -u mooring mooring verify-key           # → verify-key: OK — key matches the DB
sudo mooring doctor                          # every line reads ok
```

Run `verify-key` as the `mooring` user: on a fresh install it creates the database, which must
belong to the service. Use `sudo` for `systemctl`: without it, `systemctl enable` waits on a
password prompt you never see.

**Check:** `status` says `active (running)` and `doctor` has no `fail` lines. If Mooring doesn't
start, the reason is in its log: `sudo journalctl -u mooring -n 50 --no-pager` (config mistakes
name the exact key; see [Troubleshooting](#troubleshooting)).

## Step 9. Open the dashboard

**Through an SSH tunnel** (works right away). On your own computer:

```bash
ssh -L 9000:127.0.0.1:9000 <you>@<server>
```

then open <http://127.0.0.1:9000> and sign in with the username and password from Step 5.

**On its own hostname**, if you set it up: open `https://admin.example.com`.

You're done. **Next: [Deploy your first app →](./first-steps.md)**

---

## Optional: one wildcard certificate for all subdomains (DNS-01)

By default every hostname gets its own certificate over HTTP. Switch a domain to **one
`*.<base_domain>` wildcard certificate** when you run many subdomains, when a name isn't reachable
over HTTP, or when an app uses a [catch-all route](./edge-and-tls.md#catch-all-routes) (which
requires one). This example uses **Cloudflare**. Mooring passes the token to the provider's
[caddy-dns](https://github.com/orgs/caddy-dns/repositories) module as `api_token`, so a provider whose
module takes other credentials (Route 53, for example) is refused; see
[DNS-01 and the Caddy DNS plugin](./edge-and-tls.md#dns-01-and-the-caddy-dns-plugin).

1. **Create a Cloudflare API token** (never the Global API Key):
   1. Cloudflare dashboard → your profile (top right) → **API Tokens** → **Create Token** → the
      **Edit zone DNS** template → **Use template**.
   2. **Permissions:** keep **Zone / DNS / Edit** and add **Zone / Zone / Read**.
   3. **Zone Resources:** **Include / Specific zone /** your domain (the registered domain, e.g.
      `example.com`, even when the wildcard is for `app.example.com`).
   4. Optional: **Client IP Address Filtering → Is in →** this server's public IP.
   5. **Continue to summary → Create Token**, and copy it: it's shown once. Don't set an expiry:
      Mooring renews the certificate with it.
2. **Check the token** from the server, without leaving it in your shell history:

   ```bash
   read -rs CF_TOKEN    # paste, then Enter
   curl -s -H "Authorization: Bearer $CF_TOKEN" https://api.cloudflare.com/client/v4/user/tokens/verify
   unset CF_TOKEN
   ```

   It answers `"status": "active"`.
3. **Add it to the config** (it lives only in this root-owned file):

   ```yaml
   edge:
     base_domain: app.example.com
     dns01:
       provider: cloudflare
       api_token: "<the token>"
   ```

4. **DNS:** a wildcard record `*.app.example.com` → the server (DNS only on Cloudflare), plus a
   record for `app.example.com` itself if the base name serves a site (a wildcard never covers it).
5. **Restart:** `sudo systemctl restart mooring`. On startup Mooring installs a Caddy build with the
   Cloudflare plugin as `/var/lib/mooring/bin/caddy` (in the background; the edge stays up), restarts
   the edge on it, and requests the wildcard. This takes a minute or two.

**Check:**

```bash
sudo -u mooring /var/lib/mooring/bin/caddy list-modules | grep dns.providers.cloudflare
sudo journalctl -u mooring --since "5 min ago" | grep -i wildcard
# → edge: issuing a *.app.example.com wildcard cert via ACME DNS-01
```

If the log says `edge: Caddy DNS plugin install failed` instead, the line carries the reason; the
usual one is that the server can't reach `caddyserver.com` (allow outbound HTTPS to it). Mooring
retries on its own, and `sudo mooring doctor` shows the plugin's state.

## Optional: several domains on one server (namespaces)

Running more than one domain on one server, say production and staging? Declare **named
namespaces** under `edge.base_domains`, each with its own optional `dns01`, and apps pick one by
name. A namespace can also allow one app a [catch-all route](./edge-and-tls.md#catch-all-routes)
with `catch_all: true` (it needs `dns01`):

```yaml
edge:
  base_domains:
    - name: prod
      domain: app.example.com
      dns01: { provider: cloudflare, api_token: "<token>" }
      catch_all: true
```

Namespaces must not overlap (no domain inside another). See
[namespaces](./definition-file.md#specedgebase_domain-namespaces).

## Optional: put the dashboard on its own hostname

Instead of the SSH tunnel, Mooring can serve the dashboard over HTTPS at its own address:

1. In the config, add your own public IP to `ip_allowlist` (never a catch-all such as `0.0.0.0/0`:
   Mooring refuses that) and set either:

   ```yaml
   admin:
     hostname: "admin.example.com"     # a full name, or…
   #  subdomain: admin                  # …admin.<edge.base_domain>, covered by your wildcard
   ```

2. Turn on two-factor sign-in (`auth.totp_secret`): the login is now on the internet, behind your
   allow-list.
3. Point the name's DNS at the server ([Step 7](#step-7-point-dns-at-the-server)), then
   `sudo systemctl restart mooring` (a reload isn't enough for this).

The dashboard must be a subdomain, never the base domain itself. The SSH tunnel keeps working
alongside it. Using **Connect with GitHub**? Set your OAuth App's callback to
`https://<admin hostname>/github/callback`.

## Optional: team members and roles

The `auth:` block is your primary operator, always an **owner**. To let others in, add a `users:`
list. Mint each entry the same way (`mooring hash-password`, optionally `mooring gen-totp`) and give
it a **role**:

```yaml
users:
  - username: "alice"
    password_hash: "<from mooring hash-password>"
    totp_secret: "<from mooring gen-totp>"   # optional
    role: deployer                           # owner | deployer | viewer
```

| Role | Can |
|---|---|
| **owner** | Everything: deploy, plus every admin action (delete apps, reveal secrets, run setup scripts, manage backups, connect repos/GitHub, rotate tokens, reclaim disk). |
| **deployer** | Deploy, roll back, start/stop/restart, and edit an app's env, config files and scaling. **Not** the admin actions above. |
| **viewer** | Read-only: apps, logs, metrics, events, status. |

Roles are enforced on the server for every action. Users live in this root-owned file (there's no
sign-up page); `sudo systemctl reload mooring` applies a change and signs everyone out once, so a
removed user's sessions end at once.

## Optional: non-HTTP services (DNS, MQTT) and the L4 load balancer

For a service on a privileged non-HTTP port, install nginx with the stream module, and set
`edge.l4_enabled: true` in the config:

```bash
sudo mooring setup --l4 --yes
```

Only for a DNS resolver on `:53`, free the port from `systemd-resolved` (Mooring never rewrites
host DNS for you):

```bash
printf '[Resolve]\nDNSStubListener=no\n' | sudo tee /etc/systemd/resolved.conf.d/no-stub.conf
sudo systemctl restart systemd-resolved
sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf   # the real upstreams, NOT stub-resolv.conf
getent hosts github.com     # host DNS must still resolve
```

**Check:** `sudo mooring doctor --l4` has no `fail` lines.

## Editing the config file (reload vs restart)

`/etc/mooring/config.yaml` is read at **startup**. After you edit it, tell Mooring, and how depends
on what you changed:

| You changed… | Apply with |
|---|---|
| Who can reach the dashboard (`ip_allowlist`, `trust_proxy`, `trusted_proxies`), your login (`auth.username`, `auth.password_hash`, `auth.totp_secret`), `users`, or log retention (`retention.*`) | **`sudo systemctl reload mooring`**: applied live, no downtime |
| **Anything else**: the `encryption_key`, `bind_addr`, `edge.*` (incl. `base_domain`, `base_domains`, `dns01`, `l4_enabled`), `admin.*`, `github.*`, `alerting.*`, `session.*`, `cookie.*`, `docker.*`, `protected_projects`, … | **`sudo systemctl restart mooring`** |

When in doubt, restart: a reload that touches a restart-only setting silently does nothing. A
restart briefly drops the dashboard; your apps keep running. A reload checks the new file first and
keeps the old config if the edit is invalid. Turning on or changing two-factor on reload signs you
out, so you sign in again with the new factor.

## Keep Mooring up to date

- **APT repository (Step 3):** `sudo apt update && sudo apt upgrade`. The package keeps the service
  enabled and restarts it on the new version.
- **`.deb` file:** download the newer release the same way and `sudo apt install` it. To let the
  dashboard's **Server tab** clean up old `.deb` files, download them into
  `/var/lib/mooring/deb-cache` (create it with
  `sudo install -d -o mooring -g mooring -m 0755 /var/lib/mooring/deb-cache`) and set
  `server.deb_cache_dir: /var/lib/mooring/deb-cache` in the config.

## Other Linux: install the raw binary

No `.deb` or `.rpm`? Use the release tarball (it holds the binary and the systemd unit), then set
up the service account and folders yourself (the package does this for you):

```bash
ARCH=amd64     # or arm64
TAG=$(curl -fsSL https://api.github.com/repos/daboss2003/mooring/releases/latest | grep -oP '"tag_name":\s*"\K[^"]+')
cd /tmp
curl -fsSLO "https://github.com/daboss2003/mooring/releases/download/${TAG}/mooring_${TAG#v}_linux_${ARCH}.tar.gz"
tar -xzf "mooring_${TAG#v}_linux_${ARCH}.tar.gz" mooring deploy/systemd/mooring.service
curl -fsSLO "https://raw.githubusercontent.com/daboss2003/mooring/${TAG}/deploy/nfpm/config.example.yaml"
sudo install -m 0755 mooring /usr/local/bin/mooring     # the path the unit runs

sudo groupadd --system mooring
sudo useradd --system --no-create-home --shell /usr/sbin/nologin --gid mooring mooring
sudo usermod -aG docker mooring
sudo install -d -o root    -g mooring -m 0750 /etc/mooring
sudo install -d -o mooring -g mooring -m 0700 /var/lib/mooring
sudo install -d -o mooring -g mooring -m 0700 /var/lib/mooring-apps
sudo install -d -o mooring -g mooring -m 0700 /var/lib/caddy
sudo install -m 0644 deploy/systemd/mooring.service /etc/systemd/system/mooring.service
sudo install -m 0644 config.example.yaml /etc/mooring/config.example.yaml
sudo systemctl daemon-reload
```

Then continue at [Step 4](#step-4-install-caddy-the-https-edge) (install Caddy from
<https://caddyserver.com/docs/install> on a non-Debian system: the official build, 2.11 or later),
and copy the template from `/etc/mooring/config.example.yaml` in Step 6.

## Troubleshooting

| You see | Why | Fix |
|---|---|---|
| `edge.acme_ca: required in managed mode` | the config has no ACME issuer | add `edge.acme_ca` exactly as in [Step 6](#step-6-write-the-config-file), restart |
| `ip_allowlist: empty …` | the allow-list has no entry | add `127.0.0.1/32` and `::1/128` |
| A plain **404** at <http://127.0.0.1:9000> through the tunnel | the tunnel arrives from loopback, which isn't in `ip_allowlist` | add `127.0.0.1/32` and `::1/128`, then `sudo systemctl reload mooring` |
| `bind_addr: must bind loopback only` | `bind_addr` is a public address | set `bind_addr: "127.0.0.1:9000"` |
| `config: … must not be world-accessible` / `… group-writable` / `… owned by root` | the file's owner or mode is wrong | `sudo chown root:mooring /etc/mooring/config.yaml && sudo chmod 0640 /etc/mooring/config.yaml` |
| `sudo systemctl enable` seems to hang | it's waiting on a password prompt you can't see | press Ctrl-C and run it with `sudo` |
| `N: Download is performed unsandboxed as root …` during `apt install ./mooring….deb` | apt's sandbox user can't read your home folder | harmless (`dpkg -l mooring` confirms the install); download into `/tmp` to avoid it |
| `caddy version` prints `2.6.2` (no leading `v`) | the distribution's old Caddy | [Step 4](#step-4-install-caddy-the-https-edge): `sudo apt-get remove -y caddy`, then `sudo mooring setup --yes` |
| Log: `edge: Caddy DNS plugin install failed`; wildcard names fail with `ERR_SSL_PROTOCOL_ERROR` | the server can't download the plugin build from `caddyserver.com` (the log line has the reason) | allow outbound HTTPS to `caddyserver.com`; Mooring retries on its own. `sudo mooring doctor` shows the plugin's state |
| Log: `edge child exited: address already in use` | a packaged `caddy` or `nginx` service holds port 80/443 | `sudo mooring setup --yes` (it turns them off), or `sudo systemctl disable --now caddy nginx` |
| Deploy: *the edge has not issued the TLS cert yet* | the hostname doesn't resolve to this server yet, or port 80 is closed | check [Step 7](#step-7-point-dns-at-the-server) (`dig +short <name>`) and [Step 1](#step-1-open-ports-80-and-443) |
| `doctor`: `docker` **MISSING** | Docker isn't installed | [Step 2](#step-2-install-docker) |
| Deploys fail to reach Docker after installing it | Docker was installed after Mooring, so `mooring` isn't in the `docker` group | `sudo usermod -aG docker mooring && sudo systemctl restart mooring` |

---

*The service's hardening (memory caps, sandboxing, network egress lock-down) is in [How it works &
why it's safe](./architecture.md). Running your own Docker connection instead of the built-in one?
Set `docker.external_proxy: true`; see [the CLI reference](./cli.md).*
