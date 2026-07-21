<p align="center">
  <img src="docs/assets/logo.svg" width="96" height="96" alt="Mooring">
</p>

<h1 align="center">Mooring</h1>

<p align="center">
  <a href="https://daboss2003.github.io/mooring/"><strong>Website</strong></a>
  &nbsp;·&nbsp;
  <a href="https://daboss2003.github.io/mooring/docs/"><strong>Documentation</strong></a>
  &nbsp;·&nbsp;
  <a href="https://daboss2003.github.io/mooring/docs/#/installation"><strong>Install</strong></a>
</p>

**Run your apps on your own server — automatic HTTPS, live monitoring, and one clean dashboard — without the DevOps grind.**

Mooring is a single small binary you install on a Linux server that has Docker. It owns the public edge (Caddy + automatic HTTPS), watches your apps' health, and gives you a dashboard and CLI to deploy and manage everything — so a plain server becomes a place you can ship to in minutes. Each app is defined by a `mooring.yaml` in its Git repo: you describe the services, domains, and config there, connect the repo, and Mooring runs it — generating and owning the Compose file and Dockerfile for you. You never hand-write either, hand-edit a proxy config, or run `certbot`.

Think of it as your own small Heroku or Netlify, running on a server you own. It's **secure by default**, and built around one rule: *hosting Mooring should never be the thing that gets your server hacked.*

**What it is:** Mooring is a lightweight, **self-hosted PaaS / application control plane for Docker** — a self-hosted alternative to Heroku/Railway and to CapRover, Coolify, and Dokploy, **without Docker Swarm or Kubernetes**. You describe a multi-service app in one typed `mooring.yaml`; Mooring generates and owns the Compose file and Dockerfile, provisions HTTPS at the edge, and deploys, monitors, scales, and self-heals it.

Most tools either put a UI on top of Docker (Portainer) or layer a PaaS on Swarm/Kubernetes (CapRover, Coolify). Mooring is a **control plane**, not another Docker dashboard:

```
typed YAML  →  Mooring control plane  →  Docker Engine
```

The Compose and Dockerfile underneath are generated implementation details you never hand-edit.

## Why Mooring

| | Mooring | CapRover | Coolify | Dokploy |
|---|:--:|:--:|:--:|:--:|
| No Docker Swarm required | ✅ | ❌ | ✅ | ✅ |
| No Kubernetes | ✅ | ✅ | ✅ | ✅ |
| Multi-service apps from one file | ✅ | ⚠️ limited | ✅ | ✅ |
| Generates & **owns** Compose + Dockerfile | ✅ | ❌ | ❌ | ❌ |
| Automatic HTTPS at the edge | ✅ | ✅ | ✅ | ✅ |
| Built-in alerting + dead-man's switch | ✅ | ⚠️ basic | ⚠️ partial | ⚠️ partial |
| Documented security / threat model | ✅ | ⚠️ partial | ⚠️ partial | ⚠️ partial |
| Single static binary (no extra DB/services) | ✅ | ❌ | ❌ | ❌ |

*Comparisons are best-effort as of 2026, based on each project's public docs — corrections via PR are welcome.*

## Features

- **Automatic HTTPS** — give an app a domain and Mooring issues and renews the certificate and routes traffic to it. No proxy to run, no certbot.
- **A real dashboard** — health for every app and the host (with live CPU/memory/disk charts), logs, and start / stop / restart / redeploy per app or service.
- **Safe deploys** — straight from a Git repo's `mooring.yaml`. Every change is checked before it goes live, with automatic rollback on failure.
- **Deploy from Git, one click** — connect a repo (including one-click **Connect with GitHub**, which installs a read-only deploy key for you). Mooring watches for new commits and shows you what changed; you click Deploy. Access is fetch-only — Mooring never pushes to your repo.
- **Several apps from one repo** — keep `mooring.yaml` plus variants like `mooring.staging.yaml` and `mooring.prod.yaml` in the same repo, and Mooring deploys **each as its own app** (you pick which on connect). One `mooring.yaml`? Nothing changes.
- **Secrets, done right** — passwords and API keys are stored encrypted and referenced by name, never sitting in plain text in your files, repo, or logs.
- **Incidents in one place** — open alerts, unhealthy apps, and recent failures roll up onto a single screen.
- **Alerting** — optional email / webhook / Slack / Discord / Telegram, with quiet hours and an external dead-man's switch. Off until you turn it on.
- **Scaling & self-healing** — optional, conservative automation that keeps stateless services responsive and recovers crashed ones (and pages you when it can't).
- **Backups** — encrypted snapshots of your whole Mooring setup, with a safe restore onto a fresh server.
- **Single static binary** — no external services, no asset pipeline, no build step. Runs as its own systemd unit.

## Install

Mooring is third-party, so (like Docker or Tailscale) `apt` needs to know where to find it. Two ways:

**Quickest** — grab the `.deb` from the [latest release](https://github.com/daboss2003/mooring/releases/latest) and install it directly:

```bash
sudo apt install ./mooring_<version>_amd64.deb
```

**For automatic `apt upgrade` updates** — add the signed APT repo once, then install:

```bash
curl -fsSL https://daboss2003.github.io/mooring/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/mooring.gpg
echo "deb [signed-by=/usr/share/keyrings/mooring.gpg] https://daboss2003.github.io/mooring stable main" | sudo tee /etc/apt/sources.list.d/mooring.list
sudo apt update && sudo apt install mooring
```

A matching `.rpm` and standalone binaries are on every [release](https://github.com/daboss2003/mooring/releases). Full setup — generating your login + key, the config file, and starting the service — is in the [installation guide](./docs/installation.md).

## Quickstart

1. **[Install it](./docs/installation.md)** and generate your login + master key over SSH.
2. Open the dashboard at your `admin.hostname`.
3. **[Deploy your first app](./docs/first-steps.md)** — connect its Git repo (its `mooring.yaml` defines the app), set its secrets, and give it a domain.

After install, you work entirely in the dashboard. To change an app's structure, edit its `mooring.yaml` and deploy — see [The `mooring.yaml` file](./docs/definition-file.md).

## What you can do in the dashboard

- **Overview & Apps** — every app's status at a glance; open one to see services, logs, and lifecycle controls.
- **Repository & updates** — for repo-backed apps: what changed, and Deploy / Redeploy.
- **Edge & TLS** — see the routes declared in an app's `mooring.yaml`; Mooring handles the certificate and routing.
- **Env & secrets** — set your apps' secret values and non-secret env (the `mooring.yaml` declares secret *names*; the values live encrypted, never in the file). Config files and cert bindings are editable here too (and can be seeded from the file).
- **Incidents & Alerts** — see what needs you, and configure how you're notified.
- **Audit log, API tokens, Backups** — review privileged actions, manage machine tokens, and snapshot your setup.

## Command line

The dashboard is the day-to-day surface. The CLI is for installation and the occasional power-user task:

| Command | What it does |
|---|---|
| `mooring serve` | Run the dashboard + managed edge. |
| `mooring gen-key` · `hash-password` · `gen-totp` · `verify-key` | Generate the master key, password hash, and 2FA secret over SSH (the root of trust). |
| `mooring validate` · `init` | Check a `mooring.yaml`, or scaffold a starter one (read-only, CI-safe). |
| `mooring secret import` | Import an existing `.env` into an app's encrypted store. |
| `mooring token mint` · `list` · `revoke` | Manage scoped API tokens. |
| `mooring restore` | Restore Mooring's database from an encrypted backup. |

Full reference: [docs/cli.md](./docs/cli.md).

## Security

Mooring is secure out of the box, with no tuning required: the dashboard is private (loopback + IP allowlist), traffic is HTTPS, secrets are encrypted at rest, a push can't deploy itself, and an unsafe configuration makes it refuse to start rather than run insecure. If you're evaluating it, the [security model](./docs/security.md) covers the threat model and design in full.

> Mooring runs the write plane (`docker compose up/pull/build`) on servers with **≥ 1 GB RAM**; monitoring and HTTPS run fine on a smaller box.

## Documentation

📖 **[Read the docs →](./docs/README.md)** — start with the three-page on-ramp: **[Introduction](./docs/introduction.md) → [Install](./docs/installation.md) → [First steps](./docs/first-steps.md)**.

Guides: [Deploy from Git](./docs/gitops.md) · [Edge & TLS](./docs/edge-and-tls.md) · [Secrets & config files](./docs/config-files-and-secrets.md) · [Import a `.env`](./docs/env-import.md) · [Scaling & self-healing](./docs/scaling-and-self-healing.md) · [Alerts](./docs/alerting.md) · [Backups](./docs/backup-and-recovery.md) · [Many apps on one server](./docs/host-file.md) · [The `mooring.yaml` file](./docs/definition-file.md). For internals: [Architecture](./docs/architecture.md) · [Security](./docs/security.md).

## License & contributing

- **License** — [Apache License 2.0](./LICENSE) (see also [NOTICE](./NOTICE)).
- **Contributing** — see [CONTRIBUTING.md](./CONTRIBUTING.md). Because safety is the paramount requirement, changes to security-sensitive areas re-trigger the project's security checks before merge.
- **Security reports** — please report vulnerabilities privately (see [docs/security.md](./docs/security.md)) rather than opening a public issue.
