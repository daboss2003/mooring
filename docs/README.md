# Mooring docs

**Run your apps on your own server — with automatic HTTPS, live monitoring, and one clean dashboard — without the DevOps grind.**

Mooring is a single small program you install on a Linux server with Docker. It puts your apps online over HTTPS, renews certificates, watches their health, and gives you a dashboard to deploy and manage everything — so a plain server becomes a place you can ship to in minutes.

## New here? Start with these

1. **[Introduction](./introduction.md)** — what Mooring does for you, in two minutes.
2. **[Install it](./installation.md)** — get it running on your server.
3. **[Deploy your first app](./first-steps.md)** — log in, ship an app, put it online with HTTPS.

That's the whole on-ramp. After that, you live in the dashboard.

## Guides

- **[Deploy from a Git repo](./gitops.md)** — connect a repo (or GitHub in one click), pick a branch, and Mooring watches it for new commits. You click Deploy — and can roll back.
- **[Domains, HTTPS & the edge](./edge-and-tls.md)** — how one hostname becomes a live HTTPS site, automatically — wildcard certificates and non-HTTP (TCP/UDP) services included.
- **[Secrets & config files](./config-files-and-secrets.md)** — keep passwords and API keys safe, and template config files at deploy.
- **[Import an existing `.env`](./env-import.md)** — bring what you already have.
- **[Scaling & self-healing](./scaling-and-self-healing.md)** — keep apps responsive under load and recover crashed ones, safely.
- **[Alerts](./alerting.md)** — get told when something needs you (off until you turn it on).
- **[Backups & recovery](./backup-and-recovery.md)** — scheduled, encrypted snapshots to disk or S3, and a safe restore onto a fresh server.

## Operations

- **[The Server tab](./server-tab.md)** — live host metrics and processes, image vulnerability scanning, disk reclamation, and keeping Mooring itself up to date.
- **[The Activity tab](./activity.md)** — Mooring's own recent events (deploys, builds, backups, scans, self-heal) in one place, instead of grepping `journalctl`.
- **[Scheduled tasks](./scheduled-tasks.md)** — what your cron jobs are doing right now (with live CPU/memory) and their recent run history, results, and logs.
- **[An app's ops interface](./app-ops-interface.md)** — richer health, queues, and metrics for apps that expose them.

## Reference

- **[The `mooring.yaml` file](./definition-file.md)** — the file that describes an app: services, domains, secrets, scaling, self-healing, scheduled tasks, backups, and preview environments. The single source of truth.
- **[Server settings & many apps](./host-file.md)** — server-wide settings and running several apps on one server.
- **[The HTTP API](./api.md)** — the scoped, token-authenticated `/api/v1` for automation and scripts.
- **[Command-line reference](./cli.md)** — for installation and the occasional power-user task. You rarely need it.
- **[How it works & why it's safe](./architecture.md)** · **[Security](./security.md)** — the engineering details, if you're curious or evaluating.

---

Mooring is secure by default — private dashboard, automatic HTTPS, encrypted secrets, no configuration required to be safe. The [Security](./security.md) page covers the model in full.
