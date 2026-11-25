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
- **[Errors](./errors.md)** — every route that returned a 4xx/5xx at the edge in the last 24h, grouped by app and filterable, with an alert when a route keeps erroring.
- **[Service trends & logs](./service-trends-and-logs.md)** — per-service CPU/memory/error-rate charts over time, and searchable log history with a link from any Errors entry to the service's own output.
- **[Security detections](./security-detections.md)** — built-in and custom rules over the security logs (brute force, password spraying, new countries, impossible travel, threat-intel hits, app /ops alerts), tagged with MITRE ATT&CK®, on an owner-only Detections page, with high and critical detections sent to your alert channels.
- **[Security incidents](./security-incidents.md)** — related detections of one account or address grouped into incidents with a timeline, known attack chains raised to critical, one alert per incident, a workflow (acknowledge, resolve, false positive, notes, assignee) and a risk score per account and address.
- **[Log patterns](./security-patterns.md)** — the templates each app service's and the host's log lines fall into, with new templates and spikes reported as detections after a learning period.
- **[Automated response and the block list](./security-responses.md)** — per-rule responses (block an address at the edge, sign a Mooring account out) recommended or applied automatically, manual blocks, the addresses that are never blocked, caps and exemptions.
- **[Security logs](./security-logs.md)** — app, edge, Mooring and host security events in one searchable log, with secrets and personal data removed, 14 days on the server and an encrypted S3 archive.
- **[An app's ops interface](./app-ops-interface.md)** — richer health, queues, and metrics for apps that expose them.

## Reference

- **[The `mooring.yaml` file](./definition-file.md)** — the file that describes an app: services, domains, secrets, scaling, self-healing, scheduled tasks, backups, and preview environments. The single source of truth.
- **[Server settings & many apps](./host-file.md)** — server-wide settings and running several apps on one server.
- **[Checking and editing `config.yaml`](./config-editing.md)** — `mooring config check` and `mooring config edit`, reading a config or `mooring.yaml` error, reload or restart, and what happens with a refused file at start, reload and upgrade.
- **[The HTTP API](./api.md)** — the scoped, token-authenticated `/api/v1` for automation and scripts.
- **[Command-line reference](./cli.md)** — for installation and the occasional power-user task. You rarely need it.
- **[How it works & why it's safe](./architecture.md)** · **[Security](./security.md)** — the engineering details, if you're curious or evaluating.

---

Mooring is secure by default — private dashboard, automatic HTTPS, encrypted secrets, no configuration required to be safe. The [Security](./security.md) page covers the model in full.
