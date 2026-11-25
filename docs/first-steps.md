# Deploy your first app

> **Getting started, 3 of 3** · [← Install it](./installation.md)

Mooring is running. This guide walks through signing in and deploying an app with a public HTTPS address. It all happens in the dashboard.

> **First, if you installed Caddy or nginx yourself:** run `sudo mooring setup --yes` (or `sudo systemctl disable --now caddy nginx`) before your first deploy. Mooring supervises its own Caddy/nginx; a packaged `caddy.service`/`nginx.service` fights it for `:80`/`:443` and your first deploy fails on the TLS cert. `mooring doctor` flags this as a conflict.

## Sign in

Open the dashboard in your browser at the hostname you set during installation:

```
https://admin.example.com
```

Sign in with the username and password you set during installation.

> **Didn't set a hostname yet?** Until you do (e.g. while DNS is still propagating), reach the dashboard over an SSH tunnel — this also works as a recovery path if the edge is ever down:
>
> ```bash
> ssh -L 9000:127.0.0.1:9000 operator@your-server
> # then open http://127.0.0.1:9000
> ```

You'll arrive at the **Overview** — your server's CPU, memory, and disk, with a tile for each app once you've added some. Everything from here is in the dashboard.

## Add an app

Click **New app** and **connect a Git repo**. Your app is defined by a `mooring.yaml` at the repo root — the single source of truth: the services to run (each pulling an `image:` or built from your code via `build:`), ports, env (secret *names*; you set their values in the dashboard), volumes, edge routes, and scaling. If the repo has no `mooring.yaml`, Mooring scaffolds a starter from your detected stack so the first deploy just works; commit a real one for full control. The connect page shows a starter example to copy.

Mooring generates and owns the Compose and Dockerfile from that file — you never write either. Once connected, **Deploy** runs live in the page, and the app appears on your Overview with its health, logs, and controls. To change the app, edit `mooring.yaml` and deploy again; the dashboard stays read-only for the app's *shape* (but you set secret values and run/restart/scale there).

Your app should listen on an internal port such as `8080`. Mooring owns ports 80 and 443 and routes public traffic to your app via an edge route.

## Add a secret

Your `mooring.yaml` declares secret *names* (under `spec.secrets`, and where each is used); you set their *values* in the dashboard — one of the few things that lives there, not in the file (a value never belongs in a file you commit). Open your app, go to **Env**, add non-secret values as plain settings and passwords or API keys as **secrets** — these are encrypted and injected into the app at runtime. The app references each secret by name, and Mooring supplies the value when the app runs.

## Give it a domain

A domain is an **edge route** in your `mooring.yaml`. Add one under `spec.edge.routes`:

```yaml
spec:
  edge:
    routes:
      - hostname: app.example.com   # the public address — point its DNS at your server
        service: web                # the service to route to
        port: 8080                  # its internal port
```

Commit and deploy. Mooring issues a TLS certificate for the domain and configures the routing. Within moments, `https://app.example.com` is live. The dashboard's **Edge** page shows the deployed routes (read-only — to change them, edit the file and deploy). See [Edge & TLS](./edge-and-tls.md) for the full route fields.

## Deploy from a Git repo

To deploy from a repository, you have two options.

**Connect with GitHub.** If GitHub is configured (see [Deploy from a Git repo](./gitops.md)), click **Connect with GitHub**, authorize, and choose a repo from the list. Mooring installs a read-only deploy key for it — its access is fetch-only, so it never pushes to your repo.

**Connect any repo.** Click **Connect repo** and provide the URL, branch, and — for a private repo — a key or token. Mooring reads the `mooring.yaml` in your repo (and scaffolds a starter one if it's missing) — you don't commit a compose file.

Once connected, Mooring watches the repository. When you push a commit, an **update available** notice appears with a summary of the changes. Click **Deploy** to release it.

## Next steps

You've deployed an app, added a secret, and put it online. From here:

- [Deploy from a Git repo](./gitops.md)
- [Secrets & config files](./config-files-and-secrets.md)
- [Scaling & self-healing](./scaling-and-self-healing.md) · [Alerts](./alerting.md)
- [Backups & recovery](./backup-and-recovery.md)
- [Running many apps on one server](./host-file.md)

[← Back to the docs home](./README.md)

---

### Describing an app in a file

Your app **is** its `mooring.yaml` — the single source of truth, committed at the root of your repo. You write it (or start from the scaffold Mooring generates on the first deploy) and keep it in version control; Mooring reads it on deploy and generates the Compose file and Dockerfile from it. A minimal example:

```yaml
apiVersion: mooring/v1
kind: App
metadata:
  slug: my-app
spec:
  compose:
    source: generated
    services:
      web:
        image: ghcr.io/example/web:1.4.2
        ports: [{ internal: 8080 }]
        env:
          LOG_LEVEL: info
          DATABASE_URL: { secret: DATABASE_URL }   # referenced by name
  secrets:
    - name: DATABASE_URL
  edge:
    routes:
      - hostname: app.example.com
        service: web
        port: 8080
```

See [The `mooring.yaml` file](./definition-file.md) for the full reference.
