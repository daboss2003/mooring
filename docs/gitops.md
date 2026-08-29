# Deploy from a Git repo

Connect a repository and Mooring watches it for new commits, shows you what changed, and deploys exactly the commit you reviewed when you click **Deploy**. A push never deploys itself unless you ask it to.

See also: [Deploy your first app](./first-steps.md) · [Secrets & config files](./config-files-and-secrets.md)

---

## Connecting a repository

In the dashboard, click **Connect repo**. Two ways in:

**Connect with GitHub (one click).** If GitHub is set up (see below), click **Connect with GitHub**, authorize, and pick a repo. If the repo has **more than one branch**, Mooring asks which branch to deploy (defaulting to the repo's default branch) so its first fetch reads `mooring.yaml` from the branch you mean — a single-branch repo skips the question. Mooring creates a read-only deploy key for the repo automatically — you copy nothing.

**Connect any repo.** Provide:

- the **repository URL** and **branch**,
- for a **private** repo, a deploy key or access token.

Credentials are stored encrypted and never appear in the UI or logs.

Either way, **you don't type an app name** — Mooring reads the repo's mooring file(s) and takes the app's slug from `metadata.slug`. If the repo has [more than one mooring file](#several-apps-from-one-repo), you pick which one to deploy next. (Only the scaffold case — a repo with *no* `mooring.yaml` — asks you for a name.)

Your repo carries a **`mooring.yaml`** (see [the definition file](./definition-file.md)) describing the app — its services, build, env, edge routes, config files, and cert bindings. **That file is the single source of truth for the app's structure.** Mooring reads it, **generates the `docker-compose.yml` and any Dockerfiles**, and deploys — you never commit a compose file or a Dockerfile. If the repo has no `mooring.yaml`, Mooring scaffolds a sensible default from the stack it detects (e.g. a Node or Go project) so the first deploy still works; commit a real `mooring.yaml` when you want full control.

### Several apps from one repo

One repo can hold **several mooring files** — the plain `mooring.yaml` plus named variants like `mooring.staging.yaml` and `mooring.prod.yaml` — and **each one becomes its own deployed app**. When you connect a repo with more than one, Mooring shows a **chooser**: the plain `mooring.yaml` is the default, and variants are labelled by the text between `mooring.` and `.yaml` (`staging`, `prod`, …). Pick one to deploy now; connect the repo again to add another.

Each app's **identity (its slug) comes from that file's `metadata.slug`** — so give each variant a distinct slug (e.g. `myapp-staging`, `myapp-prod`). If the slug you pick already names a connected app, Mooring just opens it instead of overwriting — connecting never silently repoints an existing app. (Editing a file's `metadata.slug` *after* connecting doesn't rename the app; the slug is fixed at connect.) If your repo only ever has one `mooring.yaml`, none of this changes anything — you connect and deploy as usual.

To change the app's *shape* — services and edge/L4 routes — **edit `mooring.yaml` and deploy**; the dashboard then reflects it (read-only for those). The operational pieces are managed in the dashboard: **secret values** and **env** (the file declares secret *names* only), **config files** and **cert bindings** (editable in the dashboard; optionally seeded from the file), the per-service **auto-scaling policy**, and **lifecycle actions** (deploy / restart / scale-now).

## How updates work

Once connected, **Mooring checks the repo for new commits on its own** — no webhook to set up, no file to add to your repo. When a new commit lands, the app shows **"update available"** with a summary of what changed (the commits and files).

Click **Deploy** to ship it. Mooring deploys **exactly the commit you reviewed**, brings the app up, and **rolls back automatically** if anything fails — so a deploy either fully succeeds or leaves the previous version running. There's never a half-deploy.

You'll find this on the app's page (a **Repository & updates** panel) and on the dedicated **Repository** page (with the full diff and history).

> **Want instant deploys?** By default Mooring checks every couple of minutes. If you want a push to be picked up immediately, you can add an optional **webhook** — but it's not required. And if you want truly hands-off releases, turn on **auto-deploy** (off by default): Mooring then deploys a new commit for you, through the same checks, when it's a clean fast-forward. The background check on its own only ever *fetches* — it never deploys.

> **Self-healing a stuck container.** If a deploy is interrupted mid-recreate (most often the box runs out of memory and the OOM killer steps in), Docker can leave a half-renamed container occupying a service's name — and every later redeploy then fails with `the container name "…" is already in use`. Mooring now recovers automatically: it reclaims **that app's own** stuck container (verified by its compose project label — never another app's or a system container) and retries the deploy once, logging a line like *"reclaimed stuck container credlock-worker-1 … — retrying the deploy."* If the culprit is a container Mooring can't prove is yours (a foreign or manually-run one), it leaves it and tells you to `docker rm -f` it. When a deploy was OOM-killed, the log points you at the real fix (add RAM or lower the service's `mem_limit`) so it doesn't keep recurring.

## Deploy history & rolling back

Every git deploy is recorded. On the Repository page, the **Deploy history** sub-page lists each past version — when it shipped, its commit, and what changed — newest first, 20 to a page.

**Roll back to a previous deploy.** Each past deploy has a **Roll back to this** button. A rollback runs the *same* pipeline as a forward deploy — check out that commit, re-validate, bring the app up — just aimed at an earlier commit, so it's as safe as any deploy. Build services rebuild from that commit; pull-image services reuse their pinned image. Only past *git* deploys are rollback targets: a dashboard-only change (a scaling tweak, say — which also shows up in the list) has no commit and isn't one.

**Trim the history.** Delete an old entry to keep the list tidy. The current live version can't be deleted, and deleting only removes the history row — it doesn't reclaim disk (superseded build images are reclaimed on the [Server tab](./server-tab.md)).

## Starting and stopping services

From an app's page you can **start, stop, restart, or redeploy** the whole app; from a service's own page you can do the same to a **single service** — so you can take one service down without touching the rest.

A manual **Stop is a hold.** The stopped service — or, for an app-level stop, *every* service — stays down: Mooring's [self-healing](./scaling-and-self-healing.md) and auto-scaler both leave a held service alone instead of restarting it. So a service you deliberately stop stays stopped rather than bouncing back up. **Start**, **Restart**, or **Redeploy** releases the hold and brings it back. (A service that *crashes* on its own is different — self-healing does try to recover that.)

## Deleting an app

The app's page has a **Danger zone** with a **Delete** button. Deleting is **permanent and cannot be undone** — it is gated behind re-entering your password (a live session isn't enough) and, because it stops containers, it needs the write plane to be available. When you confirm, Mooring:

- stops and removes all of the app's **containers, networks, and data volumes** (`docker compose down --volumes`);
- deletes its **run directory** and its **Git object store** (the local repo clone Mooring fetched);
- erases **all of its state** — env & secrets, config files, cert bindings, edge/L4 routes, auto-scaling, self-healing, and ops — and revokes any API token whose only scope was deploying this app.

What is **not** touched: your own Git repository on GitHub/elsewhere (Mooring only deletes its local clone), the global GitHub connection, and whole-system **backups** (a backup is a snapshot of all of Mooring, not one app — restore from one if you delete by mistake). Protected/managed projects (Mooring's own infrastructure) can't be deleted.

## Why this is safe

- **Nothing deploys until you click** (unless you explicitly turn on auto-deploy). A push to your repo can't trigger a surprise build on your server.
- **Deploys are pinned to the reviewed commit** — what you saw in the diff is exactly what runs.
- **Fetching can't run code.** Mooring only downloads commits in the background; building and running happen only on the deploy you trigger, and only when the server has the resources for it.
- **Access is fetch-only.** Mooring reads your repo (with a read-only deploy key over the GitHub flow, or the deploy key / token you supply) and **never pushes to it.** The repo file stays the source of truth; the dashboard reflects what was deployed.
- **Touching a repo is treated as untrusted.** Mooring generates the compose from your `mooring.yaml` and validates it before running anything, and a force-push / rewritten history is flagged for you to review rather than deployed silently.

## Connect with GitHub — one-time setup

To offer the one-click flow, whoever installs Mooring does this once:

1. In GitHub, create an **OAuth App** (Settings → Developer settings → OAuth Apps → **New OAuth App**). You'll see these fields:

   | Field on the GitHub form | What to enter | Does Mooring use it? |
   |---|---|---|
   | **Application name** | Anything, e.g. `Mooring`. Shown to you on the authorization screen. | No — cosmetic. |
   | **Homepage URL** | The base URL you use to reach the dashboard — `http://localhost:9000` on the tunnel, or `https://<admin.hostname>` with a domain. GitHub requires *a* valid URL here. | No — cosmetic; never read by Mooring. |
   | **Application description** | Optional. Leave blank or describe it. | No — cosmetic. |
   | **Authorization callback URL** | **The one that matters** — must match exactly how your browser reaches the dashboard (see the table below). | **Yes** — must match exactly. |
   | **Enable Device Flow** (checkbox) | **Leave it OFF.** | **No** — see note. |

   > **Leave "Enable Device Flow" unchecked.** Mooring signs you in with the standard browser redirect flow (you click Connect → GitHub → back to the callback URL). Device Flow is a different mechanism for things with no browser (CLIs, TVs); Mooring never uses it. Turning it on won't break anything, but it adds an unused capability to your app — keep it off.

   The **Authorization callback URL must match the URL your browser uses to reach the dashboard** — Mooring derives the callback from `admin.hostname` if set, otherwise from the address you're on:

   | How you reach the dashboard | Set the OAuth App's callback URL to |
   |---|---|
   | A public admin domain (`admin.hostname` set in config) | `https://<admin.hostname>/github/callback` |
   | An **SSH tunnel** to loopback (no `admin.hostname`, the default before you have a domain) | `http://localhost:9000/github/callback` |

   > **You do NOT need a public domain first.** GitHub allows a `localhost` callback, and it works over the SSH tunnel — so you can set GitHub up before pointing a domain at the box. **But the match is strict, and an OAuth App has only ONE callback URL:**
   > - If `admin.hostname` **is set**, Mooring *always* uses `https://<admin.hostname>/github/callback` — so that domain must be live (its HTTPS working) when you click Connect; the `localhost` callback won't be used even if you're on the tunnel.
   > - If you later add a domain (set `admin.hostname`), **update the OAuth App's callback URL** to the `https://…` form, or Connect will fail with a redirect-URI mismatch.

2. Put the credentials in `config.yaml` and **restart** Mooring:

   ```yaml
   github:
     client_id: "<from the OAuth App>"
     client_secret: "<from the OAuth App>"
   ```

   ```bash
   sudo systemctl restart mooring
   ```

   > **Restart, not reload.** GitHub credentials are read once at startup, so `systemctl reload` will **not** pick them up — the **Connect with GitHub** button won't appear until you `systemctl restart mooring`. (See [editing the config file](./installation.md#editing-the-config-file-reload-vs-restart).)

3. Allow the server to reach `github.com` and `api.github.com` if you've locked down outbound network access (the egress filter is off by default).

After that, **Connect with GitHub** appears on the Connect-a-repository page. Operators can disconnect at any time; already-connected repos keep working, because each uses its own deploy key rather than the GitHub login.

## Building images vs pulling them

By default Mooring **pulls** the images your Compose references — it doesn't build on your server. If your app needs an on-box build, set the build option when connecting the repo; building requires a server with at least 1 GB of RAM.

## Preview environments (a deploy per pull request)

Turn this on for a connected app and every pull request gets its **own running copy** of the app — at its own URL — so reviewers can click a link and try the change instead of reading a diff. When the PR closes, the copy is torn down automatically.

**How it works.** Open a PR → GitHub sends Mooring a signed `pull_request` webhook → Mooring spins up a throwaway app, `<app>-pr<n>`, from your repo but checking out the PR's code (`refs/pull/<n>/head`, which works for forks too). It gets its own subdomain, `<app>-pr<n>.<base_domain>`, already covered by your wildcard certificate — so **HTTPS is instant**, with no new certificate to issue. Push more commits and it redeploys; close or merge the PR and it's removed.

**Turning it on.**

1. On the app's **Repository** page, click **Enable previews** (this is an owner-only action — it grants a webhook unattended authority to create and destroy preview apps).
2. Create (or rotate) the app's webhook to get its token + secret.
3. In your GitHub repo → **Settings → Webhooks → Add webhook**:
   - **Payload URL:** `https://<your-admin-host>/webhook/pr/<your-webhook-token>`
   - **Content type:** `application/json`
   - **Secret:** the app's webhook secret
   - **Events:** *Let me select individual events* → **Pull requests** only

**What a preview inherits.** The base app's **non-secret** environment (plain config values), plus fresh `generate:` secrets minted per preview — so a preview's own database gets its own random password and the app boots. It deliberately does **not** inherit the operator's pasted secrets (API keys, external DB passwords): a PR runs untrusted fork code, so leaking real credentials to it would be dangerous. If a preview needs an external secret it simply won't have it (fail-closed) rather than exposing production keys. Each preview is a separate Compose project with its own volumes — it **cannot affect production**.

**Safety.** The webhook is authenticated by GitHub's `X-Hub-Signature-256` HMAC over the request body — nothing happens without a valid signature. Teardown is **scoped**: the webhook can only remove an app that is a preview *of its own base app*, so it can never delete a real app. Because a PR's `mooring.yaml` is untrusted, a preview's routes are rewritten to its own subdomain and any fork-supplied `cert_bindings` or `l4_routes` are stripped — so a PR can't grab a production TLS certificate or claim a host port. There's a cap on live previews per app, and a TTL reaper removes previews abandoned for two weeks in case a "closed" event is ever missed.

**Requirements & limits.** Previews need a subdomain namespace to live under — the base app's namespace: `edge.base_domain`, or the named [`edge.base_domains`](./definition-file.md#specedgebase_domain-namespaces) entry the app selects with `spec.edge.base_domain`. Give that namespace a wildcard cert (`dns01`) and HTTPS is automatic. Whatever the base app declares — the subdomain shorthand **or** a fixed `hostname:` — the preview's routes are rewritten to unique **slug subdomains** under that namespace, so it works either way and can never collide with production. A preview is always **pinned to the base app's namespace**, never one a fork PR names in its `mooring.yaml`. There's a cap of 10 live previews per app, and a TTL reaper removes previews abandoned for two weeks (a backstop for a missed "closed" event).
