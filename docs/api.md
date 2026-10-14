# The HTTP API

Mooring serves a scoped, token-authenticated JSON API at **`/api/v1`** for automation: CI pipelines, status dashboards, scripts. It has four read endpoints and one write endpoint (deploy an app). It can't reveal secrets, mint tokens or change configuration.

See also: [`mooring token`](./cli.md#mooring-token-mint--list--revoke) · [Git deploys](./gitops.md) · [Security](./security.md)

---

## Authentication

- **Bearer token only.** Send `Authorization: Bearer hmt_<id>_<secret>` with each request. A request that carries a dashboard session cookie is rejected with `401`, even with a valid token. The API needs no CSRF token.
- **Tokens are minted on the server** with [`mooring token mint`](./cli.md#mooring-token-mint--list--revoke). Every token has scopes, a CIDR set it is valid from, and an expiry. The plaintext is printed once. The dashboard can't mint tokens.
- **Each endpoint requires one scope** (below). A request outside the token's scopes gets `403`.
- The token's `<id>` is what `mooring token list` shows, and the API records it as the actor `api:<id>` in the audit trail.

Responses are `application/json; charset=utf-8` with `Cache-Control: no-store`. Errors are `{"error": "<message>"}`.

## Endpoints

| Method & path | Scope required | Returns |
|---|---|---|
| `GET /api/v1/status` | `status:read` | Per-app health: `{ ok, docker_ok, apps: [{ project, services: [{ service, state, health }] }] }`. |
| `GET /api/v1/metrics` | `metrics:read` | The host resource sample (CPU, memory, disk). |
| `GET /api/v1/events` | `events:read` | The 100 most recent info-level events. |
| `GET /api/v1/audit` | `audit:read` | The 100 most recent security-level events (the audit trail). |
| `POST /api/v1/apps/{project}/deploy` | `deploy:write:<project>` | Fetches the app's tracked branch and deploys its head. See [Deploying from CI](#deploying-from-ci). |

The deploy scope names one app: a token with `deploy:write:shop` can deploy `shop` and nothing else. There is no wildcard deploy scope.

## Deploying from CI

`POST /api/v1/apps/{project}/deploy` fetches the branch the app tracks and deploys the commit at its head, through the same pipeline as the **Deploy** button: validation, build, paced start (one service at a time), edge check. The request body is ignored (capped at 1 MiB); the commit is always the branch head at the time of the fetch.

The request waits for the fetch (up to 90 seconds), then answers. The deploy itself runs in the background: the response does not wait for it to finish. Follow it on the app's **Repository** page and its **Deploy history**, on the **Activity** tab (failures), or in the audit trail.

### Responses

| Status | Body | Meaning |
|---|---|---|
| `200` | `{"status":"up_to_date","commit":"<sha>"}` | The branch head is already deployed. Nothing runs. |
| `202` | `{"status":"accepted","commit":"<sha>"}` | The deploy of `<sha>` started. |
| `202` | `{"status":"queued"}` | Another git operation (a deploy, fetch or certificate renewal of any app) is running. The request runs when it finishes. |
| `401` | `error` | Missing, malformed, unknown, expired or revoked token, or a session cookie was sent. |
| `403` | `error` | The token lacks `deploy:write:<project>`, is used from outside its CIDR set, or the app is one of Mooring's own projects. |
| `404` | `{"error":"app not found"}` | No app has that name. |
| `409` | `{"error":"history rewritten (force-push) — review and deploy it from the dashboard"}` | The deployed commit is not an ancestor of the branch head. |
| `409` | `{"error":"deploys are paused after a rollback — resume auto-deploy or deploy from the dashboard"}` | See [After a rollback](#after-a-rollback). |
| `409` | `{"error":"previews deploy from pull requests"}` | The app is a pull-request preview. |
| `409` | `{"error":"this app is not deployed from a git repository — deploy it from the dashboard"}` | The app is a legacy provisioned app. |
| `429` | `error` | More than 6 deploy requests in a minute from this token. The `Retry-After` header gives the wait in seconds. |
| `502` | `{"error":"git fetch failed: <reason>"}` | The fetch failed. `<reason>` is the same message the Repository page shows, for example `git: authentication failed`. |
| `503` | `error` | The write plane is disabled on this host (the message says why). |

### Queued requests

- An app has at most one waiting API request. Further requests while it waits answer `202 queued` and add no second request; the waiting request deploys the branch head as it is when it runs.
- The waiting request runs with the token and client address of the most recent request for the app. That token is the one checked when it runs and the one recorded as the actor.
- A waiting API request is separate from a waiting webhook for the same app. Both run, in arrival order.
- When it runs, the request is decided by the same rules as above (up to date, history rewritten, paused after a rollback). The token must still be valid and hold the scope at that point.
- The result of a queued request is recorded only in the audit trail, the logs and the deploy history; the caller has already had its `202`.
- The queue is kept in memory. A waiting request is dropped if Mooring restarts; send it again.

### After a rollback

A rollback turns auto-deploy off for the app. From then on, API deploys of the app answer `409` until either:

- auto-deploy is turned on again (the **Auto-deploy** checkbox in the app's repository configuration), or
- a deploy of the app is run from the dashboard and finishes starting the new version (a deploy that only fails the final edge check counts).

This also applies to a rollback made while auto-deploy was already off. A rollback that failed before it started the older version does not pause API deploys; one that failed only the final edge check does. A deploy that failed before it started the new version does not end a pause. A rollback that was interrupted (Mooring stopped while it ran) pauses API deploys until one of the two above.

### Audit trail

Each deploy request is recorded with the action `api_deploy` and the actor `api:<token id>`: the client IP, the app (and commit, once fetched), the outcome and the reason for a refusal. Each deploy the API starts is recorded with the action `git_deploy` and the same actor when it finishes, with the outcome the dashboard records for a deploy (`ok`, or `error` with the failure). Read them with `GET /api/v1/audit`.

### Example

Mint a token for one app, valid from the CI runners' address range, then reload so the IP gate admits that range:

```bash
mooring token mint --scopes deploy:write:shop --cidrs 203.0.113.0/24 --ttl 2160h --label ci-shop
systemctl reload mooring
```

In the CI job, after pushing to the branch the app tracks:

```bash
curl -sS --fail-with-body -X POST "https://admin.example.com/api/v1/apps/shop/deploy" \
  -H "Authorization: Bearer $MOORING_DEPLOY_TOKEN"
```

`--fail-with-body` makes `curl` exit non-zero on a `4xx`/`5xx` answer and still print the error.

A read-only status check:

```bash
curl -sS "https://admin.example.com/api/v1/status" \
  -H "Authorization: Bearer $MOORING_STATUS_TOKEN" | jq .
```

## Notes

- **The CIDR set is checked on every call.** A token presented from outside its ranges gets `403`. After minting a token, the IP gate admits its ranges only after a reload (`systemctl reload mooring`).
- **Revoke** with `mooring token revoke --id <id>`. A revoked token is rejected on its next request.
- **Deleting an app** removes `deploy:write:<app>` from every token. A token left with no scopes is revoked; a token with other scopes keeps them. An app connected later under the same name can't be deployed with a token minted before the delete.
