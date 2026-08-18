# The HTTP API

Mooring exposes a small, scoped, token-authenticated JSON API at **`/api/v1`** for automation — CI pipelines, status dashboards, a deploy step in a script. It is deliberately narrow: a handful of read endpoints plus one write (trigger a deploy). It can't reach anything the browser dashboard's sensitive actions can (revealing secrets, minting tokens, changing config).

See also: [`mooring token`](./cli.md#mooring-token-mint--list--revoke) · [Security](./security.md)

---

## Authentication

The API is a **separate auth surface** from the dashboard:

- **Bearer token only.** Send `Authorization: Bearer hmtok_…` with each request. A request carrying an admin **session cookie is rejected** — the token plane never accepts a browser session (a confused-deputy guard), and it's CSRF-exempt because it's cookieless.
- **Tokens are minted from the CLI only**, with [`mooring token mint`](./cli.md#mooring-token-mint--list--revoke). Every token is **scoped**, **CIDR-bound** (valid only from the IP ranges you name), and **expiring** (a TTL is mandatory). The plaintext is shown once. The web plane can never mint one.
- **Each endpoint requires a specific scope** (below). A token holds only the scopes you granted it; a call outside them is refused.

Responses are `application/json; charset=utf-8` with `Cache-Control: no-store`. If no API-token store is configured, `/api/v1` is disabled entirely.

## Endpoints

| Method & path | Scope required | Returns |
|---|---|---|
| `GET /api/v1/status` | `status:read` | A curated per-app health summary: `{ ok, docker_ok, apps: [{ project, services: [{ service, state, health }] }] }`. Never the raw internal snapshot. |
| `GET /api/v1/metrics` | `metrics:read` | The host resource sample (CPU / memory / disk). |
| `GET /api/v1/events` | `events:read` | Recent info-level operational events. |
| `GET /api/v1/audit` | `audit:read` | Recent security-level events — the audit trail. |
| `POST /api/v1/apps/{project}/deploy` | `deploy:write:<project>` | Triggers a deploy of that app through the normal pipeline. Request body capped at 1 MiB. |

The deploy scope is **per app**: a token with `deploy:write:shop` can deploy `shop` and nothing else. There is deliberately no wildcard deploy scope.

## Example

```bash
# A read-only token scoped status:read, valid from your CI's egress range.
curl -s https://your-admin-host/api/v1/status \
  -H "Authorization: Bearer hmtok_xxxxxxxxxxxxxxxx" | jq .

# Trigger a deploy (needs a deploy:write:<project> token).
curl -s -X POST https://your-admin-host/api/v1/apps/shop/deploy \
  -H "Authorization: Bearer hmtok_yyyyyyyyyyyyyyyy"
```

## Notes

- **The CIDR binding is enforced at every call** — a leaked token is useless from an IP outside its ranges. After minting a token, the IP gate admits its new ranges only after a reload (`systemctl reload mooring`).
- **Revoke instantly** with `mooring token revoke --id <id>`; a revoked token is rejected at auth on the next request.
- Deleting an app automatically revokes any token whose only scope was deploying that app.
