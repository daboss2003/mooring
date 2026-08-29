# The Errors tab

When an API starts throwing errors, you want to know *which route* and *how often* — without SSHing in to tail logs. The **Errors** tab shows every route that returned a **4xx or 5xx** at the edge in the last 24 hours, grouped by app, and alerts you when a route keeps failing.

See also: [Domains, HTTPS & the edge](./edge-and-tls.md) · [Alerts](./alerting.md)

---

## What it shows

Mooring's managed edge (Caddy) sees every request. The Errors tab records the ones that failed and groups them by **route** (a hostname + path), under each app:

- an accordion per route, showing its error counts (**24h**, **last hour**, and how many were server **5xx**);
- expand a route to see the erroring requests — **time, method, path, status, client IP, and latency** — newest first;
- a **filter box** on each route: type words to narrow the list (e.g. `POST 500`, or a path fragment), the same way you filter logs elsewhere;
- click a request to open a dialog with its full details (time, method, full path, status, client IP, latency, route) and a link to the service's own logs around that time.

This is the **edge's view** of each request. It shows *which* routes are erroring and *how* — not the app's internal stack trace, which lives in the app's own container logs (the edge never sees it). A request whose `Host` matches no route is dropped, so scanner noise and bogus-Host 404s never get attributed to your services.

When [log history](./service-trends-and-logs.md#log-history--search) is enabled (the default), each erroring request has an **app logs** link to the service's own logs around that request's time.

The page refreshes on its own every 10 seconds, so new errors appear without reloading. Accordions you have open and any filter text you have typed are preserved across a refresh.

Entries are kept for **24 hours**, then pruned — this is a recent-errors view, not an archive. It lives in its own file, separate from Mooring's database, so it never slows the dashboard.

## The "this route keeps erroring" alert

If a route returns **10 or more server (5xx) errors within 5 minutes**, Mooring raises one alert (then stays quiet for 15 minutes so it doesn't spam) telling you which route and app to check. **Only 5xx counts toward the alert** — 4xx (a bot spraying 404s, normal 401s) are logged but never page you, so the alert means "the service is actually breaking." Alerts go through your configured [channels](./alerting.md) like any other; if alerting is off, nothing is sent.

## Turning it on or off

It's **on by default** (it needs the **managed edge** — with an external edge there's no access log to read). To turn it off — for example on a very high-traffic edge that doesn't want the per-request bookkeeping — set in `config.yaml`:

```yaml
server:
  route_error_log_enabled: false
```
