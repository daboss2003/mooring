# Service trends & logs

Each service has its own page (open an app, then a service). Alongside its status and controls, the
page shows trend charts and a searchable log history.

See also: [Errors](./errors.md) · [Scaling & self-healing](./scaling-and-self-healing.md) · [Server tab](./server-tab.md)

---

## Trend charts

The **Trends** section shows three charts, refreshed in place:

- **CPU** — CPU use over time (%).
- **Memory** — memory use over time.
- **Edge errors** — 4xx/5xx responses the managed edge returned for the service, in 5-minute buckets.

Hover a chart to read the value at a point in time. For a scaled service, CPU and memory are the
average across its running copies.

Data sources:

- **CPU and memory** come from the per-container metrics Mooring records for the Overview, retained
  for `monitor.metrics_retention` (default 7 days).
- **Edge errors** come from the same edge error log as the [Errors tab](./errors.md), so the series
  covers the last 24 hours. A service not fronted by the managed edge shows a flat zero.

No configuration is required; the charts appear on every service page.

## Log history & search

**View logs** live-tails a service's output and retains nothing. **Log history** searches captured
output.

When log capture is enabled, Mooring records each running service's stdout/stderr into a searchable
history. The Log history page supports:

- **text filter** — a line must contain every word entered;
- **time range** — 15 minutes, 1 hour, 6 hours, 24 hours, or all retained;
- **copy filter** — one replica of a scaled service, or all merged (the default).

Each 4xx/5xx entry on the [Errors](./errors.md) page has an **app logs** link that opens the service's
logs around that entry's timestamp.

Capture begins when a service starts running and keeps output for 48 hours. It is stored in a separate
file from Mooring's database. Each service retains a bounded number of recent lines; lines beyond a
per-second rate limit are dropped and replaced with a `… N lines dropped` marker.

## Configuration

Log capture is **on by default**. The capture file is `0600` in Mooring's data directory and is
readable only by an authenticated operator. It writes the app's own output to disk, so it can contain
any secrets the app prints.

To disable it, set in `/etc/mooring/config.yaml` and reload:

```yaml
server:
  service_log_enabled: false
```

When disabled, Mooring removes the capture file on the next start. Only output produced while capture
is enabled is retained.
