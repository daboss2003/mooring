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
- **time range** — 15 minutes, 1 hour, 6 hours, 24 hours, 7 days, 30 days, or all retained (only the
  ranges within the service's retention are listed);
- **copy filter** — one replica of a scaled service, or all merged (the default).

The page shows at most 2000 matching lines at a time; narrow the filter or range to see older matches.

One search reads at most 64 MiB of captured output and runs for at most 5 seconds, waiting for a free
search slot included (at most 4 searches run at once). A search that reaches either limit, or whose
page is closed, stops: the page shows the most recent matches found so far and asks you to narrow the
filter or range.

Each line is shown on a single row. Click a line to open its full content in a dialog.

Lines are color-coded by severity, detected from the line's level keyword (`error`, `warn`, `debug`,
…) or a status field (`statusCode` / `status` = a 5xx/4xx value): error / 5xx in red, warning / 4xx in
amber, debug dimmed, everything else normal. Only a status **field** counts — a bare number elsewhere
(a response time, a byte count) is not mistaken for a status. The live **View logs** tail uses the
same coloring.

The text filter is word-AND: a line must contain every word, in any order — so `statusCode 502`
matches a line containing both `statusCode` and `502`, even when they aren't adjacent.

Each 4xx/5xx entry on the [Errors](./errors.md) page has an **app logs** link that opens the service's
logs around that entry's timestamp.

The list updates live (every few seconds) unless you opened it from an Errors entry, which shows a
fixed window around that request's time instead.

Capture begins when a service starts running. All copies of a service share one history. A service
accepts up to 200 lines per second; lines beyond that are dropped and replaced with a
`… N line(s) dropped` marker. Lines longer than 8 KiB are cut.

For comparison, the live **View logs** tail shows roughly the last 300 lines from Docker and then
streams new ones, but retains nothing — close it and it's gone. Log history is the retained,
searchable copy.

## Retention

By default each service keeps the last **48 hours**, up to its most recent **2000 lines** — whichever
is reached first. The Log history page shows the service's current window and line cap.

A service can keep more (or less) with `logs:` in its `mooring.yaml` (see
[the definition file](./definition-file.md)):

```yaml
spec:
  compose:
    services:
      api:
        logs:
          retain: 30d        # duration: 72h, 30d, …
          max_lines: 200000
```

Omit a field for the default. Each value is capped by the server's limits in
`/etc/mooring/config.yaml`; PR previews always use the default.

If the app's deployed definition can't be read, a service keeps the last retention Mooring read for it.
A service whose retention has not been read since Mooring started gets the default (48 hours, 2000
lines) from the first maintenance pass (within 30 seconds of the start) until the definition can be
read again.

| Key (`server:`) | Default | Range | Meaning |
|---|---|---|---|
| `service_log_max_retain` | `30d` | `1h`–`365d` | longest `logs.retain` any service gets |
| `service_log_max_lines` | `200000` | `100`–`10000000` | most `logs.max_lines` any service gets |
| `service_log_max_disk_mb` | `2048` | `64`–`102400` | disk space for all captured logs together |

Storage:

- Captured lines are stored under `<data_dir>/service-logs/<app>/<service>/` as JSONL files, separate
  from Mooring's database. Lines are written to disk every 30 seconds, or sooner for a busy service.
- Old lines are removed a file at a time, so a service can briefly hold somewhat more than its limits
  on disk; search never shows lines outside the service's window or line cap.
- When all captured logs together exceed `service_log_max_disk_mb`, the oldest files are removed
  first, whichever service they belong to.
- When the filesystem holding the data directory is at or above `server.disk_gc_threshold` (default
  75%), capture pauses: new lines are dropped, and every service's history is cut back to the default
  (48 hours, 2000 lines). The Log history page shows a notice while this lasts. Capture resumes
  once usage drops below the threshold, and a `… N line(s) dropped` marker records the gap.

Retention changes in `mooring.yaml` apply within a minute of the deploy. The `server:` keys are read
at start-up: restart Mooring after changing them.

## Configuration

Log capture is **on by default**. Captured files are `0600` in `0700` directories inside Mooring's
data directory, and are readable only by an authenticated operator. Capture writes the app's own
output to disk, so it can contain any secrets the app prints.

To disable it, set in `/etc/mooring/config.yaml` and restart Mooring:

```yaml
server:
  service_log_enabled: false
```

When disabled, Mooring removes all captured logs on the next start. Only output produced while
capture is enabled is retained. Deleting an app removes its captured logs at once. Output for an app
of the same name is not captured for 2 minutes after the delete.
