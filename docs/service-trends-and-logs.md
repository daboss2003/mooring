# A service's trends & logs

Each service has its own page (open an app, then click a service). Beyond its live status and
controls, that page gives you two ways to see what the service has been *doing over time* — trend
charts and a searchable log history — so you can answer "is this getting worse?" and "what actually
broke?" without SSHing in.

See also: [The Errors tab](./errors.md) · [Scaling & self-healing](./scaling-and-self-healing.md) · [The Server tab](./server-tab.md)

---

## Trend charts

Under **Trends** on the service page you get three small charts that fill in as data is collected and
refresh on their own:

- **CPU** — the service's CPU use over time (%).
- **Memory** — the service's memory use over time.
- **Edge errors** — how many 4xx/5xx responses the managed edge returned for this service, in
  5-minute buckets.

Hover any chart to read the exact value at a point in time. For a **scaled** service (several copies),
CPU and memory are the *average across its copies*, so the trend reads the same whether it's running
one replica or five.

Where the numbers come from:

- **CPU and memory** are the same per-container readings Mooring already records for the Overview, kept
  for as long as your metrics retention says (`monitor.metrics_retention`, **7 days** by default). The
  page notes the current window.
- **Edge errors** come from the same edge error log that powers the [Errors tab](./errors.md), so the
  error trend covers the **last 24 hours**. If a service isn't fronted by the managed edge (or simply
  hasn't errored), that chart is a flat zero — which is exactly the reassuring answer.

Nothing here needs configuring; the charts appear on every service page.

## Log history & search

The live **View logs** button tails a service's output right now. That's perfect in the moment, but
it's gone when you close it — so it can't tell you what a service printed *at 3am when it fell over*.

**Log history** (the button next to **View logs**) fixes that: when enabled, Mooring captures each
running service's own output (stdout/stderr) into a searchable, time-bounded history. On that page you
can:

- **filter by text** — type words; a line must contain them all (the same way you filter logs
  elsewhere);
- **pick a time range** — last 15 minutes / hour / 6 hours / 24 hours / all retained;
- **narrow to one copy** of a scaled service, or merge all copies together (the default);

and, from the [Errors tab](./errors.md), click **app logs ↗** on any erroring request to jump straight
to that service's logs *around the time of the error* — closing the loop from "which route is failing"
(the edge's view) to "why" (the app's own error/stack, which the edge never sees).

Logs are captured **going forward** from when a service starts running, and kept for about **two days**,
then expire. They live in their own file, separate from Mooring's database, so this never slows the
dashboard. Each service keeps a bounded amount of recent output, and a service that floods its logs is
rate-limited (with a "*… N lines dropped*" marker) so it can neither crowd out other services nor fill
the disk.

### Turning it on

Log retention is **off by default**, on purpose. Unlike the Errors tab — which only records the edge's
*request metadata* (method, path, status, IP) — this writes the **app's own output** to disk, and app
logs can contain secrets, tokens, or personal data that the app prints. So it's opt-in, and when on:

- the capture file is `0600` (owner-only) in Mooring's root-only data directory;
- entries expire on the short TTL above;
- reading it needs an authenticated operator — the same audience that can already live-tail.

To turn it on, set in `/etc/mooring/config.yaml` and reload:

```yaml
server:
  service_log_enabled: true
```

Because logs are only captured while it's on, turn it on *before* you need it — you can't retroactively
capture what a service printed while capture was off. On a very high-traffic box you might leave it off
(or turn it on only while chasing a specific problem). The live tail always works regardless, and never
writes to disk.
