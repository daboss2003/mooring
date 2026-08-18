# The Activity tab

The **Activity** tab is a running log of what Mooring itself has been doing — so when something looks off, you can see the recent events without SSHing in to run `journalctl -u mooring`.

See also: [Alerts](./alerting.md) · [The Server tab](./server-tab.md)

---

## What it shows

Mooring's own recent operational events — the things worth noticing, not routine chatter:

- deploys and image builds,
- vulnerability scans and backups,
- git-fetch failures (an expired token, a renamed repo),
- auto-scaling decisions and refusals,
- self-healing actions and give-ups.

Each row says what happened, when, and the detail that matters. It's **read-only** — a window onto events, not a place to act on them (you act from the app, Incidents, or Server pages).

## Why it stays readable

- **Repeats collapse.** An event that fires over and over — a git fetch failing every couple of minutes, say — shows as a **single row with a count** and its first- and last-seen times, instead of hundreds of identical lines. One glance tells you "this has been happening for an hour," not "scroll forever."
- **It's bounded.** Only the last **24 hours** are kept, up to a few hundred distinct events; older or excess rows drop off on their own. Activity is a *recent-history* view, not an archive — for the durable, security-relevant record of **who did what**, see the **Audit log**.
- **It doesn't tax the database.** The events live in their own small file on disk, separate from Mooring's database, and survive a restart. Keeping them out of the database means the Activity view never competes with the dashboard for the single database connection.

## Activity vs. Alerts vs. Audit

- **Activity** — a passive feed of recent operational events. Always on; nothing to configure.
- **[Alerts](./alerting.md)** — Mooring reaches out to *you* (email, Slack, …) when something needs attention. Opt-in.
- **Audit log** — the tamper-evident record of operator actions (logins, deploys, deletes) for security review.
