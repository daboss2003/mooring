# Alerts

Mooring can tell you when something needs your attention — an app going down, a server running hot or low on disk, a service stuck restarting — and it can even tell you when **Mooring itself** goes dark. Alerting is **off until you turn it on**, and adds nothing to a running system until you do.

See also: [Scaling & self-healing](./scaling-and-self-healing.md) · [Backups & recovery](./backup-and-recovery.md)

---

## Turning it on

Enable alerting in `config.yaml` and **restart** Mooring:

```yaml
alerting:
  enabled: true
  quiet_start_hour: 22      # optional: hold non-critical alerts overnight
  quiet_end_hour: 7
  dead_mans_url: "https://hc-ping.com/your-uuid"   # heartbeat target (see below)
```

```bash
sudo systemctl restart mooring
```

> **Restart, not reload.** The alerting engine reads `alerting.*` at boot, so `systemctl reload` neither turns it on nor applies a change to its settings (quiet hours, intervals, the heartbeat) — you must `systemctl restart mooring`. (See [editing the config file](./installation.md#editing-the-config-file-reload-vs-restart).)

Everything else is managed in the dashboard — no files or config to hand-edit. The **Alerts** page shows open alerts and links to two dedicated screens: **Channels** (where alerts go) and **Rules** (what to watch for). Each has an **Add** button that opens a form. Alerting is **not** part of any app's `mooring.yaml`: channels and rules are platform-level and live in the dashboard, and channel credentials (SMTP passwords, webhook secrets, bot tokens) are stored **encrypted at rest** — they are never rendered back into a form or written to a file. Open problems also appear on the **Incidents** screen.

## What it watches

- **Your servers** — CPU, memory, and disk.
- **Your apps** — containers going down, becoming unhealthy, or restart-looping; a dependency an app reports as down.
- **The platform** — crashed or out-of-memory containers, a restart storm, low memory headroom, a full disk.
- **The edge** — a namespace with a [catch-all route](./edge-and-tls.md#catch-all-routes) whose wildcard certificate isn't served raises a critical `edge_catchall_dark` alert naming the namespace and the cause; it resolves when the certificate is served again.
- **Host and edge maintenance** — host vulnerabilities, a pending reboot, the supervised Caddy or L4 nginx running replaced files, and refreshes of the Mooring-owned Caddy build (see below).

### Host and edge maintenance alerts

Mooring raises these on its own. They need no rule and go to every enabled channel.

| Kind | Level | Target | Sent when |
|---|---|---|---|
| `host_vulnerabilities` | `critical` if a new finding is Critical, else `warning` | `host` | A [host scan](./server-tab.md#host-vulnerabilities) finds a High or Critical finding with a fixed version (identified by CVE ID, package and target) that no earlier `host_vulnerabilities` alert included. Counts the new findings and gives the totals. Gives the upgrade command for the OS packages with such a finding (`apt-get install --only-upgrade` or `dnf upgrade`, up to 20 names), says when the upgrade restarts Docker, and what fixes each affected binary. A scan with only already-alerted findings, or fewer findings, sends nothing. Findings without a fixed version never alert. |
| `host_reboot_required` | `warning` | `host` | After a host scan while `/run/reboot-required` exists (Debian/Ubuntu). Lists the packages from `/run/reboot-required.pkgs`. Sent again when the package list changes. |
| `edge_child_restarted` | `warning` | `caddy` or `nginx-l4` | A package upgrade replaced the binary or a loaded library of the supervised Caddy or L4 nginx, and Mooring restarted it after the replaced files had stayed the same for 2 minutes and the new files passed a start check. |
| `edge_child_stale` | `warning` | `caddy` or `nginx-l4` | The supervised Caddy or L4 nginx still runs replaced files and Mooring did not restart it: the new files failed the start check, or it was already restarted automatically in the last 30 minutes. |
| `caddy_build_refreshed` | `warning` | `caddy` | With `edge.mode: managed`, the host scan found a finding with a fixed version in the Mooring-owned Caddy build (`<data_dir>/bin/caddy`), and Mooring downloaded, verified and swapped in a current build, then restarted the edge. The previous build is kept as `bin/caddy.bak`. A download whose Go build info equals the installed build is not swapped and sends no alert (it is logged). At most one download every 20 hours. |
| `caddy_build_refresh_failed` | `warning` | `caddy` | That refresh failed (download or verification), or downloaded nothing because Caddy still refuses the edge config that held the last build back; the installed build keeps running. At most one alert a day. |

Each of these is sent once per condition while Mooring runs; after a restart a condition that still holds is sent once more.

## How it decides what to send

Some apps already alert on their own. Mooring is smart about this:

- **App alerts defer to apps that cover themselves.** If an app already pages you about its own health, Mooring won't double-page. The one exception is a **down safety net**: if an app actually goes *down* or unreachable, Mooring always alerts — so "the app went dark" never results in silence.
- **Platform alerts always fire.** Container crashes, out-of-memory kills, restart storms, a full disk — these are never deferred, because a crash-looping app can't be trusted to report its own death.

You set this up as **rules** on the **Rules** page (Alerts → Rules): pick what to watch (e.g. host CPU, container down, restart storm), an optional scope (all apps, or one app), a threshold, how long it must hold before alerting, the severity, and which channel to send to (a dropdown of your channels, or all enabled).

## How an alert reaches you

Add one or more **channels** on the **Channels** page (Alerts → Channels). An alert goes to each one:

| Channel | What you provide |
|---|---|
| **Gmail** | Just your Gmail address and a Google **App Password** — Mooring fills in the rest and sends over TLS. The easy way to get email alerts (see below). |
| **Email (SMTP)** | Any provider's SMTP server details (host, port, user, password, from, to). Sent over TLS; messages link back to the dashboard. |
| **Webhook** | A URL. The request is signed so your receiver can verify it's really from Mooring. |
| **Slack** | An incoming webhook URL. |
| **Discord** | An incoming webhook URL. |
| **Telegram** | A bot token and chat id. |
| **ntfy** | A server URL, a topic, and (optionally) a token for a protected topic/server. |

The **Add a channel** form shows **only the fields for the kind you pick** — choose ntfy and you'll see just the ntfy fields, choose SMTP and you'll see just the mail fields. After adding a channel, use **Send test** to confirm it works.

### Email alerts through Gmail (the easy way)

You don't need your own mail server — send alerts through your own Gmail account:

1. On the **Channels** page → **Add a channel**, pick **Gmail**.
2. Enter your **Gmail address** and a Google **App Password** (see below). Optionally set a different
   recipient; leave it blank to email the alerts to yourself.
3. **Send test** to confirm.

**You must use an App Password, not your normal Gmail password** — Google blocks normal-password
sign-in for apps. To create one: enable **2-Step Verification** on your Google account, then go to
[myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords), generate a password,
and paste the 16-character code into Mooring. Alert volume is tiny (a handful of messages), well under
Gmail's daily sending limit. The App Password is stored **encrypted at rest** and never shown back;
Mooring only ever connects to `smtp.gmail.com` over TLS with it.

### Push to your phone with ntfy

[ntfy](https://ntfy.sh) is the easiest way to get alerts as phone push notifications. To set it up:

1. On the **Channels** page (Alerts → Channels) → **Add a channel**, pick **ntfy** and fill in:
   - **Server URL** — `https://ntfy.sh` (the free public service) or your own ntfy server.
   - **Topic** — any name, e.g. `mooring-alerts-7x2k9`. On public ntfy.sh a topic is *unauthenticated*, so **use a long, random name** (anyone who knows it can read it).
   - **Token** — leave blank for public ntfy.sh; fill it only if your topic/server requires auth.
2. Install the **ntfy app** (iOS/Android) and **subscribe to the same topic** (on a self-hosted server, subscribe to the full URL, e.g. `https://ntfy.example.com/<topic>`).
3. Back in Mooring, click **Send test** — you should get a push within a second or two.
4. Add a **rule** (below) so real conditions actually fire to it.

If you'd rather not rely on public ntfy.sh, you can self-host ntfy (a single small binary) and point the channel at it — see [the ntfy docs](https://docs.ntfy.sh/install/).

### Let Mooring host ntfy for you

If you don't want to use public ntfy.sh **or** run ntfy yourself, pick **ntfy (Mooring-hosted)** when adding a channel. Mooring runs its own private ntfy for you:

- You give it a **hostname** (a DNS name pointed at this server, e.g. `ntfy.example.com`) and a **topic**.
- Mooring starts a locked-down ntfy container, **exposes it through the managed edge with automatic HTTPS**, and creates a read-only **subscriber account** (username `phone` + a generated password). Mooring publishes with its own write token, kept server-side; the subscriber account can only **receive**, never publish.
- The **Channels** page then shows your **Server URL, Topic, Username, and Password**.

Because the server is locked down, **you must sign in before you can subscribe** — if you skip this, the ntfy app shows a misleading *"WebSocket not supported / the server may not support WebSocket connections"* error (that means *not signed in*, not a real WebSocket problem).

**ntfy Android app:**

1. Open the app → **⋮ menu → Settings → Manage users → Add user**.
2. Enter the **Service URL** (the Server URL from the Channels page, e.g. `https://ntfy.example.com`), the **Username** (`phone`), and the **Password**. Save.
3. Back on the main screen, tap **+** to add a subscription, enter the **Topic**, choose **Use another server** and enter the same Server URL, then **Subscribe**. The app uses the credentials you just added.

**Web UI or iOS:** open the **Server URL** in a browser (or add it in the iOS app), click **Sign in**, enter the username + password, then subscribe to the topic.

> Order matters: **add the user first, then subscribe.** Subscribing before the credentials exist is what triggers the "WebSocket not supported" error.

iOS gets instant push via ntfy.sh's free relay (which only ever sees an opaque topic hash, never your messages).

Requirements: the **managed edge must be enabled** (Mooring needs it to expose ntfy over HTTPS) and the hostname's **DNS must point at this server** (so the edge can get a certificate). The ntfy server is **only run once you configure this channel** — deleting the channel stops and removes it. (If you set this up before v0.3.46, delete the channel and re-add it to switch to the username+password account.)

> **If sign-in is rejected** (the ntfy app says *"user phone not authorized"* or *"invalid credentials"* even with the exact username + password from the Channels page): just **re-submit the ntfy channel form** with the same hostname and topic. Mooring restarts the ntfy server so it re-reads the current credentials, after which the username + password shown on the Channels page work. (Before v0.3.50 a re-configure rewrote the credentials but didn't restart the server, so the displayed password could lag what the running server expected.)

Alerts are **deduplicated** — one problem is one page, not a flood — and they respect your **quiet hours** (see below). Mooring paces its own sending so a slow mail server or bot can never turn it into a spam-cannon.

### Quiet hours

`alerting.quiet_start_hour` and `alerting.quiet_end_hour` (0–23, server local time) set a nightly window from the start of the start hour to the start of the end hour; a start later than the end wraps past midnight (`22` and `7` cover 22:00–06:59; use `0` for midnight). The same hour for both means no quiet hours. `-1` for either disables quiet hours (the default). Any other value turns quiet hours off, and Mooring logs a `config:` warning at startup.

- Critical alerts are sent immediately, inside the window too.
- Every other alert is held while the window lasts, then sent when it ends, oldest alert first.

### How notifications are sent

- Critical alerts are sent before any other pending alert, also when they are raised while other alerts are being sent.
- All pending notifications of one alert are sent as one message. It reports the alert's latest state and ends with a line such as `Fired and recovered 14 times since 23:04.`, or `Recovered at 23:00, then fired once.` when the first of them is a recovery. One alert is one rule on one target, or one of Mooring's own alerts (for example the self-heal alert of one service).
- That message is critical when any of the notifications it combines is critical, including one whose delivery failed until it was dropped. It is sent immediately, inside quiet hours too, when it combines a critical notification that has not been sent yet. A message that is critical only because of a dropped critical notification is held during quiet hours like a warning, and sent when they end. A critical raised for a service whose warning is being held sends one message that includes the warning; the warning is not sent again in the morning.
- A self-heal alert's recovery is sent at the highest level the alert reached: a held warning that recovers during the window is reported once in the morning, with its recovery.
- If Mooring can't record a self-heal alert (for example, the disk is full), it tries again on every check until it can. Only the service's latest state is recorded. A recovery is not sent for an alert that was never recorded. When Mooring can't tell whether the alert was recorded (it can't read its records, or the alert may be older than the 7 days records are kept), the recovery is sent.
- A failed send is retried on the channels that failed only (after a restart of Mooring, on every channel). A message every channel took is not sent again when Mooring can't record its delivery; only the record is retried. A message that isn't critical is tried 3 times in all, on the following send cycles (Mooring sends every 15 seconds and when an alert is raised). A critical message is retried 15 seconds after the first failure, then with the wait doubling up to one hour between tries, until its notifications are 24 hours old. A message that still fails is dropped; its notifications are reported with the alert's next message.
- Mooring's own alerts for a condition that lasts are not repeated while it lasts. `low_headroom` (a failing service needs a restart while memory headroom is below the floor) is sent once per failure of the service (once more if Mooring restarts meanwhile) and resolved when the service recovers. `scale_refused_no_capacity` (a service can't scale up for lack of host capacity) is sent once, also across a restart of Mooring, and resolved when the service scales up or no longer needs to.
- **Clear & retry** on a service's open self-heal circuit closes the service's self-heal alert without a message; a later failure of the service is a new alert. The self-heal alert of a service whose app no longer has any container is closed the same way. If Mooring can't record the close, it tries again on every check; until it can, the service's later alerts wait, and one that recovers meanwhile is not sent.
- Notifications still unsent 48 hours after they were raised are dropped without being sent, also while `alerting.enabled` is false, so enabling alerting later doesn't replay old states. Sent and dropped notifications are kept for 7 days.

## Knowing Mooring itself is alive (the dead-man's switch)

A dashboard that's down can't alert you that it's down. So Mooring sends a periodic heartbeat to an outside URL you choose (`dead_mans_url` — for example a free check at [healthchecks.io](https://healthchecks.io)). As long as Mooring is healthy, the pings keep arriving. If Mooring — or the whole server — dies, the pings stop and that outside service pages you. Set it once and you're covered even for a total-host failure.

## Acking and silencing

On the **Alerts** page you can see every open alert and:

- **Acknowledge** it — you've seen it; stop re-paging.
- **Silence** it for a while — useful during planned maintenance. The silence drops the alert's notifications that are waiting to be sent (for example held by quiet hours) and every notification it raises while silenced. It lasts until the chosen time, also when the alert resolves and fires again before then; a firing after that time is sent.

An alert **auto-resolves** on its own once the underlying problem clears.
