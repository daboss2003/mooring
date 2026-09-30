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

> **Restart, not reload.** The alerting engine starts at boot, so `systemctl reload` won't turn it on — you must `systemctl restart mooring`. (See [editing the config file](./installation.md#editing-the-config-file-reload-vs-restart).)

Everything else is managed in the dashboard — no files or config to hand-edit. The **Alerts** page shows open alerts and links to two dedicated screens: **Channels** (where alerts go) and **Rules** (what to watch for). Each has an **Add** button that opens a form. Alerting is **not** part of any app's `mooring.yaml`: channels and rules are platform-level and live in the dashboard, and channel credentials (SMTP passwords, webhook secrets, bot tokens) are stored **encrypted at rest** — they are never rendered back into a form or written to a file. Open problems also appear on the **Incidents** screen.

## What it watches

- **Your servers** — CPU, memory, and disk.
- **Your apps** — containers going down, becoming unhealthy, or restart-looping; a dependency an app reports as down.
- **The platform** — crashed or out-of-memory containers, a restart storm, low memory headroom, a full disk.

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

Alerts are **deduplicated** — one problem is one page, not a flood — and they respect your **quiet hours**: non-critical alerts are held overnight, while critical ones always come through. Mooring paces its own sending so a slow mail server or bot can never turn it into a spam-cannon.

## Knowing Mooring itself is alive (the dead-man's switch)

A dashboard that's down can't alert you that it's down. So Mooring sends a periodic heartbeat to an outside URL you choose (`dead_mans_url` — for example a free check at [healthchecks.io](https://healthchecks.io)). As long as Mooring is healthy, the pings keep arriving. If Mooring — or the whole server — dies, the pings stop and that outside service pages you. Set it once and you're covered even for a total-host failure.

## Acking and silencing

On the **Alerts** page you can see every open alert and:

- **Acknowledge** it — you've seen it; stop re-paging.
- **Silence** it for a while — useful during planned maintenance.

An alert **auto-resolves** on its own once the underlying problem clears.
