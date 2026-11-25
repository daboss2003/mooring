# Security incidents

[Detections](./security-detections.md) of the same account or the same address (the detection's
key) within 24 hours are grouped in one **incident**. An incident has a timeline, a severity (raised for known
attack chains), one alert, a workflow state, notes and an assignee. Each account and address also
has a **risk score**. Only an **owner** can see incidents and change them; every change is recorded
in Mooring's audit log.

Incidents are on whenever [detection](./security-detections.md) is on.

See also: [Security detections](./security-detections.md) · [Automated response](./security-responses.md) · [Log patterns](./security-patterns.md) · [Security logs](./security-logs.md) · [Alerts](./alerting.md)

---

## Entities

An incident is kept per **entity**: an account or an address.

| Kind | Key | Scope |
|---|---|---|
| `address` | An IP address. An IPv6 address counts as its /64 prefix (`2001:db8:1:2::/64`), an IPv4-mapped IPv6 address as the IPv4 address. | none |
| `account` | The account as stored: a Mooring user name, a server user name, or an app's account (a keyed hash when it is personal data). | `mooring`, `host`, `app:<slug>` or `edge` |

The scope keeps accounts of different systems apart: the server user `alice` (`host`), the Mooring
user `alice` (`mooring`) and an app's `alice` (`app:shop`) are three entities.

A detection's entities are:

- Its **key entity**: its key, when the rule's group-by is `ip` (an address) or `actor`,
  `f.account`, `f.target` or `f.user` (an account). For `f.user`, only when the event has `f.user`:
  a `host.user_change` line that names only a group joins no incident. Once a detection's key is an
  account, later events of that detection don't change it (a `groupadd` line after the `useradd`
  line of the same name).
- The addresses and accounts of its evidence events (at most 10). An evidence account takes the
  detection's scope; in an app scope, the evidence event's app.

The key entity groups detections. The evidence's addresses and accounts are listed on the
incident, and count in their risk scores, but don't join or open an incident, with one exception:
a detection that completes a [known chain](#severity-and-known-chains) (see Grouping).

The scope is the source of the detection's first event: `mooring` for Mooring's own events, `host`
for SSH, sudo, su, host account changes and Fail2Ban, `app:<slug>` for an app's events, `edge` for
the edge.

Not entities: loopback and unspecified addresses (`127.0.0.1`, `::1`, `0.0.0.0`), values that aren't
addresses (`local`), and the user name of an `ssh.invalid_user` event (a name the server doesn't
have).

An account whose name holds a control character or invalid UTF-8 (an app's logged user name) is an
entity, but the dashboard doesn't list it and it can't be muted.

## Grouping

- A new detection joins an open or acknowledged incident of its key entity when the key's latest
  detection in that incident is at most 24 hours before the new detection's last event. Of several,
  it joins the one with the latest.
- A detection of a [known chain](#severity-and-known-chains)'s step can also join another open or
  acknowledged incident that lists its key entity (same kind and scope, from a detection of a chain
  step, within 24 hours), when it is the missing step of a chain there: the incident holds a
  detection of the chain's other step that lists that entity too, in order and within the chain's
  24 hours, and doesn't make that chain for that entity yet. Example: an `ssh.bruteforce` incident
  (keyed by the address) that tried `root` gets the `ssh.login_new_country` detection of `root`.
  The incidents looked at, in this order:
  1. Its key's own incident, when that would make the chain as well.
  2. The incidents keyed by one of the detection's own evidence addresses (the addresses the sign-in
     came from): one it completes. Else one that makes the chain for that entity already (the
     address's own sign-in detection) takes it, with no new alert, and no other incident is looked
     at.
  3. The other incidents listing its key entity that it completes, the most recently active first.
- A chain made for one account is made again for another: a spray that tried `alice` and `bob`,
  then both sign in, gets both sign-ins.
- The edge's block-list rules (`edge.spamhaus_ip`, `edge.dshield_ip`) never join this way: they
  join their key's incident only.
- Otherwise it joins its key's incident, or opens a new one (state `open`). A detection of a rule
  that is no chain step never joins through an entity another incident lists from its evidence.
- The incident's key entity, the first entity it lists, is its first detection's key. Only that key
  makes later detections join it the ordinary way: a key that joined to complete a chain doesn't.
- A detection stays in the incident it joined. Its updates move the incident's last time and add
  their entities. While the incident is resolved or a false positive, they change nothing and send
  no alert.
- A resolved or false-positive incident takes no new detection: a new detection of its key opens a
  new incident, or joins another open one of that key (one reopened, for example).
- An incident lists at most 50 entities (its key first) and 20 rules.

These detections join no incident and keep their own `security_detection` alerts:

- A rule's rollup detection (key `*`, see [Detections](./security-detections.md#detections)).
- [App Ops Interface alerts](./app-ops-interface.md#alerts) (source `ops`).
- Rules whose key is no account or address: group-by `app`, `kind`, `geo.cc`, `geo.asn`, `f.host`,
  `f.jail`, `f.sender_uid`, any other `f.<name>`, or none (for example `fail2ban.ban_burst`,
  `edge.error_anomaly`, `host.forged_log_line`).
- [Muted](#false-positives-and-mutes) detections.

## Severity and known chains

An incident's severity is the highest of its detections'. It is never lowered. Its title is
`<rule name>: <summary>` of its most severe detection, or `<chain name>: <entity>` once it matches a
known chain (`203.0.113.7`, `account root (host)`).

A **known chain** raises the incident to `critical`. It matches when the incident holds a detection
of the first step and a detection of a different rule of the second step, whose entities share one
(of the kind given), and the second starts at most 24 hours after the first's last event. The two
steps are in one incident when they have the same key (`ssh.bruteforce` then
`ssh.success_after_failures`, both by address), or when one step's detection lists the other's key
(a brute force by address that names the account, then that account's unusual sign-in; see
[Grouping](#grouping)). A change keyed by another account than the one that
signed in (`mooring.user_change` of `bob` by `alice`) is no step after `alice`'s sign-in.

| Chain | First step | Second step | Shared entity | Order | MITRE ATT&CK |
|---|---|---|---|---|---|
| Brute force then sign-in | `ssh.bruteforce`, `ssh.spray`, `mooring.login_bruteforce`, `mooring.login_spray`, `app.auth_bruteforce`, `app.auth_spray` | A successful sign-in: `ssh.success_after_failures`, `mooring.login_success_after_failures`, `app.auth_success_after_failures`, and every rule of the unusual sign-in list below | address or account | the sign-in doesn't end before the brute force starts | [T1110](https://attack.mitre.org/techniques/T1110/) → [T1078](https://attack.mitre.org/techniques/T1078/) |
| Account takeover | An unusual sign-in: `ssh.login_new_country`, `mooring.login_new_country`, `app.auth_new_country`, `app.admin_new_country`, `ssh.login_travel`, `mooring.login_travel`, `baseline.signin_unusual`, `ssh.login_spamhaus_ip`, `ssh.login_dshield_ip`, `app.admin_spamhaus_ip`, `app.admin_dshield_ip`, `ssh.login_tor`, `mooring.login_tor`, `app.admin_tor_login` | A privilege or account change: `mooring.user_change`, `app.privilege_change`, `host.user_change`, `sudo.failures`, `baseline.admin_unusual` | account | the change doesn't end before the sign-in starts | [T1078](https://attack.mitre.org/techniques/T1078/) → [T1098](https://attack.mitre.org/techniques/T1098/), [T1136](https://attack.mitre.org/techniques/T1136/), [T1548](https://attack.mitre.org/techniques/T1548/) |
| Listed address with access | A listed address: `ssh.login_spamhaus_ip`, `ssh.login_dshield_ip`, `mooring.api_token_spamhaus_ip`, `mooring.api_token_dshield_ip`, `app.admin_spamhaus_ip`, `app.admin_dshield_ip`, `edge.spamhaus_ip`, `edge.dshield_ip` | A successful sign-in (as in the first chain) | address | either | [T1078](https://attack.mitre.org/techniques/T1078/) |

`host.user_change` and `mooring.user_change` are keyed by the account that was changed (`f.user`,
`f.target`), not by who changed it: in Account takeover they match an unusual sign-in of that
account.

A rule that is switched off, or a custom rule with another ID, is never a step.

## Alerts

An incident sends a `security_incident` alert to every enabled channel (see
[Alerts](./alerting.md#host-and-edge-maintenance-alerts)):

- `warning` when its severity first reaches high, `critical` when it reaches critical. At most two
  alerts per incident: a `warning` and then a `critical`, or one `critical`. Later detections update
  the incident without an alert.
- Target `security-logs`. The message is `<title> — incident #<id>`, at most 300 bytes. The dedupe key
  is `siem-incident:<id>`. The alert is not resolved.
- A detection in an incident sends no `security_detection` alert of its own, and is not counted in
  its rule's 5 alerts per hour or in its rule's hourly summary. Incident alerts have no hourly limit.
- A detection keyed by an account or address new to an incident that joins it to complete a chain
  alerts again (`critical`) when the incident already alerted `critical`: once per such key. One
  that joins the incident of the address it came from, which made the chain for it already, sends
  no new alert. A re-alert owed while the incident was resolved or a false positive is sent when it
  is reopened; one not recorded before Mooring stopped is sent at the next start.
- Two attackers' chains on the same account are two incidents: a sign-in joins the incident of the
  address it came from, and an incident that makes the chain for that account already takes no
  other address's sign-in to complete it, which then completes the other attacker's incident (or
  opens its own) and alerts. A sign-in that came from both attackers' addresses joins the incident
  it completes, not the one that makes the chain already.
- A detection alerts once. One that alerted on its own before it joined an incident (a
  `host.user_change` group line, then the user line of the same name), or while its incident
  couldn't be read, counts for the incident: the incident doesn't alert that severity again.
- While `detect.db` can't be written, an incident has no ID and can't alert. Each high or critical
  detection that opens or joins one then alerts on its own (`security_detection`, not held back by
  its rule's hourly limits); once the incident is written, it alerts only for a higher severity.
- Detections of a snoozed rule join the incident and set the severity shown, but don't count for its
  alert.
- Only an open or acknowledged incident alerts. An alert still owed when the incident was resolved or
  marked a false positive is sent if it is reopened.
- An alert that can't be recorded is tried 3 times within about a minute, then again every minute
  until it is.
- The alert sent is recorded with the incident: after a restart it isn't sent again, and one raised
  but not recorded before Mooring stopped is sent at the next start.
- A `warning` is held during [quiet hours](./alerting.md#quiet-hours); a `critical` is sent at once.

## Workflow

| State | Meaning |
|---|---|
| `open` | New, or reopened. |
| `acknowledged` | Someone is looking at it. |
| `resolved` | Handled. |
| `false_positive` | Not an attack. Set with **False positive**, see below. |

- Any state can move to `open`, `acknowledged` or `resolved`. An incident is never resolved or
  closed automatically.
- Moving an incident from `false_positive` to `open`, `acknowledged` or `resolved` removes the mutes
  it made (see below), with a `muted` timeline entry `<n> rule and entity pairs unmuted: no longer a
  false positive` and an `unmuted` event.
- A state change can carry a note.
- **Assign** sets the assignee, a Mooring user with the owner role (only owners can open the incident
  pages); an empty assignee unassigns. An assignee who is no longer an owner is shown as such. User
  names are at most 256 bytes.
- **Add note**: 1 to 4096 bytes of text; tab and line breaks are the only control characters
  allowed.
- At most 400 changes and notes per incident. The timeline holds at most 500 entries: past that the
  oldest detection entries are removed, never another kind.

Timeline entries, oldest first: `opened`, `detection` (a detection joined, with its rule, severity
and summary), `escalated` (the severity rose, and why), `state`, `assigned`, `note`, `muted` (a
false positive muted its pairs, or a mute was removed), `response` (an
[automated response](./security-responses.md) about the incident: a block or sign-out recommended,
applied, refused, failed, dismissed or expired; a refusal for the same reason, action and target at
most once an hour; at most 100 per incident). Each entry made on the
dashboard names the user who made it.

## False positives and mutes

**False positive** sets the state `false_positive`. **False positive and mute** also mutes, for 30
days, each rule of the incident's detections keyed by the incident's key entity, for that entity.
The rules of detections that joined with another key to complete a chain (the account's sign-in in
the incident of the address that brute-forced it) aren't muted, so that account's sign-ins keep
alerting. Until a mute ends, that rule's detections for that entity:

- are still recorded, marked muted on the Detections page and in their `siem.detection` event
  (`f.muted: true`),
- send no alert,
- join and open no incident, and add nothing to a risk score.

A mute applies to the rule's detections keyed by that entity only: the same rule keeps firing for
other addresses and accounts.

Marking an incident a false positive, with or without a mute, also removes the automatic
[edge blocks](./security-responses.md#false-positives-and-exemptions) placed for it, exempts their
addresses from automatic blocks for 30 days, resets their repeat history (the next automatic block
of each starts at the rule's block length), and dismisses its waiting recommendations. The
timeline gets a `response` entry (`false positive: lifted 1 automatic block, dismissed 0
recommendations`). Manual blocks stay. When the blocks can't be removed, the incident is still
marked and the page says so: remove them on the Blocked addresses page.

- The incident's page and the entity's page list its mutes in force; **Remove** on the entity page
  ends one at once and records it in its incident's timeline (`mute removed: <rule> for <entity>`).
- Moving the incident to `open`, `acknowledged` or `resolved` removes all the mutes it made.
- Marking an incident again extends its mutes to 30 days from then.
- A pair whose key holds a control character or invalid UTF-8 isn't muted.
- At most 10,000 mutes in force; at most 1,000 rule and entity pairs per incident (an incident with
  more can be marked a false positive without muting).
- Mutes are stored in Mooring's database (table `security_mutes`), so the
  [Mooring-state backup](./backup-and-recovery.md) and `mooring restore` include them. Ended mutes
  are removed at startup and when mutes are added.
- Deleting an app removes the mutes of its accounts (scope `app:<slug>`). Its incidents and
  detections stay. After a start, the mutes of apps that no longer exist (deleted while detection
  was off) are removed too. An app exists while it has a connected repository, a stored
  definition, a provisioned-app entry or a container (running or stopped). This runs once the
  list of apps, containers included, can be read, within 3 minutes of the start; when it can't be
  read, nothing is removed until the next start.

## Risk scores

Each account and address has a risk score from 0 to 100:

- Each new detection adds to the score of each of its entities: low 5, medium 15, high 35,
  critical 60. A detection's updates add nothing; muted detections add nothing.
- The score is capped at 100 and halves every 72 hours. A score below 1 is dropped.
- At most 20,000 entities have a score; past that the lowest scores are dropped first.

The score shown is the current one, with its open (open or acknowledged) incidents counted.

## Incidents as security events

Every incident change is written to the security logs as a `siem.incident` event, so it is
searchable, exported and archived to S3 like any other event. Opened and escalated events are
written once the incident is stored in `detect.db` (with its `incident_id`). The detections that
join an incident are in its `siem.detection` events, with `f.incident_id`.

| Field | Value |
|---|---|
| `src`, `kind` | `siem`, `siem.incident` |
| `lvl` | `info` (low), `warn` (medium), `error` (high), `critical` (critical): the incident's severity |
| `ip` | The incident's first address (not a /64 prefix). |
| `actor` | The incident's first account. |
| `msg` | The title; for `note` the note's text; for `escalated`, `muted` and `unmuted` the timeline entry's text. |
| `f` | `incident_id`, `change` (`opened`, `escalated`, `state`, `assigned`, `note`, `muted`, `unmuted`), `state`, `severity`, `chain`, `assignee`, `actor` (the user who made the change), `entities` (comma-separated `address:<ip>` and `account:<scope>:<key>`) |

```
kind:siem.incident f.change:state
kind:siem.incident f.incident_id:42
```

A note is stored in the security logs as written: don't put secrets in notes.

## Storage and retention

- Incidents, their entities, their timeline and the risk scores are in
  `<data_dir>/security-logs/detect.db`, with the detections.
- An incident is removed, whatever its state, with its timeline, 400 days after its last
  detection's last event (the daily prune of detections).
- Past the `detect.db` size cap (see [Storage and retention](./security-detections.md#storage-and-retention)),
  removal goes in this order, oldest first: low and medium detections in no open or acknowledged
  incident, then any detection in none, then resolved and false-positive incidents with their
  entities and timeline, then, when only open and acknowledged incidents are left, those incidents
  with their detections, entities and timeline, until `detect.db` is under the cap.
- In memory: at most 2,000 incidents (the others are read from `detect.db` when needed), 20,000 key
  entities with up to 8 incidents each, and 20,000 entities listed by chain steps with up to 8
  incidents each.

## Dashboard

All pages are for owners only. Every change is recorded in Mooring's audit log.

- **Incidents** (`/security/incidents`): incidents, most recently active first, filtered by state,
  minimum severity and assignee, with each incident's severity, title, chain, entities, detection
  count, state, assignee and last activity. A panel lists the entities with the highest risk score.
- An incident's page: its timeline, entities (each links to its entity
  page), and detections (each links to the detection). Actions: **Acknowledge**, **Resolve**,
  **Reopen**, **False positive** (with or without mute), **Assign** and **Add note**; a state change
  can carry a note. The mutes the incident made that are still in force are listed, each with
  **Remove**; reopening the incident removes them. The [responses](./security-responses.md) about
  the incident are listed.
- **Entity** (`/security/entities`): an account's or address's risk score and open incidents, its
  incidents, and its mutes, each with **Remove**. An address's page shows its
  [edge block](./security-responses.md#manual-blocks), with **Block** or **Unblock**; an address
  inside another active block shows `Blocked by <prefix>` and neither button, and an IPv6 /64 with
  a narrower active block inside it shows `Partly blocked by <prefix>` and **Block**. **Find in Security logs** searches the address, or
  the account in its own source (`src:host`, `src:mooring`, `src:edge`, `src:app`, plus `app:<slug>`
  for an app account).

---

MITRE ATT&CK® is a registered trademark of The MITRE Corporation.
