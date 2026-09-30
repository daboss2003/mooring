# Scaling & self-healing

Two optional automations keep your apps responsive and running. Both are **off until you turn them on**. If acting would risk your server, they hold back and alert you instead.

See also: [Alerts](./alerting.md) · [Incidents](./first-steps.md)

---

## Auto-scaling

Auto-scaling adjusts how many copies (**replicas**) of a service run, based on load — more under pressure, fewer when idle. You enable it **per service** on the app's page.

**Only stateless services qualify.** A service must be **stateless and edge-fronted** — no fixed host port, no read-write data volume — because running several copies of something stateful (like a database) would corrupt its data. You confirm this when enabling it, and Mooring re-checks each cycle: if a service gains a writable volume or starts looking stateful, it's scaled back down and left alone.

**Edge-fronted means HTTP *or* L4.** Normally "edge-fronted" is an HTTP service behind an `edge.route`. A **non-HTTP** stream service (DNS, MQTT) can also scale if you front it with an [`edge.l4_route`](./definition-file.md#specedgel4_routes-tcpudp-load-balancing): the L4 load balancer owns the public port and the replicas stay internal, so it no longer "publishes a fixed host port." This needs **nginx installed on the host** and `edge.l4_enabled` (it's opt-in and not bundled — see the definition-file reference). Without it, such services run as a single instance.

**It only adds capacity when there's room.** Before starting another replica, Mooring checks there's provably enough memory and CPU, keeping headroom for itself and the edge. On a server that's near its limit it **collapses to a single replica** and won't scale up. Separate scale-up and scale-down thresholds (and a hold window) keep it from flapping up and down.

**It adds one copy at a time.** Every scale-up starts a single new copy, and the next copy is started only when:

- every copy of the service is running and healthy — or, for a service without a healthcheck, past its start-up (see [start pacing](#start-pacing));
- no copy is stopped (a crashed copy is restarted by self-healing, not by the scaler);
- self-healing isn't working on the service;
- the [start gate](#start-pacing) admits the start.

Raising `min` or nudging by more than one raises the desired count at once; the copies are then started one by one. Removing copies is never delayed. A scale-up driven by load also holds while earlier copies are still being added, and doesn't happen while the host CPU is busy (another copy on a saturated host adds contention, not capacity).

If every container of an auto-scaled service is gone (removed outside Mooring, say) while the rest of its app still runs, the service is started again one copy at a time — but only when the app's deployed `mooring.yaml` still declares it as a long-running service. A scale call that fails is retried after 1 minute, then after 2, 4 and 8, and then every 10 minutes until one succeeds.

**You're alerted if it can't scale up.** If it declines to scale because the server is constrained, it can alert you — that's your cue the box needs more resources.

**Scale on more than CPU/memory.** CPU and memory aren't always the load that matters — a queue worker's real pressure is its **backlog**, and an I/O-bound API can crawl at low CPU while its **latency** climbs. You can add **custom signals** to a policy that scale on those directly (in addition to CPU/mem): a **queue depth** from the app's [ops interface](./app-ops-interface.md), or **p95 latency / request rate measured by Mooring's edge** (which the app can't fake). This is the fix when CPU-based scaling never fires because your slow endpoint is waiting on a database, not burning CPU. See [`spec.scaling` → custom scaling signals](./definition-file.md#custom-scaling-signals-metrics).

**Turn off CPU/memory scaling.** The **Scale on CPU & memory** checkbox (on by default) controls whether CPU and memory drive scaling for a service. Uncheck it and the service no longer scales up on a busy CPU or scales down when idle — it moves only on the custom signals you've defined, or, if there are none, holds at its current replica count. Use this for a service whose own start-up work is CPU-heavy: while new replicas warm up they burn CPU, which reads as high load and triggers yet more replicas, and the whole set can sit pinned at 100% without any of them becoming healthy. Turning CPU/memory off breaks that loop. The min/max bounds, the host-capacity ceiling, and hand nudges all still apply. In `mooring.yaml` this is [`spec.scaling[].scale_on_cpu_mem`](./definition-file.md#specscaling) (`true` when omitted).

You configure min/max replicas, per-replica memory and CPU, and the up/down thresholds on the service's **Auto-scaling** panel. **The auto-scaling policy is an exception to the read-only dashboard** — it is operational tuning you set live, per service, without a redeploy.

**Nudge replicas by hand.** On the same panel you can step a scalable service's replica count **+1 / −1** on demand — to pre-warm before a spike you know is coming, or to shed a copy. It's bounded by the same limits as an automatic decision (never below min, above max, or past what the host can fund), and it's a **temporary boost, not a pin**: the service rejoins normal auto-scaling and can be scaled back down again under sustained low load. Only a service that already has auto-scaling enabled can be nudged.

> The same policy can also be expressed in the app's `mooring.yaml` under [`spec.scaling`](./definition-file.md#specscaling) (one entry per service), so it lives with the rest of the app's definition. A deploy applies what the file declares; the dashboard panel is for tuning it afterward. Either way the policy lands in the same place — there is no separate "canonical" copy to keep in sync.

> Never enable this for a database, message broker, or anything that owns data — those are meant to run as a single instance.

## Self-healing

The self-healing supervisor watches your services and **recovers ones that crash or get stuck** — restarting a failed container, and escalating if a restart isn't enough. It restarts one container at a time, paced by the [start gate](#start-pacing).

**How it escalates.** For a crashed or unhealthy service it climbs a short ladder — **restart**, then **recreate** (which also re-renders the service's config files and re-syncs its certificates, healing config drift), and, only if you opt in on a box with enough RAM, **redeploy**. Each rung is tried at most once per window, with back-off between attempts. Two cases short-circuit the ladder because retrying wouldn't help: a service being **OOM-killed repeatedly** (it needs more memory, not another restart), and a restart that would need memory the host can't spare (Mooring **pages you instead of acting**). It also covers the **deploy path** — if an interrupted recreate strands a container holding a service's name, Mooring reclaims that app's own stuck container and retries once (see [self-healing a stuck container](./gitops.md#how-updates-work)).

**Services with several copies.** A scaled service is judged as a whole: it is failing when any copy is down or failing its healthcheck.

- **Restart** restarts one sick copy (`docker restart <copy>`); the other copies keep serving.
- Every other sick copy is then restarted the same way, one per action, before the service moves up the ladder. Only the first of these restarts uses up an attempt — so after a reboot that left several copies stopped, they come back one at a time.
- **Recreate**, for an auto-scaled service with at least one copy that isn't sick, removes the sick copies and the auto-scaler starts fresh ones, one at a time. Otherwise the service is recreated (`docker compose up --force-recreate --no-deps` for that service).
- The attempt count isn't reset while the service keeps running with several copies, until the attempt window (30 minutes by default) ends. A copy that keeps failing — even minutes after each restart — ends in the "gave up" state below instead of being restarted forever.

When it **can't** recover a service after trying, it stops retrying (to avoid a crash-loop hammering the box), **flags the service on the Incidents screen**, and alerts you. That's the "self-healing gave up" state — you investigate, fix the underlying problem, and click **clear & retry** to let Mooring try again. The state holds while the service waits on a dependency or on its certificate.

**Stopping a service on purpose won't fight you.** When you **Stop** a service (or a whole app), Mooring records a *hold*: the supervisor and the auto-scaler both leave it down and won't restart it. A held service stays stopped until you **Start**, **Restart**, or **Redeploy** it — so planned downtime is just Stop, with no window to set or expire. (See [Starting and stopping services](./gitops.md#starting-and-stopping-services).)

Self-healing is conservative for the same reason auto-scaling is: a recovery action that needs to recreate a container runs only when there's room, so healing one app can't knock over the server.

### Dependencies

When a service is failing while a service it depends on (`depends_on`) is failing or still recovering, it is not restarted: restarting it can't fix the dependency and only adds load. The service shows **waiting on a dependency** (`WAITING_ON_DEPENDENCY`), and the dependency is remediated first.

A dependency counts as recovering until it has been running and healthy for 60 seconds, or two of the dependent's healthcheck intervals if that is longer. Dependencies are followed through `depends_on` chains. The graph comes only from the app's deployed `mooring.yaml`.

The wait is capped at **10 minutes**. After that Mooring sends a warning alert and the service goes through its normal restart/recreate ladder.

### Reporting instead of restarting

A service that sets [`self_healing.on_unhealthy: notify`](./definition-file.md#self_healing-per-service) is never restarted for a failing healthcheck. After the failure persists it shows **failing its healthcheck** (`UNHEALTHY`) and Mooring sends one warning alert, resolved when the healthcheck passes again. A copy that exits is still restarted.

## Start pacing

Starting several services at once on a small host makes them compete for CPU, and none of them becomes healthy. The **start gate** makes Mooring's own automatic starts — auto-scaling, self-healing, and [scheduled tasks](./scheduled-tasks.md) — wait while:

- another container started recently is still starting: until its healthcheck passes, or, for a container without a healthcheck, for at least `settle_grace` and until its CPU drops below `cpu_settle_pct` of one core. One start holds others back for at most `max_settle`. A container that keeps crashing (its restart count rising) holds nothing back;
- the host CPU (averaged over the last three monitor samples) is at or above `cpu_busy_pct`. An action that has waited `max_wait` for CPU — or for other starts — starts anyway, and restoring a service with no running copy never waits for CPU. When self-healing restarts a service, that service's own containers are left out of both checks. A scheduled task held back for `max_wait` for either reason starts anyway.

Deploys, rollbacks, lifecycle actions (start, restart, redeploy) and certificate renewals start services one at a time too, but they are **paced, never held back** — a deploy is often the fix for the unhealthy service. Their waits for CPU or other apps' starts total at most `deploy_wait` per deploy or action; each service waits at most its health deadline (capped at `service_settle`); after `rollout_budget` the remaining services start without waiting; and a service that doesn't become healthy is reported while the rest carry on (see [paced starts](./gitops.md#paced-starts)). The containers they start are recorded, so the automatic starters wait for them to settle.

Configure it in `/etc/mooring/config.yaml` (restart Mooring to apply):

```yaml
server:
  start_gate:
    enabled: true        # false turns pacing off
    cpu_busy_pct: 85     # host CPU % at which starts wait (10–100)
    settle_grace: 30s    # minimum start-up time of a container without a healthcheck (0s–10m)
    cpu_settle_pct: 50   # % of one core below which it has settled (1–1000)
    max_settle: 3m       # longest one start holds others back (10s–30m)
    max_wait: 10m        # longest an action waits for CPU (1m–2h)
    deploy_wait: 2m      # deploys and operator actions: total wait for CPU or other starts (0s–30m)
    service_settle: 15m  # deploys and operator actions: longest wait for one service to become healthy (30s–1h)
    rollout_budget: 45m  # deploys and operator actions: total pacing; the rest then start unpaced (1m–3h)
```

A service whose start-up is slow should declare a [`healthcheck`](./definition-file.md#healthcheck) with a `start_period`; Mooring then waits for the healthcheck instead of guessing from CPU.

## Tuning self-healing

Every service is supervised with a conservative built-in default; you don't turn it on per service. To tune the ladder for an app — the anti-flap window, attempt cap, back-off, and the opt-in rung-3 redeploy — declare [`spec.self_healing`](./definition-file.md#specself_healing) in its `mooring.yaml` and deploy (omitted fields keep the default). The only dashboard self-healing **action** is **clear & retry** on the Incidents screen, which resets a service whose circuit has opened.
