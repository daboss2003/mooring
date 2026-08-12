# Scaling & self-healing

Two optional automations keep your apps responsive and running. Both are **off until you turn them on**. If acting would risk your server, they hold back and alert you instead.

See also: [Alerts](./alerting.md) · [Incidents](./first-steps.md)

---

## Auto-scaling

Auto-scaling adjusts how many copies (**replicas**) of a service run, based on load — more under pressure, fewer when idle. You enable it **per service** on the app's page.

**Only stateless services qualify.** A service must be **stateless and edge-fronted** — no fixed host port, no read-write data volume — because running several copies of something stateful (like a database) would corrupt its data. You confirm this when enabling it, and Mooring re-checks each cycle: if a service gains a writable volume or starts looking stateful, it's scaled back down and left alone.

**Edge-fronted means HTTP *or* L4.** Normally "edge-fronted" is an HTTP service behind an `edge.route`. A **non-HTTP** stream service (DNS, MQTT) can also scale if you front it with an [`edge.l4_route`](./definition-file.md#specedgel4_routes-tcpudp-load-balancing): the L4 load balancer owns the public port and the replicas stay internal, so it no longer "publishes a fixed host port." This needs **nginx installed on the host** and `edge.l4_enabled` (it's opt-in and not bundled — see the definition-file reference). Without it, such services run as a single instance.

**It only adds capacity when there's room.** Before starting another replica, Mooring checks there's provably enough memory and CPU, keeping headroom for itself and the edge. On a server that's near its limit it **collapses to a single replica** and won't scale up. It moves **one step at a time** with separate scale-up and scale-down thresholds (and a hold window), so it doesn't flap up and down.

**You're alerted if it can't scale up.** If it declines to scale because the server is constrained, it can alert you — that's your cue the box needs more resources.

**Scale on more than CPU/memory.** CPU and memory aren't always the load that matters — a queue worker's real pressure is its **backlog**, and an I/O-bound API can crawl at low CPU while its **latency** climbs. You can add **custom signals** to a policy that scale on those directly (in addition to CPU/mem): a **queue depth** from the app's [ops interface](./app-ops-interface.md), or **p95 latency / request rate measured by Mooring's edge** (which the app can't fake). This is the fix when CPU-based scaling never fires because your slow endpoint is waiting on a database, not burning CPU. See [`spec.scaling` → custom scaling signals](./definition-file.md#custom-scaling-signals-metrics).

You configure min/max replicas, per-replica memory and CPU, and the up/down thresholds on the service's **Auto-scaling** panel. **The auto-scaling policy is an exception to the read-only dashboard** — it is operational tuning you set live, per service, without a redeploy.

> The same policy can also be expressed in the app's `mooring.yaml` under [`spec.scaling`](./definition-file.md#specscaling) (one entry per service), so it lives with the rest of the app's definition. A deploy applies what the file declares; the dashboard panel is for tuning it afterward. Either way the policy lands in the same place — there is no separate "canonical" copy to keep in sync.

> Never enable this for a database, message broker, or anything that owns data — those are meant to run as a single instance.

## Self-healing

The self-healing supervisor watches your services and **recovers ones that crash or get stuck** — restarting a failed container, and escalating if a restart isn't enough. It only ever *reduces* pressure or holds steady; it never adds load.

When it **can't** recover a service after trying, it stops retrying (to avoid a crash-loop hammering the box), **flags the service on the Incidents screen**, and alerts you. That's the "self-healing gave up" state — you investigate, fix the underlying problem, and click **clear & retry** to let Mooring try again.

**Planned downtime:** if you're taking a service down on purpose, mark it as expected-down for a window so the supervisor doesn't fight you trying to bring it back.

Self-healing is conservative for the same reason auto-scaling is: a recovery action that needs to recreate a container runs only when there's room, so healing one app can't knock over the server.

Every service is supervised with a conservative built-in default; you don't turn it on per service. To tune the ladder for an app — the anti-flap window, attempt cap, back-off, and the opt-in rung-3 redeploy — declare [`spec.self_healing`](./definition-file.md#specself_healing) in its `mooring.yaml` and deploy (omitted fields keep the default). The only dashboard self-healing **action** is **clear & retry** on the Incidents screen, which resets a service whose circuit has opened.
