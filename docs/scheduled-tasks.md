# The Scheduled tasks tab

Cron jobs used to be invisible — you declared `spec.scheduled_tasks` in `mooring.yaml` and hoped they ran. The **Scheduled tasks** tab makes them observable: what's running now, what ran recently, whether it worked, and why it didn't.

See also: [`spec.scheduled_tasks`](./definition-file.md#specscheduled_tasks-cron-jobs) · [The Activity tab](./activity.md)

---

## Running now

Any task currently executing appears at the top, with:

- the **app** that owns it and the service it runs,
- how long it's been **running**, and
- its **live CPU and memory** (read from the task's one-shot container and refreshed on a timer).

Tasks run **one at a time** (they share the single docker slot with deploys), so this is usually empty or a single row — but when a nightly job is grinding, you can see it working and how much it's using.

## Run history

Every run is recorded — one row per run, newest first:

- **When** it started, the **app** and **task**,
- the **result** — `ok`, or `failed` with the exit code and a short reason,
- how **long** it took, and
- a link to its **logs**.

Click **logs** on any run to see its captured output (the last 64 KB — where the error usually is). History and logs are kept for **7 days**, then pruned automatically.

## Why a run failed

A failed run's row shows a concise reason — the task's last output line (often the actual error, e.g. a permission denial), or a classified reason when it printed nothing:

- **timed out after `<timeout>`** — the run hit its [`timeout`](./definition-file.md#specscheduled_tasks-cron-jobs) (default 30 minutes; make it longer for a slow batch job).
- **interrupted — Mooring restarted mid-run** — a one-shot can't survive a restart, so it's marked interrupted rather than left showing as running forever.
- the exit code, when the command exited non-zero with no output.

That same reason is written to the **Audit log** too, so a failure is never a mystery.
