-- #5 Scheduled tasks (cron): last-run bookkeeping per (app, task) so the scheduler knows when
-- a task is next due and a restart doesn't re-fire every job. One row per task; upserted on run.
CREATE TABLE scheduled_task_runs (
    slug     TEXT    NOT NULL,
    task     TEXT    NOT NULL,
    last_run INTEGER NOT NULL DEFAULT 0,  -- unix seconds of the last attempt
    last_ok  INTEGER NOT NULL DEFAULT 1,  -- 1 = last run exited 0, 0 = failed
    PRIMARY KEY (slug, task)
);
