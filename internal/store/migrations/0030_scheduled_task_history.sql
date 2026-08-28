-- Per-run history for scheduled tasks (cron): one row PER RUN, so an operator can see what ran, when,
-- how long it took, whether it succeeded, why it failed, and its captured output — plus which runs are
-- currently in flight (finished_at IS NULL). Separate from scheduled_task_runs (which keeps only the
-- single last-run-per-task the SCHEDULER needs to decide what is due). Retained on a short TTL (pruned
-- by the cron loop); the captured log is bounded at write time.
CREATE TABLE scheduled_task_history (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    slug        TEXT NOT NULL,               -- the app that owns the task
    task        TEXT NOT NULL,               -- the task name (spec.scheduled_tasks[].name)
    service     TEXT NOT NULL DEFAULT '',    -- the compose service the one-shot ran
    started_at  INTEGER NOT NULL,            -- unix seconds
    finished_at INTEGER,                     -- NULL = currently running
    ok          INTEGER,                     -- NULL until finished; 1 = success, 0 = failure
    exit_code   INTEGER NOT NULL DEFAULT 0,  -- container exit code (0 unless known)
    detail      TEXT NOT NULL DEFAULT '',    -- concise classified failure reason
    log         TEXT NOT NULL DEFAULT ''     -- captured output (bounded at write time)
);

-- History listing, newest first, per app and across all apps.
CREATE INDEX idx_sth_started ON scheduled_task_history(started_at DESC);
CREATE INDEX idx_sth_slug_started ON scheduled_task_history(slug, started_at DESC);
-- Fast lookup of in-flight runs.
CREATE INDEX idx_sth_running ON scheduled_task_history(finished_at) WHERE finished_at IS NULL;
