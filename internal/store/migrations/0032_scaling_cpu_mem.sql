-- Per-service toggle for the built-in CPU/memory autoscaling triggers. Default 1 (on) — existing
-- policies keep scaling on CPU/mem as before. Set to 0 to STOP scaling on CPU/memory: the service
-- then scales only on custom signals (queue depth / edge latency) if any are declared, or holds at a
-- fixed count if none. This exists because a CPU-bound service's own start-up CPU can trigger more
-- scale-ups (a feedback loop that pins the whole fleet); turning CPU/mem off breaks that loop.
ALTER TABLE scaling_policy ADD COLUMN cpu_mem_enabled INTEGER NOT NULL DEFAULT 1;
