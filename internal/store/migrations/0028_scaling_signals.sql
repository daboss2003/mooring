-- Custom autoscaling signals (e.g. queue depth from the ops interface) persisted as a JSON array
-- alongside the fixed CPU/mem policy columns. Empty string = no custom signals (CPU/mem only),
-- so existing policies are unaffected.
ALTER TABLE scaling_policy ADD COLUMN signals_json TEXT NOT NULL DEFAULT '';
