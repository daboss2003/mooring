-- Per-route replica selection (spec.edge.routes[].lb): least_conn | round_robin | ip_hash | cookie.
-- '' = least_conn, so existing routes are unaffected.
ALTER TABLE app_routes ADD COLUMN lb TEXT NOT NULL DEFAULT '';
