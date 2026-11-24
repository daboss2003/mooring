-- Security detection rules edited on the dashboard (internal/siem/detect): for a built-in rule of
-- the pack, the tunable fields the owner changed (enabled, severity, count, window, factor, learn,
-- speed_kmh, snoozed_until); for a custom rule ("custom.<slug>"), the whole rule. json is the
-- rule's JSON form; updated_at is unix seconds. Kept in this database, not in the security-log
-- directory, so the Mooring-state backup and `mooring restore` carry the rules.
CREATE TABLE security_rules (
	id         TEXT PRIMARY KEY,
	json       TEXT NOT NULL,
	updated_at INTEGER NOT NULL
);
