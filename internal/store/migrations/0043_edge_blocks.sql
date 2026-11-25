-- The edge block list (internal/blocklist, docs/security-responses.md): addresses and ranges the
-- managed edge answers 403, placed by automated response (source auto) or an owner (manual), each
-- until until_at (unix seconds). One row per canonical prefix ("203.0.113.7/32",
-- "2001:db8:1:2::/64"): a block placed again reuses it. hits counts its automatic blocks
-- placed within 30 days of each other, auto_step is the length (seconds) the last of them was placed with and auto_at when
-- (a repeat's automatic block is longer; an extension changes neither, and an owner's unblock or a
-- false positive clears all three). removed_at/removed_by: lifted early; exempt_until: no automatic
-- block of it, or of an address inside it, before then (an owner unblocked it, or its incident was
-- a false positive). suspended_why: in force but not served, because a protected address covers it
-- (the refusal code), so a restart doesn't serve it. Kept in this database so the Mooring-state
-- backup and `mooring restore` carry it.
CREATE TABLE edge_blocks (
	prefix       TEXT PRIMARY KEY,
	source       TEXT NOT NULL,
	rule_id      TEXT NOT NULL DEFAULT '',
	detection_id INTEGER NOT NULL DEFAULT 0,
	incident_id  INTEGER NOT NULL DEFAULT 0,
	response_id  INTEGER NOT NULL DEFAULT 0,
	reason       TEXT NOT NULL DEFAULT '',
	by_user      TEXT NOT NULL DEFAULT '',
	created_at   INTEGER NOT NULL,
	until_at     INTEGER NOT NULL,
	removed_at   INTEGER NOT NULL DEFAULT 0,
	removed_by   TEXT NOT NULL DEFAULT '',
	exempt_until INTEGER NOT NULL DEFAULT 0,
	hits         INTEGER NOT NULL DEFAULT 0,
	auto_step    INTEGER NOT NULL DEFAULT 0,
	auto_at      INTEGER NOT NULL DEFAULT 0,
	suspended_why TEXT NOT NULL DEFAULT ''
);
CREATE INDEX edge_blocks_until ON edge_blocks(until_at);
CREATE INDEX edge_blocks_incident ON edge_blocks(incident_id) WHERE incident_id != 0;

-- Blocks refused (a protected address, a full list …): one row per (prefix, code), count and the
-- last time kept, so a refusal is never silent and a repeated one is one row.
CREATE TABLE edge_block_refusals (
	prefix   TEXT NOT NULL,
	code     TEXT NOT NULL,
	source   TEXT NOT NULL,
	rule_id  TEXT NOT NULL DEFAULT '',
	detail   TEXT NOT NULL DEFAULT '',
	count    INTEGER NOT NULL DEFAULT 1,
	first_at INTEGER NOT NULL,
	last_at  INTEGER NOT NULL,
	PRIMARY KEY (prefix, code)
);
CREATE INDEX edge_block_refusals_last ON edge_block_refusals(last_at);
