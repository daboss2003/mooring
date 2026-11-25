-- Phase 4: what the log-pattern miner learned. One row per template of a scope (an app service's
-- "app:<slug>/<service>", or "host"): its state (learned, new, expected, ignored), when it was last
-- seen (unix nanoseconds), its tokens and hourly counts in a versioned binary form (a row that
-- doesn't decode is discarded), and one redacted sample line with when it was taken (cleared after
-- the security logs' hot retention).
CREATE TABLE patterns (
	id         TEXT PRIMARY KEY,
	scope      TEXT NOT NULL,
	state      TEXT NOT NULL,
	last_ns    INTEGER NOT NULL,
	data       BLOB NOT NULL,
	sample     TEXT NOT NULL DEFAULT '',
	sample_ns  INTEGER NOT NULL DEFAULT 0,
	updated_ns INTEGER NOT NULL
);
CREATE INDEX patterns_scope ON patterns(scope);
CREATE INDEX patterns_last ON patterns(last_ns);

-- Per scope: when its first line was mined (its learning period runs from there), until when it
-- learns again (after a tokenizer change), the tokenizer version its templates were made with, and
-- when a line of it was last mined (to the day: a scope without templates is dropped 30 days on).
CREATE TABLE pattern_scopes (
	scope      TEXT PRIMARY KEY,
	first_ns   INTEGER NOT NULL,
	relearn_ns INTEGER NOT NULL DEFAULT 0,
	tokenizer  INTEGER NOT NULL,
	last_ns    INTEGER NOT NULL DEFAULT 0,
	updated_ns INTEGER NOT NULL
);

-- The states the owner set (expected, ignored), by template ID, apart from the templates: a
-- template forgotten for room and made again by the same line has its owner's state again. At most
-- 2000, the ones set longest ago dropped first.
CREATE TABLE pattern_marks (
	id     TEXT PRIMARY KEY,
	scope  TEXT NOT NULL,
	state  TEXT NOT NULL,
	set_ns INTEGER NOT NULL
);
CREATE INDEX pattern_marks_scope ON pattern_marks(scope);

-- The miner's other state by name: "hours", which of the last 192 hours were watched whole, and
-- the new-pattern reports sent in the current hour.
CREATE TABLE pattern_meta (
	name TEXT PRIMARY KEY,
	data BLOB NOT NULL
);

-- The Detections page finds a pattern's detections by their key (the pattern's ID).
CREATE INDEX detections_key ON detections(key, last_ns);
