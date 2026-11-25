-- Phase 3: what the baseline rules have learned, one row per kind (signin: Mooring's and SSH
-- accounts, signin_app: apps' accounts, admin, traffic, ip) and entity (an account, a server user,
-- a host name, an address). data is the entity's state in a versioned binary form; a row that
-- doesn't decode is discarded. updated_ns is when it was last saved (unix nanoseconds): past a
-- kind's cap, the rows saved least recently are dropped.
CREATE TABLE baselines (
	kind       TEXT NOT NULL,
	key        TEXT NOT NULL,
	data       BLOB NOT NULL,
	updated_ns INTEGER NOT NULL,
	PRIMARY KEY (kind, key)
);
CREATE INDEX baselines_updated ON baselines(kind, updated_ns);

-- Per kind, the signature of the rule definition (query, group-by, state version) its rows were
-- learned under: a kind whose definition changed starts again. zone identifies the server time
-- zone the hours of a kind that learns per hour were learned in: when it changes, those hours are
-- reset (and the other learned values kept).
CREATE TABLE baseline_kinds (
	kind TEXT PRIMARY KEY,
	sig  TEXT NOT NULL,
	zone TEXT NOT NULL DEFAULT ''
);
