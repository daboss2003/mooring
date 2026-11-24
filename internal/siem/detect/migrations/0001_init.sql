-- Detections: one row per firing of a rule for one key; later firings within the coalescing window
-- update the row. Times are unix nanoseconds (UTC). mitre is comma-joined; geo and evidence are JSON.
CREATE TABLE detections (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	source     TEXT NOT NULL,
	rule_id    TEXT NOT NULL,
	rule_name  TEXT NOT NULL,
	severity   TEXT NOT NULL,
	sev_rank   INTEGER NOT NULL,
	mitre      TEXT NOT NULL DEFAULT '',
	key        TEXT NOT NULL DEFAULT '',
	app        TEXT NOT NULL DEFAULT '',
	service    TEXT NOT NULL DEFAULT '',
	first_ns   INTEGER NOT NULL,
	last_ns    INTEGER NOT NULL,
	count      INTEGER NOT NULL,
	summary    TEXT NOT NULL,
	geo        TEXT NOT NULL DEFAULT '',
	evidence   TEXT NOT NULL DEFAULT '',
	snoozed    INTEGER NOT NULL DEFAULT 0,
	alerted_ns INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX detections_rule_key ON detections(rule_id, key, id);
CREATE INDEX detections_last ON detections(last_ns);
CREATE INDEX detections_app ON detections(app, id);
CREATE INDEX detections_sev ON detections(sev_rank, id);

-- Learned rule state that survives a restart (new_value seen sets, anomaly hourly counts), one blob
-- per rule and part. sig identifies the rule's matching definition; a row whose sig differs from
-- the rule's is discarded.
CREATE TABLE rule_state (
	rule_id    TEXT NOT NULL,
	part       TEXT NOT NULL,
	sig        TEXT NOT NULL,
	data       BLOB NOT NULL,
	updated_ns INTEGER NOT NULL,
	PRIMARY KEY (rule_id, part)
);
