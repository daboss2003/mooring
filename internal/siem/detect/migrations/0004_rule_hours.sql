-- Each rule's counters for the current wall-clock hour (its new detections, its rollup detection
-- and the keys counted in it, its high alerts and the detections owed a summary alert), saved with
-- the learned state and read back at startup within the same hour, so the hourly limits hold across
-- a restart. A previous hour's row is kept only while its summary alert is owed (sent late by the
-- next start within the hour). hour is unix seconds (UTC).
CREATE TABLE rule_hours (
	rule_id   TEXT NOT NULL,
	hour      INTEGER NOT NULL,
	new_count INTEGER NOT NULL DEFAULT 0,
	rollup_id INTEGER NOT NULL DEFAULT 0, -- 0: no rollup detection stored this hour
	rolled    BLOB NOT NULL DEFAULT x'',  -- the rollup's keys: version, 16-byte HMAC key, 8 bytes a key
	sent      INTEGER NOT NULL DEFAULT 0,
	more      INTEGER NOT NULL DEFAULT 0,
	source    TEXT NOT NULL DEFAULT '',   -- '': the rule raised no high alert this hour
	name      TEXT NOT NULL DEFAULT '',
	target    TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (rule_id, hour)
);
-- The hour (unix seconds) a detection was counted in its rule's summary alert for, so a firing after
-- a restart doesn't count it again; 0: none.
ALTER TABLE detections ADD COLUMN cap_hour INTEGER NOT NULL DEFAULT 0;
