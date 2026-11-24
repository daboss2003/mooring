-- A rule's rollup detection (the keys past its new detections in one hour, key '*') is marked, so a
-- detection whose real key is '*' is never taken for it. A rollup stored before has key '*' and
-- the rollup's summary.
ALTER TABLE detections ADD COLUMN rollup INTEGER NOT NULL DEFAULT 0;
UPDATE detections SET rollup = 1
	WHERE key = '*' AND summary LIKE 'and % more key% this hour (at most % new detections per rule an hour)';
-- The alerts raised within the last hour are read at startup (the per rule and key cooldown).
CREATE INDEX detections_alerted ON detections(alerted_ns) WHERE alerted_ns > 0;
