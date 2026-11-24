-- The Detections page lists detections most recently seen first (last_ns, then id, descending) and
-- pages by that pair. The new index also serves the prune and the size cap (oldest last_ns first),
-- so the single-column one goes.
CREATE INDEX detections_last_id ON detections(last_ns, id);
DROP INDEX detections_last;
