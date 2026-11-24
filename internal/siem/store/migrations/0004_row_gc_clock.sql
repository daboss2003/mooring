-- Segments whose index rows are still being removed. Rows go in batches (a large segment never
-- holds the writer for long); after a crash the next Prune carries on.
CREATE TABLE row_gc (
    segment TEXT PRIMARY KEY
);

-- The clock as the store last saw it, and the latch a forward step of the clock sets: segments
-- captured up to latch_at are aged by latch_at + (now - jumped_to) while it is set.
CREATE TABLE clock (
    id        INTEGER PRIMARY KEY CHECK (id = 1),
    last_seen INTEGER NOT NULL,           -- unix ns
    latch_at  INTEGER NOT NULL DEFAULT 0, -- unix ns before the step; 0 = no latch
    jumped_to INTEGER NOT NULL DEFAULT 0  -- unix ns when the step was seen, moved by later steps
);
