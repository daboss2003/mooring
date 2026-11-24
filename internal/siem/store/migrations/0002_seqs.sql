-- The highest seq used for each capture hour and box. Kept apart from segments so a seq is never
-- given to a second segment after the first one was removed: the name (and its archive key) stays
-- unique.
CREATE TABLE seqs (
    hour INTEGER NOT NULL, -- unix seconds of the UTC capture hour
    box  TEXT NOT NULL,
    seq  INTEGER NOT NULL,
    PRIMARY KEY (hour, box)
);
INSERT INTO seqs(hour, box, seq) SELECT hour, box, MAX(seq) FROM segments GROUP BY hour, box;
