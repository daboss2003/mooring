-- Every box name the store has written segments under, kept after their segments are removed, so
-- the archive can prune objects stored under a previous host name. Every Open records the boxes of
-- the segments, seqs and segment files it finds (which fills it on the first Open after this
-- migration) and Options.Box.
CREATE TABLE boxes (
    name       TEXT PRIMARY KEY,
    first_seen INTEGER NOT NULL -- unix seconds: the earliest capture hour seen, or when the store first opened under it
);
