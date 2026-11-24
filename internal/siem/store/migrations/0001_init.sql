-- The security-log database (internal/siem/store), separate from mooring.db: the manifest of the
-- on-host segment files with their hash chain, and the index of classified events.

-- One row per segment file. The file is always <dir>/segments/<name>; path is informational.
-- Times are unix nanoseconds; 0 = unset.
CREATE TABLE segments (
    name        TEXT PRIMARY KEY,           -- <YYYYMMDDHH>-<box>-<seq>.ndjson.gz
    hour        INTEGER NOT NULL,           -- unix seconds of the UTC capture hour
    seq         INTEGER NOT NULL,
    box         TEXT NOT NULL,
    path        TEXT NOT NULL,
    events      INTEGER NOT NULL DEFAULT 0,
    bytes       INTEGER NOT NULL DEFAULT 0,
    sha256      TEXT NOT NULL DEFAULT '',   -- of the file's bytes, set when sealed
    prev_sha256 TEXT NOT NULL DEFAULT '',   -- sha256 of the segment sealed before it
    first_ts    INTEGER NOT NULL DEFAULT 0, -- oldest Event.TS in the file
    last_ts     INTEGER NOT NULL DEFAULT 0, -- newest Event.TS in the file
    cap_first   INTEGER NOT NULL DEFAULT 0, -- capture time of the first event
    cap_last    INTEGER NOT NULL DEFAULT 0, -- capture time of the last event
    chain       INTEGER NOT NULL DEFAULT 0, -- position in the seal order (1, 2, ...), 0 while open
    sealed_at   INTEGER NOT NULL DEFAULT 0,
    archived_at INTEGER NOT NULL DEFAULT 0,
    archive_key TEXT NOT NULL DEFAULT '',
    state       TEXT NOT NULL CHECK (state IN ('open', 'sealed')),
    UNIQUE (hour, box, seq)
);

-- The newest link of the hash chain. Kept apart from segments so that pruning every segment
-- doesn't restart the chain.
CREATE TABLE chain (
    id     INTEGER PRIMARY KEY CHECK (id = 1),
    n      INTEGER NOT NULL,
    sha256 TEXT NOT NULL
);

-- Classified events (every kind except log and http.request, and anything at warn or above).
-- src, app, svc, kind, out and actor are stored lowercased and ip in canonical form, for search;
-- json is the event as written to its segment.
CREATE TABLE events (
    id      INTEGER PRIMARY KEY,
    ts      INTEGER NOT NULL,           -- Event.TS, unix nanoseconds
    src     TEXT NOT NULL DEFAULT '',
    app     TEXT NOT NULL DEFAULT '',
    svc     TEXT NOT NULL DEFAULT '',
    kind    TEXT NOT NULL DEFAULT '',
    out     TEXT NOT NULL DEFAULT '',
    lvl     INTEGER NOT NULL DEFAULT 1, -- siem.LevelRank
    actor   TEXT NOT NULL DEFAULT '',
    ip      TEXT NOT NULL DEFAULT '',
    segment TEXT NOT NULL,
    json    TEXT NOT NULL
);
CREATE INDEX events_ts ON events(ts);
CREATE INDEX events_kind_ts ON events(kind, ts);
CREATE INDEX events_ip_ts ON events(ip, ts);
CREATE INDEX events_actor_ts ON events(actor, ts);
CREATE INDEX events_app_ts ON events(app, ts);
CREATE INDEX events_segment ON events(segment);
