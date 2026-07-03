-- Per-app image/dependency vulnerability scan results (Trivy, no-socket scan).
-- One row per app (project); overwritten on each scan. report_json holds the
-- per-target detail (top findings); the count columns drive the summary + alert.
CREATE TABLE IF NOT EXISTS image_scans (
    project     TEXT PRIMARY KEY,
    scanned_at  INTEGER NOT NULL DEFAULT 0,
    critical    INTEGER NOT NULL DEFAULT 0,
    high        INTEGER NOT NULL DEFAULT 0,
    medium      INTEGER NOT NULL DEFAULT 0,
    low         INTEGER NOT NULL DEFAULT 0,
    report_json BLOB    NOT NULL DEFAULT '',
    error       TEXT    NOT NULL DEFAULT ''
);
