-- The host's own vulnerability scan (Trivy rootfs over read-only bind mounts of the OS package
-- database and the Go binaries Mooring runs; no Docker socket). A single row (id = 1), overwritten
-- on each scan. report_json holds the per-target detail ("OS packages" first, then one per binary);
-- the count columns drive the Server-tab summary; fixable_* count findings with a fixed version
-- (fixable High/Critical raise the host_vulnerabilities alert); eosl = 1 when Trivy reports the
-- detected OS release as past its end of support.
CREATE TABLE IF NOT EXISTS host_scans (
    id               INTEGER PRIMARY KEY CHECK (id = 1),
    scanned_at       INTEGER NOT NULL DEFAULT 0,
    os               TEXT    NOT NULL DEFAULT '',
    eosl             INTEGER NOT NULL DEFAULT 0,
    critical         INTEGER NOT NULL DEFAULT 0,
    high             INTEGER NOT NULL DEFAULT 0,
    medium           INTEGER NOT NULL DEFAULT 0,
    low              INTEGER NOT NULL DEFAULT 0,
    fixable_critical INTEGER NOT NULL DEFAULT 0,
    fixable_high     INTEGER NOT NULL DEFAULT 0,
    fixable_medium   INTEGER NOT NULL DEFAULT 0,
    fixable_low      INTEGER NOT NULL DEFAULT 0,
    report_json      BLOB    NOT NULL DEFAULT '',
    error            TEXT    NOT NULL DEFAULT ''
);
