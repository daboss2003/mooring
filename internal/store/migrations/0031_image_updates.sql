-- Per-service image-update state for PULL-IMAGE app services (a service running `image: postgres:16`
-- rather than a git build). The checker periodically compares the LOCALLY-PULLED image digest with the
-- registry's current digest for the same tag; when they differ, a newer image exists for that tag and a
-- redeploy would pull it. One row per (project, service). No history is kept — this is a current-state
-- table (like image_scans), refreshed in place on each check.
CREATE TABLE image_service_updates (
    project          TEXT NOT NULL,             -- the app (compose project) that owns the service
    service          TEXT NOT NULL,             -- the compose service name
    image_ref        TEXT NOT NULL DEFAULT '',  -- the pinned image ref from mooring.yaml (e.g. postgres:16)
    deployed_digest  TEXT NOT NULL DEFAULT '',  -- sha256:… currently pulled locally ('' = not resolvable)
    latest_digest    TEXT NOT NULL DEFAULT '',  -- sha256:… the registry serves for that tag now ('' = unknown)
    update_available INTEGER NOT NULL DEFAULT 0, -- 1 when deployed and latest are both known and differ
    checked_at       INTEGER,                    -- unix seconds of the last check
    error            TEXT NOT NULL DEFAULT '',   -- non-empty when the registry check failed (no alert then)
    PRIMARY KEY (project, service)
);
