-- Milestone B (#2 app-data backups): extend the backups catalog to cover per-app snapshots
-- (a logical DB dump or a data-volume tar), and record where each lives. Existing
-- mooring-state rows default to '' / 'local' (whole-Mooring, on-box). Additive.
ALTER TABLE backups ADD COLUMN project  TEXT NOT NULL DEFAULT '';   -- app slug ('' = mooring-state)
ALTER TABLE backups ADD COLUMN target   TEXT NOT NULL DEFAULT '';   -- service (db dump) or volume name
ALTER TABLE backups ADD COLUMN location TEXT NOT NULL DEFAULT 'local'; -- 'local', 's3', or 'local+s3'

-- backup_inventory records which app data VOLUMES have a verified backup, so the prune
-- denylist (backup.PruneVolumeSafe) can refuse to remove a sole-data volume that has never
-- been backed up ("back it up first"). One row per volume; updated to the most recent backup.
CREATE TABLE backup_inventory (
    volume     TEXT PRIMARY KEY,   -- docker volume name
    backup_id  TEXT NOT NULL,      -- the backups.id that most recently captured it
    updated_at INTEGER NOT NULL
);
