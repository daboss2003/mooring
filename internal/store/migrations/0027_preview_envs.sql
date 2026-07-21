-- #3 Preview environments. A base app OPTS IN with preview_enabled. Each ephemeral per-PR app
-- carries preview_of = its base slug — which SCOPES teardown: the PR webhook can only tear down
-- an app that is a preview of ITS OWN base, never a real app. updated_at (already on the table)
-- tracks last PR activity so a TTL reaper can reap abandoned previews.
ALTER TABLE app_git ADD COLUMN preview_enabled INTEGER NOT NULL DEFAULT 0;
ALTER TABLE app_git ADD COLUMN preview_of       TEXT    NOT NULL DEFAULT '';
CREATE INDEX app_git_preview_of ON app_git(preview_of);
