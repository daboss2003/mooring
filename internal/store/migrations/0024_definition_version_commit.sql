-- Milestone A (#4 rollback): record the git commit each canonical definition version was
-- deployed from, so a version → commit map exists for a one-click "roll back to this
-- version". Empty ('') for dashboard-originated versions (config-file / scaling / ops edits
-- that carry no git commit) — those are not git-rollback targets. Additive; existing rows
-- default to '' and are shown as history but not offered for redeploy.
ALTER TABLE definition_versions ADD COLUMN commit_sha TEXT NOT NULL DEFAULT '';
