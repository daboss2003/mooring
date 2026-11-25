-- False-positive mutes of security detections (internal/siem/detect, docs/security-incidents.md):
-- a rule's detections for one entity (an account in a scope, or an address) are recorded marked
-- muted, but alert nothing and join no incident, until until_at (unix seconds). Kept in this
-- database, like security_rules, so the Mooring-state backup and `mooring restore` carry them.
CREATE TABLE security_mutes (
	rule_id     TEXT NOT NULL,
	kind        TEXT NOT NULL,
	scope       TEXT NOT NULL,
	key         TEXT NOT NULL,
	until_at    INTEGER NOT NULL,
	by_user     TEXT NOT NULL DEFAULT '',
	incident_id INTEGER NOT NULL DEFAULT 0,
	created_at  INTEGER NOT NULL,
	PRIMARY KEY (rule_id, kind, scope, key)
);
