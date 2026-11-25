-- Phase 3: incidents (docs/security-incidents.md). Detections of one account or address (their key)
-- within 24 hours are grouped in one incident. Times are unix nanoseconds (UTC).

-- A detection's incident (0: none), the kind of entity its key is ('account', 'address' or '' when
-- it is neither), the account scope of its events ('mooring', 'host', 'app:<slug>', 'edge'), and
-- whether a false-positive mute for its rule and key applied when it was last written.
ALTER TABLE detections ADD COLUMN incident_id INTEGER NOT NULL DEFAULT 0;
ALTER TABLE detections ADD COLUMN ent_kind TEXT NOT NULL DEFAULT '';
ALTER TABLE detections ADD COLUMN scope TEXT NOT NULL DEFAULT '';
ALTER TABLE detections ADD COLUMN muted INTEGER NOT NULL DEFAULT 0;
CREATE INDEX detections_incident ON detections(incident_id, last_ns) WHERE incident_id > 0;

-- One row per incident. sev_rank is the shown severity's rank (siem.SeverityRank); alert_rank the
-- rank its alert goes by (detections of rules not snoozed, and its chain; 5: critical, with a
-- re-alert owed for a new key that completed a chain); alerted_rank the highest rank an alert was
-- recorded for. entities is JSON ([]siem.Entity, at most 50; the first is the key
-- entity every detection in it has), rules comma-joined (at most 20). detections counts the
-- detections that joined it.
CREATE TABLE incidents (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	state        TEXT NOT NULL,
	severity     TEXT NOT NULL,
	sev_rank     INTEGER NOT NULL,
	alert_rank   INTEGER NOT NULL DEFAULT 0,
	alerted_rank INTEGER NOT NULL DEFAULT 0,
	alerted_ns   INTEGER NOT NULL DEFAULT 0,
	title        TEXT NOT NULL,
	chain        TEXT NOT NULL DEFAULT '',
	entities     TEXT NOT NULL DEFAULT '',
	rules        TEXT NOT NULL DEFAULT '',
	first_ns     INTEGER NOT NULL,
	last_ns      INTEGER NOT NULL,
	detections   INTEGER NOT NULL DEFAULT 0,
	assignee     TEXT NOT NULL DEFAULT '',
	created_ns   INTEGER NOT NULL,
	updated_ns   INTEGER NOT NULL
);
CREATE INDEX incidents_last_id ON incidents(last_ns, id);
CREATE INDEX incidents_state ON incidents(state, last_ns);

-- The entities of each incident with when its detections first and last concerned them: the
-- incidents of an entity, and the grouping read back at startup.
CREATE TABLE incident_entities (
	incident_id INTEGER NOT NULL,
	kind        TEXT NOT NULL,
	scope       TEXT NOT NULL,
	key         TEXT NOT NULL,
	first_ns    INTEGER NOT NULL,
	last_ns     INTEGER NOT NULL,
	PRIMARY KEY (incident_id, kind, scope, key)
);
CREATE INDEX incident_entities_entity ON incident_entities(kind, scope, key, last_ns);

-- Each incident's timeline, oldest first by id (at most 500 entries an incident).
CREATE TABLE incident_timeline (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	incident_id  INTEGER NOT NULL,
	ts_ns        INTEGER NOT NULL,
	kind         TEXT NOT NULL,
	detection_id INTEGER NOT NULL DEFAULT 0,
	rule_id      TEXT NOT NULL DEFAULT '',
	rule_name    TEXT NOT NULL DEFAULT '',
	severity     TEXT NOT NULL DEFAULT '',
	actor        TEXT NOT NULL DEFAULT '',
	text         TEXT NOT NULL DEFAULT ''
);
CREATE INDEX incident_timeline_incident ON incident_timeline(incident_id, kind, id);

-- Each entity's risk score as of updated_ns. rank is log2(score) + updated_ns / half-life: it
-- orders entities by their current (faded) score whatever the time is now.
CREATE TABLE entity_risk (
	kind       TEXT NOT NULL,
	scope      TEXT NOT NULL,
	key        TEXT NOT NULL,
	score      REAL NOT NULL,
	updated_ns INTEGER NOT NULL,
	rank       REAL NOT NULL,
	PRIMARY KEY (kind, scope, key)
);
CREATE INDEX entity_risk_rank ON entity_risk(rank);
