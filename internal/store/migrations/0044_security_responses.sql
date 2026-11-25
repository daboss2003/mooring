-- Automated responses (internal/siem/respond, docs/security-responses.md): every block or session
-- revoke a rule asked for, recommended, applied, refused, failed, dismissed or expired (state),
-- with the detection and incident it came from. target: block, the canonical prefix; revoke, the
-- Mooring username. reason: a fixed code (refused / failed). automatic: 1 when enforce mode may
-- apply it without the owner, 0 for recommend-only. by_user: the owner who applied or dismissed
-- it ('' for Mooring). Times are unix seconds; duration_s is a block's length as applied.
CREATE TABLE security_responses (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	action       TEXT NOT NULL,
	target       TEXT NOT NULL,
	state        TEXT NOT NULL,
	reason       TEXT NOT NULL DEFAULT '',
	automatic    INTEGER NOT NULL,
	rule_id      TEXT NOT NULL DEFAULT '',
	detection_id INTEGER NOT NULL DEFAULT 0,
	incident_id  INTEGER NOT NULL DEFAULT 0,
	summary      TEXT NOT NULL DEFAULT '',
	duration_s   INTEGER NOT NULL DEFAULT 0,
	by_user      TEXT NOT NULL DEFAULT '',
	created_at   INTEGER NOT NULL,
	updated_at   INTEGER NOT NULL
);
CREATE INDEX security_responses_created ON security_responses(created_at, id);
CREATE INDEX security_responses_open ON security_responses(action, target) WHERE state = 'recommended';
CREATE INDEX security_responses_incident ON security_responses(incident_id) WHERE incident_id != 0;
-- A dismissed recommendation isn't made again for a day: looked up by action, target and incident.
CREATE INDEX security_responses_dismissed ON security_responses(action, target, incident_id) WHERE state = 'dismissed';

-- The dashboard's pause of automated response (one row, or none): level 'recommend' or 'off'.
CREATE TABLE security_response_pause (
	id      INTEGER PRIMARY KEY CHECK (id = 1),
	level   TEXT NOT NULL,
	by_user TEXT NOT NULL DEFAULT '',
	at      INTEGER NOT NULL
);
