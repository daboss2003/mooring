-- Operator-held services: a durable per-(app,service) intent to keep a service DOWN / paused —
-- a manual stop, or an explicit "pause auto-restart". While a service is held, the self-heal
-- supervisor suspends remediation and the auto-scaler skips it, so a service the operator
-- deliberately stopped is never auto-restarted. Distinct from expected_down (a transient,
-- auto-expiring write-plane lease that is wiped fail-closed on boot): a hold is DURABLE and
-- survives reboots until the operator explicitly starts/resumes the service.
CREATE TABLE service_held (
    app     TEXT NOT NULL,
    service TEXT NOT NULL,
    held_by TEXT NOT NULL DEFAULT '',
    held_at INTEGER NOT NULL,
    PRIMARY KEY (app, service)
);
