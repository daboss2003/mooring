-- Infra alert rows are looked up by dedupe key, newest first: EnqueueInfra compares a new row with the
-- key's newest row on every call, and the notifier combines every undelivered row of one key into one
-- message.
CREATE INDEX IF NOT EXISTS alert_outbox_key ON alert_outbox(dedupe_key, id);
