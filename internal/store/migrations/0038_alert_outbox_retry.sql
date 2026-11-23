-- Delivery retries of the alert outbox. next_try_at: unix sec before which the notifier doesn't try an
-- unsent row again (0 = at once); a failed critical message backs off (15 s doubling, at most 1 h apart).
-- given_up: the row was closed (sent_at > 0) because its deliveries kept failing, not because a message
-- carrying it was delivered or it was dropped on purpose; given-up rows are reported again with the
-- alert's next message.
ALTER TABLE alert_outbox ADD COLUMN next_try_at INTEGER NOT NULL DEFAULT 0;
ALTER TABLE alert_outbox ADD COLUMN given_up INTEGER NOT NULL DEFAULT 0;
-- Earlier releases gave a row up after 3 failed attempts and closed it like a delivered one.
UPDATE alert_outbox SET given_up = 1 WHERE sent_at > 0 AND attempts >= 3;
