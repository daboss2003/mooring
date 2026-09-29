-- Self-heal of services with several copies (v0.21.0). The supervisor judges a service by all of its
-- copies and restarts one sick copy per action; these record how many copies the service had at the
-- last action and which copies were restarted in the current attempt window, plus the bounded wait on
-- a failing dependency.
ALTER TABLE supervisor_state ADD COLUMN replicas_at_action INTEGER NOT NULL DEFAULT 0;
ALTER TABLE supervisor_state ADD COLUMN restarted TEXT NOT NULL DEFAULT '';
ALTER TABLE supervisor_state ADD COLUMN dep_wait_since INTEGER NOT NULL DEFAULT 0;
ALTER TABLE supervisor_state ADD COLUMN dep_paged INTEGER NOT NULL DEFAULT 0;
