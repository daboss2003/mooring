-- The client's User-Agent for an audit event that comes from an HTTP request ('' otherwise): at
-- most 256 bytes, control characters removed (audit.Logger.Log).
ALTER TABLE events ADD COLUMN user_agent TEXT NOT NULL DEFAULT '';
