-- Migration bookkeeping only. Platform/challenge schemas require explicit dialect conversion.
-- No existing SQLite database is read, overwritten, or treated as a PostgreSQL fallback.
COMMENT ON SCHEMA dvaia_migrations IS 'DVAIA versioned PostgreSQL migration history';
