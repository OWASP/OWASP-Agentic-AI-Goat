-- Preserve nullable historical SQLite state; new application writes still use defaults.
ALTER TABLE mcp.progress ALTER COLUMN completed DROP NOT NULL,
 ALTER COLUMN completed_at DROP NOT NULL, ALTER COLUMN created_at DROP NOT NULL;
ALTER TABLE mcp.tool_log ALTER COLUMN success DROP NOT NULL, ALTER COLUMN created_at DROP NOT NULL;
CREATE TABLE mcp.import_provenance (
 archive_sha256 text NOT NULL CHECK(archive_sha256 ~ '^[a-f0-9]{64}$'),
 source_table text NOT NULL, source_id text NOT NULL, source_row jsonb NOT NULL,
 imported_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(archive_sha256,source_table,source_id)
);
CREATE FUNCTION mcp.protect_import_provenance() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Import provenance is immutable' USING ERRCODE='55000'; END;
$$;
CREATE TRIGGER immutable_import_provenance BEFORE UPDATE OR DELETE OR TRUNCATE ON mcp.import_provenance
 FOR EACH STATEMENT EXECUTE FUNCTION mcp.protect_import_provenance();
REVOKE ALL ON mcp.import_provenance FROM PUBLIC;

CREATE TABLE mcp.import_batches (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 archive_sha256 text NOT NULL CHECK(archive_sha256 ~ '^[a-f0-9]{64}$'),
 imported_at timestamptz NOT NULL DEFAULT now(),
 counts jsonb NOT NULL,
 retained_tables jsonb NOT NULL
);
CREATE TRIGGER immutable_import_batches BEFORE UPDATE OR DELETE OR TRUNCATE ON mcp.import_batches
 FOR EACH STATEMENT EXECUTE FUNCTION mcp.protect_import_provenance();
REVOKE ALL ON mcp.import_batches FROM PUBLIC;
