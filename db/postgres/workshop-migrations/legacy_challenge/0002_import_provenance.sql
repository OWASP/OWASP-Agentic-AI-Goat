CREATE TABLE legacy_challenge.import_provenance (
 archive_sha256 text NOT NULL CHECK(archive_sha256 ~ '^[a-f0-9]{64}$'),
 source_table text NOT NULL, source_id text NOT NULL, source_row jsonb NOT NULL CHECK(jsonb_typeof(source_row)='object'),
 imported_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(archive_sha256,source_table,source_id)
);
CREATE TABLE legacy_challenge.import_batches (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 archive_sha256 text NOT NULL CHECK(archive_sha256 ~ '^[a-f0-9]{64}$'),
 report jsonb NOT NULL CHECK(jsonb_typeof(report)='object'),
 imported_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION legacy_challenge.protect_import_history() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Import history is immutable' USING ERRCODE='55000'; END $$;
CREATE TRIGGER immutable_import_provenance BEFORE UPDATE OR DELETE OR TRUNCATE ON legacy_challenge.import_provenance FOR EACH STATEMENT EXECUTE FUNCTION legacy_challenge.protect_import_history();
CREATE TRIGGER immutable_import_batches BEFORE UPDATE OR DELETE OR TRUNCATE ON legacy_challenge.import_batches FOR EACH STATEMENT EXECUTE FUNCTION legacy_challenge.protect_import_history();
REVOKE ALL ON legacy_challenge.import_provenance,legacy_challenge.import_batches FROM PUBLIC,dvaia_legacy_challenge_runtime;
