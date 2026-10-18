-- Immutable provenance for owner-bound ARIA archive snapshots.
CREATE TABLE aria.import_provenance (
 archive_sha256 text NOT NULL CHECK (archive_sha256 ~ '^[a-f0-9]{64}$'),
 source_table text NOT NULL,
 source_id text NOT NULL,
 source_row jsonb NOT NULL,
 imported_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY (archive_sha256, source_table, source_id)
);
CREATE TABLE aria.import_batches (
 singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
 archive_sha256 text NOT NULL CHECK (archive_sha256 ~ '^[a-f0-9]{64}$'),
 importer_version text NOT NULL,
 counts jsonb NOT NULL,
 identity_map_sha256 text,
 imported_at timestamptz NOT NULL DEFAULT now()
);
CREATE FUNCTION aria.protect_import_history() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Import history is immutable' USING ERRCODE='55000'; END;
$$;
CREATE TRIGGER immutable_import_provenance BEFORE UPDATE OR DELETE OR TRUNCATE ON aria.import_provenance
 FOR EACH STATEMENT EXECUTE FUNCTION aria.protect_import_history();
CREATE TRIGGER immutable_import_batches BEFORE UPDATE OR DELETE OR TRUNCATE ON aria.import_batches
 FOR EACH STATEMENT EXECUTE FUNCTION aria.protect_import_history();
REVOKE ALL ON aria.import_provenance, aria.import_batches FROM PUBLIC;
