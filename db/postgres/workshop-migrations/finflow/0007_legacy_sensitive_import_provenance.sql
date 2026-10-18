-- Legacy Sensitive and FinFlow have independent archives and must be importable
-- into the same database. Older releases incorrectly shared FinFlow's singleton
-- receipt and provenance tables; preserve those rows while moving their
-- authority into the legacy_sensitive namespace.
CREATE FUNCTION legacy_sensitive.protect_import_provenance() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'Import provenance is immutable' USING ERRCODE='55000'; END;
$$;

CREATE TABLE legacy_sensitive.import_provenance (
 archive_sha256 text NOT NULL CHECK(archive_sha256 ~ '^[a-f0-9]{64}$'),
 source_table text NOT NULL, source_id text NOT NULL, source_row jsonb NOT NULL,
 imported_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(archive_sha256,source_table,source_id)
);
CREATE TRIGGER immutable_import_provenance
 BEFORE UPDATE OR DELETE OR TRUNCATE ON legacy_sensitive.import_provenance
 FOR EACH STATEMENT EXECUTE FUNCTION legacy_sensitive.protect_import_provenance();

CREATE TABLE legacy_sensitive.import_batches (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 archive_sha256 text NOT NULL CHECK(archive_sha256 ~ '^[a-f0-9]{64}$'),
 importer_version text NOT NULL CHECK(importer_version IN ('legacy-sensitive-v1','legacy-sensitive-v2')),
 timestamp_policy text NOT NULL CHECK(timestamp_policy IN ('UTC','reject')),
 counts jsonb NOT NULL CHECK(jsonb_typeof(counts)='object'),
 retained_decisions jsonb NOT NULL CHECK(jsonb_typeof(retained_decisions)='array'),
 identity_map_sha256 text CHECK(identity_map_sha256 IS NULL OR identity_map_sha256 ~ '^[a-f0-9]{64}$'),
 imported_at timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER immutable_import_batches
 BEFORE UPDATE OR DELETE OR TRUNCATE ON legacy_sensitive.import_batches
 FOR EACH STATEMENT EXECUTE FUNCTION legacy_sensitive.protect_import_provenance();

INSERT INTO legacy_sensitive.import_provenance
 (archive_sha256,source_table,source_id,source_row,imported_at)
SELECT archive_sha256,source_table,source_id,source_row,imported_at
FROM finflow.import_provenance WHERE starts_with(source_table,'sensitive_info.db:');

INSERT INTO legacy_sensitive.import_batches
 (singleton,archive_sha256,importer_version,timestamp_policy,counts,retained_decisions,identity_map_sha256,imported_at)
SELECT singleton,archive_sha256,importer_version,timestamp_policy,counts,retained_decisions,identity_map_sha256,imported_at
FROM finflow.import_batches WHERE importer_version='legacy-sensitive-v1';

DROP TRIGGER immutable_import_provenance ON finflow.import_provenance;
DELETE FROM finflow.import_provenance WHERE starts_with(source_table,'sensitive_info.db:');
CREATE TRIGGER immutable_import_provenance
 BEFORE UPDATE OR DELETE OR TRUNCATE ON finflow.import_provenance
 FOR EACH STATEMENT EXECUTE FUNCTION finflow.protect_import_provenance();

DROP TRIGGER immutable_import_batches ON finflow.import_batches;
DELETE FROM finflow.import_batches WHERE importer_version='legacy-sensitive-v1';
CREATE TRIGGER immutable_import_batches
 BEFORE UPDATE OR DELETE OR TRUNCATE ON finflow.import_batches
 FOR EACH STATEMENT EXECUTE FUNCTION finflow.protect_import_provenance();

REVOKE ALL ON legacy_sensitive.import_provenance,legacy_sensitive.import_batches FROM PUBLIC,dvaia_finflow_runtime;
