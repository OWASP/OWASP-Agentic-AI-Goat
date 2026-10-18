-- Metadata-only receipt exists even when the archive has no mapped state rows.
CREATE TABLE finflow.import_batches (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 archive_sha256 text NOT NULL CHECK(archive_sha256 ~ '^[a-f0-9]{64}$'),
 importer_version text NOT NULL CHECK(importer_version='agent-workshop-v1'),
 timestamp_policy text NOT NULL CHECK(timestamp_policy IN ('UTC','reject')),
 counts jsonb NOT NULL CHECK(jsonb_typeof(counts)='object'),
 retained_decisions jsonb NOT NULL CHECK(jsonb_typeof(retained_decisions)='array'),
 imported_at timestamptz NOT NULL DEFAULT now()
);
CREATE TRIGGER immutable_import_batches BEFORE UPDATE OR DELETE OR TRUNCATE ON finflow.import_batches
 FOR EACH STATEMENT EXECUTE FUNCTION finflow.protect_import_provenance();
REVOKE ALL ON finflow.import_batches FROM PUBLIC;
