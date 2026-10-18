-- Preserve nullable historical values without synthesizing completion or grading.
ALTER TABLE xss.profiles ALTER COLUMN name DROP NOT NULL, ALTER COLUMN bio DROP NOT NULL, ALTER COLUMN website DROP NOT NULL, ALTER COLUMN updated_at DROP NOT NULL;
ALTER TABLE xss.progress ALTER COLUMN completed DROP NOT NULL, ALTER COLUMN created_at DROP NOT NULL;
ALTER TABLE xss.emails ALTER COLUMN received_at DROP NOT NULL;
ALTER TABLE xss.email_profiles ALTER COLUMN created_at DROP NOT NULL, ALTER COLUMN updated_at DROP NOT NULL;
ALTER TABLE xss.email_templates ALTER COLUMN is_favorite DROP NOT NULL, ALTER COLUMN view_count DROP NOT NULL, ALTER COLUMN created_at DROP NOT NULL;
ALTER TABLE xss.template_previews ALTER COLUMN xss_detected DROP NOT NULL, ALTER COLUMN viewed_at DROP NOT NULL;
ALTER TABLE xss.xss_challenge_progress ALTER COLUMN completed DROP NOT NULL, ALTER COLUMN hints_used DROP NOT NULL, ALTER COLUMN attempts DROP NOT NULL, ALTER COLUMN created_at DROP NOT NULL;
ALTER TABLE xss.xss_email_judge_receipts ALTER COLUMN created_at DROP NOT NULL;
ALTER TABLE xss.legacy_challenge_config ALTER COLUMN updated_at DROP NOT NULL;
CREATE TABLE xss.import_provenance(archive_sha256 text NOT NULL CHECK(archive_sha256 ~ '^[a-f0-9]{64}$'),source_file text NOT NULL,source_table text NOT NULL,source_id text NOT NULL,source_row jsonb NOT NULL,PRIMARY KEY(archive_sha256,source_file,source_table,source_id));
CREATE TABLE xss.import_batches(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),archive_sha256 text NOT NULL CHECK(archive_sha256 ~ '^[a-f0-9]{64}$'),counts jsonb NOT NULL,review_metadata jsonb NOT NULL,imported_at timestamptz NOT NULL DEFAULT now());
CREATE FUNCTION xss.protect_import_history() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'XSS import history is immutable' USING ERRCODE='55000'; END; $$;
CREATE TRIGGER immutable_import_provenance BEFORE UPDATE OR DELETE OR TRUNCATE ON xss.import_provenance FOR EACH STATEMENT EXECUTE FUNCTION xss.protect_import_history();
CREATE TRIGGER immutable_import_batches BEFORE UPDATE OR DELETE OR TRUNCATE ON xss.import_batches FOR EACH STATEMENT EXECUTE FUNCTION xss.protect_import_history();
REVOKE ALL ON xss.import_provenance,xss.import_batches FROM PUBLIC;
