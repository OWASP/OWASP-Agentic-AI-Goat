-- Owner/run/generation-bound source artifacts for the IPI Email Agent.
-- SMTP submission receipts remain separate: an artifact records only content
-- actually returned by the inbox provider or explicitly entered by the learner.
CREATE TABLE identity.ipi_email_artifacts (
  artifact_id uuid PRIMARY KEY,
  owner_id integer NOT NULL REFERENCES identity.users(id),
  owner_key text NOT NULL CHECK(length(owner_key) BETWEEN 8 AND 160),
  generation bigint NOT NULL CHECK(generation >= 0),
  run_id uuid NOT NULL REFERENCES graph_runtime.runs(run_id),
  ingestion_kind text NOT NULL CHECK(ingestion_kind IN ('inbox_provider','manual_entry')),
  provider text NOT NULL CHECK(provider IN ('guerrillamail','mailpit','manual_entry')),
  provider_message_id text,
  sent_receipt_id integer REFERENCES identity.sent_emails_log(id),
  sender text NOT NULL CHECK(octet_length(sender) <= 512),
  recipient text NOT NULL CHECK(octet_length(recipient) BETWEEN 1 AND 512),
  subject text NOT NULL CHECK(octet_length(subject) <= 2048),
  body_text text NOT NULL CHECK(octet_length(body_text) BETWEEN 1 AND 32768),
  body_bytes integer NOT NULL CHECK(body_bytes BETWEEN 1 AND 32768),
  body_sha256 text NOT NULL CHECK(body_sha256 ~ '^[a-f0-9]{64}$'),
  model_body_text text NOT NULL CHECK(octet_length(model_body_text) BETWEEN 1 AND 20000),
  model_body_bytes integer NOT NULL CHECK(model_body_bytes BETWEEN 1 AND 20000),
  model_body_sha256 text NOT NULL CHECK(model_body_sha256 ~ '^[a-f0-9]{64}$'),
  model_body_truncated boolean NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  retired_at timestamptz,
  CHECK(owner_key::jsonb = jsonb_build_array('IndirectEmail',owner_id::text)),
  CHECK(body_bytes = octet_length(body_text)),
  CHECK(model_body_bytes = octet_length(model_body_text)),
  CHECK((ingestion_kind='manual_entry' AND provider='manual_entry'
      AND provider_message_id IS NULL AND sent_receipt_id IS NULL AND sender='')
    OR (ingestion_kind='inbox_provider' AND provider IN ('guerrillamail','mailpit')
      AND provider_message_id IS NOT NULL AND length(provider_message_id) BETWEEN 1 AND 256)),
  UNIQUE(owner_id,generation,artifact_id)
);

CREATE INDEX ipi_email_artifacts_owner_active_idx
  ON identity.ipi_email_artifacts(owner_id,generation,created_at DESC)
  WHERE retired_at IS NULL;
CREATE INDEX ipi_email_artifacts_owner_history_idx
  ON identity.ipi_email_artifacts(owner_id,created_at DESC);

CREATE FUNCTION identity.guard_ipi_email_artifact_insert() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM graph_runtime.runs r
    WHERE r.run_id=NEW.run_id AND r.owner_key=NEW.owner_key
      AND r.generation=NEW.generation AND r.status='running'
  ) THEN
    RAISE EXCEPTION 'IPI email artifact run is not current' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER ipi_email_artifact_current_run
  BEFORE INSERT ON identity.ipi_email_artifacts
  FOR EACH ROW EXECUTE FUNCTION identity.guard_ipi_email_artifact_insert();

CREATE FUNCTION identity.guard_ipi_email_artifact_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.retired_at IS NOT NULL OR NEW.retired_at IS NULL
     OR (to_jsonb(NEW)-'retired_at') IS DISTINCT FROM (to_jsonb(OLD)-'retired_at') THEN
    RAISE EXCEPTION 'IPI email artifact is immutable' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER ipi_email_artifact_immutable
  BEFORE UPDATE ON identity.ipi_email_artifacts
  FOR EACH ROW EXECUTE FUNCTION identity.guard_ipi_email_artifact_update();

REVOKE ALL ON identity.ipi_email_artifacts FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.guard_ipi_email_artifact_insert() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.guard_ipi_email_artifact_update() FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE,DELETE ON identity.ipi_email_artifacts TO dvaia_identity_runtime;
