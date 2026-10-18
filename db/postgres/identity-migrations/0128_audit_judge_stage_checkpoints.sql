-- Private, append-once Audit Judge stage evidence. The original grade packet
-- and terminal judgment remain immutable and are not replaced by this table.
CREATE TABLE workshop_platform.audit_judge_stage_checkpoints (
  user_id integer NOT NULL,
  evaluation_id uuid NOT NULL,
  stage text NOT NULL CHECK (stage IN ('source','effect')),
  version text NOT NULL CHECK (version = 'audit-stage-checkpoint-v1'),
  run_id uuid NOT NULL,
  evidence_digest text NOT NULL CHECK (evidence_digest ~ '^[a-f0-9]{64}$'),
  packet_sha256 text NOT NULL CHECK (packet_sha256 ~ '^[a-f0-9]{64}$'),
  judge_version text NOT NULL,
  comparison_version text NOT NULL CHECK (comparison_version = 'source-only-obligation-verified-v6'),
  policy_digest text NOT NULL CHECK (policy_digest ~ '^[a-f0-9]{64}$'),
  canonical_input_sha256 text NOT NULL CHECK (canonical_input_sha256 ~ '^[a-f0-9]{64}$'),
  actual_request_sha256 text NOT NULL CHECK (actual_request_sha256 ~ '^[a-f0-9]{64}$'),
  source_checkpoint_sha256 text CHECK (source_checkpoint_sha256 ~ '^[a-f0-9]{64}$'),
  provider text NOT NULL CHECK (length(provider) BETWEEN 1 AND 100),
  model text NOT NULL CHECK (length(model) BETWEEN 1 AND 200),
  raw_response text NOT NULL CHECK (octet_length(raw_response) BETWEEN 1 AND 16384),
  response_sha256 text NOT NULL CHECK (response_sha256 ~ '^[a-f0-9]{64}$'),
  checkpoint_sha256 text NOT NULL CHECK (checkpoint_sha256 ~ '^[a-f0-9]{64}$'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (user_id,evaluation_id,stage),
  FOREIGN KEY (user_id,evaluation_id)
    REFERENCES workshop_platform.grade_packets(user_id,evaluation_id) ON DELETE CASCADE,
  CHECK ((stage='source' AND source_checkpoint_sha256 IS NULL)
      OR (stage='effect' AND source_checkpoint_sha256 IS NOT NULL))
);
REVOKE ALL ON workshop_platform.audit_judge_stage_checkpoints FROM PUBLIC;
GRANT SELECT,INSERT,DELETE ON workshop_platform.audit_judge_stage_checkpoints TO dvaia_identity_runtime;

-- Packet-pruning and expiry already set packet=NULL. Remove private raw stage
-- text in that same statement; ordinary grade-packet deletion cascades.
CREATE FUNCTION workshop_platform.remove_audit_checkpoints_with_packet()
RETURNS trigger LANGUAGE plpgsql
SET search_path = pg_catalog, workshop_platform
AS $$
BEGIN
  IF OLD.packet IS NOT NULL AND NEW.packet IS NULL THEN
    DELETE FROM workshop_platform.audit_judge_stage_checkpoints
    WHERE user_id=NEW.user_id AND evaluation_id=NEW.evaluation_id;
  END IF;
  RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION workshop_platform.remove_audit_checkpoints_with_packet() FROM PUBLIC;
CREATE TRIGGER remove_audit_checkpoints_with_packet
AFTER UPDATE OF packet ON workshop_platform.grade_packets
FOR EACH ROW EXECUTE FUNCTION workshop_platform.remove_audit_checkpoints_with_packet();
