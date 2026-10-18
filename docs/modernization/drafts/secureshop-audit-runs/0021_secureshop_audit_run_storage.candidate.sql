-- DRAFT ONLY. Not an active application migration; qualify publication,
-- owner deletion and runtime privileges before promotion.
CREATE TABLE secureshop_agents.bound_audit_runs (
  run_id uuid PRIMARY KEY,
  request_id uuid NOT NULL,
  launch_id uuid NOT NULL,
  scenario_id uuid NOT NULL,
  generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 9007199254740991),
  original_platform_owner_id integer NOT NULL CHECK (original_platform_owner_id > 0),
  original_platform_session_id integer NOT NULL CHECK (original_platform_session_id > 0),
  shop_user_id integer NOT NULL CHECK (shop_user_id > 0),
  owner_key text NOT NULL CHECK (octet_length(owner_key) BETWEEN 1 AND 1024),
  durable_generation bigint NOT NULL CHECK (durable_generation >= 0),
  effect_key text NOT NULL CHECK (octet_length(effect_key) BETWEEN 1 AND 1024),
  requested_count bigint NOT NULL CHECK (requested_count BETWEEN 1 AND 9007199254740991),
  row_count bigint NOT NULL CHECK (row_count BETWEEN 0 AND requested_count),
  provider text NOT NULL CHECK (provider = 'ollama'),
  model text NOT NULL CHECK (octet_length(model) BETWEEN 1 AND 256),
  summary text NOT NULL CHECK (octet_length(summary) BETWEEN 1 AND 65536),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id,request_id)
);
CREATE INDEX bound_audit_runs_owner_scope ON secureshop_agents.bound_audit_runs
  (original_platform_owner_id,launch_id,scenario_id,generation,original_platform_session_id);
CREATE TABLE secureshop_agents.bound_audit_run_artifacts (
  run_id uuid NOT NULL REFERENCES secureshop_agents.bound_audit_runs ON DELETE CASCADE,
  artifact text NOT NULL CHECK (artifact IN ('log','sources','messages','traces','effects')),
  bytes bigint NOT NULL CHECK (bytes BETWEEN 0 AND 134217728),
  sha256 bytea NOT NULL CHECK (octet_length(sha256) = 32),
  PRIMARY KEY (run_id,artifact)
);
CREATE TABLE secureshop_agents.bound_audit_run_chunks (
  run_id uuid NOT NULL,
  artifact text NOT NULL,
  ordinal integer NOT NULL CHECK (ordinal >= 0),
  content bytea NOT NULL CHECK (octet_length(content) BETWEEN 1 AND 65536),
  content_sha256 bytea GENERATED ALWAYS AS (sha256(content)) STORED,
  PRIMARY KEY (run_id,artifact,ordinal),
  FOREIGN KEY (run_id,artifact) REFERENCES secureshop_agents.bound_audit_run_artifacts ON DELETE CASCADE
);
CREATE TABLE secureshop_agents.bound_audit_run_publications (
  run_id uuid PRIMARY KEY REFERENCES secureshop_agents.bound_audit_runs ON DELETE CASCADE,
  published_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

-- Every write takes the same deletion fence as the installed audit journal.
-- A publication seals all artifact manifests and chunks. Runtime UPDATE and
-- DELETE are never granted; owner cleanup is receipt-backed below.
CREATE FUNCTION secureshop_agents.guard_bound_audit_run_insert()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog,secureshop_agents AS $$
DECLARE owner_id integer;
BEGIN
  IF TG_TABLE_NAME = 'bound_audit_runs' THEN
    owner_id := NEW.original_platform_owner_id;
  ELSE
    SELECT original_platform_owner_id INTO STRICT owner_id
      FROM secureshop_agents.bound_audit_runs WHERE run_id=NEW.run_id;
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:' || owner_id::text,0));
  IF EXISTS (SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts
      WHERE original_platform_owner_id=owner_id) THEN
    RAISE EXCEPTION 'Bound audit owner is deleted' USING ERRCODE='55000';
  END IF;
  IF TG_TABLE_NAME <> 'bound_audit_runs' THEN
    PERFORM 1 FROM secureshop_agents.bound_audit_runs WHERE run_id=NEW.run_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'Audit run is unavailable' USING ERRCODE='55000'; END IF;
  END IF;
  IF EXISTS (SELECT 1 FROM secureshop_agents.bound_audit_run_publications WHERE run_id=NEW.run_id) THEN
    RAISE EXCEPTION 'Bound audit run is sealed' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER bound_audit_runs_insert BEFORE INSERT ON secureshop_agents.bound_audit_runs
  FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_audit_run_insert();
CREATE TRIGGER bound_audit_artifacts_insert BEFORE INSERT ON secureshop_agents.bound_audit_run_artifacts
  FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_audit_run_insert();
CREATE TRIGGER bound_audit_chunks_insert BEFORE INSERT ON secureshop_agents.bound_audit_run_chunks
  FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_audit_run_insert();
CREATE TRIGGER bound_audit_publications_insert BEFORE INSERT ON secureshop_agents.bound_audit_run_publications
  FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_audit_run_insert();
REVOKE ALL ON FUNCTION secureshop_agents.guard_bound_audit_run_insert() FROM PUBLIC;

-- Candidate runtime grants below require native qualification before promotion.

CREATE FUNCTION secureshop_agents.validate_bound_audit_publication()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog,secureshop_agents AS $$
DECLARE item record; actual_count bigint; actual_bytes bigint; minimum_part integer; maximum_part integer;
BEGIN
  IF (SELECT count(*) FROM secureshop_agents.bound_audit_run_artifacts WHERE run_id=NEW.run_id) <> 5 THEN
    RAISE EXCEPTION 'Audit artifact set incomplete' USING ERRCODE='23514';
  END IF;
  IF (SELECT sum(bytes) FROM secureshop_agents.bound_audit_run_artifacts
      WHERE run_id=NEW.run_id AND artifact IN ('log','sources')) > 67108864
    OR (SELECT sum(bytes) FROM secureshop_agents.bound_audit_run_artifacts
      WHERE run_id=NEW.run_id AND artifact IN ('messages','traces','effects')) > 134217728 THEN
    RAISE EXCEPTION 'Audit artifact set exceeds budget' USING ERRCODE='23514';
  END IF;
  FOR item IN SELECT * FROM secureshop_agents.bound_audit_run_artifacts WHERE run_id=NEW.run_id LOOP
    SELECT count(*),coalesce(sum(octet_length(content)),0),min(ordinal),max(ordinal)
      INTO actual_count,actual_bytes,minimum_part,maximum_part
      FROM secureshop_agents.bound_audit_run_chunks WHERE run_id=NEW.run_id AND artifact=item.artifact;
    IF actual_bytes <> item.bytes OR actual_count <> (item.bytes+65535)/65536
      OR (actual_count>0 AND (minimum_part<>0 OR maximum_part<>actual_count-1))
      OR EXISTS (SELECT 1 FROM secureshop_agents.bound_audit_run_chunks
        WHERE run_id=NEW.run_id AND artifact=item.artifact
          AND ordinal<actual_count-1 AND octet_length(content)<>65536)
      OR (item.bytes=0 AND item.sha256<>sha256(''::bytea)) THEN
      RAISE EXCEPTION 'Audit artifact chunks incomplete' USING ERRCODE='23514';
    END IF;
  END LOOP;
  -- Whole-file digest is verified by the streaming publisher and reader;
  -- never concatenate 128MiB of chunks inside a shared database aggregate.
  RETURN NEW;
END $$;
CREATE TRIGGER bound_audit_publications_validate BEFORE INSERT ON secureshop_agents.bound_audit_run_publications
  FOR EACH ROW EXECUTE FUNCTION secureshop_agents.validate_bound_audit_publication();
REVOKE ALL ON FUNCTION secureshop_agents.validate_bound_audit_publication() FROM PUBLIC;

CREATE TABLE secureshop_agents.bound_audit_run_deletion_receipts (
  deletion_job_id uuid PRIMARY KEY,
  original_platform_owner_id integer NOT NULL UNIQUE CHECK (original_platform_owner_id>0),
  deleted_run_count bigint NOT NULL CHECK (deleted_run_count>=0),
  deleted_artifact_count bigint NOT NULL CHECK (deleted_artifact_count>=0),
  deleted_chunk_count bigint NOT NULL CHECK (deleted_chunk_count>=0),
  deleted_bytes bigint NOT NULL CHECK (deleted_bytes>=0),
  receipt_sha256 bytea NOT NULL CHECK (octet_length(receipt_sha256)=32),
  completed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION secureshop_agents.destroy_bound_audit_runs(requested_owner integer,requested_job uuid)
RETURNS SETOF secureshop_agents.bound_audit_run_deletion_receipts
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE runs bigint; artifacts bigint; chunks bigint; bytes bigint;
BEGIN
  IF requested_owner IS NULL OR requested_owner<1 OR requested_job IS NULL THEN
    RAISE EXCEPTION 'Invalid audit deletion authority' USING ERRCODE='22023';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:' || requested_owner::text,0));
  IF NOT EXISTS (SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts
      WHERE original_platform_owner_id=requested_owner AND deletion_job_id=requested_job) THEN
    RAISE EXCEPTION 'Audit event deletion receipt required' USING ERRCODE='55000';
  END IF;
  IF EXISTS (SELECT 1 FROM secureshop_agents.bound_audit_run_deletion_receipts
      WHERE original_platform_owner_id=requested_owner AND deletion_job_id=requested_job) THEN
    RETURN QUERY SELECT * FROM secureshop_agents.bound_audit_run_deletion_receipts
      WHERE original_platform_owner_id=requested_owner AND deletion_job_id=requested_job;
    RETURN;
  END IF;
  SELECT count(*) INTO runs FROM secureshop_agents.bound_audit_runs WHERE original_platform_owner_id=requested_owner;
  SELECT count(*) INTO artifacts FROM secureshop_agents.bound_audit_run_artifacts a
    JOIN secureshop_agents.bound_audit_runs r USING(run_id) WHERE r.original_platform_owner_id=requested_owner;
  SELECT count(*),coalesce(sum(octet_length(c.content)),0) INTO chunks,bytes
    FROM secureshop_agents.bound_audit_run_chunks c JOIN secureshop_agents.bound_audit_runs r USING(run_id)
    WHERE r.original_platform_owner_id=requested_owner;
  INSERT INTO secureshop_agents.bound_audit_run_deletion_receipts
    (deletion_job_id,original_platform_owner_id,deleted_run_count,deleted_artifact_count,deleted_chunk_count,deleted_bytes,receipt_sha256)
    VALUES (requested_job,requested_owner,runs,artifacts,chunks,bytes,
      sha256(convert_to(concat_ws(chr(31),'secureshop-audit-run-deletion-v1',requested_job::text,
        requested_owner::text,runs::text,artifacts::text,chunks::text,bytes::text),'UTF8')));
  DELETE FROM secureshop_agents.bound_audit_runs WHERE original_platform_owner_id=requested_owner;
  RETURN QUERY SELECT * FROM secureshop_agents.bound_audit_run_deletion_receipts
    WHERE original_platform_owner_id=requested_owner AND deletion_job_id=requested_job;
END $$;
REVOKE ALL ON FUNCTION secureshop_agents.destroy_bound_audit_runs(integer,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_agents.destroy_bound_audit_runs(integer,uuid) TO dvaia_secureshop_agents_runtime;
GRANT SELECT ON secureshop_agents.bound_audit_runs,secureshop_agents.bound_audit_run_artifacts,
  secureshop_agents.bound_audit_run_chunks,secureshop_agents.bound_audit_run_publications,
  secureshop_agents.bound_audit_run_deletion_receipts TO dvaia_secureshop_agents_runtime;
GRANT INSERT (run_id,request_id,launch_id,scenario_id,generation,original_platform_owner_id,
  original_platform_session_id,shop_user_id,owner_key,durable_generation,effect_key,requested_count,row_count,provider,model,summary)
  ON secureshop_agents.bound_audit_runs TO dvaia_secureshop_agents_runtime;
GRANT INSERT (run_id,artifact,bytes,sha256) ON secureshop_agents.bound_audit_run_artifacts TO dvaia_secureshop_agents_runtime;
GRANT INSERT (run_id,artifact,ordinal,content) ON secureshop_agents.bound_audit_run_chunks TO dvaia_secureshop_agents_runtime;
GRANT INSERT (run_id) ON secureshop_agents.bound_audit_run_publications TO dvaia_secureshop_agents_runtime;

-- Dedicated audit conversations cannot alias general or other teaching flows.
ALTER TABLE secureshop_agents.agent_sessions
  DROP CONSTRAINT agent_sessions_conversation_purpose_shape;
ALTER TABLE secureshop_agents.agent_sessions
  ADD CONSTRAINT agent_sessions_conversation_purpose_shape CHECK (
    conversation_purpose IN (
      'general', 'mcp_rogue_registration', 'mcp_rug_pull', 'persona_inbox',
      'controlled_ssrf', 'review_moderation', 'secureshop_refund_request',
      'secureshop_product_assist', 'secureshop_product_manual_ingest',
      'secureshop_audit_summary'
    ) AND (authority_mode = 'launch_bound' OR conversation_purpose = 'general')
  );
