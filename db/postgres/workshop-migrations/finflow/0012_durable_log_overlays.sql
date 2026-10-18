-- PRIVATE QUALIFICATION STAGE. Canonical FinFlow migration 0012.
-- Do not apply outside an owned disposable qualification database.
--
-- Controlled log fixtures remain immutable files shipped with the workshop.
-- This schema stores only copy-on-write, owner-and-generation scoped overlays.

CREATE TABLE finflow.log_overlays (
 owner_id bigint NOT NULL CHECK(owner_id > 0),
 generation bigint NOT NULL CHECK(generation >= 0),
 log_type text NOT NULL CHECK(log_type IN ('access','error','audit','llm_requests')),
 action text NOT NULL CHECK(action IN ('delete','modify')),
 content text NOT NULL CHECK(octet_length(content) <= 1048576),
 content_sha256 text NOT NULL CHECK(content_sha256 ~ '^[a-f0-9]{64}$'),
 byte_length integer NOT NULL CHECK(byte_length >= 0 AND byte_length <= 1048576),
 revision bigint NOT NULL CHECK(revision > 0),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 retired_at timestamptz,
 content_scrubbed_at timestamptz,
 PRIMARY KEY(owner_id,generation,log_type),
 CHECK((content_scrubbed_at IS NULL AND byte_length=octet_length(content)
      AND content_sha256=encode(sha256(convert_to(content,'UTF8')),'hex'))
    OR (content_scrubbed_at IS NOT NULL AND retired_at IS NOT NULL AND content='')),
 CHECK(action<>'delete' OR content='')
);

CREATE TABLE finflow.log_overlay_mutations (
 operation_id uuid PRIMARY KEY,
 owner_id bigint NOT NULL,
 generation bigint NOT NULL,
 run_id uuid NOT NULL,
 log_type text NOT NULL CHECK(log_type IN ('access','error','audit','llm_requests')),
 action text NOT NULL CHECK(action IN ('delete','modify')),
 content_sha256 text NOT NULL CHECK(content_sha256 ~ '^[a-f0-9]{64}$'),
 byte_length integer NOT NULL CHECK(byte_length >= 0 AND byte_length <= 1048576),
 revision bigint NOT NULL CHECK(revision > 0),
 completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(owner_id,generation,log_type)
  REFERENCES finflow.log_overlays(owner_id,generation,log_type) ON DELETE RESTRICT
);

CREATE FUNCTION finflow.guard_finflow_log_overlay()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE authorized_scrub boolean:=false;
BEGIN
 IF TG_OP='DELETE' THEN
  RAISE EXCEPTION 'FinFlow log overlay lineage is immutable' USING ERRCODE='23514';
 END IF;
 authorized_scrub:=OLD.retired_at IS NOT NULL AND NEW.retired_at IS NOT NULL
   AND OLD.content_scrubbed_at IS NULL AND NEW.content_scrubbed_at IS NOT NULL
   AND NEW.content='' AND EXISTS(SELECT 1 FROM finflow.owner_resource_deletions d
     WHERE d.owner_id=OLD.owner_id AND d.status='pending');
 IF NEW.owner_id IS DISTINCT FROM OLD.owner_id OR NEW.generation IS DISTINCT FROM OLD.generation
   OR NEW.log_type IS DISTINCT FROM OLD.log_type OR NEW.created_at IS DISTINCT FROM OLD.created_at
   OR (OLD.retired_at IS NOT NULL AND NOT authorized_scrub)
   OR (authorized_scrub AND (NEW.action IS DISTINCT FROM OLD.action
      OR NEW.content_sha256 IS DISTINCT FROM OLD.content_sha256
      OR NEW.byte_length IS DISTINCT FROM OLD.byte_length OR NEW.revision IS DISTINCT FROM OLD.revision
      OR NEW.updated_at IS DISTINCT FROM OLD.updated_at OR NEW.retired_at IS DISTINCT FROM OLD.retired_at))
   OR (NOT authorized_scrub AND OLD.retired_at IS NULL AND NEW.retired_at IS NULL
      AND (NEW.revision<>OLD.revision+1 OR NEW.updated_at<=OLD.updated_at
        OR NEW.content_scrubbed_at IS NOT NULL))
   OR (NOT authorized_scrub AND OLD.retired_at IS NULL AND NEW.retired_at IS NOT NULL
      AND (NEW.action IS DISTINCT FROM OLD.action OR NEW.content IS DISTINCT FROM OLD.content
        OR NEW.content_sha256 IS DISTINCT FROM OLD.content_sha256
        OR NEW.byte_length IS DISTINCT FROM OLD.byte_length OR NEW.revision IS DISTINCT FROM OLD.revision
        OR NEW.updated_at IS DISTINCT FROM OLD.updated_at OR NEW.content_scrubbed_at IS NOT NULL)) THEN
  RAISE EXCEPTION 'FinFlow log overlay lineage is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER finflow_log_overlay_guard BEFORE UPDATE OR DELETE ON finflow.log_overlays
 FOR EACH ROW EXECUTE FUNCTION finflow.guard_finflow_log_overlay();

CREATE TRIGGER finflow_log_overlay_mutation_guard BEFORE UPDATE OR DELETE ON finflow.log_overlay_mutations
 FOR EACH ROW EXECUTE FUNCTION finflow.guard_finflow_resource_immutable();

CREATE FUNCTION finflow.read_log_overlay(p_owner_id bigint,p_generation bigint,p_log_type text)
RETURNS TABLE(owner_id bigint,generation bigint,log_type text,action text,content text,
 content_sha256 text,byte_length integer,revision bigint)
LANGUAGE plpgsql SECURITY DEFINER STABLE SET search_path=pg_catalog AS $$
BEGIN
 IF p_log_type IS NULL OR p_log_type NOT IN ('access','error','audit','llm_requests') THEN
  RAISE EXCEPTION 'Invalid FinFlow log type' USING ERRCODE='23514';
 END IF;
 PERFORM finflow.assert_finflow_generation_active(p_owner_id,p_generation);
 RETURN QUERY SELECT o.owner_id,o.generation,o.log_type,o.action,o.content,
   o.content_sha256,o.byte_length,o.revision
  FROM finflow.log_overlays o WHERE o.owner_id=p_owner_id AND o.generation=p_generation
   AND o.log_type=p_log_type AND o.retired_at IS NULL;
END $$;

CREATE FUNCTION finflow.write_log_overlay(p_operation_id uuid,p_owner_id bigint,p_generation bigint,
 p_run_id uuid,p_log_type text,p_action text,p_content text,p_content_sha256 text)
RETURNS TABLE(operation_id uuid,owner_id bigint,generation bigint,run_id uuid,log_type text,
 action text,content_sha256 text,byte_length integer,revision bigint,completed_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE mutation finflow.log_overlay_mutations%ROWTYPE; overlay finflow.log_overlays%ROWTYPE;
DECLARE content_bytes integer;
BEGIN
 IF p_operation_id IS NULL OR p_run_id IS NULL OR p_log_type IS NULL
   OR p_log_type NOT IN ('access','error','audit','llm_requests')
   OR p_action IS NULL OR p_action NOT IN ('delete','modify') OR p_content IS NULL
   OR (p_action='delete' AND p_content<>'') OR p_content_sha256 IS NULL
   OR p_content_sha256 !~ '^[a-f0-9]{64}$'
   OR p_content_sha256<>encode(sha256(convert_to(p_content,'UTF8')),'hex') THEN
  RAISE EXCEPTION 'Invalid FinFlow log overlay mutation' USING ERRCODE='23514';
 END IF;
 content_bytes:=octet_length(p_content);
 IF content_bytes>1048576 THEN RAISE EXCEPTION 'FinFlow log overlay is too large' USING ERRCODE='22001'; END IF;
 PERFORM pg_advisory_xact_lock(1196444750,(p_owner_id % 2147483647)::integer);
 PERFORM finflow.assert_finflow_generation_active(p_owner_id,p_generation);
 SELECT m.* INTO mutation FROM finflow.log_overlay_mutations m WHERE m.operation_id=p_operation_id;
 IF FOUND THEN
  IF mutation.owner_id IS DISTINCT FROM p_owner_id OR mutation.generation IS DISTINCT FROM p_generation
    OR mutation.run_id IS DISTINCT FROM p_run_id OR mutation.log_type IS DISTINCT FROM p_log_type
    OR mutation.action IS DISTINCT FROM p_action OR mutation.content_sha256 IS DISTINCT FROM p_content_sha256
    OR mutation.byte_length IS DISTINCT FROM content_bytes THEN
   RAISE EXCEPTION 'FinFlow log overlay replay mismatch' USING ERRCODE='23514';
  END IF;
  SELECT o.* INTO STRICT overlay FROM finflow.log_overlays o WHERE o.owner_id=p_owner_id
    AND o.generation=p_generation AND o.log_type=p_log_type FOR UPDATE;
  IF overlay.retired_at IS NOT NULL OR overlay.revision IS DISTINCT FROM mutation.revision
    OR overlay.content_sha256 IS DISTINCT FROM mutation.content_sha256
    OR overlay.byte_length IS DISTINCT FROM mutation.byte_length THEN
   RAISE EXCEPTION 'FinFlow log overlay replay is stale' USING ERRCODE='55000';
  END IF;
 ELSE
  SELECT o.* INTO overlay FROM finflow.log_overlays o WHERE o.owner_id=p_owner_id
    AND o.generation=p_generation AND o.log_type=p_log_type FOR UPDATE;
  IF FOUND THEN
   IF overlay.retired_at IS NOT NULL THEN RAISE EXCEPTION 'FinFlow log overlay is retired' USING ERRCODE='55000'; END IF;
   IF overlay.content IS NOT DISTINCT FROM p_content THEN
    RAISE EXCEPTION 'FinFlow log overlay mutation has no effect' USING ERRCODE='55000';
   END IF;
   UPDATE finflow.log_overlays o SET action=p_action,content=p_content,content_sha256=p_content_sha256,
     byte_length=content_bytes,revision=o.revision+1,updated_at=clock_timestamp()
    WHERE o.owner_id=p_owner_id AND o.generation=p_generation AND o.log_type=p_log_type RETURNING * INTO overlay;
  ELSE
   INSERT INTO finflow.log_overlays(owner_id,generation,log_type,action,content,content_sha256,byte_length,revision)
    VALUES(p_owner_id,p_generation,p_log_type,p_action,p_content,p_content_sha256,content_bytes,1)
    RETURNING * INTO overlay;
  END IF;
  INSERT INTO finflow.log_overlay_mutations(operation_id,owner_id,generation,run_id,log_type,action,
    content_sha256,byte_length,revision) VALUES(p_operation_id,p_owner_id,p_generation,p_run_id,p_log_type,
    p_action,p_content_sha256,content_bytes,overlay.revision) RETURNING * INTO mutation;
 END IF;
 RETURN QUERY SELECT mutation.operation_id,mutation.owner_id,mutation.generation,mutation.run_id,
  mutation.log_type,mutation.action,mutation.content_sha256,mutation.byte_length,mutation.revision,mutation.completed_at;
END $$;

-- Extend the existing generation completion transaction. Physical backup bytes
-- have already been removed before this function can publish completion.
CREATE OR REPLACE FUNCTION finflow.complete_resource_retirement(
 p_operation_id uuid,p_owner_id bigint,p_from_generation bigint,p_to_generation bigint,p_file_tokens uuid[])
RETURNS TABLE(operation_id uuid,owner_id bigint,from_generation bigint,to_generation bigint,status text,
 artifact_count integer,completed_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE value finflow.resource_retirements%ROWTYPE;
BEGIN
 IF p_operation_id IS NULL OR p_owner_id IS NULL OR p_owner_id<=0 OR p_from_generation IS NULL
   OR p_from_generation<0 OR p_to_generation IS NULL OR p_to_generation IS DISTINCT FROM p_from_generation+1
   OR p_file_tokens IS NULL THEN
  RAISE EXCEPTION 'Invalid FinFlow retirement completion' USING ERRCODE='23514';
 END IF;
 PERFORM pg_advisory_xact_lock(1196444750,(p_owner_id % 2147483647)::integer);
 SELECT r.* INTO STRICT value FROM finflow.resource_retirements r WHERE r.operation_id=p_operation_id FOR UPDATE;
 IF value.owner_id IS DISTINCT FROM p_owner_id OR value.from_generation IS DISTINCT FROM p_from_generation
   OR value.to_generation IS DISTINCT FROM p_to_generation OR value.file_tokens IS DISTINCT FROM p_file_tokens THEN
  RAISE EXCEPTION 'FinFlow retirement completion mismatch' USING ERRCODE='23514';
 END IF;
 IF value.status='pending' THEN
  UPDATE finflow.backup_artifacts b SET status='retired',retired_at=clock_timestamp()
   WHERE b.owner_id=p_owner_id AND b.generation=p_from_generation AND b.status IN ('writing','ready');
  UPDATE finflow.customer_datasets d SET retired_at=clock_timestamp(),updated_at=clock_timestamp()
   WHERE d.owner_id=p_owner_id AND d.generation=p_from_generation AND d.retired_at IS NULL;
  UPDATE finflow.log_overlays o SET retired_at=clock_timestamp()
   WHERE o.owner_id=p_owner_id AND o.generation=p_from_generation AND o.retired_at IS NULL;
  UPDATE finflow.resource_retirements r SET status='completed',completed_at=clock_timestamp()
   WHERE r.operation_id=p_operation_id RETURNING * INTO value;
 END IF;
 RETURN QUERY SELECT value.operation_id,value.owner_id,value.from_generation,value.to_generation,
  value.status,value.artifact_count,value.completed_at;
END $$;

-- Extend account cleanup without weakening the existing physical-backup gate.
CREATE OR REPLACE FUNCTION finflow.complete_owner_resource_deletion(p_job_id uuid,p_owner_id bigint,p_file_tokens uuid[])
RETURNS TABLE(job_id uuid,owner_id bigint,status text,file_tokens uuid[],artifact_count integer,
 dataset_count integer,completed_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE value finflow.owner_resource_deletions%ROWTYPE;
BEGIN
 IF p_job_id IS NULL OR p_owner_id IS NULL OR p_owner_id<=0 OR p_file_tokens IS NULL THEN
  RAISE EXCEPTION 'Invalid FinFlow owner deletion completion' USING ERRCODE='23514';
 END IF;
 PERFORM pg_advisory_xact_lock(1196444750,(p_owner_id % 2147483647)::integer);
 SELECT d.* INTO STRICT value FROM finflow.owner_resource_deletions d WHERE d.job_id=p_job_id FOR UPDATE;
 IF value.owner_id IS DISTINCT FROM p_owner_id OR value.file_tokens IS DISTINCT FROM p_file_tokens THEN
  RAISE EXCEPTION 'FinFlow owner deletion completion mismatch' USING ERRCODE='23514';
 END IF;
 IF value.status='pending' THEN
  UPDATE finflow.backup_artifacts b SET status='retired',retired_at=COALESCE(b.retired_at,clock_timestamp()),
   snapshot_records='[]'::jsonb,content_scrubbed_at=clock_timestamp() WHERE b.owner_id=p_owner_id;
  UPDATE finflow.customer_datasets d SET records='[]'::jsonb,deleted=true,
   retired_at=COALESCE(d.retired_at,clock_timestamp()),updated_at=clock_timestamp() WHERE d.owner_id=p_owner_id;
  UPDATE finflow.log_overlays o SET retired_at=clock_timestamp()
   WHERE o.owner_id=p_owner_id AND o.retired_at IS NULL;
  UPDATE finflow.log_overlays o SET content='',content_scrubbed_at=clock_timestamp()
   WHERE o.owner_id=p_owner_id AND o.content_scrubbed_at IS NULL;
  UPDATE finflow.owner_resource_deletions d SET status='completed',completed_at=clock_timestamp()
   WHERE d.job_id=p_job_id RETURNING * INTO value;
 END IF;
 RETURN QUERY SELECT value.job_id,value.owner_id,value.status,value.file_tokens,value.artifact_count,
  value.dataset_count,value.completed_at;
END $$;

REVOKE ALL ON finflow.log_overlays,finflow.log_overlay_mutations FROM PUBLIC,dvaia_finflow_runtime;
REVOKE ALL ON FUNCTION finflow.guard_finflow_log_overlay(),
 finflow.read_log_overlay(bigint,bigint,text),
 finflow.write_log_overlay(uuid,bigint,bigint,uuid,text,text,text,text),
 finflow.complete_resource_retirement(uuid,bigint,bigint,bigint,uuid[]),
 finflow.complete_owner_resource_deletion(uuid,bigint,uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION finflow.read_log_overlay(bigint,bigint,text),
 finflow.write_log_overlay(uuid,bigint,bigint,uuid,text,text,text,text),
 finflow.complete_resource_retirement(uuid,bigint,bigint,bigint,uuid[]),
 finflow.complete_owner_resource_deletion(uuid,bigint,uuid[]) TO dvaia_finflow_runtime;
