-- CANDIDATE ONLY: proposed secureshop_review/0017 migration.
-- Do not register until disposable fresh/populated/no-op and lifecycle proof passes.

CREATE TABLE secureshop_review.bound_system_rebuild_owner_deletion_receipts (
 deletion_job_id uuid PRIMARY KEY,
 original_platform_owner_id integer NOT NULL UNIQUE CHECK(original_platform_owner_id>=1),
 deleted_operation_count bigint NOT NULL CHECK(deleted_operation_count>=0),
 receipt_sha256 bytea NOT NULL CHECK(octet_length(receipt_sha256)=32),
 completed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE secureshop_review.bound_system_rebuild_operations (
 operation_id uuid PRIMARY KEY,
 target_id uuid NOT NULL REFERENCES secureshop_review.product_targets(target_id),
 launch_id uuid NOT NULL,scenario_id uuid NOT NULL,
 generation bigint NOT NULL CHECK(generation BETWEEN 1 AND 9007199254740991),
 original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id>=1),
 original_platform_session_id integer NOT NULL CHECK(original_platform_session_id>=1),
 shop_user_id integer NOT NULL CHECK(shop_user_id>=1),
 persona_session_id uuid NOT NULL,
 authority_version bigint NOT NULL CHECK(authority_version BETWEEN 1 AND 9007199254740991),
 corpus text NOT NULL CHECK(corpus IN ('products','reviews','manuals')),
 request_sha256 bytea NOT NULL CHECK(octet_length(request_sha256)=32),
 binding_sha256 bytea NOT NULL CHECK(octet_length(binding_sha256)=32),
 source_set_sha256 bytea NOT NULL CHECK(octet_length(source_set_sha256)=32),
 runtime_sha256 bytea NOT NULL CHECK(octet_length(runtime_sha256)=32),
 expected_head uuid,
 base_revision_id uuid NOT NULL,
 state text NOT NULL DEFAULT 'admitted' CHECK(state IN ('admitted','running','completed','failed','retired')),
 worker_token uuid,
 failure_code text CHECK(failure_code IS NULL OR failure_code IN
  ('ABORTED','AUTHORITY_REVOKED','RUNTIME_CHANGED','SOURCE_CHANGED','PUBLICATION_REJECTED','EXECUTION_FAILED')),
 revision_id uuid,
 vector_sha256 bytea CHECK(vector_sha256 IS NULL OR octet_length(vector_sha256)=32),
 document_count integer CHECK(document_count IS NULL OR document_count BETWEEN 0 AND 4096),
 admitted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 started_at timestamptz,completed_at timestamptz,
 CHECK(
  (state='admitted' AND worker_token IS NULL AND started_at IS NULL AND completed_at IS NULL
   AND failure_code IS NULL AND revision_id IS NULL AND vector_sha256 IS NULL AND document_count IS NULL)
  OR (state='running' AND worker_token IS NOT NULL AND started_at IS NOT NULL AND completed_at IS NULL
   AND failure_code IS NULL AND revision_id IS NULL AND vector_sha256 IS NULL AND document_count IS NULL)
  OR (state='completed' AND worker_token IS NOT NULL AND started_at IS NOT NULL AND completed_at IS NOT NULL
   AND failure_code IS NULL AND revision_id=operation_id AND vector_sha256 IS NOT NULL AND document_count IS NOT NULL)
  OR (state='failed' AND worker_token IS NOT NULL AND started_at IS NOT NULL AND completed_at IS NOT NULL
   AND failure_code IS NOT NULL AND revision_id IS NULL AND vector_sha256 IS NULL AND document_count IS NULL)
  OR (state='retired' AND completed_at IS NOT NULL AND revision_id IS NULL AND vector_sha256 IS NULL AND document_count IS NULL)
 )
);
CREATE INDEX bound_system_rebuild_scope_read ON secureshop_review.bound_system_rebuild_operations
 (target_id,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id,admitted_at DESC);
CREATE INDEX bound_system_rebuild_owner_cleanup ON secureshop_review.bound_system_rebuild_operations
 (original_platform_owner_id,operation_id);

CREATE FUNCTION secureshop_review.system_rebuild_owner_receipt_digest(uuid,integer,bigint)
RETURNS bytea LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT sha256(convert_to(concat_ws(chr(31),'secureshop-system-rebuild-owner-deletion-v1',
  $1::text,$2::text,$3::text),'UTF8'))
$$;

CREATE FUNCTION secureshop_review.guard_bound_system_rebuild_operation()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE target secureshop_review.product_targets%ROWTYPE;
BEGIN
 IF TG_OP='INSERT' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||NEW.original_platform_owner_id::text,0));
  IF EXISTS(SELECT 1 FROM secureshop_review.bound_audit_owner_deletion_receipts WHERE original_platform_owner_id=NEW.original_platform_owner_id)
   OR EXISTS(SELECT 1 FROM secureshop_review.bound_system_rebuild_owner_deletion_receipts WHERE original_platform_owner_id=NEW.original_platform_owner_id) THEN
   RAISE EXCEPTION 'Bound rebuild owner is deleted' USING ERRCODE='55000';
  END IF;
  SELECT * INTO target FROM secureshop_review.product_targets WHERE target_id=NEW.target_id FOR SHARE;
  IF NOT FOUND OR target.lifecycle<>'active' OR target.launch_id<>NEW.launch_id OR target.scenario_id<>NEW.scenario_id
   OR target.generation<>NEW.generation OR target.original_platform_owner_id<>NEW.original_platform_owner_id
   OR target.original_platform_session_id<>NEW.original_platform_session_id
   OR NOT EXISTS(SELECT 1 FROM secureshop_review.product_target_retrieval_config c WHERE c.target_id=NEW.target_id AND c.lifecycle='active') THEN
   RAISE EXCEPTION 'Active rebuild target required' USING ERRCODE='55000';
  END IF;
  IF NEW.state<>'admitted' OR NEW.worker_token IS NOT NULL OR NEW.started_at IS NOT NULL
   OR NEW.completed_at IS NOT NULL OR NEW.failure_code IS NOT NULL OR NEW.revision_id IS NOT NULL
   OR NEW.vector_sha256 IS NOT NULL OR NEW.document_count IS NOT NULL THEN
   RAISE EXCEPTION 'Bound rebuild must begin as an admission' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
 END IF;
 IF TG_OP='DELETE' THEN
  IF NOT EXISTS(SELECT 1 FROM secureshop_review.bound_system_rebuild_owner_deletion_receipts r
   WHERE r.original_platform_owner_id=OLD.original_platform_owner_id) THEN
   RAISE EXCEPTION 'Bound rebuild operation is immutable' USING ERRCODE='55000';
  END IF;
  RETURN OLD;
 END IF;
 IF ROW(NEW.operation_id,NEW.target_id,NEW.launch_id,NEW.scenario_id,NEW.generation,
   NEW.original_platform_owner_id,NEW.original_platform_session_id,NEW.shop_user_id,NEW.persona_session_id,
   NEW.authority_version,NEW.corpus,NEW.request_sha256,NEW.binding_sha256,NEW.source_set_sha256,
   NEW.runtime_sha256,NEW.expected_head,NEW.base_revision_id,NEW.admitted_at)
   IS DISTINCT FROM ROW(OLD.operation_id,OLD.target_id,OLD.launch_id,OLD.scenario_id,OLD.generation,
   OLD.original_platform_owner_id,OLD.original_platform_session_id,OLD.shop_user_id,OLD.persona_session_id,
   OLD.authority_version,OLD.corpus,OLD.request_sha256,OLD.binding_sha256,OLD.source_set_sha256,
   OLD.runtime_sha256,OLD.expected_head,OLD.base_revision_id,OLD.admitted_at) THEN
  RAISE EXCEPTION 'Bound rebuild admission is immutable' USING ERRCODE='55000';
 END IF;
 IF OLD.state='admitted' AND NEW.state='running' THEN RETURN NEW; END IF;
 IF OLD.state='running' AND NEW.state IN ('completed','failed')
   AND NEW.worker_token=OLD.worker_token AND NEW.started_at=OLD.started_at THEN
  IF NEW.state='completed' AND NOT EXISTS(
   SELECT 1 FROM secureshop_review.product_target_embedding_revisions r
   JOIN secureshop_review.product_targets t USING(target_id)
   WHERE r.revision_id=NEW.operation_id AND r.target_id=NEW.target_id
    AND r.launch_id=NEW.launch_id AND r.scenario_id=NEW.scenario_id AND r.generation=NEW.generation
    AND r.original_platform_owner_id=NEW.original_platform_owner_id
    AND r.original_platform_session_id=NEW.original_platform_session_id
    AND r.source_set_digest=NEW.source_set_sha256 AND r.runtime_fingerprint=NEW.runtime_sha256
    AND r.vector_digest=NEW.vector_sha256 AND r.document_count=NEW.document_count
    AND t.lifecycle='active') THEN
   RAISE EXCEPTION 'Bound rebuild completion receipt mismatch' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
 END IF;
 IF OLD.state IN ('admitted','running') AND NEW.state='retired'
   AND EXISTS(SELECT 1 FROM secureshop_review.product_targets t WHERE t.target_id=OLD.target_id AND t.lifecycle='retired') THEN RETURN NEW; END IF;
 RAISE EXCEPTION 'Bound rebuild lifecycle transition rejected' USING ERRCODE='55000';
END $$;
CREATE TRIGGER bound_system_rebuild_operation_guard BEFORE INSERT OR UPDATE OR DELETE
 ON secureshop_review.bound_system_rebuild_operations FOR EACH ROW
 EXECUTE FUNCTION secureshop_review.guard_bound_system_rebuild_operation();

CREATE FUNCTION secureshop_review.retire_bound_system_rebuild_operations()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
BEGIN
 IF OLD.lifecycle='active' AND NEW.lifecycle='retired' THEN
  UPDATE secureshop_review.bound_system_rebuild_operations SET state='retired',worker_token=NULL,
   failure_code=NULL,revision_id=NULL,vector_sha256=NULL,document_count=NULL,completed_at=clock_timestamp()
   WHERE target_id=NEW.target_id AND state IN ('admitted','running');
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER product_target_rebuild_retirement AFTER UPDATE OF lifecycle ON secureshop_review.product_targets
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.retire_bound_system_rebuild_operations();

CREATE FUNCTION secureshop_review.guard_bound_system_rebuild_owner_receipt()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN
 RAISE EXCEPTION 'Bound rebuild deletion receipt is immutable' USING ERRCODE='55000';
END $$;
CREATE TRIGGER bound_system_rebuild_owner_receipt_guard BEFORE UPDATE OR DELETE
 ON secureshop_review.bound_system_rebuild_owner_deletion_receipts FOR EACH ROW
 EXECUTE FUNCTION secureshop_review.guard_bound_system_rebuild_owner_receipt();

-- Forward replacement preserves the applied 0013 audit receipt contract while
-- composing rebuild-journal privacy cleanup under the same owner lock/job id.
CREATE OR REPLACE FUNCTION secureshop_review.destroy_bound_audit_owner(requested_owner integer,requested_deletion_job uuid)
RETURNS SETOF secureshop_review.bound_audit_owner_deletion_receipts
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE audit_prior secureshop_review.bound_audit_owner_deletion_receipts%ROWTYPE;
 rebuild_prior secureshop_review.bound_system_rebuild_owner_deletion_receipts%ROWTYPE;
 audit_count bigint;rebuild_count bigint;deleted bigint;audit_replay boolean;rebuild_replay boolean;
BEGIN
 IF requested_owner IS NULL OR requested_owner<1 OR requested_deletion_job IS NULL THEN RAISE EXCEPTION 'Valid bound audit deletion scope required' USING ERRCODE='22023'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||requested_owner::text,0));
 SELECT * INTO audit_prior FROM secureshop_review.bound_audit_owner_deletion_receipts
  WHERE deletion_job_id=requested_deletion_job OR original_platform_owner_id=requested_owner FOR UPDATE;
 SELECT * INTO rebuild_prior FROM secureshop_review.bound_system_rebuild_owner_deletion_receipts
  WHERE deletion_job_id=requested_deletion_job OR original_platform_owner_id=requested_owner FOR UPDATE;
 audit_replay:=audit_prior.deletion_job_id IS NOT NULL;
 rebuild_replay:=rebuild_prior.deletion_job_id IS NOT NULL;
 IF audit_prior.deletion_job_id IS NULL THEN
  SELECT count(*) INTO audit_count FROM secureshop_review.bound_audit_events WHERE original_platform_owner_id=requested_owner;
  INSERT INTO secureshop_review.bound_audit_owner_deletion_receipts(deletion_job_id,original_platform_owner_id,deleted_event_count,receipt_sha256)
   VALUES(requested_deletion_job,requested_owner,audit_count,secureshop_review.bound_audit_owner_receipt_digest(requested_deletion_job,requested_owner,audit_count)) RETURNING * INTO audit_prior;
 ELSE
  IF audit_prior.deletion_job_id<>requested_deletion_job OR audit_prior.original_platform_owner_id<>requested_owner
   OR audit_prior.receipt_sha256<>secureshop_review.bound_audit_owner_receipt_digest(audit_prior.deletion_job_id,audit_prior.original_platform_owner_id,audit_prior.deleted_event_count) THEN
   RAISE EXCEPTION 'Bound audit owner deletion replay mismatch' USING ERRCODE='55000'; END IF;
 END IF;
 IF rebuild_prior.deletion_job_id IS NULL THEN
  SELECT count(*) INTO rebuild_count FROM secureshop_review.bound_system_rebuild_operations WHERE original_platform_owner_id=requested_owner;
  INSERT INTO secureshop_review.bound_system_rebuild_owner_deletion_receipts(deletion_job_id,original_platform_owner_id,deleted_operation_count,receipt_sha256)
   VALUES(requested_deletion_job,requested_owner,rebuild_count,secureshop_review.system_rebuild_owner_receipt_digest(requested_deletion_job,requested_owner,rebuild_count)) RETURNING * INTO rebuild_prior;
 ELSE
  IF rebuild_prior.deletion_job_id<>requested_deletion_job OR rebuild_prior.original_platform_owner_id<>requested_owner
   OR rebuild_prior.receipt_sha256<>secureshop_review.system_rebuild_owner_receipt_digest(rebuild_prior.deletion_job_id,rebuild_prior.original_platform_owner_id,rebuild_prior.deleted_operation_count) THEN
   RAISE EXCEPTION 'Bound rebuild owner deletion replay mismatch' USING ERRCODE='55000'; END IF;
 END IF;
 IF audit_replay THEN
  IF EXISTS(SELECT 1 FROM secureshop_review.bound_audit_events WHERE original_platform_owner_id=requested_owner) THEN RAISE EXCEPTION 'Bound audit owner deletion replay mismatch' USING ERRCODE='55000';END IF;
 ELSE
  DELETE FROM secureshop_review.bound_audit_events WHERE original_platform_owner_id=requested_owner;GET DIAGNOSTICS deleted=ROW_COUNT;
  IF deleted<>audit_prior.deleted_event_count THEN RAISE EXCEPTION 'Bound audit owner deletion count mismatch' USING ERRCODE='55000';END IF;
 END IF;
 IF rebuild_replay THEN
  IF EXISTS(SELECT 1 FROM secureshop_review.bound_system_rebuild_operations WHERE original_platform_owner_id=requested_owner) THEN RAISE EXCEPTION 'Bound rebuild owner deletion replay mismatch' USING ERRCODE='55000';END IF;
 ELSE
  DELETE FROM secureshop_review.bound_system_rebuild_operations WHERE original_platform_owner_id=requested_owner;GET DIAGNOSTICS deleted=ROW_COUNT;
  IF deleted<>rebuild_prior.deleted_operation_count THEN RAISE EXCEPTION 'Bound rebuild owner deletion count mismatch' USING ERRCODE='55000';END IF;
 END IF;
 RETURN NEXT audit_prior;
END $$;

REVOKE ALL ON TABLE secureshop_review.bound_system_rebuild_operations,
 secureshop_review.bound_system_rebuild_owner_deletion_receipts FROM PUBLIC,dvaia_secureshop_review_runtime;
REVOKE ALL ON FUNCTION secureshop_review.system_rebuild_owner_receipt_digest(uuid,integer,bigint),
 secureshop_review.guard_bound_system_rebuild_operation(),secureshop_review.retire_bound_system_rebuild_operations(),
 secureshop_review.guard_bound_system_rebuild_owner_receipt(),
 secureshop_review.destroy_bound_audit_owner(integer,uuid) FROM PUBLIC;
GRANT SELECT,INSERT ON secureshop_review.bound_system_rebuild_operations TO dvaia_secureshop_review_runtime;
GRANT UPDATE(state,worker_token,failure_code,revision_id,vector_sha256,document_count,started_at,completed_at)
 ON secureshop_review.bound_system_rebuild_operations TO dvaia_secureshop_review_runtime;
GRANT SELECT ON secureshop_review.bound_system_rebuild_owner_deletion_receipts TO dvaia_secureshop_review_runtime;
GRANT EXECUTE ON FUNCTION secureshop_review.destroy_bound_audit_owner(integer,uuid)
 TO dvaia_secureshop_review_runtime;
