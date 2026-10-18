-- CANDIDATE ONLY: persistent launch-owned synthetic restart target and journal.
CREATE TABLE secureshop_review.bound_system_restart_targets(
 target_id uuid PRIMARY KEY REFERENCES secureshop_review.product_targets(target_id),launch_id uuid NOT NULL,scenario_id uuid NOT NULL,generation bigint NOT NULL CHECK(generation BETWEEN 1 AND 9007199254740991),
 original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id>0),original_platform_session_id integer NOT NULL CHECK(original_platform_session_id>0),
 instance_id uuid NOT NULL,restart_generation bigint NOT NULL DEFAULT 1 CHECK(restart_generation BETWEEN 1 AND 9007199254740991),
 lifecycle text NOT NULL DEFAULT 'active' CHECK(lifecycle IN('active','retired')),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),retired_at timestamptz,
 UNIQUE(launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id),CHECK((lifecycle='retired')=(retired_at IS NOT NULL))
);
CREATE TABLE secureshop_review.bound_system_restart_owner_deletion_receipts(
 deletion_job_id uuid PRIMARY KEY,original_platform_owner_id integer NOT NULL UNIQUE CHECK(original_platform_owner_id>0),
 deleted_target_count bigint NOT NULL CHECK(deleted_target_count>=0),deleted_operation_count bigint NOT NULL CHECK(deleted_operation_count>=0),
 receipt_sha256 bytea NOT NULL CHECK(octet_length(receipt_sha256)=32),completed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE secureshop_review.bound_system_restart_operations(
 operation_id uuid PRIMARY KEY,target_id uuid NOT NULL REFERENCES secureshop_review.bound_system_restart_targets(target_id),
 launch_id uuid NOT NULL,scenario_id uuid NOT NULL,generation bigint NOT NULL CHECK(generation BETWEEN 1 AND 9007199254740991),
 original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id>0),original_platform_session_id integer NOT NULL CHECK(original_platform_session_id>0),
 shop_user_id integer NOT NULL CHECK(shop_user_id>0),persona_session_id uuid NOT NULL,authority_version bigint NOT NULL CHECK(authority_version BETWEEN 1 AND 9007199254740991),
 service_name text NOT NULL CHECK(octet_length(service_name) BETWEEN 1 AND 128),request_sha256 bytea NOT NULL CHECK(octet_length(request_sha256)=32),binding_sha256 bytea NOT NULL CHECK(octet_length(binding_sha256)=32),
 state text NOT NULL DEFAULT 'admitted' CHECK(state IN('admitted','running','completed','failed','retired')),worker_token uuid,before_instance_id uuid,after_instance_id uuid,
 before_generation bigint,after_generation bigint,effect_sha256 bytea CHECK(effect_sha256 IS NULL OR octet_length(effect_sha256)=32),
 output_sha256 bytea CHECK(output_sha256 IS NULL OR octet_length(output_sha256)=32),output_bytes integer CHECK(output_bytes IS NULL OR output_bytes BETWEEN 0 AND 65536),
 failure_code text CHECK(failure_code IS NULL OR failure_code IN('ABORTED','AUTHORITY_REVOKED','TARGET_CHANGED','EXECUTION_FAILED','OUTCOME_UNCERTAIN')),
 admitted_at timestamptz NOT NULL DEFAULT clock_timestamp(),started_at timestamptz,completed_at timestamptz,
 CHECK((state='admitted' AND worker_token IS NULL AND before_instance_id IS NULL AND after_instance_id IS NULL AND completed_at IS NULL)
  OR(state='running' AND worker_token IS NOT NULL AND before_instance_id IS NOT NULL AND before_generation IS NOT NULL AND started_at IS NOT NULL AND completed_at IS NULL)
  OR(state='completed' AND worker_token IS NOT NULL AND before_instance_id IS NOT NULL AND after_instance_id IS NOT NULL AND before_instance_id<>after_instance_id AND after_generation=before_generation+1 AND effect_sha256 IS NOT NULL AND completed_at IS NOT NULL AND failure_code IS NULL)
  OR(state='failed' AND worker_token IS NOT NULL AND completed_at IS NOT NULL AND failure_code IS NOT NULL AND after_instance_id IS NULL AND effect_sha256 IS NULL)
  OR(state='retired' AND completed_at IS NOT NULL AND after_instance_id IS NULL AND effect_sha256 IS NULL))
);
CREATE INDEX bound_system_restart_scope_read ON secureshop_review.bound_system_restart_operations(target_id,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id,admitted_at DESC);
REVOKE ALL ON TABLE secureshop_review.bound_system_restart_targets,secureshop_review.bound_system_restart_operations FROM PUBLIC;
GRANT SELECT,INSERT ON secureshop_review.bound_system_restart_targets,secureshop_review.bound_system_restart_operations TO dvaia_secureshop_review_runtime;

CREATE FUNCTION secureshop_review.guard_bound_system_restart_target() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE target secureshop_review.product_targets%ROWTYPE;
BEGIN
 IF TG_OP='INSERT' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||NEW.original_platform_owner_id::text,0));
  IF EXISTS(SELECT 1 FROM secureshop_review.bound_audit_owner_deletion_receipts WHERE original_platform_owner_id=NEW.original_platform_owner_id)
   OR EXISTS(SELECT 1 FROM secureshop_review.bound_system_restart_owner_deletion_receipts WHERE original_platform_owner_id=NEW.original_platform_owner_id) THEN RAISE EXCEPTION 'owned restart owner deleted' USING ERRCODE='55000'; END IF;
  SELECT * INTO target FROM secureshop_review.product_targets WHERE target_id=NEW.target_id FOR SHARE;
  IF NOT FOUND OR target.lifecycle<>'active' OR ROW(target.launch_id,target.scenario_id,target.generation,target.original_platform_owner_id,target.original_platform_session_id)
   IS DISTINCT FROM ROW(NEW.launch_id,NEW.scenario_id,NEW.generation,NEW.original_platform_owner_id,NEW.original_platform_session_id)
   OR NEW.restart_generation<>1 OR NEW.lifecycle<>'active' OR NEW.retired_at IS NOT NULL THEN RAISE EXCEPTION 'active owned restart target required' USING ERRCODE='55000'; END IF; RETURN NEW;
 END IF;
 IF TG_OP='DELETE' THEN IF EXISTS(SELECT 1 FROM secureshop_review.bound_system_restart_owner_deletion_receipts r WHERE r.original_platform_owner_id=OLD.original_platform_owner_id) THEN RETURN OLD; END IF; RAISE EXCEPTION 'owned restart target is immutable' USING ERRCODE='55000'; END IF;
 IF ROW(NEW.target_id,NEW.launch_id,NEW.scenario_id,NEW.generation,NEW.original_platform_owner_id,NEW.original_platform_session_id,NEW.created_at)
  IS DISTINCT FROM ROW(OLD.target_id,OLD.launch_id,OLD.scenario_id,OLD.generation,OLD.original_platform_owner_id,OLD.original_platform_session_id,OLD.created_at) THEN RAISE EXCEPTION 'owned restart identity is immutable' USING ERRCODE='55000'; END IF;
 IF OLD.lifecycle='active' AND NEW.lifecycle='active' AND NEW.restart_generation=OLD.restart_generation+1 AND NEW.instance_id<>OLD.instance_id THEN RETURN NEW; END IF;
 IF OLD.lifecycle='active' AND NEW.lifecycle='retired' AND NEW.instance_id=OLD.instance_id AND NEW.restart_generation=OLD.restart_generation AND NEW.retired_at IS NOT NULL
  AND EXISTS(SELECT 1 FROM secureshop_review.product_targets p WHERE p.target_id=OLD.target_id AND p.lifecycle='retired') THEN RETURN NEW; END IF;
 RAISE EXCEPTION 'owned restart transition rejected' USING ERRCODE='55000';
END $$;
CREATE TRIGGER bound_system_restart_target_guard BEFORE INSERT OR UPDATE OR DELETE ON secureshop_review.bound_system_restart_targets FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_bound_system_restart_target();

CREATE FUNCTION secureshop_review.guard_bound_system_restart_operation() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE target secureshop_review.bound_system_restart_targets%ROWTYPE;
BEGIN
 IF TG_OP='INSERT' THEN SELECT * INTO target FROM secureshop_review.bound_system_restart_targets WHERE target_id=NEW.target_id FOR SHARE;
  PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||NEW.original_platform_owner_id::text,0));
  IF EXISTS(SELECT 1 FROM secureshop_review.bound_audit_owner_deletion_receipts WHERE original_platform_owner_id=NEW.original_platform_owner_id) THEN RAISE EXCEPTION 'owned restart owner deleted' USING ERRCODE='55000'; END IF;
  IF NOT FOUND OR target.lifecycle<>'active' OR ROW(target.launch_id,target.scenario_id,target.generation,target.original_platform_owner_id,target.original_platform_session_id)
   IS DISTINCT FROM ROW(NEW.launch_id,NEW.scenario_id,NEW.generation,NEW.original_platform_owner_id,NEW.original_platform_session_id)
   OR NEW.state<>'admitted' OR NEW.worker_token IS NOT NULL THEN RAISE EXCEPTION 'owned restart admission rejected' USING ERRCODE='55000'; END IF; RETURN NEW; END IF;
 IF TG_OP='DELETE' THEN IF EXISTS(SELECT 1 FROM secureshop_review.bound_system_restart_owner_deletion_receipts r WHERE r.original_platform_owner_id=OLD.original_platform_owner_id) THEN RETURN OLD; END IF; RAISE EXCEPTION 'owned restart operation is immutable' USING ERRCODE='55000'; END IF;
 IF ROW(NEW.operation_id,NEW.target_id,NEW.launch_id,NEW.scenario_id,NEW.generation,NEW.original_platform_owner_id,NEW.original_platform_session_id,NEW.shop_user_id,NEW.persona_session_id,NEW.authority_version,NEW.service_name,NEW.request_sha256,NEW.binding_sha256,NEW.admitted_at)
  IS DISTINCT FROM ROW(OLD.operation_id,OLD.target_id,OLD.launch_id,OLD.scenario_id,OLD.generation,OLD.original_platform_owner_id,OLD.original_platform_session_id,OLD.shop_user_id,OLD.persona_session_id,OLD.authority_version,OLD.service_name,OLD.request_sha256,OLD.binding_sha256,OLD.admitted_at) THEN RAISE EXCEPTION 'owned restart admission is immutable' USING ERRCODE='55000'; END IF;
 IF OLD.state='admitted' AND NEW.state='running' AND NEW.worker_token IS NOT NULL AND NEW.before_instance_id IS NOT NULL AND NEW.before_generation IS NOT NULL THEN RETURN NEW; END IF;
 IF OLD.state='running' AND NEW.state IN('completed','failed') AND NEW.worker_token=OLD.worker_token AND NEW.started_at=OLD.started_at THEN RETURN NEW; END IF;
 IF OLD.state IN('admitted','running') AND NEW.state='retired' AND EXISTS(SELECT 1 FROM secureshop_review.bound_system_restart_targets t WHERE t.target_id=OLD.target_id AND t.lifecycle='retired') THEN RETURN NEW; END IF;
 RAISE EXCEPTION 'owned restart operation transition rejected' USING ERRCODE='55000';
END $$;
CREATE TRIGGER bound_system_restart_operation_guard BEFORE INSERT OR UPDATE OR DELETE ON secureshop_review.bound_system_restart_operations FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_bound_system_restart_operation();

CREATE FUNCTION secureshop_review.complete_bound_system_restart(requested_operation uuid,requested_worker uuid,requested_before uuid,requested_after uuid,requested_before_generation bigint,requested_after_generation bigint,requested_effect bytea,requested_output bytea,requested_output_bytes integer)
RETURNS SETOF secureshop_review.bound_system_restart_operations LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE op secureshop_review.bound_system_restart_operations%ROWTYPE; target secureshop_review.bound_system_restart_targets%ROWTYPE;
BEGIN
 SELECT * INTO op FROM secureshop_review.bound_system_restart_operations WHERE operation_id=requested_operation FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'owned restart receipt mismatch' USING ERRCODE='55000'; END IF;
 SELECT * INTO target FROM secureshop_review.bound_system_restart_targets WHERE target_id=op.target_id FOR UPDATE;
 IF NOT FOUND OR requested_worker IS NULL OR requested_before IS NULL OR requested_after IS NULL OR requested_before_generation IS NULL OR requested_after_generation IS NULL
  OR requested_effect IS NULL OR requested_output IS NULL OR requested_output_bytes IS NULL OR op.state IS DISTINCT FROM 'running'
  OR op.worker_token IS DISTINCT FROM requested_worker OR target.target_id IS NULL OR target.lifecycle IS DISTINCT FROM 'active'
  OR op.before_instance_id IS DISTINCT FROM requested_before OR op.before_generation IS DISTINCT FROM requested_before_generation
  OR target.instance_id IS DISTINCT FROM requested_before OR target.restart_generation IS DISTINCT FROM requested_before_generation
  OR requested_after IS NOT DISTINCT FROM requested_before OR requested_after_generation IS DISTINCT FROM requested_before_generation+1
  OR octet_length(requested_effect) IS DISTINCT FROM 32 OR octet_length(requested_output) IS DISTINCT FROM 32
  OR requested_output_bytes NOT BETWEEN 0 AND 65536 THEN RAISE EXCEPTION 'owned restart receipt mismatch' USING ERRCODE='55000'; END IF;
 UPDATE secureshop_review.bound_system_restart_targets SET instance_id=requested_after,restart_generation=requested_after_generation WHERE target_id=target.target_id;
 RETURN QUERY UPDATE secureshop_review.bound_system_restart_operations SET state='completed',after_instance_id=requested_after,after_generation=requested_after_generation,effect_sha256=requested_effect,output_sha256=requested_output,output_bytes=requested_output_bytes,completed_at=clock_timestamp() WHERE operation_id=requested_operation RETURNING *;
END $$;
REVOKE ALL ON FUNCTION secureshop_review.complete_bound_system_restart(uuid,uuid,uuid,uuid,bigint,bigint,bytea,bytea,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.complete_bound_system_restart(uuid,uuid,uuid,uuid,bigint,bigint,bytea,bytea,integer) TO dvaia_secureshop_review_runtime;
REVOKE UPDATE ON secureshop_review.bound_system_restart_targets,secureshop_review.bound_system_restart_operations FROM dvaia_secureshop_review_runtime;

CREATE FUNCTION secureshop_review.retire_bound_system_restart_target() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
BEGIN
 IF OLD.lifecycle='active' AND NEW.lifecycle='retired' THEN
  UPDATE secureshop_review.bound_system_restart_targets SET lifecycle='retired',retired_at=clock_timestamp() WHERE target_id=NEW.target_id AND lifecycle='active';
  UPDATE secureshop_review.bound_system_restart_operations SET state='retired',completed_at=clock_timestamp(),after_instance_id=NULL,effect_sha256=NULL,failure_code=NULL WHERE target_id=NEW.target_id AND state IN('admitted','running');
 END IF;RETURN NEW;
END $$;
CREATE TRIGGER product_target_restart_retirement AFTER UPDATE OF lifecycle ON secureshop_review.product_targets FOR EACH ROW EXECUTE FUNCTION secureshop_review.retire_bound_system_restart_target();

CREATE FUNCTION secureshop_review.guard_bound_system_restart_owner_receipt() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'owned restart deletion receipt is immutable' USING ERRCODE='55000'; END $$;
CREATE TRIGGER bound_system_restart_owner_receipt_guard BEFORE UPDATE OR DELETE ON secureshop_review.bound_system_restart_owner_deletion_receipts FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_bound_system_restart_owner_receipt();

CREATE FUNCTION secureshop_review.cleanup_bound_system_restart_owner() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE targets bigint;operations bigint;deleted bigint;digest bytea;
BEGIN
 SELECT count(*) INTO targets FROM secureshop_review.bound_system_restart_targets WHERE original_platform_owner_id=NEW.original_platform_owner_id;
 SELECT count(*) INTO operations FROM secureshop_review.bound_system_restart_operations WHERE original_platform_owner_id=NEW.original_platform_owner_id;
 digest:=sha256(convert_to(concat_ws(chr(31),'secureshop-owned-restart-owner-deletion-v1',NEW.deletion_job_id::text,NEW.original_platform_owner_id::text,targets::text,operations::text),'UTF8'));
 INSERT INTO secureshop_review.bound_system_restart_owner_deletion_receipts(deletion_job_id,original_platform_owner_id,deleted_target_count,deleted_operation_count,receipt_sha256)
 VALUES(NEW.deletion_job_id,NEW.original_platform_owner_id,targets,operations,digest);
 DELETE FROM secureshop_review.bound_system_restart_operations WHERE original_platform_owner_id=NEW.original_platform_owner_id;GET DIAGNOSTICS deleted=ROW_COUNT;
 IF deleted<>operations THEN RAISE EXCEPTION 'owned restart operation cleanup mismatch' USING ERRCODE='55000'; END IF;
 DELETE FROM secureshop_review.bound_system_restart_targets WHERE original_platform_owner_id=NEW.original_platform_owner_id;GET DIAGNOSTICS deleted=ROW_COUNT;
 IF deleted<>targets THEN RAISE EXCEPTION 'owned restart target cleanup mismatch' USING ERRCODE='55000'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER z_bound_system_restart_owner_cleanup AFTER INSERT ON secureshop_review.bound_audit_owner_deletion_receipts FOR EACH ROW EXECUTE FUNCTION secureshop_review.cleanup_bound_system_restart_owner();

REVOKE ALL ON TABLE secureshop_review.bound_system_restart_owner_deletion_receipts FROM PUBLIC,dvaia_secureshop_review_runtime;
GRANT SELECT ON secureshop_review.bound_system_restart_owner_deletion_receipts TO dvaia_secureshop_review_runtime;
REVOKE ALL ON FUNCTION secureshop_review.retire_bound_system_restart_target(),secureshop_review.guard_bound_system_restart_owner_receipt(),secureshop_review.cleanup_bound_system_restart_owner() FROM PUBLIC;

CREATE FUNCTION secureshop_review.begin_bound_system_restart(requested_operation uuid,requested_worker uuid)
RETURNS SETOF secureshop_review.bound_system_restart_operations LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE op secureshop_review.bound_system_restart_operations%ROWTYPE;target secureshop_review.bound_system_restart_targets%ROWTYPE;
BEGIN
 SELECT * INTO op FROM secureshop_review.bound_system_restart_operations WHERE operation_id=requested_operation FOR UPDATE;
 IF NOT FOUND OR op.state<>'admitted' OR requested_worker IS NULL THEN RAISE EXCEPTION 'owned restart admission unavailable' USING ERRCODE='55000'; END IF;
 SELECT * INTO target FROM secureshop_review.bound_system_restart_targets WHERE target_id=op.target_id FOR UPDATE;
 IF NOT FOUND OR target.lifecycle<>'active' THEN RAISE EXCEPTION 'owned restart target unavailable' USING ERRCODE='55000'; END IF;
 IF EXISTS(SELECT 1 FROM secureshop_review.bound_system_restart_operations x WHERE x.target_id=op.target_id AND x.state='running' AND x.operation_id<>op.operation_id) THEN RAISE EXCEPTION 'owned restart busy' USING ERRCODE='55000'; END IF;
 RETURN QUERY UPDATE secureshop_review.bound_system_restart_operations SET state='running',worker_token=requested_worker,before_instance_id=target.instance_id,before_generation=target.restart_generation,started_at=clock_timestamp() WHERE operation_id=requested_operation RETURNING *;
END $$;
CREATE FUNCTION secureshop_review.fail_bound_system_restart(requested_operation uuid,requested_worker uuid,requested_code text)
RETURNS SETOF secureshop_review.bound_system_restart_operations LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
BEGIN
 IF requested_worker IS NULL OR requested_code IS NULL OR requested_code NOT IN('ABORTED','AUTHORITY_REVOKED','TARGET_CHANGED','EXECUTION_FAILED','OUTCOME_UNCERTAIN') THEN RAISE EXCEPTION 'owned restart failure invalid' USING ERRCODE='22023'; END IF;
 RETURN QUERY UPDATE secureshop_review.bound_system_restart_operations SET state='failed',failure_code=requested_code,completed_at=clock_timestamp()
  WHERE operation_id=requested_operation AND state='running' AND worker_token=requested_worker RETURNING *;
 IF NOT FOUND THEN RAISE EXCEPTION 'owned restart worker mismatch' USING ERRCODE='55000'; END IF;
END $$;
REVOKE ALL ON FUNCTION secureshop_review.begin_bound_system_restart(uuid,uuid),secureshop_review.fail_bound_system_restart(uuid,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.begin_bound_system_restart(uuid,uuid),secureshop_review.fail_bound_system_restart(uuid,uuid,text) TO dvaia_secureshop_review_runtime;
