-- Forward-only multi-target manager receipt and exact retirement journal.
ALTER TABLE secureshop_review.bound_system_restart_operations
 ADD COLUMN output_text text,
 ADD CONSTRAINT bound_system_restart_output_text_valid CHECK(
  output_text IS NULL OR (
   state='completed' AND octet_length(output_text)<=16384
   AND output_bytes=octet_length(output_text)
   AND output_sha256=sha256(convert_to(output_text,'UTF8'))
  )
 );

CREATE TABLE secureshop_review.bound_system_restart_retirements(
 operation_id uuid PRIMARY KEY,
 target_id uuid NOT NULL REFERENCES secureshop_review.bound_system_restart_targets(target_id),
 launch_id uuid NOT NULL,scenario_id uuid NOT NULL,generation bigint NOT NULL CHECK(generation BETWEEN 1 AND 9007199254740991),
 original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id>0),
 original_platform_session_id integer NOT NULL CHECK(original_platform_session_id>0),
 request_sha256 bytea NOT NULL CHECK(octet_length(request_sha256)=32),
 state text NOT NULL DEFAULT 'admitted' CHECK(state IN('admitted','dispatching','completed')),
 instance_id uuid,generation_before bigint,manager_receipt_sha256 bytea,
 admitted_at timestamptz NOT NULL DEFAULT clock_timestamp(),completed_at timestamptz,
 CHECK((state='admitted' AND instance_id IS NULL AND generation_before IS NULL AND manager_receipt_sha256 IS NULL AND completed_at IS NULL)
   OR(state='dispatching' AND instance_id IS NOT NULL AND generation_before BETWEEN 1 AND 9007199254740991 AND manager_receipt_sha256 IS NULL AND completed_at IS NULL)
   OR(state='completed' AND instance_id IS NOT NULL AND generation_before BETWEEN 1 AND 9007199254740991
      AND octet_length(manager_receipt_sha256)=32 AND completed_at IS NOT NULL))
);
REVOKE ALL ON TABLE secureshop_review.bound_system_restart_retirements FROM PUBLIC;
GRANT SELECT,INSERT ON TABLE secureshop_review.bound_system_restart_retirements TO dvaia_secureshop_review_runtime;

CREATE FUNCTION secureshop_review.guard_bound_system_restart_retirement() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE target secureshop_review.bound_system_restart_targets%ROWTYPE;
BEGIN
 IF TG_OP='INSERT' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||NEW.original_platform_owner_id::text,0));
  SELECT * INTO target FROM secureshop_review.bound_system_restart_targets WHERE target_id=NEW.target_id FOR SHARE;
  IF NOT FOUND OR target.lifecycle<>'active'
    OR ROW(target.launch_id,target.scenario_id,target.generation,target.original_platform_owner_id,target.original_platform_session_id)
      IS DISTINCT FROM ROW(NEW.launch_id,NEW.scenario_id,NEW.generation,NEW.original_platform_owner_id,NEW.original_platform_session_id)
    OR NEW.state<>'admitted' OR NEW.instance_id IS NOT NULL OR NEW.completed_at IS NOT NULL
  THEN RAISE EXCEPTION 'owned restart retirement admission rejected' USING ERRCODE='55000'; END IF;
  RETURN NEW;
 END IF;
 IF TG_OP='DELETE' THEN
  IF EXISTS(SELECT 1 FROM secureshop_review.bound_system_restart_owner_deletion_receipts r WHERE r.original_platform_owner_id=OLD.original_platform_owner_id) THEN RETURN OLD; END IF;
  RAISE EXCEPTION 'owned restart retirement is immutable' USING ERRCODE='55000';
 END IF;
 IF ROW(NEW.operation_id,NEW.target_id,NEW.launch_id,NEW.scenario_id,NEW.generation,NEW.original_platform_owner_id,
    NEW.original_platform_session_id,NEW.request_sha256,NEW.admitted_at)
   IS DISTINCT FROM ROW(OLD.operation_id,OLD.target_id,OLD.launch_id,OLD.scenario_id,OLD.generation,OLD.original_platform_owner_id,
    OLD.original_platform_session_id,OLD.request_sha256,OLD.admitted_at)
 THEN RAISE EXCEPTION 'owned restart retirement identity is immutable' USING ERRCODE='55000'; END IF;
 IF OLD.state='admitted' AND NEW.state='dispatching' THEN RETURN NEW; END IF;
 IF OLD.state='dispatching' AND NEW.state='completed' THEN RETURN NEW; END IF;
 RAISE EXCEPTION 'owned restart retirement transition rejected' USING ERRCODE='55000';
END $$;
CREATE TRIGGER bound_system_restart_retirement_guard BEFORE INSERT OR UPDATE OR DELETE
 ON secureshop_review.bound_system_restart_retirements FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_bound_system_restart_retirement();

CREATE OR REPLACE FUNCTION secureshop_review.complete_bound_system_restart(
 requested_operation uuid,requested_worker uuid,requested_before uuid,requested_after uuid,
 requested_before_generation bigint,requested_after_generation bigint,requested_effect bytea,
 requested_output bytea,requested_output_bytes integer,requested_output_text text)
RETURNS SETOF secureshop_review.bound_system_restart_operations LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE op secureshop_review.bound_system_restart_operations%ROWTYPE; target secureshop_review.bound_system_restart_targets%ROWTYPE;
BEGIN
 SELECT * INTO op FROM secureshop_review.bound_system_restart_operations WHERE operation_id=requested_operation FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'owned restart receipt mismatch' USING ERRCODE='55000'; END IF;
 SELECT * INTO target FROM secureshop_review.bound_system_restart_targets WHERE target_id=op.target_id FOR UPDATE;
 IF NOT FOUND OR requested_worker IS NULL OR requested_before IS NULL OR requested_after IS NULL OR requested_before_generation IS NULL OR requested_after_generation IS NULL
  OR requested_effect IS NULL OR requested_output IS NULL OR requested_output_bytes IS NULL OR requested_output_text IS NULL OR op.state IS DISTINCT FROM 'running'
  OR op.worker_token IS DISTINCT FROM requested_worker OR target.lifecycle IS DISTINCT FROM 'active'
  OR op.before_instance_id IS DISTINCT FROM requested_before OR op.before_generation IS DISTINCT FROM requested_before_generation
  OR target.instance_id IS DISTINCT FROM requested_before OR target.restart_generation IS DISTINCT FROM requested_before_generation
  OR requested_after IS NOT DISTINCT FROM requested_before OR requested_after_generation IS DISTINCT FROM requested_before_generation+1
  OR octet_length(requested_effect) IS DISTINCT FROM 32 OR octet_length(requested_output) IS DISTINCT FROM 32
  OR requested_output_bytes IS DISTINCT FROM octet_length(requested_output_text) OR requested_output_bytes NOT BETWEEN 0 AND 16384
  OR requested_output IS DISTINCT FROM sha256(convert_to(requested_output_text,'UTF8'))
 THEN RAISE EXCEPTION 'owned restart receipt mismatch' USING ERRCODE='55000'; END IF;
 UPDATE secureshop_review.bound_system_restart_targets SET instance_id=requested_after,restart_generation=requested_after_generation WHERE target_id=target.target_id;
 RETURN QUERY UPDATE secureshop_review.bound_system_restart_operations SET state='completed',after_instance_id=requested_after,
  after_generation=requested_after_generation,effect_sha256=requested_effect,output_sha256=requested_output,
  output_bytes=requested_output_bytes,output_text=requested_output_text,completed_at=clock_timestamp()
 WHERE operation_id=requested_operation RETURNING *;
END $$;
REVOKE ALL ON FUNCTION secureshop_review.complete_bound_system_restart(uuid,uuid,uuid,uuid,bigint,bigint,bytea,bytea,integer,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.complete_bound_system_restart(uuid,uuid,uuid,uuid,bigint,bigint,bytea,bytea,integer,text) TO dvaia_secureshop_review_runtime;
REVOKE ALL ON FUNCTION secureshop_review.complete_bound_system_restart(uuid,uuid,uuid,uuid,bigint,bigint,bytea,bytea,integer) FROM dvaia_secureshop_review_runtime;

CREATE FUNCTION secureshop_review.begin_bound_system_restart_retirement(requested_operation uuid)
RETURNS SETOF secureshop_review.bound_system_restart_retirements LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE op secureshop_review.bound_system_restart_retirements%ROWTYPE; target secureshop_review.bound_system_restart_targets%ROWTYPE;
BEGIN
 SELECT * INTO op FROM secureshop_review.bound_system_restart_retirements WHERE operation_id=requested_operation FOR UPDATE;
 IF NOT FOUND OR op.state<>'admitted' THEN RAISE EXCEPTION 'owned restart retirement admission unavailable' USING ERRCODE='55000'; END IF;
 SELECT * INTO target FROM secureshop_review.bound_system_restart_targets WHERE target_id=op.target_id FOR UPDATE;
 IF NOT FOUND OR target.lifecycle<>'active' THEN RAISE EXCEPTION 'owned restart retirement target unavailable' USING ERRCODE='55000'; END IF;
 RETURN QUERY UPDATE secureshop_review.bound_system_restart_retirements SET state='dispatching',instance_id=target.instance_id,
  generation_before=target.restart_generation WHERE operation_id=requested_operation RETURNING *;
END $$;
REVOKE ALL ON FUNCTION secureshop_review.begin_bound_system_restart_retirement(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.begin_bound_system_restart_retirement(uuid) TO dvaia_secureshop_review_runtime;

CREATE FUNCTION secureshop_review.complete_bound_system_restart_retirement(
 requested_operation uuid,requested_instance uuid,requested_generation bigint,requested_receipt bytea)
RETURNS SETOF secureshop_review.bound_system_restart_retirements LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE op secureshop_review.bound_system_restart_retirements%ROWTYPE; target secureshop_review.bound_system_restart_targets%ROWTYPE;
BEGIN
 SELECT * INTO op FROM secureshop_review.bound_system_restart_retirements WHERE operation_id=requested_operation FOR UPDATE;
 IF NOT FOUND OR op.state<>'dispatching' OR requested_instance IS NULL OR requested_generation IS NULL
  OR requested_receipt IS NULL OR octet_length(requested_receipt)<>32
 THEN RAISE EXCEPTION 'owned restart retirement receipt mismatch' USING ERRCODE='55000'; END IF;
 SELECT * INTO target FROM secureshop_review.bound_system_restart_targets WHERE target_id=op.target_id FOR UPDATE;
 IF NOT FOUND OR target.lifecycle<>'active' OR target.instance_id IS DISTINCT FROM requested_instance
  OR target.restart_generation IS DISTINCT FROM requested_generation
  OR op.instance_id IS DISTINCT FROM requested_instance OR op.generation_before IS DISTINCT FROM requested_generation
 THEN RAISE EXCEPTION 'owned restart retirement target mismatch' USING ERRCODE='55000'; END IF;
 RETURN QUERY UPDATE secureshop_review.bound_system_restart_retirements SET state='completed',instance_id=requested_instance,
  generation_before=requested_generation,manager_receipt_sha256=requested_receipt,completed_at=clock_timestamp()
 WHERE operation_id=requested_operation RETURNING *;
END $$;
REVOKE ALL ON FUNCTION secureshop_review.complete_bound_system_restart_retirement(uuid,uuid,bigint,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.complete_bound_system_restart_retirement(uuid,uuid,bigint,bytea) TO dvaia_secureshop_review_runtime;
REVOKE UPDATE ON secureshop_review.bound_system_restart_retirements FROM dvaia_secureshop_review_runtime;

CREATE OR REPLACE FUNCTION secureshop_review.cleanup_bound_system_restart_owner() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE targets bigint;operations bigint;retirements bigint;deleted bigint;digest bytea;
BEGIN
 SELECT count(*) INTO targets FROM secureshop_review.bound_system_restart_targets WHERE original_platform_owner_id=NEW.original_platform_owner_id;
 SELECT count(*) INTO operations FROM secureshop_review.bound_system_restart_operations WHERE original_platform_owner_id=NEW.original_platform_owner_id;
 SELECT count(*) INTO retirements FROM secureshop_review.bound_system_restart_retirements WHERE original_platform_owner_id=NEW.original_platform_owner_id;
 -- Preserve the immutable v1 public receipt contract. Retirement rows are an
 -- internal child journal and are separately counted/verified before deletion.
 digest:=sha256(convert_to(concat_ws(chr(31),'secureshop-owned-restart-owner-deletion-v1',NEW.deletion_job_id::text,
  NEW.original_platform_owner_id::text,targets::text,operations::text),'UTF8'));
 INSERT INTO secureshop_review.bound_system_restart_owner_deletion_receipts(deletion_job_id,original_platform_owner_id,deleted_target_count,deleted_operation_count,receipt_sha256)
 VALUES(NEW.deletion_job_id,NEW.original_platform_owner_id,targets,operations,digest);
 DELETE FROM secureshop_review.bound_system_restart_retirements WHERE original_platform_owner_id=NEW.original_platform_owner_id;GET DIAGNOSTICS deleted=ROW_COUNT;
 IF deleted<>retirements THEN RAISE EXCEPTION 'owned restart retirement cleanup mismatch' USING ERRCODE='55000'; END IF;
 DELETE FROM secureshop_review.bound_system_restart_operations WHERE original_platform_owner_id=NEW.original_platform_owner_id;GET DIAGNOSTICS deleted=ROW_COUNT;
 IF deleted<>operations THEN RAISE EXCEPTION 'owned restart operation cleanup mismatch' USING ERRCODE='55000'; END IF;
 DELETE FROM secureshop_review.bound_system_restart_targets WHERE original_platform_owner_id=NEW.original_platform_owner_id;GET DIAGNOSTICS deleted=ROW_COUNT;
 IF deleted<>targets THEN RAISE EXCEPTION 'owned restart target cleanup mismatch' USING ERRCODE='55000'; END IF;
 RETURN NEW;
END $$;
