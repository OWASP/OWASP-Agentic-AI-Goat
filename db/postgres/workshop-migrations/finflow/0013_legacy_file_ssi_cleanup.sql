-- DRAFT ONLY. Destination-store fence for the identity reset journal.
CREATE TABLE finflow.legacy_file_ssi_cleanup_operations (
 operation_id uuid PRIMARY KEY,
 owner_id bigint NOT NULL CHECK(owner_id > 0),
 from_generation integer NOT NULL CHECK(from_generation >= 0),
 to_generation integer NOT NULL CHECK(to_generation=from_generation+1),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(owner_id,to_generation)
);
ALTER TABLE finflow.legacy_file_ssi_cleanup_operations
 ADD CONSTRAINT legacy_file_ssi_cleanup_operation_identity UNIQUE(operation_id,owner_id,to_generation);
CREATE TABLE finflow.legacy_file_ssi_cleanup_receipts (
 operation_id uuid NOT NULL REFERENCES finflow.legacy_file_ssi_cleanup_operations(operation_id) ON DELETE RESTRICT,
 step_key text NOT NULL CHECK(step_key='legacy_store'),
 owner_id bigint NOT NULL CHECK(owner_id > 0),
 from_generation integer NOT NULL CHECK(from_generation >= 0),
 to_generation integer NOT NULL CHECK(to_generation=from_generation+1),
 completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(operation_id,step_key),
 FOREIGN KEY(operation_id,owner_id,to_generation)
   REFERENCES finflow.legacy_file_ssi_cleanup_operations(operation_id,owner_id,to_generation) ON DELETE RESTRICT
);

-- The migration role may inspect these rows, but even it cannot rewrite a
-- published operation or receipt.  Runtime receives function EXECUTE only.
CREATE FUNCTION finflow.guard_legacy_file_ssi_cleanup_binding()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 RAISE EXCEPTION 'Legacy file/SSI cleanup binding is immutable' USING ERRCODE='23514';
END $$;
CREATE TRIGGER legacy_file_ssi_cleanup_operation_binding_guard BEFORE UPDATE OR DELETE
 ON finflow.legacy_file_ssi_cleanup_operations FOR EACH ROW
 EXECUTE FUNCTION finflow.guard_legacy_file_ssi_cleanup_binding();
CREATE TRIGGER legacy_file_ssi_cleanup_receipt_binding_guard BEFORE UPDATE OR DELETE
 ON finflow.legacy_file_ssi_cleanup_receipts FOR EACH ROW
 EXECUTE FUNCTION finflow.guard_legacy_file_ssi_cleanup_binding();

CREATE FUNCTION finflow.apply_legacy_file_ssi_cleanup(
 p_operation_id uuid,p_owner_id bigint,p_from_generation integer,p_to_generation integer,p_step_key text)
RETURNS TABLE(operation_id uuid,step_key text,owner_id bigint,from_generation integer,to_generation integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE existing finflow.legacy_file_ssi_cleanup_operations%ROWTYPE;
 latest finflow.legacy_file_ssi_cleanup_operations%ROWTYPE;
BEGIN
 IF p_owner_id<=0 OR p_to_generation<>p_from_generation+1
   OR p_step_key IS DISTINCT FROM 'legacy_store' THEN
  RAISE EXCEPTION 'Invalid Legacy file/SSI cleanup scope' USING ERRCODE='23514';
 END IF;
 PERFORM pg_advisory_xact_lock(1936287822,(p_owner_id % 2147483647)::integer);
 SELECT operation.* INTO existing FROM finflow.legacy_file_ssi_cleanup_operations operation
  WHERE operation.operation_id=p_operation_id FOR UPDATE;
 IF FOUND THEN
  IF existing.owner_id<>p_owner_id OR existing.from_generation<>p_from_generation
    OR existing.to_generation<>p_to_generation THEN
   RAISE EXCEPTION 'Legacy file/SSI cleanup scope mismatch' USING ERRCODE='23514';
  END IF;
 ELSE
  SELECT operation.* INTO latest FROM finflow.legacy_file_ssi_cleanup_operations operation
   WHERE operation.owner_id=p_owner_id
   ORDER BY operation.to_generation DESC LIMIT 1 FOR UPDATE;
  IF FOUND AND (p_from_generation<>latest.to_generation OR p_to_generation<=latest.to_generation) THEN
   RAISE EXCEPTION 'Stale Legacy file/SSI cleanup generation' USING ERRCODE='23514';
  END IF;
  INSERT INTO finflow.legacy_file_ssi_cleanup_operations(operation_id,owner_id,from_generation,to_generation)
   VALUES(p_operation_id,p_owner_id,p_from_generation,p_to_generation);
 END IF;
 IF EXISTS(SELECT 1 FROM finflow.legacy_file_ssi_cleanup_receipts r
   WHERE r.operation_id=p_operation_id AND r.step_key=p_step_key) THEN
  RETURN QUERY SELECT p_operation_id,p_step_key,p_owner_id,p_from_generation,p_to_generation; RETURN;
 END IF;
 IF p_step_key='legacy_store' THEN
  -- Legacy manual resets have their own generation lineage.  Advance that
  -- lineage once for this immutable aggregate operation instead of comparing
  -- it with the independent canonical workshop generation.
  INSERT INTO legacy_sensitive.owner_state(user_id,generation) VALUES(p_owner_id,1)
   ON CONFLICT(user_id) DO UPDATE
   SET generation=legacy_sensitive.owner_state.generation+1;
  DELETE FROM legacy_sensitive.access_logs WHERE user_id=p_owner_id;
 END IF;
 INSERT INTO finflow.legacy_file_ssi_cleanup_receipts
  (operation_id,step_key,owner_id,from_generation,to_generation)
 VALUES(p_operation_id,p_step_key,p_owner_id,p_from_generation,p_to_generation);
 RETURN QUERY SELECT p_operation_id,p_step_key,p_owner_id,p_from_generation,p_to_generation;
END $$;

CREATE FUNCTION finflow.read_legacy_file_ssi_cleanup_receipt(p_operation_id uuid,p_step_key text)
RETURNS TABLE(operation_id uuid,step_key text,owner_id bigint,from_generation integer,to_generation integer)
LANGUAGE sql SECURITY DEFINER STABLE SET search_path=pg_catalog AS $$
 SELECT r.operation_id,r.step_key,r.owner_id,r.from_generation,r.to_generation
 FROM finflow.legacy_file_ssi_cleanup_receipts r
 WHERE r.operation_id=p_operation_id AND r.step_key=p_step_key
$$;
REVOKE ALL ON FUNCTION finflow.apply_legacy_file_ssi_cleanup(uuid,bigint,integer,integer,text),
 finflow.read_legacy_file_ssi_cleanup_receipt(uuid,text),
 finflow.guard_legacy_file_ssi_cleanup_binding() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION finflow.apply_legacy_file_ssi_cleanup(uuid,bigint,integer,integer,text),
 finflow.read_legacy_file_ssi_cleanup_receipt(uuid,text) TO dvaia_finflow_runtime;
