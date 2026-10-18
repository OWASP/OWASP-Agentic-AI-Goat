-- DRAFT ONLY. Shared documents/objectives and immutable import provenance remain.
CREATE FUNCTION finflow.destroy_student_owner(requested_user_id bigint)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,finflow,legacy_sensitive AS $$
DECLARE removed integer:=0; DECLARE n integer;
BEGIN
  IF requested_user_id<1 THEN RAISE EXCEPTION 'Invalid deletion owner' USING ERRCODE='22023'; END IF;
  DELETE FROM finflow.tool_log WHERE user_id=requested_user_id::text; GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
  DELETE FROM finflow.progress WHERE user_id=requested_user_id::text; GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
  DELETE FROM legacy_sensitive.access_logs WHERE user_id=requested_user_id; GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
  DELETE FROM legacy_sensitive.judgments WHERE user_id=requested_user_id; GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
  DELETE FROM legacy_sensitive.owner_state WHERE user_id=requested_user_id; GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
  RETURN removed;
END $$;
REVOKE ALL ON FUNCTION finflow.destroy_student_owner(bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION finflow.destroy_student_owner(bigint) TO dvaia_finflow_runtime;
