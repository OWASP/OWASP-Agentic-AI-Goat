-- DRAFT ONLY. Fixed-purpose owner cleanup; shared mail and solution fixtures remain.
CREATE FUNCTION xss.destroy_student_owner(requested_user_id bigint)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,xss AS $$
DECLARE removed integer:=0; DECLARE n integer;
BEGIN
  IF requested_user_id<1 THEN RAISE EXCEPTION 'Invalid deletion owner' USING ERRCODE='22023'; END IF;
  DELETE FROM xss.template_previews WHERE user_id=requested_user_id; GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
  DELETE FROM xss.email_templates WHERE user_id=requested_user_id; GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
  DELETE FROM xss.email_profiles WHERE user_id=requested_user_id; GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
  DELETE FROM xss.xss_challenge_progress WHERE user_id=requested_user_id; GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
  DELETE FROM xss.xss_email_judge_receipts WHERE user_id=requested_user_id; GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
  DELETE FROM xss.emails WHERE user_key=requested_user_id::text; GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
  DELETE FROM xss.progress WHERE user_key=requested_user_id::text; GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
  DELETE FROM xss.profiles WHERE user_key=requested_user_id::text; GET DIAGNOSTICS n=ROW_COUNT; removed:=removed+n;
  RETURN removed;
END $$;
REVOKE ALL ON FUNCTION xss.destroy_student_owner(bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION xss.destroy_student_owner(bigint) TO dvaia_xss_runtime;
