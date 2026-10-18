CREATE FUNCTION sensitive_lookup.destroy_student_owner(requested_owner text)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE removed integer;
BEGIN
 IF requested_owner IS NULL OR requested_owner='' OR length(requested_owner)>200 THEN RAISE EXCEPTION 'Valid deletion owner required'; END IF;
 DELETE FROM sensitive_lookup.exploitation_log WHERE user_id=requested_owner;
 GET DIAGNOSTICS removed=ROW_COUNT;
 RETURN removed;
END $$;
REVOKE ALL ON FUNCTION sensitive_lookup.destroy_student_owner(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION sensitive_lookup.destroy_student_owner(text) TO dvaia_sensitive_lookup_runtime;
