-- Keep the runtime unable to delete arbitrary audit rows. The admin endpoint
-- may invoke only this fixed seven-day retention operation after reauthentication.
CREATE FUNCTION identity.clear_old_activity_logs() RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $$
DECLARE removed bigint;
BEGIN
  DELETE FROM identity.activity_logs WHERE timestamp < clock_timestamp() - interval '7 days';
  GET DIAGNOSTICS removed = ROW_COUNT;
  RETURN removed;
END;
$$;
REVOKE ALL ON FUNCTION identity.clear_old_activity_logs() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.clear_old_activity_logs() TO dvaia_identity_runtime;
