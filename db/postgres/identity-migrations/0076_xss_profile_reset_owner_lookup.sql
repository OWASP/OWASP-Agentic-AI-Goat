-- Internal owner-scoped lookup for parent-reset composition. This does not
-- grant journal table visibility or mutate reset authority.
CREATE FUNCTION identity.read_nonterminal_xss_profile_reset_for_owner(
  requested_owner_id integer
) RETURNS SETOF identity.xss_profile_reset_operations
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,identity AS $$
BEGIN
  IF requested_owner_id IS NULL OR requested_owner_id<=0 THEN
    RAISE EXCEPTION 'Invalid XSS profile reset owner' USING ERRCODE='22023';
  END IF;
  PERFORM 1 FROM identity.users u
    WHERE u.id=requested_owner_id AND u.is_active=1
      AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_jobs d
        WHERE d.subject_user_id=u.id)
    FOR SHARE OF u;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'XSS profile reset owner is unavailable' USING ERRCODE='55000';
  END IF;
  RETURN QUERY SELECT r.* FROM identity.xss_profile_reset_operations r
    WHERE r.owner_id=requested_owner_id
      AND r.status NOT IN ('completed','superseded');
END $$;

REVOKE ALL ON FUNCTION identity.read_nonterminal_xss_profile_reset_for_owner(integer)
  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.read_nonterminal_xss_profile_reset_for_owner(integer)
  TO dvaia_identity_runtime;
