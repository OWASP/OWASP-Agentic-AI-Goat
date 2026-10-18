-- Filter the authenticated recovery scope before bounding results, so unrelated
-- older pending operations cannot hide a matching cohort on another device.
CREATE FUNCTION identity.list_bulk_resets_for_scope(a integer,s bigint,kind text,k text) RETURNS jsonb
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE result jsonb;BEGIN
 PERFORM identity.assert_bulk_reset_actor(a,s);
 IF kind IS NULL OR kind NOT IN ('all','workshop') OR (kind='all' AND k IS NOT NULL)
 OR (kind='workshop' AND (k IS NULL OR k !~ '^[a-z][a-z0-9_]{0,95}$'))
 THEN RAISE EXCEPTION 'Invalid reset recovery scope' USING ERRCODE='22023';END IF;
 SELECT COALESCE(jsonb_agg(identity.bulk_reset_snapshot(operation_id)),'[]'::jsonb) INTO result
 FROM (SELECT p.operation_id FROM identity.bulk_reset_operations p
 WHERE p.actor_id=a AND p.request_kind=kind AND (kind='all' OR p.workshop_keys=ARRAY[k])
 AND EXISTS(SELECT 1 FROM identity.bulk_reset_children c WHERE c.operation_id=p.operation_id AND c.state NOT IN ('completed','deleted'))
 ORDER BY p.created_at,p.operation_id LIMIT 1) pending;
 RETURN result;
END $$;
REVOKE ALL ON FUNCTION identity.list_bulk_resets_for_scope(integer,bigint,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.list_bulk_resets_for_scope(integer,bigint,text,text) TO dvaia_identity_runtime;
