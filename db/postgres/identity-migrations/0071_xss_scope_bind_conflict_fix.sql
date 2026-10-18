-- 0070 used column-list ON CONFLICT inside a RETURNS TABLE PL/pgSQL function;
-- its output variables make owner_id/scope_key ambiguous (42702). Preserve the
-- applied migration and replace only this function with the named constraint.
CREATE OR REPLACE FUNCTION identity.bind_xss_run_scope(
  requested_run_id uuid, requested_owner_id integer, requested_owner_key text,
  requested_scope_key text, requested_parent_generation bigint
) RETURNS TABLE(
  run_id uuid, owner_id integer, owner_key text, scope_key text,
  parent_generation bigint, child_generation bigint
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,identity,graph_runtime AS $$
DECLARE bound_child_generation bigint;
BEGIN
  IF requested_run_id IS NULL OR requested_owner_id IS NULL OR requested_owner_id<=0
     OR requested_owner_key IS NULL
     OR requested_owner_key<>( '["XSS","'||requested_owner_id::text||'"]')
     OR requested_scope_key IS NULL
     OR requested_scope_key NOT IN ('reflected','stored_user','stored_llm','email')
     OR requested_parent_generation IS NULL OR requested_parent_generation<0 THEN
    RAISE EXCEPTION 'Invalid XSS run scope' USING ERRCODE='22023';
  END IF;
  PERFORM 1 FROM identity.users u
    WHERE u.id=requested_owner_id AND u.is_active=1
      AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_jobs d
        WHERE d.subject_user_id=u.id)
    FOR SHARE OF u;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'XSS scope owner is unavailable' USING ERRCODE='55000';
  END IF;
  PERFORM 1 FROM graph_runtime.owners o
    WHERE o.owner_key=requested_owner_key
      AND o.generation=requested_parent_generation
    FOR SHARE OF o;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'XSS graph owner is unavailable' USING ERRCODE='55000';
  END IF;
  PERFORM 1 FROM graph_runtime.runs r
    WHERE r.run_id=requested_run_id AND r.owner_key=requested_owner_key
      AND r.generation=requested_parent_generation AND r.status='running'
    FOR SHARE OF r;
  IF NOT FOUND OR EXISTS(SELECT 1 FROM identity.student_deletion_run_blocks b
      WHERE b.owner_key=requested_owner_key) THEN
    RAISE EXCEPTION 'XSS graph run is unavailable' USING ERRCODE='55000';
  END IF;
  INSERT INTO identity.xss_scope_state(owner_id,owner_key,scope_key)
    VALUES(requested_owner_id,requested_owner_key,requested_scope_key)
    ON CONFLICT ON CONSTRAINT xss_scope_state_pkey DO NOTHING;
  SELECT s.child_generation INTO bound_child_generation
    FROM identity.xss_scope_state s
    WHERE s.owner_id=requested_owner_id AND s.owner_key=requested_owner_key
      AND s.scope_key=requested_scope_key AND s.state='active'
    FOR SHARE OF s;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'XSS child scope is unavailable' USING ERRCODE='55000';
  END IF;
  INSERT INTO identity.xss_run_bindings(
    run_id,owner_id,owner_key,scope_key,parent_generation,child_generation
  ) VALUES(
    requested_run_id,requested_owner_id,requested_owner_key,requested_scope_key,
    requested_parent_generation,bound_child_generation
  );
  RETURN QUERY SELECT b.run_id,b.owner_id,b.owner_key,b.scope_key,
    b.parent_generation,b.child_generation
    FROM identity.xss_run_bindings b WHERE b.run_id=requested_run_id;
END $$;

REVOKE ALL ON FUNCTION identity.bind_xss_run_scope(uuid,integer,text,text,bigint)
  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.bind_xss_run_scope(uuid,integer,text,text,bigint)
  TO dvaia_identity_runtime;
