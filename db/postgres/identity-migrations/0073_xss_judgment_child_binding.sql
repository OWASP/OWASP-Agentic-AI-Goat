-- Inactive XSS Judge child-authority binding. Existing unscoped judgments keep
-- their historical behavior until XSS routes opt into protected scoped runs.
CREATE TABLE identity.xss_judgment_bindings (
  user_id integer NOT NULL,
  evaluation_id uuid NOT NULL,
  run_id uuid NOT NULL,
  owner_id integer NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
  owner_key text NOT NULL CHECK(octet_length(owner_key) BETWEEN 8 AND 160),
  scope_key text NOT NULL CHECK(scope_key IN ('reflected','stored_user','stored_llm','email')),
  parent_generation bigint NOT NULL CHECK(parent_generation >= 0),
  workshop_generation bigint NOT NULL CHECK(workshop_generation >= 0),
  child_generation bigint NOT NULL CHECK(child_generation >= 0),
  bound_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(user_id,evaluation_id),
  FOREIGN KEY(user_id,evaluation_id)
    REFERENCES workshop_platform.objective_judgments(user_id,evaluation_id) ON DELETE CASCADE,
  CHECK(owner_id=user_id),
  CHECK(owner_key=('['||chr(34)||'XSS'||chr(34)||','||chr(34)||owner_id::text||chr(34)||']'))
);

CREATE INDEX xss_judgment_bindings_current_scope
  ON identity.xss_judgment_bindings(owner_id,scope_key,parent_generation,
    workshop_generation,child_generation);

CREATE FUNCTION identity.guard_xss_judgment_binding_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'XSS judgment bindings are immutable' USING ERRCODE='55000';
END $$;
CREATE TRIGGER xss_judgment_binding_immutable
  BEFORE UPDATE ON identity.xss_judgment_bindings
  FOR EACH ROW EXECUTE FUNCTION identity.guard_xss_judgment_binding_update();

-- Serialize the existence decision even while the run has no binding row. A
-- scoped binding and an unbound XSS judgment for the same run are mutually
-- exclusive regardless of which transaction arrives first.
CREATE FUNCTION identity.guard_xss_run_binding_judgment_exclusion() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('xss-judgment-run:'||NEW.run_id::text,0));
  IF EXISTS(
    SELECT 1 FROM workshop_platform.objective_judgments j
    WHERE j.run_id=NEW.run_id AND j.workshop_key='xss_workshop'
      AND NOT EXISTS(SELECT 1 FROM identity.xss_judgment_bindings b
        WHERE b.user_id=j.user_id AND b.evaluation_id=j.evaluation_id)
  ) THEN
    RAISE EXCEPTION 'Unbound XSS judgment already exists for graph run' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER xss_run_binding_judgment_exclusion
  BEFORE INSERT ON identity.xss_run_bindings
  FOR EACH ROW EXECUTE FUNCTION identity.guard_xss_run_binding_judgment_exclusion();

-- Replace the public binder so the common run admission lock is the first
-- acquired lock, before user/graph/child rows. The insert trigger independently
-- protects migration-role direct inserts.
CREATE OR REPLACE FUNCTION identity.bind_xss_run_scope(
  requested_run_id uuid, requested_owner_id integer, requested_owner_key text,
  requested_scope_key text, requested_parent_generation bigint
) RETURNS TABLE(
  run_id uuid, owner_id integer, owner_key text, scope_key text,
  parent_generation bigint, child_generation bigint
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,identity,graph_runtime,workshop_platform AS $$
DECLARE bound_child_generation bigint;
BEGIN
  IF requested_run_id IS NULL OR requested_owner_id IS NULL OR requested_owner_id<=0
     OR requested_owner_key IS NULL
     OR requested_owner_key<>( '['||chr(34)||'XSS'||chr(34)||','||chr(34)||requested_owner_id::text||chr(34)||']')
     OR requested_scope_key IS NULL
     OR requested_scope_key NOT IN ('reflected','stored_user','stored_llm','email')
     OR requested_parent_generation IS NULL OR requested_parent_generation<0 THEN
    RAISE EXCEPTION 'Invalid XSS run scope' USING ERRCODE='22023';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('xss-judgment-run:'||requested_run_id::text,0));
  IF EXISTS(
    SELECT 1 FROM workshop_platform.objective_judgments j
    WHERE j.run_id=requested_run_id AND j.workshop_key='xss_workshop'
      AND NOT EXISTS(SELECT 1 FROM identity.xss_judgment_bindings b
        WHERE b.user_id=j.user_id AND b.evaluation_id=j.evaluation_id)
  ) THEN
    RAISE EXCEPTION 'Unbound XSS judgment already exists for graph run' USING ERRCODE='55000';
  END IF;
  PERFORM 1 FROM identity.users u
    WHERE u.id=requested_owner_id AND u.is_active=1
      AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_jobs d
        WHERE d.subject_user_id=u.id)
    FOR SHARE OF u;
  IF NOT FOUND THEN RAISE EXCEPTION 'XSS scope owner is unavailable' USING ERRCODE='55000'; END IF;
  PERFORM 1 FROM graph_runtime.owners o
    WHERE o.owner_key=requested_owner_key AND o.generation=requested_parent_generation
    FOR SHARE OF o;
  IF NOT FOUND THEN RAISE EXCEPTION 'XSS graph owner is unavailable' USING ERRCODE='55000'; END IF;
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
  IF NOT FOUND THEN RAISE EXCEPTION 'XSS child scope is unavailable' USING ERRCODE='55000'; END IF;
  INSERT INTO identity.xss_run_bindings(
    run_id,owner_id,owner_key,scope_key,parent_generation,child_generation
  ) VALUES(requested_run_id,requested_owner_id,requested_owner_key,requested_scope_key,
    requested_parent_generation,bound_child_generation);
  RETURN QUERY SELECT b.run_id,b.owner_id,b.owner_key,b.scope_key,
    b.parent_generation,b.child_generation FROM identity.xss_run_bindings b
    WHERE b.run_id=requested_run_id;
END $$;

-- Called before the workshop user_state lock. Locks identity user, graph owner,
-- graph run, and the exact run binding in that order.
CREATE FUNCTION identity.lock_xss_judgment_run_prefix(
  requested_run_id uuid, requested_owner_id integer, requested_owner_key text,
  requested_scope_key text, requested_parent_generation bigint,
  requested_child_generation bigint
) RETURNS TABLE(
  run_id uuid, owner_id integer, owner_key text, scope_key text,
  parent_generation bigint, child_generation bigint
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,identity,graph_runtime AS $$
BEGIN
  IF requested_run_id IS NULL OR requested_owner_id IS NULL OR requested_owner_id<=0
     OR requested_owner_key<>( '['||chr(34)||'XSS'||chr(34)||','||chr(34)||requested_owner_id::text||chr(34)||']')
     OR requested_scope_key NOT IN ('reflected','stored_user','stored_llm','email')
     OR requested_parent_generation IS NULL OR requested_parent_generation<0
     OR requested_child_generation IS NULL OR requested_child_generation<0 THEN
    RAISE EXCEPTION 'Invalid XSS judgment scope' USING ERRCODE='22023';
  END IF;
  PERFORM 1 FROM identity.users u
    WHERE u.id=requested_owner_id AND u.is_active=1
      AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_jobs d WHERE d.subject_user_id=u.id)
    FOR SHARE OF u;
  IF NOT FOUND THEN RAISE EXCEPTION 'XSS judgment owner is unavailable' USING ERRCODE='55000'; END IF;
  IF EXISTS(SELECT 1 FROM identity.student_deletion_run_blocks b WHERE b.owner_key=requested_owner_key) THEN
    RAISE EXCEPTION 'XSS judgment owner is being deleted' USING ERRCODE='55000';
  END IF;
  PERFORM 1 FROM graph_runtime.owners o
    WHERE o.owner_key=requested_owner_key AND o.generation=requested_parent_generation
    FOR SHARE OF o;
  IF NOT FOUND THEN RAISE EXCEPTION 'XSS judgment parent is unavailable' USING ERRCODE='55000'; END IF;
  PERFORM 1 FROM graph_runtime.runs r
    WHERE r.run_id=requested_run_id AND r.owner_key=requested_owner_key
      AND r.generation=requested_parent_generation AND r.status='running'
    FOR SHARE OF r;
  IF NOT FOUND THEN RAISE EXCEPTION 'XSS judgment run is unavailable' USING ERRCODE='55000'; END IF;
  PERFORM 1 FROM identity.xss_run_bindings b
    WHERE b.run_id=requested_run_id AND b.owner_id=requested_owner_id
      AND b.owner_key=requested_owner_key AND b.scope_key=requested_scope_key
      AND b.parent_generation=requested_parent_generation
      AND b.child_generation=requested_child_generation
    FOR SHARE OF b;
  IF NOT FOUND THEN RAISE EXCEPTION 'XSS judgment run binding is unavailable' USING ERRCODE='55000'; END IF;
  RETURN QUERY SELECT b.run_id,b.owner_id,b.owner_key,b.scope_key,
    b.parent_generation,b.child_generation FROM identity.xss_run_bindings b
    WHERE b.run_id=requested_run_id;
END $$;

-- Loads and locks the immutable identity/graph prefix of an existing judgment.
-- An unbound historical judgment deliberately returns no row.
CREATE FUNCTION identity.lock_xss_judgment_prefix(
  requested_user_id integer, requested_evaluation_id uuid
) RETURNS TABLE(
  run_id uuid, owner_id integer, owner_key text, scope_key text,
  parent_generation bigint, child_generation bigint
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,identity,graph_runtime AS $$
DECLARE binding identity.xss_judgment_bindings%ROWTYPE;
BEGIN
  IF requested_user_id IS NULL OR requested_user_id<=0 OR requested_evaluation_id IS NULL THEN
    RAISE EXCEPTION 'Invalid XSS judgment coordinates' USING ERRCODE='22023';
  END IF;
  SELECT b.* INTO binding FROM identity.xss_judgment_bindings b
    WHERE b.user_id=requested_user_id AND b.evaluation_id=requested_evaluation_id;
  IF NOT FOUND THEN RETURN; END IF;
  PERFORM 1 FROM identity.users u
    WHERE u.id=binding.owner_id AND u.is_active=1
      AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_jobs d WHERE d.subject_user_id=u.id)
    FOR SHARE OF u;
  IF NOT FOUND OR EXISTS(SELECT 1 FROM identity.student_deletion_run_blocks x
      WHERE x.owner_key=binding.owner_key) THEN
    RAISE EXCEPTION 'XSS judgment owner is unavailable' USING ERRCODE='55000';
  END IF;
  PERFORM 1 FROM graph_runtime.owners o
    WHERE o.owner_key=binding.owner_key AND o.generation=binding.parent_generation
    FOR SHARE OF o;
  IF NOT FOUND THEN RAISE EXCEPTION 'XSS judgment parent is unavailable' USING ERRCODE='55000'; END IF;
  PERFORM 1 FROM graph_runtime.runs r
    WHERE r.run_id=binding.run_id AND r.owner_key=binding.owner_key
      AND r.generation=binding.parent_generation
    FOR SHARE OF r;
  IF NOT FOUND THEN RAISE EXCEPTION 'XSS judgment run is unavailable' USING ERRCODE='55000'; END IF;
  PERFORM 1 FROM identity.xss_run_bindings b
    WHERE b.run_id=binding.run_id AND b.owner_id=binding.owner_id
      AND b.owner_key=binding.owner_key AND b.scope_key=binding.scope_key
      AND b.parent_generation=binding.parent_generation
      AND b.child_generation=binding.child_generation
    FOR SHARE OF b;
  IF NOT FOUND THEN RAISE EXCEPTION 'XSS judgment run binding is unavailable' USING ERRCODE='55000'; END IF;
  RETURN QUERY SELECT binding.run_id,binding.owner_id,binding.owner_key,binding.scope_key,
    binding.parent_generation,binding.child_generation;
END $$;

-- A protected scoped run can never silently downgrade to an unbound judgment.
-- Legacy route runs have no xss_run_bindings row and remain compatible until
-- route activation opts them into scoped admission.
CREATE FUNCTION identity.xss_run_is_scoped(requested_run_id uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,identity AS $$
  SELECT requested_run_id IS NOT NULL AND EXISTS(
    SELECT 1 FROM identity.xss_run_bindings b WHERE b.run_id=requested_run_id
  )
$$;

CREATE FUNCTION identity.assert_xss_run_unscoped_for_judgment(requested_run_id uuid)
RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,identity AS $$
BEGIN
  IF requested_run_id IS NULL THEN RETURN true; END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('xss-judgment-run:'||requested_run_id::text,0));
  IF EXISTS(SELECT 1 FROM identity.xss_run_bindings b WHERE b.run_id=requested_run_id) THEN
    RAISE EXCEPTION 'Protected XSS run requires exact child scope' USING ERRCODE='55000';
  END IF;
  RETURN true;
END $$;

-- Called only after workshop_platform.user_state is locked by the caller.
CREATE FUNCTION identity.bind_xss_judgment_scope(
  requested_user_id integer, requested_evaluation_id uuid, requested_run_id uuid,
  requested_owner_id integer, requested_owner_key text, requested_scope_key text,
  requested_parent_generation bigint, requested_child_generation bigint,
  requested_workshop_generation bigint
) RETURNS TABLE(
  run_id uuid, owner_id integer, owner_key text, scope_key text,
  parent_generation bigint, child_generation bigint
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,identity,graph_runtime,workshop_platform AS $$
DECLARE expected_scope text; stored identity.xss_judgment_bindings%ROWTYPE;
BEGIN
  SELECT CASE
      WHEN j.objective_id IN ('xss_r1','xss_r2','xss_r3') THEN 'reflected'
      WHEN j.objective_id IN ('xss_s1','xss_s2','xss_s3') THEN 'stored_user'
      WHEN j.objective_id IN ('xss_g1','xss_g2','xss_g3') THEN 'stored_llm'
      WHEN j.objective_id IN ('xss_e1','xss_e2','xss_e3') THEN 'email'
    END INTO expected_scope
    FROM workshop_platform.objective_judgments j
    WHERE j.user_id=requested_user_id AND j.evaluation_id=requested_evaluation_id
      AND j.workshop_key='xss_workshop' AND j.run_id=requested_run_id
      AND j.generation=requested_workshop_generation;
  IF expected_scope IS NULL OR expected_scope<>requested_scope_key
     OR requested_owner_id<>requested_user_id THEN
    RAISE EXCEPTION 'XSS judgment objective scope mismatch' USING ERRCODE='55000';
  END IF;
  PERFORM 1 FROM identity.xss_run_bindings b
    WHERE b.run_id=requested_run_id AND b.owner_id=requested_owner_id
      AND b.owner_key=requested_owner_key AND b.scope_key=requested_scope_key
      AND b.parent_generation=requested_parent_generation
      AND b.child_generation=requested_child_generation
    FOR SHARE OF b;
  IF NOT FOUND THEN RAISE EXCEPTION 'XSS judgment run binding is unavailable' USING ERRCODE='55000'; END IF;
  PERFORM 1 FROM identity.xss_scope_state s
    WHERE s.owner_id=requested_owner_id AND s.owner_key=requested_owner_key
      AND s.scope_key=requested_scope_key AND s.state='active'
      AND s.child_generation=requested_child_generation
    FOR SHARE OF s;
  IF NOT FOUND THEN RAISE EXCEPTION 'XSS judgment child is unavailable' USING ERRCODE='55000'; END IF;
  INSERT INTO identity.xss_judgment_bindings(
    user_id,evaluation_id,run_id,owner_id,owner_key,scope_key,
    parent_generation,workshop_generation,child_generation
  ) VALUES(
    requested_user_id,requested_evaluation_id,requested_run_id,requested_owner_id,
    requested_owner_key,requested_scope_key,requested_parent_generation,
    requested_workshop_generation,requested_child_generation
  ) ON CONFLICT(user_id,evaluation_id) DO NOTHING;
  SELECT b.* INTO stored FROM identity.xss_judgment_bindings b
    WHERE b.user_id=requested_user_id AND b.evaluation_id=requested_evaluation_id;
  IF stored.run_id<>requested_run_id OR stored.owner_id<>requested_owner_id
     OR stored.owner_key<>requested_owner_key OR stored.scope_key<>requested_scope_key
     OR stored.parent_generation<>requested_parent_generation
     OR stored.workshop_generation<>requested_workshop_generation
     OR stored.child_generation<>requested_child_generation THEN
    RAISE EXCEPTION 'XSS judgment binding conflict' USING ERRCODE='55000';
  END IF;
  RETURN QUERY SELECT stored.run_id,stored.owner_id,stored.owner_key,stored.scope_key,
    stored.parent_generation,stored.child_generation;
END $$;

-- Called after the exact workshop generation row is locked by the caller.
CREATE FUNCTION identity.assert_xss_judgment_child_current(
  requested_user_id integer, requested_evaluation_id uuid,
  requested_workshop_generation bigint
) RETURNS TABLE(
  run_id uuid, owner_id integer, owner_key text, scope_key text,
  parent_generation bigint, child_generation bigint
)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,identity,workshop_platform AS $$
DECLARE binding identity.xss_judgment_bindings%ROWTYPE;
BEGIN
  SELECT b.* INTO binding FROM identity.xss_judgment_bindings b
    WHERE b.user_id=requested_user_id AND b.evaluation_id=requested_evaluation_id;
  IF NOT FOUND OR binding.workshop_generation<>requested_workshop_generation THEN
    RAISE EXCEPTION 'XSS judgment workshop authority is unavailable' USING ERRCODE='55000';
  END IF;
  PERFORM 1 FROM workshop_platform.user_state w
    WHERE w.user_id=requested_user_id AND w.workshop_key='xss_workshop'
      AND w.generation=requested_workshop_generation
    FOR SHARE OF w;
  IF NOT FOUND THEN RAISE EXCEPTION 'XSS judgment workshop is unavailable' USING ERRCODE='55000'; END IF;
  PERFORM 1 FROM identity.xss_scope_state s
    WHERE s.owner_id=binding.owner_id AND s.owner_key=binding.owner_key
      AND s.scope_key=binding.scope_key AND s.state='active'
      AND s.child_generation=binding.child_generation
    FOR SHARE OF s;
  IF NOT FOUND THEN RAISE EXCEPTION 'XSS judgment child is unavailable' USING ERRCODE='55000'; END IF;
  RETURN QUERY SELECT binding.run_id,binding.owner_id,binding.owner_key,binding.scope_key,
    binding.parent_generation,binding.child_generation;
END $$;

-- Lock-free, bounded recovery eligibility. It exposes one boolean and never
-- grants runtime visibility into authority coordinates or sibling rows.
CREATE FUNCTION identity.xss_judgment_binding_is_current(
  requested_user_id integer, requested_evaluation_id uuid
) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,identity,graph_runtime,workshop_platform AS $$
  SELECT CASE WHEN NOT EXISTS(
      SELECT 1 FROM identity.xss_judgment_bindings b
      WHERE b.user_id=requested_user_id AND b.evaluation_id=requested_evaluation_id
    ) THEN NOT EXISTS(
      SELECT 1 FROM workshop_platform.objective_judgments j
      JOIN identity.xss_run_bindings rb ON rb.run_id=j.run_id
      WHERE j.user_id=requested_user_id AND j.evaluation_id=requested_evaluation_id
    ) ELSE EXISTS(
      SELECT 1 FROM identity.xss_judgment_bindings b
      JOIN identity.users u ON u.id=b.owner_id AND u.is_active=1
      JOIN graph_runtime.owners o ON o.owner_key=b.owner_key
        AND o.generation=b.parent_generation
      JOIN identity.xss_run_bindings rb ON rb.run_id=b.run_id
        AND rb.owner_id=b.owner_id AND rb.owner_key=b.owner_key
        AND rb.scope_key=b.scope_key AND rb.parent_generation=b.parent_generation
        AND rb.child_generation=b.child_generation
      JOIN identity.xss_scope_state s ON s.owner_id=b.owner_id
        AND s.owner_key=b.owner_key AND s.scope_key=b.scope_key
        AND s.state='active' AND s.child_generation=b.child_generation
      JOIN workshop_platform.user_state w ON w.user_id=b.user_id
        AND w.workshop_key='xss_workshop' AND w.generation=b.workshop_generation
      WHERE b.user_id=requested_user_id AND b.evaluation_id=requested_evaluation_id
        AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_jobs d
          WHERE d.subject_user_id=b.owner_id)
        AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_run_blocks x
          WHERE x.owner_key=b.owner_key)
    ) END
$$;

REVOKE ALL ON identity.xss_judgment_bindings FROM PUBLIC,dvaia_identity_runtime;
REVOKE ALL ON FUNCTION identity.guard_xss_judgment_binding_update(),
  identity.guard_xss_run_binding_judgment_exclusion(),
  identity.lock_xss_judgment_run_prefix(uuid,integer,text,text,bigint,bigint),
  identity.lock_xss_judgment_prefix(integer,uuid),
  identity.xss_run_is_scoped(uuid),
  identity.assert_xss_run_unscoped_for_judgment(uuid),
  identity.bind_xss_judgment_scope(integer,uuid,uuid,integer,text,text,bigint,bigint,bigint),
  identity.assert_xss_judgment_child_current(integer,uuid,bigint),
  identity.xss_judgment_binding_is_current(integer,uuid)
  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
  identity.lock_xss_judgment_run_prefix(uuid,integer,text,text,bigint,bigint),
  identity.lock_xss_judgment_prefix(integer,uuid),
  identity.xss_run_is_scoped(uuid),
  identity.assert_xss_run_unscoped_for_judgment(uuid),
  identity.bind_xss_judgment_scope(integer,uuid,uuid,integer,text,text,bigint,bigint,bigint),
  identity.assert_xss_judgment_child_current(integer,uuid,bigint),
  identity.xss_judgment_binding_is_current(integer,uuid)
  TO dvaia_identity_runtime;
