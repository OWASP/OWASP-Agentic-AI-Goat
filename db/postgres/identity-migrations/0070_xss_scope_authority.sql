-- Inactive XSS child-scope authority foundation. Production XSS routes do not
-- use these rows until the later run, grading, reset, and deletion gates are
-- activated together.
CREATE TABLE identity.xss_scope_state (
  owner_id integer NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
  owner_key text NOT NULL CHECK(octet_length(owner_key) BETWEEN 8 AND 160),
  scope_key text NOT NULL CHECK(scope_key IN ('reflected','stored_user','stored_llm','email')),
  child_generation bigint NOT NULL DEFAULT 0 CHECK(child_generation >= 0),
  state text NOT NULL DEFAULT 'active' CHECK(state IN ('active','resetting','deleted')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(owner_id,scope_key),
  UNIQUE(owner_id,scope_key,owner_key),
  CHECK(owner_id > 0),
  CHECK(owner_key=('["XSS","'||owner_id::text||'"]'))
);

-- Bindings are retained with their graph run. Ordinary graph-run retention or
-- an explicit authority-owner purge may cascade-delete them; the runtime has
-- no direct UPDATE or DELETE privilege and cannot rewrite their coordinates.
CREATE TABLE identity.xss_run_bindings (
  run_id uuid PRIMARY KEY REFERENCES graph_runtime.runs(run_id) ON DELETE CASCADE,
  owner_id integer NOT NULL,
  owner_key text NOT NULL CHECK(octet_length(owner_key) BETWEEN 8 AND 160),
  scope_key text NOT NULL CHECK(scope_key IN ('reflected','stored_user','stored_llm','email')),
  parent_generation bigint NOT NULL CHECK(parent_generation >= 0),
  child_generation bigint NOT NULL CHECK(child_generation >= 0),
  bound_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY(owner_id,scope_key,owner_key)
    REFERENCES identity.xss_scope_state(owner_id,scope_key,owner_key) ON DELETE CASCADE,
  CHECK(owner_id > 0),
  CHECK(owner_key=('["XSS","'||owner_id::text||'"]'))
);

CREATE INDEX xss_run_bindings_current_scope
  ON identity.xss_run_bindings(owner_id,scope_key,parent_generation,child_generation);

CREATE FUNCTION identity.guard_xss_scope_state_insert() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.child_generation<>0 OR NEW.state<>'active' THEN
    RAISE EXCEPTION 'XSS scope state must start at the initial active generation'
      USING ERRCODE='23514';
  END IF;
  PERFORM 1 FROM identity.users u
    WHERE u.id=NEW.owner_id AND u.is_active=1
      AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_jobs d
        WHERE d.subject_user_id=u.id)
    FOR SHARE OF u;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'XSS scope owner is unavailable' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER xss_scope_state_initial_authority
  BEFORE INSERT ON identity.xss_scope_state
  FOR EACH ROW EXECUTE FUNCTION identity.guard_xss_scope_state_insert();

CREATE FUNCTION identity.guard_xss_run_binding_insert() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  PERFORM 1
    FROM identity.users u
    JOIN graph_runtime.owners o ON o.owner_key=NEW.owner_key
    JOIN graph_runtime.runs r ON r.run_id=NEW.run_id
      AND r.owner_key=o.owner_key AND r.generation=o.generation
    JOIN identity.xss_scope_state s ON s.owner_id=NEW.owner_id
      AND s.owner_key=NEW.owner_key AND s.scope_key=NEW.scope_key
    WHERE u.id=NEW.owner_id AND u.is_active=1
      AND o.generation=NEW.parent_generation
      AND r.status='running'
      AND s.state='active' AND s.child_generation=NEW.child_generation
      AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_jobs d
        WHERE d.subject_user_id=u.id)
      AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_run_blocks b
        WHERE b.owner_key=NEW.owner_key)
    FOR SHARE OF u,o,r,s;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'XSS run scope authority is unavailable' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER xss_run_binding_current_authority
  BEFORE INSERT ON identity.xss_run_bindings
  FOR EACH ROW EXECUTE FUNCTION identity.guard_xss_run_binding_insert();

CREATE FUNCTION identity.guard_xss_run_binding_update() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'XSS run bindings are immutable' USING ERRCODE='55000';
END $$;
CREATE TRIGGER xss_run_binding_immutable
  BEFORE UPDATE ON identity.xss_run_bindings
  FOR EACH ROW EXECUTE FUNCTION identity.guard_xss_run_binding_update();

CREATE FUNCTION identity.bind_xss_run_scope(
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
    ON CONFLICT(owner_id,scope_key) DO NOTHING;
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

CREATE FUNCTION identity.assert_xss_run_scope_current(
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
     OR requested_owner_key IS NULL
     OR requested_owner_key<>( '["XSS","'||requested_owner_id::text||'"]')
     OR requested_scope_key IS NULL
     OR requested_scope_key NOT IN ('reflected','stored_user','stored_llm','email')
     OR requested_parent_generation IS NULL OR requested_parent_generation<0
     OR requested_child_generation IS NULL OR requested_child_generation<0 THEN
    RAISE EXCEPTION 'Invalid XSS run scope' USING ERRCODE='22023';
  END IF;
  RETURN QUERY
    SELECT b.run_id,b.owner_id,b.owner_key,b.scope_key,
      b.parent_generation,b.child_generation
    FROM identity.xss_run_bindings b
    JOIN identity.users u ON u.id=b.owner_id AND u.is_active=1
    JOIN graph_runtime.owners o ON o.owner_key=b.owner_key
      AND o.generation=b.parent_generation
    JOIN graph_runtime.runs r ON r.run_id=b.run_id AND r.owner_key=b.owner_key
      AND r.generation=b.parent_generation AND r.status='running'
    JOIN identity.xss_scope_state s ON s.owner_id=b.owner_id
      AND s.owner_key=b.owner_key AND s.scope_key=b.scope_key
      AND s.child_generation=b.child_generation AND s.state='active'
    WHERE b.run_id=requested_run_id AND b.owner_id=requested_owner_id
      AND b.owner_key=requested_owner_key AND b.scope_key=requested_scope_key
      AND b.parent_generation=requested_parent_generation
      AND b.child_generation=requested_child_generation
      AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_jobs d
        WHERE d.subject_user_id=b.owner_id)
      AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_run_blocks x
        WHERE x.owner_key=b.owner_key)
    FOR SHARE OF b,u,o,r,s;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'XSS run scope authority is unavailable' USING ERRCODE='55000';
  END IF;
END $$;

REVOKE ALL ON identity.xss_scope_state,identity.xss_run_bindings
  FROM PUBLIC,dvaia_identity_runtime;
REVOKE ALL ON FUNCTION identity.guard_xss_scope_state_insert(),
  identity.guard_xss_run_binding_insert(),identity.guard_xss_run_binding_update()
  FROM PUBLIC,dvaia_identity_runtime;
REVOKE ALL ON FUNCTION identity.bind_xss_run_scope(uuid,integer,text,text,bigint),
  identity.assert_xss_run_scope_current(uuid,integer,text,text,bigint,bigint)
  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.bind_xss_run_scope(uuid,integer,text,text,bigint),
  identity.assert_xss_run_scope_current(uuid,integer,text,text,bigint,bigint)
  TO dvaia_identity_runtime;
