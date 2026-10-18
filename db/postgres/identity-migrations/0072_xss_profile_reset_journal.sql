-- Inactive identity authority for the two-scope XSS profile reset. Routes do
-- not use this journal until lifecycle, Judge, origin and parent gates are
-- activated together.
CREATE TABLE identity.xss_profile_reset_operations (
  operation_id uuid PRIMARY KEY,
  owner_id integer NOT NULL REFERENCES identity.users(id) ON DELETE RESTRICT,
  owner_key text NOT NULL,
  graph_parent_generation bigint NOT NULL CHECK(graph_parent_generation>=0),
  workshop_generation bigint NOT NULL CHECK(workshop_generation>=0),
  stored_user_from bigint NOT NULL CHECK(stored_user_from>=0 AND stored_user_from<9223372036854775807),
  stored_user_to bigint NOT NULL,
  stored_llm_from bigint NOT NULL CHECK(stored_llm_from>=0 AND stored_llm_from<9223372036854775807),
  stored_llm_to bigint NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','running','failed','completed')),
  lease_token uuid,
  lease_expires_at timestamptz,
  failure_code text CHECK(failure_code IS NULL OR failure_code~'^[A-Z][A-Z0-9_]{0,63}$'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  completed_at timestamptz,
  CHECK(owner_id>0),
  CHECK(owner_key=('['||'"XSS"'||','||'"'||owner_id::text||'"'||']')),
  CHECK(stored_user_to=stored_user_from+1),
  CHECK(stored_llm_to=stored_llm_from+1),
  CHECK((lease_token IS NULL)=(lease_expires_at IS NULL)),
  CHECK((status='running')=(lease_token IS NOT NULL)),
  CHECK((status='completed')=(completed_at IS NOT NULL)),
  CHECK(status='failed' OR failure_code IS NULL)
);
CREATE UNIQUE INDEX xss_profile_reset_one_nonterminal_owner
  ON identity.xss_profile_reset_operations(owner_id) WHERE status<>'completed';
CREATE INDEX xss_profile_reset_recovery
  ON identity.xss_profile_reset_operations(status,lease_expires_at,updated_at)
  WHERE status<>'completed';

CREATE TABLE identity.xss_profile_reset_steps (
  operation_id uuid PRIMARY KEY REFERENCES identity.xss_profile_reset_operations(operation_id) ON DELETE RESTRICT,
  step_key text NOT NULL DEFAULT 'xss_store' CHECK(step_key='xss_store'),
  ordinal integer NOT NULL DEFAULT 0 CHECK(ordinal=0),
  status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','failed','completed')),
  attempts integer NOT NULL DEFAULT 0 CHECK(attempts>=0),
  receipt jsonb,
  receipt_sha256 text CHECK(receipt_sha256 IS NULL OR receipt_sha256~'^[0-9a-f]{64}$'),
  failure_code text CHECK(failure_code IS NULL OR failure_code~'^[A-Z][A-Z0-9_]{0,63}$'),
  completed_at timestamptz,
  CHECK((status='completed')=(completed_at IS NOT NULL)),
  CHECK((receipt IS NULL)=(receipt_sha256 IS NULL)),
  CHECK((status='completed')=(receipt IS NOT NULL)),
  CHECK(status='failed' OR failure_code IS NULL)
);

CREATE FUNCTION identity.guard_xss_profile_reset_operation_binding() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' OR NEW.operation_id IS DISTINCT FROM OLD.operation_id
     OR NEW.owner_id IS DISTINCT FROM OLD.owner_id OR NEW.owner_key IS DISTINCT FROM OLD.owner_key
     OR NEW.graph_parent_generation IS DISTINCT FROM OLD.graph_parent_generation
     OR NEW.workshop_generation IS DISTINCT FROM OLD.workshop_generation
     OR NEW.stored_user_from IS DISTINCT FROM OLD.stored_user_from
     OR NEW.stored_user_to IS DISTINCT FROM OLD.stored_user_to
     OR NEW.stored_llm_from IS DISTINCT FROM OLD.stored_llm_from
     OR NEW.stored_llm_to IS DISTINCT FROM OLD.stored_llm_to
     OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'XSS profile reset coordinates are immutable' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER xss_profile_reset_operation_binding_immutable
  BEFORE UPDATE OR DELETE ON identity.xss_profile_reset_operations
  FOR EACH ROW EXECUTE FUNCTION identity.guard_xss_profile_reset_operation_binding();

CREATE FUNCTION identity.guard_xss_profile_reset_step_binding() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' OR NEW.operation_id IS DISTINCT FROM OLD.operation_id
     OR NEW.step_key IS DISTINCT FROM OLD.step_key OR NEW.ordinal IS DISTINCT FROM OLD.ordinal
     OR (OLD.status='completed' AND (NEW.status IS DISTINCT FROM OLD.status
       OR NEW.receipt IS DISTINCT FROM OLD.receipt
       OR NEW.receipt_sha256 IS DISTINCT FROM OLD.receipt_sha256
       OR NEW.completed_at IS DISTINCT FROM OLD.completed_at)) THEN
    RAISE EXCEPTION 'XSS profile reset step binding is immutable' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER xss_profile_reset_step_binding_immutable
  BEFORE UPDATE OR DELETE ON identity.xss_profile_reset_steps
  FOR EACH ROW EXECUTE FUNCTION identity.guard_xss_profile_reset_step_binding();

CREATE FUNCTION identity.begin_xss_profile_reset(
  requested_operation_id uuid, requested_owner_id integer,
  requested_graph_parent_generation bigint, requested_workshop_generation bigint
) RETURNS SETOF identity.xss_profile_reset_operations
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,identity,graph_runtime,workshop_platform AS $$
DECLARE prior identity.xss_profile_reset_operations%ROWTYPE;
DECLARE owner_key_value text;
DECLARE stored_user_generation bigint;
DECLARE stored_llm_generation bigint;
BEGIN
  IF requested_operation_id IS NULL OR requested_owner_id IS NULL OR requested_owner_id<=0
     OR requested_graph_parent_generation IS NULL OR requested_graph_parent_generation<0
     OR requested_workshop_generation IS NULL OR requested_workshop_generation<0 THEN
    RAISE EXCEPTION 'Invalid XSS profile reset coordinates' USING ERRCODE='22023';
  END IF;
  owner_key_value:='["XSS","'||requested_owner_id::text||'"]';
  PERFORM 1 FROM identity.users u WHERE u.id=requested_owner_id AND u.is_active=1
    AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_jobs d WHERE d.subject_user_id=u.id)
    FOR UPDATE OF u;
  IF NOT FOUND THEN RAISE EXCEPTION 'XSS profile reset owner is unavailable' USING ERRCODE='55000'; END IF;
  PERFORM 1 FROM graph_runtime.owners o WHERE o.owner_key=owner_key_value
    AND o.generation=requested_graph_parent_generation FOR SHARE OF o;
  IF NOT FOUND THEN RAISE EXCEPTION 'XSS profile graph parent is unavailable' USING ERRCODE='55000'; END IF;
  INSERT INTO workshop_platform.user_state(user_id,workshop_key)
    VALUES(requested_owner_id,'xss_workshop') ON CONFLICT DO NOTHING;
  PERFORM 1 FROM workshop_platform.user_state w WHERE w.user_id=requested_owner_id
    AND w.workshop_key='xss_workshop' AND w.generation=requested_workshop_generation FOR SHARE OF w;
  IF NOT FOUND THEN RAISE EXCEPTION 'XSS profile workshop parent is unavailable' USING ERRCODE='55000'; END IF;

  SELECT r.* INTO prior FROM identity.xss_profile_reset_operations r
    WHERE r.operation_id=requested_operation_id FOR UPDATE OF r;
  IF FOUND THEN
    IF prior.owner_id IS DISTINCT FROM requested_owner_id
       OR prior.graph_parent_generation IS DISTINCT FROM requested_graph_parent_generation
       OR prior.workshop_generation IS DISTINCT FROM requested_workshop_generation THEN
      RAISE EXCEPTION 'XSS profile reset operation mismatch' USING ERRCODE='22023';
    END IF;
    RETURN NEXT prior; RETURN;
  END IF;
  SELECT r.* INTO prior FROM identity.xss_profile_reset_operations r
    WHERE r.owner_id=requested_owner_id AND r.status<>'completed' FOR UPDATE OF r;
  IF FOUND THEN RAISE EXCEPTION 'XSS profile reset is already in progress' USING ERRCODE='55000'; END IF;

  INSERT INTO identity.xss_scope_state(owner_id,owner_key,scope_key)
    VALUES(requested_owner_id,owner_key_value,'stored_user'),
          (requested_owner_id,owner_key_value,'stored_llm')
    ON CONFLICT ON CONSTRAINT xss_scope_state_pkey DO NOTHING;
  SELECT s.child_generation INTO stored_user_generation FROM identity.xss_scope_state s
    WHERE s.owner_id=requested_owner_id AND s.owner_key=owner_key_value
      AND s.scope_key='stored_user' AND s.state='active' FOR UPDATE OF s;
  IF NOT FOUND OR stored_user_generation>=9223372036854775807 THEN
    RAISE EXCEPTION 'XSS stored_user scope is unavailable' USING ERRCODE='55000';
  END IF;
  SELECT s.child_generation INTO stored_llm_generation FROM identity.xss_scope_state s
    WHERE s.owner_id=requested_owner_id AND s.owner_key=owner_key_value
      AND s.scope_key='stored_llm' AND s.state='active' FOR UPDATE OF s;
  IF NOT FOUND OR stored_llm_generation>=9223372036854775807 THEN
    RAISE EXCEPTION 'XSS stored_llm scope is unavailable' USING ERRCODE='55000';
  END IF;
  UPDATE identity.xss_scope_state SET child_generation=child_generation+1,state='resetting',
    updated_at=clock_timestamp() WHERE owner_id=requested_owner_id
      AND scope_key IN ('stored_user','stored_llm');
  INSERT INTO identity.xss_profile_reset_operations(
    operation_id,owner_id,owner_key,graph_parent_generation,workshop_generation,
    stored_user_from,stored_user_to,stored_llm_from,stored_llm_to
  ) VALUES(requested_operation_id,requested_owner_id,owner_key_value,
    requested_graph_parent_generation,requested_workshop_generation,
    stored_user_generation,stored_user_generation+1,stored_llm_generation,stored_llm_generation+1)
  RETURNING * INTO prior;
  INSERT INTO identity.xss_profile_reset_steps(operation_id) VALUES(requested_operation_id);
  RETURN NEXT prior;
END $$;

CREATE FUNCTION identity.read_xss_profile_reset(requested_operation_id uuid)
RETURNS SETOF identity.xss_profile_reset_operations
LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,identity AS $$
  SELECT r.* FROM identity.xss_profile_reset_operations r
    WHERE r.operation_id=requested_operation_id
$$;

CREATE FUNCTION identity.list_recoverable_xss_profile_resets(requested_limit integer)
RETURNS TABLE(operation_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,identity AS $$
BEGIN
  IF requested_limit IS NULL OR requested_limit<1 OR requested_limit>100 THEN
    RAISE EXCEPTION 'Invalid XSS profile reset recovery limit' USING ERRCODE='22023';
  END IF;
  RETURN QUERY SELECT r.operation_id FROM identity.xss_profile_reset_operations r
    WHERE r.status IN ('pending','failed')
       OR (r.status='running' AND r.lease_expires_at<=clock_timestamp())
    ORDER BY r.updated_at,r.operation_id LIMIT requested_limit;
END $$;

CREATE FUNCTION identity.claim_xss_profile_reset(
  requested_operation_id uuid, requested_lease_token uuid, requested_lease_ms integer
) RETURNS SETOF identity.xss_profile_reset_operations
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,identity AS $$
BEGIN
  IF requested_operation_id IS NULL OR requested_lease_token IS NULL
     OR requested_lease_ms IS NULL OR requested_lease_ms<1000 OR requested_lease_ms>300000 THEN
    RAISE EXCEPTION 'Invalid XSS profile reset lease' USING ERRCODE='22023';
  END IF;
  RETURN QUERY UPDATE identity.xss_profile_reset_operations r
    SET status='running',lease_token=requested_lease_token,
      lease_expires_at=clock_timestamp()+(requested_lease_ms*interval '1 millisecond'),
      failure_code=NULL,updated_at=clock_timestamp()
    WHERE r.operation_id=requested_operation_id AND (r.status IN ('pending','failed')
      OR (r.status='running' AND r.lease_expires_at<=clock_timestamp()))
    RETURNING r.*;
END $$;

CREATE FUNCTION identity.assert_xss_profile_reset_current(
  requested_operation_id uuid, requested_lease_token uuid
) RETURNS SETOF identity.xss_profile_reset_operations
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,identity,graph_runtime,workshop_platform AS $$
BEGIN
  RETURN QUERY SELECT r.* FROM identity.xss_profile_reset_operations r
    JOIN identity.users u ON u.id=r.owner_id AND u.is_active=1
    JOIN graph_runtime.owners o ON o.owner_key=r.owner_key
      AND o.generation=r.graph_parent_generation
    JOIN workshop_platform.user_state w ON w.user_id=r.owner_id
      AND w.workshop_key='xss_workshop' AND w.generation=r.workshop_generation
    JOIN identity.xss_scope_state su ON su.owner_id=r.owner_id AND su.owner_key=r.owner_key
      AND su.scope_key='stored_user' AND su.child_generation=r.stored_user_to AND su.state='resetting'
    JOIN identity.xss_scope_state sl ON sl.owner_id=r.owner_id AND sl.owner_key=r.owner_key
      AND sl.scope_key='stored_llm' AND sl.child_generation=r.stored_llm_to AND sl.state='resetting'
    WHERE r.operation_id=requested_operation_id AND r.status='running'
      AND r.lease_token=requested_lease_token AND r.lease_expires_at>clock_timestamp()
      AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_jobs d WHERE d.subject_user_id=r.owner_id)
    FOR SHARE OF r,u,o,w,su,sl;
END $$;

CREATE FUNCTION identity.acknowledge_xss_profile_reset_store(
  requested_operation_id uuid, requested_lease_token uuid, requested_receipt jsonb
) RETURNS TABLE(receipt_sha256 text,replayed boolean)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,identity,graph_runtime,workshop_platform AS $$
DECLARE operation identity.xss_profile_reset_operations%ROWTYPE;
DECLARE step identity.xss_profile_reset_steps%ROWTYPE;
DECLARE normalized jsonb;
DECLARE calculated text;
BEGIN
  SELECT * INTO operation FROM identity.assert_xss_profile_reset_current(
    requested_operation_id,requested_lease_token);
  IF NOT FOUND THEN RAISE EXCEPTION 'Stale XSS profile reset lease' USING ERRCODE='55000'; END IF;
  IF requested_receipt IS NULL OR jsonb_typeof(requested_receipt)<>'object'
     OR (SELECT count(*) FROM jsonb_object_keys(requested_receipt))<>9
     OR NOT requested_receipt ?& ARRAY['operationId','ownerId','graphParentGeneration',
       'workshopGeneration','children','profileRevisions','originsRemoved','appliedAt','replayed']
     OR jsonb_typeof(requested_receipt->'ownerId')<>'number'
     OR jsonb_typeof(requested_receipt->'children')<>'object'
     OR jsonb_typeof(requested_receipt->'profileRevisions')<>'object'
     OR jsonb_typeof(requested_receipt->'originsRemoved')<>'number'
     OR jsonb_typeof(requested_receipt->'appliedAt')<>'string'
     OR jsonb_typeof(requested_receipt->'replayed')<>'boolean'
     OR (SELECT count(*) FROM jsonb_object_keys(requested_receipt->'children'))<>2
     OR NOT (requested_receipt->'children') ?& ARRAY['stored_user','stored_llm']
     OR jsonb_typeof(requested_receipt#>'{children,stored_user}')<>'object'
     OR jsonb_typeof(requested_receipt#>'{children,stored_llm}')<>'object'
     OR (SELECT count(*) FROM jsonb_object_keys(requested_receipt#>'{children,stored_user}'))<>2
     OR (SELECT count(*) FROM jsonb_object_keys(requested_receipt#>'{children,stored_llm}'))<>2
     OR NOT (requested_receipt#>'{children,stored_user}') ?& ARRAY['from','to']
     OR NOT (requested_receipt#>'{children,stored_llm}') ?& ARRAY['from','to']
     OR (SELECT count(*) FROM jsonb_object_keys(requested_receipt->'profileRevisions'))<>3
     OR NOT (requested_receipt->'profileRevisions') ?& ARRAY['name','bio','website']
     OR requested_receipt->>'operationId'<>operation.operation_id::text
     OR requested_receipt->>'ownerId'!~'^[1-9][0-9]{0,9}$'
     OR (requested_receipt->>'ownerId')::bigint<>operation.owner_id
     OR requested_receipt->>'graphParentGeneration'!~'^(0|[1-9][0-9]{0,18})$'
     OR requested_receipt->>'workshopGeneration'!~'^(0|[1-9][0-9]{0,18})$'
     OR requested_receipt#>>'{children,stored_user,from}'!~'^(0|[1-9][0-9]{0,18})$'
     OR requested_receipt#>>'{children,stored_user,to}'!~'^(0|[1-9][0-9]{0,18})$'
     OR requested_receipt#>>'{children,stored_llm,from}'!~'^(0|[1-9][0-9]{0,18})$'
     OR requested_receipt#>>'{children,stored_llm,to}'!~'^(0|[1-9][0-9]{0,18})$'
     OR (requested_receipt->>'graphParentGeneration')::numeric<>operation.graph_parent_generation
     OR (requested_receipt->>'workshopGeneration')::numeric<>operation.workshop_generation
     OR (requested_receipt#>>'{children,stored_user,from}')::numeric<>operation.stored_user_from
     OR (requested_receipt#>>'{children,stored_user,to}')::numeric<>operation.stored_user_to
     OR (requested_receipt#>>'{children,stored_llm,from}')::numeric<>operation.stored_llm_from
     OR (requested_receipt#>>'{children,stored_llm,to}')::numeric<>operation.stored_llm_to
     OR requested_receipt#>>'{profileRevisions,name}'!~'^[1-9][0-9]{0,18}$'
     OR requested_receipt#>>'{profileRevisions,bio}'!~'^[1-9][0-9]{0,18}$'
     OR requested_receipt#>>'{profileRevisions,website}'!~'^[1-9][0-9]{0,18}$'
     OR (requested_receipt#>>'{profileRevisions,name}')::numeric>9223372036854775807
     OR (requested_receipt#>>'{profileRevisions,bio}')::numeric>9223372036854775807
     OR (requested_receipt#>>'{profileRevisions,website}')::numeric>9223372036854775807
     OR requested_receipt->>'originsRemoved'!~'^(0|[1-9][0-9]{0,9})$'
     OR (requested_receipt->>'originsRemoved')::numeric>2147483647
     OR octet_length(requested_receipt->>'appliedAt') NOT BETWEEN 10 AND 64 THEN
    RAISE EXCEPTION 'Invalid XSS profile reset receipt' USING ERRCODE='22023';
  END IF;
  BEGIN PERFORM (requested_receipt->>'appliedAt')::timestamptz;
  EXCEPTION WHEN others THEN RAISE EXCEPTION 'Invalid XSS profile reset receipt time' USING ERRCODE='22023'; END;
  normalized:=requested_receipt-'replayed';
  calculated:=encode(sha256(convert_to(normalized::text,'UTF8')),'hex');
  SELECT s.* INTO step FROM identity.xss_profile_reset_steps s
    WHERE s.operation_id=requested_operation_id FOR UPDATE OF s;
  IF operation.lease_expires_at<=clock_timestamp() THEN
    RAISE EXCEPTION 'Stale XSS profile reset lease' USING ERRCODE='55000';
  END IF;
  IF step.status='completed' THEN
    IF step.receipt IS DISTINCT FROM normalized OR step.receipt_sha256 IS DISTINCT FROM calculated THEN
      RAISE EXCEPTION 'XSS profile reset receipt mismatch' USING ERRCODE='22023';
    END IF;
    RETURN QUERY SELECT calculated,true; RETURN;
  END IF;
  UPDATE identity.xss_profile_reset_steps s SET status='completed',attempts=attempts+1,
    receipt=normalized,receipt_sha256=calculated,failure_code=NULL,completed_at=clock_timestamp()
    FROM identity.xss_profile_reset_operations r
    WHERE s.operation_id=requested_operation_id AND r.operation_id=s.operation_id
      AND r.status='running' AND r.lease_token=requested_lease_token
      AND r.lease_expires_at>clock_timestamp();
  IF NOT FOUND THEN RAISE EXCEPTION 'Stale XSS profile reset lease' USING ERRCODE='55000'; END IF;
  RETURN QUERY SELECT calculated,false;
END $$;

CREATE FUNCTION identity.fail_xss_profile_reset(
  requested_operation_id uuid, requested_lease_token uuid, requested_failure_code text
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,identity AS $$
BEGIN
  IF requested_failure_code IS NULL OR requested_failure_code!~'^[A-Z][A-Z0-9_]{0,63}$' THEN
    RAISE EXCEPTION 'Invalid XSS profile reset failure code' USING ERRCODE='22023';
  END IF;
  UPDATE identity.xss_profile_reset_steps s SET status='failed',attempts=attempts+1,
    failure_code=requested_failure_code,completed_at=NULL
    FROM identity.xss_profile_reset_operations r
    WHERE s.operation_id=requested_operation_id AND s.status<>'completed'
      AND r.operation_id=s.operation_id AND r.status='running'
      AND r.lease_token=requested_lease_token AND r.lease_expires_at>clock_timestamp();
  UPDATE identity.xss_profile_reset_operations r SET status='failed',
    failure_code=requested_failure_code,lease_token=NULL,lease_expires_at=NULL,
    updated_at=clock_timestamp() WHERE r.operation_id=requested_operation_id
      AND r.status='running' AND r.lease_token=requested_lease_token
      AND r.lease_expires_at>clock_timestamp();
  RETURN FOUND;
END $$;

CREATE FUNCTION identity.complete_xss_profile_reset(
  requested_operation_id uuid, requested_lease_token uuid
) RETURNS SETOF identity.xss_profile_reset_operations
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,identity,graph_runtime,workshop_platform AS $$
DECLARE operation identity.xss_profile_reset_operations%ROWTYPE;
BEGIN
  SELECT * INTO operation FROM identity.assert_xss_profile_reset_current(
    requested_operation_id,requested_lease_token);
  IF NOT FOUND OR NOT EXISTS(SELECT 1 FROM identity.xss_profile_reset_steps s
      WHERE s.operation_id=requested_operation_id AND s.status='completed'
        AND s.receipt IS NOT NULL AND s.receipt_sha256 IS NOT NULL) THEN
    RAISE EXCEPTION 'XSS profile reset is incomplete' USING ERRCODE='55000';
  END IF;
  UPDATE identity.xss_scope_state SET state='active',updated_at=clock_timestamp()
    WHERE owner_id=operation.owner_id AND owner_key=operation.owner_key
      AND ((scope_key='stored_user' AND child_generation=operation.stored_user_to)
        OR (scope_key='stored_llm' AND child_generation=operation.stored_llm_to))
      AND state='resetting';
  IF FOUND THEN
    IF (SELECT count(*) FROM identity.xss_scope_state s WHERE s.owner_id=operation.owner_id
      AND s.owner_key=operation.owner_key AND s.state='active'
      AND ((s.scope_key='stored_user' AND s.child_generation=operation.stored_user_to)
        OR (s.scope_key='stored_llm' AND s.child_generation=operation.stored_llm_to)))<>2 THEN
      RAISE EXCEPTION 'XSS profile reset child state mismatch' USING ERRCODE='55000';
    END IF;
  ELSE
    RAISE EXCEPTION 'XSS profile reset child state mismatch' USING ERRCODE='55000';
  END IF;
  UPDATE identity.xss_profile_reset_operations r SET status='completed',failure_code=NULL,
    lease_token=NULL,lease_expires_at=NULL,completed_at=clock_timestamp(),updated_at=clock_timestamp()
    WHERE r.operation_id=requested_operation_id AND r.status='running'
      AND r.lease_token=requested_lease_token AND r.lease_expires_at>clock_timestamp()
    RETURNING r.* INTO operation;
  IF NOT FOUND THEN RAISE EXCEPTION 'Stale XSS profile reset lease' USING ERRCODE='55000'; END IF;
  RETURN NEXT operation;
END $$;

REVOKE ALL ON identity.xss_profile_reset_operations,identity.xss_profile_reset_steps
  FROM PUBLIC,dvaia_identity_runtime;
REVOKE ALL ON FUNCTION identity.guard_xss_profile_reset_operation_binding(),
  identity.guard_xss_profile_reset_step_binding() FROM PUBLIC,dvaia_identity_runtime;
REVOKE ALL ON FUNCTION identity.begin_xss_profile_reset(uuid,integer,bigint,bigint),
  identity.read_xss_profile_reset(uuid),identity.list_recoverable_xss_profile_resets(integer),
  identity.claim_xss_profile_reset(uuid,uuid,integer),
  identity.assert_xss_profile_reset_current(uuid,uuid),
  identity.acknowledge_xss_profile_reset_store(uuid,uuid,jsonb),
  identity.fail_xss_profile_reset(uuid,uuid,text),
  identity.complete_xss_profile_reset(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.begin_xss_profile_reset(uuid,integer,bigint,bigint),
  identity.read_xss_profile_reset(uuid),identity.list_recoverable_xss_profile_resets(integer),
  identity.claim_xss_profile_reset(uuid,uuid,integer),
  identity.assert_xss_profile_reset_current(uuid,uuid),
  identity.acknowledge_xss_profile_reset_store(uuid,uuid,jsonb),
  identity.fail_xss_profile_reset(uuid,uuid,text),
  identity.complete_xss_profile_reset(uuid,uuid) TO dvaia_identity_runtime;
