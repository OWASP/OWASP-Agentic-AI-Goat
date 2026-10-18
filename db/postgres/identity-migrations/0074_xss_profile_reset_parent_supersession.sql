-- Forward-only parent-supersession recovery for the inactive XSS profile reset
-- journal. Applied 0072/0073 bytes remain immutable.
ALTER TABLE identity.xss_profile_reset_operations
  DROP CONSTRAINT xss_profile_reset_operations_status_check,
  DROP CONSTRAINT xss_profile_reset_operations_check2,
  DROP CONSTRAINT xss_profile_reset_operations_check3;
ALTER TABLE identity.xss_profile_reset_operations
  ADD COLUMN reconciliation_kind text,
  ADD COLUMN reconciliation_sha256 text,
  ADD COLUMN reconciled_graph_parent_generation bigint,
  ADD COLUMN reconciled_workshop_generation bigint,
  ADD CONSTRAINT xss_profile_reset_operations_status_check
    CHECK(status IN ('pending','running','failed','completed','superseded')),
  ADD CONSTRAINT xss_profile_reset_operations_terminal_time_check
    CHECK((status IN ('completed','superseded'))=(completed_at IS NOT NULL)),
  ADD CONSTRAINT xss_profile_reset_operations_failure_check
    CHECK(status IN ('failed','superseded') OR failure_code IS NULL),
  ADD CONSTRAINT xss_profile_reset_operations_reconciliation_check CHECK(
    (status='superseded')=(reconciliation_kind IS NOT NULL)
    AND (reconciliation_kind IS NULL)=(reconciliation_sha256 IS NULL)
    AND (reconciliation_kind IS NULL)=(reconciled_graph_parent_generation IS NULL)
    AND (reconciliation_kind IS NULL)=(reconciled_workshop_generation IS NULL)
    AND (reconciliation_kind IS NULL OR reconciliation_kind IN ('retired_no_effect','committed'))
    AND (reconciliation_sha256 IS NULL OR reconciliation_sha256~'^[0-9a-f]{64}$')
    AND (reconciled_graph_parent_generation IS NULL OR reconciled_graph_parent_generation>=0)
    AND (reconciled_workshop_generation IS NULL OR reconciled_workshop_generation>=0)
    AND (status<>'superseded' OR failure_code='PARENT_RESET_SUPERSEDED')
  );

DROP INDEX identity.xss_profile_reset_one_nonterminal_owner;
DROP INDEX identity.xss_profile_reset_recovery;
CREATE UNIQUE INDEX xss_profile_reset_one_nonterminal_owner
  ON identity.xss_profile_reset_operations(owner_id)
  WHERE status NOT IN ('completed','superseded');
CREATE INDEX xss_profile_reset_recovery
  ON identity.xss_profile_reset_operations(status,lease_expires_at,updated_at)
  WHERE status NOT IN ('completed','superseded');

ALTER TABLE identity.xss_profile_reset_steps
  DROP CONSTRAINT xss_profile_reset_steps_status_check,
  DROP CONSTRAINT xss_profile_reset_steps_check,
  DROP CONSTRAINT xss_profile_reset_steps_check1,
  DROP CONSTRAINT xss_profile_reset_steps_check2,
  DROP CONSTRAINT xss_profile_reset_steps_check3;
ALTER TABLE identity.xss_profile_reset_steps
  ADD CONSTRAINT xss_profile_reset_steps_status_check
    CHECK(status IN ('pending','failed','completed','superseded')),
  ADD CONSTRAINT xss_profile_reset_steps_terminal_time_check
    CHECK((status IN ('completed','superseded'))=(completed_at IS NOT NULL)),
  ADD CONSTRAINT xss_profile_reset_steps_receipt_check
    CHECK((receipt IS NULL)=(receipt_sha256 IS NULL)
      AND (status IN ('completed','superseded'))=(receipt IS NOT NULL)),
  ADD CONSTRAINT xss_profile_reset_steps_failure_check
    CHECK(status IN ('failed','superseded') OR failure_code IS NULL),
  ADD CONSTRAINT xss_profile_reset_steps_superseded_check
    CHECK(status<>'superseded' OR failure_code='PARENT_RESET_SUPERSEDED');

CREATE OR REPLACE FUNCTION identity.guard_xss_profile_reset_operation_binding() RETURNS trigger
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
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR (OLD.reconciliation_kind IS NOT NULL AND (
       NEW.reconciliation_kind IS DISTINCT FROM OLD.reconciliation_kind
       OR NEW.reconciliation_sha256 IS DISTINCT FROM OLD.reconciliation_sha256
       OR NEW.reconciled_graph_parent_generation IS DISTINCT FROM OLD.reconciled_graph_parent_generation
       OR NEW.reconciled_workshop_generation IS DISTINCT FROM OLD.reconciled_workshop_generation)) THEN
    RAISE EXCEPTION 'XSS profile reset coordinates are immutable' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION identity.guard_xss_profile_reset_step_binding() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' OR NEW.operation_id IS DISTINCT FROM OLD.operation_id
     OR NEW.step_key IS DISTINCT FROM OLD.step_key OR NEW.ordinal IS DISTINCT FROM OLD.ordinal
     OR (OLD.status IN ('completed','superseded') AND (
       NEW.status IS DISTINCT FROM OLD.status OR NEW.receipt IS DISTINCT FROM OLD.receipt
       OR NEW.receipt_sha256 IS DISTINCT FROM OLD.receipt_sha256
       OR NEW.completed_at IS DISTINCT FROM OLD.completed_at)) THEN
    RAISE EXCEPTION 'XSS profile reset step binding is immutable' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION identity.begin_xss_profile_reset(
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
  PERFORM 1 FROM graph_runtime.owners o WHERE o.owner_key=owner_key_value
    AND o.generation=requested_graph_parent_generation FOR SHARE OF o;
  IF NOT FOUND THEN RAISE EXCEPTION 'XSS profile graph parent is unavailable' USING ERRCODE='55000'; END IF;
  INSERT INTO workshop_platform.user_state(user_id,workshop_key)
    VALUES(requested_owner_id,'xss_workshop') ON CONFLICT DO NOTHING;
  PERFORM 1 FROM workshop_platform.user_state w WHERE w.user_id=requested_owner_id
    AND w.workshop_key='xss_workshop' AND w.generation=requested_workshop_generation FOR SHARE OF w;
  IF NOT FOUND THEN RAISE EXCEPTION 'XSS profile workshop parent is unavailable' USING ERRCODE='55000'; END IF;
  SELECT r.* INTO prior FROM identity.xss_profile_reset_operations r
    WHERE r.owner_id=requested_owner_id AND r.status NOT IN ('completed','superseded') FOR UPDATE OF r;
  IF FOUND THEN RAISE EXCEPTION 'XSS profile reset is already in progress' USING ERRCODE='55000'; END IF;
  INSERT INTO identity.xss_scope_state(owner_id,owner_key,scope_key)
    VALUES(requested_owner_id,owner_key_value,'stored_user'),(requested_owner_id,owner_key_value,'stored_llm')
    ON CONFLICT ON CONSTRAINT xss_scope_state_pkey DO NOTHING;
  SELECT s.child_generation INTO stored_user_generation FROM identity.xss_scope_state s
    WHERE s.owner_id=requested_owner_id AND s.owner_key=owner_key_value
      AND s.scope_key='stored_user' AND s.state='active' FOR UPDATE OF s;
  IF NOT FOUND OR stored_user_generation>=9223372036854775807 THEN
    RAISE EXCEPTION 'XSS stored_user scope is unavailable' USING ERRCODE='55000'; END IF;
  SELECT s.child_generation INTO stored_llm_generation FROM identity.xss_scope_state s
    WHERE s.owner_id=requested_owner_id AND s.owner_key=owner_key_value
      AND s.scope_key='stored_llm' AND s.state='active' FOR UPDATE OF s;
  IF NOT FOUND OR stored_llm_generation>=9223372036854775807 THEN
    RAISE EXCEPTION 'XSS stored_llm scope is unavailable' USING ERRCODE='55000'; END IF;
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

CREATE FUNCTION identity.reconcile_xss_profile_reset_after_parent(
  requested_operation_id uuid, requested_owner_id integer,
  observed_graph_parent_generation bigint, observed_workshop_generation bigint,
  requested_outcome jsonb
) RETURNS SETOF identity.xss_profile_reset_operations
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,identity,graph_runtime,workshop_platform AS $$
DECLARE operation identity.xss_profile_reset_operations%ROWTYPE;
DECLARE step identity.xss_profile_reset_steps%ROWTYPE;
DECLARE owner_key_value text;
DECLARE outcome_kind text;
DECLARE normalized jsonb;
DECLARE calculated text;
BEGIN
  IF requested_operation_id IS NULL OR requested_owner_id IS NULL OR requested_owner_id<=0
     OR observed_graph_parent_generation IS NULL OR observed_graph_parent_generation<0
     OR observed_workshop_generation IS NULL OR observed_workshop_generation<0
     OR requested_outcome IS NULL OR jsonb_typeof(requested_outcome)<>'object' THEN
    RAISE EXCEPTION 'Invalid XSS parent reconciliation coordinates' USING ERRCODE='22023';
  END IF;
  owner_key_value:='["XSS","'||requested_owner_id::text||'"]';
  PERFORM 1 FROM identity.users u WHERE u.id=requested_owner_id AND u.is_active=1
    AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_jobs d WHERE d.subject_user_id=u.id)
    FOR UPDATE OF u;
  IF NOT FOUND THEN RAISE EXCEPTION 'XSS reconciliation owner is unavailable' USING ERRCODE='55000'; END IF;
  PERFORM 1 FROM graph_runtime.owners o WHERE o.owner_key=owner_key_value
    AND o.generation=observed_graph_parent_generation FOR SHARE OF o;
  IF NOT FOUND THEN RAISE EXCEPTION 'XSS reconciliation graph parent is unavailable' USING ERRCODE='55000'; END IF;
  PERFORM 1 FROM workshop_platform.user_state w WHERE w.user_id=requested_owner_id
    AND w.workshop_key='xss_workshop' AND w.generation=observed_workshop_generation FOR SHARE OF w;
  IF NOT FOUND THEN RAISE EXCEPTION 'XSS reconciliation workshop parent is unavailable' USING ERRCODE='55000'; END IF;
  SELECT r.* INTO operation FROM identity.xss_profile_reset_operations r
    WHERE r.operation_id=requested_operation_id FOR UPDATE OF r;
  IF NOT FOUND OR operation.owner_id<>requested_owner_id THEN
    RAISE EXCEPTION 'XSS reconciliation operation is unavailable' USING ERRCODE='55000';
  END IF;
  IF operation.status='completed' THEN
    RAISE EXCEPTION 'Completed XSS reset cannot be superseded' USING ERRCODE='55000';
  END IF;
  IF operation.graph_parent_generation=observed_graph_parent_generation
     AND operation.workshop_generation=observed_workshop_generation THEN
    RAISE EXCEPTION 'XSS reset parent was not superseded' USING ERRCODE='55000';
  END IF;
  SELECT s.* INTO step FROM identity.xss_profile_reset_steps s
    WHERE s.operation_id=requested_operation_id FOR UPDATE OF s;
  outcome_kind:=requested_outcome->>'kind';
  IF outcome_kind='committed' THEN
    IF (SELECT count(*) FROM jsonb_object_keys(requested_outcome))<>2
       OR NOT requested_outcome ?& ARRAY['kind','receipt']
       OR jsonb_typeof(requested_outcome->'receipt')<>'object'
       OR (SELECT count(*) FROM jsonb_object_keys(requested_outcome->'receipt'))<>9
       OR NOT (requested_outcome->'receipt') ?& ARRAY['operationId','ownerId','graphParentGeneration',
         'workshopGeneration','children','profileRevisions','originsRemoved','appliedAt','replayed']
       OR jsonb_typeof(requested_outcome#>'{receipt,ownerId}')<>'number'
       OR jsonb_typeof(requested_outcome#>'{receipt,children}')<>'object'
       OR jsonb_typeof(requested_outcome#>'{receipt,profileRevisions}')<>'object'
       OR jsonb_typeof(requested_outcome#>'{receipt,originsRemoved}')<>'number'
       OR jsonb_typeof(requested_outcome#>'{receipt,appliedAt}')<>'string'
       OR jsonb_typeof(requested_outcome#>'{receipt,replayed}')<>'boolean'
       OR (SELECT count(*) FROM jsonb_object_keys(requested_outcome#>'{receipt,children}'))<>2
       OR NOT (requested_outcome#>'{receipt,children}') ?& ARRAY['stored_user','stored_llm']
       OR jsonb_typeof(requested_outcome#>'{receipt,children,stored_user}')<>'object'
       OR jsonb_typeof(requested_outcome#>'{receipt,children,stored_llm}')<>'object'
       OR (SELECT count(*) FROM jsonb_object_keys(requested_outcome#>'{receipt,children,stored_user}'))<>2
       OR (SELECT count(*) FROM jsonb_object_keys(requested_outcome#>'{receipt,children,stored_llm}'))<>2
       OR NOT (requested_outcome#>'{receipt,children,stored_user}') ?& ARRAY['from','to']
       OR NOT (requested_outcome#>'{receipt,children,stored_llm}') ?& ARRAY['from','to']
       OR (SELECT count(*) FROM jsonb_object_keys(requested_outcome#>'{receipt,profileRevisions}'))<>3
       OR NOT (requested_outcome#>'{receipt,profileRevisions}') ?& ARRAY['name','bio','website']
       OR requested_outcome#>>'{receipt,operationId}' IS NULL
       OR requested_outcome#>>'{receipt,ownerId}'!~'^[1-9][0-9]{0,9}$'
       OR requested_outcome#>>'{receipt,graphParentGeneration}'!~'^(0|[1-9][0-9]{0,18})$'
       OR requested_outcome#>>'{receipt,workshopGeneration}'!~'^(0|[1-9][0-9]{0,18})$'
       OR requested_outcome#>>'{receipt,children,stored_user,from}'!~'^(0|[1-9][0-9]{0,18})$'
       OR requested_outcome#>>'{receipt,children,stored_user,to}'!~'^(0|[1-9][0-9]{0,18})$'
       OR requested_outcome#>>'{receipt,children,stored_llm,from}'!~'^(0|[1-9][0-9]{0,18})$'
       OR requested_outcome#>>'{receipt,children,stored_llm,to}'!~'^(0|[1-9][0-9]{0,18})$'
       OR requested_outcome#>>'{receipt,profileRevisions,name}'!~'^[1-9][0-9]{0,18}$'
       OR requested_outcome#>>'{receipt,profileRevisions,bio}'!~'^[1-9][0-9]{0,18}$'
       OR requested_outcome#>>'{receipt,profileRevisions,website}'!~'^[1-9][0-9]{0,18}$'
       OR requested_outcome#>>'{receipt,originsRemoved}'!~'^(0|[1-9][0-9]{0,9})$'
       OR (requested_outcome#>>'{receipt,ownerId}')::numeric>2147483647
       OR (requested_outcome#>>'{receipt,graphParentGeneration}')::numeric>9223372036854775807
       OR (requested_outcome#>>'{receipt,workshopGeneration}')::numeric>9223372036854775807
       OR (requested_outcome#>>'{receipt,children,stored_user,from}')::numeric>9223372036854775807
       OR (requested_outcome#>>'{receipt,children,stored_user,to}')::numeric>9223372036854775807
       OR (requested_outcome#>>'{receipt,children,stored_llm,from}')::numeric>9223372036854775807
       OR (requested_outcome#>>'{receipt,children,stored_llm,to}')::numeric>9223372036854775807
       OR (requested_outcome#>>'{receipt,profileRevisions,name}')::numeric>9223372036854775807
       OR (requested_outcome#>>'{receipt,profileRevisions,bio}')::numeric>9223372036854775807
       OR (requested_outcome#>>'{receipt,profileRevisions,website}')::numeric>9223372036854775807
       OR (requested_outcome#>>'{receipt,originsRemoved}')::numeric>2147483647
       OR octet_length(requested_outcome#>>'{receipt,appliedAt}') NOT BETWEEN 10 AND 64 THEN
      RAISE EXCEPTION 'Invalid committed XSS retirement outcome' USING ERRCODE='22023';
    END IF;
    BEGIN PERFORM (requested_outcome#>>'{receipt,appliedAt}')::timestamptz;
    EXCEPTION WHEN others THEN RAISE EXCEPTION 'Invalid committed XSS receipt time' USING ERRCODE='22023'; END;
    normalized:=jsonb_build_object('kind','committed','receipt',(requested_outcome->'receipt')-'replayed');
  ELSIF outcome_kind='retired_no_effect' THEN
    IF (SELECT count(*) FROM jsonb_object_keys(requested_outcome))<>6
       OR NOT requested_outcome ?& ARRAY['kind','operationId','ownerId','graphParentGeneration',
         'workshopGeneration','children']
       OR jsonb_typeof(requested_outcome->'ownerId')<>'number'
       OR jsonb_typeof(requested_outcome->'children')<>'object'
       OR (SELECT count(*) FROM jsonb_object_keys(requested_outcome->'children'))<>2
       OR NOT (requested_outcome->'children') ?& ARRAY['stored_user','stored_llm']
       OR jsonb_typeof(requested_outcome#>'{children,stored_user}')<>'object'
       OR jsonb_typeof(requested_outcome#>'{children,stored_llm}')<>'object'
       OR (SELECT count(*) FROM jsonb_object_keys(requested_outcome#>'{children,stored_user}'))<>2
       OR (SELECT count(*) FROM jsonb_object_keys(requested_outcome#>'{children,stored_llm}'))<>2
       OR NOT (requested_outcome#>'{children,stored_user}') ?& ARRAY['from','to']
       OR NOT (requested_outcome#>'{children,stored_llm}') ?& ARRAY['from','to']
       OR requested_outcome->>'operationId' IS NULL
       OR requested_outcome->>'ownerId'!~'^[1-9][0-9]{0,9}$'
       OR requested_outcome->>'graphParentGeneration'!~'^(0|[1-9][0-9]{0,18})$'
       OR requested_outcome->>'workshopGeneration'!~'^(0|[1-9][0-9]{0,18})$'
       OR requested_outcome#>>'{children,stored_user,from}'!~'^(0|[1-9][0-9]{0,18})$'
       OR requested_outcome#>>'{children,stored_user,to}'!~'^(0|[1-9][0-9]{0,18})$'
       OR requested_outcome#>>'{children,stored_llm,from}'!~'^(0|[1-9][0-9]{0,18})$'
       OR requested_outcome#>>'{children,stored_llm,to}'!~'^(0|[1-9][0-9]{0,18})$'
       OR (requested_outcome->>'ownerId')::numeric>2147483647
       OR (requested_outcome->>'graphParentGeneration')::numeric>9223372036854775807
       OR (requested_outcome->>'workshopGeneration')::numeric>9223372036854775807
       OR (requested_outcome#>>'{children,stored_user,from}')::numeric>9223372036854775807
       OR (requested_outcome#>>'{children,stored_user,to}')::numeric>9223372036854775807
       OR (requested_outcome#>>'{children,stored_llm,from}')::numeric>9223372036854775807
       OR (requested_outcome#>>'{children,stored_llm,to}')::numeric>9223372036854775807 THEN
      RAISE EXCEPTION 'Invalid retired XSS outcome' USING ERRCODE='22023';
    END IF;
    normalized:=requested_outcome;
  ELSE RAISE EXCEPTION 'Invalid XSS retirement outcome kind' USING ERRCODE='22023'; END IF;
  IF normalized#>>'{receipt,operationId}' IS DISTINCT FROM operation.operation_id::text
     AND normalized->>'operationId' IS DISTINCT FROM operation.operation_id::text THEN
    RAISE EXCEPTION 'XSS retirement outcome operation mismatch' USING ERRCODE='22023';
  END IF;
  IF COALESCE(normalized#>>'{receipt,ownerId}',normalized->>'ownerId')!~'^[1-9][0-9]{0,9}$'
     OR COALESCE(normalized#>>'{receipt,ownerId}',normalized->>'ownerId')::bigint<>operation.owner_id
     OR COALESCE(normalized#>>'{receipt,graphParentGeneration}',normalized->>'graphParentGeneration')::numeric<>operation.graph_parent_generation
     OR COALESCE(normalized#>>'{receipt,workshopGeneration}',normalized->>'workshopGeneration')::numeric<>operation.workshop_generation
     OR COALESCE(normalized#>>'{receipt,children,stored_user,from}',normalized#>>'{children,stored_user,from}')::numeric<>operation.stored_user_from
     OR COALESCE(normalized#>>'{receipt,children,stored_user,to}',normalized#>>'{children,stored_user,to}')::numeric<>operation.stored_user_to
     OR COALESCE(normalized#>>'{receipt,children,stored_llm,from}',normalized#>>'{children,stored_llm,from}')::numeric<>operation.stored_llm_from
     OR COALESCE(normalized#>>'{receipt,children,stored_llm,to}',normalized#>>'{children,stored_llm,to}')::numeric<>operation.stored_llm_to THEN
    RAISE EXCEPTION 'XSS retirement outcome coordinates mismatch' USING ERRCODE='22023';
  END IF;
  calculated:=encode(sha256(convert_to(normalized::text,'UTF8')),'hex');
  IF operation.status='superseded' THEN
    IF operation.reconciliation_kind<>outcome_kind OR operation.reconciliation_sha256<>calculated
       OR operation.reconciled_graph_parent_generation<>observed_graph_parent_generation
       OR operation.reconciled_workshop_generation<>observed_workshop_generation THEN
      RAISE EXCEPTION 'XSS parent reconciliation replay mismatch' USING ERRCODE='22023';
    END IF;
    RETURN NEXT operation; RETURN;
  END IF;
  IF operation.status NOT IN ('pending','running','failed') OR step.status='superseded' THEN
    RAISE EXCEPTION 'XSS reset cannot be reconciled' USING ERRCODE='55000';
  END IF;
  PERFORM 1 FROM identity.xss_scope_state s WHERE s.owner_id=operation.owner_id
    AND s.owner_key=operation.owner_key AND s.scope_key='stored_llm'
    AND s.child_generation=operation.stored_llm_to AND s.state='resetting' FOR UPDATE OF s;
  IF NOT FOUND THEN RAISE EXCEPTION 'XSS stored_llm reconciliation mismatch' USING ERRCODE='55000'; END IF;
  PERFORM 1 FROM identity.xss_scope_state s WHERE s.owner_id=operation.owner_id
    AND s.owner_key=operation.owner_key AND s.scope_key='stored_user'
    AND s.child_generation=operation.stored_user_to AND s.state='resetting' FOR UPDATE OF s;
  IF NOT FOUND THEN RAISE EXCEPTION 'XSS stored_user reconciliation mismatch' USING ERRCODE='55000'; END IF;
  UPDATE identity.xss_scope_state SET state='active',updated_at=clock_timestamp()
    WHERE owner_id=operation.owner_id AND owner_key=operation.owner_key
      AND scope_key IN ('stored_llm','stored_user') AND state='resetting'
      AND ((scope_key='stored_llm' AND child_generation=operation.stored_llm_to)
        OR (scope_key='stored_user' AND child_generation=operation.stored_user_to));
  UPDATE identity.xss_profile_reset_steps SET status='superseded',attempts=attempts+1,
    receipt=normalized,receipt_sha256=calculated,failure_code='PARENT_RESET_SUPERSEDED',
    completed_at=clock_timestamp() WHERE operation_id=requested_operation_id;
  UPDATE identity.xss_profile_reset_operations SET status='superseded',
    failure_code='PARENT_RESET_SUPERSEDED',lease_token=NULL,lease_expires_at=NULL,
    reconciliation_kind=outcome_kind,reconciliation_sha256=calculated,
    reconciled_graph_parent_generation=observed_graph_parent_generation,
    reconciled_workshop_generation=observed_workshop_generation,
    completed_at=clock_timestamp(),updated_at=clock_timestamp()
    WHERE operation_id=requested_operation_id RETURNING * INTO operation;
  RETURN NEXT operation;
END $$;

REVOKE ALL ON FUNCTION identity.reconcile_xss_profile_reset_after_parent(uuid,integer,bigint,bigint,jsonb)
  FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.reconcile_xss_profile_reset_after_parent(uuid,integer,bigint,bigint,jsonb)
  TO dvaia_identity_runtime;
