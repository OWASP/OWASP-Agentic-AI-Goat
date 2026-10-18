-- Inactive durable authority for the administrator whole-XSS reset. The
-- student progress-only reset and the profile-scoped reset remain separate.
CREATE TABLE identity.xss_parent_reset_operations (
  operation_id uuid PRIMARY KEY,
  owner_id integer NOT NULL REFERENCES identity.users(id) ON DELETE RESTRICT,
  owner_key text NOT NULL,
  workshop_generation_from bigint NOT NULL CHECK(workshop_generation_from>=0),
  workshop_generation_to bigint,
  child_operation_id uuid REFERENCES identity.xss_profile_reset_operations(operation_id) ON DELETE RESTRICT,
  child_outcome jsonb,
  child_outcome_sha256 text,
  clear_receipt jsonb,
  clear_receipt_sha256 text,
  graph_generation bigint,
  status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','running','failed','completed')),
  lease_token uuid,
  lease_expires_at timestamptz,
  failure_code text CHECK(failure_code IS NULL OR failure_code~'^[A-Z][A-Z0-9_]{0,63}$'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  completed_at timestamptz,
  CHECK(owner_key='["XSS","'||owner_id::text||'"]'),
  CHECK((workshop_generation_to IS NULL)=(status<>'completed')),
  CHECK(workshop_generation_to IS NULL OR workshop_generation_to=workshop_generation_from+1),
  CHECK((child_outcome IS NULL)=(child_outcome_sha256 IS NULL)),
  CHECK((clear_receipt IS NULL)=(clear_receipt_sha256 IS NULL)),
  CHECK(child_outcome_sha256 IS NULL OR child_outcome_sha256~'^[0-9a-f]{64}$'),
  CHECK(clear_receipt_sha256 IS NULL OR clear_receipt_sha256~'^[0-9a-f]{64}$'),
  CHECK((lease_token IS NULL)=(lease_expires_at IS NULL)),
  CHECK((status='running')=(lease_token IS NOT NULL)),
  CHECK((status='completed')=(completed_at IS NOT NULL)),
  CHECK(status='failed' OR failure_code IS NULL),
  CHECK(graph_generation IS NULL OR graph_generation>=0)
);
CREATE UNIQUE INDEX xss_parent_reset_one_nonterminal_owner
  ON identity.xss_parent_reset_operations(owner_id) WHERE status<>'completed';
CREATE INDEX xss_parent_reset_recovery ON identity.xss_parent_reset_operations(status,lease_expires_at,updated_at)
  WHERE status<>'completed';

CREATE TABLE identity.xss_parent_reset_steps (
  operation_id uuid NOT NULL REFERENCES identity.xss_parent_reset_operations(operation_id) ON DELETE RESTRICT,
  step_key text NOT NULL CHECK(step_key IN ('child_retirement','xss_clear','canonical_finalize')),
  ordinal integer NOT NULL CHECK(ordinal IN (0,1,2)),
  status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','completed')),
  receipt_sha256 text CHECK(receipt_sha256 IS NULL OR receipt_sha256~'^[0-9a-f]{64}$'),
  completed_at timestamptz,
  PRIMARY KEY(operation_id,step_key), UNIQUE(operation_id,ordinal),
  CHECK((status='completed')=(completed_at IS NOT NULL)),
  CHECK((status='completed')=(receipt_sha256 IS NOT NULL))
);

CREATE FUNCTION identity.guard_xss_parent_reset_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
  IF TG_OP='DELETE' OR NEW.operation_id IS DISTINCT FROM OLD.operation_id
    OR NEW.owner_id IS DISTINCT FROM OLD.owner_id OR NEW.owner_key IS DISTINCT FROM OLD.owner_key
    OR NEW.workshop_generation_from IS DISTINCT FROM OLD.workshop_generation_from
    OR NEW.child_operation_id IS DISTINCT FROM OLD.child_operation_id
    OR NEW.created_at IS DISTINCT FROM OLD.created_at
    OR (OLD.child_outcome IS NOT NULL AND (NEW.child_outcome IS DISTINCT FROM OLD.child_outcome
      OR NEW.child_outcome_sha256 IS DISTINCT FROM OLD.child_outcome_sha256))
    OR (OLD.clear_receipt IS NOT NULL AND (NEW.clear_receipt IS DISTINCT FROM OLD.clear_receipt
      OR NEW.clear_receipt_sha256 IS DISTINCT FROM OLD.clear_receipt_sha256))
    OR (OLD.status='completed' AND NEW IS DISTINCT FROM OLD) THEN
    RAISE EXCEPTION 'XSS parent reset authority is immutable' USING ERRCODE='55000';
  END IF; RETURN NEW;
END $$;
CREATE TRIGGER xss_parent_reset_immutable BEFORE UPDATE OR DELETE ON identity.xss_parent_reset_operations
  FOR EACH ROW EXECUTE FUNCTION identity.guard_xss_parent_reset_immutable();
CREATE FUNCTION identity.guard_xss_parent_reset_step_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN
  IF TG_OP='DELETE' OR NEW.operation_id IS DISTINCT FROM OLD.operation_id
    OR NEW.step_key IS DISTINCT FROM OLD.step_key OR NEW.ordinal IS DISTINCT FROM OLD.ordinal
    OR (OLD.status='completed' AND NEW IS DISTINCT FROM OLD) THEN
    RAISE EXCEPTION 'XSS parent reset step is immutable' USING ERRCODE='55000';
  END IF; RETURN NEW;
END $$;
CREATE TRIGGER xss_parent_reset_step_immutable BEFORE UPDATE OR DELETE ON identity.xss_parent_reset_steps
  FOR EACH ROW EXECUTE FUNCTION identity.guard_xss_parent_reset_step_immutable();

CREATE FUNCTION identity.begin_xss_parent_reset(requested_operation_id uuid,requested_owner_id integer)
RETURNS SETOF identity.xss_parent_reset_operations LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,identity,workshop_platform AS $$
DECLARE prior identity.xss_parent_reset_operations%ROWTYPE; child identity.xss_profile_reset_operations%ROWTYPE;
DECLARE current_generation bigint;
BEGIN
  IF requested_operation_id IS NULL OR requested_owner_id IS NULL OR requested_owner_id<=0 THEN
    RAISE EXCEPTION 'Invalid XSS parent reset coordinates' USING ERRCODE='22023'; END IF;
  PERFORM 1 FROM identity.users u WHERE u.id=requested_owner_id AND u.is_active=1
    AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_jobs d WHERE d.subject_user_id=u.id) FOR UPDATE OF u;
  IF NOT FOUND THEN RAISE EXCEPTION 'XSS parent reset owner is unavailable' USING ERRCODE='55000'; END IF;
  SELECT p.* INTO prior FROM identity.xss_parent_reset_operations p
    WHERE p.operation_id=requested_operation_id FOR UPDATE OF p;
  IF FOUND THEN
    IF prior.owner_id<>requested_owner_id THEN RAISE EXCEPTION 'XSS parent reset replay mismatch' USING ERRCODE='22023'; END IF;
    RETURN NEXT prior; RETURN;
  END IF;
  SELECT p.* INTO prior FROM identity.xss_parent_reset_operations p
    WHERE p.owner_id=requested_owner_id AND p.status<>'completed' FOR UPDATE OF p;
  IF FOUND THEN RETURN NEXT prior; RETURN; END IF;
  INSERT INTO workshop_platform.user_state(user_id,workshop_key) VALUES(requested_owner_id,'xss_workshop') ON CONFLICT DO NOTHING;
  SELECT s.generation INTO current_generation FROM workshop_platform.user_state s
    WHERE s.user_id=requested_owner_id AND s.workshop_key='xss_workshop' FOR SHARE OF s;
  SELECT r.* INTO child FROM identity.xss_profile_reset_operations r
    WHERE r.owner_id=requested_owner_id AND r.status NOT IN ('completed','superseded') FOR SHARE OF r;
  INSERT INTO identity.xss_parent_reset_operations(operation_id,owner_id,owner_key,workshop_generation_from,child_operation_id)
    VALUES(requested_operation_id,requested_owner_id,'["XSS","'||requested_owner_id::text||'"]',current_generation,child.operation_id)
    RETURNING * INTO prior;
  INSERT INTO identity.xss_parent_reset_steps(operation_id,step_key,ordinal,status,receipt_sha256,completed_at)
    VALUES(requested_operation_id,'child_retirement',0,
      CASE WHEN child.operation_id IS NULL THEN 'completed' ELSE 'pending' END,
      CASE WHEN child.operation_id IS NULL THEN encode(sha256(convert_to('{"kind":"none"}','UTF8')),'hex') END,
      CASE WHEN child.operation_id IS NULL THEN clock_timestamp() END),
      (requested_operation_id,'xss_clear',1,'pending',NULL,NULL),
      (requested_operation_id,'canonical_finalize',2,'pending',NULL,NULL);
  RETURN NEXT prior;
END $$;

CREATE FUNCTION identity.read_xss_parent_reset(requested_operation_id uuid)
RETURNS SETOF identity.xss_parent_reset_operations LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,identity AS $$
 SELECT p.* FROM identity.xss_parent_reset_operations p WHERE p.operation_id=requested_operation_id $$;
CREATE FUNCTION identity.list_recoverable_xss_parent_resets(requested_limit integer) RETURNS TABLE(operation_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,identity AS $$ BEGIN
 IF requested_limit IS NULL OR requested_limit<1 OR requested_limit>100 THEN RAISE EXCEPTION 'Invalid recovery limit' USING ERRCODE='22023'; END IF;
 RETURN QUERY SELECT p.operation_id FROM identity.xss_parent_reset_operations p
  WHERE p.status IN ('pending','failed') OR (p.status='running' AND p.lease_expires_at<=clock_timestamp())
  ORDER BY p.updated_at,p.operation_id LIMIT requested_limit;
END $$;
CREATE FUNCTION identity.claim_xss_parent_reset(requested_operation_id uuid,requested_owner_id integer,requested_token uuid,requested_ms integer)
RETURNS SETOF identity.xss_parent_reset_operations LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,identity AS $$ BEGIN
 IF requested_operation_id IS NULL OR requested_owner_id IS NULL OR requested_owner_id<=0
   OR requested_token IS NULL OR requested_ms IS NULL
   OR requested_ms NOT BETWEEN 1000 AND 300000 THEN
  RAISE EXCEPTION 'Invalid XSS parent reset lease' USING ERRCODE='22023'; END IF;
 RETURN QUERY UPDATE identity.xss_parent_reset_operations p SET status='running',lease_token=requested_token,
  lease_expires_at=clock_timestamp()+(requested_ms*interval '1 millisecond'),failure_code=NULL,updated_at=clock_timestamp()
  WHERE p.operation_id=requested_operation_id AND p.owner_id=requested_owner_id
   AND (p.status IN ('pending','failed') OR
    (p.status='running' AND p.lease_expires_at<=clock_timestamp())) RETURNING p.*;
END $$;
CREATE FUNCTION identity.assert_xss_parent_reset_current(requested_operation_id uuid,requested_token uuid)
RETURNS SETOF identity.xss_parent_reset_operations LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,identity AS $$
 SELECT p.* FROM identity.xss_parent_reset_operations p JOIN identity.users u ON u.id=p.owner_id AND u.is_active=1
 WHERE p.operation_id=requested_operation_id AND p.status='running' AND p.lease_token=requested_token
  AND p.lease_expires_at>clock_timestamp() AND NOT EXISTS(
   SELECT 1 FROM identity.student_deletion_jobs d WHERE d.subject_user_id=p.owner_id)
 FOR UPDATE OF p FOR SHARE OF u $$;

CREATE FUNCTION identity.acknowledge_xss_parent_child(requested_operation_id uuid,requested_token uuid,requested_outcome jsonb)
RETURNS TABLE(receipt_sha256 text,replayed boolean) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,identity AS $$
DECLARE parent identity.xss_parent_reset_operations%ROWTYPE; child identity.xss_profile_reset_operations%ROWTYPE;
DECLARE normalized jsonb; calculated text; existing text;
BEGIN
 SELECT * INTO parent FROM identity.assert_xss_parent_reset_current(requested_operation_id,requested_token);
 IF NOT FOUND OR parent.child_operation_id IS NULL THEN RAISE EXCEPTION 'XSS child retirement is unavailable' USING ERRCODE='55000'; END IF;
 SELECT r.* INTO child FROM identity.xss_profile_reset_operations r WHERE r.operation_id=parent.child_operation_id FOR SHARE OF r;
 IF requested_outcome IS NULL OR jsonb_typeof(requested_outcome)<>'object' OR requested_outcome->>'kind' NOT IN ('retired_no_effect','committed')
   OR (requested_outcome->>'kind'='retired_no_effect' AND ((SELECT count(*) FROM jsonb_object_keys(requested_outcome))<>6
     OR NOT requested_outcome ?& ARRAY['kind','operationId','ownerId','graphParentGeneration','workshopGeneration','children']
     OR jsonb_typeof(requested_outcome->'ownerId')<>'number' OR jsonb_typeof(requested_outcome->'children')<>'object'))
   OR (requested_outcome->>'kind'='committed' AND ((SELECT count(*) FROM jsonb_object_keys(requested_outcome))<>2
     OR NOT requested_outcome ?& ARRAY['kind','receipt'] OR jsonb_typeof(requested_outcome->'receipt')<>'object'
     OR (SELECT count(*) FROM jsonb_object_keys(requested_outcome->'receipt'))<>9
     OR NOT (requested_outcome->'receipt') ?& ARRAY['operationId','ownerId','graphParentGeneration','workshopGeneration',
       'children','profileRevisions','originsRemoved','appliedAt','replayed']
     OR jsonb_typeof(requested_outcome#>'{receipt,replayed}')<>'boolean')) THEN
  RAISE EXCEPTION 'Invalid XSS child outcome' USING ERRCODE='22023'; END IF;
 normalized:=CASE WHEN requested_outcome->>'kind'='committed'
   THEN jsonb_build_object('kind','committed','receipt',(requested_outcome->'receipt')-'replayed') ELSE requested_outcome END;
 IF COALESCE(normalized->>'operationId',normalized#>>'{receipt,operationId}') IS DISTINCT FROM child.operation_id::text
   OR COALESCE(normalized->>'ownerId',normalized#>>'{receipt,ownerId}') IS DISTINCT FROM child.owner_id::text
   OR COALESCE(normalized->>'graphParentGeneration',normalized#>>'{receipt,graphParentGeneration}') IS DISTINCT FROM child.graph_parent_generation::text
   OR COALESCE(normalized->>'workshopGeneration',normalized#>>'{receipt,workshopGeneration}') IS DISTINCT FROM child.workshop_generation::text THEN
  RAISE EXCEPTION 'XSS child outcome mismatch' USING ERRCODE='22023'; END IF;
 calculated:=encode(sha256(convert_to(normalized::text,'UTF8')),'hex');
 SELECT p.child_outcome_sha256 INTO existing FROM identity.xss_parent_reset_operations p WHERE p.operation_id=requested_operation_id FOR UPDATE OF p;
 IF existing IS NOT NULL THEN
  IF existing<>calculated THEN RAISE EXCEPTION 'XSS child acknowledgement mismatch' USING ERRCODE='22023'; END IF;
  RETURN QUERY SELECT existing,true; RETURN;
 END IF;
 UPDATE identity.xss_parent_reset_operations SET child_outcome=normalized,child_outcome_sha256=calculated,updated_at=clock_timestamp()
  WHERE operation_id=requested_operation_id;
 UPDATE identity.xss_parent_reset_steps SET status='completed',receipt_sha256=calculated,completed_at=clock_timestamp()
  WHERE operation_id=requested_operation_id AND step_key='child_retirement';
 RETURN QUERY SELECT calculated,false;
END $$;

CREATE FUNCTION identity.acknowledge_xss_parent_clear(requested_operation_id uuid,requested_token uuid,requested_receipt jsonb)
RETURNS TABLE(receipt_sha256 text,replayed boolean) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,identity AS $$
DECLARE parent identity.xss_parent_reset_operations%ROWTYPE; normalized jsonb; calculated text; existing text;
BEGIN
 SELECT * INTO parent FROM identity.assert_xss_parent_reset_current(requested_operation_id,requested_token);
 IF NOT FOUND OR requested_receipt IS NULL OR jsonb_typeof(requested_receipt)<>'object'
   OR (SELECT count(*) FROM jsonb_object_keys(requested_receipt))<>7
   OR NOT requested_receipt ?& ARRAY['operationId','ownerId','profileRevisions','progressRemoved','originsRemoved','appliedAt','replayed']
   OR jsonb_typeof(requested_receipt->'operationId')<>'string'
   OR jsonb_typeof(requested_receipt->'ownerId')<>'number'
   OR requested_receipt->>'operationId' IS DISTINCT FROM parent.operation_id::text
   OR requested_receipt->>'ownerId' IS DISTINCT FROM parent.owner_id::text
   OR jsonb_typeof(requested_receipt->'profileRevisions')<>'object'
   OR (SELECT count(*) FROM jsonb_object_keys(requested_receipt->'profileRevisions'))<>3
   OR NOT (requested_receipt->'profileRevisions') ?& ARRAY['name','bio','website']
   OR jsonb_typeof(requested_receipt#>'{profileRevisions,name}')<>'string'
   OR jsonb_typeof(requested_receipt#>'{profileRevisions,bio}')<>'string'
   OR jsonb_typeof(requested_receipt#>'{profileRevisions,website}')<>'string'
   OR requested_receipt#>>'{profileRevisions,name}'!~'^[1-9][0-9]{0,18}$'
   OR requested_receipt#>>'{profileRevisions,bio}'!~'^[1-9][0-9]{0,18}$'
   OR requested_receipt#>>'{profileRevisions,website}'!~'^[1-9][0-9]{0,18}$'
   OR (requested_receipt#>>'{profileRevisions,name}')::numeric>9223372036854775807
   OR (requested_receipt#>>'{profileRevisions,bio}')::numeric>9223372036854775807
   OR (requested_receipt#>>'{profileRevisions,website}')::numeric>9223372036854775807
   OR jsonb_typeof(requested_receipt->'progressRemoved')<>'number'
   OR jsonb_typeof(requested_receipt->'originsRemoved')<>'number'
   OR requested_receipt->>'progressRemoved'!~'^(0|[1-9][0-9]{0,9})$'
   OR requested_receipt->>'originsRemoved'!~'^(0|[1-9][0-9]{0,9})$'
   OR (requested_receipt->>'progressRemoved')::numeric>2147483647
   OR (requested_receipt->>'originsRemoved')::numeric>2147483647
   OR jsonb_typeof(requested_receipt->'appliedAt')<>'string'
   OR octet_length(requested_receipt->>'appliedAt') NOT BETWEEN 10 AND 64
   OR jsonb_typeof(requested_receipt->'replayed')<>'boolean' THEN
  RAISE EXCEPTION 'Invalid XSS clear receipt' USING ERRCODE='22023'; END IF;
 BEGIN PERFORM (requested_receipt->>'appliedAt')::timestamptz;
 EXCEPTION WHEN others THEN RAISE EXCEPTION 'Invalid XSS clear receipt time' USING ERRCODE='22023'; END;
 normalized:=requested_receipt-'replayed'; calculated:=encode(sha256(convert_to(normalized::text,'UTF8')),'hex');
 SELECT p.clear_receipt_sha256 INTO existing FROM identity.xss_parent_reset_operations p WHERE p.operation_id=requested_operation_id FOR UPDATE OF p;
 IF existing IS NOT NULL THEN
  IF existing<>calculated THEN RAISE EXCEPTION 'XSS clear receipt mismatch' USING ERRCODE='22023'; END IF;
  RETURN QUERY SELECT existing,true; RETURN;
 END IF;
 UPDATE identity.xss_parent_reset_operations SET clear_receipt=normalized,clear_receipt_sha256=calculated,updated_at=clock_timestamp()
  WHERE operation_id=requested_operation_id;
 UPDATE identity.xss_parent_reset_steps SET status='completed',receipt_sha256=calculated,completed_at=clock_timestamp()
  WHERE operation_id=requested_operation_id AND step_key='xss_clear';
 RETURN QUERY SELECT calculated,false;
END $$;

CREATE FUNCTION identity.complete_xss_parent_reset(requested_operation_id uuid,requested_token uuid,observed_graph_generation bigint)
RETURNS SETOF identity.xss_parent_reset_operations LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,identity,graph_runtime,workshop_platform AS $$
DECLARE parent identity.xss_parent_reset_operations%ROWTYPE; child identity.xss_profile_reset_operations%ROWTYPE; next_generation bigint;
BEGIN
 SELECT * INTO parent FROM identity.assert_xss_parent_reset_current(requested_operation_id,requested_token);
 IF NOT FOUND OR observed_graph_generation IS NULL OR observed_graph_generation<0 THEN RAISE EXCEPTION 'Stale XSS parent reset' USING ERRCODE='55000'; END IF;
 IF parent.child_operation_id IS NOT NULL AND parent.child_outcome IS NULL THEN RAISE EXCEPTION 'XSS child retirement incomplete' USING ERRCODE='55000'; END IF;
 IF parent.clear_receipt IS NULL THEN RAISE EXCEPTION 'XSS clear incomplete' USING ERRCODE='55000'; END IF;
 PERFORM 1 FROM graph_runtime.owners o WHERE o.owner_key=parent.owner_key AND o.generation=observed_graph_generation FOR SHARE OF o;
 IF NOT FOUND THEN RAISE EXCEPTION 'XSS graph parent is stale' USING ERRCODE='55000'; END IF;
 -- Match workshopProgressRepository's canonical lock order: state authority is
 -- acquired before any of its dependent progress/activity/time projections.
  PERFORM 1 FROM workshop_platform.user_state s WHERE s.user_id=parent.owner_id AND s.workshop_key='xss_workshop'
  AND s.generation=parent.workshop_generation_from FOR UPDATE OF s;
  IF NOT FOUND THEN RAISE EXCEPTION 'XSS workshop parent is stale' USING ERRCODE='55000'; END IF;
 PERFORM 1 FROM workshop_platform.completions c WHERE c.user_id=parent.owner_id AND c.workshop_key='xss_workshop' ORDER BY c.objective_id FOR UPDATE OF c;
 PERFORM 1 FROM workshop_platform.activity_counters a WHERE a.user_id=parent.owner_id AND a.workshop_key='xss_workshop' ORDER BY a.activity_key FOR UPDATE OF a;
 PERFORM 1 FROM workshop_platform.time_tracking t WHERE t.user_id=parent.owner_id AND t.workshop_key='xss_workshop' ORDER BY t.id FOR UPDATE OF t;
 DELETE FROM workshop_platform.completions WHERE user_id=parent.owner_id AND workshop_key='xss_workshop';
 DELETE FROM workshop_platform.activity_counters WHERE user_id=parent.owner_id AND workshop_key='xss_workshop';
 DELETE FROM workshop_platform.time_tracking WHERE user_id=parent.owner_id AND workshop_key='xss_workshop';
 UPDATE workshop_platform.user_state SET generation=generation+1,started_at=NULL,updated_at=clock_timestamp()
  WHERE user_id=parent.owner_id AND workshop_key='xss_workshop' RETURNING generation INTO next_generation;
 INSERT INTO workshop_platform.revisions(scope_type,scope_key,category,revision)
  VALUES('user',parent.owner_id::text,'workshop_progress',1),('user',parent.owner_id::text,'workshop_time',1)
  ON CONFLICT(scope_type,scope_key,category) DO UPDATE SET revision=workshop_platform.revisions.revision+1,updated_at=clock_timestamp();
 IF parent.child_operation_id IS NOT NULL THEN
  SELECT r.* INTO child FROM identity.xss_profile_reset_operations r WHERE r.operation_id=parent.child_operation_id FOR UPDATE OF r;
  IF NOT FOUND OR observed_graph_generation<=child.graph_parent_generation OR next_generation<=child.workshop_generation THEN
   RAISE EXCEPTION 'XSS child reset was not superseded' USING ERRCODE='55000'; END IF;
  PERFORM identity.reconcile_xss_profile_reset_after_parent(parent.child_operation_id,parent.owner_id,
    observed_graph_generation,next_generation,parent.child_outcome);
 END IF;
 UPDATE identity.xss_parent_reset_steps SET status='completed',receipt_sha256=encode(sha256(convert_to(
   jsonb_build_object('graphGeneration',observed_graph_generation::text,'workshopGeneration',next_generation::text)::text,'UTF8')),'hex'),
   completed_at=clock_timestamp() WHERE operation_id=parent.operation_id AND step_key='canonical_finalize';
 UPDATE identity.xss_parent_reset_operations SET status='completed',graph_generation=observed_graph_generation,
  workshop_generation_to=next_generation,lease_token=NULL,lease_expires_at=NULL,completed_at=clock_timestamp(),updated_at=clock_timestamp()
  WHERE operation_id=parent.operation_id RETURNING * INTO parent;
 RETURN NEXT parent;
END $$;

CREATE FUNCTION identity.fail_xss_parent_reset(requested_operation_id uuid,requested_token uuid,requested_code text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,identity AS $$ BEGIN
 IF requested_code IS NULL OR requested_code!~'^[A-Z][A-Z0-9_]{0,63}$' THEN RAISE EXCEPTION 'Invalid failure code' USING ERRCODE='22023'; END IF;
 UPDATE identity.xss_parent_reset_operations SET status='failed',failure_code=requested_code,lease_token=NULL,
  lease_expires_at=NULL,updated_at=clock_timestamp() WHERE operation_id=requested_operation_id AND status='running'
  AND lease_token=requested_token AND lease_expires_at>clock_timestamp(); RETURN FOUND;
END $$;

CREATE FUNCTION identity.guard_xss_parent_reset_run() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,identity AS $$
DECLARE uid integer; BEGIN
 IF NEW.status='running' AND NEW.owner_key~'^\["XSS","[1-9][0-9]*"\]$' THEN uid:=(NEW.owner_key::jsonb->>1)::integer;
  IF EXISTS(SELECT 1 FROM identity.xss_parent_reset_operations p WHERE p.owner_id=uid AND p.status<>'completed') THEN
   RAISE EXCEPTION 'XSS parent reset is in progress' USING ERRCODE='55000'; END IF; END IF; RETURN NEW;
END $$;
CREATE TRIGGER xss_parent_reset_run_guard BEFORE INSERT OR UPDATE OF owner_key,status ON graph_runtime.runs
 FOR EACH ROW EXECUTE FUNCTION identity.guard_xss_parent_reset_run();
CREATE FUNCTION identity.guard_xss_parent_reset_admission() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,identity AS $$
DECLARE uid integer; workshop text; BEGIN
 uid:=COALESCE(NEW.user_id,OLD.user_id);workshop:=COALESCE(NEW.workshop_key,OLD.workshop_key);
 IF workshop='xss_workshop' AND EXISTS(SELECT 1 FROM identity.xss_parent_reset_operations p
  WHERE p.owner_id=uid AND p.status<>'completed') THEN RAISE EXCEPTION 'XSS parent reset is in progress' USING ERRCODE='55000'; END IF; RETURN NEW;
END $$;
CREATE TRIGGER xss_parent_reset_judgment_guard BEFORE INSERT OR UPDATE ON workshop_platform.objective_judgments
 FOR EACH ROW EXECUTE FUNCTION identity.guard_xss_parent_reset_admission();
CREATE TRIGGER xss_parent_reset_completion_guard BEFORE INSERT OR UPDATE ON workshop_platform.completions
 FOR EACH ROW EXECUTE FUNCTION identity.guard_xss_parent_reset_admission();
CREATE TRIGGER xss_parent_reset_activity_guard BEFORE INSERT OR UPDATE ON workshop_platform.activity_counters
 FOR EACH ROW EXECUTE FUNCTION identity.guard_xss_parent_reset_admission();
CREATE TRIGGER xss_parent_reset_time_guard BEFORE INSERT OR UPDATE ON workshop_platform.time_tracking
 FOR EACH ROW EXECUTE FUNCTION identity.guard_xss_parent_reset_admission();

REVOKE ALL ON identity.xss_parent_reset_operations,identity.xss_parent_reset_steps FROM PUBLIC,dvaia_identity_runtime;
REVOKE ALL ON FUNCTION identity.guard_xss_parent_reset_immutable(),identity.guard_xss_parent_reset_step_immutable(),
 identity.begin_xss_parent_reset(uuid,integer),identity.read_xss_parent_reset(uuid),identity.list_recoverable_xss_parent_resets(integer),
 identity.claim_xss_parent_reset(uuid,integer,uuid,integer),identity.assert_xss_parent_reset_current(uuid,uuid),
 identity.acknowledge_xss_parent_child(uuid,uuid,jsonb),identity.acknowledge_xss_parent_clear(uuid,uuid,jsonb),
 identity.complete_xss_parent_reset(uuid,uuid,bigint),identity.fail_xss_parent_reset(uuid,uuid,text),
 identity.guard_xss_parent_reset_run(),identity.guard_xss_parent_reset_admission() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.begin_xss_parent_reset(uuid,integer),identity.read_xss_parent_reset(uuid),
 identity.list_recoverable_xss_parent_resets(integer),identity.claim_xss_parent_reset(uuid,integer,uuid,integer),
 identity.assert_xss_parent_reset_current(uuid,uuid),identity.acknowledge_xss_parent_child(uuid,uuid,jsonb),
 identity.acknowledge_xss_parent_clear(uuid,uuid,jsonb),identity.complete_xss_parent_reset(uuid,uuid,bigint),
 identity.fail_xss_parent_reset(uuid,uuid,text) TO dvaia_identity_runtime;
