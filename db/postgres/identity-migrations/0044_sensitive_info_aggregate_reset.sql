-- DRAFT ONLY. Not discovered by the production migration loader.
-- Durable owner reset for the shared Legacy Sensitive + FinFlow workshop.
CREATE TABLE identity.sensitive_info_resets (
 operation_id uuid PRIMARY KEY,
 owner_id integer NOT NULL REFERENCES identity.users(id) ON DELETE RESTRICT,
 from_generation integer NOT NULL CHECK(from_generation >= 0),
 to_generation integer NOT NULL CHECK(to_generation = from_generation + 1),
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','running','failed','completed')),
 lease_token uuid,
 lease_expires_at timestamptz,
 failure_code text CHECK(failure_code IS NULL OR failure_code ~ '^[A-Z][A-Z0-9_]{0,63}$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 completed_at timestamptz,
 CHECK ((lease_token IS NULL) = (lease_expires_at IS NULL)),
 CHECK ((status = 'running') = (lease_token IS NOT NULL)),
 CHECK ((status = 'completed') = (completed_at IS NOT NULL)),
 CHECK (status = 'failed' OR failure_code IS NULL)
);
CREATE TABLE identity.sensitive_info_reset_authority (
 owner_id integer PRIMARY KEY REFERENCES identity.users(id) ON DELETE RESTRICT
);
CREATE UNIQUE INDEX sensitive_info_reset_incomplete_owner
 ON identity.sensitive_info_resets(owner_id) WHERE status <> 'completed';
CREATE INDEX sensitive_info_reset_recovery
 ON identity.sensitive_info_resets(status,lease_expires_at,updated_at) WHERE status <> 'completed';

CREATE TABLE identity.sensitive_info_reset_steps (
 operation_id uuid NOT NULL REFERENCES identity.sensitive_info_resets(operation_id) ON DELETE RESTRICT,
 step_key text NOT NULL CHECK(step_key IN ('legacy_store','finflow_store')),
 ordinal integer NOT NULL CHECK(ordinal IN (0,1)),
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','failed','completed')),
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts >= 0),
 failure_code text CHECK(failure_code IS NULL OR failure_code ~ '^[A-Z][A-Z0-9_]{0,63}$'),
 completed_at timestamptz,
 PRIMARY KEY(operation_id,step_key), UNIQUE(operation_id,ordinal),
 CHECK ((status = 'completed') = (completed_at IS NOT NULL)),
 CHECK (status = 'failed' OR failure_code IS NULL)
);

CREATE FUNCTION identity.begin_sensitive_info_reset(p_owner_id integer,p_operation_id uuid)
RETURNS TABLE(operation_id uuid,owner_id integer,from_generation integer,to_generation integer,status text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE account identity.users%ROWTYPE; state workshop_platform.user_state%ROWTYPE;
 prior identity.sensitive_info_resets%ROWTYPE;
BEGIN
 SELECT * INTO account FROM identity.users WHERE id=p_owner_id FOR UPDATE;
 IF account.id IS NULL OR account.is_active<>1 OR account.role NOT IN ('student','admin','super_admin') THEN
  RAISE EXCEPTION 'Sensitive Information owner is unavailable' USING ERRCODE='23514';
 END IF;
 SELECT r.* INTO prior FROM identity.sensitive_info_resets r
  WHERE r.operation_id=p_operation_id;
 IF FOUND THEN
  IF prior.owner_id<>p_owner_id THEN RAISE EXCEPTION 'Sensitive Information reset scope mismatch' USING ERRCODE='23514'; END IF;
  RETURN QUERY SELECT prior.operation_id,prior.owner_id,prior.from_generation,prior.to_generation,prior.status; RETURN;
 END IF;
 INSERT INTO identity.sensitive_info_reset_authority(owner_id) VALUES(p_owner_id) ON CONFLICT DO NOTHING;
 PERFORM 1 FROM identity.sensitive_info_reset_authority authority
  WHERE authority.owner_id=p_owner_id FOR UPDATE;
 -- A direct runtime transaction admitted just before begin holds authority
 -- SHARE until it commits. Once begin obtains UPDATE, retire any such active
 -- rows before publishing the reset journal. Production coordinators also
 -- drain their process-local execution, but correctness does not depend on it.
 UPDATE graph_runtime.runs run SET status='interrupted',finished_at=clock_timestamp()
  WHERE run.owner_key IN ('["LegacySensitiveInfo","'||p_owner_id::text||'"]',
                          '["FinFlow","'||p_owner_id::text||'"]')
    AND run.status='running';
 UPDATE graph_runtime.effects effect SET status='uncertain',updated_at=clock_timestamp()
  WHERE effect.owner_key IN ('["LegacySensitiveInfo","'||p_owner_id::text||'"]',
                             '["FinFlow","'||p_owner_id::text||'"]')
    AND effect.status='started';
 -- Row-level UPDATE triggers acquire their target tuple before they can take
 -- user_state SHARE. Lock every resettable projection in the same fixed order
 -- before user_state so begin never holds state while waiting for such a row.
 PERFORM 1 FROM workshop_platform.completions
  WHERE user_id=p_owner_id AND workshop_key='sensitive_info_disclosure'
  ORDER BY objective_id FOR UPDATE;
 PERFORM 1 FROM workshop_platform.activity_counters
  WHERE user_id=p_owner_id AND workshop_key='sensitive_info_disclosure'
  ORDER BY activity_key FOR UPDATE;
 PERFORM 1 FROM workshop_platform.time_tracking
  WHERE user_id=p_owner_id AND workshop_key='sensitive_info_disclosure'
  ORDER BY id FOR UPDATE;
 INSERT INTO workshop_platform.user_state(user_id,workshop_key)
 VALUES(p_owner_id,'sensitive_info_disclosure') ON CONFLICT DO NOTHING;
 SELECT * INTO state FROM workshop_platform.user_state
 WHERE user_id=p_owner_id AND workshop_key='sensitive_info_disclosure' FOR UPDATE;
 RETURN QUERY SELECT r.operation_id,r.owner_id,r.from_generation,r.to_generation,r.status
 FROM identity.sensitive_info_resets r WHERE r.owner_id=p_owner_id AND r.status<>'completed' FOR UPDATE;
 IF FOUND THEN RETURN; END IF;
 -- Advance canonical authority and remove current credit atomically before the
 -- cross-store work becomes recoverable. Stale Judge receipts can never award
 -- against to_generation after this transaction commits.
 DELETE FROM workshop_platform.completions WHERE user_id=p_owner_id AND workshop_key='sensitive_info_disclosure';
 DELETE FROM workshop_platform.activity_counters WHERE user_id=p_owner_id AND workshop_key='sensitive_info_disclosure';
 DELETE FROM workshop_platform.time_tracking WHERE user_id=p_owner_id AND workshop_key='sensitive_info_disclosure';
 UPDATE workshop_platform.user_state SET generation=generation+1,started_at=NULL,updated_at=clock_timestamp()
 WHERE user_id=p_owner_id AND workshop_key='sensitive_info_disclosure'
 RETURNING * INTO state;
 INSERT INTO identity.sensitive_info_resets(operation_id,owner_id,from_generation,to_generation)
 VALUES(p_operation_id,p_owner_id,state.generation-1,state.generation);
 INSERT INTO identity.sensitive_info_reset_steps(operation_id,step_key,ordinal)
 VALUES(p_operation_id,'legacy_store',0),(p_operation_id,'finflow_store',1);
 INSERT INTO workshop_platform.revisions(scope_type,scope_key,category,revision)
 VALUES('user',p_owner_id::text,'workshop_progress',1),('user',p_owner_id::text,'workshop_time',1)
 ON CONFLICT(scope_type,scope_key,category) DO UPDATE
 SET revision=workshop_platform.revisions.revision+1,updated_at=clock_timestamp();
 RETURN QUERY SELECT r.operation_id,r.owner_id,r.from_generation,r.to_generation,r.status
 FROM identity.sensitive_info_resets r WHERE r.operation_id=p_operation_id;
END $$;

-- New grading/time writes are denied while either local store still owes
-- cleanup. The reset function inserts the journal in the same transaction as
-- its generation bump, so concurrent writers serialize on user_state.
CREATE FUNCTION identity.guard_sensitive_info_reset_admission()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE uid integer; workshop text;
BEGIN
 uid:=COALESCE(NEW.user_id,OLD.user_id); workshop:=COALESCE(NEW.workshop_key,OLD.workshop_key);
 IF workshop='sensitive_info_disclosure' THEN
  INSERT INTO workshop_platform.user_state(user_id,workshop_key)
   VALUES(uid,'sensitive_info_disclosure') ON CONFLICT DO NOTHING;
  PERFORM 1 FROM workshop_platform.user_state
   WHERE user_id=uid AND workshop_key='sensitive_info_disclosure' FOR SHARE;
 END IF;
 IF workshop='sensitive_info_disclosure' AND EXISTS(
   SELECT 1 FROM identity.sensitive_info_resets r WHERE r.owner_id=uid AND r.status<>'completed') THEN
  RAISE EXCEPTION 'Sensitive Information reset is in progress' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sensitive_info_reset_completion_guard BEFORE INSERT OR UPDATE
 ON workshop_platform.completions FOR EACH ROW EXECUTE FUNCTION identity.guard_sensitive_info_reset_admission();
CREATE TRIGGER sensitive_info_reset_activity_guard BEFORE INSERT OR UPDATE
 ON workshop_platform.activity_counters FOR EACH ROW EXECUTE FUNCTION identity.guard_sensitive_info_reset_admission();
CREATE TRIGGER sensitive_info_reset_time_guard BEFORE INSERT OR UPDATE
 ON workshop_platform.time_tracking FOR EACH ROW EXECUTE FUNCTION identity.guard_sensitive_info_reset_admission();
CREATE TRIGGER sensitive_info_reset_judgment_guard BEFORE INSERT
 ON workshop_platform.objective_judgments FOR EACH ROW EXECUTE FUNCTION identity.guard_sensitive_info_reset_admission();
CREATE TRIGGER sensitive_info_reset_state_guard BEFORE UPDATE
 ON workshop_platform.user_state FOR EACH ROW EXECUTE FUNCTION identity.guard_sensitive_info_reset_admission();

CREATE FUNCTION identity.guard_sensitive_info_reset_run()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE uid integer;
BEGIN
 IF NEW.status='running' AND NEW.owner_key ~ '^\["(LegacySensitiveInfo|FinFlow)","[1-9][0-9]*"\]$' THEN
  uid := (NEW.owner_key::jsonb->>1)::integer;
  INSERT INTO identity.sensitive_info_reset_authority(owner_id) VALUES(uid) ON CONFLICT DO NOTHING;
  PERFORM 1 FROM identity.sensitive_info_reset_authority WHERE owner_id=uid FOR SHARE;
  IF EXISTS(SELECT 1 FROM identity.sensitive_info_resets r
    WHERE r.owner_id=uid AND r.status<>'completed') THEN
   RAISE EXCEPTION 'Sensitive Information reset is in progress' USING ERRCODE='23514';
  END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER sensitive_info_reset_run_guard BEFORE INSERT OR UPDATE OF owner_key,status ON graph_runtime.runs
 FOR EACH ROW EXECUTE FUNCTION identity.guard_sensitive_info_reset_run();

CREATE FUNCTION identity.guard_sensitive_info_reset_binding()
RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF TG_OP='DELETE' OR NEW.operation_id IS DISTINCT FROM OLD.operation_id
   OR NEW.owner_id IS DISTINCT FROM OLD.owner_id
   OR NEW.from_generation IS DISTINCT FROM OLD.from_generation
   OR NEW.to_generation IS DISTINCT FROM OLD.to_generation
   OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
  RAISE EXCEPTION 'Sensitive Information reset binding is immutable' USING ERRCODE='23514';
 END IF; RETURN NEW;
END $$;
CREATE TRIGGER sensitive_info_reset_binding_guard BEFORE UPDATE OR DELETE
 ON identity.sensitive_info_resets FOR EACH ROW EXECUTE FUNCTION identity.guard_sensitive_info_reset_binding();
CREATE FUNCTION identity.guard_sensitive_info_reset_step_binding()
RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF TG_OP='DELETE' OR NEW.operation_id IS DISTINCT FROM OLD.operation_id
   OR NEW.step_key IS DISTINCT FROM OLD.step_key OR NEW.ordinal IS DISTINCT FROM OLD.ordinal THEN
  RAISE EXCEPTION 'Sensitive Information reset step binding is immutable' USING ERRCODE='23514';
 END IF; RETURN NEW;
END $$;
CREATE TRIGGER sensitive_info_reset_step_binding_guard BEFORE UPDATE OR DELETE
 ON identity.sensitive_info_reset_steps FOR EACH ROW EXECUTE FUNCTION identity.guard_sensitive_info_reset_step_binding();

REVOKE ALL ON FUNCTION identity.begin_sensitive_info_reset(integer,uuid),
 identity.guard_sensitive_info_reset_admission(),identity.guard_sensitive_info_reset_binding(),
 identity.guard_sensitive_info_reset_step_binding(),identity.guard_sensitive_info_reset_run() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.begin_sensitive_info_reset(integer,uuid) TO dvaia_identity_runtime;
GRANT SELECT,UPDATE(status,lease_token,lease_expires_at,failure_code,updated_at,completed_at)
 ON identity.sensitive_info_resets TO dvaia_identity_runtime;
GRANT SELECT,UPDATE(status,attempts,failure_code,completed_at)
 ON identity.sensitive_info_reset_steps TO dvaia_identity_runtime;
