-- Forward-only cross-process admission fence for the applied 0077 XSS parent
-- journal. Every admission path shares the owner row; begin takes it FOR
-- UPDATE before publishing a parent operation. This closes both race orders.
CREATE OR REPLACE FUNCTION identity.assert_xss_parent_reset_current(
  requested_operation_id uuid, requested_token uuid
) RETURNS SETOF identity.xss_parent_reset_operations
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,identity AS $$
DECLARE requested_owner_id integer;
DECLARE operation identity.xss_parent_reset_operations%ROWTYPE;
BEGIN
  IF requested_operation_id IS NULL OR requested_token IS NULL THEN
    RAISE EXCEPTION 'Invalid XSS parent reset lease' USING ERRCODE='22023';
  END IF;
  -- The operation owner is immutable. Read only that coordinate, then acquire
  -- the global user-before-parent order used by begin and every admission gate.
  SELECT p.owner_id INTO requested_owner_id
    FROM identity.xss_parent_reset_operations p
    WHERE p.operation_id=requested_operation_id;
  IF NOT FOUND THEN RETURN; END IF;
  PERFORM 1 FROM identity.users u
    WHERE u.id=requested_owner_id AND u.is_active=1
      AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_jobs d
        WHERE d.subject_user_id=u.id)
    FOR UPDATE OF u;
  IF NOT FOUND THEN RETURN; END IF;
  SELECT p.* INTO operation FROM identity.xss_parent_reset_operations p
    WHERE p.operation_id=requested_operation_id AND p.owner_id=requested_owner_id
      AND p.status='running' AND p.lease_token=requested_token
      AND p.lease_expires_at>clock_timestamp()
    FOR UPDATE OF p;
  IF FOUND THEN RETURN NEXT operation; END IF;
END $$;

CREATE FUNCTION identity.assert_xss_mutation_admitted(requested_owner_id integer)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,identity AS $$
BEGIN
  IF requested_owner_id IS NULL OR requested_owner_id<=0 THEN
    RAISE EXCEPTION 'Invalid XSS owner' USING ERRCODE='22023';
  END IF;
  PERFORM 1 FROM identity.users u WHERE u.id=requested_owner_id AND u.is_active=1
    AND NOT EXISTS(SELECT 1 FROM identity.student_deletion_jobs d
      WHERE d.subject_user_id=u.id)
    FOR SHARE OF u;
  IF NOT FOUND THEN RAISE EXCEPTION 'XSS owner is unavailable' USING ERRCODE='55000'; END IF;
  IF EXISTS(SELECT 1 FROM identity.xss_parent_reset_operations p
    WHERE p.owner_id=requested_owner_id AND p.status<>'completed') THEN
    RAISE EXCEPTION 'XSS parent reset is in progress' USING ERRCODE='55000';
  END IF;
  RETURN true;
END $$;

CREATE OR REPLACE FUNCTION identity.guard_xss_parent_reset_admission() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,identity AS $$
DECLARE candidate_owner integer;
BEGIN
  IF TG_OP='UPDATE' THEN
    -- Moving a protected row cannot evade the fence. Lock both old and new
    -- XSS owners in numeric order so cross-owner updates cannot invert locks.
    FOR candidate_owner IN
      SELECT DISTINCT v.owner_id FROM (VALUES
        (CASE WHEN OLD.workshop_key='xss_workshop' THEN OLD.user_id END),
        (CASE WHEN NEW.workshop_key='xss_workshop' THEN NEW.user_id END)
      ) AS v(owner_id) WHERE v.owner_id IS NOT NULL ORDER BY v.owner_id
    LOOP
      PERFORM identity.assert_xss_mutation_admitted(candidate_owner);
    END LOOP;
  ELSIF NEW.workshop_key='xss_workshop' THEN
    PERFORM identity.assert_xss_mutation_admitted(NEW.user_id);
  END IF;
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION identity.guard_xss_parent_reset_run() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,identity AS $$
DECLARE uid integer;
BEGIN
  IF NEW.status='running' AND NEW.owner_key~'^\["XSS","[1-9][0-9]*"\]$' THEN
    uid:=(NEW.owner_key::jsonb->>1)::integer;
    PERFORM identity.assert_xss_mutation_admitted(uid);
  END IF;
  RETURN NEW;
END $$;

CREATE FUNCTION identity.guard_xss_parent_reset_scope_binding() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,identity AS $$
BEGIN
  PERFORM identity.assert_xss_mutation_admitted(NEW.owner_id);
  RETURN NEW;
END $$;
CREATE TRIGGER xss_parent_reset_scope_binding_guard
  BEFORE INSERT ON identity.xss_run_bindings
  FOR EACH ROW EXECUTE FUNCTION identity.guard_xss_parent_reset_scope_binding();

REVOKE ALL ON FUNCTION identity.assert_xss_parent_reset_current(uuid,uuid),
  identity.assert_xss_mutation_admitted(integer),
  identity.guard_xss_parent_reset_admission(),identity.guard_xss_parent_reset_run(),
  identity.guard_xss_parent_reset_scope_binding() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.assert_xss_parent_reset_current(uuid,uuid)
  TO dvaia_identity_runtime;
GRANT EXECUTE ON FUNCTION identity.assert_xss_mutation_admitted(integer)
  TO dvaia_identity_runtime;
