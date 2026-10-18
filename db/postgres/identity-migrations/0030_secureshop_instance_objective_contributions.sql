-- DRAFT ONLY. Do not add to the identity migration ledger until the
-- SecureShop catalog, reset retirement, and bound grading composition are
-- qualified together.

ALTER TABLE workshop_platform.objective_judgments
  ADD COLUMN platform_launch_id uuid,
  ADD COLUMN platform_scenario_id uuid,
  ADD COLUMN platform_launch_generation bigint,
  ADD CONSTRAINT objective_judgments_launch_scope_shape CHECK (
    (platform_launch_id IS NULL
      AND platform_scenario_id IS NULL
      AND platform_launch_generation IS NULL)
    OR
    (platform_launch_id IS NOT NULL
      AND platform_scenario_id IS NOT NULL
      AND platform_launch_generation BETWEEN 1 AND 9007199254740991)
  );

-- This workshop is not activated yet. Refuse a future migration if any caller
-- has written canonical credit or judgments without instance provenance.
DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM workshop_platform.completions
      WHERE workshop_key='secureshop_agent_security')
     OR EXISTS (SELECT 1 FROM workshop_platform.objective_judgments
      WHERE workshop_key='secureshop_agent_security') THEN
    RAISE EXCEPTION 'SecureShop progress already exists without instance provenance';
  END IF;
END $$;

CREATE FUNCTION workshop_platform.guard_objective_judgment_launch_scope()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity, workshop_platform
AS $$
DECLARE authority identity.secureshop_launches%ROWTYPE;
DECLARE authority_session_id integer;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF NEW.platform_launch_id IS DISTINCT FROM OLD.platform_launch_id
       OR NEW.platform_scenario_id IS DISTINCT FROM OLD.platform_scenario_id
       OR NEW.platform_launch_generation IS DISTINCT FROM OLD.platform_launch_generation
       OR (OLD.platform_launch_id IS NOT NULL AND (
         NEW.user_id IS DISTINCT FROM OLD.user_id
         OR NEW.evaluation_id IS DISTINCT FROM OLD.evaluation_id
         OR NEW.workshop_key IS DISTINCT FROM OLD.workshop_key
         OR NEW.objective_id IS DISTINCT FROM OLD.objective_id
       ))
       OR (NEW.workshop_key='secureshop_agent_security'
         AND NEW.platform_launch_id IS NULL)
       OR (NEW.workshop_key<>'secureshop_agent_security'
         AND NEW.platform_launch_id IS NOT NULL) THEN
      RAISE EXCEPTION 'Objective judgment launch scope is immutable';
    END IF;
    RETURN NEW;
  END IF;

  IF NEW.workshop_key = 'secureshop_agent_security' THEN
    IF NEW.platform_launch_id IS NULL
       OR NEW.platform_scenario_id IS NULL
       OR NEW.platform_launch_generation IS NULL THEN
      RAISE EXCEPTION 'SecureShop objective judgment requires launch scope';
    END IF;
    SELECT l.platform_session_id INTO authority_session_id
      FROM identity.secureshop_launches l WHERE l.launch_id=NEW.platform_launch_id;
    PERFORM 1 FROM identity.users u
      WHERE u.id=NEW.user_id AND u.is_active=1
        AND (u.account_locked_until IS NULL OR u.account_locked_until<=clock_timestamp())
      FOR SHARE OF u;
    PERFORM 1 FROM identity.user_sessions s
      WHERE s.id=authority_session_id AND s.user_id=NEW.user_id
        AND s.is_active=1 AND s.expires_at>clock_timestamp()
      FOR SHARE OF s;
    SELECT l.* INTO authority
      FROM identity.secureshop_launches l
      JOIN identity.user_sessions s ON s.id=l.platform_session_id
      JOIN identity.users u ON u.id=s.user_id
      WHERE l.launch_id=NEW.platform_launch_id
        AND l.scenario_id=NEW.platform_scenario_id
        AND l.generation=NEW.platform_launch_generation
        AND l.original_platform_owner_id=NEW.user_id
        AND s.user_id=NEW.user_id AND s.is_active=1 AND s.expires_at>clock_timestamp()
        AND u.is_active=1
        AND (u.account_locked_until IS NULL OR u.account_locked_until<=clock_timestamp())
        AND l.status='active' AND l.expires_at>clock_timestamp()
      FOR SHARE OF l;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'SecureShop objective judgment launch scope is stale or unauthorized';
    END IF;
  ELSIF NEW.platform_launch_id IS NOT NULL
     OR NEW.platform_scenario_id IS NOT NULL
     OR NEW.platform_launch_generation IS NOT NULL THEN
    RAISE EXCEPTION 'Launch scope is reserved for SecureShop objective judgments';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER objective_judgment_launch_scope_guard
BEFORE INSERT OR UPDATE ON workshop_platform.objective_judgments
FOR EACH ROW EXECUTE FUNCTION workshop_platform.guard_objective_judgment_launch_scope();

CREATE TABLE workshop_platform.objective_contributions (
  user_id integer NOT NULL,
  evaluation_id uuid NOT NULL,
  workshop_key text NOT NULL CHECK (workshop_key = 'secureshop_agent_security'),
  objective_id text NOT NULL,
  platform_launch_id uuid NOT NULL
    REFERENCES identity.secureshop_launches(launch_id) ON DELETE RESTRICT,
  platform_scenario_id uuid NOT NULL,
  platform_launch_generation bigint NOT NULL
    CHECK (platform_launch_generation BETWEEN 1 AND 9007199254740991),
  workshop_generation integer NOT NULL CHECK (workshop_generation >= 0),
  accepted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (user_id,evaluation_id),
  FOREIGN KEY (user_id,evaluation_id)
    REFERENCES workshop_platform.objective_judgments(user_id,evaluation_id)
    ON DELETE RESTRICT,
  FOREIGN KEY (workshop_key,objective_id)
    REFERENCES workshop_platform.objectives(workshop_key,objective_id)
    ON DELETE RESTRICT
);

CREATE INDEX objective_contributions_instance
  ON workshop_platform.objective_contributions
    (user_id,platform_launch_id,platform_launch_generation,objective_id);

CREATE INDEX objective_contributions_canonical
  ON workshop_platform.objective_contributions
    (user_id,workshop_key,workshop_generation,objective_id);

CREATE FUNCTION workshop_platform.guard_objective_contribution()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity, workshop_platform
AS $$
DECLARE judgment workshop_platform.objective_judgments%ROWTYPE;
DECLARE live_generation integer;
DECLARE authority_session_id integer;
BEGIN
  IF TG_OP <> 'INSERT' THEN
    RAISE EXCEPTION 'Accepted objective contributions are immutable';
  END IF;

  -- Keep the same order as launch issuance/reset and the repository:
  -- owner, session, launch, workshop state, judgment/contribution/completion.
  SELECT l.platform_session_id INTO authority_session_id
    FROM identity.secureshop_launches l WHERE l.launch_id=NEW.platform_launch_id;
  PERFORM 1 FROM identity.users u
    WHERE u.id=NEW.user_id AND u.is_active=1
      AND (u.account_locked_until IS NULL OR u.account_locked_until<=clock_timestamp())
    FOR SHARE OF u;
  PERFORM 1 FROM identity.user_sessions s
    WHERE s.id=authority_session_id AND s.user_id=NEW.user_id
      AND s.is_active=1 AND s.expires_at>clock_timestamp()
    FOR SHARE OF s;
  PERFORM 1 FROM identity.secureshop_launches l
    JOIN identity.user_sessions s ON s.id=l.platform_session_id
    JOIN identity.users u ON u.id=s.user_id
    WHERE l.launch_id=NEW.platform_launch_id
      AND l.scenario_id=NEW.platform_scenario_id
      AND l.generation=NEW.platform_launch_generation
      AND l.original_platform_owner_id=NEW.user_id
      AND s.user_id=NEW.user_id AND s.is_active=1 AND s.expires_at>clock_timestamp()
      AND u.is_active=1
      AND (u.account_locked_until IS NULL OR u.account_locked_until<=clock_timestamp())
      AND l.status='active' AND l.expires_at>clock_timestamp()
    FOR SHARE OF l;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Accepted contribution launch scope is stale or unauthorized';
  END IF;

  SELECT s.generation INTO live_generation
    FROM workshop_platform.user_state s
    WHERE s.user_id=NEW.user_id AND s.workshop_key=NEW.workshop_key
    FOR SHARE OF s;
  IF live_generation IS NULL OR live_generation<>NEW.workshop_generation THEN
    RAISE EXCEPTION 'Accepted contribution workshop generation is stale';
  END IF;

  SELECT j.* INTO judgment
    FROM workshop_platform.objective_judgments j
    WHERE j.user_id=NEW.user_id AND j.evaluation_id=NEW.evaluation_id;
  IF NOT FOUND
     OR judgment.workshop_key<>NEW.workshop_key
     OR judgment.objective_id<>NEW.objective_id
     OR judgment.platform_launch_id<>NEW.platform_launch_id
     OR judgment.platform_scenario_id<>NEW.platform_scenario_id
     OR judgment.platform_launch_generation<>NEW.platform_launch_generation
     OR judgment.generation<>NEW.workshop_generation
     OR judgment.verdict<>'pass'
     OR judgment.disposition NOT IN ('awarded','already_complete')
     OR judgment.evaluated_at IS NULL THEN
    RAISE EXCEPTION 'Accepted contribution does not match an authoritative passing judgment';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER objective_contribution_guard
BEFORE INSERT OR UPDATE OR DELETE ON workshop_platform.objective_contributions
FOR EACH ROW EXECUTE FUNCTION workshop_platform.guard_objective_contribution();

-- Canonical SecureShop completion is a projection of one immutable accepted
-- judgment.  The runtime role cannot write that projection directly.
ALTER TABLE workshop_platform.completions ENABLE ROW LEVEL SECURITY;
CREATE POLICY completions_runtime_read ON workshop_platform.completions
  FOR SELECT TO dvaia_identity_runtime USING (true);
CREATE POLICY completions_runtime_legacy_insert ON workshop_platform.completions
  FOR INSERT TO dvaia_identity_runtime
  WITH CHECK (workshop_key <> 'secureshop_agent_security');
CREATE POLICY completions_runtime_legacy_update ON workshop_platform.completions
  FOR UPDATE TO dvaia_identity_runtime
  USING (workshop_key <> 'secureshop_agent_security')
  WITH CHECK (workshop_key <> 'secureshop_agent_security');
CREATE POLICY completions_runtime_legacy_delete ON workshop_platform.completions
  FOR DELETE TO dvaia_identity_runtime
  USING (workshop_key <> 'secureshop_agent_security');

CREATE FUNCTION workshop_platform.accept_secureshop_objective_contribution(
  requested_user_id integer,
  requested_evaluation_id uuid
) RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, identity, workshop_platform
AS $$
DECLARE judgment workshop_platform.objective_judgments%ROWTYPE;
DECLARE completion_inserted boolean;
DECLARE authority_session_id integer;
BEGIN
  SELECT j.* INTO judgment FROM workshop_platform.objective_judgments j
    WHERE j.user_id=requested_user_id AND j.evaluation_id=requested_evaluation_id;
  IF NOT FOUND OR judgment.platform_launch_id IS NULL THEN
    RAISE EXCEPTION 'Accepted contribution requires an authoritative passing judgment';
  END IF;
  SELECT l.platform_session_id INTO authority_session_id FROM identity.secureshop_launches l
    WHERE l.launch_id=judgment.platform_launch_id;
  PERFORM 1 FROM identity.users u WHERE u.id=requested_user_id AND u.is_active=1
    AND (u.account_locked_until IS NULL OR u.account_locked_until<=clock_timestamp()) FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Accepted contribution owner is unavailable'; END IF;
  PERFORM 1 FROM identity.user_sessions s WHERE s.id=authority_session_id
    AND s.user_id=requested_user_id AND s.is_active=1 AND s.expires_at>clock_timestamp() FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Accepted contribution session is unavailable'; END IF;
  PERFORM 1 FROM identity.secureshop_launches l WHERE l.launch_id=judgment.platform_launch_id
    AND l.scenario_id=judgment.platform_scenario_id
    AND l.generation=judgment.platform_launch_generation
    AND l.original_platform_owner_id=requested_user_id AND l.platform_session_id=authority_session_id
    AND l.status='active' AND l.expires_at>clock_timestamp() FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Accepted contribution launch is stale'; END IF;
  PERFORM 1 FROM workshop_platform.user_state s WHERE s.user_id=requested_user_id
    AND s.workshop_key='secureshop_agent_security' AND s.generation=judgment.generation FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Accepted contribution workshop generation is stale'; END IF;
  SELECT j.* INTO judgment
    FROM workshop_platform.objective_judgments j
    WHERE j.user_id=requested_user_id
      AND j.evaluation_id=requested_evaluation_id
    FOR UPDATE;
  IF NOT FOUND
     OR judgment.workshop_key<>'secureshop_agent_security'
     OR judgment.platform_launch_id IS NULL
     OR judgment.verdict<>'pass'
     OR judgment.disposition NOT IN ('awarded','already_complete')
     OR judgment.evaluated_at IS NULL THEN
    RAISE EXCEPTION 'Accepted contribution requires an authoritative passing judgment';
  END IF;

  INSERT INTO workshop_platform.objective_contributions
    (user_id,evaluation_id,workshop_key,objective_id,platform_launch_id,
     platform_scenario_id,platform_launch_generation,workshop_generation)
  VALUES(judgment.user_id,judgment.evaluation_id,judgment.workshop_key,
    judgment.objective_id,judgment.platform_launch_id,
    judgment.platform_scenario_id,judgment.platform_launch_generation,
    judgment.generation);

  WITH inserted AS (
    INSERT INTO workshop_platform.completions
      (user_id,workshop_key,objective_id)
    VALUES(judgment.user_id,judgment.workshop_key,judgment.objective_id)
    ON CONFLICT DO NOTHING RETURNING 1
  ) SELECT EXISTS(SELECT 1 FROM inserted) INTO completion_inserted;
  IF completion_inserted IS DISTINCT FROM (judgment.disposition='awarded') THEN
    RAISE EXCEPTION 'Accepted contribution disposition does not match canonical projection';
  END IF;
  RETURN completion_inserted;
END $$;

REVOKE ALL ON FUNCTION workshop_platform.guard_objective_judgment_launch_scope() FROM PUBLIC;
REVOKE ALL ON FUNCTION workshop_platform.guard_objective_contribution() FROM PUBLIC;
REVOKE ALL ON FUNCTION workshop_platform.accept_secureshop_objective_contribution(integer,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION workshop_platform.guard_objective_judgment_launch_scope() TO dvaia_identity_runtime;
GRANT EXECUTE ON FUNCTION workshop_platform.guard_objective_contribution() TO dvaia_identity_runtime;
GRANT EXECUTE ON FUNCTION workshop_platform.accept_secureshop_objective_contribution(integer,uuid) TO dvaia_identity_runtime;
GRANT SELECT ON workshop_platform.objective_contributions TO dvaia_identity_runtime;
