-- DRAFT: not auto-applied. Instance-scoped SecureShop progress retirement.
-- Apply after secureshop-instance-objective-contributions.sql. Contributions
-- and time rows remain history; this receipt retires one launch generation.
DO $$ BEGIN
  IF EXISTS(SELECT 1 FROM workshop_platform.activity_counters
      WHERE workshop_key='secureshop_agent_security')
    OR EXISTS(SELECT 1 FROM workshop_platform.time_tracking
      WHERE workshop_key='secureshop_agent_security') THEN
    RAISE EXCEPTION 'SecureShop progress exists without instance provenance';
  END IF;
END $$;

ALTER TABLE identity.secureshop_launch_resets
  ADD COLUMN progress_reconciliation_required boolean NOT NULL DEFAULT true;
CREATE INDEX secureshop_launch_reset_progress_pending
  ON identity.secureshop_launch_resets(updated_at) WHERE progress_reconciliation_required;

CREATE TABLE workshop_platform.instance_activity_contributions (
  user_id integer NOT NULL REFERENCES identity.users(id) ON DELETE RESTRICT,
  contribution_id uuid NOT NULL,
  workshop_key text NOT NULL CHECK (workshop_key='secureshop_agent_security'),
  activity_key text NOT NULL CHECK (activity_key ~ '^[a-z][a-z0-9_-]{0,99}$'),
  activity_delta integer NOT NULL CHECK (activity_delta BETWEEN 1 AND 1000000),
  platform_launch_id uuid NOT NULL REFERENCES identity.secureshop_launches(launch_id) ON DELETE RESTRICT,
  platform_scenario_id uuid NOT NULL,
  platform_launch_generation bigint NOT NULL CHECK (platform_launch_generation BETWEEN 1 AND 9007199254740991),
  workshop_generation integer NOT NULL CHECK (workshop_generation>=0),
  accepted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(user_id,contribution_id)
);
CREATE INDEX instance_activity_by_instance ON workshop_platform.instance_activity_contributions
  (user_id,platform_launch_id,platform_launch_generation,activity_key);
CREATE INDEX instance_activity_by_projection ON workshop_platform.instance_activity_contributions
  (user_id,workshop_key,workshop_generation,activity_key);

ALTER TABLE workshop_platform.time_tracking
  ADD COLUMN platform_launch_id uuid REFERENCES identity.secureshop_launches(launch_id) ON DELETE RESTRICT,
  ADD COLUMN platform_scenario_id uuid,
  ADD COLUMN platform_launch_generation bigint,
  ADD COLUMN workshop_generation integer,
  ADD CONSTRAINT time_tracking_instance_shape CHECK (
    (platform_launch_id IS NULL AND platform_scenario_id IS NULL
      AND platform_launch_generation IS NULL AND workshop_generation IS NULL)
    OR (platform_launch_id IS NOT NULL AND platform_scenario_id IS NOT NULL
      AND platform_launch_generation BETWEEN 1 AND 9007199254740991
      AND workshop_generation>=0));
CREATE INDEX time_tracking_instance ON workshop_platform.time_tracking
  (user_id,platform_launch_id,platform_launch_generation,id DESC);

CREATE FUNCTION workshop_platform.validate_secureshop_progress_source()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,identity,workshop_platform AS $$
DECLARE owner_id integer; DECLARE session_id integer; DECLARE live_generation integer;
BEGIN
  IF TG_TABLE_NAME='time_tracking' THEN
    IF TG_OP='UPDATE' AND ROW(NEW.user_id,NEW.workshop_key,NEW.platform_launch_id,
      NEW.platform_scenario_id,NEW.platform_launch_generation,NEW.workshop_generation,
      NEW.session_start) IS DISTINCT FROM ROW(OLD.user_id,OLD.workshop_key,OLD.platform_launch_id,
      OLD.platform_scenario_id,OLD.platform_launch_generation,OLD.workshop_generation,
      OLD.session_start) THEN
      RAISE EXCEPTION 'Time contribution identity is immutable' USING ERRCODE='55000';
    END IF;
    IF NEW.workshop_key<>'secureshop_agent_security' THEN
      IF NEW.platform_launch_id IS NOT NULL THEN RAISE EXCEPTION 'Launch scope is reserved for SecureShop time'; END IF;
      RETURN NEW;
    END IF;
    IF NEW.platform_launch_id IS NULL THEN RAISE EXCEPTION 'SecureShop time requires launch scope'; END IF;
  ELSE
    IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Instance activity contributions are immutable' USING ERRCODE='55000'; END IF;
  END IF;
  owner_id:=NEW.user_id;
  SELECT l.platform_session_id INTO session_id FROM identity.secureshop_launches l
    WHERE l.launch_id=NEW.platform_launch_id;
  PERFORM 1 FROM identity.users u WHERE u.id=owner_id AND u.is_active=1
    AND (u.account_locked_until IS NULL OR u.account_locked_until<=clock_timestamp()) FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'SecureShop progress owner is unavailable'; END IF;
  PERFORM 1 FROM identity.user_sessions s WHERE s.id=session_id AND s.user_id=owner_id
    AND s.is_active=1 AND s.expires_at>clock_timestamp() FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'SecureShop progress session is unavailable'; END IF;
  PERFORM 1 FROM identity.secureshop_launches l WHERE l.launch_id=NEW.platform_launch_id
    AND l.scenario_id=NEW.platform_scenario_id AND l.generation=NEW.platform_launch_generation
    AND l.original_platform_owner_id=owner_id AND l.platform_session_id=session_id
    AND l.status='active' AND l.expires_at>clock_timestamp() FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'SecureShop progress launch is stale'; END IF;
  SELECT s.generation INTO live_generation FROM workshop_platform.user_state s
    WHERE s.user_id=owner_id AND s.workshop_key='secureshop_agent_security' FOR SHARE;
  IF live_generation IS NULL OR live_generation<>NEW.workshop_generation THEN
    RAISE EXCEPTION 'SecureShop progress generation is stale';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER instance_activity_source_guard BEFORE INSERT OR UPDATE OR DELETE
  ON workshop_platform.instance_activity_contributions FOR EACH ROW
  EXECUTE FUNCTION workshop_platform.validate_secureshop_progress_source();
CREATE TRIGGER time_tracking_instance_guard BEFORE INSERT OR UPDATE
  ON workshop_platform.time_tracking FOR EACH ROW
  EXECUTE FUNCTION workshop_platform.validate_secureshop_progress_source();

-- Keep legacy workshop mutations available while making every SecureShop row
-- writable only through the fixed-purpose functions below.  Table owners used
-- by migrations retain their normal PostgreSQL RLS bypass.
ALTER TABLE workshop_platform.activity_counters ENABLE ROW LEVEL SECURITY;
CREATE POLICY activity_counters_runtime_read ON workshop_platform.activity_counters
  FOR SELECT TO dvaia_identity_runtime USING (true);
CREATE POLICY activity_counters_runtime_legacy_insert ON workshop_platform.activity_counters
  FOR INSERT TO dvaia_identity_runtime WITH CHECK (workshop_key<>'secureshop_agent_security');
CREATE POLICY activity_counters_runtime_legacy_update ON workshop_platform.activity_counters
  FOR UPDATE TO dvaia_identity_runtime USING (workshop_key<>'secureshop_agent_security')
  WITH CHECK (workshop_key<>'secureshop_agent_security');
CREATE POLICY activity_counters_runtime_legacy_delete ON workshop_platform.activity_counters
  FOR DELETE TO dvaia_identity_runtime USING (workshop_key<>'secureshop_agent_security');

ALTER TABLE workshop_platform.time_tracking ENABLE ROW LEVEL SECURITY;
CREATE POLICY time_tracking_runtime_read ON workshop_platform.time_tracking
  FOR SELECT TO dvaia_identity_runtime USING (true);
CREATE POLICY time_tracking_runtime_legacy_insert ON workshop_platform.time_tracking
  FOR INSERT TO dvaia_identity_runtime WITH CHECK (workshop_key<>'secureshop_agent_security');
CREATE POLICY time_tracking_runtime_legacy_update ON workshop_platform.time_tracking
  FOR UPDATE TO dvaia_identity_runtime USING (workshop_key<>'secureshop_agent_security')
  WITH CHECK (workshop_key<>'secureshop_agent_security');
CREATE POLICY time_tracking_runtime_legacy_delete ON workshop_platform.time_tracking
  FOR DELETE TO dvaia_identity_runtime USING (workshop_key<>'secureshop_agent_security');

CREATE FUNCTION workshop_platform.record_secureshop_activity_contribution(
  requested_user_id integer, requested_contribution_id uuid,
  requested_activity_key text, requested_activity_delta integer,
  requested_launch_id uuid, requested_scenario_id uuid,
  requested_launch_generation bigint, requested_workshop_generation integer
) RETURNS TABLE(changed boolean, activity_count integer)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,identity,workshop_platform AS $$
DECLARE prior workshop_platform.instance_activity_contributions%ROWTYPE;
DECLARE authority_session_id integer;
BEGIN
  SELECT l.platform_session_id INTO authority_session_id FROM identity.secureshop_launches l
    WHERE l.launch_id=requested_launch_id;
  PERFORM 1 FROM identity.users u WHERE u.id=requested_user_id AND u.is_active=1
    AND (u.account_locked_until IS NULL OR u.account_locked_until<=clock_timestamp()) FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'SecureShop activity owner is unavailable'; END IF;
  PERFORM 1 FROM identity.user_sessions s WHERE s.id=authority_session_id
    AND s.user_id=requested_user_id AND s.is_active=1 AND s.expires_at>clock_timestamp() FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'SecureShop activity session is unavailable'; END IF;
  PERFORM 1 FROM identity.secureshop_launches l WHERE l.launch_id=requested_launch_id
    AND l.scenario_id=requested_scenario_id AND l.generation=requested_launch_generation
    AND l.original_platform_owner_id=requested_user_id AND l.platform_session_id=authority_session_id
    AND l.status='active' AND l.expires_at>clock_timestamp() FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'SecureShop activity launch is stale'; END IF;
  PERFORM 1 FROM workshop_platform.user_state s WHERE s.user_id=requested_user_id
    AND s.workshop_key='secureshop_agent_security'
    AND s.generation=requested_workshop_generation FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'SecureShop activity workshop generation is stale'; END IF;
  INSERT INTO workshop_platform.instance_activity_contributions
    (user_id,contribution_id,workshop_key,activity_key,activity_delta,
     platform_launch_id,platform_scenario_id,platform_launch_generation,workshop_generation)
  VALUES(requested_user_id,requested_contribution_id,'secureshop_agent_security',
    requested_activity_key,requested_activity_delta,requested_launch_id,
    requested_scenario_id,requested_launch_generation,requested_workshop_generation)
  ON CONFLICT(user_id,contribution_id) DO NOTHING;
  changed:=FOUND;
  IF NOT changed THEN
    SELECT a.* INTO prior FROM workshop_platform.instance_activity_contributions a
      WHERE a.user_id=requested_user_id AND a.contribution_id=requested_contribution_id;
    IF NOT FOUND OR prior.workshop_key<>'secureshop_agent_security'
       OR prior.activity_key<>requested_activity_key
       OR prior.activity_delta<>requested_activity_delta
       OR prior.platform_launch_id<>requested_launch_id
       OR prior.platform_scenario_id<>requested_scenario_id
       OR prior.platform_launch_generation<>requested_launch_generation
       OR prior.workshop_generation<>requested_workshop_generation THEN
      RAISE EXCEPTION 'Activity contribution idempotency scope changed';
    END IF;
  END IF;
  SELECT COALESCE(sum(a.activity_delta),0)::integer INTO activity_count
    FROM workshop_platform.instance_activity_contributions a
    WHERE a.user_id=requested_user_id AND a.workshop_key='secureshop_agent_security'
      AND a.activity_key=requested_activity_key
      AND a.workshop_generation=requested_workshop_generation
      AND NOT EXISTS(SELECT 1 FROM identity.secureshop_progress_cleanup_history h
        WHERE h.launch_id=a.platform_launch_id
          AND h.from_launch_generation=a.platform_launch_generation);
  INSERT INTO workshop_platform.activity_counters(user_id,workshop_key,activity_key,activity_count)
    VALUES(requested_user_id,'secureshop_agent_security',requested_activity_key,activity_count)
    ON CONFLICT(user_id,workshop_key,activity_key) DO UPDATE
      SET activity_count=EXCLUDED.activity_count,updated_at=clock_timestamp();
  RETURN NEXT;
END $$;

CREATE FUNCTION workshop_platform.record_secureshop_heartbeat(
  requested_user_id integer,
  requested_launch_id uuid, requested_scenario_id uuid,
  requested_launch_generation bigint, requested_workshop_generation integer
) RETURNS TABLE(added integer,new_session boolean)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,identity,workshop_platform AS $$
DECLARE current_row workshop_platform.time_tracking%ROWTYPE;
DECLARE elapsed integer;
DECLARE recorded_at timestamptz;
DECLARE authority_session_id integer;
BEGIN
  recorded_at:=clock_timestamp();
  SELECT l.platform_session_id INTO authority_session_id FROM identity.secureshop_launches l
    WHERE l.launch_id=requested_launch_id;
  PERFORM 1 FROM identity.users u WHERE u.id=requested_user_id AND u.is_active=1
    AND (u.account_locked_until IS NULL OR u.account_locked_until<=clock_timestamp()) FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'SecureShop heartbeat owner is unavailable'; END IF;
  PERFORM 1 FROM identity.user_sessions s WHERE s.id=authority_session_id
    AND s.user_id=requested_user_id AND s.is_active=1 AND s.expires_at>clock_timestamp() FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'SecureShop heartbeat session is unavailable'; END IF;
  PERFORM 1 FROM identity.secureshop_launches l WHERE l.launch_id=requested_launch_id
    AND l.scenario_id=requested_scenario_id AND l.generation=requested_launch_generation
    AND l.original_platform_owner_id=requested_user_id AND l.platform_session_id=authority_session_id
    AND l.status='active' AND l.expires_at>clock_timestamp() FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'SecureShop heartbeat launch is stale'; END IF;
  PERFORM 1 FROM workshop_platform.user_state s WHERE s.user_id=requested_user_id
    AND s.workshop_key='secureshop_agent_security'
    AND s.generation=requested_workshop_generation FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'SecureShop heartbeat workshop generation is stale'; END IF;
  SELECT t.* INTO current_row FROM workshop_platform.time_tracking t
    WHERE t.user_id=requested_user_id AND t.workshop_key='secureshop_agent_security'
      AND t.platform_launch_id=requested_launch_id
      AND t.platform_launch_generation=requested_launch_generation
      AND t.workshop_generation=requested_workshop_generation
    ORDER BY t.id DESC LIMIT 1 FOR UPDATE;
  elapsed:=CASE WHEN current_row.id IS NULL THEN 120
    ELSE round(extract(epoch FROM (recorded_at-current_row.last_heartbeat)))::integer END;
  IF elapsed<=0 THEN added:=0;new_session:=false;RETURN NEXT;RETURN;END IF;
  IF current_row.id IS NOT NULL AND elapsed<120 THEN
    UPDATE workshop_platform.time_tracking SET last_heartbeat=recorded_at,
      duration_seconds=duration_seconds+elapsed WHERE id=current_row.id;
    added:=elapsed;new_session:=false;
  ELSE
    INSERT INTO workshop_platform.time_tracking
      (user_id,workshop_key,session_start,last_heartbeat,platform_launch_id,
       platform_scenario_id,platform_launch_generation,workshop_generation)
    VALUES(requested_user_id,'secureshop_agent_security',recorded_at,recorded_at,
      requested_launch_id,requested_scenario_id,requested_launch_generation,
      requested_workshop_generation);
    added:=0;new_session:=true;
  END IF;
  RETURN NEXT;
END $$;

CREATE TABLE identity.secureshop_progress_cleanup_history (
  reset_id uuid PRIMARY KEY REFERENCES identity.secureshop_launch_resets(reset_id) ON DELETE RESTRICT,
  launch_id uuid NOT NULL REFERENCES identity.secureshop_launches(launch_id) ON DELETE RESTRICT,
  scenario_id uuid NOT NULL,
  from_launch_generation bigint NOT NULL CHECK (from_launch_generation BETWEEN 1 AND 9007199254740991),
  original_platform_owner_id integer NOT NULL CHECK (original_platform_owner_id>=1),
  original_platform_session_id integer NOT NULL CHECK (original_platform_session_id>=1),
  workshop_key text NOT NULL CHECK (workshop_key='secureshop_agent_security'),
  workshop_generation integer NOT NULL CHECK (workshop_generation>=0),
  retired_objective_contribution_count integer NOT NULL CHECK (retired_objective_contribution_count>=0),
  retired_activity_contribution_count integer NOT NULL CHECK (retired_activity_contribution_count>=0),
  retired_time_entry_count integer NOT NULL CHECK (retired_time_entry_count>=0),
  retired_time_seconds bigint NOT NULL CHECK (retired_time_seconds>=0),
  projected_completion_count integer NOT NULL CHECK (projected_completion_count>=0),
  projected_activity_count integer NOT NULL CHECK (projected_activity_count>=0),
  projected_time_entry_count integer NOT NULL CHECK (projected_time_entry_count>=0),
  projected_time_seconds bigint NOT NULL CHECK (projected_time_seconds>=0),
  completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(launch_id,from_launch_generation)
);

CREATE FUNCTION identity.validate_secureshop_progress_cleanup_history()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,identity,workshop_platform AS $$
DECLARE launch identity.secureshop_launches%ROWTYPE;
DECLARE reset identity.secureshop_launch_resets%ROWTYPE;
DECLARE live_generation integer;
DECLARE actual integer;
DECLARE actual_seconds bigint;
DECLARE catalog_ready boolean;
DECLARE coordinates identity.secureshop_launches%ROWTYPE;
BEGIN
  SELECT * INTO coordinates FROM identity.secureshop_launches WHERE launch_id=NEW.launch_id;
  IF coordinates.launch_id IS NULL THEN RAISE EXCEPTION 'SecureShop progress cleanup launch is unavailable'; END IF;
  PERFORM 1 FROM identity.users WHERE id=coordinates.original_platform_owner_id FOR SHARE;
  PERFORM 1 FROM identity.user_sessions WHERE id=coordinates.original_platform_session_id FOR SHARE;
  SELECT * INTO launch FROM identity.secureshop_launches WHERE launch_id=NEW.launch_id FOR UPDATE;
  SELECT * INTO reset FROM identity.secureshop_launch_resets WHERE reset_id=NEW.reset_id FOR UPDATE;
  PERFORM 1 FROM workshop_platform.config_revision WHERE id=1 FOR SHARE;
  SELECT true INTO catalog_ready FROM workshop_platform.exercises WHERE workshop_key='secureshop_agent_security'
    AND catalog_active=true FOR SHARE;
  SELECT generation INTO live_generation FROM workshop_platform.user_state
    WHERE user_id=NEW.original_platform_owner_id AND workshop_key=NEW.workshop_key FOR UPDATE;
  IF launch.launch_id IS NULL OR reset.reset_id IS NULL OR catalog_ready IS NOT TRUE
    OR reset.launch_id<>NEW.launch_id OR reset.from_generation<>NEW.from_launch_generation
    OR launch.scenario_id<>NEW.scenario_id
    OR launch.original_platform_owner_id<>NEW.original_platform_owner_id
    OR launch.original_platform_session_id<>NEW.original_platform_session_id
    OR launch.generation<>reset.to_generation OR NEW.workshop_key<>'secureshop_agent_security'
    OR live_generation IS NULL OR live_generation<>NEW.workshop_generation THEN
    RAISE EXCEPTION 'SecureShop progress cleanup history binding is invalid';
  END IF;
  SELECT count(*)::integer INTO actual FROM workshop_platform.objective_contributions c
    WHERE c.user_id=NEW.original_platform_owner_id AND c.workshop_key=NEW.workshop_key
      AND c.workshop_generation=NEW.workshop_generation AND c.platform_launch_id=NEW.launch_id
      AND c.platform_launch_generation=NEW.from_launch_generation;
  IF actual<>NEW.retired_objective_contribution_count THEN RAISE EXCEPTION 'Retired objective count is invalid'; END IF;
  SELECT count(*)::integer INTO actual FROM workshop_platform.instance_activity_contributions a
    WHERE a.user_id=NEW.original_platform_owner_id AND a.workshop_key=NEW.workshop_key
      AND a.workshop_generation=NEW.workshop_generation AND a.platform_launch_id=NEW.launch_id
      AND a.platform_launch_generation=NEW.from_launch_generation;
  IF actual<>NEW.retired_activity_contribution_count THEN RAISE EXCEPTION 'Retired activity count is invalid'; END IF;
  SELECT count(*)::integer,COALESCE(sum(duration_seconds),0)::bigint INTO actual,actual_seconds
    FROM workshop_platform.time_tracking t WHERE t.user_id=NEW.original_platform_owner_id
      AND t.workshop_key=NEW.workshop_key AND t.workshop_generation=NEW.workshop_generation
      AND t.platform_launch_id=NEW.launch_id AND t.platform_launch_generation=NEW.from_launch_generation;
  IF actual<>NEW.retired_time_entry_count OR actual_seconds<>NEW.retired_time_seconds THEN
    RAISE EXCEPTION 'Retired time count is invalid';
  END IF;
  SELECT count(*)::integer INTO actual FROM workshop_platform.completions
    WHERE user_id=NEW.original_platform_owner_id AND workshop_key=NEW.workshop_key;
  IF actual<>NEW.projected_completion_count OR EXISTS(
      (SELECT objective_id FROM workshop_platform.completions WHERE user_id=NEW.original_platform_owner_id AND workshop_key=NEW.workshop_key
       EXCEPT SELECT DISTINCT c.objective_id FROM workshop_platform.objective_contributions c
        WHERE c.user_id=NEW.original_platform_owner_id AND c.workshop_key=NEW.workshop_key
          AND c.workshop_generation=NEW.workshop_generation
          AND NOT(c.platform_launch_id=NEW.launch_id AND c.platform_launch_generation=NEW.from_launch_generation)
          AND NOT EXISTS(SELECT 1 FROM identity.secureshop_progress_cleanup_history h
            WHERE h.launch_id=c.platform_launch_id AND h.from_launch_generation=c.platform_launch_generation))
      UNION ALL
      (SELECT DISTINCT c.objective_id FROM workshop_platform.objective_contributions c
        WHERE c.user_id=NEW.original_platform_owner_id AND c.workshop_key=NEW.workshop_key
          AND c.workshop_generation=NEW.workshop_generation
          AND NOT(c.platform_launch_id=NEW.launch_id AND c.platform_launch_generation=NEW.from_launch_generation)
          AND NOT EXISTS(SELECT 1 FROM identity.secureshop_progress_cleanup_history h
            WHERE h.launch_id=c.platform_launch_id AND h.from_launch_generation=c.platform_launch_generation)
       EXCEPT SELECT objective_id FROM workshop_platform.completions WHERE user_id=NEW.original_platform_owner_id AND workshop_key=NEW.workshop_key)) THEN
    RAISE EXCEPTION 'Completion projection is invalid';
  END IF;
  SELECT count(*)::integer INTO actual FROM workshop_platform.activity_counters
    WHERE user_id=NEW.original_platform_owner_id AND workshop_key=NEW.workshop_key;
  IF actual<>NEW.projected_activity_count OR EXISTS(SELECT 1 FROM (
    SELECT actual.activity_key,actual.activity_count,expected.expected_count
    FROM (SELECT activity_key,activity_count FROM workshop_platform.activity_counters
      WHERE user_id=NEW.original_platform_owner_id AND workshop_key=NEW.workshop_key) actual
    FULL JOIN (SELECT a.activity_key,sum(a.activity_delta)::integer AS expected_count
      FROM workshop_platform.instance_activity_contributions a
      WHERE a.user_id=NEW.original_platform_owner_id AND a.workshop_key=NEW.workshop_key
        AND a.workshop_generation=NEW.workshop_generation
        AND NOT(a.platform_launch_id=NEW.launch_id AND a.platform_launch_generation=NEW.from_launch_generation)
        AND NOT EXISTS(SELECT 1 FROM identity.secureshop_progress_cleanup_history h
          WHERE h.launch_id=a.platform_launch_id AND h.from_launch_generation=a.platform_launch_generation)
      GROUP BY a.activity_key) expected USING(activity_key)
    WHERE activity_count IS DISTINCT FROM expected_count) mismatch) THEN
    RAISE EXCEPTION 'Activity projection is invalid';
  END IF;
  SELECT count(*)::integer,COALESCE(sum(duration_seconds),0)::bigint INTO actual,actual_seconds
    FROM workshop_platform.time_tracking t WHERE t.user_id=NEW.original_platform_owner_id
      AND t.workshop_key=NEW.workshop_key AND t.workshop_generation=NEW.workshop_generation
      AND NOT(t.platform_launch_id=NEW.launch_id AND t.platform_launch_generation=NEW.from_launch_generation)
      AND NOT EXISTS(SELECT 1 FROM identity.secureshop_progress_cleanup_history h
        WHERE h.launch_id=t.platform_launch_id AND h.from_launch_generation=t.platform_launch_generation);
  IF actual<>NEW.projected_time_entry_count OR actual_seconds<>NEW.projected_time_seconds THEN
    RAISE EXCEPTION 'Time projection is invalid';
  END IF;
  NEW.completed_at:=clock_timestamp();
  RETURN NEW;
END $$;

CREATE FUNCTION identity.guard_secureshop_progress_cleanup_history()
RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
  RAISE EXCEPTION 'SecureShop progress cleanup history is immutable' USING ERRCODE='55000';
END $$;
CREATE FUNCTION identity.guard_secureshop_progress_cleanup_gate()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,identity AS $$
BEGIN
  IF NEW.progress_reconciliation_required IS DISTINCT FROM OLD.progress_reconciliation_required THEN
    IF OLD.progress_reconciliation_required IS NOT TRUE OR NEW.progress_reconciliation_required IS NOT FALSE
      OR NOT EXISTS(SELECT 1 FROM identity.secureshop_progress_cleanup_history h
        WHERE h.reset_id=NEW.reset_id AND h.launch_id=NEW.launch_id
          AND h.from_launch_generation=NEW.from_generation) THEN
      RAISE EXCEPTION 'SecureShop progress cleanup gate requires canonical history' USING ERRCODE='55000';
    END IF;
  END IF;
  IF NEW.status='committed' AND NEW.progress_reconciliation_required THEN
    RAISE EXCEPTION 'SecureShop canonical progress cleanup remains required' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER secureshop_progress_cleanup_history_immutable BEFORE UPDATE OR DELETE
  ON identity.secureshop_progress_cleanup_history FOR EACH ROW EXECUTE FUNCTION identity.guard_secureshop_progress_cleanup_history();
CREATE TRIGGER secureshop_progress_cleanup_history_validate BEFORE INSERT
  ON identity.secureshop_progress_cleanup_history FOR EACH ROW EXECUTE FUNCTION identity.validate_secureshop_progress_cleanup_history();
CREATE TRIGGER secureshop_progress_cleanup_gate BEFORE UPDATE OF status,progress_reconciliation_required
  ON identity.secureshop_launch_resets FOR EACH ROW EXECUTE FUNCTION identity.guard_secureshop_progress_cleanup_gate();

CREATE FUNCTION identity.finalize_secureshop_progress_cleanup(requested_reset_id uuid)
RETURNS SETOF identity.secureshop_progress_cleanup_history
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,identity,workshop_platform AS $$
DECLARE located_launch_id uuid;
DECLARE coordinates identity.secureshop_launches%ROWTYPE;
DECLARE launch identity.secureshop_launches%ROWTYPE;
DECLARE reset identity.secureshop_launch_resets%ROWTYPE;
DECLARE prior identity.secureshop_progress_cleanup_history%ROWTYPE;
DECLARE live_generation integer;
DECLARE retired_objectives integer;
DECLARE retired_activity integer;
DECLARE retired_time_entries integer;
DECLARE retired_time_seconds bigint;
DECLARE projected_completions integer;
DECLARE projected_activity integer;
DECLARE projected_time_entries integer;
DECLARE projected_time_seconds bigint;
DECLARE projected_started_at timestamptz;
DECLARE result identity.secureshop_progress_cleanup_history%ROWTYPE;
BEGIN
  SELECT r.launch_id INTO located_launch_id FROM identity.secureshop_launch_resets r
    WHERE r.reset_id=requested_reset_id;
  IF located_launch_id IS NULL THEN RAISE EXCEPTION 'Reset cleanup authority is required'; END IF;
  SELECT l.* INTO coordinates FROM identity.secureshop_launches l WHERE l.launch_id=located_launch_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'Reset cleanup authority is required'; END IF;
  PERFORM 1 FROM identity.users u WHERE u.id=coordinates.original_platform_owner_id FOR SHARE;
  PERFORM 1 FROM identity.user_sessions s WHERE s.id=coordinates.original_platform_session_id FOR SHARE;
  SELECT l.* INTO launch FROM identity.secureshop_launches l
    WHERE l.launch_id=located_launch_id FOR UPDATE;
  SELECT r.* INTO reset FROM identity.secureshop_launch_resets r
    WHERE r.reset_id=requested_reset_id AND r.launch_id=located_launch_id FOR UPDATE;
  IF launch.launch_id IS NULL OR reset.reset_id IS NULL
     OR reset.status NOT IN ('fenced','committed','aborted') THEN
    RAISE EXCEPTION 'Reset cleanup authority is required';
  END IF;
  SELECT h.* INTO prior FROM identity.secureshop_progress_cleanup_history h
    WHERE h.reset_id=requested_reset_id
       OR (h.launch_id=launch.launch_id AND h.from_launch_generation=reset.from_generation);
  IF FOUND THEN
    IF prior.reset_id<>requested_reset_id OR prior.launch_id<>launch.launch_id
       OR prior.scenario_id<>launch.scenario_id
       OR prior.from_launch_generation<>reset.from_generation
       OR prior.original_platform_owner_id<>launch.original_platform_owner_id
       OR prior.original_platform_session_id<>launch.original_platform_session_id
       OR prior.workshop_key<>'secureshop_agent_security'
       OR reset.progress_reconciliation_required THEN
      RAISE EXCEPTION 'SecureShop progress cleanup history mismatch';
    END IF;
    RETURN NEXT prior; RETURN;
  END IF;
  IF launch.generation<>reset.to_generation THEN RAISE EXCEPTION 'SecureShop launch generation is stale'; END IF;
  PERFORM 1 FROM workshop_platform.config_revision WHERE id=1 FOR SHARE;
  PERFORM 1 FROM workshop_platform.exercises e
    WHERE e.workshop_key='secureshop_agent_security' AND e.catalog_active=true FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'SecureShop catalog is unavailable'; END IF;
  INSERT INTO workshop_platform.user_state(user_id,workshop_key)
    VALUES(launch.original_platform_owner_id,'secureshop_agent_security') ON CONFLICT DO NOTHING;
  SELECT s.generation INTO live_generation FROM workshop_platform.user_state s
    WHERE s.user_id=launch.original_platform_owner_id
      AND s.workshop_key='secureshop_agent_security' FOR UPDATE;
  IF live_generation IS NULL OR live_generation<0 THEN RAISE EXCEPTION 'Workshop generation is stale'; END IF;

  SELECT count(*)::integer INTO retired_objectives
    FROM workshop_platform.objective_contributions c
    WHERE c.user_id=launch.original_platform_owner_id AND c.workshop_key='secureshop_agent_security'
      AND c.platform_launch_id=launch.launch_id AND c.platform_launch_generation=reset.from_generation
      AND c.workshop_generation=live_generation;
  SELECT count(*)::integer INTO retired_activity
    FROM workshop_platform.instance_activity_contributions a
    WHERE a.user_id=launch.original_platform_owner_id AND a.workshop_key='secureshop_agent_security'
      AND a.platform_launch_id=launch.launch_id AND a.platform_launch_generation=reset.from_generation
      AND a.workshop_generation=live_generation;
  SELECT count(*)::integer,COALESCE(sum(t.duration_seconds),0)::bigint
    INTO retired_time_entries,retired_time_seconds
    FROM workshop_platform.time_tracking t
    WHERE t.user_id=launch.original_platform_owner_id AND t.workshop_key='secureshop_agent_security'
      AND t.platform_launch_id=launch.launch_id AND t.platform_launch_generation=reset.from_generation
      AND t.workshop_generation=live_generation;

  DELETE FROM workshop_platform.completions c
    WHERE c.user_id=launch.original_platform_owner_id AND c.workshop_key='secureshop_agent_security';
  INSERT INTO workshop_platform.completions(user_id,workshop_key,objective_id,completed_at)
    SELECT launch.original_platform_owner_id,'secureshop_agent_security',c.objective_id,min(c.accepted_at)
    FROM workshop_platform.objective_contributions c
    WHERE c.user_id=launch.original_platform_owner_id AND c.workshop_key='secureshop_agent_security'
      AND c.workshop_generation=live_generation
      AND NOT(c.platform_launch_id=launch.launch_id AND c.platform_launch_generation=reset.from_generation)
      AND NOT EXISTS(SELECT 1 FROM identity.secureshop_progress_cleanup_history h
        WHERE h.launch_id=c.platform_launch_id AND h.from_launch_generation=c.platform_launch_generation)
    GROUP BY c.objective_id;
  DELETE FROM workshop_platform.activity_counters a
    WHERE a.user_id=launch.original_platform_owner_id AND a.workshop_key='secureshop_agent_security';
  INSERT INTO workshop_platform.activity_counters(user_id,workshop_key,activity_key,activity_count)
    SELECT launch.original_platform_owner_id,'secureshop_agent_security',a.activity_key,
      sum(a.activity_delta)::integer
    FROM workshop_platform.instance_activity_contributions a
    WHERE a.user_id=launch.original_platform_owner_id AND a.workshop_key='secureshop_agent_security'
      AND a.workshop_generation=live_generation
      AND NOT(a.platform_launch_id=launch.launch_id AND a.platform_launch_generation=reset.from_generation)
      AND NOT EXISTS(SELECT 1 FROM identity.secureshop_progress_cleanup_history h
        WHERE h.launch_id=a.platform_launch_id AND h.from_launch_generation=a.platform_launch_generation)
    GROUP BY a.activity_key;
  SELECT count(*)::integer INTO projected_completions FROM workshop_platform.completions c
    WHERE c.user_id=launch.original_platform_owner_id AND c.workshop_key='secureshop_agent_security';
  SELECT count(*)::integer INTO projected_activity FROM workshop_platform.activity_counters a
    WHERE a.user_id=launch.original_platform_owner_id AND a.workshop_key='secureshop_agent_security';
  SELECT count(*)::integer,COALESCE(sum(t.duration_seconds),0)::bigint
    INTO projected_time_entries,projected_time_seconds
    FROM workshop_platform.time_tracking t
    WHERE t.user_id=launch.original_platform_owner_id AND t.workshop_key='secureshop_agent_security'
      AND t.workshop_generation=live_generation
      AND NOT(t.platform_launch_id=launch.launch_id AND t.platform_launch_generation=reset.from_generation)
      AND NOT EXISTS(SELECT 1 FROM identity.secureshop_progress_cleanup_history h
        WHERE h.launch_id=t.platform_launch_id AND h.from_launch_generation=t.platform_launch_generation);
  SELECT min(started) INTO projected_started_at FROM (
    SELECT min(c.accepted_at) AS started FROM workshop_platform.objective_contributions c
      WHERE c.user_id=launch.original_platform_owner_id AND c.workshop_key='secureshop_agent_security'
        AND c.workshop_generation=live_generation
        AND NOT(c.platform_launch_id=launch.launch_id AND c.platform_launch_generation=reset.from_generation)
        AND NOT EXISTS(SELECT 1 FROM identity.secureshop_progress_cleanup_history h
          WHERE h.launch_id=c.platform_launch_id AND h.from_launch_generation=c.platform_launch_generation)
    UNION ALL SELECT min(a.accepted_at) FROM workshop_platform.instance_activity_contributions a
      WHERE a.user_id=launch.original_platform_owner_id AND a.workshop_key='secureshop_agent_security'
        AND a.workshop_generation=live_generation
        AND NOT(a.platform_launch_id=launch.launch_id AND a.platform_launch_generation=reset.from_generation)
        AND NOT EXISTS(SELECT 1 FROM identity.secureshop_progress_cleanup_history h
          WHERE h.launch_id=a.platform_launch_id AND h.from_launch_generation=a.platform_launch_generation)
    UNION ALL SELECT min(t.session_start) FROM workshop_platform.time_tracking t
      WHERE t.user_id=launch.original_platform_owner_id AND t.workshop_key='secureshop_agent_security'
        AND t.workshop_generation=live_generation
        AND NOT(t.platform_launch_id=launch.launch_id AND t.platform_launch_generation=reset.from_generation)
        AND NOT EXISTS(SELECT 1 FROM identity.secureshop_progress_cleanup_history h
          WHERE h.launch_id=t.platform_launch_id AND h.from_launch_generation=t.platform_launch_generation)
  ) starts;
  UPDATE workshop_platform.user_state SET started_at=projected_started_at,updated_at=clock_timestamp()
    WHERE user_id=launch.original_platform_owner_id AND workshop_key='secureshop_agent_security';
  INSERT INTO identity.secureshop_progress_cleanup_history
    (reset_id,launch_id,scenario_id,from_launch_generation,original_platform_owner_id,
     original_platform_session_id,workshop_key,workshop_generation,
     retired_objective_contribution_count,retired_activity_contribution_count,
     retired_time_entry_count,retired_time_seconds,projected_completion_count,
     projected_activity_count,projected_time_entry_count,projected_time_seconds)
  VALUES(requested_reset_id,launch.launch_id,launch.scenario_id,reset.from_generation,
    launch.original_platform_owner_id,launch.original_platform_session_id,'secureshop_agent_security',
    live_generation,retired_objectives,retired_activity,retired_time_entries,retired_time_seconds,
    projected_completions,projected_activity,projected_time_entries,projected_time_seconds)
  RETURNING * INTO result;
  INSERT INTO workshop_platform.revisions(scope_type,scope_key,category,revision)
    SELECT 'user',launch.original_platform_owner_id::text,category,1
      FROM unnest(ARRAY['workshop_progress','workshop_time']) category
    ON CONFLICT(scope_type,scope_key,category) DO UPDATE SET
      revision=workshop_platform.revisions.revision+1,updated_at=clock_timestamp();
  UPDATE identity.secureshop_launch_resets SET progress_reconciliation_required=false,
    updated_at=clock_timestamp() WHERE reset_id=requested_reset_id AND progress_reconciliation_required;
  IF NOT FOUND THEN RAISE EXCEPTION 'SecureShop progress cleanup gate mismatch'; END IF;
  RETURN NEXT result;
END $$;

REVOKE ALL ON TABLE workshop_platform.instance_activity_contributions FROM PUBLIC;
REVOKE ALL ON TABLE identity.secureshop_progress_cleanup_history FROM PUBLIC;
REVOKE ALL ON FUNCTION workshop_platform.validate_secureshop_progress_source() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.validate_secureshop_progress_cleanup_history() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.guard_secureshop_progress_cleanup_history() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.guard_secureshop_progress_cleanup_gate() FROM PUBLIC;
REVOKE ALL ON FUNCTION workshop_platform.record_secureshop_activity_contribution(integer,uuid,text,integer,uuid,uuid,bigint,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION workshop_platform.record_secureshop_heartbeat(integer,uuid,uuid,bigint,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.finalize_secureshop_progress_cleanup(uuid) FROM PUBLIC;
GRANT SELECT ON workshop_platform.instance_activity_contributions TO dvaia_identity_runtime;
GRANT SELECT ON identity.secureshop_progress_cleanup_history TO dvaia_identity_runtime;
GRANT EXECUTE ON FUNCTION workshop_platform.validate_secureshop_progress_source() TO dvaia_identity_runtime;
GRANT EXECUTE ON FUNCTION identity.validate_secureshop_progress_cleanup_history() TO dvaia_identity_runtime;
GRANT EXECUTE ON FUNCTION identity.guard_secureshop_progress_cleanup_history() TO dvaia_identity_runtime;
GRANT EXECUTE ON FUNCTION identity.guard_secureshop_progress_cleanup_gate() TO dvaia_identity_runtime;
GRANT EXECUTE ON FUNCTION workshop_platform.record_secureshop_activity_contribution(integer,uuid,text,integer,uuid,uuid,bigint,integer) TO dvaia_identity_runtime;
GRANT EXECUTE ON FUNCTION workshop_platform.record_secureshop_heartbeat(integer,uuid,uuid,bigint,integer) TO dvaia_identity_runtime;
GRANT EXECUTE ON FUNCTION identity.finalize_secureshop_progress_cleanup(uuid) TO dvaia_identity_runtime;
