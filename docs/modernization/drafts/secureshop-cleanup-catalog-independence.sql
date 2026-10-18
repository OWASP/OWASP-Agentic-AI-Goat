-- Forward-only lifecycle correction. Learner visibility gates admission and grading,
-- but cannot strand an already-fenced reset or account deletion. The canonical
-- exercise row remains required for FK/projection identity.
CREATE OR REPLACE FUNCTION identity.validate_secureshop_progress_cleanup_history()
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
    FOR SHARE;
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

CREATE OR REPLACE FUNCTION identity.finalize_secureshop_progress_cleanup(requested_reset_id uuid)
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
    WHERE e.workshop_key='secureshop_agent_security' FOR SHARE;
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
REVOKE ALL ON FUNCTION identity.validate_secureshop_progress_cleanup_history() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.finalize_secureshop_progress_cleanup(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.validate_secureshop_progress_cleanup_history() TO dvaia_identity_runtime;
GRANT EXECUTE ON FUNCTION identity.finalize_secureshop_progress_cleanup(uuid) TO dvaia_identity_runtime;
