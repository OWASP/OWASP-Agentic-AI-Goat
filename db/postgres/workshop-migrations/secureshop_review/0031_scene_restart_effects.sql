-- Keep the historical restart operation bound to its immutable storage birth.
-- A separate immutable receipt attributes a newly completed effect to the
-- current authorized scene execution without rewriting old operations.
-- Historic receipts outlive owner cleanup, which deletes restart operation
-- rows but retains target/grant tombstones. Insertion verifies live rows.
CREATE TABLE secureshop_review.scene_restart_admissions (
  operation_id uuid PRIMARY KEY,
  target_id uuid NOT NULL REFERENCES secureshop_review.product_targets(target_id),
  grant_id uuid NOT NULL REFERENCES secureshop_review.scene_execution_grants(grant_id),
  birth_launch_id uuid NOT NULL,
  birth_scenario_id uuid NOT NULL,
  birth_generation bigint NOT NULL,
  birth_owner_id integer NOT NULL,
  birth_session_id integer NOT NULL,
  scene_id uuid NOT NULL,
  scene_generation bigint NOT NULL,
  execution_launch_id uuid NOT NULL,
  execution_scenario_id uuid NOT NULL,
  execution_generation bigint NOT NULL,
  execution_owner_id integer NOT NULL,
  execution_session_id integer NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE secureshop_review.scene_restart_effects (
  operation_id uuid PRIMARY KEY,
  target_id uuid NOT NULL REFERENCES secureshop_review.product_targets(target_id),
  grant_id uuid NOT NULL REFERENCES secureshop_review.scene_execution_grants(grant_id),
  birth_launch_id uuid NOT NULL,
  birth_scenario_id uuid NOT NULL,
  birth_generation bigint NOT NULL,
  birth_owner_id integer NOT NULL,
  birth_session_id integer NOT NULL,
  scene_id uuid NOT NULL,
  scene_generation bigint NOT NULL,
  execution_launch_id uuid NOT NULL,
  execution_scenario_id uuid NOT NULL,
  execution_generation bigint NOT NULL,
  execution_owner_id integer NOT NULL,
  execution_session_id integer NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER scene_restart_admissions_immutable BEFORE UPDATE OR DELETE
  ON secureshop_review.scene_restart_admissions FOR EACH ROW
  EXECUTE FUNCTION secureshop_review.guard_product_retrieval_immutable();
CREATE TRIGGER scene_restart_effects_immutable BEFORE UPDATE OR DELETE
  ON secureshop_review.scene_restart_effects FOR EACH ROW
  EXECUTE FUNCTION secureshop_review.guard_product_retrieval_immutable();

CREATE FUNCTION secureshop_review.record_scene_restart_admission(
  requested_operation uuid,requested_target uuid,requested_grant uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,secureshop_review AS $$
DECLARE inserted integer;
BEGIN
  IF requested_operation IS NULL OR requested_target IS NULL OR requested_grant IS NULL THEN
    RAISE EXCEPTION 'Invalid scene restart admission' USING ERRCODE='22023';
  END IF;
  PERFORM 1 FROM secureshop_review.bound_system_restart_operations o
    JOIN secureshop_review.scene_execution_grants g ON g.grant_id=requested_grant
    JOIN secureshop_review.product_targets p ON p.target_id=o.target_id
    WHERE o.operation_id=requested_operation AND o.target_id=requested_target
      AND o.state='running' AND g.target_id=requested_target
      AND g.original_platform_owner_id=o.original_platform_owner_id
      AND p.original_platform_owner_id=o.original_platform_owner_id
      AND p.lifecycle='active' FOR SHARE OF o,g,p;
  IF NOT FOUND THEN RAISE EXCEPTION 'Scene restart admission unavailable' USING ERRCODE='55000'; END IF;
  INSERT INTO secureshop_review.scene_restart_admissions
    (operation_id,target_id,grant_id,birth_launch_id,birth_scenario_id,
      birth_generation,birth_owner_id,birth_session_id,scene_id,scene_generation,
      execution_launch_id,execution_scenario_id,execution_generation,
      execution_owner_id,execution_session_id)
    SELECT requested_operation,requested_target,requested_grant,
      p.launch_id,p.scenario_id,p.generation,p.original_platform_owner_id,
      p.original_platform_session_id,g.scene_id,g.scene_generation,
      g.launch_id,g.scenario_id,g.generation,g.original_platform_owner_id,
      g.original_platform_session_id
    FROM secureshop_review.scene_execution_grants g
      JOIN secureshop_review.product_targets p ON p.target_id=g.target_id
    WHERE g.grant_id=requested_grant AND g.target_id=requested_target
    ON CONFLICT(operation_id) DO NOTHING;
  GET DIAGNOSTICS inserted = ROW_COUNT;
  IF inserted=0 AND NOT EXISTS (SELECT 1 FROM secureshop_review.scene_restart_admissions a
    WHERE a.operation_id=requested_operation AND a.target_id=requested_target
      AND a.grant_id=requested_grant) THEN
    RAISE EXCEPTION 'Scene restart admission conflict' USING ERRCODE='55000';
  END IF;
  RETURN inserted=1;
END $$;

CREATE FUNCTION secureshop_review.record_scene_restart_effect(
  requested_operation uuid,requested_target uuid,requested_grant uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,secureshop_review AS $$
DECLARE inserted integer;
BEGIN
  IF requested_operation IS NULL OR requested_target IS NULL OR requested_grant IS NULL THEN
    RAISE EXCEPTION 'Invalid scene restart effect' USING ERRCODE='22023';
  END IF;
  PERFORM 1 FROM secureshop_review.bound_system_restart_operations o
    JOIN secureshop_review.scene_restart_admissions a ON a.operation_id=o.operation_id
    JOIN secureshop_review.scene_execution_grants g ON g.grant_id=requested_grant
    JOIN secureshop_review.product_targets p ON p.target_id=o.target_id
    WHERE o.operation_id=requested_operation AND o.target_id=requested_target
      AND o.state='completed' AND o.effect_sha256 IS NOT NULL
      AND a.target_id=requested_target AND a.grant_id=requested_grant
      AND g.target_id=requested_target
      AND g.original_platform_owner_id=o.original_platform_owner_id
      AND p.original_platform_owner_id=o.original_platform_owner_id
      AND p.lifecycle='active' FOR SHARE OF o,g,p;
  IF NOT FOUND THEN RAISE EXCEPTION 'Scene restart effect unavailable' USING ERRCODE='55000'; END IF;
  INSERT INTO secureshop_review.scene_restart_effects
    (operation_id,target_id,grant_id,birth_launch_id,birth_scenario_id,
      birth_generation,birth_owner_id,birth_session_id,scene_id,scene_generation,
      execution_launch_id,execution_scenario_id,execution_generation,
      execution_owner_id,execution_session_id)
    SELECT requested_operation,requested_target,requested_grant,
      p.launch_id,p.scenario_id,p.generation,p.original_platform_owner_id,
      p.original_platform_session_id,g.scene_id,g.scene_generation,
      g.launch_id,g.scenario_id,g.generation,g.original_platform_owner_id,
      g.original_platform_session_id
    FROM secureshop_review.scene_execution_grants g
      JOIN secureshop_review.product_targets p ON p.target_id=g.target_id
    WHERE g.grant_id=requested_grant AND g.target_id=requested_target
    ON CONFLICT(operation_id) DO NOTHING;
  GET DIAGNOSTICS inserted = ROW_COUNT;
  IF inserted=0 AND NOT EXISTS (SELECT 1 FROM secureshop_review.scene_restart_effects e
    WHERE e.operation_id=requested_operation AND e.target_id=requested_target
      AND e.grant_id=requested_grant) THEN
    RAISE EXCEPTION 'Scene restart effect conflict' USING ERRCODE='55000';
  END IF;
  RETURN inserted=1;
END $$;

REVOKE ALL ON secureshop_review.scene_restart_admissions,
  secureshop_review.scene_restart_effects FROM PUBLIC;
GRANT SELECT ON secureshop_review.scene_restart_admissions,
  secureshop_review.scene_restart_effects TO dvaia_secureshop_review_runtime;
REVOKE ALL ON FUNCTION secureshop_review.record_scene_restart_admission(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.record_scene_restart_admission(uuid,uuid,uuid)
  TO dvaia_secureshop_review_runtime;
REVOKE ALL ON FUNCTION secureshop_review.record_scene_restart_effect(uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.record_scene_restart_effect(uuid,uuid,uuid)
  TO dvaia_secureshop_review_runtime;
