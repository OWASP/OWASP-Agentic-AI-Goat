-- Birth coordinates remain on the original target and effect rows. This immutable
-- companion records which current scene grant produced a new retrieval effect.
-- The insertion function verifies live references; birth targets and grants
-- remain as immutable tombstones after owner cleanup.
CREATE TABLE secureshop_review.scene_retrieval_embedding_effects (
  effect_kind text NOT NULL CHECK (effect_kind IN ('retrieval_provision','retrieval_ingest','embedding_revision')),
  effect_id uuid NOT NULL,
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
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (effect_kind,effect_id)
);

CREATE TRIGGER scene_retrieval_embedding_effects_immutable
  BEFORE UPDATE OR DELETE ON secureshop_review.scene_retrieval_embedding_effects
  FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_product_retrieval_immutable();

CREATE FUNCTION secureshop_review.record_scene_retrieval_embedding_effect(
  requested_kind text, requested_effect uuid, requested_target uuid, requested_grant uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,secureshop_review AS $$
DECLARE inserted integer;
BEGIN
  IF requested_kind NOT IN ('retrieval_provision','retrieval_ingest','embedding_revision')
      OR requested_effect IS NULL OR requested_target IS NULL OR requested_grant IS NULL THEN
    RAISE EXCEPTION 'Invalid scene retrieval effect' USING ERRCODE='22023';
  END IF;
  PERFORM 1 FROM secureshop_review.scene_execution_grants g
    JOIN secureshop_review.product_targets t ON t.target_id=g.target_id
    WHERE g.grant_id=requested_grant AND g.target_id=requested_target
      AND t.lifecycle='active' AND t.original_platform_owner_id=g.original_platform_owner_id
    FOR SHARE OF g,t;
  IF NOT FOUND THEN RAISE EXCEPTION 'Scene retrieval grant unavailable' USING ERRCODE='55000'; END IF;
  IF requested_kind='retrieval_provision' THEN
    IF requested_effect<>requested_target OR NOT EXISTS (
      SELECT 1 FROM secureshop_review.product_target_retrieval_config c
      WHERE c.target_id=requested_target AND c.lifecycle='active') THEN
      RAISE EXCEPTION 'Retrieval provision effect unavailable' USING ERRCODE='55000';
    END IF;
  ELSIF requested_kind='retrieval_ingest' THEN
    IF NOT EXISTS (SELECT 1 FROM secureshop_review.product_target_retrieval_ingest_receipts r
      WHERE r.operation_id=requested_effect AND r.target_id=requested_target) THEN
      RAISE EXCEPTION 'Retrieval ingest effect unavailable' USING ERRCODE='55000';
    END IF;
  ELSE
    IF NOT EXISTS (SELECT 1 FROM secureshop_review.product_target_embedding_revisions r
      WHERE r.revision_id=requested_effect AND r.target_id=requested_target) THEN
      RAISE EXCEPTION 'Embedding revision effect unavailable' USING ERRCODE='55000';
    END IF;
  END IF;
  INSERT INTO secureshop_review.scene_retrieval_embedding_effects
    (effect_kind,effect_id,target_id,grant_id,birth_launch_id,birth_scenario_id,
      birth_generation,birth_owner_id,birth_session_id,scene_id,scene_generation,
      execution_launch_id,execution_scenario_id,execution_generation,
      execution_owner_id,execution_session_id)
    SELECT requested_kind,requested_effect,requested_target,requested_grant,
      t.launch_id,t.scenario_id,t.generation,t.original_platform_owner_id,
      t.original_platform_session_id,g.scene_id,g.scene_generation,
      g.launch_id,g.scenario_id,g.generation,g.original_platform_owner_id,
      g.original_platform_session_id
    FROM secureshop_review.scene_execution_grants g
      JOIN secureshop_review.product_targets t ON t.target_id=g.target_id
    WHERE g.grant_id=requested_grant AND g.target_id=requested_target
    ON CONFLICT (effect_kind,effect_id) DO NOTHING;
  GET DIAGNOSTICS inserted = ROW_COUNT;
  IF inserted=0 AND NOT EXISTS (
    SELECT 1 FROM secureshop_review.scene_retrieval_embedding_effects e
    WHERE e.effect_kind=requested_kind AND e.effect_id=requested_effect
      AND e.target_id=requested_target AND e.grant_id=requested_grant) THEN
    RAISE EXCEPTION 'Scene retrieval effect conflict' USING ERRCODE='55000';
  END IF;
  RETURN inserted=1;
END $$;

REVOKE ALL ON secureshop_review.scene_retrieval_embedding_effects FROM PUBLIC;
GRANT SELECT ON secureshop_review.scene_retrieval_embedding_effects TO dvaia_secureshop_review_runtime;
REVOKE ALL ON FUNCTION secureshop_review.record_scene_retrieval_embedding_effect(text,uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.record_scene_retrieval_embedding_effect(text,uuid,uuid,uuid)
  TO dvaia_secureshop_review_runtime;
