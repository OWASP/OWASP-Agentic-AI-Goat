-- A review target keeps its original launch coordinates. One immutable mapping
-- associates it with the durable product scene for later authorized sessions.
CREATE TABLE secureshop_review.scene_review_targets (
  scene_id uuid PRIMARY KEY,
  product_target_id uuid NOT NULL UNIQUE REFERENCES secureshop_review.product_targets(target_id),
  review_target_id uuid NOT NULL UNIQUE REFERENCES secureshop_review.review_targets(target_id),
  original_platform_owner_id integer NOT NULL CHECK (original_platform_owner_id > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER scene_review_targets_immutable BEFORE UPDATE OR DELETE
  ON secureshop_review.scene_review_targets FOR EACH ROW
  EXECUTE FUNCTION secureshop_review.guard_product_retrieval_immutable();

CREATE FUNCTION secureshop_review.bind_scene_review_target(
  requested_scene uuid, requested_product_target uuid, requested_review_target uuid,
  requested_grant uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,secureshop_review AS $$
DECLARE inserted integer;
BEGIN
  IF requested_scene IS NULL OR requested_product_target IS NULL
      OR requested_review_target IS NULL OR requested_grant IS NULL THEN
    RAISE EXCEPTION 'Invalid scene review target' USING ERRCODE='22023';
  END IF;
  PERFORM 1 FROM secureshop_review.scene_execution_grants g
    JOIN secureshop_review.product_targets p ON p.target_id=g.target_id
    JOIN secureshop_review.review_targets r
      ON r.target_id=requested_review_target
      AND r.original_platform_owner_id=g.original_platform_owner_id
    WHERE g.grant_id=requested_grant AND g.scene_id=requested_scene
      AND g.target_id=requested_product_target AND p.lifecycle='active'
      AND r.lifecycle='active'
      AND p.original_platform_owner_id=g.original_platform_owner_id
      AND ((r.launch_id,r.scenario_id,r.generation,r.original_platform_owner_id,
        r.original_platform_session_id)
        =(p.launch_id,p.scenario_id,p.generation,p.original_platform_owner_id,
          p.original_platform_session_id)
        OR (r.launch_id,r.scenario_id,r.generation,r.original_platform_owner_id,
          r.original_platform_session_id)
        =(g.launch_id,g.scenario_id,g.generation,g.original_platform_owner_id,
          g.original_platform_session_id))
    FOR SHARE OF g,p,r;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Scene review authority unavailable' USING ERRCODE='55000';
  END IF;
  INSERT INTO secureshop_review.scene_review_targets
    (scene_id,product_target_id,review_target_id,original_platform_owner_id)
    SELECT requested_scene,requested_product_target,requested_review_target,
      g.original_platform_owner_id
    FROM secureshop_review.scene_execution_grants g
    WHERE g.grant_id=requested_grant
    ON CONFLICT DO NOTHING;
  GET DIAGNOSTICS inserted = ROW_COUNT;
  IF inserted=0 AND NOT EXISTS (
    SELECT 1 FROM secureshop_review.scene_review_targets m
    WHERE m.scene_id=requested_scene AND m.product_target_id=requested_product_target
      AND m.review_target_id=requested_review_target) THEN
    RAISE EXCEPTION 'Scene review binding conflict' USING ERRCODE='55000';
  END IF;
  RETURN inserted=1;
END $$;

-- Existing bound review targets used the product launch as their birth. Keep
-- their approved and pending rows visible when a scene grant already exists.
INSERT INTO secureshop_review.scene_review_targets
  (scene_id,product_target_id,review_target_id,original_platform_owner_id)
SELECT DISTINCT ON (g.scene_id) g.scene_id,p.target_id,r.target_id,
  p.original_platform_owner_id
FROM secureshop_review.scene_execution_grants g
JOIN secureshop_review.product_targets p ON p.target_id=g.target_id
JOIN secureshop_review.review_targets r
  ON (r.launch_id,r.scenario_id,r.generation,r.original_platform_owner_id,
      r.original_platform_session_id)
   =(p.launch_id,p.scenario_id,p.generation,p.original_platform_owner_id,
      p.original_platform_session_id)
WHERE p.lifecycle='active' AND r.lifecycle='active'
ORDER BY g.scene_id,g.created_at,g.grant_id
ON CONFLICT DO NOTHING;

REVOKE ALL ON secureshop_review.scene_review_targets FROM PUBLIC;
GRANT SELECT ON secureshop_review.scene_review_targets TO dvaia_secureshop_review_runtime;
REVOKE ALL ON FUNCTION secureshop_review.bind_scene_review_target(uuid,uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.bind_scene_review_target(uuid,uuid,uuid,uuid)
  TO dvaia_secureshop_review_runtime;
