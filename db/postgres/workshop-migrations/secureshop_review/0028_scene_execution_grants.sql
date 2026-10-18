-- A current execution may access an older product snapshot only through an
-- explicit owned scene grant. The identity-store lease supplies live session
-- and reset authority; this relation pins the storage-side transaction.
CREATE TABLE secureshop_review.scene_execution_grants (
  grant_id uuid PRIMARY KEY,
  scene_id uuid NOT NULL,
  scene_generation bigint NOT NULL CHECK(scene_generation > 0),
  target_id uuid NOT NULL REFERENCES secureshop_review.product_targets(target_id),
  launch_id uuid NOT NULL,
  scenario_id uuid NOT NULL,
  generation bigint NOT NULL CHECK(generation > 0),
  original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id > 0),
  original_platform_session_id integer NOT NULL CHECK(original_platform_session_id > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(scene_id,launch_id,generation)
);
CREATE FUNCTION secureshop_review.guard_scene_execution_grant() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,secureshop_review AS $$
BEGIN
  IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Scene execution grant is immutable' USING ERRCODE='55000'; END IF;
  PERFORM 1 FROM secureshop_review.product_targets
    WHERE target_id=NEW.target_id AND original_platform_owner_id=NEW.original_platform_owner_id
      AND lifecycle='active' FOR SHARE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Scene storage owner unavailable' USING ERRCODE='55000'; END IF;
  IF EXISTS(SELECT 1 FROM secureshop_review.scene_execution_grants
    WHERE scene_id=NEW.scene_id AND
      (target_id,scene_generation,original_platform_owner_id)
      IS DISTINCT FROM (NEW.target_id,NEW.scene_generation,NEW.original_platform_owner_id)) THEN
    RAISE EXCEPTION 'Scene storage identity conflict' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER scene_execution_grant_guard BEFORE INSERT OR UPDATE OR DELETE
  ON secureshop_review.scene_execution_grants FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_scene_execution_grant();

CREATE FUNCTION secureshop_review.assert_scene_execution_grant(
  requested_grant uuid,requested_scene uuid,requested_scene_generation bigint,requested_target uuid,
  requested_launch uuid,requested_scenario uuid,requested_generation bigint,requested_owner integer,requested_session integer)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
BEGIN
  PERFORM 1 FROM secureshop_review.scene_execution_grants g
    JOIN secureshop_review.product_targets p ON p.target_id=g.target_id
    WHERE g.grant_id=requested_grant AND g.scene_id=requested_scene
      AND g.scene_generation=requested_scene_generation AND g.target_id=requested_target
      AND g.launch_id=requested_launch AND g.scenario_id=requested_scenario AND g.generation=requested_generation
      AND g.original_platform_owner_id=requested_owner AND g.original_platform_session_id=requested_session
      AND p.original_platform_owner_id=requested_owner AND p.lifecycle='active'
    FOR SHARE OF g,p;
  RETURN FOUND;
END $$;
REVOKE ALL ON secureshop_review.scene_execution_grants FROM PUBLIC;
GRANT SELECT,INSERT ON secureshop_review.scene_execution_grants TO dvaia_secureshop_review_runtime;
REVOKE ALL ON FUNCTION secureshop_review.guard_scene_execution_grant(),
  secureshop_review.assert_scene_execution_grant(uuid,uuid,bigint,uuid,uuid,uuid,bigint,integer,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.assert_scene_execution_grant(uuid,uuid,bigint,uuid,uuid,uuid,bigint,integer,integer)
  TO dvaia_secureshop_review_runtime;
