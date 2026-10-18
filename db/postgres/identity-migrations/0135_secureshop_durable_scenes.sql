-- Durable shop storage is separate from the session that executes a request.
-- Birth coordinates and prior evidence are never rebound to a later login.
CREATE TABLE identity.secureshop_scenes (
  scene_id uuid PRIMARY KEY,
  original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id > 0),
  product_target_id uuid NOT NULL UNIQUE,
  birth_launch_id uuid NOT NULL REFERENCES identity.secureshop_launches(launch_id),
  birth_scenario_id uuid NOT NULL,
  birth_generation bigint NOT NULL CHECK(birth_generation > 0),
  birth_platform_session_id integer NOT NULL CHECK(birth_platform_session_id > 0),
  scene_generation bigint NOT NULL DEFAULT 1 CHECK(scene_generation > 0),
  status text NOT NULL DEFAULT 'active' CHECK(status IN ('active','retired')),
  is_default boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK(status='active' OR NOT is_default)
);
CREATE UNIQUE INDEX secureshop_scene_default_owner ON identity.secureshop_scenes(original_platform_owner_id)
  WHERE is_default AND status='active';

CREATE TABLE identity.secureshop_scene_principals (
  principal_id uuid PRIMARY KEY,
  scene_id uuid NOT NULL REFERENCES identity.secureshop_scenes(scene_id),
  shop_user_id integer NOT NULL CHECK(shop_user_id > 0),
  seed_role text NOT NULL CHECK(seed_role IN ('customer','merchant','admin')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(scene_id,shop_user_id)
);

CREATE TABLE identity.secureshop_scene_execution_grants (
  grant_id uuid PRIMARY KEY,
  scene_id uuid NOT NULL REFERENCES identity.secureshop_scenes(scene_id),
  scene_generation bigint NOT NULL CHECK(scene_generation > 0),
  launch_id uuid NOT NULL REFERENCES identity.secureshop_launches(launch_id),
  scenario_id uuid NOT NULL,
  generation bigint NOT NULL CHECK(generation > 0),
  original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id > 0),
  original_platform_session_id integer NOT NULL CHECK(original_platform_session_id > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(scene_id,launch_id,generation)
);

CREATE FUNCTION identity.guard_secureshop_scene() RETURNS trigger LANGUAGE plpgsql
SET search_path=pg_catalog,identity AS $$
BEGIN
  IF TG_OP='INSERT' THEN
    IF NOT EXISTS(SELECT 1 FROM identity.secureshop_target_reservations r
      JOIN identity.secureshop_launches l USING(launch_id)
      WHERE r.target_id=NEW.product_target_id AND r.target_kind='products'
        AND r.launch_id=NEW.birth_launch_id AND r.generation=NEW.birth_generation
        AND r.original_platform_owner_id=NEW.original_platform_owner_id
        AND l.scenario_id=NEW.birth_scenario_id
        AND l.original_platform_session_id=NEW.birth_platform_session_id
        AND l.original_platform_owner_id=NEW.original_platform_owner_id)
      OR NEW.status<>'active' OR NEW.scene_generation<>1 THEN
      RAISE EXCEPTION 'Invalid shop scene birth binding' USING ERRCODE='55000';
    END IF;
    RETURN NEW;
  END IF;
  IF TG_OP='DELETE' OR
    (NEW.scene_id,NEW.original_platform_owner_id,NEW.product_target_id,NEW.birth_launch_id,
     NEW.birth_scenario_id,NEW.birth_generation,NEW.birth_platform_session_id,NEW.scene_generation,NEW.created_at)
    IS DISTINCT FROM
    (OLD.scene_id,OLD.original_platform_owner_id,OLD.product_target_id,OLD.birth_launch_id,
     OLD.birth_scenario_id,OLD.birth_generation,OLD.birth_platform_session_id,OLD.scene_generation,OLD.created_at)
    OR OLD.status='retired' THEN
    RAISE EXCEPTION 'Shop scene birth identity is immutable' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER secureshop_scene_guard BEFORE INSERT OR UPDATE OR DELETE ON identity.secureshop_scenes
  FOR EACH ROW EXECUTE FUNCTION identity.guard_secureshop_scene();

CREATE FUNCTION identity.guard_secureshop_scene_grant() RETURNS trigger LANGUAGE plpgsql
SET search_path=pg_catalog,identity AS $$
BEGIN
  IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Shop scene grant is immutable' USING ERRCODE='55000'; END IF;
  IF NOT EXISTS(SELECT 1 FROM identity.secureshop_scenes scene
    JOIN identity.secureshop_launches l ON l.launch_id=NEW.launch_id
    JOIN identity.user_sessions session ON session.id=l.platform_session_id
    JOIN identity.users owner ON owner.id=session.user_id
    WHERE scene.scene_id=NEW.scene_id AND scene.scene_generation=NEW.scene_generation
      AND scene.status='active' AND scene.original_platform_owner_id=NEW.original_platform_owner_id
      AND l.scenario_id=NEW.scenario_id AND l.generation=NEW.generation
      AND l.original_platform_owner_id=NEW.original_platform_owner_id
      AND l.platform_session_id=NEW.original_platform_session_id
      AND l.status='active' AND l.expires_at>clock_timestamp()
      AND session.user_id=NEW.original_platform_owner_id AND session.is_active=1
      AND session.expires_at>clock_timestamp() AND owner.is_active=1
      AND (owner.account_locked_until IS NULL OR owner.account_locked_until<=clock_timestamp())) THEN
    RAISE EXCEPTION 'Shop scene execution authority is unavailable' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER secureshop_scene_grant_guard BEFORE INSERT OR UPDATE OR DELETE
  ON identity.secureshop_scene_execution_grants FOR EACH ROW EXECUTE FUNCTION identity.guard_secureshop_scene_grant();

-- Explicit launch reset retires every scene used by that execution, including
-- a scene born in an older login. Logout/expiry alone does not destroy a shop.
CREATE FUNCTION identity.retire_reset_secureshop_scenes() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,identity AS $$
BEGIN
  IF NEW.generation IS DISTINCT FROM OLD.generation THEN
    UPDATE identity.secureshop_scenes s SET status='retired',is_default=false
      WHERE s.status='active' AND (s.birth_launch_id=OLD.launch_id OR EXISTS(
        SELECT 1 FROM identity.secureshop_scene_execution_grants g
        WHERE g.scene_id=s.scene_id AND g.launch_id=OLD.launch_id AND g.generation=OLD.generation));
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER secureshop_reset_retires_scenes AFTER UPDATE OF generation ON identity.secureshop_launches
  FOR EACH ROW EXECUTE FUNCTION identity.retire_reset_secureshop_scenes();

REVOKE ALL ON identity.secureshop_scenes,identity.secureshop_scene_principals,
  identity.secureshop_scene_execution_grants FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON identity.secureshop_scenes TO dvaia_identity_runtime;
GRANT SELECT,INSERT ON identity.secureshop_scene_principals,identity.secureshop_scene_execution_grants TO dvaia_identity_runtime;
REVOKE ALL ON FUNCTION identity.guard_secureshop_scene(),identity.guard_secureshop_scene_grant(),
  identity.retire_reset_secureshop_scenes() FROM PUBLIC;
