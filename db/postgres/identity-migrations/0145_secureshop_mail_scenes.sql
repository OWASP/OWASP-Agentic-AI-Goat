-- An inbox retains its original reservation and evidence. A scene mapping
-- authorizes reuse; it never turns a later session into the original session.
CREATE TABLE identity.secureshop_mail_scenes (
 scene_id uuid PRIMARY KEY REFERENCES identity.secureshop_scenes(scene_id),
 target_id uuid NOT NULL UNIQUE,
 original_platform_owner_id integer NOT NULL,
 birth_launch_id uuid NOT NULL REFERENCES identity.secureshop_launches(launch_id),
 birth_scenario_id uuid NOT NULL,
 birth_generation bigint NOT NULL CHECK(birth_generation>=1),
 birth_platform_session_id integer NOT NULL,
 adopted_by_grant_id uuid NOT NULL REFERENCES identity.secureshop_scene_execution_grants(grant_id),
 adoption_kind text NOT NULL CHECK(adoption_kind IN ('birth_grant','unique_owner')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION identity.guard_secureshop_mail_scene() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,identity AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Immutable mail scene binding' USING ERRCODE='55000'; END IF;
 IF NOT EXISTS (
  SELECT 1 FROM identity.secureshop_scenes scene
  JOIN identity.secureshop_scene_execution_grants g ON g.scene_id=scene.scene_id
  JOIN identity.secureshop_launches current_launch ON current_launch.launch_id=g.launch_id
  JOIN identity.secureshop_authority_sessions session ON session.id=current_launch.platform_session_id
  JOIN identity.secureshop_authority_owners owner ON owner.id=session.user_id
  JOIN identity.secureshop_target_reservations r ON r.target_id=NEW.target_id
  JOIN identity.secureshop_launches birth ON birth.launch_id=r.launch_id
  WHERE scene.scene_id=NEW.scene_id AND scene.status='active'
   AND scene.original_platform_owner_id=NEW.original_platform_owner_id
   AND g.grant_id=NEW.adopted_by_grant_id AND g.scene_generation=scene.scene_generation
   AND g.original_platform_owner_id=scene.original_platform_owner_id
   AND current_launch.status='active' AND current_launch.expires_at>clock_timestamp()
   AND current_launch.generation=g.generation
   AND current_launch.scenario_id=g.scenario_id
   AND current_launch.original_platform_session_id=g.original_platform_session_id
   AND session.user_id=NEW.original_platform_owner_id AND session.is_active=1
   AND session.expires_at>clock_timestamp() AND owner.is_active=1
   AND (owner.account_locked_until IS NULL OR owner.account_locked_until<=clock_timestamp())
   AND r.target_kind='persona_inbox' AND r.original_platform_owner_id=NEW.original_platform_owner_id
   AND (r.launch_id,birth.scenario_id,r.generation,birth.original_platform_session_id)=
     (NEW.birth_launch_id,NEW.birth_scenario_id,NEW.birth_generation,NEW.birth_platform_session_id)
   AND ((NEW.adoption_kind='birth_grant' AND EXISTS (
     SELECT 1 FROM identity.secureshop_scene_execution_grants original_grant
     WHERE original_grant.scene_id=scene.scene_id AND original_grant.launch_id=r.launch_id
       AND original_grant.generation=r.generation
       AND original_grant.original_platform_owner_id=NEW.original_platform_owner_id
       AND original_grant.original_platform_session_id=NEW.birth_platform_session_id))
    OR (NEW.adoption_kind='unique_owner'
      AND (SELECT count(*) FROM identity.secureshop_scenes s WHERE s.original_platform_owner_id=NEW.original_platform_owner_id AND s.status='active')=1
      AND (SELECT count(*) FROM identity.secureshop_target_reservations candidate WHERE candidate.original_platform_owner_id=NEW.original_platform_owner_id AND candidate.target_kind='persona_inbox')=1))
 ) THEN RAISE EXCEPTION 'Mail scene admission unavailable' USING ERRCODE='42501'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER secureshop_mail_scene_guard BEFORE INSERT OR UPDATE OR DELETE
 ON identity.secureshop_mail_scenes FOR EACH ROW EXECUTE FUNCTION identity.guard_secureshop_mail_scene();
REVOKE ALL ON identity.secureshop_mail_scenes FROM PUBLIC;
GRANT SELECT,INSERT ON identity.secureshop_mail_scenes TO dvaia_identity_runtime;
REVOKE ALL ON FUNCTION identity.guard_secureshop_mail_scene() FROM PUBLIC,dvaia_identity_runtime;

-- The first generation transition that retires a shared scene owns cleanup.
-- Owner reset/deletion insert their reset journal after advancing generation,
-- so retain its unique launch/to-generation key rather than require that row
-- prematurely. A concurrent reset never manufactures a second private receipt.
CREATE TABLE identity.secureshop_mail_scene_retirements (
 scene_id uuid PRIMARY KEY REFERENCES identity.secureshop_mail_scenes(scene_id),
 target_id uuid NOT NULL UNIQUE,
 retiring_launch_id uuid NOT NULL REFERENCES identity.secureshop_launches(launch_id),
 from_generation bigint NOT NULL CHECK(from_generation>=1),
 to_generation bigint NOT NULL CHECK(to_generation=from_generation+1),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION identity.guard_secureshop_mail_scene_retirement() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,identity AS $$
BEGIN
 IF TG_OP<>'INSERT' OR NOT EXISTS (
  SELECT 1 FROM identity.secureshop_mail_scenes m
  JOIN identity.secureshop_scenes s ON s.scene_id=m.scene_id
  JOIN identity.secureshop_launches l ON l.launch_id=NEW.retiring_launch_id
  WHERE m.scene_id=NEW.scene_id AND m.target_id=NEW.target_id AND s.status='retired'
   AND l.generation=NEW.to_generation AND l.original_platform_owner_id=m.original_platform_owner_id
   AND (s.birth_launch_id=l.launch_id OR EXISTS (
    SELECT 1 FROM identity.secureshop_scene_execution_grants g
    WHERE g.scene_id=s.scene_id AND g.launch_id=l.launch_id AND g.generation=NEW.from_generation
     AND g.original_platform_owner_id=l.original_platform_owner_id
     AND g.original_platform_session_id=l.original_platform_session_id))
 ) THEN RAISE EXCEPTION 'Invalid immutable mail retirement' USING ERRCODE='55000'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER secureshop_mail_scene_retirement_guard BEFORE INSERT OR UPDATE OR DELETE
 ON identity.secureshop_mail_scene_retirements FOR EACH ROW
 EXECUTE FUNCTION identity.guard_secureshop_mail_scene_retirement();

CREATE OR REPLACE FUNCTION identity.retire_reset_secureshop_scenes() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,identity AS $$
DECLARE retired_scene uuid;
BEGIN
 IF NEW.generation IS DISTINCT FROM OLD.generation THEN
  FOR retired_scene IN
   UPDATE identity.secureshop_scenes s SET status='retired',is_default=false
    WHERE s.status='active' AND (s.birth_launch_id=OLD.launch_id OR EXISTS (
     SELECT 1 FROM identity.secureshop_scene_execution_grants g
     WHERE g.scene_id=s.scene_id AND g.launch_id=OLD.launch_id AND g.generation=OLD.generation))
    RETURNING s.scene_id
  LOOP
   INSERT INTO identity.secureshop_mail_scene_retirements
    (scene_id,target_id,retiring_launch_id,from_generation,to_generation)
   SELECT m.scene_id,m.target_id,OLD.launch_id,OLD.generation,NEW.generation
    FROM identity.secureshop_mail_scenes m WHERE m.scene_id=retired_scene;
  END LOOP;
 END IF;
 RETURN NEW;
END $$;

CREATE FUNCTION identity.mail_scene_reset_cleanup_authorized(
 requested_reset uuid,requested_target uuid,birth_launch uuid,birth_scenario uuid,
 birth_generation bigint,birth_owner integer,birth_session integer)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,identity AS $$
 SELECT EXISTS (
  SELECT 1 FROM identity.secureshop_mail_scenes m
  JOIN identity.secureshop_scenes s ON s.scene_id=m.scene_id
  JOIN identity.secureshop_mail_scene_retirements c ON c.scene_id=m.scene_id AND c.target_id=m.target_id
  JOIN identity.secureshop_launch_resets o ON o.launch_id=c.retiring_launch_id
   AND o.from_generation=c.from_generation AND o.to_generation=c.to_generation
  JOIN identity.secureshop_launches l ON l.launch_id=o.launch_id
  JOIN identity.secureshop_launches born ON born.launch_id=m.birth_launch_id
  WHERE o.reset_id=$1 AND m.target_id=$2 AND s.status='retired'
   AND l.generation>=o.to_generation AND l.original_platform_owner_id=m.original_platform_owner_id
   AND (m.birth_launch_id,m.birth_scenario_id,m.birth_generation,m.original_platform_owner_id,m.birth_platform_session_id)
    =($3,$4,$5,$6,$7)
   AND (born.scenario_id,born.original_platform_owner_id,born.original_platform_session_id)
    =($4,$6,$7)
   AND (EXISTS (SELECT 1 FROM identity.secureshop_target_reservations r
     WHERE r.target_id=m.target_id AND r.target_kind='persona_inbox'
      AND r.launch_id=m.birth_launch_id AND r.generation=m.birth_generation
      AND r.original_platform_owner_id=m.original_platform_owner_id)
    OR EXISTS (SELECT 1 FROM identity.secureshop_target_cleanup_history h
     WHERE h.target_id=m.target_id AND h.target_kind='persona_inbox' AND h.operation_id=o.reset_id
      AND (h.launch_id,h.scenario_id,h.from_generation,h.original_platform_owner_id,h.original_platform_session_id)
       =($3,$4,$5,$6,$7)))
 )
$$;

CREATE OR REPLACE FUNCTION identity.validate_secureshop_target_cleanup_history()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,identity AS $$
DECLARE authority identity.secureshop_launches%ROWTYPE;
DECLARE reset_authority identity.secureshop_launch_resets%ROWTYPE;
DECLARE reservation identity.secureshop_target_reservations%ROWTYPE;
DECLARE mapped_mail boolean;
BEGIN
 SELECT * INTO authority FROM identity.secureshop_launches WHERE launch_id=NEW.launch_id FOR UPDATE;
 SELECT * INTO reset_authority FROM identity.secureshop_launch_resets WHERE reset_id=NEW.operation_id FOR UPDATE;
 SELECT * INTO reservation FROM identity.secureshop_target_reservations WHERE target_id=NEW.target_id FOR UPDATE;
 mapped_mail:=NEW.target_kind='persona_inbox' AND EXISTS (
  SELECT 1 FROM identity.secureshop_mail_scenes m WHERE m.target_id=NEW.target_id);
 IF reservation.target_id IS NULL OR authority.launch_id IS NULL OR reset_authority.reset_id IS NULL
  OR reservation.launch_id<>NEW.launch_id OR reservation.generation<>NEW.from_generation
  OR reservation.target_kind<>NEW.target_kind OR reservation.original_platform_owner_id<>NEW.original_platform_owner_id
  OR authority.scenario_id<>NEW.scenario_id OR authority.original_platform_owner_id<>NEW.original_platform_owner_id
  OR authority.original_platform_session_id<>NEW.original_platform_session_id
  OR (mapped_mail AND NOT identity.mail_scene_reset_cleanup_authorized(NEW.operation_id,NEW.target_id,
    NEW.launch_id,NEW.scenario_id,NEW.from_generation,NEW.original_platform_owner_id,NEW.original_platform_session_id))
  OR (NOT mapped_mail AND (reset_authority.launch_id<>NEW.launch_id OR reset_authority.from_generation<>NEW.from_generation))
 THEN RAISE EXCEPTION 'SecureShop cleanup history binding is invalid'; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON identity.secureshop_mail_scene_retirements FROM PUBLIC,dvaia_identity_runtime;
GRANT SELECT ON identity.secureshop_mail_scene_retirements TO dvaia_identity_runtime;
REVOKE ALL ON FUNCTION identity.guard_secureshop_mail_scene_retirement() FROM PUBLIC,dvaia_identity_runtime;
REVOKE ALL ON FUNCTION identity.mail_scene_reset_cleanup_authorized(uuid,uuid,uuid,uuid,bigint,integer,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.mail_scene_reset_cleanup_authorized(uuid,uuid,uuid,uuid,bigint,integer,integer) TO dvaia_identity_runtime;
