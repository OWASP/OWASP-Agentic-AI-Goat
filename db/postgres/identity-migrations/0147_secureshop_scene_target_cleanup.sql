-- Product scenes can outlive their birth launch. Reviews have a separate
-- physical target; this immutable identity mirror is established only after
-- the review-store scene binding has committed and been read back.
CREATE TABLE identity.secureshop_scene_review_targets (
 scene_id uuid PRIMARY KEY REFERENCES identity.secureshop_scenes(scene_id),
 target_id uuid NOT NULL UNIQUE,
 original_platform_owner_id integer NOT NULL,
 birth_launch_id uuid NOT NULL REFERENCES identity.secureshop_launches(launch_id),
 birth_scenario_id uuid NOT NULL,
 birth_generation bigint NOT NULL CHECK(birth_generation>=1),
 birth_platform_session_id integer NOT NULL,
 adopted_by_grant_id uuid NOT NULL REFERENCES identity.secureshop_scene_execution_grants(grant_id),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION identity.guard_secureshop_scene_review_target() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,identity AS $$
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Immutable review scene binding' USING ERRCODE='55000'; END IF;
 IF NOT EXISTS (
  SELECT 1 FROM identity.secureshop_scenes s
  JOIN identity.secureshop_scene_execution_grants g ON g.scene_id=s.scene_id
  JOIN identity.secureshop_target_reservations r ON r.target_id=NEW.target_id
  JOIN identity.secureshop_launches birth ON birth.launch_id=r.launch_id
  WHERE s.scene_id=NEW.scene_id AND g.grant_id=NEW.adopted_by_grant_id
   AND s.original_platform_owner_id=NEW.original_platform_owner_id
   AND g.original_platform_owner_id=NEW.original_platform_owner_id
   AND r.target_kind='reviews' AND r.original_platform_owner_id=NEW.original_platform_owner_id
   AND (r.launch_id,birth.scenario_id,r.generation,birth.original_platform_session_id)=
     (NEW.birth_launch_id,NEW.birth_scenario_id,NEW.birth_generation,NEW.birth_platform_session_id)
   AND ((NEW.birth_launch_id,NEW.birth_scenario_id,NEW.birth_generation,NEW.birth_platform_session_id)=
       (s.birth_launch_id,s.birth_scenario_id,s.birth_generation,s.birth_platform_session_id)
     OR (NEW.birth_launch_id,NEW.birth_scenario_id,NEW.birth_generation,NEW.birth_platform_session_id)=
       (g.launch_id,g.scenario_id,g.generation,g.original_platform_session_id))
 ) THEN RAISE EXCEPTION 'Review scene admission unavailable' USING ERRCODE='42501'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER secureshop_scene_review_target_guard BEFORE INSERT OR UPDATE OR DELETE
 ON identity.secureshop_scene_review_targets FOR EACH ROW
 EXECUTE FUNCTION identity.guard_secureshop_scene_review_target();

-- The first generation transition that retires the scene is the sole cleanup
-- claimant, irrespective of where a physical product/review target was born.
CREATE TABLE identity.secureshop_scene_target_retirements (
 scene_id uuid NOT NULL REFERENCES identity.secureshop_scenes(scene_id),
 target_kind text NOT NULL CHECK(target_kind IN ('products','reviews')),
 target_id uuid NOT NULL UNIQUE,
 retiring_launch_id uuid NOT NULL REFERENCES identity.secureshop_launches(launch_id),
 from_generation bigint NOT NULL CHECK(from_generation>=1),
 to_generation bigint NOT NULL CHECK(to_generation=from_generation+1),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(scene_id,target_kind)
);
CREATE FUNCTION identity.guard_secureshop_scene_target_retirement() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,identity AS $$
BEGIN
 IF TG_OP<>'INSERT' OR NOT EXISTS (
  SELECT 1 FROM identity.secureshop_scenes s
  JOIN identity.secureshop_launches l ON l.launch_id=NEW.retiring_launch_id
  LEFT JOIN identity.secureshop_scene_review_targets review ON review.scene_id=s.scene_id
  WHERE s.scene_id=NEW.scene_id AND s.status='retired'
   AND l.generation>=NEW.to_generation AND l.original_platform_owner_id=s.original_platform_owner_id
   AND ((NEW.target_kind='products' AND NEW.target_id=s.product_target_id)
     OR (NEW.target_kind='reviews' AND NEW.target_id=review.target_id))
   AND (s.birth_launch_id=l.launch_id OR EXISTS (
    SELECT 1 FROM identity.secureshop_scene_execution_grants g
    WHERE g.scene_id=s.scene_id AND g.launch_id=l.launch_id AND g.generation=NEW.from_generation
      AND g.original_platform_owner_id=l.original_platform_owner_id
      AND g.original_platform_session_id=l.original_platform_session_id))
 ) THEN RAISE EXCEPTION 'Invalid immutable scene target retirement' USING ERRCODE='55000'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER secureshop_scene_target_retirement_guard BEFORE INSERT OR UPDATE OR DELETE
 ON identity.secureshop_scene_target_retirements FOR EACH ROW
 EXECUTE FUNCTION identity.guard_secureshop_scene_target_retirement();

-- Preserve already completed product cleanup without inventing a claimant:
-- the immutable target history identifies its exact reset. A mapped mail
-- retirement also identifies the exact transition for still-reserved product
-- debt. Other older retired scenes remain unresolved for explicit recovery.
INSERT INTO identity.secureshop_scene_target_retirements
 (scene_id,target_kind,target_id,retiring_launch_id,from_generation,to_generation)
SELECT s.scene_id,'products',s.product_target_id,o.launch_id,o.from_generation,o.to_generation
FROM identity.secureshop_scenes s
JOIN identity.secureshop_target_cleanup_history h ON h.target_id=s.product_target_id
 AND h.target_kind='products'
JOIN identity.secureshop_launch_resets o ON o.reset_id=h.operation_id
WHERE s.status='retired' AND (s.birth_launch_id=o.launch_id OR EXISTS (
 SELECT 1 FROM identity.secureshop_scene_execution_grants g
 WHERE g.scene_id=s.scene_id AND g.launch_id=o.launch_id AND g.generation=o.from_generation))
ON CONFLICT DO NOTHING;
INSERT INTO identity.secureshop_scene_target_retirements
 (scene_id,target_kind,target_id,retiring_launch_id,from_generation,to_generation)
SELECT s.scene_id,'products',s.product_target_id,c.retiring_launch_id,c.from_generation,c.to_generation
FROM identity.secureshop_scenes s
JOIN identity.secureshop_mail_scene_retirements c ON c.scene_id=s.scene_id
WHERE s.status='retired'
ON CONFLICT DO NOTHING;

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
   INSERT INTO identity.secureshop_scene_target_retirements
    (scene_id,target_kind,target_id,retiring_launch_id,from_generation,to_generation)
   SELECT s.scene_id,'products',s.product_target_id,OLD.launch_id,OLD.generation,NEW.generation
    FROM identity.secureshop_scenes s WHERE s.scene_id=retired_scene;
   INSERT INTO identity.secureshop_scene_target_retirements
    (scene_id,target_kind,target_id,retiring_launch_id,from_generation,to_generation)
   SELECT m.scene_id,'reviews',m.target_id,OLD.launch_id,OLD.generation,NEW.generation
    FROM identity.secureshop_scene_review_targets m WHERE m.scene_id=retired_scene;
  END LOOP;
 END IF;
 RETURN NEW;
END $$;

CREATE FUNCTION identity.scene_target_reset_cleanup_authorized(
 requested_reset uuid,requested_target uuid,requested_kind text,birth_launch uuid,birth_scenario uuid,
 birth_generation bigint,birth_owner integer,birth_session integer)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,identity AS $$
 SELECT EXISTS (
  SELECT 1 FROM identity.secureshop_scene_target_retirements claim
  JOIN identity.secureshop_scenes s ON s.scene_id=claim.scene_id
  LEFT JOIN identity.secureshop_scene_review_targets review ON review.scene_id=s.scene_id
  JOIN identity.secureshop_launch_resets o ON o.launch_id=claim.retiring_launch_id
   AND o.from_generation=claim.from_generation AND o.to_generation=claim.to_generation
  JOIN identity.secureshop_launches retiring ON retiring.launch_id=o.launch_id
  JOIN identity.secureshop_launches born ON born.launch_id=$4
  WHERE o.reset_id=$1 AND claim.target_id=$2 AND claim.target_kind=$3
   AND s.status='retired' AND retiring.generation>=o.to_generation
   AND retiring.original_platform_owner_id=s.original_platform_owner_id
   AND born.scenario_id=$5 AND born.original_platform_owner_id=$7
   AND born.original_platform_session_id=$8
   AND ((claim.target_kind='products' AND
     (s.product_target_id,s.birth_launch_id,s.birth_scenario_id,s.birth_generation,
       s.original_platform_owner_id,s.birth_platform_session_id)=($2,$4,$5,$6,$7,$8))
    OR (claim.target_kind='reviews' AND
     (review.target_id,review.birth_launch_id,review.birth_scenario_id,review.birth_generation,
       review.original_platform_owner_id,review.birth_platform_session_id)=($2,$4,$5,$6,$7,$8)))
   AND (EXISTS (SELECT 1 FROM identity.secureshop_target_reservations r
     WHERE r.target_id=$2 AND r.target_kind=$3 AND r.launch_id=$4 AND r.generation=$6
       AND r.original_platform_owner_id=$7)
    OR EXISTS (SELECT 1 FROM identity.secureshop_target_cleanup_history h
     WHERE h.target_id=$2 AND h.target_kind=$3 AND h.operation_id=$1
       AND (h.launch_id,h.scenario_id,h.from_generation,h.original_platform_owner_id,
         h.original_platform_session_id)=($4,$5,$6,$7,$8)))
 )
$$;

-- Runtime may repair a crash after the exact mirror was stored, but cannot
-- choose or replace the canonical reset claimant. Only the product claim
-- already captured from the actual scene transition supplies its tuple.
CREATE FUNCTION identity.ensure_secureshop_scene_review_retirement(
 requested_scene uuid,requested_review uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,identity AS $$
DECLARE product_claim identity.secureshop_scene_target_retirements%ROWTYPE;
BEGIN
 SELECT claim.* INTO product_claim
 FROM identity.secureshop_scene_target_retirements claim
 JOIN identity.secureshop_scenes scene ON scene.scene_id=claim.scene_id
 JOIN identity.secureshop_scene_review_targets review ON review.scene_id=scene.scene_id
 WHERE claim.scene_id=requested_scene AND claim.target_kind='products'
   AND claim.target_id=scene.product_target_id AND scene.status='retired'
   AND review.target_id=requested_review;
 IF product_claim.scene_id IS NULL THEN RETURN false; END IF;
 INSERT INTO identity.secureshop_scene_target_retirements
   (scene_id,target_kind,target_id,retiring_launch_id,from_generation,to_generation)
 VALUES(requested_scene,'reviews',requested_review,product_claim.retiring_launch_id,
   product_claim.from_generation,product_claim.to_generation)
 ON CONFLICT DO NOTHING;
 RETURN EXISTS(SELECT 1 FROM identity.secureshop_scene_target_retirements claim
  WHERE claim.scene_id=requested_scene AND claim.target_kind='reviews'
   AND claim.target_id=requested_review
   AND (claim.retiring_launch_id,claim.from_generation,claim.to_generation)=
     (product_claim.retiring_launch_id,product_claim.from_generation,product_claim.to_generation));
END $$;

-- History remains one immutable row per target. Multiple targets of a kind
-- may share the canonical reset only when each has its own private receipt.
ALTER TABLE identity.secureshop_target_cleanup_history
 DROP CONSTRAINT secureshop_target_cleanup_history_operation_id_target_kind_key;
CREATE INDEX secureshop_target_cleanup_operation_kind
 ON identity.secureshop_target_cleanup_history(operation_id,target_kind,target_id);

CREATE OR REPLACE FUNCTION identity.validate_secureshop_target_cleanup_history()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,identity AS $$
DECLARE authority identity.secureshop_launches%ROWTYPE;
DECLARE reset_authority identity.secureshop_launch_resets%ROWTYPE;
DECLARE reservation identity.secureshop_target_reservations%ROWTYPE;
DECLARE mapped_mail boolean;
DECLARE mapped_scene boolean;
BEGIN
 SELECT * INTO authority FROM identity.secureshop_launches WHERE launch_id=NEW.launch_id FOR UPDATE;
 SELECT * INTO reset_authority FROM identity.secureshop_launch_resets WHERE reset_id=NEW.operation_id FOR UPDATE;
 SELECT * INTO reservation FROM identity.secureshop_target_reservations WHERE target_id=NEW.target_id FOR UPDATE;
 mapped_mail:=NEW.target_kind='persona_inbox' AND EXISTS (
  SELECT 1 FROM identity.secureshop_mail_scenes m WHERE m.target_id=NEW.target_id);
 mapped_scene:=((NEW.target_kind='products' AND EXISTS (
  SELECT 1 FROM identity.secureshop_scenes s WHERE s.product_target_id=NEW.target_id))
  OR (NEW.target_kind='reviews' AND EXISTS (
  SELECT 1 FROM identity.secureshop_scene_review_targets m WHERE m.target_id=NEW.target_id)));
 IF reservation.target_id IS NULL OR authority.launch_id IS NULL OR reset_authority.reset_id IS NULL
  OR reservation.launch_id<>NEW.launch_id OR reservation.generation<>NEW.from_generation
  OR reservation.target_kind<>NEW.target_kind OR reservation.original_platform_owner_id<>NEW.original_platform_owner_id
  OR authority.scenario_id<>NEW.scenario_id OR authority.original_platform_owner_id<>NEW.original_platform_owner_id
  OR authority.original_platform_session_id<>NEW.original_platform_session_id
  OR (mapped_mail AND NOT identity.mail_scene_reset_cleanup_authorized(NEW.operation_id,NEW.target_id,
    NEW.launch_id,NEW.scenario_id,NEW.from_generation,NEW.original_platform_owner_id,NEW.original_platform_session_id))
  OR (mapped_scene AND NOT identity.scene_target_reset_cleanup_authorized(NEW.operation_id,NEW.target_id,
    NEW.target_kind,NEW.launch_id,NEW.scenario_id,NEW.from_generation,
    NEW.original_platform_owner_id,NEW.original_platform_session_id))
  OR (NOT mapped_mail AND NOT mapped_scene AND (reset_authority.launch_id<>NEW.launch_id
    OR reset_authority.from_generation<>NEW.from_generation))
 THEN RAISE EXCEPTION 'SecureShop cleanup history binding is invalid'; END IF;
 RETURN NEW;
END $$;

REVOKE ALL ON identity.secureshop_scene_review_targets,identity.secureshop_scene_target_retirements FROM PUBLIC;
GRANT SELECT,INSERT ON identity.secureshop_scene_review_targets TO dvaia_identity_runtime;
GRANT SELECT ON identity.secureshop_scene_target_retirements TO dvaia_identity_runtime;
REVOKE ALL ON FUNCTION identity.guard_secureshop_scene_review_target(),
 identity.guard_secureshop_scene_target_retirement(),
 identity.scene_target_reset_cleanup_authorized(uuid,uuid,text,uuid,uuid,bigint,integer,integer),
 identity.ensure_secureshop_scene_review_retirement(uuid,uuid)
 FROM PUBLIC,dvaia_identity_runtime;
GRANT EXECUTE ON FUNCTION identity.scene_target_reset_cleanup_authorized(uuid,uuid,text,uuid,uuid,bigint,integer,integer)
 TO dvaia_identity_runtime;
GRANT EXECUTE ON FUNCTION identity.ensure_secureshop_scene_review_retirement(uuid,uuid)
 TO dvaia_identity_runtime;
