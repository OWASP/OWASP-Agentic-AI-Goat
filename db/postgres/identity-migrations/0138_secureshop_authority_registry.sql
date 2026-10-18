-- SecureShop execution authority supports independent shop accounts without
-- creating a workshop user, role, permission or platform session. Historical
-- coordinates retain their exact numeric values and explicit source realm.
CREATE TABLE identity.secureshop_authority_owners (
  id integer PRIMARY KEY CHECK(id>0),
  realm text NOT NULL CHECK(realm IN ('platform','shop')),
  platform_user_id integer UNIQUE,
  shop_principal_id uuid UNIQUE REFERENCES secureshop_auth.principals(principal_id),
  is_active integer NOT NULL CHECK(is_active IN (0,1)),
  account_locked_until timestamptz,
  source_deleted boolean NOT NULL DEFAULT false,
  CHECK((realm='platform' AND platform_user_id=id AND shop_principal_id IS NULL)
    OR (realm='shop' AND platform_user_id IS NULL AND shop_principal_id IS NOT NULL))
);
CREATE TABLE identity.secureshop_authority_sessions (
  id integer PRIMARY KEY CHECK(id>0),
  user_id integer NOT NULL REFERENCES identity.secureshop_authority_owners(id),
  realm text NOT NULL CHECK(realm IN ('platform','shop')),
  platform_session_id integer UNIQUE,
  shop_session_id integer UNIQUE REFERENCES secureshop_auth.sessions(session_id),
  is_active integer NOT NULL CHECK(is_active IN (0,1)),
  expires_at timestamptz NOT NULL,
  source_deleted boolean NOT NULL DEFAULT false,
  CHECK((realm='platform' AND platform_session_id=id AND shop_session_id IS NULL)
    OR (realm='shop' AND platform_session_id IS NULL AND shop_session_id=id))
);

INSERT INTO identity.secureshop_authority_owners(id,realm,platform_user_id,is_active,account_locked_until)
  SELECT id,'platform',id,is_active,account_locked_until FROM identity.users;
-- Deleted legacy owners/sessions remain inactive tombstones, never accounts.
INSERT INTO identity.secureshop_authority_owners(id,realm,platform_user_id,is_active,source_deleted)
  SELECT DISTINCT original_platform_owner_id,'platform',original_platform_owner_id,0,true
  FROM identity.secureshop_launches ON CONFLICT(id) DO NOTHING;
INSERT INTO identity.secureshop_authority_owners(id,realm,shop_principal_id,is_active,account_locked_until)
  SELECT owner_id,'shop',principal_id,is_active::integer,locked_until FROM secureshop_auth.principals;
INSERT INTO identity.secureshop_authority_sessions(id,user_id,realm,platform_session_id,is_active,expires_at)
  SELECT id,user_id,'platform',id,is_active,expires_at FROM identity.user_sessions;
INSERT INTO identity.secureshop_authority_sessions(id,user_id,realm,platform_session_id,is_active,expires_at,source_deleted)
  SELECT DISTINCT ON(original_platform_session_id) original_platform_session_id,original_platform_owner_id,
    'platform',original_platform_session_id,0,expires_at,true
  FROM identity.secureshop_launches ORDER BY original_platform_session_id,created_at
  ON CONFLICT(id) DO NOTHING;
INSERT INTO identity.secureshop_authority_sessions(id,user_id,realm,shop_session_id,is_active,expires_at)
  SELECT s.session_id,p.owner_id,'shop',s.session_id,
    (s.revoked_at IS NULL AND p.is_active AND s.credential_version=p.credential_version
      AND s.authority_version=p.authority_version)::integer,s.expires_at
  FROM secureshop_auth.sessions s JOIN secureshop_auth.principals p USING(principal_id);

-- Imports may retain identifiers above the present sequence head. Advance
-- allocation past all retained identities; never reuse a deleted subject.
DO $$
DECLARE owner_sequence regclass; session_sequence regclass;
BEGIN
  owner_sequence:=pg_get_serial_sequence('identity.users','id')::regclass;
  session_sequence:=pg_get_serial_sequence('identity.user_sessions','id')::regclass;
  PERFORM setval(owner_sequence,GREATEST(nextval(owner_sequence),
    COALESCE((SELECT max(id) FROM identity.secureshop_authority_owners),1)),true);
  PERFORM setval(session_sequence,GREATEST(nextval(session_sequence),
    COALESCE((SELECT max(id) FROM identity.secureshop_authority_sessions),1)),true);
END $$;

-- Source triggers maintain the registry under the same row locks used by shop
-- execution. A registry write must match its canonical source exactly.
CREATE FUNCTION identity.guard_secureshop_authority_registry() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,identity,secureshop_auth AS $$
DECLARE valid boolean;
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Shop authority history is immutable' USING ERRCODE='55000'; END IF;
  IF TG_OP='UPDATE' THEN
    IF NEW.id<>OLD.id OR NEW.realm<>OLD.realm OR OLD.source_deleted THEN
      RAISE EXCEPTION 'Shop authority identity is immutable' USING ERRCODE='55000';
    END IF;
    IF TG_TABLE_NAME='secureshop_authority_owners' THEN
      IF (NEW.platform_user_id,NEW.shop_principal_id) IS DISTINCT FROM (OLD.platform_user_id,OLD.shop_principal_id) THEN
        RAISE EXCEPTION 'Shop authority owner is immutable' USING ERRCODE='55000';
      END IF;
    ELSIF (NEW.user_id,NEW.platform_session_id,NEW.shop_session_id)
      IS DISTINCT FROM (OLD.user_id,OLD.platform_session_id,OLD.shop_session_id) THEN
      RAISE EXCEPTION 'Shop authority session is immutable' USING ERRCODE='55000';
    END IF;
  END IF;
  IF TG_TABLE_NAME='secureshop_authority_owners' THEN
    IF NEW.realm='platform' THEN
      SELECT EXISTS(SELECT 1 FROM identity.users u WHERE u.id=NEW.id
        AND u.is_active=NEW.is_active AND u.account_locked_until IS NOT DISTINCT FROM NEW.account_locked_until
        AND NOT NEW.source_deleted) OR (NEW.source_deleted AND NEW.is_active=0
          AND NOT EXISTS(SELECT 1 FROM identity.users WHERE id=NEW.id)) INTO valid;
    ELSE
      SELECT EXISTS(SELECT 1 FROM secureshop_auth.principals p WHERE p.principal_id=NEW.shop_principal_id
        AND p.owner_id=NEW.id AND p.is_active::integer=NEW.is_active
        AND p.locked_until IS NOT DISTINCT FROM NEW.account_locked_until AND NOT NEW.source_deleted) INTO valid;
    END IF;
  ELSE
    IF NEW.realm='platform' THEN
      SELECT EXISTS(SELECT 1 FROM identity.user_sessions s WHERE s.id=NEW.id AND s.user_id=NEW.user_id
        AND s.is_active=NEW.is_active AND s.expires_at=NEW.expires_at AND NOT NEW.source_deleted)
        OR (NEW.source_deleted AND NEW.is_active=0 AND NOT EXISTS(SELECT 1 FROM identity.user_sessions WHERE id=NEW.id)) INTO valid;
    ELSE
      SELECT EXISTS(SELECT 1 FROM secureshop_auth.sessions s JOIN secureshop_auth.principals p USING(principal_id)
        WHERE s.session_id=NEW.id AND p.owner_id=NEW.user_id AND s.expires_at=NEW.expires_at
          AND (s.revoked_at IS NULL AND p.is_active AND s.credential_version=p.credential_version
            AND s.authority_version=p.authority_version)::integer=NEW.is_active AND NOT NEW.source_deleted) INTO valid;
    END IF;
  END IF;
  IF valid IS DISTINCT FROM true THEN RAISE EXCEPTION 'Shop authority source mismatch' USING ERRCODE='55000'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER secureshop_authority_owner_guard BEFORE INSERT OR UPDATE OR DELETE ON identity.secureshop_authority_owners
  FOR EACH ROW EXECUTE FUNCTION identity.guard_secureshop_authority_registry();
CREATE TRIGGER secureshop_authority_session_guard BEFORE INSERT OR UPDATE OR DELETE ON identity.secureshop_authority_sessions
  FOR EACH ROW EXECUTE FUNCTION identity.guard_secureshop_authority_registry();

CREATE FUNCTION identity.sync_secureshop_authority_registry() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,identity,secureshop_auth AS $$
DECLARE source_id integer; principal uuid;
BEGIN
  IF TG_TABLE_SCHEMA='identity' AND TG_TABLE_NAME='users' THEN
    IF TG_OP='DELETE' THEN
      UPDATE identity.secureshop_authority_owners SET is_active=0,source_deleted=true WHERE id=OLD.id;
      RETURN OLD;
    END IF;
    INSERT INTO identity.secureshop_authority_owners(id,realm,platform_user_id,is_active,account_locked_until)
      VALUES(NEW.id,'platform',NEW.id,NEW.is_active,NEW.account_locked_until)
      ON CONFLICT(id) DO UPDATE SET realm=EXCLUDED.realm,platform_user_id=EXCLUDED.platform_user_id,
        shop_principal_id=EXCLUDED.shop_principal_id,is_active=EXCLUDED.is_active,account_locked_until=EXCLUDED.account_locked_until;
  ELSIF TG_TABLE_SCHEMA='identity' AND TG_TABLE_NAME='user_sessions' THEN
    IF TG_OP='DELETE' THEN
      UPDATE identity.secureshop_authority_sessions SET is_active=0,source_deleted=true WHERE id=OLD.id;
      UPDATE identity.secureshop_launches SET platform_session_id=NULL WHERE platform_session_id=OLD.id;
      RETURN OLD;
    END IF;
    INSERT INTO identity.secureshop_authority_sessions(id,user_id,realm,platform_session_id,is_active,expires_at)
      VALUES(NEW.id,NEW.user_id,'platform',NEW.id,NEW.is_active,NEW.expires_at)
      ON CONFLICT(id) DO UPDATE SET realm=EXCLUDED.realm,user_id=EXCLUDED.user_id,
        platform_session_id=EXCLUDED.platform_session_id,shop_session_id=EXCLUDED.shop_session_id,
        is_active=EXCLUDED.is_active,expires_at=EXCLUDED.expires_at;
  ELSIF TG_TABLE_NAME='principals' THEN
    IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Shop principal deletion requires lifecycle receipts'; END IF;
    INSERT INTO identity.secureshop_authority_owners(id,realm,shop_principal_id,is_active,account_locked_until)
      VALUES(NEW.owner_id,'shop',NEW.principal_id,NEW.is_active::integer,NEW.locked_until)
      ON CONFLICT(id) DO UPDATE SET realm=EXCLUDED.realm,platform_user_id=EXCLUDED.platform_user_id,
        shop_principal_id=EXCLUDED.shop_principal_id,is_active=EXCLUDED.is_active,account_locked_until=EXCLUDED.account_locked_until;
    -- Password/role version changes immediately fence every previous session.
    UPDATE identity.secureshop_authority_sessions registry SET is_active=
      (s.revoked_at IS NULL AND NEW.is_active AND s.credential_version=NEW.credential_version
        AND s.authority_version=NEW.authority_version)::integer
      FROM secureshop_auth.sessions s WHERE registry.shop_session_id=s.session_id AND s.principal_id=NEW.principal_id;
  ELSIF TG_TABLE_NAME='sessions' THEN
    IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Shop session history is immutable'; END IF;
    INSERT INTO identity.secureshop_authority_sessions(id,user_id,realm,shop_session_id,is_active,expires_at)
      SELECT NEW.session_id,p.owner_id,'shop',NEW.session_id,
        (NEW.revoked_at IS NULL AND p.is_active AND NEW.credential_version=p.credential_version
          AND NEW.authority_version=p.authority_version)::integer,NEW.expires_at
      FROM secureshop_auth.principals p WHERE p.principal_id=NEW.principal_id
      ON CONFLICT(id) DO UPDATE SET realm=EXCLUDED.realm,user_id=EXCLUDED.user_id,
        platform_session_id=EXCLUDED.platform_session_id,shop_session_id=EXCLUDED.shop_session_id,
        is_active=EXCLUDED.is_active,expires_at=EXCLUDED.expires_at;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER secureshop_platform_owner_registry AFTER INSERT OR UPDATE OR DELETE ON identity.users
  FOR EACH ROW EXECUTE FUNCTION identity.sync_secureshop_authority_registry();
CREATE TRIGGER secureshop_platform_session_registry AFTER INSERT OR UPDATE OR DELETE ON identity.user_sessions
  FOR EACH ROW EXECUTE FUNCTION identity.sync_secureshop_authority_registry();
CREATE TRIGGER secureshop_shop_owner_registry AFTER INSERT OR UPDATE ON secureshop_auth.principals
  FOR EACH ROW EXECUTE FUNCTION identity.sync_secureshop_authority_registry();
CREATE TRIGGER secureshop_shop_session_registry AFTER INSERT OR UPDATE ON secureshop_auth.sessions
  FOR EACH ROW EXECUTE FUNCTION identity.sync_secureshop_authority_registry();

-- Point the current execution FK at the realm registry. Birth columns, target
-- rows, reset journals and prior model/effect receipts are unchanged.
ALTER TABLE identity.secureshop_launches DROP CONSTRAINT secureshop_launches_platform_session_id_fkey;
ALTER TABLE identity.secureshop_launches ADD CONSTRAINT secureshop_launches_authority_session_fkey
  FOREIGN KEY(platform_session_id) REFERENCES identity.secureshop_authority_sessions(id) ON DELETE RESTRICT;
CREATE TRIGGER secureshop_registry_session_fence BEFORE UPDATE OF is_active ON identity.secureshop_authority_sessions
  FOR EACH ROW EXECUTE FUNCTION identity.fence_secureshop_launch_on_session_end();

REVOKE ALL ON identity.secureshop_authority_owners,identity.secureshop_authority_sessions FROM PUBLIC;
GRANT SELECT,UPDATE ON identity.secureshop_authority_owners,identity.secureshop_authority_sessions TO dvaia_identity_runtime;
REVOKE ALL ON FUNCTION identity.guard_secureshop_authority_registry(),identity.sync_secureshop_authority_registry() FROM PUBLIC;

CREATE OR REPLACE FUNCTION identity.validate_secureshop_launch_identity()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE actual_owner integer;
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.platform_session_id IS NULL
       OR NEW.original_platform_session_id <> NEW.platform_session_id THEN
      RAISE EXCEPTION 'SecureShop launch cleanup identity is invalid';
    END IF;
    SELECT s.user_id INTO actual_owner FROM identity.secureshop_authority_sessions s
      WHERE s.id = NEW.platform_session_id;
    IF actual_owner IS NULL OR NEW.original_platform_owner_id <> actual_owner THEN
      RAISE EXCEPTION 'SecureShop launch cleanup identity is invalid';
    END IF;
  ELSIF NEW.launch_id IS DISTINCT FROM OLD.launch_id
     OR NEW.original_platform_session_id IS DISTINCT FROM OLD.original_platform_session_id
     OR NEW.original_platform_owner_id IS DISTINCT FROM OLD.original_platform_owner_id
     OR NEW.scenario_id IS DISTINCT FROM OLD.scenario_id
     OR NOT (NEW.platform_session_id IS NOT DISTINCT FROM OLD.platform_session_id
       OR (OLD.platform_session_id IS NOT NULL AND NEW.platform_session_id IS NULL)) THEN
    RAISE EXCEPTION 'SecureShop launch cleanup identity is immutable';
  END IF;
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION identity.validate_secureshop_target_reservation()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE authority identity.secureshop_launches%ROWTYPE;
BEGIN
  IF NEW.target_kind IN ('products','reviews') THEN
    -- Same owner-before-launch lock order as the admission/reset repositories.
    PERFORM 1 FROM identity.secureshop_authority_owners WHERE id=NEW.original_platform_owner_id FOR UPDATE;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'SecureShop target reservation owner is unavailable';
    END IF;
  END IF;
  SELECT * INTO authority FROM identity.secureshop_launches
    WHERE launch_id=NEW.launch_id FOR KEY SHARE;
  IF NOT FOUND OR authority.original_platform_owner_id <> NEW.original_platform_owner_id
     OR authority.generation <> NEW.generation OR authority.status <> 'active'
     OR authority.expires_at <= clock_timestamp() THEN
    RAISE EXCEPTION 'SecureShop target reservation binding is invalid';
  END IF;
  IF NEW.target_kind='products' THEN
    SELECT slot INTO NEW.product_owner_slot FROM generate_series(1,256) AS slots(slot)
      WHERE NOT EXISTS (
        SELECT 1 FROM identity.secureshop_target_reservations r
        WHERE r.original_platform_owner_id=NEW.original_platform_owner_id
          AND r.target_kind='products' AND r.product_owner_slot=slots.slot
      ) ORDER BY slot LIMIT 1;
    IF NEW.product_owner_slot IS NULL THEN
      RAISE EXCEPTION USING ERRCODE='54000', MESSAGE='SecureShop retained shop session limit reached';
    END IF;
  ELSIF NEW.target_kind='reviews' THEN
    SELECT slot INTO NEW.review_owner_slot FROM generate_series(1,256) AS slots(slot)
      WHERE NOT EXISTS (
        SELECT 1 FROM identity.secureshop_target_reservations r
        WHERE r.original_platform_owner_id=NEW.original_platform_owner_id
          AND r.target_kind='reviews' AND r.review_owner_slot=slots.slot
      ) ORDER BY slot LIMIT 1;
    IF NEW.review_owner_slot IS NULL THEN
      RAISE EXCEPTION USING ERRCODE='54000', MESSAGE='SecureShop retained review session limit reached';
    END IF;
  END IF;
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION identity.admit_secureshop_launch_capacity()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,identity AS $$
DECLARE available_slot smallint;
BEGIN
  PERFORM 1 FROM identity.secureshop_authority_owners WHERE id=NEW.original_platform_owner_id FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'SecureShop launch owner is unavailable';
  END IF;
  IF (SELECT count(*) FROM identity.secureshop_launches l
      WHERE l.original_platform_owner_id=NEW.original_platform_owner_id
        AND NOT identity.secureshop_launch_is_retired(l.launch_id)) >= 256 THEN
    RAISE EXCEPTION USING ERRCODE='54000', MESSAGE='SecureShop retained session limit reached';
  END IF;
  DELETE FROM identity.secureshop_launch_capacity c
    WHERE c.original_platform_owner_id=NEW.original_platform_owner_id
      AND identity.secureshop_launch_is_retired(c.launch_id);
  SELECT slot INTO available_slot FROM generate_series(1,256) AS slots(slot)
    WHERE NOT EXISTS (
      SELECT 1 FROM identity.secureshop_launch_capacity c
      WHERE c.original_platform_owner_id=NEW.original_platform_owner_id AND c.owner_slot=slots.slot
    ) ORDER BY slot LIMIT 1;
  IF available_slot IS NULL THEN
    RAISE EXCEPTION USING ERRCODE='54000', MESSAGE='SecureShop retained session limit reached';
  END IF;
  INSERT INTO identity.secureshop_launch_capacity(launch_id,original_platform_owner_id,owner_slot)
    VALUES(NEW.launch_id,NEW.original_platform_owner_id,available_slot);
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION identity.guard_secureshop_scene_grant() RETURNS trigger LANGUAGE plpgsql
SET search_path=pg_catalog,identity AS $$
BEGIN
  IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Shop scene grant is immutable' USING ERRCODE='55000'; END IF;
  IF NOT EXISTS(SELECT 1 FROM identity.secureshop_scenes scene
    JOIN identity.secureshop_launches l ON l.launch_id=NEW.launch_id
    JOIN identity.secureshop_authority_sessions session ON session.id=l.platform_session_id
    JOIN identity.secureshop_authority_owners owner ON owner.id=session.user_id
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
