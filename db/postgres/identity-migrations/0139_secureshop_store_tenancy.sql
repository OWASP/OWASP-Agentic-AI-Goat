-- One explicit public synthetic storefront, with independent account authority.
-- Principal-owned histories from earlier revisions retain their exact IDs.
CREATE TABLE secureshop_auth.tenants (
  tenant_id uuid PRIMARY KEY,
  owner_id integer NOT NULL UNIQUE DEFAULT nextval(pg_get_serial_sequence('identity.users','id')::regclass),
  slug text NOT NULL UNIQUE CHECK(slug ~ '^[a-z][a-z0-9_-]{0,63}$'),
  seed_merchant_id integer REFERENCES secureshop_auth.principals(shop_user_id),
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE secureshop_auth.tenant_memberships (
  tenant_id uuid NOT NULL REFERENCES secureshop_auth.tenants(tenant_id),
  principal_id uuid NOT NULL REFERENCES secureshop_auth.principals(principal_id),
  shop_user_id integer NOT NULL REFERENCES secureshop_auth.principals(shop_user_id),
  role text NOT NULL CHECK(role IN ('customer','merchant','admin')),
  membership_version bigint NOT NULL DEFAULT 1 CHECK(membership_version>0),
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(tenant_id,principal_id), UNIQUE(tenant_id,shop_user_id)
);
CREATE TABLE secureshop_auth.execution_sessions (
  session_id integer PRIMARY KEY DEFAULT nextval(pg_get_serial_sequence('identity.user_sessions','id')::regclass),
  auth_session_id integer NOT NULL REFERENCES secureshop_auth.sessions(session_id),
  tenant_id uuid NOT NULL,
  principal_id uuid NOT NULL,
  membership_version bigint NOT NULL CHECK(membership_version>0),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY(tenant_id,principal_id) REFERENCES secureshop_auth.tenant_memberships(tenant_id,principal_id),
  UNIQUE(auth_session_id,tenant_id,membership_version),
  CHECK(expires_at>created_at)
);
CREATE INDEX shop_execution_principal ON secureshop_auth.execution_sessions(principal_id,tenant_id);
CREATE INDEX shop_execution_tenant ON secureshop_auth.execution_sessions(tenant_id);

ALTER TABLE identity.secureshop_authority_owners ADD COLUMN shop_tenant_id uuid UNIQUE
  REFERENCES secureshop_auth.tenants(tenant_id);
ALTER TABLE identity.secureshop_authority_owners DROP CONSTRAINT secureshop_authority_owners_check;
ALTER TABLE identity.secureshop_authority_owners ADD CONSTRAINT secureshop_authority_owner_realm CHECK(
  (realm='platform' AND platform_user_id=id AND shop_principal_id IS NULL AND shop_tenant_id IS NULL)
  OR (realm='shop' AND platform_user_id IS NULL AND num_nonnulls(shop_principal_id,shop_tenant_id)=1));
ALTER TABLE identity.secureshop_authority_sessions ADD COLUMN shop_execution_session_id integer UNIQUE
  REFERENCES secureshop_auth.execution_sessions(session_id);
ALTER TABLE identity.secureshop_authority_sessions DROP CONSTRAINT secureshop_authority_sessions_check;
ALTER TABLE identity.secureshop_authority_sessions ADD CONSTRAINT secureshop_authority_session_realm CHECK(
  (realm='platform' AND platform_session_id=id AND shop_session_id IS NULL AND shop_execution_session_id IS NULL)
  OR (realm='shop' AND platform_session_id IS NULL AND
    ((shop_session_id=id AND shop_execution_session_id IS NULL) OR
     (shop_execution_session_id=id AND shop_session_id IS NULL))));

CREATE FUNCTION secureshop_auth.guard_store_identity() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,secureshop_auth AS $$
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Shop store identity history is immutable' USING ERRCODE='55000'; END IF;
  IF TG_TABLE_NAME='tenants' THEN
    IF TG_OP='UPDATE' AND ((NEW.tenant_id,NEW.owner_id,NEW.slug,NEW.created_at)
      IS DISTINCT FROM (OLD.tenant_id,OLD.owner_id,OLD.slug,OLD.created_at)
      OR (OLD.seed_merchant_id IS NOT NULL AND NEW.seed_merchant_id IS DISTINCT FROM OLD.seed_merchant_id)) THEN
      RAISE EXCEPTION 'Shop store identity is immutable' USING ERRCODE='55000';
    END IF;
    IF NEW.seed_merchant_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM secureshop_auth.tenant_memberships m
      WHERE m.tenant_id=NEW.tenant_id AND m.shop_user_id=NEW.seed_merchant_id AND m.role='merchant' AND m.is_active) THEN
      RAISE EXCEPTION 'Seed inventory merchant must belong to this shop' USING ERRCODE='55000';
    END IF;
  ELSIF TG_TABLE_NAME='tenant_memberships' THEN
    IF NOT EXISTS(SELECT 1 FROM secureshop_auth.principals p WHERE p.principal_id=NEW.principal_id
      AND p.shop_user_id=NEW.shop_user_id) THEN RAISE EXCEPTION 'Shop member identity mismatch' USING ERRCODE='55000'; END IF;
    IF TG_OP='UPDATE' AND ((NEW.tenant_id,NEW.principal_id,NEW.shop_user_id,NEW.created_at)
      IS DISTINCT FROM (OLD.tenant_id,OLD.principal_id,OLD.shop_user_id,OLD.created_at)
      OR NEW.membership_version<OLD.membership_version
      OR ((NEW.role,NEW.is_active) IS DISTINCT FROM (OLD.role,OLD.is_active) AND NEW.membership_version<=OLD.membership_version)) THEN
      RAISE EXCEPTION 'Shop membership identity/version mismatch' USING ERRCODE='55000';
    END IF;
  ELSE
    IF TG_OP='INSERT' AND NOT EXISTS(SELECT 1 FROM secureshop_auth.sessions s
      JOIN secureshop_auth.principals p USING(principal_id)
      JOIN secureshop_auth.tenant_memberships m ON m.principal_id=p.principal_id AND m.tenant_id=NEW.tenant_id
      JOIN secureshop_auth.tenants t USING(tenant_id)
      WHERE s.session_id=NEW.auth_session_id AND p.principal_id=NEW.principal_id
        AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND NEW.expires_at<=s.expires_at
        AND p.is_active AND (p.locked_until IS NULL OR p.locked_until<=clock_timestamp())
        AND s.credential_version=p.credential_version AND s.authority_version=p.authority_version
        AND m.is_active AND m.membership_version=NEW.membership_version AND t.is_active AND NEW.revoked_at IS NULL) THEN
      RAISE EXCEPTION 'Shop execution membership unavailable' USING ERRCODE='55000';
    END IF;
    IF TG_OP='UPDATE' AND ((NEW.session_id,NEW.auth_session_id,NEW.tenant_id,NEW.principal_id,
      NEW.membership_version,NEW.expires_at,NEW.created_at) IS DISTINCT FROM
      (OLD.session_id,OLD.auth_session_id,OLD.tenant_id,OLD.principal_id,
       OLD.membership_version,OLD.expires_at,OLD.created_at) OR OLD.revoked_at IS NOT NULL) THEN
      RAISE EXCEPTION 'Shop execution session identity is immutable' USING ERRCODE='55000';
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER shop_tenant_identity BEFORE INSERT OR UPDATE OR DELETE ON secureshop_auth.tenants
  FOR EACH ROW EXECUTE FUNCTION secureshop_auth.guard_store_identity();
CREATE TRIGGER shop_membership_identity BEFORE INSERT OR UPDATE OR DELETE ON secureshop_auth.tenant_memberships
  FOR EACH ROW EXECUTE FUNCTION secureshop_auth.guard_store_identity();
CREATE TRIGGER shop_execution_identity BEFORE INSERT OR UPDATE OR DELETE ON secureshop_auth.execution_sessions
  FOR EACH ROW EXECUTE FUNCTION secureshop_auth.guard_store_identity();

CREATE VIEW secureshop_auth.execution_authority_state AS
  SELECT e.session_id,t.owner_id,e.expires_at,
    (e.revoked_at IS NULL AND s.revoked_at IS NULL AND p.is_active AND t.is_active AND m.is_active
      AND (p.locked_until IS NULL OR p.locked_until<=clock_timestamp())
      AND s.credential_version=p.credential_version AND s.authority_version=p.authority_version
      AND e.membership_version=m.membership_version)::integer AS is_active,
    e.auth_session_id,e.principal_id,e.tenant_id
  FROM secureshop_auth.execution_sessions e JOIN secureshop_auth.sessions s ON s.session_id=e.auth_session_id
  JOIN secureshop_auth.principals p ON p.principal_id=e.principal_id AND p.principal_id=s.principal_id
  JOIN secureshop_auth.tenant_memberships m ON m.tenant_id=e.tenant_id AND m.principal_id=e.principal_id
  JOIN secureshop_auth.tenants t ON t.tenant_id=e.tenant_id;

CREATE OR REPLACE FUNCTION identity.guard_secureshop_authority_registry() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,identity,secureshop_auth AS $$
DECLARE valid boolean;
BEGIN
  IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Shop authority history is immutable' USING ERRCODE='55000'; END IF;
  IF TG_OP='UPDATE' THEN
    IF NEW.id<>OLD.id OR NEW.realm<>OLD.realm OR OLD.source_deleted THEN
      RAISE EXCEPTION 'Shop authority identity is immutable' USING ERRCODE='55000';
    END IF;
    IF TG_TABLE_NAME='secureshop_authority_owners' THEN
      IF (NEW.platform_user_id,NEW.shop_principal_id,NEW.shop_tenant_id) IS DISTINCT FROM (OLD.platform_user_id,OLD.shop_principal_id,OLD.shop_tenant_id) THEN
        RAISE EXCEPTION 'Shop authority owner is immutable' USING ERRCODE='55000';
      END IF;
    ELSIF (NEW.user_id,NEW.platform_session_id,NEW.shop_session_id,NEW.shop_execution_session_id)
      IS DISTINCT FROM (OLD.user_id,OLD.platform_session_id,OLD.shop_session_id,OLD.shop_execution_session_id) THEN
      RAISE EXCEPTION 'Shop authority session is immutable' USING ERRCODE='55000';
    END IF;
  END IF;
  IF TG_TABLE_NAME='secureshop_authority_owners' THEN
    IF NEW.shop_tenant_id IS NOT NULL THEN
      SELECT EXISTS(SELECT 1 FROM secureshop_auth.tenants t WHERE t.tenant_id=NEW.shop_tenant_id
        AND t.owner_id=NEW.id AND t.is_active::integer=NEW.is_active
        AND NEW.account_locked_until IS NULL AND NOT NEW.source_deleted) INTO valid;
    ELSIF NEW.realm='platform' THEN
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
    IF NEW.shop_execution_session_id IS NOT NULL THEN
      SELECT EXISTS(SELECT 1 FROM secureshop_auth.execution_authority_state e
        WHERE e.session_id=NEW.id AND e.owner_id=NEW.user_id AND e.expires_at=NEW.expires_at
          AND e.is_active=NEW.is_active AND NOT NEW.source_deleted) INTO valid;
    ELSIF NEW.realm='platform' THEN
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

CREATE FUNCTION secureshop_auth.sync_store_execution_authority() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,identity,secureshop_auth AS $$
DECLARE selected_tenant uuid; selected_principal uuid; selected_auth integer; selected_execution integer;
BEGIN
  IF TG_TABLE_NAME='tenants' THEN
    selected_tenant:=NEW.tenant_id;
    INSERT INTO identity.secureshop_authority_owners(id,realm,shop_tenant_id,is_active)
      VALUES(NEW.owner_id,'shop',NEW.tenant_id,NEW.is_active::integer)
      ON CONFLICT(id) DO UPDATE SET realm=EXCLUDED.realm,platform_user_id=NULL,shop_principal_id=NULL,
        shop_tenant_id=EXCLUDED.shop_tenant_id,is_active=EXCLUDED.is_active;
  ELSIF TG_TABLE_NAME='tenant_memberships' THEN
    selected_tenant:=NEW.tenant_id; selected_principal:=NEW.principal_id;
  ELSIF TG_TABLE_NAME='principals' THEN selected_principal:=NEW.principal_id;
  ELSIF TG_TABLE_NAME='sessions' THEN selected_auth:=NEW.session_id;
  ELSE selected_execution:=NEW.session_id;
  END IF;
  INSERT INTO identity.secureshop_authority_sessions(id,user_id,realm,shop_execution_session_id,is_active,expires_at)
    SELECT e.session_id,e.owner_id,'shop',e.session_id,e.is_active,e.expires_at
    FROM secureshop_auth.execution_authority_state e
    WHERE (selected_tenant IS NULL OR e.tenant_id=selected_tenant)
      AND (selected_principal IS NULL OR e.principal_id=selected_principal)
      AND (selected_auth IS NULL OR e.auth_session_id=selected_auth)
      AND (selected_execution IS NULL OR e.session_id=selected_execution)
    ON CONFLICT(id) DO UPDATE SET realm=EXCLUDED.realm,user_id=EXCLUDED.user_id,
      platform_session_id=NULL,shop_session_id=NULL,shop_execution_session_id=EXCLUDED.shop_execution_session_id,
      is_active=EXCLUDED.is_active,expires_at=EXCLUDED.expires_at;
  RETURN NEW;
END $$;
CREATE TRIGGER shop_tenant_registry AFTER INSERT OR UPDATE ON secureshop_auth.tenants
  FOR EACH ROW EXECUTE FUNCTION secureshop_auth.sync_store_execution_authority();
CREATE TRIGGER shop_member_registry AFTER INSERT OR UPDATE ON secureshop_auth.tenant_memberships
  FOR EACH ROW EXECUTE FUNCTION secureshop_auth.sync_store_execution_authority();
CREATE TRIGGER shop_execution_registry AFTER INSERT OR UPDATE ON secureshop_auth.execution_sessions
  FOR EACH ROW EXECUTE FUNCTION secureshop_auth.sync_store_execution_authority();
CREATE TRIGGER shop_principal_execution_registry AFTER UPDATE ON secureshop_auth.principals
  FOR EACH ROW EXECUTE FUNCTION secureshop_auth.sync_store_execution_authority();
CREATE TRIGGER shop_auth_execution_registry AFTER UPDATE ON secureshop_auth.sessions
  FOR EACH ROW EXECUTE FUNCTION secureshop_auth.sync_store_execution_authority();

-- Enrollment never rebinds existing launches, private scenes or evidence.
-- The public shop is explicit; existing principal-owned histories stay separate.
INSERT INTO secureshop_auth.tenants(tenant_id,slug)
  VALUES('5ec0e500-0000-4000-8000-000000000001','default');
INSERT INTO secureshop_auth.tenant_memberships(tenant_id,principal_id,shop_user_id,role)
  SELECT '5ec0e500-0000-4000-8000-000000000001',principal_id,shop_user_id,role
  FROM secureshop_auth.principals;
UPDATE secureshop_auth.tenants t SET seed_merchant_id=p.shop_user_id
  FROM secureshop_auth.principals p WHERE t.slug='default' AND t.seed_merchant_id IS NULL
    AND p.username='student_merchant' AND p.role='merchant' AND p.is_active;

REVOKE ALL ON secureshop_auth.tenants,secureshop_auth.tenant_memberships,
  secureshop_auth.execution_sessions,secureshop_auth.execution_authority_state FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON secureshop_auth.tenants,secureshop_auth.tenant_memberships,
  secureshop_auth.execution_sessions TO dvaia_identity_runtime;
GRANT SELECT ON secureshop_auth.execution_authority_state TO dvaia_identity_runtime;
REVOKE ALL ON FUNCTION secureshop_auth.guard_store_identity(),secureshop_auth.sync_store_execution_authority() FROM PUBLIC;
