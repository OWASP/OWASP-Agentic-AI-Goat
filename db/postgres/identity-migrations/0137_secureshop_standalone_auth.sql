-- Standalone SecureShop authority. These identifiers consume the platform
-- sequences for global uniqueness without creating a platform user or session.
-- Challenge-store roles receive no access to this schema.
CREATE SCHEMA secureshop_auth;
REVOKE ALL ON SCHEMA secureshop_auth FROM PUBLIC;

CREATE SEQUENCE secureshop_auth.shop_user_id_seq AS integer
  START WITH 1000000000 MINVALUE 1000000000 MAXVALUE 2147483647 NO CYCLE;

CREATE TABLE secureshop_auth.principals (
  principal_id uuid PRIMARY KEY,
  owner_id integer NOT NULL UNIQUE
    DEFAULT nextval(pg_get_serial_sequence('identity.users','id')::regclass),
  shop_user_id integer NOT NULL UNIQUE
    DEFAULT nextval('secureshop_auth.shop_user_id_seq'::regclass),
  username text NOT NULL UNIQUE
    CHECK (username ~ '^[a-z][a-z0-9_]{2,31}$'),
  email text NOT NULL UNIQUE
    CHECK (octet_length(email) BETWEEN 3 AND 320
      AND email = lower(email) AND email ~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$'),
  password_hash text NOT NULL
    CHECK (password_hash ~ '^\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}$'),
  role text NOT NULL CHECK (role IN ('customer','merchant','admin')),
  credential_version bigint NOT NULL DEFAULT 1 CHECK (credential_version > 0),
  authority_version bigint NOT NULL DEFAULT 1 CHECK (authority_version > 0),
  is_active boolean NOT NULL DEFAULT true,
  locked_until timestamptz,
  failed_login_count integer NOT NULL DEFAULT 0 CHECK (failed_login_count BETWEEN 0 AND 1000000),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE FUNCTION secureshop_auth.guard_principal() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,secureshop_auth AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'Shop principal deletion requires its owned lifecycle' USING ERRCODE='55000';
  END IF;
  IF TG_OP='UPDATE' THEN
    IF (NEW.principal_id,NEW.owner_id,NEW.shop_user_id,NEW.username,NEW.email,NEW.role,NEW.created_at)
       IS DISTINCT FROM
       (OLD.principal_id,OLD.owner_id,OLD.shop_user_id,OLD.username,OLD.email,OLD.role,OLD.created_at)
       OR NEW.credential_version < OLD.credential_version
       OR NEW.authority_version < OLD.authority_version
       OR (NEW.password_hash IS DISTINCT FROM OLD.password_hash
           AND NEW.credential_version <= OLD.credential_version) THEN
      RAISE EXCEPTION 'Shop principal identity is immutable' USING ERRCODE='55000';
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER secureshop_auth_principal_guard BEFORE UPDATE OR DELETE
  ON secureshop_auth.principals FOR EACH ROW EXECUTE FUNCTION secureshop_auth.guard_principal();

CREATE TABLE secureshop_auth.sessions (
  session_id integer PRIMARY KEY
    DEFAULT nextval(pg_get_serial_sequence('identity.user_sessions','id')::regclass),
  principal_id uuid NOT NULL REFERENCES secureshop_auth.principals(principal_id) ON DELETE RESTRICT,
  token_hash text NOT NULL UNIQUE CHECK (token_hash ~ '^[a-f0-9]{64}$'),
  credential_version bigint NOT NULL CHECK (credential_version > 0),
  authority_version bigint NOT NULL CHECK (authority_version > 0),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (expires_at > created_at)
);
CREATE INDEX secureshop_auth_session_principal
  ON secureshop_auth.sessions(principal_id,created_at DESC);
CREATE INDEX secureshop_auth_session_expiry
  ON secureshop_auth.sessions(expires_at) WHERE revoked_at IS NULL;

CREATE FUNCTION secureshop_auth.guard_session() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,secureshop_auth AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'Shop session deletion requires its owned lifecycle' USING ERRCODE='55000';
  END IF;
  IF TG_OP='UPDATE' THEN
    IF (NEW.session_id,NEW.principal_id,NEW.credential_version,NEW.authority_version,NEW.created_at)
       IS DISTINCT FROM
       (OLD.session_id,OLD.principal_id,OLD.credential_version,OLD.authority_version,OLD.created_at)
       OR (OLD.revoked_at IS NOT NULL AND NEW IS DISTINCT FROM OLD)
       OR (OLD.revoked_at IS NULL AND NEW.revoked_at IS NOT NULL
           AND (NEW.token_hash,NEW.expires_at) IS DISTINCT FROM (OLD.token_hash,OLD.expires_at)) THEN
      RAISE EXCEPTION 'Shop session identity is immutable' USING ERRCODE='55000';
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER secureshop_auth_session_guard BEFORE UPDATE OR DELETE
  ON secureshop_auth.sessions FOR EACH ROW EXECUTE FUNCTION secureshop_auth.guard_session();

-- A completed initial seed is durable. Reseeding must never recreate a
-- deliberately removed practice account or reset instructor-owned credentials.
CREATE TABLE secureshop_auth.default_seed_state (
  seed_key text PRIMARY KEY CHECK (seed_key = 'fresh-install-v1'),
  defaults_sha256 text NOT NULL CHECK (defaults_sha256 ~ '^[a-f0-9]{64}$'),
  completed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION secureshop_auth.guard_default_seed_state() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,secureshop_auth AS $$
BEGIN
  RAISE EXCEPTION 'Shop default seed receipt is immutable' USING ERRCODE='55000';
END $$;
CREATE TRIGGER secureshop_auth_default_seed_guard BEFORE UPDATE OR DELETE
  ON secureshop_auth.default_seed_state FOR EACH ROW
  EXECUTE FUNCTION secureshop_auth.guard_default_seed_state();

REVOKE ALL ON secureshop_auth.principals,secureshop_auth.sessions,
  secureshop_auth.default_seed_state FROM PUBLIC;
REVOKE ALL ON SEQUENCE secureshop_auth.shop_user_id_seq FROM PUBLIC;
REVOKE ALL ON FUNCTION secureshop_auth.guard_principal(),secureshop_auth.guard_session(),
  secureshop_auth.guard_default_seed_state() FROM PUBLIC;
GRANT USAGE ON SCHEMA secureshop_auth TO dvaia_identity_runtime;
GRANT SELECT,INSERT,UPDATE ON secureshop_auth.principals,secureshop_auth.sessions TO dvaia_identity_runtime;
GRANT SELECT,INSERT ON secureshop_auth.default_seed_state TO dvaia_identity_runtime;
GRANT USAGE,SELECT ON SEQUENCE secureshop_auth.shop_user_id_seq TO dvaia_identity_runtime;
