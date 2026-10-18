-- DRAFT ONLY. Launch-bound shop authentication state belongs in the isolated
-- agents store. Immutable credential templates prevent legacy commerce role,
-- ban, or password mutations from changing another learner's admitted bound
-- persona. Do not promote until aggregate generation retirement and the
-- bound gateway are qualified together.
CREATE TABLE secureshop_agents.bound_persona_template_catalog (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  version smallint NOT NULL CHECK (version=1),
  template_count smallint NOT NULL CHECK (template_count=3),
  template_sha256 bytea NOT NULL CHECK (octet_length(template_sha256)=32),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE secureshop_agents.bound_persona_templates (
  username text PRIMARY KEY,
  shop_user_id integer NOT NULL UNIQUE CHECK (shop_user_id>=1),
  email text NOT NULL,
  password_hash text NOT NULL CHECK (octet_length(password_hash) BETWEEN 50 AND 128),
  role text NOT NULL CHECK (role IN ('customer','merchant','admin')),
  full_name text,
  phone text,
  source_sha256 bytea NOT NULL CHECK (octet_length(source_sha256)=32),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(shop_user_id,role,username)
);

CREATE TABLE secureshop_agents.bound_persona_sessions (
  session_id uuid PRIMARY KEY,
  jti_sha256 bytea NOT NULL UNIQUE CHECK (octet_length(jti_sha256)=32),
  platform_launch_id uuid NOT NULL,
  platform_scenario_id uuid NOT NULL,
  platform_launch_generation bigint NOT NULL
    CHECK (platform_launch_generation BETWEEN 1 AND 9007199254740991),
  original_platform_owner_id integer NOT NULL CHECK (original_platform_owner_id>=1),
  original_platform_session_id integer NOT NULL CHECK (original_platform_session_id>=1),
  shop_user_id integer NOT NULL CHECK (shop_user_id>=1),
  username text NOT NULL,
  role text NOT NULL CHECK (role IN ('customer','merchant','admin')),
  email text NOT NULL,
  full_name text,
  phone text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  CHECK (expires_at>created_at),
  CHECK (revoked_at IS NULL OR revoked_at>=created_at),
  FOREIGN KEY(shop_user_id,role,username)
    REFERENCES secureshop_agents.bound_persona_templates(shop_user_id,role,username)
);

CREATE INDEX bound_persona_sessions_scope
  ON secureshop_agents.bound_persona_sessions
  (platform_launch_id,platform_launch_generation,revoked_at,expires_at);

CREATE FUNCTION secureshop_agents.guard_bound_persona_session()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,secureshop_agents AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'Bound persona session history cannot be deleted' USING ERRCODE='55000';
  END IF;
  IF TG_OP='INSERT' THEN
    IF NEW.revoked_at IS NOT NULL THEN
      RAISE EXCEPTION 'Bound persona session must begin active' USING ERRCODE='55000';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(
      'secureshop-conversation-admission:' || NEW.platform_launch_id::text,0));
    IF EXISTS (SELECT 1 FROM secureshop_agents.conversation_generation_retirements
      WHERE platform_launch_id=NEW.platform_launch_id
        AND from_generation=NEW.platform_launch_generation) THEN
      RAISE EXCEPTION 'Bound persona generation is retired' USING ERRCODE='55000';
    END IF;
    RETURN NEW;
  END IF;
  IF ROW(NEW.session_id,NEW.jti_sha256,NEW.platform_launch_id,NEW.platform_scenario_id,
      NEW.platform_launch_generation,NEW.original_platform_owner_id,
      NEW.original_platform_session_id,NEW.shop_user_id,NEW.username,NEW.role,NEW.email,
      NEW.full_name,NEW.phone,NEW.created_at,NEW.expires_at)
    IS DISTINCT FROM
    ROW(OLD.session_id,OLD.jti_sha256,OLD.platform_launch_id,OLD.platform_scenario_id,
      OLD.platform_launch_generation,OLD.original_platform_owner_id,
      OLD.original_platform_session_id,OLD.shop_user_id,OLD.username,OLD.role,OLD.email,
      OLD.full_name,OLD.phone,OLD.created_at,OLD.expires_at)
    OR OLD.revoked_at IS NOT NULL OR NEW.revoked_at IS NULL THEN
    RAISE EXCEPTION 'Bound persona session identity is immutable' USING ERRCODE='55000';
  END IF;
  NEW.revoked_at := clock_timestamp();
  RETURN NEW;
END $$;

CREATE TRIGGER bound_persona_session_guard
BEFORE INSERT OR UPDATE OR DELETE ON secureshop_agents.bound_persona_sessions
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_persona_session();

CREATE FUNCTION secureshop_agents.retire_bound_persona_sessions()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,secureshop_agents AS $$
BEGIN
  UPDATE secureshop_agents.bound_persona_sessions SET revoked_at=clock_timestamp()
    WHERE platform_launch_id=NEW.platform_launch_id
      AND platform_scenario_id=NEW.platform_scenario_id
      AND platform_launch_generation=NEW.from_generation
      AND original_platform_owner_id=NEW.original_platform_owner_id
      AND original_platform_session_id=NEW.original_platform_session_id
      AND revoked_at IS NULL;
  RETURN NEW;
END $$;

CREATE TRIGGER retire_bound_persona_sessions
AFTER INSERT ON secureshop_agents.conversation_generation_retirements
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.retire_bound_persona_sessions();

CREATE FUNCTION secureshop_agents.guard_bound_persona_templates()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'Bound persona templates are immutable' USING ERRCODE='55000';
END $$;
CREATE TRIGGER bound_persona_template_guard
BEFORE UPDATE OR DELETE ON secureshop_agents.bound_persona_templates
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_persona_templates();
CREATE TRIGGER bound_persona_template_catalog_guard
BEFORE UPDATE OR DELETE ON secureshop_agents.bound_persona_template_catalog
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_persona_templates();

REVOKE ALL ON TABLE secureshop_agents.bound_persona_sessions FROM PUBLIC;
REVOKE ALL ON TABLE secureshop_agents.bound_persona_templates,
  secureshop_agents.bound_persona_template_catalog FROM PUBLIC;
REVOKE ALL ON FUNCTION secureshop_agents.guard_bound_persona_session() FROM PUBLIC;
REVOKE ALL ON FUNCTION secureshop_agents.retire_bound_persona_sessions() FROM PUBLIC;
REVOKE ALL ON FUNCTION secureshop_agents.guard_bound_persona_templates() FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON secureshop_agents.bound_persona_sessions
  TO dvaia_secureshop_agents_runtime;
GRANT SELECT,INSERT ON secureshop_agents.bound_persona_templates,
  secureshop_agents.bound_persona_template_catalog TO dvaia_secureshop_agents_runtime;
GRANT EXECUTE ON FUNCTION secureshop_agents.guard_bound_persona_templates()
  TO dvaia_secureshop_agents_runtime;
