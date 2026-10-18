-- Launch-local password overlays keep the immutable three-persona catalog as
-- the source of identity while allowing an authenticated learner to change a
-- password for one exact launch tuple. Credential versions fence sessions
-- created before a password change.
CREATE TABLE secureshop_agents.bound_persona_credentials (
  platform_launch_id uuid NOT NULL,
  platform_scenario_id uuid NOT NULL,
  platform_launch_generation bigint NOT NULL
    CHECK (platform_launch_generation BETWEEN 1 AND 9007199254740991),
  original_platform_owner_id integer NOT NULL CHECK (original_platform_owner_id>=1),
  original_platform_session_id integer NOT NULL CHECK (original_platform_session_id>=1),
  shop_user_id integer NOT NULL REFERENCES secureshop_agents.bound_persona_templates(shop_user_id),
  password_hash text NOT NULL CHECK (
    octet_length(password_hash) BETWEEN 50 AND 128
    AND password_hash ~ '^\$2[aby]\$[0-9][0-9]\$'),
  credential_version bigint NOT NULL DEFAULT 2 CHECK (credential_version>=2),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(platform_launch_id,platform_scenario_id,platform_launch_generation,
    original_platform_owner_id,original_platform_session_id,shop_user_id)
);

ALTER TABLE secureshop_agents.bound_persona_sessions
  ADD COLUMN credential_version bigint NOT NULL DEFAULT 1
    CHECK (credential_version>=1);

CREATE FUNCTION secureshop_agents.guard_bound_persona_session_credential_version()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.credential_version<OLD.credential_version
      OR NEW.credential_version>OLD.credential_version+1
      OR (NEW.revoked_at IS NOT NULL
        AND NEW.credential_version IS DISTINCT FROM OLD.credential_version) THEN
    RAISE EXCEPTION 'Bound persona session credential version transition is invalid'
      USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER bound_persona_session_credential_version_guard
BEFORE UPDATE ON secureshop_agents.bound_persona_sessions
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_persona_session_credential_version();

CREATE INDEX bound_persona_credentials_scope
  ON secureshop_agents.bound_persona_credentials
  (platform_launch_id,platform_launch_generation,shop_user_id);

CREATE TABLE secureshop_agents.bound_persona_credential_cleanup_receipts (
  platform_launch_id uuid NOT NULL,
  platform_scenario_id uuid NOT NULL,
  platform_launch_generation bigint NOT NULL,
  original_platform_owner_id integer NOT NULL,
  original_platform_session_id integer NOT NULL,
  deleted_credential_count integer NOT NULL CHECK (deleted_credential_count>=0),
  receipt_sha256 bytea NOT NULL CHECK (octet_length(receipt_sha256)=32),
  completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(platform_launch_id,platform_scenario_id,platform_launch_generation,
    original_platform_owner_id,original_platform_session_id)
);

CREATE FUNCTION secureshop_agents.guard_bound_persona_credentials()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,secureshop_agents AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    RETURN OLD;
  END IF;
  IF TG_OP='UPDATE' AND ROW(NEW.platform_launch_id,NEW.platform_scenario_id,
      NEW.platform_launch_generation,NEW.original_platform_owner_id,
      NEW.original_platform_session_id,NEW.shop_user_id)
    IS DISTINCT FROM ROW(OLD.platform_launch_id,OLD.platform_scenario_id,
      OLD.platform_launch_generation,OLD.original_platform_owner_id,
      OLD.original_platform_session_id,OLD.shop_user_id) THEN
    RAISE EXCEPTION 'Bound persona credential identity is immutable' USING ERRCODE='55000';
  END IF;
  IF TG_OP='UPDATE' AND NEW.credential_version<>OLD.credential_version+1 THEN
    RAISE EXCEPTION 'Bound persona credential version must advance once' USING ERRCODE='55000';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'secureshop-conversation-admission:' || NEW.platform_launch_id::text,0));
  IF EXISTS (SELECT 1 FROM secureshop_agents.conversation_generation_retirements
    WHERE platform_launch_id=NEW.platform_launch_id
      AND platform_scenario_id=NEW.platform_scenario_id
      AND from_generation=NEW.platform_launch_generation
      AND original_platform_owner_id=NEW.original_platform_owner_id
      AND original_platform_session_id=NEW.original_platform_session_id) THEN
    RAISE EXCEPTION 'Bound persona generation is retired' USING ERRCODE='55000';
  END IF;
  NEW.updated_at:=clock_timestamp();
  RETURN NEW;
END $$;

CREATE TRIGGER bound_persona_credentials_guard
BEFORE INSERT OR UPDATE OR DELETE ON secureshop_agents.bound_persona_credentials
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_persona_credentials();

CREATE FUNCTION secureshop_agents.retire_bound_persona_credentials()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE removed integer;
DECLARE receipt_digest bytea;
BEGIN
  DELETE FROM secureshop_agents.bound_persona_credentials
    WHERE platform_launch_id=NEW.platform_launch_id
      AND platform_scenario_id=NEW.platform_scenario_id
      AND platform_launch_generation=NEW.from_generation
      AND original_platform_owner_id=NEW.original_platform_owner_id
      AND original_platform_session_id=NEW.original_platform_session_id;
  GET DIAGNOSTICS removed=ROW_COUNT;
  receipt_digest:=sha256(convert_to(concat_ws(':',NEW.platform_launch_id::text,
    NEW.platform_scenario_id::text,NEW.from_generation::text,
    NEW.original_platform_owner_id::text,NEW.original_platform_session_id::text,
    removed::text),'UTF8'));
  INSERT INTO secureshop_agents.bound_persona_credential_cleanup_receipts
    (platform_launch_id,platform_scenario_id,platform_launch_generation,
     original_platform_owner_id,original_platform_session_id,
     deleted_credential_count,receipt_sha256)
  VALUES(NEW.platform_launch_id,NEW.platform_scenario_id,NEW.from_generation,
    NEW.original_platform_owner_id,NEW.original_platform_session_id,removed,receipt_digest);
  RETURN NEW;
END $$;

CREATE TRIGGER retire_bound_persona_credentials
AFTER INSERT ON secureshop_agents.conversation_generation_retirements
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.retire_bound_persona_credentials();

-- Retirements committed before this migration have no credential table to
-- clean. Backfill a deterministic zero-count receipt so reset reconciliation
-- remains total across the schema upgrade boundary.
INSERT INTO secureshop_agents.bound_persona_credential_cleanup_receipts
  (platform_launch_id,platform_scenario_id,platform_launch_generation,
   original_platform_owner_id,original_platform_session_id,
   deleted_credential_count,receipt_sha256,completed_at)
SELECT r.platform_launch_id,r.platform_scenario_id,r.from_generation,
  r.original_platform_owner_id,r.original_platform_session_id,0,
  sha256(convert_to(concat_ws(':',r.platform_launch_id::text,
    r.platform_scenario_id::text,r.from_generation::text,
    r.original_platform_owner_id::text,r.original_platform_session_id::text,'0'),'UTF8')),
  COALESCE(r.completed_at,r.created_at)
FROM secureshop_agents.conversation_generation_retirements r;

CREATE FUNCTION secureshop_agents.guard_bound_persona_credential_receipt()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'Bound persona credential cleanup receipt is immutable' USING ERRCODE='55000';
END $$;

CREATE TRIGGER bound_persona_credential_receipt_guard
BEFORE UPDATE OR DELETE ON secureshop_agents.bound_persona_credential_cleanup_receipts
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_persona_credential_receipt();

REVOKE ALL ON TABLE secureshop_agents.bound_persona_credentials,
  secureshop_agents.bound_persona_credential_cleanup_receipts FROM PUBLIC;
REVOKE ALL ON FUNCTION secureshop_agents.guard_bound_persona_credentials(),
  secureshop_agents.retire_bound_persona_credentials(),
  secureshop_agents.guard_bound_persona_session_credential_version(),
  secureshop_agents.guard_bound_persona_credential_receipt() FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON secureshop_agents.bound_persona_credentials
  TO dvaia_secureshop_agents_runtime;
GRANT SELECT ON secureshop_agents.bound_persona_credential_cleanup_receipts
  TO dvaia_secureshop_agents_runtime;
