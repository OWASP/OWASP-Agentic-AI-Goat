-- Bound account session inventory. Metadata is captured by the server at
-- login and remains immutable; last_seen_at may advance monotonically while
-- the session is active. The complete launch tuple and persona remain the
-- authority for listing and revocation.
DROP TRIGGER bound_persona_session_guard
  ON secureshop_agents.bound_persona_sessions;

ALTER TABLE secureshop_agents.bound_persona_sessions
  ADD COLUMN ip text,
  ADD COLUMN user_agent text,
  ADD COLUMN last_seen_at timestamptz;

UPDATE secureshop_agents.bound_persona_sessions
SET last_seen_at=created_at;

ALTER TABLE secureshop_agents.bound_persona_sessions
  ALTER COLUMN last_seen_at SET DEFAULT clock_timestamp(),
  ALTER COLUMN last_seen_at SET NOT NULL,
  ADD CONSTRAINT bound_persona_session_ip_bytes
    CHECK (ip IS NULL OR octet_length(ip)<=128),
  ADD CONSTRAINT bound_persona_session_user_agent_bytes
    CHECK (user_agent IS NULL OR octet_length(user_agent)<=1024),
  ADD CONSTRAINT bound_persona_session_last_seen_order
    CHECK (last_seen_at>=created_at);

CREATE INDEX bound_persona_sessions_persona_inventory
  ON secureshop_agents.bound_persona_sessions
  (platform_launch_id,platform_scenario_id,platform_launch_generation,
   original_platform_owner_id,original_platform_session_id,shop_user_id,
   revoked_at,last_seen_at DESC);

CREATE OR REPLACE FUNCTION secureshop_agents.guard_bound_persona_session()
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
      NEW.full_name,NEW.phone,NEW.created_at,NEW.ip,NEW.user_agent)
    IS DISTINCT FROM
    ROW(OLD.session_id,OLD.jti_sha256,OLD.platform_launch_id,OLD.platform_scenario_id,
      OLD.platform_launch_generation,OLD.original_platform_owner_id,
      OLD.original_platform_session_id,OLD.shop_user_id,OLD.username,OLD.role,OLD.email,
      OLD.full_name,OLD.phone,OLD.created_at,OLD.ip,OLD.user_agent)
    OR OLD.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'Bound persona session identity is immutable' USING ERRCODE='55000';
  END IF;
  IF NEW.revoked_at IS NOT NULL THEN
    IF NEW.expires_at IS DISTINCT FROM OLD.expires_at
        OR NEW.last_seen_at IS DISTINCT FROM OLD.last_seen_at THEN
      RAISE EXCEPTION 'Bound persona revocation cannot alter session time' USING ERRCODE='55000';
    END IF;
    NEW.revoked_at := clock_timestamp();
    RETURN NEW;
  END IF;
  IF NEW.expires_at<OLD.expires_at OR NEW.last_seen_at<OLD.last_seen_at THEN
    RAISE EXCEPTION 'Bound persona session time cannot decrease' USING ERRCODE='55000';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'secureshop-conversation-admission:' || NEW.platform_launch_id::text,0));
  IF EXISTS (SELECT 1 FROM secureshop_agents.conversation_generation_retirements
    WHERE platform_launch_id=NEW.platform_launch_id
      AND from_generation=NEW.platform_launch_generation) THEN
    RAISE EXCEPTION 'Bound persona generation is retired' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER bound_persona_session_guard
BEFORE INSERT OR UPDATE OR DELETE ON secureshop_agents.bound_persona_sessions
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_persona_session();
