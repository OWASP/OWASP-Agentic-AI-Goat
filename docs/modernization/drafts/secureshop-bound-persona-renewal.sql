-- DRAFT ONLY. Permit only monotonic expiry extension on an otherwise immutable
-- active persona session. The launch advisory lock serializes extension with
-- generation retirement; no identity or profile field becomes mutable.
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
      NEW.full_name,NEW.phone,NEW.created_at)
    IS DISTINCT FROM
    ROW(OLD.session_id,OLD.jti_sha256,OLD.platform_launch_id,OLD.platform_scenario_id,
      OLD.platform_launch_generation,OLD.original_platform_owner_id,
      OLD.original_platform_session_id,OLD.shop_user_id,OLD.username,OLD.role,OLD.email,
      OLD.full_name,OLD.phone,OLD.created_at)
    OR OLD.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'Bound persona session identity is immutable' USING ERRCODE='55000';
  END IF;
  IF NEW.revoked_at IS NOT NULL THEN
    IF NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
      RAISE EXCEPTION 'Bound persona revocation cannot alter expiry' USING ERRCODE='55000';
    END IF;
    NEW.revoked_at := clock_timestamp();
    RETURN NEW;
  END IF;
  IF NEW.expires_at <= OLD.expires_at THEN
    RAISE EXCEPTION 'Bound persona expiry must increase' USING ERRCODE='55000';
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
