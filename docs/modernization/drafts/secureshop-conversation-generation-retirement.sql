-- DRAFT: not auto-applied. Durable lifecycle retirement for one immutable
-- launch generation. Promote only after native qualification with the bound
-- conversation and turn-admission migrations.
CREATE TABLE secureshop_agents.conversation_generation_retirements (
  reset_id uuid PRIMARY KEY,
  platform_launch_id uuid NOT NULL,
  platform_scenario_id uuid NOT NULL,
  from_generation bigint NOT NULL CHECK (from_generation BETWEEN 1 AND 9007199254740991),
  original_platform_owner_id integer NOT NULL CHECK (original_platform_owner_id >= 1),
  original_platform_session_id integer NOT NULL CHECK (original_platform_session_id >= 1),
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','completed')),
  session_count integer,
  uncertain_turn_count integer,
  session_set_sha256 bytea,
  receipt_sha256 bytea,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  completed_at timestamptz,
  UNIQUE(platform_launch_id,from_generation),
  CHECK (
    (status='pending' AND session_count IS NULL AND uncertain_turn_count IS NULL
      AND session_set_sha256 IS NULL AND receipt_sha256 IS NULL AND completed_at IS NULL)
    OR
    (status='completed' AND session_count IS NOT NULL AND session_count >= 0
      AND uncertain_turn_count IS NOT NULL AND uncertain_turn_count >= 0
      AND session_set_sha256 IS NOT NULL AND octet_length(session_set_sha256)=32
      AND receipt_sha256 IS NOT NULL AND octet_length(receipt_sha256)=32
      AND completed_at IS NOT NULL)
  )
);

CREATE FUNCTION secureshop_agents.guard_conversation_generation_retirement()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' THEN
    RAISE EXCEPTION 'Conversation generation retirement history cannot be deleted';
  END IF;
  IF TG_OP='INSERT' THEN
    IF NEW.status <> 'pending' THEN
      RAISE EXCEPTION 'Conversation generation retirement must begin pending';
    END IF;
    RETURN NEW;
  END IF;
  IF ROW(NEW.reset_id,NEW.platform_launch_id,NEW.platform_scenario_id,NEW.from_generation,
      NEW.original_platform_owner_id,NEW.original_platform_session_id,NEW.created_at)
    IS DISTINCT FROM ROW(OLD.reset_id,OLD.platform_launch_id,OLD.platform_scenario_id,OLD.from_generation,
      OLD.original_platform_owner_id,OLD.original_platform_session_id,OLD.created_at)
    OR OLD.status <> 'pending' OR NEW.status <> 'completed' THEN
    RAISE EXCEPTION 'Conversation generation retirement identity and completion are immutable';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER conversation_generation_retirement_guard
BEFORE INSERT OR UPDATE OR DELETE ON secureshop_agents.conversation_generation_retirements
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_conversation_generation_retirement();

CREATE INDEX conversation_generation_retirements_scope
  ON secureshop_agents.conversation_generation_retirements
  (platform_launch_id,from_generation,status);

-- Every launch-bound insert and every update that would leave a conversation
-- usable takes the same launch admission lock as beginRetirement(). This also
-- fences recovery helpers that bypass acquireBoundSession().
CREATE FUNCTION secureshop_agents.guard_retired_conversation_admission()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.authority_mode <> 'launch_bound' OR NEW.binding_state NOT IN ('pending','active') THEN
    RETURN NEW;
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'secureshop-conversation-admission:' || NEW.platform_launch_id::text, 0));
  PERFORM 1 FROM secureshop_agents.conversation_generation_retirements
    WHERE platform_launch_id=NEW.platform_launch_id
      AND from_generation=NEW.platform_launch_generation;
  IF FOUND THEN
    RAISE EXCEPTION 'Conversation generation is retired' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER retired_conversation_admission_guard
BEFORE INSERT OR UPDATE ON secureshop_agents.agent_sessions
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_retired_conversation_admission();

REVOKE ALL ON FUNCTION secureshop_agents.guard_conversation_generation_retirement() FROM PUBLIC;
REVOKE ALL ON FUNCTION secureshop_agents.guard_retired_conversation_admission() FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON secureshop_agents.conversation_generation_retirements
  TO dvaia_secureshop_agents_runtime;
