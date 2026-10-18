-- Additive SecureShop agent conversation authority binding.
-- Preserve legacy rows while enabling explicit launch-bound conversations.
-- The identity launch database and secureshop_agents database are separate;
-- these copied coordinates are an immutable audit/lookup binding, not proof of
-- current launch authority. The application must resolve and reassert the
-- trusted launch before creating, activating, or using a bound conversation.

ALTER TABLE secureshop_agents.agent_sessions
  ADD COLUMN authority_mode text NOT NULL DEFAULT 'legacy',
  ADD COLUMN binding_state text NOT NULL DEFAULT 'active',
  ADD COLUMN platform_launch_id uuid,
  ADD COLUMN platform_scenario_id uuid,
  ADD COLUMN platform_launch_generation bigint,
  ADD COLUMN original_platform_owner_id integer,
  ADD COLUMN original_platform_session_id integer;

ALTER TABLE secureshop_agents.agent_sessions
  ADD CONSTRAINT agent_sessions_authority_binding_shape CHECK (
    (
      authority_mode = 'legacy'
      AND binding_state = 'active'
      AND platform_launch_id IS NULL
      AND platform_scenario_id IS NULL
      AND platform_launch_generation IS NULL
      AND original_platform_owner_id IS NULL
      AND original_platform_session_id IS NULL
    )
    OR
    (
      authority_mode = 'launch_bound'
      AND binding_state IN ('pending', 'active', 'abandoned')
      AND id ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
      AND user_id >= 1
      AND role IN ('customer', 'merchant', 'admin')
      AND platform_launch_id IS NOT NULL
      AND platform_scenario_id IS NOT NULL
      AND platform_launch_generation IS NOT NULL
      AND platform_launch_generation BETWEEN 1 AND 9007199254740991
      AND original_platform_owner_id IS NOT NULL
      AND original_platform_owner_id >= 1
      AND original_platform_session_id IS NOT NULL
      AND original_platform_session_id >= 1
      AND token_budget_used >= 0
      AND (binding_state <> 'pending'
        OR (messages_json = '[]' AND token_budget_used = 0))
    )
  );

CREATE FUNCTION secureshop_agents.guard_agent_session_authority_binding()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'INSERT' THEN
    IF NEW.authority_mode = 'launch_bound' AND NEW.binding_state <> 'pending' THEN
      RAISE EXCEPTION 'Launch-bound conversation must begin pending' USING ERRCODE = '55000';
    END IF;
    RETURN NEW;
  END IF;

  IF TG_OP = 'DELETE' THEN
    IF OLD.authority_mode = 'launch_bound' THEN
      RAISE EXCEPTION 'Launch-bound conversation history is retained' USING ERRCODE = '55000';
    END IF;
    RETURN OLD;
  END IF;

  IF NEW.id IS DISTINCT FROM OLD.id
     OR NEW.authority_mode IS DISTINCT FROM OLD.authority_mode THEN
    RAISE EXCEPTION 'Conversation authority identity is immutable' USING ERRCODE = '55000';
  END IF;

  -- Legacy sessions retain their existing update behavior. Their shape check
  -- keeps all launch coordinates null and their state active.
  IF OLD.authority_mode = 'legacy' THEN
    RETURN NEW;
  END IF;

  IF NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'Launch-bound conversation creation time is immutable' USING ERRCODE = '55000';
  END IF;

  IF NEW.user_id IS DISTINCT FROM OLD.user_id
     OR NEW.role IS DISTINCT FROM OLD.role
     OR NEW.platform_launch_id IS DISTINCT FROM OLD.platform_launch_id
     OR NEW.platform_scenario_id IS DISTINCT FROM OLD.platform_scenario_id
     OR NEW.platform_launch_generation IS DISTINCT FROM OLD.platform_launch_generation
     OR NEW.original_platform_owner_id IS DISTINCT FROM OLD.original_platform_owner_id
     OR NEW.original_platform_session_id IS DISTINCT FROM OLD.original_platform_session_id THEN
    RAISE EXCEPTION 'Launch-bound conversation coordinates are immutable' USING ERRCODE = '55000';
  END IF;

  IF NEW.binding_state IS DISTINCT FROM OLD.binding_state
     AND NOT (
       (OLD.binding_state = 'pending' AND NEW.binding_state IN ('active', 'abandoned'))
       OR (OLD.binding_state = 'active' AND NEW.binding_state = 'abandoned')
     ) THEN
    RAISE EXCEPTION 'Launch-bound conversation state transition is invalid' USING ERRCODE = '55000';
  END IF;

  IF (NEW.messages_json IS DISTINCT FROM OLD.messages_json
      OR NEW.token_budget_used IS DISTINCT FROM OLD.token_budget_used)
     AND (OLD.binding_state <> 'active' OR NEW.binding_state <> 'active') THEN
    RAISE EXCEPTION 'Inactive launch-bound conversation content is immutable' USING ERRCODE = '55000';
  END IF;

  RETURN NEW;
END $$;

CREATE TRIGGER agent_session_authority_binding_guard
BEFORE INSERT OR UPDATE OR DELETE ON secureshop_agents.agent_sessions
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_agent_session_authority_binding();

CREATE INDEX agent_sessions_launch_binding
  ON secureshop_agents.agent_sessions (platform_launch_id, platform_launch_generation, binding_state)
  WHERE authority_mode = 'launch_bound';

CREATE INDEX agent_sessions_original_owner
  ON secureshop_agents.agent_sessions
    (original_platform_owner_id, original_platform_session_id, binding_state)
  WHERE authority_mode = 'launch_bound';

REVOKE ALL ON FUNCTION secureshop_agents.guard_agent_session_authority_binding() FROM PUBLIC;
