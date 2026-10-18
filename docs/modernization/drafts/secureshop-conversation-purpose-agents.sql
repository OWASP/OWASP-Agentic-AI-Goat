-- DRAFT ONLY. Stable server-owned workflow purpose for launch-bound agent
-- conversations. This prevents independent exercises from inheriting each
-- other's tool history while preserving the existing `general` conversation
-- and its intentional cross-agent memory teaching behavior.

ALTER TABLE secureshop_agents.agent_sessions
  ADD COLUMN conversation_purpose text NOT NULL DEFAULT 'general';

ALTER TABLE secureshop_agents.agent_sessions
  ADD CONSTRAINT agent_sessions_conversation_purpose_shape CHECK (
    conversation_purpose IN (
      'general',
      'mcp_rogue_registration',
      'mcp_rug_pull',
      'persona_inbox',
      'controlled_ssrf',
      'review_moderation'
    )
    AND (authority_mode = 'launch_bound' OR conversation_purpose = 'general')
  );

-- One durable conversation per exact launch generation, shop persona and
-- server-selected workflow. Abandoned rows retain the identity and prevent a
-- workflow from silently replacing its history.
CREATE UNIQUE INDEX agent_sessions_launch_binding_purpose
  ON secureshop_agents.agent_sessions (
    platform_launch_id,
    platform_scenario_id,
    platform_launch_generation,
    original_platform_owner_id,
    original_platform_session_id,
    user_id,
    role,
    conversation_purpose
  )
  WHERE authority_mode = 'launch_bound';

CREATE FUNCTION secureshop_agents.guard_agent_session_conversation_purpose()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE'
     AND NEW.conversation_purpose IS DISTINCT FROM OLD.conversation_purpose THEN
    RAISE EXCEPTION 'Conversation purpose is immutable' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER agent_session_conversation_purpose_guard
BEFORE UPDATE ON secureshop_agents.agent_sessions
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_agent_session_conversation_purpose();

REVOKE ALL ON FUNCTION secureshop_agents.guard_agent_session_conversation_purpose() FROM PUBLIC;
