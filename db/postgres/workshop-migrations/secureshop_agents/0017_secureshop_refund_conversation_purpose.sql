-- Forward-only extension for the bound refund workflow. Existing purpose
-- values and the general teaching conversation remain unchanged.
ALTER TABLE secureshop_agents.agent_sessions
  DROP CONSTRAINT agent_sessions_conversation_purpose_shape;
ALTER TABLE secureshop_agents.agent_sessions
  ADD CONSTRAINT agent_sessions_conversation_purpose_shape CHECK (
    conversation_purpose IN (
      'general', 'mcp_rogue_registration', 'mcp_rug_pull', 'persona_inbox',
      'controlled_ssrf', 'review_moderation', 'secureshop_refund_request'
    )
    AND (authority_mode = 'launch_bound' OR conversation_purpose = 'general')
  );
