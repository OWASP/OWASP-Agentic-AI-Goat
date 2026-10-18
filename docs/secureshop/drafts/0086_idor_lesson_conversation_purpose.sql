-- NEVER APPLIED DRAFT. Promote only after the owned V10/V12 repository draft,
-- native grants, and integrated graph qualification are reviewed. The current
-- agents tip is 0085; this forward successor adds one launch-bound lesson
-- purpose while preserving every purpose admitted by 0058.
ALTER TABLE secureshop_agents.agent_sessions
  DROP CONSTRAINT agent_sessions_conversation_purpose_shape;
ALTER TABLE secureshop_agents.agent_sessions
  ADD CONSTRAINT agent_sessions_conversation_purpose_shape CHECK (
    conversation_purpose IN (
      'general','mcp_rogue_registration','mcp_rug_pull','persona_inbox',
      'controlled_ssrf','review_moderation','secureshop_refund_request',
      'secureshop_product_assist','secureshop_product_manual_ingest',
      'secureshop_audit_summary','secureshop_audit_sql','secureshop_analytics',
      'secureshop_price_advisor','secureshop_pricing_strategy',
      'secureshop_listing_rewrite','secureshop_listing_import',
      'secureshop_listing_template','secureshop_mail_reply','secureshop_inventory',
      'secureshop_customer_chat','secureshop_merchant_assistant',
      'secureshop_admin_assistant','secureshop_idor_lesson'
    )
    AND (authority_mode='launch_bound' OR conversation_purpose='general')
  );
