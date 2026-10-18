-- Forward-only V03 Listings image optimization conversation-purpose admission.
-- Preserve every prior purpose and launch-bound authority rule.
ALTER TABLE secureshop_agents.agent_sessions
  DROP CONSTRAINT agent_sessions_conversation_purpose_shape;

ALTER TABLE secureshop_agents.agent_sessions
  ADD CONSTRAINT agent_sessions_conversation_purpose_shape CHECK (
    conversation_purpose IN (
      'general','mcp_rogue_registration','mcp_rug_pull','persona_inbox',
      'controlled_ssrf','review_moderation','secureshop_refund_request',
      'secureshop_product_assist','secureshop_product_manual_ingest',
      'secureshop_audit_summary','secureshop_audit_unbounded',
      'secureshop_audit_sql','secureshop_audit_sql_timing','secureshop_analytics',
      'secureshop_price_advisor','secureshop_pricing_strategy',
      'secureshop_listing_rewrite','secureshop_listing_import',
      'secureshop_listing_template','secureshop_mail_reply',
      'secureshop_mail_summary','secureshop_inventory','secureshop_customer_chat',
      'secureshop_merchant_assistant','secureshop_admin_assistant',
      'secureshop_idor_lesson','secureshop_coupon_probe','secureshop_product_search_union','secureshop_order_status_error',
      'secureshop_checkout_audit_jwt','secureshop_avatar_upload','secureshop_listing_optimize'
    )
    AND (authority_mode='launch_bound' OR conversation_purpose='general')
  );

