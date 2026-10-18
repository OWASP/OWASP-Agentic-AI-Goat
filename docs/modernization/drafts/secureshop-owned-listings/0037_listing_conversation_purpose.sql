-- DRAFT ONLY. Reserve after MCP 0035/0036; preserve all existing purposes.
ALTER TABLE secureshop_agents.agent_sessions DROP CONSTRAINT agent_sessions_conversation_purpose_shape;
ALTER TABLE secureshop_agents.agent_sessions ADD CONSTRAINT agent_sessions_conversation_purpose_shape CHECK (
 conversation_purpose IN ('general','mcp_rogue_registration','mcp_rug_pull','persona_inbox','controlled_ssrf','review_moderation','secureshop_refund_request','secureshop_product_assist','secureshop_product_manual_ingest','secureshop_audit_summary','secureshop_audit_sql','secureshop_analytics','secureshop_price_advisor','secureshop_pricing_strategy','secureshop_listing_rewrite','secureshop_listing_import')
 AND (authority_mode='launch_bound' OR conversation_purpose='general')
);

-- Task policy recipient `listing` maps to merchant in the application catalog.
-- Existing policy snapshots and instructor-edited target arrays are immutable/preserved.
-- Policy targets are JSON and require no additional SQL enum widening: new v2
-- admissions select merchant defaults plus explicitly listing-targeted policies.
