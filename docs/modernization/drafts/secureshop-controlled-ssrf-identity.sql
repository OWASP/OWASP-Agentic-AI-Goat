-- DRAFT ONLY. Unnumbered until the identity migration suffix is reserved.
-- Requires the SecureShop MCP trust target kinds if that candidate is promoted first.
ALTER TABLE identity.secureshop_target_reservations
  DROP CONSTRAINT secureshop_target_reservations_target_kind_check;
ALTER TABLE identity.secureshop_target_reservations
  ADD CONSTRAINT secureshop_target_reservations_target_kind_check
  CHECK (target_kind IN ('files','reviews','products','persona_inbox','mcp_rogue','mcp_rug_pull','controlled_ssrf'));
ALTER TABLE identity.secureshop_target_cleanup_history
  DROP CONSTRAINT secureshop_target_cleanup_history_target_kind_check;
ALTER TABLE identity.secureshop_target_cleanup_history
  ADD CONSTRAINT secureshop_target_cleanup_history_target_kind_check
  CHECK (target_kind IN ('files','reviews','products','persona_inbox','mcp_rogue','mcp_rug_pull','controlled_ssrf'));
