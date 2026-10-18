-- DRAFT ONLY. Forward target-kind admission for the two distinct launch-bound
-- MCP trust lessons. This follows the unregistered persona-inbox identity
-- draft and must be numbered only when the complete package is promoted.
ALTER TABLE identity.secureshop_target_reservations
  DROP CONSTRAINT secureshop_target_reservations_target_kind_check;
ALTER TABLE identity.secureshop_target_reservations
  ADD CONSTRAINT secureshop_target_reservations_target_kind_check
  CHECK (target_kind IN ('files','reviews','products','persona_inbox','mcp_rogue','mcp_rug_pull'));

ALTER TABLE identity.secureshop_target_cleanup_history
  DROP CONSTRAINT secureshop_target_cleanup_history_target_kind_check;
ALTER TABLE identity.secureshop_target_cleanup_history
  ADD CONSTRAINT secureshop_target_cleanup_history_target_kind_check
  CHECK (target_kind IN ('files','reviews','products','persona_inbox','mcp_rogue','mcp_rug_pull'));
