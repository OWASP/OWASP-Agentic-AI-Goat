-- Forward-only cardinality repair for v18 registry receipts.
-- Preserve 0076's exact legal-edge guard; admit only denial cardinalities used by its 153 published transitions.
ALTER TABLE secureshop_agents.bound_tool_registry_upgrades
 DROP CONSTRAINT bound_tool_registry_upgrades_added_denials_check,
 ADD CONSTRAINT bound_tool_registry_upgrades_added_denials_check
  CHECK(jsonb_typeof(added_denials)='array' AND jsonb_array_length(added_denials) IN (1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,38,39,45,48,54));
