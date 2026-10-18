-- Compatibility ledger entry for retained candidate fixtures.
-- The reviewed state schema was promoted unchanged as secureshop_agents migration 0023.
DO $$
BEGIN
 IF to_regclass('secureshop_agents.bound_persona_state') IS NULL
   OR to_regclass('secureshop_agents.bound_persona_admin_operations') IS NULL
   OR to_regclass('secureshop_agents.bound_persona_admin_cleanup_receipts') IS NULL
   OR to_regprocedure('secureshop_agents.revoke_admin_target_api_keys(uuid,uuid,bigint,integer,integer,integer,uuid,integer)') IS NULL
   OR to_regprocedure('secureshop_agents.cleanup_bound_persona_admin()') IS NULL THEN
   RAISE EXCEPTION 'Promoted persona authority state schema is unavailable';
 END IF;
END $$;
