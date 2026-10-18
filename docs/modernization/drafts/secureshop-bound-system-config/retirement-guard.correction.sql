-- UNREGISTERED forward correction; preserves previously applied candidate bytes.
CREATE OR REPLACE FUNCTION secureshop_agents.guard_system_config_record() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE retired boolean;
BEGIN
 retired:=EXISTS(SELECT 1 FROM secureshop_agents.conversation_generation_retirements WHERE platform_launch_id=OLD.platform_launch_id AND platform_scenario_id=OLD.platform_scenario_id AND from_generation=OLD.platform_launch_generation AND original_platform_owner_id=OLD.original_platform_owner_id AND original_platform_session_id=OLD.original_platform_session_id)
 OR EXISTS(SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts WHERE original_platform_owner_id=OLD.original_platform_owner_id);
 IF TG_OP='DELETE' THEN
  IF EXISTS(SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts WHERE original_platform_owner_id=OLD.original_platform_owner_id) THEN RETURN OLD; END IF;
 ELSIF retired THEN
  IF TG_TABLE_NAME='bound_system_config_admissions' THEN
   IF NEW.request_json IS NULL AND (to_jsonb(NEW)-'request_json')=(to_jsonb(OLD)-'request_json') THEN RETURN NEW; END IF;
  ELSIF TG_TABLE_NAME='bound_system_config_outcomes' THEN
   IF NEW.receipt_json IS NULL AND (to_jsonb(NEW)-'receipt_json')=(to_jsonb(OLD)-'receipt_json') THEN RETURN NEW; END IF;
  END IF;
 END IF;
 RAISE EXCEPTION 'System config evidence immutable' USING ERRCODE='55000';
END $$;
REVOKE ALL ON FUNCTION secureshop_agents.guard_system_config_record() FROM PUBLIC,dvaia_secureshop_agents_runtime;
