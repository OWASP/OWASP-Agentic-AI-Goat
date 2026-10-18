-- Isolated teaching state only. These roles never participate in authentication.
CREATE TABLE secureshop_agents.owned_agency_role_targets (
 target_key text PRIMARY KEY CHECK(target_key ~ '^[0-9a-f]{64}$'),
 platform_launch_id uuid NOT NULL, platform_scenario_id uuid NOT NULL,
 platform_launch_generation bigint NOT NULL CHECK(platform_launch_generation>0),
 original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id>0),
 original_platform_session_id bigint NOT NULL CHECK(original_platform_session_id>0),
 target_id uuid NOT NULL, scene_id uuid NOT NULL,
 scene_generation bigint NOT NULL CHECK(scene_generation>0), grant_id uuid NOT NULL,
 customer_id integer NOT NULL CHECK(customer_id>0),
 teaching_role text NOT NULL DEFAULT 'customer', revision bigint NOT NULL DEFAULT 1,
 lifecycle text NOT NULL DEFAULT 'active' CHECK(lifecycle IN ('active','retired')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK((teaching_role='customer' AND revision=1) OR (teaching_role='admin' AND revision=2)),
 UNIQUE(platform_launch_id,platform_scenario_id,platform_launch_generation,
  original_platform_owner_id,original_platform_session_id,target_id,scene_id,scene_generation,grant_id,customer_id)
);
CREATE TABLE secureshop_agents.owned_agency_role_effects (
 target_key text NOT NULL REFERENCES secureshop_agents.owned_agency_role_targets(target_key),
 request_id uuid NOT NULL, run_id uuid NOT NULL, call_id text NOT NULL CHECK(octet_length(call_id) BETWEEN 1 AND 256),
 effect_key text NOT NULL CHECK(octet_length(effect_key) BETWEEN 1 AND 1024),
 request_json jsonb NOT NULL CHECK(jsonb_typeof(request_json)='object' AND octet_length(request_json::text)<=16384),
 request_sha256 bytea NOT NULL CHECK(octet_length(request_sha256)=32),
 receipt_json jsonb NOT NULL CHECK(jsonb_typeof(receipt_json)='object' AND octet_length(receipt_json::text)<=20000),
 receipt_sha256 bytea NOT NULL CHECK(octet_length(receipt_sha256)=32),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(target_key,request_id,call_id),
 UNIQUE(target_key,run_id,effect_key)
);
CREATE FUNCTION secureshop_agents.guard_owned_agency_role_target() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Teaching role history is immutable' USING ERRCODE='55000'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.teaching_role<>'customer' OR NEW.revision<>1 OR NEW.lifecycle<>'active' THEN
   RAISE EXCEPTION 'Teaching role must start as customer' USING ERRCODE='55000';
  END IF;
 ELSE
  IF (to_jsonb(NEW)-ARRAY['teaching_role','revision','lifecycle']) IS DISTINCT FROM
     (to_jsonb(OLD)-ARRAY['teaching_role','revision','lifecycle']) OR OLD.lifecycle<>'active'
   OR NOT ((NEW.lifecycle='retired' AND NEW.teaching_role=OLD.teaching_role AND NEW.revision=OLD.revision)
    OR (NEW.lifecycle='active' AND OLD.teaching_role='customer' AND OLD.revision=1
     AND NEW.teaching_role='admin' AND NEW.revision=2)) THEN
   RAISE EXCEPTION 'Teaching role transition invalid' USING ERRCODE='55000';
  END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER owned_agency_role_target_guard BEFORE INSERT OR UPDATE OR DELETE
 ON secureshop_agents.owned_agency_role_targets FOR EACH ROW
 EXECUTE FUNCTION secureshop_agents.guard_owned_agency_role_target();
CREATE TRIGGER owned_agency_role_target_admission BEFORE INSERT
 ON secureshop_agents.owned_agency_role_targets FOR EACH ROW
 EXECUTE FUNCTION secureshop_agents.guard_bound_persona_admin_insert();
CREATE TRIGGER owned_agency_role_effect_immutable BEFORE UPDATE OR DELETE
 ON secureshop_agents.owned_agency_role_effects FOR EACH ROW
 EXECUTE FUNCTION secureshop_agents.guard_bound_audit_owner_deletion_receipt();
CREATE FUNCTION secureshop_agents.retire_owned_agency_roles() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN
 IF TG_TABLE_NAME='conversation_generation_retirements' THEN
  UPDATE secureshop_agents.owned_agency_role_targets SET lifecycle='retired'
   WHERE platform_launch_id=NEW.platform_launch_id AND platform_scenario_id=NEW.platform_scenario_id
    AND platform_launch_generation=NEW.from_generation AND original_platform_owner_id=NEW.original_platform_owner_id
    AND original_platform_session_id=NEW.original_platform_session_id AND lifecycle='active';
 ELSE
  UPDATE secureshop_agents.owned_agency_role_targets SET lifecycle='retired'
   WHERE original_platform_owner_id=NEW.original_platform_owner_id AND lifecycle='active';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER owned_agency_role_retirement AFTER INSERT ON secureshop_agents.conversation_generation_retirements
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.retire_owned_agency_roles();
CREATE TRIGGER owned_agency_role_owner_retirement AFTER INSERT ON secureshop_agents.bound_audit_owner_deletion_receipts
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.retire_owned_agency_roles();
REVOKE ALL ON secureshop_agents.owned_agency_role_targets,secureshop_agents.owned_agency_role_effects FROM PUBLIC,dvaia_secureshop_agents_runtime;
GRANT SELECT,INSERT ON secureshop_agents.owned_agency_role_targets,secureshop_agents.owned_agency_role_effects TO dvaia_secureshop_agents_runtime;
GRANT UPDATE(teaching_role,revision,lifecycle) ON secureshop_agents.owned_agency_role_targets TO dvaia_secureshop_agents_runtime;
REVOKE ALL ON FUNCTION secureshop_agents.guard_owned_agency_role_target(),secureshop_agents.retire_owned_agency_roles() FROM PUBLIC,dvaia_secureshop_agents_runtime;
