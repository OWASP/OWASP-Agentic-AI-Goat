-- Unregistered candidate agents0026. No production activation.
CREATE TABLE secureshop_agents.bound_password_reset_operations (
 platform_launch_id uuid NOT NULL,platform_scenario_id uuid NOT NULL,
 platform_launch_generation bigint NOT NULL CONSTRAINT password_reset_generation CHECK(platform_launch_generation>0),
 original_platform_owner_id integer NOT NULL CONSTRAINT password_reset_owner CHECK(original_platform_owner_id>0),
 original_platform_session_id integer NOT NULL CONSTRAINT password_reset_session CHECK(original_platform_session_id>0),
 operation_id uuid NOT NULL,actor_id integer NOT NULL,original_actor_session_id uuid NOT NULL,
 actor_authority_version bigint NOT NULL CONSTRAINT password_reset_actor_version CHECK(actor_authority_version>0),target_id integer NOT NULL CONSTRAINT password_reset_target CHECK(target_id>0 AND target_id<>actor_id),
 request_sha256 bytea NOT NULL CONSTRAINT password_reset_request_digest CHECK(octet_length(request_sha256)=32),
 receipt_json jsonb NOT NULL CONSTRAINT password_reset_receipt_type CHECK(jsonb_typeof(receipt_json)='object') CONSTRAINT password_reset_receipt_bytes CHECK(octet_length(receipt_json::text)<=4096),
 PRIMARY KEY(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,operation_id)
);
CREATE TABLE secureshop_agents.bound_password_reset_recovery (
 platform_launch_id uuid NOT NULL,platform_scenario_id uuid NOT NULL,platform_launch_generation bigint NOT NULL,
 original_platform_owner_id integer NOT NULL,original_platform_session_id integer NOT NULL,operation_id uuid NOT NULL,
 envelope_json jsonb CONSTRAINT password_reset_envelope_type CHECK(envelope_json IS NULL OR jsonb_typeof(envelope_json)='object') CONSTRAINT password_reset_envelope_bytes CHECK(envelope_json IS NULL OR octet_length(envelope_json::text)<=2048),
 expires_at timestamptz NOT NULL,
 PRIMARY KEY(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,operation_id),
 FOREIGN KEY(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,operation_id)
 REFERENCES secureshop_agents.bound_password_reset_operations ON DELETE CASCADE
);
CREATE TRIGGER password_reset_operation_insert BEFORE INSERT ON secureshop_agents.bound_password_reset_operations FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_persona_admin_insert();
CREATE TRIGGER password_reset_operation_immutable BEFORE UPDATE OR DELETE ON secureshop_agents.bound_password_reset_operations FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_persona_admin_operation();
CREATE TRIGGER password_reset_recovery_insert BEFORE INSERT ON secureshop_agents.bound_password_reset_recovery FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_persona_admin_insert();
CREATE FUNCTION secureshop_agents.guard_password_reset_recovery() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='UPDATE' AND (to_jsonb(NEW)-'envelope_json')=(to_jsonb(OLD)-'envelope_json') AND NEW.envelope_json IS NULL THEN RETURN NEW; END IF;
 IF TG_OP='DELETE' AND (OLD.expires_at<=clock_timestamp()
 OR EXISTS(SELECT 1 FROM secureshop_agents.conversation_generation_retirements WHERE platform_launch_id=OLD.platform_launch_id AND from_generation=OLD.platform_launch_generation)
 OR EXISTS(SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts WHERE original_platform_owner_id=OLD.original_platform_owner_id)) THEN RETURN OLD; END IF;
 RAISE EXCEPTION 'Reset recovery immutable' USING ERRCODE='55000';
END $$;
CREATE TRIGGER password_reset_recovery_immutable BEFORE UPDATE OR DELETE ON secureshop_agents.bound_password_reset_recovery FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_password_reset_recovery();
CREATE FUNCTION secureshop_agents.cleanup_password_reset_recovery() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_TABLE_NAME='conversation_generation_retirements' THEN
 DELETE FROM secureshop_agents.bound_password_reset_recovery WHERE platform_launch_id=NEW.platform_launch_id AND platform_scenario_id=NEW.platform_scenario_id AND platform_launch_generation=NEW.from_generation AND original_platform_owner_id=NEW.original_platform_owner_id AND original_platform_session_id=NEW.original_platform_session_id;
 ELSE
 DELETE FROM secureshop_agents.bound_password_reset_operations WHERE original_platform_owner_id=NEW.original_platform_owner_id;
 END IF;RETURN NEW;
END $$;
CREATE TRIGGER password_reset_retirement AFTER INSERT ON secureshop_agents.conversation_generation_retirements FOR EACH ROW EXECUTE FUNCTION secureshop_agents.cleanup_password_reset_recovery();
CREATE TRIGGER password_reset_owner_delete AFTER INSERT ON secureshop_agents.bound_audit_owner_deletion_receipts FOR EACH ROW EXECUTE FUNCTION secureshop_agents.cleanup_password_reset_recovery();
REVOKE ALL ON secureshop_agents.bound_password_reset_operations,secureshop_agents.bound_password_reset_recovery FROM PUBLIC;
GRANT SELECT,INSERT ON secureshop_agents.bound_password_reset_operations,secureshop_agents.bound_password_reset_recovery TO dvaia_secureshop_agents_runtime;
GRANT UPDATE(envelope_json) ON secureshop_agents.bound_password_reset_recovery TO dvaia_secureshop_agents_runtime;
REVOKE ALL ON FUNCTION secureshop_agents.guard_password_reset_recovery(),secureshop_agents.cleanup_password_reset_recovery() FROM PUBLIC,dvaia_secureshop_agents_runtime;
