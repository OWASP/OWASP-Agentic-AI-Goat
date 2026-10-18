-- Reserved agents0025; unregistered until native lifecycle qualification.
CREATE TABLE secureshop_agents.bound_synthetic_user_directories (
 platform_launch_id uuid NOT NULL, platform_scenario_id uuid NOT NULL,
 platform_launch_generation bigint NOT NULL CHECK(platform_launch_generation>0),
 original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id>0),
 original_platform_session_id bigint NOT NULL CHECK(original_platform_session_id>0),
 rows_json jsonb NOT NULL,
 CONSTRAINT synthetic_directory_rows_type CHECK(jsonb_typeof(rows_json)='array'),
 CONSTRAINT synthetic_directory_rows_count CHECK(jsonb_array_length(rows_json)=3),
 CONSTRAINT synthetic_directory_rows_bytes CHECK(octet_length(rows_json::text)<32768),
 content_sha256 bytea NOT NULL CHECK(octet_length(content_sha256)=32),
 PRIMARY KEY(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id)
);
CREATE TRIGGER synthetic_user_directory_admission BEFORE INSERT ON secureshop_agents.bound_synthetic_user_directories
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_persona_admin_insert();
CREATE TRIGGER synthetic_user_directory_immutable BEFORE UPDATE ON secureshop_agents.bound_synthetic_user_directories
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_audit_owner_deletion_receipt();
CREATE FUNCTION secureshop_agents.cleanup_synthetic_user_directory() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_TABLE_NAME='conversation_generation_retirements' THEN
  DELETE FROM secureshop_agents.bound_synthetic_user_directories WHERE platform_launch_id=NEW.platform_launch_id
   AND platform_launch_generation=NEW.from_generation AND original_platform_owner_id=NEW.original_platform_owner_id;
 ELSE
  DELETE FROM secureshop_agents.bound_synthetic_user_directories WHERE original_platform_owner_id=NEW.original_platform_owner_id;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER synthetic_user_directory_retirement AFTER INSERT ON secureshop_agents.conversation_generation_retirements
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.cleanup_synthetic_user_directory();
CREATE TRIGGER synthetic_user_directory_owner AFTER INSERT ON secureshop_agents.bound_audit_owner_deletion_receipts
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.cleanup_synthetic_user_directory();
REVOKE ALL ON secureshop_agents.bound_synthetic_user_directories FROM PUBLIC;
GRANT SELECT,INSERT ON secureshop_agents.bound_synthetic_user_directories TO dvaia_secureshop_agents_runtime;
REVOKE ALL ON FUNCTION secureshop_agents.cleanup_synthetic_user_directory() FROM PUBLIC,dvaia_secureshop_agents_runtime;
