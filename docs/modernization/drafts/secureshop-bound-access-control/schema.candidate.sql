-- Unregistered candidate. Qualify fresh/populated/no-op and least privilege before promotion.
-- Repository must acquire owner audit -> launch admission -> policy head locks.
CREATE TABLE secureshop_agents.bound_tool_policy_heads (
 platform_launch_id uuid NOT NULL, platform_scenario_id uuid NOT NULL, platform_launch_generation bigint NOT NULL CHECK(platform_launch_generation>0), original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id>0), original_platform_session_id bigint NOT NULL CHECK(original_platform_session_id>0), policy_version bigint NOT NULL DEFAULT 1 CHECK(policy_version>0),
 enforcement_enabled boolean NOT NULL, registry_sha256 bytea NOT NULL CHECK(octet_length(registry_sha256)=32),
 PRIMARY KEY(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id)
);
CREATE TABLE secureshop_agents.bound_tool_policy_overrides (
 platform_launch_id uuid NOT NULL, platform_scenario_id uuid NOT NULL, platform_launch_generation bigint NOT NULL CHECK(platform_launch_generation>0), original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id>0), original_platform_session_id bigint NOT NULL CHECK(original_platform_session_id>0), tool_key text NOT NULL CHECK(length(tool_key)<=160 AND tool_key ~ '^[a-z][a-z0-9-]*\.[a-z][a-z0-9_]*$'),
 role text NOT NULL CHECK(role IN ('customer','merchant','admin')), allowed boolean NOT NULL,
 PRIMARY KEY(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,tool_key,role),
 FOREIGN KEY(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id) REFERENCES secureshop_agents.bound_tool_policy_heads(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id)
);
CREATE TABLE secureshop_agents.bound_tool_policy_operations (
 platform_launch_id uuid NOT NULL, platform_scenario_id uuid NOT NULL, platform_launch_generation bigint NOT NULL CHECK(platform_launch_generation>0), original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id>0), original_platform_session_id bigint NOT NULL CHECK(original_platform_session_id>0), operation_id uuid NOT NULL, persona_id integer NOT NULL CHECK(persona_id>0),
 persona_session_id uuid NOT NULL, persona_role text NOT NULL CHECK(persona_role='admin'),
 authority_version bigint NOT NULL CHECK(authority_version>0),
 expected_version bigint NOT NULL CHECK(expected_version>0), policy_version bigint NOT NULL CHECK(policy_version=expected_version+1),
 request_sha256 bytea NOT NULL CHECK(octet_length(request_sha256)=32),
 receipt_json jsonb NOT NULL CHECK(jsonb_typeof(receipt_json)='object' AND octet_length(receipt_json::text)<=16384),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,operation_id)
);
CREATE TABLE secureshop_agents.bound_tool_admissions (
 platform_launch_id uuid NOT NULL, platform_scenario_id uuid NOT NULL, platform_launch_generation bigint NOT NULL CHECK(platform_launch_generation>0), original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id>0), original_platform_session_id bigint NOT NULL CHECK(original_platform_session_id>0), admission_id uuid NOT NULL, run_id uuid NOT NULL, invocation_id text NOT NULL CHECK(length(invocation_id) BETWEEN 1 AND 256),
 persona_id integer NOT NULL CHECK(persona_id>0), persona_session_id uuid NOT NULL,
 persona_role text NOT NULL CHECK(persona_role IN ('customer','merchant','admin')), authority_version bigint NOT NULL CHECK(authority_version>0),
 tool_key text NOT NULL CHECK(length(tool_key)<=160 AND tool_key ~ '^[a-z][a-z0-9-]*\.[a-z][a-z0-9_]*$'),
 args_sha256 bytea NOT NULL CHECK(octet_length(args_sha256)=32), registry_sha256 bytea NOT NULL CHECK(octet_length(registry_sha256)=32),
 policy_version bigint NOT NULL CHECK(policy_version>0), enforcement_enabled boolean NOT NULL, allowed boolean NOT NULL,
 action text NOT NULL CHECK(action IN ('dispatch','block')), policy_violation text,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,admission_id),
 UNIQUE(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,run_id,invocation_id),
 CHECK(action=CASE WHEN allowed OR NOT enforcement_enabled THEN 'dispatch' ELSE 'block' END),
 CHECK(policy_violation IS NOT DISTINCT FROM CASE WHEN allowed THEN NULL ELSE 'denied-by-acl' END)
);
CREATE TABLE secureshop_agents.bound_tool_policy_cleanup_receipts (
 cleanup_kind text NOT NULL CHECK(cleanup_kind IN ('retirement','owner_deletion')), cleanup_id uuid NOT NULL,
 original_platform_owner_id integer NOT NULL, platform_launch_id uuid, platform_generation bigint,
 deleted_head_count bigint NOT NULL CHECK(deleted_head_count>=0), deleted_override_count bigint NOT NULL CHECK(deleted_override_count>=0),
 deleted_operation_count bigint NOT NULL CHECK(deleted_operation_count>=0), deleted_admission_count bigint NOT NULL CHECK(deleted_admission_count>=0),
 receipt_sha256 bytea NOT NULL CHECK(octet_length(receipt_sha256)=32), completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(cleanup_kind,cleanup_id)
);
CREATE TRIGGER bound_tool_cleanup_immutable BEFORE UPDATE OR DELETE ON secureshop_agents.bound_tool_policy_cleanup_receipts
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_audit_owner_deletion_receipt();

CREATE FUNCTION secureshop_agents.guard_bound_tool_policy_write() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||NEW.original_platform_owner_id::text,0));
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-conversation-admission:'||NEW.platform_launch_id::text,0));
 IF EXISTS(SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts WHERE original_platform_owner_id=NEW.original_platform_owner_id)
 OR EXISTS(SELECT 1 FROM secureshop_agents.conversation_generation_retirements WHERE platform_launch_id=NEW.platform_launch_id AND from_generation=NEW.platform_launch_generation) THEN
  RAISE EXCEPTION 'Tool policy authority retired' USING ERRCODE='55000'; END IF;
 IF TG_OP='UPDATE' AND ROW(NEW.platform_launch_id,NEW.platform_scenario_id,NEW.platform_launch_generation,NEW.original_platform_owner_id,NEW.original_platform_session_id) IS DISTINCT FROM ROW(OLD.platform_launch_id,OLD.platform_scenario_id,OLD.platform_launch_generation,OLD.original_platform_owner_id,OLD.original_platform_session_id) THEN
  RAISE EXCEPTION 'Tool policy identity immutable' USING ERRCODE='55000'; END IF;
 IF TG_TABLE_NAME='bound_tool_policy_overrides' AND TG_OP='UPDATE' THEN
  IF ROW(NEW.tool_key,NEW.role) IS DISTINCT FROM ROW(OLD.tool_key,OLD.role) THEN
   RAISE EXCEPTION 'Tool override identity immutable' USING ERRCODE='55000'; END IF;
 END IF;
 IF TG_TABLE_NAME='bound_tool_policy_heads' AND TG_OP='UPDATE' THEN
  IF NEW.policy_version<>OLD.policy_version+1 THEN
   RAISE EXCEPTION 'Tool policy version conflict' USING ERRCODE='40001'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE FUNCTION secureshop_agents.guard_bound_tool_policy_history() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
BEGIN
 IF TG_OP='DELETE' AND EXISTS(SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts WHERE original_platform_owner_id=OLD.original_platform_owner_id) THEN RETURN OLD; END IF;
 RAISE EXCEPTION 'Tool policy evidence immutable' USING ERRCODE='55000';
END $$;
CREATE FUNCTION secureshop_agents.guard_bound_tool_policy_delete() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts WHERE original_platform_owner_id=OLD.original_platform_owner_id)
 OR EXISTS(SELECT 1 FROM secureshop_agents.conversation_generation_retirements WHERE platform_launch_id=OLD.platform_launch_id AND from_generation=OLD.platform_launch_generation) THEN RETURN OLD; END IF;
 RAISE EXCEPTION 'Tool policy cleanup authority required' USING ERRCODE='55000';
END $$;
CREATE FUNCTION secureshop_agents.guard_bound_tool_admission_actor() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE p secureshop_agents.bound_tool_policy_heads%ROWTYPE;
BEGIN
 SELECT * INTO p FROM secureshop_agents.bound_tool_policy_heads WHERE platform_launch_id=NEW.platform_launch_id AND platform_scenario_id=NEW.platform_scenario_id AND platform_launch_generation=NEW.platform_launch_generation AND original_platform_owner_id=NEW.original_platform_owner_id AND original_platform_session_id=NEW.original_platform_session_id FOR UPDATE;
 IF NOT FOUND OR p.policy_version<>NEW.policy_version THEN RAISE EXCEPTION 'Tool policy version mismatch' USING ERRCODE='40001'; END IF;
 IF TG_TABLE_NAME='bound_tool_admissions' THEN
  IF p.enforcement_enabled<>NEW.enforcement_enabled OR p.registry_sha256<>NEW.registry_sha256 THEN RAISE EXCEPTION 'Tool policy admission mismatch' USING ERRCODE='55000'; END IF;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_persona_sessions s
  JOIN secureshop_agents.bound_persona_templates t ON t.shop_user_id=s.shop_user_id
  LEFT JOIN secureshop_agents.bound_persona_state st ON st.platform_launch_id=s.platform_launch_id AND st.platform_scenario_id=s.platform_scenario_id AND st.platform_launch_generation=s.platform_launch_generation AND st.original_platform_owner_id=s.original_platform_owner_id AND st.original_platform_session_id=s.original_platform_session_id AND st.shop_user_id=s.shop_user_id
  WHERE s.platform_launch_id=NEW.platform_launch_id AND s.platform_scenario_id=NEW.platform_scenario_id AND s.platform_launch_generation=NEW.platform_launch_generation AND s.original_platform_owner_id=NEW.original_platform_owner_id AND s.original_platform_session_id=NEW.original_platform_session_id
  AND s.shop_user_id=NEW.persona_id AND s.session_id=NEW.persona_session_id AND s.role=NEW.persona_role
  AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND st.banned_at IS NULL
  AND COALESCE(st.effective_role,t.role)=NEW.persona_role AND COALESCE(st.authority_version,1)=NEW.authority_version
  AND s.credential_version=COALESCE((SELECT c.credential_version FROM secureshop_agents.bound_persona_credentials c
   WHERE c.platform_launch_id=NEW.platform_launch_id AND c.platform_scenario_id=NEW.platform_scenario_id AND c.platform_launch_generation=NEW.platform_launch_generation AND c.original_platform_owner_id=NEW.original_platform_owner_id AND c.original_platform_session_id=NEW.original_platform_session_id AND c.shop_user_id=NEW.persona_id),1)) THEN
  RAISE EXCEPTION 'Tool policy persona unavailable' USING ERRCODE='55000'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER a_bound_tool_policy_heads_fence BEFORE INSERT OR UPDATE ON secureshop_agents.bound_tool_policy_heads FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_tool_policy_write();
CREATE TRIGGER z_bound_tool_policy_heads_guard BEFORE DELETE ON secureshop_agents.bound_tool_policy_heads FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_tool_policy_delete();
CREATE TRIGGER a_bound_tool_policy_overrides_fence BEFORE INSERT OR UPDATE ON secureshop_agents.bound_tool_policy_overrides FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_tool_policy_write();
CREATE TRIGGER z_bound_tool_policy_overrides_guard BEFORE DELETE ON secureshop_agents.bound_tool_policy_overrides FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_tool_policy_delete();
CREATE TRIGGER a_bound_tool_policy_operations_fence BEFORE INSERT ON secureshop_agents.bound_tool_policy_operations FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_tool_policy_write();
CREATE TRIGGER z_bound_tool_policy_operations_guard BEFORE UPDATE OR DELETE ON secureshop_agents.bound_tool_policy_operations FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_tool_policy_history();
CREATE TRIGGER b_bound_tool_policy_operations_actor BEFORE INSERT ON secureshop_agents.bound_tool_policy_operations FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_tool_admission_actor();
CREATE TRIGGER a_bound_tool_admissions_fence BEFORE INSERT ON secureshop_agents.bound_tool_admissions FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_tool_policy_write();
CREATE TRIGGER z_bound_tool_admissions_guard BEFORE UPDATE OR DELETE ON secureshop_agents.bound_tool_admissions FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_tool_policy_history();
CREATE TRIGGER b_bound_tool_admissions_actor BEFORE INSERT ON secureshop_agents.bound_tool_admissions FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_tool_admission_actor();

CREATE FUNCTION secureshop_agents.cleanup_bound_tool_policy() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE h bigint:=0; o bigint:=0; r bigint:=0; a bigint:=0; kind text; id uuid; launch uuid; generation bigint;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||NEW.original_platform_owner_id::text,0));
 IF TG_TABLE_NAME='conversation_generation_retirements' THEN
  kind:='retirement';id:=NEW.reset_id;launch:=NEW.platform_launch_id;generation:=NEW.from_generation;
  PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-conversation-admission:'||launch::text,0));
  DELETE FROM secureshop_agents.bound_tool_policy_overrides WHERE platform_launch_id=launch AND platform_launch_generation=generation AND platform_scenario_id=NEW.platform_scenario_id AND original_platform_owner_id=NEW.original_platform_owner_id AND original_platform_session_id=NEW.original_platform_session_id;
  GET DIAGNOSTICS o=ROW_COUNT;
  DELETE FROM secureshop_agents.bound_tool_policy_heads WHERE platform_launch_id=launch AND platform_launch_generation=generation AND platform_scenario_id=NEW.platform_scenario_id AND original_platform_owner_id=NEW.original_platform_owner_id AND original_platform_session_id=NEW.original_platform_session_id;
  GET DIAGNOSTICS h=ROW_COUNT;
 ELSE
  kind:='owner_deletion';id:=NEW.deletion_job_id;
  DELETE FROM secureshop_agents.bound_tool_policy_overrides WHERE original_platform_owner_id=NEW.original_platform_owner_id;
  GET DIAGNOSTICS o=ROW_COUNT;
  DELETE FROM secureshop_agents.bound_tool_policy_heads WHERE original_platform_owner_id=NEW.original_platform_owner_id;
  GET DIAGNOSTICS h=ROW_COUNT;
  DELETE FROM secureshop_agents.bound_tool_policy_operations WHERE original_platform_owner_id=NEW.original_platform_owner_id;
  GET DIAGNOSTICS r=ROW_COUNT;
  DELETE FROM secureshop_agents.bound_tool_admissions WHERE original_platform_owner_id=NEW.original_platform_owner_id;
  GET DIAGNOSTICS a=ROW_COUNT;
 END IF;
 INSERT INTO secureshop_agents.bound_tool_policy_cleanup_receipts(cleanup_kind,cleanup_id,original_platform_owner_id,platform_launch_id,platform_generation,
 deleted_head_count,deleted_override_count,deleted_operation_count,deleted_admission_count,receipt_sha256)
 VALUES(kind,id,NEW.original_platform_owner_id,launch,generation,h,o,r,a,
 sha256(convert_to(jsonb_build_array('tool-policy-cleanup-v1',kind,id,NEW.original_platform_owner_id,launch,generation,h,o,r,a)::text,'UTF8')));
 RETURN NEW;
END $$;
CREATE TRIGGER cleanup_bound_tool_policy_retirement AFTER INSERT ON secureshop_agents.conversation_generation_retirements
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.cleanup_bound_tool_policy();
CREATE TRIGGER cleanup_bound_tool_policy_owner AFTER INSERT ON secureshop_agents.bound_audit_owner_deletion_receipts
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.cleanup_bound_tool_policy();
INSERT INTO secureshop_agents.bound_tool_policy_cleanup_receipts(cleanup_kind,cleanup_id,original_platform_owner_id,platform_launch_id,platform_generation,deleted_head_count,deleted_override_count,deleted_operation_count,deleted_admission_count,receipt_sha256) SELECT 'retirement',reset_id,original_platform_owner_id,platform_launch_id,from_generation,0,0,0,0,sha256(convert_to(jsonb_build_array('tool-policy-cleanup-v1','retirement',reset_id,original_platform_owner_id,platform_launch_id,from_generation,0,0,0,0)::text,'UTF8')) FROM secureshop_agents.conversation_generation_retirements;
INSERT INTO secureshop_agents.bound_tool_policy_cleanup_receipts(cleanup_kind,cleanup_id,original_platform_owner_id,platform_launch_id,platform_generation,deleted_head_count,deleted_override_count,deleted_operation_count,deleted_admission_count,receipt_sha256) SELECT 'owner_deletion',deletion_job_id,original_platform_owner_id,NULL::uuid,NULL::bigint,0,0,0,0,sha256(convert_to(jsonb_build_array('tool-policy-cleanup-v1','owner_deletion',deletion_job_id,original_platform_owner_id,NULL::uuid,NULL::bigint,0,0,0,0)::text,'UTF8')) FROM secureshop_agents.bound_audit_owner_deletion_receipts;
REVOKE ALL ON secureshop_agents.bound_tool_policy_heads FROM PUBLIC,dvaia_secureshop_agents_runtime;
GRANT SELECT,INSERT,UPDATE ON secureshop_agents.bound_tool_policy_heads TO dvaia_secureshop_agents_runtime;
REVOKE ALL ON secureshop_agents.bound_tool_policy_overrides FROM PUBLIC,dvaia_secureshop_agents_runtime;
GRANT SELECT,INSERT,UPDATE ON secureshop_agents.bound_tool_policy_overrides TO dvaia_secureshop_agents_runtime;
REVOKE ALL ON secureshop_agents.bound_tool_policy_operations FROM PUBLIC,dvaia_secureshop_agents_runtime;
GRANT SELECT,INSERT ON secureshop_agents.bound_tool_policy_operations TO dvaia_secureshop_agents_runtime;
REVOKE ALL ON secureshop_agents.bound_tool_admissions FROM PUBLIC,dvaia_secureshop_agents_runtime;
GRANT SELECT,INSERT ON secureshop_agents.bound_tool_admissions TO dvaia_secureshop_agents_runtime;
REVOKE ALL ON secureshop_agents.bound_tool_policy_cleanup_receipts FROM PUBLIC,dvaia_secureshop_agents_runtime;
GRANT SELECT ON secureshop_agents.bound_tool_policy_cleanup_receipts TO dvaia_secureshop_agents_runtime;
REVOKE ALL ON FUNCTION secureshop_agents.guard_bound_tool_policy_write() FROM PUBLIC,dvaia_secureshop_agents_runtime;
REVOKE ALL ON FUNCTION secureshop_agents.guard_bound_tool_policy_history() FROM PUBLIC,dvaia_secureshop_agents_runtime;
REVOKE ALL ON FUNCTION secureshop_agents.guard_bound_tool_policy_delete() FROM PUBLIC,dvaia_secureshop_agents_runtime;
REVOKE ALL ON FUNCTION secureshop_agents.guard_bound_tool_admission_actor() FROM PUBLIC,dvaia_secureshop_agents_runtime;
REVOKE ALL ON FUNCTION secureshop_agents.cleanup_bound_tool_policy() FROM PUBLIC,dvaia_secureshop_agents_runtime;
