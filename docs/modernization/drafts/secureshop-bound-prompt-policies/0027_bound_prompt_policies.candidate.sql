-- Unregistered agents0027 candidate. No runtime or renderer activation.
CREATE TABLE secureshop_agents.bound_prompt_policy_heads (platform_launch_id uuid NOT NULL,platform_scenario_id uuid NOT NULL,platform_launch_generation bigint NOT NULL CHECK(platform_launch_generation>0),original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id>0),original_platform_session_id integer NOT NULL CHECK(original_platform_session_id>0),policy_version bigint NOT NULL DEFAULT 1 CHECK(policy_version BETWEEN 1 AND 9007199254740991),PRIMARY KEY(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id));
CREATE TABLE secureshop_agents.bound_prompt_policy_current (platform_launch_id uuid NOT NULL,platform_scenario_id uuid NOT NULL,platform_launch_generation bigint NOT NULL CHECK(platform_launch_generation>0),original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id>0),original_platform_session_id integer NOT NULL CHECK(original_platform_session_id>0),name text NOT NULL CHECK(octet_length(name) BETWEEN 1 AND 80),policy_version bigint NOT NULL CHECK(policy_version>1),payload_json jsonb NOT NULL CHECK(octet_length(payload_json::text)<=1048576),payload_sha256 bytea NOT NULL CHECK(octet_length(payload_sha256)=32),PRIMARY KEY(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,name));
CREATE TABLE secureshop_agents.bound_prompt_policy_revisions (platform_launch_id uuid NOT NULL,platform_scenario_id uuid NOT NULL,platform_launch_generation bigint NOT NULL CHECK(platform_launch_generation>0),original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id>0),original_platform_session_id integer NOT NULL CHECK(original_platform_session_id>0),operation_id uuid NOT NULL,name text NOT NULL,policy_version bigint NOT NULL CHECK(policy_version>1),action text NOT NULL CHECK(action IN ('upsert','delete')),payload_json jsonb CHECK(payload_json IS NULL OR octet_length(payload_json::text)<=1048576),payload_sha256 bytea NOT NULL CHECK(octet_length(payload_sha256)=32),PRIMARY KEY(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,operation_id));
CREATE TABLE secureshop_agents.bound_prompt_policy_operations (platform_launch_id uuid NOT NULL,platform_scenario_id uuid NOT NULL,platform_launch_generation bigint NOT NULL CHECK(platform_launch_generation>0),original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id>0),original_platform_session_id integer NOT NULL CHECK(original_platform_session_id>0),operation_id uuid NOT NULL,persona_id integer NOT NULL,persona_session_id uuid NOT NULL,persona_role text NOT NULL DEFAULT 'admin' CHECK(persona_role='admin'),authority_version bigint NOT NULL,action text NOT NULL CHECK(action IN ('upsert','preview','delete')),expected_version bigint NOT NULL CHECK(expected_version>0),mutation_sha256 bytea NOT NULL CHECK(octet_length(mutation_sha256)=32),request_sha256 bytea CHECK(request_sha256 IS NULL OR octet_length(request_sha256)=32),payload_json jsonb CHECK(payload_json IS NULL OR octet_length(payload_json::text)<=1048576),result_json jsonb CHECK(result_json IS NULL OR octet_length(result_json::text)<=1048576),result_sha256 bytea CHECK(result_sha256 IS NULL OR octet_length(result_sha256)=32),PRIMARY KEY(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,operation_id));
CREATE TABLE secureshop_agents.bound_prompt_policy_snapshots (platform_launch_id uuid NOT NULL,platform_scenario_id uuid NOT NULL,platform_launch_generation bigint NOT NULL CHECK(platform_launch_generation>0),original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id>0),original_platform_session_id integer NOT NULL CHECK(original_platform_session_id>0),run_id uuid NOT NULL,persona_id integer NOT NULL,persona_session_id uuid NOT NULL,authority_version bigint NOT NULL,persona_role text NOT NULL CHECK(persona_role IN ('customer','merchant','admin')),policy_version bigint NOT NULL CHECK(policy_version>0),payload_json jsonb CHECK(payload_json IS NULL OR octet_length(payload_json::text)<=1048576),payload_sha256 bytea NOT NULL CHECK(octet_length(payload_sha256)=32),PRIMARY KEY(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,run_id));
CREATE FUNCTION secureshop_agents.guard_prompt_policy_record() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE retired boolean;
BEGIN
 retired:=EXISTS(SELECT 1 FROM secureshop_agents.conversation_generation_retirements WHERE platform_launch_id=OLD.platform_launch_id AND from_generation=OLD.platform_launch_generation)
 OR EXISTS(SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts WHERE original_platform_owner_id=OLD.original_platform_owner_id);
 IF TG_OP='DELETE' THEN
  IF (TG_TABLE_NAME IN ('bound_prompt_policy_heads','bound_prompt_policy_current') AND retired)
   OR EXISTS(SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts WHERE original_platform_owner_id=OLD.original_platform_owner_id) THEN RETURN OLD; END IF;
  -- Current-row deletion is a versioned tombstone operation in the same transaction.
  IF TG_TABLE_NAME='bound_prompt_policy_current' AND EXISTS(SELECT 1 FROM secureshop_agents.bound_prompt_policy_revisions r WHERE r.platform_launch_id=OLD.platform_launch_id AND r.platform_scenario_id=OLD.platform_scenario_id AND r.platform_launch_generation=OLD.platform_launch_generation AND r.original_platform_owner_id=OLD.original_platform_owner_id AND r.original_platform_session_id=OLD.original_platform_session_id AND r.name=OLD.name AND r.action='delete' AND r.policy_version>OLD.policy_version) THEN RETURN OLD; END IF;
  RAISE EXCEPTION 'Prompt policy evidence immutable' USING ERRCODE='55000';
 END IF;
 IF TG_TABLE_NAME='bound_prompt_policy_heads' THEN
  IF NOT retired AND (to_jsonb(NEW)-'policy_version')=(to_jsonb(OLD)-'policy_version') AND NEW.policy_version=OLD.policy_version+1 THEN RETURN NEW; END IF;
 ELSIF TG_TABLE_NAME='bound_prompt_policy_current' THEN
  IF NOT retired AND (to_jsonb(NEW)-ARRAY['policy_version','payload_json','payload_sha256'])=(to_jsonb(OLD)-ARRAY['policy_version','payload_json','payload_sha256']) AND NEW.policy_version>OLD.policy_version THEN RETURN NEW; END IF;
 ELSIF TG_TABLE_NAME='bound_prompt_policy_operations' THEN
  IF NOT retired AND OLD.result_json IS NULL AND OLD.result_sha256 IS NULL AND NEW.result_json IS NOT NULL AND NEW.result_sha256 IS NOT NULL AND (to_jsonb(NEW)-ARRAY['result_json','result_sha256'])=(to_jsonb(OLD)-ARRAY['result_json','result_sha256']) THEN RETURN NEW; END IF;
  IF retired AND NEW.payload_json IS NULL AND NEW.result_json IS NULL AND (to_jsonb(NEW)-ARRAY['payload_json','result_json'])=(to_jsonb(OLD)-ARRAY['payload_json','result_json']) THEN RETURN NEW; END IF;
 ELSE
  IF retired AND NEW.payload_json IS NULL AND (to_jsonb(NEW)-'payload_json')=(to_jsonb(OLD)-'payload_json') THEN RETURN NEW; END IF;
 END IF;
 RAISE EXCEPTION 'Prompt policy transition invalid' USING ERRCODE='55000';
END $$;
CREATE TRIGGER prompt_policy_heads_insert BEFORE INSERT ON secureshop_agents.bound_prompt_policy_heads FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_persona_admin_insert();
CREATE TRIGGER prompt_policy_heads_guard BEFORE UPDATE OR DELETE ON secureshop_agents.bound_prompt_policy_heads FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_prompt_policy_record();
CREATE TRIGGER prompt_policy_current_insert BEFORE INSERT ON secureshop_agents.bound_prompt_policy_current FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_persona_admin_insert();
CREATE TRIGGER prompt_policy_current_guard BEFORE UPDATE OR DELETE ON secureshop_agents.bound_prompt_policy_current FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_prompt_policy_record();
CREATE TRIGGER prompt_policy_revisions_insert BEFORE INSERT ON secureshop_agents.bound_prompt_policy_revisions FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_persona_admin_insert();
CREATE TRIGGER prompt_policy_revisions_guard BEFORE UPDATE OR DELETE ON secureshop_agents.bound_prompt_policy_revisions FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_prompt_policy_record();
CREATE TRIGGER prompt_policy_operations_insert BEFORE INSERT ON secureshop_agents.bound_prompt_policy_operations FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_persona_admin_insert();
CREATE TRIGGER prompt_policy_operations_guard BEFORE UPDATE OR DELETE ON secureshop_agents.bound_prompt_policy_operations FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_prompt_policy_record();
CREATE TRIGGER prompt_policy_snapshots_insert BEFORE INSERT ON secureshop_agents.bound_prompt_policy_snapshots FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_persona_admin_insert();
CREATE TRIGGER prompt_policy_snapshots_guard BEFORE UPDATE OR DELETE ON secureshop_agents.bound_prompt_policy_snapshots FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_prompt_policy_record();
CREATE TABLE secureshop_agents.bound_prompt_policy_cleanup_receipts (
 cleanup_id uuid PRIMARY KEY,cleanup_kind text NOT NULL CHECK(cleanup_kind IN ('retirement','owner_deletion')),
 original_platform_owner_id integer NOT NULL,platform_launch_id uuid,platform_generation bigint,
 deleted_current integer NOT NULL,redacted_records integer NOT NULL,receipt_sha256 bytea NOT NULL CHECK(octet_length(receipt_sha256)=32));
CREATE TRIGGER prompt_policy_cleanup_immutable BEFORE UPDATE OR DELETE ON secureshop_agents.bound_prompt_policy_cleanup_receipts FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_audit_owner_deletion_receipt();
CREATE FUNCTION secureshop_agents.cleanup_prompt_policy_records() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE n integer:=0; m integer:=0; k integer; id uuid; kind text; l uuid; g bigint;
BEGIN
 IF TG_TABLE_NAME='conversation_generation_retirements' THEN
 id:=NEW.reset_id;kind:='retirement';l:=NEW.platform_launch_id;g:=NEW.from_generation;
 DELETE FROM secureshop_agents.bound_prompt_policy_current WHERE platform_launch_id=l AND platform_scenario_id=NEW.platform_scenario_id AND platform_launch_generation=g AND original_platform_owner_id=NEW.original_platform_owner_id AND original_platform_session_id=NEW.original_platform_session_id;GET DIAGNOSTICS n=ROW_COUNT;
 DELETE FROM secureshop_agents.bound_prompt_policy_heads WHERE platform_launch_id=l AND platform_scenario_id=NEW.platform_scenario_id AND platform_launch_generation=g AND original_platform_owner_id=NEW.original_platform_owner_id AND original_platform_session_id=NEW.original_platform_session_id;
 UPDATE secureshop_agents.bound_prompt_policy_revisions SET payload_json=NULL WHERE platform_launch_id=l AND platform_launch_generation=g AND original_platform_owner_id=NEW.original_platform_owner_id;GET DIAGNOSTICS k=ROW_COUNT;m:=m+k;
 UPDATE secureshop_agents.bound_prompt_policy_operations SET payload_json=NULL,result_json=NULL WHERE platform_launch_id=l AND platform_launch_generation=g AND original_platform_owner_id=NEW.original_platform_owner_id;GET DIAGNOSTICS k=ROW_COUNT;m:=m+k;
 UPDATE secureshop_agents.bound_prompt_policy_snapshots SET payload_json=NULL WHERE platform_launch_id=l AND platform_launch_generation=g AND original_platform_owner_id=NEW.original_platform_owner_id;GET DIAGNOSTICS k=ROW_COUNT;m:=m+k;
 ELSE
 id:=NEW.deletion_job_id;kind:='owner_deletion';
 DELETE FROM secureshop_agents.bound_prompt_policy_current WHERE original_platform_owner_id=NEW.original_platform_owner_id;GET DIAGNOSTICS n=ROW_COUNT;
 DELETE FROM secureshop_agents.bound_prompt_policy_heads WHERE original_platform_owner_id=NEW.original_platform_owner_id;
 DELETE FROM secureshop_agents.bound_prompt_policy_revisions WHERE original_platform_owner_id=NEW.original_platform_owner_id;GET DIAGNOSTICS k=ROW_COUNT;m:=m+k;
 DELETE FROM secureshop_agents.bound_prompt_policy_operations WHERE original_platform_owner_id=NEW.original_platform_owner_id;GET DIAGNOSTICS k=ROW_COUNT;m:=m+k;
 DELETE FROM secureshop_agents.bound_prompt_policy_snapshots WHERE original_platform_owner_id=NEW.original_platform_owner_id;GET DIAGNOSTICS k=ROW_COUNT;m:=m+k;
 END IF;
 INSERT INTO secureshop_agents.bound_prompt_policy_cleanup_receipts VALUES(id,kind,NEW.original_platform_owner_id,l,g,n,m,sha256(convert_to(jsonb_build_array(id,kind,NEW.original_platform_owner_id,l,g,n,m)::text,'UTF8')));
 RETURN NEW;
END $$;
CREATE TRIGGER prompt_policy_retirement AFTER INSERT ON secureshop_agents.conversation_generation_retirements FOR EACH ROW EXECUTE FUNCTION secureshop_agents.cleanup_prompt_policy_records();
CREATE TRIGGER prompt_policy_owner_delete AFTER INSERT ON secureshop_agents.bound_audit_owner_deletion_receipts FOR EACH ROW EXECUTE FUNCTION secureshop_agents.cleanup_prompt_policy_records();
REVOKE ALL ON secureshop_agents.bound_prompt_policy_heads FROM PUBLIC,dvaia_secureshop_agents_runtime;
GRANT SELECT,INSERT ON secureshop_agents.bound_prompt_policy_heads TO dvaia_secureshop_agents_runtime;
REVOKE ALL ON secureshop_agents.bound_prompt_policy_current FROM PUBLIC,dvaia_secureshop_agents_runtime;
GRANT SELECT,INSERT ON secureshop_agents.bound_prompt_policy_current TO dvaia_secureshop_agents_runtime;
REVOKE ALL ON secureshop_agents.bound_prompt_policy_revisions FROM PUBLIC,dvaia_secureshop_agents_runtime;
GRANT SELECT,INSERT ON secureshop_agents.bound_prompt_policy_revisions TO dvaia_secureshop_agents_runtime;
REVOKE ALL ON secureshop_agents.bound_prompt_policy_operations FROM PUBLIC,dvaia_secureshop_agents_runtime;
GRANT SELECT,INSERT ON secureshop_agents.bound_prompt_policy_operations TO dvaia_secureshop_agents_runtime;
REVOKE ALL ON secureshop_agents.bound_prompt_policy_snapshots FROM PUBLIC,dvaia_secureshop_agents_runtime;
GRANT SELECT,INSERT ON secureshop_agents.bound_prompt_policy_snapshots TO dvaia_secureshop_agents_runtime;
GRANT UPDATE(policy_version) ON secureshop_agents.bound_prompt_policy_heads TO dvaia_secureshop_agents_runtime;
GRANT UPDATE(policy_version,payload_json,payload_sha256),DELETE ON secureshop_agents.bound_prompt_policy_current TO dvaia_secureshop_agents_runtime;
GRANT UPDATE(result_json,result_sha256) ON secureshop_agents.bound_prompt_policy_operations TO dvaia_secureshop_agents_runtime;
REVOKE ALL ON secureshop_agents.bound_prompt_policy_cleanup_receipts FROM PUBLIC,dvaia_secureshop_agents_runtime;
GRANT SELECT ON secureshop_agents.bound_prompt_policy_cleanup_receipts TO dvaia_secureshop_agents_runtime;
REVOKE ALL ON FUNCTION secureshop_agents.guard_prompt_policy_record(),secureshop_agents.cleanup_prompt_policy_records() FROM PUBLIC,dvaia_secureshop_agents_runtime;
CREATE FUNCTION secureshop_agents.guard_prompt_policy_actor() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
BEGIN
 IF TG_TABLE_NAME='bound_prompt_policy_operations' THEN
  IF TG_OP='UPDATE' AND NEW.result_json IS NULL THEN RETURN NEW; END IF;
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
  RAISE EXCEPTION 'Prompt policy persona unavailable' USING ERRCODE='55000'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER z_prompt_policy_operations_actor BEFORE INSERT OR UPDATE OF result_json ON secureshop_agents.bound_prompt_policy_operations FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_prompt_policy_actor();
CREATE TRIGGER z_prompt_policy_snapshots_actor BEFORE INSERT ON secureshop_agents.bound_prompt_policy_snapshots FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_prompt_policy_actor();
REVOKE ALL ON FUNCTION secureshop_agents.guard_prompt_policy_actor() FROM PUBLIC,dvaia_secureshop_agents_runtime;
-- NULL payload/result after retirement is a redacted state; immutable mutation/render/result digests remain intentionally retained.
