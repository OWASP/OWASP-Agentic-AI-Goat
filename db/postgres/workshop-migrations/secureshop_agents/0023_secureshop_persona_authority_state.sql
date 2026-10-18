-- UNAPPLIED FOUNDATION. Reserve a forward migration number after native qualification.
-- No authentication or effect consumer may treat this candidate as available.
CREATE TABLE secureshop_agents.bound_persona_state (
  platform_launch_id uuid NOT NULL,
  platform_scenario_id uuid NOT NULL,
  platform_launch_generation bigint NOT NULL CHECK(platform_launch_generation BETWEEN 1 AND 9007199254740991),
  original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id>0),
  original_platform_session_id integer NOT NULL CHECK(original_platform_session_id>0),
  shop_user_id integer NOT NULL REFERENCES secureshop_agents.bound_persona_templates(shop_user_id),
  effective_role text NOT NULL CHECK(effective_role IN ('customer','merchant','admin')),
  banned_at timestamptz,
  ban_reason text CHECK(ban_reason IS NULL OR octet_length(ban_reason)<=1024),
  authority_version bigint NOT NULL CHECK(authority_version BETWEEN 1 AND 9007199254740991),
  PRIMARY KEY(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,shop_user_id)
);
CREATE TABLE secureshop_agents.bound_persona_admin_operations (
  platform_launch_id uuid NOT NULL,
  platform_scenario_id uuid NOT NULL,
  platform_launch_generation bigint NOT NULL CHECK(platform_launch_generation>0),
  original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id>0),
  original_platform_session_id integer NOT NULL CHECK(original_platform_session_id>0),
  operation_id uuid NOT NULL,
  actor_id integer NOT NULL,
  original_actor_session_id uuid NOT NULL,
  target_id integer NOT NULL,
  request_sha256 bytea NOT NULL CHECK(octet_length(request_sha256)=32),
  result_json jsonb NOT NULL CHECK(jsonb_typeof(result_json)='object'),
  completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,operation_id)
);
CREATE FUNCTION secureshop_agents.guard_bound_persona_admin_state() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
BEGIN
 IF TG_OP='DELETE' THEN
  IF EXISTS(SELECT 1 FROM secureshop_agents.conversation_generation_retirements WHERE platform_launch_id=OLD.platform_launch_id AND from_generation=OLD.platform_launch_generation)
   OR EXISTS(SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts WHERE original_platform_owner_id=OLD.original_platform_owner_id) THEN RETURN OLD; END IF;
  RAISE EXCEPTION 'Persona state requires lifecycle cleanup' USING ERRCODE='55000'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-conversation-admission:'||NEW.platform_launch_id::text,0));
 IF EXISTS(SELECT 1 FROM secureshop_agents.conversation_generation_retirements
  WHERE platform_launch_id=NEW.platform_launch_id AND from_generation=NEW.platform_launch_generation)
 OR EXISTS(SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts
  WHERE original_platform_owner_id=NEW.original_platform_owner_id) THEN
  RAISE EXCEPTION 'Persona authority retired' USING ERRCODE='55000'; END IF;
 IF TG_OP='UPDATE' THEN
  IF ROW(NEW.platform_launch_id,NEW.platform_scenario_id,NEW.platform_launch_generation,NEW.original_platform_owner_id,NEW.original_platform_session_id,NEW.shop_user_id)
   IS DISTINCT FROM ROW(OLD.platform_launch_id,OLD.platform_scenario_id,OLD.platform_launch_generation,OLD.original_platform_owner_id,OLD.original_platform_session_id,OLD.shop_user_id)
   OR NEW.authority_version<>OLD.authority_version+1 THEN
   RAISE EXCEPTION 'Persona state identity/version invalid' USING ERRCODE='55000'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER bound_persona_state_guard BEFORE INSERT OR UPDATE OR DELETE ON secureshop_agents.bound_persona_state
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_persona_admin_state();
-- Separate immutable-operation trigger avoids record-field assumptions across tables.
CREATE FUNCTION secureshop_agents.guard_bound_persona_admin_operation() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
BEGIN
 IF TG_OP='DELETE' AND EXISTS(SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts WHERE original_platform_owner_id=OLD.original_platform_owner_id) THEN RETURN OLD; END IF;
 RAISE EXCEPTION 'Persona administration receipt immutable' USING ERRCODE='55000'; END $$;
CREATE TRIGGER bound_persona_admin_operation_guard BEFORE UPDATE OR DELETE ON secureshop_agents.bound_persona_admin_operations
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_persona_admin_operation();
REVOKE ALL ON secureshop_agents.bound_persona_state,secureshop_agents.bound_persona_admin_operations FROM PUBLIC;
REVOKE ALL ON FUNCTION secureshop_agents.guard_bound_persona_admin_state(),secureshop_agents.guard_bound_persona_admin_operation() FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON secureshop_agents.bound_persona_state TO dvaia_secureshop_agents_runtime;
GRANT SELECT,INSERT ON secureshop_agents.bound_persona_admin_operations TO dvaia_secureshop_agents_runtime;
-- Lifecycle functions and function-only mutation grants must be qualified before promotion.
-- In particular direct runtime table writes are NOT a complete authority boundary.
CREATE FUNCTION secureshop_agents.revoke_admin_target_api_keys(
 l uuid,s uuid,g bigint,o integer,p integer,a integer,sid uuid,t integer) RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE removed integer;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-conversation-admission:'||l::text,0));
 IF NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_persona_sessions x
 LEFT JOIN secureshop_agents.bound_persona_state st ON st.platform_launch_id=l AND st.platform_scenario_id=s
 AND st.platform_launch_generation=g AND st.original_platform_owner_id=o AND st.original_platform_session_id=p AND st.shop_user_id=a
 WHERE x.platform_launch_id=l AND x.platform_scenario_id=s AND x.platform_launch_generation=g
 AND x.original_platform_owner_id=o AND x.original_platform_session_id=p AND x.shop_user_id=a
 AND x.session_id=sid AND x.revoked_at IS NULL AND x.expires_at>clock_timestamp()
 AND x.credential_version=COALESCE((SELECT c.credential_version FROM secureshop_agents.bound_persona_credentials c WHERE c.platform_launch_id=l AND c.platform_scenario_id=s AND c.platform_launch_generation=g AND c.original_platform_owner_id=o AND c.original_platform_session_id=p AND c.shop_user_id=a),1)
 AND x.role='admin' AND COALESCE(st.effective_role,x.role)='admin' AND st.banned_at IS NULL)
 OR EXISTS(SELECT 1 FROM secureshop_agents.conversation_generation_retirements WHERE platform_launch_id=l AND from_generation=g)
 OR EXISTS(SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts WHERE original_platform_owner_id=o)
 THEN RAISE EXCEPTION 'Persona admin authority unavailable' USING ERRCODE='42501'; END IF;
 DELETE FROM secureshop_agents.bound_persona_api_keys WHERE platform_launch_id=l AND platform_scenario_id=s
 AND platform_launch_generation=g AND original_platform_owner_id=o AND original_platform_session_id=p AND shop_user_id=t;
 GET DIAGNOSTICS removed=ROW_COUNT; RETURN removed;
END $$;
REVOKE ALL ON FUNCTION secureshop_agents.revoke_admin_target_api_keys(uuid,uuid,bigint,integer,integer,integer,uuid,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_agents.revoke_admin_target_api_keys(uuid,uuid,bigint,integer,integer,integer,uuid,integer) TO dvaia_secureshop_agents_runtime;

-- Retirement removes mutable state but retains immutable operation/audit history.
-- Canonical bound-audit owner deletion removes personal operation records as well.
CREATE TABLE secureshop_agents.bound_persona_admin_cleanup_receipts (
 cleanup_id uuid NOT NULL,
 cleanup_kind text NOT NULL CHECK(cleanup_kind IN ('retirement','owner_deletion')),
 PRIMARY KEY(cleanup_kind,cleanup_id),
 original_platform_owner_id integer NOT NULL,
 platform_launch_id uuid,
 platform_generation bigint,
 deleted_state_count bigint NOT NULL CHECK(deleted_state_count>=0),
 deleted_operation_count bigint NOT NULL CHECK(deleted_operation_count>=0),
 receipt_sha256 bytea NOT NULL CHECK(octet_length(receipt_sha256)=32),
 completed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER bound_persona_admin_cleanup_immutable BEFORE UPDATE OR DELETE ON secureshop_agents.bound_persona_admin_cleanup_receipts
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_audit_owner_deletion_receipt();
CREATE FUNCTION secureshop_agents.cleanup_bound_persona_admin() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE n bigint; m bigint:=0; id uuid; kind text; launch uuid; generation bigint;
BEGIN
 IF TG_TABLE_NAME='conversation_generation_retirements' THEN
  id:=NEW.reset_id;kind:='retirement';launch:=NEW.platform_launch_id;generation:=NEW.from_generation;
  DELETE FROM secureshop_agents.bound_persona_state WHERE platform_launch_id=launch
   AND platform_scenario_id=NEW.platform_scenario_id AND platform_launch_generation=generation
   AND original_platform_owner_id=NEW.original_platform_owner_id AND original_platform_session_id=NEW.original_platform_session_id;
  GET DIAGNOSTICS n=ROW_COUNT;
 ELSE
  id:=NEW.deletion_job_id;kind:='owner_deletion';
  DELETE FROM secureshop_agents.bound_persona_state WHERE original_platform_owner_id=NEW.original_platform_owner_id;
  GET DIAGNOSTICS n=ROW_COUNT;
  DELETE FROM secureshop_agents.bound_persona_admin_operations WHERE original_platform_owner_id=NEW.original_platform_owner_id;
  GET DIAGNOSTICS m=ROW_COUNT;
 END IF;
 INSERT INTO secureshop_agents.bound_persona_admin_cleanup_receipts
  (cleanup_id,cleanup_kind,original_platform_owner_id,platform_launch_id,platform_generation,deleted_state_count,deleted_operation_count,receipt_sha256)
 VALUES(id,kind,NEW.original_platform_owner_id,launch,generation,n,m,
  sha256(convert_to(jsonb_build_array('persona-admin-cleanup-v1',id,kind,NEW.original_platform_owner_id,launch,generation,n,m)::text,'UTF8')));
 RETURN NEW;
END $$;
CREATE TRIGGER cleanup_bound_persona_admin_retirement AFTER INSERT ON secureshop_agents.conversation_generation_retirements
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.cleanup_bound_persona_admin();
CREATE TRIGGER cleanup_bound_persona_admin_owner AFTER INSERT ON secureshop_agents.bound_audit_owner_deletion_receipts
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.cleanup_bound_persona_admin();
-- Existing receipts predate these new empty tables; record zero-count upgrade receipts.
INSERT INTO secureshop_agents.bound_persona_admin_cleanup_receipts
 (cleanup_id,cleanup_kind,original_platform_owner_id,platform_launch_id,platform_generation,deleted_state_count,deleted_operation_count,receipt_sha256)
 SELECT reset_id,'retirement',original_platform_owner_id,platform_launch_id,from_generation,0,0,
 sha256(convert_to(jsonb_build_array('persona-admin-cleanup-v1',reset_id,'retirement',original_platform_owner_id,platform_launch_id,from_generation,0,0)::text,'UTF8'))
 FROM secureshop_agents.conversation_generation_retirements;
INSERT INTO secureshop_agents.bound_persona_admin_cleanup_receipts
 (cleanup_id,cleanup_kind,original_platform_owner_id,deleted_state_count,deleted_operation_count,receipt_sha256)
 SELECT deletion_job_id,'owner_deletion',original_platform_owner_id,0,0,
 sha256(convert_to(jsonb_build_array('persona-admin-cleanup-v1',deletion_job_id,'owner_deletion',original_platform_owner_id,NULL,NULL,0,0)::text,'UTF8'))
 FROM secureshop_agents.bound_audit_owner_deletion_receipts;
CREATE FUNCTION secureshop_agents.guard_bound_persona_admin_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||NEW.original_platform_owner_id::text,0));
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-conversation-admission:'||NEW.platform_launch_id::text,0));
 IF EXISTS(SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts WHERE original_platform_owner_id=NEW.original_platform_owner_id)
 OR EXISTS(SELECT 1 FROM secureshop_agents.conversation_generation_retirements WHERE platform_launch_id=NEW.platform_launch_id AND from_generation=NEW.platform_launch_generation) THEN
 RAISE EXCEPTION 'Persona authority retired' USING ERRCODE='55000'; END IF;RETURN NEW;
END $$;
CREATE TRIGGER bound_persona_admin_insert_guard BEFORE INSERT ON secureshop_agents.bound_persona_admin_operations
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_persona_admin_insert();
-- Shared owner-first fence also covers direct runtime state writes against deletion.
CREATE TRIGGER bound_persona_admin_state_fence BEFORE INSERT OR UPDATE ON secureshop_agents.bound_persona_state
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_persona_admin_insert();
REVOKE ALL ON secureshop_agents.bound_persona_admin_cleanup_receipts FROM PUBLIC;
GRANT SELECT ON secureshop_agents.bound_persona_admin_cleanup_receipts TO dvaia_secureshop_agents_runtime;
REVOKE ALL ON FUNCTION secureshop_agents.cleanup_bound_persona_admin(),secureshop_agents.guard_bound_persona_admin_insert() FROM PUBLIC;

-- Stable template identity remains immutable; new session role is admitted from
-- effective launch state, not constrained to the original template role.
ALTER TABLE secureshop_agents.bound_persona_templates ADD CONSTRAINT bound_persona_template_stable_identity UNIQUE(shop_user_id,username);
ALTER TABLE secureshop_agents.bound_persona_sessions DROP CONSTRAINT bound_persona_sessions_shop_user_id_role_username_fkey;
ALTER TABLE secureshop_agents.bound_persona_sessions ADD CONSTRAINT bound_persona_session_stable_identity
 FOREIGN KEY(shop_user_id,username) REFERENCES secureshop_agents.bound_persona_templates(shop_user_id,username);
CREATE FUNCTION secureshop_agents.guard_bound_persona_effective_session() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE effective text; banned timestamptz;
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||NEW.original_platform_owner_id::text,0));
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-conversation-admission:'||NEW.platform_launch_id::text,0));
 SELECT COALESCE(st.effective_role,t.role),st.banned_at INTO effective,banned
 FROM secureshop_agents.bound_persona_templates t LEFT JOIN secureshop_agents.bound_persona_state st
 ON st.platform_launch_id=NEW.platform_launch_id AND st.platform_scenario_id=NEW.platform_scenario_id
 AND st.platform_launch_generation=NEW.platform_launch_generation AND st.original_platform_owner_id=NEW.original_platform_owner_id
 AND st.original_platform_session_id=NEW.original_platform_session_id AND st.shop_user_id=t.shop_user_id
 WHERE t.shop_user_id=NEW.shop_user_id AND t.username=NEW.username;
 IF effective IS NULL OR effective<>NEW.role OR banned IS NOT NULL
 OR EXISTS(SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts WHERE original_platform_owner_id=NEW.original_platform_owner_id) THEN
 RAISE EXCEPTION 'Effective persona authority unavailable' USING ERRCODE='55000'; END IF;RETURN NEW;
END $$;
CREATE TRIGGER bound_persona_effective_session_guard BEFORE INSERT ON secureshop_agents.bound_persona_sessions
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_persona_effective_session();
REVOKE ALL ON FUNCTION secureshop_agents.guard_bound_persona_effective_session() FROM PUBLIC;
