-- Retain the exact bounded teaching source for admission-before-provision recovery.
-- Legacy hash-only admissions stay NULL and cannot be reconstructed from new logs.
ALTER TABLE identity.secureshop_audit_target_admissions ADD COLUMN snapshot_json jsonb;
ALTER TABLE identity.secureshop_audit_target_admissions ADD CONSTRAINT audit_target_snapshot_shape CHECK (
 snapshot_json IS NULL OR (jsonb_typeof(snapshot_json)='object'
 AND snapshot_json - ARRAY['version','sources']='{}'::jsonb
 AND snapshot_json ?& ARRAY['version','sources'] AND snapshot_json->'version'='1'::jsonb
 AND jsonb_typeof(snapshot_json->'sources')='array'
 AND jsonb_array_length(snapshot_json->'sources')<=200 AND octet_length(snapshot_json::text)<=16777216)
);
CREATE FUNCTION identity.guard_secureshop_audit_target_snapshot() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  PERFORM 1 FROM identity.secureshop_launches l WHERE l.launch_id=NEW.launch_id AND l.generation=NEW.generation AND l.scenario_id=NEW.scenario_id
   AND l.platform_session_id=NEW.platform_session_id AND l.original_platform_owner_id=NEW.original_platform_owner_id
   AND l.status='active' AND l.expires_at>clock_timestamp() FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Audit target admission retired' USING ERRCODE='55000'; END IF;
  RETURN NEW;
 END IF;
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Audit target admission immutable' USING ERRCODE='42501'; END IF;
 IF OLD.user_id IS NOT NULL AND NEW.user_id IS NULL
 AND NOT EXISTS(SELECT 1 FROM identity.users WHERE id=OLD.user_id)
 AND (to_jsonb(NEW)-'user_id')=(to_jsonb(OLD)-'user_id') THEN RETURN NEW; END IF;
 IF OLD.snapshot_json IS NOT NULL AND NEW.snapshot_json IS NULL
 AND (to_jsonb(NEW)-'snapshot_json')=(to_jsonb(OLD)-'snapshot_json') AND (
 NOT EXISTS(SELECT 1 FROM identity.users WHERE id=OLD.original_platform_owner_id)
 OR EXISTS(SELECT 1 FROM identity.secureshop_launches l WHERE l.launch_id=OLD.launch_id
 AND (l.generation<>OLD.generation OR l.status<>'active'))) THEN RETURN NEW; END IF;
 RAISE EXCEPTION 'Audit target admission immutable' USING ERRCODE='42501';
END;
$$;
CREATE TRIGGER secureshop_audit_target_snapshot_immutable BEFORE INSERT OR UPDATE OR DELETE ON identity.secureshop_audit_target_admissions
 FOR EACH ROW EXECUTE FUNCTION identity.guard_secureshop_audit_target_snapshot();
CREATE FUNCTION identity.redact_secureshop_audit_target_snapshot() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_TABLE_NAME='users' THEN
  UPDATE identity.secureshop_audit_target_admissions SET snapshot_json=NULL WHERE original_platform_owner_id=OLD.id AND snapshot_json IS NOT NULL;
 ELSE
  UPDATE identity.secureshop_audit_target_admissions SET snapshot_json=NULL WHERE launch_id=NEW.launch_id
   AND (generation<>NEW.generation OR NEW.status<>'active') AND snapshot_json IS NOT NULL;
 END IF;
 RETURN NULL;
END;
$$;
CREATE TRIGGER redact_audit_target_on_launch AFTER UPDATE OF generation,status ON identity.secureshop_launches
 FOR EACH ROW EXECUTE FUNCTION identity.redact_secureshop_audit_target_snapshot();
CREATE TRIGGER redact_audit_target_on_owner_delete AFTER DELETE ON identity.users
 FOR EACH ROW EXECUTE FUNCTION identity.redact_secureshop_audit_target_snapshot();
REVOKE ALL ON FUNCTION identity.guard_secureshop_audit_target_snapshot() FROM PUBLIC,dvaia_identity_runtime;
REVOKE ALL ON FUNCTION identity.redact_secureshop_audit_target_snapshot() FROM PUBLIC,dvaia_identity_runtime;
-- Existing SELECT/INSERT grants are retained; runtime may not alter recovery bytes.
