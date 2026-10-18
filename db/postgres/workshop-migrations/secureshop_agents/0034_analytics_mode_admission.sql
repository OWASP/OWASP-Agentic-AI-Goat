-- Candidate; unregistered until native fresh/populated/no-op qualification.
-- Existing admissions remain immutable historical records with NULL mode.
ALTER TABLE secureshop_agents.analytics_request_admissions ADD COLUMN mode_snapshot jsonb;
ALTER TABLE secureshop_agents.analytics_request_admissions ADD CONSTRAINT analytics_admission_mode_shape CHECK(
 mode_snapshot IS NULL OR (
 jsonb_typeof(mode_snapshot)='object'
 AND mode_snapshot ?& ARRAY['version','mode','generation','modeStamp']
 AND mode_snapshot - ARRAY['version','mode','generation','modeStamp']='{}'::jsonb
 AND mode_snapshot->'version'='1'::jsonb
 AND jsonb_typeof(mode_snapshot->'mode')='string'
 AND mode_snapshot->>'mode' IN ('vuln','fixed')
 AND jsonb_typeof(mode_snapshot->'generation')='number'
 AND mode_snapshot->>'generation' ~ '^(0|[1-9][0-9]{0,9})$'
 AND (mode_snapshot->>'generation')::integer>=0
 AND jsonb_typeof(mode_snapshot->'modeStamp')='string'
 AND octet_length(mode_snapshot->>'modeStamp') BETWEEN 1 AND 128
 ));
CREATE FUNCTION secureshop_agents.guard_analytics_mode_admission() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.mode_snapshot IS NULL THEN RAISE EXCEPTION 'Canonical Analytics mode required'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER analytics_mode_admission_guard BEFORE INSERT ON secureshop_agents.analytics_request_admissions
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_analytics_mode_admission();
REVOKE ALL ON FUNCTION secureshop_agents.guard_analytics_mode_admission() FROM PUBLIC,dvaia_secureshop_agents_runtime;
-- The existing whole-row immutable guard also covers this additive column.
