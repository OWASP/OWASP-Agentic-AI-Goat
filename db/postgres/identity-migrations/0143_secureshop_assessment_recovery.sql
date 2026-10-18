-- Retained evidence is replayed only by the Judge. Every admitted retry keeps
-- its fresh execution identity; the single child retains original evidence.
CREATE TABLE secureshop_auth.assessment_retry_invocations (
 tenant_id uuid NOT NULL,principal_id uuid NOT NULL,parent_id uuid NOT NULL,
 attempt integer NOT NULL CHECK(attempt BETWEEN 1 AND 3),run_id uuid NOT NULL,
 execution_json jsonb NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,principal_id,parent_id,attempt),
 UNIQUE(tenant_id,principal_id,parent_id,run_id),
 FOREIGN KEY(tenant_id,principal_id,parent_id) REFERENCES secureshop_auth.assessment_retries(tenant_id,principal_id,parent_id)
);
CREATE TRIGGER assessment_retry_invocation_history BEFORE UPDATE OR DELETE ON secureshop_auth.assessment_retry_invocations
 FOR EACH ROW EXECUTE FUNCTION secureshop_auth.guard_assessment_history();
REVOKE ALL ON secureshop_auth.assessment_retry_invocations FROM PUBLIC;
GRANT SELECT,INSERT ON secureshop_auth.assessment_retry_invocations TO dvaia_identity_runtime;

-- Preserve the exact canonical result when a fresh provider provenance witness
-- is present. Historical normalized results remain unchanged.
ALTER TABLE secureshop_auth.assessment_judgments ADD COLUMN judge_result_json text, ADD COLUMN result_serialized text;
ALTER TABLE secureshop_auth.assessment_judgments ADD CONSTRAINT assessment_raw_judge_bound
 CHECK((judge_result_json IS NULL OR octet_length(judge_result_json)<=2097152)
   AND (result_serialized IS NULL OR octet_length(result_serialized)<=2097152));
CREATE OR REPLACE FUNCTION secureshop_auth.guard_assessment_history() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,secureshop_auth AS $$
BEGIN
 IF TG_OP='DELETE' OR TG_TABLE_NAME<>'assessment_judgments' THEN
  RAISE EXCEPTION 'Shop assessment history is immutable' USING ERRCODE='55000'; END IF;
 IF OLD.verdict IS NOT NULL OR NEW.verdict IS NULL OR
  (to_jsonb(NEW)-ARRAY['verdict','disposition','result_json','result_digest','evaluated_at','judge_observations','judge_result_json','result_serialized'])
  IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['verdict','disposition','result_json','result_digest','evaluated_at','judge_observations','judge_result_json','result_serialized']) THEN
  RAISE EXCEPTION 'Shop assessment binding is immutable' USING ERRCODE='55000'; END IF;
 RETURN NEW;
END $$;
GRANT UPDATE(judge_result_json,result_serialized) ON secureshop_auth.assessment_judgments TO dvaia_identity_runtime;
