-- Bounded policy provenance only. Policy text and credentials remain excluded.
CREATE FUNCTION graph_runtime.valid_prompt_policy_snapshot(value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
BEGIN
 IF value IS NULL OR jsonb_typeof(value)<>'object' THEN RETURN false; END IF;
 IF (SELECT count(*) FROM jsonb_object_keys(value))<>4
  OR NOT(value ?& ARRAY['policyCount','policyVersion','role','sha256']) THEN RETURN false; END IF;
 IF jsonb_typeof(value->'policyVersion')<>'string'
  OR jsonb_typeof(value->'role')<>'string'
  OR jsonb_typeof(value->'sha256')<>'string'
  OR jsonb_typeof(value->'policyCount')<>'number' THEN RETURN false; END IF;
 IF value->>'policyVersion' !~ '^[1-9][0-9]{0,18}$'
  OR value->>'sha256' !~ '^[a-f0-9]{64}$'
  OR value->>'role' NOT IN ('customer','merchant','admin') THEN RETURN false; END IF;
 RETURN (value->>'policyVersion')::numeric<=9223372036854775807
  AND (value->>'policyCount')::numeric BETWEEN 0 AND 32
  AND trunc((value->>'policyCount')::numeric)=(value->>'policyCount')::numeric;
END;
$$;
REVOKE ALL ON FUNCTION graph_runtime.valid_prompt_policy_snapshot(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION graph_runtime.valid_prompt_policy_snapshot(jsonb) TO dvaia_identity_runtime;
ALTER TABLE graph_runtime.events DROP CONSTRAINT events_metadata_keys_check;
ALTER TABLE graph_runtime.events ADD CONSTRAINT events_metadata_keys_check CHECK (
 metadata - ARRAY['decisionSource','tool','provider','model','tokens','durationMs','attempt','errorCode','validationCode','objectiveId','rubricVersion','judgeVersion','judgePolicyDigest','contextTokens','verdict','evidenceSummary','terminationReason','toolSteps','policyProfile','policyVersion','policyDigest','comparisonStage','reviewerProfileId','reviewerProfileVersion','reviewerPolicyDigest','policyAdmission','responseSource','promptPolicySnapshot'] = '{}'::jsonb
);
ALTER TABLE graph_runtime.events DROP CONSTRAINT events_metadata_values_check;
ALTER TABLE graph_runtime.events ADD CONSTRAINT events_metadata_values_check CHECK (
 graph_runtime.valid_trace_values(metadata-ARRAY['policyAdmission','promptPolicySnapshot'])
 AND (NOT(metadata ? 'policyAdmission') OR graph_runtime.valid_tool_policy_trace(metadata->'policyAdmission'))
 AND (NOT(metadata ? 'promptPolicySnapshot') OR graph_runtime.valid_prompt_policy_snapshot(metadata->'promptPolicySnapshot'))
);
