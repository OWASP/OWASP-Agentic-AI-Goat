-- Add only the bounded public policy receipt. Arguments, persona credentials,
-- prompts and response bodies remain excluded; the existing 2048-byte cap stays.
CREATE FUNCTION graph_runtime.valid_tool_policy_trace(value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE uuid_pattern text := '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
BEGIN
 IF value IS NULL OR jsonb_typeof(value)<>'object' THEN RETURN false; END IF;
 IF (SELECT count(*) FROM jsonb_object_keys(value))<>10 OR
    NOT(value ?& ARRAY['admissionId','runId','invocationId','toolKey','policyVersion','registrySha256','enforcement','allowed','action','policyViolation']) THEN RETURN false; END IF;
 IF EXISTS(SELECT 1 FROM jsonb_each(value) e WHERE e.key=ANY(ARRAY['admissionId','runId','invocationId','toolKey','policyVersion','registrySha256','action']) AND jsonb_typeof(e.value)<>'string')
 OR jsonb_typeof(value->'allowed')<>'boolean' OR jsonb_typeof(value->'enforcement')<>'boolean' THEN RETURN false; END IF;
 IF value->>'admissionId' !~ uuid_pattern OR value->>'runId' !~ uuid_pattern
 OR value->>'invocationId' !~ '^[1-9][0-9]*:[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$' OR length(value->>'invocationId')>256
 OR value->>'toolKey' !~ '^[a-z][a-z0-9-]*\.[a-z][a-z0-9_]*$' OR length(value->>'toolKey')>160
 OR value->>'policyVersion' !~ '^[1-9][0-9]{0,18}$'
 OR value->>'registrySha256' !~ '^[a-f0-9]{64}$' THEN RETURN false; END IF;
 IF (value->>'policyVersion')::numeric>9223372036854775807 THEN RETURN false; END IF;
 RETURN value->>'action'=CASE WHEN (value->>'allowed')::boolean OR NOT (value->>'enforcement')::boolean THEN 'dispatch' ELSE 'block' END
 AND value->'policyViolation'=CASE WHEN (value->>'allowed')::boolean THEN 'null'::jsonb ELSE '"denied-by-acl"'::jsonb END;
END;
$$;
REVOKE ALL ON FUNCTION graph_runtime.valid_tool_policy_trace(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION graph_runtime.valid_tool_policy_trace(jsonb) TO dvaia_identity_runtime;
ALTER TABLE graph_runtime.events DROP CONSTRAINT events_metadata_keys_check;
ALTER TABLE graph_runtime.events ADD CONSTRAINT events_metadata_keys_check CHECK (
 metadata - ARRAY['decisionSource','tool','provider','model','tokens','durationMs','attempt','errorCode','validationCode','objectiveId','rubricVersion','judgeVersion','judgePolicyDigest','contextTokens','verdict','evidenceSummary','terminationReason','toolSteps','policyProfile','policyVersion','policyDigest','comparisonStage','reviewerProfileId','reviewerProfileVersion','reviewerPolicyDigest','policyAdmission'] = '{}'::jsonb
);
ALTER TABLE graph_runtime.events DROP CONSTRAINT events_metadata_values_check;
ALTER TABLE graph_runtime.events ADD CONSTRAINT events_metadata_values_check CHECK (
 graph_runtime.valid_trace_values(metadata-'policyAdmission') AND
 (NOT(metadata ? 'policyAdmission') OR graph_runtime.valid_tool_policy_trace(metadata->'policyAdmission'))
);
ALTER TABLE graph_runtime.events ADD CONSTRAINT events_tool_policy_run_check CHECK (
 NOT(metadata ? 'policyAdmission') OR metadata#>>'{policyAdmission,runId}'=run_id::text
);
