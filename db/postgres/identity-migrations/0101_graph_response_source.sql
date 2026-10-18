-- Record response provenance separately from model-selected tool decisions.
-- Preserve existing public trace fields and limits; never store response text.
ALTER TABLE graph_runtime.events DROP CONSTRAINT events_metadata_keys_check;
ALTER TABLE graph_runtime.events ADD CONSTRAINT events_metadata_keys_check CHECK (
 metadata - ARRAY['decisionSource','tool','provider','model','tokens','durationMs','attempt','errorCode','validationCode','objectiveId','rubricVersion','judgeVersion','judgePolicyDigest','contextTokens','verdict','evidenceSummary','terminationReason','toolSteps','policyProfile','policyVersion','policyDigest','comparisonStage','reviewerProfileId','reviewerProfileVersion','reviewerPolicyDigest','policyAdmission','responseSource'] = '{}'::jsonb
);
ALTER TABLE graph_runtime.events ADD CONSTRAINT events_response_source_check CHECK (
 NOT(metadata ? 'responseSource') OR (
  jsonb_typeof(metadata->'responseSource')='string'
  AND metadata->>'responseSource' IN ('model','fixture','fallback')
 )
);
