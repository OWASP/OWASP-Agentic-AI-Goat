-- Preserve bounded objective-Judge stage identity and the exact known CTF
-- reviewer profile. No prompt, response, citation, or protected reference is
-- admitted to the durable graph trace.
ALTER TABLE graph_runtime.events DROP CONSTRAINT events_metadata_keys_check;
ALTER TABLE graph_runtime.events ADD CONSTRAINT events_metadata_keys_check CHECK (
 metadata - ARRAY['decisionSource','tool','provider','model','tokens','durationMs','attempt','errorCode','validationCode','objectiveId','rubricVersion','judgeVersion','judgePolicyDigest','contextTokens','verdict','evidenceSummary','terminationReason','toolSteps','policyProfile','policyVersion','policyDigest','comparisonStage','reviewerProfileId','reviewerProfileVersion','reviewerPolicyDigest'] = '{}'::jsonb
);
ALTER TABLE graph_runtime.events ADD CONSTRAINT events_reviewer_profile_check CHECK (
 NOT (metadata ?| ARRAY['reviewerProfileId','reviewerProfileVersion','reviewerPolicyDigest']) OR (
   metadata ?& ARRAY['reviewerProfileId','reviewerProfileVersion','reviewerPolicyDigest'] AND
   jsonb_typeof(metadata->'reviewerProfileId') = 'string' AND
   metadata->>'reviewerProfileId' = 'ctf-stage5-learner-claimed-telemetry' AND
   jsonb_typeof(metadata->'reviewerProfileVersion') = 'string' AND
   metadata->>'reviewerProfileVersion' = 'structured-artifact-v1' AND
   jsonb_typeof(metadata->'reviewerPolicyDigest') = 'string' AND
   metadata->>'reviewerPolicyDigest' ~ '^[a-f0-9]{64}$'
 )
);
ALTER TABLE graph_runtime.events ADD CONSTRAINT events_comparison_stage_check CHECK (
 NOT (metadata ? 'comparisonStage') OR (
   jsonb_typeof(metadata->'comparisonStage') = 'string' AND
   metadata->>'comparisonStage' IN ('source','effect','support')
 )
);
