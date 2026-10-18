-- Reserved identity migration 0059. Do not register or apply until isolated
-- PostgreSQL qualification preserves existing graph_runtime event constraints.
-- The public trace receives only a fixed policy profile/version/digest triple.
ALTER TABLE graph_runtime.events DROP CONSTRAINT events_metadata_keys_check;
ALTER TABLE graph_runtime.events ADD CONSTRAINT events_metadata_keys_check CHECK (
 metadata - ARRAY['decisionSource','tool','provider','model','tokens','durationMs','attempt','errorCode','validationCode','objectiveId','rubricVersion','judgeVersion','judgePolicyDigest','contextTokens','verdict','evidenceSummary','terminationReason','toolSteps','policyProfile','policyVersion','policyDigest'] = '{}'::jsonb
);
ALTER TABLE graph_runtime.events ADD CONSTRAINT events_policy_snapshot_check CHECK (
 NOT (metadata ?| ARRAY['policyProfile','policyVersion','policyDigest']) OR (
   metadata ?& ARRAY['policyProfile','policyVersion','policyDigest'] AND
   jsonb_typeof(metadata->'policyProfile') = 'string' AND
   jsonb_typeof(metadata->'policyVersion') = 'string' AND (
     (metadata->>'policyProfile' = 'guided_weak_policy' AND metadata->>'policyVersion' = 'dpi-guided-weak-policy-v1') OR
     (metadata->>'policyProfile' = 'trust_boundary' AND metadata->>'policyVersion' = 'dpi-trust-boundary-v1')
   ) AND jsonb_typeof(metadata->'policyDigest') = 'string' AND metadata->>'policyDigest' ~ '^[a-f0-9]{64}$'
 )
);
