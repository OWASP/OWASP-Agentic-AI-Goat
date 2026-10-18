-- Bounded graph outcome metadata; preserve existing event history and limits.
ALTER TABLE graph_runtime.events DROP CONSTRAINT events_metadata_keys_check;
ALTER TABLE graph_runtime.events ADD CONSTRAINT events_metadata_keys_check CHECK (
 metadata - ARRAY['decisionSource','tool','provider','model','tokens','durationMs','attempt','errorCode','validationCode','objectiveId','rubricVersion','judgeVersion','judgePolicyDigest','contextTokens','verdict','evidenceSummary','terminationReason','toolSteps'] = '{}'::jsonb
);
ALTER TABLE graph_runtime.events ADD CONSTRAINT events_termination_reason_check CHECK (
 NOT (metadata ? 'terminationReason') OR (
 jsonb_typeof(metadata->'terminationReason') = 'string' AND
 metadata->>'terminationReason' IN ('duplicate_action','tool_budget','model_finished','decision_unavailable')
 ));
ALTER TABLE graph_runtime.events ADD CONSTRAINT events_tool_steps_check CHECK (
 NOT (metadata ? 'toolSteps') OR (
 jsonb_typeof(metadata->'toolSteps') = 'number' AND
 metadata->>'toolSteps' IN ('0','1','2','3','4')
 ));
