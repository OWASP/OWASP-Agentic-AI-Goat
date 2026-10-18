-- Reserved identity migration 0046. Keep this draft unregistered until its
-- PostgreSQL qualification and coordinated promotion complete.
--
-- ObjectiveJudge emits only this bounded diagnostic enum. Raw model output,
-- prompts, evidence, credentials and private payloads remain forbidden from
-- graph_runtime.events.metadata.
ALTER TABLE graph_runtime.events DROP CONSTRAINT events_metadata_keys_check;
ALTER TABLE graph_runtime.events ADD CONSTRAINT events_metadata_keys_check CHECK (
 metadata - ARRAY['decisionSource','tool','provider','model','tokens','durationMs','attempt','errorCode','validationCode','objectiveId','rubricVersion','judgeVersion','judgePolicyDigest','contextTokens','verdict','evidenceSummary'] = '{}'::jsonb
);

ALTER TABLE graph_runtime.events ADD CONSTRAINT events_validation_code_check CHECK (
 NOT (metadata ? 'validationCode') OR (
  jsonb_typeof(metadata->'validationCode') = 'string'
  AND metadata->>'validationCode' IN (
   'JSON_SYNTAX',
   'SCHEMA_SHAPE_OR_TYPE',
   'EXACT_FACT_CONTRADICTION',
   'CRITERION_EVIDENCE_INVALID',
   'CITATION_NOT_GROUNDED',
   'CITATION_REQUIRED',
   'OBSERVABLE_SOURCE_REQUIRED',
   'VERDICT_INCONSISTENT',
   'REQUIRED_FACT_CONTRADICTION',
   'VALIDATION_REJECTED'
  )
 )
);
