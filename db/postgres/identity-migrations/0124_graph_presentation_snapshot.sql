-- Content-free presentation provenance. Preserve all prior trace constraints,
-- including the 2048-byte ceiling for all preexisting metadata. Only the
-- schema-validated presentation envelope receives a separate bounded allowance.
CREATE FUNCTION graph_runtime.valid_presentation_snapshot(value jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE item jsonb; ordinal bigint; effect_key text; seen text[] := ARRAY[]::text[];
BEGIN
 IF value IS NULL OR jsonb_typeof(value)<>'object' THEN RETURN false; END IF;
 IF (SELECT count(*) FROM jsonb_object_keys(value))<>6
  OR NOT(value ?& ARRAY['version','narrativeSource','errorCode','narrativeSha256','responseSha256','blocks']) THEN RETURN false; END IF;
 IF jsonb_typeof(value->'version')<>'string'
  OR jsonb_typeof(value->'narrativeSource')<>'string'
  OR jsonb_typeof(value->'narrativeSha256')<>'string'
  OR jsonb_typeof(value->'responseSha256')<>'string'
  OR jsonb_typeof(value->'blocks')<>'array' THEN RETURN false; END IF;
 IF value->>'version'<>'workshop-result-presentation-v1'
  OR value->>'narrativeSource' NOT IN ('model','fixture','unavailable')
  OR value->>'narrativeSha256' !~ '^[a-f0-9]{64}$'
  OR value->>'responseSha256' !~ '^[a-f0-9]{64}$' THEN RETURN false; END IF;
 IF value->'errorCode'<>'null'::jsonb AND (
  jsonb_typeof(value->'errorCode')<>'string'
  OR value->>'errorCode' NOT IN ('MODEL_OUTPUT_LIMIT','MODEL_RESPONSE_UNAVAILABLE','MODEL_RESPONSE_ERROR')
 ) THEN RETURN false; END IF;
 IF jsonb_array_length(value->'blocks')>4 THEN RETURN false; END IF;
 FOR item,ordinal IN SELECT e.value,e.ordinality FROM jsonb_array_elements(value->'blocks') WITH ORDINALITY AS e(value,ordinality) LOOP
  IF jsonb_typeof(item)<>'object' THEN RETURN false; END IF;
  IF (SELECT count(*) FROM jsonb_object_keys(item))<>5
   OR NOT(item ?& ARRAY['index','tool','effectKey','resultSha256','displaySha256']) THEN RETURN false; END IF;
  IF jsonb_typeof(item->'index')<>'number'
   OR jsonb_typeof(item->'tool')<>'string'
   OR jsonb_typeof(item->'effectKey')<>'string'
   OR jsonb_typeof(item->'resultSha256')<>'string'
   OR jsonb_typeof(item->'displaySha256')<>'string' THEN RETURN false; END IF;
  IF (item->>'index')::numeric<>ordinal-1
   OR item->>'tool' !~ '^[a-z][a-z0-9_]{0,127}$'
   OR item->>'resultSha256' !~ '^[a-f0-9]{64}$'
   OR item->>'displaySha256' !~ '^[a-f0-9]{64}$' THEN RETURN false; END IF;
  effect_key:=item->>'effectKey';
  -- Match JavaScript String.length (UTF-16 units), not code-point length.
  IF length(effect_key)=0 OR (SELECT sum(CASE WHEN ascii(c)>65535 THEN 2 ELSE 1 END) FROM regexp_split_to_table(effect_key,'') AS chars(c))>512
   OR effect_key ~ ('['||chr(1)||'-'||chr(31)||chr(127)||']')
   OR effect_key=ANY(seen) THEN RETURN false; END IF;
  seen:=array_append(seen,effect_key);
 END LOOP;
 RETURN true;
END;
$$;
REVOKE ALL ON FUNCTION graph_runtime.valid_presentation_snapshot(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION graph_runtime.valid_presentation_snapshot(jsonb) TO dvaia_identity_runtime;
ALTER TABLE graph_runtime.events DROP CONSTRAINT events_metadata_keys_check;
ALTER TABLE graph_runtime.events ADD CONSTRAINT events_metadata_keys_check CHECK (
 metadata - ARRAY['decisionSource','tool','provider','model','tokens','durationMs','attempt','errorCode','validationCode','objectiveId','rubricVersion','judgeVersion','judgePolicyDigest','contextTokens','verdict','evidenceSummary','terminationReason','toolSteps','policyProfile','policyVersion','policyDigest','comparisonStage','reviewerProfileId','reviewerProfileVersion','reviewerPolicyDigest','policyAdmission','responseSource','promptPolicySnapshot','presentationSnapshot'] = '{}'::jsonb
);
ALTER TABLE graph_runtime.events DROP CONSTRAINT events_metadata_values_check;
ALTER TABLE graph_runtime.events ADD CONSTRAINT events_metadata_values_check CHECK (
 graph_runtime.valid_trace_values(metadata-ARRAY['policyAdmission','promptPolicySnapshot','presentationSnapshot'])
 AND (NOT(metadata ? 'policyAdmission') OR graph_runtime.valid_tool_policy_trace(metadata->'policyAdmission'))
 AND (NOT(metadata ? 'promptPolicySnapshot') OR graph_runtime.valid_prompt_policy_snapshot(metadata->'promptPolicySnapshot'))
 AND (NOT(metadata ? 'presentationSnapshot') OR graph_runtime.valid_presentation_snapshot(metadata->'presentationSnapshot'))
);
-- Four supported observations with a 128-character idempotency prefix exceed
-- 2048 bytes. Four 512-UTF16-unit keys (at most 1536 UTF8 bytes each), bounded
-- tools/digests and fixed JSON structure fit within 8192 bytes. Neither raw
-- content nor an oversized ordinary event gains admission through this branch.
ALTER TABLE graph_runtime.events DROP CONSTRAINT events_metadata_check2;
ALTER TABLE graph_runtime.events ADD CONSTRAINT events_metadata_size_check CHECK (
 octet_length((metadata-'presentationSnapshot')::text)<=2048
 AND (NOT(metadata ? 'presentationSnapshot') OR (
  graph_runtime.valid_presentation_snapshot(metadata->'presentationSnapshot')
  AND octet_length((metadata->'presentationSnapshot')::text)<=8192
 ))
 AND octet_length(metadata::text)<=10240
);
