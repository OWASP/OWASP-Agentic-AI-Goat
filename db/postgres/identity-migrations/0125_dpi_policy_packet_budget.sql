-- Preserve the original recovery budget. Only compact, typed DPI policy
-- metadata receives an additional allowance; application admission separately
-- validates the unchanged stripped semantic packet with boundedJson(24000).
CREATE FUNCTION workshop_platform.valid_dpi_policy_packet_budget(packet text) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE value jsonb; rubric jsonb; envelope jsonb; policy jsonb; extension jsonb;
 objective text; mode text; expected_lesson text; key_count integer;
BEGIN
 IF packet IS NULL OR octet_length(packet)<=24000 THEN RETURN true; END IF;
 IF octet_length(packet)>25024 THEN RETURN false; END IF;
 BEGIN value:=packet::jsonb; EXCEPTION WHEN invalid_text_representation THEN RETURN false; END;
 IF jsonb_typeof(value) IS DISTINCT FROM 'object' THEN RETURN false; END IF;
 IF NOT(value ?& ARRAY['rubric','evidence','facts']) OR (SELECT count(*) FROM jsonb_object_keys(value))<>3 THEN RETURN false; END IF;
 rubric:=value->'rubric';
 IF jsonb_typeof(rubric) IS DISTINCT FROM 'object' OR jsonb_typeof(value->'evidence') IS DISTINCT FROM 'array' THEN RETURN false; END IF;
 IF rubric->>'family' IS DISTINCT FROM 'DPI' OR rubric->>'scenario' IS DISTINCT FROM 'aws_assistant'
  OR rubric->>'dpiPolicyBinding' IS DISTINCT FROM 'dpi-policy-binding-v2' THEN RETURN false; END IF;
 IF (SELECT count(*) FROM jsonb_array_elements(value->'evidence') e WHERE e->>'id'='owned_policy')<>1 THEN RETURN false; END IF;
 SELECT e->'content' INTO envelope FROM jsonb_array_elements(value->'evidence') e
  WHERE e->>'id'='owned_policy' AND e->>'source'='server_observation';
 IF jsonb_typeof(envelope) IS DISTINCT FROM 'object' THEN RETURN false; END IF;
 IF NOT(envelope ?& ARRAY['version','objective','mode','policy','extension','legacyEvidenceSha256'])
  OR (SELECT count(*) FROM jsonb_object_keys(envelope))<>6 THEN RETURN false; END IF;
 IF envelope->>'version' IS DISTINCT FROM 'dpi-policy-binding-v2'
  OR jsonb_typeof(envelope->'objective') IS DISTINCT FROM 'string'
  OR jsonb_typeof(envelope->'mode') IS DISTINCT FROM 'string'
  OR jsonb_typeof(envelope->'legacyEvidenceSha256') IS DISTINCT FROM 'string'
  OR envelope->>'legacyEvidenceSha256' !~ '^[a-f0-9]{64}$' THEN RETURN false; END IF;
 objective:=envelope->>'objective'; mode:=envelope->>'mode';
 IF objective IS DISTINCT FROM rubric->>'objectiveId' OR mode IS DISTINCT FROM rubric->>'mode'
  OR mode NOT IN ('vuln','fixed') OR (mode='fixed' AND objective<>'obfuscation') THEN RETURN false; END IF;
 expected_lesson:=CASE objective WHEN 'interact' THEN 'aws-baseline'
  WHEN 'system_prompt' THEN 'guided-confidentiality-exception' WHEN 'jailbreak' THEN 'guided-override-exception'
  WHEN 'multi_language' THEN 'guided-language-exception' WHEN 'virtualization' THEN 'guided-hypothetical-exception'
  WHEN 'role_playing' THEN 'guided-persona-exception' WHEN 'side_stepping' THEN 'guided-scope-delegation'
  WHEN 'obfuscation' THEN 'decoder-tool-authority' ELSE NULL END;
 IF expected_lesson IS NULL THEN RETURN false; END IF;
 policy:=envelope->'policy'; extension:=envelope->'extension';
 IF jsonb_typeof(policy) IS DISTINCT FROM 'object' OR jsonb_typeof(extension) IS DISTINCT FROM 'object' THEN RETURN false; END IF;
 IF NOT(policy ?& ARRAY['version','profile','objectiveId','mode','lessonKind','policyVersion','systemPolicySha256'])
  OR policy->>'version' IS DISTINCT FROM 'dpi-policy-contract-v1'
  OR policy->>'profile' IS DISTINCT FROM 'guided' OR policy->>'policyVersion' IS DISTINCT FROM 'dpi-guided-v1'
  OR policy->>'objectiveId' IS DISTINCT FROM objective OR policy->>'mode' IS DISTINCT FROM mode
  OR policy->>'lessonKind' IS DISTINCT FROM expected_lesson
  OR jsonb_typeof(policy->'systemPolicySha256') IS DISTINCT FROM 'string'
  OR policy->>'systemPolicySha256' !~ '^[a-f0-9]{64}$' THEN RETURN false; END IF;
 -- All policy fields are strings; no JSON-null/number coercion gains admission.
 IF EXISTS(SELECT 1 FROM jsonb_each(policy) e WHERE jsonb_typeof(e.value)<>'string') THEN RETURN false; END IF;
 SELECT count(*) INTO key_count FROM jsonb_object_keys(policy);
 IF (SELECT count(*) FROM jsonb_object_keys(extension))<>1 THEN RETURN false; END IF;
 IF objective='obfuscation' THEN
  IF key_count<>9 OR NOT(policy ?& ARRAY['decisionPolicySha256','handoffPolicySha256'])
   OR policy->>'decisionPolicySha256' !~ '^[a-f0-9]{64}$' OR policy->>'handoffPolicySha256' !~ '^[a-f0-9]{64}$'
   OR NOT(extension ? 'decisionMessagesSha256') THEN RETURN false; END IF;
 ELSE
  IF key_count<>7 OR NOT(extension ? 'messagesSha256') THEN RETURN false; END IF;
 END IF;
 IF EXISTS(SELECT 1 FROM jsonb_each(extension) e WHERE jsonb_typeof(e.value)<>'string' OR e.value#>>'{}' !~ '^[a-f0-9]{64}$') THEN RETURN false; END IF;
 -- JSONB includes formatting spaces: this is an independent conservative bound
 -- on the typed envelope, not a reimplementation of JavaScript serialization.
 IF octet_length(envelope::text)>1024 THEN RETURN false; END IF;
 RETURN true;
END;
$$;
REVOKE ALL ON FUNCTION workshop_platform.valid_dpi_policy_packet_budget(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION workshop_platform.valid_dpi_policy_packet_budget(text) TO dvaia_identity_runtime;
ALTER TABLE workshop_platform.grade_packets DROP CONSTRAINT grade_packets_packet_check;
ALTER TABLE workshop_platform.grade_packets ADD CONSTRAINT grade_packets_packet_budget_check
 CHECK(workshop_platform.valid_dpi_policy_packet_budget(packet));
