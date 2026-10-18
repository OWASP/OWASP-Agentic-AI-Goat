-- Forward-only correction to the Stage 6 decision matcher: disambiguate JSONB subtraction.
-- Preserve 0129 as applied; all other matcher predicates and existing receipts are unchanged.
CREATE OR REPLACE FUNCTION identity.ctf_decision_document_matches(e jsonb) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE j jsonb; profile jsonb; checked jsonb;
BEGIN
 profile:=e->'guardian'->'reviewerProfile';checked:=e;
 IF profile IS NOT NULL THEN checked:=jsonb_set(e,'{guardian}',(e->'guardian') - 'reviewerProfile'); END IF;
 IF NOT identity.ctf_json_matches(checked,'{"type":"object","properties":{"version":{"type":"number","enum":[1]},"binding":{"type":"object","properties":{"ownerId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"sessionId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"admissionId":{"type":"string","bytes":36,"pattern":"^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$"},"runId":{"type":"string","bytes":36,"pattern":"^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$"},"ownerGeneration":{"type":"string","bytes":19,"pattern":"^(0|[1-9][0-9]*)$","minimum":0,"maximum":"9223372036854775807"},"globalRevision":{"type":"string","bytes":19,"pattern":"^(0|[1-9][0-9]*)$","minimum":0,"maximum":"9223372036854775807"},"stageRevision":{"type":"string","bytes":19,"pattern":"^(0|[1-9][0-9]*)$","minimum":0,"maximum":"9223372036854775807"},"participantId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"progressId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"stageId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"stageNumber":{"type":"number","minimum":1,"maximum":2147483647,"integer":true},"stageDigest":{"type":"string","bytes":64,"pattern":"^[a-f0-9]{64}$"}}},"payload":{"type":"string","bytes":16384},"normalizedPayload":{"type":"string","bytes":16384,"pattern":"^[a-z0-9_ ]*$"},"payloadHash":{"type":"string","bytes":64,"pattern":"^[a-f0-9]{64}$"},"visibleResponse":{"type":"string","bytes":16384},"observedSecret":{"type":"boolean"},"techniqueTag":{"type":"string","bytes":128},"guardian":{"type":"object","properties":{"version":{"type":"string","enum":["ctf-guardian-provenance-v1"]},"provider":{"type":"string","enum":["ollama","anthropic","claude","openai","chatgpt","bedrock","lmstudio"]},"model":{"type":"string","bytes":256,"pattern":"."},"rawResponseSha256":{"type":"string","bytes":64,"pattern":"^[a-f0-9]{64}$"},"visibleResponseSha256":{"type":"string","bytes":64,"pattern":"^[a-f0-9]{64}$"},"rawResponseBytes":{"type":"number","minimum":1,"maximum":1048576,"integer":true},"visibleResponseBytes":{"type":"number","minimum":0,"maximum":16384,"integer":true}},"nullable":true},"judgment":{"type":"object","properties":{"verdict":{"type":"string","enum":["pass","fail","inconclusive","unavailable","blocked"]},"provider":{"type":"string","bytes":128,"nullable":true},"model":{"type":"string","bytes":256,"nullable":true},"judgeVersion":{"type":"string","bytes":256,"nullable":true},"rubricVersion":{"type":"string","enum":["ctf-visible-secret-v2"]},"receiptHash":{"type":"string","bytes":64,"pattern":"^[a-f0-9]{64}$"}}},"judgeReceipt":{"type":"string","bytes":24576}}}'::jsonb) THEN RETURN false; END IF;
 IF e->>'payloadHash' IS DISTINCT FROM encode(sha256(convert_to(e->>'normalizedPayload','UTF8')),'hex')
 OR e->'judgment'->>'receiptHash' IS DISTINCT FROM encode(sha256(convert_to(e->>'judgeReceipt','UTF8')),'hex')
 OR NOT ((e->>'judgeReceipt') IS JSON OBJECT WITH UNIQUE KEYS) THEN RETURN false; END IF;
 j:=(e->>'judgeReceipt')::jsonb;
 IF profile IS NOT NULL THEN
  IF e->'binding'->>'stageNumber' IS DISTINCT FROM '6'
   OR profile IS DISTINCT FROM '{"id":"ctf-stage6-learner-claimed-rotation-handoff","version":"rotation-handoff-v1","policyDigest":"ec4d475c82c25daf344f51b7b375da33142c4bdbf7816e097a6c294e5086812a"}'::jsonb
   OR j->'reviewerProfile' IS DISTINCT FROM profile THEN RETURN false; END IF;
 ELSIF j ? 'reviewerProfile' THEN RETURN false; END IF;
 IF (j->'verdict') IS DISTINCT FROM e->'judgment'->'verdict' OR (j->'rubricVersion') IS DISTINCT FROM e->'judgment'->'rubricVersion'
 OR COALESCE(j->'provider','null'::jsonb) IS DISTINCT FROM e->'judgment'->'provider'
 OR COALESCE(j->'model','null'::jsonb) IS DISTINCT FROM e->'judgment'->'model'
 OR COALESCE(j->'judgeVersion','null'::jsonb) IS DISTINCT FROM e->'judgment'->'judgeVersion' THEN RETURN false; END IF;
 IF e->'guardian'='null'::jsonb THEN RETURN e->'observedSecret'='false'::jsonb AND e->'judgment'->>'verdict'<>'pass'; END IF;
 RETURN (e->'guardian'->>'visibleResponseSha256'=encode(sha256(convert_to(e->>'visibleResponse','UTF8')),'hex')
 AND (e->'guardian'->>'visibleResponseBytes')::integer=octet_length(e->>'visibleResponse')) IS TRUE;
END; $$;
