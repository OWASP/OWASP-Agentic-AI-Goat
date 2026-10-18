-- Forward-only Stage 6 reviewer profile binding. Historical migrations and receipts are immutable.
-- Stage 6 binds one exact versioned reviewer policy to the immutable stage snapshot.
-- Historical and instructor-owned stages without this layer retain their prior shape.
CREATE FUNCTION identity.ctf_stage6_reviewer_profile_valid(stage jsonb) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE layers jsonb; profile jsonb:=stage->'__ctf_reviewer_profile'; selected boolean:=false;
BEGIN
 BEGIN layers:=(stage->>'defense_style')::jsonb; EXCEPTION WHEN others THEN RETURN profile IS NULL; END;
 IF jsonb_typeof(layers)='array' THEN
  SELECT EXISTS(SELECT 1 FROM jsonb_array_elements_text(layers) AS item(layer) WHERE item.layer='meta_rotation_handoff_reviewer_v1') INTO selected;
 END IF;
 IF selected THEN
  RETURN (stage->>'stage_number'='6' AND profile IS NOT DISTINCT FROM
   '{"id":"ctf-stage6-learner-claimed-rotation-handoff","version":"rotation-handoff-v1","policyDigest":"ec4d475c82c25daf344f51b7b375da33142c4bdbf7816e097a6c294e5086812a"}'::jsonb) IS TRUE;
 END IF;
 RETURN profile IS NULL;
END; $$;
REVOKE ALL ON FUNCTION identity.ctf_stage6_reviewer_profile_valid(jsonb) FROM PUBLIC;

CREATE OR REPLACE FUNCTION identity.claim_ctf_predefense(p_actor integer,p_session integer,p_token_hash text,p_document text,p_hash text,p_snapshot text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE e jsonb;b jsonb;prior identity.ctf_predefense_claims%ROWTYPE;ad jsonb;pair jsonb;k text;previous_key text;stage jsonb:='{}'::jsonb;
BEGIN
 IF p_document IS NULL OR octet_length(p_document)>32768 OR NOT(p_document IS JSON OBJECT WITH UNIQUE KEYS) OR p_hash IS DISTINCT FROM encode(sha256(convert_to(p_document,'UTF8')),'hex')
 OR p_snapshot IS NULL OR octet_length(p_snapshot)>65536 OR NOT(p_snapshot IS JSON ARRAY WITH UNIQUE KEYS) THEN RAISE EXCEPTION 'CTF pre-defense bytes invalid'; END IF;
 e:=p_document::jsonb;b:=e->'binding';
 IF NOT identity.ctf_predefense_input_matches(e) OR e->>'payloadHash' IS DISTINCT FROM encode(sha256(convert_to(e->>'normalizedPayload','UTF8')),'hex') OR b->>'stageDigest' IS DISTINCT FROM encode(sha256(convert_to(p_snapshot,'UTF8')),'hex') THEN RAISE EXCEPTION 'CTF pre-defense input invalid'; END IF;
 FOR pair IN SELECT value FROM jsonb_array_elements(p_snapshot::jsonb) LOOP
  IF jsonb_typeof(pair) IS DISTINCT FROM 'array' OR jsonb_array_length(pair)<>2 OR jsonb_typeof(pair->0) IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'CTF pre-defense stage pairs invalid'; END IF;
  k:=pair->>0;
  IF NOT(k=ANY(ARRAY['id','stage_number','stage_name','stage_description','difficulty_level','ai_guardian_name','ai_guardian_personality','system_prompt','success_criteria','hints','max_attempts','time_penalty_per_wrong_attempt','is_active','stage_order','difficulty','defense_style','adaptive_mode','level_score','time_bonus_seconds','feedback_mode','created_at','__ctf_reviewer_profile'])) OR (previous_key IS NOT NULL AND k COLLATE "C"<=previous_key COLLATE "C") THEN RAISE EXCEPTION 'CTF pre-defense stage keys invalid'; END IF;
  previous_key:=k;stage:=stage||jsonb_build_object(k,pair->1);
 END LOOP;
 IF identity.ctf_stage6_reviewer_profile_valid(stage) IS NOT TRUE THEN RAISE EXCEPTION 'CTF Stage 6 reviewer profile snapshot invalid'; END IF;
 IF stage->>'id' IS DISTINCT FROM b->>'stageId' THEN RAISE EXCEPTION 'CTF pre-defense stage identity invalid'; END IF;
 PERFORM identity.lock_ctf_predefense(p_actor,p_session,p_token_hash,b,false);
 SELECT * INTO prior FROM identity.ctf_predefense_claims cc WHERE cc.run_id=(b->>'runId')::uuid;
 IF FOUND THEN
  IF prior.canonical_input IS DISTINCT FROM p_document OR prior.stage_snapshot IS DISTINCT FROM p_snapshot THEN RAISE EXCEPTION 'CTF pre-defense replay conflict'; END IF;
  RETURN jsonb_build_object('claimed',false,'currentState',false,'runId',prior.run_id,'admissionOperationId',prior.admission_operation_id,'blockedOperationId',prior.blocked_operation_id,'initialAdaptive',prior.initial_adaptive,'outcome',(SELECT oo.outcome FROM identity.ctf_predefense_outcomes oo WHERE oo.run_id=prior.run_id),'consumption',(SELECT to_jsonb(cc) FROM identity.ctf_predefense_consumptions cc WHERE cc.run_id=prior.run_id));
 END IF;
 PERFORM identity.lock_ctf_predefense(p_actor,p_session,p_token_hash,b,true);
 ad:=identity.ctf_predefense_adaptive(e);
 INSERT INTO identity.ctf_predefense_claims(run_id,owner_id,session_id,canonical_input,input_hash,input,stage_snapshot,initial_adaptive) VALUES((b->>'runId')::uuid,p_actor,p_session,p_document,p_hash,e,p_snapshot,ad) RETURNING * INTO prior;
 RETURN jsonb_build_object('claimed',true,'currentState',false,'runId',prior.run_id,'admissionOperationId',prior.admission_operation_id,'blockedOperationId',prior.blocked_operation_id,'initialAdaptive',ad,'outcome',NULL,'consumption',NULL);
END; $$;

CREATE OR REPLACE FUNCTION identity.claim_ctf_projection_input(p_actor integer,p_session integer,p_token_hash text,p_document text,p_hash text,p_stage_snapshot text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE e jsonb; pairs jsonb;pair jsonb;stage jsonb:='{}'::jsonb;k text;previous_key text;answer jsonb;prior identity.ctf_projection_context%ROWTYPE;
BEGIN
 IF p_document IS NULL OR NOT(p_document IS JSON OBJECT WITH UNIQUE KEYS) OR octet_length(p_document)>32768
 OR p_stage_snapshot IS NULL OR octet_length(p_stage_snapshot)>65536 OR NOT(p_stage_snapshot IS JSON ARRAY WITH UNIQUE KEYS) THEN RAISE EXCEPTION 'CTF projection context invalid'; END IF;
 e:=p_document::jsonb;pairs:=p_stage_snapshot::jsonb;
 IF encode(sha256(convert_to(p_stage_snapshot,'UTF8')),'hex') IS DISTINCT FROM e->'binding'->>'stageDigest' THEN RAISE EXCEPTION 'CTF stage snapshot digest mismatch'; END IF;
 FOR pair IN SELECT value FROM jsonb_array_elements(pairs) LOOP
  IF jsonb_typeof(pair) IS DISTINCT FROM 'array' OR jsonb_array_length(pair)<>2 OR jsonb_typeof(pair->0) IS DISTINCT FROM 'string' THEN RAISE EXCEPTION 'CTF stage snapshot pairs invalid'; END IF;
  k:=pair->>0;
  IF NOT(k=ANY(ARRAY['id','stage_number','stage_name','stage_description','difficulty_level','ai_guardian_name','ai_guardian_personality','system_prompt','success_criteria','hints','max_attempts','time_penalty_per_wrong_attempt','is_active','stage_order','difficulty','defense_style','adaptive_mode','level_score','time_bonus_seconds','feedback_mode','created_at','__ctf_reviewer_profile']))
  OR (previous_key IS NOT NULL AND k COLLATE "C"<=previous_key COLLATE "C") THEN RAISE EXCEPTION 'CTF stage snapshot keys invalid'; END IF;
  previous_key:=k;stage:=stage||jsonb_build_object(k,pair->1);
 END LOOP;
 IF identity.ctf_stage6_reviewer_profile_valid(stage) IS NOT TRUE THEN RAISE EXCEPTION 'CTF Stage 6 reviewer profile snapshot invalid'; END IF;
 IF NOT identity.ctf_json_matches(stage->'stage_name','{"type":"string","bytes":1024}'::jsonb)
 OR NOT identity.ctf_json_matches(stage->'adaptive_mode','{"type":"string","enum":["none","technique","payload","hybrid"]}'::jsonb)
 OR NOT identity.ctf_json_matches(stage->'level_score','{"type":"number","integer":true,"minimum":0,"maximum":1000000,"nullable":true}'::jsonb)
 OR (stage->>'id') IS DISTINCT FROM e->'binding'->>'stageId' OR (stage->>'stage_number') IS DISTINCT FROM e->'binding'->>'stageNumber' THEN RAISE EXCEPTION 'CTF stage snapshot projection fields invalid'; END IF;
 -- Existing function authenticates original admitted session, takes the user
 -- row lock and atomically inserts the durable at-most-once inference claim.
 answer:=identity.capture_ctf_decision_input(p_actor,p_session,p_token_hash,p_document,p_hash);
 SELECT * INTO prior FROM identity.ctf_projection_context pc WHERE pc.admission_id=(e->'binding'->>'admissionId')::uuid;
 IF FOUND THEN
  IF prior.stage_snapshot IS DISTINCT FROM p_stage_snapshot THEN RAISE EXCEPTION 'CTF projection context replay mismatch'; END IF;
 ELSE
  IF answer->'claimed' IS DISTINCT FROM 'true'::jsonb THEN RAISE EXCEPTION 'CTF historical input requires explicit recovery'; END IF;
  INSERT INTO identity.ctf_projection_context VALUES((e->'binding'->>'admissionId')::uuid,p_stage_snapshot,e->'binding'->>'stageDigest',stage->>'stage_name',stage->>'adaptive_mode',(stage->>'level_score')::integer);
 END IF;
 RETURN answer;
END; $$;

CREATE OR REPLACE FUNCTION identity.ctf_decision_document_matches(e jsonb) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE j jsonb; profile jsonb; checked jsonb;
BEGIN
 profile:=e->'guardian'->'reviewerProfile';checked:=e;
 IF profile IS NOT NULL THEN checked:=jsonb_set(e,'{guardian}',e->'guardian'-'reviewerProfile'); END IF;
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

CREATE OR REPLACE FUNCTION identity.stage_ctf_server_proposal(p_proposal uuid,p_actor integer,p_session integer,p_token_hash text,p_document text,p_hash text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE e jsonb;b jsonb;stage_snapshot text;snapshot_stage jsonb;expected_profile jsonb;a identity.ctf_attempt_admissions%ROWTYPE;r graph_runtime.runs%ROWTYPE;prior identity.ctf_decision_proposals%ROWTYPE;
BEGIN
 IF p_document IS NULL OR octet_length(p_document)>65536 OR NOT(p_document IS JSON OBJECT WITH UNIQUE KEYS)
 OR p_hash IS DISTINCT FROM encode(sha256(convert_to(p_document,'UTF8')),'hex') THEN RAISE EXCEPTION 'CTF proposal bytes invalid'; END IF;
 e:=p_document::jsonb;b:=e->'binding';
 SELECT pc.stage_snapshot INTO stage_snapshot FROM identity.ctf_projection_context pc WHERE pc.admission_id=(b->>'admissionId')::uuid;
 IF stage_snapshot IS NULL AND e->'guardian'->'reviewerProfile' IS NOT NULL THEN RAISE EXCEPTION 'CTF reviewer profile context missing'; END IF;
 IF stage_snapshot IS NOT NULL THEN
  SELECT jsonb_object_agg(item.pair->>0,item.pair->1) INTO snapshot_stage FROM jsonb_array_elements(stage_snapshot::jsonb) AS item(pair);
  IF identity.ctf_stage6_reviewer_profile_valid(snapshot_stage) IS NOT TRUE THEN RAISE EXCEPTION 'CTF reviewer profile context invalid'; END IF;
  expected_profile:=snapshot_stage->'__ctf_reviewer_profile';
  IF e->'guardian'<>'null'::jsonb AND e->'guardian'->'reviewerProfile' IS DISTINCT FROM expected_profile THEN RAISE EXCEPTION 'CTF reviewer profile evidence mismatch'; END IF;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM identity.ctf_decision_inputs di WHERE di.admission_id=(b->>'admissionId')::uuid AND di.owner_id=p_actor AND di.session_id=p_session AND di.input->'binding'=b AND di.input->'payload'=e->'payload' AND di.input->'techniqueTag'=e->'techniqueTag' AND di.input->'normalizedPayload'=e->'normalizedPayload' AND di.input->'payloadHash'=e->'payloadHash') THEN RAISE EXCEPTION 'CTF proposal input mismatch'; END IF;
 IF NOT identity.ctf_decision_document_matches(e) THEN RAISE EXCEPTION 'CTF proposal schema invalid'; END IF;
 IF (b->>'ownerId')::integer IS DISTINCT FROM p_actor OR (b->>'sessionId')::integer IS DISTINCT FROM p_session THEN RAISE EXCEPTION 'CTF proposal actor mismatch'; END IF;
 PERFORM 1 FROM identity.users WHERE id=p_actor FOR UPDATE;
 PERFORM 1 FROM identity.user_sessions WHERE id=p_session AND user_id=p_actor FOR UPDATE;
 IF NOT EXISTS(SELECT 1 FROM identity.users u JOIN identity.user_sessions s ON s.user_id=u.id WHERE u.id=p_actor AND s.id=p_session AND u.is_active=1 AND (u.account_locked_until IS NULL OR u.account_locked_until<=clock_timestamp()) AND s.is_active=1 AND s.expires_at>clock_timestamp() AND s.session_token_hash=p_token_hash)
 OR EXISTS(SELECT 1 FROM identity.student_deletion_jobs WHERE subject_user_id=p_actor)
 OR EXISTS(SELECT 1 FROM identity.student_deletion_run_blocks WHERE owner_key='["CTF","'||p_actor||'"]') THEN RAISE EXCEPTION 'SESSION_REVOKED' USING ERRCODE='28000'; END IF;
 SELECT * INTO prior FROM identity.ctf_decision_proposals WHERE proposal_id=p_proposal;
 IF FOUND THEN IF prior.owner_id<>p_actor OR prior.session_id<>p_session OR prior.evidence_hash<>p_hash OR prior.canonical_evidence<>p_document THEN RAISE EXCEPTION 'CTF proposal replay conflict'; END IF;RETURN p_proposal;END IF;
 SELECT * INTO a FROM identity.ctf_attempt_admissions WHERE operation_id=(b->>'admissionId')::uuid;
 SELECT * INTO r FROM graph_runtime.runs WHERE run_id=(b->>'runId')::uuid;
 IF a.owner_id IS DISTINCT FROM p_actor OR a.owner_generation IS DISTINCT FROM (b->>'ownerGeneration')::bigint OR a.participant_id IS DISTINCT FROM (b->>'participantId')::bigint OR a.progress_id IS DISTINCT FROM (b->>'progressId')::bigint OR a.stage_id IS DISTINCT FROM (b->>'stageId')::bigint
 OR r.owner_key IS DISTINCT FROM '["CTF","'||p_actor||'"]' OR r.generation IS DISTINCT FROM a.owner_generation OR r.status IS DISTINCT FROM 'running' THEN RAISE EXCEPTION 'CTF proposal admission mismatch'; END IF;
 INSERT INTO identity.ctf_decision_proposals VALUES(p_proposal,r.run_id,a.operation_id,p_actor,p_session,p_document,p_hash,e,clock_timestamp());
 RETURN p_proposal;
END; $$;

-- Keep protected text out of trace metadata. Stage 5 remains valid unchanged.
ALTER TABLE graph_runtime.events DROP CONSTRAINT events_reviewer_profile_check;
ALTER TABLE graph_runtime.events ADD CONSTRAINT events_reviewer_profile_check CHECK (
 NOT (metadata ?| ARRAY['reviewerProfileId','reviewerProfileVersion','reviewerPolicyDigest']) OR (
  metadata ?& ARRAY['reviewerProfileId','reviewerProfileVersion','reviewerPolicyDigest'] AND
  jsonb_typeof(metadata->'reviewerProfileId')='string' AND
  jsonb_typeof(metadata->'reviewerProfileVersion')='string' AND
  jsonb_typeof(metadata->'reviewerPolicyDigest')='string' AND (
   (metadata->>'reviewerProfileId'='ctf-stage5-learner-claimed-telemetry' AND metadata->>'reviewerProfileVersion'='structured-artifact-v1' AND metadata->>'reviewerPolicyDigest' ~ '^[a-f0-9]{64}$') OR
   (metadata->>'reviewerProfileId'='ctf-stage6-learner-claimed-rotation-handoff' AND metadata->>'reviewerProfileVersion'='rotation-handoff-v1' AND metadata->>'reviewerPolicyDigest'='ec4d475c82c25daf344f51b7b375da33142c4bdbf7816e097a6c294e5086812a')
  )
 )
);
ALTER TABLE graph_runtime.events DROP CONSTRAINT events_metadata_keys_check;
ALTER TABLE graph_runtime.events ADD CONSTRAINT events_metadata_keys_check CHECK (
 metadata - ARRAY['decisionSource','tool','provider','model','tokens','durationMs','attempt','errorCode','validationCode','objectiveId','rubricVersion','judgeVersion','judgePolicyDigest','contextTokens','verdict','evidenceSummary','terminationReason','toolSteps','policyProfile','policyVersion','policyDigest','comparisonStage','reviewerProfileId','reviewerProfileVersion','reviewerPolicyDigest','policyAdmission','responseSource','promptPolicySnapshot','presentationSnapshot','modelVerdict','policyShapeRejected'] = '{}'::jsonb
);
ALTER TABLE graph_runtime.events ADD CONSTRAINT events_stage6_reviewer_veto_check CHECK (
 NOT (metadata ?| ARRAY['modelVerdict','policyShapeRejected']) OR ((
  metadata ?& ARRAY['modelVerdict','policyShapeRejected','reviewerProfileId','reviewerProfileVersion','reviewerPolicyDigest','verdict'] AND
  metadata->>'reviewerProfileId'='ctf-stage6-learner-claimed-rotation-handoff' AND
  metadata->'modelVerdict'='"SAFE"'::jsonb AND
  metadata->'policyShapeRejected'='true'::jsonb AND
  metadata->'verdict'='"LEAKED"'::jsonb
 ) IS TRUE)
);
