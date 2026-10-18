-- Unmounted pre-defense at-most-once claim. Trusted server outcome, not model attestation.
CREATE FUNCTION identity.ctf_predefense_input_matches(v jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$ SELECT identity.ctf_json_matches(v,'{"type":"object","properties":{"version":{"type":"number","enum":[1]},"binding":{"type":"object","properties":{"ownerId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"sessionId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"runId":{"type":"string","bytes":36,"pattern":"^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$"},"ownerGeneration":{"type":"string","bytes":19,"pattern":"^(0|[1-9][0-9]*)$","minimum":0,"maximum":"9223372036854775807"},"globalRevision":{"type":"string","bytes":19,"pattern":"^(0|[1-9][0-9]*)$","minimum":0,"maximum":"9223372036854775807"},"stageRevision":{"type":"string","bytes":19,"pattern":"^(0|[1-9][0-9]*)$","minimum":0,"maximum":"9223372036854775807"},"ownerRevision":{"type":"string","bytes":19,"pattern":"^(0|[1-9][0-9]*)$","minimum":0,"maximum":"9223372036854775807"},"participantId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"progressId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"stageId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"stageDigest":{"type":"string","bytes":64,"pattern":"^[a-f0-9]{64}$"}}},"payload":{"type":"string","bytes":16384},"normalizedPayload":{"type":"string","bytes":16384,"pattern":"^[a-z0-9_ ]*$"},"payloadHash":{"type":"string","bytes":64,"pattern":"^[a-f0-9]{64}$"},"techniqueTag":{"type":"string","bytes":128},"techniqueConfidence":{"type":"number","minimum":0,"maximum":1}}}'::jsonb) $$;
REVOKE ALL ON FUNCTION identity.ctf_predefense_input_matches(jsonb) FROM PUBLIC;
CREATE FUNCTION identity.ctf_predefense_outcome_matches(v jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$ SELECT identity.ctf_json_matches(v,'{"type":"object","properties":{"version":{"type":"number","enum":[1]},"inputHash":{"type":"string","bytes":64,"pattern":"^[a-f0-9]{64}$"},"inputDecision":{"type":"string","enum":["allow","block","skipped"]},"reason":{"type":"string","bytes":4096},"languageStatus":{"type":"string","bytes":128,"nullable":true},"providerReceipt":{"type":"string","bytes":16384,"nullable":true}}}'::jsonb) $$;
REVOKE ALL ON FUNCTION identity.ctf_predefense_outcome_matches(jsonb) FROM PUBLIC;
CREATE TABLE identity.ctf_predefense_claims (
 run_id uuid PRIMARY KEY,admission_operation_id uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),blocked_operation_id uuid NOT NULL UNIQUE DEFAULT gen_random_uuid(),owner_id integer NOT NULL,session_id integer NOT NULL,
 canonical_input text NOT NULL CHECK(octet_length(canonical_input)<=32768),input_hash text NOT NULL CHECK(input_hash=encode(sha256(convert_to(canonical_input,'UTF8')),'hex')),
 input jsonb NOT NULL CHECK(input=canonical_input::jsonb AND identity.ctf_predefense_input_matches(input)),
 stage_snapshot text NOT NULL CHECK(octet_length(stage_snapshot)<=65536),initial_adaptive jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK(input->'binding'->>'runId'=run_id::text AND input->'binding'->>'ownerId'=owner_id::text AND input->'binding'->>'sessionId'=session_id::text),
 CHECK(input->'binding'->>'stageDigest'=encode(sha256(convert_to(stage_snapshot,'UTF8')),'hex'))
);
CREATE TABLE identity.ctf_predefense_outcomes (
 run_id uuid PRIMARY KEY REFERENCES identity.ctf_predefense_claims(run_id),canonical_outcome text NOT NULL CHECK(octet_length(canonical_outcome)<=24576),
 outcome_hash text NOT NULL CHECK(outcome_hash=encode(sha256(convert_to(canonical_outcome,'UTF8')),'hex')),
 outcome jsonb NOT NULL CHECK(outcome=canonical_outcome::jsonb AND identity.ctf_predefense_outcome_matches(outcome))
);
CREATE TABLE identity.ctf_predefense_consumptions (
 run_id uuid PRIMARY KEY REFERENCES identity.ctf_predefense_claims(run_id),operation_id uuid NOT NULL UNIQUE REFERENCES identity.ctf_outbox(operation_id),
 final_disposition text NOT NULL CHECK(final_disposition IN ('category','payload','input','continue')),matched_payload_hash text CHECK(matched_payload_hash~'^[a-f0-9]{64}$'),
 CHECK((final_disposition='payload')=(matched_payload_hash IS NOT NULL)),
 failed boolean NOT NULL CHECK(failed=(final_disposition='input'))
);
CREATE TRIGGER ctf_predefense_claim_immutable BEFORE UPDATE OR DELETE ON identity.ctf_predefense_claims FOR EACH ROW EXECUTE FUNCTION identity.reject_ctf_decision_mutation();
CREATE TRIGGER ctf_predefense_outcome_immutable BEFORE UPDATE OR DELETE ON identity.ctf_predefense_outcomes FOR EACH ROW EXECUTE FUNCTION identity.reject_ctf_decision_mutation();
CREATE TRIGGER ctf_predefense_consumption_immutable BEFORE UPDATE OR DELETE ON identity.ctf_predefense_consumptions FOR EACH ROW EXECUTE FUNCTION identity.reject_ctf_decision_mutation();
REVOKE ALL ON identity.ctf_predefense_claims,identity.ctf_predefense_outcomes,identity.ctf_predefense_consumptions FROM PUBLIC,dvaia_identity_runtime;
GRANT SELECT ON identity.ctf_predefense_claims,identity.ctf_predefense_outcomes,identity.ctf_predefense_consumptions TO dvaia_identity_runtime;

-- Same order as enqueue: global, stage, owner, user, original session, graph owner/run.
-- No advisory lock or model call occurs while these rows are held.
CREATE FUNCTION identity.lock_ctf_predefense(p_actor integer,p_session integer,p_hash text,b jsonb,p_current boolean)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE g identity.ctf_authority%ROWTYPE;s identity.ctf_authority%ROWTYPE;o identity.ctf_authority%ROWTYPE;u identity.users%ROWTYPE;part identity.ctf_participant_bindings%ROWTYPE;pr identity.ctf_progress_bindings%ROWTYPE;st identity.ctf_stage_bindings%ROWTYPE;cfg identity.ctf_config_binding%ROWTYPE;
BEGIN
 PERFORM set_config('lock_timeout','250ms',true);PERFORM set_config('statement_timeout','2000ms',true);
 IF b->>'ownerId' IS DISTINCT FROM p_actor::text OR b->>'sessionId' IS DISTINCT FROM p_session::text THEN RAISE EXCEPTION 'CTF pre-defense original session mismatch' USING ERRCODE='42501'; END IF;
 SELECT * INTO g FROM identity.ctf_authority a WHERE a.scope_key='global' FOR UPDATE;
 SELECT * INTO s FROM identity.ctf_authority a WHERE a.scope_key='stage:'||(b->>'stageId') FOR UPDATE;
 SELECT * INTO o FROM identity.ctf_authority a WHERE a.scope_key='owner:'||p_actor FOR UPDATE;
 SELECT * INTO u FROM identity.users uu WHERE uu.id=p_actor FOR UPDATE;
 PERFORM 1 FROM identity.user_sessions us WHERE us.id=p_session AND us.user_id=p_actor FOR UPDATE;
 IF u.id IS NULL OR u.is_active IS DISTINCT FROM 1 OR (u.account_locked_until IS NOT NULL AND u.account_locked_until>clock_timestamp())
 OR NOT EXISTS(SELECT 1 FROM identity.user_sessions us WHERE us.id=p_session AND us.user_id=p_actor AND us.is_active=1 AND us.expires_at>clock_timestamp() AND us.session_token_hash=p_hash)
 OR EXISTS(SELECT 1 FROM identity.student_deletion_jobs dj WHERE dj.subject_user_id=p_actor)
 OR EXISTS(SELECT 1 FROM identity.student_deletion_run_blocks rb WHERE rb.owner_key='["CTF","'||p_actor||'"]') THEN RAISE EXCEPTION 'SESSION_REVOKED' USING ERRCODE='28000'; END IF;
 PERFORM 1 FROM graph_runtime.owners go WHERE go.owner_key='["CTF","'||p_actor||'"]' FOR UPDATE;
 PERFORM 1 FROM graph_runtime.runs rr WHERE rr.run_id=(b->>'runId')::uuid FOR UPDATE;
 IF NOT p_current THEN RETURN; END IF;
 IF g.lifecycle_state IS DISTINCT FROM 'ready' OR s.lifecycle_state IS DISTINCT FROM 'ready' OR o.lifecycle_state IS DISTINCT FROM 'ready'
 OR g.revision IS DISTINCT FROM (b->>'globalRevision')::bigint OR s.revision IS DISTINCT FROM (b->>'stageRevision')::bigint OR o.revision IS DISTINCT FROM (b->>'ownerRevision')::bigint OR o.owner_generation IS DISTINCT FROM (b->>'ownerGeneration')::bigint
 OR NOT EXISTS(SELECT 1 FROM graph_runtime.owners go WHERE go.owner_key='["CTF","'||p_actor||'"]' AND go.generation=o.owner_generation)
 OR NOT EXISTS(SELECT 1 FROM graph_runtime.runs rr WHERE rr.run_id=(b->>'runId')::uuid AND rr.owner_key='["CTF","'||p_actor||'"]' AND rr.generation=o.owner_generation AND rr.status='running') THEN RAISE EXCEPTION 'CTF pre-defense scope stale'; END IF;
 SELECT * INTO part FROM identity.ctf_participant_bindings pp WHERE pp.owner_id=p_actor;
 SELECT * INTO pr FROM identity.ctf_progress_bindings pp WHERE pp.owner_id=p_actor AND pp.owner_generation=o.owner_generation AND pp.stage_id=(b->>'stageId')::bigint;
 SELECT * INTO st FROM identity.ctf_stage_bindings ss WHERE ss.stage_id=(b->>'stageId')::bigint;
 SELECT * INTO cfg FROM identity.ctf_config_binding WHERE singleton;
 IF part.active IS DISTINCT FROM true OR part.banned OR o.banned OR part.owner_generation IS DISTINCT FROM o.owner_generation OR part.participant_id IS DISTINCT FROM (b->>'participantId')::bigint
 OR pr.progress_id IS DISTINCT FROM (b->>'progressId')::bigint OR pr.participant_id IS DISTINCT FROM part.participant_id OR pr.status IS DISTINCT FROM 'in_progress'
 OR st.active IS DISTINCT FROM true OR st.stage_digest IS DISTINCT FROM b->>'stageDigest'
 OR cfg.enabled IS DISTINCT FROM true OR (NOT cfg.visible_to_students AND NOT(u.role='admin' OR COALESCE(u.admin_level,0)>0))
 OR (cfg.time_limit_ms<>-1 AND extract(epoch FROM clock_timestamp()-part.registered_at)*1000>cfg.time_limit_ms) THEN RAISE EXCEPTION 'CTF pre-defense eligibility unavailable'; END IF;
END; $$;
REVOKE ALL ON FUNCTION identity.lock_ctf_predefense(integer,integer,text,jsonb,boolean) FROM PUBLIC;

-- Existing exact-hash precedence is retained; fuzzy ties use immutable
-- memory_id order. The selected hash is persisted for later hit accounting.
CREATE FUNCTION identity.ctf_predefense_adaptive(e jsonb) RETURNS jsonb LANGUAGE plpgsql SET search_path=pg_catalog AS $$
DECLARE memory jsonb;entry jsonb;mode text;matched text;fuzzy text;category boolean:=false;
BEGIN
 SELECT sb.adaptive_mode INTO mode FROM identity.ctf_stage_bindings sb WHERE sb.stage_id=(e->'binding'->>'stageId')::bigint;
 SELECT COALESCE(jsonb_agg(to_jsonb(x)),'[]'::jsonb) INTO memory FROM (SELECT kind,technique_tag,payload_hash,normalized_payload FROM identity.ctf_adaptive_memory m WHERE m.stage_id=(e->'binding'->>'stageId')::bigint AND (m.kind='payload' OR (m.owner_id=(e->'binding'->>'ownerId')::integer AND m.owner_generation=(e->'binding'->>'ownerGeneration')::bigint)) ORDER BY memory_id LIMIT 257)x;
 IF jsonb_array_length(memory)>256 OR octet_length(memory::text)>262144 THEN RAISE EXCEPTION 'CTF adaptive snapshot unavailable'; END IF;
 FOR entry IN SELECT value FROM jsonb_array_elements(memory) LOOP
  IF entry->>'kind'='payload' AND (entry->>'normalized_payload' IS NULL OR entry->>'normalized_payload' !~ '^[a-z0-9_ ]*$' OR entry->>'payload_hash' IS DISTINCT FROM encode(sha256(convert_to(entry->>'normalized_payload','UTF8')),'hex')) THEN RAISE EXCEPTION 'CTF adaptive normalization unavailable'; END IF;
  IF mode IN ('technique','hybrid') AND entry->>'kind'='technique' AND e->>'techniqueTag'<>'other' AND entry->>'technique_tag'=e->>'techniqueTag' THEN category:=true; END IF;
  IF mode IN ('payload','hybrid') AND entry->>'kind'='payload' THEN
   IF entry->>'payload_hash'=e->>'payloadHash' THEN matched:=entry->>'payload_hash';
   ELSIF identity.ctf_ascii_payload_similar(e->>'normalizedPayload',entry->>'normalized_payload') THEN IF fuzzy IS NULL THEN fuzzy:=entry->>'payload_hash'; END IF; END IF;
  END IF;
 END LOOP;
 IF category THEN RETURN jsonb_build_object('disposition','category','matchedPayloadHash',NULL); END IF;
 IF matched IS NULL THEN matched:=fuzzy; END IF;
 RETURN jsonb_build_object('disposition',CASE WHEN matched IS NULL THEN 'continue' ELSE 'payload' END,'matchedPayloadHash',matched);
END; $$;
REVOKE ALL ON FUNCTION identity.ctf_predefense_adaptive(jsonb) FROM PUBLIC;
CREATE FUNCTION identity.claim_ctf_predefense(p_actor integer,p_session integer,p_token_hash text,p_document text,p_hash text,p_snapshot text)
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
  IF NOT(k=ANY(ARRAY['id','stage_number','stage_name','stage_description','difficulty_level','ai_guardian_name','ai_guardian_personality','system_prompt','success_criteria','hints','max_attempts','time_penalty_per_wrong_attempt','is_active','stage_order','difficulty','defense_style','adaptive_mode','level_score','time_bonus_seconds','feedback_mode','created_at'])) OR (previous_key IS NOT NULL AND k COLLATE "C"<=previous_key COLLATE "C") THEN RAISE EXCEPTION 'CTF pre-defense stage keys invalid'; END IF;
  previous_key:=k;stage:=stage||jsonb_build_object(k,pair->1);
 END LOOP;
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
REVOKE ALL ON FUNCTION identity.claim_ctf_predefense(integer,integer,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.claim_ctf_predefense(integer,integer,text,text,text,text) TO dvaia_identity_runtime;

-- This function receives a trusted server observation, never an HTTP verdict.
-- SQL binds exact bytes but cannot attest provider execution.
CREATE FUNCTION identity.store_ctf_predefense_outcome(p_actor integer,p_session integer,p_token_hash text,p_run uuid,p_document text,p_hash text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c identity.ctf_predefense_claims%ROWTYPE;o identity.ctf_predefense_outcomes%ROWTYPE;e jsonb;
BEGIN
 IF p_document IS NULL OR octet_length(p_document)>24576 OR NOT(p_document IS JSON OBJECT WITH UNIQUE KEYS) OR p_hash IS DISTINCT FROM encode(sha256(convert_to(p_document,'UTF8')),'hex') THEN RAISE EXCEPTION 'CTF defense outcome bytes invalid'; END IF;
 e:=p_document::jsonb;IF NOT identity.ctf_predefense_outcome_matches(e) THEN RAISE EXCEPTION 'CTF defense outcome invalid'; END IF;
 SELECT * INTO c FROM identity.ctf_predefense_claims cc WHERE cc.run_id=p_run;
 IF c.run_id IS NULL THEN RAISE EXCEPTION 'CTF pre-defense claim unavailable'; END IF;
 PERFORM identity.lock_ctf_predefense(p_actor,p_session,p_token_hash,c.input->'binding',false);
 IF e->>'inputHash' IS DISTINCT FROM c.input_hash OR ((e->>'inputDecision'='skipped') IS DISTINCT FROM (c.initial_adaptive->>'disposition'<>'continue')) THEN RAISE EXCEPTION 'CTF defense outcome binding invalid'; END IF;
 SELECT * INTO o FROM identity.ctf_predefense_outcomes oo WHERE oo.run_id=p_run;
 IF FOUND THEN IF o.canonical_outcome IS DISTINCT FROM p_document THEN RAISE EXCEPTION 'CTF defense outcome replay conflict'; END IF;RETURN jsonb_build_object('stored',true,'replayed',true,'currentState',false);END IF;
 PERFORM identity.lock_ctf_predefense(p_actor,p_session,p_token_hash,c.input->'binding',true);
 INSERT INTO identity.ctf_predefense_outcomes VALUES(p_run,p_document,p_hash,e);
 RETURN jsonb_build_object('stored',true,'replayed',false,'currentState',false);
END; $$;
REVOKE ALL ON FUNCTION identity.store_ctf_predefense_outcome(integer,integer,text,uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.store_ctf_predefense_outcome(integer,integer,text,uuid,text,text) TO dvaia_identity_runtime;

CREATE FUNCTION identity.consume_ctf_predefense(p_actor integer,p_session integer,p_token_hash text,p_run uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c identity.ctf_predefense_claims%ROWTYPE;o identity.ctf_predefense_outcomes%ROWTYPE;prior identity.ctf_predefense_consumptions%ROWTYPE;b jsonb;ad jsonb;disposition text;doc jsonb;raw text;allocated record;
BEGIN
 SELECT * INTO c FROM identity.ctf_predefense_claims cc WHERE cc.run_id=p_run;
 IF c.run_id IS NULL THEN RAISE EXCEPTION 'CTF pre-defense claim unavailable'; END IF;
 b:=c.input->'binding';PERFORM identity.lock_ctf_predefense(p_actor,p_session,p_token_hash,b,false);
 SELECT * INTO prior FROM identity.ctf_predefense_consumptions pc WHERE pc.run_id=p_run;
 IF FOUND THEN RETURN jsonb_build_object('consumed',true,'replayed',true,'currentState',false,'operationId',prior.operation_id,'blockedOperationId',c.blocked_operation_id,'disposition',prior.final_disposition,'matchedPayloadHash',prior.matched_payload_hash,'failed',prior.failed); END IF;
 SELECT * INTO o FROM identity.ctf_predefense_outcomes oo WHERE oo.run_id=p_run;
 IF NOT FOUND THEN RETURN jsonb_build_object('consumed',false,'status','unknown','currentState',false); END IF;
 PERFORM identity.lock_ctf_predefense(p_actor,p_session,p_token_hash,b,true);
 ad:=identity.ctf_predefense_adaptive(c.input);disposition:=ad->>'disposition';
 IF disposition='continue' THEN
  IF o.outcome->>'inputDecision'='skipped' THEN RAISE EXCEPTION 'CTF adaptive block cleared after skipped defense; new attempt required'; END IF;
  disposition:=CASE WHEN o.outcome->>'inputDecision'='block' THEN 'input' ELSE 'continue' END;
 END IF;
 doc:=jsonb_build_object('version',1,'kind','admit_attempt','operationId',c.admission_operation_id,'actorId',p_actor::text,'occurredAt',to_char(date_trunc('milliseconds',transaction_timestamp()) AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
  'scope',jsonb_build_object('ownerId',b->>'ownerId','ownerGeneration',b->>'ownerGeneration','globalRevision',b->>'globalRevision','stageRevision',b->>'stageRevision','participantId',b->>'participantId','stageId',b->>'stageId','progressId',b->>'progressId'),'body',jsonb_build_object('failed',disposition='input'));
 -- Closed all-string/boolean/integer schema: explicit recursively sorted keys
 -- match canonicalCtfJson exactly. Do not use jsonb::text object serialization.
 raw:='{"actorId":'||(doc->'actorId')::text||',"body":{"failed":'||(doc->'body'->'failed')::text||'},"kind":"admit_attempt","occurredAt":'||(doc->'occurredAt')::text||',"operationId":'||(doc->'operationId')::text||',"scope":{"globalRevision":'||(b->'globalRevision')::text||',"ownerGeneration":'||(b->'ownerGeneration')::text||',"ownerId":'||(b->'ownerId')::text||',"participantId":'||(b->'participantId')::text||',"progressId":'||(b->'progressId')::text||',"stageId":'||(b->'stageId')::text||',"stageRevision":'||(b->'stageRevision')::text||'},"version":1}';
 IF raw::jsonb IS DISTINCT FROM doc THEN RAISE EXCEPTION 'CTF pre-defense command encoding mismatch'; END IF;
 -- Reentrant locks, same identity transaction: command and disposition either
 -- both commit or neither does. No CTF/client/model lease is held here.
 SELECT * INTO allocated FROM identity.enqueue_ctf_user_command(p_actor::bigint,p_session::bigint,p_token_hash,c.admission_operation_id,raw,encode(sha256(convert_to(raw,'UTF8')),'hex'));
 INSERT INTO identity.ctf_predefense_consumptions VALUES(p_run,c.admission_operation_id,disposition,ad->>'matchedPayloadHash',disposition='input');
 RETURN jsonb_build_object('consumed',true,'replayed',false,'currentState',false,'operationId',c.admission_operation_id,'blockedOperationId',c.blocked_operation_id,'disposition',disposition,'matchedPayloadHash',ad->>'matchedPayloadHash','failed',disposition='input');
END; $$;
REVOKE ALL ON FUNCTION identity.consume_ctf_predefense(integer,integer,text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.consume_ctf_predefense(integer,integer,text,uuid) TO dvaia_identity_runtime;
