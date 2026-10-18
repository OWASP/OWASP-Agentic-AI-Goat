-- Unmounted deterministic recovery only. Qualified running-only claim/outcome APIs remain unchanged.
-- No new inference, caller-supplied outcome, or automatic completion.


CREATE FUNCTION identity.lock_ctf_predefense_recovery_state(p_actor integer,p_session integer,p_hash text,p_run uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c identity.ctf_predefense_claims%ROWTYPE;b jsonb;g identity.ctf_authority%ROWTYPE;s identity.ctf_authority%ROWTYPE;o identity.ctf_authority%ROWTYPE;u identity.users%ROWTYPE;part identity.ctf_participant_bindings%ROWTYPE;pr identity.ctf_progress_bindings%ROWTYPE;st identity.ctf_stage_bindings%ROWTYPE;cfg identity.ctf_config_binding%ROWTYPE;
BEGIN
 SELECT * INTO c FROM identity.ctf_predefense_claims cc WHERE cc.run_id=p_run;
 IF c.run_id IS NULL THEN RAISE EXCEPTION 'CTF recovery unavailable' USING ERRCODE='42501';END IF;
 b:=c.input->'binding';
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

 IF g.lifecycle_state IS DISTINCT FROM 'ready' OR s.lifecycle_state IS DISTINCT FROM 'ready' OR NOT(o.lifecycle_state='ready' OR (o.lifecycle_state='pending' AND (o.pending_operation_id IN(c.admission_operation_id,c.blocked_operation_id) OR EXISTS(SELECT 1 FROM identity.ctf_decisions dd WHERE dd.run_id=p_run AND dd.owner_id=p_actor AND dd.session_id=p_session AND dd.decision_id=o.pending_operation_id))))
 OR g.revision IS DISTINCT FROM (b->>'globalRevision')::bigint OR s.revision IS DISTINCT FROM (b->>'stageRevision')::bigint OR o.revision IS DISTINCT FROM (b->>'ownerRevision')::bigint OR o.owner_generation IS DISTINCT FROM (b->>'ownerGeneration')::bigint
 OR NOT EXISTS(SELECT 1 FROM graph_runtime.owners go WHERE go.owner_key='["CTF","'||p_actor||'"]' AND go.generation=o.owner_generation)
 OR NOT EXISTS(SELECT 1 FROM graph_runtime.runs rr WHERE rr.run_id=(b->>'runId')::uuid AND rr.owner_key='["CTF","'||p_actor||'"]' AND rr.generation=o.owner_generation AND rr.status IN('running','completed')) OR identity.ctf_publication_bootstrap_ready() IS DISTINCT FROM true THEN RAISE EXCEPTION 'CTF recovery scope stale' USING ERRCODE='42501'; END IF;
 SELECT * INTO part FROM identity.ctf_participant_bindings pp WHERE pp.owner_id=p_actor;
 SELECT * INTO pr FROM identity.ctf_progress_bindings pp WHERE pp.owner_id=p_actor AND pp.owner_generation=o.owner_generation AND pp.stage_id=(b->>'stageId')::bigint;
 SELECT * INTO st FROM identity.ctf_stage_bindings ss WHERE ss.stage_id=(b->>'stageId')::bigint;
 SELECT * INTO cfg FROM identity.ctf_config_binding WHERE singleton;
 IF part.active IS DISTINCT FROM true OR part.banned OR o.banned OR part.owner_generation IS DISTINCT FROM o.owner_generation OR part.participant_id IS DISTINCT FROM (b->>'participantId')::bigint
 OR pr.progress_id IS DISTINCT FROM (b->>'progressId')::bigint OR pr.participant_id IS DISTINCT FROM part.participant_id OR pr.status NOT IN('in_progress','completed') OR pr.status IS NULL
 OR st.active IS DISTINCT FROM true OR st.stage_digest IS DISTINCT FROM b->>'stageDigest'
 OR cfg.enabled IS DISTINCT FROM true OR (NOT cfg.visible_to_students AND NOT(u.role='admin' OR COALESCE(u.admin_level,0)>0))
 OR (cfg.time_limit_ms<>-1 AND extract(epoch FROM clock_timestamp()-part.registered_at)*1000>cfg.time_limit_ms) THEN RAISE EXCEPTION 'CTF recovery eligibility unavailable' USING ERRCODE='42501'; END IF;
END; $$;

CREATE FUNCTION identity.lock_ctf_predefense_recovery_effect(p_actor integer,p_session integer,p_hash text,p_run uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c identity.ctf_predefense_claims%ROWTYPE;o identity.ctf_predefense_outcomes%ROWTYPE;b jsonb;
BEGIN
 PERFORM identity.lock_ctf_predefense_recovery_state(p_actor,p_session,p_hash,p_run);
 SELECT * INTO c FROM identity.ctf_predefense_claims cc WHERE cc.run_id=p_run;b:=c.input->'binding';
 SELECT * INTO o FROM identity.ctf_predefense_outcomes oo WHERE oo.run_id=p_run;
 IF NOT EXISTS(SELECT 1 FROM graph_runtime.runs rr WHERE rr.run_id=p_run AND rr.owner_key='["CTF","'||p_actor||'"]' AND rr.generation=(b->>'ownerGeneration')::bigint AND rr.status='completed')
 OR NOT EXISTS(SELECT 1 FROM identity.ctf_authority aa WHERE aa.scope_key='owner:'||p_actor AND aa.lifecycle_state='ready')
 OR NOT EXISTS(SELECT 1 FROM identity.ctf_progress_bindings pp WHERE pp.owner_id=p_actor AND pp.owner_generation=(b->>'ownerGeneration')::bigint AND pp.progress_id=(b->>'progressId')::bigint AND pp.status='in_progress')
 OR o.run_id IS NULL OR o.outcome->>'inputHash' IS DISTINCT FROM c.input_hash
 OR o.outcome IS DISTINCT FROM o.canonical_outcome::jsonb OR o.outcome_hash IS DISTINCT FROM encode(sha256(convert_to(o.canonical_outcome,'UTF8')),'hex')
 THEN RAISE EXCEPTION 'CTF completed recovery outcome unavailable' USING ERRCODE='42501';END IF;
END; $$;


CREATE FUNCTION identity.consume_ctf_predefense_recovery(p_actor integer,p_session integer,p_token_hash text,p_run uuid)
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
 PERFORM identity.lock_ctf_predefense_recovery_effect(p_actor,p_session,p_token_hash,p_run);
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

CREATE FUNCTION identity.prepare_ctf_blocked_recovery(p_actor integer,p_session integer,p_token_hash text,p_run uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c identity.ctf_predefense_claims%ROWTYPE;done identity.ctf_predefense_consumptions%ROWTYPE;o identity.ctf_predefense_outcomes%ROWTYPE;a identity.ctf_attempt_admissions%ROWTYPE;
 ev identity.ctf_outbox%ROWTYPE;old identity.ctf_outbox%ROWTYPE;b jsonb;body jsonb;doc jsonb;reason text;show_feedback boolean;feedback text;
BEGIN
 SELECT * INTO c FROM identity.ctf_predefense_claims cc WHERE cc.run_id=p_run;
 IF c.run_id IS NULL THEN RAISE EXCEPTION 'CTF pre-defense claim unavailable'; END IF;
 b:=c.input->'binding';PERFORM identity.lock_ctf_predefense(p_actor,p_session,p_token_hash,b,false);
 SELECT * INTO done FROM identity.ctf_predefense_consumptions pc WHERE pc.run_id=p_run;
 IF done.run_id IS NULL OR done.final_disposition='continue' THEN RAISE EXCEPTION 'CTF blocked disposition unavailable'; END IF;
 SELECT oo.* INTO old FROM identity.ctf_predefense_blocked_commands bc JOIN identity.ctf_outbox oo ON oo.operation_id=bc.operation_id AND oo.command_hash=bc.command_hash WHERE bc.run_id=p_run;
 IF FOUND THEN
  IF old.operation_id IS DISTINCT FROM c.blocked_operation_id OR old.actor_id IS DISTINCT FROM p_actor OR old.session_id IS DISTINCT FROM p_session OR old.kind IS DISTINCT FROM 'record_blocked_attempt' THEN RAISE EXCEPTION 'CTF blocked replay binding mismatch'; END IF;
  RETURN jsonb_build_object('operationId',old.operation_id,'command',old.command,'canonicalCommand',old.canonical_command,'replayed',true,'currentState',false);
 END IF;
 IF EXISTS(SELECT 1 FROM identity.ctf_outbox oo WHERE oo.operation_id=c.blocked_operation_id) THEN RAISE EXCEPTION 'CTF blocked reserved operation conflict'; END IF;
 SELECT * INTO ev FROM identity.ctf_outbox oo WHERE oo.operation_id=done.operation_id;
 SELECT * INTO a FROM identity.ctf_attempt_admissions aa WHERE aa.operation_id=done.operation_id;
 SELECT * INTO o FROM identity.ctf_predefense_outcomes po WHERE po.run_id=p_run;
 IF ev.state IS DISTINCT FROM 'applied' OR ev.kind IS DISTINCT FROM 'admit_attempt' OR ev.actor_id IS DISTINCT FROM p_actor OR ev.session_id IS DISTINCT FROM p_session OR ev.operation_id IS DISTINCT FROM c.admission_operation_id
 OR a.owner_id IS DISTINCT FROM p_actor OR a.owner_generation IS DISTINCT FROM (b->>'ownerGeneration')::bigint OR a.participant_id IS DISTINCT FROM (b->>'participantId')::bigint OR a.progress_id IS DISTINCT FROM (b->>'progressId')::bigint OR a.stage_id IS DISTINCT FROM (b->>'stageId')::bigint OR a.failed_counter_increment IS DISTINCT FROM done.failed OR o.run_id IS NULL THEN RAISE EXCEPTION 'CTF blocked admission not acknowledged'; END IF;
 PERFORM identity.lock_ctf_predefense_recovery_effect(p_actor,p_session,p_token_hash,p_run);
 SELECT cfg.show_technique_feedback INTO show_feedback FROM identity.ctf_config_binding cfg WHERE cfg.singleton;
 SELECT st.feedback_mode INTO feedback FROM identity.ctf_stage_bindings st WHERE st.stage_id=a.stage_id;
 IF done.final_disposition='category' THEN reason:=CASE WHEN show_feedback THEN 'Technique "'||(c.input->>'techniqueTag')||'" has already been used on this level. Try a different approach.' ELSE 'This approach has been blocked. Try something different.' END;
 ELSIF done.final_disposition='payload' THEN reason:=CASE WHEN show_feedback THEN 'This payload (or a very similar one) has already been used successfully by another participant.' ELSE 'This approach has been blocked by the community shield.' END;
 ELSE reason:=CASE WHEN feedback='silent' THEN 'Your input was blocked by the defense system.' ELSE o.outcome->>'reason' END;
 END IF;
 body:=jsonb_build_object('admissionOperationId',c.admission_operation_id,'matchedPayloadHash',done.matched_payload_hash,'attemptNumber',a.attempt_number,'payload',c.input->>'payload','response',NULL,'responseTime',0,'teachingSessionToken',(SELECT l.registration_token FROM identity.ctf_predefense_registration_locators l WHERE l.run_id=c.run_id),'techniqueTag',c.input->>'techniqueTag','techniqueConfidence',c.input->'techniqueConfidence','reason',reason,'payloadHash',c.input->>'payloadHash');
 doc:=jsonb_build_object('version',1,'kind','record_blocked_attempt','operationId',c.blocked_operation_id,'actorId',p_actor::text,'occurredAt',to_char(date_trunc('milliseconds',transaction_timestamp()) AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
 'scope',jsonb_build_object('ownerId',b->>'ownerId','ownerGeneration',b->>'ownerGeneration','globalRevision',b->>'globalRevision','stageRevision',b->>'stageRevision','participantId',b->>'participantId','stageId',b->>'stageId','progressId',b->>'progressId'),'body',body);
 RETURN jsonb_build_object('operationId',c.blocked_operation_id,'command',doc,'canonicalCommand',NULL,'replayed',false,'currentState',false);
END; $$;

-- Closed blocked-command encoder. Only confidence uses binary64; all other
-- numbers are schema-bounded integers. No arbitrary JSON numeric conversion.
CREATE FUNCTION identity.canonical_ctf_recovery_blocked(v jsonb) RETURNS text
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog SET extra_float_digits=1 AS $$
DECLARE confidence double precision; token text; raw text;
BEGIN
 IF v->>'kind' IS DISTINCT FROM 'record_blocked_attempt' THEN RAISE EXCEPTION 'CTF recovery encoding kind invalid';END IF;
 confidence:=(v->'body'->>'techniqueConfidence')::double precision;
 IF confidence IS NULL OR confidence<0 OR confidence>1 OR confidence='NaN'::double precision THEN RAISE EXCEPTION 'CTF recovery confidence invalid';END IF;
 token:=confidence::text;
 IF confidence=0 THEN token:='0';
 ELSIF confidence<0.000001 THEN token:=regexp_replace(token,'e-0+','e-');
 ELSE token:=trim(trailing '.' FROM trim(trailing '0' FROM (token::numeric)::text||CASE WHEN position('.' IN (token::numeric)::text)=0 THEN '.' ELSE '' END));
 END IF;
 raw:='{'||'"actorId":'||(v->'actorId')::text||',"body":'||'{'||'"admissionOperationId":'||(v->'body'->'admissionOperationId')::text||',"attemptNumber":'||(v->'body'->'attemptNumber')::text||',"matchedPayloadHash":'||(v->'body'->'matchedPayloadHash')::text||',"payload":'||(v->'body'->'payload')::text||',"payloadHash":'||(v->'body'->'payloadHash')::text||',"reason":'||(v->'body'->'reason')::text||',"response":'||(v->'body'->'response')::text||',"responseTime":'||(v->'body'->'responseTime')::text||',"teachingSessionToken":'||(v->'body'->'teachingSessionToken')::text||',"techniqueConfidence":'||token||',"techniqueTag":'||(v->'body'->'techniqueTag')::text||'}'||',"kind":'||(v->'kind')::text||',"occurredAt":'||(v->'occurredAt')::text||',"operationId":'||(v->'operationId')::text||',"scope":'||'{'||'"globalRevision":'||(v->'scope'->'globalRevision')::text||',"ownerGeneration":'||(v->'scope'->'ownerGeneration')::text||',"ownerId":'||(v->'scope'->'ownerId')::text||',"participantId":'||(v->'scope'->'participantId')::text||',"progressId":'||(v->'scope'->'progressId')::text||',"stageId":'||(v->'scope'->'stageId')::text||',"stageRevision":'||(v->'scope'->'stageRevision')::text||'}'||',"version":'||(v->'version')::text||'}';
 IF raw IS NULL OR raw::jsonb IS DISTINCT FROM v THEN RAISE EXCEPTION 'CTF recovery encoding mismatch';END IF;
 RETURN raw;
END; $$;
REVOKE ALL ON FUNCTION identity.canonical_ctf_recovery_blocked(jsonb) FROM PUBLIC,dvaia_identity_runtime;

CREATE FUNCTION identity.enqueue_ctf_blocked_recovery(p_actor integer,p_session integer,p_token_hash text,p_run uuid,p_document text,p_hash text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE expected jsonb;allocated record;op uuid;
BEGIN
 expected:=identity.prepare_ctf_blocked_recovery(p_actor,p_session,p_token_hash,p_run);op:=(expected->>'operationId')::uuid;
 IF p_document IS NULL OR octet_length(p_document)>65536 OR NOT(p_document IS JSON OBJECT WITH UNIQUE KEYS) OR p_hash IS DISTINCT FROM encode(sha256(convert_to(p_document,'UTF8')),'hex') OR p_document::jsonb IS DISTINCT FROM expected->'command' OR p_document IS DISTINCT FROM identity.canonical_ctf_recovery_blocked(expected->'command') THEN RAISE EXCEPTION 'CTF blocked canonical command mismatch'; END IF;
 IF (expected->>'replayed')::boolean THEN
  IF expected->>'canonicalCommand' IS DISTINCT FROM p_document THEN RAISE EXCEPTION 'CTF blocked replay encoding mismatch'; END IF;
  RETURN jsonb_build_object('operationId',op,'replayed',true,'currentState',false);
 END IF;
 SELECT * INTO allocated FROM identity.enqueue_ctf_user_command(p_actor::bigint,p_session::bigint,p_token_hash,op,p_document,p_hash);
 INSERT INTO identity.ctf_predefense_blocked_commands VALUES(p_run,op,p_hash);
 RETURN jsonb_build_object('operationId',op,'replayed',false,'currentState',false);
END; $$;

REVOKE ALL ON FUNCTION identity.lock_ctf_predefense_recovery_state(integer,integer,text,uuid) FROM PUBLIC,dvaia_identity_runtime;

REVOKE ALL ON FUNCTION identity.lock_ctf_predefense_recovery_effect(integer,integer,text,uuid) FROM PUBLIC,dvaia_identity_runtime;

REVOKE ALL ON FUNCTION identity.consume_ctf_predefense_recovery(integer,integer,text,uuid) FROM PUBLIC,dvaia_identity_runtime;

GRANT EXECUTE ON FUNCTION identity.consume_ctf_predefense_recovery(integer,integer,text,uuid) TO dvaia_identity_runtime;

REVOKE ALL ON FUNCTION identity.prepare_ctf_blocked_recovery(integer,integer,text,uuid) FROM PUBLIC,dvaia_identity_runtime;

GRANT EXECUTE ON FUNCTION identity.prepare_ctf_blocked_recovery(integer,integer,text,uuid) TO dvaia_identity_runtime;

REVOKE ALL ON FUNCTION identity.enqueue_ctf_blocked_recovery(integer,integer,text,uuid,text,text) FROM PUBLIC,dvaia_identity_runtime;

GRANT EXECUTE ON FUNCTION identity.enqueue_ctf_blocked_recovery(integer,integer,text,uuid,text,text) TO dvaia_identity_runtime;

CREATE FUNCTION identity.read_ctf_predefense_recovery(p_actor integer,p_session integer,p_token_hash text,p_run uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c identity.ctf_predefense_claims%ROWTYPE;o identity.ctf_predefense_outcomes%ROWTYPE;used identity.ctf_predefense_consumptions%ROWTYPE;
 ev identity.ctf_outbox%ROWTYPE;ad identity.ctf_attempt_admissions%ROWTYPE;bc identity.ctf_predefense_blocked_commands%ROWTYPE;
 di identity.ctf_decision_inputs%ROWTYPE;proposal identity.ctf_decision_proposals%ROWTYPE;decision identity.ctf_decisions%ROWTYPE;
 answer jsonb;b jsonb;receipt jsonb;run_state text;
BEGIN
 PERFORM set_config('lock_timeout','250ms',true);PERFORM set_config('statement_timeout','2000ms',true);
 answer:=jsonb_build_object('version',1,'state','not_found','runId',p_run,'admissionId',NULL,'blockedOperationId',NULL,'decisionId',NULL,'currentCompletion',false);
 SELECT * INTO c FROM identity.ctf_predefense_claims cc WHERE cc.run_id=p_run;
 IF c.run_id IS NULL THEN
  -- No later global/scope lock on this branch: user/session lock order stays local.
  PERFORM 1 FROM identity.users uu WHERE uu.id=p_actor FOR SHARE;
  PERFORM 1 FROM identity.user_sessions ss WHERE ss.id=p_session AND ss.user_id=p_actor FOR SHARE;
  IF NOT EXISTS(SELECT 1 FROM identity.users uu JOIN identity.user_sessions ss ON ss.user_id=uu.id WHERE uu.id=p_actor AND ss.id=p_session AND uu.is_active=1 AND (uu.account_locked_until IS NULL OR uu.account_locked_until<=clock_timestamp()) AND ss.is_active=1 AND ss.expires_at>clock_timestamp() AND ss.session_token_hash=p_token_hash)
   OR EXISTS(SELECT 1 FROM identity.student_deletion_jobs jj WHERE jj.subject_user_id=p_actor)
   OR EXISTS(SELECT 1 FROM identity.student_deletion_run_blocks bb WHERE bb.owner_key='["CTF","'||p_actor||'"]') THEN RAISE EXCEPTION 'SESSION_REVOKED' USING ERRCODE='28000';END IF;
  RETURN answer;
 END IF;
 PERFORM identity.lock_ctf_predefense_recovery_state(p_actor,p_session,p_token_hash,p_run);
 b:=c.input->'binding';
 answer:=answer||jsonb_build_object('admissionId',c.admission_operation_id,'blockedOperationId',c.blocked_operation_id);
 SELECT rr.status INTO run_state FROM graph_runtime.runs rr WHERE rr.run_id=p_run;
 IF run_state='running' THEN RETURN answer||jsonb_build_object('state','in_progress');END IF;
 SELECT * INTO o FROM identity.ctf_predefense_outcomes oo WHERE oo.run_id=p_run;
 IF o.run_id IS NULL THEN RETURN answer||jsonb_build_object('state','outcome_indeterminate');END IF;
 IF o.outcome->>'inputHash' IS DISTINCT FROM c.input_hash THEN RAISE EXCEPTION 'CTF recovery outcome binding invalid' USING ERRCODE='42501';END IF;
 SELECT * INTO used FROM identity.ctf_predefense_consumptions cc WHERE cc.run_id=p_run;
 IF used.run_id IS NULL THEN RETURN answer||jsonb_build_object('state','outcome_stored');END IF;
 SELECT * INTO ev FROM identity.ctf_outbox ee WHERE ee.operation_id=used.operation_id;
 IF used.operation_id IS DISTINCT FROM c.admission_operation_id OR ev.operation_id IS NULL OR ev.actor_id IS DISTINCT FROM p_actor OR ev.session_id IS DISTINCT FROM p_session OR ev.kind IS DISTINCT FROM 'admit_attempt'
 OR ev.command->'body'->'failed' IS DISTINCT FROM to_jsonb(used.failed)
 THEN RAISE EXCEPTION 'CTF recovery admission binding invalid' USING ERRCODE='42501';END IF;
 IF ev.state='pending' THEN RETURN answer||jsonb_build_object('state','admission_pending');END IF;
 IF ev.state<>'applied' THEN RETURN answer||jsonb_build_object('state','recovery_required');END IF;
 IF ev.canonical_command IS NULL OR ev.command IS DISTINCT FROM ev.canonical_command::jsonb
 OR ev.command_hash IS DISTINCT FROM encode(sha256(convert_to(ev.canonical_command,'UTF8')),'hex')
 OR ev.command->>'actorId' IS DISTINCT FROM p_actor::text OR ev.command->>'operationId' IS DISTINCT FROM ev.operation_id::text OR ev.command->>'kind' IS DISTINCT FROM ev.kind
 OR ev.command->'scope' IS DISTINCT FROM jsonb_build_object('ownerId',b->>'ownerId','ownerGeneration',b->>'ownerGeneration','globalRevision',b->>'globalRevision','stageRevision',b->>'stageRevision','participantId',b->>'participantId','stageId',b->>'stageId','progressId',b->>'progressId')
 OR ev.canonical_result IS NULL THEN RAISE EXCEPTION 'CTF recovery event binding invalid' USING ERRCODE='42501';END IF;
 receipt:=ev.canonical_result::jsonb;
 IF identity.ctf_result_matches(receipt) IS NOT TRUE OR receipt->>'kind' IS DISTINCT FROM ev.kind THEN RAISE EXCEPTION 'CTF recovery receipt schema invalid' USING ERRCODE='42501';END IF;
 IF receipt->>'operationId' IS DISTINCT FROM ev.operation_id::text OR receipt->>'commandHash' IS DISTINCT FROM ev.command_hash OR receipt->>'sequence' IS DISTINCT FROM ev.sequence::text OR receipt->>'outcome' IS DISTINCT FROM 'applied'
 OR ev.result_hash IS DISTINCT FROM encode(sha256(convert_to(ev.canonical_result,'UTF8')),'hex') THEN RAISE EXCEPTION 'CTF recovery admission receipt invalid' USING ERRCODE='42501';END IF;
 SELECT * INTO ad FROM identity.ctf_attempt_admissions aa WHERE aa.operation_id=used.operation_id;
 IF ad.owner_id IS DISTINCT FROM p_actor OR ad.owner_generation IS DISTINCT FROM (b->>'ownerGeneration')::bigint OR ad.participant_id IS DISTINCT FROM (b->>'participantId')::bigint OR ad.progress_id IS DISTINCT FROM (b->>'progressId')::bigint OR ad.stage_id IS DISTINCT FROM (b->>'stageId')::bigint OR ad.failed_counter_increment IS DISTINCT FROM used.failed
 OR receipt->'data'->>'attemptNumber' IS DISTINCT FROM ad.attempt_number::text THEN RAISE EXCEPTION 'CTF recovery admission unavailable' USING ERRCODE='42501';END IF;
 IF used.final_disposition='continue' THEN
  SELECT * INTO di FROM identity.ctf_decision_inputs ii WHERE ii.admission_id=c.admission_operation_id AND ii.run_id=p_run AND ii.owner_id=p_actor AND ii.session_id=p_session;
  IF di.admission_id IS NULL THEN RETURN answer||jsonb_build_object('state','guardian_not_started_or_unknown');END IF;
  SELECT * INTO proposal FROM identity.ctf_decision_proposals pp WHERE pp.admission_operation_id=di.admission_id AND pp.run_id=p_run AND pp.owner_id=p_actor AND pp.session_id=p_session;
  IF proposal.proposal_id IS NULL THEN RETURN answer||jsonb_build_object('state','guardian_not_started_or_unknown');END IF;
  SELECT * INTO decision FROM identity.ctf_decisions dd WHERE dd.proposal_id=proposal.proposal_id AND dd.run_id=p_run AND dd.owner_id=p_actor AND dd.session_id=p_session AND dd.evidence_hash=proposal.evidence_hash;
  RETURN answer||jsonb_build_object('state',CASE WHEN decision.decision_id IS NULL THEN 'proposal_staged' ELSE 'decision_available' END,'decisionId',decision.decision_id);
 END IF;
 SELECT * INTO bc FROM identity.ctf_predefense_blocked_commands bb WHERE bb.run_id=p_run;
 IF bc.run_id IS NULL THEN RETURN answer||jsonb_build_object('state','blocked_ready_to_enqueue');END IF;
 SELECT * INTO ev FROM identity.ctf_outbox ee WHERE ee.operation_id=bc.operation_id;
 IF bc.operation_id IS DISTINCT FROM c.blocked_operation_id OR ev.operation_id IS NULL OR ev.kind IS DISTINCT FROM 'record_blocked_attempt' OR ev.actor_id IS DISTINCT FROM p_actor OR ev.session_id IS DISTINCT FROM p_session OR ev.command_hash IS DISTINCT FROM bc.command_hash
 OR ev.command->'body'->>'admissionOperationId' IS DISTINCT FROM c.admission_operation_id::text OR ev.command->'body'->>'attemptNumber' IS DISTINCT FROM ad.attempt_number::text
 OR ev.command->'body'->>'matchedPayloadHash' IS DISTINCT FROM used.matched_payload_hash THEN RAISE EXCEPTION 'CTF recovery blocked binding invalid' USING ERRCODE='42501';END IF;
 IF ev.state='pending' THEN RETURN answer||jsonb_build_object('state','blocked_pending');END IF;
 IF ev.state<>'applied' THEN RETURN answer||jsonb_build_object('state','recovery_required');END IF;
 IF ev.canonical_command IS NULL OR ev.command IS DISTINCT FROM ev.canonical_command::jsonb
 OR ev.command_hash IS DISTINCT FROM encode(sha256(convert_to(ev.canonical_command,'UTF8')),'hex')
 OR ev.command->>'actorId' IS DISTINCT FROM p_actor::text OR ev.command->>'operationId' IS DISTINCT FROM ev.operation_id::text OR ev.command->>'kind' IS DISTINCT FROM ev.kind
 OR ev.command->'scope' IS DISTINCT FROM jsonb_build_object('ownerId',b->>'ownerId','ownerGeneration',b->>'ownerGeneration','globalRevision',b->>'globalRevision','stageRevision',b->>'stageRevision','participantId',b->>'participantId','stageId',b->>'stageId','progressId',b->>'progressId')
 OR ev.canonical_result IS NULL THEN RAISE EXCEPTION 'CTF recovery event binding invalid' USING ERRCODE='42501';END IF;
 receipt:=ev.canonical_result::jsonb;
 IF identity.ctf_result_matches(receipt) IS NOT TRUE OR receipt->>'kind' IS DISTINCT FROM ev.kind THEN RAISE EXCEPTION 'CTF recovery receipt schema invalid' USING ERRCODE='42501';END IF;
 IF receipt->>'operationId' IS DISTINCT FROM ev.operation_id::text OR receipt->>'commandHash' IS DISTINCT FROM ev.command_hash OR receipt->>'sequence' IS DISTINCT FROM ev.sequence::text OR receipt->>'outcome' IS DISTINCT FROM 'applied'
 OR receipt->'data'->>'admissionOperationId' IS DISTINCT FROM c.admission_operation_id::text OR ev.result_hash IS DISTINCT FROM encode(sha256(convert_to(ev.canonical_result,'UTF8')),'hex') THEN RAISE EXCEPTION 'CTF recovery blocked receipt invalid' USING ERRCODE='42501';END IF;
 RETURN answer||jsonb_build_object('state','blocked_publishable');
END; $$;
REVOKE ALL ON FUNCTION identity.read_ctf_predefense_recovery(integer,integer,text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.read_ctf_predefense_recovery(integer,integer,text,uuid) TO dvaia_identity_runtime;
