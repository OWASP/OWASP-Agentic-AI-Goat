-- Forward-only: settled CTF deletion is a permanent denial tombstone, not pending delivery.
CREATE OR REPLACE FUNCTION identity.enqueue_ctf_user_command(p_actor bigint,p_session bigint,p_token_hash text,p_operation uuid,p_canonical text,p_hash text)
RETURNS TABLE(operation_id uuid,sequence bigint,state text,command_hash text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE e jsonb; b jsonb; sc jsonb; k text; target bigint; sid bigint; seq bigint; units smallint:=0;
 g identity.ctf_authority%ROWTYPE; o identity.ctf_authority%ROWTYPE; st identity.ctf_stage_bindings%ROWTYPE;
 u identity.users%ROWTYPE; sess identity.user_sessions%ROWTYPE; cfg identity.ctf_config_binding%ROWTYPE;
 part identity.ctf_participant_bindings%ROWTYPE; pr identity.ctf_progress_bindings%ROWTYPE; prior identity.ctf_outbox%ROWTYPE;
 fingerprint text; generation_after bigint; disposition text; r_body jsonb; affected_scope text; expected_keys text[]; allowed_keys text[]; admin_kind boolean; n bigint;
BEGIN
 PERFORM set_config('lock_timeout','250ms',true);
 PERFORM set_config('statement_timeout','2000ms',true);
 IF p_canonical IS NULL OR octet_length(p_canonical)>65536 OR p_hash IS NULL OR p_hash<>encode(sha256(convert_to(p_canonical,'UTF8')),'hex') THEN RAISE EXCEPTION 'CTF command digest invalid'; END IF;
 IF NOT (p_canonical IS JSON OBJECT WITH UNIQUE KEYS) THEN RAISE EXCEPTION 'CTF duplicate or invalid JSON'; END IF;
 e:=p_canonical::jsonb;b:=e->'body';sc:=e->'scope';k:=e->>'kind';
 IF jsonb_typeof(e) IS DISTINCT FROM 'object' OR jsonb_typeof(b) IS DISTINCT FROM 'object' OR jsonb_typeof(sc) IS DISTINCT FROM 'object'
 OR e->'version' IS DISTINCT FROM '1'::jsonb OR jsonb_typeof(e->'actorId') IS DISTINCT FROM 'string' OR (e->>'actorId')::bigint IS DISTINCT FROM p_actor OR jsonb_typeof(e->'operationId') IS DISTINCT FROM 'string' OR (e->>'operationId')::uuid IS DISTINCT FROM p_operation
 OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(e) key)<>ARRAY['actorId','body','kind','occurredAt','operationId','scope','version']
 OR (SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(sc) key)<>ARRAY['globalRevision','ownerGeneration','ownerId','participantId','progressId','stageId','stageRevision']
 THEN RAISE EXCEPTION 'CTF command envelope invalid'; END IF;
 IF k IS NULL OR k NOT IN ('catalog_mutation','config_mutation','owner_reset','owner_remove','global_reset','ban','unban','blocklist_clear','register','start','hint','admit_attempt','record_blocked_attempt') THEN RAISE EXCEPTION 'CTF command kind unavailable'; END IF;
 expected_keys:=CASE k WHEN 'catalog_mutation' THEN ARRAY['action','fields'] WHEN 'config_mutation' THEN ARRAY['key','value'] WHEN 'ban' THEN ARRAY['reason'] WHEN 'blocklist_clear' THEN ARRAY['memory'] WHEN 'register' THEN ARRAY['clientIp','email','teachingSessionToken','teamName','userAgent','username'] WHEN 'hint' THEN ARRAY['cost','expectedHints'] WHEN 'admit_attempt' THEN ARRAY['failed'] WHEN 'record_blocked_attempt' THEN ARRAY['admissionOperationId','attemptNumber','matchedPayloadHash','payload','payloadHash','reason','response','responseTime','teachingSessionToken','techniqueConfidence','techniqueTag'] ELSE ARRAY[]::text[] END;
 IF COALESCE((SELECT array_agg(key ORDER BY key) FROM jsonb_object_keys(b) key),ARRAY[]::text[])<>expected_keys THEN RAISE EXCEPTION 'CTF command fields invalid'; END IF;
 r_body:=CASE k
 WHEN 'owner_reset' THEN '{"type":"object","properties":{},"optional":false}'::jsonb
 WHEN 'owner_remove' THEN '{"type":"object","properties":{},"optional":false}'::jsonb
 WHEN 'global_reset' THEN '{"type":"object","properties":{},"optional":false}'::jsonb
 WHEN 'unban' THEN '{"type":"object","properties":{},"optional":false}'::jsonb
 WHEN 'start' THEN '{"type":"object","properties":{},"optional":false}'::jsonb
 WHEN 'catalog_mutation' THEN '{"type":"object","properties":{"action":{"type":"string","enum":["create","update","delete"]},"fields":{"type":"object","properties":{"stage_number":{"type":"number","minimum":1,"maximum":2147483647,"integer":true},"stage_name":{"type":"string","bytes":1024},"stage_description":{"type":"string","bytes":8192,"nullable":true},"difficulty_level":{"type":"string","bytes":128,"nullable":true},"ai_guardian_name":{"type":"string","bytes":1024,"nullable":true},"ai_guardian_personality":{"type":"string","bytes":8192,"nullable":true},"system_prompt":{"type":"string","bytes":16384,"nullable":true},"success_criteria":{"type":"string","bytes":4096},"hints":{"type":"string","bytes":8192,"nullable":true},"stage_order":{"type":"number","minimum":0,"maximum":2147483647,"integer":true},"difficulty":{"type":"string","enum":["trivial","easy","medium","hard","expert","legendary"]},"defense_style":{"type":"string","bytes":4096},"adaptive_mode":{"type":"string","enum":["none","technique","payload","hybrid"]},"level_score":{"type":"number","minimum":0,"maximum":1000000,"integer":true},"time_bonus_seconds":{"type":"number","minimum":0,"maximum":2147483647,"integer":true},"feedback_mode":{"type":"string","enum":["full","reason","silent"]},"is_active":{"type":"number","minimum":0,"maximum":1,"integer":true},"max_attempts":{"type":"number","minimum":-1,"maximum":1000000,"integer":true}},"optional":true}},"optional":false}'::jsonb
 WHEN 'config_mutation' THEN '{"type":"object","properties":{"key":{"type":"string","enum":["ctf_enabled","ctf_visible_to_students","student_leaderboard_visible","public_leaderboard_visible","ctf_registration_open","ctf_max_participants","ctf_time_limit","leaderboard_update_interval","ctf_nav_visible","ctf_show_technique_feedback","ctf_show_attempt_counter","ctf_hint_gating_attempts","ctf_hint_cost_1","ctf_hint_cost_2","ctf_hint_cost_3"]},"value":{"type":"string","bytes":8192}},"optional":false}'::jsonb
 WHEN 'ban' THEN '{"type":"object","properties":{"reason":{"type":"string","bytes":4096}},"optional":false}'::jsonb
 WHEN 'blocklist_clear' THEN '{"type":"object","properties":{"memory":{"type":"string","enum":["technique","payload"]}},"optional":false}'::jsonb
 WHEN 'register' THEN '{"type":"object","properties":{"username":{"type":"string","bytes":256},"email":{"type":"string","bytes":320,"nullable":true},"teamName":{"type":"string","bytes":256,"nullable":true},"teachingSessionToken":{"type":"string","bytes":256},"clientIp":{"type":"string","bytes":128,"nullable":true},"userAgent":{"type":"string","bytes":1024,"nullable":true}},"optional":false}'::jsonb
 WHEN 'hint' THEN '{"type":"object","properties":{"expectedHints":{"type":"number","minimum":0,"maximum":1000000,"integer":true},"cost":{"type":"number","minimum":0,"maximum":715827882,"integer":true}},"optional":false}'::jsonb
 WHEN 'admit_attempt' THEN '{"type":"object","properties":{"failed":{"type":"boolean"}},"optional":false}'::jsonb
 WHEN 'record_blocked_attempt' THEN '{"type":"object","properties":{"admissionOperationId":{"type":"string","bytes":36,"pattern":"^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$"},"matchedPayloadHash":{"type":"string","bytes":64,"pattern":"^[a-f0-9]{64}$","nullable":true},"attemptNumber":{"type":"number","minimum":1,"maximum":1000000,"integer":true},"payload":{"type":"string","bytes":16384},"response":{"type":"string","bytes":16384,"nullable":true},"responseTime":{"type":"number","minimum":0,"maximum":300000,"integer":true},"teachingSessionToken":{"type":"string","bytes":256,"nullable":true},"techniqueTag":{"type":"string","bytes":128,"nullable":true},"techniqueConfidence":{"type":"number","minimum":0,"maximum":1,"nullable":true},"reason":{"type":"string","bytes":4096},"payloadHash":{"type":"string","bytes":64,"pattern":"^[a-f0-9]{64}$","nullable":true}},"optional":false}'::jsonb
 ELSE NULL END;
 IF NOT identity.ctf_json_matches(b,r_body) THEN RAISE EXCEPTION 'CTF command body invalid'; END IF;
 -- SQL callers receive the same closed scope rules as the pure constructor.
 IF EXISTS(SELECT 1 FROM jsonb_each(sc) x WHERE
   CASE WHEN x.key IN ('globalRevision','ownerGeneration','stageRevision') THEN
    NOT identity.ctf_json_matches(x.value,'{"type":"string","bytes":19,"pattern":"^(0|[1-9][0-9]*)$","minimum":0,"maximum":9223372036854775807,"nullable":true}'::jsonb)
   ELSE NOT identity.ctf_json_matches(x.value,'{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647,"nullable":true}'::jsonb) END)
 OR sc->'globalRevision'='null'::jsonb
 OR ((sc->'ownerId'='null'::jsonb) IS DISTINCT FROM (sc->'ownerGeneration'='null'::jsonb))
 OR ((sc->'stageId'='null'::jsonb) IS DISTINCT FROM (sc->'stageRevision'='null'::jsonb))
 OR (k IN ('owner_reset','owner_remove','ban','unban','register','start','hint','admit_attempt','record_blocked_attempt') AND sc->'ownerId'='null'::jsonb)
 OR (k IN ('start','hint','admit_attempt','record_blocked_attempt') AND (sc->'participantId'='null'::jsonb OR sc->'stageId'='null'::jsonb))
 OR (k IN ('hint','admit_attempt','record_blocked_attempt') AND sc->'progressId'='null'::jsonb)
 OR (k IN ('global_reset','config_mutation','catalog_mutation','blocklist_clear') AND EXISTS(SELECT 1 FROM jsonb_each(sc) x WHERE x.key IN ('ownerId','ownerGeneration','participantId','progressId') AND x.value<>'null'::jsonb))
 OR (k IN ('global_reset','config_mutation') AND sc->'stageId'<>'null'::jsonb)
 OR (k IN ('owner_reset','owner_remove','ban','unban','register') AND (sc->'stageId'<>'null'::jsonb OR sc->'progressId'<>'null'::jsonb))
 OR (k IN ('owner_reset','owner_remove') AND sc->'participantId'='null'::jsonb)
 OR (k IN ('ban','unban','register') AND sc->'participantId'<>'null'::jsonb)
 OR (k='start' AND sc->'progressId'<>'null'::jsonb)
 OR (k='catalog_mutation' AND ((b->>'action'='create') IS DISTINCT FROM (sc->'stageId'='null'::jsonb)))
 THEN RAISE EXCEPTION 'CTF command scope invalid'; END IF;
 IF k='catalog_mutation' AND (
   ((b->>'action'='delete') IS DISTINCT FROM (b->'fields'='{}'::jsonb))
   OR (b->>'action'='create' AND NOT (b->'fields' ?& ARRAY['stage_number','stage_name','stage_order']))
   OR (b->>'action'='update' AND b->'fields' ? 'stage_number')) THEN RAISE EXCEPTION 'CTF catalog fields invalid'; END IF;
 IF jsonb_typeof(e->'occurredAt') IS DISTINCT FROM 'string' OR NOT (e->>'occurredAt' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$')
 OR p_actor IS NULL OR p_actor NOT BETWEEN 1 AND 2147483647 OR p_session IS NULL OR p_session NOT BETWEEN 1 AND 2147483647
 OR e->>'actorId' !~ '^[1-9][0-9]*$' OR e->>'operationId' !~ '^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$'
 OR p_operation IS NULL OR p_token_hash IS NULL OR p_token_hash !~ '^[a-f0-9]{64}$'
 THEN RAISE EXCEPTION 'CTF authority scalar invalid'; END IF;
 IF k='config_mutation' THEN
  IF b->>'key' IN ('ctf_max_participants','ctf_time_limit','leaderboard_update_interval','ctf_hint_gating_attempts','ctf_hint_cost_1','ctf_hint_cost_2','ctf_hint_cost_3') THEN
   IF NOT (b->>'value' ~ '^(?:-1|0|[1-9][0-9]*)$') THEN RAISE EXCEPTION 'CTF config scalar invalid'; END IF;
   IF (b->>'value')::numeric < (CASE WHEN b->>'key' IN ('ctf_max_participants','ctf_time_limit') THEN -1 ELSE 0 END)
    OR (b->>'value')::numeric > (CASE WHEN b->>'key' IN ('ctf_max_participants','ctf_time_limit') THEN 9223372036854775807 WHEN b->>'key' IN ('ctf_hint_cost_1','ctf_hint_cost_2','ctf_hint_cost_3') THEN 715827882 ELSE 2147483647 END)
   THEN RAISE EXCEPTION 'CTF config scalar range invalid'; END IF;
  ELSIF b->>'value' NOT IN ('true','false') THEN RAISE EXCEPTION 'CTF config boolean invalid'; END IF;
 END IF;
 target:=(sc->>'ownerId')::bigint;sid:=(sc->>'stageId')::bigint;
 admin_kind:=k IN ('catalog_mutation','config_mutation','owner_reset','owner_remove','global_reset','ban','unban','blocklist_clear');
 IF NOT admin_kind AND target IS DISTINCT FROM p_actor THEN RAISE EXCEPTION 'CTF owner mismatch'; END IF;
 SELECT * INTO g FROM identity.ctf_authority a WHERE a.scope_key='global' FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'CTF authority uninitialized'; END IF;
 IF sid IS NOT NULL THEN PERFORM 1 FROM identity.ctf_authority a WHERE a.scope_key='stage:'||sid FOR UPDATE; END IF;
 IF target IS NOT NULL THEN PERFORM 1 FROM identity.ctf_authority a WHERE a.scope_key='owner:'||target FOR UPDATE; END IF;
 PERFORM 1 FROM identity.users WHERE id IN (p_actor,target) ORDER BY id FOR UPDATE;
 SELECT * INTO u FROM identity.users WHERE id=p_actor;
 SELECT * INTO sess FROM identity.user_sessions WHERE id=p_session AND user_id=p_actor FOR UPDATE;
 IF u.id IS NULL OR u.is_active<>1 OR (u.account_locked_until IS NOT NULL AND u.account_locked_until>clock_timestamp())
 OR sess.id IS NULL OR sess.is_active<>1 OR sess.expires_at<=clock_timestamp() OR sess.session_token_hash IS DISTINCT FROM p_token_hash
 OR EXISTS(SELECT 1 FROM identity.student_deletion_jobs WHERE subject_user_id=p_actor)
 OR EXISTS(SELECT 1 FROM identity.student_deletion_run_blocks WHERE owner_key='["CTF","'||p_actor||'"]')
 THEN RAISE EXCEPTION 'SESSION_REVOKED' USING ERRCODE='28000'; END IF;
 IF admin_kind AND NOT (u.role='admin' OR COALESCE(u.admin_level,0)>0) THEN RAISE EXCEPTION 'CTF admin required' USING ERRCODE='42501'; END IF;
 -- Graph rows follow user/session locks. No advisory lock is acquired here.
 IF target IS NOT NULL THEN
  INSERT INTO graph_runtime.owners(owner_key) VALUES('["CTF","'||target||'"]') ON CONFLICT DO NOTHING;
  PERFORM 1 FROM graph_runtime.owners WHERE owner_key='["CTF","'||target||'"]' FOR UPDATE;
  INSERT INTO identity.ctf_authority(scope_key,owner_generation,lifecycle_state)
   SELECT 'owner:'||target,generation,'ready' FROM graph_runtime.owners WHERE owner_key='["CTF","'||target||'"]' ON CONFLICT DO NOTHING;
  SELECT * INTO o FROM identity.ctf_authority a WHERE a.scope_key='owner:'||target FOR UPDATE;
  IF o.owner_generation IS DISTINCT FROM (SELECT generation FROM graph_runtime.owners WHERE owner_key='["CTF","'||target||'"]') THEN RAISE EXCEPTION 'CTF owner generation drift'; END IF;
 END IF;
 fingerprint:=encode(sha256(convert_to((jsonb_build_object('actor',p_actor,'kind',k,'scope',sc,'body',b))::text,'UTF8')),'hex');
 SELECT * INTO prior FROM identity.ctf_outbox x WHERE x.operation_id=p_operation;
 IF FOUND THEN
  IF prior.actor_id IS DISTINCT FROM p_actor OR prior.request_fingerprint IS DISTINCT FROM fingerprint THEN RAISE EXCEPTION 'CTF operation conflict'; END IF;
  RETURN QUERY SELECT prior.operation_id,prior.sequence,prior.state,prior.command_hash;RETURN;
 END IF;
 IF k='global_reset' AND (g.next_sequence<>g.applied_sequence OR EXISTS(SELECT 1 FROM identity.ctf_outbox AS queued WHERE queued.state IN ('pending','blocked')) OR EXISTS(SELECT 1 FROM identity.ctf_authority tomb WHERE tomb.lifecycle_state IN ('pending','blocked') AND NOT EXISTS(
 SELECT 1 FROM identity.ctf_outbox deleted
 JOIN identity.ctf_deletion_commands dc ON dc.operation_id=deleted.operation_id AND dc.sequence=deleted.sequence
 JOIN identity.student_deletion_jobs job ON job.job_id=dc.job_id AND job.subject_user_id=dc.subject_id
 JOIN identity.student_deletion_run_blocks rb ON rb.job_id=job.job_id AND rb.owner_key='["CTF","'||dc.subject_id||'"]'
 CROSS JOIN LATERAL (SELECT CASE WHEN deleted.canonical_result IS JSON OBJECT WITH UNIQUE KEYS THEN deleted.canonical_result::jsonb ELSE NULL END AS receipt) proof
 WHERE (tomb.lifecycle_state='blocked' AND tomb.failure_code='student_deleted' AND tomb.banned=true AND tomb.pending_operation_id IS NULL
 AND tomb.scope_key='owner:'||dc.subject_id AND tomb.blocked_operation_id=deleted.operation_id
 AND deleted.kind='student_delete' AND deleted.state='applied'
 AND identity.ctf_deletion_command_matches(deleted.command)
 AND deleted.command->>'subjectId'=dc.subject_id::text AND deleted.command->>'jobId'=dc.job_id::text
 AND deleted.command->>'operationId'=deleted.operation_id::text
 AND deleted.command->>'generationAfter'=tomb.owner_generation::text
 AND deleted.command->>'ownerRevision'=tomb.revision::text
 AND deleted.command=(CASE WHEN deleted.canonical_command IS JSON OBJECT WITH UNIQUE KEYS THEN deleted.canonical_command::jsonb ELSE NULL END)
 AND deleted.command_hash=encode(sha256(convert_to(deleted.canonical_command,'UTF8')),'hex')
 AND octet_length(deleted.canonical_result)<=16384
 AND identity.ctf_deletion_receipt_matches(proof.receipt)
 AND deleted.result_hash=encode(sha256(convert_to(deleted.canonical_result,'UTF8')),'hex')
 AND proof.receipt->>'operationId'=deleted.operation_id::text AND proof.receipt->>'sequence'=deleted.sequence::text
 AND proof.receipt->>'commandHash'=deleted.command_hash AND proof.receipt->>'outcome'='applied'
 AND proof.receipt->'data'->'jobId'=deleted.command->'jobId' AND proof.receipt->'data'->'subjectId'=deleted.command->'subjectId'
 AND proof.receipt->'data'->'participantId'=deleted.command->'participantId'
 AND proof.receipt->'data'->'generationBefore'=deleted.command->'generationBefore'
 AND proof.receipt->'data'->'generationAfter'=deleted.command->'generationAfter'
 AND proof.receipt->'data'->'policyVersion'=deleted.command->'policyVersion'
 AND proof.receipt->'data'->'removed'->>'participants'=(CASE WHEN deleted.command->'participantId'='null'::jsonb THEN '0' ELSE '1' END)
 AND EXISTS(SELECT 1 FROM graph_runtime.owners retained WHERE retained.owner_key=rb.owner_key AND retained.generation=tomb.owner_generation)) IS TRUE)) OR EXISTS(SELECT 1 FROM identity.ctf_registration_reservations AS reservation WHERE reservation.state='held')) THEN RAISE EXCEPTION 'CTF global reset requires drained delivery'; END IF;
 IF (e->>'occurredAt')::timestamptz IS DISTINCT FROM date_trunc('milliseconds',transaction_timestamp()) THEN RAISE EXCEPTION 'CTF event timestamp invalid'; END IF;
 IF g.lifecycle_state<>'ready' OR (sc->>'globalRevision')::bigint IS DISTINCT FROM g.revision THEN RAISE EXCEPTION 'CTF global authority unavailable'; END IF;
 IF target IS NOT NULL AND (o.lifecycle_state<>'ready' OR o.owner_generation IS DISTINCT FROM (sc->>'ownerGeneration')::bigint
  OR EXISTS(SELECT 1 FROM identity.student_deletion_jobs WHERE subject_user_id=target)
  OR EXISTS(SELECT 1 FROM identity.student_deletion_run_blocks WHERE owner_key='["CTF","'||target||'"]')) THEN RAISE EXCEPTION 'CTF owner authority unavailable'; END IF;
 IF sid IS NOT NULL THEN
  SELECT * INTO st FROM identity.ctf_stage_bindings WHERE stage_id=sid;
  IF st.stage_id IS NULL OR NOT EXISTS(SELECT 1 FROM identity.ctf_authority a WHERE a.scope_key='stage:'||sid AND a.lifecycle_state='ready' AND a.revision=(sc->>'stageRevision')::bigint) THEN RAISE EXCEPTION 'CTF stage authority unavailable'; END IF;
 END IF;
 SELECT * INTO cfg FROM identity.ctf_config_binding WHERE singleton;
 IF cfg.singleton IS NULL THEN RAISE EXCEPTION 'CTF config uninitialized'; END IF;
 SELECT * INTO part FROM identity.ctf_participant_bindings WHERE owner_id=target;
 IF NOT admin_kind AND (NOT cfg.enabled OR (NOT cfg.visible_to_students AND NOT (u.role='admin' OR COALESCE(u.admin_level,0)>0))) THEN RAISE EXCEPTION 'CTF learner visibility unavailable'; END IF;
 IF NOT admin_kind AND k<>'register' THEN
  IF part.owner_id IS NULL OR NOT part.active OR o.banned OR part.banned OR part.owner_generation<>o.owner_generation
    OR part.participant_id IS DISTINCT FROM (sc->>'participantId')::bigint OR st.stage_id IS NULL OR NOT st.active
    OR (cfg.time_limit_ms<>-1 AND extract(epoch FROM clock_timestamp()-part.registered_at)*1000>cfg.time_limit_ms)
  THEN RAISE EXCEPTION 'CTF learner eligibility unavailable'; END IF;
  SELECT * INTO pr FROM identity.ctf_progress_bindings WHERE owner_id=target AND owner_generation=o.owner_generation AND stage_id=sid;
  IF k<>'start' AND (pr.progress_id IS NULL OR pr.progress_id IS DISTINCT FROM (sc->>'progressId')::bigint OR pr.status<>'in_progress') THEN RAISE EXCEPTION 'CTF progress incarnation unavailable'; END IF;
 END IF;
 IF k='register' THEN
  IF NOT cfg.registration_open THEN RAISE EXCEPTION 'CTF registration closed'; END IF;
  units:=CASE WHEN part.active THEN 0 ELSE 1 END;
  SELECT (SELECT count(*) FROM identity.ctf_participant_bindings WHERE active)+COALESCE((SELECT sum(r.units) FROM identity.ctf_registration_reservations r WHERE r.state='held'),0) INTO n;
  IF units=1 AND cfg.max_participants<>-1 AND n+1>cfg.max_participants THEN RAISE EXCEPTION 'CTF capacity reached'; END IF;
 ELSIF k='start' THEN
  IF EXISTS(SELECT 1 FROM identity.ctf_stage_bindings prev WHERE prev.active AND prev.stage_order=(SELECT max(stage_order) FROM identity.ctf_stage_bindings WHERE active AND stage_order<st.stage_order)
    AND NOT EXISTS(SELECT 1 FROM identity.ctf_progress_bindings p WHERE p.owner_id=target AND p.owner_generation=o.owner_generation AND p.stage_id=prev.stage_id AND p.status='completed')) THEN RAISE EXCEPTION 'CTF prerequisite incomplete'; END IF;
 ELSIF k='hint' THEN
  IF pr.hints_used IS DISTINCT FROM (b->>'expectedHints')::integer OR pr.hints_used>=st.hint_count OR pr.hints_used>=3 OR pr.attempts_count<cfg.hint_gating_attempts
   OR (b->>'cost')::integer IS DISTINCT FROM (CASE pr.hints_used WHEN 0 THEN cfg.hint_cost_1 WHEN 1 THEN cfg.hint_cost_2 ELSE cfg.hint_cost_3 END) THEN RAISE EXCEPTION 'CTF hint eligibility changed'; END IF;
 ELSIF k='record_blocked_attempt' THEN
  IF NOT EXISTS(SELECT 1 FROM identity.ctf_attempt_admissions a WHERE a.operation_id=(b->>'admissionOperationId')::uuid AND a.owner_id=target AND a.owner_generation=o.owner_generation AND a.progress_id=pr.progress_id AND a.attempt_number=(b->>'attemptNumber')::integer) THEN RAISE EXCEPTION 'CTF attempt admission unavailable'; END IF;
 END IF;
 IF (SELECT count(*) FROM identity.ctf_outbox AS queued WHERE queued.state='pending')>=512 OR (SELECT COALESCE(sum(octet_length(queued.command::text)),0) FROM identity.ctf_outbox AS queued WHERE queued.state='pending')+octet_length(p_canonical)>16777216
 OR EXISTS(SELECT 1 FROM identity.ctf_outbox AS queued WHERE queued.state='pending' AND queued.created_at<clock_timestamp()-interval '60 seconds') THEN RAISE EXCEPTION 'CTF delivery backlog unavailable'; END IF;
 generation_after:=o.owner_generation;
 IF k='register' THEN
  disposition:=CASE WHEN part.owner_id IS NULL THEN 'new' WHEN part.active THEN 'active_recovery' ELSE 'reactivate' END;
 END IF;
 IF target IS NOT NULL AND (k IN ('owner_reset','owner_remove') OR (k='register' AND disposition<>'active_recovery')) THEN
  UPDATE graph_runtime.owners SET generation=generation+1,updated_at=clock_timestamp() WHERE owner_key='["CTF","'||target||'"]' RETURNING generation INTO generation_after;
  UPDATE identity.ctf_authority SET owner_generation=generation_after,revision=revision+1 WHERE identity.ctf_authority.scope_key='owner:'||target;
 END IF;
 seq:=g.next_sequence+1;
 UPDATE identity.ctf_authority SET next_sequence=seq WHERE identity.ctf_authority.scope_key='global';
 INSERT INTO identity.ctf_outbox(sequence,operation_id,kind,command,command_hash,actor_id,session_id,request_fingerprint,canonical_command,owner_generation_after,registration_disposition,registration_participant_before)
 VALUES(seq,p_operation,k,e,p_hash,p_actor,p_session,fingerprint,p_canonical,generation_after,disposition,CASE WHEN k='register' THEN part.participant_id ELSE NULL END);
 IF target IS NOT NULL THEN
  UPDATE identity.ctf_authority SET lifecycle_state='pending',pending_operation_id=p_operation WHERE identity.ctf_authority.scope_key='owner:'||target;
 ELSE
  affected_scope:=CASE WHEN k IN ('catalog_mutation','blocklist_clear') AND sid IS NOT NULL AND NOT (k='catalog_mutation' AND (b->>'action'='delete' OR b->'fields' ?| ARRAY['stage_order','is_active'])) THEN 'stage:'||sid ELSE 'global' END;
  UPDATE identity.ctf_authority SET lifecycle_state='pending',pending_operation_id=p_operation,revision=revision+1 WHERE identity.ctf_authority.scope_key=affected_scope;
 END IF;
 IF k='register' THEN INSERT INTO identity.ctf_registration_reservations(operation_id,sequence,owner_id,units) VALUES(p_operation,seq,target,units); END IF;
 RETURN QUERY SELECT p_operation,seq,'pending'::text,p_hash;
END; $$;
REVOKE ALL ON FUNCTION identity.enqueue_ctf_user_command(bigint,bigint,text,uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.enqueue_ctf_user_command(bigint,bigint,text,uuid,text,text) TO dvaia_identity_runtime;
