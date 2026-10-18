-- Canonical platform administrator policy. Existing receipts and grants remain unchanged.
-- CREATE OR REPLACE preserves ACLs, including private helper runtime revocations.

-- Preserves existing signature, SECURITY DEFINER/search_path and ACLs from 0121_ctf_global_reset_deleted_tombstones.sql
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
 WHEN 'catalog_mutation' THEN '{"type":"object","properties":{"action":{"type":"string","enum":["create","update","delete"]},"fields":{"type":"object","properties":{"stage_number":{"type":"number","minimum":1,"maximum":2147483647,"integer":true},"stage_name":{"type":"string","bytes":1024},"stage_description":{"type":"string","bytes":8192,"nullable":true},"difficulty_level":{"type":"string","bytes":128,"nullable":true},"ai_guardian_name":{"type":"string","bytes":1024,"nullable":true},"ai_guardian_personality":{"type":"string","bytes":8192,"nullable":true},"system_prompt":{"type":"string","bytes":16384,"nullable":true},"success_criteria":{"type":"string","bytes":4096},"hints":{"type":"string","bytes":8192,"nullable":true},"teaching_objective":{"type":"string","bytes":8192},"solution_content":{"type":"string","bytes":16384},"stage_order":{"type":"number","minimum":0,"maximum":2147483647,"integer":true},"difficulty":{"type":"string","enum":["trivial","easy","medium","hard","expert","legendary"]},"defense_style":{"type":"string","bytes":4096},"adaptive_mode":{"type":"string","enum":["none","technique","payload","hybrid"]},"level_score":{"type":"number","minimum":0,"maximum":1000000,"integer":true},"time_bonus_seconds":{"type":"number","minimum":0,"maximum":2147483647,"integer":true},"feedback_mode":{"type":"string","enum":["full","reason","silent"]},"is_active":{"type":"number","minimum":0,"maximum":1,"integer":true},"max_attempts":{"type":"number","minimum":-1,"maximum":1000000,"integer":true}},"optional":true}},"optional":false}'::jsonb
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
 IF admin_kind AND NOT (u.role IN ('admin','super_admin') AND COALESCE(u.admin_level,0)>=1) THEN RAISE EXCEPTION 'CTF admin required' USING ERRCODE='42501'; END IF;
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
 IF NOT admin_kind AND (NOT cfg.enabled OR (NOT cfg.visible_to_students AND NOT (u.role IN ('admin','super_admin') AND COALESCE(u.admin_level,0)>=1))) THEN RAISE EXCEPTION 'CTF learner visibility unavailable'; END IF;
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

-- Preserves existing signature, SECURITY DEFINER/search_path and ACLs from 0111_ctf_operation_recovery.sql
CREATE OR REPLACE FUNCTION identity.read_ctf_user_operation(p_operation uuid,p_actor integer,p_session integer,p_token_hash text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE u identity.users%ROWTYPE;ev identity.ctf_outbox%ROWTYPE;r jsonb;
BEGIN
 SELECT * INTO u FROM identity.users uu WHERE uu.id=p_actor FOR UPDATE;
 PERFORM 1 FROM identity.user_sessions us WHERE us.id=p_session AND us.user_id=p_actor FOR UPDATE;
 IF u.id IS NULL OR u.is_active IS DISTINCT FROM 1 OR (u.account_locked_until IS NOT NULL AND u.account_locked_until>clock_timestamp())
 OR NOT EXISTS(SELECT 1 FROM identity.user_sessions us WHERE us.id=p_session AND us.user_id=p_actor AND us.is_active=1 AND us.expires_at>clock_timestamp() AND us.session_token_hash=p_token_hash)
 OR EXISTS(SELECT 1 FROM identity.student_deletion_jobs dj WHERE dj.subject_user_id=p_actor)
 OR EXISTS(SELECT 1 FROM identity.student_deletion_run_blocks rb WHERE rb.owner_key='["CTF","'||p_actor||'"]') THEN RAISE EXCEPTION 'SESSION_REVOKED' USING ERRCODE='28000'; END IF;
 -- No global/scope/outbox lock follows user locks: one MVCC row snapshot
 -- observes pending or an immutable applied receipt without lock inversion.
 SELECT * INTO ev FROM identity.ctf_outbox oo WHERE oo.operation_id=p_operation AND oo.actor_id=p_actor AND oo.session_id=p_session;
 IF NOT FOUND THEN RETURN NULL; END IF;
 IF ev.kind NOT IN ('register','start','hint','admit_attempt','record_blocked_attempt','catalog_mutation','config_mutation','owner_reset','owner_remove','global_reset','ban','unban','blocklist_clear') THEN RAISE EXCEPTION 'CTF operation unavailable' USING ERRCODE='42501'; END IF;
 IF ev.kind IN ('catalog_mutation','config_mutation','owner_reset','owner_remove','global_reset','ban','unban','blocklist_clear') AND NOT(u.role IN ('admin','super_admin') AND COALESCE(u.admin_level,0)>=1) THEN RAISE EXCEPTION 'CTF operation unavailable' USING ERRCODE='42501'; END IF;
 IF ev.canonical_command IS NULL OR NOT(ev.canonical_command IS JSON OBJECT WITH UNIQUE KEYS)
 OR ev.command IS DISTINCT FROM ev.canonical_command::jsonb OR ev.command_hash IS DISTINCT FROM encode(sha256(convert_to(ev.canonical_command,'UTF8')),'hex')
 OR ev.command->>'operationId' IS DISTINCT FROM ev.operation_id::text OR ev.command->>'actorId' IS DISTINCT FROM p_actor::text OR ev.command->>'kind' IS DISTINCT FROM ev.kind
 THEN RAISE EXCEPTION 'CTF operation encoding unavailable' USING ERRCODE='42501'; END IF;
 IF ev.canonical_result IS NOT NULL THEN
  IF NOT(ev.canonical_result IS JSON OBJECT WITH UNIQUE KEYS) OR ev.result_hash IS DISTINCT FROM encode(sha256(convert_to(ev.canonical_result,'UTF8')),'hex') THEN RAISE EXCEPTION 'CTF operation receipt unavailable' USING ERRCODE='42501'; END IF;
  r:=ev.canonical_result::jsonb;
  IF NOT identity.ctf_result_matches(r) OR r->>'operationId' IS DISTINCT FROM ev.operation_id::text OR r->>'sequence' IS DISTINCT FROM ev.sequence::text OR r->>'commandHash' IS DISTINCT FROM ev.command_hash OR r->>'kind' IS DISTINCT FROM ev.kind THEN RAISE EXCEPTION 'CTF operation receipt unavailable' USING ERRCODE='42501'; END IF;
 ELSIF ev.state='applied' THEN RAISE EXCEPTION 'CTF operation receipt unavailable' USING ERRCODE='42501'; END IF;
 RETURN jsonb_build_object('actorId',p_actor::text,'sessionId',p_session::text,'state',ev.state,'sequence',ev.sequence::text,'canonicalCommand',ev.canonical_command,'commandHash',ev.command_hash,'canonicalResult',ev.canonical_result,'resultHash',ev.result_hash,'currentState',false);
END; $$;

-- Preserves existing signature, SECURITY DEFINER/search_path and ACLs from 0109_ctf_current_publication.sql
CREATE OR REPLACE FUNCTION identity.authorize_ctf_current_publication(p_decision uuid,p_actor integer,p_session integer,p_token_hash text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE d identity.ctf_decisions%ROWTYPE;g identity.ctf_authority%ROWTYPE;s identity.ctf_authority%ROWTYPE;o identity.ctf_authority%ROWTYPE;
 u identity.users%ROWTYPE;part identity.ctf_participant_bindings%ROWTYPE;pr identity.ctf_progress_bindings%ROWTYPE;st identity.ctf_stage_bindings%ROWTYPE;cfg identity.ctf_config_binding%ROWTYPE;ev identity.ctf_outbox%ROWTYPE;
BEGIN
 SELECT * INTO d FROM identity.ctf_decisions dd WHERE dd.decision_id=p_decision;
 IF d.decision_id IS NULL OR d.owner_id IS DISTINCT FROM p_actor OR d.session_id IS DISTINCT FROM p_session OR d.proposal_id IS NULL THEN RAISE EXCEPTION 'CTF publication unavailable' USING ERRCODE='42501'; END IF;
 -- Match enqueue/authorization lock order; never lock deletion jobs after user.
 SELECT * INTO g FROM identity.ctf_authority a WHERE a.scope_key='global' FOR UPDATE;
 SELECT * INTO s FROM identity.ctf_authority a WHERE a.scope_key='stage:'||d.stage_id FOR UPDATE;
 SELECT * INTO o FROM identity.ctf_authority a WHERE a.scope_key='owner:'||p_actor FOR UPDATE;
 SELECT * INTO u FROM identity.users uu WHERE uu.id=p_actor FOR UPDATE;
 PERFORM 1 FROM identity.user_sessions us WHERE us.id=p_session AND us.user_id=p_actor FOR UPDATE;
 IF u.id IS NULL OR u.is_active IS DISTINCT FROM 1 OR (u.account_locked_until IS NOT NULL AND u.account_locked_until>clock_timestamp())
 OR NOT EXISTS(SELECT 1 FROM identity.user_sessions us WHERE us.id=p_session AND us.user_id=p_actor AND us.is_active=1 AND us.expires_at>clock_timestamp() AND us.session_token_hash=p_token_hash)
 OR EXISTS(SELECT 1 FROM identity.student_deletion_jobs dj WHERE dj.subject_user_id=p_actor)
 OR EXISTS(SELECT 1 FROM identity.student_deletion_run_blocks rb WHERE rb.owner_key='["CTF","'||p_actor||'"]') THEN RAISE EXCEPTION 'SESSION_REVOKED' USING ERRCODE='28000'; END IF;
 PERFORM 1 FROM graph_runtime.owners go WHERE go.owner_key=d.owner_key FOR UPDATE;
 PERFORM 1 FROM graph_runtime.runs gr WHERE gr.run_id=d.run_id FOR UPDATE;
 IF identity.ctf_publication_bootstrap_ready() IS DISTINCT FROM true OR g.lifecycle_state IS DISTINCT FROM 'ready' OR s.lifecycle_state IS DISTINCT FROM 'ready' OR o.lifecycle_state IS DISTINCT FROM 'ready'
 OR g.revision IS DISTINCT FROM d.global_revision OR s.revision IS DISTINCT FROM d.stage_revision OR o.owner_generation IS DISTINCT FROM d.owner_generation OR o.banned
 OR d.owner_key IS DISTINCT FROM '["CTF","'||p_actor||'"]'
 OR NOT EXISTS(SELECT 1 FROM graph_runtime.owners go WHERE go.owner_key=d.owner_key AND go.generation=d.owner_generation)
 OR NOT EXISTS(SELECT 1 FROM graph_runtime.runs gr WHERE gr.run_id=d.run_id AND gr.owner_key=d.owner_key AND gr.generation=d.owner_generation AND gr.status IN ('running','completed'))
 THEN RAISE EXCEPTION 'CTF publication scope stale' USING ERRCODE='42501'; END IF;
 -- A completed run can publish its acknowledged current result; cancelled,
 -- failed and interrupted executions cannot. Running status
 -- is not required. Historical binding revision stamps are provenance only.
 SELECT * INTO part FROM identity.ctf_participant_bindings b WHERE b.owner_id=p_actor;
 SELECT * INTO pr FROM identity.ctf_progress_bindings b WHERE b.progress_id=d.progress_id;
 SELECT * INTO st FROM identity.ctf_stage_bindings b WHERE b.stage_id=d.stage_id;
 SELECT * INTO cfg FROM identity.ctf_config_binding b WHERE b.singleton;
 SELECT * INTO ev FROM identity.ctf_outbox b WHERE b.decision_id=d.decision_id AND b.sequence=d.sequence;
 IF part.active IS DISTINCT FROM true OR part.banned IS DISTINCT FROM false OR part.owner_generation IS DISTINCT FROM d.owner_generation OR part.participant_id IS DISTINCT FROM d.participant_id
 OR pr.owner_id IS DISTINCT FROM p_actor OR pr.owner_generation IS DISTINCT FROM d.owner_generation OR pr.participant_id IS DISTINCT FROM d.participant_id OR pr.stage_id IS DISTINCT FROM d.stage_id
 OR st.active IS DISTINCT FROM true OR st.stage_digest IS DISTINCT FROM d.stage_digest
 OR cfg.enabled IS DISTINCT FROM true OR (cfg.visible_to_students IS DISTINCT FROM true AND NOT(u.role IN ('admin','super_admin') AND COALESCE(u.admin_level,0)>=1))
 OR pr.applied_operation_id IS DISTINCT FROM d.decision_id OR pr.applied_sequence IS DISTINCT FROM d.sequence
 OR pr.status IS DISTINCT FROM (CASE WHEN d.accepted THEN 'completed' ELSE 'in_progress' END)
 OR pr.completion_time IS DISTINCT FROM d.completion_time_ms OR (d.accepted AND pr.completed_at IS DISTINCT FROM d.authorized_at)
 OR ev.kind IS DISTINCT FROM 'decision' OR ev.operation_id IS DISTINCT FROM d.decision_id OR ev.actor_id IS DISTINCT FROM p_actor OR ev.session_id IS DISTINCT FROM p_session
 OR ev.state IS DISTINCT FROM 'applied' OR ev.canonical_result IS NULL OR ev.result_hash IS DISTINCT FROM encode(sha256(convert_to(ev.canonical_result,'UTF8')),'hex')
 OR g.applied_sequence<d.sequence
 THEN RAISE EXCEPTION 'CTF publication projection unavailable' USING ERRCODE='42501'; END IF;
 IF NOT EXISTS(SELECT 1 FROM identity.ctf_decision_proposals p JOIN identity.ctf_decision_inputs i ON i.admission_id=p.admission_operation_id
 JOIN identity.ctf_attempt_admissions a ON a.operation_id=i.admission_id JOIN identity.ctf_outbox admission ON admission.operation_id=a.operation_id
 JOIN identity.ctf_decision_projection_facts f ON f.decision_id=d.decision_id AND f.sequence=d.sequence
 WHERE p.proposal_id=d.proposal_id AND p.owner_id=p_actor AND p.session_id=p_session AND p.run_id=d.run_id AND p.evidence_hash=d.evidence_hash
 AND i.owner_id=p_actor AND i.session_id=p_session AND i.run_id=d.run_id AND i.input->'binding'=p.evidence->'binding'
 AND a.owner_id=p_actor AND a.owner_generation=d.owner_generation AND a.participant_id=d.participant_id AND a.progress_id=d.progress_id AND a.stage_id=d.stage_id
 AND admission.actor_id=p_actor AND admission.session_id=p_session AND admission.state='applied' AND admission.kind='admit_attempt'
 AND f.evidence_hash=d.evidence_hash AND ev.canonical_result::jsonb->'data'->>'factsHash'=f.facts_hash)
 OR NOT identity.ctf_decision_receipt_matches(ev.canonical_result::jsonb)
 OR ev.canonical_result::jsonb->>'operationId' IS DISTINCT FROM d.decision_id::text
 OR ev.canonical_result::jsonb->>'sequence' IS DISTINCT FROM d.sequence::text
 OR ev.canonical_result::jsonb->>'commandHash' IS DISTINCT FROM ev.command_hash
 OR ev.canonical_result::jsonb->'data'->'accepted' IS DISTINCT FROM to_jsonb(d.accepted)
 OR ev.canonical_result::jsonb->'data'->>'verdict' IS DISTINCT FROM d.verdict
 OR ev.canonical_result::jsonb->'data'->>'progressId' IS DISTINCT FROM d.progress_id::text
 OR ev.canonical_result::jsonb->'data'->>'decisionId' IS DISTINCT FROM d.decision_id::text
 OR ev.canonical_result::jsonb->'data'->>'evidenceHash' IS DISTINCT FROM d.evidence_hash
 THEN RAISE EXCEPTION 'CTF publication receipt unavailable' USING ERRCODE='42501'; END IF;
 RETURN jsonb_build_object('decisionId',d.decision_id,'runId',d.run_id,'sequence',d.sequence::text,'verdict',d.verdict,'currentCompletion',d.accepted,'evidenceHash',d.evidence_hash,'authorizedAt',to_char(d.authorized_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'));
END; $$;

-- Preserves existing signature, SECURITY DEFINER/search_path and ACLs from 0113_ctf_predefense_claim.sql
CREATE OR REPLACE FUNCTION identity.lock_ctf_predefense(p_actor integer,p_session integer,p_hash text,b jsonb,p_current boolean)
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
 OR cfg.enabled IS DISTINCT FROM true OR (NOT cfg.visible_to_students AND NOT(u.role IN ('admin','super_admin') AND COALESCE(u.admin_level,0)>=1))
 OR (cfg.time_limit_ms<>-1 AND extract(epoch FROM clock_timestamp()-part.registered_at)*1000>cfg.time_limit_ms) THEN RAISE EXCEPTION 'CTF pre-defense eligibility unavailable'; END IF;
END; $$;

-- Preserves existing signature, SECURITY DEFINER/search_path and ACLs from 0120_ctf_completed_proposal_authorization.sql
CREATE OR REPLACE FUNCTION identity.authorize_ctf_decision(p_proposal uuid,p_actor integer,p_session integer,p_token_hash text,p_decision uuid)
RETURNS TABLE(decision_id uuid,accepted boolean,verdict text,sequence bigint,authorized_at timestamptz,replayed boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE p identity.ctf_decision_proposals%ROWTYPE;prior identity.ctf_decisions%ROWTYPE;e jsonb;b jsonb;j jsonb;g identity.ctf_authority%ROWTYPE;o identity.ctf_authority%ROWTYPE;s identity.ctf_authority%ROWTYPE;
 st identity.ctf_stage_bindings%ROWTYPE;pr identity.ctf_progress_bindings%ROWTYPE;part identity.ctf_participant_bindings%ROWTYPE;cfg identity.ctf_config_binding%ROWTYPE;u identity.users%ROWTYPE;
 memory jsonb;entry jsonb;blocked boolean:=false;real_guardian boolean;real_judge boolean;credit boolean;v text;seq bigint;at_time timestamptz;elapsed bigint;consume boolean;mutated integer:=0;n integer;command jsonb;encoded text;digest text;
BEGIN
 SELECT * INTO p FROM identity.ctf_decision_proposals WHERE proposal_id=p_proposal;
 IF p.proposal_id IS NULL OR p.owner_id IS DISTINCT FROM p_actor OR p.session_id IS DISTINCT FROM p_session THEN RAISE EXCEPTION 'CTF proposal unavailable'; END IF;
 e:=p.evidence;b:=e->'binding';j:=e->'judgment';
 IF NOT EXISTS(SELECT 1 FROM identity.ctf_decision_inputs di JOIN identity.ctf_attempt_admissions aa ON aa.operation_id=di.admission_id WHERE di.admission_id=p.admission_operation_id AND di.run_id=p.run_id AND di.owner_id=p_actor AND di.session_id=p_session AND di.input->'binding'=b AND aa.owner_id=p_actor AND aa.owner_generation=(b->>'ownerGeneration')::bigint AND aa.participant_id=(b->>'participantId')::bigint AND aa.progress_id=(b->>'progressId')::bigint AND aa.stage_id=(b->>'stageId')::bigint) THEN RAISE EXCEPTION 'CTF decision admission mismatch'; END IF;
 SELECT * INTO g FROM identity.ctf_authority WHERE scope_key='global' FOR UPDATE;
 SELECT * INTO s FROM identity.ctf_authority WHERE scope_key='stage:'||(b->>'stageId') FOR UPDATE;
 SELECT * INTO o FROM identity.ctf_authority WHERE scope_key='owner:'||p_actor FOR UPDATE;
 SELECT * INTO u FROM identity.users WHERE id=p_actor FOR UPDATE;
 PERFORM 1 FROM identity.user_sessions WHERE id=p_session AND user_id=p_actor FOR UPDATE;
 IF u.id IS NULL OR u.is_active<>1 OR (u.account_locked_until IS NOT NULL AND u.account_locked_until>clock_timestamp())
 OR NOT EXISTS(SELECT 1 FROM identity.user_sessions WHERE id=p_session AND user_id=p_actor AND is_active=1 AND expires_at>clock_timestamp() AND session_token_hash=p_token_hash)
 OR EXISTS(SELECT 1 FROM identity.student_deletion_jobs WHERE subject_user_id=p_actor)
 OR EXISTS(SELECT 1 FROM identity.student_deletion_run_blocks WHERE owner_key='["CTF","'||p_actor||'"]') THEN RAISE EXCEPTION 'SESSION_REVOKED' USING ERRCODE='28000'; END IF;
 PERFORM 1 FROM graph_runtime.owners WHERE owner_key='["CTF","'||p_actor||'"]' FOR UPDATE;
 SELECT * INTO prior FROM identity.ctf_decisions d WHERE d.proposal_id=p_proposal OR d.run_id=p.run_id;
 IF FOUND THEN
  IF prior.proposal_id IS DISTINCT FROM p_proposal OR prior.evidence_hash<>p.evidence_hash THEN RAISE EXCEPTION 'CTF decision replay conflict'; END IF;
  RETURN QUERY SELECT prior.decision_id,prior.accepted,prior.verdict,prior.sequence,prior.authorized_at,true;RETURN;
 END IF;
 PERFORM 1 FROM graph_runtime.runs rr WHERE rr.run_id=p.run_id AND rr.owner_key='["CTF","'||p_actor||'"]' AND rr.generation=(b->>'ownerGeneration')::bigint FOR UPDATE;
 IF g.lifecycle_state IS DISTINCT FROM 'ready' OR o.lifecycle_state IS DISTINCT FROM 'ready' OR s.lifecycle_state IS DISTINCT FROM 'ready'
 OR g.revision IS DISTINCT FROM (b->>'globalRevision')::bigint OR s.revision IS DISTINCT FROM (b->>'stageRevision')::bigint OR o.owner_generation IS DISTINCT FROM (b->>'ownerGeneration')::bigint
 OR NOT EXISTS(SELECT 1 FROM graph_runtime.owners WHERE owner_key='["CTF","'||p_actor||'"]' AND generation=o.owner_generation)
 OR NOT EXISTS(SELECT 1 FROM graph_runtime.runs WHERE run_id=p.run_id AND owner_key='["CTF","'||p_actor||'"]' AND generation=o.owner_generation AND status IN ('running','completed')) THEN RAISE EXCEPTION 'CTF decision scope stale'; END IF;
 SELECT * INTO part FROM identity.ctf_participant_bindings WHERE owner_id=p_actor;
 SELECT * INTO pr FROM identity.ctf_progress_bindings WHERE owner_id=p_actor AND owner_generation=o.owner_generation AND stage_id=(b->>'stageId')::bigint;
 SELECT * INTO st FROM identity.ctf_stage_bindings WHERE stage_id=(b->>'stageId')::bigint;
 SELECT * INTO cfg FROM identity.ctf_config_binding WHERE singleton;
 IF part.active IS DISTINCT FROM true OR part.banned OR o.banned OR part.owner_generation IS DISTINCT FROM o.owner_generation OR part.participant_id IS DISTINCT FROM (b->>'participantId')::bigint
 OR pr.participant_id IS DISTINCT FROM part.participant_id OR pr.progress_id IS DISTINCT FROM (b->>'progressId')::bigint OR pr.status IS DISTINCT FROM 'in_progress'
 OR st.active IS DISTINCT FROM true OR st.stage_digest IS DISTINCT FROM b->>'stageDigest' OR st.stage_number IS DISTINCT FROM (b->>'stageNumber')::integer
 OR cfg.enabled IS DISTINCT FROM true OR (NOT cfg.visible_to_students AND NOT(u.role IN ('admin','super_admin') AND COALESCE(u.admin_level,0)>=1))
 OR (cfg.time_limit_ms<>-1 AND extract(epoch FROM clock_timestamp()-part.registered_at)*1000>cfg.time_limit_ms) THEN RAISE EXCEPTION 'CTF decision membership unavailable'; END IF;
 -- Active memory rows persist across content edits; stage_revision is provenance.
 -- Explicit ordered clear deletes active rows; immutable decisions retain history.
 SELECT jsonb_agg(to_jsonb(x)) INTO memory FROM (SELECT kind,owner_id,owner_generation,technique_tag,payload_hash,normalized_payload FROM identity.ctf_adaptive_memory WHERE stage_id=st.stage_id AND (kind='payload' OR (owner_id=p_actor AND owner_generation=o.owner_generation)) ORDER BY memory_id LIMIT 257)x;
 memory:=COALESCE(memory,'[]'::jsonb);
 IF jsonb_array_length(memory)>256 OR octet_length(memory::text)>262144 THEN RAISE EXCEPTION 'CTF adaptive snapshot unavailable'; END IF;
 FOR entry IN SELECT value FROM jsonb_array_elements(memory) LOOP
  IF entry->>'kind'='payload' AND ((entry->>'normalized_payload') IS NULL OR (entry->>'normalized_payload') !~ '^[a-z0-9_ ]*$' OR entry->>'payload_hash' IS DISTINCT FROM encode(sha256(convert_to(entry->>'normalized_payload','UTF8')),'hex')) THEN RAISE EXCEPTION 'CTF adaptive normalization unavailable'; END IF;
  IF st.adaptive_mode IN ('technique','hybrid') AND entry->>'kind'='technique' AND entry->>'technique_tag'=e->>'techniqueTag' AND e->>'techniqueTag'<>'other' THEN blocked:=true; END IF;
  IF st.adaptive_mode IN ('payload','hybrid') AND entry->>'kind'='payload' AND (entry->>'payload_hash'=e->>'payloadHash' OR identity.ctf_ascii_payload_similar(e->>'normalizedPayload',entry->>'normalized_payload')) THEN blocked:=true; END IF;
 END LOOP;
 real_guardian:=e->'guardian'<>'null'::jsonb;
 real_judge:=j->>'provider' IN ('ollama','anthropic','claude','openai','chatgpt','bedrock','lmstudio') AND length(j->>'model')>0 AND length(j->>'judgeVersion')>0 AND j->>'rubricVersion'='ctf-visible-secret-v2';
 v:=CASE WHEN blocked THEN 'blocked' ELSE j->>'verdict' END;
 credit:=(NOT blocked AND v='pass' AND real_guardian AND real_judge AND e->'observedSecret'='true'::jsonb) IS TRUE;
 IF (SELECT count(*) FROM identity.ctf_outbox queued WHERE queued.state='pending')>=512 OR (SELECT COALESCE(sum(octet_length(queued.command::text)),0) FROM identity.ctf_outbox queued WHERE queued.state='pending')>16711680 OR EXISTS(SELECT 1 FROM identity.ctf_outbox queued WHERE queued.state='pending' AND created_at<clock_timestamp()-interval '60 seconds') THEN RAISE EXCEPTION 'CTF decision backlog unavailable'; END IF;
 at_time:=clock_timestamp();elapsed:=CASE WHEN credit THEN greatest(0,floor(extract(epoch FROM at_time-pr.started_at)*1000))::bigint ELSE NULL END;seq:=g.next_sequence+1;
 INSERT INTO identity.ctf_decisions(decision_id,run_id,owner_id,session_id,owner_key,owner_generation,global_revision,stage_revision,participant_id,progress_id,stage_id,stage_digest,evidence_hash,evidence,verdict,accepted,sequence,authorized_at,proposal_id,completion_time_ms,hint_penalty_total,adaptive_revision)
 VALUES(p_decision,p.run_id,p_actor,p_session,'["CTF","'||p_actor||'"]',o.owner_generation,g.revision,s.revision,part.participant_id,pr.progress_id,st.stage_id,st.stage_digest,p.evidence_hash,e,v,credit,seq,at_time,p_proposal,elapsed,pr.hint_penalty_total,s.adaptive_revision);
 consume:=NOT blocked AND e->>'techniqueTag'<>'other' AND (credit OR (real_guardian AND real_judge AND v='fail' AND st.adaptive_mode IN ('technique','hybrid')));
 IF consume AND NOT EXISTS(SELECT 1 FROM identity.ctf_adaptive_memory WHERE kind='technique' AND stage_id=st.stage_id AND owner_id=p_actor AND owner_generation=o.owner_generation AND technique_tag=e->>'techniqueTag') THEN
  INSERT INTO identity.ctf_adaptive_memory(memory_id,kind,stage_id,stage_revision,clear_revision,owner_id,owner_generation,technique_tag,decision_id) VALUES(gen_random_uuid(),'technique',st.stage_id,s.revision,s.clear_revision,p_actor,o.owner_generation,e->>'techniqueTag',p_decision);mutated:=mutated+1;
 END IF;
 IF credit AND st.adaptive_mode IN ('payload','hybrid') THEN
  INSERT INTO identity.ctf_adaptive_memory(memory_id,kind,stage_id,stage_revision,clear_revision,payload_hash,normalized_payload,decision_id) VALUES(gen_random_uuid(),'payload',st.stage_id,s.revision,s.clear_revision,e->>'payloadHash',e->>'normalizedPayload',p_decision);mutated:=mutated+1;
 END IF;
 IF mutated>0 THEN UPDATE identity.ctf_authority SET adaptive_revision=adaptive_revision+1 WHERE scope_key='stage:'||st.stage_id;END IF;
 command:=jsonb_build_object('version',1,'kind','decision','operationId',p_decision,'actorId',p_actor::text,'occurredAt',to_char(at_time AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),'scope',jsonb_build_object('ownerId',p_actor::text,'ownerGeneration',o.owner_generation::text,'participantId',part.participant_id::text,'progressId',pr.progress_id::text,'stageId',st.stage_id::text,'stageRevision',s.revision::text,'globalRevision',g.revision::text),'body',jsonb_build_object('decisionId',p_decision,'proposalId',p_proposal,'evidenceHash',p.evidence_hash));
 encoded:=command::text;digest:=encode(sha256(convert_to(encoded,'UTF8')),'hex');
 INSERT INTO identity.ctf_outbox(sequence,operation_id,decision_id,kind,command,command_hash,actor_id,session_id,request_fingerprint,canonical_command,owner_generation_after) VALUES(seq,p_decision,p_decision,'decision',command,digest,p_actor,p_session,p.evidence_hash,encoded,o.owner_generation);
 UPDATE identity.ctf_authority SET next_sequence=seq WHERE scope_key='global';
 UPDATE identity.ctf_authority SET lifecycle_state='pending',pending_operation_id=p_decision WHERE scope_key='owner:'||p_actor;
 RETURN QUERY SELECT p_decision,credit,v,seq,at_time,false;
END; $$;

-- Preserves existing signature, SECURITY DEFINER/search_path and ACLs from 0122_ctf_predefense_recovery.sql
CREATE OR REPLACE FUNCTION identity.lock_ctf_predefense_recovery_state(p_actor integer,p_session integer,p_hash text,p_run uuid)
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
 OR cfg.enabled IS DISTINCT FROM true OR (NOT cfg.visible_to_students AND NOT(u.role IN ('admin','super_admin') AND COALESCE(u.admin_level,0)>=1))
 OR (cfg.time_limit_ms<>-1 AND extract(epoch FROM clock_timestamp()-part.registered_at)*1000>cfg.time_limit_ms) THEN RAISE EXCEPTION 'CTF recovery eligibility unavailable' USING ERRCODE='42501'; END IF;
END; $$;

