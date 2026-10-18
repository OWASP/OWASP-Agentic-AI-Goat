-- Forward repair: retain the qualified 0105 command validator exactly, except
-- record_blocked_attempt expected keys must match its ORDER BY key comparison.
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
 IF k='global_reset' AND (g.next_sequence<>g.applied_sequence OR EXISTS(SELECT 1 FROM identity.ctf_outbox AS queued WHERE queued.state IN ('pending','blocked')) OR EXISTS(SELECT 1 FROM identity.ctf_authority WHERE lifecycle_state IN ('pending','blocked')) OR EXISTS(SELECT 1 FROM identity.ctf_registration_reservations AS reservation WHERE reservation.state='held')) THEN RAISE EXCEPTION 'CTF global reset requires drained delivery'; END IF;
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

-- Unmounted guarded continuation of an acknowledged 0113 admission.
CREATE TABLE identity.ctf_predefense_blocked_commands (
 run_id uuid PRIMARY KEY REFERENCES identity.ctf_predefense_consumptions(run_id),
 operation_id uuid NOT NULL UNIQUE REFERENCES identity.ctf_outbox(operation_id),
 command_hash text NOT NULL CHECK(command_hash~'^[a-f0-9]{64}$')
);
CREATE TRIGGER ctf_predefense_blocked_immutable BEFORE UPDATE OR DELETE ON identity.ctf_predefense_blocked_commands FOR EACH ROW EXECUTE FUNCTION identity.reject_ctf_decision_mutation();
REVOKE ALL ON identity.ctf_predefense_blocked_commands FROM PUBLIC,dvaia_identity_runtime;
GRANT SELECT ON identity.ctf_predefense_blocked_commands TO dvaia_identity_runtime;
CREATE FUNCTION identity.prepare_ctf_blocked_predefense(p_actor integer,p_session integer,p_token_hash text,p_run uuid)
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
 PERFORM identity.lock_ctf_predefense(p_actor,p_session,p_token_hash,b,true);
 SELECT cfg.show_technique_feedback INTO show_feedback FROM identity.ctf_config_binding cfg WHERE cfg.singleton;
 SELECT st.feedback_mode INTO feedback FROM identity.ctf_stage_bindings st WHERE st.stage_id=a.stage_id;
 IF done.final_disposition='category' THEN reason:=CASE WHEN show_feedback THEN 'Technique "'||(c.input->>'techniqueTag')||'" has already been used on this level. Try a different approach.' ELSE 'This approach has been blocked. Try something different.' END;
 ELSIF done.final_disposition='payload' THEN reason:=CASE WHEN show_feedback THEN 'This payload (or a very similar one) has already been used successfully by another participant.' ELSE 'This approach has been blocked by the community shield.' END;
 ELSE reason:=CASE WHEN feedback='silent' THEN 'Your input was blocked by the defense system.' ELSE o.outcome->>'reason' END;
 END IF;
 body:=jsonb_build_object('admissionOperationId',c.admission_operation_id,'matchedPayloadHash',done.matched_payload_hash,'attemptNumber',a.attempt_number,'payload',c.input->>'payload','response',NULL,'responseTime',0,'teachingSessionToken',NULL,'techniqueTag',c.input->>'techniqueTag','techniqueConfidence',c.input->'techniqueConfidence','reason',reason,'payloadHash',c.input->>'payloadHash');
 doc:=jsonb_build_object('version',1,'kind','record_blocked_attempt','operationId',c.blocked_operation_id,'actorId',p_actor::text,'occurredAt',to_char(date_trunc('milliseconds',transaction_timestamp()) AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
 'scope',jsonb_build_object('ownerId',b->>'ownerId','ownerGeneration',b->>'ownerGeneration','globalRevision',b->>'globalRevision','stageRevision',b->>'stageRevision','participantId',b->>'participantId','stageId',b->>'stageId','progressId',b->>'progressId'),'body',body);
 RETURN jsonb_build_object('operationId',c.blocked_operation_id,'command',doc,'canonicalCommand',NULL,'replayed',false,'currentState',false);
END; $$;
REVOKE ALL ON FUNCTION identity.prepare_ctf_blocked_predefense(integer,integer,text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.prepare_ctf_blocked_predefense(integer,integer,text,uuid) TO dvaia_identity_runtime;
CREATE FUNCTION identity.enqueue_ctf_blocked_predefense(p_actor integer,p_session integer,p_token_hash text,p_run uuid,p_document text,p_hash text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE expected jsonb;allocated record;op uuid;
BEGIN
 expected:=identity.prepare_ctf_blocked_predefense(p_actor,p_session,p_token_hash,p_run);op:=(expected->>'operationId')::uuid;
 IF p_document IS NULL OR octet_length(p_document)>65536 OR NOT(p_document IS JSON OBJECT WITH UNIQUE KEYS) OR p_hash IS DISTINCT FROM encode(sha256(convert_to(p_document,'UTF8')),'hex') OR p_document::jsonb IS DISTINCT FROM expected->'command' THEN RAISE EXCEPTION 'CTF blocked canonical command mismatch'; END IF;
 IF (expected->>'replayed')::boolean THEN
  IF expected->>'canonicalCommand' IS DISTINCT FROM p_document THEN RAISE EXCEPTION 'CTF blocked replay encoding mismatch'; END IF;
  RETURN jsonb_build_object('operationId',op,'replayed',true,'currentState',false);
 END IF;
 SELECT * INTO allocated FROM identity.enqueue_ctf_user_command(p_actor::bigint,p_session::bigint,p_token_hash,op,p_document,p_hash);
 INSERT INTO identity.ctf_predefense_blocked_commands VALUES(p_run,op,p_hash);
 RETURN jsonb_build_object('operationId',op,'replayed',false,'currentState',false);
END; $$;
REVOKE ALL ON FUNCTION identity.enqueue_ctf_blocked_predefense(integer,integer,text,uuid,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.enqueue_ctf_blocked_predefense(integer,integer,text,uuid,text,text) TO dvaia_identity_runtime;
