-- Authenticated historical lifecycle receipt read. Never grants current-state
-- or completion authority, and never retries enqueue or projection.
CREATE FUNCTION identity.read_ctf_user_operation(p_operation uuid,p_actor integer,p_session integer,p_token_hash text)
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
 IF ev.kind IN ('catalog_mutation','config_mutation','owner_reset','owner_remove','global_reset','ban','unban','blocklist_clear') AND NOT(u.role='admin' OR COALESCE(u.admin_level,0)>0) THEN RAISE EXCEPTION 'CTF operation unavailable' USING ERRCODE='42501'; END IF;
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
REVOKE ALL ON FUNCTION identity.read_ctf_user_operation(uuid,integer,integer,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.read_ctf_user_operation(uuid,integer,integer,text) TO dvaia_identity_runtime;
