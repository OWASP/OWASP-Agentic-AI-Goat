-- Closed telemetry lane: transport sequence only, never a lifecycle revision.
ALTER TABLE identity.ctf_outbox DROP CONSTRAINT ctf_outbox_kind_check;
ALTER TABLE identity.ctf_outbox ADD CONSTRAINT ctf_outbox_kind_check CHECK(kind IN ('decision','catalog_mutation','config_mutation','owner_reset','owner_remove','global_reset','ban','unban','blocklist_clear','admit_attempt','record_blocked_attempt','register','start','hint','student_delete','heartbeat'));
CREATE FUNCTION identity.ctf_heartbeat_command_matches(v jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$ SELECT identity.ctf_json_matches(v,'{"type":"object","properties":{"version":{"type":"number","enum":[1]},"kind":{"type":"string","enum":["heartbeat"]},"operationId":{"type":"string","bytes":36,"pattern":"^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$"},"actorId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"sessionId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"scope":{"type":"object","properties":{"ownerId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"ownerGeneration":{"type":"string","bytes":19,"pattern":"^(0|[1-9][0-9]*)$","minimum":0,"maximum":"9223372036854775807"},"participantId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"globalRevision":{"type":"string","bytes":19,"pattern":"^(0|[1-9][0-9]*)$","minimum":0,"maximum":"9223372036854775807"}}},"occurredAt":{"type":"string","bytes":24,"pattern":"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$"},"registrationToken":{"type":"string","bytes":256},"incrementMs":{"type":"number","enum":[1000]}}}'::jsonb) AND v->>'actorId'=v->'scope'->>'ownerId' AND length(v->>'registrationToken')>0 $$;
REVOKE ALL ON FUNCTION identity.ctf_heartbeat_command_matches(jsonb) FROM PUBLIC;
CREATE FUNCTION identity.ctf_heartbeat_receipt_matches(v jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$ SELECT CASE WHEN identity.ctf_json_matches(v,'{"type":"object","properties":{"version":{"type":"number","enum":[4]},"kind":{"type":"string","enum":["heartbeat"]},"operationId":{"type":"string","bytes":36,"pattern":"^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$"},"sequence":{"type":"string","bytes":19,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":"9223372036854775807"},"commandHash":{"type":"string","bytes":64,"pattern":"^[a-f0-9]{64}$"},"outcome":{"type":"string","enum":["applied"]},"data":{"type":"object","properties":{"matched":{"type":"boolean"},"incrementMs":{"type":"number","enum":[0,1000]}}}}}'::jsonb) THEN (v->'data'->>'incrementMs')::integer=CASE WHEN v->'data'->'matched'='true'::jsonb THEN 1000 ELSE 0 END ELSE false END $$;
REVOKE ALL ON FUNCTION identity.ctf_heartbeat_receipt_matches(jsonb) FROM PUBLIC;
-- Only this closed schema is encoded; PostgreSQL object text inserts spaces and
-- uses a different key order than canonicalCtfJson. Scalar JSON string encoding
-- preserves locator Unicode, quotes and control characters without rewriting it.
CREATE FUNCTION identity.canonical_ctf_heartbeat_command(v jsonb) RETURNS text
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
BEGIN
 IF identity.ctf_heartbeat_command_matches(v) IS NOT TRUE THEN RAISE EXCEPTION 'CTF heartbeat command invalid';END IF;
 RETURN '{"actorId":'||(v->'actorId')::text||',"incrementMs":1000,"kind":"heartbeat","occurredAt":'||(v->'occurredAt')::text||
 ',"operationId":'||(v->'operationId')::text||',"registrationToken":'||(v->'registrationToken')::text||
 ',"scope":{"globalRevision":'||(v->'scope'->'globalRevision')::text||',"ownerGeneration":'||(v->'scope'->'ownerGeneration')::text||
 ',"ownerId":'||(v->'scope'->'ownerId')::text||',"participantId":'||(v->'scope'->'participantId')::text||
 '},"sessionId":'||(v->'sessionId')::text||',"version":1}';
END $$;
REVOKE ALL ON FUNCTION identity.canonical_ctf_heartbeat_command(jsonb) FROM PUBLIC;
CREATE FUNCTION identity.canonical_ctf_heartbeat_receipt(v jsonb) RETURNS text
LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
BEGIN
 IF identity.ctf_heartbeat_receipt_matches(v) IS NOT TRUE THEN RAISE EXCEPTION 'CTF heartbeat receipt invalid';END IF;
 RETURN '{"commandHash":'||(v->'commandHash')::text||',"data":{"incrementMs":'||(v->'data'->>'incrementMs')::integer::text||
 ',"matched":'||(v->'data'->'matched')::text||'},"kind":"heartbeat","operationId":'||(v->'operationId')::text||
 ',"outcome":"applied","sequence":'||(v->'sequence')::text||',"version":4}';
END $$;
REVOKE ALL ON FUNCTION identity.canonical_ctf_heartbeat_receipt(jsonb) FROM PUBLIC;
CREATE FUNCTION identity.prepare_ctf_heartbeat(p_actor integer,p_session integer,p_token_hash text,p_operation uuid,p_locator text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE g identity.ctf_authority%ROWTYPE;o identity.ctf_authority%ROWTYPE;u identity.users%ROWTYPE;s identity.user_sessions%ROWTYPE;p identity.ctf_participant_bindings%ROWTYPE;e identity.ctf_outbox%ROWTYPE;doc jsonb;locator text:=nullif(p_locator,'');
BEGIN
 PERFORM set_config('lock_timeout','250ms',true);PERFORM set_config('statement_timeout','2000ms',true);
 IF p_actor IS NULL OR p_actor<1 OR p_session IS NULL OR p_session<1 OR p_operation IS NULL OR p_token_hash IS NULL OR p_token_hash !~ '^[a-f0-9]{64}$' OR octet_length(locator)>256 THEN RAISE EXCEPTION 'CTF heartbeat arguments invalid';END IF;
 SELECT * INTO g FROM identity.ctf_authority WHERE scope_key='global' FOR UPDATE;
 SELECT * INTO o FROM identity.ctf_authority WHERE scope_key='owner:'||p_actor FOR UPDATE;
 SELECT * INTO u FROM identity.users WHERE id=p_actor FOR UPDATE;
 SELECT * INTO s FROM identity.user_sessions WHERE id=p_session AND user_id=p_actor FOR UPDATE;
 IF u.id IS NULL OR u.is_active<>1 OR (u.account_locked_until IS NOT NULL AND u.account_locked_until>clock_timestamp()) OR s.id IS NULL OR s.is_active<>1 OR s.expires_at<=clock_timestamp() OR s.session_token_hash IS DISTINCT FROM p_token_hash
 OR EXISTS(SELECT 1 FROM identity.student_deletion_jobs WHERE subject_user_id=p_actor) OR EXISTS(SELECT 1 FROM identity.student_deletion_run_blocks WHERE owner_key='["CTF","'||p_actor||'"]') THEN RAISE EXCEPTION 'SESSION_REVOKED' USING ERRCODE='28000';END IF;
 SELECT * INTO e FROM identity.ctf_outbox WHERE operation_id=p_operation;
 IF FOUND THEN
  IF e.kind IS DISTINCT FROM 'heartbeat' OR e.actor_id IS DISTINCT FROM p_actor OR e.session_id IS DISTINCT FROM p_session OR e.command->>'registrationToken' IS DISTINCT FROM locator THEN RAISE EXCEPTION 'CTF heartbeat operation conflict' USING ERRCODE='42501';END IF;
  RETURN jsonb_build_object('state',e.state,'command',e.command,'replayed',true);
 END IF;
 IF g.lifecycle_state IS DISTINCT FROM 'ready' OR NOT EXISTS(SELECT 1 FROM identity.ctf_config_binding WHERE singleton AND enabled) THEN RAISE EXCEPTION 'CTF heartbeat unavailable';END IF;
 IF locator IS NULL THEN RETURN jsonb_build_object('state','noop');END IF;
 SELECT * INTO p FROM identity.ctf_participant_bindings WHERE owner_id=p_actor;
 -- Authenticated unregistered owners cannot name another participant or create a write.
 IF p.owner_id IS NULL THEN RETURN jsonb_build_object('state','noop');END IF;
 PERFORM 1 FROM graph_runtime.owners WHERE owner_key='["CTF","'||p_actor||'"]' FOR SHARE;
 IF o.lifecycle_state IS DISTINCT FROM 'ready' OR o.owner_generation IS DISTINCT FROM p.owner_generation OR o.owner_generation IS DISTINCT FROM (SELECT generation FROM graph_runtime.owners WHERE owner_key='["CTF","'||p_actor||'"]') THEN RAISE EXCEPTION 'CTF heartbeat owner unavailable';END IF;
 IF g.next_sequence-g.applied_sequence>=512 THEN RAISE EXCEPTION 'CTF_HEARTBEAT_BACKPRESSURE' USING ERRCODE='55000';END IF;
 doc:=jsonb_build_object('version',1,'kind','heartbeat','operationId',p_operation,'actorId',p_actor::text,'sessionId',p_session::text,
  'scope',jsonb_build_object('ownerId',p_actor::text,'ownerGeneration',o.owner_generation::text,'participantId',p.participant_id::text,'globalRevision',g.revision::text),
  'occurredAt',to_char(date_trunc('milliseconds',transaction_timestamp()) AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),'registrationToken',locator,'incrementMs',1000);
 RETURN jsonb_build_object('state','prepared','command',doc,'replayed',false);
END $$;
REVOKE ALL ON FUNCTION identity.prepare_ctf_heartbeat(integer,integer,text,uuid,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.prepare_ctf_heartbeat(integer,integer,text,uuid,text) TO dvaia_identity_runtime;
CREATE FUNCTION identity.enqueue_ctf_heartbeat(p_actor integer,p_session integer,p_token_hash text,p_operation uuid,p_locator text,p_canonical text,p_hash text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE prepared jsonb;doc jsonb;seq bigint;e identity.ctf_outbox%ROWTYPE;
BEGIN
 prepared:=identity.prepare_ctf_heartbeat(p_actor,p_session,p_token_hash,p_operation,p_locator);
 IF prepared->>'state'='noop' THEN RETURN jsonb_build_object('state','noop','operationId',NULL);END IF;
 IF p_canonical IS NULL OR octet_length(p_canonical)>4096 OR NOT(p_canonical IS JSON OBJECT WITH UNIQUE KEYS) OR p_hash IS DISTINCT FROM encode(sha256(convert_to(p_canonical,'UTF8')),'hex') THEN RAISE EXCEPTION 'CTF heartbeat encoding invalid';END IF;
 doc:=p_canonical::jsonb;
 IF identity.ctf_heartbeat_command_matches(doc) IS NOT TRUE OR doc IS DISTINCT FROM prepared->'command' OR p_canonical IS DISTINCT FROM identity.canonical_ctf_heartbeat_command(doc) THEN RAISE EXCEPTION 'CTF heartbeat command invalid';END IF;
 SELECT * INTO e FROM identity.ctf_outbox WHERE operation_id=p_operation;
 IF FOUND THEN
  IF e.canonical_command IS DISTINCT FROM p_canonical OR e.command_hash IS DISTINCT FROM p_hash THEN RAISE EXCEPTION 'CTF heartbeat replay conflict';END IF;
  RETURN jsonb_build_object('state',e.state,'operationId',p_operation,'sequence',e.sequence::text,'replayed',true);
 END IF;
 UPDATE identity.ctf_authority SET next_sequence=next_sequence+1 WHERE scope_key='global' RETURNING next_sequence INTO seq;
 INSERT INTO identity.ctf_outbox(sequence,operation_id,kind,command,command_hash,actor_id,session_id,request_fingerprint,canonical_command,owner_generation_after)
 VALUES(seq,p_operation,'heartbeat',doc,p_hash,p_actor,p_session,p_hash,p_canonical,(doc->'scope'->>'ownerGeneration')::bigint);
 RETURN jsonb_build_object('state','pending','operationId',p_operation,'sequence',seq::text,'replayed',false);
END $$;
REVOKE ALL ON FUNCTION identity.enqueue_ctf_heartbeat(integer,integer,text,uuid,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.enqueue_ctf_heartbeat(integer,integer,text,uuid,text,text,text) TO dvaia_identity_runtime;
CREATE FUNCTION identity.ack_ctf_heartbeat(p_operation uuid,p_sequence bigint,p_command_hash text,p_result text,p_result_hash text)
RETURNS TABLE(state text,applied_sequence bigint) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE g identity.ctf_authority%ROWTYPE;e identity.ctf_outbox%ROWTYPE;r jsonb;
BEGIN
 PERFORM set_config('lock_timeout','250ms',true);PERFORM set_config('statement_timeout','2000ms',true);
 IF p_result IS NULL OR octet_length(p_result)>16384 OR NOT(p_result IS JSON OBJECT WITH UNIQUE KEYS) OR p_result_hash IS DISTINCT FROM encode(sha256(convert_to(p_result,'UTF8')),'hex') THEN RAISE EXCEPTION 'CTF heartbeat receipt encoding invalid';END IF;
 r:=p_result::jsonb;
 IF identity.ctf_heartbeat_receipt_matches(r) IS NOT TRUE OR p_result IS DISTINCT FROM identity.canonical_ctf_heartbeat_receipt(r) OR r->>'operationId' IS DISTINCT FROM p_operation::text OR r->>'sequence' IS DISTINCT FROM p_sequence::text OR r->>'commandHash' IS DISTINCT FROM p_command_hash THEN RAISE EXCEPTION 'CTF heartbeat receipt invalid';END IF;
 SELECT a.* INTO g FROM identity.ctf_authority a WHERE a.scope_key='global' FOR UPDATE;
 SELECT x.* INTO e FROM identity.ctf_outbox x WHERE x.operation_id=p_operation FOR UPDATE;
 IF e.kind IS DISTINCT FROM 'heartbeat' OR e.sequence IS DISTINCT FROM p_sequence OR e.command_hash IS DISTINCT FROM p_command_hash THEN RAISE EXCEPTION 'CTF heartbeat receipt identity invalid';END IF;
 IF e.state='applied' THEN
  IF e.canonical_result IS DISTINCT FROM p_result OR e.result_hash IS DISTINCT FROM p_result_hash THEN RAISE EXCEPTION 'CTF heartbeat receipt replay conflict';END IF;
  RETURN QUERY SELECT 'applied'::text,g.applied_sequence;RETURN;
 END IF;
 IF e.state IS DISTINCT FROM 'pending' OR g.lifecycle_state NOT IN ('ready','pending') OR g.applied_sequence+1 IS DISTINCT FROM p_sequence THEN RAISE EXCEPTION 'CTF heartbeat delivery order invalid';END IF;
 UPDATE identity.ctf_outbox x SET state='applied',canonical_result=p_result,result_hash=p_result_hash,applied_at=clock_timestamp() WHERE x.operation_id=p_operation;
 UPDATE identity.ctf_authority a SET applied_sequence=p_sequence WHERE a.scope_key='global';
 RETURN QUERY SELECT 'applied'::text,p_sequence;
END $$;
REVOKE ALL ON FUNCTION identity.ack_ctf_heartbeat(uuid,bigint,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.ack_ctf_heartbeat(uuid,bigint,text,text,text) TO dvaia_identity_runtime;
