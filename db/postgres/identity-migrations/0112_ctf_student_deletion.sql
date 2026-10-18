-- Unmounted deletion-job authority; no learner session can create this command.
ALTER TABLE identity.ctf_outbox DROP CONSTRAINT ctf_outbox_kind_check;
ALTER TABLE identity.ctf_outbox ADD CONSTRAINT ctf_outbox_kind_check CHECK(kind IN ('decision','catalog_mutation','config_mutation','owner_reset','owner_remove','global_reset','ban','unban','blocklist_clear','admit_attempt','record_blocked_attempt','register','start','hint','student_delete'));
CREATE TABLE identity.ctf_deletion_commands(job_id uuid PRIMARY KEY,subject_id integer NOT NULL CHECK(subject_id>0),operation_id uuid NOT NULL UNIQUE,sequence bigint NOT NULL UNIQUE,FOREIGN KEY(operation_id,sequence) REFERENCES identity.ctf_outbox(operation_id,sequence));
CREATE TRIGGER ctf_deletion_commands_immutable BEFORE UPDATE OR DELETE ON identity.ctf_deletion_commands FOR EACH ROW EXECUTE FUNCTION identity.reject_ctf_decision_mutation();
REVOKE ALL ON identity.ctf_deletion_commands FROM PUBLIC,dvaia_identity_runtime;
GRANT SELECT ON identity.ctf_deletion_commands TO dvaia_identity_runtime;
CREATE FUNCTION identity.ctf_deletion_command_matches(v jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$ SELECT identity.ctf_json_matches(v,'{"type":"object","properties":{"version":{"type":"number","enum":[1]},"kind":{"type":"string","enum":["student_delete"]},"operationId":{"type":"string","bytes":36,"pattern":"^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$"},"jobId":{"type":"string","bytes":36,"pattern":"^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$"},"subjectId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"participantId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647,"nullable":true},"generationBefore":{"type":"string","bytes":19,"pattern":"^(0|[1-9][0-9]*)$","minimum":0,"maximum":"9223372036854775807"},"generationAfter":{"type":"string","bytes":19,"pattern":"^(0|[1-9][0-9]*)$","minimum":0,"maximum":"9223372036854775807"},"globalRevision":{"type":"string","bytes":19,"pattern":"^(0|[1-9][0-9]*)$","minimum":0,"maximum":"9223372036854775807"},"ownerRevision":{"type":"string","bytes":19,"pattern":"^(0|[1-9][0-9]*)$","minimum":0,"maximum":"9223372036854775807"},"occurredAt":{"type":"string","bytes":24},"policyVersion":{"type":"string","enum":["ctf-student-delete-v1"]}}}'::jsonb) $$;
CREATE FUNCTION identity.ctf_deletion_receipt_matches(v jsonb) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$ SELECT identity.ctf_json_matches(v,'{"type":"object","properties":{"version":{"type":"number","enum":[3]},"kind":{"type":"string","enum":["student_delete"]},"operationId":{"type":"string","bytes":36,"pattern":"^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$"},"sequence":{"type":"string","bytes":19,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":"9223372036854775807"},"commandHash":{"type":"string","bytes":64,"pattern":"^[a-f0-9]{64}$"},"outcome":{"type":"string","enum":["applied"]},"data":{"type":"object","properties":{"jobId":{"type":"string","bytes":36,"pattern":"^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$"},"subjectId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"participantId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647,"nullable":true},"generationBefore":{"type":"string","bytes":19,"pattern":"^(0|[1-9][0-9]*)$","minimum":0,"maximum":"9223372036854775807"},"generationAfter":{"type":"string","bytes":19,"pattern":"^(0|[1-9][0-9]*)$","minimum":0,"maximum":"9223372036854775807"},"policyVersion":{"type":"string","enum":["ctf-student-delete-v1"]},"removed":{"type":"object","properties":{"bans":{"type":"number","integer":true,"minimum":0,"maximum":2147483647},"judgments":{"type":"number","integer":true,"minimum":0,"maximum":2147483647},"attempts":{"type":"number","integer":true,"minimum":0,"maximum":2147483647},"progress":{"type":"number","integer":true,"minimum":0,"maximum":2147483647},"techniques":{"type":"number","integer":true,"minimum":0,"maximum":2147483647},"leaderboard":{"type":"number","integer":true,"minimum":0,"maximum":2147483647},"events":{"type":"number","integer":true,"minimum":0,"maximum":2147483647},"sessions":{"type":"number","integer":true,"minimum":0,"maximum":2147483647},"participants":{"type":"number","integer":true,"minimum":0,"maximum":2147483647}}}}}}}'::jsonb) $$;
REVOKE ALL ON FUNCTION identity.ctf_deletion_command_matches(jsonb),identity.ctf_deletion_receipt_matches(jsonb) FROM PUBLIC;
CREATE FUNCTION identity.admit_ctf_student_deletion(p_job uuid,p_lease uuid,p_subject integer) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE j identity.student_deletion_jobs%ROWTYPE;g identity.ctf_authority%ROWTYPE;o identity.ctf_authority%ROWTYPE;part identity.ctf_participant_bindings%ROWTYPE;ev identity.ctf_outbox%ROWTYPE;gen bigint;seq bigint;op uuid;doc jsonb;encoded text;pid bigint;
BEGIN
 IF p_subject IS NULL OR p_subject<1 OR NOT pg_try_advisory_xact_lock(hashtextextended('["CTF","'||p_subject||'"]',0)) THEN RAISE EXCEPTION 'CTF deletion run lease unavailable'; END IF;
 SELECT * INTO j FROM identity.student_deletion_jobs dj WHERE dj.job_id=p_job FOR UPDATE;
 IF j.subject_user_id IS DISTINCT FROM p_subject OR j.state IS DISTINCT FROM 'running' OR j.lease_token IS DISTINCT FROM p_lease OR j.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'DELETION_LEASE_STALE' USING ERRCODE='42501'; END IF;
 IF NOT EXISTS(SELECT 1 FROM identity.student_deletion_steps st WHERE st.job_id=p_job AND st.step_key='ctf')
 OR NOT EXISTS(SELECT 1 FROM identity.student_deletion_steps st WHERE st.job_id=p_job AND st.step_key='ctf' AND st.ordinal=11)
 OR (SELECT array_agg(st.step_key ORDER BY st.ordinal) FROM identity.student_deletion_steps st WHERE st.job_id=p_job AND st.ordinal<11) IS DISTINCT FROM ARRAY['revoke_runs','secureshop','excessive_agency','session_disclosure','sql_injection_workshop','nosql_injection_workshop','mcp_workshop','csrf_workshop','direct_prompt_injection','indirect_prompt_injection','supply_chain_rce']
 OR NOT EXISTS(SELECT 1 FROM identity.student_deletion_steps st WHERE st.job_id=p_job AND st.step_key='revoke_runs' AND st.state='completed')
 OR EXISTS(SELECT 1 FROM identity.student_deletion_steps st JOIN identity.student_deletion_steps target ON target.job_id=st.job_id AND target.step_key='ctf' WHERE st.job_id=p_job AND st.ordinal<target.ordinal AND st.state<>'completed')
 OR NOT EXISTS(SELECT 1 FROM identity.student_deletion_run_blocks rb WHERE rb.job_id=p_job AND rb.owner_key='["CTF","'||p_subject||'"]') THEN RAISE EXCEPTION 'CTF deletion step unavailable'; END IF;
 SELECT oo.* INTO ev FROM identity.ctf_deletion_commands dc JOIN identity.ctf_outbox oo ON oo.operation_id=dc.operation_id WHERE dc.job_id=p_job AND dc.subject_id=p_subject;
 IF FOUND THEN RETURN jsonb_build_object('sequence',ev.sequence::text,'canonicalCommand',ev.canonical_command,'commandHash',ev.command_hash,'state',ev.state); END IF;
 IF EXISTS(SELECT 1 FROM identity.student_deletion_steps st WHERE st.job_id=p_job AND st.step_key='ctf' AND st.state='completed') THEN RAISE EXCEPTION 'CTF deletion completed without command'; END IF;
 SELECT * INTO g FROM identity.ctf_authority a WHERE a.scope_key='global' FOR UPDATE;
 SELECT * INTO o FROM identity.ctf_authority a WHERE a.scope_key='owner:'||p_subject FOR UPDATE;
 PERFORM 1 FROM identity.users u WHERE u.id=p_subject FOR UPDATE;
 IF NOT EXISTS(SELECT 1 FROM identity.users u WHERE u.id=p_subject AND u.is_active=0 AND u.role='student' AND COALESCE(u.admin_level,0)=0) THEN RAISE EXCEPTION 'CTF deletion subject unavailable'; END IF;
 SELECT go.generation INTO gen FROM graph_runtime.owners go WHERE go.owner_key='["CTF","'||p_subject||'"]' FOR UPDATE;
 IF gen IS NULL OR EXISTS(SELECT 1 FROM graph_runtime.runs rr WHERE rr.owner_key='["CTF","'||p_subject||'"]' AND rr.status='running') THEN RAISE EXCEPTION 'CTF deletion runs not drained'; END IF;
 IF g.lifecycle_state IS DISTINCT FROM 'ready' OR (o.scope_key IS NOT NULL AND o.lifecycle_state IS DISTINCT FROM 'ready') OR gen<COALESCE(o.owner_generation,gen) THEN RAISE EXCEPTION 'CTF deletion authority unavailable'; END IF;
 IF (SELECT count(*) FROM identity.ctf_outbox oo WHERE oo.state='pending')>=512 OR (SELECT COALESCE(sum(octet_length(oo.command::text)),0) FROM identity.ctf_outbox oo WHERE oo.state='pending')>16711680 OR EXISTS(SELECT 1 FROM identity.ctf_outbox oo WHERE oo.state='pending' AND oo.created_at<clock_timestamp()-interval '60 seconds') THEN RAISE EXCEPTION 'CTF deletion backlog unavailable'; END IF;
 IF o.scope_key IS NULL THEN INSERT INTO identity.ctf_authority(scope_key,owner_generation,lifecycle_state) VALUES('owner:'||p_subject,gen,'ready') RETURNING * INTO o; END IF;
 SELECT * INTO part FROM identity.ctf_participant_bindings b WHERE b.owner_id=p_subject;
 pid:=part.participant_id;
 IF EXISTS(SELECT 1 FROM identity.ctf_outbox oo WHERE oo.operation_id=part.applied_operation_id AND oo.kind IN ('owner_remove','global_reset')) THEN pid:=NULL; END IF;
 seq:=g.next_sequence+1;op:=p_job;
 doc:=jsonb_build_object('version',1,'kind','student_delete','operationId',op,'jobId',p_job,'subjectId',p_subject::text,'participantId',pid::text,'generationBefore',o.owner_generation::text,'generationAfter',gen::text,'globalRevision',g.revision::text,'ownerRevision',o.revision::text,'occurredAt',to_char(date_trunc('milliseconds',clock_timestamp()) AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),'policyVersion','ctf-student-delete-v1');
 IF NOT identity.ctf_deletion_command_matches(doc) OR j.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'CTF deletion admission unavailable'; END IF;
 encoded:=doc::text;
 INSERT INTO identity.ctf_outbox(sequence,operation_id,kind,command,command_hash,canonical_command) VALUES(seq,op,'student_delete',doc,encode(sha256(convert_to(encoded,'UTF8')),'hex'),encoded);
 INSERT INTO identity.ctf_deletion_commands VALUES(p_job,p_subject,op,seq);
 UPDATE identity.ctf_authority SET next_sequence=seq WHERE scope_key='global';
 UPDATE identity.ctf_authority SET lifecycle_state='pending',pending_operation_id=op WHERE scope_key='owner:'||p_subject;
 RETURN jsonb_build_object('sequence',seq::text,'canonicalCommand',encoded,'commandHash',encode(sha256(convert_to(encoded,'UTF8')),'hex'),'state','pending');
END; $$;
REVOKE ALL ON FUNCTION identity.admit_ctf_student_deletion(uuid,uuid,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.admit_ctf_student_deletion(uuid,uuid,integer) TO dvaia_identity_runtime;
CREATE FUNCTION identity.ack_ctf_student_deletion(p_job uuid,p_lease uuid,p_subject integer,p_result text,p_hash text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE j identity.student_deletion_jobs%ROWTYPE;g identity.ctf_authority%ROWTYPE;o identity.ctf_authority%ROWTYPE;ev identity.ctf_outbox%ROWTYPE;c jsonb;r jsonb;d jsonb;
BEGIN
 SELECT * INTO j FROM identity.student_deletion_jobs jj WHERE jj.job_id=p_job FOR UPDATE;
 IF j.subject_user_id IS DISTINCT FROM p_subject OR j.state IS DISTINCT FROM 'running' OR j.lease_token IS DISTINCT FROM p_lease OR j.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'DELETION_LEASE_STALE' USING ERRCODE='42501'; END IF;
 SELECT * INTO g FROM identity.ctf_authority a WHERE a.scope_key='global' FOR UPDATE;
 SELECT * INTO o FROM identity.ctf_authority a WHERE a.scope_key='owner:'||p_subject FOR UPDATE;
 SELECT oo.* INTO ev FROM identity.ctf_deletion_commands dc JOIN identity.ctf_outbox oo ON oo.operation_id=dc.operation_id WHERE dc.job_id=p_job AND dc.subject_id=p_subject FOR UPDATE OF oo;
 IF ev.kind IS DISTINCT FROM 'student_delete' OR p_result IS NULL OR octet_length(p_result)>16384 OR NOT(p_result IS JSON OBJECT WITH UNIQUE KEYS) OR p_hash IS DISTINCT FROM encode(sha256(convert_to(p_result,'UTF8')),'hex') THEN RAISE EXCEPTION 'CTF deletion receipt invalid'; END IF;
 c:=ev.command;r:=p_result::jsonb;d:=r->'data';
 IF NOT identity.ctf_deletion_receipt_matches(r) OR r->>'operationId' IS DISTINCT FROM ev.operation_id::text OR r->>'sequence' IS DISTINCT FROM ev.sequence::text OR r->>'commandHash' IS DISTINCT FROM ev.command_hash
 OR d->>'jobId' IS DISTINCT FROM p_job::text OR d->>'subjectId' IS DISTINCT FROM p_subject::text OR d->'participantId' IS DISTINCT FROM c->'participantId'
 OR d->'generationBefore' IS DISTINCT FROM c->'generationBefore' OR d->'generationAfter' IS DISTINCT FROM c->'generationAfter' OR d->'policyVersion' IS DISTINCT FROM c->'policyVersion'
 OR d->'removed'->>'participants' IS DISTINCT FROM (CASE WHEN c->'participantId'='null'::jsonb THEN '0' ELSE '1' END) THEN RAISE EXCEPTION 'CTF deletion receipt mismatch'; END IF;
 IF ev.state='applied' THEN IF ev.canonical_result IS DISTINCT FROM p_result OR ev.result_hash IS DISTINCT FROM p_hash THEN RAISE EXCEPTION 'CTF deletion replay mismatch'; END IF; RETURN jsonb_build_object('completed',true,'operationId',ev.operation_id); END IF;
 IF ev.state IS DISTINCT FROM 'pending' OR g.applied_sequence+1 IS DISTINCT FROM ev.sequence OR o.lifecycle_state IS DISTINCT FROM 'pending' OR o.pending_operation_id IS DISTINCT FROM ev.operation_id
 OR o.owner_generation IS DISTINCT FROM (c->>'generationBefore')::bigint THEN RAISE EXCEPTION 'CTF deletion delivery unavailable'; END IF;
 IF j.lease_expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'DELETION_LEASE_STALE' USING ERRCODE='42501'; END IF;
 UPDATE identity.ctf_participant_bindings SET active=false,banned=true,applied_sequence=ev.sequence,applied_operation_id=ev.operation_id WHERE owner_id=p_subject;
 DELETE FROM identity.ctf_adaptive_memory WHERE kind='technique' AND owner_id=p_subject;
 UPDATE identity.ctf_outbox SET state='applied',canonical_result=p_result,result_hash=p_hash,applied_at=clock_timestamp() WHERE operation_id=ev.operation_id;
 UPDATE identity.ctf_authority SET applied_sequence=ev.sequence WHERE scope_key='global';
 UPDATE identity.ctf_authority SET owner_generation=(c->>'generationAfter')::bigint,lifecycle_state='blocked',pending_operation_id=NULL,blocked_operation_id=ev.operation_id,banned=true,failure_code='student_deleted' WHERE scope_key='owner:'||p_subject;
 RETURN jsonb_build_object('completed',true,'operationId',ev.operation_id);
END; $$;
REVOKE ALL ON FUNCTION identity.ack_ctf_student_deletion(uuid,uuid,integer,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.ack_ctf_student_deletion(uuid,uuid,integer,text,text) TO dvaia_identity_runtime;
