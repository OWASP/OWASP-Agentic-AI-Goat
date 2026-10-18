-- Unmounted decision authority. No bootstrap, route, worker or reader activation.
ALTER TABLE identity.ctf_decisions DROP CONSTRAINT ctf_decisions_verdict_check;
ALTER TABLE identity.ctf_decisions ADD CONSTRAINT ctf_decisions_verdict_check CHECK(verdict IN ('pass','fail','inconclusive','unavailable','blocked'));
CREATE TABLE identity.ctf_decision_proposals (
 proposal_id uuid PRIMARY KEY,run_id uuid NOT NULL UNIQUE,admission_operation_id uuid NOT NULL UNIQUE REFERENCES identity.ctf_attempt_admissions(operation_id),
 owner_id integer NOT NULL,session_id integer NOT NULL,canonical_evidence text NOT NULL CHECK(octet_length(canonical_evidence)<=65536),
 evidence_hash text NOT NULL CHECK(evidence_hash=encode(sha256(convert_to(canonical_evidence,'UTF8')),'hex')),
 evidence jsonb NOT NULL CHECK(evidence=canonical_evidence::jsonb),created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER ctf_proposal_immutable BEFORE UPDATE OR DELETE ON identity.ctf_decision_proposals FOR EACH ROW EXECUTE FUNCTION identity.reject_ctf_decision_mutation();
REVOKE ALL ON identity.ctf_decision_proposals FROM PUBLIC,dvaia_identity_runtime;
GRANT SELECT ON identity.ctf_decision_proposals TO dvaia_identity_runtime;
ALTER TABLE identity.ctf_decisions ADD COLUMN proposal_id uuid UNIQUE REFERENCES identity.ctf_decision_proposals(proposal_id);
ALTER TABLE identity.ctf_decisions ADD COLUMN completion_time_ms bigint CHECK(completion_time_ms>=0);
ALTER TABLE identity.ctf_decisions ADD COLUMN hint_penalty_total integer CHECK(hint_penalty_total>=0);
ALTER TABLE identity.ctf_decisions ADD COLUMN adaptive_revision bigint CHECK(adaptive_revision>=0);

-- Inputs to this helper are the exact staged ASCII normalization produced by
-- existing JS hashPayload. This does NOT reimplement Unicode lowercasing in SQL.
CREATE FUNCTION identity.ctf_ascii_payload_similar(a text,b text) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$
 WITH aa AS (SELECT DISTINCT substr(a,n,3) AS t FROM generate_series(1,length(a)-2)n),
 bb AS (SELECT DISTINCT substr(b,n,3) AS t FROM generate_series(1,length(b)-2)n),
 common AS (SELECT t FROM aa INTERSECT SELECT t FROM bb),combined AS (SELECT t FROM aa UNION SELECT t FROM bb)
 SELECT length(a)>=10 AND COALESCE((SELECT count(*)::numeric FROM common)/NULLIF((SELECT count(*) FROM combined),0),0)>=0.85
$$;
REVOKE ALL ON FUNCTION identity.ctf_ascii_payload_similar(text,text) FROM PUBLIC;


-- Exact JSON keys/types are enforced in SQL even for direct runtime calls.
CREATE FUNCTION identity.ctf_decision_document_matches(e jsonb) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
DECLARE j jsonb;
BEGIN
 IF NOT identity.ctf_json_matches(e,'{"type":"object","properties":{"version":{"type":"number","enum":[1]},"binding":{"type":"object","properties":{"ownerId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"sessionId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"admissionId":{"type":"string","bytes":36,"pattern":"^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$"},"runId":{"type":"string","bytes":36,"pattern":"^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$"},"ownerGeneration":{"type":"string","bytes":19,"pattern":"^(0|[1-9][0-9]*)$","minimum":0,"maximum":"9223372036854775807"},"globalRevision":{"type":"string","bytes":19,"pattern":"^(0|[1-9][0-9]*)$","minimum":0,"maximum":"9223372036854775807"},"stageRevision":{"type":"string","bytes":19,"pattern":"^(0|[1-9][0-9]*)$","minimum":0,"maximum":"9223372036854775807"},"participantId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"progressId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"stageId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"stageNumber":{"type":"number","minimum":1,"maximum":2147483647,"integer":true},"stageDigest":{"type":"string","bytes":64,"pattern":"^[a-f0-9]{64}$"}}},"payload":{"type":"string","bytes":16384},"normalizedPayload":{"type":"string","bytes":16384,"pattern":"^[a-z0-9_ ]*$"},"payloadHash":{"type":"string","bytes":64,"pattern":"^[a-f0-9]{64}$"},"visibleResponse":{"type":"string","bytes":16384},"observedSecret":{"type":"boolean"},"techniqueTag":{"type":"string","bytes":128},"guardian":{"type":"object","properties":{"version":{"type":"string","enum":["ctf-guardian-provenance-v1"]},"provider":{"type":"string","enum":["ollama","anthropic","claude","openai","chatgpt","bedrock","lmstudio"]},"model":{"type":"string","bytes":256,"pattern":"."},"rawResponseSha256":{"type":"string","bytes":64,"pattern":"^[a-f0-9]{64}$"},"visibleResponseSha256":{"type":"string","bytes":64,"pattern":"^[a-f0-9]{64}$"},"rawResponseBytes":{"type":"number","minimum":1,"maximum":1048576,"integer":true},"visibleResponseBytes":{"type":"number","minimum":0,"maximum":16384,"integer":true}},"nullable":true},"judgment":{"type":"object","properties":{"verdict":{"type":"string","enum":["pass","fail","inconclusive","unavailable","blocked"]},"provider":{"type":"string","bytes":128,"nullable":true},"model":{"type":"string","bytes":256,"nullable":true},"judgeVersion":{"type":"string","bytes":256,"nullable":true},"rubricVersion":{"type":"string","enum":["ctf-visible-secret-v2"]},"receiptHash":{"type":"string","bytes":64,"pattern":"^[a-f0-9]{64}$"}}},"judgeReceipt":{"type":"string","bytes":24576}}}'::jsonb) THEN RETURN false; END IF;
 IF e->>'payloadHash' IS DISTINCT FROM encode(sha256(convert_to(e->>'normalizedPayload','UTF8')),'hex')
 OR e->'judgment'->>'receiptHash' IS DISTINCT FROM encode(sha256(convert_to(e->>'judgeReceipt','UTF8')),'hex')
 OR NOT ((e->>'judgeReceipt') IS JSON OBJECT WITH UNIQUE KEYS) THEN RETURN false; END IF;
 j:=(e->>'judgeReceipt')::jsonb;
 IF (j->'verdict') IS DISTINCT FROM e->'judgment'->'verdict' OR (j->'rubricVersion') IS DISTINCT FROM e->'judgment'->'rubricVersion'
 OR COALESCE(j->'provider','null'::jsonb) IS DISTINCT FROM e->'judgment'->'provider'
 OR COALESCE(j->'model','null'::jsonb) IS DISTINCT FROM e->'judgment'->'model'
 OR COALESCE(j->'judgeVersion','null'::jsonb) IS DISTINCT FROM e->'judgment'->'judgeVersion' THEN RETURN false; END IF;
 IF e->'guardian'='null'::jsonb THEN RETURN e->'observedSecret'='false'::jsonb AND e->'judgment'->>'verdict'<>'pass'; END IF;
 RETURN (e->'guardian'->>'visibleResponseSha256'=encode(sha256(convert_to(e->>'visibleResponse','UTF8')),'hex')
 AND (e->'guardian'->>'visibleResponseBytes')::integer=octet_length(e->>'visibleResponse')) IS TRUE;
END; $$;
REVOKE ALL ON FUNCTION identity.ctf_decision_document_matches(jsonb) FROM PUBLIC;
CREATE TABLE identity.ctf_decision_inputs (
 admission_id uuid PRIMARY KEY REFERENCES identity.ctf_attempt_admissions(operation_id),run_id uuid NOT NULL UNIQUE,
 owner_id integer NOT NULL,session_id integer NOT NULL,canonical_input text NOT NULL CHECK(octet_length(canonical_input)<=32768),
 input_hash text NOT NULL CHECK(input_hash=encode(sha256(convert_to(canonical_input,'UTF8')),'hex')),
 input jsonb NOT NULL CHECK(input=canonical_input::jsonb)
);
CREATE TRIGGER ctf_input_immutable BEFORE UPDATE OR DELETE ON identity.ctf_decision_inputs FOR EACH ROW EXECUTE FUNCTION identity.reject_ctf_decision_mutation();
REVOKE ALL ON identity.ctf_decision_inputs FROM PUBLIC,dvaia_identity_runtime;
GRANT SELECT ON identity.ctf_decision_inputs TO dvaia_identity_runtime;
CREATE FUNCTION identity.capture_ctf_decision_input(p_actor integer,p_session integer,p_token_hash text,p_document text,p_hash text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE e jsonb;b jsonb;a identity.ctf_attempt_admissions%ROWTYPE;ev identity.ctf_outbox%ROWTYPE;prior identity.ctf_decision_inputs%ROWTYPE;
BEGIN
 IF p_document IS NULL OR octet_length(p_document)>32768 OR NOT(p_document IS JSON OBJECT WITH UNIQUE KEYS)
 OR p_hash IS DISTINCT FROM encode(sha256(convert_to(p_document,'UTF8')),'hex') THEN RAISE EXCEPTION 'CTF input bytes invalid'; END IF;
 e:=p_document::jsonb;b:=e->'binding';
 IF NOT identity.ctf_json_matches(e,'{"type":"object","properties":{"version":{"type":"number","enum":[1]},"binding":{"type":"object","properties":{"ownerId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"sessionId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"admissionId":{"type":"string","bytes":36,"pattern":"^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$"},"runId":{"type":"string","bytes":36,"pattern":"^[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}$"},"ownerGeneration":{"type":"string","bytes":19,"pattern":"^(0|[1-9][0-9]*)$","minimum":0,"maximum":"9223372036854775807"},"globalRevision":{"type":"string","bytes":19,"pattern":"^(0|[1-9][0-9]*)$","minimum":0,"maximum":"9223372036854775807"},"stageRevision":{"type":"string","bytes":19,"pattern":"^(0|[1-9][0-9]*)$","minimum":0,"maximum":"9223372036854775807"},"participantId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"progressId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"stageId":{"type":"string","bytes":10,"pattern":"^[1-9][0-9]*$","minimum":1,"maximum":2147483647},"stageNumber":{"type":"number","minimum":1,"maximum":2147483647,"integer":true},"stageDigest":{"type":"string","bytes":64,"pattern":"^[a-f0-9]{64}$"}}},"payload":{"type":"string","bytes":16384},"techniqueTag":{"type":"string","bytes":128},"normalizedPayload":{"type":"string","bytes":16384,"pattern":"^[a-z0-9_ ]*$"},"payloadHash":{"type":"string","bytes":64,"pattern":"^[a-f0-9]{64}$"}}}'::jsonb) OR (b->>'ownerId')::integer IS DISTINCT FROM p_actor OR (b->>'sessionId')::integer IS DISTINCT FROM p_session OR e->>'payloadHash' IS DISTINCT FROM encode(sha256(convert_to(e->>'normalizedPayload','UTF8')),'hex') THEN RAISE EXCEPTION 'CTF input schema invalid'; END IF;
 PERFORM 1 FROM identity.users u WHERE u.id=p_actor FOR UPDATE;
 PERFORM 1 FROM identity.user_sessions us WHERE us.id=p_session AND us.user_id=p_actor FOR UPDATE;
 IF NOT EXISTS(SELECT 1 FROM identity.users u JOIN identity.user_sessions us ON us.user_id=u.id WHERE u.id=p_actor AND us.id=p_session AND u.is_active=1 AND (u.account_locked_until IS NULL OR u.account_locked_until<=clock_timestamp()) AND us.is_active=1 AND us.expires_at>clock_timestamp() AND us.session_token_hash=p_token_hash)
 OR EXISTS(SELECT 1 FROM identity.student_deletion_jobs dj WHERE dj.subject_user_id=p_actor)
 OR EXISTS(SELECT 1 FROM identity.student_deletion_run_blocks rb WHERE rb.owner_key='["CTF","'||p_actor||'"]') THEN RAISE EXCEPTION 'SESSION_REVOKED' USING ERRCODE='28000'; END IF;
 SELECT * INTO a FROM identity.ctf_attempt_admissions aa WHERE aa.operation_id=(b->>'admissionId')::uuid;
 SELECT * INTO ev FROM identity.ctf_outbox oo WHERE oo.operation_id=a.operation_id;
 IF a.owner_id IS DISTINCT FROM p_actor OR a.owner_generation IS DISTINCT FROM (b->>'ownerGeneration')::bigint
 OR a.participant_id IS DISTINCT FROM (b->>'participantId')::bigint OR a.progress_id IS DISTINCT FROM (b->>'progressId')::bigint OR a.stage_id IS DISTINCT FROM (b->>'stageId')::bigint
 OR ev.state IS DISTINCT FROM 'applied' OR ev.kind IS DISTINCT FROM 'admit_attempt' OR ev.actor_id IS DISTINCT FROM p_actor OR ev.session_id IS DISTINCT FROM p_session
 OR ev.command->'scope'->>'globalRevision' IS DISTINCT FROM b->>'globalRevision' OR ev.command->'scope'->>'stageRevision' IS DISTINCT FROM b->>'stageRevision'
 OR NOT EXISTS(SELECT 1 FROM graph_runtime.runs rr WHERE rr.run_id=(b->>'runId')::uuid AND rr.owner_key='["CTF","'||p_actor||'"]' AND rr.generation=a.owner_generation AND rr.status='running')
 OR NOT EXISTS(SELECT 1 FROM identity.ctf_stage_bindings sb WHERE sb.stage_id=a.stage_id AND sb.stage_digest=b->>'stageDigest' AND sb.stage_number=(b->>'stageNumber')::integer) THEN RAISE EXCEPTION 'CTF input admission mismatch'; END IF;
 SELECT * INTO prior FROM identity.ctf_decision_inputs di WHERE di.admission_id=a.operation_id;
 IF FOUND THEN IF prior.canonical_input IS DISTINCT FROM p_document OR prior.input_hash IS DISTINCT FROM p_hash OR prior.session_id IS DISTINCT FROM p_session THEN RAISE EXCEPTION 'CTF input replay conflict'; END IF; RETURN jsonb_build_object('claimed',false,'admissionId',a.operation_id,'proposalId',(SELECT pp.proposal_id FROM identity.ctf_decision_proposals pp WHERE pp.admission_operation_id=a.operation_id)); END IF;
 INSERT INTO identity.ctf_decision_inputs VALUES(a.operation_id,(b->>'runId')::uuid,p_actor,p_session,p_document,p_hash,e);
 RETURN jsonb_build_object('claimed',true,'admissionId',a.operation_id,'proposalId',NULL);
END; $$;
REVOKE ALL ON FUNCTION identity.capture_ctf_decision_input(integer,integer,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.capture_ctf_decision_input(integer,integer,text,text,text) TO dvaia_identity_runtime;

-- The runtime server is the trusted observer of provider/Judge calls. This
-- function is never a learner HTTP endpoint; SQL cannot attest a remote model.
-- Authorization later accepts only this immutable proposal ID, not new verdicts.
CREATE FUNCTION identity.stage_ctf_server_proposal(p_proposal uuid,p_actor integer,p_session integer,p_token_hash text,p_document text,p_hash text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE e jsonb;b jsonb;a identity.ctf_attempt_admissions%ROWTYPE;r graph_runtime.runs%ROWTYPE;prior identity.ctf_decision_proposals%ROWTYPE;
BEGIN
 IF p_document IS NULL OR octet_length(p_document)>65536 OR NOT(p_document IS JSON OBJECT WITH UNIQUE KEYS)
 OR p_hash IS DISTINCT FROM encode(sha256(convert_to(p_document,'UTF8')),'hex') THEN RAISE EXCEPTION 'CTF proposal bytes invalid'; END IF;
 e:=p_document::jsonb;b:=e->'binding';
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
REVOKE ALL ON FUNCTION identity.stage_ctf_server_proposal(uuid,integer,integer,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.stage_ctf_server_proposal(uuid,integer,integer,text,text,text) TO dvaia_identity_runtime;

CREATE FUNCTION identity.authorize_ctf_decision(p_proposal uuid,p_actor integer,p_session integer,p_token_hash text,p_decision uuid)
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
 IF g.lifecycle_state IS DISTINCT FROM 'ready' OR o.lifecycle_state IS DISTINCT FROM 'ready' OR s.lifecycle_state IS DISTINCT FROM 'ready'
 OR g.revision IS DISTINCT FROM (b->>'globalRevision')::bigint OR s.revision IS DISTINCT FROM (b->>'stageRevision')::bigint OR o.owner_generation IS DISTINCT FROM (b->>'ownerGeneration')::bigint
 OR NOT EXISTS(SELECT 1 FROM graph_runtime.owners WHERE owner_key='["CTF","'||p_actor||'"]' AND generation=o.owner_generation)
 OR NOT EXISTS(SELECT 1 FROM graph_runtime.runs WHERE run_id=p.run_id AND owner_key='["CTF","'||p_actor||'"]' AND generation=o.owner_generation AND status='running') THEN RAISE EXCEPTION 'CTF decision scope stale'; END IF;
 SELECT * INTO part FROM identity.ctf_participant_bindings WHERE owner_id=p_actor;
 SELECT * INTO pr FROM identity.ctf_progress_bindings WHERE owner_id=p_actor AND owner_generation=o.owner_generation AND stage_id=(b->>'stageId')::bigint;
 SELECT * INTO st FROM identity.ctf_stage_bindings WHERE stage_id=(b->>'stageId')::bigint;
 SELECT * INTO cfg FROM identity.ctf_config_binding WHERE singleton;
 IF part.active IS DISTINCT FROM true OR part.banned OR o.banned OR part.owner_generation IS DISTINCT FROM o.owner_generation OR part.participant_id IS DISTINCT FROM (b->>'participantId')::bigint
 OR pr.participant_id IS DISTINCT FROM part.participant_id OR pr.progress_id IS DISTINCT FROM (b->>'progressId')::bigint OR pr.status IS DISTINCT FROM 'in_progress'
 OR st.active IS DISTINCT FROM true OR st.stage_digest IS DISTINCT FROM b->>'stageDigest' OR st.stage_number IS DISTINCT FROM (b->>'stageNumber')::integer
 OR cfg.enabled IS DISTINCT FROM true OR (NOT cfg.visible_to_students AND NOT(u.role='admin' OR COALESCE(u.admin_level,0)>0))
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
REVOKE ALL ON FUNCTION identity.authorize_ctf_decision(uuid,integer,integer,text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.authorize_ctf_decision(uuid,integer,integer,text,uuid) TO dvaia_identity_runtime;
