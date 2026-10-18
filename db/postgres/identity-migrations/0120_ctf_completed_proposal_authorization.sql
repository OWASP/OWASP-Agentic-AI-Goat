-- Recover an immutable staged proposal after execution has completed.
-- Prior receipts remain historical replay; capture and staging are unchanged.
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
