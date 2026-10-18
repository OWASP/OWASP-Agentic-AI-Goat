-- A pending decision can acknowledge only that its owned projection is queued.
-- Final results remain guarded by authorize_ctf_current_publication.
CREATE FUNCTION identity.ctf_current_decision_pending(p_decision uuid,p_actor integer,p_session integer,p_token_hash text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE d identity.ctf_decisions%ROWTYPE;g identity.ctf_authority%ROWTYPE;s identity.ctf_authority%ROWTYPE;o identity.ctf_authority%ROWTYPE;
 u identity.users%ROWTYPE;part identity.ctf_participant_bindings%ROWTYPE;pr identity.ctf_progress_bindings%ROWTYPE;st identity.ctf_stage_bindings%ROWTYPE;cfg identity.ctf_config_binding%ROWTYPE;ev identity.ctf_outbox%ROWTYPE;
BEGIN
 IF p_decision IS NULL OR p_actor IS NULL OR p_session IS NULL OR p_token_hash IS NULL OR p_token_hash !~ '^[a-f0-9]{64}$' THEN RETURN false; END IF;
 SELECT * INTO d FROM identity.ctf_decisions dd WHERE dd.decision_id=p_decision;
 IF d.decision_id IS NULL OR d.owner_id IS DISTINCT FROM p_actor OR d.session_id IS DISTINCT FROM p_session OR d.proposal_id IS NULL THEN RETURN false; END IF;
 -- Match the final publication and enqueue lock order. The read is current,
 -- but never releases a decision's verdict, completion, evidence or receipt.
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
 SELECT * INTO part FROM identity.ctf_participant_bindings b WHERE b.owner_id=p_actor;
 SELECT * INTO pr FROM identity.ctf_progress_bindings b WHERE b.progress_id=d.progress_id;
 SELECT * INTO st FROM identity.ctf_stage_bindings b WHERE b.stage_id=d.stage_id;
 SELECT * INTO cfg FROM identity.ctf_config_binding b WHERE b.singleton;
 SELECT * INTO ev FROM identity.ctf_outbox b WHERE b.operation_id=d.decision_id AND b.decision_id=d.decision_id AND b.sequence=d.sequence;
 IF ev.canonical_command IS NULL OR NOT(ev.canonical_command IS JSON OBJECT WITH UNIQUE KEYS) THEN RETURN false; END IF;
 RETURN (identity.ctf_publication_bootstrap_ready() IS TRUE
  AND g.lifecycle_state='ready' AND s.lifecycle_state='ready' AND o.lifecycle_state='pending' AND o.pending_operation_id=d.decision_id
  AND g.revision=d.global_revision AND s.revision=d.stage_revision AND o.owner_generation=d.owner_generation AND o.banned=false
  AND d.owner_key='["CTF","'||p_actor||'"]'
  AND EXISTS(SELECT 1 FROM graph_runtime.owners go WHERE go.owner_key=d.owner_key AND go.generation=d.owner_generation)
  AND EXISTS(SELECT 1 FROM graph_runtime.runs gr WHERE gr.run_id=d.run_id AND gr.owner_key=d.owner_key AND gr.generation=d.owner_generation AND gr.status IN ('running','completed'))
  AND part.active=true AND part.banned=false AND part.owner_generation=d.owner_generation AND part.participant_id=d.participant_id
  AND pr.owner_id=p_actor AND pr.owner_generation=d.owner_generation AND pr.participant_id=d.participant_id AND pr.progress_id=d.progress_id AND pr.stage_id=d.stage_id AND pr.status='in_progress'
  AND st.active=true AND st.stage_digest=d.stage_digest
  AND cfg.enabled=true AND (cfg.visible_to_students=true OR (u.role IN ('admin','super_admin') AND COALESCE(u.admin_level,0)>=1))
  AND ev.kind='decision' AND ev.operation_id=d.decision_id AND ev.decision_id=d.decision_id AND ev.sequence=d.sequence AND ev.actor_id=p_actor AND ev.session_id=p_session
  AND ev.state='pending' AND ev.canonical_result IS NULL AND ev.result_hash IS NULL AND ev.request_fingerprint=d.evidence_hash AND ev.owner_generation_after=d.owner_generation
  AND ev.command=ev.canonical_command::jsonb AND ev.command_hash=encode(sha256(convert_to(ev.canonical_command,'UTF8')),'hex')
  AND ev.command->>'kind'='decision' AND ev.command->>'operationId'=d.decision_id::text AND ev.command->>'actorId'=p_actor::text
  AND ev.command->'scope'->>'ownerId'=p_actor::text AND ev.command->'scope'->>'ownerGeneration'=d.owner_generation::text
  AND ev.command->'scope'->>'participantId'=d.participant_id::text AND ev.command->'scope'->>'progressId'=d.progress_id::text
  AND ev.command->'scope'->>'stageId'=d.stage_id::text AND ev.command->'scope'->>'stageRevision'=d.stage_revision::text
  AND ev.command->'scope'->>'globalRevision'=d.global_revision::text
  AND ev.command->'body'->>'decisionId'=d.decision_id::text AND ev.command->'body'->>'proposalId'=d.proposal_id::text
  AND ev.command->'body'->>'evidenceHash'=d.evidence_hash AND g.applied_sequence<d.sequence) IS TRUE;
END; $$;
REVOKE ALL ON FUNCTION identity.ctf_current_decision_pending(uuid,integer,integer,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.ctf_current_decision_pending(uuid,integer,integer,text) TO dvaia_identity_runtime;
