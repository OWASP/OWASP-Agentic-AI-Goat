-- A later complete activation migration must replace this predicate with an
-- exact finalized-checkpoint check.0110 PREPARED is not readiness. Runtime cannot grant itself readiness.
CREATE FUNCTION identity.ctf_publication_bootstrap_ready() RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS 'SELECT false';
REVOKE ALL ON FUNCTION identity.ctf_publication_bootstrap_ready() FROM PUBLIC,dvaia_identity_runtime;

-- Unmounted current publication authorization. Historical receipt reads are
-- deliberately separate. This is a bounded authorization point, not a socket
-- delivery guarantee against a revocation committed after this transaction.
CREATE FUNCTION identity.authorize_ctf_current_publication(p_decision uuid,p_actor integer,p_session integer,p_token_hash text)
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
 OR cfg.enabled IS DISTINCT FROM true OR (cfg.visible_to_students IS DISTINCT FROM true AND NOT(u.role='admin' OR COALESCE(u.admin_level,0)>0))
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
REVOKE ALL ON FUNCTION identity.authorize_ctf_current_publication(uuid,integer,integer,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.authorize_ctf_current_publication(uuid,integer,integer,text) TO dvaia_identity_runtime;
