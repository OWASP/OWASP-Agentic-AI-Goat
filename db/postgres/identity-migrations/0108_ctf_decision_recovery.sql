-- Unmounted authenticated recovery. Historical receipts never authorize current
-- publication. No graph-running/current-stage precondition for reading history.
CREATE FUNCTION identity.read_ctf_decision_recovery(p_admission uuid,p_actor integer,p_session integer,p_token_hash text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE i identity.ctf_decision_inputs%ROWTYPE;p identity.ctf_decision_proposals%ROWTYPE;d identity.ctf_decisions%ROWTYPE;
BEGIN
 PERFORM 1 FROM identity.users u WHERE u.id=p_actor FOR UPDATE;
 PERFORM 1 FROM identity.user_sessions us WHERE us.id=p_session AND us.user_id=p_actor FOR UPDATE;
 IF NOT EXISTS(SELECT 1 FROM identity.users u JOIN identity.user_sessions us ON us.user_id=u.id WHERE u.id=p_actor AND us.id=p_session AND u.is_active=1 AND (u.account_locked_until IS NULL OR u.account_locked_until<=clock_timestamp()) AND us.is_active=1 AND us.expires_at>clock_timestamp() AND us.session_token_hash=p_token_hash)
 OR EXISTS(SELECT 1 FROM identity.student_deletion_jobs dj WHERE dj.subject_user_id=p_actor)
 OR EXISTS(SELECT 1 FROM identity.student_deletion_run_blocks rb WHERE rb.owner_key='["CTF","'||p_actor||'"]') THEN RAISE EXCEPTION 'SESSION_REVOKED' USING ERRCODE='28000'; END IF;
 SELECT * INTO i FROM identity.ctf_decision_inputs ii WHERE ii.admission_id=p_admission AND ii.owner_id=p_actor AND ii.session_id=p_session;
 IF NOT FOUND THEN RETURN jsonb_build_object('state','not_found','admissionId',p_admission,'proposalId',NULL,'receipt',NULL); END IF;
 SELECT * INTO p FROM identity.ctf_decision_proposals pp WHERE pp.admission_operation_id=i.admission_id AND pp.owner_id=i.owner_id AND pp.session_id=i.session_id AND pp.run_id=i.run_id;
 IF NOT FOUND THEN RETURN jsonb_build_object('state','claimed_without_proposal','admissionId',p_admission,'proposalId',NULL,'receipt',NULL); END IF;
 SELECT * INTO d FROM identity.ctf_decisions dd WHERE dd.proposal_id=p.proposal_id AND dd.run_id=i.run_id AND dd.owner_id=i.owner_id AND dd.session_id=i.session_id AND dd.evidence_hash=p.evidence_hash;
 IF NOT FOUND THEN RETURN jsonb_build_object('state','proposal_staged','admissionId',p_admission,'proposalId',p.proposal_id,'receipt',NULL); END IF;
 RETURN jsonb_build_object('state','decided','admissionId',p_admission,'proposalId',p.proposal_id,'receipt',jsonb_build_object('decision_id',d.decision_id,'sequence',d.sequence::text,'accepted',d.accepted,'verdict',d.verdict,'authorized_at',to_char(d.authorized_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'evidence_hash',d.evidence_hash,'replayed',true));
END; $$;
REVOKE ALL ON FUNCTION identity.read_ctf_decision_recovery(uuid,integer,integer,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.read_ctf_decision_recovery(uuid,integer,integer,text) TO dvaia_identity_runtime;
