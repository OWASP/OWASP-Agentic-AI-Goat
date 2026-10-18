-- Preserve XSS reset journals as immutable audit metadata after student
-- deletion. Recovery workers must not claim inactive/deleting owners, while
-- the identity finalizer receives one transaction-local authority to redact
-- only the identifying result body of retained objective judgments.
CREATE TABLE identity.xss_deletion_redaction_authority (
  backend_pid integer NOT NULL,
  transaction_id bigint NOT NULL,
  job_id uuid NOT NULL,
  lease_token uuid NOT NULL,
  subject_user_id integer NOT NULL CHECK(subject_user_id>0),
  PRIMARY KEY(backend_pid,transaction_id,subject_user_id)
);
REVOKE ALL ON identity.xss_deletion_redaction_authority FROM PUBLIC,dvaia_identity_runtime;

CREATE OR REPLACE FUNCTION identity.list_recoverable_xss_profile_resets(requested_limit integer)
RETURNS TABLE(operation_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,identity AS $$
BEGIN
  IF requested_limit IS NULL OR requested_limit<1 OR requested_limit>100 THEN
    RAISE EXCEPTION 'Invalid XSS profile reset recovery limit' USING ERRCODE='22023';
  END IF;
  RETURN QUERY SELECT r.operation_id FROM identity.xss_profile_reset_operations r
    JOIN identity.users u ON u.id=r.owner_id AND u.is_active=1
    WHERE NOT EXISTS(SELECT 1 FROM identity.student_deletion_jobs d
      WHERE d.subject_user_id=r.owner_id)
      AND (r.status IN ('pending','failed')
        OR (r.status='running' AND r.lease_expires_at<=clock_timestamp()))
    ORDER BY r.updated_at,r.operation_id LIMIT requested_limit;
END $$;

CREATE OR REPLACE FUNCTION identity.list_recoverable_xss_parent_resets(requested_limit integer)
RETURNS TABLE(operation_id uuid)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,identity AS $$
BEGIN
  IF requested_limit IS NULL OR requested_limit<1 OR requested_limit>100 THEN
    RAISE EXCEPTION 'Invalid recovery limit' USING ERRCODE='22023';
  END IF;
  RETURN QUERY SELECT p.operation_id FROM identity.xss_parent_reset_operations p
    JOIN identity.users u ON u.id=p.owner_id AND u.is_active=1
    WHERE NOT EXISTS(SELECT 1 FROM identity.student_deletion_jobs d
      WHERE d.subject_user_id=p.owner_id)
      AND (p.status IN ('pending','failed')
        OR (p.status='running' AND p.lease_expires_at<=clock_timestamp()))
    ORDER BY p.updated_at,p.operation_id LIMIT requested_limit;
END $$;

CREATE OR REPLACE FUNCTION identity.guard_xss_parent_reset_admission() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,identity AS $$
DECLARE candidate_owner integer;
DECLARE redaction_authorized boolean;
BEGIN
  IF TG_OP='UPDATE' THEN
    -- The student-deletion finalizer may redact only the two documented result
    -- fields. Its authority is bound to this backend, transaction, subject,
    -- active deletion job and current lease. No public/runtime caller can mint
    -- the private authority row.
    IF TG_TABLE_NAME='objective_judgments' THEN
      IF OLD.workshop_key='xss_workshop' AND NEW.workshop_key='xss_workshop'
         AND OLD.user_id=NEW.user_id
         AND (to_jsonb(NEW)-ARRAY['result_json','result_digest'])
             =(to_jsonb(OLD)-ARRAY['result_json','result_digest'])
         AND NEW.result_digest IS NULL
         AND NEW.result_json IS NOT DISTINCT FROM
           (CASE WHEN OLD.verdict IS NULL THEN NULL ELSE jsonb_build_object('deleted',true) END) THEN
        SELECT EXISTS(
          SELECT 1 FROM identity.xss_deletion_redaction_authority a
          JOIN identity.student_deletion_jobs d
            ON d.job_id=a.job_id AND d.subject_user_id=a.subject_user_id
           AND d.state='running' AND d.lease_token=a.lease_token
           AND d.lease_expires_at>clock_timestamp()
          WHERE a.backend_pid=pg_backend_pid()
            AND a.transaction_id=txid_current()
            AND a.subject_user_id=OLD.user_id
        ) INTO redaction_authorized;
        IF redaction_authorized THEN RETURN NEW; END IF;
      END IF;
    END IF;
    -- Moving a protected row cannot evade the fence. Lock both old and new
    -- XSS owners in numeric order so cross-owner updates cannot invert locks.
    FOR candidate_owner IN
      SELECT DISTINCT v.owner_id FROM (VALUES
        (CASE WHEN OLD.workshop_key='xss_workshop' THEN OLD.user_id END),
        (CASE WHEN NEW.workshop_key='xss_workshop' THEN NEW.user_id END)
      ) AS v(owner_id) WHERE v.owner_id IS NOT NULL ORDER BY v.owner_id
    LOOP
      PERFORM identity.assert_xss_mutation_admitted(candidate_owner);
    END LOOP;
  ELSIF NEW.workshop_key='xss_workshop' THEN
    PERFORM identity.assert_xss_mutation_admitted(NEW.user_id);
  END IF;
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION identity.finalize_student_deletion(
  requested_job_id uuid, requested_lease_token uuid, requested_subject_id integer
) RETURNS boolean
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,identity,workshop_platform AS $$
DECLARE job identity.student_deletion_jobs%ROWTYPE;
DECLARE subject identity.users%ROWTYPE;
BEGIN
  SELECT * INTO job FROM identity.student_deletion_jobs
    WHERE job_id=requested_job_id AND subject_user_id=requested_subject_id
      AND state='running' AND lease_token=requested_lease_token
      AND lease_expires_at>clock_timestamp() FOR UPDATE;
  IF NOT FOUND THEN RAISE EXCEPTION 'Deletion authority is unavailable' USING ERRCODE='55000'; END IF;
  IF EXISTS(SELECT 1 FROM identity.student_deletion_steps
      WHERE job_id=requested_job_id AND step_key<>'identity' AND state<>'completed')
     OR NOT EXISTS(SELECT 1 FROM identity.student_deletion_steps
      WHERE job_id=requested_job_id AND step_key='identity' AND state<>'completed') THEN
    RAISE EXCEPTION 'Deletion cleanup is incomplete' USING ERRCODE='55000';
  END IF;
  SELECT * INTO subject FROM identity.users WHERE id=requested_subject_id FOR UPDATE;
  IF NOT FOUND OR subject.role<>'student' OR subject.admin_level<>0 OR subject.is_active<>0 THEN
    RAISE EXCEPTION 'Deletion subject is unavailable' USING ERRCODE='55000';
  END IF;

  DELETE FROM workshop_platform.grade_packets WHERE user_id=requested_subject_id;
  DELETE FROM workshop_platform.objective_evidence WHERE user_id=requested_subject_id;
  INSERT INTO identity.xss_deletion_redaction_authority(
    backend_pid,transaction_id,job_id,lease_token,subject_user_id
  ) VALUES(pg_backend_pid(),txid_current(),requested_job_id,requested_lease_token,requested_subject_id);
  -- Pending attempts retain the NULL verdict/result invariant. Evaluated
  -- receipts retain the assessment coordinates while losing result content.
  UPDATE workshop_platform.objective_judgments SET
    result_json=CASE WHEN verdict IS NULL THEN NULL ELSE jsonb_build_object('deleted',true) END,
    result_digest=NULL
    WHERE user_id=requested_subject_id;
  DELETE FROM identity.xss_deletion_redaction_authority
    WHERE backend_pid=pg_backend_pid() AND transaction_id=txid_current()
      AND subject_user_id=requested_subject_id;
  DELETE FROM workshop_platform.completions WHERE user_id=requested_subject_id;
  DELETE FROM workshop_platform.time_tracking WHERE user_id=requested_subject_id;
  DELETE FROM workshop_platform.user_modes WHERE user_id=requested_subject_id;
  DELETE FROM workshop_platform.user_state WHERE user_id=requested_subject_id;
  DELETE FROM identity.email_agent_progress
    WHERE user_key IN (requested_subject_id::text,subject.username,subject.email);
  DELETE FROM identity.sent_emails_log
    WHERE user_key IN (requested_subject_id::text,subject.username,subject.email);
  DELETE FROM identity.email_verification_tokens WHERE user_id=requested_subject_id;
  DELETE FROM identity.activity_logs WHERE user_id=requested_subject_id;
  DELETE FROM identity.user_sessions WHERE user_id=requested_subject_id;
  UPDATE identity.admin_permissions SET granted_by=NULL WHERE granted_by=requested_subject_id;
  UPDATE workshop_platform.exercises SET updated_by=NULL WHERE updated_by=requested_subject_id;
  UPDATE workshop_platform.objectives SET updated_by=NULL WHERE updated_by=requested_subject_id;
  UPDATE workshop_platform.xss_legacy_solution_visibility SET enabled_by=NULL
    WHERE enabled_by=requested_subject_id;
  UPDATE identity.users SET
    username='deleted-'||requested_job_id::text,
    email='deleted-'||requested_job_id::text||'@invalid.local',
    password='$2b$12$000000000000000000000uG3W0Jp6IPhhD1TRqN8Yc2zJQG3vVnSA',
    full_name=NULL,phone=NULL,department=NULL,profile_image=NULL,
    email_verified=0,account_locked_until=NULL,login_attempts=0,last_login=NULL,
    password_reset_required=0,two_factor_enabled=0,two_factor_secret=NULL,
    created_by_ip=NULL,last_login_ip=NULL,updated_at=clock_timestamp()
    WHERE id=requested_subject_id;
  RETURN true;
END $$;

REVOKE ALL ON FUNCTION identity.list_recoverable_xss_profile_resets(integer),
  identity.list_recoverable_xss_parent_resets(integer),
  identity.guard_xss_parent_reset_admission(),
  identity.finalize_student_deletion(uuid,uuid,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.list_recoverable_xss_profile_resets(integer),
  identity.list_recoverable_xss_parent_resets(integer),
  identity.finalize_student_deletion(uuid,uuid,integer) TO dvaia_identity_runtime;
