-- DRAFT ONLY. Final account-content cleanup after every earlier deletion step.
-- The numeric user row remains as an inactive, anonymized tombstone because
-- immutable grading and launch receipts retain that internal identifier.
CREATE FUNCTION identity.finalize_student_deletion(
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
  -- Pending attempts must retain the table's NULL verdict/result invariant.
  -- Evaluated receipts stay immutable evidence that an assessment occurred,
  -- while their potentially identifying result body is replaced.
  UPDATE workshop_platform.objective_judgments SET
    result_json=CASE WHEN verdict IS NULL THEN NULL ELSE jsonb_build_object('deleted',true) END,
    result_digest=NULL
    WHERE user_id=requested_subject_id;
  DELETE FROM workshop_platform.completions WHERE user_id=requested_subject_id;
  DELETE FROM workshop_platform.time_tracking WHERE user_id=requested_subject_id;
  DELETE FROM workshop_platform.user_modes WHERE user_id=requested_subject_id;
  DELETE FROM workshop_platform.user_state WHERE user_id=requested_subject_id;
  -- Imported auxiliary rows may use the historical username or email as the
  -- user_key. These aliases are read from the locked identity row before it is
  -- anonymized; arbitrary caller-supplied aliases are never accepted.
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
REVOKE ALL ON FUNCTION identity.finalize_student_deletion(uuid,uuid,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.finalize_student_deletion(uuid,uuid,integer)
  TO dvaia_identity_runtime;
