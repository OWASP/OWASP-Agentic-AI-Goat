-- Qualification draft; not discovered by startup migration execution.
-- The subject has deliberately no FK: this receipt must survive final deletion.
CREATE TABLE identity.student_deletion_jobs (
 job_id uuid PRIMARY KEY,
 subject_user_id integer NOT NULL UNIQUE CHECK(subject_user_id > 0),
 requested_by integer NOT NULL CHECK(requested_by > 0),
 state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','running','failed','quarantined','completed')),
 failure_code text CHECK(failure_code IS NULL OR failure_code='DELETION_MANIFEST_MISMATCH'),
 lease_token uuid,
 lease_expires_at timestamptz,
 requested_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 completed_at timestamptz,
 CHECK((lease_token IS NULL) = (lease_expires_at IS NULL)),
 CHECK((state='running') = (lease_token IS NOT NULL)),
 CHECK((state='completed') = (completed_at IS NOT NULL)),
 CHECK((state='quarantined') = (failure_code IS NOT NULL)),
 CHECK(subject_user_id <> requested_by)
);
CREATE TABLE identity.student_deletion_steps (
 job_id uuid NOT NULL REFERENCES identity.student_deletion_jobs(job_id) ON DELETE RESTRICT,
 step_key text NOT NULL CHECK(step_key ~ '^[a-z][a-z0-9_]{0,63}$'),
 ordinal integer NOT NULL CHECK(ordinal >= 0),
 state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','completed','failed')),
 attempts integer NOT NULL DEFAULT 0 CHECK(attempts >= 0),
 error_code text CHECK(error_code IS NULL OR error_code ~ '^[A-Z][A-Z0-9_]{0,63}$'),
 completed_at timestamptz,
 PRIMARY KEY(job_id,step_key), UNIQUE(job_id,ordinal),
 CHECK((state='completed') = (completed_at IS NOT NULL)),
 CHECK(state='failed' OR error_code IS NULL)
);
CREATE INDEX student_deletion_recovery ON identity.student_deletion_jobs(state,lease_expires_at,requested_at)
 WHERE state <> 'completed';
GRANT SELECT,INSERT,UPDATE ON identity.student_deletion_jobs,identity.student_deletion_steps TO dvaia_identity_runtime;

-- Admission deactivates the subject atomically with the job. Other account
-- update routes must not restore access or promote a subject during cleanup.
CREATE FUNCTION identity.guard_student_deletion_subject()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF (NEW.is_active <> 0 OR NEW.role <> 'student' OR NEW.admin_level <> 0)
    AND EXISTS (SELECT 1 FROM identity.student_deletion_jobs WHERE subject_user_id=OLD.id) THEN
   RAISE EXCEPTION 'Account deletion is in progress' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER student_deletion_subject_guard
BEFORE UPDATE OF is_active,role,admin_level ON identity.users
FOR EACH ROW EXECUTE FUNCTION identity.guard_student_deletion_subject();
REVOKE ALL ON FUNCTION identity.guard_student_deletion_subject() FROM PUBLIC;

CREATE TABLE identity.student_deletion_run_blocks (
 owner_key text PRIMARY KEY,
 job_id uuid NOT NULL REFERENCES identity.student_deletion_jobs(job_id) ON DELETE RESTRICT
);
GRANT SELECT,INSERT ON identity.student_deletion_run_blocks TO dvaia_identity_runtime;
CREATE FUNCTION identity.guard_deleted_student_run()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM identity.student_deletion_run_blocks WHERE owner_key=NEW.owner_key) THEN
  RAISE EXCEPTION 'Agent owner is unavailable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER student_deletion_run_guard BEFORE INSERT ON graph_runtime.runs
FOR EACH ROW EXECUTE FUNCTION identity.guard_deleted_student_run();
REVOKE ALL ON FUNCTION identity.guard_deleted_student_run() FROM PUBLIC;

-- Immutable bridge from one deletion job to existing SecureShop reset cleanup
-- authority. The reset remains the source of cleanup coordinates; this table
-- only proves which reset operations belong to the deletion job.
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_constraint
   WHERE conrelid='identity.secureshop_launch_resets'::regclass
     AND conname='secureshop_launch_reset_identity_pair') THEN
  ALTER TABLE identity.secureshop_launch_resets
    ADD CONSTRAINT secureshop_launch_reset_identity_pair UNIQUE(reset_id,launch_id);
 END IF;
END $$;
CREATE TABLE identity.student_deletion_secureshop_resets (
 job_id uuid NOT NULL REFERENCES identity.student_deletion_jobs(job_id) ON DELETE RESTRICT,
 reset_id uuid NOT NULL UNIQUE,
 launch_id uuid NOT NULL REFERENCES identity.secureshop_launches(launch_id) ON DELETE RESTRICT,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(job_id,launch_id),
 FOREIGN KEY(reset_id,launch_id)
   REFERENCES identity.secureshop_launch_resets(reset_id,launch_id) ON DELETE RESTRICT
);
GRANT SELECT,INSERT ON identity.student_deletion_secureshop_resets TO dvaia_identity_runtime;
