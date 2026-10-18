-- Qualification draft; not discovered by startup migration execution.
-- Owner-wide reset is distinct from account deletion: the platform identity
-- remains active while every launch present at admission is reset or retired.
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_constraint
   WHERE conrelid='identity.secureshop_launch_resets'::regclass
     AND conname='secureshop_launch_reset_identity_pair') THEN
  ALTER TABLE identity.secureshop_launch_resets
    ADD CONSTRAINT secureshop_launch_reset_identity_pair UNIQUE(reset_id,launch_id);
 END IF;
END $$;
CREATE TABLE identity.secureshop_owner_resets (
 operation_id uuid PRIMARY KEY,
 owner_id integer NOT NULL CHECK(owner_id > 0),
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','completed')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 completed_at timestamptz,
 CHECK((status='completed')=(completed_at IS NOT NULL))
);
CREATE UNIQUE INDEX secureshop_owner_reset_pending
  ON identity.secureshop_owner_resets(owner_id) WHERE status='pending';

CREATE TABLE identity.secureshop_owner_reset_launches (
 operation_id uuid NOT NULL REFERENCES identity.secureshop_owner_resets(operation_id) ON DELETE RESTRICT,
 launch_id uuid NOT NULL REFERENCES identity.secureshop_launches(launch_id) ON DELETE RESTRICT,
 reset_id uuid NOT NULL UNIQUE,
 platform_session_id integer NOT NULL CHECK(platform_session_id > 0),
 from_generation bigint NOT NULL CHECK(from_generation >= 1),
 to_generation bigint NOT NULL CHECK(to_generation=from_generation+1),
 reactivate boolean NOT NULL,
 PRIMARY KEY(operation_id,launch_id),
 FOREIGN KEY(reset_id,launch_id)
   REFERENCES identity.secureshop_launch_resets(reset_id,launch_id) ON DELETE RESTRICT
);

CREATE FUNCTION identity.guard_secureshop_owner_reset_journal()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' OR OLD.status='completed'
   OR NEW.operation_id IS DISTINCT FROM OLD.operation_id
   OR NEW.owner_id IS DISTINCT FROM OLD.owner_id
   OR NEW.created_at IS DISTINCT FROM OLD.created_at
   OR NOT (OLD.status='pending' AND NEW.status='completed' AND NEW.completed_at IS NOT NULL) THEN
   RAISE EXCEPTION 'SecureShop owner reset journal is immutable' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER secureshop_owner_reset_journal_guard
BEFORE UPDATE OR DELETE ON identity.secureshop_owner_resets
FOR EACH ROW EXECUTE FUNCTION identity.guard_secureshop_owner_reset_journal();
CREATE FUNCTION identity.guard_secureshop_owner_reset_mapping()
RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 RAISE EXCEPTION 'SecureShop owner reset mapping is immutable' USING ERRCODE='23514';
END $$;
CREATE TRIGGER secureshop_owner_reset_mapping_guard
BEFORE UPDATE OR DELETE ON identity.secureshop_owner_reset_launches
FOR EACH ROW EXECUTE FUNCTION identity.guard_secureshop_owner_reset_mapping();

CREATE FUNCTION identity.guard_secureshop_owner_reset_admission()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE reset_owner_id integer;
BEGIN
 IF TG_OP='INSERT' THEN reset_owner_id := NEW.original_platform_owner_id;
 ELSE reset_owner_id := OLD.original_platform_owner_id;
 END IF;
 IF EXISTS(SELECT 1 FROM identity.secureshop_owner_resets r
   WHERE r.owner_id=reset_owner_id AND r.status='pending')
   AND (TG_OP='INSERT' OR (OLD.status='active' AND NEW.status='active')) THEN
   RAISE EXCEPTION 'SecureShop owner reset is in progress' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER secureshop_owner_reset_admission_guard
BEFORE INSERT OR UPDATE ON identity.secureshop_launches
FOR EACH ROW EXECUTE FUNCTION identity.guard_secureshop_owner_reset_admission();
REVOKE ALL ON FUNCTION identity.guard_secureshop_owner_reset_admission() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.guard_secureshop_owner_reset_journal() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.guard_secureshop_owner_reset_mapping() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.guard_secureshop_owner_reset_admission() TO dvaia_identity_runtime;
GRANT EXECUTE ON FUNCTION identity.guard_secureshop_owner_reset_journal(),
  identity.guard_secureshop_owner_reset_mapping() TO dvaia_identity_runtime;
GRANT SELECT,INSERT,UPDATE ON identity.secureshop_owner_resets TO dvaia_identity_runtime;
GRANT SELECT,INSERT ON identity.secureshop_owner_reset_launches TO dvaia_identity_runtime;
