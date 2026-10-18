ALTER TABLE identity.email_agent_progress
  ADD COLUMN legacy_id integer,
  ADD CONSTRAINT email_agent_progress_legacy_id_unique UNIQUE (legacy_id),
  ADD CONSTRAINT email_agent_progress_legacy_id_positive CHECK (legacy_id IS NULL OR legacy_id > 0);

ALTER TABLE identity.system_config
  ADD COLUMN legacy_id integer,
  ADD COLUMN description text,
  -- Historical actor IDs deliberately have no live FK: deleting a current user
  -- must not erase who changed the archived configuration.
  ADD COLUMN source_updated_by integer CHECK (source_updated_by IS NULL OR source_updated_by > 0),
  ADD COLUMN source_updated_at timestamptz,
  ADD CONSTRAINT system_config_legacy_id_unique UNIQUE (legacy_id),
  ADD CONSTRAINT system_config_legacy_id_positive CHECK (legacy_id IS NULL OR legacy_id > 0);

CREATE FUNCTION identity.reject_auxiliary_provenance_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_TABLE_NAME = 'email_agent_progress' AND NEW.legacy_id IS DISTINCT FROM OLD.legacy_id THEN
    RAISE EXCEPTION 'Imported email progress provenance is immutable' USING ERRCODE='55000';
  END IF;
  IF TG_TABLE_NAME = 'system_config' AND (
    NEW.legacy_id IS DISTINCT FROM OLD.legacy_id OR
    NEW.description IS DISTINCT FROM OLD.description OR
    NEW.source_updated_by IS DISTINCT FROM OLD.source_updated_by OR
    NEW.source_updated_at IS DISTINCT FROM OLD.source_updated_at
  ) THEN
    RAISE EXCEPTION 'Imported system configuration provenance is immutable' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END;
$$;
CREATE TRIGGER email_agent_progress_provenance_immutable BEFORE UPDATE ON identity.email_agent_progress
  FOR EACH ROW EXECUTE FUNCTION identity.reject_auxiliary_provenance_update();
CREATE TRIGGER system_config_provenance_immutable BEFORE UPDATE ON identity.system_config
  FOR EACH ROW EXECUTE FUNCTION identity.reject_auxiliary_provenance_update();
REVOKE ALL ON FUNCTION identity.reject_auxiliary_provenance_update() FROM PUBLIC;

-- Imported provenance is written by the migration role. Application runtime
-- queries retain access only to fields that represent current mutable state.
REVOKE INSERT, UPDATE ON identity.email_agent_progress FROM dvaia_identity_runtime;
GRANT INSERT (user_key, objective_number, completed, user_email, completed_at, created_at, updated_at)
  ON identity.email_agent_progress TO dvaia_identity_runtime;
GRANT UPDATE (completed, user_email, completed_at, updated_at)
  ON identity.email_agent_progress TO dvaia_identity_runtime;

REVOKE INSERT, UPDATE ON identity.system_config FROM dvaia_identity_runtime;
GRANT INSERT (config_key, config_value, config_type, is_public)
  ON identity.system_config TO dvaia_identity_runtime;
GRANT UPDATE (config_value, config_type, is_public)
  ON identity.system_config TO dvaia_identity_runtime;
