-- PL/pgSQL resolves record fields before evaluating boolean short-circuit
-- conditions. Separate table branches before referencing table-specific fields.
CREATE OR REPLACE FUNCTION identity.reject_auxiliary_provenance_update() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_TABLE_NAME = 'email_agent_progress' THEN
    IF NEW.legacy_id IS DISTINCT FROM OLD.legacy_id THEN
      RAISE EXCEPTION 'Imported email progress provenance is immutable' USING ERRCODE='55000';
    END IF;
  ELSIF TG_TABLE_NAME = 'system_config' THEN
    IF NEW.legacy_id IS DISTINCT FROM OLD.legacy_id OR
       NEW.description IS DISTINCT FROM OLD.description OR
       NEW.source_updated_by IS DISTINCT FROM OLD.source_updated_by OR
       NEW.source_updated_at IS DISTINCT FROM OLD.source_updated_at THEN
      RAISE EXCEPTION 'Imported system configuration provenance is immutable' USING ERRCODE='55000';
    END IF;
  END IF;
  RETURN NEW;
END;
$$;
