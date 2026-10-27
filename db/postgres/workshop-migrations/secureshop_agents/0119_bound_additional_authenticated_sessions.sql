-- Existing rows remain canonical; no identity/session data is rewritten.
ALTER TABLE secureshop_agents.bound_persona_sessions
 ADD COLUMN additional_session boolean NOT NULL DEFAULT false,
 ADD CONSTRAINT bound_additional_requires_bootstrap CHECK (NOT additional_session OR bootstrap_jti IS NOT NULL);
DROP INDEX secureshop_agents.bound_standalone_active_bootstrap;
CREATE UNIQUE INDEX bound_standalone_active_bootstrap
 ON secureshop_agents.bound_persona_sessions
 (platform_launch_id,platform_launch_generation,original_platform_owner_id,
 original_platform_session_id,standalone_principal_id,standalone_session_id,
 standalone_credential_version,standalone_authority_version,bootstrap_persona_authority_version)
 WHERE bootstrap_jti IS NOT NULL AND revoked_at IS NULL AND NOT additional_session;
CREATE FUNCTION secureshop_agents.guard_additional_session_kind() RETURNS trigger
 LANGUAGE plpgsql SET search_path=pg_catalog,secureshop_agents AS $$
 BEGIN
 IF NEW.additional_session IS DISTINCT FROM OLD.additional_session THEN
 RAISE EXCEPTION 'Session issuance kind is immutable' USING ERRCODE='55000';
 END IF;
 RETURN NEW;
 END $$;
REVOKE ALL ON FUNCTION secureshop_agents.guard_additional_session_kind() FROM PUBLIC;
CREATE TRIGGER bound_additional_session_kind_immutable BEFORE UPDATE
 ON secureshop_agents.bound_persona_sessions FOR EACH ROW
 EXECUTE FUNCTION secureshop_agents.guard_additional_session_kind();
