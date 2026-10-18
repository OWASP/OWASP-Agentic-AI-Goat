-- Candidate only: not part of the active migration ledger.
-- Absolute expiry bounds both live records and revocation tombstones.
CREATE TABLE identity.teaching_sessions (
 session_hash text PRIMARY KEY CHECK(session_hash ~ '^[0-9a-f]{64}$'),
 owner_id integer,
 platform_session_id bigint,
 payload jsonb,
 expires_at timestamptz NOT NULL,
 revoked boolean NOT NULL DEFAULT false,
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK ((owner_id IS NULL) = (platform_session_id IS NULL)),
 CHECK (owner_id IS NULL OR owner_id > 0),
 CHECK (platform_session_id IS NULL OR platform_session_id > 0),
 CHECK ((revoked AND payload IS NULL) OR
   (NOT revoked AND owner_id IS NOT NULL AND payload IS NOT NULL AND jsonb_typeof(payload)='object'
    AND octet_length(payload::text)<=65536))
);
CREATE INDEX teaching_sessions_expiry ON identity.teaching_sessions(expires_at);
CREATE INDEX teaching_sessions_owner ON identity.teaching_sessions(owner_id) WHERE owner_id IS NOT NULL;
REVOKE ALL ON identity.teaching_sessions FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE,DELETE ON identity.teaching_sessions TO dvaia_identity_runtime;

-- Erase personal payloads during canonical deletion while retaining the bounded
-- revocation record needed to reject an already-running request's late save.
CREATE FUNCTION identity.retire_deleted_owner_teaching_sessions()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 UPDATE identity.teaching_sessions SET payload=NULL,revoked=true,owner_id=NULL,
   platform_session_id=NULL,updated_at=clock_timestamp() WHERE owner_id=OLD.id;
 IF TG_OP='UPDATE' THEN RETURN NEW; END IF;
 RETURN OLD;
END $$;
REVOKE ALL ON FUNCTION identity.retire_deleted_owner_teaching_sessions() FROM PUBLIC,dvaia_identity_runtime;
CREATE TRIGGER retire_deleted_owner_teaching_sessions BEFORE DELETE ON identity.users
FOR EACH ROW EXECUTE FUNCTION identity.retire_deleted_owner_teaching_sessions();

-- Supported account deletion retains the identity row as an inactive tombstone.
-- Administrative inactivation likewise retires cookies before reactivation.
CREATE TRIGGER retire_inactive_owner_teaching_sessions BEFORE UPDATE OF is_active ON identity.users
FOR EACH ROW WHEN (NEW.is_active=0) EXECUTE FUNCTION identity.retire_deleted_owner_teaching_sessions();
