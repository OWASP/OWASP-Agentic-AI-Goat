CREATE TABLE identity.legacy_upload_intents (
 intent_id uuid PRIMARY KEY,
 owner_id integer NOT NULL REFERENCES identity.users(id) ON DELETE RESTRICT,
 session_id bigint NOT NULL,
 state text NOT NULL DEFAULT 'admitted' CHECK(state IN ('admitted','published','retired')),
 file_path text CHECK(file_path IS NULL OR length(file_path) BETWEEN 1 AND 4096),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 published_at timestamptz,
 retired_at timestamptz,
 CHECK(state<>'admitted' OR published_at IS NULL),
 CHECK(state<>'published' OR published_at IS NOT NULL),
 CHECK((state='retired')=(retired_at IS NOT NULL))
);
CREATE INDEX legacy_upload_intents_owner ON identity.legacy_upload_intents(owner_id,state,intent_id);
REVOKE ALL ON identity.legacy_upload_intents FROM PUBLIC,dvaia_identity_runtime;

CREATE FUNCTION identity.assert_legacy_platform_mutation(requested_owner integer,requested_session bigint)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE account identity.users%ROWTYPE; session identity.user_sessions%ROWTYPE;
BEGIN
 IF requested_owner IS NULL OR requested_session IS NULL THEN RAISE EXCEPTION 'Complete legacy mutation authority required'; END IF;
 SELECT * INTO account FROM identity.users WHERE id=requested_owner FOR SHARE;
 SELECT * INTO session FROM identity.user_sessions WHERE id=requested_session AND user_id=requested_owner FOR SHARE;
 IF account.id IS NULL OR account.is_active<>1 OR account.role NOT IN ('student','admin','super_admin')
   OR (account.account_locked_until IS NOT NULL AND account.account_locked_until>clock_timestamp())
   OR session.id IS NULL OR session.is_active<>1 OR session.expires_at<=clock_timestamp()
   OR EXISTS(SELECT 1 FROM identity.student_deletion_jobs WHERE subject_user_id=requested_owner)
 THEN RAISE EXCEPTION 'Legacy mutation authority unavailable' USING ERRCODE='55000'; END IF;
END $$;

CREATE FUNCTION identity.admit_legacy_upload(requested_intent uuid,requested_owner integer,requested_session bigint)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE account identity.users%ROWTYPE; session identity.user_sessions%ROWTYPE;
BEGIN
 IF requested_intent IS NULL OR requested_owner IS NULL OR requested_session IS NULL THEN RAISE EXCEPTION 'Complete upload authority required'; END IF;
 SELECT * INTO account FROM identity.users WHERE id=requested_owner FOR SHARE;
 SELECT * INTO session FROM identity.user_sessions WHERE id=requested_session AND user_id=requested_owner FOR SHARE;
 IF account.id IS NULL OR account.is_active<>1 OR account.role NOT IN ('student','admin','super_admin')
   OR (account.account_locked_until IS NOT NULL AND account.account_locked_until>clock_timestamp())
   OR session.id IS NULL OR session.is_active<>1 OR session.expires_at<=clock_timestamp()
   OR EXISTS(SELECT 1 FROM identity.student_deletion_jobs WHERE subject_user_id=requested_owner) THEN
  RAISE EXCEPTION 'Upload authority unavailable' USING ERRCODE='55000';
 END IF;
 INSERT INTO identity.legacy_upload_intents(intent_id,owner_id,session_id)
 VALUES(requested_intent,requested_owner,requested_session);
END $$;

CREATE FUNCTION identity.bind_legacy_upload_path(requested_intent uuid,requested_owner integer,requested_path text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF requested_path IS NULL OR length(requested_path) NOT BETWEEN 1 AND 4096 THEN RAISE EXCEPTION 'Valid upload path required'; END IF;
 UPDATE identity.legacy_upload_intents SET file_path=requested_path
 WHERE intent_id=requested_intent AND owner_id=requested_owner AND state='admitted' AND file_path IS NULL;
 IF NOT FOUND THEN RAISE EXCEPTION 'Upload intent unavailable' USING ERRCODE='55000'; END IF;
END $$;

CREATE FUNCTION identity.publish_legacy_upload(requested_intent uuid,requested_owner integer)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 UPDATE identity.legacy_upload_intents SET state='published',published_at=clock_timestamp()
 WHERE intent_id=requested_intent AND owner_id=requested_owner AND state='admitted' AND file_path IS NOT NULL;
 IF NOT FOUND THEN RAISE EXCEPTION 'Upload intent unavailable' USING ERRCODE='55000'; END IF;
END $$;

CREATE FUNCTION identity.read_legacy_upload_intent(requested_intent uuid,requested_owner integer)
RETURNS TABLE(file_path text,state text) LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT i.file_path,i.state FROM identity.legacy_upload_intents i
 WHERE i.intent_id=requested_intent AND i.owner_id=requested_owner
$$;
CREATE FUNCTION identity.list_legacy_upload_cleanup(requested_owner integer)
RETURNS TABLE(intent_id uuid,file_path text,state text) LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT i.intent_id,i.file_path,i.state FROM identity.legacy_upload_intents i
 WHERE i.owner_id=requested_owner AND i.state<>'retired' ORDER BY i.intent_id
$$;
CREATE FUNCTION identity.retire_legacy_upload(requested_intent uuid,requested_owner integer)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 UPDATE identity.legacy_upload_intents SET state='retired',file_path=NULL,retired_at=clock_timestamp()
 WHERE intent_id=requested_intent AND owner_id=requested_owner AND state<>'retired';
 IF NOT FOUND AND NOT EXISTS(SELECT 1 FROM identity.legacy_upload_intents WHERE intent_id=requested_intent AND owner_id=requested_owner AND state='retired')
 THEN RAISE EXCEPTION 'Upload intent unavailable' USING ERRCODE='55000'; END IF;
END $$;
CREATE FUNCTION identity.retire_legacy_uploads(requested_owner integer)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE changed integer;
BEGIN
 UPDATE identity.legacy_upload_intents SET state='retired',file_path=NULL,retired_at=clock_timestamp()
 WHERE owner_id=requested_owner AND state<>'retired';GET DIAGNOSTICS changed=ROW_COUNT;RETURN changed;
END $$;

CREATE FUNCTION identity.guard_student_deletion_upload_retirement()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM identity.student_deletion_jobs WHERE subject_user_id=OLD.id)
   AND EXISTS(SELECT 1 FROM identity.legacy_upload_intents WHERE owner_id=OLD.id AND state<>'retired') THEN
  RAISE EXCEPTION 'Legacy upload cleanup is incomplete' USING ERRCODE='55000';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER student_deletion_upload_retirement
BEFORE UPDATE OF username,email ON identity.users FOR EACH ROW
EXECUTE FUNCTION identity.guard_student_deletion_upload_retirement();

REVOKE ALL ON FUNCTION identity.admit_legacy_upload(uuid,integer,bigint),
 identity.bind_legacy_upload_path(uuid,integer,text),identity.publish_legacy_upload(uuid,integer),
 identity.read_legacy_upload_intent(uuid,integer),identity.list_legacy_upload_cleanup(integer),
 identity.retire_legacy_upload(uuid,integer),identity.retire_legacy_uploads(integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.guard_student_deletion_upload_retirement() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.assert_legacy_platform_mutation(integer,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.admit_legacy_upload(uuid,integer,bigint),
 identity.bind_legacy_upload_path(uuid,integer,text),identity.publish_legacy_upload(uuid,integer),
 identity.read_legacy_upload_intent(uuid,integer),identity.list_legacy_upload_cleanup(integer),
 identity.retire_legacy_upload(uuid,integer),identity.retire_legacy_uploads(integer) TO dvaia_identity_runtime;
GRANT EXECUTE ON FUNCTION identity.assert_legacy_platform_mutation(integer,bigint) TO dvaia_identity_runtime;
