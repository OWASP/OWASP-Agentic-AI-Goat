-- Preserve the three immutable demonstration templates while admitting distinct,
-- owner-bound standalone shop principals. Authentication secrets stay in identity.
CREATE TABLE secureshop_agents.bound_actor_identities (
  shop_user_id integer PRIMARY KEY CHECK (shop_user_id > 0),
  username text NOT NULL CHECK (octet_length(username) BETWEEN 1 AND 256),
  email text NOT NULL CHECK (octet_length(email) BETWEEN 1 AND 512),
  base_role text NOT NULL CHECK (base_role IN ('customer','merchant','admin')),
  principal_id uuid UNIQUE,
  original_platform_owner_id integer,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (shop_user_id,username),
  CHECK ((principal_id IS NULL AND original_platform_owner_id IS NULL AND shop_user_id < 1000000000)
      OR (principal_id IS NOT NULL AND original_platform_owner_id > 0
          AND shop_user_id >= 1000000000))
);

INSERT INTO secureshop_agents.bound_actor_identities
  (shop_user_id,username,email,base_role)
SELECT shop_user_id,username,email,role
FROM secureshop_agents.bound_persona_templates;

CREATE FUNCTION secureshop_agents.record_bound_template_actor() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
BEGIN
  INSERT INTO secureshop_agents.bound_actor_identities
    (shop_user_id,username,email,base_role)
  VALUES (NEW.shop_user_id,NEW.username,NEW.email,NEW.role);
  RETURN NEW;
END $$;
CREATE TRIGGER bound_template_actor_insert
AFTER INSERT ON secureshop_agents.bound_persona_templates
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.record_bound_template_actor();

CREATE FUNCTION secureshop_agents.guard_bound_actor_identity() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
BEGIN
  IF TG_OP <> 'INSERT' THEN
    RAISE EXCEPTION 'Shop actor identity is immutable' USING ERRCODE='55000';
  END IF;
  IF NEW.principal_id IS NULL THEN
    IF NOT EXISTS (SELECT 1 FROM secureshop_agents.bound_persona_templates t
      WHERE t.shop_user_id=NEW.shop_user_id AND t.username=NEW.username
        AND t.email=NEW.email AND t.role=NEW.base_role) THEN
      RAISE EXCEPTION 'Unknown demonstration actor' USING ERRCODE='55000';
    END IF;
  ELSIF NEW.shop_user_id < 1000000000 OR NEW.original_platform_owner_id IS NULL THEN
    RAISE EXCEPTION 'Registered shop actor is invalid' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER bound_actor_identity_guard
BEFORE INSERT OR UPDATE OR DELETE ON secureshop_agents.bound_actor_identities
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_actor_identity();

-- Every preexisting reference remains valid because its template actor was copied
-- above. No historical session, credential, mail, or lesson row is rewritten.
DO $$
DECLARE entry record;
BEGIN
  FOR entry IN SELECT c.conrelid::regclass AS table_name,c.conname
    FROM pg_constraint c
    WHERE c.contype='f'
      AND c.confrelid='secureshop_agents.bound_persona_templates'::regclass
      AND c.conrelid IN (
        'secureshop_agents.bound_persona_sessions'::regclass,
        'secureshop_agents.bound_persona_credentials'::regclass,
        'secureshop_agents.bound_persona_state'::regclass,
        'secureshop_agents.bound_persona_api_keys'::regclass,
        'secureshop_agents.persona_inbox_messages'::regclass,
        'secureshop_agents.lab_mail_messages'::regclass,
        'secureshop_agents.lab_mail_operation_receipts'::regclass)
  LOOP
    EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I',entry.table_name,entry.conname);
  END LOOP;
END $$;
ALTER TABLE secureshop_agents.bound_persona_sessions
  ADD CONSTRAINT bound_persona_session_actor_identity FOREIGN KEY (shop_user_id,username)
  REFERENCES secureshop_agents.bound_actor_identities(shop_user_id,username);
ALTER TABLE secureshop_agents.bound_persona_sessions
  ADD COLUMN standalone_principal_id uuid,
  ADD COLUMN standalone_session_id integer,
  ADD COLUMN bootstrap_jti uuid,
  ADD COLUMN standalone_credential_version bigint,
  ADD COLUMN standalone_authority_version bigint,
  ADD COLUMN bootstrap_persona_authority_version bigint,
  ADD CONSTRAINT bound_standalone_bootstrap_complete CHECK (
    (standalone_principal_id IS NULL AND standalone_session_id IS NULL
      AND bootstrap_jti IS NULL AND standalone_credential_version IS NULL
      AND standalone_authority_version IS NULL AND bootstrap_persona_authority_version IS NULL)
    OR (standalone_principal_id IS NOT NULL AND standalone_session_id > 0
      AND bootstrap_jti IS NOT NULL AND standalone_credential_version > 0
      AND standalone_authority_version > 0 AND bootstrap_persona_authority_version > 0
      AND shop_user_id >= 1000000000));
CREATE UNIQUE INDEX bound_standalone_active_bootstrap
ON secureshop_agents.bound_persona_sessions
  (platform_launch_id,platform_launch_generation,original_platform_owner_id,
   original_platform_session_id,standalone_principal_id,standalone_session_id,
   standalone_credential_version,standalone_authority_version,
   bootstrap_persona_authority_version)
WHERE bootstrap_jti IS NOT NULL AND revoked_at IS NULL;
CREATE FUNCTION secureshop_agents.guard_bound_standalone_bootstrap() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
BEGIN
  IF (NEW.standalone_principal_id,NEW.standalone_session_id,NEW.bootstrap_jti,
      NEW.standalone_credential_version,NEW.standalone_authority_version,
      NEW.bootstrap_persona_authority_version) IS DISTINCT FROM
     (OLD.standalone_principal_id,OLD.standalone_session_id,OLD.bootstrap_jti,
      OLD.standalone_credential_version,OLD.standalone_authority_version,
      OLD.bootstrap_persona_authority_version) THEN
    RAISE EXCEPTION 'Standalone bootstrap identity is immutable' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER bound_standalone_bootstrap_immutable
BEFORE UPDATE ON secureshop_agents.bound_persona_sessions
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_standalone_bootstrap();
ALTER TABLE secureshop_agents.bound_persona_credentials
  ADD CONSTRAINT bound_persona_credential_actor_identity FOREIGN KEY (shop_user_id)
  REFERENCES secureshop_agents.bound_actor_identities(shop_user_id);
ALTER TABLE secureshop_agents.bound_persona_state
  ADD CONSTRAINT bound_persona_state_actor_identity FOREIGN KEY (shop_user_id)
  REFERENCES secureshop_agents.bound_actor_identities(shop_user_id);
ALTER TABLE secureshop_agents.bound_persona_api_keys
  ADD CONSTRAINT bound_persona_api_key_actor_identity FOREIGN KEY (shop_user_id)
  REFERENCES secureshop_agents.bound_actor_identities(shop_user_id);
ALTER TABLE secureshop_agents.persona_inbox_messages
  ADD CONSTRAINT persona_inbox_message_actor_identity FOREIGN KEY (owner_shop_user_id)
  REFERENCES secureshop_agents.bound_actor_identities(shop_user_id);
ALTER TABLE secureshop_agents.lab_mail_messages
  ADD CONSTRAINT lab_mail_sender_actor_identity FOREIGN KEY (sender_id)
  REFERENCES secureshop_agents.bound_actor_identities(shop_user_id),
  ADD CONSTRAINT lab_mail_recipient_actor_identity FOREIGN KEY (recipient_id)
  REFERENCES secureshop_agents.bound_actor_identities(shop_user_id);
ALTER TABLE secureshop_agents.lab_mail_operation_receipts
  ADD CONSTRAINT lab_mail_caller_actor_identity FOREIGN KEY (caller_id)
  REFERENCES secureshop_agents.bound_actor_identities(shop_user_id);

CREATE FUNCTION secureshop_agents.assert_bound_actor_owner() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE actor_owner integer; actor_id integer;
BEGIN
  actor_id := (to_jsonb(NEW)->>TG_ARGV[0])::integer;
  SELECT original_platform_owner_id INTO actor_owner
  FROM secureshop_agents.bound_actor_identities WHERE shop_user_id=actor_id;
  IF NOT FOUND OR (actor_owner IS NOT NULL
      AND actor_owner <> NEW.original_platform_owner_id) THEN
    RAISE EXCEPTION 'Shop actor owner mismatch' USING ERRCODE='42501';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER bound_session_actor_owner BEFORE INSERT ON secureshop_agents.bound_persona_sessions
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.assert_bound_actor_owner('shop_user_id');
CREATE TRIGGER bound_credential_actor_owner BEFORE INSERT OR UPDATE ON secureshop_agents.bound_persona_credentials
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.assert_bound_actor_owner('shop_user_id');
CREATE TRIGGER bound_state_actor_owner BEFORE INSERT OR UPDATE ON secureshop_agents.bound_persona_state
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.assert_bound_actor_owner('shop_user_id');
CREATE TRIGGER bound_api_key_actor_owner BEFORE INSERT OR UPDATE ON secureshop_agents.bound_persona_api_keys
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.assert_bound_actor_owner('shop_user_id');

CREATE FUNCTION secureshop_agents.assert_target_bound_actor_owner() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE target_owner integer; actor_owner integer; actor_id integer; column_name text;
BEGIN
  SELECT original_platform_owner_id INTO target_owner
  FROM secureshop_agents.persona_inbox_targets WHERE target_id=NEW.target_id;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'Shop target unavailable' USING ERRCODE='42501';
  END IF;
  FOREACH column_name IN ARRAY TG_ARGV LOOP
    actor_id := (to_jsonb(NEW)->>column_name)::integer;
    SELECT original_platform_owner_id INTO actor_owner
    FROM secureshop_agents.bound_actor_identities WHERE shop_user_id=actor_id;
    IF NOT FOUND OR (actor_owner IS NOT NULL AND actor_owner<>target_owner) THEN
      RAISE EXCEPTION 'Shop actor target owner mismatch' USING ERRCODE='42501';
    END IF;
  END LOOP;
  RETURN NEW;
END $$;
CREATE TRIGGER persona_inbox_message_actor_owner
BEFORE INSERT ON secureshop_agents.persona_inbox_messages
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.assert_target_bound_actor_owner('owner_shop_user_id');
CREATE TRIGGER lab_mail_message_actor_owner
BEFORE INSERT ON secureshop_agents.lab_mail_messages
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.assert_target_bound_actor_owner('sender_id','recipient_id');
CREATE TRIGGER lab_mail_operation_actor_owner
BEFORE INSERT ON secureshop_agents.lab_mail_operation_receipts
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.assert_target_bound_actor_owner('caller_id');

-- The older effective-session trigger read only the three template rows.
-- Keep its role/version/ban checks while resolving both kinds of actor.
CREATE OR REPLACE FUNCTION secureshop_agents.guard_bound_persona_effective_session() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE effective text; banned timestamptz;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||NEW.original_platform_owner_id::text,0));
  PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-conversation-admission:'||NEW.platform_launch_id::text,0));
  SELECT COALESCE(st.effective_role,a.base_role),st.banned_at INTO effective,banned
  FROM secureshop_agents.bound_actor_identities a
  LEFT JOIN secureshop_agents.bound_persona_state st
    ON st.platform_launch_id=NEW.platform_launch_id
    AND st.platform_scenario_id=NEW.platform_scenario_id
    AND st.platform_launch_generation=NEW.platform_launch_generation
    AND st.original_platform_owner_id=NEW.original_platform_owner_id
    AND st.original_platform_session_id=NEW.original_platform_session_id
    AND st.shop_user_id=a.shop_user_id
  WHERE a.shop_user_id=NEW.shop_user_id AND a.username=NEW.username
    AND (a.original_platform_owner_id IS NULL
      OR a.original_platform_owner_id=NEW.original_platform_owner_id);
  IF effective IS NULL OR effective<>NEW.role OR banned IS NOT NULL
    OR EXISTS(SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts
      WHERE original_platform_owner_id=NEW.original_platform_owner_id) THEN
    RAISE EXCEPTION 'Effective persona authority unavailable' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;

REVOKE ALL ON TABLE secureshop_agents.bound_actor_identities FROM PUBLIC;
GRANT SELECT,INSERT ON secureshop_agents.bound_actor_identities TO dvaia_secureshop_agents_runtime;
REVOKE ALL ON FUNCTION secureshop_agents.record_bound_template_actor(),
  secureshop_agents.guard_bound_actor_identity(),
  secureshop_agents.assert_bound_actor_owner(),
  secureshop_agents.assert_target_bound_actor_owner(),
  secureshop_agents.guard_bound_standalone_bootstrap() FROM PUBLIC;
