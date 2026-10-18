-- DRAFT ONLY. Launch-bound, synthetic private inbox for the SecureShop
-- cross-persona and ACL exercises. This schema never references legacy
-- commerce resources.
CREATE TABLE secureshop_agents.persona_inbox_targets (
  target_id uuid PRIMARY KEY,
  launch_id uuid NOT NULL,
  scenario_id uuid NOT NULL,
  generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 9007199254740991),
  original_platform_owner_id integer NOT NULL CHECK (original_platform_owner_id>=1),
  original_platform_session_id integer NOT NULL CHECK (original_platform_session_id>=1),
  lifecycle text NOT NULL DEFAULT 'active' CHECK (lifecycle IN ('active','retired')),
  seed_count smallint NOT NULL CHECK (seed_count=3),
  seed_sha256 bytea NOT NULL CHECK (octet_length(seed_sha256)=32),
  current_acl_version integer NOT NULL DEFAULT 1 CHECK (current_acl_version BETWEEN 1 AND 1024),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  retired_at timestamptz,
  UNIQUE(launch_id,generation),
  CHECK ((lifecycle='retired')=(retired_at IS NOT NULL))
);

CREATE TABLE secureshop_agents.persona_inbox_messages (
  message_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  target_id uuid NOT NULL REFERENCES secureshop_agents.persona_inbox_targets(target_id) ON DELETE RESTRICT,
  fixture_key text NOT NULL CHECK (fixture_key IN ('customer-note','merchant-note','admin-note')),
  owner_shop_user_id integer NOT NULL CHECK (owner_shop_user_id>=1),
  owner_shop_role text NOT NULL CHECK (owner_shop_role IN ('customer','merchant','admin')),
  subject text NOT NULL CHECK (octet_length(subject) BETWEEN 1 AND 256),
  body text NOT NULL CHECK (octet_length(body) BETWEEN 1 AND 4096),
  body_sha256 bytea NOT NULL CHECK (octet_length(body_sha256)=32),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(target_id,fixture_key),
  UNIQUE(target_id,message_id)
);
ALTER TABLE secureshop_agents.persona_inbox_messages
  ADD FOREIGN KEY(owner_shop_user_id)
  REFERENCES secureshop_agents.bound_persona_templates(shop_user_id);

CREATE TABLE secureshop_agents.persona_inbox_acl_versions (
  target_id uuid NOT NULL REFERENCES secureshop_agents.persona_inbox_targets(target_id) ON DELETE RESTRICT,
  version integer NOT NULL CHECK (version BETWEEN 1 AND 1024),
  mode text NOT NULL CHECK (mode IN ('advisory','enforced')),
  policy_sha256 bytea NOT NULL CHECK (octet_length(policy_sha256)=32),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(target_id,version)
);

CREATE TABLE secureshop_agents.persona_inbox_access_events (
  event_id uuid PRIMARY KEY,
  operation_id uuid NOT NULL UNIQUE,
  target_id uuid NOT NULL,
  message_id bigint NOT NULL,
  caller_shop_user_id integer NOT NULL CHECK (caller_shop_user_id>=1),
  caller_shop_role text NOT NULL CHECK (caller_shop_role IN ('customer','merchant','admin')),
  resource_owner_shop_user_id integer NOT NULL CHECK (resource_owner_shop_user_id>=1),
  resource_owner_shop_role text NOT NULL CHECK (resource_owner_shop_role IN ('customer','merchant','admin')),
  acl_version integer NOT NULL CHECK (acl_version BETWEEN 1 AND 1024),
  acl_mode text NOT NULL CHECK (acl_mode IN ('advisory','enforced')),
  acl_decision text NOT NULL CHECK (acl_decision IN ('allow','deny')),
  cross_persona boolean NOT NULL,
  disclosed boolean NOT NULL,
  body_sha256 bytea CHECK (body_sha256 IS NULL OR octet_length(body_sha256)=32),
  request_sha256 bytea NOT NULL CHECK (octet_length(request_sha256)=32),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY(target_id,message_id)
    REFERENCES secureshop_agents.persona_inbox_messages(target_id,message_id) ON DELETE RESTRICT,
  FOREIGN KEY(target_id,acl_version)
    REFERENCES secureshop_agents.persona_inbox_acl_versions(target_id,version) ON DELETE RESTRICT,
  CHECK (cross_persona=(caller_shop_user_id<>resource_owner_shop_user_id)),
  CHECK ((acl_decision='deny')=cross_persona),
  CHECK (disclosed=(acl_decision='allow' OR acl_mode='advisory')),
  CHECK ((body_sha256 IS NOT NULL)=disclosed)
);

CREATE TABLE secureshop_agents.persona_inbox_cleanup_receipts (
  operation_id uuid PRIMARY KEY,
  target_id uuid NOT NULL UNIQUE REFERENCES secureshop_agents.persona_inbox_targets(target_id),
  launch_id uuid NOT NULL,
  scenario_id uuid NOT NULL,
  generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 9007199254740991),
  original_platform_owner_id integer NOT NULL CHECK (original_platform_owner_id>=1),
  original_platform_session_id integer NOT NULL CHECK (original_platform_session_id>=1),
  deleted_message_count smallint NOT NULL CHECK (deleted_message_count=3),
  deleted_acl_version_count integer NOT NULL CHECK (deleted_acl_version_count BETWEEN 1 AND 1024),
  deleted_access_event_count integer NOT NULL CHECK (deleted_access_event_count BETWEEN 0 AND 4096),
  seed_sha256 bytea NOT NULL CHECK (octet_length(seed_sha256)=32),
  receipt_sha256 bytea NOT NULL CHECK (octet_length(receipt_sha256)=32),
  completed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX persona_inbox_events_target ON secureshop_agents.persona_inbox_access_events(target_id,created_at);

CREATE FUNCTION secureshop_agents.require_active_persona_inbox_target()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE state text;
BEGIN
  SELECT lifecycle INTO state FROM secureshop_agents.persona_inbox_targets
    WHERE target_id=NEW.target_id FOR SHARE;
  IF state IS DISTINCT FROM 'active' THEN
    RAISE EXCEPTION 'Persona inbox target is not active' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER persona_inbox_message_active_guard
BEFORE INSERT ON secureshop_agents.persona_inbox_messages
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.require_active_persona_inbox_target();
CREATE TRIGGER persona_inbox_acl_active_guard
BEFORE INSERT ON secureshop_agents.persona_inbox_acl_versions
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.require_active_persona_inbox_target();

CREATE FUNCTION secureshop_agents.guard_persona_inbox_receipt()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'Persona inbox cleanup receipts are immutable' USING ERRCODE='55000';
END $$;
CREATE TRIGGER persona_inbox_cleanup_receipt_guard
BEFORE UPDATE OR DELETE ON secureshop_agents.persona_inbox_cleanup_receipts
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_persona_inbox_receipt();

CREATE FUNCTION secureshop_agents.list_persona_inbox_messages(
  requested_target uuid, requested_launch uuid, requested_scenario uuid,
  requested_generation bigint, requested_owner integer, requested_session integer)
RETURNS TABLE(message_id bigint,owner_shop_user_id integer,owner_shop_role text,subject text)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE target secureshop_agents.persona_inbox_targets%ROWTYPE;
BEGIN
  SELECT * INTO target FROM secureshop_agents.persona_inbox_targets t
    WHERE t.target_id=requested_target AND t.launch_id=requested_launch
      AND t.scenario_id=requested_scenario AND t.generation=requested_generation
      AND t.original_platform_owner_id=requested_owner
      AND t.original_platform_session_id=requested_session FOR SHARE;
  IF target.target_id IS NULL OR target.lifecycle<>'active' THEN
    RAISE EXCEPTION 'Persona inbox target is unavailable' USING ERRCODE='55000';
  END IF;
  RETURN QUERY SELECT m.message_id,m.owner_shop_user_id,m.owner_shop_role,m.subject
    FROM secureshop_agents.persona_inbox_messages m
    WHERE m.target_id=requested_target ORDER BY m.message_id;
END $$;

-- The caller supplies exact coordinates and a server-created operation UUID.
-- The database derives the ACL result and never accepts an enforcement claim.
CREATE FUNCTION secureshop_agents.read_persona_inbox_message(
  requested_target uuid, requested_launch uuid, requested_scenario uuid,
  requested_generation bigint, requested_owner integer, requested_session integer,
  requested_caller integer, requested_role text, requested_message bigint,
  requested_operation uuid, requested_request_sha256 bytea)
RETURNS TABLE(event_id uuid,message_id bigint,owner_shop_user_id integer,
  owner_shop_role text,subject text,body text,body_sha256 bytea,acl_version integer,
  acl_mode text,acl_decision text,cross_persona boolean,disclosed boolean,created_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE target secureshop_agents.persona_inbox_targets%ROWTYPE;
DECLARE message secureshop_agents.persona_inbox_messages%ROWTYPE;
DECLARE policy secureshop_agents.persona_inbox_acl_versions%ROWTYPE;
DECLARE prior secureshop_agents.persona_inbox_access_events%ROWTYPE;
DECLARE made uuid;
DECLARE is_cross boolean;
DECLARE reveal boolean;
BEGIN
  SELECT * INTO target FROM secureshop_agents.persona_inbox_targets t
    WHERE t.target_id=requested_target AND t.launch_id=requested_launch
      AND t.scenario_id=requested_scenario AND t.generation=requested_generation
      AND t.original_platform_owner_id=requested_owner
      AND t.original_platform_session_id=requested_session FOR UPDATE;
  IF target.target_id IS NULL OR target.lifecycle<>'active' THEN
    RAISE EXCEPTION 'Persona inbox target is unavailable' USING ERRCODE='55000';
  END IF;
  SELECT * INTO message FROM secureshop_agents.persona_inbox_messages m
    WHERE m.target_id=requested_target AND m.message_id=requested_message;
  SELECT * INTO policy FROM secureshop_agents.persona_inbox_acl_versions a
    WHERE a.target_id=requested_target AND a.version=target.current_acl_version;
  IF message.message_id IS NULL OR policy.version IS NULL OR requested_role NOT IN ('customer','merchant','admin')
     OR NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_persona_templates p
       WHERE p.shop_user_id=requested_caller AND p.role=requested_role)
     OR octet_length(requested_request_sha256)<>32 THEN
    RAISE EXCEPTION 'Persona inbox request is invalid' USING ERRCODE='55000';
  END IF;
  SELECT * INTO prior FROM secureshop_agents.persona_inbox_access_events e
    WHERE e.operation_id=requested_operation;
  is_cross:=requested_caller<>message.owner_shop_user_id;
  reveal:=NOT is_cross OR policy.mode='advisory';
  IF prior.event_id IS NOT NULL THEN
    IF prior.target_id<>requested_target OR prior.message_id<>requested_message
       OR prior.caller_shop_user_id<>requested_caller OR prior.caller_shop_role<>requested_role
       OR prior.acl_version<>policy.version OR prior.request_sha256<>requested_request_sha256 THEN
      RAISE EXCEPTION 'Persona inbox operation conflicts' USING ERRCODE='55000';
    END IF;
    made:=prior.event_id;
  ELSE
    IF (SELECT count(*) FROM secureshop_agents.persona_inbox_access_events e
        WHERE e.target_id=requested_target)>=4096 THEN
      RAISE EXCEPTION 'Persona inbox access capacity is exhausted' USING ERRCODE='54000';
    END IF;
    made:=requested_operation;
    INSERT INTO secureshop_agents.persona_inbox_access_events
      (event_id,operation_id,target_id,message_id,caller_shop_user_id,caller_shop_role,
       resource_owner_shop_user_id,resource_owner_shop_role,acl_version,acl_mode,
       acl_decision,cross_persona,disclosed,body_sha256,request_sha256)
    VALUES(made,requested_operation,requested_target,requested_message,requested_caller,requested_role,
      message.owner_shop_user_id,message.owner_shop_role,policy.version,policy.mode,
      CASE WHEN is_cross THEN 'deny' ELSE 'allow' END,is_cross,reveal,
      CASE WHEN reveal THEN message.body_sha256 ELSE NULL END,requested_request_sha256);
  END IF;
  SELECT * INTO prior FROM secureshop_agents.persona_inbox_access_events e WHERE e.event_id=made;
  RETURN QUERY SELECT made,message.message_id,message.owner_shop_user_id,message.owner_shop_role,
    message.subject,CASE WHEN reveal THEN message.body ELSE NULL END,
    CASE WHEN reveal THEN message.body_sha256 ELSE NULL END,policy.version,policy.mode,
    CASE WHEN is_cross THEN 'deny' ELSE 'allow' END,is_cross,reveal,prior.created_at;
END $$;

CREATE FUNCTION secureshop_agents.advance_persona_inbox_acl(
  requested_target uuid,requested_launch uuid,requested_scenario uuid,
  requested_generation bigint,requested_owner integer,requested_session integer,
  expected_version integer,next_mode text,next_policy_sha256 bytea)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE target secureshop_agents.persona_inbox_targets%ROWTYPE;
DECLARE next_version integer;
BEGIN
  SELECT * INTO target FROM secureshop_agents.persona_inbox_targets t
    WHERE t.target_id=requested_target AND t.launch_id=requested_launch
      AND t.scenario_id=requested_scenario AND t.generation=requested_generation
      AND t.original_platform_owner_id=requested_owner
      AND t.original_platform_session_id=requested_session FOR UPDATE;
  IF target.target_id IS NULL OR target.lifecycle<>'active'
     OR target.current_acl_version<>expected_version OR next_mode<>'enforced'
     OR octet_length(next_policy_sha256)<>32 THEN
    RAISE EXCEPTION 'Persona inbox ACL transition is invalid' USING ERRCODE='55000';
  END IF;
  IF NOT EXISTS(SELECT 1 FROM secureshop_agents.persona_inbox_acl_versions a
      WHERE a.target_id=requested_target AND a.version=expected_version AND a.mode='advisory') THEN
    RAISE EXCEPTION 'Persona inbox ACL is already enforced' USING ERRCODE='55000';
  END IF;
  next_version:=expected_version+1;
  INSERT INTO secureshop_agents.persona_inbox_acl_versions(target_id,version,mode,policy_sha256)
    VALUES(requested_target,next_version,next_mode,next_policy_sha256);
  UPDATE secureshop_agents.persona_inbox_targets SET current_acl_version=next_version
    WHERE target_id=requested_target;
  RETURN next_version;
END $$;

-- Retirement is the only payload deletion path. The target tombstone and
-- bounded receipt remain immutable for replay verification.
CREATE FUNCTION secureshop_agents.retire_persona_inbox_target(
  requested_operation uuid,requested_target uuid,requested_launch uuid,
  requested_scenario uuid,requested_generation bigint,requested_owner integer,
  requested_session integer)
RETURNS SETOF secureshop_agents.persona_inbox_cleanup_receipts
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE target secureshop_agents.persona_inbox_targets%ROWTYPE;
DECLARE prior secureshop_agents.persona_inbox_cleanup_receipts%ROWTYPE;
DECLARE operation_prior secureshop_agents.persona_inbox_cleanup_receipts%ROWTYPE;
DECLARE messages integer; DECLARE policies integer; DECLARE events integer;
BEGIN
  SELECT * INTO target FROM secureshop_agents.persona_inbox_targets t
    WHERE t.target_id=requested_target AND t.launch_id=requested_launch
      AND t.scenario_id=requested_scenario AND t.generation=requested_generation
      AND t.original_platform_owner_id=requested_owner
      AND t.original_platform_session_id=requested_session FOR UPDATE;
  IF target.target_id IS NULL THEN RAISE EXCEPTION 'Persona inbox target is unavailable'; END IF;
  SELECT * INTO operation_prior FROM secureshop_agents.persona_inbox_cleanup_receipts r
    WHERE r.operation_id=requested_operation;
  SELECT * INTO prior FROM secureshop_agents.persona_inbox_cleanup_receipts r
    WHERE r.target_id=requested_target;
  IF operation_prior.operation_id IS NOT NULL OR prior.operation_id IS NOT NULL THEN
    IF operation_prior.operation_id IS NULL OR prior.operation_id IS NULL
       OR operation_prior.target_id<>prior.target_id
       OR prior.operation_id<>requested_operation OR prior.target_id<>requested_target
       OR prior.launch_id<>requested_launch OR prior.scenario_id<>requested_scenario
       OR prior.generation<>requested_generation
       OR prior.original_platform_owner_id<>requested_owner
       OR prior.original_platform_session_id<>requested_session
       OR target.lifecycle<>'retired'
       OR EXISTS(SELECT 1 FROM secureshop_agents.persona_inbox_messages WHERE target_id=requested_target)
       OR EXISTS(SELECT 1 FROM secureshop_agents.persona_inbox_acl_versions WHERE target_id=requested_target)
       OR EXISTS(SELECT 1 FROM secureshop_agents.persona_inbox_access_events WHERE target_id=requested_target)
       OR prior.seed_sha256<>target.seed_sha256 OR prior.receipt_sha256<>
          sha256(convert_to(concat_ws(chr(31),'persona-inbox-cleanup-v1',prior.operation_id::text,
            prior.target_id::text,prior.launch_id::text,prior.scenario_id::text,prior.generation::text,
            prior.original_platform_owner_id::text,prior.original_platform_session_id::text,
            prior.deleted_message_count::text,prior.deleted_acl_version_count::text,
            prior.deleted_access_event_count::text,encode(prior.seed_sha256,'hex')),'UTF8'))
       OR operation_prior.receipt_sha256<>prior.receipt_sha256 THEN
      RAISE EXCEPTION 'Persona inbox cleanup replay mismatch';
    END IF;
    RETURN NEXT prior; RETURN;
  END IF;
  IF target.lifecycle<>'active' THEN
    RAISE EXCEPTION 'Persona inbox cleanup is invalid';
  END IF;
  SELECT count(*) INTO messages FROM secureshop_agents.persona_inbox_messages WHERE target_id=requested_target;
  SELECT count(*) INTO policies FROM secureshop_agents.persona_inbox_acl_versions WHERE target_id=requested_target;
  SELECT count(*) INTO events FROM secureshop_agents.persona_inbox_access_events WHERE target_id=requested_target;
  IF messages<>target.seed_count OR policies<1 OR policies>1024 OR events>4096 THEN
    RAISE EXCEPTION 'Persona inbox cleanup counts are invalid';
  END IF;
  DELETE FROM secureshop_agents.persona_inbox_access_events WHERE target_id=requested_target;
  DELETE FROM secureshop_agents.persona_inbox_acl_versions WHERE target_id=requested_target;
  DELETE FROM secureshop_agents.persona_inbox_messages WHERE target_id=requested_target;
  UPDATE secureshop_agents.persona_inbox_targets
    SET lifecycle='retired',retired_at=clock_timestamp() WHERE target_id=requested_target;
  INSERT INTO secureshop_agents.persona_inbox_cleanup_receipts
    (operation_id,target_id,launch_id,scenario_id,generation,original_platform_owner_id,
     original_platform_session_id,deleted_message_count,deleted_acl_version_count,
     deleted_access_event_count,seed_sha256,receipt_sha256)
  VALUES(requested_operation,requested_target,requested_launch,requested_scenario,requested_generation,
    requested_owner,requested_session,messages,policies,events,target.seed_sha256,
    sha256(convert_to(concat_ws(chr(31),'persona-inbox-cleanup-v1',requested_operation::text,
      requested_target::text,requested_launch::text,requested_scenario::text,requested_generation::text,
      requested_owner::text,requested_session::text,messages::text,policies::text,events::text,
      encode(target.seed_sha256,'hex')),'UTF8')))
  RETURNING * INTO prior;
  RETURN NEXT prior;
END $$;

REVOKE ALL ON TABLE secureshop_agents.persona_inbox_targets,
  secureshop_agents.persona_inbox_messages,secureshop_agents.persona_inbox_acl_versions,
  secureshop_agents.persona_inbox_access_events,secureshop_agents.persona_inbox_cleanup_receipts FROM PUBLIC;
REVOKE ALL ON FUNCTION secureshop_agents.list_persona_inbox_messages(uuid,uuid,uuid,bigint,integer,integer),
  secureshop_agents.read_persona_inbox_message(uuid,uuid,uuid,bigint,integer,integer,integer,text,bigint,uuid,bytea),
  secureshop_agents.advance_persona_inbox_acl(uuid,uuid,uuid,bigint,integer,integer,integer,text,bytea),
  secureshop_agents.retire_persona_inbox_target(uuid,uuid,uuid,uuid,bigint,integer,integer) FROM PUBLIC;
REVOKE ALL ON FUNCTION secureshop_agents.require_active_persona_inbox_target(),
  secureshop_agents.guard_persona_inbox_receipt() FROM PUBLIC;
GRANT SELECT,INSERT ON secureshop_agents.persona_inbox_targets,
  secureshop_agents.persona_inbox_messages,secureshop_agents.persona_inbox_acl_versions
  TO dvaia_secureshop_agents_runtime;
GRANT SELECT ON secureshop_agents.persona_inbox_access_events,
  secureshop_agents.persona_inbox_cleanup_receipts TO dvaia_secureshop_agents_runtime;
GRANT USAGE,SELECT ON SEQUENCE secureshop_agents.persona_inbox_messages_message_id_seq
  TO dvaia_secureshop_agents_runtime;
GRANT EXECUTE ON FUNCTION secureshop_agents.list_persona_inbox_messages(uuid,uuid,uuid,bigint,integer,integer),
  secureshop_agents.read_persona_inbox_message(uuid,uuid,uuid,bigint,integer,integer,integer,text,bigint,uuid,bytea),
  secureshop_agents.advance_persona_inbox_acl(uuid,uuid,uuid,bigint,integer,integer,integer,text,bytea),
  secureshop_agents.retire_persona_inbox_target(uuid,uuid,uuid,uuid,bigint,integer,integer)
  TO dvaia_secureshop_agents_runtime;
GRANT EXECUTE ON FUNCTION secureshop_agents.require_active_persona_inbox_target(),
  secureshop_agents.guard_persona_inbox_receipt() TO dvaia_secureshop_agents_runtime;
