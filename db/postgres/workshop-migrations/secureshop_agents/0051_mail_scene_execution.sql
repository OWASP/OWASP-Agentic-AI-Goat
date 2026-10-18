-- Mirror the identity-owned mail scene selection into the agents store. The
-- immutable inbox target keeps its original birth coordinates; each live
-- launch receives a separate grant for current execution.
CREATE TABLE secureshop_agents.mail_scene_targets (
 scene_id uuid PRIMARY KEY,
 scene_generation bigint NOT NULL CHECK(scene_generation>0),
 target_id uuid NOT NULL UNIQUE REFERENCES secureshop_agents.persona_inbox_targets(target_id),
 original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id>0),
 birth_launch_id uuid NOT NULL,
 birth_scenario_id uuid NOT NULL,
 birth_generation bigint NOT NULL CHECK(birth_generation>0),
 birth_platform_session_id integer NOT NULL CHECK(birth_platform_session_id>0),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(scene_id,scene_generation,target_id)
);
CREATE TABLE secureshop_agents.mail_scene_execution_grants (
 grant_id uuid PRIMARY KEY,
 scene_id uuid NOT NULL,
 scene_generation bigint NOT NULL,
 target_id uuid NOT NULL,
 launch_id uuid NOT NULL,
 scenario_id uuid NOT NULL,
 generation bigint NOT NULL CHECK(generation>0),
 original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id>0),
 original_platform_session_id integer NOT NULL CHECK(original_platform_session_id>0),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(scene_id,scene_generation,target_id) REFERENCES secureshop_agents.mail_scene_targets(scene_id,scene_generation,target_id),
 UNIQUE(scene_id,launch_id,generation)
);
CREATE TABLE secureshop_agents.mail_scene_operation_provenance (
 operation_id uuid PRIMARY KEY REFERENCES secureshop_agents.lab_mail_operation_receipts(operation_id),
 grant_id uuid NOT NULL REFERENCES secureshop_agents.mail_scene_execution_grants(grant_id),
 scene_id uuid NOT NULL,
 scene_generation bigint NOT NULL,
 target_id uuid NOT NULL,
 launch_id uuid NOT NULL,
 scenario_id uuid NOT NULL,
 generation bigint NOT NULL,
 original_platform_owner_id integer NOT NULL,
 original_platform_session_id integer NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE secureshop_agents.persona_inbox_scene_access_provenance (
 -- Access-event payload rows are removed by the canonical target reset; this
 -- immutable hash-and-coordinate snapshot remains after that cleanup.
 event_id uuid PRIMARY KEY,
 grant_id uuid NOT NULL REFERENCES secureshop_agents.mail_scene_execution_grants(grant_id),
 scene_id uuid NOT NULL,
 scene_generation bigint NOT NULL,
 target_id uuid NOT NULL,
 birth_launch_id uuid NOT NULL,
 birth_scenario_id uuid NOT NULL,
 birth_generation bigint NOT NULL,
 birth_platform_session_id integer NOT NULL,
 launch_id uuid NOT NULL,
 scenario_id uuid NOT NULL,
 generation bigint NOT NULL,
 original_platform_owner_id integer NOT NULL,
 original_platform_session_id integer NOT NULL,
 persona_session_id uuid NOT NULL,
 authority_version bigint NOT NULL,
 message_id bigint NOT NULL,
 caller_id integer NOT NULL,
 caller_role text NOT NULL,
 request_sha256 bytea NOT NULL CHECK(octet_length(request_sha256)=32),
 digest_version integer NOT NULL DEFAULT 2 CHECK(digest_version=2),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION secureshop_agents.guard_mail_scene_immutable() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE target secureshop_agents.persona_inbox_targets%ROWTYPE;
DECLARE mapped secureshop_agents.mail_scene_targets%ROWTYPE;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Immutable mail scene authority' USING ERRCODE='55000'; END IF;
 IF TG_TABLE_NAME='mail_scene_targets' THEN
  SELECT * INTO target FROM secureshop_agents.persona_inbox_targets WHERE target_id=NEW.target_id FOR SHARE;
  IF target.target_id IS NULL OR target.lifecycle<>'active'
   OR (target.launch_id,target.scenario_id,target.generation,target.original_platform_owner_id,target.original_platform_session_id)
      IS DISTINCT FROM (NEW.birth_launch_id,NEW.birth_scenario_id,NEW.birth_generation,NEW.original_platform_owner_id,NEW.birth_platform_session_id)
  THEN RAISE EXCEPTION 'Mail scene birth mismatch' USING ERRCODE='55000'; END IF;
 ELSIF TG_TABLE_NAME='mail_scene_execution_grants' THEN
  SELECT * INTO mapped FROM secureshop_agents.mail_scene_targets
   WHERE scene_id=NEW.scene_id AND scene_generation=NEW.scene_generation AND target_id=NEW.target_id FOR SHARE;
  IF mapped.scene_id IS NULL OR mapped.original_platform_owner_id<>NEW.original_platform_owner_id
   OR EXISTS(SELECT 1 FROM secureshop_agents.conversation_generation_retirements
      WHERE platform_launch_id=NEW.launch_id AND from_generation=NEW.generation)
   OR EXISTS(SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts
      WHERE original_platform_owner_id=NEW.original_platform_owner_id)
  THEN RAISE EXCEPTION 'Mail scene grant mismatch' USING ERRCODE='55000'; END IF;
 ELSIF TG_TABLE_NAME='mail_scene_operation_provenance' THEN
  IF NOT secureshop_agents.assert_mail_scene_execution_grant(NEW.grant_id,NEW.scene_id,NEW.scene_generation,
   NEW.target_id,NEW.launch_id,NEW.scenario_id,NEW.generation,NEW.original_platform_owner_id,NEW.original_platform_session_id)
   OR NOT EXISTS(SELECT 1 FROM secureshop_agents.lab_mail_operation_receipts r
      WHERE r.operation_id=NEW.operation_id AND r.target_id=NEW.target_id
       AND secureshop_agents.bound_mail_live_actor(NEW.launch_id,NEW.scenario_id,NEW.generation,
        NEW.original_platform_owner_id,NEW.original_platform_session_id,r.caller_id,
        r.persona_session_id,r.role,r.authority_version))
  THEN RAISE EXCEPTION 'Mail scene operation mismatch' USING ERRCODE='55000'; END IF;
 ELSIF TG_TABLE_NAME='persona_inbox_scene_access_provenance' THEN
  IF NOT secureshop_agents.assert_mail_scene_execution_grant(NEW.grant_id,NEW.scene_id,NEW.scene_generation,
   NEW.target_id,NEW.launch_id,NEW.scenario_id,NEW.generation,NEW.original_platform_owner_id,NEW.original_platform_session_id)
   OR NOT EXISTS(SELECT 1 FROM secureshop_agents.persona_inbox_access_events e
      JOIN secureshop_agents.mail_scene_targets m ON m.target_id=e.target_id
      WHERE e.event_id=NEW.event_id AND e.target_id=NEW.target_id
       AND e.message_id=NEW.message_id AND e.caller_shop_user_id=NEW.caller_id
       AND e.caller_shop_role=NEW.caller_role AND e.request_sha256=NEW.request_sha256
       AND secureshop_agents.bound_mail_live_actor(NEW.launch_id,NEW.scenario_id,NEW.generation,
        NEW.original_platform_owner_id,NEW.original_platform_session_id,NEW.caller_id,
        NEW.persona_session_id,NEW.caller_role,NEW.authority_version)
       AND (m.birth_launch_id,m.birth_scenario_id,m.birth_generation,m.birth_platform_session_id)
        IS NOT DISTINCT FROM (NEW.birth_launch_id,NEW.birth_scenario_id,NEW.birth_generation,NEW.birth_platform_session_id))
  THEN RAISE EXCEPTION 'Inbox scene read mismatch' USING ERRCODE='55000'; END IF;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER mail_scene_target_guard BEFORE INSERT OR UPDATE OR DELETE ON secureshop_agents.mail_scene_targets
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_mail_scene_immutable();
CREATE TRIGGER mail_scene_grant_guard BEFORE INSERT OR UPDATE OR DELETE ON secureshop_agents.mail_scene_execution_grants
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_mail_scene_immutable();
CREATE TRIGGER mail_scene_operation_guard BEFORE INSERT OR UPDATE OR DELETE ON secureshop_agents.mail_scene_operation_provenance
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_mail_scene_immutable();
CREATE TRIGGER persona_inbox_scene_access_guard BEFORE INSERT OR UPDATE OR DELETE ON secureshop_agents.persona_inbox_scene_access_provenance
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_mail_scene_immutable();
CREATE FUNCTION secureshop_agents.assert_mail_scene_execution_grant(
 requested_grant uuid,requested_scene uuid,requested_scene_generation bigint,requested_target uuid,
 requested_launch uuid,requested_scenario uuid,requested_generation bigint,requested_owner integer,requested_session integer)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
BEGIN
 PERFORM 1 FROM secureshop_agents.mail_scene_execution_grants g
 JOIN secureshop_agents.mail_scene_targets m ON m.scene_id=g.scene_id AND m.scene_generation=g.scene_generation AND m.target_id=g.target_id
 JOIN secureshop_agents.persona_inbox_targets t ON t.target_id=g.target_id
 WHERE g.grant_id=requested_grant AND g.scene_id=requested_scene AND g.scene_generation=requested_scene_generation
  AND g.target_id=requested_target AND g.launch_id=requested_launch AND g.scenario_id=requested_scenario
  AND g.generation=requested_generation AND g.original_platform_owner_id=requested_owner
  AND g.original_platform_session_id=requested_session AND m.original_platform_owner_id=requested_owner
  AND t.lifecycle='active' AND t.launch_id=m.birth_launch_id AND t.scenario_id=m.birth_scenario_id
  AND t.generation=m.birth_generation AND t.original_platform_owner_id=m.original_platform_owner_id
  AND t.original_platform_session_id=m.birth_platform_session_id
  AND NOT EXISTS(SELECT 1 FROM secureshop_agents.conversation_generation_retirements r
   WHERE r.platform_launch_id=requested_launch AND r.from_generation=requested_generation)
  AND NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts d
   WHERE d.original_platform_owner_id=requested_owner)
 FOR SHARE OF g,m,t;
 RETURN FOUND;
END $$;

-- Scene-only overload. The legacy 14-argument function and all old receipts remain unchanged.
CREATE OR REPLACE FUNCTION secureshop_agents.bound_lab_mail(
 requested_target uuid, requested_launch uuid, requested_scenario uuid, requested_generation bigint,
 requested_owner integer, requested_session integer, caller integer, persona_session uuid,
 caller_role text, caller_version bigint, requested_mode text, operation uuid, requested_action text, payload jsonb, requested_grant uuid
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE target secureshop_agents.persona_inbox_targets%ROWTYPE;
DECLARE granted secureshop_agents.mail_scene_execution_grants%ROWTYPE;
DECLARE prior secureshop_agents.lab_mail_operation_receipts%ROWTYPE;
DECLARE sender secureshop_agents.bound_actor_identities%ROWTYPE;
DECLARE recipient secureshop_agents.bound_actor_identities%ROWTYPE;
DECLARE recipient_count integer; chosen_recipient_id integer;
DECLARE request_hash bytea; content_hash bytea; result jsonb; rows_json jsonb; made bigint; tid bigint; replay boolean:=false;
BEGIN
 IF requested_mode IS NULL OR requested_action IS NULL OR requested_mode NOT IN ('vuln','fixed') OR requested_action NOT IN ('send','read','browse','recover')
  OR operation IS NULL OR jsonb_typeof(payload) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'Invalid mail request'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||requested_owner,0));
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-conversation-admission:'||requested_launch,0));
 SELECT * INTO granted FROM secureshop_agents.mail_scene_execution_grants g
  WHERE g.grant_id=requested_grant AND g.target_id=requested_target
   AND g.launch_id=requested_launch AND g.scenario_id=requested_scenario
   AND g.generation=requested_generation AND g.original_platform_owner_id=requested_owner
   AND g.original_platform_session_id=requested_session FOR SHARE;
 SELECT * INTO target FROM secureshop_agents.persona_inbox_targets t
  WHERE t.target_id=requested_target FOR UPDATE;
 IF granted.grant_id IS NULL OR target.target_id IS NULL OR target.lifecycle<>'active'
  OR NOT secureshop_agents.assert_mail_scene_execution_grant(granted.grant_id,granted.scene_id,
   granted.scene_generation,requested_target,requested_launch,requested_scenario,requested_generation,requested_owner,requested_session)
  OR EXISTS(SELECT 1 FROM secureshop_agents.conversation_generation_retirements
   WHERE platform_launch_id=requested_launch AND from_generation=requested_generation)
  OR EXISTS(SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts
   WHERE original_platform_owner_id=requested_owner)
  OR NOT secureshop_agents.bound_mail_live_actor(requested_launch,requested_scenario,requested_generation,
   requested_owner,requested_session,caller,persona_session,caller_role,caller_version)
 THEN RAISE EXCEPTION 'Mail authority unavailable' USING ERRCODE='42501'; END IF;
 SELECT * INTO prior FROM secureshop_agents.lab_mail_operation_receipts WHERE operation_id=operation;
 IF prior.operation_id IS NOT NULL AND (prior.target_id<>requested_target OR prior.caller_id<>caller
  OR prior.persona_session_id<>persona_session OR prior.authority_version<>caller_version OR prior.role<>caller_role OR prior.mode<>requested_mode)
 THEN RAISE EXCEPTION 'Mail operation conflict' USING ERRCODE='23505'; END IF;
 IF prior.operation_id IS NOT NULL AND NOT EXISTS(
  SELECT 1 FROM secureshop_agents.mail_scene_operation_provenance p
  WHERE p.operation_id=operation AND p.grant_id=requested_grant AND p.target_id=requested_target
   AND p.launch_id=requested_launch AND p.scenario_id=requested_scenario
   AND p.generation=requested_generation AND p.original_platform_owner_id=requested_owner
   AND p.original_platform_session_id=requested_session)
  AND NOT (target.launch_id=requested_launch AND target.scenario_id=requested_scenario
   AND target.generation=requested_generation AND target.original_platform_owner_id=requested_owner
   AND target.original_platform_session_id=requested_session
   AND NOT EXISTS(SELECT 1 FROM secureshop_agents.mail_scene_operation_provenance p WHERE p.operation_id=operation))
 THEN RAISE EXCEPTION 'Mail operation provenance conflict' USING ERRCODE='23505'; END IF;
 IF requested_action='recover' THEN
  IF payload<>'{}'::jsonb THEN RAISE EXCEPTION 'Invalid recovery'; END IF;
  IF prior.operation_id IS NULL THEN RETURN jsonb_build_object('found',false); END IF;
  RETURN jsonb_build_object('found',true,'operationId',operation,'action',prior.action,'receipt',prior.result,'requestSha256',encode(prior.request_sha256,'hex'));
 END IF;
 IF requested_action='send' THEN
  IF payload-ARRAY['from','to','subject','body_markdown','body_html','headers_raw','threadId']<>'{}'::jsonb
   OR NOT (payload ?& ARRAY['from','to','subject','body_markdown','body_html','headers_raw'])
   OR EXISTS(SELECT 1 FROM jsonb_each(payload-ARRAY['threadId']) WHERE jsonb_typeof(value)<>'string')
   OR octet_length(payload->>'from') NOT BETWEEN 1 AND 512 OR octet_length(payload->>'to') NOT BETWEEN 1 AND 512
   OR octet_length(payload->>'subject') NOT BETWEEN 1 AND 512 OR octet_length(payload->>'body_markdown')>32768
   OR octet_length(payload->>'body_html')>65536 OR octet_length(payload->>'headers_raw')>2048
  THEN RAISE EXCEPTION 'Invalid send payload'; END IF;
  -- Envelope fields and actual stored header bytes agree, even in vulnerable mode.
  payload:=jsonb_set(payload,'{headers_raw}',to_jsonb('From: '||(payload->>'from')||chr(13)||chr(10)||'To: '||(payload->>'to')||chr(13)||chr(10)||'Subject: '||(payload->>'subject')));
  IF requested_mode='fixed' THEN
   payload:=jsonb_set(payload,'{body_html}',to_jsonb('<pre>'||replace(replace(replace(COALESCE(payload->>'body_markdown',''),'&','&amp;'),'<','&lt;'),'>','&gt;')||'</pre>'));
  END IF;
 END IF;
 request_hash:=sha256(convert_to(jsonb_build_array(requested_action,payload)::text,'UTF8'));
 IF prior.operation_id IS NOT NULL AND requested_action<>'browse' THEN
  IF prior.action<>requested_action OR prior.request_sha256<>request_hash THEN RAISE EXCEPTION 'Mail operation conflict' USING ERRCODE='23505'; END IF;
  result:=prior.result; replay:=true;
 ELSE
  IF requested_action<>'browse' THEN
  INSERT INTO secureshop_agents.lab_mail_targets(target_id) VALUES(requested_target) ON CONFLICT DO NOTHING;
  IF (SELECT count(*) FROM secureshop_agents.lab_mail_operation_receipts WHERE target_id=requested_target)>=4096 THEN RAISE EXCEPTION 'Mail operation capacity reached'; END IF;
  END IF;
  IF requested_action='send' THEN
   IF payload-ARRAY['from','to','subject','body_markdown','body_html','headers_raw','threadId']<>'{}'::jsonb
    OR NOT (payload ?& ARRAY['from','to','subject','body_markdown','body_html','headers_raw'])
    OR EXISTS(SELECT 1 FROM jsonb_each(payload-ARRAY['threadId']) WHERE jsonb_typeof(value)<>'string') THEN RAISE EXCEPTION 'Invalid send payload'; END IF;
   SELECT * INTO sender FROM secureshop_agents.bound_actor_identities a
    WHERE a.shop_user_id=caller AND secureshop_agents.bound_actor_in_owner(a.shop_user_id,requested_owner);
   SELECT count(*)::integer,min(a.shop_user_id) INTO recipient_count,chosen_recipient_id
    FROM secureshop_agents.bound_actor_identities a
    WHERE a.email=split_part(replace(payload->>'to',chr(13),''),chr(10),1)
      AND secureshop_agents.bound_actor_in_owner(a.shop_user_id,requested_owner);
   IF recipient_count<>1 OR sender.shop_user_id IS NULL
    OR split_part(replace(payload->>'from',chr(13),''),chr(10),1)<>sender.email
    THEN RAISE EXCEPTION 'Mail envelope must name owned synthetic personas'; END IF;
   SELECT * INTO recipient FROM secureshop_agents.bound_actor_identities WHERE shop_user_id=chosen_recipient_id;
   IF requested_mode='fixed' AND ((payload->>'from')~'[\r\n]' OR (payload->>'to')~'[\r\n]' OR (payload->>'subject')~'[\r\n]') THEN RAISE EXCEPTION 'Invalid fixed mail header'; END IF;
   IF (SELECT count(*) FROM secureshop_agents.lab_mail_messages WHERE target_id=requested_target)>=1024 THEN RAISE EXCEPTION 'Mail message capacity reached'; END IF;
   IF payload ? 'threadId' THEN
    tid:=(payload->>'threadId')::bigint;
    IF NOT EXISTS(SELECT 1 FROM secureshop_agents.lab_mail_messages WHERE target_id=requested_target AND thread_id=tid AND (sender_id=caller OR recipient_id=caller)) THEN RAISE EXCEPTION 'Mail thread unavailable'; END IF;
   END IF;
   content_hash:=sha256(convert_to(payload::text,'UTF8'));
   INSERT INTO secureshop_agents.lab_mail_messages(target_id,thread_id,sender_id,recipient_id,from_addr,to_addr,subject,body_markdown,body_html,headers_raw,content_sha256)
   VALUES(requested_target,COALESCE(tid,0),caller,recipient.shop_user_id,payload->>'from',payload->>'to',payload->>'subject',payload->>'body_markdown',payload->>'body_html',payload->>'headers_raw',content_hash)
   RETURNING message_id INTO made;
   IF tid IS NULL THEN tid:=made; UPDATE secureshop_agents.lab_mail_messages SET thread_id=tid WHERE message_id=made; END IF;
   result:=jsonb_build_object('email_id',made,'thread_id',tid,'senderId',caller,'recipientId',recipient.shop_user_id,'contentSha256',encode(content_hash,'hex'));
  ELSE
   IF payload-ARRAY['userId']<>'{}'::jsonb OR jsonb_typeof(payload->'userId') IS DISTINCT FROM 'number' THEN RAISE EXCEPTION 'Invalid mailbox'; END IF;
   IF NOT secureshop_agents.bound_actor_in_owner((payload->>'userId')::integer,requested_owner) THEN RAISE EXCEPTION 'Mailbox unavailable'; END IF;
   -- @intentional-vulnerability idor-inbox: another persona, same owned target only.
   IF requested_mode='fixed' AND (payload->>'userId')::integer<>caller THEN RAISE EXCEPTION 'Mailbox forbidden' USING ERRCODE='42501'; END IF;
   SELECT COALESCE(jsonb_agg(jsonb_build_object('id',message_id,'sha256',encode(content_sha256,'hex')) ORDER BY message_id),'[]'::jsonb)
    INTO rows_json FROM secureshop_agents.lab_mail_messages WHERE target_id=requested_target AND recipient_id=(payload->>'userId')::integer;
   result:=jsonb_build_object('userId',(payload->>'userId')::integer,'messages',rows_json);
  END IF;
  IF requested_action<>'browse' THEN
  INSERT INTO secureshop_agents.lab_mail_operation_receipts(operation_id,target_id,caller_id,persona_session_id,authority_version,role,mode,action,request_sha256,result)
   VALUES(operation,requested_target,caller,persona_session,caller_version,caller_role,requested_mode,requested_action,request_hash,result);
   INSERT INTO secureshop_agents.mail_scene_operation_provenance
    (operation_id,grant_id,scene_id,scene_generation,target_id,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id)
   VALUES(operation,requested_grant,granted.scene_id,granted.scene_generation,requested_target,
    requested_launch,requested_scenario,requested_generation,requested_owner,requested_session);
  END IF;
 END IF;
 IF requested_action IN ('read','browse') THEN
  -- Authenticate returned bytes against the immutable original send, not only
  -- the mutable message digest. These are the two supported sender payloads:
  -- a new thread (no threadId), or a reply with its integer threadId.
  IF EXISTS (
   SELECT 1 FROM secureshop_agents.lab_mail_messages m
   WHERE m.target_id=requested_target
    AND EXISTS(SELECT 1 FROM jsonb_array_elements(result->'messages') saved WHERE (saved->>'id')::bigint=m.message_id)
    AND NOT EXISTS (
     SELECT 1 FROM secureshop_agents.lab_mail_operation_receipts sent
     CROSS JOIN LATERAL (SELECT jsonb_build_object(
      'from',m.from_addr,'to',m.to_addr,'subject',m.subject,
      'body_markdown',m.body_markdown,'body_html',m.body_html,'headers_raw',m.headers_raw) AS base) fields
     CROSS JOIN LATERAL (VALUES (fields.base), (fields.base||jsonb_build_object('threadId',m.thread_id))) candidate(payload)
     WHERE sent.target_id=m.target_id AND sent.action='send' AND sent.caller_id=m.sender_id
      AND sent.result->>'email_id'=m.message_id::text AND sent.result->>'thread_id'=m.thread_id::text
      AND sent.result->>'senderId'=m.sender_id::text AND sent.result->>'recipientId'=m.recipient_id::text
      AND sent.result->>'contentSha256'=encode(m.content_sha256,'hex')
      AND m.content_sha256=sha256(convert_to(candidate.payload::text,'UTF8'))
      AND sent.request_sha256=sha256(convert_to(jsonb_build_array('send',candidate.payload)::text,'UTF8'))
    )
  ) THEN RAISE EXCEPTION 'Mail snapshot integrity failure' USING ERRCODE='P0001'; END IF;
  SELECT COALESCE(jsonb_agg(jsonb_build_object('id',m.message_id,'thread_id',m.thread_id,'from_addr',m.from_addr,'to_addr',m.to_addr,
   'subject',m.subject,'body_markdown',m.body_markdown,'body_html',m.body_html,'headers_raw',m.headers_raw,'created_at',m.created_at) ORDER BY m.message_id),'[]'::jsonb)
  INTO rows_json FROM secureshop_agents.lab_mail_messages m WHERE m.target_id=requested_target
   AND EXISTS(SELECT 1 FROM jsonb_array_elements(result->'messages') r WHERE (r->>'id')::bigint=m.message_id AND r->>'sha256'=encode(m.content_sha256,'hex'));
  IF jsonb_array_length(rows_json)<>jsonb_array_length(result->'messages') THEN RAISE EXCEPTION 'Mail snapshot integrity failure'; END IF;
  RETURN jsonb_build_object('ok',true,'operationId',operation,'replayed',replay,'receipt',result,'emails',rows_json);
 END IF;
 RETURN jsonb_build_object('ok',true,'operationId',operation,'replayed',replay,'receipt',result,'email_id',result->'email_id','thread_id',result->'thread_id');
END $$;

-- Scene-only read overload: the ACL lesson sink remains advisory in vuln mode.
CREATE FUNCTION secureshop_agents.read_persona_inbox_message(
  requested_target uuid, requested_launch uuid, requested_scenario uuid,
  requested_generation bigint, requested_owner integer, requested_session integer,
  requested_caller integer, requested_role text, requested_message bigint,
  requested_operation uuid, requested_request_sha256 bytea,
  requested_grant uuid, requested_persona_session uuid, requested_authority_version bigint)
RETURNS TABLE(event_id uuid,message_id bigint,owner_shop_user_id integer,
  owner_shop_role text,subject text,body text,body_sha256 bytea,acl_version integer,
  acl_mode text,acl_decision text,cross_persona boolean,disclosed boolean,created_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE target secureshop_agents.persona_inbox_targets%ROWTYPE;
DECLARE granted secureshop_agents.mail_scene_execution_grants%ROWTYPE;
DECLARE message secureshop_agents.persona_inbox_messages%ROWTYPE;
DECLARE policy secureshop_agents.persona_inbox_acl_versions%ROWTYPE;
DECLARE prior secureshop_agents.persona_inbox_access_events%ROWTYPE;
DECLARE made uuid;
DECLARE is_cross boolean;
DECLARE reveal boolean;
BEGIN
  SELECT * INTO granted FROM secureshop_agents.mail_scene_execution_grants g
    WHERE g.grant_id=requested_grant AND g.target_id=requested_target
      AND g.launch_id=requested_launch AND g.scenario_id=requested_scenario
      AND g.generation=requested_generation AND g.original_platform_owner_id=requested_owner
      AND g.original_platform_session_id=requested_session FOR SHARE;
  SELECT * INTO target FROM secureshop_agents.persona_inbox_targets t
    WHERE t.target_id=requested_target FOR UPDATE;
  IF target.target_id IS NULL OR target.lifecycle<>'active' OR granted.grant_id IS NULL
    OR NOT secureshop_agents.assert_mail_scene_execution_grant(granted.grant_id,granted.scene_id,
      granted.scene_generation,requested_target,requested_launch,requested_scenario,requested_generation,requested_owner,requested_session)
    OR NOT secureshop_agents.bound_mail_live_actor(requested_launch,requested_scenario,requested_generation,
      requested_owner,requested_session,requested_caller,requested_persona_session,requested_role,requested_authority_version)
  THEN RAISE EXCEPTION 'Persona inbox scene authority unavailable' USING ERRCODE='42501'; END IF;
  SELECT * INTO message FROM secureshop_agents.persona_inbox_messages m
    WHERE m.target_id=requested_target AND m.message_id=requested_message;
  SELECT * INTO policy FROM secureshop_agents.persona_inbox_acl_versions a
    WHERE a.target_id=requested_target AND a.version=target.current_acl_version;
  IF message.message_id IS NULL OR policy.version IS NULL OR requested_role NOT IN ('customer','merchant','admin')
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
    IF NOT EXISTS(SELECT 1 FROM secureshop_agents.persona_inbox_scene_access_provenance p
      WHERE p.event_id=prior.event_id AND p.grant_id=requested_grant AND p.target_id=requested_target
       AND p.launch_id=requested_launch AND p.scenario_id=requested_scenario
       AND p.generation=requested_generation AND p.original_platform_owner_id=requested_owner
       AND p.original_platform_session_id=requested_session AND p.persona_session_id=requested_persona_session
       AND p.authority_version=requested_authority_version)
    THEN RAISE EXCEPTION 'Persona inbox scene replay conflicts' USING ERRCODE='55000'; END IF;
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
    INSERT INTO secureshop_agents.persona_inbox_scene_access_provenance
      (event_id,grant_id,scene_id,scene_generation,target_id,
       birth_launch_id,birth_scenario_id,birth_generation,birth_platform_session_id,
       launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id,
       persona_session_id,authority_version,message_id,caller_id,caller_role,request_sha256)
    VALUES(made,requested_grant,granted.scene_id,granted.scene_generation,requested_target,
      target.launch_id,target.scenario_id,target.generation,target.original_platform_session_id,
      requested_launch,requested_scenario,requested_generation,requested_owner,requested_session,
      requested_persona_session,requested_authority_version,requested_message,requested_caller,requested_role,
      requested_request_sha256);
  END IF;
  SELECT * INTO prior FROM secureshop_agents.persona_inbox_access_events e WHERE e.event_id=made;
  RETURN QUERY SELECT made,message.message_id,message.owner_shop_user_id,message.owner_shop_role,
    message.subject,CASE WHEN reveal THEN message.body ELSE NULL END,
    CASE WHEN reveal THEN message.body_sha256 ELSE NULL END,policy.version,policy.mode,
    CASE WHEN is_cross THEN 'deny' ELSE 'allow' END,is_cross,reveal,prior.created_at;
END $$;


-- Retain old function bodies privately, but fence every legacy entrypoint once a
-- target is mapped. Old mail recovery may still read its exact stored receipt.
ALTER FUNCTION secureshop_agents.bound_lab_mail(uuid,uuid,uuid,bigint,integer,integer,integer,uuid,text,bigint,text,uuid,text,jsonb)
 RENAME TO bound_lab_mail_unmapped_core;
CREATE FUNCTION secureshop_agents.bound_lab_mail(
 requested_target uuid,requested_launch uuid,requested_scenario uuid,requested_generation bigint,
 requested_owner integer,requested_session integer,caller integer,persona_session uuid,
 caller_role text,caller_version bigint,requested_mode text,operation uuid,requested_action text,payload jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
BEGIN
 IF requested_action<>'recover' AND EXISTS(SELECT 1 FROM secureshop_agents.mail_scene_targets WHERE target_id=requested_target)
 THEN RAISE EXCEPTION 'Mapped mail target requires scene grant' USING ERRCODE='42501'; END IF;
 RETURN secureshop_agents.bound_lab_mail_unmapped_core(requested_target,requested_launch,requested_scenario,
  requested_generation,requested_owner,requested_session,caller,persona_session,caller_role,caller_version,
  requested_mode,operation,requested_action,payload);
END $$;

ALTER FUNCTION secureshop_agents.list_persona_inbox_messages(uuid,uuid,uuid,bigint,integer,integer)
 RENAME TO list_persona_inbox_messages_unmapped_core;
CREATE FUNCTION secureshop_agents.list_persona_inbox_messages(
 requested_target uuid,requested_launch uuid,requested_scenario uuid,requested_generation bigint,
 requested_owner integer,requested_session integer)
RETURNS TABLE(message_id bigint,owner_shop_user_id integer,owner_shop_role text,subject text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM secureshop_agents.mail_scene_targets WHERE target_id=requested_target)
 THEN RAISE EXCEPTION 'Mapped inbox target requires scene grant' USING ERRCODE='42501'; END IF;
 RETURN QUERY SELECT * FROM secureshop_agents.list_persona_inbox_messages_unmapped_core(
  requested_target,requested_launch,requested_scenario,requested_generation,requested_owner,requested_session);
END $$;

ALTER FUNCTION secureshop_agents.read_persona_inbox_message(uuid,uuid,uuid,bigint,integer,integer,integer,text,bigint,uuid,bytea)
 RENAME TO read_persona_inbox_message_unmapped_core;
CREATE FUNCTION secureshop_agents.read_persona_inbox_message(
 requested_target uuid,requested_launch uuid,requested_scenario uuid,requested_generation bigint,
 requested_owner integer,requested_session integer,requested_caller integer,requested_role text,
 requested_message bigint,requested_operation uuid,requested_request_sha256 bytea)
RETURNS TABLE(event_id uuid,message_id bigint,owner_shop_user_id integer,owner_shop_role text,subject text,
 body text,body_sha256 bytea,acl_version integer,acl_mode text,acl_decision text,cross_persona boolean,
 disclosed boolean,created_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM secureshop_agents.mail_scene_targets WHERE target_id=requested_target)
 THEN RAISE EXCEPTION 'Mapped inbox target requires scene grant' USING ERRCODE='42501'; END IF;
 RETURN QUERY SELECT * FROM secureshop_agents.read_persona_inbox_message_unmapped_core(
  requested_target,requested_launch,requested_scenario,requested_generation,requested_owner,requested_session,
  requested_caller,requested_role,requested_message,requested_operation,requested_request_sha256);
END $$;

ALTER FUNCTION secureshop_agents.advance_persona_inbox_acl(uuid,uuid,uuid,bigint,integer,integer,integer,text,bytea)
 RENAME TO advance_persona_inbox_acl_unmapped_core;
CREATE FUNCTION secureshop_agents.advance_persona_inbox_acl(
 requested_target uuid,requested_launch uuid,requested_scenario uuid,requested_generation bigint,
 requested_owner integer,requested_session integer,expected_version integer,next_mode text,next_policy_sha256 bytea)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM secureshop_agents.mail_scene_targets WHERE target_id=requested_target)
 THEN RAISE EXCEPTION 'Mapped inbox target requires scene grant' USING ERRCODE='42501'; END IF;
 RETURN secureshop_agents.advance_persona_inbox_acl_unmapped_core(requested_target,requested_launch,
  requested_scenario,requested_generation,requested_owner,requested_session,expected_version,next_mode,next_policy_sha256);
END $$;

-- Mapped reads/ACL transitions use exact current grant and then reuse the
-- historical storage operation on immutable birth coordinates.
CREATE FUNCTION secureshop_agents.list_persona_inbox_messages(
 requested_target uuid,requested_launch uuid,requested_scenario uuid,requested_generation bigint,
 requested_owner integer,requested_session integer,requested_grant uuid)
RETURNS TABLE(message_id bigint,owner_shop_user_id integer,owner_shop_role text,subject text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE g secureshop_agents.mail_scene_execution_grants%ROWTYPE;
DECLARE m secureshop_agents.mail_scene_targets%ROWTYPE;
BEGIN
 SELECT * INTO g FROM secureshop_agents.mail_scene_execution_grants
  WHERE grant_id=requested_grant AND target_id=requested_target AND launch_id=requested_launch
   AND scenario_id=requested_scenario AND generation=requested_generation
   AND original_platform_owner_id=requested_owner AND original_platform_session_id=requested_session FOR SHARE;
 IF g.grant_id IS NULL OR NOT secureshop_agents.assert_mail_scene_execution_grant(
  g.grant_id,g.scene_id,g.scene_generation,requested_target,requested_launch,requested_scenario,
  requested_generation,requested_owner,requested_session)
 THEN RAISE EXCEPTION 'Inbox scene grant unavailable' USING ERRCODE='42501'; END IF;
 SELECT * INTO m FROM secureshop_agents.mail_scene_targets WHERE scene_id=g.scene_id FOR SHARE;
 RETURN QUERY SELECT * FROM secureshop_agents.list_persona_inbox_messages_unmapped_core(
  requested_target,m.birth_launch_id,m.birth_scenario_id,m.birth_generation,
  m.original_platform_owner_id,m.birth_platform_session_id);
END $$;
CREATE FUNCTION secureshop_agents.advance_persona_inbox_acl(
 requested_target uuid,requested_launch uuid,requested_scenario uuid,requested_generation bigint,
 requested_owner integer,requested_session integer,expected_version integer,next_mode text,next_policy_sha256 bytea,
 requested_grant uuid)
RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE g secureshop_agents.mail_scene_execution_grants%ROWTYPE;
DECLARE m secureshop_agents.mail_scene_targets%ROWTYPE;
BEGIN
 SELECT * INTO g FROM secureshop_agents.mail_scene_execution_grants
  WHERE grant_id=requested_grant AND target_id=requested_target AND launch_id=requested_launch
   AND scenario_id=requested_scenario AND generation=requested_generation
   AND original_platform_owner_id=requested_owner AND original_platform_session_id=requested_session FOR SHARE;
 IF g.grant_id IS NULL OR NOT secureshop_agents.assert_mail_scene_execution_grant(
  g.grant_id,g.scene_id,g.scene_generation,requested_target,requested_launch,requested_scenario,
  requested_generation,requested_owner,requested_session)
 THEN RAISE EXCEPTION 'Inbox scene grant unavailable' USING ERRCODE='42501'; END IF;
 SELECT * INTO m FROM secureshop_agents.mail_scene_targets WHERE scene_id=g.scene_id FOR SHARE;
 RETURN secureshop_agents.advance_persona_inbox_acl_unmapped_core(requested_target,m.birth_launch_id,
  m.birth_scenario_id,m.birth_generation,m.original_platform_owner_id,m.birth_platform_session_id,
  expected_version,next_mode,next_policy_sha256);
END $$;

REVOKE ALL ON secureshop_agents.mail_scene_targets,
 secureshop_agents.mail_scene_execution_grants,
 secureshop_agents.mail_scene_operation_provenance,
 secureshop_agents.persona_inbox_scene_access_provenance FROM PUBLIC;
GRANT SELECT,INSERT ON secureshop_agents.mail_scene_targets,
 secureshop_agents.mail_scene_execution_grants,
 secureshop_agents.mail_scene_operation_provenance,
 secureshop_agents.persona_inbox_scene_access_provenance TO dvaia_secureshop_agents_runtime;
REVOKE ALL ON FUNCTION secureshop_agents.guard_mail_scene_immutable(),
 secureshop_agents.assert_mail_scene_execution_grant(uuid,uuid,bigint,uuid,uuid,uuid,bigint,integer,integer),
 secureshop_agents.bound_lab_mail_unmapped_core(uuid,uuid,uuid,bigint,integer,integer,integer,uuid,text,bigint,text,uuid,text,jsonb),
 secureshop_agents.list_persona_inbox_messages_unmapped_core(uuid,uuid,uuid,bigint,integer,integer),
 secureshop_agents.read_persona_inbox_message_unmapped_core(uuid,uuid,uuid,bigint,integer,integer,integer,text,bigint,uuid,bytea),
 secureshop_agents.advance_persona_inbox_acl_unmapped_core(uuid,uuid,uuid,bigint,integer,integer,integer,text,bytea)
 FROM PUBLIC,dvaia_secureshop_agents_runtime;
REVOKE ALL ON FUNCTION secureshop_agents.bound_lab_mail(uuid,uuid,uuid,bigint,integer,integer,integer,uuid,text,bigint,text,uuid,text,jsonb),
 secureshop_agents.bound_lab_mail(uuid,uuid,uuid,bigint,integer,integer,integer,uuid,text,bigint,text,uuid,text,jsonb,uuid),
 secureshop_agents.list_persona_inbox_messages(uuid,uuid,uuid,bigint,integer,integer),
 secureshop_agents.list_persona_inbox_messages(uuid,uuid,uuid,bigint,integer,integer,uuid),
 secureshop_agents.read_persona_inbox_message(uuid,uuid,uuid,bigint,integer,integer,integer,text,bigint,uuid,bytea),
 secureshop_agents.read_persona_inbox_message(uuid,uuid,uuid,bigint,integer,integer,integer,text,bigint,uuid,bytea,uuid,uuid,bigint),
 secureshop_agents.advance_persona_inbox_acl(uuid,uuid,uuid,bigint,integer,integer,integer,text,bytea),
 secureshop_agents.advance_persona_inbox_acl(uuid,uuid,uuid,bigint,integer,integer,integer,text,bytea,uuid)
 FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_agents.assert_mail_scene_execution_grant(uuid,uuid,bigint,uuid,uuid,uuid,bigint,integer,integer),
 secureshop_agents.bound_lab_mail(uuid,uuid,uuid,bigint,integer,integer,integer,uuid,text,bigint,text,uuid,text,jsonb),
 secureshop_agents.bound_lab_mail(uuid,uuid,uuid,bigint,integer,integer,integer,uuid,text,bigint,text,uuid,text,jsonb,uuid),
 secureshop_agents.list_persona_inbox_messages(uuid,uuid,uuid,bigint,integer,integer),
 secureshop_agents.list_persona_inbox_messages(uuid,uuid,uuid,bigint,integer,integer,uuid),
 secureshop_agents.read_persona_inbox_message(uuid,uuid,uuid,bigint,integer,integer,integer,text,bigint,uuid,bytea),
 secureshop_agents.read_persona_inbox_message(uuid,uuid,uuid,bigint,integer,integer,integer,text,bigint,uuid,bytea,uuid,uuid,bigint),
 secureshop_agents.advance_persona_inbox_acl(uuid,uuid,uuid,bigint,integer,integer,integer,text,bytea),
 secureshop_agents.advance_persona_inbox_acl(uuid,uuid,uuid,bigint,integer,integer,integer,text,bytea,uuid)
 TO dvaia_secureshop_agents_runtime;

-- Current mail attempt/uncertainty admission is always scene-granted once an
-- inbox is mapped, including its original birth session.
CREATE FUNCTION secureshop_agents.mail_scene_target_current(
 requested_target uuid,requested_launch uuid,requested_scenario uuid,requested_generation bigint,
 requested_owner integer,requested_session integer)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE t secureshop_agents.persona_inbox_targets%ROWTYPE;
DECLARE g secureshop_agents.mail_scene_execution_grants%ROWTYPE;
BEGIN
 SELECT * INTO t FROM secureshop_agents.persona_inbox_targets WHERE target_id=requested_target FOR SHARE;
 IF t.target_id IS NULL OR t.lifecycle<>'active' THEN RETURN false; END IF;
 IF NOT EXISTS(SELECT 1 FROM secureshop_agents.mail_scene_targets WHERE target_id=requested_target) THEN
  RETURN (t.launch_id,t.scenario_id,t.generation,t.original_platform_owner_id,t.original_platform_session_id)
   IS NOT DISTINCT FROM (requested_launch,requested_scenario,requested_generation,requested_owner,requested_session);
 END IF;
 SELECT * INTO g FROM secureshop_agents.mail_scene_execution_grants
  WHERE target_id=requested_target AND launch_id=requested_launch AND scenario_id=requested_scenario
   AND generation=requested_generation AND original_platform_owner_id=requested_owner
   AND original_platform_session_id=requested_session FOR SHARE;
 RETURN g.grant_id IS NOT NULL AND secureshop_agents.assert_mail_scene_execution_grant(
  g.grant_id,g.scene_id,g.scene_generation,requested_target,requested_launch,requested_scenario,
  requested_generation,requested_owner,requested_session);
END $$;

CREATE OR REPLACE FUNCTION secureshop_agents.guard_bound_mail_uncertain_receipt() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
BEGIN
  IF TG_OP<>'INSERT' THEN
    RAISE EXCEPTION 'Immutable mail uncertainty evidence' USING ERRCODE='55000';
  END IF;
  IF TG_TABLE_NAME='bound_mail_thread_attempts' THEN
    IF NOT EXISTS (
      SELECT 1 FROM secureshop_agents.turn_requests tr
      JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id
      JOIN secureshop_agents.persona_inbox_targets target ON target.target_id=NEW.target_id
      WHERE tr.session_id=NEW.session_id AND tr.request_id=NEW.request_id
        AND tr.claim_id=NEW.claim_id AND tr.request_hash=NEW.request_hash
        AND tr.status='started' AND s.conversation_purpose='secureshop_mail_reply'
        AND s.authority_mode='launch_bound' AND s.binding_state='active'
        AND s.user_id=NEW.persona_id
        AND secureshop_agents.mail_scene_target_current(NEW.target_id,s.platform_launch_id,
          s.platform_scenario_id,s.platform_launch_generation,s.original_platform_owner_id,
          s.original_platform_session_id)
        AND target.lifecycle='active'
        AND secureshop_agents.bound_mail_live_actor(s.platform_launch_id,
          s.platform_scenario_id,s.platform_launch_generation,
          s.original_platform_owner_id,s.original_platform_session_id,
          NEW.persona_id,NEW.persona_session_id,s.role,NEW.authority_version)
    ) THEN RAISE EXCEPTION 'Mail thread admission unavailable' USING ERRCODE='55000'; END IF;
  ELSIF TG_TABLE_NAME='bound_mail_preexecution_rejections' THEN
    IF NOT EXISTS (
      SELECT 1 FROM secureshop_agents.turn_requests tr
      JOIN secureshop_agents.bound_mail_thread_attempts attempt
        ON attempt.session_id=tr.session_id AND attempt.request_id=tr.request_id
      JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id
      WHERE tr.session_id=NEW.session_id AND tr.request_id=NEW.request_id
        AND tr.claim_id=NEW.claim_id AND tr.request_hash=NEW.request_hash
        AND tr.status='started' AND attempt.claim_id=NEW.claim_id
        AND attempt.request_hash=NEW.request_hash AND attempt.run_id=NEW.run_id
        AND attempt.target_id=NEW.target_id AND attempt.persona_id=NEW.persona_id
        AND attempt.thread_id=NEW.thread_id AND attempt.mode=NEW.mode
        AND attempt.blocked=(NEW.stage='thread_admission')
        AND secureshop_agents.bound_mail_live_actor(s.platform_launch_id,
          s.platform_scenario_id,s.platform_launch_generation,
          s.original_platform_owner_id,s.original_platform_session_id,
          attempt.persona_id,attempt.persona_session_id,s.role,attempt.authority_version)
    ) THEN RAISE EXCEPTION 'Mail rejection admission unavailable' USING ERRCODE='55000'; END IF;
  ELSIF TG_TABLE_NAME='bound_mail_unresolved_detaches' THEN
    IF NOT EXISTS (
      SELECT 1 FROM secureshop_agents.turn_requests tr
      JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id
      JOIN secureshop_agents.persona_inbox_targets target ON target.target_id=NEW.target_id
      WHERE tr.session_id=NEW.session_id AND tr.request_id=NEW.request_id
        AND tr.claim_id=NEW.claim_id AND tr.request_hash=NEW.request_hash
        AND tr.status='uncertain' AND s.conversation_purpose='secureshop_mail_reply'
        AND s.authority_mode='launch_bound' AND s.binding_state='active'
        AND s.user_id=NEW.persona_id
        AND secureshop_agents.mail_scene_target_current(NEW.target_id,s.platform_launch_id,
          s.platform_scenario_id,s.platform_launch_generation,s.original_platform_owner_id,
          s.original_platform_session_id)
        AND secureshop_agents.bound_mail_live_actor(s.platform_launch_id,
          s.platform_scenario_id,s.platform_launch_generation,
          s.original_platform_owner_id,s.original_platform_session_id,
          NEW.persona_id,NEW.persona_session_id,s.role,NEW.authority_version)
    ) THEN RAISE EXCEPTION 'Mail unresolved admission unavailable' USING ERRCODE='55000'; END IF;
  ELSE
    RAISE EXCEPTION 'Mail uncertainty table unavailable' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;

REVOKE ALL ON FUNCTION secureshop_agents.mail_scene_target_current(uuid,uuid,uuid,bigint,integer,integer)
 FROM PUBLIC,dvaia_secureshop_agents_runtime;
