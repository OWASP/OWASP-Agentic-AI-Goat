-- Extend the immutable lab mail transport to owner-scoped registered actors.
-- Keep vulnerable in-target IDOR, raw header construction, and saved HTML intact.
CREATE OR REPLACE FUNCTION secureshop_agents.bound_lab_mail(
 requested_target uuid, requested_launch uuid, requested_scenario uuid, requested_generation bigint,
 requested_owner integer, requested_session integer, caller integer, persona_session uuid,
 caller_role text, caller_version bigint, requested_mode text, operation uuid, requested_action text, payload jsonb
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE target secureshop_agents.persona_inbox_targets%ROWTYPE;
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
 SELECT * INTO target FROM secureshop_agents.persona_inbox_targets t WHERE t.target_id=requested_target
  AND t.launch_id=requested_launch AND t.scenario_id=requested_scenario AND t.generation=requested_generation
  AND t.original_platform_owner_id=requested_owner AND t.original_platform_session_id=requested_session FOR UPDATE;
 IF target.target_id IS NULL OR target.lifecycle<>'active'
  OR EXISTS(SELECT 1 FROM secureshop_agents.conversation_generation_retirements WHERE platform_launch_id=requested_launch AND from_generation=requested_generation)
  OR EXISTS(SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts WHERE original_platform_owner_id=requested_owner)
  OR NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_persona_sessions s
   JOIN secureshop_agents.bound_actor_identities a ON a.shop_user_id=s.shop_user_id
   LEFT JOIN secureshop_agents.bound_actor_tenant_memberships m
    ON m.tenant_owner_id=requested_owner AND m.shop_user_id=s.shop_user_id
    AND m.membership_version=s.bootstrap_membership_version AND m.is_active
   LEFT JOIN secureshop_agents.bound_persona_state st ON st.platform_launch_id=requested_launch AND st.platform_scenario_id=requested_scenario
    AND st.platform_launch_generation=requested_generation AND st.original_platform_owner_id=requested_owner
    AND st.original_platform_session_id=requested_session AND st.shop_user_id=caller
   WHERE s.session_id=persona_session AND s.shop_user_id=caller AND s.platform_launch_id=requested_launch
    AND s.platform_scenario_id=requested_scenario AND s.platform_launch_generation=requested_generation
    AND s.original_platform_owner_id=requested_owner AND s.original_platform_session_id=requested_session
    AND secureshop_agents.bound_actor_in_owner(s.shop_user_id,requested_owner,s.bootstrap_membership_version)
    AND s.role=caller_role AND COALESCE(st.effective_role,m.role,a.base_role)=caller_role
    AND COALESCE(st.authority_version,1)=caller_version AND st.banned_at IS NULL
    AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
    AND s.credential_version=COALESCE((SELECT c.credential_version FROM secureshop_agents.bound_persona_credentials c
      WHERE c.platform_launch_id=requested_launch AND c.platform_scenario_id=requested_scenario AND c.platform_launch_generation=requested_generation
       AND c.original_platform_owner_id=requested_owner AND c.original_platform_session_id=requested_session AND c.shop_user_id=caller),1))
 THEN RAISE EXCEPTION 'Mail authority unavailable' USING ERRCODE='42501'; END IF;
 SELECT * INTO prior FROM secureshop_agents.lab_mail_operation_receipts WHERE operation_id=operation;
 IF prior.operation_id IS NOT NULL AND (prior.target_id<>requested_target OR prior.caller_id<>caller
  OR prior.persona_session_id<>persona_session OR prior.authority_version<>caller_version OR prior.role<>caller_role OR prior.mode<>requested_mode)
 THEN RAISE EXCEPTION 'Mail operation conflict' USING ERRCODE='23505'; END IF;
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
