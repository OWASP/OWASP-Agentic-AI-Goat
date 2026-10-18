-- DRAFT ONLY: additive mutable mail, separate from the fixed three-note lesson.
CREATE TABLE secureshop_agents.lab_mail_targets (
 target_id uuid PRIMARY KEY REFERENCES secureshop_agents.persona_inbox_targets(target_id),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE secureshop_agents.lab_mail_messages (
 message_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
 target_id uuid NOT NULL REFERENCES secureshop_agents.lab_mail_targets(target_id),
 thread_id bigint NOT NULL,
 sender_id integer NOT NULL REFERENCES secureshop_agents.bound_persona_templates(shop_user_id),
 recipient_id integer NOT NULL REFERENCES secureshop_agents.bound_persona_templates(shop_user_id),
 from_addr text NOT NULL CHECK(octet_length(from_addr) BETWEEN 1 AND 512),
 to_addr text NOT NULL CHECK(octet_length(to_addr) BETWEEN 1 AND 512),
 subject text NOT NULL CHECK(octet_length(subject) BETWEEN 1 AND 512),
 body_markdown text NOT NULL CHECK(octet_length(body_markdown)<=32768),
 body_html text NOT NULL CHECK(octet_length(body_html)<=65536),
 headers_raw text NOT NULL CHECK(octet_length(headers_raw)<=2048),
 content_sha256 bytea NOT NULL CHECK(octet_length(content_sha256)=32),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(target_id,message_id)
);
CREATE INDEX lab_mail_inbox ON secureshop_agents.lab_mail_messages(target_id,recipient_id,message_id);
CREATE TABLE secureshop_agents.lab_mail_operation_receipts (
 operation_id uuid PRIMARY KEY,
 target_id uuid NOT NULL REFERENCES secureshop_agents.lab_mail_targets(target_id),
 caller_id integer NOT NULL REFERENCES secureshop_agents.bound_persona_templates(shop_user_id),
 persona_session_id uuid NOT NULL,
 authority_version bigint NOT NULL CHECK(authority_version>=1),
 role text NOT NULL CHECK(role IN ('customer','merchant','admin')),
 mode text NOT NULL CHECK(mode IN ('vuln','fixed')),
 action text NOT NULL CHECK(action IN ('send','read')),
 request_sha256 bytea NOT NULL CHECK(octet_length(request_sha256)=32),
 -- Hashes and opaque IDs only: no message body/header survives target cleanup here.
 result jsonb NOT NULL CHECK(jsonb_typeof(result)='object'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE secureshop_agents.lab_mail_cleanup_receipts (
 operation_id uuid PRIMARY KEY REFERENCES secureshop_agents.persona_inbox_cleanup_receipts(operation_id),
 target_id uuid NOT NULL UNIQUE REFERENCES secureshop_agents.lab_mail_targets(target_id),
 deleted_message_count integer NOT NULL CHECK(deleted_message_count BETWEEN 0 AND 1024),
 retained_operation_count integer NOT NULL CHECK(retained_operation_count BETWEEN 0 AND 4096),
 evidence_sha256 bytea NOT NULL CHECK(octet_length(evidence_sha256)=32),
 receipt_sha256 bytea NOT NULL CHECK(octet_length(receipt_sha256)=32),
 completed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION secureshop_agents.guard_lab_mail_immutable() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
BEGIN RAISE EXCEPTION 'Immutable lab mail evidence' USING ERRCODE='55000'; END $$;
CREATE TRIGGER lab_mail_operation_immutable BEFORE UPDATE OR DELETE ON secureshop_agents.lab_mail_operation_receipts
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_lab_mail_immutable();
CREATE TRIGGER lab_mail_target_immutable BEFORE UPDATE OR DELETE ON secureshop_agents.lab_mail_targets
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_lab_mail_immutable();
CREATE TRIGGER lab_mail_cleanup_immutable BEFORE UPDATE OR DELETE ON secureshop_agents.lab_mail_cleanup_receipts
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_lab_mail_immutable();

CREATE FUNCTION secureshop_agents.cleanup_bound_lab_mail() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE removed integer; retained integer; evidence bytea;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM secureshop_agents.lab_mail_targets WHERE target_id=NEW.target_id) THEN RETURN NEW; END IF;
 IF NOT EXISTS(SELECT 1 FROM secureshop_agents.persona_inbox_targets WHERE target_id=NEW.target_id AND lifecycle='retired') THEN
  RAISE EXCEPTION 'Mail cleanup requires canonical retirement'; END IF;
 SELECT count(*) INTO removed FROM secureshop_agents.lab_mail_messages WHERE target_id=NEW.target_id;
 SELECT count(*),sha256(convert_to(COALESCE(jsonb_agg(jsonb_build_array(operation_id,encode(request_sha256,'hex'),result)
  ORDER BY operation_id)::text,'[]'),'UTF8')) INTO retained,evidence
 FROM secureshop_agents.lab_mail_operation_receipts WHERE target_id=NEW.target_id;
 DELETE FROM secureshop_agents.lab_mail_messages WHERE target_id=NEW.target_id;
 INSERT INTO secureshop_agents.lab_mail_cleanup_receipts(operation_id,target_id,deleted_message_count,
  retained_operation_count,evidence_sha256,receipt_sha256)
 VALUES(NEW.operation_id,NEW.target_id,removed,retained,evidence,
  sha256(convert_to(concat_ws(chr(31),'lab-mail-cleanup-v1',NEW.operation_id::text,NEW.target_id::text,
   removed::text,retained::text,encode(evidence,'hex')),'UTF8')));
 RETURN NEW;
END $$;
CREATE TRIGGER canonical_persona_cleanup_lab_mail AFTER INSERT ON secureshop_agents.persona_inbox_cleanup_receipts
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.cleanup_bound_lab_mail();

-- SQL independently checks current scope/persona, in addition to the repository's
-- shared persona fence. Lock order matches canonical retirement/deletion.
CREATE FUNCTION secureshop_agents.bound_lab_mail(
 requested_target uuid, requested_launch uuid, requested_scenario uuid, requested_generation bigint,
 requested_owner integer, requested_session integer, caller integer, persona_session uuid,
 caller_role text, caller_version bigint, requested_mode text, operation uuid, requested_action text, payload jsonb
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE target secureshop_agents.persona_inbox_targets%ROWTYPE;
DECLARE prior secureshop_agents.lab_mail_operation_receipts%ROWTYPE;
DECLARE sender secureshop_agents.bound_persona_templates%ROWTYPE;
DECLARE recipient secureshop_agents.bound_persona_templates%ROWTYPE;
DECLARE request_hash bytea; content_hash bytea; result jsonb; rows_json jsonb; made bigint; tid bigint; replay boolean:=false;
BEGIN
 IF requested_mode IS NULL OR requested_action IS NULL OR requested_mode NOT IN ('vuln','fixed') OR requested_action NOT IN ('send','read','recover')
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
   JOIN secureshop_agents.bound_persona_templates t ON t.shop_user_id=s.shop_user_id
   LEFT JOIN secureshop_agents.bound_persona_state st ON st.platform_launch_id=requested_launch AND st.platform_scenario_id=requested_scenario
    AND st.platform_launch_generation=requested_generation AND st.original_platform_owner_id=requested_owner
    AND st.original_platform_session_id=requested_session AND st.shop_user_id=caller
   WHERE s.session_id=persona_session AND s.shop_user_id=caller AND s.platform_launch_id=requested_launch
    AND s.platform_scenario_id=requested_scenario AND s.platform_launch_generation=requested_generation
    AND s.original_platform_owner_id=requested_owner AND s.original_platform_session_id=requested_session
    AND s.role=caller_role AND COALESCE(st.effective_role,t.role)=caller_role
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
 IF prior.operation_id IS NOT NULL THEN
  IF prior.action<>requested_action OR prior.request_sha256<>request_hash THEN RAISE EXCEPTION 'Mail operation conflict' USING ERRCODE='23505'; END IF;
  result:=prior.result; replay:=true;
 ELSE
  INSERT INTO secureshop_agents.lab_mail_targets(target_id) VALUES(requested_target) ON CONFLICT DO NOTHING;
  IF (SELECT count(*) FROM secureshop_agents.lab_mail_operation_receipts WHERE target_id=requested_target)>=4096 THEN RAISE EXCEPTION 'Mail operation capacity reached'; END IF;
  IF requested_action='send' THEN
   IF payload-ARRAY['from','to','subject','body_markdown','body_html','headers_raw','threadId']<>'{}'::jsonb
    OR NOT (payload ?& ARRAY['from','to','subject','body_markdown','body_html','headers_raw'])
    OR EXISTS(SELECT 1 FROM jsonb_each(payload-ARRAY['threadId']) WHERE jsonb_typeof(value)<>'string') THEN RAISE EXCEPTION 'Invalid send payload'; END IF;
   SELECT * INTO sender FROM secureshop_agents.bound_persona_templates WHERE shop_user_id=caller;
   SELECT * INTO recipient FROM secureshop_agents.bound_persona_templates WHERE email=split_part(replace(payload->>'to',chr(13),''),chr(10),1);
   IF recipient.shop_user_id IS NULL OR split_part(replace(payload->>'from',chr(13),''),chr(10),1)<>sender.email
    THEN RAISE EXCEPTION 'Mail envelope must name owned synthetic personas'; END IF;
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
   IF NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_persona_templates WHERE shop_user_id=(payload->>'userId')::integer) THEN RAISE EXCEPTION 'Mailbox unavailable'; END IF;
   -- @intentional-vulnerability idor-inbox: another persona, same owned target only.
   IF requested_mode='fixed' AND (payload->>'userId')::integer<>caller THEN RAISE EXCEPTION 'Mailbox forbidden' USING ERRCODE='42501'; END IF;
   SELECT COALESCE(jsonb_agg(jsonb_build_object('id',message_id,'sha256',encode(content_sha256,'hex')) ORDER BY message_id),'[]'::jsonb)
    INTO rows_json FROM secureshop_agents.lab_mail_messages WHERE target_id=requested_target AND recipient_id=(payload->>'userId')::integer;
   result:=jsonb_build_object('userId',(payload->>'userId')::integer,'messages',rows_json);
  END IF;
  INSERT INTO secureshop_agents.lab_mail_operation_receipts(operation_id,target_id,caller_id,persona_session_id,authority_version,role,mode,action,request_sha256,result)
   VALUES(operation,requested_target,caller,persona_session,caller_version,caller_role,requested_mode,requested_action,request_hash,result);
 END IF;
 IF requested_action='read' THEN
  SELECT COALESCE(jsonb_agg(jsonb_build_object('id',m.message_id,'thread_id',m.thread_id,'from_addr',m.from_addr,'to_addr',m.to_addr,
   'subject',m.subject,'body_markdown',m.body_markdown,'body_html',m.body_html,'headers_raw',m.headers_raw,'created_at',m.created_at) ORDER BY m.message_id),'[]'::jsonb)
  INTO rows_json FROM secureshop_agents.lab_mail_messages m WHERE m.target_id=requested_target
   AND EXISTS(SELECT 1 FROM jsonb_array_elements(result->'messages') r WHERE (r->>'id')::bigint=m.message_id AND r->>'sha256'=encode(m.content_sha256,'hex'));
  IF jsonb_array_length(rows_json)<>jsonb_array_length(result->'messages') THEN RAISE EXCEPTION 'Mail snapshot integrity failure'; END IF;
  RETURN jsonb_build_object('ok',true,'operationId',operation,'replayed',replay,'receipt',result,'emails',rows_json);
 END IF;
 RETURN jsonb_build_object('ok',true,'operationId',operation,'replayed',replay,'receipt',result,'email_id',result->'email_id','thread_id',result->'thread_id');
END $$;

CREATE FUNCTION secureshop_agents.verify_bound_lab_mail_cleanup(requested_target uuid, requested_operation uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE r secureshop_agents.lab_mail_cleanup_receipts%ROWTYPE; evidence bytea; retained integer;
BEGIN
 IF NOT EXISTS(SELECT 1 FROM secureshop_agents.lab_mail_targets WHERE target_id=requested_target) THEN
  RETURN jsonb_build_object('provisioned',false); END IF;
 SELECT * INTO r FROM secureshop_agents.lab_mail_cleanup_receipts WHERE target_id=requested_target AND operation_id=requested_operation;
 SELECT count(*),sha256(convert_to(COALESCE(jsonb_agg(jsonb_build_array(operation_id,encode(request_sha256,'hex'),result)
  ORDER BY operation_id)::text,'[]'),'UTF8')) INTO retained,evidence
 FROM secureshop_agents.lab_mail_operation_receipts WHERE target_id=requested_target;
 IF r.target_id IS NULL OR r.retained_operation_count<>retained OR r.evidence_sha256<>evidence
  OR r.receipt_sha256<>sha256(convert_to(concat_ws(chr(31),'lab-mail-cleanup-v1',r.operation_id::text,r.target_id::text,
   r.deleted_message_count::text,r.retained_operation_count::text,encode(evidence,'hex')),'UTF8'))
  OR EXISTS(SELECT 1 FROM secureshop_agents.lab_mail_messages WHERE target_id=requested_target)
  OR NOT EXISTS(SELECT 1 FROM secureshop_agents.persona_inbox_cleanup_receipts c
   JOIN secureshop_agents.persona_inbox_targets t USING(target_id)
   WHERE c.operation_id=requested_operation AND c.target_id=requested_target AND t.lifecycle='retired')
 THEN RAISE EXCEPTION 'Mail cleanup receipt mismatch' USING ERRCODE='55000'; END IF;
 RETURN jsonb_build_object('provisioned',true,'operationId',r.operation_id,'targetId',r.target_id,
  'deletedMessageCount',r.deleted_message_count,'retainedOperationCount',r.retained_operation_count,
  'evidenceSha256',encode(evidence,'hex'),'receiptSha256',encode(r.receipt_sha256,'hex'));
END $$;
REVOKE ALL ON FUNCTION secureshop_agents.verify_bound_lab_mail_cleanup(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_agents.verify_bound_lab_mail_cleanup(uuid,uuid) TO dvaia_secureshop_agents_runtime;

REVOKE ALL ON TABLE secureshop_agents.lab_mail_targets,secureshop_agents.lab_mail_messages,
 secureshop_agents.lab_mail_operation_receipts,secureshop_agents.lab_mail_cleanup_receipts FROM PUBLIC,dvaia_secureshop_agents_runtime;
GRANT SELECT ON secureshop_agents.lab_mail_targets,secureshop_agents.lab_mail_operation_receipts,
 secureshop_agents.lab_mail_cleanup_receipts TO dvaia_secureshop_agents_runtime;
REVOKE ALL ON SEQUENCE secureshop_agents.lab_mail_messages_message_id_seq FROM PUBLIC,dvaia_secureshop_agents_runtime;
REVOKE ALL ON FUNCTION secureshop_agents.guard_lab_mail_immutable(),secureshop_agents.cleanup_bound_lab_mail() FROM PUBLIC,dvaia_secureshop_agents_runtime;
REVOKE ALL ON FUNCTION secureshop_agents.bound_lab_mail(uuid,uuid,uuid,bigint,integer,integer,integer,uuid,text,bigint,text,uuid,text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_agents.bound_lab_mail(uuid,uuid,uuid,bigint,integer,integer,integer,uuid,text,bigint,text,uuid,text,jsonb) TO dvaia_secureshop_agents_runtime;
