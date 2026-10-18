-- Project a bounded view of an immutable mail-read receipt. The runtime role
-- never receives SELECT on lab_mail_messages, and this function never creates
-- a browse, read, send, or provisioning effect.
CREATE FUNCTION secureshop_agents.project_bound_lab_mail_read(
 requested_target uuid,requested_launch uuid,requested_scenario uuid,
 requested_generation bigint,requested_owner integer,requested_session integer,
 requested_caller integer,requested_persona_session uuid,requested_role text,
 requested_authority_version bigint,requested_mode text,requested_operation uuid,
 requested_grant uuid,requested_message bigint,requested_offset integer)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE recovered jsonb; saved jsonb; entries jsonb; selected jsonb;
recipient integer; total integer; next_offset integer; item jsonb;
message secureshop_agents.lab_mail_messages%ROWTYPE;
headers jsonb:='[]'::jsonb; detail jsonb; source_bytes integer;
receipt_sha text;
BEGIN
 IF requested_role IS DISTINCT FROM 'merchant' OR requested_offset IS NULL OR requested_offset<0
  OR requested_offset>1020 OR requested_offset%5<>0
  OR (requested_message IS NOT NULL AND requested_offset<>0)
  OR (requested_message IS NOT NULL AND requested_message<1)
 THEN RAISE EXCEPTION 'Invalid mail projection request' USING ERRCODE='22023'; END IF;
 recovered:=secureshop_agents.bound_lab_mail(requested_target,requested_launch,
  requested_scenario,requested_generation,requested_owner,requested_session,
  requested_caller,requested_persona_session,requested_role,
  requested_authority_version,requested_mode,requested_operation,'recover',
  '{}'::jsonb,requested_grant);
 IF COALESCE(recovered->>'found','false')<>'true' THEN RETURN NULL; END IF;
 IF recovered->>'action'<>'read' OR recovered->>'operationId'<>requested_operation::text
  OR jsonb_typeof(recovered->'receipt') IS DISTINCT FROM 'object'
  OR COALESCE(recovered->>'requestSha256','') !~ '^[0-9a-f]{64}$'
 THEN RAISE EXCEPTION 'Saved mail read mismatch' USING ERRCODE='55000'; END IF;
 saved:=recovered->'receipt';
 IF saved-ARRAY['userId','messages']<>'{}'::jsonb
  OR jsonb_typeof(saved->'userId') IS DISTINCT FROM 'number'
  OR jsonb_typeof(saved->'messages') IS DISTINCT FROM 'array'
  OR jsonb_array_length(saved->'messages')>1024
 THEN RAISE EXCEPTION 'Saved mail read shape mismatch' USING ERRCODE='55000'; END IF;
 recipient:=(saved->>'userId')::integer;
 IF recipient<1 OR NOT secureshop_agents.bound_actor_in_owner(recipient,requested_owner)
  OR (requested_mode='fixed' AND recipient<>requested_caller)
  OR recovered->>'requestSha256'<>encode(sha256(convert_to(
   jsonb_build_array('read',jsonb_build_object('userId',recipient))::text,'UTF8')),'hex')
 THEN RAISE EXCEPTION 'Saved mail read owner mismatch' USING ERRCODE='42501'; END IF;
 total:=jsonb_array_length(saved->'messages');
 IF EXISTS (
  SELECT 1 FROM jsonb_array_elements(saved->'messages') AS member(value)
  WHERE jsonb_typeof(member.value) IS DISTINCT FROM 'object'
   OR member.value-ARRAY['id','sha256']<>'{}'::jsonb
   OR jsonb_typeof(member.value->'id') IS DISTINCT FROM 'number'
   OR COALESCE(member.value->>'sha256','') !~ '^[0-9a-f]{64}$'
 ) OR (SELECT count(DISTINCT member.value->>'id')
       FROM jsonb_array_elements(saved->'messages') AS member(value))<>total
 THEN RAISE EXCEPTION 'Saved mail membership mismatch' USING ERRCODE='55000'; END IF;
 -- Verify the complete saved membership, including entries outside this page.
 -- A mutable row/hash pair cannot replace the original immutable send request.
 IF EXISTS (
  SELECT 1 FROM jsonb_array_elements(saved->'messages') AS entry(value)
  LEFT JOIN secureshop_agents.lab_mail_messages m
   ON m.target_id=requested_target AND m.message_id=(entry.value->>'id')::bigint
  WHERE m.message_id IS NULL OR m.recipient_id<>recipient
   OR encode(m.content_sha256,'hex') IS DISTINCT FROM entry.value->>'sha256'
   OR NOT EXISTS (
    SELECT 1 FROM secureshop_agents.lab_mail_operation_receipts sent
    CROSS JOIN LATERAL (SELECT jsonb_build_object(
     'from',m.from_addr,'to',m.to_addr,'subject',m.subject,
     'body_markdown',m.body_markdown,'body_html',m.body_html,
     'headers_raw',m.headers_raw) AS base) fields
    CROSS JOIN LATERAL (VALUES (fields.base),
     (fields.base||jsonb_build_object('threadId',m.thread_id))) candidate(payload)
    WHERE sent.target_id=m.target_id AND sent.action='send'
     AND sent.caller_id=m.sender_id
     AND sent.result->>'email_id'=m.message_id::text
     AND sent.result->>'thread_id'=m.thread_id::text
     AND sent.result->>'senderId'=m.sender_id::text
     AND sent.result->>'recipientId'=m.recipient_id::text
     AND sent.result->>'contentSha256'=encode(m.content_sha256,'hex')
     AND m.content_sha256=sha256(convert_to(candidate.payload::text,'UTF8'))
     AND sent.request_sha256=sha256(convert_to(
      jsonb_build_array('send',candidate.payload)::text,'UTF8'))
   )
 ) THEN RAISE EXCEPTION 'Saved mail content mismatch' USING ERRCODE='55000'; END IF;
 receipt_sha:=encode(sha256(convert_to(saved::text,'UTF8')),'hex');
 IF requested_message IS NULL THEN
  SELECT COALESCE(jsonb_agg(value ORDER BY ordinal DESC),'[]'::jsonb) INTO entries
  FROM (SELECT value,ordinal
   FROM jsonb_array_elements(saved->'messages') WITH ORDINALITY AS member(value,ordinal)
   ORDER BY ordinal DESC OFFSET requested_offset LIMIT 5) page;
  FOR item IN SELECT value FROM jsonb_array_elements(entries) AS member(value) LOOP
   SELECT * INTO message FROM secureshop_agents.lab_mail_messages m
   WHERE m.target_id=requested_target AND m.message_id=(item->>'id')::bigint;
   headers:=headers||jsonb_build_array(jsonb_build_object(
    'id',message.message_id,'threadId',message.thread_id,
    'from',message.from_addr,'to',message.to_addr,'subject',message.subject,
    'createdAt',message.created_at,'sha256',item->>'sha256'));
  END LOOP;
  next_offset:=CASE WHEN requested_offset+5<total THEN requested_offset+5 ELSE NULL END;
  RETURN jsonb_build_object('kind','page','readOperationId',requested_operation,
   'recipientId',recipient,'receiptSha256',receipt_sha,'total',total,
   'offset',requested_offset,'headers',headers,'nextOffset',next_offset);
 END IF;
 SELECT value INTO selected FROM jsonb_array_elements(saved->'messages') AS member(value)
 WHERE (value->>'id')::bigint=requested_message;
 IF selected IS NULL THEN RAISE EXCEPTION 'Mail message not in saved read' USING ERRCODE='42501'; END IF;
 SELECT * INTO message FROM secureshop_agents.lab_mail_messages m
 WHERE m.target_id=requested_target AND m.message_id=requested_message;
 source_bytes:=octet_length(COALESCE(message.body_markdown,''))
  +octet_length(COALESCE(message.body_html,''))
  +octet_length(COALESCE(message.headers_raw,''));
 detail:=jsonb_build_object('id',message.message_id,'threadId',message.thread_id,
  'from',message.from_addr,'to',message.to_addr,'subject',message.subject,
  'createdAt',message.created_at,'sha256',selected->>'sha256',
  'bodyMarkdown',CASE WHEN source_bytes>16384 THEN NULL ELSE message.body_markdown END,
  'bodyHtml',CASE WHEN source_bytes>16384 THEN NULL ELSE message.body_html END,
  'headersRaw',CASE WHEN source_bytes>16384 THEN NULL ELSE message.headers_raw END,
  'sourceBytes',source_bytes,'oversized',source_bytes>16384);
 RETURN jsonb_build_object('kind','detail','readOperationId',requested_operation,
  'recipientId',recipient,'receiptSha256',receipt_sha,'total',total,'message',detail);
END $$;
REVOKE ALL ON FUNCTION secureshop_agents.project_bound_lab_mail_read(
 uuid,uuid,uuid,bigint,integer,integer,integer,uuid,text,bigint,text,uuid,uuid,bigint,integer)
 FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_agents.project_bound_lab_mail_read(
 uuid,uuid,uuid,bigint,integer,integer,integer,uuid,text,bigint,text,uuid,uuid,bigint,integer)
 TO dvaia_secureshop_agents_runtime;
