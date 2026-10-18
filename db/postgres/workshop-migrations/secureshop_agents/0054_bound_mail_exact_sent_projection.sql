-- Read one attested saved send for its exact current actor and scene. This is
-- neither an inbox change nor an enumerable sent-mail collection.
CREATE FUNCTION secureshop_agents.project_bound_lab_mail_send(
 requested_target uuid,requested_launch uuid,requested_scenario uuid,
 requested_generation bigint,requested_owner integer,requested_session integer,
 requested_caller integer,requested_persona_session uuid,requested_role text,
 requested_authority_version bigint,requested_mode text,requested_operation uuid,
 requested_grant uuid)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE recovered jsonb; saved jsonb; message secureshop_agents.lab_mail_messages%ROWTYPE;
candidate jsonb; matched boolean:=false;
BEGIN
 recovered:=secureshop_agents.bound_lab_mail(requested_target,requested_launch,
  requested_scenario,requested_generation,requested_owner,requested_session,
  requested_caller,requested_persona_session,requested_role,
  requested_authority_version,requested_mode,requested_operation,'recover',
  '{}'::jsonb,requested_grant);
 IF COALESCE(recovered->>'found','false')<>'true' THEN RETURN NULL; END IF;
 IF recovered->>'action'<>'send' OR recovered->>'operationId'<>requested_operation::text
  OR jsonb_typeof(recovered->'receipt')<>'object' THEN
  RAISE EXCEPTION 'Saved mail receipt mismatch' USING ERRCODE='55000';
 END IF;
 saved:=recovered->'receipt';
 IF jsonb_typeof(saved->'email_id') IS DISTINCT FROM 'number'
  OR jsonb_typeof(saved->'thread_id') IS DISTINCT FROM 'number'
  OR jsonb_typeof(saved->'senderId') IS DISTINCT FROM 'number'
  OR jsonb_typeof(saved->'recipientId') IS DISTINCT FROM 'number'
  OR COALESCE(saved->>'contentSha256','') !~ '^[0-9a-f]{64}$'
  OR COALESCE(recovered->>'requestSha256','') !~ '^[0-9a-f]{64}$' THEN
  RAISE EXCEPTION 'Saved mail receipt shape mismatch' USING ERRCODE='55000';
 END IF;
 SELECT * INTO message FROM secureshop_agents.lab_mail_messages m
 WHERE m.target_id=requested_target AND m.message_id=(saved->>'email_id')::bigint;
 IF message.message_id IS NULL OR message.sender_id<>requested_caller
  OR message.thread_id IS DISTINCT FROM (saved->>'thread_id')::bigint
  OR message.sender_id IS DISTINCT FROM (saved->>'senderId')::integer
  OR message.recipient_id IS DISTINCT FROM (saved->>'recipientId')::integer
  OR encode(message.content_sha256,'hex') IS DISTINCT FROM saved->>'contentSha256' THEN
  RAISE EXCEPTION 'Saved mail row mismatch' USING ERRCODE='55000';
 END IF;
 -- A send can start a thread or reply within one. Recompute the original
 -- immutable request hash from the persisted row, never a model draft.
 candidate:=jsonb_build_object('from',message.from_addr,'to',message.to_addr,
  'subject',message.subject,'body_markdown',message.body_markdown,
  'body_html',message.body_html,'headers_raw',message.headers_raw);
 IF message.content_sha256=sha256(convert_to(candidate::text,'UTF8'))
  AND recovered->>'requestSha256'=encode(sha256(convert_to(
   jsonb_build_array('send',candidate)::text,'UTF8')),'hex') THEN matched:=true; END IF;
 candidate:=candidate||jsonb_build_object('threadId',message.thread_id);
 IF message.content_sha256=sha256(convert_to(candidate::text,'UTF8'))
  AND recovered->>'requestSha256'=encode(sha256(convert_to(
   jsonb_build_array('send',candidate)::text,'UTF8')),'hex') THEN matched:=true; END IF;
 IF NOT matched THEN RAISE EXCEPTION 'Saved mail content mismatch' USING ERRCODE='55000'; END IF;
 RETURN jsonb_build_object('recipientId',message.recipient_id,'to',message.to_addr,
  'subject',message.subject,'body_markdown',message.body_markdown);
END $$;
REVOKE ALL ON FUNCTION secureshop_agents.project_bound_lab_mail_send(
 uuid,uuid,uuid,bigint,integer,integer,integer,uuid,text,bigint,text,uuid,uuid)
 FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_agents.project_bound_lab_mail_send(
 uuid,uuid,uuid,bigint,integer,integer,integer,uuid,text,bigint,text,uuid,uuid)
 TO dvaia_secureshop_agents_runtime;
