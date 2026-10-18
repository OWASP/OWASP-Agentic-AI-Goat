-- V55 binds a pre-save owned listener reservation to an ordinary immutable mail
-- send without changing the v1 receipt JSON or generic mail send contract.
CREATE TABLE secureshop_agents.lab_mail_inline_bindings (
  issuance_id uuid PRIMARY KEY,
  send_operation_id uuid NOT NULL UNIQUE REFERENCES secureshop_agents.lab_mail_operation_receipts(operation_id),
  target_id uuid NOT NULL REFERENCES secureshop_agents.persona_inbox_targets(target_id),
  message_id bigint NOT NULL,
  message_sha256 bytea NOT NULL CHECK(octet_length(message_sha256)=32),
  thread_id bigint NOT NULL CHECK(thread_id>0),
  recipient_id integer NOT NULL CHECK(recipient_id>0),
  listener_target_id uuid NOT NULL,
  nonce_sha256 bytea NOT NULL CHECK(octet_length(nonce_sha256)=32),
  path text NOT NULL CHECK(octet_length(path) BETWEEN 1 AND 1024 AND path ~ '^/[A-Za-z0-9._~/-]*$'),
  resource_kind text NOT NULL CHECK(resource_kind='mail_inline_image_v1'),
  url_sha256 bytea NOT NULL CHECK(octet_length(url_sha256)=32),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(target_id,message_id)
);
CREATE INDEX lab_mail_inline_bindings_target_message ON secureshop_agents.lab_mail_inline_bindings(target_id,message_id);

CREATE FUNCTION secureshop_agents.guard_lab_mail_inline_binding_immutable() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
BEGIN RAISE EXCEPTION 'Immutable mail inline binding' USING ERRCODE='55000'; END $$;
CREATE TRIGGER lab_mail_inline_bindings_immutable BEFORE UPDATE OR DELETE
 ON secureshop_agents.lab_mail_inline_bindings FOR EACH ROW
 EXECUTE FUNCTION secureshop_agents.guard_lab_mail_inline_binding_immutable();

-- This is private: callers first verify the opaque pending listener capability.
-- The ordinary send and binding insert share the same SQL function transaction
-- and the target/grant lock held by mapped bound_lab_mail.
CREATE FUNCTION secureshop_agents.save_bound_mail_inline(
 requested_target uuid,requested_launch uuid,requested_scenario uuid,requested_generation bigint,
 requested_owner integer,requested_session integer,requested_caller integer,requested_persona_session uuid,
 requested_role text,requested_authority_version bigint,requested_mode text,requested_operation uuid,
 requested_grant uuid,requested_payload jsonb,requested_issuance uuid,requested_listener_target uuid,
 requested_nonce_sha256 bytea,requested_path text,requested_resource_kind text,requested_url_sha256 bytea
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE sent jsonb; prior secureshop_agents.lab_mail_inline_bindings%ROWTYPE; msg secureshop_agents.lab_mail_messages%ROWTYPE;
DECLARE got_sha bytea; got_message bigint; got_thread bigint; got_recipient integer;
BEGIN
 IF requested_role IS DISTINCT FROM 'merchant' THEN RAISE EXCEPTION 'Inline mail role unavailable' USING ERRCODE='42501'; END IF;
 IF requested_issuance IS NULL OR requested_listener_target IS NULL OR requested_nonce_sha256 IS NULL
  OR octet_length(requested_nonce_sha256)<>32 OR requested_url_sha256 IS NULL OR octet_length(requested_url_sha256)<>32
  OR requested_resource_kind IS DISTINCT FROM 'mail_inline_image_v1' OR requested_path IS NULL
  OR octet_length(requested_path) NOT BETWEEN 1 AND 1024 OR requested_path !~ '^/[A-Za-z0-9._~/-]*$'
 THEN RAISE EXCEPTION 'Invalid inline issuance' USING ERRCODE='22023'; END IF;
 sent:=secureshop_agents.bound_lab_mail(requested_target,requested_launch,requested_scenario,requested_generation,
  requested_owner,requested_session,requested_caller,requested_persona_session,requested_role,
  requested_authority_version,requested_mode,requested_operation,'send',requested_payload,requested_grant);
 IF COALESCE(sent->>'ok','false')<>'true' OR sent->>'operationId'<>requested_operation::text
  OR jsonb_typeof(sent->'receipt') IS DISTINCT FROM 'object'
  OR COALESCE(sent->'receipt'->>'email_id','') !~ '^[1-9][0-9]*$'
  OR COALESCE(sent->'receipt'->>'thread_id','') !~ '^[1-9][0-9]*$'
  OR COALESCE(sent->'receipt'->>'recipientId','') !~ '^[1-9][0-9]*$'
  OR COALESCE(sent->'receipt'->>'contentSha256','') !~ '^[0-9a-f]{64}$'
 THEN RAISE EXCEPTION 'Inline mail receipt unavailable' USING ERRCODE='55000'; END IF;
 got_message:=(sent->'receipt'->>'email_id')::bigint; got_thread:=(sent->'receipt'->>'thread_id')::bigint;
 got_recipient:=(sent->'receipt'->>'recipientId')::integer; got_sha:=decode(sent->'receipt'->>'contentSha256','hex');
 SELECT * INTO msg FROM secureshop_agents.lab_mail_messages m WHERE m.target_id=requested_target AND m.message_id=got_message FOR SHARE;
 IF msg.message_id IS NULL OR msg.thread_id<>got_thread OR msg.recipient_id<>got_recipient OR msg.content_sha256<>got_sha
 THEN RAISE EXCEPTION 'Inline mail message mismatch' USING ERRCODE='55000'; END IF;
 SELECT * INTO prior FROM secureshop_agents.lab_mail_inline_bindings b WHERE b.send_operation_id=requested_operation FOR UPDATE;
 IF prior.send_operation_id IS NOT NULL THEN
  IF prior.issuance_id IS DISTINCT FROM requested_issuance OR prior.target_id IS DISTINCT FROM requested_target OR prior.message_id IS DISTINCT FROM got_message
   OR prior.message_sha256 IS DISTINCT FROM got_sha OR prior.thread_id IS DISTINCT FROM got_thread OR prior.recipient_id IS DISTINCT FROM got_recipient
   OR prior.listener_target_id IS DISTINCT FROM requested_listener_target OR prior.nonce_sha256 IS DISTINCT FROM requested_nonce_sha256
   OR prior.path IS DISTINCT FROM requested_path OR prior.resource_kind IS DISTINCT FROM requested_resource_kind OR prior.url_sha256 IS DISTINCT FROM requested_url_sha256
  THEN RAISE EXCEPTION 'Inline mail binding conflict' USING ERRCODE='23505'; END IF;
 ELSIF COALESCE(sent->>'replayed','false')='true' THEN
  RAISE EXCEPTION 'Unbound historical mail send' USING ERRCODE='55000';
 ELSE
  INSERT INTO secureshop_agents.lab_mail_inline_bindings(issuance_id,send_operation_id,target_id,message_id,message_sha256,thread_id,recipient_id,listener_target_id,nonce_sha256,path,resource_kind,url_sha256)
  VALUES(requested_issuance,requested_operation,requested_target,got_message,got_sha,got_thread,got_recipient,requested_listener_target,requested_nonce_sha256,requested_path,requested_resource_kind,requested_url_sha256);
  SELECT * INTO prior FROM secureshop_agents.lab_mail_inline_bindings WHERE send_operation_id=requested_operation;
 END IF;
 RETURN jsonb_build_object('send',sent,'binding',jsonb_build_object('issuanceId',prior.issuance_id,
  'sendOperationId',prior.send_operation_id,'targetId',prior.target_id,'messageId',prior.message_id,
  'messageSha256',encode(prior.message_sha256,'hex'),'threadId',prior.thread_id,'recipientId',prior.recipient_id,
  'listenerTargetId',prior.listener_target_id,'nonceSha256',encode(prior.nonce_sha256,'hex'),
  'path',prior.path,'resourceKind',prior.resource_kind,'urlSha256',encode(prior.url_sha256,'hex')));
END $$;

CREATE FUNCTION secureshop_agents.read_bound_mail_inline_binding(
 requested_target uuid,requested_launch uuid,requested_scenario uuid,requested_generation bigint,
 requested_owner integer,requested_session integer,requested_caller integer,requested_persona_session uuid,
 requested_role text,requested_authority_version bigint,requested_grant uuid,
 requested_message bigint,requested_message_sha256 bytea,requested_recipient integer
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE grant_row secureshop_agents.mail_scene_execution_grants%ROWTYPE; target secureshop_agents.persona_inbox_targets%ROWTYPE;
DECLARE binding secureshop_agents.lab_mail_inline_bindings%ROWTYPE;
BEGIN
 IF requested_role IS DISTINCT FROM 'merchant' THEN RAISE EXCEPTION 'Inline mail role unavailable' USING ERRCODE='42501'; END IF;
 IF requested_message<1 OR requested_recipient<1 OR requested_message_sha256 IS NULL OR octet_length(requested_message_sha256)<>32 THEN
  RAISE EXCEPTION 'Invalid inline mail read' USING ERRCODE='22023'; END IF;
 SELECT * INTO grant_row FROM secureshop_agents.mail_scene_execution_grants g WHERE g.grant_id=requested_grant
  AND g.target_id=requested_target AND g.launch_id=requested_launch AND g.scenario_id=requested_scenario
  AND g.generation=requested_generation AND g.original_platform_owner_id=requested_owner
  AND g.original_platform_session_id=requested_session FOR SHARE;
 SELECT * INTO target FROM secureshop_agents.persona_inbox_targets WHERE target_id=requested_target FOR SHARE;
 IF grant_row.grant_id IS NULL OR target.target_id IS NULL OR target.lifecycle<>'active'
  OR NOT secureshop_agents.assert_mail_scene_execution_grant(grant_row.grant_id,grant_row.scene_id,grant_row.scene_generation,
   requested_target,requested_launch,requested_scenario,requested_generation,requested_owner,requested_session)
  OR NOT secureshop_agents.bound_mail_live_actor(requested_launch,requested_scenario,requested_generation,
   requested_owner,requested_session,requested_caller,requested_persona_session,requested_role,requested_authority_version)
 THEN RAISE EXCEPTION 'Inline mail authority unavailable' USING ERRCODE='42501'; END IF;
 SELECT * INTO binding FROM secureshop_agents.lab_mail_inline_bindings b WHERE b.target_id=requested_target
  AND b.message_id=requested_message AND b.message_sha256=requested_message_sha256 AND b.recipient_id=requested_recipient;
 IF binding.issuance_id IS NULL THEN RETURN NULL; END IF;
 RETURN jsonb_build_object('issuanceId',binding.issuance_id,'sendOperationId',binding.send_operation_id,
  'targetId',binding.target_id,'messageId',binding.message_id,'messageSha256',encode(binding.message_sha256,'hex'),
  'threadId',binding.thread_id,'recipientId',binding.recipient_id,'listenerTargetId',binding.listener_target_id,
  'nonceSha256',encode(binding.nonce_sha256,'hex'),'path',binding.path,'resourceKind',binding.resource_kind,
  'urlSha256',encode(binding.url_sha256,'hex'));
END $$;


-- The listener receipt must be recorded durably before its one-shot capability
-- is consumed. This keeps the exact HTTP proof out of bounded graph traces.
CREATE TABLE secureshop_agents.lab_mail_inline_http_invocations (
  summary_request_id uuid PRIMARY KEY,
  target_id uuid NOT NULL REFERENCES secureshop_agents.persona_inbox_targets(target_id),
  issuance_id uuid NOT NULL REFERENCES secureshop_agents.lab_mail_inline_bindings(issuance_id),
  send_operation_id uuid NOT NULL REFERENCES secureshop_agents.lab_mail_operation_receipts(operation_id),
  message_id bigint NOT NULL,
  message_sha256 bytea NOT NULL CHECK(octet_length(message_sha256)=32),
  thread_id bigint NOT NULL CHECK(thread_id>0),
  recipient_id integer NOT NULL CHECK(recipient_id>0),
  listener_target_id uuid NOT NULL,
  nonce_sha256 bytea NOT NULL CHECK(octet_length(nonce_sha256)=32),
  path text NOT NULL CHECK(octet_length(path) BETWEEN 1 AND 1024 AND path ~ '^/[A-Za-z0-9._~/-]*$'),
  resource_kind text NOT NULL CHECK(resource_kind='mail_inline_image_v1'),
  url_sha256 bytea NOT NULL CHECK(octet_length(url_sha256)=32),
  read_operation_id uuid NOT NULL,
  read_receipt_sha256 bytea NOT NULL CHECK(octet_length(read_receipt_sha256)=32),
  body_html_sha256 bytea NOT NULL CHECK(octet_length(body_html_sha256)=32),
  run_id uuid NOT NULL,
  owner_key text NOT NULL CHECK(octet_length(owner_key) BETWEEN 1 AND 1024),
  durable_generation bigint NOT NULL CHECK(durable_generation>=1),
  session_id uuid NOT NULL,
  call_id text NOT NULL CHECK(octet_length(call_id) BETWEEN 1 AND 128),
  effect_key text NOT NULL CHECK(octet_length(effect_key) BETWEEN 1 AND 1024),
  target_receipt_sha256 bytea NOT NULL CHECK(octet_length(target_receipt_sha256)=32),
  response_sha256 bytea NOT NULL CHECK(octet_length(response_sha256)=32),
  parsed_result_sha256 bytea NOT NULL CHECK(octet_length(parsed_result_sha256)=32),
  observation_sha256 bytea NOT NULL CHECK(octet_length(observation_sha256)=32),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE(target_id,issuance_id),
  UNIQUE(target_id,run_id,effect_key)
);
CREATE FUNCTION secureshop_agents.guard_lab_mail_inline_http_invocation_immutable() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
BEGIN RAISE EXCEPTION 'Immutable mail inline invocation' USING ERRCODE='55000'; END $$;
CREATE TRIGGER lab_mail_inline_http_invocations_immutable BEFORE UPDATE OR DELETE
 ON secureshop_agents.lab_mail_inline_http_invocations FOR EACH ROW
 EXECUTE FUNCTION secureshop_agents.guard_lab_mail_inline_http_invocation_immutable();

CREATE FUNCTION secureshop_agents.record_bound_mail_inline_http_invocation(
 requested_target uuid,requested_launch uuid,requested_scenario uuid,requested_generation bigint,
 requested_owner integer,requested_platform_session integer,requested_caller integer,requested_persona_session uuid,
 requested_role text,requested_authority_version bigint,requested_grant uuid,
 requested_summary_request uuid,requested_run uuid,requested_owner_key text,requested_record_generation bigint,
 requested_session uuid,requested_call text,requested_effect_key text,
 requested_read_operation uuid,requested_read_receipt_sha256 bytea,requested_body_html_sha256 bytea,
 requested_issuance uuid,requested_send_operation uuid,requested_message bigint,requested_message_sha256 bytea,
 requested_thread bigint,requested_recipient integer,requested_listener_target uuid,requested_nonce_sha256 bytea,
 requested_path text,requested_resource_kind text,requested_url_sha256 bytea,
 requested_target_receipt_sha256 bytea,requested_response_sha256 bytea,
 requested_parsed_result_sha256 bytea,requested_observation_sha256 bytea
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE grant_row secureshop_agents.mail_scene_execution_grants%ROWTYPE;
DECLARE target secureshop_agents.persona_inbox_targets%ROWTYPE;
DECLARE bound secureshop_agents.lab_mail_inline_bindings%ROWTYPE;
DECLARE prior secureshop_agents.lab_mail_inline_http_invocations%ROWTYPE;
BEGIN
 IF requested_role IS DISTINCT FROM 'merchant' OR requested_summary_request IS NULL OR requested_run IS NULL
  OR requested_session IS NULL OR requested_read_operation IS NULL OR requested_issuance IS NULL
  OR requested_summary_request=requested_issuance OR requested_summary_request=requested_send_operation
  OR requested_owner_key IS NULL OR octet_length(requested_owner_key) NOT BETWEEN 1 AND 1024
  OR requested_record_generation IS NULL OR requested_record_generation<1
  OR requested_call IS NULL OR octet_length(requested_call) NOT BETWEEN 1 AND 128
  OR requested_effect_key IS NULL OR octet_length(requested_effect_key) NOT BETWEEN 1 AND 1024
  OR requested_message IS NULL OR requested_message<1 OR requested_thread IS NULL OR requested_thread<1
  OR requested_recipient IS NULL OR requested_recipient<1
  OR requested_path IS NULL OR octet_length(requested_path) NOT BETWEEN 1 AND 1024
  OR requested_path !~ '^/[A-Za-z0-9._~/-]*$'
  OR requested_resource_kind IS DISTINCT FROM 'mail_inline_image_v1'
  OR requested_read_receipt_sha256 IS NULL OR octet_length(requested_read_receipt_sha256)<>32
  OR requested_body_html_sha256 IS NULL OR octet_length(requested_body_html_sha256)<>32
  OR requested_message_sha256 IS NULL OR octet_length(requested_message_sha256)<>32
  OR requested_nonce_sha256 IS NULL OR octet_length(requested_nonce_sha256)<>32
  OR requested_url_sha256 IS NULL OR octet_length(requested_url_sha256)<>32
  OR requested_target_receipt_sha256 IS NULL OR octet_length(requested_target_receipt_sha256)<>32
  OR requested_response_sha256 IS NULL OR octet_length(requested_response_sha256)<>32
  OR requested_parsed_result_sha256 IS NULL OR octet_length(requested_parsed_result_sha256)<>32
  OR requested_observation_sha256 IS NULL OR octet_length(requested_observation_sha256)<>32
 THEN RAISE EXCEPTION 'Invalid mail inline invocation' USING ERRCODE='22023'; END IF;
 SELECT * INTO grant_row FROM secureshop_agents.mail_scene_execution_grants g WHERE g.grant_id=requested_grant
  AND g.target_id=requested_target AND g.launch_id=requested_launch AND g.scenario_id=requested_scenario
  AND g.generation=requested_generation AND g.original_platform_owner_id=requested_owner
  AND g.original_platform_session_id=requested_platform_session FOR SHARE;
 SELECT * INTO target FROM secureshop_agents.persona_inbox_targets WHERE target_id=requested_target FOR SHARE;
 IF grant_row.grant_id IS NULL OR target.target_id IS NULL OR target.lifecycle<>'active'
  OR NOT secureshop_agents.assert_mail_scene_execution_grant(grant_row.grant_id,grant_row.scene_id,grant_row.scene_generation,
   requested_target,requested_launch,requested_scenario,requested_generation,requested_owner,requested_platform_session)
  OR NOT secureshop_agents.bound_mail_live_actor(requested_launch,requested_scenario,requested_generation,
   requested_owner,requested_platform_session,requested_caller,requested_persona_session,requested_role,requested_authority_version)
 THEN RAISE EXCEPTION 'Inline mail invocation authority unavailable' USING ERRCODE='42501'; END IF;
 SELECT * INTO bound FROM secureshop_agents.lab_mail_inline_bindings b WHERE b.issuance_id=requested_issuance FOR UPDATE;
 IF bound.issuance_id IS NULL OR bound.target_id IS DISTINCT FROM requested_target
  OR bound.send_operation_id IS DISTINCT FROM requested_send_operation
  OR bound.message_id IS DISTINCT FROM requested_message OR bound.message_sha256 IS DISTINCT FROM requested_message_sha256
  OR bound.thread_id IS DISTINCT FROM requested_thread OR bound.recipient_id IS DISTINCT FROM requested_recipient
  OR bound.listener_target_id IS DISTINCT FROM requested_listener_target OR bound.nonce_sha256 IS DISTINCT FROM requested_nonce_sha256
  OR bound.path IS DISTINCT FROM requested_path OR bound.resource_kind IS DISTINCT FROM requested_resource_kind
  OR bound.url_sha256 IS DISTINCT FROM requested_url_sha256
 THEN RAISE EXCEPTION 'Inline mail invocation binding mismatch' USING ERRCODE='55000'; END IF;
 SELECT * INTO prior FROM secureshop_agents.lab_mail_inline_http_invocations i WHERE i.summary_request_id=requested_summary_request FOR UPDATE;
 IF prior.summary_request_id IS NULL THEN
  IF EXISTS(SELECT 1 FROM secureshop_agents.lab_mail_inline_http_invocations i WHERE i.target_id=requested_target AND i.issuance_id=requested_issuance) THEN
   RAISE EXCEPTION 'Inline mail issuance already consumed' USING ERRCODE='23505';
  END IF;
  INSERT INTO secureshop_agents.lab_mail_inline_http_invocations(
   summary_request_id,target_id,issuance_id,send_operation_id,message_id,message_sha256,thread_id,recipient_id,
   listener_target_id,nonce_sha256,path,resource_kind,url_sha256,read_operation_id,read_receipt_sha256,body_html_sha256,
   run_id,owner_key,durable_generation,session_id,call_id,effect_key,target_receipt_sha256,response_sha256,
   parsed_result_sha256,observation_sha256
  ) VALUES(
   requested_summary_request,requested_target,requested_issuance,requested_send_operation,requested_message,requested_message_sha256,
   requested_thread,requested_recipient,requested_listener_target,requested_nonce_sha256,requested_path,requested_resource_kind,
   requested_url_sha256,requested_read_operation,requested_read_receipt_sha256,requested_body_html_sha256,requested_run,
   requested_owner_key,requested_record_generation,requested_session,requested_call,requested_effect_key,
   requested_target_receipt_sha256,requested_response_sha256,requested_parsed_result_sha256,requested_observation_sha256
  ) RETURNING * INTO prior;
 ELSIF prior.target_id IS DISTINCT FROM requested_target OR prior.issuance_id IS DISTINCT FROM requested_issuance
  OR prior.send_operation_id IS DISTINCT FROM requested_send_operation OR prior.message_id IS DISTINCT FROM requested_message
  OR prior.message_sha256 IS DISTINCT FROM requested_message_sha256 OR prior.thread_id IS DISTINCT FROM requested_thread
  OR prior.recipient_id IS DISTINCT FROM requested_recipient OR prior.listener_target_id IS DISTINCT FROM requested_listener_target
  OR prior.nonce_sha256 IS DISTINCT FROM requested_nonce_sha256 OR prior.path IS DISTINCT FROM requested_path
  OR prior.resource_kind IS DISTINCT FROM requested_resource_kind OR prior.url_sha256 IS DISTINCT FROM requested_url_sha256
  OR prior.read_operation_id IS DISTINCT FROM requested_read_operation OR prior.read_receipt_sha256 IS DISTINCT FROM requested_read_receipt_sha256
  OR prior.body_html_sha256 IS DISTINCT FROM requested_body_html_sha256 OR prior.run_id IS DISTINCT FROM requested_run
  OR prior.owner_key IS DISTINCT FROM requested_owner_key OR prior.durable_generation IS DISTINCT FROM requested_record_generation
  OR prior.session_id IS DISTINCT FROM requested_session OR prior.call_id IS DISTINCT FROM requested_call
  OR prior.effect_key IS DISTINCT FROM requested_effect_key OR prior.target_receipt_sha256 IS DISTINCT FROM requested_target_receipt_sha256
  OR prior.response_sha256 IS DISTINCT FROM requested_response_sha256 OR prior.parsed_result_sha256 IS DISTINCT FROM requested_parsed_result_sha256
  OR prior.observation_sha256 IS DISTINCT FROM requested_observation_sha256
 THEN RAISE EXCEPTION 'Inline mail invocation conflict' USING ERRCODE='23505'; END IF;
 RETURN jsonb_build_object('version',1,
  'binding',jsonb_build_object('issuanceId',prior.issuance_id,'sendOperationId',prior.send_operation_id,'targetId',prior.target_id,
   'messageId',prior.message_id,'messageSha256',encode(prior.message_sha256,'hex'),'threadId',prior.thread_id,
   'recipientId',prior.recipient_id,'listenerTargetId',prior.listener_target_id,'nonceSha256',encode(prior.nonce_sha256,'hex'),
   'path',prior.path,'resourceKind',prior.resource_kind,'urlSha256',encode(prior.url_sha256,'hex')),
  'source',jsonb_build_object('readOperationId',prior.read_operation_id,'receiptSha256',encode(prior.read_receipt_sha256,'hex'),
   'bodyHtmlSha256',encode(prior.body_html_sha256,'hex')),
  'targetReceipt',jsonb_build_object('version',1,'issuanceId',prior.issuance_id,'sendOperationId',prior.send_operation_id,
   'targetId',prior.target_id,'listenerTargetId',prior.listener_target_id,'nonceSha256',encode(prior.nonce_sha256,'hex'),
   'path',prior.path,'resourceKind',prior.resource_kind,'urlSha256',encode(prior.url_sha256,'hex'),
   'method','GET','status',200,'responseSha256',encode(prior.response_sha256,'hex'),'receiptSha256',encode(prior.target_receipt_sha256,'hex')),
  'runId',prior.run_id,'ownerKey',prior.owner_key,'generation',prior.durable_generation::text,'sessionId',prior.session_id,
  'summaryRequestId',prior.summary_request_id,'callId',prior.call_id,'effectKey',prior.effect_key,
  'parsedResultSha256',encode(prior.parsed_result_sha256,'hex'),'observationSha256',encode(prior.observation_sha256,'hex'));
END $$;

CREATE FUNCTION secureshop_agents.read_bound_mail_inline_http_invocation(
 requested_target uuid,requested_launch uuid,requested_scenario uuid,requested_generation bigint,
 requested_owner integer,requested_platform_session integer,requested_caller integer,requested_persona_session uuid,
 requested_role text,requested_authority_version bigint,requested_grant uuid,requested_summary_request uuid
) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE grant_row secureshop_agents.mail_scene_execution_grants%ROWTYPE;
DECLARE target secureshop_agents.persona_inbox_targets%ROWTYPE;
DECLARE prior secureshop_agents.lab_mail_inline_http_invocations%ROWTYPE;
BEGIN
 IF requested_role IS DISTINCT FROM 'merchant' OR requested_summary_request IS NULL THEN
  RAISE EXCEPTION 'Inline mail invocation authority unavailable' USING ERRCODE='42501'; END IF;
 SELECT * INTO grant_row FROM secureshop_agents.mail_scene_execution_grants g WHERE g.grant_id=requested_grant
  AND g.target_id=requested_target AND g.launch_id=requested_launch AND g.scenario_id=requested_scenario
  AND g.generation=requested_generation AND g.original_platform_owner_id=requested_owner
  AND g.original_platform_session_id=requested_platform_session FOR SHARE;
 SELECT * INTO target FROM secureshop_agents.persona_inbox_targets WHERE target_id=requested_target FOR SHARE;
 IF grant_row.grant_id IS NULL OR target.target_id IS NULL OR target.lifecycle<>'active'
  OR NOT secureshop_agents.assert_mail_scene_execution_grant(grant_row.grant_id,grant_row.scene_id,grant_row.scene_generation,
   requested_target,requested_launch,requested_scenario,requested_generation,requested_owner,requested_platform_session)
  OR NOT secureshop_agents.bound_mail_live_actor(requested_launch,requested_scenario,requested_generation,
   requested_owner,requested_platform_session,requested_caller,requested_persona_session,requested_role,requested_authority_version)
 THEN RAISE EXCEPTION 'Inline mail invocation authority unavailable' USING ERRCODE='42501'; END IF;
 SELECT * INTO prior FROM secureshop_agents.lab_mail_inline_http_invocations i WHERE i.target_id=requested_target
  AND i.summary_request_id=requested_summary_request;
 IF prior.summary_request_id IS NULL THEN RETURN NULL; END IF;
 RETURN jsonb_build_object('version',1,
  'binding',jsonb_build_object('issuanceId',prior.issuance_id,'sendOperationId',prior.send_operation_id,'targetId',prior.target_id,
   'messageId',prior.message_id,'messageSha256',encode(prior.message_sha256,'hex'),'threadId',prior.thread_id,
   'recipientId',prior.recipient_id,'listenerTargetId',prior.listener_target_id,'nonceSha256',encode(prior.nonce_sha256,'hex'),
   'path',prior.path,'resourceKind',prior.resource_kind,'urlSha256',encode(prior.url_sha256,'hex')),
  'source',jsonb_build_object('readOperationId',prior.read_operation_id,'receiptSha256',encode(prior.read_receipt_sha256,'hex'),
   'bodyHtmlSha256',encode(prior.body_html_sha256,'hex')),
  'targetReceipt',jsonb_build_object('version',1,'issuanceId',prior.issuance_id,'sendOperationId',prior.send_operation_id,
   'targetId',prior.target_id,'listenerTargetId',prior.listener_target_id,'nonceSha256',encode(prior.nonce_sha256,'hex'),
   'path',prior.path,'resourceKind',prior.resource_kind,'urlSha256',encode(prior.url_sha256,'hex'),
   'method','GET','status',200,'responseSha256',encode(prior.response_sha256,'hex'),'receiptSha256',encode(prior.target_receipt_sha256,'hex')),
  'runId',prior.run_id,'ownerKey',prior.owner_key,'generation',prior.durable_generation::text,'sessionId',prior.session_id,
  'summaryRequestId',prior.summary_request_id,'callId',prior.call_id,'effectKey',prior.effect_key,
  'parsedResultSha256',encode(prior.parsed_result_sha256,'hex'),'observationSha256',encode(prior.observation_sha256,'hex'));
END $$;

REVOKE ALL ON secureshop_agents.lab_mail_inline_bindings,secureshop_agents.lab_mail_inline_http_invocations
 FROM PUBLIC,dvaia_secureshop_agents_runtime;
REVOKE ALL ON FUNCTION secureshop_agents.guard_lab_mail_inline_binding_immutable(),
 secureshop_agents.guard_lab_mail_inline_http_invocation_immutable(),
 secureshop_agents.save_bound_mail_inline(uuid,uuid,uuid,bigint,integer,integer,integer,uuid,text,bigint,text,uuid,uuid,jsonb,uuid,uuid,bytea,text,text,bytea),
 secureshop_agents.read_bound_mail_inline_binding(uuid,uuid,uuid,bigint,integer,integer,integer,uuid,text,bigint,uuid,bigint,bytea,integer),
 secureshop_agents.record_bound_mail_inline_http_invocation(uuid,uuid,uuid,bigint,integer,integer,integer,uuid,text,bigint,uuid,uuid,uuid,text,bigint,uuid,text,text,uuid,bytea,bytea,uuid,uuid,bigint,bytea,bigint,integer,uuid,bytea,text,text,bytea,bytea,bytea,bytea,bytea),
 secureshop_agents.read_bound_mail_inline_http_invocation(uuid,uuid,uuid,bigint,integer,integer,integer,uuid,text,bigint,uuid,uuid)
 FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_agents.save_bound_mail_inline(uuid,uuid,uuid,bigint,integer,integer,integer,uuid,text,bigint,text,uuid,uuid,jsonb,uuid,uuid,bytea,text,text,bytea),
 secureshop_agents.read_bound_mail_inline_binding(uuid,uuid,uuid,bigint,integer,integer,integer,uuid,text,bigint,uuid,bigint,bytea,integer),
 secureshop_agents.record_bound_mail_inline_http_invocation(uuid,uuid,uuid,bigint,integer,integer,integer,uuid,text,bigint,uuid,uuid,uuid,text,bigint,uuid,text,text,uuid,bytea,bytea,uuid,uuid,bigint,bytea,bigint,integer,uuid,bytea,text,text,bytea,bytea,bytea,bytea,bytea),
 secureshop_agents.read_bound_mail_inline_http_invocation(uuid,uuid,uuid,bigint,integer,integer,integer,uuid,text,bigint,uuid,uuid)
 TO dvaia_secureshop_agents_runtime;
