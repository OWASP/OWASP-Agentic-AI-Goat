-- V55 summary graph owners begin at durable generation zero. Preserve the
-- immutable 0090 schema and replace only its incompatible positive-generation
-- predicate with the canonical nonnegative generation domain.
ALTER TABLE secureshop_agents.lab_mail_inline_http_invocations
  DROP CONSTRAINT lab_mail_inline_http_invocations_durable_generation_check,
  ADD CONSTRAINT lab_mail_inline_http_invocations_durable_generation_check
    CHECK (durable_generation >= 0);

CREATE OR REPLACE FUNCTION secureshop_agents.record_bound_mail_inline_http_invocation(
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
  OR requested_record_generation IS NULL OR requested_record_generation<0
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

REVOKE ALL ON FUNCTION secureshop_agents.record_bound_mail_inline_http_invocation(uuid,uuid,uuid,bigint,integer,integer,integer,uuid,text,bigint,uuid,uuid,uuid,text,bigint,uuid,text,text,uuid,bytea,bytea,uuid,uuid,bigint,bytea,bigint,integer,uuid,bytea,text,text,bytea,bytea,bytea,bytea,bytea)
 FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_agents.record_bound_mail_inline_http_invocation(uuid,uuid,uuid,bigint,integer,integer,integer,uuid,text,bigint,uuid,uuid,uuid,text,bigint,uuid,text,text,uuid,bytea,bytea,uuid,uuid,bigint,bytea,bigint,integer,uuid,bytea,text,text,bytea,bytea,bytea,bytea,bytea)
 TO dvaia_secureshop_agents_runtime;
