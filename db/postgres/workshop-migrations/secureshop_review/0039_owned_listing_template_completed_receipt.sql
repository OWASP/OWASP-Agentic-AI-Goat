-- Preserve 0038 checksum. A completed event repeats the immutable effect_received
-- receipt; only effect_received compares its executor request to the running decision.
CREATE OR REPLACE FUNCTION secureshop_review.append_owned_listing_template_event(
 requested_operation uuid,requested_event uuid,expected_sequence integer,
 requested_state text,requested_payload jsonb,requested_capability text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE admission secureshop_review.owned_listing_template_operations%ROWTYPE;
 prior secureshop_review.owned_listing_template_events%ROWTYPE; previous_state text;
 selected_grant secureshop_review.scene_execution_grants%ROWTYPE; current_context jsonb;
BEGIN
 IF requested_operation IS NULL OR requested_event IS NULL OR expected_sequence NOT BETWEEN 0 AND 7
  OR requested_state NOT IN ('running','declined','denied','unknown','effect_received','completed')
  OR requested_capability !~ '^[a-f0-9]{64}$'
 THEN RAISE EXCEPTION 'Listing template event invalid' USING ERRCODE='22023'; END IF;
 SELECT * INTO admission FROM secureshop_review.owned_listing_template_operations
  WHERE operation_id=requested_operation;
 IF NOT FOUND THEN RAISE EXCEPTION 'Listing template operation missing' USING ERRCODE='55000'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||admission.platform_owner_id::text,0));
 PERFORM pg_advisory_xact_lock(hashtextextended('owned-listing-template:'||requested_operation::text,0));
 SELECT * INTO admission FROM secureshop_review.owned_listing_template_operations
  WHERE operation_id=requested_operation FOR SHARE;
 IF admission.redacted_at IS NOT NULL OR admission.capability_sha256 IS DISTINCT FROM
  encode(sha256(convert_to(requested_capability,'UTF8')),'hex')
 THEN RAISE EXCEPTION 'Listing template operation denied' USING ERRCODE='42501'; END IF;
 SELECT * INTO selected_grant FROM secureshop_review.scene_execution_grants WHERE grant_id=admission.grant_id;
 IF NOT FOUND OR NOT secureshop_review.assert_scene_execution_grant(selected_grant.grant_id,
   selected_grant.scene_id,selected_grant.scene_generation,admission.target_id,admission.launch_id,admission.scenario_id,
   admission.generation,admission.platform_owner_id,admission.platform_session_id)
 THEN RAISE EXCEPTION 'Listing template scene unavailable' USING ERRCODE='42501'; END IF;
 SELECT * INTO prior FROM secureshop_review.owned_listing_template_events
  WHERE operation_id=requested_operation ORDER BY sequence DESC LIMIT 1;
 previous_state:=CASE WHEN FOUND THEN prior.state ELSE 'admitted' END;
 IF expected_sequence<>COALESCE(prior.sequence,0) OR NOT (
  (previous_state='admitted' AND requested_state IN ('running','declined','denied')) OR
  (previous_state='running' AND requested_state IN ('effect_received','unknown','denied')) OR
  (previous_state='effect_received' AND requested_state='completed'))
 THEN RAISE EXCEPTION 'Listing template transition conflict' USING ERRCODE='55000'; END IF;
 IF requested_state IN ('running','completed') THEN
  current_context:=secureshop_review.owned_listing_template_context(
   admission.target_id,admission.product_id,admission.merchant_id);
  IF encode(sha256(convert_to(current_context::text,'UTF8')),'hex') IS DISTINCT FROM admission.context_sha256
  THEN RAISE EXCEPTION 'Listing template source changed' USING ERRCODE='55000'; END IF;
 END IF;
 IF requested_state IN ('running','declined','denied') THEN
  IF jsonb_typeof(requested_payload) IS DISTINCT FROM 'object'
   OR requested_payload->>'operationId' IS DISTINCT FROM requested_operation::text
   OR requested_payload->>'productId' IS DISTINCT FROM admission.product_id::text
   OR requested_payload->>'requestSha256' IS DISTINCT FROM admission.request_sha256
   OR requested_payload#>>'{model,mocked}' IS DISTINCT FROM 'false'
   OR requested_payload#>>'{model,fallback}' IS DISTINCT FROM 'false'
   OR COALESCE(requested_payload#>>'{model,provider}','') ~* '^(|mock|fixture|scripted|fallback|unavailable)$'
   OR COALESCE(requested_payload#>>'{model,model}','') ~* '^(|mock|fixture|scripted|fallback|unavailable)$'
   OR COALESCE(requested_payload#>>'{model,callId}','')=''
   OR (requested_state='running' AND requested_payload->>'decision' IS DISTINCT FROM 'listing.render_template')
   OR (requested_state='running' AND COALESCE(requested_payload->>'executorRequestSha256','') !~ '^[a-f0-9]{64}$')
   OR (requested_state='denied' AND (admission.mode<>'fixed'
     OR requested_payload->>'decision' IS DISTINCT FROM 'listing.render_template'
     OR requested_payload->>'code' IS DISTINCT FROM 'LISTING_TEMPLATE_FIXED_DENIED'))
   OR (requested_state='declined' AND requested_payload->>'decision' IS DISTINCT FROM 'declined')
  THEN RAISE EXCEPTION 'Listing template model decision required' USING ERRCODE='22023'; END IF;
 END IF;
 IF requested_state='unknown' AND requested_payload IS NOT NULL
 THEN RAISE EXCEPTION 'Listing template unknown must retain uncertainty' USING ERRCODE='22023'; END IF;
 IF requested_state IN ('effect_received','completed') THEN
  IF jsonb_typeof(requested_payload) IS DISTINCT FROM 'object'
   OR requested_payload->>'operationId' IS DISTINCT FROM requested_operation::text
   OR requested_payload->>'productId' IS DISTINCT FROM admission.product_id::text
   OR requested_payload->>'sourceSha256' IS DISTINCT FROM admission.source_sha256
   OR requested_payload->>'contextSha256' IS DISTINCT FROM admission.context_sha256
   OR requested_payload->>'requestSha256' IS DISTINCT FROM admission.request_sha256
   OR requested_payload#>>'{effect,isolation}' IS DISTINCT FROM 'bwrap-listing-template-v1'
   OR requested_payload#>>'{effect,operationId}' IS DISTINCT FROM requested_operation::text
   OR requested_payload#>>'{effect,productId}' IS DISTINCT FROM admission.product_id::text
   OR requested_payload#>>'{effect,sourceSha256}' IS DISTINCT FROM admission.source_sha256
   OR (requested_state='effect_received' AND requested_payload#>>'{effect,requestSha256}' IS DISTINCT FROM prior.payload_json->>'executorRequestSha256')
   OR requested_payload#>>'{effect,exitCode}' IS DISTINCT FROM '0'
   OR requested_payload#>>'{effect,timedOut}' IS DISTINCT FROM 'false'
   OR requested_payload#>>'{effect,truncated}' IS DISTINCT FROM 'false'
   OR requested_payload#>>'{effect,workerAttested}' IS DISTINCT FROM 'true'
   OR requested_payload#>>'{effect,drained}' IS DISTINCT FROM 'true'
   OR requested_payload#>>'{effect,commandEffectObserved}' IS NULL
   OR requested_payload#>>'{effect,commandEffectObserved}' NOT IN ('true','false')
   OR (requested_payload#>>'{effect,commandEffectObserved}'='true'
     AND COALESCE(requested_payload#>>'{effect,effectSha256}','') !~ '^[a-f0-9]{64}$')
   OR (requested_payload#>>'{effect,commandEffectObserved}'='false'
     AND requested_payload#>'{effect,effectSha256}' IS DISTINCT FROM 'null'::jsonb)
   OR requested_payload#>>'{model,mocked}' IS DISTINCT FROM 'false'
   OR requested_payload#>>'{model,fallback}' IS DISTINCT FROM 'false'
   OR COALESCE(requested_payload#>>'{model,provider}','') ~* '^(|mock|fixture|scripted|fallback|unavailable)$'
   OR COALESCE(requested_payload#>>'{model,model}','') ~* '^(|mock|fixture|scripted|fallback|unavailable)$'
   OR (requested_state='effect_received' AND requested_payload->'model' IS DISTINCT FROM prior.payload_json->'model')
  THEN RAISE EXCEPTION 'Listing template effect receipt invalid' USING ERRCODE='22023'; END IF;
  IF requested_state='completed' AND (prior.payload_json IS DISTINCT FROM requested_payload
   OR prior.payload_sha256 IS DISTINCT FROM encode(sha256(convert_to(requested_payload::text,'UTF8')),'hex'))
  THEN RAISE EXCEPTION 'Listing template effect changed' USING ERRCODE='55000'; END IF;
  IF requested_state='effect_received' AND admission.mode<>'vuln'
  THEN RAISE EXCEPTION 'Fixed template execution denied' USING ERRCODE='42501'; END IF;
 END IF;
 INSERT INTO secureshop_review.owned_listing_template_events(
  operation_id,sequence,event_id,state,payload_json,payload_sha256)
 VALUES(requested_operation,expected_sequence+1,requested_event,requested_state,requested_payload,
  CASE WHEN requested_payload IS NULL THEN NULL ELSE encode(sha256(convert_to(requested_payload::text,'UTF8')),'hex') END);
END $$;
REVOKE ALL ON FUNCTION secureshop_review.append_owned_listing_template_event(uuid,uuid,integer,text,jsonb,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.append_owned_listing_template_event(uuid,uuid,integer,text,jsonb,text) TO dvaia_secureshop_review_runtime;
