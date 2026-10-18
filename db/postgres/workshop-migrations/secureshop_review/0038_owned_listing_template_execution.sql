-- Product-scoped template execution has a separate journal. The 0037 import
-- and rewrite state machine, its receipts, and prior learner evidence stay
-- byte-for-byte unchanged.
CREATE TABLE secureshop_review.owned_listing_template_operations (
 operation_id uuid PRIMARY KEY,
 target_id uuid NOT NULL REFERENCES secureshop_review.product_targets(target_id),
 grant_id uuid NOT NULL REFERENCES secureshop_review.scene_execution_grants(grant_id),
 product_id integer NOT NULL CHECK(product_id>0),
 merchant_id integer NOT NULL CHECK(merchant_id>=1000000000),
 launch_id uuid NOT NULL,
 scenario_id uuid NOT NULL,
 generation bigint NOT NULL CHECK(generation BETWEEN 1 AND 9007199254740991),
 platform_owner_id integer NOT NULL CHECK(platform_owner_id>0),
 platform_session_id integer NOT NULL CHECK(platform_session_id>0),
 persona_session_id uuid NOT NULL,
 authority_version bigint NOT NULL CHECK(authority_version BETWEEN 1 AND 9007199254740991),
 mode text NOT NULL CHECK(mode IN ('vuln','fixed')),
 request_sha256 text NOT NULL CHECK(request_sha256 ~ '^[a-f0-9]{64}$'),
 source_sha256 text NOT NULL CHECK(source_sha256 ~ '^[a-f0-9]{64}$'),
 context_sha256 text NOT NULL CHECK(context_sha256 ~ '^[a-f0-9]{64}$'),
 context_json jsonb,
 capability_sha256 text NOT NULL CHECK(capability_sha256 ~ '^[a-f0-9]{64}$'),
 admitted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 redacted_at timestamptz,
 CHECK((context_json IS NULL)=(redacted_at IS NOT NULL))
);
CREATE INDEX owned_listing_template_target ON secureshop_review.owned_listing_template_operations(target_id,operation_id);
CREATE TABLE secureshop_review.owned_listing_template_events (
 operation_id uuid NOT NULL REFERENCES secureshop_review.owned_listing_template_operations(operation_id),
 sequence integer NOT NULL CHECK(sequence BETWEEN 1 AND 8),
 event_id uuid NOT NULL UNIQUE,
 state text NOT NULL CHECK(state IN ('running','declined','denied','unknown','effect_received','completed')),
 payload_json jsonb,
 payload_sha256 text,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 redacted_at timestamptz,
 PRIMARY KEY(operation_id,sequence),
 CHECK(payload_json IS NULL OR payload_sha256 IS NOT NULL),
 CHECK(payload_sha256 IS NULL OR payload_sha256 ~ '^[a-f0-9]{64}$'),
 CHECK((payload_json IS NULL OR encode(sha256(convert_to(payload_json::text,'UTF8')),'hex')=payload_sha256)),
 CHECK(redacted_at IS NULL OR payload_json IS NULL)
);
CREATE TABLE secureshop_review.owned_listing_template_cleanup_receipts (
 target_id uuid PRIMARY KEY REFERENCES secureshop_review.product_targets(target_id),
 platform_owner_id integer NOT NULL,
 operation_count integer NOT NULL CHECK(operation_count>=0),
 event_count integer NOT NULL CHECK(event_count>=0),
 evidence_sha256 text NOT NULL CHECK(evidence_sha256 ~ '^[a-f0-9]{64}$'),
 completed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON secureshop_review.owned_listing_template_operations,
 secureshop_review.owned_listing_template_events,
 secureshop_review.owned_listing_template_cleanup_receipts FROM PUBLIC,dvaia_secureshop_review_runtime;
GRANT SELECT ON secureshop_review.owned_listing_template_operations,
 secureshop_review.owned_listing_template_events,
 secureshop_review.owned_listing_template_cleanup_receipts TO dvaia_secureshop_review_runtime;

CREATE FUNCTION secureshop_review.guard_owned_listing_template_storage()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE target_id_value uuid; owner_id_value integer;
BEGIN
 IF TG_OP='DELETE' OR TG_TABLE_NAME='owned_listing_template_cleanup_receipts'
 THEN RAISE EXCEPTION 'Listing template evidence is immutable' USING ERRCODE='55000'; END IF;
 IF TG_TABLE_NAME='owned_listing_template_operations' THEN
  target_id_value:=OLD.target_id; owner_id_value:=OLD.platform_owner_id;
  IF OLD.redacted_at IS NOT NULL OR OLD.context_json IS NULL OR NEW.context_json IS NOT NULL
   OR NEW.redacted_at IS NULL OR to_jsonb(NEW)-ARRAY['context_json','redacted_at']
    IS DISTINCT FROM to_jsonb(OLD)-ARRAY['context_json','redacted_at']
  THEN RAISE EXCEPTION 'Listing template admission is immutable' USING ERRCODE='55000'; END IF;
 ELSE
  SELECT target_id,platform_owner_id INTO target_id_value,owner_id_value
   FROM secureshop_review.owned_listing_template_operations WHERE operation_id=OLD.operation_id;
  IF OLD.redacted_at IS NOT NULL OR NEW.payload_json IS NOT NULL OR NEW.redacted_at IS NULL
   OR to_jsonb(NEW)-ARRAY['payload_json','redacted_at']
    IS DISTINCT FROM to_jsonb(OLD)-ARRAY['payload_json','redacted_at']
  THEN RAISE EXCEPTION 'Listing template event is immutable' USING ERRCODE='55000'; END IF;
 END IF;
 IF NOT EXISTS(SELECT 1 FROM secureshop_review.product_targets
   WHERE target_id=target_id_value AND lifecycle='retired')
  AND NOT EXISTS(SELECT 1 FROM secureshop_review.bound_audit_owner_deletion_receipts
   WHERE original_platform_owner_id=owner_id_value)
 THEN RAISE EXCEPTION 'Listing template redaction requires retirement' USING ERRCODE='55000'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER owned_listing_template_operation_immutable BEFORE UPDATE OR DELETE
 ON secureshop_review.owned_listing_template_operations FOR EACH ROW
 EXECUTE FUNCTION secureshop_review.guard_owned_listing_template_storage();
CREATE TRIGGER owned_listing_template_event_immutable BEFORE UPDATE OR DELETE
 ON secureshop_review.owned_listing_template_events FOR EACH ROW
 EXECUTE FUNCTION secureshop_review.guard_owned_listing_template_storage();
CREATE TRIGGER owned_listing_template_cleanup_immutable BEFORE UPDATE OR DELETE
 ON secureshop_review.owned_listing_template_cleanup_receipts FOR EACH ROW
 EXECUTE FUNCTION secureshop_review.guard_owned_listing_template_storage();
REVOKE ALL ON FUNCTION secureshop_review.guard_owned_listing_template_storage()
 FROM PUBLIC,dvaia_secureshop_review_runtime;

CREATE FUNCTION secureshop_review.owned_listing_template_context(requested_target uuid,requested_product integer,requested_merchant integer)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE result jsonb;
BEGIN
 SELECT jsonb_build_object('templateSource',COALESCE(o.template_source,p.template_source),
  'title',COALESCE(o.name,p.name),'description',COALESCE(o.description,p.description,''),
  'price',COALESCE(o.price,p.price)) INTO result
 FROM secureshop_review.product_target_products p
 JOIN secureshop_review.product_targets t ON t.target_id=p.target_id AND t.lifecycle='active'
 LEFT JOIN secureshop_review.product_target_listing_overlays o
  ON o.target_id=p.target_id AND o.product_id=p.product_id
 WHERE p.target_id=requested_target AND p.product_id=requested_product
  AND p.retailer_id=requested_merchant AND COALESCE(o.shop_user_id,p.retailer_id)=requested_merchant
  AND COALESCE(o.status,p.status)='active' AND o.archived_at IS NULL
 FOR SHARE OF p,t;
 IF result IS NULL OR result->>'templateSource' IS NULL
  OR octet_length(result->>'templateSource') NOT BETWEEN 1 AND 16384
 THEN RAISE EXCEPTION 'Owned listing template unavailable' USING ERRCODE='55000'; END IF;
 RETURN result;
END $$;
REVOKE ALL ON FUNCTION secureshop_review.owned_listing_template_context(uuid,integer,integer)
 FROM PUBLIC,dvaia_secureshop_review_runtime;

CREATE FUNCTION secureshop_review.admit_owned_listing_template(
 requested_operation uuid,requested_target uuid,requested_grant uuid,requested_product integer,
 requested_merchant integer,requested_launch uuid,requested_scenario uuid,requested_generation bigint,
 requested_owner integer,requested_platform_session integer,requested_persona_session uuid,
 requested_authority bigint,requested_mode text,requested_request_sha text,requested_capability text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE prior secureshop_review.owned_listing_template_operations%ROWTYPE;
 selected_grant secureshop_review.scene_execution_grants%ROWTYPE; context jsonb; source_hash text; context_hash text;
BEGIN
 IF requested_operation IS NULL OR requested_target IS NULL OR requested_grant IS NULL OR requested_product IS NULL OR requested_product<1
  OR requested_merchant IS NULL OR requested_merchant<1000000000 OR requested_launch IS NULL OR requested_scenario IS NULL
  OR requested_generation IS NULL OR requested_generation<1 OR requested_owner IS NULL OR requested_owner<1 OR requested_platform_session IS NULL OR requested_platform_session<1
  OR requested_persona_session IS NULL OR requested_authority IS NULL OR requested_authority<1 OR requested_mode IS NULL OR requested_mode NOT IN ('vuln','fixed')
  OR requested_request_sha IS NULL OR requested_request_sha !~ '^[a-f0-9]{64}$' OR requested_capability IS NULL OR requested_capability !~ '^[a-f0-9]{64}$'
 THEN RAISE EXCEPTION 'Listing template admission invalid' USING ERRCODE='22023'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||requested_owner::text,0));
 PERFORM pg_advisory_xact_lock(hashtextextended('owned-listing-template:'||requested_operation::text,0));
 IF EXISTS(SELECT 1 FROM secureshop_review.bound_audit_owner_deletion_receipts
   WHERE original_platform_owner_id=requested_owner) THEN
  RAISE EXCEPTION 'Listing template owner unavailable' USING ERRCODE='55000'; END IF;
 SELECT * INTO selected_grant FROM secureshop_review.scene_execution_grants WHERE grant_id=requested_grant;
 IF NOT FOUND OR NOT secureshop_review.assert_scene_execution_grant(requested_grant,
   selected_grant.scene_id,selected_grant.scene_generation,requested_target,requested_launch,requested_scenario,
   requested_generation,requested_owner,requested_platform_session)
 THEN RAISE EXCEPTION 'Listing template scene unavailable' USING ERRCODE='42501'; END IF;
 SELECT * INTO prior FROM secureshop_review.owned_listing_template_operations
  WHERE operation_id=requested_operation;
 IF FOUND THEN
  IF ROW(prior.target_id,prior.grant_id,prior.product_id,prior.merchant_id,prior.launch_id,
   prior.scenario_id,prior.generation,prior.platform_owner_id,prior.platform_session_id,
   prior.persona_session_id,prior.authority_version,prior.mode,prior.request_sha256,prior.capability_sha256)
   IS DISTINCT FROM ROW(requested_target,requested_grant,requested_product,requested_merchant,
   requested_launch,requested_scenario,requested_generation,requested_owner,requested_platform_session,
   requested_persona_session,requested_authority,requested_mode,requested_request_sha,
   encode(sha256(convert_to(requested_capability,'UTF8')),'hex'))
  THEN RAISE EXCEPTION 'Listing template operation conflict' USING ERRCODE='55000'; END IF;
  IF prior.redacted_at IS NOT NULL THEN RAISE EXCEPTION 'Listing template retired' USING ERRCODE='55000'; END IF;
  RETURN jsonb_build_object('newlyAdmitted',false,'context',prior.context_json,
   'contextSha256',prior.context_sha256,'sourceSha256',prior.source_sha256);
 END IF;
 context:=secureshop_review.owned_listing_template_context(requested_target,requested_product,requested_merchant);
 source_hash:=encode(sha256(convert_to(context->>'templateSource','UTF8')),'hex');
 context_hash:=encode(sha256(convert_to(context::text,'UTF8')),'hex');
 INSERT INTO secureshop_review.owned_listing_template_operations(
  operation_id,target_id,grant_id,product_id,merchant_id,launch_id,scenario_id,generation,
  platform_owner_id,platform_session_id,persona_session_id,authority_version,mode,request_sha256,
  source_sha256,context_sha256,context_json,capability_sha256)
 VALUES(requested_operation,requested_target,requested_grant,requested_product,requested_merchant,
  requested_launch,requested_scenario,requested_generation,requested_owner,requested_platform_session,
  requested_persona_session,requested_authority,requested_mode,requested_request_sha,source_hash,
  context_hash,context,encode(sha256(convert_to(requested_capability,'UTF8')),'hex'));
 RETURN jsonb_build_object('newlyAdmitted',true,'context',context,
  'contextSha256',context_hash,'sourceSha256',source_hash);
END $$;
REVOKE ALL ON FUNCTION secureshop_review.admit_owned_listing_template(
 uuid,uuid,uuid,integer,integer,uuid,uuid,bigint,integer,integer,uuid,bigint,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.admit_owned_listing_template(
 uuid,uuid,uuid,integer,integer,uuid,uuid,bigint,integer,integer,uuid,bigint,text,text,text)
 TO dvaia_secureshop_review_runtime;

CREATE FUNCTION secureshop_review.append_owned_listing_template_event(
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
   OR requested_payload#>>'{effect,requestSha256}' IS DISTINCT FROM prior.payload_json->>'executorRequestSha256'
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
REVOKE ALL ON FUNCTION secureshop_review.append_owned_listing_template_event(uuid,uuid,integer,text,jsonb,text)
 FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.append_owned_listing_template_event(uuid,uuid,integer,text,jsonb,text)
 TO dvaia_secureshop_review_runtime;

-- Reset and owner deletion retain immutable operation hashes while removing
-- source and result bytes in the same transaction as target retirement.
CREATE FUNCTION secureshop_review.redact_owned_listing_template_target(requested_target uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE owner_id integer; operations integer; events integer; digest text;
BEGIN
 SELECT original_platform_owner_id INTO owner_id FROM secureshop_review.product_targets
  WHERE target_id=requested_target;
 IF NOT FOUND THEN RETURN; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||owner_id::text,0));
 IF NOT EXISTS(SELECT 1 FROM secureshop_review.product_targets
   WHERE target_id=requested_target AND lifecycle='retired')
  AND NOT EXISTS(SELECT 1 FROM secureshop_review.bound_audit_owner_deletion_receipts
   WHERE original_platform_owner_id=owner_id)
 THEN RAISE EXCEPTION 'Listing template target remains active' USING ERRCODE='55000'; END IF;
 IF EXISTS(SELECT 1 FROM secureshop_review.owned_listing_template_cleanup_receipts
   WHERE target_id=requested_target) THEN RETURN; END IF;
 SELECT count(*) INTO operations FROM secureshop_review.owned_listing_template_operations
  WHERE target_id=requested_target;
 SELECT count(*) INTO events FROM secureshop_review.owned_listing_template_events e
  JOIN secureshop_review.owned_listing_template_operations a USING(operation_id)
  WHERE a.target_id=requested_target;
 SELECT encode(sha256(convert_to(COALESCE(string_agg(a.operation_id::text||':'||a.request_sha256||':'||a.context_sha256||':'||
  COALESCE(e.sequence::text,'')||':'||COALESCE(e.payload_sha256,''),'|' ORDER BY a.operation_id,e.sequence),''),'UTF8')),'hex')
 INTO digest FROM secureshop_review.owned_listing_template_operations a
 LEFT JOIN secureshop_review.owned_listing_template_events e USING(operation_id)
 WHERE a.target_id=requested_target;
 UPDATE secureshop_review.owned_listing_template_events e
  SET payload_json=NULL,redacted_at=clock_timestamp()
  FROM secureshop_review.owned_listing_template_operations a
  WHERE a.operation_id=e.operation_id AND a.target_id=requested_target AND e.redacted_at IS NULL;
 UPDATE secureshop_review.owned_listing_template_operations
  SET context_json=NULL,redacted_at=clock_timestamp()
  WHERE target_id=requested_target AND redacted_at IS NULL;
 INSERT INTO secureshop_review.owned_listing_template_cleanup_receipts(
  target_id,platform_owner_id,operation_count,event_count,evidence_sha256)
 VALUES(requested_target,owner_id,operations,events,digest);
END $$;
CREATE FUNCTION secureshop_review.cleanup_owned_listing_template_lifecycle()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE selected_target uuid;
BEGIN
 IF TG_TABLE_NAME='product_targets' THEN
  IF OLD.lifecycle='active' AND NEW.lifecycle='retired' THEN
   PERFORM secureshop_review.redact_owned_listing_template_target(NEW.target_id); END IF;
 ELSE
  FOR selected_target IN SELECT target_id FROM secureshop_review.product_targets
   WHERE original_platform_owner_id=NEW.original_platform_owner_id
  LOOP PERFORM secureshop_review.redact_owned_listing_template_target(selected_target); END LOOP;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER z_product_target_template_retirement AFTER UPDATE OF lifecycle
 ON secureshop_review.product_targets FOR EACH ROW
 EXECUTE FUNCTION secureshop_review.cleanup_owned_listing_template_lifecycle();
CREATE TRIGGER z_owner_template_cleanup AFTER INSERT
 ON secureshop_review.bound_audit_owner_deletion_receipts FOR EACH ROW
 EXECUTE FUNCTION secureshop_review.cleanup_owned_listing_template_lifecycle();
REVOKE ALL ON FUNCTION secureshop_review.redact_owned_listing_template_target(uuid),
 secureshop_review.cleanup_owned_listing_template_lifecycle() FROM PUBLIC,dvaia_secureshop_review_runtime;
