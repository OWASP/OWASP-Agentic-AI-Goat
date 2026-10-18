-- Retained storage birth is distinct from a current Listings execution.
-- All predecessor admissions, packets, source rows and cleanup receipts remain
-- unchanged. Only new scene admissions obtain an immutable current grant link.
CREATE TABLE secureshop_review.owned_listing_scene_admissions(
 operation_id uuid PRIMARY KEY REFERENCES secureshop_review.owned_listing_admissions(operation_id) DEFERRABLE INITIALLY DEFERRED,
 grant_id uuid NOT NULL REFERENCES secureshop_review.scene_execution_grants(grant_id),
 target_id uuid NOT NULL REFERENCES secureshop_review.product_targets(target_id),
 merchant_id integer NOT NULL CHECK(merchant_id>=1000000000),
 binding_sha256 text NOT NULL CHECK(binding_sha256 ~ '^[a-f0-9]{64}$')
);
CREATE TRIGGER owned_listing_scene_admission_immutable BEFORE UPDATE OR DELETE
 ON secureshop_review.owned_listing_scene_admissions FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_owned_listing_cleanup();
REVOKE ALL ON secureshop_review.owned_listing_scene_admissions FROM PUBLIC,dvaia_secureshop_review_runtime;
GRANT SELECT ON secureshop_review.owned_listing_scene_admissions TO dvaia_secureshop_review_runtime;

-- Called only inside capability-checked journal functions. Current session,
-- persona and reset authority is additionally held by the server's private
-- persona/scene leases; this checks the exact immutable storage-side tuple.
CREATE FUNCTION secureshop_review.assert_owned_listing_target(op uuid,requested_target uuid,binding text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE t secureshop_review.product_targets%ROWTYPE;
 a secureshop_review.owned_listing_scene_admissions%ROWTYPE;
 g secureshop_review.scene_execution_grants%ROWTYPE; b jsonb;
BEGIN
 b:=binding::jsonb;
 SELECT * INTO t FROM secureshop_review.product_targets WHERE target_id=requested_target FOR SHARE;
 IF NOT FOUND OR t.lifecycle<>'active' OR t.original_platform_owner_id IS DISTINCT FROM (b#>>'{scope,platformOwnerId}')::integer
 OR EXISTS(SELECT 1 FROM secureshop_review.bound_audit_owner_deletion_receipts WHERE original_platform_owner_id=t.original_platform_owner_id)
 THEN RAISE EXCEPTION 'active owned listing target required' USING ERRCODE='55000'; END IF;
 SELECT * INTO a FROM secureshop_review.owned_listing_scene_admissions WHERE operation_id=op;
 IF FOUND THEN
  SELECT * INTO STRICT g FROM secureshop_review.scene_execution_grants WHERE grant_id=a.grant_id;
  IF a.target_id IS DISTINCT FROM requested_target OR a.merchant_id IS DISTINCT FROM (b#>>'{persona,id}')::integer
  OR a.binding_sha256 IS DISTINCT FROM encode(sha256(convert_to(binding,'UTF8')),'hex')
  OR NOT secureshop_review.assert_scene_execution_grant(g.grant_id,g.scene_id,g.scene_generation,requested_target,
   (b#>>'{scope,launchId}')::uuid,(b#>>'{scope,scenarioId}')::uuid,(b#>>'{scope,generation}')::bigint,
   (b#>>'{scope,platformOwnerId}')::integer,(b#>>'{scope,platformSessionId}')::integer)
  THEN RAISE EXCEPTION 'listing scene execution denied' USING ERRCODE='42501'; END IF;
 ELSE
  -- A mapped target cannot use a legacy packet to admit or mutate an operation,
  -- even when its first current grant happens to equal its birth scope.
  IF EXISTS(SELECT 1 FROM secureshop_review.scene_execution_grants WHERE target_id=requested_target)
  OR ROW(t.launch_id,t.scenario_id,t.generation,t.original_platform_owner_id,t.original_platform_session_id,t.own_merchant_id)
   IS DISTINCT FROM ROW((b#>>'{scope,launchId}')::uuid,(b#>>'{scope,scenarioId}')::uuid,(b#>>'{scope,generation}')::bigint,
    (b#>>'{scope,platformOwnerId}')::integer,(b#>>'{scope,platformSessionId}')::integer,(b#>>'{persona,id}')::integer)
  THEN RAISE EXCEPTION 'active legacy listing target required' USING ERRCODE='55000'; END IF;
 END IF;
END $$;
REVOKE ALL ON FUNCTION secureshop_review.assert_owned_listing_target(uuid,uuid,text) FROM PUBLIC,dvaia_secureshop_review_runtime;

CREATE FUNCTION secureshop_review.admit_owned_listing_scene_operation(op uuid,target uuid,binding text,binding_hash text,request text,request_hash text,requested_action text,capability text,requested_grant uuid)
RETURNS TABLE(newly_admitted boolean) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE prior secureshop_review.owned_listing_scene_admissions%ROWTYPE;
 g secureshop_review.scene_execution_grants%ROWTYPE; b jsonb;
BEGIN
 IF binding IS NULL OR requested_grant IS NULL THEN RAISE EXCEPTION 'listing scene admission invalid' USING ERRCODE='22023'; END IF;
 b:=binding::jsonb;
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||(b#>>'{scope,platformOwnerId}'),0));
 PERFORM pg_advisory_xact_lock(hashtextextended('owned-listing:'||op::text,0));
 SELECT * INTO g FROM secureshop_review.scene_execution_grants WHERE grant_id=requested_grant;
 IF NOT FOUND OR (b#>>'{persona,id}')::integer<1000000000 OR b#>>'{persona,role}' IS DISTINCT FROM 'merchant'
 OR NOT secureshop_review.assert_scene_execution_grant(requested_grant,g.scene_id,g.scene_generation,target,
   (b#>>'{scope,launchId}')::uuid,(b#>>'{scope,scenarioId}')::uuid,(b#>>'{scope,generation}')::bigint,
   (b#>>'{scope,platformOwnerId}')::integer,(b#>>'{scope,platformSessionId}')::integer)
 THEN RAISE EXCEPTION 'listing scene admission denied' USING ERRCODE='42501'; END IF;
 SELECT * INTO prior FROM secureshop_review.owned_listing_scene_admissions WHERE operation_id=op;
 IF FOUND THEN
  IF ROW(prior.grant_id,prior.target_id,prior.merchant_id,prior.binding_sha256)
   IS DISTINCT FROM ROW(requested_grant,target,(b#>>'{persona,id}')::integer,binding_hash)
  THEN RAISE EXCEPTION 'listing original grant conflict' USING ERRCODE='55000'; END IF;
 ELSE
  IF EXISTS(SELECT 1 FROM secureshop_review.owned_listing_admissions WHERE operation_id=op)
  THEN RAISE EXCEPTION 'historical listing admission cannot acquire a grant' USING ERRCODE='55000'; END IF;
  INSERT INTO secureshop_review.owned_listing_scene_admissions(operation_id,grant_id,target_id,merchant_id,binding_sha256)
  VALUES(op,requested_grant,target,(b#>>'{persona,id}')::integer,binding_hash);
 END IF;
 RETURN QUERY SELECT * FROM secureshop_review.admit_owned_listing_operation(op,target,binding,binding_hash,request,request_hash,requested_action,capability);
END $$;
REVOKE ALL ON FUNCTION secureshop_review.admit_owned_listing_scene_operation(uuid,uuid,text,text,text,text,text,text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.admit_owned_listing_scene_operation(uuid,uuid,text,text,text,text,text,text,uuid) TO dvaia_secureshop_review_runtime;

CREATE OR REPLACE FUNCTION secureshop_review.guard_owned_listing_journal() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE admission secureshop_review.owned_listing_admissions%ROWTYPE;
 target secureshop_review.product_targets%ROWTYPE;
 prior secureshop_review.owned_listing_events%ROWTYPE;
 b jsonb; r jsonb; p jsonb; previous_state text; previous_sequence integer;
BEGIN
 IF TG_OP='UPDATE' THEN
   IF TG_TABLE_NAME='owned_listing_admissions' THEN admission:=OLD;
   ELSE SELECT * INTO STRICT admission FROM secureshop_review.owned_listing_admissions WHERE operation_id=OLD.operation_id; END IF;
   IF OLD.redacted_at IS NULL AND NEW.redacted_at IS NOT NULL
   AND ((TG_TABLE_NAME='owned_listing_admissions' AND to_jsonb(NEW)-ARRAY['request_json','redacted_at']=to_jsonb(OLD)-ARRAY['request_json','redacted_at'] AND to_jsonb(NEW)->'request_json'='null'::jsonb)
     OR (TG_TABLE_NAME='owned_listing_events' AND to_jsonb(NEW)-ARRAY['payload_json','redacted_at']=to_jsonb(OLD)-ARRAY['payload_json','redacted_at'] AND to_jsonb(NEW)->'payload_json'='null'::jsonb))
   AND (EXISTS(SELECT 1 FROM secureshop_review.product_targets t WHERE t.target_id=admission.target_id AND t.lifecycle='retired')
     OR EXISTS(SELECT 1 FROM secureshop_review.bound_audit_owner_deletion_receipts d WHERE d.original_platform_owner_id=(admission.binding_json::jsonb#>>'{scope,platformOwnerId}')::integer))
   THEN RETURN NEW; END IF;
   RAISE EXCEPTION 'listing journal is immutable' USING ERRCODE='55000';
 END IF;
 IF TG_OP<>'INSERT' OR NEW.redacted_at IS NOT NULL THEN RAISE EXCEPTION 'listing journal is immutable' USING ERRCODE='55000'; END IF;
 IF TG_TABLE_NAME='owned_listing_admissions' THEN
   admission:=NEW;
 ELSE
   SELECT * INTO STRICT admission FROM secureshop_review.owned_listing_admissions WHERE operation_id=NEW.operation_id;
 END IF;
 IF admission.redacted_at IS NOT NULL OR admission.request_json IS NULL THEN RAISE EXCEPTION 'listing retired' USING ERRCODE='55000'; END IF;
 b:=admission.binding_json::jsonb; r:=admission.request_json::jsonb;
 IF jsonb_typeof(b) IS DISTINCT FROM 'object' OR jsonb_typeof(r) IS DISTINCT FROM 'object'
 OR b->>'mode' IS NULL OR b->>'mode' NOT IN ('vuln','fixed')
 OR b#>>'{persona,role}' IS DISTINCT FROM 'merchant'
 OR b#>>'{personaSession,sessionId}' IS NULL
 OR b#>>'{personaSession,authorityVersion}' IS NULL
 OR b->>'catalogRevision' IS NULL
 OR (b#>>'{personaSession,sessionId}')::uuid IS NULL
 OR (b#>>'{personaSession,authorityVersion}')::bigint NOT BETWEEN 1 AND 9007199254740991
 OR (b->>'catalogRevision')::bigint NOT BETWEEN 0 AND 9007199254740991
 OR r->>'action' IS DISTINCT FROM admission.action OR r->>'version' IS DISTINCT FROM '1'
 OR r->>'operationId' IS DISTINCT FROM admission.operation_id::text
 OR b->>'targetId' IS DISTINCT FROM admission.target_id::text
 THEN RAISE EXCEPTION 'listing binding invalid' USING ERRCODE='22023'; END IF;
 -- Canonical owner lock matches cleanup order before target lock.
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||(b#>>'{scope,platformOwnerId}'),0));
 PERFORM pg_advisory_xact_lock(hashtextextended('owned-listing:'||NEW.operation_id::text,0));
 IF EXISTS(SELECT 1 FROM secureshop_review.bound_audit_owner_deletion_receipts d WHERE d.original_platform_owner_id=(b#>>'{scope,platformOwnerId}')::integer) THEN RAISE EXCEPTION 'listing owner deleted' USING ERRCODE='55000'; END IF;
 PERFORM secureshop_review.assert_owned_listing_target(admission.operation_id,admission.target_id,admission.binding_json);
 IF TG_TABLE_NAME='owned_listing_admissions' THEN RETURN NEW; END IF;
 SELECT * INTO prior FROM secureshop_review.owned_listing_events WHERE operation_id=NEW.operation_id ORDER BY sequence DESC LIMIT 1;
 previous_state:=CASE WHEN FOUND THEN prior.state ELSE 'admitted' END;
 previous_sequence:=COALESCE(prior.sequence,0);
 IF NEW.sequence<>previous_sequence+1 OR NOT (
   (previous_state='admitted' AND NEW.state IN ('running','failed')) OR
   (admission.action='import' AND previous_state IN ('admitted','effect_received') AND NEW.state='declined') OR
   (previous_state='running' AND NEW.state IN ('effect_received','unknown','failed')) OR
   (previous_state='unknown' AND NEW.state='effect_received') OR
   (previous_state='effect_received' AND NEW.state='completed'))
 THEN RAISE EXCEPTION 'listing transition conflict' USING ERRCODE='55000'; END IF;
 IF NEW.state='failed' THEN
   p:=NEW.payload_json::jsonb;
   IF jsonb_typeof(p) IS DISTINCT FROM 'object' OR p->>'code' IS NULL
   OR p->>'code' NOT IN ('INVALID_DECISION','MODEL_UNAVAILABLE','ADMISSION_REJECTED')
   OR (admission.action='import' AND previous_state<>'admitted')
   THEN RAISE EXCEPTION 'definite listing failure required' USING ERRCODE='22023'; END IF;
 END IF;
 IF NEW.state='declined' THEN
   p:=NEW.payload_json::jsonb;
   IF admission.action<>'import' OR jsonb_typeof(p) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(p))<>11
   OR p->>'version' IS DISTINCT FROM '1' OR p->>'operationId' IS DISTINCT FROM admission.operation_id::text
   OR p->>'requestSha256' IS DISTINCT FROM admission.request_sha256
   OR p->>'importReceiptSha256' IS DISTINCT FROM (CASE WHEN previous_state='effect_received' THEN prior.payload_sha256 ELSE NULL END)
   OR p->'mocked' IS DISTINCT FROM 'false'::jsonb OR p->'fallback' IS DISTINCT FROM 'false'::jsonb
   OR p->>'provider' IS NULL OR length(btrim(p->>'provider'))=0 OR p->>'model' IS NULL OR length(btrim(p->>'model'))=0
   OR btrim(p->>'provider') ~* '^(mock|fixture|scripted|fallback|unavailable)$' OR btrim(p->>'model') ~* '^(mock|fixture|scripted|fallback|unavailable)$'
   OR p->>'callId' IS NULL OR octet_length(p->>'callId') NOT BETWEEN 1 AND 256
   OR p->>'reason' IS NULL OR octet_length(p->>'reason') NOT BETWEEN 1 AND 16384
   OR p->>'reasonSha256' IS DISTINCT FROM encode(sha256(convert_to(p->>'reason','UTF8')),'hex')
   THEN RAISE EXCEPTION 'model decline receipt required' USING ERRCODE='22023'; END IF;
 END IF;
 IF NEW.state IN ('effect_received','completed') THEN
   p:=NEW.payload_json::jsonb;
   IF jsonb_typeof(p) IS DISTINCT FROM 'object' THEN RAISE EXCEPTION 'listing receipt required' USING ERRCODE='22023'; END IF;
   IF admission.action='rewrite' AND (
     p->>'version' IS DISTINCT FROM '1' OR p->>'operationId' IS DISTINCT FROM admission.operation_id::text
     OR p->>'requestSha256' IS DISTINCT FROM admission.request_sha256
     OR p->'mocked' IS DISTINCT FROM 'false'::jsonb OR p->'fallback' IS DISTINCT FROM 'false'::jsonb
     OR p->>'provider' IS NULL OR p->>'model' IS NULL OR p->>'callId' IS NULL
     OR p->>'provider' ~* '^(mock|fixture|scripted|fallback|unavailable)$'
     OR p->>'model' ~* '^(mock|fixture|scripted|fallback|unavailable)$'
     OR p->>'html' IS NULL OR octet_length(p->>'html') NOT BETWEEN 1 AND 65536
     OR p->>'htmlSha256' IS DISTINCT FROM encode(sha256(convert_to(p->>'html','UTF8')),'hex')
   ) THEN RAISE EXCEPTION 'model rewrite receipt required' USING ERRCODE='22023'; END IF;
   IF NEW.state='completed' AND admission.action='rewrite' AND (NEW.payload_json IS DISTINCT FROM prior.payload_json OR NEW.payload_sha256 IS DISTINCT FROM prior.payload_sha256)
   THEN RAISE EXCEPTION 'rewrite receipt changed' USING ERRCODE='55000'; END IF;
   IF NEW.state='completed' AND admission.action='import' AND NOT EXISTS(SELECT 1 FROM secureshop_review.owned_listing_publications publication WHERE publication.operation_id=NEW.operation_id AND publication.event_id=NEW.event_id AND publication.receipt_json=NEW.payload_json AND publication.receipt_sha256=NEW.payload_sha256) THEN RAISE EXCEPTION 'atomic listing publication required' USING ERRCODE='55000'; END IF;
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION secureshop_review.guard_owned_listing_journal() FROM PUBLIC,dvaia_secureshop_review_runtime;

-- Attribute NEW scene audit packets to both immutable storage birth and the
-- current execution grant; legacy params bytes retain their original shape.
CREATE FUNCTION secureshop_review.owned_listing_audit_params(op uuid,requested_target uuid,params jsonb)
RETURNS text LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
 SELECT (CASE WHEN c.operation_id IS NULL THEN params ELSE params||jsonb_build_object('storage',jsonb_build_object(
  'targetId',t.target_id,'birthLaunchId',t.launch_id,'birthScenarioId',t.scenario_id,
  'birthGeneration',t.generation,'birthPlatformSessionId',t.original_platform_session_id,
  'sceneId',g.scene_id,'sceneGeneration',g.scene_generation,'grantId',g.grant_id)) END)::text
 FROM secureshop_review.product_targets t
 LEFT JOIN secureshop_review.owned_listing_scene_admissions c ON c.operation_id=op AND c.target_id=t.target_id
 LEFT JOIN secureshop_review.scene_execution_grants g ON g.grant_id=c.grant_id
 WHERE t.target_id=requested_target
$$;
REVOKE ALL ON FUNCTION secureshop_review.owned_listing_audit_params(uuid,uuid,jsonb) FROM PUBLIC,dvaia_secureshop_review_runtime;

CREATE OR REPLACE FUNCTION secureshop_review.publish_owned_listing_import(op uuid,event uuid,expected_sequence integer,capability text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE a secureshop_review.owned_listing_admissions%ROWTYPE;
 prior secureshop_review.owned_listing_events%ROWTYPE;
 target secureshop_review.product_targets%ROWTYPE;
 b jsonb; effect jsonb; item jsonb; source jsonb; ids jsonb:='[]'::jsonb;
 revision_value bigint; next_id integer; receipt text; item_bytes integer; source_count integer;
BEGIN
 IF op IS NULL OR event IS NULL OR expected_sequence IS NULL OR capability IS NULL OR capability !~ '^[0-9a-f]{64}$'
 THEN RAISE EXCEPTION 'listing publication invalid' USING ERRCODE='22023'; END IF;
 SELECT * INTO a FROM secureshop_review.owned_listing_admissions WHERE operation_id=op;
 IF NOT FOUND OR a.action<>'import' OR a.redacted_at IS NOT NULL OR a.capability_sha256 IS DISTINCT FROM encode(sha256(convert_to(capability,'UTF8')),'hex')
 THEN RAISE EXCEPTION 'listing publication denied' USING ERRCODE='42501'; END IF;
 b:=a.binding_json::jsonb;
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||(b#>>'{scope,platformOwnerId}'),0));
 PERFORM pg_advisory_xact_lock(hashtextextended('owned-listing:'||op::text,0));
 SELECT * INTO target FROM secureshop_review.product_targets WHERE target_id=a.target_id FOR UPDATE;
 PERFORM secureshop_review.assert_owned_listing_target(op,a.target_id,a.binding_json);
 IF EXISTS(SELECT 1 FROM secureshop_review.owned_listing_publications WHERE operation_id=op) THEN RETURN; END IF;
 SELECT * INTO prior FROM secureshop_review.owned_listing_events WHERE operation_id=op ORDER BY sequence DESC LIMIT 1;
 IF NOT FOUND OR prior.state<>'effect_received' OR prior.sequence<>expected_sequence OR prior.redacted_at IS NOT NULL
 THEN RAISE EXCEPTION 'listing effect unavailable' USING ERRCODE='55000'; END IF;
 effect:=prior.payload_json::jsonb;
 IF effect->>'operationId' IS DISTINCT FROM op::text OR effect->>'requestSha256' IS DISTINCT FROM a.request_sha256
 OR effect->>'executorReceiptSha256' IS NULL OR effect->>'executorReceiptSha256' !~ '^[0-9a-f]{64}$'
 OR jsonb_typeof(effect->'products') IS DISTINCT FROM 'array' OR jsonb_array_length(effect->'products') NOT BETWEEN 1 AND 100
 OR jsonb_typeof(effect->'sources') IS DISTINCT FROM 'array'
 THEN RAISE EXCEPTION 'listing effect invalid' USING ERRCODE='22023'; END IF;
 source_count:=0;
 FOR source IN SELECT value FROM jsonb_array_elements(effect->'sources') LOOP
   IF source->>'status' IS DISTINCT FROM 'completed' OR source->>'sourceSha256' IS NULL OR source->>'sourceSha256' !~ '^[0-9a-f]{64}$'
   OR source->>'url' IS DISTINCT FROM (CASE WHEN source_count=0 AND a.request_json::jsonb->>'json_url' IS NOT NULL THEN a.request_json::jsonb->>'json_url' ELSE a.request_json::jsonb->>'xml_url' END)
   THEN RAISE EXCEPTION 'listing source incomplete' USING ERRCODE='22023'; END IF;
   source_count:=source_count+1;
 END LOOP;
 IF source_count<>(CASE WHEN a.request_json::jsonb->>'json_url' IS NOT NULL THEN 1 ELSE 0 END)+(CASE WHEN a.request_json::jsonb->>'xml_url' IS NOT NULL THEN 1 ELSE 0 END)
 THEN RAISE EXCEPTION 'listing source count invalid' USING ERRCODE='22023'; END IF;
 INSERT INTO secureshop_review.owned_listing_catalog_revisions(target_id,revision) VALUES(a.target_id,0) ON CONFLICT DO NOTHING;
 SELECT revision INTO revision_value FROM secureshop_review.owned_listing_catalog_revisions WHERE target_id=a.target_id FOR UPDATE;
 IF revision_value<>(b->>'catalogRevision')::bigint THEN RAISE EXCEPTION 'listing catalog changed' USING ERRCODE='40001'; END IF;
 SELECT COALESCE(max(product_id),0) INTO next_id FROM secureshop_review.product_target_products WHERE target_id=a.target_id;
 FOR item IN SELECT value FROM jsonb_array_elements(effect->'products') LOOP
   IF jsonb_typeof(item) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(item))<>6
   OR NOT(item ?& ARRAY['name','description','price','category','images','templateSource'])
   OR jsonb_typeof(item->'name') IS DISTINCT FROM 'string' OR octet_length(item->>'name') NOT BETWEEN 1 AND 4096
   OR jsonb_typeof(item->'price') IS DISTINCT FROM 'number' OR (item->>'price')::numeric NOT BETWEEN 0 AND 99999999.99
   OR (item->'description'<>'null'::jsonb AND (jsonb_typeof(item->'description')<>'string' OR octet_length(item->>'description')>65536))
   OR (item->'category'<>'null'::jsonb AND (jsonb_typeof(item->'category')<>'string' OR octet_length(item->>'category')>1024))
   OR (item->'templateSource'<>'null'::jsonb AND (jsonb_typeof(item->'templateSource')<>'string' OR octet_length(item->>'templateSource')>65536))
   OR jsonb_typeof(item->'images') IS DISTINCT FROM 'array' OR jsonb_array_length(item->'images')>16
   OR EXISTS(SELECT 1 FROM jsonb_array_elements(item->'images') image WHERE jsonb_typeof(image)<>'string' OR octet_length(image#>>'{}') NOT BETWEEN 1 AND 8192)
   THEN RAISE EXCEPTION 'listing row invalid' USING ERRCODE='22023'; END IF;
   SELECT COALESCE(sum(octet_length(value#>>'{}')),0) INTO item_bytes FROM jsonb_array_elements(item->'images');
   item_bytes:=item_bytes+octet_length(item->>'name')+COALESCE(octet_length(item->>'description'),0)+COALESCE(octet_length(item->>'category'),0)+COALESCE(octet_length(item->>'templateSource'),0);
   IF item_bytes>65536 THEN RAISE EXCEPTION 'listing row limit' USING ERRCODE='22023'; END IF;
   next_id:=next_id+1;
   INSERT INTO secureshop_review.product_target_products(target_id,product_id,source_retailer_id,retailer_id,source_product_sha256,name,description,description_html,price,category,image_url,images,stock_quantity,status,template_source,source_created_at,source_updated_at)
   VALUES(a.target_id,next_id,(b#>>'{persona,id}')::integer,(b#>>'{persona,id}')::integer,sha256(convert_to(item::text,'UTF8')),item->>'name',item->>'description',NULL,round((item->>'price')::numeric,2),item->>'category',item#>>'{images,0}',item->'images',0,'active',item->>'templateSource',clock_timestamp(),clock_timestamp());
   INSERT INTO secureshop_review.product_target_merchant_listings(target_id,product_id,shop_user_id) VALUES(a.target_id,next_id,(b#>>'{persona,id}')::integer);
   INSERT INTO secureshop_review.bound_audit_events(event_id,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id,shop_user_id,shop_role,actor,action,target,params_json,outcome,source_kind,source_id)
   VALUES(gen_random_uuid(),(b#>>'{scope,launchId}')::uuid,(b#>>'{scope,scenarioId}')::uuid,(b#>>'{scope,generation}')::bigint,(b#>>'{scope,platformOwnerId}')::integer,(b#>>'{scope,platformSessionId}')::integer,(b#>>'{persona,id}')::integer,'merchant','merchant','listing_import',next_id::text,secureshop_review.owned_listing_audit_params(op,a.target_id,item),'completed','product',next_id::text);
   ids:=ids||jsonb_build_array(next_id);
 END LOOP;
 SELECT revision INTO revision_value FROM secureshop_review.owned_listing_catalog_revisions WHERE target_id=a.target_id;
 receipt:=jsonb_build_object('version',1,'operationId',op::text,'requestSha256',a.request_sha256,'executorReceiptSha256',effect->>'executorReceiptSha256','importReceiptSha256',prior.payload_sha256,'productIds',ids,'catalogRevision',revision_value::text)::text;
 INSERT INTO secureshop_review.owned_listing_publications(operation_id,event_id,receipt_json,receipt_sha256)
 VALUES(op,event,receipt,encode(sha256(convert_to(receipt,'UTF8')),'hex'));
 INSERT INTO secureshop_review.owned_listing_events(operation_id,event_id,sequence,state,payload_json,payload_sha256)
 VALUES(op,event,expected_sequence+1,'completed',receipt,encode(sha256(convert_to(receipt,'UTF8')),'hex'));
END $$;
REVOKE ALL ON FUNCTION secureshop_review.publish_owned_listing_import(uuid,uuid,integer,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.publish_owned_listing_import(uuid,uuid,integer,text) TO dvaia_secureshop_review_runtime;

CREATE OR REPLACE FUNCTION secureshop_review.consume_owned_listing_rewrite(save_id uuid,op uuid,binding text,requested_product integer,item_text text,item_hash text,capability text)
RETURNS text LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE admission secureshop_review.owned_listing_admissions%ROWTYPE;
 event secureshop_review.owned_listing_events%ROWTYPE;
 target secureshop_review.product_targets%ROWTYPE;
 saved secureshop_review.owned_listing_rewrite_saves%ROWTYPE;
 base secureshop_review.product_target_products%ROWTYPE;
 overlay secureshop_review.product_target_listing_overlays%ROWTYPE;
 b jsonb; item jsonb; effect jsonb; item_id integer; stock integer; item_status text; receipt text; current_revision bigint;
BEGIN
 IF save_id IS NULL OR op IS NULL OR binding IS NULL OR item_text IS NULL OR item_hash IS NULL
 OR capability IS NULL OR capability !~ '^[a-f0-9]{64}$' OR requested_product IS NOT NULL AND requested_product<1
 OR item_hash IS DISTINCT FROM encode(sha256(convert_to(item_text,'UTF8')),'hex')
 THEN RAISE EXCEPTION 'rewrite save invalid' USING ERRCODE='22023'; END IF;
 SELECT * INTO admission FROM secureshop_review.owned_listing_admissions WHERE operation_id=op;
 IF NOT FOUND OR admission.action<>'rewrite' OR admission.redacted_at IS NOT NULL OR admission.binding_json IS DISTINCT FROM binding
 OR admission.capability_sha256 IS DISTINCT FROM encode(sha256(convert_to(capability,'UTF8')),'hex')
 THEN RAISE EXCEPTION 'rewrite save denied' USING ERRCODE='42501'; END IF;
 b:=binding::jsonb; item:=item_text::jsonb;
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||(b#>>'{scope,platformOwnerId}'),0));
 PERFORM pg_advisory_xact_lock(hashtextextended('owned-listing-save:'||save_id::text,0));
 SELECT * INTO target FROM secureshop_review.product_targets WHERE target_id=admission.target_id FOR UPDATE;
 PERFORM secureshop_review.assert_owned_listing_target(op,admission.target_id,binding);
 SELECT * INTO saved FROM secureshop_review.owned_listing_rewrite_saves WHERE save_operation_id=save_id;
 IF FOUND THEN
  IF saved.rewrite_operation_id IS DISTINCT FROM op OR saved.target_id IS DISTINCT FROM admission.target_id
  OR saved.binding_sha256 IS DISTINCT FROM admission.binding_sha256 OR saved.request_sha256 IS DISTINCT FROM item_hash
  OR (saved.receipt_json::jsonb->>'requestedProductId')::integer IS DISTINCT FROM requested_product
  THEN RAISE EXCEPTION 'rewrite save conflict' USING ERRCODE='23505'; END IF;
  RETURN saved.receipt_json;
 END IF;
 -- Replay above is stable after subsequent catalog changes. First publication
 -- must still match the snapshot captured before model rewriting.
 INSERT INTO secureshop_review.owned_listing_catalog_revisions(target_id,revision) VALUES(admission.target_id,0) ON CONFLICT DO NOTHING;
 SELECT revision INTO current_revision FROM secureshop_review.owned_listing_catalog_revisions WHERE target_id=admission.target_id FOR UPDATE;
 IF current_revision IS DISTINCT FROM (b->>'catalogRevision')::bigint THEN
  RAISE EXCEPTION 'rewrite catalog changed' USING ERRCODE='40001';
 END IF;
 SELECT * INTO event FROM secureshop_review.owned_listing_events WHERE operation_id=op ORDER BY sequence DESC LIMIT 1;
 IF NOT FOUND OR event.state<>'completed' OR event.redacted_at IS NOT NULL OR event.payload_json IS NULL
 OR event.payload_sha256 IS DISTINCT FROM encode(sha256(convert_to(event.payload_json,'UTF8')),'hex')
 THEN RAISE EXCEPTION 'completed rewrite required' USING ERRCODE='55000'; END IF;
 effect:=event.payload_json::jsonb;
 IF effect->>'operationId' IS DISTINCT FROM op::text OR effect->>'requestSha256' IS DISTINCT FROM admission.request_sha256
 OR effect->'mocked' IS DISTINCT FROM 'false'::jsonb OR effect->'fallback' IS DISTINCT FROM 'false'::jsonb
 OR effect->>'provider' IS NULL OR btrim(effect->>'provider')='' OR btrim(effect->>'provider') ~* '^(mock|fixture|scripted|fallback|unavailable)$'
 OR effect->>'model' IS NULL OR btrim(effect->>'model')='' OR btrim(effect->>'model') ~* '^(mock|fixture|scripted|fallback|unavailable)$'
 OR effect->>'callId' IS NULL OR octet_length(effect->>'callId') NOT BETWEEN 1 AND 256
 OR effect->>'html' IS NULL OR octet_length(effect->>'html') NOT BETWEEN 1 AND 65536
 OR effect->>'htmlSha256' IS DISTINCT FROM encode(sha256(convert_to(effect->>'html','UTF8')),'hex')
 OR effect->>'sourceSha256' IS DISTINCT FROM encode(sha256(convert_to('['||to_json(admission.request_json::jsonb->>'title')::text||','||to_json(admission.request_json::jsonb->>'description')::text||']','UTF8')),'hex')
 THEN RAISE EXCEPTION 'genuine rewrite receipt required' USING ERRCODE='22023'; END IF;
 IF jsonb_typeof(item) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(item))<>6
 OR NOT(item ?& ARRAY['name','description','price','category','images','templateSource'])
 OR item->>'name' IS DISTINCT FROM admission.request_json::jsonb->>'title'
 OR item->>'description' IS DISTINCT FROM admission.request_json::jsonb->>'description'
 OR jsonb_typeof(item->'price') IS DISTINCT FROM 'number' OR (item->>'price')::numeric NOT BETWEEN 0 AND 99999999.99
 OR (item->>'price')::numeric<>round((item->>'price')::numeric,2)
 OR (item->'category'<>'null'::jsonb AND (jsonb_typeof(item->'category')<>'string' OR octet_length(item->>'category')>1024))
 OR (item->'templateSource'<>'null'::jsonb AND (jsonb_typeof(item->'templateSource')<>'string' OR octet_length(item->>'templateSource')>65536))
 OR jsonb_typeof(item->'images') IS DISTINCT FROM 'array' OR jsonb_array_length(item->'images')>16
 OR EXISTS(SELECT 1 FROM jsonb_array_elements(item->'images') image WHERE jsonb_typeof(image)<>'string' OR octet_length(image#>>'{}') NOT BETWEEN 1 AND 8192)
 THEN RAISE EXCEPTION 'rewrite source or product mismatch' USING ERRCODE='22023'; END IF;
 IF requested_product IS NULL THEN
  SELECT COALESCE(max(product_id),0)+1 INTO item_id FROM secureshop_review.product_target_products WHERE target_id=admission.target_id;
  INSERT INTO secureshop_review.product_target_products(target_id,product_id,source_retailer_id,retailer_id,source_product_sha256,name,description,description_html,price,category,image_url,images,stock_quantity,status,template_source,source_created_at,source_updated_at)
  VALUES(admission.target_id,item_id,(b#>>'{persona,id}')::integer,(b#>>'{persona,id}')::integer,sha256(convert_to(item_text,'UTF8')),item->>'name',item->>'description',effect->>'html',(item->>'price')::numeric,item->>'category',item#>>'{images,0}',item->'images',0,'active',item->>'templateSource',clock_timestamp(),clock_timestamp());
  INSERT INTO secureshop_review.product_target_merchant_listings(target_id,product_id,shop_user_id) VALUES(admission.target_id,item_id,(b#>>'{persona,id}')::integer);
 ELSE
  item_id:=requested_product;
  SELECT * INTO base FROM secureshop_review.product_target_products WHERE target_id=admission.target_id AND product_id=item_id AND retailer_id=(b#>>'{persona,id}')::integer;
  IF NOT FOUND THEN RAISE EXCEPTION 'owned product required' USING ERRCODE='42501'; END IF;
  SELECT * INTO overlay FROM secureshop_review.product_target_listing_overlays WHERE target_id=admission.target_id AND product_id=item_id;
  IF FOUND AND (overlay.shop_user_id IS DISTINCT FROM (b#>>'{persona,id}')::integer OR overlay.archived_at IS NOT NULL) THEN RAISE EXCEPTION 'product archived' USING ERRCODE='55000'; END IF;
  stock:=CASE WHEN overlay.product_id IS NULL THEN base.stock_quantity ELSE overlay.stock_quantity END;
  item_status:=CASE WHEN overlay.product_id IS NULL THEN base.status ELSE overlay.status END;
  -- Replace provenance inside this transaction before the ordinary-edit trigger.
  DELETE FROM secureshop_review.owned_listing_generated_products WHERE target_id=admission.target_id AND product_id=item_id;
  INSERT INTO secureshop_review.product_target_listing_overlays(target_id,product_id,shop_user_id,name,description,description_html,price,category,image_url,images,stock_quantity,status,template_source)
  VALUES(admission.target_id,item_id,(b#>>'{persona,id}')::integer,item->>'name',item->>'description',effect->>'html',(item->>'price')::numeric,item->>'category',item#>>'{images,0}',item->'images',stock,item_status,item->>'templateSource')
  ON CONFLICT(target_id,product_id) DO UPDATE SET name=EXCLUDED.name,description=EXCLUDED.description,description_html=EXCLUDED.description_html,price=EXCLUDED.price,category=EXCLUDED.category,image_url=EXCLUDED.image_url,images=EXCLUDED.images,stock_quantity=EXCLUDED.stock_quantity,status=EXCLUDED.status,template_source=EXCLUDED.template_source;
 END IF;
 INSERT INTO secureshop_review.owned_listing_generated_products(target_id,product_id,rewrite_operation_id,source_name,source_description,source_sha256,html_sha256)
 VALUES(admission.target_id,item_id,op,item->>'name',item->>'description',effect->>'sourceSha256',effect->>'htmlSha256');
 INSERT INTO secureshop_review.bound_audit_events(event_id,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id,shop_user_id,shop_role,actor,action,target,params_json,outcome,source_kind,source_id)
 VALUES(gen_random_uuid(),(b#>>'{scope,launchId}')::uuid,(b#>>'{scope,scenarioId}')::uuid,(b#>>'{scope,generation}')::bigint,(b#>>'{scope,platformOwnerId}')::integer,(b#>>'{scope,platformSessionId}')::integer,(b#>>'{persona,id}')::integer,'merchant','merchant','listing_rewrite_save',item_id::text,secureshop_review.owned_listing_audit_params(op,admission.target_id,jsonb_build_object('rewriteOperationId',op,'saveOperationId',save_id,'htmlSha256',effect->>'htmlSha256')),'completed','product',item_id::text);
 receipt:=jsonb_build_object('version',1,'saveOperationId',save_id,'rewriteOperationId',op,'targetId',admission.target_id,'requestedProductId',requested_product,'productId',item_id,'bindingSha256',admission.binding_sha256,'requestSha256',item_hash,'sourceSha256',effect->>'sourceSha256','htmlSha256',effect->>'htmlSha256')::text;
 INSERT INTO secureshop_review.owned_listing_rewrite_saves(save_operation_id,rewrite_operation_id,target_id,product_id,binding_sha256,request_sha256,receipt_json,receipt_sha256)
 VALUES(save_id,op,admission.target_id,item_id,admission.binding_sha256,item_hash,receipt,encode(sha256(convert_to(receipt,'UTF8')),'hex'));
 RETURN receipt;
END $$;
REVOKE ALL ON FUNCTION secureshop_review.consume_owned_listing_rewrite(uuid,uuid,text,integer,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.consume_owned_listing_rewrite(uuid,uuid,text,integer,text,text,text) TO dvaia_secureshop_review_runtime;

-- Retain the original cleanup packet format. New cleanup digests also bind
-- the retained immutable original grant; legacy digest bytes remain identical.
CREATE OR REPLACE FUNCTION secureshop_review.redact_owned_listing_target(requested_target uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE owner_id integer; ops integer; events integer; digest text;
BEGIN
 SELECT (binding_json::jsonb#>>'{scope,platformOwnerId}')::integer INTO owner_id
 FROM secureshop_review.owned_listing_admissions WHERE target_id=requested_target LIMIT 1;
 IF NOT FOUND THEN RETURN; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||owner_id::text,0));
 IF NOT EXISTS(SELECT 1 FROM secureshop_review.product_targets WHERE target_id=requested_target AND lifecycle='retired')
 AND NOT EXISTS(SELECT 1 FROM secureshop_review.bound_audit_owner_deletion_receipts WHERE original_platform_owner_id=owner_id)
 THEN RAISE EXCEPTION 'listing target remains active' USING ERRCODE='55000'; END IF;
 IF EXISTS(SELECT 1 FROM secureshop_review.owned_listing_cleanup_receipts WHERE target_id=requested_target) THEN RETURN; END IF;
 SELECT count(*)::integer INTO ops FROM secureshop_review.owned_listing_admissions WHERE target_id=requested_target;
 SELECT count(*)::integer INTO events FROM secureshop_review.owned_listing_events e JOIN secureshop_review.owned_listing_admissions a USING(operation_id) WHERE a.target_id=requested_target;
 SELECT encode(sha256(convert_to(COALESCE(string_agg(a.operation_id::text||':'||a.binding_sha256||':'||a.request_sha256||':'||COALESCE(e.sequence::text,'')||':'||COALESCE(e.payload_sha256,'')||CASE WHEN c.grant_id IS NULL THEN '' ELSE ':scene:'||c.grant_id::text END,'|' ORDER BY a.operation_id,e.sequence),''),'UTF8')),'hex') INTO digest
 FROM secureshop_review.owned_listing_admissions a LEFT JOIN secureshop_review.owned_listing_events e USING(operation_id) LEFT JOIN secureshop_review.owned_listing_scene_admissions c USING(operation_id) WHERE a.target_id=requested_target;
 UPDATE secureshop_review.owned_listing_events e SET payload_json=NULL,redacted_at=clock_timestamp()
 FROM secureshop_review.owned_listing_admissions a WHERE a.operation_id=e.operation_id AND a.target_id=requested_target AND e.redacted_at IS NULL;
 UPDATE secureshop_review.owned_listing_admissions SET request_json=NULL,redacted_at=clock_timestamp() WHERE target_id=requested_target AND redacted_at IS NULL;
 INSERT INTO secureshop_review.owned_listing_cleanup_receipts(target_id,original_platform_owner_id,operation_count,event_count,evidence_sha256)
 VALUES(requested_target,owner_id,ops,events,digest);
END $$;
