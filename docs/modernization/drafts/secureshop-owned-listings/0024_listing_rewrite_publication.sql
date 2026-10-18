-- Unregistered forward-only candidate. Requires qualified 0022/0023 unchanged.
CREATE TABLE secureshop_review.owned_listing_generated_products(
 target_id uuid NOT NULL, product_id integer NOT NULL, rewrite_operation_id uuid NOT NULL,
 source_name text NOT NULL, source_description text NOT NULL, source_sha256 text NOT NULL,
 html_sha256 text NOT NULL, PRIMARY KEY(target_id,product_id),
 FOREIGN KEY(target_id,product_id) REFERENCES secureshop_review.product_target_products(target_id,product_id) ON DELETE CASCADE,
 CHECK(source_sha256 ~ '^[a-f0-9]{64}$' AND html_sha256 ~ '^[a-f0-9]{64}$')
);
CREATE TABLE secureshop_review.owned_listing_rewrite_saves(
 save_operation_id uuid PRIMARY KEY, rewrite_operation_id uuid NOT NULL, target_id uuid NOT NULL,
 product_id integer NOT NULL, binding_sha256 text NOT NULL, request_sha256 text NOT NULL,
 receipt_json text NOT NULL, receipt_sha256 text NOT NULL,
 CHECK(binding_sha256 ~ '^[a-f0-9]{64}$' AND request_sha256 ~ '^[a-f0-9]{64}$'),
 CHECK(receipt_sha256=encode(sha256(convert_to(receipt_json,'UTF8')),'hex'))
);
CREATE TRIGGER owned_listing_rewrite_saves_immutable BEFORE UPDATE OR DELETE ON secureshop_review.owned_listing_rewrite_saves
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_owned_listing_cleanup();
REVOKE ALL ON secureshop_review.owned_listing_generated_products,secureshop_review.owned_listing_rewrite_saves FROM PUBLIC,dvaia_secureshop_review_runtime;
GRANT SELECT ON secureshop_review.owned_listing_generated_products,secureshop_review.owned_listing_rewrite_saves TO dvaia_secureshop_review_runtime;

CREATE FUNCTION secureshop_review.invalidate_owned_listing_generated_html() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE provenance secureshop_review.owned_listing_generated_products%ROWTYPE;
BEGIN
 SELECT * INTO provenance FROM secureshop_review.owned_listing_generated_products
 WHERE target_id=NEW.target_id AND product_id=NEW.product_id;
 IF FOUND AND (NEW.name IS DISTINCT FROM provenance.source_name OR NEW.description IS DISTINCT FROM provenance.source_description
 OR encode(sha256(convert_to(COALESCE(NEW.description_html,''),'UTF8')),'hex') IS DISTINCT FROM provenance.html_sha256) THEN
   -- Only previously receipt-generated HTML is invalidated. Raw/seeded teaching
   -- HTML with no generated provenance is never rewritten by this trigger.
   -- Ordinary source-only CRUD carries the old generated HTML: clear that
   -- stale value. An explicitly different raw HTML value is a new teaching
   -- sink, so retain it while removing all model-generated provenance.
   IF encode(sha256(convert_to(COALESCE(NEW.description_html,''),'UTF8')),'hex') = provenance.html_sha256 THEN
     NEW.description_html:=NULL;
   END IF;
   DELETE FROM secureshop_review.owned_listing_generated_products WHERE target_id=NEW.target_id AND product_id=NEW.product_id;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER invalidate_owned_listing_generated_product BEFORE UPDATE ON secureshop_review.product_target_products
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.invalidate_owned_listing_generated_html();
CREATE TRIGGER invalidate_owned_listing_generated_overlay BEFORE INSERT OR UPDATE ON secureshop_review.product_target_listing_overlays
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.invalidate_owned_listing_generated_html();
REVOKE ALL ON FUNCTION secureshop_review.invalidate_owned_listing_generated_html() FROM PUBLIC,dvaia_secureshop_review_runtime;

CREATE FUNCTION secureshop_review.consume_owned_listing_rewrite(save_id uuid,op uuid,binding text,requested_product integer,item_text text,item_hash text,capability text)
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
 IF NOT FOUND OR target.lifecycle<>'active' OR target.own_merchant_id IS DISTINCT FROM (b#>>'{persona,id}')::integer
 OR target.launch_id IS DISTINCT FROM (b#>>'{scope,launchId}')::uuid OR target.scenario_id IS DISTINCT FROM (b#>>'{scope,scenarioId}')::uuid
 OR target.generation IS DISTINCT FROM (b#>>'{scope,generation}')::integer
 OR target.original_platform_owner_id IS DISTINCT FROM (b#>>'{scope,platformOwnerId}')::integer
 OR target.original_platform_session_id IS DISTINCT FROM (b#>>'{scope,platformSessionId}')::integer
 OR EXISTS(SELECT 1 FROM secureshop_review.bound_audit_owner_deletion_receipts WHERE original_platform_owner_id=target.original_platform_owner_id)
 THEN RAISE EXCEPTION 'rewrite target unavailable' USING ERRCODE='55000'; END IF;
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
  VALUES(admission.target_id,item_id,target.own_merchant_id,target.own_merchant_id,sha256(convert_to(item_text,'UTF8')),item->>'name',item->>'description',effect->>'html',(item->>'price')::numeric,item->>'category',item#>>'{images,0}',item->'images',0,'active',item->>'templateSource',clock_timestamp(),clock_timestamp());
  INSERT INTO secureshop_review.product_target_merchant_listings(target_id,product_id,shop_user_id) VALUES(admission.target_id,item_id,target.own_merchant_id);
 ELSE
  item_id:=requested_product;
  SELECT * INTO base FROM secureshop_review.product_target_products WHERE target_id=admission.target_id AND product_id=item_id AND retailer_id=target.own_merchant_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'owned product required' USING ERRCODE='42501'; END IF;
  SELECT * INTO overlay FROM secureshop_review.product_target_listing_overlays WHERE target_id=admission.target_id AND product_id=item_id;
  IF FOUND AND overlay.archived_at IS NOT NULL THEN RAISE EXCEPTION 'product archived' USING ERRCODE='55000'; END IF;
  stock:=CASE WHEN overlay.product_id IS NULL THEN base.stock_quantity ELSE overlay.stock_quantity END;
  item_status:=CASE WHEN overlay.product_id IS NULL THEN base.status ELSE overlay.status END;
  -- Replace provenance inside this transaction before the ordinary-edit trigger.
  DELETE FROM secureshop_review.owned_listing_generated_products WHERE target_id=admission.target_id AND product_id=item_id;
  INSERT INTO secureshop_review.product_target_listing_overlays(target_id,product_id,shop_user_id,name,description,description_html,price,category,image_url,images,stock_quantity,status,template_source)
  VALUES(admission.target_id,item_id,target.own_merchant_id,item->>'name',item->>'description',effect->>'html',(item->>'price')::numeric,item->>'category',item#>>'{images,0}',item->'images',stock,item_status,item->>'templateSource')
  ON CONFLICT(target_id,product_id) DO UPDATE SET name=EXCLUDED.name,description=EXCLUDED.description,description_html=EXCLUDED.description_html,price=EXCLUDED.price,category=EXCLUDED.category,image_url=EXCLUDED.image_url,images=EXCLUDED.images,stock_quantity=EXCLUDED.stock_quantity,status=EXCLUDED.status,template_source=EXCLUDED.template_source;
 END IF;
 INSERT INTO secureshop_review.owned_listing_generated_products(target_id,product_id,rewrite_operation_id,source_name,source_description,source_sha256,html_sha256)
 VALUES(admission.target_id,item_id,op,item->>'name',item->>'description',effect->>'sourceSha256',effect->>'htmlSha256');
 INSERT INTO secureshop_review.bound_audit_events(event_id,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id,shop_user_id,shop_role,actor,action,target,params_json,outcome,source_kind,source_id)
 VALUES(gen_random_uuid(),target.launch_id,target.scenario_id,target.generation,target.original_platform_owner_id,target.original_platform_session_id,target.own_merchant_id,'merchant','merchant','listing_rewrite_save',item_id::text,jsonb_build_object('rewriteOperationId',op,'saveOperationId',save_id,'htmlSha256',effect->>'htmlSha256')::text,'completed','product',item_id::text);
 receipt:=jsonb_build_object('version',1,'saveOperationId',save_id,'rewriteOperationId',op,'targetId',admission.target_id,'requestedProductId',requested_product,'productId',item_id,'bindingSha256',admission.binding_sha256,'requestSha256',item_hash,'sourceSha256',effect->>'sourceSha256','htmlSha256',effect->>'htmlSha256')::text;
 INSERT INTO secureshop_review.owned_listing_rewrite_saves(save_operation_id,rewrite_operation_id,target_id,product_id,binding_sha256,request_sha256,receipt_json,receipt_sha256)
 VALUES(save_id,op,admission.target_id,item_id,admission.binding_sha256,item_hash,receipt,encode(sha256(convert_to(receipt,'UTF8')),'hex'));
 RETURN receipt;
END $$;
REVOKE ALL ON FUNCTION secureshop_review.consume_owned_listing_rewrite(uuid,uuid,text,integer,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.consume_owned_listing_rewrite(uuid,uuid,text,integer,text,text,text) TO dvaia_secureshop_review_runtime;
