-- DRAFT forward-only extension of native-qualified 0022. Do not edit its predecessor.
-- Model decline is terminal, retains evidence, and is never successful publication/credit.
DO $$
DECLARE c record; matched integer:=0;
BEGIN
 FOR c IN SELECT conname FROM pg_constraint
 WHERE conrelid='secureshop_review.owned_listing_events'::regclass AND contype='c'
 AND pg_get_constraintdef(oid) ~ '\mstate\M'
 LOOP
   matched:=matched+1;
   EXECUTE format('ALTER TABLE secureshop_review.owned_listing_events DROP CONSTRAINT %I',c.conname);
 END LOOP;
 IF matched<>2 THEN RAISE EXCEPTION 'unexpected listing predecessor constraints'; END IF;
END $$;
ALTER TABLE secureshop_review.owned_listing_events ADD CONSTRAINT owned_listing_event_terminal_state
 CHECK(state IN ('running','effect_received','completed','unknown','failed','declined'));
ALTER TABLE secureshop_review.owned_listing_events ADD CONSTRAINT owned_listing_event_terminal_payload
 CHECK(redacted_at IS NOT NULL OR (state IN ('running','unknown') AND payload_json IS NULL)
 OR (state IN ('effect_received','completed','failed','declined') AND payload_json IS NOT NULL));
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
 SELECT * INTO target FROM secureshop_review.product_targets WHERE target_id=admission.target_id FOR SHARE;
 IF NOT FOUND OR target.lifecycle<>'active'
 OR ROW(target.launch_id,target.scenario_id,target.generation,target.original_platform_owner_id,target.original_platform_session_id,target.own_merchant_id)
 IS DISTINCT FROM ROW((b#>>'{scope,launchId}')::uuid,(b#>>'{scope,scenarioId}')::uuid,(b#>>'{scope,generation}')::bigint,
 (b#>>'{scope,platformOwnerId}')::integer,(b#>>'{scope,platformSessionId}')::integer,(b#>>'{persona,id}')::integer)
 THEN RAISE EXCEPTION 'active owned listing target required' USING ERRCODE='55000'; END IF;
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
