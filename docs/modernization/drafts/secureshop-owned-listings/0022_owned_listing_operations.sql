-- DRAFT ONLY. Not registered; native migration/permissions/lifecycle qualification is pending.
-- Platform persona authority is held by application cross-store fence. The local guard
-- additionally validates exact immutable product-target scope and active lifecycle.
CREATE TABLE secureshop_review.owned_listing_admissions (
 operation_id uuid PRIMARY KEY,
 target_id uuid NOT NULL,
 binding_json text NOT NULL CHECK(octet_length(binding_json)<=8192),
 binding_sha256 text NOT NULL CHECK(binding_sha256 ~ '^[0-9a-f]{64}$'),
 request_json text CHECK(request_json IS NULL OR octet_length(request_json)<=262144),
 capability_sha256 text NOT NULL CHECK(capability_sha256 ~ '^[0-9a-f]{64}$'),
 redacted_at timestamptz,
 request_sha256 text NOT NULL CHECK(request_sha256 ~ '^[0-9a-f]{64}$'),
 action text NOT NULL CHECK(action IN ('rewrite','import')),
 admitted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK(encode(sha256(convert_to(binding_json,'UTF8')),'hex')=binding_sha256),
 CHECK((request_json IS NULL)=(redacted_at IS NOT NULL)),
 CHECK(request_json IS NULL OR encode(sha256(convert_to(request_json,'UTF8')),'hex')=request_sha256)
);
CREATE TABLE secureshop_review.owned_listing_events (
 operation_id uuid NOT NULL REFERENCES secureshop_review.owned_listing_admissions(operation_id),
 event_id uuid NOT NULL UNIQUE,
 sequence integer NOT NULL CHECK(sequence BETWEEN 1 AND 16),
 state text NOT NULL CHECK(state IN ('running','effect_received','completed','unknown','failed')),
 payload_json text CHECK(payload_json IS NULL OR octet_length(payload_json)<=1048576),
 payload_sha256 text CHECK(payload_sha256 IS NULL OR payload_sha256 ~ '^[0-9a-f]{64}$'),
 recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 redacted_at timestamptz,
 PRIMARY KEY(operation_id,sequence),
 CHECK(redacted_at IS NOT NULL OR (payload_json IS NULL)=(payload_sha256 IS NULL)),
 CHECK(redacted_at IS NULL OR payload_json IS NULL),
 CHECK(payload_json IS NULL OR encode(sha256(convert_to(payload_json,'UTF8')),'hex')=payload_sha256),
 CHECK(redacted_at IS NOT NULL OR (state IN ('running','unknown') AND payload_json IS NULL)
    OR(state IN ('effect_received','completed','failed') AND payload_json IS NOT NULL))
);
REVOKE ALL ON secureshop_review.owned_listing_admissions,secureshop_review.owned_listing_events FROM PUBLIC;
REVOKE ALL ON secureshop_review.owned_listing_admissions,secureshop_review.owned_listing_events FROM dvaia_secureshop_review_runtime;
GRANT SELECT ON secureshop_review.owned_listing_admissions,secureshop_review.owned_listing_events TO dvaia_secureshop_review_runtime;

CREATE FUNCTION secureshop_review.guard_owned_listing_journal() RETURNS trigger
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
CREATE TRIGGER owned_listing_admission_guard BEFORE INSERT OR UPDATE OR DELETE ON secureshop_review.owned_listing_admissions
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_owned_listing_journal();
CREATE TRIGGER owned_listing_event_guard BEFORE INSERT OR UPDATE OR DELETE ON secureshop_review.owned_listing_events
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_owned_listing_journal();
REVOKE ALL ON FUNCTION secureshop_review.guard_owned_listing_journal() FROM PUBLIC;
REVOKE ALL ON FUNCTION secureshop_review.guard_owned_listing_journal() FROM dvaia_secureshop_review_runtime;

-- No runtime table mutation: capability preimage is supplied by the server and never stored.
CREATE FUNCTION secureshop_review.admit_owned_listing_operation(op uuid,target uuid,binding text,binding_hash text,request text,request_hash text,requested_action text,capability text)
RETURNS TABLE(newly_admitted boolean) LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE prior secureshop_review.owned_listing_admissions%ROWTYPE;
BEGIN
 IF op IS NULL OR target IS NULL OR binding IS NULL OR binding_hash IS NULL OR request IS NULL OR request_hash IS NULL OR requested_action IS NULL
 OR capability IS NULL OR capability !~ '^[0-9a-f]{64}$' THEN RAISE EXCEPTION 'listing admission invalid' USING ERRCODE='22023'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||(binding::jsonb#>>'{scope,platformOwnerId}'),0));
 PERFORM pg_advisory_xact_lock(hashtextextended('owned-listing:'||op::text,0));
 SELECT * INTO prior FROM secureshop_review.owned_listing_admissions WHERE operation_id=op;
 IF FOUND THEN
   IF prior.redacted_at IS NOT NULL OR ROW(prior.target_id,prior.binding_json,prior.binding_sha256,prior.request_json,prior.request_sha256,prior.action,prior.capability_sha256)
     IS DISTINCT FROM ROW(target,binding,binding_hash,request,request_hash,requested_action,encode(sha256(convert_to(capability,'UTF8')),'hex'))
   THEN RAISE EXCEPTION 'listing operation conflict' USING ERRCODE='55000'; END IF;
   RETURN QUERY SELECT false; RETURN;
 END IF;
 INSERT INTO secureshop_review.owned_listing_admissions(operation_id,target_id,binding_json,binding_sha256,request_json,request_sha256,action,capability_sha256)
 VALUES(op,target,binding,binding_hash,request,request_hash,requested_action,encode(sha256(convert_to(capability,'UTF8')),'hex'));
 RETURN QUERY SELECT true;
END $$;
CREATE FUNCTION secureshop_review.append_owned_listing_event(op uuid,event uuid,requested_sequence integer,requested_state text,payload text,payload_hash text,capability text)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE admission secureshop_review.owned_listing_admissions%ROWTYPE;
BEGIN
 IF op IS NULL OR event IS NULL OR requested_sequence IS NULL OR requested_state IS NULL OR capability IS NULL OR capability !~ '^[0-9a-f]{64}$'
 THEN RAISE EXCEPTION 'listing event invalid' USING ERRCODE='22023'; END IF;
 SELECT * INTO admission FROM secureshop_review.owned_listing_admissions WHERE operation_id=op;
 IF NOT FOUND OR admission.redacted_at IS NOT NULL OR admission.capability_sha256 IS DISTINCT FROM encode(sha256(convert_to(capability,'UTF8')),'hex')
 THEN RAISE EXCEPTION 'listing capability denied' USING ERRCODE='42501'; END IF;
 INSERT INTO secureshop_review.owned_listing_events(operation_id,event_id,sequence,state,payload_json,payload_sha256)
 VALUES(op,event,requested_sequence,requested_state,payload,payload_hash);
END $$;
REVOKE ALL ON FUNCTION secureshop_review.admit_owned_listing_operation(uuid,uuid,text,text,text,text,text,text),secureshop_review.append_owned_listing_event(uuid,uuid,integer,text,text,text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.admit_owned_listing_operation(uuid,uuid,text,text,text,text,text,text),secureshop_review.append_owned_listing_event(uuid,uuid,integer,text,text,text,text) TO dvaia_secureshop_review_runtime;

CREATE TABLE secureshop_review.owned_listing_cleanup_receipts(
 target_id uuid PRIMARY KEY, original_platform_owner_id integer NOT NULL,
 operation_count integer NOT NULL CHECK(operation_count>=0),event_count integer NOT NULL CHECK(event_count>=0),
 evidence_sha256 text NOT NULL CHECK(evidence_sha256 ~ '^[0-9a-f]{64}$'),redacted_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON secureshop_review.owned_listing_cleanup_receipts FROM PUBLIC,dvaia_secureshop_review_runtime;
GRANT SELECT ON secureshop_review.owned_listing_cleanup_receipts TO dvaia_secureshop_review_runtime;
CREATE FUNCTION secureshop_review.guard_owned_listing_cleanup() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN RAISE EXCEPTION 'listing cleanup receipt immutable' USING ERRCODE='55000'; END $$;
CREATE TRIGGER owned_listing_cleanup_immutable BEFORE UPDATE OR DELETE ON secureshop_review.owned_listing_cleanup_receipts
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_owned_listing_cleanup();
CREATE FUNCTION secureshop_review.redact_owned_listing_target(requested_target uuid) RETURNS void
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
 SELECT encode(sha256(convert_to(COALESCE(string_agg(a.operation_id::text||':'||a.binding_sha256||':'||a.request_sha256||':'||COALESCE(e.sequence::text,'')||':'||COALESCE(e.payload_sha256,''),'|' ORDER BY a.operation_id,e.sequence),''),'UTF8')),'hex') INTO digest
 FROM secureshop_review.owned_listing_admissions a LEFT JOIN secureshop_review.owned_listing_events e USING(operation_id) WHERE a.target_id=requested_target;
 UPDATE secureshop_review.owned_listing_events e SET payload_json=NULL,redacted_at=clock_timestamp()
 FROM secureshop_review.owned_listing_admissions a WHERE a.operation_id=e.operation_id AND a.target_id=requested_target AND e.redacted_at IS NULL;
 UPDATE secureshop_review.owned_listing_admissions SET request_json=NULL,redacted_at=clock_timestamp() WHERE target_id=requested_target AND redacted_at IS NULL;
 INSERT INTO secureshop_review.owned_listing_cleanup_receipts(target_id,original_platform_owner_id,operation_count,event_count,evidence_sha256)
 VALUES(requested_target,owner_id,ops,events,digest);
END $$;
CREATE FUNCTION secureshop_review.cleanup_owned_listing_lifecycle() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE selected_target uuid;
BEGIN
 IF TG_TABLE_NAME='product_targets' THEN
   IF OLD.lifecycle='active' AND NEW.lifecycle='retired' THEN PERFORM secureshop_review.redact_owned_listing_target(NEW.target_id); END IF;
 ELSE
   FOR selected_target IN SELECT DISTINCT target_id FROM secureshop_review.owned_listing_admissions WHERE (binding_json::jsonb#>>'{scope,platformOwnerId}')::integer=NEW.original_platform_owner_id
   LOOP PERFORM secureshop_review.redact_owned_listing_target(selected_target); END LOOP;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER product_target_listing_retirement AFTER UPDATE OF lifecycle ON secureshop_review.product_targets
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.cleanup_owned_listing_lifecycle();
CREATE TRIGGER z_owned_listing_owner_cleanup AFTER INSERT ON secureshop_review.bound_audit_owner_deletion_receipts
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.cleanup_owned_listing_lifecycle();
REVOKE ALL ON FUNCTION secureshop_review.guard_owned_listing_cleanup(),secureshop_review.redact_owned_listing_target(uuid),secureshop_review.cleanup_owned_listing_lifecycle() FROM PUBLIC,dvaia_secureshop_review_runtime;
-- Native SQL, deletion ordering, exact cleanup receipts and publication remain unqualified.

-- Catalog revision covers ordinary CRUD too; existing mutable content is untouched.
CREATE TABLE secureshop_review.owned_listing_catalog_revisions(
 target_id uuid PRIMARY KEY, revision bigint NOT NULL CHECK(revision BETWEEN 0 AND 9007199254740991)
);
CREATE TABLE secureshop_review.owned_listing_publications(
 operation_id uuid PRIMARY KEY REFERENCES secureshop_review.owned_listing_admissions(operation_id),
 event_id uuid NOT NULL UNIQUE, receipt_json text NOT NULL, receipt_sha256 text NOT NULL,
 published_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK(encode(sha256(convert_to(receipt_json,'UTF8')),'hex')=receipt_sha256)
);
REVOKE ALL ON secureshop_review.owned_listing_catalog_revisions,secureshop_review.owned_listing_publications FROM PUBLIC,dvaia_secureshop_review_runtime;
GRANT SELECT ON secureshop_review.owned_listing_catalog_revisions,secureshop_review.owned_listing_publications TO dvaia_secureshop_review_runtime;
CREATE TRIGGER owned_listing_publication_immutable BEFORE UPDATE OR DELETE ON secureshop_review.owned_listing_publications
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_owned_listing_cleanup();
CREATE FUNCTION secureshop_review.advance_owned_listing_catalog() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE selected_target uuid;
BEGIN
 selected_target:=CASE WHEN TG_OP='DELETE' THEN OLD.target_id ELSE NEW.target_id END;
 INSERT INTO secureshop_review.owned_listing_catalog_revisions(target_id,revision) VALUES(selected_target,1)
 ON CONFLICT(target_id) DO UPDATE SET revision=secureshop_review.owned_listing_catalog_revisions.revision+1;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER owned_listing_product_revision AFTER INSERT OR UPDATE OR DELETE ON secureshop_review.product_target_products
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.advance_owned_listing_catalog();
CREATE TRIGGER owned_listing_overlay_revision AFTER INSERT OR UPDATE OR DELETE ON secureshop_review.product_target_listing_overlays
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.advance_owned_listing_catalog();
REVOKE ALL ON FUNCTION secureshop_review.advance_owned_listing_catalog() FROM PUBLIC,dvaia_secureshop_review_runtime;

CREATE FUNCTION secureshop_review.publish_owned_listing_import(op uuid,event uuid,expected_sequence integer,capability text)
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
 IF NOT FOUND OR target.lifecycle<>'active' OR target.own_merchant_id IS DISTINCT FROM (b#>>'{persona,id}')::integer
 OR EXISTS(SELECT 1 FROM secureshop_review.bound_audit_owner_deletion_receipts WHERE original_platform_owner_id=target.original_platform_owner_id)
 THEN RAISE EXCEPTION 'listing target unavailable' USING ERRCODE='55000'; END IF;
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
   VALUES(a.target_id,next_id,target.own_merchant_id,target.own_merchant_id,sha256(convert_to(item::text,'UTF8')),item->>'name',item->>'description',NULL,round((item->>'price')::numeric,2),item->>'category',item#>>'{images,0}',item->'images',0,'active',item->>'templateSource',clock_timestamp(),clock_timestamp());
   INSERT INTO secureshop_review.product_target_merchant_listings(target_id,product_id,shop_user_id) VALUES(a.target_id,next_id,target.own_merchant_id);
   INSERT INTO secureshop_review.bound_audit_events(event_id,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id,shop_user_id,shop_role,actor,action,target,params_json,outcome,source_kind,source_id)
   VALUES(gen_random_uuid(),target.launch_id,target.scenario_id,target.generation,target.original_platform_owner_id,target.original_platform_session_id,target.own_merchant_id,'merchant','merchant','listing_import',next_id::text,item::text,'completed','product',next_id::text);
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
