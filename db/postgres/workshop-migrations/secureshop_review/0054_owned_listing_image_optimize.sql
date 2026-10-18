-- Forward-only V03 owned listing image optimization journal successor.
-- Preserve the intentional command construction sink while extending only the owned Listings journal.
DO $$
DECLARE constraint_name text; constraint_count integer;
BEGIN
 SELECT count(*),min(conname) INTO constraint_count,constraint_name FROM pg_constraint WHERE conrelid='secureshop_review.owned_listing_admissions'::regclass AND contype='c' AND pg_get_constraintdef(oid)=$def$CHECK ((action = ANY (ARRAY['rewrite'::text, 'import'::text])))$def$;
 IF constraint_count<>1 THEN RAISE EXCEPTION 'Expected exact V03 predecessor constraint unavailable' USING ERRCODE='55000'; END IF;
 EXECUTE format('ALTER TABLE secureshop_review.owned_listing_admissions DROP CONSTRAINT %I',constraint_name);
 ALTER TABLE secureshop_review.owned_listing_admissions ADD CONSTRAINT owned_listing_admissions_action_v03 CHECK(action IN ('rewrite','import','optimize'));
 SELECT count(*),min(conname) INTO constraint_count,constraint_name FROM pg_constraint WHERE conrelid='secureshop_review.owned_listing_events'::regclass AND contype='c' AND pg_get_constraintdef(oid)=$def$CHECK ((state = ANY (ARRAY['running'::text, 'effect_received'::text, 'completed'::text, 'unknown'::text, 'failed'::text, 'declined'::text])))$def$;
 IF constraint_count<>1 THEN RAISE EXCEPTION 'Expected exact V03 predecessor constraint unavailable' USING ERRCODE='55000'; END IF;
 EXECUTE format('ALTER TABLE secureshop_review.owned_listing_events DROP CONSTRAINT %I',constraint_name);
 ALTER TABLE secureshop_review.owned_listing_events ADD CONSTRAINT owned_listing_events_state_v03 CHECK(state IN ('running','effect_received','completed','unknown','failed','declined','denied'));
 SELECT count(*),min(conname) INTO constraint_count,constraint_name FROM pg_constraint WHERE conrelid='secureshop_review.owned_listing_events'::regclass AND contype='c' AND pg_get_constraintdef(oid) LIKE '%state = ANY%running%unknown%payload_json IS NULL%effect_received%completed%failed%payload_json IS NOT NULL%';
 IF constraint_count<>1 THEN RAISE EXCEPTION 'Expected exact V03 payload predecessor unavailable' USING ERRCODE='55000'; END IF;
 EXECUTE format('ALTER TABLE secureshop_review.owned_listing_events DROP CONSTRAINT %I',constraint_name);
 ALTER TABLE secureshop_review.owned_listing_events ADD CONSTRAINT owned_listing_events_payload_v03 CHECK(redacted_at IS NOT NULL OR (state IN ('running','unknown') AND payload_json IS NULL) OR(state IN ('effect_received','completed','failed','declined','denied') AND payload_json IS NOT NULL));
END $$;

DO $$
DECLARE guard_source text;
 old_guard_sha256 constant text := '335b7bc74b8c7c4d1d531ac4f7f02c3f7e3513646c17603011b6a9e1a8c8fa83';
 upgraded_guard_sha256 constant text := 'dd34dd8956071640c4af36f8489afbcb22b40dbe3d17d3d6c3f24fb1845bb426';
 old_0 constant text := $old0$ THEN RAISE EXCEPTION 'listing binding invalid' USING ERRCODE='22023'; END IF;
 -- Canonical owner lock matches cleanup order before target lock.$old0$;
 new_0 constant text := $new0$ THEN RAISE EXCEPTION 'listing binding invalid' USING ERRCODE='22023'; END IF;
 IF admission.action='optimize' AND (
   (SELECT count(*) FROM jsonb_object_keys(r))<>9 OR NOT (r ?& ARRAY['version','action','operationId','productId','imageUrl','imageUrlSha256','sceneId','sceneGeneration','grantId']) OR jsonb_typeof(r->'version') IS DISTINCT FROM 'number' OR r->'version' IS DISTINCT FROM '1'::jsonb OR jsonb_typeof(r->'productId') IS DISTINCT FROM 'number' OR jsonb_typeof(r->'sceneGeneration') IS DISTINCT FROM 'number' OR jsonb_typeof(r->'imageUrl') IS DISTINCT FROM 'string' OR jsonb_typeof(r->'imageUrlSha256') IS DISTINCT FROM 'string' OR jsonb_typeof(r->'sceneId') IS DISTINCT FROM 'string' OR jsonb_typeof(r->'grantId') IS DISTINCT FROM 'string'
   OR (r->>'productId')::numeric<>trunc((r->>'productId')::numeric) OR (r->>'productId')::bigint NOT BETWEEN 1 AND 2147483647 OR octet_length(r->>'imageUrl') NOT BETWEEN 1 AND 4096 OR (r->>'sceneGeneration')::numeric<>trunc((r->>'sceneGeneration')::numeric) OR (r->>'sceneGeneration')::bigint<1
   OR r->>'imageUrlSha256' IS DISTINCT FROM encode(sha256(convert_to(r->>'imageUrl','UTF8')),'hex') OR r->>'sceneId' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$' OR r->>'grantId' !~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
   OR octet_length((r->>'imageUrl')||' -strip -quality 82 '||(r->>'imageUrl')||'.opt.jpg')>8192 OR NOT EXISTS(SELECT 1 FROM secureshop_review.owned_listing_scene_admissions a JOIN secureshop_review.scene_execution_grants g ON g.grant_id=a.grant_id WHERE a.operation_id=admission.operation_id AND a.target_id=admission.target_id AND a.grant_id=(r->>'grantId')::uuid AND g.scene_id=(r->>'sceneId')::uuid AND g.scene_generation=(r->>'sceneGeneration')::bigint)
 ) THEN RAISE EXCEPTION 'listing optimize request invalid' USING ERRCODE='22023'; END IF;
 -- Canonical owner lock matches cleanup order before target lock.$new0$;
 old_1 constant text := $old1$   (previous_state='admitted' AND NEW.state IN ('running','failed')) OR
   (admission.action='import' AND previous_state IN ('admitted','effect_received') AND NEW.state='declined') OR$old1$;
 new_1 constant text := $new1$   (previous_state='admitted' AND NEW.state IN ('running','failed')) OR
   (admission.action='optimize' AND previous_state='admitted' AND NEW.state='denied') OR
   (admission.action='import' AND previous_state IN ('admitted','effect_received') AND NEW.state='declined') OR$new1$;
 old_2 constant text := $old2$ IF NEW.state='failed' THEN$old2$;
 new_2 constant text := $new2$ IF NEW.state='denied' THEN
   p:=NEW.payload_json::jsonb;
   IF admission.action<>'optimize' OR b->>'mode'<>'fixed' OR jsonb_typeof(p) IS DISTINCT FROM 'object'
   OR (SELECT count(*) FROM jsonb_object_keys(p))<>7 OR jsonb_typeof(p->'version') IS DISTINCT FROM 'number' OR p->'version' IS DISTINCT FROM '1'::jsonb OR jsonb_typeof(p->'productId') IS DISTINCT FROM 'number' OR p->'productId' IS DISTINCT FROM r->'productId'
   OR p->>'operationId' IS DISTINCT FROM admission.operation_id::text
   OR p->>'imageUrlSha256' IS DISTINCT FROM r->>'imageUrlSha256' OR p->>'mode' IS DISTINCT FROM 'fixed'
   OR p->>'code' IS DISTINCT FROM 'LISTING_OPTIMIZE_FIXED_DENIED' OR p->'dispatched' IS DISTINCT FROM 'false'::jsonb
   THEN RAISE EXCEPTION 'listing optimize denial required' USING ERRCODE='22023'; END IF;
 END IF;
 IF NEW.state='failed' THEN$new2$;
 old_3 constant text := $old3$   IF NEW.state='completed' AND admission.action='rewrite' AND (NEW.payload_json IS DISTINCT FROM prior.payload_json OR NEW.payload_sha256 IS DISTINCT FROM prior.payload_sha256)
   THEN RAISE EXCEPTION 'rewrite receipt changed' USING ERRCODE='55000'; END IF;$old3$;
 new_3 constant text := $new3$   IF admission.action='optimize' AND (
     (SELECT count(*) FROM jsonb_object_keys(p))<>9 OR jsonb_typeof(p->'version') IS DISTINCT FROM 'number' OR p->'version' IS DISTINCT FROM '1'::jsonb OR jsonb_typeof(p->'productId') IS DISTINCT FROM 'number' OR p->'productId' IS DISTINCT FROM r->'productId'
     OR p->>'operationId' IS DISTINCT FROM admission.operation_id::text
     OR p->>'imageUrlSha256' IS DISTINCT FROM r->>'imageUrlSha256' OR p->>'targetId' IS DISTINCT FROM admission.target_id::text
     OR p->>'command' IS DISTINCT FROM 'convert '||(r->>'imageUrl')||' -strip -quality 82 '||(r->>'imageUrl')||'.opt.jpg'
     OR p->>'hostname' IS DISTINCT FROM 'system-diag-'||replace(admission.target_id::text,'-','')
     OR p->>'diagnosticBindingSha256' IS NULL OR p->>'diagnosticBindingSha256' !~ '^[a-f0-9]{64}$'
     OR jsonb_typeof(p->'remoteReceipt') IS DISTINCT FROM 'object'
     OR p#>>'{remoteReceipt,targetId}' IS DISTINCT FROM admission.target_id::text
     OR p#>>'{remoteReceipt,hostname}' IS DISTINCT FROM p->>'hostname'
     OR p#>>'{remoteReceipt,bindingSha256}' IS DISTINCT FROM p->>'diagnosticBindingSha256'
     OR p#>>'{remoteReceipt,result,operationId}' IS DISTINCT FROM admission.operation_id::text
     OR p#>>'{remoteReceipt,result,command}' IS DISTINCT FROM p->>'command'
     OR p#>'{remoteReceipt,result,executed}' IS DISTINCT FROM 'true'::jsonb
     OR p#>'{remoteReceipt,result,drained}' IS DISTINCT FROM 'true'::jsonb
     OR p#>'{remoteReceipt,result,timedOut}' IS DISTINCT FROM 'false'::jsonb
   ) THEN RAISE EXCEPTION 'listing optimize receipt required' USING ERRCODE='22023'; END IF;
   IF NEW.state='completed' AND admission.action IN ('rewrite','optimize') AND (NEW.payload_json IS DISTINCT FROM prior.payload_json OR NEW.payload_sha256 IS DISTINCT FROM prior.payload_sha256)
   THEN RAISE EXCEPTION 'listing receipt changed' USING ERRCODE='55000'; END IF;$new3$;
BEGIN
 SELECT p.prosrc INTO guard_source FROM pg_proc p WHERE p.oid='secureshop_review.guard_owned_listing_journal()'::regprocedure;
 IF guard_source IS NULL OR encode(sha256(convert_to(guard_source,'UTF8')),'hex')<>old_guard_sha256 THEN RAISE EXCEPTION 'Expected scene-bound Listings journal guard unavailable' USING ERRCODE='55000'; END IF;
 IF position(old_0 IN guard_source)=0 THEN RAISE EXCEPTION 'V03 journal anchor 0 unavailable' USING ERRCODE='55000'; END IF;
 guard_source:=replace(guard_source,old_0,new_0);
 IF position(old_1 IN guard_source)=0 THEN RAISE EXCEPTION 'V03 journal anchor 1 unavailable' USING ERRCODE='55000'; END IF;
 guard_source:=replace(guard_source,old_1,new_1);
 IF position(old_2 IN guard_source)=0 THEN RAISE EXCEPTION 'V03 journal anchor 2 unavailable' USING ERRCODE='55000'; END IF;
 guard_source:=replace(guard_source,old_2,new_2);
 IF position(old_3 IN guard_source)=0 THEN RAISE EXCEPTION 'V03 journal anchor 3 unavailable' USING ERRCODE='55000'; END IF;
 guard_source:=replace(guard_source,old_3,new_3);
 IF encode(sha256(convert_to(guard_source,'UTF8')),'hex')<>upgraded_guard_sha256 THEN RAISE EXCEPTION 'V03 journal guard checksum mismatch' USING ERRCODE='55000'; END IF;
 EXECUTE format('CREATE OR REPLACE FUNCTION secureshop_review.guard_owned_listing_journal() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS %L',guard_source);
END $$;
REVOKE ALL ON FUNCTION secureshop_review.guard_owned_listing_journal() FROM PUBLIC,dvaia_secureshop_review_runtime;
