-- Preserve exact publication preimages without retaining them past canonical
-- target retirement. Old revisions are intentionally NOT backfilled.
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_proc WHERE oid='secureshop_review.publish_product_embedding_revision(uuid,uuid,uuid,bigint,integer,integer,uuid,bytea,bytea,uuid,jsonb)'::regprocedure
  AND encode(sha256(convert_to(prosrc,'UTF8')),'hex')='9a3f74d85640bb5b957074a101077935fa2bd44a0813dcf551c89cc119a2f283') THEN
  RAISE EXCEPTION 'Unexpected embedding publisher predecessor';
 END IF;
END $$;

CREATE TABLE secureshop_review.product_target_embedding_preimages (
 revision_id uuid PRIMARY KEY REFERENCES secureshop_review.product_target_embedding_revisions(revision_id),
 target_id uuid NOT NULL REFERENCES secureshop_review.product_targets(target_id),
 source_set_json text NOT NULL, vectors_json text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE secureshop_review.product_target_manual_preimages (
 operation_id uuid PRIMARY KEY REFERENCES secureshop_review.product_target_manual_ingests(operation_id),
 target_id uuid NOT NULL REFERENCES secureshop_review.product_targets(target_id),
 documents_json text NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON TABLE secureshop_review.product_target_embedding_preimages,secureshop_review.product_target_manual_preimages FROM PUBLIC,dvaia_secureshop_review_runtime;
GRANT SELECT ON TABLE secureshop_review.product_target_embedding_preimages,secureshop_review.product_target_manual_preimages TO dvaia_secureshop_review_runtime;

CREATE FUNCTION secureshop_review.guard_embedding_preimage_privacy_cleanup()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,secureshop_review AS $$
BEGIN
 IF TG_OP='DELETE' AND current_user='dvaia_secureshop_review_migration' AND EXISTS(
  SELECT 1 FROM secureshop_review.product_targets t
  JOIN secureshop_review.product_target_embedding_cleanup_receipts c USING(target_id)
  WHERE t.target_id=OLD.target_id AND t.lifecycle='retired'
   AND c.launch_id=t.launch_id AND c.scenario_id=t.scenario_id AND c.generation=t.generation
   AND c.original_platform_owner_id=t.original_platform_owner_id
   AND c.original_platform_session_id=t.original_platform_session_id
 ) THEN RETURN OLD; END IF;
 RAISE EXCEPTION 'Original preimages are immutable outside canonical retirement' USING ERRCODE='55000';
END $$;
REVOKE ALL ON FUNCTION secureshop_review.guard_embedding_preimage_privacy_cleanup() FROM PUBLIC;
CREATE TRIGGER embedding_preimages_immutable BEFORE UPDATE OR DELETE ON secureshop_review.product_target_embedding_preimages
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_embedding_preimage_privacy_cleanup();
CREATE TRIGGER manual_preimages_immutable BEFORE UPDATE OR DELETE ON secureshop_review.product_target_manual_preimages
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_embedding_preimage_privacy_cleanup();

CREATE FUNCTION secureshop_review.cleanup_original_preimages_on_target_retirement()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
BEGIN
 IF NEW.lifecycle='retired' THEN
  -- Reuse the checked canonical cleanup, including its replay conflict guards.
  PERFORM secureshop_review.cleanup_retired_product_embeddings(NEW.target_id);
  DELETE FROM secureshop_review.product_target_embedding_preimages WHERE target_id=NEW.target_id;
  DELETE FROM secureshop_review.product_target_manual_preimages WHERE target_id=NEW.target_id;
 END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION secureshop_review.cleanup_original_preimages_on_target_retirement() FROM PUBLIC,dvaia_secureshop_review_runtime;
CREATE TRIGGER zz_original_preimage_privacy_retirement AFTER UPDATE OF lifecycle ON secureshop_review.product_targets
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.cleanup_original_preimages_on_target_retirement();

CREATE OR REPLACE FUNCTION secureshop_review.publish_product_embedding_revision(
 requested_target uuid,requested_launch uuid,requested_scenario uuid,requested_generation bigint,
 requested_owner integer,requested_session integer,requested_operation uuid,requested_fingerprint bytea,
 requested_source_digest bytea,requested_head uuid,documents jsonb)
RETURNS TABLE(revision_id uuid,runtime_fingerprint bytea,source_set_digest bytea,vector_digest bytea,document_count integer,replayed boolean)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE target secureshop_review.product_targets%ROWTYPE; cfg secureshop_review.product_target_retrieval_config%ROWTYPE;
 prior secureshop_review.product_target_embedding_revisions%ROWTYPE; current_head uuid; current_digest bytea;
 computed_vector_digest bytea; item jsonb; val jsonb; source_count integer; payload_count integer;
BEGIN
 IF requested_operation IS NULL OR requested_fingerprint IS NULL OR octet_length(requested_fingerprint)<>32
 OR requested_source_digest IS NULL OR octet_length(requested_source_digest)<>32
 OR jsonb_typeof(documents) IS DISTINCT FROM 'array' OR octet_length(documents::text)>67108864 THEN
 RAISE EXCEPTION 'invalid embedding publication' USING ERRCODE='22023'; END IF;
 payload_count:=jsonb_array_length(documents);
 IF payload_count>4096 THEN RAISE EXCEPTION 'embedding publication too large' USING ERRCODE='22023'; END IF;
 SELECT * INTO target FROM secureshop_review.product_targets t WHERE t.target_id=requested_target FOR UPDATE;
 IF NOT FOUND OR target.lifecycle<>'active' OR target.launch_id IS DISTINCT FROM requested_launch
 OR target.scenario_id IS DISTINCT FROM requested_scenario OR target.generation IS DISTINCT FROM requested_generation
 OR target.original_platform_owner_id IS DISTINCT FROM requested_owner OR target.original_platform_session_id IS DISTINCT FROM requested_session THEN
 RAISE EXCEPTION 'embedding target unavailable' USING ERRCODE='55000'; END IF;
 SELECT * INTO cfg FROM secureshop_review.product_target_retrieval_config c WHERE c.target_id=requested_target FOR SHARE;
 IF NOT FOUND OR cfg.lifecycle<>'active' THEN RAISE EXCEPTION 'embedding source unavailable' USING ERRCODE='55000'; END IF;
 SELECT secureshop_review.product_embedding_source_digest(requested_target,requested_generation) INTO current_digest;
 IF current_digest<>requested_source_digest THEN RAISE EXCEPTION 'embedding sources changed' USING ERRCODE='55000'; END IF;
 SELECT count(*) INTO source_count FROM secureshop_review.product_target_retrieval_documents d WHERE d.target_id=requested_target AND d.generation=requested_generation;
 IF source_count<>payload_count THEN RAISE EXCEPTION 'embedding cardinality mismatch' USING ERRCODE='22023'; END IF;
 FOR item IN SELECT value FROM jsonb_array_elements(documents) LOOP
  IF jsonb_typeof(item) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(item))<>5
  OR NOT(item ?& ARRAY['sourceKind','sourceId','chunkIndex','sourceSha256','embedding'])
  OR jsonb_typeof(item->'sourceKind') IS DISTINCT FROM 'string'
  OR jsonb_typeof(item->'sourceId') IS DISTINCT FROM 'string' OR item->>'sourceId' !~ '^[1-9][0-9]{0,15}$'
  OR jsonb_typeof(item->'chunkIndex') IS DISTINCT FROM 'number' OR (item->>'chunkIndex')::numeric<>trunc((item->>'chunkIndex')::numeric)
  OR jsonb_typeof(item->'sourceSha256') IS DISTINCT FROM 'string' OR item->>'sourceSha256' !~ '^[0-9a-f]{64}$'
  OR jsonb_typeof(item->'embedding') IS DISTINCT FROM 'array' THEN
   RAISE EXCEPTION 'invalid embedding document' USING ERRCODE='22023'; END IF;
  IF jsonb_array_length(item->'embedding')<>384 THEN RAISE EXCEPTION 'embedding dimension mismatch' USING ERRCODE='22023'; END IF;
  FOR val IN SELECT value FROM jsonb_array_elements(item->'embedding') LOOP
   IF jsonb_typeof(val) IS DISTINCT FROM 'number' OR val::text::double precision='NaN'::double precision OR abs(val::text::double precision)='Infinity'::double precision THEN
    RAISE EXCEPTION 'embedding must be finite' USING ERRCODE='22023'; END IF;
  END LOOP;
  IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(item->'embedding') n WHERE n::text::double precision<>0) THEN RAISE EXCEPTION 'zero embedding' USING ERRCODE='22023'; END IF;
  IF NOT EXISTS(SELECT 1 FROM secureshop_review.product_target_retrieval_documents d WHERE d.target_id=requested_target AND d.generation=requested_generation
   AND d.source_kind=item->>'sourceKind' AND d.source_id=(item->>'sourceId')::bigint AND d.chunk_index=(item->>'chunkIndex')::integer
   AND d.source_sha256=decode(item->>'sourceSha256','hex')) THEN RAISE EXCEPTION 'embedding source mismatch' USING ERRCODE='55000'; END IF;
 END LOOP;
 IF EXISTS(SELECT 1 FROM jsonb_array_elements(documents) d GROUP BY d->>'sourceKind',d->>'sourceId',(d->>'chunkIndex')::integer HAVING count(*)>1) THEN RAISE EXCEPTION 'duplicate embedding source' USING ERRCODE='22023'; END IF;
 SELECT sha256(convert_to(COALESCE(jsonb_agg(value ORDER BY value->>'sourceKind' COLLATE "C",(value->>'sourceId')::bigint,(value->>'chunkIndex')::integer),'[]'::jsonb)::text,'UTF8')) INTO computed_vector_digest FROM jsonb_array_elements(documents);
 SELECT * INTO prior FROM secureshop_review.product_target_embedding_revisions r WHERE r.revision_id=requested_operation;
 IF FOUND THEN
  IF prior.target_id<>requested_target OR prior.runtime_fingerprint<>requested_fingerprint OR prior.source_set_digest<>requested_source_digest
   OR prior.vector_digest<>computed_vector_digest OR prior.expected_head IS DISTINCT FROM requested_head THEN RAISE EXCEPTION 'embedding replay conflict' USING ERRCODE='55000'; END IF;
  RETURN QUERY SELECT prior.revision_id,prior.runtime_fingerprint,prior.source_set_digest,prior.vector_digest,prior.document_count,true; RETURN;
 END IF;
 SELECT h.revision_id INTO current_head FROM secureshop_review.product_target_embedding_heads h WHERE h.target_id=requested_target FOR UPDATE;
 IF current_head IS DISTINCT FROM requested_head THEN RAISE EXCEPTION 'embedding head changed' USING ERRCODE='55000'; END IF;
 INSERT INTO secureshop_review.product_target_embedding_revisions(revision_id,target_id,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id,runtime_fingerprint,source_set_digest,vector_digest,expected_head,document_count)
 VALUES(requested_operation,requested_target,requested_launch,requested_scenario,requested_generation,requested_owner,requested_session,requested_fingerprint,requested_source_digest,computed_vector_digest,requested_head,payload_count);
 INSERT INTO secureshop_review.product_target_embedding_vectors(revision_id,source_kind,source_id,chunk_index,source_sha256,embedding)
 SELECT requested_operation,d->>'sourceKind',(d->>'sourceId')::bigint,(d->>'chunkIndex')::integer,decode(d->>'sourceSha256','hex'),ARRAY(SELECT v::text::double precision FROM jsonb_array_elements(d->'embedding') v) FROM jsonb_array_elements(documents) d;
 -- Capture original canonical input, never float8[] reserialization.
 INSERT INTO secureshop_review.product_target_embedding_preimages(revision_id,target_id,source_set_json,vectors_json)
 SELECT requested_operation,requested_target,
  COALESCE((SELECT jsonb_agg(jsonb_build_object('sourceKind',d.source_kind,'sourceId',d.source_id::text,
   'chunkIndex',d.chunk_index,'text',d.body,'sourceSha256',encode(d.source_sha256,'hex'))
   ORDER BY d.source_kind COLLATE "C",d.source_id,d.chunk_index)
   FROM secureshop_review.product_target_retrieval_documents d
   WHERE d.target_id=requested_target AND d.generation=requested_generation),'[]'::jsonb)::text,
  COALESCE((SELECT jsonb_agg(value ORDER BY value->>'sourceKind' COLLATE "C",(value->>'sourceId')::bigint,
   (value->>'chunkIndex')::integer) FROM jsonb_array_elements(documents)),'[]'::jsonb)::text;
 IF NOT EXISTS(SELECT 1 FROM secureshop_review.product_target_embedding_preimages p
  JOIN secureshop_review.product_target_embedding_revisions r USING(revision_id)
  WHERE p.revision_id=requested_operation AND p.target_id=r.target_id
   AND sha256(convert_to(p.source_set_json,'UTF8'))=r.source_set_digest
   AND sha256(convert_to(p.vectors_json,'UTF8'))=r.vector_digest) THEN
  RAISE EXCEPTION 'Original revision preimage mismatch' USING ERRCODE='55000';
 END IF;
 INSERT INTO secureshop_review.product_target_embedding_heads(target_id,revision_id) VALUES(requested_target,requested_operation)
 ON CONFLICT(target_id) DO UPDATE SET revision_id=EXCLUDED.revision_id;
 RETURN QUERY SELECT requested_operation,requested_fingerprint,requested_source_digest,computed_vector_digest,payload_count,false;
END $$;
REVOKE ALL ON FUNCTION secureshop_review.publish_product_embedding_revision(uuid,uuid,uuid,bigint,integer,integer,uuid,bytea,bytea,uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.publish_product_embedding_revision(uuid,uuid,uuid,bigint,integer,integer,uuid,bytea,bytea,uuid,jsonb) TO dvaia_secureshop_review_runtime;

-- Only the original append transaction can capture its numeric JSON preimage.
-- This function does not reconstruct or backfill previously committed uploads.
CREATE FUNCTION secureshop_review.capture_product_manual_preimage(
 requested_operation uuid, requested_target uuid, chunks jsonb)
RETURNS TABLE(operation_id uuid,target_id uuid,document_digest bytea,receipt_sha256 bytea,runtime_receipt_sha256 bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE original secureshop_review.product_target_manual_ingests%ROWTYPE;
 runtime_receipt secureshop_review.product_target_manual_runtime_receipts%ROWTYPE;
 original_xid xid; matched_count integer;
BEGIN
 IF requested_operation IS NULL OR requested_target IS NULL OR jsonb_typeof(chunks) IS DISTINCT FROM 'array'
  OR jsonb_array_length(chunks)>129 OR octet_length(chunks::text)>67108864 THEN
  RAISE EXCEPTION 'Invalid original manual preimage' USING ERRCODE='22023';
 END IF;
 PERFORM 1 FROM secureshop_review.product_targets t WHERE t.target_id=requested_target AND t.lifecycle='active' FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Original manual target unavailable' USING ERRCODE='55000'; END IF;
 SELECT i.* INTO original FROM secureshop_review.product_target_manual_ingests i
 WHERE i.operation_id=requested_operation AND i.target_id=requested_target;
 IF NOT FOUND OR original.receipt_version<>2 OR NOT original.is_public
  OR original.document_count<>jsonb_array_length(chunks)
  OR original.document_digest<>sha256(convert_to(chunks::text,'UTF8'))
  OR original.receipt_sha256<>secureshop_review.product_manual_scene_receipt_digest(original)
  OR NOT EXISTS(SELECT 1 FROM secureshop_review.product_targets t WHERE t.target_id=original.target_id
   AND t.launch_id=original.launch_id AND t.scenario_id=original.scenario_id AND t.generation=original.generation
   AND t.original_platform_owner_id=original.original_platform_owner_id
   AND t.original_platform_session_id=original.original_platform_session_id) THEN
  RAISE EXCEPTION 'Original manual receipt mismatch' USING ERRCODE='55000';
 END IF;
 SELECT i.xmin INTO original_xid FROM secureshop_review.product_target_manual_ingests i WHERE i.operation_id=requested_operation;
 IF original_xid IS DISTINCT FROM pg_current_xact_id()::text::xid THEN
  RAISE EXCEPTION 'Historical manual preimage capture forbidden' USING ERRCODE='55000';
 END IF;
 SELECT r.* INTO runtime_receipt FROM secureshop_review.product_target_manual_runtime_receipts r WHERE r.operation_id=requested_operation;
 IF NOT FOUND OR runtime_receipt.original_receipt_sha256<>original.receipt_sha256
  OR runtime_receipt.receipt_sha256<>secureshop_review.manual_runtime_receipt_digest(
   runtime_receipt.operation_id,runtime_receipt.runtime_fingerprint,runtime_receipt.original_receipt_sha256) THEN
  RAISE EXCEPTION 'Original manual runtime mismatch' USING ERRCODE='55000';
 END IF;
 SELECT count(*) INTO matched_count FROM jsonb_array_elements(chunks) WITH ORDINALITY c(value,ordinality)
 JOIN secureshop_review.product_target_retrieval_documents d ON d.target_id=original.target_id
  AND d.generation=original.generation AND d.source_kind='manual' AND d.source_id=original.manual_source_id
  AND d.chunk_index=c.ordinality-1
  AND d.source_sha256=sha256(convert_to(jsonb_build_object('sourceKind','manual','sourceId',original.manual_source_id,
   'chunkIndex',c.ordinality-1,'text',c.value->>'text','embedding',c.value->'embedding')::text,'UTF8'));
 IF matched_count<>original.document_count OR matched_count<1 OR matched_count<>(SELECT count(*) FROM
  secureshop_review.product_target_retrieval_documents d WHERE d.target_id=original.target_id
   AND d.generation=original.generation AND d.source_kind='manual' AND d.source_id=original.manual_source_id) THEN
  RAISE EXCEPTION 'Original manual chunk mismatch' USING ERRCODE='55000';
 END IF;
 INSERT INTO secureshop_review.product_target_manual_preimages(operation_id,target_id,documents_json)
 VALUES(requested_operation,requested_target,chunks::text) ON CONFLICT DO NOTHING;
 IF NOT EXISTS(SELECT 1 FROM secureshop_review.product_target_manual_preimages p WHERE p.operation_id=requested_operation
  AND p.target_id=requested_target AND p.documents_json=chunks::text) THEN
  RAISE EXCEPTION 'Original manual preimage conflict' USING ERRCODE='55000';
 END IF;
 RETURN QUERY SELECT original.operation_id,original.target_id,original.document_digest,
  original.receipt_sha256,runtime_receipt.receipt_sha256;
END $$;
REVOKE ALL ON FUNCTION secureshop_review.capture_product_manual_preimage(uuid,uuid,jsonb) FROM PUBLIC,dvaia_secureshop_review_runtime;
GRANT EXECUTE ON FUNCTION secureshop_review.capture_product_manual_preimage(uuid,uuid,jsonb) TO dvaia_secureshop_review_runtime;
