-- Derived vectors preserve original product/manual documents and ingestion evidence.
-- Lock order: canonical product target, retrieval configuration, embedding head.
CREATE TABLE secureshop_review.product_target_embedding_revisions (
 revision_id uuid PRIMARY KEY,
 target_id uuid NOT NULL REFERENCES secureshop_review.product_targets(target_id),
 launch_id uuid NOT NULL, scenario_id uuid NOT NULL, generation bigint NOT NULL,
 original_platform_owner_id integer NOT NULL, original_platform_session_id integer NOT NULL,
 runtime_fingerprint bytea NOT NULL CHECK(octet_length(runtime_fingerprint)=32),
 source_set_digest bytea NOT NULL CHECK(octet_length(source_set_digest)=32),
 vector_digest bytea NOT NULL CHECK(octet_length(vector_digest)=32),
 expected_head uuid, document_count integer NOT NULL CHECK(document_count BETWEEN 0 AND 4096),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(target_id,revision_id)
);
CREATE TABLE secureshop_review.product_target_embedding_vectors (
 revision_id uuid NOT NULL REFERENCES secureshop_review.product_target_embedding_revisions(revision_id),
 source_kind text NOT NULL, source_id bigint NOT NULL, chunk_index integer NOT NULL,
 source_sha256 bytea NOT NULL CHECK(octet_length(source_sha256)=32), embedding double precision[] NOT NULL,
 PRIMARY KEY(revision_id,source_kind,source_id,chunk_index)
);
CREATE TABLE secureshop_review.product_target_embedding_heads (
 target_id uuid PRIMARY KEY REFERENCES secureshop_review.product_targets(target_id),
 revision_id uuid NOT NULL,
 FOREIGN KEY(target_id,revision_id) REFERENCES secureshop_review.product_target_embedding_revisions(target_id,revision_id)
);
CREATE TRIGGER embedding_revisions_immutable BEFORE UPDATE OR DELETE ON secureshop_review.product_target_embedding_revisions
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_product_retrieval_immutable();
CREATE TRIGGER embedding_vectors_immutable BEFORE UPDATE OR DELETE ON secureshop_review.product_target_embedding_vectors
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_product_retrieval_immutable();
CREATE FUNCTION secureshop_review.product_embedding_source_digest(target uuid,generation bigint)
RETURNS bytea LANGUAGE sql STABLE STRICT SET search_path=pg_catalog AS $$
 SELECT sha256(convert_to(COALESCE(jsonb_agg(jsonb_build_object(
 'sourceKind',d.source_kind,'sourceId',d.source_id::text,'chunkIndex',d.chunk_index,
 'text',d.body,'sourceSha256',encode(d.source_sha256,'hex'))
 ORDER BY d.source_kind COLLATE "C",d.source_id,d.chunk_index),'[]'::jsonb)::text,'UTF8'))
 FROM secureshop_review.product_target_retrieval_documents d WHERE d.target_id=$1 AND d.generation=$2
$$;
REVOKE ALL ON FUNCTION secureshop_review.product_embedding_source_digest(uuid,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.product_embedding_source_digest(uuid,bigint) TO dvaia_secureshop_review_runtime;
CREATE FUNCTION secureshop_review.invalidate_product_embedding_head()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE target uuid;
BEGIN
 IF TG_TABLE_NAME='product_targets' THEN
  IF NEW.lifecycle IS NOT DISTINCT FROM OLD.lifecycle THEN RETURN NEW; END IF;
  target:=NEW.target_id;
 ELSE
  target:=CASE WHEN TG_OP='DELETE' THEN OLD.target_id ELSE NEW.target_id END;
  PERFORM 1 FROM secureshop_review.product_targets WHERE target_id=target FOR UPDATE;
 END IF;
 DELETE FROM secureshop_review.product_target_embedding_heads WHERE target_id=target;
 IF TG_OP='DELETE' THEN RETURN OLD; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION secureshop_review.invalidate_product_embedding_head() FROM PUBLIC;
CREATE TRIGGER product_embedding_source_changed BEFORE INSERT OR DELETE ON secureshop_review.product_target_retrieval_documents
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.invalidate_product_embedding_head();
CREATE TRIGGER product_embedding_target_changed AFTER UPDATE OF lifecycle ON secureshop_review.product_targets
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.invalidate_product_embedding_head();

CREATE FUNCTION secureshop_review.publish_product_embedding_revision(
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
 INSERT INTO secureshop_review.product_target_embedding_heads(target_id,revision_id) VALUES(requested_target,requested_operation)
 ON CONFLICT(target_id) DO UPDATE SET revision_id=EXCLUDED.revision_id;
 RETURN QUERY SELECT requested_operation,requested_fingerprint,requested_source_digest,computed_vector_digest,payload_count,false;
END $$;
REVOKE ALL ON FUNCTION secureshop_review.publish_product_embedding_revision(uuid,uuid,uuid,bigint,integer,integer,uuid,bytea,bytea,uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.publish_product_embedding_revision(uuid,uuid,uuid,bigint,integer,integer,uuid,bytea,bytea,uuid,jsonb) TO dvaia_secureshop_review_runtime;
REVOKE ALL ON TABLE secureshop_review.product_target_embedding_revisions,secureshop_review.product_target_embedding_vectors,secureshop_review.product_target_embedding_heads FROM PUBLIC,dvaia_secureshop_review_runtime;
GRANT SELECT ON TABLE secureshop_review.product_target_embedding_revisions,secureshop_review.product_target_embedding_vectors,secureshop_review.product_target_embedding_heads TO dvaia_secureshop_review_runtime;
