-- Immutable, target-bound product-manual ingestion. Raw manual text remains in
-- the retrieval documents only; the audit receipt retains hashes and metadata.
CREATE TABLE secureshop_review.product_target_manual_ingests (
  operation_id uuid PRIMARY KEY,
  manual_source_id bigint GENERATED ALWAYS AS IDENTITY UNIQUE
    CHECK (manual_source_id BETWEEN 1 AND 9007199254740991),
  target_id uuid NOT NULL REFERENCES secureshop_review.product_targets(target_id) ON DELETE RESTRICT,
  launch_id uuid NOT NULL,
  scenario_id uuid NOT NULL,
  generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 9007199254740991),
  original_platform_owner_id integer NOT NULL CHECK (original_platform_owner_id >= 1),
  original_platform_session_id integer NOT NULL CHECK (original_platform_session_id >= 1),
  product_id integer NOT NULL CHECK (product_id >= 1),
  merchant_id integer NOT NULL CHECK (merchant_id >= 1),
  file_target_id uuid NOT NULL,
  file_launch_id uuid NOT NULL,
  file_scenario_id uuid NOT NULL,
  file_generation bigint NOT NULL CHECK (file_generation BETWEEN 1 AND 9007199254740991),
  file_platform_owner_id integer NOT NULL CHECK (file_platform_owner_id >= 1),
  file_platform_session_id integer NOT NULL CHECK (file_platform_session_id >= 1),
  virtual_path text NOT NULL CHECK (octet_length(virtual_path) BETWEEN 1 AND 4096),
  byte_count integer NOT NULL CHECK (byte_count BETWEEN 1 AND 20971520),
  file_sha256 bytea NOT NULL CHECK (octet_length(file_sha256)=32),
  filename text NOT NULL CHECK (octet_length(filename) BETWEEN 1 AND 4096),
  mime text NOT NULL CHECK (octet_length(mime) BETWEEN 1 AND 1024),
  is_public boolean NOT NULL,
  extractor text NOT NULL CHECK (octet_length(extractor) BETWEEN 1 AND 128),
  extraction_sha256 bytea NOT NULL CHECK (octet_length(extraction_sha256)=32),
  embedding_model text NOT NULL CHECK (octet_length(embedding_model) BETWEEN 1 AND 256),
  embedding_dimension integer NOT NULL CHECK (embedding_dimension BETWEEN 1 AND 4096),
  document_digest bytea NOT NULL CHECK (octet_length(document_digest)=32),
  document_count integer NOT NULL CHECK (document_count BETWEEN 1 AND 129),
  receipt_sha256 bytea NOT NULL CHECK (octet_length(receipt_sha256)=32),
  completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (file_target_id<>target_id),
  CHECK (file_launch_id=launch_id AND file_scenario_id=scenario_id
    AND file_generation=generation
    AND file_platform_owner_id=original_platform_owner_id
    AND file_platform_session_id=original_platform_session_id),
  CHECK (virtual_path=('/uploads/product_manuals/' || product_id::text || '/'
    || operation_id::text || '-manual'))
);

CREATE INDEX product_target_manual_ingests_target
  ON secureshop_review.product_target_manual_ingests(target_id,generation,product_id,manual_source_id);

CREATE TRIGGER product_target_manual_ingest_guard
BEFORE UPDATE OR DELETE ON secureshop_review.product_target_manual_ingests
FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_product_retrieval_immutable();

REVOKE ALL ON TABLE secureshop_review.product_target_manual_ingests FROM PUBLIC;
REVOKE ALL ON SEQUENCE secureshop_review.product_target_manual_ingests_manual_source_id_seq FROM PUBLIC;
GRANT SELECT ON TABLE secureshop_review.product_target_manual_ingests
  TO dvaia_secureshop_review_runtime;

CREATE FUNCTION secureshop_review.product_manual_ingest_receipt_digest(
  op uuid, source_id bigint,
  product_target uuid, launch uuid, scenario uuid, target_generation bigint,
  owner_id integer, session_id integer, selected_product integer, selected_merchant integer,
  files_target uuid, files_launch uuid, files_scenario uuid, files_generation bigint,
  files_owner integer, files_session integer, stored_path text, stored_bytes integer,
  stored_sha bytea, display_filename text, declared_mime text, public_file boolean,
  extractor_name text, extracted_sha bytea, model_name text, model_dimension integer,
  documents_sha bytea, documents_count integer)
RETURNS bytea LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
  SELECT sha256(convert_to(jsonb_build_object(
    'version',1,'kind','product_manual_ingest','operationId',op,'manualSourceId',source_id,
    'targetId',product_target,'launchId',launch,'scenarioId',scenario,
    'generation',target_generation,'platformOwnerId',owner_id,
    'platformSessionId',session_id,'productId',selected_product,'merchantId',selected_merchant,
    'fileTargetId',files_target,'fileLaunchId',files_launch,'fileScenarioId',files_scenario,
    'fileGeneration',files_generation,'filePlatformOwnerId',files_owner,
    'filePlatformSessionId',files_session,'virtualPath',stored_path,'bytes',stored_bytes,
    'fileSha256',encode(stored_sha,'hex'),'filename',display_filename,'mime',declared_mime,
    'isPublic',public_file,'extractor',extractor_name,'extractionSha256',encode(extracted_sha,'hex'),
    'embeddingModel',model_name,'embeddingDimension',model_dimension,
    'documentDigest',encode(documents_sha,'hex'),'documentCount',documents_count
  )::text,'UTF8'))
$$;

REVOKE ALL ON FUNCTION secureshop_review.product_manual_ingest_receipt_digest(
  uuid,bigint,uuid,uuid,uuid,bigint,integer,integer,integer,integer,
  uuid,uuid,uuid,bigint,integer,integer,text,integer,bytea,text,text,boolean,
  text,bytea,text,integer,bytea,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.product_manual_ingest_receipt_digest(
  uuid,bigint,uuid,uuid,uuid,bigint,integer,integer,integer,integer,
  uuid,uuid,uuid,bigint,integer,integer,text,integer,bytea,text,text,boolean,
  text,bytea,text,integer,bytea,integer) TO dvaia_secureshop_review_runtime;

CREATE FUNCTION secureshop_review.append_product_manual_retrieval(
  requested_operation uuid,
  requested_target uuid, requested_launch uuid, requested_scenario uuid,
  requested_generation bigint, requested_owner integer, requested_session integer,
  requested_product integer, requested_merchant integer,
  requested_file_target uuid, requested_file_launch uuid, requested_file_scenario uuid,
  requested_file_generation bigint, requested_file_owner integer, requested_file_session integer,
  requested_virtual_path text, requested_bytes integer, requested_file_sha bytea,
  requested_filename text, requested_mime text, requested_public boolean,
  requested_extractor text, requested_extraction_sha bytea,
  requested_model text, requested_dimension integer, requested_chunks jsonb)
RETURNS TABLE(replayed boolean, operation_id uuid, manual_source_id bigint,
  document_digest bytea, document_count integer, receipt_sha256 bytea,
  completed_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE
  target secureshop_review.product_targets%ROWTYPE;
  config secureshop_review.product_target_retrieval_config%ROWTYPE;
  prior secureshop_review.product_target_manual_ingests%ROWTYPE;
  inserted secureshop_review.product_target_manual_ingests%ROWTYPE;
  normalized_documents jsonb;
  chunks_digest bytea;
  computed_receipt bytea;
  new_source_id bigint;
  expected_path text;
  chunk_count integer;
  item jsonb;
  element jsonb;
  chunk_index integer;
  embedding double precision[];
BEGIN
  SELECT * INTO target FROM secureshop_review.product_targets t
    WHERE t.target_id=requested_target AND t.launch_id=requested_launch
      AND t.scenario_id=requested_scenario AND t.generation=requested_generation
      AND t.original_platform_owner_id=requested_owner
      AND t.original_platform_session_id=requested_session
    FOR UPDATE;
  IF target.target_id IS NULL OR target.lifecycle<>'active'
      OR target.own_merchant_id<>requested_merchant THEN
    RAISE EXCEPTION 'manual ingest target unavailable' USING ERRCODE='55000';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM secureshop_review.product_target_products p
      WHERE p.target_id=requested_target AND p.product_id=requested_product
        AND p.retailer_id=requested_merchant) THEN
    RAISE EXCEPTION 'manual ingest product is not merchant owned' USING ERRCODE='55000';
  END IF;
  SELECT * INTO config FROM secureshop_review.product_target_retrieval_config c
    WHERE c.target_id=requested_target FOR SHARE;
  IF config.target_id IS NULL OR config.lifecycle<>'active'
      OR config.embedding_model<>requested_model
      OR config.embedding_dimension<>requested_dimension THEN
    RAISE EXCEPTION 'manual ingest retrieval config mismatch' USING ERRCODE='55000';
  END IF;

  expected_path := '/uploads/product_manuals/' || requested_product::text || '/'
    || requested_operation::text || '-manual';
  IF requested_operation IS NULL OR requested_product IS NULL OR requested_product<1
      OR requested_merchant IS NULL OR requested_merchant<1
      OR requested_file_target IS NULL OR requested_file_target=requested_target
      OR requested_file_launch IS NULL OR requested_file_scenario IS NULL
      OR requested_file_generation IS NULL OR requested_file_owner IS NULL
      OR requested_file_session IS NULL OR requested_virtual_path IS NULL
      OR requested_file_launch IS DISTINCT FROM requested_launch
      OR requested_file_scenario IS DISTINCT FROM requested_scenario
      OR requested_file_generation IS DISTINCT FROM requested_generation
      OR requested_file_owner IS DISTINCT FROM requested_owner
      OR requested_file_session IS DISTINCT FROM requested_session
      OR requested_virtual_path IS DISTINCT FROM expected_path
      OR requested_bytes IS NULL OR requested_bytes NOT BETWEEN 1 AND 20971520
      OR requested_file_sha IS NULL
      OR octet_length(requested_file_sha) IS DISTINCT FROM 32
      OR requested_filename IS NULL
      OR octet_length(requested_filename) NOT BETWEEN 1 AND 4096
      OR requested_mime IS NULL
      OR octet_length(requested_mime) NOT BETWEEN 1 AND 1024
      OR requested_public IS NULL
      OR requested_extractor IS NULL
      OR octet_length(requested_extractor) NOT BETWEEN 1 AND 128
      OR requested_extraction_sha IS NULL
      OR octet_length(requested_extraction_sha) IS DISTINCT FROM 32
      OR requested_model IS NULL
      OR octet_length(requested_model) NOT BETWEEN 1 AND 256
      OR requested_dimension IS NULL
      OR requested_dimension NOT BETWEEN 1 AND 4096
      OR requested_chunks IS NULL
      OR jsonb_typeof(requested_chunks) IS DISTINCT FROM 'array'
      OR jsonb_array_length(requested_chunks) NOT BETWEEN 1 AND 129 THEN
    RAISE EXCEPTION 'manual ingest payload invalid' USING ERRCODE='22023';
  END IF;

  chunk_index := 0;
  FOR item IN SELECT value FROM jsonb_array_elements(requested_chunks) LOOP
    IF jsonb_typeof(item) IS DISTINCT FROM 'object'
        OR (SELECT count(*) FROM jsonb_object_keys(item))<>2
        OR NOT (item ?& ARRAY['text','embedding'])
        OR jsonb_typeof(item->'text') IS DISTINCT FROM 'string'
        OR octet_length(item->>'text') NOT BETWEEN 1 AND 65536
        OR jsonb_typeof(item->'embedding') IS DISTINCT FROM 'array'
        OR jsonb_array_length(item->'embedding')<>requested_dimension THEN
      RAISE EXCEPTION 'manual ingest chunk invalid' USING ERRCODE='22023';
    END IF;
    FOR element IN SELECT value FROM jsonb_array_elements(item->'embedding') LOOP
      IF jsonb_typeof(element) IS DISTINCT FROM 'number'
          OR abs(element::text::double precision)='Infinity'::double precision THEN
        RAISE EXCEPTION 'manual ingest embedding invalid' USING ERRCODE='22023';
      END IF;
    END LOOP;
    IF NOT EXISTS (SELECT 1 FROM jsonb_array_elements(item->'embedding') v
        WHERE v::text::double precision<>0) THEN
      RAISE EXCEPTION 'manual ingest embedding cannot be zero' USING ERRCODE='22023';
    END IF;
    chunk_index := chunk_index + 1;
  END LOOP;
  chunk_count := chunk_index;
  chunks_digest := sha256(convert_to(requested_chunks::text,'UTF8'));

  SELECT * INTO prior FROM secureshop_review.product_target_manual_ingests i
    WHERE i.operation_id=requested_operation FOR UPDATE;
  IF prior.operation_id IS NOT NULL THEN
    computed_receipt := secureshop_review.product_manual_ingest_receipt_digest(
      requested_operation,prior.manual_source_id,requested_target,requested_launch,
      requested_scenario,requested_generation,requested_owner,requested_session,
      requested_product,requested_merchant,requested_file_target,requested_file_launch,
      requested_file_scenario,requested_file_generation,requested_file_owner,
      requested_file_session,requested_virtual_path,requested_bytes,requested_file_sha,
      requested_filename,requested_mime,requested_public,requested_extractor,
      requested_extraction_sha,requested_model,requested_dimension,chunks_digest,chunk_count);
    IF prior.receipt_sha256<>computed_receipt OR prior.document_digest<>chunks_digest
        OR prior.document_count<>chunk_count THEN
      RAISE EXCEPTION 'manual ingest replay mismatch' USING ERRCODE='55000';
    END IF;
    RETURN QUERY SELECT true,prior.operation_id,prior.manual_source_id,
      prior.document_digest,prior.document_count,prior.receipt_sha256,prior.completed_at;
    RETURN;
  END IF;

  new_source_id := nextval('secureshop_review.product_target_manual_ingests_manual_source_id_seq');
  IF new_source_id NOT BETWEEN 1 AND 9007199254740991 THEN
    RAISE EXCEPTION 'manual source identity exhausted' USING ERRCODE='55000';
  END IF;
  computed_receipt := secureshop_review.product_manual_ingest_receipt_digest(
    requested_operation,new_source_id,requested_target,requested_launch,
    requested_scenario,requested_generation,requested_owner,requested_session,
    requested_product,requested_merchant,requested_file_target,requested_file_launch,
    requested_file_scenario,requested_file_generation,requested_file_owner,
    requested_file_session,requested_virtual_path,requested_bytes,requested_file_sha,
    requested_filename,requested_mime,requested_public,requested_extractor,
    requested_extraction_sha,requested_model,requested_dimension,chunks_digest,chunk_count);

  INSERT INTO secureshop_review.product_target_manual_ingests(
    operation_id,target_id,launch_id,scenario_id,generation,
    manual_source_id,
    original_platform_owner_id,original_platform_session_id,product_id,merchant_id,
    file_target_id,file_launch_id,file_scenario_id,file_generation,
    file_platform_owner_id,file_platform_session_id,virtual_path,byte_count,file_sha256,
    filename,mime,is_public,extractor,extraction_sha256,embedding_model,
    embedding_dimension,document_digest,document_count,receipt_sha256)
  OVERRIDING SYSTEM VALUE
  VALUES(requested_operation,requested_target,requested_launch,requested_scenario,
    requested_generation,new_source_id,requested_owner,requested_session,requested_product,requested_merchant,
    requested_file_target,requested_file_launch,requested_file_scenario,
    requested_file_generation,requested_file_owner,requested_file_session,
    requested_virtual_path,requested_bytes,requested_file_sha,requested_filename,
    requested_mime,requested_public,requested_extractor,requested_extraction_sha,
    requested_model,requested_dimension,chunks_digest,chunk_count,computed_receipt)
  RETURNING * INTO inserted;

  normalized_documents := (
    SELECT jsonb_agg(jsonb_build_object('sourceKind','manual',
      'sourceId',inserted.manual_source_id,'chunkIndex',ordinality-1,
      'text',value->>'text','embedding',value->'embedding') ORDER BY ordinality)
    FROM jsonb_array_elements(requested_chunks) WITH ORDINALITY AS rows(value,ordinality));
  PERFORM secureshop_review.validate_product_retrieval_documents(
    normalized_documents,requested_dimension);
  FOR item IN SELECT value FROM jsonb_array_elements(normalized_documents) LOOP
    embedding := ARRAY(SELECT jsonb_array_elements_text(item->'embedding')::double precision);
    INSERT INTO secureshop_review.product_target_retrieval_documents(
      target_id,generation,source_kind,source_id,chunk_index,body,embedding,source_sha256)
    VALUES(requested_target,requested_generation,'manual',inserted.manual_source_id,
      (item->>'chunkIndex')::integer,item->>'text',embedding,
      sha256(convert_to(item::text,'UTF8')));
  END LOOP;

  RETURN QUERY SELECT false,inserted.operation_id,inserted.manual_source_id,
    inserted.document_digest,inserted.document_count,inserted.receipt_sha256,
    inserted.completed_at;
END $$;

REVOKE ALL ON FUNCTION secureshop_review.append_product_manual_retrieval(
  uuid,uuid,uuid,uuid,bigint,integer,integer,integer,integer,
  uuid,uuid,uuid,bigint,integer,integer,text,integer,bytea,text,text,boolean,
  text,bytea,text,integer,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.append_product_manual_retrieval(
  uuid,uuid,uuid,uuid,bigint,integer,integer,integer,integer,
  uuid,uuid,uuid,bigint,integer,integer,text,integer,bytea,text,text,boolean,
  text,bytea,text,integer,jsonb) TO dvaia_secureshop_review_runtime;

-- Direct writes remain unavailable; runtime can only append through the exact
-- security-definer contract and can read immutable audit metadata.
REVOKE INSERT,UPDATE,DELETE ON TABLE secureshop_review.product_target_manual_ingests
  FROM dvaia_secureshop_review_runtime;
REVOKE USAGE,SELECT,UPDATE ON SEQUENCE
  secureshop_review.product_target_manual_ingests_manual_source_id_seq
  FROM dvaia_secureshop_review_runtime;
