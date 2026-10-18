-- A manual belongs to the immutable product snapshot, while the upload and
-- file receipt belong to the current, explicitly granted execution. Historical
-- version-one receipts and their digest function are left byte-for-byte intact.
ALTER TABLE secureshop_review.product_target_manual_ingests
  ADD COLUMN receipt_version integer NOT NULL DEFAULT 1,
  ADD COLUMN scene_id uuid,
  ADD COLUMN scene_generation bigint,
  ADD COLUMN scene_grant_id uuid,
  ADD COLUMN execution_launch_id uuid,
  ADD COLUMN execution_scenario_id uuid,
  ADD COLUMN execution_generation bigint,
  ADD COLUMN execution_platform_owner_id integer,
  ADD COLUMN execution_platform_session_id integer;

DO $$
DECLARE old_constraint name; matches integer;
BEGIN
  SELECT count(*), min(c.conname::text)::name INTO matches, old_constraint
    FROM pg_constraint c
    WHERE c.conrelid='secureshop_review.product_target_manual_ingests'::regclass
      AND c.contype='c'
      AND position('file_launch_id' IN pg_get_constraintdef(c.oid))>0
      AND position('file_scenario_id' IN pg_get_constraintdef(c.oid))>0
      AND position('file_platform_session_id' IN pg_get_constraintdef(c.oid))>0;
  IF matches<>1 THEN
    RAISE EXCEPTION 'historical manual file-binding constraint unavailable';
  END IF;
  EXECUTE format('ALTER TABLE secureshop_review.product_target_manual_ingests DROP CONSTRAINT %I',old_constraint);
END $$;

ALTER TABLE secureshop_review.product_target_manual_ingests
  ADD CONSTRAINT product_manual_scene_grant_fk FOREIGN KEY (scene_grant_id)
    REFERENCES secureshop_review.scene_execution_grants(grant_id) ON DELETE RESTRICT,
  ADD CONSTRAINT product_manual_receipt_execution_binding CHECK (COALESCE((
    (receipt_version=1 AND scene_id IS NULL AND scene_generation IS NULL
      AND scene_grant_id IS NULL AND execution_launch_id IS NULL
      AND execution_scenario_id IS NULL AND execution_generation IS NULL
      AND execution_platform_owner_id IS NULL AND execution_platform_session_id IS NULL
      AND file_launch_id=launch_id AND file_scenario_id=scenario_id
      AND file_generation=generation
      AND file_platform_owner_id=original_platform_owner_id
      AND file_platform_session_id=original_platform_session_id)
    OR
    (receipt_version=2 AND scene_id IS NOT NULL AND scene_generation BETWEEN 1 AND 9007199254740991
      AND scene_grant_id IS NOT NULL AND execution_launch_id IS NOT NULL
      AND execution_scenario_id IS NOT NULL
      AND execution_generation BETWEEN 1 AND 9007199254740991
      AND execution_platform_owner_id>=1 AND execution_platform_session_id>=1
      AND execution_platform_owner_id=original_platform_owner_id
      AND file_launch_id=execution_launch_id AND file_scenario_id=execution_scenario_id
      AND file_generation=execution_generation
      AND file_platform_owner_id=execution_platform_owner_id
      AND file_platform_session_id=execution_platform_session_id)
  ),false));

CREATE FUNCTION secureshop_review.product_manual_scene_receipt_digest(
  receipt secureshop_review.product_target_manual_ingests)
RETURNS bytea LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
  SELECT sha256(convert_to(jsonb_build_object('kind','product_manual_ingest',
    'version',2,
    'manualFieldsSha256',encode(secureshop_review.product_manual_ingest_receipt_digest(
      receipt.operation_id,receipt.manual_source_id,receipt.target_id,
      receipt.launch_id,receipt.scenario_id,receipt.generation,
      receipt.original_platform_owner_id,receipt.original_platform_session_id,
      receipt.product_id,receipt.merchant_id,receipt.file_target_id,
      receipt.file_launch_id,receipt.file_scenario_id,receipt.file_generation,
      receipt.file_platform_owner_id,receipt.file_platform_session_id,
      receipt.virtual_path,receipt.byte_count,receipt.file_sha256,
      receipt.filename,receipt.mime,receipt.is_public,receipt.extractor,
      receipt.extraction_sha256,receipt.embedding_model,receipt.embedding_dimension,
      receipt.document_digest,receipt.document_count),'hex'),
    'sceneId',receipt.scene_id,'sceneGeneration',receipt.scene_generation,
    'sceneGrantId',receipt.scene_grant_id,
    'executionLaunchId',receipt.execution_launch_id,
    'executionScenarioId',receipt.execution_scenario_id,
    'executionGeneration',receipt.execution_generation,
    'executionPlatformOwnerId',receipt.execution_platform_owner_id,
    'executionPlatformSessionId',receipt.execution_platform_session_id)::text,'UTF8'))
$$;
REVOKE ALL ON FUNCTION secureshop_review.product_manual_scene_receipt_digest(
  secureshop_review.product_target_manual_ingests) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.product_manual_scene_receipt_digest(
  secureshop_review.product_target_manual_ingests) TO dvaia_secureshop_review_runtime;

CREATE FUNCTION secureshop_review.set_product_manual_scene_digest() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,secureshop_review AS $$
BEGIN
  IF NEW.receipt_version=2 THEN
    NEW.receipt_sha256:=secureshop_review.product_manual_scene_receipt_digest(NEW);
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER product_manual_scene_digest BEFORE INSERT
  ON secureshop_review.product_target_manual_ingests FOR EACH ROW
  EXECUTE FUNCTION secureshop_review.set_product_manual_scene_digest();
REVOKE ALL ON FUNCTION secureshop_review.set_product_manual_scene_digest() FROM PUBLIC;

-- This is a separate v2 append. The v1 function remains available only for
-- its original same-launch contract; it cannot reinterpret an old receipt.
CREATE FUNCTION secureshop_review.append_product_manual_retrieval_attested_scene(
  requested_operation uuid,
  requested_target uuid, requested_launch uuid, requested_scenario uuid,
  requested_generation bigint, requested_owner integer, requested_session integer,
  requested_scene uuid, requested_scene_generation bigint, requested_grant uuid,
  requested_execution_launch uuid, requested_execution_scenario uuid,
  requested_execution_generation bigint, requested_execution_owner integer,
  requested_execution_session integer,
  requested_product integer, requested_merchant integer,
  requested_file_target uuid, requested_file_launch uuid, requested_file_scenario uuid,
  requested_file_generation bigint, requested_file_owner integer, requested_file_session integer,
  requested_virtual_path text, requested_bytes integer, requested_file_sha bytea,
  requested_filename text, requested_mime text, requested_public boolean,
  requested_extractor text, requested_extraction_sha bytea,
  requested_model text, requested_dimension integer, requested_chunks jsonb,
  requested_runtime_fingerprint bytea)
RETURNS TABLE(replayed boolean, operation_id uuid, manual_source_id bigint,
  document_digest bytea, document_count integer, receipt_sha256 bytea,
  completed_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE
  target secureshop_review.product_targets%ROWTYPE;
  config secureshop_review.product_target_retrieval_config%ROWTYPE;
  prior secureshop_review.product_target_manual_ingests%ROWTYPE;
  inserted secureshop_review.product_target_manual_ingests%ROWTYPE;
  runtime_prior secureshop_review.product_target_manual_runtime_receipts%ROWTYPE;
  normalized_documents jsonb;
  chunks_digest bytea;
  new_source_id bigint;
  expected_path text;
  chunk_count integer;
  item jsonb;
  element jsonb;
  chunk_index integer;
  embedding double precision[];
BEGIN
  IF NOT (ROW(requested_operation,requested_target,requested_launch,requested_scenario,
      requested_generation,requested_owner,requested_session,requested_scene,
      requested_scene_generation,requested_grant,requested_execution_launch,
      requested_execution_scenario,requested_execution_generation,
      requested_execution_owner,requested_execution_session,requested_product,
      requested_merchant,requested_file_target,requested_file_launch,
      requested_file_scenario,requested_file_generation,requested_file_owner,
      requested_file_session,requested_virtual_path,requested_bytes,requested_file_sha,
      requested_filename,requested_mime,requested_public,requested_extractor,
      requested_extraction_sha,requested_model,requested_dimension,requested_chunks,
      requested_runtime_fingerprint) IS NOT NULL)
      OR requested_operation IS NULL OR requested_target IS NULL
      OR requested_launch IS NULL OR requested_scenario IS NULL
      OR requested_generation NOT BETWEEN 1 AND 9007199254740991
      OR requested_owner<1 OR requested_session<1
      OR requested_scene IS NULL OR requested_scene_generation NOT BETWEEN 1 AND 9007199254740991
      OR requested_grant IS NULL OR requested_execution_launch IS NULL
      OR requested_execution_scenario IS NULL
      OR requested_execution_generation NOT BETWEEN 1 AND 9007199254740991
      OR requested_execution_owner IS DISTINCT FROM requested_owner
      OR requested_execution_session<1
      OR requested_product<1 OR requested_merchant<1
      OR requested_file_target IS NULL OR requested_file_target=requested_target
      OR requested_file_launch IS DISTINCT FROM requested_execution_launch
      OR requested_file_scenario IS DISTINCT FROM requested_execution_scenario
      OR requested_file_generation IS DISTINCT FROM requested_execution_generation
      OR requested_file_owner IS DISTINCT FROM requested_execution_owner
      OR requested_file_session IS DISTINCT FROM requested_execution_session
      OR requested_bytes NOT BETWEEN 1 AND 20971520
      OR octet_length(requested_file_sha) IS DISTINCT FROM 32
      OR octet_length(requested_filename) NOT BETWEEN 1 AND 4096
      OR octet_length(requested_mime) NOT BETWEEN 1 AND 1024
      OR requested_public IS NULL
      OR octet_length(requested_extractor) NOT BETWEEN 1 AND 128
      OR octet_length(requested_extraction_sha) IS DISTINCT FROM 32
      OR octet_length(requested_model) NOT BETWEEN 1 AND 256
      OR requested_dimension NOT BETWEEN 1 AND 4096
      OR octet_length(requested_runtime_fingerprint) IS DISTINCT FROM 32
      OR jsonb_typeof(requested_chunks) IS DISTINCT FROM 'array'
      OR jsonb_array_length(requested_chunks) NOT BETWEEN 1 AND 129 THEN
    RAISE EXCEPTION 'manual scene ingest payload invalid' USING ERRCODE='22023';
  END IF;
  expected_path:='/uploads/product_manuals/' || requested_product::text || '/'
    || requested_operation::text || '-manual';
  IF requested_virtual_path IS DISTINCT FROM expected_path THEN
    RAISE EXCEPTION 'manual scene file path invalid' USING ERRCODE='22023';
  END IF;

  -- The grant is transaction-pinned in the review store; the caller also
  -- holds the live identity-store scene lease across this transaction.
  IF NOT secureshop_review.assert_scene_execution_grant(requested_grant,
      requested_scene,requested_scene_generation,requested_target,
      requested_execution_launch,requested_execution_scenario,
      requested_execution_generation,requested_execution_owner,
      requested_execution_session) THEN
    RAISE EXCEPTION 'manual scene execution grant unavailable' USING ERRCODE='55000';
  END IF;
  SELECT * INTO target FROM secureshop_review.product_targets t
    WHERE t.target_id=requested_target AND t.launch_id=requested_launch
      AND t.scenario_id=requested_scenario AND t.generation=requested_generation
      AND t.original_platform_owner_id=requested_owner
      AND t.original_platform_session_id=requested_session
    FOR UPDATE;
  IF target.target_id IS NULL OR target.lifecycle<>'active' THEN
    RAISE EXCEPTION 'manual scene target unavailable' USING ERRCODE='55000';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM secureshop_review.product_target_products p
      WHERE p.target_id=requested_target AND p.product_id=requested_product
        AND p.retailer_id=requested_merchant) THEN
    RAISE EXCEPTION 'manual scene product is not merchant owned' USING ERRCODE='55000';
  END IF;
  SELECT * INTO config FROM secureshop_review.product_target_retrieval_config c
    WHERE c.target_id=requested_target FOR SHARE;
  IF config.target_id IS NULL OR config.lifecycle<>'active'
      OR config.embedding_model<>requested_model
      OR config.embedding_dimension<>requested_dimension THEN
    RAISE EXCEPTION 'manual scene retrieval config mismatch' USING ERRCODE='55000';
  END IF;

  chunk_index:=0;
  FOR item IN SELECT value FROM jsonb_array_elements(requested_chunks) LOOP
    IF jsonb_typeof(item) IS DISTINCT FROM 'object'
        OR (SELECT count(*) FROM jsonb_object_keys(item))<>2
        OR NOT (item ?& ARRAY['text','embedding'])
        OR jsonb_typeof(item->'text') IS DISTINCT FROM 'string'
        OR octet_length(item->>'text') NOT BETWEEN 1 AND 65536
        OR jsonb_typeof(item->'embedding') IS DISTINCT FROM 'array'
        OR jsonb_array_length(item->'embedding')<>requested_dimension THEN
      RAISE EXCEPTION 'manual scene chunk invalid' USING ERRCODE='22023';
    END IF;
    FOR element IN SELECT value FROM jsonb_array_elements(item->'embedding') LOOP
      IF jsonb_typeof(element) IS DISTINCT FROM 'number'
          OR abs(element::text::double precision)='Infinity'::double precision THEN
        RAISE EXCEPTION 'manual scene embedding invalid' USING ERRCODE='22023';
      END IF;
    END LOOP;
    IF NOT EXISTS (SELECT 1 FROM jsonb_array_elements(item->'embedding') v
        WHERE v::text::double precision<>0) THEN
      RAISE EXCEPTION 'manual scene embedding cannot be zero' USING ERRCODE='22023';
    END IF;
    chunk_index:=chunk_index+1;
  END LOOP;
  chunk_count:=chunk_index;
  chunks_digest:=sha256(convert_to(requested_chunks::text,'UTF8'));

  -- Serialize identical operation attempts, including a lost-ACK retry.
  PERFORM pg_advisory_xact_lock(hashtextextended(requested_operation::text,0));
  SELECT * INTO prior FROM secureshop_review.product_target_manual_ingests i
    WHERE i.operation_id=requested_operation FOR UPDATE;
  IF prior.operation_id IS NOT NULL THEN
    SELECT * INTO runtime_prior FROM secureshop_review.product_target_manual_runtime_receipts r
      WHERE r.operation_id=requested_operation;
    IF prior.receipt_version<>2
        OR ROW(prior.target_id,prior.launch_id,prior.scenario_id,prior.generation,
          prior.original_platform_owner_id,prior.original_platform_session_id,
          prior.scene_id,prior.scene_generation,prior.scene_grant_id,
          prior.execution_launch_id,prior.execution_scenario_id,prior.execution_generation,
          prior.execution_platform_owner_id,prior.execution_platform_session_id,
          prior.product_id,prior.merchant_id,prior.file_target_id,prior.file_launch_id,
          prior.file_scenario_id,prior.file_generation,prior.file_platform_owner_id,
          prior.file_platform_session_id,prior.virtual_path,prior.byte_count,prior.file_sha256,
          prior.filename,prior.mime,prior.is_public,prior.extractor,
          prior.extraction_sha256,prior.embedding_model,prior.embedding_dimension,
          prior.document_digest,prior.document_count) IS DISTINCT FROM
        ROW(requested_target,requested_launch,requested_scenario,requested_generation,
          requested_owner,requested_session,requested_scene,requested_scene_generation,
          requested_grant,requested_execution_launch,requested_execution_scenario,
          requested_execution_generation,requested_execution_owner,requested_execution_session,
          requested_product,requested_merchant,requested_file_target,requested_file_launch,
          requested_file_scenario,requested_file_generation,requested_file_owner,
          requested_file_session,requested_virtual_path,requested_bytes,requested_file_sha,
          requested_filename,requested_mime,requested_public,requested_extractor,
          requested_extraction_sha,requested_model,requested_dimension,
          chunks_digest,chunk_count)
        OR prior.receipt_sha256<>secureshop_review.product_manual_scene_receipt_digest(prior)
        OR runtime_prior.operation_id IS NULL
        OR runtime_prior.runtime_fingerprint<>requested_runtime_fingerprint
        OR runtime_prior.original_receipt_sha256<>prior.receipt_sha256
        OR runtime_prior.receipt_sha256<>secureshop_review.manual_runtime_receipt_digest(
          requested_operation,runtime_prior.runtime_fingerprint,runtime_prior.original_receipt_sha256) THEN
      RAISE EXCEPTION 'manual scene replay mismatch' USING ERRCODE='55000';
    END IF;
    RETURN QUERY SELECT true,prior.operation_id,prior.manual_source_id,
      prior.document_digest,prior.document_count,prior.receipt_sha256,prior.completed_at;
    RETURN;
  END IF;

  new_source_id:=nextval('secureshop_review.product_target_manual_ingests_manual_source_id_seq');
  IF new_source_id NOT BETWEEN 1 AND 9007199254740991 THEN
    RAISE EXCEPTION 'manual source identity exhausted' USING ERRCODE='55000';
  END IF;
  INSERT INTO secureshop_review.product_target_manual_ingests(
    operation_id,manual_source_id,target_id,launch_id,scenario_id,generation,
    original_platform_owner_id,original_platform_session_id,
    receipt_version,scene_id,scene_generation,scene_grant_id,
    execution_launch_id,execution_scenario_id,execution_generation,
    execution_platform_owner_id,execution_platform_session_id,
    product_id,merchant_id,file_target_id,file_launch_id,file_scenario_id,file_generation,
    file_platform_owner_id,file_platform_session_id,virtual_path,byte_count,file_sha256,
    filename,mime,is_public,extractor,extraction_sha256,embedding_model,
    embedding_dimension,document_digest,document_count,receipt_sha256)
  OVERRIDING SYSTEM VALUE VALUES(
    requested_operation,new_source_id,requested_target,requested_launch,requested_scenario,
    requested_generation,requested_owner,requested_session,
    2,requested_scene,requested_scene_generation,requested_grant,
    requested_execution_launch,requested_execution_scenario,requested_execution_generation,
    requested_execution_owner,requested_execution_session,
    requested_product,requested_merchant,requested_file_target,requested_file_launch,
    requested_file_scenario,requested_file_generation,requested_file_owner,requested_file_session,
    requested_virtual_path,requested_bytes,requested_file_sha,requested_filename,requested_mime,
    requested_public,requested_extractor,requested_extraction_sha,requested_model,
    requested_dimension,chunks_digest,chunk_count,decode(repeat('00',32),'hex'))
  RETURNING * INTO inserted;

  normalized_documents:=(
    SELECT jsonb_agg(jsonb_build_object('sourceKind','manual',
      'sourceId',inserted.manual_source_id,'chunkIndex',ordinality-1,
      'text',value->>'text','embedding',value->'embedding') ORDER BY ordinality)
    FROM jsonb_array_elements(requested_chunks) WITH ORDINALITY AS rows(value,ordinality));
  PERFORM secureshop_review.validate_product_retrieval_documents(
    normalized_documents,requested_dimension);
  FOR item IN SELECT value FROM jsonb_array_elements(normalized_documents) LOOP
    embedding:=ARRAY(SELECT jsonb_array_elements_text(item->'embedding')::double precision);
    INSERT INTO secureshop_review.product_target_retrieval_documents(
      target_id,generation,source_kind,source_id,chunk_index,body,embedding,source_sha256)
    VALUES(requested_target,requested_generation,'manual',inserted.manual_source_id,
      (item->>'chunkIndex')::integer,item->>'text',embedding,
      sha256(convert_to(item::text,'UTF8')));
  END LOOP;
  INSERT INTO secureshop_review.product_target_manual_runtime_receipts(
    operation_id,runtime_fingerprint,original_receipt_sha256,receipt_sha256)
  VALUES(requested_operation,requested_runtime_fingerprint,inserted.receipt_sha256,
    secureshop_review.manual_runtime_receipt_digest(requested_operation,
      requested_runtime_fingerprint,inserted.receipt_sha256));

  RETURN QUERY SELECT false,inserted.operation_id,inserted.manual_source_id,
    inserted.document_digest,inserted.document_count,inserted.receipt_sha256,
    inserted.completed_at;
END $$;
REVOKE ALL ON FUNCTION secureshop_review.append_product_manual_retrieval_attested_scene(
  uuid,uuid,uuid,uuid,bigint,integer,integer,uuid,bigint,uuid,
  uuid,uuid,bigint,integer,integer,integer,integer,uuid,uuid,uuid,
  bigint,integer,integer,text,integer,bytea,text,text,boolean,text,bytea,
  text,integer,jsonb,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.append_product_manual_retrieval_attested_scene(
  uuid,uuid,uuid,uuid,bigint,integer,integer,uuid,bigint,uuid,
  uuid,uuid,bigint,integer,integer,integer,integer,uuid,uuid,uuid,
  bigint,integer,integer,text,integer,bytea,text,text,boolean,text,bytea,
  text,integer,jsonb,bytea) TO dvaia_secureshop_review_runtime;
