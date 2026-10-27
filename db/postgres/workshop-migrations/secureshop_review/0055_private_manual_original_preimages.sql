-- Separate private-manual producer capability. The public 0050 function and
-- its contract remain unchanged. Both use the same immutable table and its
-- canonical retirement trigger; historical uploads are never backfilled.
CREATE FUNCTION secureshop_review.capture_private_product_manual_preimage(
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
 IF NOT FOUND OR original.receipt_version<>2 OR original.is_public IS DISTINCT FROM false
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
REVOKE ALL ON FUNCTION secureshop_review.capture_private_product_manual_preimage(uuid,uuid,jsonb) FROM PUBLIC,dvaia_secureshop_review_runtime;
GRANT EXECUTE ON FUNCTION secureshop_review.capture_private_product_manual_preimage(uuid,uuid,jsonb) TO dvaia_secureshop_review_runtime;
