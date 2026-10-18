-- One reset may retire several durable scenes. Preserve one immutable receipt per
-- exact target while allowing their shared canonical reset operation UUID.
ALTER TABLE secureshop_review.review_cleanup_receipts
  DROP CONSTRAINT review_cleanup_receipts_pkey,
  ADD PRIMARY KEY (operation_id,target_id);
ALTER TABLE secureshop_review.product_cleanup_receipts
  DROP CONSTRAINT product_cleanup_receipts_pkey,
  ADD PRIMARY KEY (operation_id,target_id);
ALTER TABLE secureshop_review.product_account_cleanup_receipts
  DROP CONSTRAINT product_account_cleanup_receipts_pkey,
  ADD PRIMARY KEY (operation_id,target_id);
ALTER TABLE secureshop_review.product_listing_cleanup_receipts
  DROP CONSTRAINT product_listing_cleanup_receipts_pkey,
  ADD PRIMARY KEY (operation_id,target_id);
ALTER TABLE secureshop_review.product_target_refund_cleanup_receipts
  DROP CONSTRAINT product_target_refund_cleanup_receipts_pkey,
  ADD PRIMARY KEY (operation_id,target_id);
ALTER TABLE secureshop_review.product_target_retrieval_cleanup_receipts
  DROP CONSTRAINT product_target_retrieval_cleanup_receipts_pkey,
  ADD PRIMARY KEY (operation_id,target_id);

-- The original retrieval retire function also treated operation_id alone as a
-- replay key. A reset may now retire multiple exact product targets.
CREATE OR REPLACE FUNCTION secureshop_review.retire_product_target_retrieval(
  requested_operation uuid, requested_target uuid, requested_launch uuid, requested_scenario uuid,
  requested_generation bigint, requested_owner integer, requested_session integer)
RETURNS SETOF secureshop_review.product_target_retrieval_cleanup_receipts
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE target secureshop_review.product_targets%ROWTYPE; config secureshop_review.product_target_retrieval_config%ROWTYPE;
DECLARE prior secureshop_review.product_target_retrieval_cleanup_receipts%ROWTYPE; count integer; dg bytea; row secureshop_review.product_target_retrieval_cleanup_receipts%ROWTYPE;
BEGIN
  SELECT * INTO target FROM secureshop_review.product_targets t WHERE t.target_id=requested_target AND t.launch_id=requested_launch AND t.scenario_id=requested_scenario AND t.generation=requested_generation AND t.original_platform_owner_id=requested_owner AND t.original_platform_session_id=requested_session FOR UPDATE;
  IF target.target_id IS NULL OR target.lifecycle<>'retired' THEN RAISE EXCEPTION 'canonical product target must already be retired' USING ERRCODE='55000'; END IF;
  SELECT * INTO prior FROM secureshop_review.product_target_retrieval_cleanup_receipts r WHERE r.target_id=requested_target FOR UPDATE;
  IF prior.target_id IS NOT NULL THEN
    IF prior.operation_id<>requested_operation THEN RAISE EXCEPTION 'retrieval cleanup replay mismatch' USING ERRCODE='55000'; END IF;
    RETURN NEXT prior; RETURN;
  END IF;
  SELECT * INTO config FROM secureshop_review.product_target_retrieval_config c WHERE c.target_id=requested_target FOR UPDATE;
  IF config.target_id IS NULL OR config.lifecycle<>'active' THEN RAISE EXCEPTION 'retrieval config unavailable' USING ERRCODE='55000'; END IF;
  SELECT count(*)::integer INTO count FROM secureshop_review.product_target_retrieval_documents d WHERE d.target_id=requested_target;
  dg := secureshop_review.product_retrieval_cleanup_digest(requested_operation,requested_target,
    requested_launch,requested_scenario,requested_generation,requested_owner,requested_session,count);
  UPDATE secureshop_review.product_target_retrieval_config SET lifecycle='retired',retired_at=clock_timestamp() WHERE target_id=requested_target;
  DELETE FROM secureshop_review.product_target_retrieval_documents WHERE target_id=requested_target;
  INSERT INTO secureshop_review.product_target_retrieval_cleanup_receipts(operation_id,target_id,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id,deleted_document_count,receipt_sha256)
    VALUES(requested_operation,requested_target,requested_launch,requested_scenario,requested_generation,requested_owner,requested_session,count,dg) RETURNING * INTO row;
  RETURN NEXT row;
END $$;
