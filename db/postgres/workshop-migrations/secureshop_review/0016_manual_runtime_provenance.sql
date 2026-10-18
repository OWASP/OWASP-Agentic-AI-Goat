-- New ingestion provenance is additive. Historical manual receipts remain exact.
CREATE TABLE secureshop_review.product_target_manual_runtime_receipts (
 operation_id uuid PRIMARY KEY REFERENCES secureshop_review.product_target_manual_ingests(operation_id) ON DELETE RESTRICT,
 runtime_fingerprint bytea NOT NULL CHECK(octet_length(runtime_fingerprint)=32),
 original_receipt_sha256 bytea NOT NULL CHECK(octet_length(original_receipt_sha256)=32),
 receipt_sha256 bytea NOT NULL CHECK(octet_length(receipt_sha256)=32),
 completed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TRIGGER manual_runtime_receipts_immutable BEFORE UPDATE OR DELETE ON secureshop_review.product_target_manual_runtime_receipts
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_product_retrieval_immutable();
CREATE FUNCTION secureshop_review.manual_runtime_receipt_digest(op uuid,fingerprint bytea,original bytea)
 RETURNS bytea LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT sha256(convert_to(jsonb_build_object('version',1,'kind','manual_embedding_runtime','operationId',op,'runtimeFingerprint',encode(fingerprint,'hex'),'originalReceiptSha256',encode(original,'hex'))::text,'UTF8'))
$$;
REVOKE ALL ON FUNCTION secureshop_review.manual_runtime_receipt_digest(uuid,bytea,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.manual_runtime_receipt_digest(uuid,bytea,bytea) TO dvaia_secureshop_review_runtime;
REVOKE ALL ON TABLE secureshop_review.product_target_manual_runtime_receipts FROM PUBLIC,dvaia_secureshop_review_runtime;
GRANT SELECT ON TABLE secureshop_review.product_target_manual_runtime_receipts TO dvaia_secureshop_review_runtime;
CREATE FUNCTION secureshop_review.append_product_manual_retrieval_attested(
  requested_operation uuid,
  requested_target uuid, requested_launch uuid, requested_scenario uuid,
  requested_generation bigint, requested_owner integer, requested_session integer,
  requested_product integer, requested_merchant integer,
  requested_file_target uuid, requested_file_launch uuid, requested_file_scenario uuid,
  requested_file_generation bigint, requested_file_owner integer, requested_file_session integer,
  requested_virtual_path text, requested_bytes integer, requested_file_sha bytea,
  requested_filename text, requested_mime text, requested_public boolean,
  requested_extractor text, requested_extraction_sha bytea,
  requested_model text, requested_dimension integer, requested_chunks jsonb, requested_runtime_fingerprint bytea)
RETURNS TABLE(replayed boolean, operation_id uuid, manual_source_id bigint,
  document_digest bytea, document_count integer, receipt_sha256 bytea,
  completed_at timestamptz)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE appended record; prior secureshop_review.product_target_manual_runtime_receipts%ROWTYPE;
BEGIN
 IF requested_runtime_fingerprint IS NULL OR octet_length(requested_runtime_fingerprint)<>32 THEN RAISE EXCEPTION 'verified embedding runtime required' USING ERRCODE='22023'; END IF;
 SELECT * INTO appended FROM secureshop_review.append_product_manual_retrieval(requested_operation,requested_target,requested_launch,requested_scenario,requested_generation,requested_owner,requested_session,requested_product,requested_merchant,requested_file_target,requested_file_launch,requested_file_scenario,requested_file_generation,requested_file_owner,requested_file_session,requested_virtual_path,requested_bytes,requested_file_sha,requested_filename,requested_mime,requested_public,requested_extractor,requested_extraction_sha,requested_model,requested_dimension,requested_chunks);
 SELECT * INTO prior FROM secureshop_review.product_target_manual_runtime_receipts r WHERE r.operation_id=requested_operation;
 IF appended.replayed THEN
  IF prior.operation_id IS NULL THEN RAISE EXCEPTION 'historical manual has no runtime attestation; read original receipt or use a new operation' USING ERRCODE='55000'; END IF;
  IF prior.runtime_fingerprint<>requested_runtime_fingerprint OR prior.original_receipt_sha256<>appended.receipt_sha256 OR prior.receipt_sha256<>secureshop_review.manual_runtime_receipt_digest(requested_operation,prior.runtime_fingerprint,prior.original_receipt_sha256) THEN RAISE EXCEPTION 'manual runtime replay conflict' USING ERRCODE='55000'; END IF;
 ELSE
  INSERT INTO secureshop_review.product_target_manual_runtime_receipts(operation_id,runtime_fingerprint,original_receipt_sha256,receipt_sha256)
  VALUES(requested_operation,requested_runtime_fingerprint,appended.receipt_sha256,secureshop_review.manual_runtime_receipt_digest(requested_operation,requested_runtime_fingerprint,appended.receipt_sha256));
 END IF;
 RETURN QUERY SELECT appended.replayed,appended.operation_id,appended.manual_source_id,appended.document_digest,appended.document_count,appended.receipt_sha256,appended.completed_at;
END $$;
REVOKE ALL ON FUNCTION secureshop_review.append_product_manual_retrieval(uuid,uuid,uuid,uuid,bigint,integer,integer,integer,integer,uuid,uuid,uuid,bigint,integer,integer,text,integer,bytea,text,text,boolean,text,bytea,text,integer,jsonb) FROM PUBLIC,dvaia_secureshop_review_runtime;
REVOKE ALL ON FUNCTION secureshop_review.append_product_manual_retrieval_attested(uuid,uuid,uuid,uuid,bigint,integer,integer,integer,integer,uuid,uuid,uuid,bigint,integer,integer,text,integer,bytea,text,text,boolean,text,bytea,text,integer,jsonb,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.append_product_manual_retrieval_attested(uuid,uuid,uuid,uuid,bigint,integer,integer,integer,integer,uuid,uuid,uuid,bigint,integer,integer,text,integer,bytea,text,text,boolean,text,bytea,text,integer,jsonb,bytea) TO dvaia_secureshop_review_runtime;
