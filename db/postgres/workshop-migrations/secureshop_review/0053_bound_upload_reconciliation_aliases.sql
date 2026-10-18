CREATE OR REPLACE FUNCTION secureshop_review.reconcile_bound_upload(
 selected_operation uuid,selected_effect uuid,selected_action text,
 selected_storage_key uuid,selected_receipt_sha bytea,
 selected_binding_sha bytea,selected_request_sha bytea)
RETURNS TABLE(replayed boolean,operation_id uuid,receipt_sha256 bytea)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
DECLARE admission secureshop_review.bound_upload_admissions%ROWTYPE; effect secureshop_review.bound_upload_effects%ROWTYPE; prior secureshop_review.bound_upload_reconciliations%ROWTYPE;
BEGIN
 SELECT a.* INTO admission FROM secureshop_review.bound_upload_admissions a
  WHERE a.operation_id=selected_operation FOR SHARE;
 IF FOUND THEN PERFORM pg_advisory_xact_lock(hashtextextended('bound-upload-target:'||admission.target_id::text,0)); END IF;
 SELECT e.* INTO effect FROM secureshop_review.bound_upload_effects e
  WHERE e.operation_id=selected_operation FOR SHARE;
 IF admission.operation_id IS NULL
  OR (selected_effect IS NULL AND effect.effect_id IS NOT NULL)
  OR (selected_effect IS NOT NULL AND (effect.effect_id IS DISTINCT FROM selected_effect
   OR effect.outcome<>'unresolved' OR effect.quarantine_required IS DISTINCT FROM true))
  OR admission.binding_sha256 IS DISTINCT FROM selected_binding_sha
  OR admission.request_sha256 IS DISTINCT FROM selected_request_sha
  OR selected_storage_key IS DISTINCT FROM admission.storage_key
  OR selected_action NOT IN('quarantined','deleted') OR octet_length(selected_receipt_sha)<>32
  OR EXISTS(SELECT 1 FROM secureshop_review.bound_upload_cleanup_receipts c WHERE c.target_id=admission.target_id) THEN
  RAISE EXCEPTION 'bound upload reconciliation unavailable' USING ERRCODE='55000';
 END IF;
 SELECT r.* INTO prior FROM secureshop_review.bound_upload_reconciliations r
  WHERE r.operation_id=selected_operation FOR UPDATE;
 IF FOUND THEN
  IF ROW(prior.effect_id,prior.action,prior.storage_key,prior.receipt_sha256)
   IS DISTINCT FROM ROW(selected_effect,selected_action,selected_storage_key,selected_receipt_sha) THEN
   RAISE EXCEPTION 'bound upload reconciliation replay conflict' USING ERRCODE='55000';
  END IF;
  RETURN QUERY SELECT true,prior.operation_id,prior.receipt_sha256; RETURN;
 END IF;
 INSERT INTO secureshop_review.bound_upload_reconciliations(operation_id,effect_id,action,storage_key,receipt_sha256)
 VALUES(selected_operation,selected_effect,selected_action,selected_storage_key,selected_receipt_sha);
 RETURN QUERY SELECT false,selected_operation,selected_receipt_sha;
END $$;
