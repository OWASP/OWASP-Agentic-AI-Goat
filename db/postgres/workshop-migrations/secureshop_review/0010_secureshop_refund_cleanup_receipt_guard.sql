-- Immutable receipt guard added after the original 0009 receipt migration.
CREATE FUNCTION secureshop_review.guard_refund_cleanup_receipt() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP IN ('UPDATE','DELETE') THEN
    RAISE EXCEPTION 'refund cleanup receipts are immutable' USING ERRCODE = '55000';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER refund_cleanup_receipt_immutable
BEFORE UPDATE OR DELETE ON secureshop_review.product_target_refund_cleanup_receipts
FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_refund_cleanup_receipt();
REVOKE ALL ON FUNCTION secureshop_review.guard_refund_cleanup_receipt() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.guard_refund_cleanup_receipt()
  TO dvaia_secureshop_review_runtime;
