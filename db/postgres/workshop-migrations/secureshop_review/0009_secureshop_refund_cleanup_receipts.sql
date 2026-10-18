-- Forward-only receipt for removing launch-owned refund tickets during reset.
CREATE TABLE secureshop_review.product_target_refund_cleanup_receipts (
  operation_id uuid PRIMARY KEY,
  target_id uuid NOT NULL UNIQUE REFERENCES secureshop_review.product_targets(target_id),
  deleted_ticket_count integer NOT NULL CHECK (deleted_ticket_count BETWEEN 0 AND 256),
  receipt_sha256 bytea NOT NULL CHECK (octet_length(receipt_sha256)=32),
  completed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON TABLE secureshop_review.product_target_refund_cleanup_receipts FROM PUBLIC;
GRANT SELECT,INSERT ON secureshop_review.product_target_refund_cleanup_receipts
  TO dvaia_secureshop_review_runtime;
