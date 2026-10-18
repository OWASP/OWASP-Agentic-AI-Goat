-- A confirmed chat creation commits the owned product, merchant row, audit, and
-- immutable hash-only operation receipt in one review-store transaction.
CREATE TABLE secureshop_review.owned_merchant_listing_create_receipts (
  operation_id uuid PRIMARY KEY,
  target_id uuid NOT NULL REFERENCES secureshop_review.product_targets(target_id) ON DELETE RESTRICT,
  launch_id uuid NOT NULL,
  scenario_id uuid NOT NULL,
  generation bigint NOT NULL CHECK (generation >= 1),
  original_platform_owner_id integer NOT NULL CHECK (original_platform_owner_id >= 1),
  original_platform_session_id integer NOT NULL CHECK (original_platform_session_id >= 1),
  scene_id uuid NOT NULL,
  scene_generation bigint NOT NULL CHECK (scene_generation >= 1),
  grant_id uuid NOT NULL,
  merchant_id integer NOT NULL CHECK (merchant_id >= 1),
  persona_session_id uuid NOT NULL,
  authority_version text NOT NULL CHECK (authority_version ~ '^[1-9][0-9]*$'),
  product_id integer NOT NULL CHECK (product_id >= 1),
  scope_key bytea NOT NULL CHECK (octet_length(scope_key) = 32),
  request_sha256 bytea NOT NULL CHECK (octet_length(request_sha256) = 32),
  source_sha256 bytea NOT NULL CHECK (octet_length(source_sha256) = 32),
  receipt_sha256 bytea NOT NULL CHECK (octet_length(receipt_sha256) = 32),
  completed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX owned_merchant_listing_create_owner_read
  ON secureshop_review.owned_merchant_listing_create_receipts
  (target_id,merchant_id,persona_session_id,operation_id);
CREATE TRIGGER owned_merchant_listing_create_receipt_guard
BEFORE UPDATE OR DELETE ON secureshop_review.owned_merchant_listing_create_receipts
FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_product_cleanup_receipt();

REVOKE ALL ON TABLE secureshop_review.owned_merchant_listing_create_receipts
  FROM PUBLIC,dvaia_secureshop_review_runtime;
GRANT SELECT,INSERT ON secureshop_review.owned_merchant_listing_create_receipts
  TO dvaia_secureshop_review_runtime;
