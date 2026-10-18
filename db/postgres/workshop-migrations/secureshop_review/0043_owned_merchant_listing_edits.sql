-- Completed merchant listing edits retain only hashes and owner/birth coordinates.
-- The editable presentation remains in the owned overlay and is removed by the
-- existing product-target cleanup; reset never retains listing text in receipts.
CREATE TABLE secureshop_review.owned_merchant_listing_edit_receipts (
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
  catalog_revision bigint NOT NULL CHECK (catalog_revision BETWEEN 0 AND 9007199254740991),
  request_sha256 bytea NOT NULL CHECK (octet_length(request_sha256) = 32),
  before_sha256 bytea NOT NULL CHECK (octet_length(before_sha256) = 32),
  after_sha256 bytea NOT NULL CHECK (octet_length(after_sha256) = 32),
  receipt_sha256 bytea NOT NULL CHECK (octet_length(receipt_sha256) = 32),
  completed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX owned_merchant_listing_edit_owner_read
  ON secureshop_review.owned_merchant_listing_edit_receipts
  (target_id,merchant_id,persona_session_id,operation_id);
CREATE TRIGGER owned_merchant_listing_edit_receipt_guard
BEFORE UPDATE OR DELETE ON secureshop_review.owned_merchant_listing_edit_receipts
FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_product_cleanup_receipt();

REVOKE ALL ON TABLE secureshop_review.owned_merchant_listing_edit_receipts
  FROM PUBLIC,dvaia_secureshop_review_runtime;
GRANT SELECT,INSERT ON secureshop_review.owned_merchant_listing_edit_receipts
  TO dvaia_secureshop_review_runtime;
