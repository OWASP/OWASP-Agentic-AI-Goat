-- Launch-owned merchant listing additions and overlays. Copied source product
-- rows remain immutable; every editable presentation is held separately.
CREATE TABLE secureshop_review.product_target_merchant_listings (
  target_id uuid NOT NULL,
  product_id integer NOT NULL CHECK (product_id >= 1),
  shop_user_id integer NOT NULL CHECK (shop_user_id >= 1),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (target_id,product_id),
  FOREIGN KEY (target_id,product_id)
    REFERENCES secureshop_review.product_target_products(target_id,product_id) ON DELETE CASCADE
);

CREATE TABLE secureshop_review.product_target_listing_overlays (
  target_id uuid NOT NULL,
  product_id integer NOT NULL CHECK (product_id >= 1),
  shop_user_id integer NOT NULL CHECK (shop_user_id >= 1),
  name text NOT NULL CHECK (octet_length(name) BETWEEN 1 AND 4096),
  description text CHECK (description IS NULL OR octet_length(description) <= 65536),
  description_html text CHECK (description_html IS NULL OR octet_length(description_html) <= 65536),
  price numeric(10,2) NOT NULL CHECK (price >= 0),
  category text CHECK (category IS NULL OR octet_length(category) <= 1024),
  image_url text CHECK (image_url IS NULL OR octet_length(image_url) <= 8192),
  images jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(images)='array'),
  stock_quantity integer NOT NULL,
  status text NOT NULL CHECK (octet_length(status) BETWEEN 1 AND 64),
  template_source text CHECK (template_source IS NULL OR octet_length(template_source) <= 65536),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  archived_at timestamptz,
  PRIMARY KEY (target_id,product_id),
  FOREIGN KEY (target_id,product_id)
    REFERENCES secureshop_review.product_target_products(target_id,product_id) ON DELETE CASCADE
);
CREATE INDEX product_target_listing_owner
  ON secureshop_review.product_target_listing_overlays(target_id,shop_user_id,status,product_id);

CREATE TABLE secureshop_review.product_listing_cleanup_receipts (
  operation_id uuid PRIMARY KEY,
  target_id uuid NOT NULL UNIQUE REFERENCES secureshop_review.product_targets(target_id) ON DELETE RESTRICT,
  deleted_created_count integer NOT NULL CHECK (deleted_created_count BETWEEN 0 AND 256),
  deleted_overlay_count integer NOT NULL CHECK (deleted_overlay_count BETWEEN 0 AND 512),
  receipt_sha256 bytea NOT NULL CHECK (octet_length(receipt_sha256)=32),
  completed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE FUNCTION secureshop_review.guard_listing_overlay_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.target_id IS DISTINCT FROM OLD.target_id
      OR NEW.product_id IS DISTINCT FROM OLD.product_id
      OR NEW.shop_user_id IS DISTINCT FROM OLD.shop_user_id
      OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'listing overlay identity is immutable' USING ERRCODE='55000';
  END IF;
  NEW.updated_at=clock_timestamp();
  RETURN NEW;
END $$;
CREATE TRIGGER merchant_listing_write_requires_active_target
BEFORE INSERT OR UPDATE ON secureshop_review.product_target_merchant_listings
FOR EACH ROW EXECUTE FUNCTION secureshop_review.require_active_commerce_target();
CREATE TRIGGER listing_overlay_write_requires_active_target
BEFORE INSERT OR UPDATE ON secureshop_review.product_target_listing_overlays
FOR EACH ROW EXECUTE FUNCTION secureshop_review.require_active_commerce_target();
CREATE TRIGGER listing_overlay_identity_guard
BEFORE UPDATE ON secureshop_review.product_target_listing_overlays
FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_listing_overlay_identity();
CREATE TRIGGER product_listing_cleanup_receipt_guard
BEFORE UPDATE OR DELETE ON secureshop_review.product_listing_cleanup_receipts
FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_product_cleanup_receipt();

REVOKE ALL ON TABLE secureshop_review.product_target_merchant_listings,
  secureshop_review.product_target_listing_overlays,
  secureshop_review.product_listing_cleanup_receipts FROM PUBLIC;
REVOKE ALL ON FUNCTION secureshop_review.guard_listing_overlay_identity() FROM PUBLIC;
GRANT SELECT,INSERT,DELETE ON secureshop_review.product_target_merchant_listings
  TO dvaia_secureshop_review_runtime;
GRANT SELECT,INSERT,UPDATE,DELETE ON secureshop_review.product_target_listing_overlays
  TO dvaia_secureshop_review_runtime;
GRANT SELECT,INSERT ON secureshop_review.product_listing_cleanup_receipts
  TO dvaia_secureshop_review_runtime;
GRANT EXECUTE ON FUNCTION secureshop_review.guard_listing_overlay_identity()
  TO dvaia_secureshop_review_runtime;
