-- Launch-owned account presentation state. Canonical personas remain immutable
-- in secureshop_agents.bound_persona_templates.
CREATE TABLE secureshop_review.product_target_profile_overlays (
  target_id uuid NOT NULL REFERENCES secureshop_review.product_targets(target_id) ON DELETE RESTRICT,
  shop_user_id integer NOT NULL CHECK (shop_user_id >= 1),
  email text NOT NULL CHECK (octet_length(email) BETWEEN 3 AND 320),
  full_name text CHECK (full_name IS NULL OR octet_length(full_name) <= 512),
  phone text CHECK (phone IS NULL OR octet_length(phone) <= 128),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (target_id,shop_user_id)
);

CREATE TABLE secureshop_review.product_target_addresses (
  target_id uuid NOT NULL REFERENCES secureshop_review.product_targets(target_id) ON DELETE RESTRICT,
  address_id bigint GENERATED ALWAYS AS IDENTITY,
  shop_user_id integer NOT NULL CHECK (shop_user_id >= 1),
  label text CHECK (label IS NULL OR octet_length(label) <= 128),
  line1 text NOT NULL CHECK (octet_length(line1) BETWEEN 1 AND 1024),
  line2 text CHECK (line2 IS NULL OR octet_length(line2) <= 1024),
  city text CHECK (city IS NULL OR octet_length(city) <= 256),
  state text CHECK (state IS NULL OR octet_length(state) <= 128),
  zip text CHECK (zip IS NULL OR octet_length(zip) <= 64),
  phone text CHECK (phone IS NULL OR octet_length(phone) <= 128),
  is_default boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (target_id,address_id)
);

CREATE INDEX product_target_address_owner
  ON secureshop_review.product_target_addresses(target_id,shop_user_id,is_default DESC,address_id);
CREATE UNIQUE INDEX product_target_one_default_address
  ON secureshop_review.product_target_addresses(target_id,shop_user_id) WHERE is_default;

CREATE TABLE secureshop_review.product_account_cleanup_receipts (
  operation_id uuid PRIMARY KEY,
  target_id uuid NOT NULL UNIQUE REFERENCES secureshop_review.product_targets(target_id) ON DELETE RESTRICT,
  launch_id uuid NOT NULL,
  scenario_id uuid NOT NULL,
  generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 9007199254740991),
  original_platform_owner_id integer NOT NULL CHECK (original_platform_owner_id >= 1),
  original_platform_session_id integer NOT NULL CHECK (original_platform_session_id >= 1),
  deleted_profile_count integer NOT NULL CHECK (deleted_profile_count BETWEEN 0 AND 3),
  deleted_address_count integer NOT NULL CHECK (deleted_address_count BETWEEN 0 AND 96),
  receipt_sha256 bytea NOT NULL CHECK (octet_length(receipt_sha256)=32),
  completed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE FUNCTION secureshop_review.guard_profile_overlay_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.target_id IS DISTINCT FROM OLD.target_id
      OR NEW.shop_user_id IS DISTINCT FROM OLD.shop_user_id
      OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'account overlay identity is immutable' USING ERRCODE='55000';
  END IF;
  NEW.updated_at=clock_timestamp();
  RETURN NEW;
END $$;

CREATE FUNCTION secureshop_review.guard_address_overlay_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.target_id IS DISTINCT FROM OLD.target_id
      OR NEW.shop_user_id IS DISTINCT FROM OLD.shop_user_id
      OR NEW.address_id IS DISTINCT FROM OLD.address_id
      OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
    RAISE EXCEPTION 'account overlay identity is immutable' USING ERRCODE='55000';
  END IF;
  NEW.updated_at=clock_timestamp();
  RETURN NEW;
END $$;

CREATE TRIGGER profile_write_requires_active_target
BEFORE INSERT OR UPDATE ON secureshop_review.product_target_profile_overlays
FOR EACH ROW EXECUTE FUNCTION secureshop_review.require_active_commerce_target();
CREATE TRIGGER address_write_requires_active_target
BEFORE INSERT OR UPDATE ON secureshop_review.product_target_addresses
FOR EACH ROW EXECUTE FUNCTION secureshop_review.require_active_commerce_target();
CREATE TRIGGER profile_overlay_identity_guard
BEFORE UPDATE ON secureshop_review.product_target_profile_overlays
FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_profile_overlay_identity();
CREATE TRIGGER address_overlay_identity_guard
BEFORE UPDATE ON secureshop_review.product_target_addresses
FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_address_overlay_identity();
CREATE TRIGGER product_account_cleanup_receipt_guard
BEFORE UPDATE OR DELETE ON secureshop_review.product_account_cleanup_receipts
FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_product_cleanup_receipt();

REVOKE ALL ON TABLE secureshop_review.product_target_profile_overlays,
  secureshop_review.product_target_addresses,
  secureshop_review.product_account_cleanup_receipts FROM PUBLIC;
REVOKE ALL ON FUNCTION secureshop_review.guard_profile_overlay_identity(),
  secureshop_review.guard_address_overlay_identity() FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE,DELETE ON secureshop_review.product_target_profile_overlays,
  secureshop_review.product_target_addresses TO dvaia_secureshop_review_runtime;
GRANT SELECT,INSERT ON secureshop_review.product_account_cleanup_receipts
  TO dvaia_secureshop_review_runtime;
GRANT USAGE,SELECT ON SEQUENCE secureshop_review.product_target_addresses_address_id_seq
  TO dvaia_secureshop_review_runtime;
GRANT EXECUTE ON FUNCTION secureshop_review.guard_profile_overlay_identity(),
  secureshop_review.guard_address_overlay_identity()
  TO dvaia_secureshop_review_runtime;
