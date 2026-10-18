-- DRAFT ONLY. Launch-bound product snapshots live with the dedicated review
-- lab, outside the intentionally queryable shared commerce database.
CREATE TABLE secureshop_review.product_targets (
  target_id uuid PRIMARY KEY,
  launch_id uuid NOT NULL,
  scenario_id uuid NOT NULL,
  generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 9007199254740991),
  original_platform_owner_id integer NOT NULL CHECK (original_platform_owner_id >= 1),
  original_platform_session_id integer NOT NULL CHECK (original_platform_session_id >= 1),
  own_merchant_id integer NOT NULL CHECK (own_merchant_id >= 1),
  lifecycle text NOT NULL DEFAULT 'active' CHECK (lifecycle IN ('active','retired')),
  source_count integer NOT NULL CHECK (source_count BETWEEN 1 AND 256),
  source_sha256 bytea NOT NULL CHECK (octet_length(source_sha256)=32),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  retired_at timestamptz,
  UNIQUE (launch_id,generation),
  CHECK ((lifecycle='retired') = (retired_at IS NOT NULL))
);

CREATE TABLE secureshop_review.product_target_products (
  target_id uuid NOT NULL REFERENCES secureshop_review.product_targets(target_id) ON DELETE RESTRICT,
  product_id integer NOT NULL CHECK (product_id >= 1),
  source_retailer_id integer NOT NULL CHECK (source_retailer_id >= 1),
  retailer_id integer NOT NULL CHECK (retailer_id >= 1),
  source_product_sha256 bytea NOT NULL CHECK (octet_length(source_product_sha256)=32),
  name text NOT NULL CHECK (octet_length(name)<=4096),
  description text CHECK (description IS NULL OR octet_length(description)<=65536),
  description_html text CHECK (description_html IS NULL OR octet_length(description_html)<=65536),
  price numeric(10,2) NOT NULL CHECK (price>=0),
  category text CHECK (category IS NULL OR octet_length(category)<=1024),
  image_url text CHECK (image_url IS NULL OR octet_length(image_url)<=8192),
  images jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(images)='array'),
  stock_quantity integer NOT NULL,
  status text NOT NULL CHECK (octet_length(status)<=64),
  template_source text CHECK (template_source IS NULL OR octet_length(template_source)<=65536),
  source_created_at timestamptz,
  source_updated_at timestamptz,
  PRIMARY KEY(target_id,product_id)
);

CREATE INDEX product_target_merchant_list
  ON secureshop_review.product_target_products(target_id,retailer_id,product_id);

CREATE TABLE secureshop_review.product_cleanup_receipts (
  operation_id uuid PRIMARY KEY,
  target_id uuid NOT NULL UNIQUE REFERENCES secureshop_review.product_targets(target_id) ON DELETE RESTRICT,
  launch_id uuid NOT NULL,
  scenario_id uuid NOT NULL,
  generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 9007199254740991),
  original_platform_owner_id integer NOT NULL CHECK (original_platform_owner_id>=1),
  original_platform_session_id integer NOT NULL CHECK (original_platform_session_id>=1),
  deleted_product_count integer NOT NULL CHECK (deleted_product_count BETWEEN 1 AND 256),
  source_count integer NOT NULL CHECK (source_count BETWEEN 1 AND 256),
  source_sha256 bytea NOT NULL CHECK (octet_length(source_sha256)=32),
  receipt_sha256 bytea NOT NULL CHECK (octet_length(receipt_sha256)=32),
  completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (deleted_product_count=source_count)
);

CREATE FUNCTION secureshop_review.guard_product_target() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP='DELETE' OR NEW.target_id IS DISTINCT FROM OLD.target_id
     OR NEW.launch_id IS DISTINCT FROM OLD.launch_id
     OR NEW.scenario_id IS DISTINCT FROM OLD.scenario_id
     OR NEW.generation IS DISTINCT FROM OLD.generation
     OR NEW.original_platform_owner_id IS DISTINCT FROM OLD.original_platform_owner_id
     OR NEW.original_platform_session_id IS DISTINCT FROM OLD.original_platform_session_id
     OR NEW.own_merchant_id IS DISTINCT FROM OLD.own_merchant_id
     OR NEW.source_count IS DISTINCT FROM OLD.source_count
     OR NEW.source_sha256 IS DISTINCT FROM OLD.source_sha256
     OR NEW.created_at IS DISTINCT FROM OLD.created_at
     OR OLD.lifecycle='retired'
     OR NEW.lifecycle NOT IN ('active','retired') THEN
    RAISE EXCEPTION 'product target identity or lifecycle is immutable' USING ERRCODE='55000';
  END IF;
  IF NEW.lifecycle='retired' THEN NEW.retired_at=clock_timestamp(); END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER product_target_guard BEFORE UPDATE OR DELETE ON secureshop_review.product_targets
FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_product_target();

CREATE FUNCTION secureshop_review.require_active_product_target() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE state text;
BEGIN
  SELECT lifecycle INTO state FROM secureshop_review.product_targets
    WHERE target_id=NEW.target_id FOR SHARE;
  IF state IS DISTINCT FROM 'active' THEN
    RAISE EXCEPTION 'product target is not active' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER product_insert_requires_active_target
BEFORE INSERT ON secureshop_review.product_target_products
FOR EACH ROW EXECUTE FUNCTION secureshop_review.require_active_product_target();

CREATE FUNCTION secureshop_review.guard_product_identity() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'product snapshot is immutable' USING ERRCODE='55000';
END $$;
CREATE TRIGGER product_identity_guard BEFORE UPDATE ON secureshop_review.product_target_products
FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_product_identity();

CREATE FUNCTION secureshop_review.guard_product_cleanup_receipt() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'product cleanup receipt is immutable' USING ERRCODE='55000';
END $$;
CREATE TRIGGER product_cleanup_receipt_guard
BEFORE UPDATE OR DELETE ON secureshop_review.product_cleanup_receipts
FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_product_cleanup_receipt();

REVOKE ALL ON TABLE secureshop_review.product_targets,
  secureshop_review.product_target_products,
  secureshop_review.product_cleanup_receipts FROM PUBLIC;
REVOKE ALL ON FUNCTION secureshop_review.guard_product_target(),
  secureshop_review.require_active_product_target(),
  secureshop_review.guard_product_identity(),
  secureshop_review.guard_product_cleanup_receipt() FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON secureshop_review.product_targets
  TO dvaia_secureshop_review_runtime;
GRANT SELECT,INSERT,DELETE ON secureshop_review.product_target_products
  TO dvaia_secureshop_review_runtime;
GRANT SELECT,INSERT,UPDATE ON secureshop_review.product_cleanup_receipts
  TO dvaia_secureshop_review_runtime;
GRANT EXECUTE ON FUNCTION secureshop_review.guard_product_target(),
  secureshop_review.require_active_product_target(),
  secureshop_review.guard_product_identity(),
  secureshop_review.guard_product_cleanup_receipt()
  TO dvaia_secureshop_review_runtime;
