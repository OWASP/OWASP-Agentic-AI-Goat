-- Launch-owned commerce state. Product data remains an immutable snapshot;
-- mutable carts and orders are isolated by the same target and persona.
CREATE TABLE secureshop_review.product_target_cart_items (
  cart_item_id bigint GENERATED ALWAYS AS IDENTITY,
  target_id uuid NOT NULL,
  shop_user_id integer NOT NULL CHECK (shop_user_id >= 1),
  product_id integer NOT NULL,
  quantity integer NOT NULL CHECK (quantity BETWEEN 1 AND 99),
  added_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (target_id,cart_item_id),
  UNIQUE (target_id,shop_user_id,product_id),
  FOREIGN KEY (target_id,product_id) REFERENCES secureshop_review.product_target_products(target_id,product_id) ON DELETE RESTRICT
);

CREATE TABLE secureshop_review.product_target_orders (
  target_id uuid NOT NULL REFERENCES secureshop_review.product_targets(target_id) ON DELETE RESTRICT,
  order_id bigint GENERATED ALWAYS AS IDENTITY,
  shop_user_id integer NOT NULL CHECK (shop_user_id >= 1),
  -- 256 source products * quantity 99 * maximum product price fits numeric(15,2)
  -- and remains below JavaScript's exact-integer limit when represented in cents.
  total_amount numeric(15,2) NOT NULL CHECK (total_amount >= 0),
  status text NOT NULL DEFAULT 'confirmed' CHECK (status IN ('pending','confirmed','shipped','delivered','cancelled')),
  payment_method text NOT NULL CHECK (octet_length(payment_method) BETWEEN 1 AND 256),
  payment_status text NOT NULL DEFAULT 'approved' CHECK (payment_status IN ('pending','approved','declined','refunded')),
  shipping_address text NOT NULL CHECK (octet_length(shipping_address) BETWEEN 1 AND 4096),
  order_date timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (target_id,order_id)
);

CREATE TABLE secureshop_review.product_target_order_items (
  target_id uuid NOT NULL,
  order_id bigint NOT NULL,
  order_item_id bigint GENERATED ALWAYS AS IDENTITY,
  product_id integer NOT NULL,
  product_name text NOT NULL CHECK (octet_length(product_name) BETWEEN 1 AND 4096),
  quantity integer NOT NULL CHECK (quantity BETWEEN 1 AND 99),
  price numeric(10,2) NOT NULL CHECK (price >= 0),
  PRIMARY KEY (target_id,order_item_id),
  FOREIGN KEY (target_id,order_id) REFERENCES secureshop_review.product_target_orders(target_id,order_id) ON DELETE CASCADE,
  FOREIGN KEY (target_id,product_id) REFERENCES secureshop_review.product_target_products(target_id,product_id) ON DELETE RESTRICT
);

CREATE INDEX product_target_cart_owner ON secureshop_review.product_target_cart_items(target_id,shop_user_id,cart_item_id);
CREATE INDEX product_target_order_owner ON secureshop_review.product_target_orders(target_id,shop_user_id,order_date DESC,order_id DESC);
CREATE INDEX product_target_order_lines ON secureshop_review.product_target_order_items(target_id,order_id,order_item_id);

CREATE FUNCTION secureshop_review.require_active_commerce_target() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE state text;
BEGIN
  SELECT lifecycle INTO state FROM secureshop_review.product_targets WHERE target_id=NEW.target_id FOR SHARE;
  IF state IS DISTINCT FROM 'active' THEN
    RAISE EXCEPTION 'product target is not active' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER cart_write_requires_active_target BEFORE INSERT OR UPDATE ON secureshop_review.product_target_cart_items
FOR EACH ROW EXECUTE FUNCTION secureshop_review.require_active_commerce_target();
CREATE TRIGGER order_write_requires_active_target BEFORE INSERT OR UPDATE ON secureshop_review.product_target_orders
FOR EACH ROW EXECUTE FUNCTION secureshop_review.require_active_commerce_target();

REVOKE ALL ON TABLE secureshop_review.product_target_cart_items,
  secureshop_review.product_target_orders,secureshop_review.product_target_order_items FROM PUBLIC;
REVOKE ALL ON FUNCTION secureshop_review.require_active_commerce_target() FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE,DELETE ON secureshop_review.product_target_cart_items,
  secureshop_review.product_target_orders,secureshop_review.product_target_order_items TO dvaia_secureshop_review_runtime;
GRANT USAGE,SELECT ON SEQUENCE secureshop_review.product_target_cart_items_cart_item_id_seq,
  secureshop_review.product_target_orders_order_id_seq,
  secureshop_review.product_target_order_items_order_item_id_seq TO dvaia_secureshop_review_runtime;
GRANT EXECUTE ON FUNCTION secureshop_review.require_active_commerce_target() TO dvaia_secureshop_review_runtime;
