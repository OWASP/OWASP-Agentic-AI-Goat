-- REVIEW0025 candidate. Apply only after immutable Listings0022-0024.
CREATE TABLE secureshop_review.bound_commerce_operations (
 operation_id uuid PRIMARY KEY,
 target_id uuid NOT NULL REFERENCES secureshop_review.product_targets(target_id),
 shop_user_id integer NOT NULL CHECK(shop_user_id>0),
 kind text NOT NULL CHECK(kind IN ('coupon','checkout')),
 persona_session_id uuid NOT NULL,
 authority_version bigint NOT NULL CHECK(authority_version>0),
 mode text NOT NULL CHECK(mode IN ('vuln','fixed')),
 request_sha256 text NOT NULL CHECK(request_sha256 ~ '^[a-f0-9]{64}$'),
 request_json text,
 state text NOT NULL DEFAULT 'admitted' CHECK(state IN ('admitted','completed','redacted')),
 result_sha256 text CHECK(result_sha256 ~ '^[a-f0-9]{64}$'),
 result_json text,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK(request_json IS NULL OR octet_length(request_json)<=131072),
 CHECK(result_json IS NULL OR octet_length(result_json)<=16384),
 CHECK((state='admitted' AND request_json IS NOT NULL AND result_json IS NULL AND result_sha256 IS NULL)
    OR (state='completed' AND request_json IS NOT NULL AND result_json IS NOT NULL AND result_sha256 IS NOT NULL)
    OR (state='redacted' AND request_json IS NULL AND result_json IS NULL))
);
CREATE INDEX bound_commerce_operation_owner ON secureshop_review.bound_commerce_operations(target_id,shop_user_id,created_at);
CREATE TABLE secureshop_review.product_target_cart_coupons (
 target_id uuid NOT NULL REFERENCES secureshop_review.product_targets(target_id),
 shop_user_id integer NOT NULL CHECK(shop_user_id>0),
 operation_id uuid NOT NULL REFERENCES secureshop_review.bound_commerce_operations(operation_id),
 coupon_id integer NOT NULL CHECK(coupon_id>0),
 code text NOT NULL CHECK(octet_length(code) BETWEEN 1 AND 1024),
 discount_percent integer NOT NULL CHECK(discount_percent BETWEEN 0 AND 100),
 mode text NOT NULL CHECK(mode IN ('vuln','fixed')),
 PRIMARY KEY(target_id,shop_user_id)
);
CREATE FUNCTION secureshop_review.guard_bound_commerce_operation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Commerce operation is immutable'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'admitted' OR NOT EXISTS(SELECT 1 FROM secureshop_review.product_targets WHERE target_id=NEW.target_id AND lifecycle='active' FOR SHARE) THEN RAISE EXCEPTION 'Commerce target unavailable'; END IF;
  RETURN NEW;
 END IF;
 IF (to_jsonb(NEW)-ARRAY['state','result_json','result_sha256','request_json']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','result_json','result_sha256','request_json']) THEN RAISE EXCEPTION 'Commerce binding immutable'; END IF;
 IF OLD.state='admitted' AND NEW.state='completed' AND NEW.request_json=OLD.request_json AND EXISTS(SELECT 1 FROM secureshop_review.product_targets WHERE target_id=NEW.target_id AND lifecycle='active' FOR SHARE) THEN RETURN NEW; END IF;
 IF OLD.state IN ('admitted','completed') AND NEW.state='redacted' AND NEW.request_json IS NULL AND NEW.result_json IS NULL AND NEW.result_sha256 IS NOT DISTINCT FROM OLD.result_sha256 AND EXISTS(SELECT 1 FROM secureshop_review.product_targets WHERE target_id=NEW.target_id AND lifecycle='retired') THEN RETURN NEW; END IF;
 RAISE EXCEPTION 'Commerce transition unavailable';
END $$;
CREATE TRIGGER bound_commerce_operation_guard BEFORE INSERT OR UPDATE OR DELETE ON secureshop_review.bound_commerce_operations FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_bound_commerce_operation();
CREATE FUNCTION secureshop_review.guard_cart_coupon() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM secureshop_review.product_targets WHERE target_id=NEW.target_id AND lifecycle='active' FOR SHARE) OR NOT EXISTS(SELECT 1 FROM secureshop_review.bound_commerce_operations WHERE operation_id=NEW.operation_id AND target_id=NEW.target_id AND shop_user_id=NEW.shop_user_id AND kind='coupon' AND mode=NEW.mode AND state='completed') THEN RAISE EXCEPTION 'Coupon authority unavailable'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER cart_coupon_guard BEFORE INSERT OR UPDATE ON secureshop_review.product_target_cart_coupons FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_cart_coupon();
CREATE FUNCTION secureshop_review.retire_bound_commerce_operations() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
BEGIN
 IF NEW.lifecycle='retired' AND OLD.lifecycle IS DISTINCT FROM NEW.lifecycle THEN
  DELETE FROM secureshop_review.product_target_cart_coupons WHERE target_id=NEW.target_id;
  UPDATE secureshop_review.bound_commerce_operations SET state='redacted',request_json=NULL,result_json=NULL WHERE target_id=NEW.target_id AND state<>'redacted';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER retire_bound_commerce_operations AFTER UPDATE OF lifecycle ON secureshop_review.product_targets FOR EACH ROW EXECUTE FUNCTION secureshop_review.retire_bound_commerce_operations();
ALTER TABLE secureshop_review.product_target_orders
 ADD COLUMN subtotal_amount numeric(15,2),
 ADD COLUMN discount_amount numeric(15,2) NOT NULL DEFAULT 0,
 ADD COLUMN coupon_code text,
 ADD COLUMN coupon_percent integer;
UPDATE secureshop_review.product_target_orders SET subtotal_amount=total_amount;
ALTER TABLE secureshop_review.product_target_orders ALTER COLUMN subtotal_amount SET NOT NULL;
ALTER TABLE secureshop_review.product_target_orders ADD CONSTRAINT order_discount_shape CHECK(
 subtotal_amount>=0 AND discount_amount>=0 AND discount_amount<=subtotal_amount AND total_amount=subtotal_amount-discount_amount
 AND ((coupon_code IS NULL AND coupon_percent IS NULL AND discount_amount=0)
 OR (coupon_code IS NOT NULL AND coupon_percent IS NOT NULL AND octet_length(coupon_code) BETWEEN 1 AND 1024 AND coupon_percent BETWEEN 0 AND 100 AND discount_amount=round(subtotal_amount*coupon_percent/100,2))));
CREATE FUNCTION secureshop_review.default_order_subtotal() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN NEW.subtotal_amount=COALESCE(NEW.subtotal_amount,NEW.total_amount+NEW.discount_amount);RETURN NEW;END $$;
CREATE TRIGGER default_order_subtotal BEFORE INSERT ON secureshop_review.product_target_orders FOR EACH ROW EXECUTE FUNCTION secureshop_review.default_order_subtotal();
ALTER TABLE secureshop_review.product_target_order_items ADD COLUMN discount_amount numeric(15,2) NOT NULL DEFAULT 0 CHECK(discount_amount>=0 AND discount_amount<=quantity*price);
REVOKE ALL ON secureshop_review.bound_commerce_operations,secureshop_review.product_target_cart_coupons FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON secureshop_review.bound_commerce_operations TO dvaia_secureshop_review_runtime;
GRANT SELECT,INSERT,UPDATE,DELETE ON secureshop_review.product_target_cart_coupons TO dvaia_secureshop_review_runtime;
REVOKE ALL ON FUNCTION secureshop_review.guard_bound_commerce_operation(),secureshop_review.guard_cart_coupon(),secureshop_review.retire_bound_commerce_operations(),secureshop_review.default_order_subtotal() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.guard_bound_commerce_operation(),secureshop_review.guard_cart_coupon(),secureshop_review.retire_bound_commerce_operations(),secureshop_review.default_order_subtotal() TO dvaia_secureshop_review_runtime;
