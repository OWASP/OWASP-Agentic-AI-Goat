-- Actual observations, never reconstructed daily estimates. Existing products
-- start at this migration's observation time, not their source catalog dates.
LOCK TABLE secureshop_review.product_targets,secureshop_review.product_target_products,
  secureshop_review.product_target_listing_overlays IN SHARE ROW EXCLUSIVE MODE;
CREATE TABLE secureshop_review.product_target_price_history (
  observation_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  target_id uuid NOT NULL,
  product_id integer NOT NULL,
  price numeric(10,2) NOT NULL CHECK (price >= 0),
  observed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  source text NOT NULL CHECK (source IN ('migration_baseline','product_insert','price_change')),
  FOREIGN KEY (target_id,product_id)
    REFERENCES secureshop_review.product_target_products(target_id,product_id) ON DELETE CASCADE
);
CREATE INDEX product_price_history_read ON secureshop_review.product_target_price_history
  (target_id,product_id,observed_at DESC,observation_id DESC);

INSERT INTO secureshop_review.product_target_price_history(target_id,product_id,price,source)
SELECT p.target_id,p.product_id,COALESCE(o.price,p.price),'migration_baseline'
FROM secureshop_review.product_target_products p
JOIN secureshop_review.product_targets t ON t.target_id=p.target_id AND t.lifecycle='active'
LEFT JOIN secureshop_review.product_target_listing_overlays o
  ON o.target_id=p.target_id AND o.product_id=p.product_id;

CREATE FUNCTION secureshop_review.observe_product_price() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE storage uuid; product integer; base_price numeric; previous_price numeric; next_price numeric;
BEGIN
  IF TG_TABLE_NAME='product_target_products' THEN
    INSERT INTO secureshop_review.product_target_price_history(target_id,product_id,price,source)
      VALUES(NEW.target_id,NEW.product_id,NEW.price,'product_insert');
    RETURN NEW;
  END IF;
  IF TG_OP='DELETE' THEN storage=OLD.target_id; product=OLD.product_id;
  ELSE storage=NEW.target_id; product=NEW.product_id; END IF;
  SELECT p.price INTO base_price FROM secureshop_review.product_target_products p
    JOIN secureshop_review.product_targets t ON t.target_id=p.target_id AND t.lifecycle='active'
    WHERE p.target_id=storage AND p.product_id=product;
  -- Retired-target cleanup removes overlays/products; it is not a price change.
  IF NOT FOUND THEN RETURN NULL; END IF;
  previous_price=CASE WHEN TG_OP='INSERT' THEN base_price ELSE OLD.price END;
  next_price=CASE WHEN TG_OP='DELETE' THEN base_price ELSE NEW.price END;
  IF next_price IS DISTINCT FROM previous_price THEN
    INSERT INTO secureshop_review.product_target_price_history(target_id,product_id,price,source)
      VALUES(storage,product,next_price,'price_change');
  END IF;
  RETURN NULL;
END $$;
CREATE TRIGGER product_price_insert_observation AFTER INSERT ON secureshop_review.product_target_products
  FOR EACH ROW EXECUTE FUNCTION secureshop_review.observe_product_price();
CREATE TRIGGER product_price_overlay_observation AFTER INSERT OR UPDATE OR DELETE
  ON secureshop_review.product_target_listing_overlays
  FOR EACH ROW EXECUTE FUNCTION secureshop_review.observe_product_price();

CREATE FUNCTION secureshop_review.guard_product_price_history() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
  IF TG_OP='DELETE' AND EXISTS(SELECT 1 FROM secureshop_review.product_targets
    WHERE target_id=OLD.target_id AND lifecycle='retired') THEN RETURN OLD; END IF;
  RAISE EXCEPTION 'price observations are immutable while their target is active' USING ERRCODE='55000';
END $$;
CREATE TRIGGER product_price_history_guard BEFORE UPDATE OR DELETE
  ON secureshop_review.product_target_price_history
  FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_product_price_history();

REVOKE ALL ON TABLE secureshop_review.product_target_price_history FROM PUBLIC,dvaia_secureshop_review_runtime;
REVOKE ALL ON SEQUENCE secureshop_review.product_target_price_history_observation_id_seq
  FROM PUBLIC,dvaia_secureshop_review_runtime;
REVOKE ALL ON FUNCTION secureshop_review.observe_product_price(),secureshop_review.guard_product_price_history()
  FROM PUBLIC,dvaia_secureshop_review_runtime;
GRANT SELECT ON TABLE secureshop_review.product_target_price_history TO dvaia_secureshop_review_runtime;
