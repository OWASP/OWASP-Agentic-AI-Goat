-- Launch-owned refund requests. This is a support request effect, not a payment
-- refund and never touches the shared legacy secureshop database.
CREATE TABLE secureshop_review.product_target_refund_requests (
  target_id uuid NOT NULL,
  ticket_id bigint GENERATED ALWAYS AS IDENTITY,
  shop_user_id integer NOT NULL CHECK (shop_user_id >= 1),
  order_id bigint NOT NULL,
  operation_kind text NOT NULL DEFAULT 'refund_request'
    CHECK (operation_kind = 'refund_request'),
  request_id uuid NOT NULL,
  run_id uuid,
  status text NOT NULL DEFAULT 'open' CHECK (status IN ('open','closed','rejected')),
  reason text NOT NULL CHECK (octet_length(reason) BETWEEN 1 AND 4096),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (target_id,ticket_id),
  UNIQUE (target_id,shop_user_id,order_id,operation_kind),
  FOREIGN KEY (target_id,order_id)
    REFERENCES secureshop_review.product_target_orders(target_id,order_id) ON DELETE RESTRICT
);
CREATE INDEX product_target_refund_owner
  ON secureshop_review.product_target_refund_requests(target_id,shop_user_id,order_id);

CREATE FUNCTION secureshop_review.require_active_refund_target() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE state text;
BEGIN
  SELECT lifecycle INTO state FROM secureshop_review.product_targets
    WHERE target_id=NEW.target_id FOR SHARE;
  IF state IS DISTINCT FROM 'active' THEN
    RAISE EXCEPTION 'product target is not active' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER refund_request_requires_active_target
BEFORE INSERT ON secureshop_review.product_target_refund_requests
FOR EACH ROW EXECUTE FUNCTION secureshop_review.require_active_refund_target();

REVOKE ALL ON TABLE secureshop_review.product_target_refund_requests FROM PUBLIC;
REVOKE ALL ON FUNCTION secureshop_review.require_active_refund_target() FROM PUBLIC;
GRANT SELECT,INSERT,DELETE ON secureshop_review.product_target_refund_requests
  TO dvaia_secureshop_review_runtime;
GRANT USAGE,SELECT ON SEQUENCE secureshop_review.product_target_refund_requests_ticket_id_seq
  TO dvaia_secureshop_review_runtime;
GRANT EXECUTE ON FUNCTION secureshop_review.require_active_refund_target()
  TO dvaia_secureshop_review_runtime;
