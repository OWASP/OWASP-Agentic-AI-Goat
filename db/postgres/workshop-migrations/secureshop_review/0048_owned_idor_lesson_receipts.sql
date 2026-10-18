-- Target-local synthetic customer lessons. These tables never authorize the
-- ordinary cart/order APIs; the scene grant and current target are checked by
-- the dedicated repository for every operation.
CREATE TABLE secureshop_review.owned_idor_lesson_births (
  birth_id uuid PRIMARY KEY,
  target_id uuid NOT NULL UNIQUE REFERENCES secureshop_review.product_targets(target_id),
  scene_id uuid NOT NULL,
  scene_generation bigint NOT NULL CHECK (scene_generation > 0),
  birth_grant_id uuid NOT NULL REFERENCES secureshop_review.scene_execution_grants(grant_id),
  birth_launch_id uuid NOT NULL,
  birth_scenario_id uuid NOT NULL,
  birth_generation bigint NOT NULL CHECK (birth_generation > 0),
  platform_owner_id integer NOT NULL CHECK (platform_owner_id > 0),
  attacker_shop_user_id integer NOT NULL CHECK (attacker_shop_user_id >= 1000000000),
  victim_shop_user_id integer NOT NULL CHECK (victim_shop_user_id > 0 AND victim_shop_user_id < 1000000000),
  victim_identity_sha256 bytea NOT NULL CHECK (octet_length(victim_identity_sha256) = 32),
  cart_item_id bigint NOT NULL CHECK (cart_item_id > 0),
  order_id bigint NOT NULL CHECK (order_id > 0),
  cart_preimage jsonb NOT NULL CHECK (jsonb_typeof(cart_preimage) = 'object'),
  order_preimage jsonb NOT NULL CHECK (jsonb_typeof(order_preimage) = 'object'),
  birth_sha256 bytea NOT NULL CHECK (octet_length(birth_sha256) = 32),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (attacker_shop_user_id <> victim_shop_user_id)
);

CREATE TABLE secureshop_review.owned_idor_lesson_operations (
  operation_id uuid PRIMARY KEY,
  birth_id uuid NOT NULL REFERENCES secureshop_review.owned_idor_lesson_births(birth_id),
  target_id uuid NOT NULL REFERENCES secureshop_review.product_targets(target_id),
  scene_id uuid NOT NULL,
  scene_generation bigint NOT NULL CHECK (scene_generation > 0),
  grant_id uuid NOT NULL REFERENCES secureshop_review.scene_execution_grants(grant_id),
  launch_id uuid NOT NULL,
  scenario_id uuid NOT NULL,
  generation bigint NOT NULL CHECK (generation > 0),
  platform_owner_id integer NOT NULL CHECK (platform_owner_id > 0),
  platform_session_id integer NOT NULL CHECK (platform_session_id > 0),
  actor_shop_user_id integer NOT NULL CHECK (actor_shop_user_id >= 1000000000),
  persona_session_id uuid NOT NULL,
  authority_version text NOT NULL CHECK (authority_version ~ '^[1-9][0-9]*$'),
  action text NOT NULL CHECK (action IN ('cart_remove','order_status')),
  numeric_id bigint NOT NULL CHECK (numeric_id > 0),
  mode_snapshot jsonb NOT NULL CHECK (jsonb_typeof(mode_snapshot) = 'object'),
  turn_origin jsonb NOT NULL CHECK (jsonb_typeof(turn_origin) = 'object'),
  request_sha256 bytea NOT NULL CHECK (octet_length(request_sha256) = 32),
  result_json jsonb NOT NULL CHECK (jsonb_typeof(result_json) = 'object'),
  receipt_sha256 bytea NOT NULL CHECK (octet_length(receipt_sha256) = 32),
  completed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX owned_idor_operations_target ON secureshop_review.owned_idor_lesson_operations(target_id,completed_at);

CREATE FUNCTION secureshop_review.guard_owned_idor_birth_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,secureshop_review AS $$
BEGIN
  PERFORM 1 FROM secureshop_review.product_targets p
    JOIN secureshop_review.scene_execution_grants g ON g.grant_id=NEW.birth_grant_id
    JOIN secureshop_review.product_target_cart_items c
      ON c.target_id=p.target_id AND c.cart_item_id=NEW.cart_item_id
    JOIN secureshop_review.product_target_orders o
      ON o.target_id=p.target_id AND o.order_id=NEW.order_id
    JOIN secureshop_review.product_target_order_items i
      ON i.target_id=o.target_id AND i.order_id=o.order_id
        AND i.order_item_id=(NEW.order_preimage->'item'->>'orderItemId')::bigint
    WHERE p.target_id=NEW.target_id AND p.lifecycle='active'
      AND p.launch_id=NEW.birth_launch_id AND p.scenario_id=NEW.birth_scenario_id
      AND p.generation=NEW.birth_generation
      AND p.original_platform_owner_id=NEW.platform_owner_id
      AND g.target_id=p.target_id AND g.scene_id=NEW.scene_id
      AND g.scene_generation=NEW.scene_generation
      AND g.launch_id=NEW.birth_launch_id
      AND g.scenario_id=NEW.birth_scenario_id
      AND g.generation=NEW.birth_generation
      AND g.original_platform_owner_id=NEW.platform_owner_id
      AND g.original_platform_session_id=p.original_platform_session_id
      AND c.shop_user_id=NEW.victim_shop_user_id
      AND o.shop_user_id=NEW.victim_shop_user_id
      AND o.total_amount=1.00 AND o.subtotal_amount=1.00 AND o.discount_amount=0
      AND o.coupon_code IS NULL AND o.coupon_percent IS NULL
      AND o.payment_method='synthetic lesson' AND o.shipping_address='Synthetic lesson address'
      AND i.product_name='Synthetic lesson product' AND i.quantity=1
      AND i.price=1.00 AND i.discount_amount=0
      AND (SELECT count(*) FROM jsonb_object_keys(NEW.cart_preimage))=5
      AND (SELECT count(*) FROM jsonb_object_keys(NEW.order_preimage))=14
      AND (SELECT count(*) FROM jsonb_object_keys(NEW.order_preimage->'item'))=6
      AND NEW.cart_preimage->>'cartItemId'=NEW.cart_item_id::text
      AND NEW.cart_preimage->>'shopUserId'=NEW.victim_shop_user_id::text
      AND NEW.cart_preimage->>'productId'=c.product_id::text
      AND NEW.cart_preimage->>'quantity'=c.quantity::text
      AND NEW.cart_preimage->>'addedAt'=
        to_char(c.added_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
      AND NEW.order_preimage->>'orderId'=NEW.order_id::text
      AND NEW.order_preimage->>'shopUserId'=NEW.victim_shop_user_id::text
      AND NEW.order_preimage->>'totalAmount'=o.total_amount::text
      AND NEW.order_preimage->>'subtotalAmount'=o.subtotal_amount::text
      AND NEW.order_preimage->>'discountAmount'=o.discount_amount::text
      AND NEW.order_preimage->>'status'=o.status
      AND NEW.order_preimage->>'paymentStatus'=o.payment_status
      AND NEW.order_preimage->>'paymentMethod'=o.payment_method
      AND NEW.order_preimage->>'shippingAddress'=o.shipping_address
      AND NEW.order_preimage->>'orderDate'=
        to_char(o.order_date AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
      AND NEW.order_preimage->>'updatedAt'=
        to_char(o.updated_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
      AND NEW.order_preimage->'couponCode'='null'::jsonb
      AND NEW.order_preimage->'couponPercent'='null'::jsonb
      AND NEW.order_preimage->'item'->>'orderItemId'=i.order_item_id::text
      AND NEW.order_preimage->'item'->>'productId'=i.product_id::text
      AND NEW.order_preimage->'item'->>'productName'=i.product_name
      AND NEW.order_preimage->'item'->>'quantity'=i.quantity::text
      AND NEW.order_preimage->'item'->>'price'=i.price::text
      AND NEW.order_preimage->'item'->>'discountAmount'=i.discount_amount::text;
  IF NOT FOUND THEN RAISE EXCEPTION 'Owned IDOR birth source unavailable' USING ERRCODE='55000'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER owned_idor_birth_source BEFORE INSERT
  ON secureshop_review.owned_idor_lesson_births FOR EACH ROW
  EXECUTE FUNCTION secureshop_review.guard_owned_idor_birth_insert();

CREATE FUNCTION secureshop_review.guard_owned_idor_operation_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,secureshop_review AS $$
BEGIN
  PERFORM 1 FROM secureshop_review.owned_idor_lesson_births b
    JOIN secureshop_review.scene_execution_grants g ON g.grant_id=NEW.grant_id
    JOIN secureshop_review.product_targets p ON p.target_id=b.target_id
    WHERE b.birth_id=NEW.birth_id AND b.target_id=NEW.target_id
      AND b.scene_id=NEW.scene_id AND b.scene_generation=NEW.scene_generation
      AND b.platform_owner_id=NEW.platform_owner_id
      AND b.attacker_shop_user_id=NEW.actor_shop_user_id
      AND ((NEW.action='cart_remove' AND b.cart_item_id=NEW.numeric_id)
        OR (NEW.action='order_status' AND b.order_id=NEW.numeric_id))
      AND g.target_id=b.target_id AND g.scene_id=NEW.scene_id
      AND g.scene_generation=NEW.scene_generation
      AND g.launch_id=NEW.launch_id AND g.scenario_id=NEW.scenario_id
      AND g.generation=NEW.generation
      AND g.original_platform_owner_id=NEW.platform_owner_id
      AND g.original_platform_session_id=NEW.platform_session_id
      AND p.lifecycle='active';
  IF NOT FOUND THEN RAISE EXCEPTION 'Owned IDOR operation source unavailable' USING ERRCODE='55000'; END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER owned_idor_operation_source BEFORE INSERT
  ON secureshop_review.owned_idor_lesson_operations FOR EACH ROW
  EXECUTE FUNCTION secureshop_review.guard_owned_idor_operation_insert();

CREATE FUNCTION secureshop_review.guard_owned_idor_lesson_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,secureshop_review AS $$
BEGIN
  RAISE EXCEPTION 'Owned IDOR lesson receipt is immutable' USING ERRCODE='55000';
END $$;
CREATE TRIGGER owned_idor_birth_immutable BEFORE UPDATE OR DELETE
  ON secureshop_review.owned_idor_lesson_births FOR EACH ROW
  EXECUTE FUNCTION secureshop_review.guard_owned_idor_lesson_immutable();
CREATE TRIGGER owned_idor_operation_immutable BEFORE UPDATE OR DELETE
  ON secureshop_review.owned_idor_lesson_operations FOR EACH ROW
  EXECUTE FUNCTION secureshop_review.guard_owned_idor_lesson_immutable();

REVOKE ALL ON TABLE secureshop_review.owned_idor_lesson_births,
  secureshop_review.owned_idor_lesson_operations FROM PUBLIC;
REVOKE ALL ON FUNCTION secureshop_review.guard_owned_idor_birth_insert(),
  secureshop_review.guard_owned_idor_operation_insert(),
  secureshop_review.guard_owned_idor_lesson_immutable() FROM PUBLIC;
GRANT SELECT,INSERT ON secureshop_review.owned_idor_lesson_births,
  secureshop_review.owned_idor_lesson_operations TO dvaia_secureshop_review_runtime;
GRANT EXECUTE ON FUNCTION secureshop_review.guard_owned_idor_birth_insert(),
  secureshop_review.guard_owned_idor_operation_insert(),
  secureshop_review.guard_owned_idor_lesson_immutable() TO dvaia_secureshop_review_runtime;
