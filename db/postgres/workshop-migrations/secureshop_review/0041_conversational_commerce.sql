-- Local synthetic shopping only: no processor tokens, card numbers or CVV.
CREATE TABLE secureshop_review.practice_payment_methods (
 method_id uuid PRIMARY KEY,
 target_id uuid NOT NULL REFERENCES secureshop_review.product_targets(target_id),
 shop_user_id integer NOT NULL CHECK(shop_user_id>0),
 scenario text NOT NULL CHECK(scenario IN ('approved','declined')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(target_id,shop_user_id,scenario)
);
CREATE TABLE secureshop_review.chat_commerce_choices (
 choice_id uuid PRIMARY KEY,
 target_id uuid NOT NULL REFERENCES secureshop_review.product_targets(target_id),
 shop_user_id integer NOT NULL CHECK(shop_user_id>0),
 kind text NOT NULL CHECK(kind IN ('product','cart_item','order','address','payment_method')),
 context_json text CHECK(context_json IS NULL OR octet_length(context_json)<=8192),
 snapshot_json text CHECK(snapshot_json IS NULL OR octet_length(snapshot_json)<=65536),
 snapshot_sha256 text NOT NULL CHECK(snapshot_sha256 ~ '^[a-f0-9]{64}$'),
 state text NOT NULL DEFAULT 'active' CHECK(state IN ('active','redacted')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK ((state='active' AND context_json IS NOT NULL AND snapshot_json IS NOT NULL)
 OR (state='redacted' AND context_json IS NULL AND snapshot_json IS NULL))
);
CREATE INDEX chat_commerce_choice_owner ON secureshop_review.chat_commerce_choices(target_id,shop_user_id);
-- One UUID claims one family, including checkout prepare+confirm. No cross-kind reuse.
CREATE TABLE secureshop_review.chat_commerce_operations (
 operation_id uuid PRIMARY KEY,
 target_id uuid NOT NULL REFERENCES secureshop_review.product_targets(target_id),
 shop_user_id integer NOT NULL CHECK(shop_user_id>0),
 kind text NOT NULL CHECK(kind IN ('cart.add','cart.update','cart.remove','payment.create','checkout')),
 context_json text CHECK(context_json IS NULL OR octet_length(context_json)<=8192),
 request_json text CHECK(request_json IS NULL OR octet_length(request_json)<=8192),
 intent_sha256 text NOT NULL CHECK(intent_sha256 ~ '^[a-f0-9]{64}$'),
 proposal_json text CHECK(proposal_json IS NULL OR octet_length(proposal_json)<=131072),
 proposal_sha256 text CHECK(proposal_sha256 IS NULL OR proposal_sha256 ~ '^[a-f0-9]{64}$'),
 result_json text CHECK(result_json IS NULL OR octet_length(result_json)<=65536),
 result_sha256 text CHECK(result_sha256 IS NULL OR result_sha256 ~ '^[a-f0-9]{64}$'),
 state text NOT NULL CHECK(state IN ('prepared','completed','redacted')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK ((state='prepared' AND kind='checkout' AND context_json IS NOT NULL AND request_json IS NOT NULL
  AND proposal_json IS NOT NULL AND proposal_sha256 IS NOT NULL AND result_json IS NULL AND result_sha256 IS NULL)
 OR (state='completed' AND context_json IS NOT NULL AND request_json IS NOT NULL AND result_json IS NOT NULL
  AND result_sha256 IS NOT NULL AND ((kind='checkout' AND proposal_json IS NOT NULL AND proposal_sha256 IS NOT NULL)
   OR (kind<>'checkout' AND proposal_json IS NULL AND proposal_sha256 IS NULL)))
 OR (state='redacted' AND context_json IS NULL AND request_json IS NULL AND proposal_json IS NULL AND result_json IS NULL))
);
CREATE INDEX chat_commerce_operation_owner ON secureshop_review.chat_commerce_operations(target_id,shop_user_id);
CREATE FUNCTION secureshop_review.guard_chat_commerce() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,secureshop_review AS $$
BEGIN
 IF TG_OP='INSERT' THEN
  IF TG_TABLE_NAME='chat_commerce_choices' THEN
   IF NEW.state<>'active' THEN RAISE EXCEPTION 'Choice admission invalid'; END IF;
  END IF;
  IF TG_TABLE_NAME='chat_commerce_operations' THEN
   IF NEW.state='redacted' THEN RAISE EXCEPTION 'Operation admission invalid'; END IF;
  END IF;
  IF NOT EXISTS(SELECT 1 FROM secureshop_review.product_targets WHERE target_id=NEW.target_id AND lifecycle='active' FOR SHARE)
   THEN RAISE EXCEPTION 'Conversational commerce target unavailable'; END IF;
  RETURN NEW;
 END IF;
 IF TG_TABLE_NAME='practice_payment_methods' THEN
  IF TG_OP='DELETE' AND EXISTS(SELECT 1 FROM secureshop_review.product_targets WHERE target_id=OLD.target_id AND lifecycle='retired') THEN RETURN OLD; END IF;
  RAISE EXCEPTION 'Practice payment method immutable';
 END IF;
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Conversational commerce record immutable'; END IF;
 IF TG_TABLE_NAME='chat_commerce_operations' AND OLD.state='prepared' AND NEW.state='completed'
  AND (to_jsonb(OLD)-ARRAY['state','result_json','result_sha256'])=(to_jsonb(NEW)-ARRAY['state','result_json','result_sha256'])
  AND EXISTS(SELECT 1 FROM secureshop_review.product_targets WHERE target_id=NEW.target_id AND lifecycle='active' FOR SHARE)
  THEN RETURN NEW; END IF;
 IF NEW.state='redacted' AND OLD.state<>'redacted'
  AND EXISTS(SELECT 1 FROM secureshop_review.product_targets WHERE target_id=NEW.target_id AND lifecycle='retired') THEN
  IF TG_TABLE_NAME='chat_commerce_choices' THEN
   IF NEW.context_json IS NULL AND NEW.snapshot_json IS NULL
    AND (to_jsonb(OLD)-ARRAY['state','context_json','snapshot_json'])=(to_jsonb(NEW)-ARRAY['state','context_json','snapshot_json']) THEN RETURN NEW; END IF;
  ELSIF TG_TABLE_NAME='chat_commerce_operations' THEN
   IF NEW.context_json IS NULL AND NEW.request_json IS NULL AND NEW.proposal_json IS NULL AND NEW.result_json IS NULL
    AND (to_jsonb(OLD)-ARRAY['state','context_json','request_json','proposal_json','result_json'])=(to_jsonb(NEW)-ARRAY['state','context_json','request_json','proposal_json','result_json']) THEN RETURN NEW; END IF;
  END IF;
 END IF;
 RAISE EXCEPTION 'Conversational commerce record immutable';
END $$;
CREATE TRIGGER practice_payment_guard BEFORE INSERT OR UPDATE OR DELETE ON secureshop_review.practice_payment_methods
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_chat_commerce();
CREATE TRIGGER chat_choice_guard BEFORE INSERT OR UPDATE OR DELETE ON secureshop_review.chat_commerce_choices
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_chat_commerce();
CREATE TRIGGER chat_operation_guard BEFORE INSERT OR UPDATE OR DELETE ON secureshop_review.chat_commerce_operations
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_chat_commerce();
CREATE FUNCTION secureshop_review.retire_chat_commerce() RETURNS trigger LANGUAGE plpgsql
 SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
BEGIN
 IF NEW.lifecycle='retired' AND OLD.lifecycle IS DISTINCT FROM NEW.lifecycle THEN
  DELETE FROM secureshop_review.practice_payment_methods WHERE target_id=NEW.target_id;
  UPDATE secureshop_review.chat_commerce_choices SET state='redacted',context_json=NULL,snapshot_json=NULL
   WHERE target_id=NEW.target_id AND state<>'redacted';
  UPDATE secureshop_review.chat_commerce_operations SET state='redacted',context_json=NULL,request_json=NULL,proposal_json=NULL,result_json=NULL
   WHERE target_id=NEW.target_id AND state<>'redacted';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER retire_chat_commerce AFTER UPDATE OF lifecycle ON secureshop_review.product_targets
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.retire_chat_commerce();
REVOKE ALL ON secureshop_review.practice_payment_methods,secureshop_review.chat_commerce_choices,secureshop_review.chat_commerce_operations FROM PUBLIC;
GRANT SELECT,INSERT ON secureshop_review.practice_payment_methods,secureshop_review.chat_commerce_choices TO dvaia_secureshop_review_runtime;
GRANT SELECT,INSERT,UPDATE ON secureshop_review.chat_commerce_operations TO dvaia_secureshop_review_runtime;
REVOKE ALL ON FUNCTION secureshop_review.guard_chat_commerce(),secureshop_review.retire_chat_commerce() FROM PUBLIC,dvaia_secureshop_review_runtime;
