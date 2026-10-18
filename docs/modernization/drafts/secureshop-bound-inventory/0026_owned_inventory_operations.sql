-- REVIEW0026 candidate: immutable stock read/write receipts, retired content redaction.
CREATE TABLE secureshop_review.owned_inventory_operations (
 operation_id uuid PRIMARY KEY,
 target_id uuid NOT NULL REFERENCES secureshop_review.product_targets(target_id),
 shop_user_id integer NOT NULL CHECK(shop_user_id>0),
 persona_session_id uuid NOT NULL,
 authority_version bigint NOT NULL CHECK(authority_version>0),
 mode text NOT NULL CHECK(mode IN ('vuln','fixed')),
 action text NOT NULL CHECK(action IN ('stock_levels','reorder_suggestion','set_stock')),
 run_id uuid, request_id uuid, call_id text,
 request_sha256 text NOT NULL CHECK(request_sha256 ~ '^[a-f0-9]{64}$'),
 request_json text,
 state text NOT NULL DEFAULT 'admitted' CHECK(state IN ('admitted','completed','redacted')),
 result_sha256 text CHECK(result_sha256 ~ '^[a-f0-9]{64}$'), result_json text,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK((run_id IS NULL AND request_id IS NULL AND call_id IS NULL) OR (run_id IS NOT NULL AND request_id IS NOT NULL AND call_id IS NOT NULL AND octet_length(call_id) BETWEEN 1 AND 128)),
 CHECK(request_json IS NULL OR octet_length(request_json)<=16384),
 CHECK(result_json IS NULL OR octet_length(result_json)<=131072),
 CHECK((state='admitted' AND request_json IS NOT NULL AND result_json IS NULL AND result_sha256 IS NULL)
  OR (state='completed' AND request_json IS NOT NULL AND result_json IS NOT NULL AND result_sha256 IS NOT NULL)
  OR (state='redacted' AND request_json IS NULL AND result_json IS NULL))
);
CREATE INDEX owned_inventory_scope ON secureshop_review.owned_inventory_operations(target_id,shop_user_id,created_at);
CREATE FUNCTION secureshop_review.guard_owned_inventory_operation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Inventory receipt immutable'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'admitted' OR NOT EXISTS(SELECT 1 FROM secureshop_review.product_targets WHERE target_id=NEW.target_id AND lifecycle='active' FOR SHARE) THEN RAISE EXCEPTION 'Inventory target unavailable'; END IF;
  RETURN NEW;
 END IF;
 IF (to_jsonb(NEW)-ARRAY['state','request_json','result_json','result_sha256']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['state','request_json','result_json','result_sha256']) THEN RAISE EXCEPTION 'Inventory binding immutable'; END IF;
 IF OLD.state='admitted' AND NEW.state='completed' AND NEW.request_json=OLD.request_json AND EXISTS(SELECT 1 FROM secureshop_review.product_targets WHERE target_id=NEW.target_id AND lifecycle='active' FOR SHARE) THEN RETURN NEW; END IF;
 IF OLD.state IN ('admitted','completed') AND NEW.state='redacted' AND NEW.request_json IS NULL AND NEW.result_json IS NULL AND NEW.result_sha256 IS NOT DISTINCT FROM OLD.result_sha256 AND EXISTS(SELECT 1 FROM secureshop_review.product_targets WHERE target_id=NEW.target_id AND lifecycle='retired') THEN RETURN NEW; END IF;
 RAISE EXCEPTION 'Inventory transition unavailable';
END $$;
CREATE TRIGGER owned_inventory_operation_guard BEFORE INSERT OR UPDATE OR DELETE ON secureshop_review.owned_inventory_operations FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_owned_inventory_operation();
CREATE FUNCTION secureshop_review.retire_owned_inventory_operations() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
BEGIN
 IF NEW.lifecycle='retired' AND OLD.lifecycle IS DISTINCT FROM NEW.lifecycle THEN
  UPDATE secureshop_review.owned_inventory_operations SET state='redacted',request_json=NULL,result_json=NULL WHERE target_id=NEW.target_id AND state<>'redacted';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER retire_owned_inventory_operations AFTER UPDATE OF lifecycle ON secureshop_review.product_targets FOR EACH ROW EXECUTE FUNCTION secureshop_review.retire_owned_inventory_operations();
REVOKE ALL ON secureshop_review.owned_inventory_operations FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON secureshop_review.owned_inventory_operations TO dvaia_secureshop_review_runtime;
REVOKE ALL ON FUNCTION secureshop_review.guard_owned_inventory_operation(),secureshop_review.retire_owned_inventory_operations() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.guard_owned_inventory_operation(),secureshop_review.retire_owned_inventory_operations() TO dvaia_secureshop_review_runtime;
