-- A guest-cart import is one atomic cart effect. The receipt survives a lost HTTP
-- response, while target retirement redacts its teaching content.
CREATE TABLE secureshop_review.guest_cart_imports (
 request_id uuid PRIMARY KEY,
 target_id uuid NOT NULL REFERENCES secureshop_review.product_targets(target_id),
 shop_user_id integer NOT NULL CHECK (shop_user_id > 0),
 intent_sha256 text NOT NULL CHECK (intent_sha256 ~ '^[a-f0-9]{64}$'),
 execution_json text CHECK (execution_json IS NULL OR octet_length(execution_json) <= 4096),
 request_json text CHECK (request_json IS NULL OR octet_length(request_json) <= 8192),
 result_json text CHECK (result_json IS NULL OR octet_length(result_json) <= 2097152),
 result_sha256 text NOT NULL CHECK (result_sha256 ~ '^[a-f0-9]{64}$'),
 state text NOT NULL DEFAULT 'completed' CHECK (state IN ('completed','redacted')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CHECK ((state='completed' AND execution_json IS NOT NULL AND request_json IS NOT NULL AND result_json IS NOT NULL)
   OR (state='redacted' AND execution_json IS NULL AND request_json IS NULL AND result_json IS NULL))
);
CREATE INDEX guest_cart_import_scope ON secureshop_review.guest_cart_imports(target_id,shop_user_id,created_at);
CREATE FUNCTION secureshop_review.guard_guest_cart_import() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Guest cart import receipt immutable'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state <> 'completed' OR NOT EXISTS (SELECT 1 FROM secureshop_review.product_targets
      WHERE target_id=NEW.target_id AND lifecycle='active' FOR SHARE) THEN
   RAISE EXCEPTION 'Guest cart import target unavailable';
  END IF;
  RETURN NEW;
 END IF;
 IF OLD.state='completed' AND NEW.state='redacted'
   AND (to_jsonb(NEW)-ARRAY['state','execution_json','request_json','result_json'])
       = (to_jsonb(OLD)-ARRAY['state','execution_json','request_json','result_json'])
   AND NEW.execution_json IS NULL AND NEW.request_json IS NULL AND NEW.result_json IS NULL
   AND EXISTS (SELECT 1 FROM secureshop_review.product_targets
     WHERE target_id=NEW.target_id AND lifecycle='retired') THEN RETURN NEW; END IF;
 RAISE EXCEPTION 'Guest cart import receipt immutable';
END $$;
CREATE TRIGGER guest_cart_import_guard BEFORE INSERT OR UPDATE OR DELETE
 ON secureshop_review.guest_cart_imports FOR EACH ROW EXECUTE FUNCTION secureshop_review.guard_guest_cart_import();
CREATE FUNCTION secureshop_review.retire_guest_cart_imports() RETURNS trigger LANGUAGE plpgsql
 SECURITY DEFINER SET search_path=pg_catalog,secureshop_review AS $$
BEGIN
 IF NEW.lifecycle='retired' AND OLD.lifecycle IS DISTINCT FROM NEW.lifecycle THEN
  UPDATE secureshop_review.guest_cart_imports
   SET state='redacted',execution_json=NULL,request_json=NULL,result_json=NULL
   WHERE target_id=NEW.target_id AND state='completed';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER retire_guest_cart_imports AFTER UPDATE OF lifecycle ON secureshop_review.product_targets
 FOR EACH ROW EXECUTE FUNCTION secureshop_review.retire_guest_cart_imports();
REVOKE ALL ON secureshop_review.guest_cart_imports FROM PUBLIC;
GRANT SELECT,INSERT ON secureshop_review.guest_cart_imports TO dvaia_secureshop_review_runtime;
REVOKE ALL ON FUNCTION secureshop_review.guard_guest_cart_import(),secureshop_review.retire_guest_cart_imports() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_review.guard_guest_cart_import(),secureshop_review.retire_guest_cart_imports() TO dvaia_secureshop_review_runtime;
