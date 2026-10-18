ALTER TABLE legacy_challenge.comments ADD COLUMN platform_owner_id integer CHECK(platform_owner_id IS NULL OR platform_owner_id>0);
ALTER TABLE legacy_challenge.reviews ADD COLUMN platform_owner_id integer CHECK(platform_owner_id IS NULL OR platform_owner_id>0);
ALTER TABLE legacy_challenge.cart ADD COLUMN platform_owner_id integer CHECK(platform_owner_id IS NULL OR platform_owner_id>0);
ALTER TABLE legacy_challenge.orders ADD COLUMN platform_owner_id integer CHECK(platform_owner_id IS NULL OR platform_owner_id>0);
ALTER TABLE legacy_challenge.ai_conversations ADD COLUMN platform_owner_id integer CHECK(platform_owner_id IS NULL OR platform_owner_id>0);
ALTER TABLE legacy_challenge.files ADD COLUMN platform_owner_id integer;
ALTER TABLE legacy_challenge.files ADD COLUMN upload_intent_id uuid;
ALTER TABLE legacy_challenge.files ADD CONSTRAINT files_platform_upload_scope_ck CHECK (
 (platform_owner_id IS NULL AND upload_intent_id IS NULL)
 OR (platform_owner_id IS NOT NULL AND platform_owner_id > 0 AND upload_intent_id IS NOT NULL));
CREATE UNIQUE INDEX files_upload_intent_uq ON legacy_challenge.files(upload_intent_id) WHERE upload_intent_id IS NOT NULL;

CREATE FUNCTION legacy_challenge.destroy_student_owner(requested_owner integer, requested_intents uuid[])
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE removed integer := 0; changed integer;
BEGIN
 IF requested_owner IS NULL OR requested_owner < 1 OR requested_intents IS NULL OR cardinality(requested_intents)>1000
   THEN RAISE EXCEPTION 'Valid deletion owner and intent scope required'; END IF;
 LOCK TABLE legacy_challenge.files IN SHARE ROW EXCLUSIVE MODE;
 -- Classic shop user_id values belong to the intentionally weak local shop
 -- identity and may numerically collide with a platform account. Only the
 -- authenticated durable-upload path records platform ownership, and the
 -- identity store supplies its immutable admitted intent IDs for deletion.
 DELETE FROM legacy_challenge.order_items item USING legacy_challenge.orders owned
   WHERE item.order_id=owned.id AND owned.platform_owner_id=requested_owner;
 GET DIAGNOSTICS changed=ROW_COUNT; removed:=removed+changed;
 DELETE FROM legacy_challenge.orders WHERE platform_owner_id=requested_owner;
 GET DIAGNOSTICS changed=ROW_COUNT; removed:=removed+changed;
 DELETE FROM legacy_challenge.cart WHERE platform_owner_id=requested_owner;
 GET DIAGNOSTICS changed=ROW_COUNT; removed:=removed+changed;
 DELETE FROM legacy_challenge.reviews WHERE platform_owner_id=requested_owner;
 GET DIAGNOSTICS changed=ROW_COUNT; removed:=removed+changed;
 DELETE FROM legacy_challenge.comments WHERE platform_owner_id=requested_owner;
 GET DIAGNOSTICS changed=ROW_COUNT; removed:=removed+changed;
 DELETE FROM legacy_challenge.ai_conversations WHERE platform_owner_id=requested_owner;
 GET DIAGNOSTICS changed=ROW_COUNT; removed:=removed+changed;
 DELETE FROM legacy_challenge.files
 WHERE platform_owner_id=requested_owner AND upload_intent_id=ANY(requested_intents);
 GET DIAGNOSTICS changed=ROW_COUNT; removed:=removed+changed;
 RETURN removed;
END $$;
REVOKE ALL ON FUNCTION legacy_challenge.destroy_student_owner(integer,uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION legacy_challenge.destroy_student_owner(integer,uuid[]) TO dvaia_legacy_challenge_runtime;
