-- Historical conversations are retained byte-for-byte for the attested operator
-- snapshot/quarantine/cutover. Their mutable owner column is not an ownership
-- attestation. No runtime teaching query or deletion helper may access them.
REVOKE ALL ON TABLE legacy_challenge.ai_conversations FROM PUBLIC,dvaia_legacy_challenge_runtime;
REVOKE ALL (id,user_id,prompt,response,model_used,created_at,platform_owner_id)
 ON TABLE legacy_challenge.ai_conversations FROM PUBLIC,dvaia_legacy_challenge_runtime;
REVOKE ALL ON SEQUENCE legacy_challenge.ai_conversations_id_seq FROM PUBLIC,dvaia_legacy_challenge_runtime;

-- Explicitly fictional read-only records preserve the SQL injection and missing
-- authorization lessons without mixing platform submissions into teaching data.
CREATE TABLE legacy_challenge.synthetic_ai_conversations (
 id integer PRIMARY KEY,
 user_id integer,
 username text NOT NULL,
 prompt text NOT NULL,
 response text,
 model_used text,
 created_at timestamptz,
 platform_owner_id integer CHECK(platform_owner_id IS NULL)
);
INSERT INTO legacy_challenge.synthetic_ai_conversations
 (id,user_id,username,prompt,response,model_used,created_at) VALUES
 (1,1,'synthetic-customer','Fictional learner Alice asks about the teaching store.','Synthetic teaching secret: DVAIA-DEMO-ALICE','synthetic-fixture','2026-01-01T00:00:00Z'),
 (2,2,'synthetic-support','Fictional learner Bob asks about the teaching store.','Synthetic teaching secret: DVAIA-DEMO-BOB','synthetic-fixture','2026-01-01T00:00:00Z');
REVOKE ALL ON TABLE legacy_challenge.synthetic_ai_conversations FROM PUBLIC,dvaia_legacy_challenge_runtime;
GRANT SELECT ON TABLE legacy_challenge.synthetic_ai_conversations TO dvaia_legacy_challenge_runtime;

-- Keep the existing deletion capability for other owned records. Historical
-- conversations require the separately authorized exact source cleanup; private
-- authenticated history is deleted by the identity finalizer.
CREATE OR REPLACE FUNCTION legacy_challenge.destroy_student_owner(requested_owner integer, requested_intents uuid[])
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
 DELETE FROM legacy_challenge.files
 WHERE platform_owner_id=requested_owner AND upload_intent_id=ANY(requested_intents);
 GET DIAGNOSTICS changed=ROW_COUNT; removed:=removed+changed;
 RETURN removed;
END $$;
REVOKE ALL ON FUNCTION legacy_challenge.destroy_student_owner(integer,uuid[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION legacy_challenge.destroy_student_owner(integer,uuid[]) TO dvaia_legacy_challenge_runtime;
