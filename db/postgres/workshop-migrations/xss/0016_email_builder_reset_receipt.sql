CREATE TABLE xss.email_builder_reset_receipts (
 operation_id uuid PRIMARY KEY, owner_id integer NOT NULL,
 from_generation bigint NOT NULL CHECK(from_generation>=0),
 to_generation bigint NOT NULL CHECK(to_generation=from_generation+1),
 applied_at timestamptz NOT NULL DEFAULT now()
);
REVOKE ALL ON xss.email_builder_reset_receipts FROM PUBLIC,dvaia_xss_runtime;
GRANT SELECT ON xss.email_builder_reset_receipts TO dvaia_xss_runtime;
CREATE FUNCTION xss.clear_email_builder(p_operation uuid,p_owner integer,p_from bigint,p_to bigint)
RETURNS xss.email_builder_reset_receipts LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE prior xss.email_builder_reset_receipts%ROWTYPE;
BEGIN
 IF p_operation IS NULL OR p_owner IS NULL OR p_owner<1 OR p_from IS NULL OR p_from<0 OR p_to IS DISTINCT FROM p_from+1 THEN RAISE EXCEPTION 'Invalid builder cleanup scope'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended(p_owner::text,8012));
 IF EXISTS(SELECT 1 FROM xss.scoped_profile_reset_owner_deletions WHERE owner_id=p_owner) THEN RAISE EXCEPTION 'XSS owner deleted'; END IF;
 SELECT * INTO prior FROM xss.email_builder_reset_receipts WHERE operation_id=p_operation;
 IF FOUND THEN
  IF prior.owner_id<>p_owner OR prior.from_generation<>p_from OR prior.to_generation<>p_to THEN RAISE EXCEPTION 'Builder cleanup scope mismatch'; END IF;
  RETURN prior;
 END IF;
 DELETE FROM xss.email_templates WHERE user_id=p_owner;
 DELETE FROM xss.xss_challenge_progress WHERE user_id=p_owner;
 -- Profiles and immutable Judge receipts are intentionally retained.
 INSERT INTO xss.email_builder_reset_receipts(operation_id,owner_id,from_generation,to_generation)
 VALUES(p_operation,p_owner,p_from,p_to) RETURNING * INTO prior;
 RETURN prior;
END $$;
REVOKE ALL ON FUNCTION xss.clear_email_builder(uuid,integer,bigint,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION xss.clear_email_builder(uuid,integer,bigint,bigint) TO dvaia_xss_runtime;
-- Existing student destruction writes this permanent tombstone before clearing
-- owned data. New reset receipts follow that same deletion lifecycle.
CREATE FUNCTION xss.delete_email_builder_reset_receipts() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 DELETE FROM xss.email_builder_reset_receipts WHERE owner_id=NEW.owner_id;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION xss.delete_email_builder_reset_receipts() FROM PUBLIC,dvaia_xss_runtime;
CREATE TRIGGER email_builder_reset_receipt_owner_delete
 AFTER INSERT ON xss.scoped_profile_reset_owner_deletions
 FOR EACH ROW EXECUTE FUNCTION xss.delete_email_builder_reset_receipts();
