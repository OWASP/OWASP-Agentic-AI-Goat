ALTER TABLE owned_audit_queries ADD COLUMN retired_result_sha256 text CHECK(retired_result_sha256 ~ '^[a-f0-9]{64}$');
ALTER TABLE owned_audit_queries DROP CONSTRAINT owned_audit_queries_state_check;
ALTER TABLE owned_audit_queries ADD CHECK(state IN ('pending','completed','redacted'));
ALTER TABLE owned_audit_queries DROP CONSTRAINT owned_audit_queries_check;
ALTER TABLE owned_audit_queries ADD CHECK((state='pending' AND receipt IS NULL AND retired_result_sha256 IS NULL) OR (state='completed' AND receipt IS NOT NULL AND retired_result_sha256 IS NULL) OR (state='redacted' AND receipt IS NULL));
CREATE OR REPLACE FUNCTION immutable_owned_audit_query() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Immutable owned query identity'; END IF;
 IF ROW(NEW.target,NEW.operation_id,NEW.request_sha256,NEW.created_at) IS DISTINCT FROM ROW(OLD.target,OLD.operation_id,OLD.request_sha256,OLD.created_at) THEN RAISE EXCEPTION 'Immutable owned query identity'; END IF;
 IF OLD.state='pending' AND NEW.state='completed' AND NEW.retired_result_sha256 IS NULL THEN RETURN NEW; END IF;
 IF OLD.state IN ('pending','completed') AND NEW.state='redacted' AND NEW.receipt IS NULL
 AND NEW.retired_result_sha256 IS NOT DISTINCT FROM OLD.receipt->>'resultSha256'
 AND EXISTS(SELECT 1 FROM owned_audit_targets WHERE target=OLD.target AND state='retired') THEN RETURN NEW; END IF;
 RAISE EXCEPTION 'Immutable owned query receipt';
END $$;
REVOKE ALL ON FUNCTION immutable_owned_audit_query() FROM PUBLIC;
