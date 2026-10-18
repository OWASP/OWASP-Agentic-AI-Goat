CREATE TABLE owned_audit_queries (
 target text NOT NULL REFERENCES owned_audit_targets(target),
 operation_id uuid NOT NULL,
 request_sha256 text NOT NULL CHECK(request_sha256 ~ '^[a-f0-9]{64}$'),
 state text NOT NULL CHECK(state IN ('pending','completed')),
 receipt jsonb,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(target,operation_id),
 CHECK((state='pending' AND receipt IS NULL) OR (state='completed' AND receipt IS NOT NULL))
);
REVOKE ALL ON owned_audit_queries FROM PUBLIC;
CREATE FUNCTION immutable_owned_audit_query() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP <> 'UPDATE' OR OLD.state <> 'pending' OR NEW.state <> 'completed'
 OR NEW.target <> OLD.target OR NEW.operation_id <> OLD.operation_id
 OR NEW.request_sha256 <> OLD.request_sha256 OR NEW.created_at <> OLD.created_at
 THEN RAISE EXCEPTION 'Immutable owned query receipt'; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION immutable_owned_audit_query() FROM PUBLIC;
CREATE TRIGGER owned_audit_queries_immutable BEFORE UPDATE OR DELETE ON owned_audit_queries
 FOR EACH ROW EXECUTE FUNCTION immutable_owned_audit_query();
