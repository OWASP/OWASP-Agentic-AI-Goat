-- Candidate for a dedicated synthetic service control database only.
-- Never apply this to an application store. Native qualification is pending.
CREATE TABLE owned_analytics_targets (
 binding_sha256 text PRIMARY KEY CHECK(binding_sha256 ~ '^[a-f0-9]{64}$'),
 target_id uuid NOT NULL UNIQUE,
 scope jsonb NOT NULL CHECK(jsonb_typeof(scope)='object'),
 source_manifest_sha256 text NOT NULL CHECK(source_manifest_sha256 ~ '^[a-f0-9]{64}$'),
 state text NOT NULL CHECK(state IN ('pending','ready','retiring','retired')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE owned_analytics_credentials (
 target_id uuid PRIMARY KEY REFERENCES owned_analytics_targets(target_id),
 password text NOT NULL CHECK(length(password)=64)
);
CREATE TABLE owned_analytics_queries (
 target_id uuid NOT NULL REFERENCES owned_analytics_targets(target_id),
 operation_id uuid NOT NULL,
 request_sha256 text NOT NULL CHECK(request_sha256 ~ '^[a-f0-9]{64}$'),
 state text NOT NULL CHECK(state IN ('pending','completed','redacted')),
 receipt jsonb,
 result_sha256 text CHECK(result_sha256 ~ '^[a-f0-9]{64}$'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(target_id,operation_id),
 CHECK((state='pending' AND receipt IS NULL AND result_sha256 IS NULL)
    OR (state='completed' AND receipt IS NOT NULL AND result_sha256 IS NOT NULL)
    OR (state='redacted' AND receipt IS NULL AND result_sha256 IS NOT NULL))
);
CREATE FUNCTION guard_owned_analytics_query() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Query receipt is immutable'; END IF;
 IF NEW.target_id<>OLD.target_id OR NEW.operation_id<>OLD.operation_id OR NEW.request_sha256<>OLD.request_sha256
  OR NEW.created_at<>OLD.created_at THEN RAISE EXCEPTION 'Query binding is immutable'; END IF;
 IF OLD.state='pending' AND NEW.state='completed' THEN RETURN NEW; END IF;
 IF OLD.state='completed' AND NEW.state='redacted' AND NEW.result_sha256=OLD.result_sha256
  AND EXISTS(SELECT 1 FROM owned_analytics_targets t WHERE t.target_id=OLD.target_id AND t.state='retired') THEN RETURN NEW; END IF;
 RAISE EXCEPTION 'Query receipt is immutable';
END $$;
CREATE TRIGGER owned_analytics_query_immutable BEFORE UPDATE OR DELETE ON owned_analytics_queries
 FOR EACH ROW EXECUTE FUNCTION guard_owned_analytics_query();
REVOKE ALL ON owned_analytics_targets,owned_analytics_credentials,owned_analytics_queries FROM PUBLIC;
REVOKE ALL ON FUNCTION guard_owned_analytics_query() FROM PUBLIC;
CREATE FUNCTION guard_owned_analytics_target() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'Target tombstone is immutable'; END IF;
 IF NEW.binding_sha256<>OLD.binding_sha256 OR NEW.target_id<>OLD.target_id OR NEW.scope<>OLD.scope
  OR NEW.source_manifest_sha256<>OLD.source_manifest_sha256 OR NEW.created_at<>OLD.created_at
  THEN RAISE EXCEPTION 'Target binding is immutable'; END IF;
 IF (OLD.state='pending' AND NEW.state IN ('ready','retiring'))
  OR (OLD.state='ready' AND NEW.state='retiring') OR (OLD.state='retiring' AND NEW.state='retired') THEN RETURN NEW; END IF;
 RAISE EXCEPTION 'Invalid target lifecycle transition';
END $$;
CREATE TRIGGER owned_analytics_target_immutable BEFORE UPDATE OR DELETE ON owned_analytics_targets
 FOR EACH ROW EXECUTE FUNCTION guard_owned_analytics_target();
REVOKE ALL ON FUNCTION guard_owned_analytics_target() FROM PUBLIC;
