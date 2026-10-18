-- Candidate only: graph-mediated SQLi query evidence, not direct web admission.
CREATE TABLE identity.secureshop_audit_query_operations (
 operation_id uuid PRIMARY KEY,
 user_id integer REFERENCES identity.users(id) ON DELETE SET NULL,
 original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id>0),
 launch_id uuid NOT NULL REFERENCES identity.secureshop_launches(launch_id),
 run_id uuid NOT NULL REFERENCES graph_runtime.runs(run_id),
 request_sha256 text NOT NULL CHECK(request_sha256 ~ '^[a-f0-9]{64}$'),
 request_json jsonb NOT NULL CHECK(octet_length(request_json::text)<=32768),
 receipt_sha256 text CHECK(receipt_sha256 ~ '^[a-f0-9]{64}$'),
 receipt_json jsonb CHECK(octet_length(receipt_json::text)<=18000000),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 completed_at timestamptz,
 CHECK((receipt_json IS NULL)=(receipt_sha256 IS NULL)),
 CHECK((receipt_json IS NULL)=(completed_at IS NULL))
);
CREATE FUNCTION identity.guard_secureshop_audit_query_operation() RETURNS trigger LANGUAGE plpgsql
 SET search_path=pg_catalog AS $$
BEGIN
 IF OLD.user_id IS NOT NULL AND NEW.user_id IS NULL AND NOT EXISTS(SELECT 1 FROM identity.users WHERE id=OLD.user_id) AND (to_jsonb(NEW)-'user_id')=(to_jsonb(OLD)-'user_id') THEN RETURN NEW; END IF;
 IF ROW(NEW.operation_id,NEW.user_id,NEW.original_platform_owner_id,NEW.launch_id,NEW.run_id,NEW.request_sha256,NEW.request_json,NEW.created_at)
 IS DISTINCT FROM ROW(OLD.operation_id,OLD.user_id,OLD.original_platform_owner_id,OLD.launch_id,OLD.run_id,OLD.request_sha256,OLD.request_json,OLD.created_at)
 OR OLD.receipt_json IS NOT NULL OR NEW.receipt_json IS NULL THEN
 RAISE EXCEPTION 'Immutable audit query operation' USING ERRCODE='42501'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER secureshop_audit_query_immutable BEFORE UPDATE ON identity.secureshop_audit_query_operations
 FOR EACH ROW EXECUTE FUNCTION identity.guard_secureshop_audit_query_operation();
REVOKE ALL ON identity.secureshop_audit_query_operations FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.guard_secureshop_audit_query_operation() FROM PUBLIC;
GRANT SELECT,INSERT ON identity.secureshop_audit_query_operations TO dvaia_identity_runtime;
GRANT UPDATE(receipt_json,receipt_sha256,completed_at) ON identity.secureshop_audit_query_operations TO dvaia_identity_runtime;

-- Direct authenticated admin actions have no graph identity or model provenance.
CREATE TABLE identity.secureshop_audit_manual_operations (
 operation_id uuid PRIMARY KEY,
 user_id integer REFERENCES identity.users(id) ON DELETE SET NULL,
 original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id>0),
 launch_id uuid NOT NULL REFERENCES identity.secureshop_launches(launch_id),
 request_sha256 text NOT NULL CHECK(request_sha256 ~ '^[a-f0-9]{64}$'),
 request_json jsonb NOT NULL CHECK(octet_length(request_json::text)<=32768),
 receipt_sha256 text CHECK(receipt_sha256 ~ '^[a-f0-9]{64}$'),
 receipt_json jsonb CHECK(octet_length(receipt_json::text)<=18000000),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),completed_at timestamptz,
 CHECK((receipt_json IS NULL)=(receipt_sha256 IS NULL)),CHECK((receipt_json IS NULL)=(completed_at IS NULL))
);
CREATE FUNCTION identity.guard_secureshop_audit_manual_operation() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF OLD.user_id IS NOT NULL AND NEW.user_id IS NULL AND NOT EXISTS(SELECT 1 FROM identity.users WHERE id=OLD.user_id) AND (to_jsonb(NEW)-'user_id')=(to_jsonb(OLD)-'user_id') THEN RETURN NEW; END IF;
 IF (to_jsonb(NEW)-ARRAY['receipt_json','receipt_sha256','completed_at']) IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['receipt_json','receipt_sha256','completed_at']) OR OLD.receipt_json IS NOT NULL OR NEW.receipt_json IS NULL THEN RAISE EXCEPTION 'Immutable manual audit operation' USING ERRCODE='42501'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER secureshop_audit_manual_immutable BEFORE UPDATE ON identity.secureshop_audit_manual_operations FOR EACH ROW EXECUTE FUNCTION identity.guard_secureshop_audit_manual_operation();
REVOKE ALL ON identity.secureshop_audit_manual_operations FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.guard_secureshop_audit_manual_operation() FROM PUBLIC;
GRANT SELECT,INSERT ON identity.secureshop_audit_manual_operations TO dvaia_identity_runtime;
GRANT UPDATE(receipt_json,receipt_sha256,completed_at) ON identity.secureshop_audit_manual_operations TO dvaia_identity_runtime;
