-- A UUID cannot authorize both a teaching-persona and a registered-account
-- mutation. This reservation is durable even when the other store's outcome
-- is unknown; the original journals remain the only completion receipts.
CREATE TABLE secureshop_auth.admin_operation_kinds (
 launch_id uuid NOT NULL REFERENCES identity.secureshop_launches(launch_id),
 generation bigint NOT NULL CHECK(generation>0),operation_id uuid NOT NULL,
 scenario_id uuid NOT NULL,owner_id integer NOT NULL CHECK(owner_id>0),
 execution_session_id integer NOT NULL CHECK(execution_session_id>0),
 operation_kind text NOT NULL CHECK(operation_kind IN ('registered','teaching')),
 actor_id integer NOT NULL CHECK(actor_id>0),target_id integer NOT NULL CHECK(target_id>0),
 request_sha256 bytea NOT NULL CHECK(octet_length(request_sha256)=32),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(launch_id,generation,operation_id)
);
CREATE TRIGGER shop_admin_operation_kind_history BEFORE UPDATE OR DELETE ON secureshop_auth.admin_operation_kinds
 FOR EACH ROW EXECUTE FUNCTION secureshop_auth.guard_tenant_admin_history();
REVOKE ALL ON secureshop_auth.admin_operation_kinds FROM PUBLIC;
GRANT SELECT,INSERT ON secureshop_auth.admin_operation_kinds TO dvaia_identity_runtime;
