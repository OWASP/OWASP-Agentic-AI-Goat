-- Parent-only, tenant-scoped credential reset of registered SecureShop actors.
-- Receipts retain immutable provenance; private recovery may only be destroyed.
CREATE TABLE secureshop_auth.registered_admin_reset_operations (
  operation_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES secureshop_auth.tenants(tenant_id),
  actor_principal_id uuid NOT NULL REFERENCES secureshop_auth.principals(principal_id),
  actor_auth_session_id integer NOT NULL REFERENCES secureshop_auth.sessions(session_id),
  actor_execution_session_id integer NOT NULL REFERENCES secureshop_auth.execution_sessions(session_id),
  actor_membership_version bigint NOT NULL CHECK (actor_membership_version > 0),
  actor_authority_version bigint NOT NULL CHECK (actor_authority_version > 0),
  target_principal_id uuid NOT NULL REFERENCES secureshop_auth.principals(principal_id),
  target_shop_user_id integer NOT NULL REFERENCES secureshop_auth.principals(shop_user_id),
  request_sha256 bytea NOT NULL CHECK (octet_length(request_sha256) = 32),
  receipt_json jsonb NOT NULL CHECK (jsonb_typeof(receipt_json) = 'object'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (actor_principal_id <> target_principal_id)
);
CREATE INDEX registered_admin_reset_actor ON secureshop_auth.registered_admin_reset_operations
  (actor_principal_id, created_at DESC);
CREATE INDEX registered_admin_reset_target ON secureshop_auth.registered_admin_reset_operations
  (target_principal_id, created_at DESC);

CREATE TABLE secureshop_auth.registered_admin_reset_recovery (
  operation_id uuid PRIMARY KEY REFERENCES secureshop_auth.registered_admin_reset_operations(operation_id),
  envelope_json jsonb CHECK (envelope_json IS NULL OR jsonb_typeof(envelope_json) = 'object'),
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE FUNCTION secureshop_auth.guard_registered_admin_reset() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,secureshop_auth AS $$
BEGIN
  IF TG_OP = 'DELETE' OR TG_TABLE_NAME = 'registered_admin_reset_operations' THEN
    RAISE EXCEPTION 'Registered reset receipt is immutable' USING ERRCODE='55000';
  END IF;
  IF TG_OP = 'UPDATE' THEN
    IF OLD.envelope_json IS NULL OR NEW.envelope_json IS NOT NULL
       OR (NEW.operation_id,NEW.expires_at,NEW.created_at) IS DISTINCT FROM
          (OLD.operation_id,OLD.expires_at,OLD.created_at) THEN
      RAISE EXCEPTION 'Registered reset recovery may only be acknowledged' USING ERRCODE='55000';
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER registered_admin_reset_operation_guard BEFORE UPDATE OR DELETE
  ON secureshop_auth.registered_admin_reset_operations FOR EACH ROW
  EXECUTE FUNCTION secureshop_auth.guard_registered_admin_reset();
CREATE TRIGGER registered_admin_reset_recovery_guard BEFORE UPDATE OR DELETE
  ON secureshop_auth.registered_admin_reset_recovery FOR EACH ROW
  EXECUTE FUNCTION secureshop_auth.guard_registered_admin_reset();

REVOKE ALL ON secureshop_auth.registered_admin_reset_operations,
  secureshop_auth.registered_admin_reset_recovery FROM PUBLIC;
REVOKE ALL ON FUNCTION secureshop_auth.guard_registered_admin_reset() FROM PUBLIC;
GRANT SELECT, INSERT ON secureshop_auth.registered_admin_reset_operations TO dvaia_identity_runtime;
GRANT SELECT, INSERT ON secureshop_auth.registered_admin_reset_recovery TO dvaia_identity_runtime;
GRANT UPDATE(envelope_json) ON secureshop_auth.registered_admin_reset_recovery TO dvaia_identity_runtime;
