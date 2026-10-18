-- The combined platform import is the authority for source-user to target-user
-- ownership. Workshop importers verify this immutable record before applying
-- attendee-owned rows in their isolated databases.
CREATE TABLE identity.archive_owner_bindings (
  archive_sha256 text PRIMARY KEY CHECK (archive_sha256 ~ '^[a-f0-9]{64}$'),
  identity_map_sha256 text NOT NULL CHECK (identity_map_sha256 ~ '^[a-f0-9]{64}$'),
  identity_map jsonb NOT NULL CHECK (jsonb_typeof(identity_map) = 'object'),
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TRIGGER archive_owner_bindings_immutable
BEFORE UPDATE OR DELETE OR TRUNCATE ON identity.archive_owner_bindings
FOR EACH STATEMENT EXECUTE FUNCTION identity.reject_historical_provenance_mutation();

REVOKE ALL ON identity.archive_owner_bindings FROM PUBLIC,dvaia_identity_runtime;
GRANT SELECT ON identity.archive_owner_bindings TO dvaia_identity_runtime;
