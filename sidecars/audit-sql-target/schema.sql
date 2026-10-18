-- Service-private control database only. Never apply to an application store.
CREATE TABLE IF NOT EXISTS owned_audit_targets (
 binding_sha256 text PRIMARY KEY CHECK(binding_sha256 ~ '^[a-f0-9]{64}$'),
 target text NOT NULL UNIQUE CHECK(target ~ '^audit_[a-f0-9]{32}$'),
 receipt jsonb NOT NULL,
 state text NOT NULL CHECK(state IN ('pending','ready','retiring','retired')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE IF NOT EXISTS owned_audit_credentials (
 target text PRIMARY KEY REFERENCES owned_audit_targets(target),
 password text NOT NULL
);
REVOKE ALL ON owned_audit_targets,owned_audit_credentials FROM PUBLIC;
