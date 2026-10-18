-- Separate bootstrap stream: never add entries to dvaia_migrations.ledger.
CREATE TABLE dvaia_maintenance.control (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 version integer NOT NULL CHECK(version=1),
 installation_id uuid NOT NULL,
 database_oid oid NOT NULL,
 epoch bigint NOT NULL CHECK(epoch>0),
 state text NOT NULL CHECK(state IN ('dirty','clean')),
 operation_id uuid NOT NULL,
 owner_host_sha256 text NOT NULL CHECK(owner_host_sha256 ~ '^[a-f0-9]{64}$'),
 begun_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 finished_at timestamptz,
 CHECK((state='dirty' AND finished_at IS NULL) OR (state='clean' AND finished_at IS NOT NULL))
);
CREATE TABLE dvaia_maintenance.epochs (
 epoch bigint PRIMARY KEY,
 operation_id uuid NOT NULL UNIQUE,
 owner_host_sha256 text NOT NULL CHECK(owner_host_sha256 ~ '^[a-f0-9]{64}$'),
 begun_at timestamptz NOT NULL,
 finished_at timestamptz
);
REVOKE ALL ON SCHEMA dvaia_maintenance FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA dvaia_maintenance FROM PUBLIC;
GRANT USAGE ON SCHEMA dvaia_maintenance TO dvaia_identity_runtime;
GRANT SELECT ON dvaia_maintenance.control,dvaia_maintenance.ledger TO dvaia_identity_runtime;
