-- Record an owned target before any external provisioning can begin. A row is
-- an unresolved cleanup obligation, never proof that provisioning or cleanup
-- happened. No runtime deletion or completion setter is granted here.
CREATE TABLE identity.secureshop_target_reservations (
  target_id uuid PRIMARY KEY,
  launch_id uuid NOT NULL REFERENCES identity.secureshop_launches(launch_id) ON DELETE RESTRICT,
  generation bigint NOT NULL CHECK (generation BETWEEN 1 AND 9007199254740991),
  target_kind text NOT NULL CHECK (target_kind IN ('files')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  UNIQUE (launch_id, generation, target_kind)
);

CREATE INDEX secureshop_target_reservations_launch ON identity.secureshop_target_reservations(launch_id);

GRANT SELECT, INSERT ON identity.secureshop_target_reservations TO dvaia_identity_runtime;
