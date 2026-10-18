-- Runtime records intentionally contain node/status metadata, never raw prompts,
-- tool results, credentials or automatic replay payloads.
CREATE SCHEMA graph_runtime;
CREATE TABLE graph_runtime.owners (
 owner_key text PRIMARY KEY,
 generation bigint NOT NULL DEFAULT 0 CHECK(generation >= 0),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE graph_runtime.runs (
 run_id uuid PRIMARY KEY,
 owner_key text NOT NULL REFERENCES graph_runtime.owners(owner_key),
 generation bigint NOT NULL,
 status text NOT NULL CHECK(status IN ('running','completed','failed','cancelled','interrupted')),
 last_node text,
 started_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 finished_at timestamptz
);
CREATE INDEX graph_runtime_runs_owner ON graph_runtime.runs(owner_key,started_at DESC);
CREATE TABLE graph_runtime.effects (
 owner_key text NOT NULL REFERENCES graph_runtime.owners(owner_key),
 generation bigint NOT NULL,
 effect_key text NOT NULL,
 run_id uuid NOT NULL REFERENCES graph_runtime.runs(run_id),
 status text NOT NULL CHECK(status IN ('started','completed','uncertain')),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(owner_key,generation,effect_key)
);
GRANT USAGE ON SCHEMA graph_runtime TO dvaia_identity_runtime;
GRANT SELECT,INSERT,UPDATE ON ALL TABLES IN SCHEMA graph_runtime TO dvaia_identity_runtime;
