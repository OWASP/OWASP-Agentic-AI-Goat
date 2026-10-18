CREATE SCHEMA mcp;
REVOKE ALL ON SCHEMA mcp FROM PUBLIC;
CREATE TABLE mcp.progress (
 user_key text NOT NULL, objective_id text NOT NULL, completed integer NOT NULL DEFAULT 1 CHECK(completed IN (0,1)),
 completed_at timestamptz NOT NULL DEFAULT now(), created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(user_key,objective_id)
);
CREATE TABLE mcp.tool_log (
 id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, user_key text NOT NULL, tool_name text NOT NULL,
 args text, result_summary text, outcome text, success integer NOT NULL DEFAULT 1 CHECK(success IN (0,1)), created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX tool_log_owner ON mcp.tool_log(user_key,id DESC);
GRANT USAGE ON SCHEMA mcp TO dvaia_mcp_runtime;
GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA mcp TO dvaia_mcp_runtime;
GRANT USAGE,SELECT ON ALL SEQUENCES IN SCHEMA mcp TO dvaia_mcp_runtime;
