-- RESERVED IDENTITY 0053, DRAFT ONLY. Not discovered by application startup.
-- Requires the qualified but separately unregistered 0050-0052 prefix.
CREATE TABLE graph_runtime.codebot_requests (
 owner_key text NOT NULL REFERENCES graph_runtime.owners(owner_key),
 request_key_sha256 text NOT NULL CHECK(request_key_sha256 ~ '^[a-f0-9]{64}$'),
 request_fingerprint_sha256 text NOT NULL CHECK(request_fingerprint_sha256 ~ '^[a-f0-9]{64}$'),
 user_id integer NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
 platform_session_id integer NOT NULL REFERENCES identity.user_sessions(id) ON DELETE CASCADE,
 generation bigint NOT NULL CHECK(generation >= 0),
 run_id uuid NOT NULL UNIQUE REFERENCES graph_runtime.runs(run_id),
 status text NOT NULL CHECK(status IN ('started','completed','uncertain')),
 response_json jsonb,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(owner_key,request_key_sha256),
 CHECK((status='completed')=(response_json IS NOT NULL)),
 CHECK(response_json IS NULL OR (jsonb_typeof(response_json)='object' AND octet_length(response_json::text)<=262144))
);
CREATE INDEX codebot_requests_session ON graph_runtime.codebot_requests(platform_session_id,created_at DESC);
GRANT SELECT,INSERT ON graph_runtime.codebot_requests TO dvaia_identity_runtime;
GRANT UPDATE(status,response_json,updated_at) ON graph_runtime.codebot_requests TO dvaia_identity_runtime;
REVOKE ALL ON graph_runtime.codebot_requests FROM PUBLIC;

