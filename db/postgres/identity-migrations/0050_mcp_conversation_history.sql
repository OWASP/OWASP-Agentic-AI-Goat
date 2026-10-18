-- RESERVED IDENTITY 0050, DRAFT ONLY. Not discovered by application startup migrations.
-- Promote only after copied normal-loader/replay qualification; do not edit prior migration bytes.
CREATE SCHEMA workshop_conversations;
CREATE TABLE workshop_conversations.turns (
 run_id uuid PRIMARY KEY REFERENCES graph_runtime.runs(run_id),
 user_id integer NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
 owner_key text NOT NULL REFERENCES graph_runtime.owners(owner_key),
 generation bigint NOT NULL CHECK(generation>=0),
 user_text text NOT NULL CHECK(octet_length(user_text) BETWEEN 1 AND 16384),
 assistant_text text NOT NULL CHECK(octet_length(assistant_text) BETWEEN 1 AND 32768),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX conversation_owner_generation ON workshop_conversations.turns(owner_key,generation,created_at,run_id);
GRANT USAGE ON SCHEMA workshop_conversations TO dvaia_identity_runtime;
GRANT SELECT,INSERT ON workshop_conversations.turns TO dvaia_identity_runtime;

CREATE TABLE workshop_conversations.requests (
 user_id integer NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
 request_id uuid NOT NULL,
 owner_key text NOT NULL REFERENCES graph_runtime.owners(owner_key),
 generation bigint NOT NULL CHECK(generation>=0),
 run_id uuid NOT NULL UNIQUE REFERENCES graph_runtime.runs(run_id),
 user_text text CHECK(user_text IS NULL OR octet_length(user_text) BETWEEN 1 AND 16384),
 response_json jsonb CHECK(response_json IS NULL OR (jsonb_typeof(response_json)='object' AND octet_length(response_json::text)<=131072)),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(user_id,request_id)
);
GRANT SELECT,INSERT ON workshop_conversations.requests TO dvaia_identity_runtime;
GRANT UPDATE(user_text,response_json) ON workshop_conversations.requests TO dvaia_identity_runtime;
GRANT DELETE ON workshop_conversations.turns TO dvaia_identity_runtime;
