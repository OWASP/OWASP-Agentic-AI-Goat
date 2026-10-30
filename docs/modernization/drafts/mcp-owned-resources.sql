-- DRAFT ONLY. Do not add to the MCP migration loader before the identity-bound
-- repository, runner adapter, and populated/replay qualification are frozen.
CREATE TABLE mcp.runner_targets (
 target_id uuid PRIMARY KEY,
 user_key text NOT NULL CHECK(user_key ~ '^[1-9][0-9]{0,9}$'),
 platform_session_id bigint NOT NULL CHECK(platform_session_id > 0),
 generation bigint NOT NULL CHECK(generation >= 0),
 state text NOT NULL DEFAULT 'active' CHECK(state IN ('active','retiring','retired')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 retired_at timestamptz,
 CHECK((state='retired') = (retired_at IS NOT NULL)),
 UNIQUE(target_id,user_key,platform_session_id,generation)
);
CREATE UNIQUE INDEX runner_targets_current_scope ON mcp.runner_targets(user_key,platform_session_id,generation) WHERE state <> 'retired';

CREATE TABLE mcp.runner_target_cleanups (
 operation_id uuid PRIMARY KEY,
 target_id uuid NOT NULL REFERENCES mcp.runner_targets(target_id),
 user_key text NOT NULL,
 platform_session_id bigint NOT NULL,
 generation bigint NOT NULL,
 status text NOT NULL CHECK(status IN ('pending','completed')),
 receipt_version integer,
 receipt_sha256 text,
 receipt_json jsonb,
 completed_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(operation_id,target_id,user_key,platform_session_id,generation),
 FOREIGN KEY(target_id,user_key,platform_session_id,generation)
   REFERENCES mcp.runner_targets(target_id,user_key,platform_session_id,generation),
 CHECK(status='pending' OR (receipt_version=1 AND receipt_sha256 ~ '^[a-f0-9]{64}$' AND receipt_json IS NOT NULL AND completed_at IS NOT NULL)),
 CHECK(status='completed' OR (receipt_version IS NULL AND receipt_sha256 IS NULL AND receipt_json IS NULL AND completed_at IS NULL))
);
CREATE INDEX runner_target_cleanup_scope ON mcp.runner_target_cleanups(user_key,generation,status);

CREATE TABLE mcp.mail_intents (
 intent_id uuid PRIMARY KEY,
 target_id uuid NOT NULL,
 user_key text NOT NULL,
 platform_session_id bigint NOT NULL,
 generation bigint NOT NULL,
 assigned_message_id text NOT NULL UNIQUE CHECK(assigned_message_id ~ '^mcp-[a-f0-9-]{36}@owasp-ai-goat\.local$'),
 recipient_sha256 text NOT NULL CHECK(recipient_sha256 ~ '^[a-f0-9]{64}$'),
 payload_sha256 text NOT NULL CHECK(payload_sha256 ~ '^[a-f0-9]{64}$'),
 status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','accepted','uncertain')),
 settled_at timestamptz,
 cleaned_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(target_id,user_key,platform_session_id,generation)
   REFERENCES mcp.runner_targets(target_id,user_key,platform_session_id,generation),
 CHECK((status='pending')=(settled_at IS NULL))
);
CREATE INDEX mail_intents_cleanup_scope ON mcp.mail_intents(target_id,user_key,platform_session_id,generation,cleaned_at);

CREATE TABLE mcp.mail_cleanups (
 operation_id uuid PRIMARY KEY,
 target_id uuid NOT NULL,
 user_key text NOT NULL,
 platform_session_id bigint NOT NULL,
 generation bigint NOT NULL,
 status text NOT NULL CHECK(status IN ('pending','completed')),
 message_ids jsonb NOT NULL CHECK(jsonb_typeof(message_ids)='array'),
 receipt_version integer,
 receipt_sha256 text,
 receipt_json jsonb,
 completed_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(operation_id,target_id,user_key,platform_session_id,generation)
   REFERENCES mcp.runner_target_cleanups(operation_id,target_id,user_key,platform_session_id,generation),
 UNIQUE(target_id,user_key,platform_session_id,generation),
 CHECK(status='pending' OR (receipt_version=1 AND receipt_sha256 ~ '^[a-f0-9]{64}$' AND receipt_json IS NOT NULL AND completed_at IS NOT NULL)),
 CHECK(status='completed' OR (receipt_version IS NULL AND receipt_sha256 IS NULL AND receipt_json IS NULL AND completed_at IS NULL))
);
CREATE INDEX mail_cleanups_scope ON mcp.mail_cleanups(user_key,generation,status);

REVOKE ALL ON mcp.runner_targets,mcp.runner_target_cleanups,mcp.mail_intents,mcp.mail_cleanups FROM PUBLIC;
-- Deliberately no runtime grants in the draft. Promotion must expose only the
-- reviewed repository functions/role, after exact identity-session validation.
