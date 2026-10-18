-- Candidate only; not in active loader. Recheck successor ordering before promotion.
CREATE TABLE workshop_conversations.mcp_shadow_operations (
 operation_id uuid PRIMARY KEY,
 registration_id uuid NOT NULL,
 action text NOT NULL CHECK(action IN ('register','invoke')),
 user_id integer NOT NULL REFERENCES identity.users(id) ON DELETE CASCADE,
 owner_key text NOT NULL REFERENCES graph_runtime.owners(owner_key),
 run_id uuid NOT NULL REFERENCES graph_runtime.runs(run_id),
 generation bigint NOT NULL CHECK(generation>=0),
 target_id uuid NOT NULL,
 platform_session_id bigint NOT NULL CHECK(platform_session_id>0),
 invocation_id uuid NOT NULL,
 request_digest text NOT NULL CHECK(request_digest ~ '^[a-f0-9]{64}$'),
 request_json jsonb NOT NULL CHECK(jsonb_typeof(request_json)='object' AND octet_length(request_json::text)<=8192),
 receipt_sha256 text CHECK(receipt_sha256 ~ '^[a-f0-9]{64}$'),
 receipt_json jsonb CHECK(receipt_json IS NULL OR (jsonb_typeof(receipt_json)='object' AND octet_length(receipt_json::text)<=131072)),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 completed_at timestamptz,
 CHECK((receipt_json IS NULL)=(receipt_sha256 IS NULL)),
 CHECK((receipt_json IS NULL)=(completed_at IS NULL)),
 UNIQUE(run_id,invocation_id)
);
CREATE UNIQUE INDEX mcp_shadow_registration ON workshop_conversations.mcp_shadow_operations(registration_id) WHERE action='register';
CREATE INDEX mcp_shadow_operation_owner ON workshop_conversations.mcp_shadow_operations(owner_key,generation,created_at);
CREATE FUNCTION workshop_conversations.guard_mcp_shadow_operation() RETURNS trigger LANGUAGE plpgsql
 SET search_path=pg_catalog AS $$
BEGIN
 IF ROW(NEW.registration_id,NEW.action,NEW.operation_id,NEW.user_id,NEW.owner_key,NEW.run_id,NEW.generation,NEW.target_id,
        NEW.platform_session_id,NEW.invocation_id,NEW.request_digest,NEW.request_json,NEW.created_at)
 IS DISTINCT FROM ROW(OLD.registration_id,OLD.action,OLD.operation_id,OLD.user_id,OLD.owner_key,OLD.run_id,OLD.generation,OLD.target_id,
        OLD.platform_session_id,OLD.invocation_id,OLD.request_digest,OLD.request_json,OLD.created_at)
 OR OLD.receipt_json IS NOT NULL THEN
  RAISE EXCEPTION 'Shadow operation history is immutable' USING ERRCODE='42501';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER mcp_shadow_operation_immutable BEFORE UPDATE ON workshop_conversations.mcp_shadow_operations
 FOR EACH ROW EXECUTE FUNCTION workshop_conversations.guard_mcp_shadow_operation();
REVOKE ALL ON workshop_conversations.mcp_shadow_operations FROM PUBLIC;
REVOKE ALL ON FUNCTION workshop_conversations.guard_mcp_shadow_operation() FROM PUBLIC;
GRANT SELECT,INSERT ON workshop_conversations.mcp_shadow_operations TO dvaia_identity_runtime;
GRANT UPDATE(receipt_json,receipt_sha256,completed_at) ON workshop_conversations.mcp_shadow_operations TO dvaia_identity_runtime;
