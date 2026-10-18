-- Candidate only, outside active migration chain. Distinct Shadow service lease.
CREATE TABLE mcp.shadow_target_leases (
 target_id uuid PRIMARY KEY,
 user_key text NOT NULL,
 platform_session_id bigint NOT NULL,
 generation bigint NOT NULL,
 state text NOT NULL DEFAULT 'provisioning' CHECK(state IN ('provisioning','active','retiring','retired')),
 cleanup_operation_id uuid UNIQUE,
 cleanup_receipt jsonb,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(target_id,user_key,platform_session_id,generation)
 REFERENCES mcp.runner_targets(target_id,user_key,platform_session_id,generation),
 CHECK((state IN ('retiring','retired'))=(cleanup_operation_id IS NOT NULL)),
 CHECK((state='retired')=(cleanup_receipt IS NOT NULL)),
 CHECK(cleanup_receipt IS NULL OR (jsonb_typeof(cleanup_receipt)='object' AND octet_length(cleanup_receipt::text)<=4096))
);
CREATE FUNCTION mcp.guard_shadow_target_lease() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF ROW(NEW.target_id,NEW.user_key,NEW.platform_session_id,NEW.generation,NEW.created_at)
 IS DISTINCT FROM ROW(OLD.target_id,OLD.user_key,OLD.platform_session_id,OLD.generation,OLD.created_at)
 OR OLD.state='retired'
 OR (OLD.cleanup_operation_id IS NOT NULL AND OLD.cleanup_operation_id IS DISTINCT FROM NEW.cleanup_operation_id)
 OR NOT ((OLD.state='provisioning' AND NEW.state IN ('active','retiring'))
 OR (OLD.state='active' AND NEW.state='retiring') OR (OLD.state='retiring' AND NEW.state='retired')) THEN
  RAISE EXCEPTION 'Shadow child lease transition rejected' USING ERRCODE='42501';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER shadow_target_lease_immutable BEFORE UPDATE ON mcp.shadow_target_leases
 FOR EACH ROW EXECUTE FUNCTION mcp.guard_shadow_target_lease();
REVOKE ALL ON mcp.shadow_target_leases FROM PUBLIC;
REVOKE ALL ON FUNCTION mcp.guard_shadow_target_lease() FROM PUBLIC;
GRANT SELECT,INSERT ON mcp.shadow_target_leases TO dvaia_mcp_runtime;
GRANT UPDATE(state,cleanup_operation_id,cleanup_receipt) ON mcp.shadow_target_leases TO dvaia_mcp_runtime;
-- Old callers cannot certify CLI-only cleanup after a child lease is admitted.
CREATE FUNCTION mcp.guard_shadow_child_retirement() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.state='retired' AND EXISTS(SELECT 1 FROM mcp.shadow_target_leases h
   WHERE h.target_id=NEW.target_id AND h.state<>'retired') THEN
  RAISE EXCEPTION 'Shadow child cleanup remains required' USING ERRCODE='42501';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER runner_shadow_child_retirement BEFORE UPDATE OF state ON mcp.runner_targets
 FOR EACH ROW EXECUTE FUNCTION mcp.guard_shadow_child_retirement();
REVOKE ALL ON FUNCTION mcp.guard_shadow_child_retirement() FROM PUBLIC;
