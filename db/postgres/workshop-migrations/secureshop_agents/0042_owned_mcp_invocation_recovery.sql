-- Private status/settlement recovery only. This function cannot admit or dispatch.
-- The runtime role is trusted; worker_token is a correlation value, not a secret
-- against that role (0041 admission already returns it through SETOF).
CREATE FUNCTION secureshop_agents.read_owned_mcp_invocation_recovery(
 id uuid, owner_id integer, launch uuid, scenario uuid, generation bigint, session_id integer
) RETURNS SETOF secureshop_agents.owned_mcp_invocation_journal
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE r secureshop_agents.owned_mcp_invocation_journal%ROWTYPE;
BEGIN
 IF id IS NULL OR owner_id IS NULL OR owner_id<1 OR launch IS NULL OR scenario IS NULL
 OR generation IS NULL OR generation<1 OR session_id IS NULL OR session_id<1 THEN
  RAISE EXCEPTION 'Invocation recovery unavailable' USING ERRCODE='55000';
 END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||owner_id::text,0));
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-conversation-admission:'||launch::text,0));
 SELECT * INTO r FROM secureshop_agents.owned_mcp_invocation_journal
 WHERE invocation_id=id AND original_platform_owner_id=owner_id AND platform_launch_id=launch
 AND platform_scenario_id=scenario AND platform_launch_generation=generation
 AND original_platform_session_id=session_id AND redacted_at IS NULL AND request_json IS NOT NULL;
 IF NOT FOUND THEN RAISE EXCEPTION 'Invocation recovery unavailable' USING ERRCODE='55000'; END IF;
 RETURN NEXT r;
END $$;
REVOKE ALL ON FUNCTION secureshop_agents.read_owned_mcp_invocation_recovery(uuid,integer,uuid,uuid,bigint,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_agents.read_owned_mcp_invocation_recovery(uuid,integer,uuid,uuid,bigint,integer) TO dvaia_secureshop_agents_runtime;
