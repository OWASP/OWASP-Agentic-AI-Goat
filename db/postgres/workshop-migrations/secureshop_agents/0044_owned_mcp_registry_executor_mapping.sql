-- Add a versioned mapping to the existing journal; legacy requests retain their
-- existing admission and cleanup contract. No endpoint is dispatched by SQL.
ALTER FUNCTION secureshop_agents.admit_owned_mcp_invocation(jsonb,uuid)
 RENAME TO admit_owned_mcp_invocation_legacy;
REVOKE ALL ON FUNCTION secureshop_agents.admit_owned_mcp_invocation_legacy(jsonb,uuid) FROM PUBLIC,dvaia_secureshop_agents_runtime;
CREATE FUNCTION secureshop_agents.admit_owned_mcp_invocation(v jsonb, worker uuid)
RETURNS SETOF secureshop_agents.owned_mcp_invocation_journal LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE m jsonb:=v->'executorMapping'; q jsonb:=m->'request'; b jsonb:=v->'request'->'binding';
 e secureshop_agents.bound_mcp_registry_entries%ROWTYPE;
BEGIN
 IF v ? 'executorMapping' THEN
  IF jsonb_typeof(m) IS DISTINCT FROM 'object' OR m->'version' IS DISTINCT FROM '1'::jsonb
   OR q->'version' IS DISTINCT FROM '1'::jsonb
   OR m->>'requestSha256' IS NULL OR m->>'requestSha256' !~ '^[0-9a-f]{64}$'
   OR m->>'instanceId' IS DISTINCT FROM v->>'managerInstanceId'
   OR m->>'runtimeSha256' IS DISTINCT FROM v->>'runtimeSha256'
   OR q->>'instanceId' IS DISTINCT FROM m->>'instanceId'
   OR q->>'operationId' IS DISTINCT FROM v->>'invocationId'
   OR q->'entry'->>'entryId' IS DISTINCT FROM v->'request'->>'entryId'
   OR q->'entry'->>'registryVersion' IS DISTINCT FROM v->'request'->>'registryVersion'
   OR q->'entry'->>'schemaSha256' IS DISTINCT FROM v->'request'->>'schemaSha256'
   OR q->'entry'->'tools' IS DISTINCT FROM v->'snapshot'->'tools'
   OR q->>'toolName' IS DISTINCT FROM v->'request'->>'toolName'
   OR q->'args' IS DISTINCT FROM v->'request'->'args' THEN
   RAISE EXCEPTION 'Executor mapping mismatch' USING ERRCODE='22023'; END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||(b->>'platformOwnerId'),0));
  PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-conversation-admission:'||(b->>'launchId'),0));
  SELECT * INTO e FROM secureshop_agents.bound_mcp_registry_entries
   WHERE platform_launch_id=(b->>'launchId')::uuid AND platform_scenario_id=(b->>'scenarioId')::uuid
    AND platform_launch_generation=(b->>'generation')::bigint AND original_platform_owner_id=(b->>'platformOwnerId')::integer
    AND original_platform_session_id=(b->>'platformSessionId')::integer AND entry_id=(q->'entry'->>'entryId')::uuid
    AND lifecycle='active' FOR UPDATE;
  IF NOT FOUND OR e.transport IS DISTINCT FROM q->'entry'->>'transport'
    OR e.endpoint_text IS DISTINCT FROM q->'entry'->>'endpoint' THEN
   RAISE EXCEPTION 'Executor endpoint changed' USING ERRCODE='55000'; END IF;
 END IF;
 RETURN QUERY SELECT * FROM secureshop_agents.admit_owned_mcp_invocation_legacy(v,worker);
END $$;
REVOKE ALL ON FUNCTION secureshop_agents.admit_owned_mcp_invocation(jsonb,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_agents.admit_owned_mcp_invocation(jsonb,uuid) TO dvaia_secureshop_agents_runtime;

ALTER FUNCTION secureshop_agents.settle_owned_mcp_invocation(uuid,uuid,text,jsonb)
 RENAME TO settle_owned_mcp_invocation_legacy;
REVOKE ALL ON FUNCTION secureshop_agents.settle_owned_mcp_invocation_legacy(uuid,uuid,text,jsonb) FROM PUBLIC,dvaia_secureshop_agents_runtime;
CREATE FUNCTION secureshop_agents.settle_owned_mcp_invocation(id uuid, worker uuid, outcome text, receipt jsonb)
RETURNS SETOF secureshop_agents.owned_mcp_invocation_journal LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE m jsonb; p jsonb:=receipt->'executorProof';
BEGIN
 SELECT request_json->'executorMapping' INTO m FROM secureshop_agents.owned_mcp_invocation_journal WHERE invocation_id=id;
 IF m IS NOT NULL THEN
  IF receipt ? 'localNotDispatched' THEN
   IF outcome IS DISTINCT FROM 'failed_before_effect' OR receipt ? 'executorProof'
    OR receipt->'drained' IS DISTINCT FROM 'true'::jsonb
    OR receipt->'localNotDispatched' IS DISTINCT FROM jsonb_build_object('version',1,
      'instanceId',m->>'instanceId','operationId',id::text,'requestSha256',m->>'requestSha256') THEN
    RAISE EXCEPTION 'Local settlement mismatch' USING ERRCODE='55000'; END IF;
  ELSE
  IF p->>'operationId' IS DISTINCT FROM id::text OR p->>'instanceId' IS DISTINCT FROM m->>'instanceId'
   OR p->>'requestSha256' IS DISTINCT FROM m->>'requestSha256' OR p->'version' IS DISTINCT FROM '1'::jsonb
   OR (outcome='completed' AND (p->>'isolation' IS DISTINCT FROM 'owned-mcp-registry-v1' OR NOT(p ? 'resultSha256')))
   OR (outcome<>'completed' AND (p->>'state' IS NULL OR p->>'state' NOT IN ('running','completed','retired','unknown')
       OR p->'drained' IS DISTINCT FROM receipt->'drained')) THEN
   RAISE EXCEPTION 'Executor settlement mismatch' USING ERRCODE='55000'; END IF;
  END IF;
 END IF;
 RETURN QUERY SELECT * FROM secureshop_agents.settle_owned_mcp_invocation_legacy(id,worker,outcome,receipt);
END $$;
REVOKE ALL ON FUNCTION secureshop_agents.settle_owned_mcp_invocation(uuid,uuid,text,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_agents.settle_owned_mcp_invocation(uuid,uuid,text,jsonb) TO dvaia_secureshop_agents_runtime;
