-- UNREGISTERED forward-only candidate following unchanged 0035. Native qualification required.
CREATE OR REPLACE FUNCTION secureshop_agents.publish_owned_mcp_registry_operation(
 requested_launch uuid, requested_scenario uuid, requested_generation bigint, requested_owner integer, requested_platform_session integer,
 requested_operation uuid, requested_worker uuid, requested_request bytea, requested_binding bytea,
 requested_receipt jsonb, requested_receipt_sha bytea, requested_changes jsonb, requested_audit uuid)
RETURNS SETOF secureshop_agents.bound_mcp_registry_operations
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE op secureshop_agents.bound_mcp_registry_operations%ROWTYPE; item jsonb; next_version bigint; current_active integer; existing secureshop_agents.bound_mcp_registry_entries%ROWTYPE; changed_count integer:=0; expected_receipt_changes jsonb;
BEGIN
 IF requested_operation IS NULL OR requested_worker IS NULL OR requested_request IS NULL OR requested_binding IS NULL OR requested_receipt IS NULL
  OR requested_receipt_sha IS NULL OR requested_changes IS NULL OR requested_audit IS NULL OR octet_length(requested_request)<>32
  OR octet_length(requested_binding)<>32 OR octet_length(requested_receipt_sha)<>32 OR jsonb_typeof(requested_receipt) IS DISTINCT FROM 'object'
  OR jsonb_typeof(requested_changes) IS DISTINCT FROM 'array' OR jsonb_array_length(requested_changes) NOT BETWEEN 1 AND 32
 THEN RAISE EXCEPTION 'Owned MCP publication invalid' USING ERRCODE='55000'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||requested_owner::text,0));
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-conversation-admission:'||requested_launch::text,0));
 SELECT * INTO op FROM secureshop_agents.bound_mcp_registry_operations WHERE platform_launch_id=requested_launch
  AND platform_scenario_id=requested_scenario AND platform_launch_generation=requested_generation AND original_platform_owner_id=requested_owner
  AND original_platform_session_id=requested_platform_session AND operation_id=requested_operation FOR UPDATE;
 IF op.operation_id IS NULL OR op.worker_token IS DISTINCT FROM requested_worker OR op.request_sha256 IS DISTINCT FROM requested_request
  OR op.binding_sha256 IS DISTINCT FROM requested_binding THEN RAISE EXCEPTION 'Owned MCP publication mismatch' USING ERRCODE='55000'; END IF;
 IF op.state='completed' THEN
  IF op.receipt_json IS DISTINCT FROM requested_receipt OR op.receipt_sha256 IS DISTINCT FROM requested_receipt_sha THEN RAISE EXCEPTION 'Owned MCP receipt conflict' USING ERRCODE='55000'; END IF;
  RETURN NEXT op; RETURN;
 END IF;
 IF op.state<>'admitted' THEN RAISE EXCEPTION 'Owned MCP operation terminal' USING ERRCODE='55000'; END IF;
 PERFORM secureshop_agents.assert_owned_mcp_registry_actor_current(requested_launch,requested_scenario,requested_generation,requested_owner,requested_platform_session,op.persona_id,op.persona_session_id,op.authority_version);
 SELECT registry_version,active_count INTO next_version,current_active FROM secureshop_agents.bound_mcp_registry_heads WHERE platform_launch_id=requested_launch
  AND platform_scenario_id=requested_scenario AND platform_launch_generation=requested_generation AND original_platform_owner_id=requested_owner
  AND original_platform_session_id=requested_platform_session FOR UPDATE;
 IF next_version IS DISTINCT FROM op.expected_version THEN RAISE EXCEPTION 'Owned MCP registry version conflict' USING ERRCODE='55000'; END IF;
 next_version:=next_version+1;
 SELECT jsonb_agg(jsonb_build_object('name',value->'name','entryId',value->'entryId','action',value->'action',
  'schemaSha256',value->'schemaSha256','effect',value->'effect') ORDER BY ordinal)
 INTO expected_receipt_changes FROM jsonb_array_elements(requested_changes) WITH ORDINALITY AS changes(value,ordinal);
 IF NOT (requested_receipt ?& ARRAY['version','operationId','state','action','requestSha256','registryVersion','changes'])
  OR requested_receipt-ARRAY['version','operationId','state','action','requestSha256','registryVersion','changes']<>'{}'::jsonb
  OR jsonb_typeof(requested_receipt->'version') IS DISTINCT FROM 'string' OR jsonb_typeof(requested_receipt->'operationId') IS DISTINCT FROM 'string'
  OR jsonb_typeof(requested_receipt->'state') IS DISTINCT FROM 'string' OR jsonb_typeof(requested_receipt->'action') IS DISTINCT FROM 'string'
  OR jsonb_typeof(requested_receipt->'requestSha256') IS DISTINCT FROM 'string' OR jsonb_typeof(requested_receipt->'registryVersion') IS DISTINCT FROM 'string'
  OR requested_receipt->>'version'<>'secureshop-owned-mcp-registry.v1' OR requested_receipt->>'operationId'<>requested_operation::text
  OR requested_receipt->>'state'<>'completed' OR requested_receipt->>'action'<>op.action
  OR requested_receipt->>'requestSha256'<>encode(op.request_sha256,'hex') OR requested_receipt->>'registryVersion'<>next_version::text
  OR jsonb_typeof(requested_receipt->'changes') IS DISTINCT FROM 'array'
  OR requested_receipt->'changes' IS DISTINCT FROM expected_receipt_changes
 THEN RAISE EXCEPTION 'Owned MCP receipt invalid' USING ERRCODE='55000'; END IF;
 IF op.action IN ('register','retire') AND jsonb_array_length(requested_changes)<>1 THEN
  RAISE EXCEPTION 'Owned MCP request cardinality mismatch' USING ERRCODE='55000';
 END IF;
 FOR item IN SELECT value FROM jsonb_array_elements(requested_changes) LOOP
  IF jsonb_typeof(item) IS DISTINCT FROM 'object' OR NOT (item ?& ARRAY['name','entryId','action','transport','endpoint','schemaSha256','tools','effect'])
   OR item-ARRAY['name','entryId','action','transport','endpoint','schemaSha256','tools','effect']<>'{}'::jsonb
   OR jsonb_typeof(item->'name') IS DISTINCT FROM 'string' OR octet_length(item->>'name') NOT BETWEEN 1 AND 256
   OR jsonb_typeof(item->'entryId') IS DISTINCT FROM 'string' OR NOT (item->>'entryId' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
   OR jsonb_typeof(item->'action') IS DISTINCT FROM 'string' OR item->>'action' NOT IN ('register','import','retire')
   OR (op.action='register' AND item->>'action'<>'register') OR (op.action='retire' AND item->>'action'<>'retire')
   OR (op.action='import' AND item->>'action'<>'import') THEN RAISE EXCEPTION 'Owned MCP revision invalid' USING ERRCODE='55000'; END IF;
  IF op.action IN ('register','retire') AND item->>'name' IS DISTINCT FROM op.request_json->>'name' THEN
   RAISE EXCEPTION 'Owned MCP request target mismatch' USING ERRCODE='55000';
  END IF;
  IF op.action='register' AND (item->>'transport' IS DISTINCT FROM op.request_json->>'transport'
   OR item->>'endpoint' IS DISTINCT FROM CASE WHEN op.request_json->>'transport'='stdio' THEN op.request_json->>'stdio_cmd' ELSE op.request_json->>'url' END) THEN
   RAISE EXCEPTION 'Owned MCP request endpoint mismatch' USING ERRCODE='55000';
  END IF;
  SELECT * INTO existing FROM secureshop_agents.bound_mcp_registry_entries WHERE platform_launch_id=requested_launch
   AND platform_scenario_id=requested_scenario AND platform_launch_generation=requested_generation AND original_platform_owner_id=requested_owner
   AND original_platform_session_id=requested_platform_session AND name=item->>'name' FOR UPDATE;
  IF item->>'action'='retire' THEN
   IF existing.name IS NULL OR existing.lifecycle<>'active' OR existing.entry_id::text IS DISTINCT FROM item->>'entryId'
    OR item->'transport'<>'null'::jsonb OR item->'endpoint'<>'null'::jsonb OR item->'schemaSha256'<>'null'::jsonb OR item->'tools'<>'null'::jsonb
    OR jsonb_typeof(item->'effect') IS DISTINCT FROM 'object' OR octet_length((item->'effect')::text)>65536
   THEN RAISE EXCEPTION 'Owned MCP retirement invalid' USING ERRCODE='55000'; END IF;
   UPDATE secureshop_agents.bound_mcp_registry_entries SET lifecycle='retired',current_version=next_version WHERE platform_launch_id=requested_launch
    AND platform_scenario_id=requested_scenario AND platform_launch_generation=requested_generation AND original_platform_owner_id=requested_owner
    AND original_platform_session_id=requested_platform_session AND name=item->>'name'; current_active:=current_active-1;
  ELSE
   IF jsonb_typeof(item->'transport') IS DISTINCT FROM 'string' OR item->>'transport' NOT IN ('sse','streamable-http','stdio')
    OR jsonb_typeof(item->'endpoint') IS DISTINCT FROM 'string' OR octet_length(item->>'endpoint') NOT BETWEEN 1 AND 4096
    OR jsonb_typeof(item->'schemaSha256') IS DISTINCT FROM 'string' OR NOT (item->>'schemaSha256' ~ '^[0-9a-f]{64}$')
    OR jsonb_typeof(item->'tools') IS DISTINCT FROM 'array' OR jsonb_array_length(item->'tools')>64 OR octet_length((item->'tools')::text)>65536
    OR jsonb_typeof(item->'effect') IS DISTINCT FROM 'object' OR octet_length((item->'effect')::text)>65536
   THEN RAISE EXCEPTION 'Owned MCP discovery invalid' USING ERRCODE='55000'; END IF;
   IF op.mode='fixed' AND existing.name IS NOT NULL AND (existing.transport IS DISTINCT FROM item->>'transport'
    OR existing.endpoint_text IS DISTINCT FROM item->>'endpoint' OR encode(existing.schema_sha256,'hex') IS DISTINCT FROM item->>'schemaSha256') THEN
    RAISE EXCEPTION 'Owned MCP fixed identity mismatch' USING ERRCODE='55000';
   END IF;
   IF existing.name IS NOT NULL AND existing.entry_id::text IS DISTINCT FROM item->>'entryId' THEN RAISE EXCEPTION 'Owned MCP entry identity mismatch' USING ERRCODE='55000'; END IF;
   IF existing.name IS NULL THEN current_active:=current_active+1;
   ELSIF existing.lifecycle='retired' THEN current_active:=current_active+1; END IF;
   INSERT INTO secureshop_agents.bound_mcp_registry_entries VALUES(requested_launch,requested_scenario,requested_generation,requested_owner,requested_platform_session,
    item->>'name',(item->>'entryId')::uuid,next_version,'active',item->>'transport',item->>'endpoint',decode(item->>'schemaSha256','hex'),op.persona_id,clock_timestamp())
   ON CONFLICT(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,name)
   DO UPDATE SET current_version=EXCLUDED.current_version,lifecycle='active',transport=EXCLUDED.transport,endpoint_text=EXCLUDED.endpoint_text,
    schema_sha256=EXCLUDED.schema_sha256,registered_by=EXCLUDED.registered_by,registered_at=EXCLUDED.registered_at;
  END IF;
  INSERT INTO secureshop_agents.bound_mcp_registry_revisions VALUES(requested_launch,requested_scenario,requested_generation,requested_owner,requested_platform_session,
   requested_operation,item->>'name',next_version,(item->>'entryId')::uuid,item->>'action',NULLIF(item->>'transport',''),NULLIF(item->>'endpoint',''),
   CASE WHEN item->'schemaSha256'='null'::jsonb THEN NULL ELSE decode(item->>'schemaSha256','hex') END,
   CASE WHEN item->'tools'='null'::jsonb THEN NULL ELSE item->'tools' END,
   item->'effect'||jsonb_build_object('requestSha256',encode(op.request_sha256,'hex'),'bindingSha256',encode(op.binding_sha256,'hex')),NULL,clock_timestamp());
  changed_count:=changed_count+1;
 END LOOP;
 IF current_active NOT BETWEEN 0 AND 32 THEN RAISE EXCEPTION 'Owned MCP active registry quota' USING ERRCODE='55000'; END IF;
 UPDATE secureshop_agents.bound_mcp_registry_heads SET registry_version=next_version,active_count=current_active WHERE platform_launch_id=requested_launch
  AND platform_scenario_id=requested_scenario AND platform_launch_generation=requested_generation AND original_platform_owner_id=requested_owner
  AND original_platform_session_id=requested_platform_session;
 UPDATE secureshop_agents.bound_mcp_registry_operations SET state='completed',receipt_json=requested_receipt,receipt_sha256=requested_receipt_sha,completed_at=clock_timestamp()
  WHERE platform_launch_id=requested_launch AND platform_scenario_id=requested_scenario AND platform_launch_generation=requested_generation
  AND original_platform_owner_id=requested_owner AND original_platform_session_id=requested_platform_session AND operation_id=requested_operation RETURNING * INTO op;
 INSERT INTO secureshop_agents.bound_audit_events(event_id,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id,
  shop_user_id,shop_role,actor,action,target,params_json,outcome,source_kind,source_id)
 VALUES(requested_audit,requested_launch,requested_scenario,requested_generation,requested_owner,requested_platform_session,op.persona_id,'admin',
  'admin','mcp_registry_'||op.action,'mcp-registry',jsonb_build_object('operationId',requested_operation,'registryVersion',next_version,'changed',changed_count)::text,
  'completed','bound_mcp_registry_operation',requested_operation::text);
 RETURN NEXT op;
END $$;
