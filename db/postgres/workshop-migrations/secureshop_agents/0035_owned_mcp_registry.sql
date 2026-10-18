-- UNREGISTERED candidate. General launch-owned MCP registry storage is separate
-- from the two immutable bound_mcp_targets trust scenarios. Native
-- fresh/populated/no-op, privilege and lifecycle qualification is required
-- before this migration may be registered or advertised.
CREATE TABLE secureshop_agents.bound_mcp_registry_heads (
 platform_launch_id uuid NOT NULL, platform_scenario_id uuid NOT NULL,
 platform_launch_generation bigint NOT NULL CHECK(platform_launch_generation>0),
 original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id>0),
 original_platform_session_id integer NOT NULL CHECK(original_platform_session_id>0),
 registry_version bigint NOT NULL DEFAULT 0 CHECK(registry_version BETWEEN 0 AND 9007199254740991),
 active_count integer NOT NULL DEFAULT 0 CHECK(active_count BETWEEN 0 AND 32),
 PRIMARY KEY(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id)
);
CREATE TABLE secureshop_agents.bound_mcp_registry_entries (
 platform_launch_id uuid NOT NULL, platform_scenario_id uuid NOT NULL,
 platform_launch_generation bigint NOT NULL, original_platform_owner_id integer NOT NULL,
 original_platform_session_id integer NOT NULL, name text NOT NULL CHECK(octet_length(name) BETWEEN 1 AND 256),
 entry_id uuid NOT NULL, current_version bigint NOT NULL CHECK(current_version>0),
 lifecycle text NOT NULL CHECK(lifecycle IN ('active','retired')),
 transport text NOT NULL CHECK(transport IN ('sse','streamable-http','stdio')),
 endpoint_text text NOT NULL CHECK(octet_length(endpoint_text) BETWEEN 1 AND 4096),
 schema_sha256 bytea NOT NULL CHECK(octet_length(schema_sha256)=32),
 registered_by integer NOT NULL CHECK(registered_by>0), registered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,name),
 UNIQUE(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,entry_id),
 FOREIGN KEY(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id)
  REFERENCES secureshop_agents.bound_mcp_registry_heads ON DELETE RESTRICT
);
CREATE TABLE secureshop_agents.bound_mcp_registry_revisions (
 platform_launch_id uuid NOT NULL, platform_scenario_id uuid NOT NULL,
 platform_launch_generation bigint NOT NULL, original_platform_owner_id integer NOT NULL,
 original_platform_session_id integer NOT NULL, operation_id uuid NOT NULL, name text NOT NULL,
 registry_version bigint NOT NULL CHECK(registry_version>0), entry_id uuid NOT NULL,
 action text NOT NULL CHECK(action IN ('register','import','retire')),
 transport text CHECK(transport IS NULL OR transport IN ('sse','streamable-http','stdio')),
 endpoint_text text CHECK(endpoint_text IS NULL OR octet_length(endpoint_text) BETWEEN 1 AND 4096),
 schema_sha256 bytea CHECK(schema_sha256 IS NULL OR octet_length(schema_sha256)=32),
 tools_json jsonb CHECK(tools_json IS NULL OR (jsonb_typeof(tools_json)='array' AND jsonb_array_length(tools_json)<=64 AND octet_length(tools_json::text)<=65536)),
 effect_json jsonb CHECK(effect_json IS NULL OR (jsonb_typeof(effect_json)='object' AND octet_length(effect_json::text)<=65536)),
 redacted_at timestamptz,
 discovered_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 CONSTRAINT bound_mcp_registry_revision_shape CHECK(redacted_at IS NOT NULL AND endpoint_text IS NULL AND tools_json IS NULL AND effect_json IS NULL OR
  redacted_at IS NULL AND (
  (action='retire' AND transport IS NULL AND endpoint_text IS NULL AND schema_sha256 IS NULL AND tools_json IS NULL)
  OR (action IN ('register','import') AND transport IS NOT NULL AND endpoint_text IS NOT NULL AND schema_sha256 IS NOT NULL AND tools_json IS NOT NULL AND effect_json IS NOT NULL))),
 PRIMARY KEY(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,name,registry_version),
 FOREIGN KEY(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id)
  REFERENCES secureshop_agents.bound_mcp_registry_heads ON DELETE RESTRICT
);
CREATE TABLE secureshop_agents.bound_mcp_registry_operations (
 platform_launch_id uuid NOT NULL, platform_scenario_id uuid NOT NULL,
 platform_launch_generation bigint NOT NULL CHECK(platform_launch_generation>0),
 original_platform_owner_id integer NOT NULL CHECK(original_platform_owner_id>0),
 original_platform_session_id integer NOT NULL CHECK(original_platform_session_id>0),
 operation_id uuid NOT NULL, persona_id integer NOT NULL CHECK(persona_id>0), persona_session_id uuid NOT NULL,
 persona_role text NOT NULL CHECK(persona_role='admin'), authority_version bigint NOT NULL CHECK(authority_version>0),
 mode text NOT NULL CHECK(mode IN ('vuln','fixed')),
 action text NOT NULL CHECK(action IN ('register','import','retire')),
 expected_version bigint NOT NULL CHECK(expected_version BETWEEN 0 AND 9007199254740990),
 request_sha256 bytea NOT NULL CHECK(octet_length(request_sha256)=32),
 binding_sha256 bytea NOT NULL CHECK(octet_length(binding_sha256)=32), worker_token uuid NOT NULL,
 state text NOT NULL CHECK(state IN ('admitted','completed','failed','unknown')),
 request_json jsonb CHECK(request_json IS NULL OR (jsonb_typeof(request_json)='object' AND octet_length(request_json::text)<=131072)),
 receipt_json jsonb CHECK(receipt_json IS NULL OR (jsonb_typeof(receipt_json)='object' AND octet_length(receipt_json::text)<=524288)),
 receipt_sha256 bytea CHECK(receipt_sha256 IS NULL OR octet_length(receipt_sha256)=32),
 admitted_at timestamptz NOT NULL DEFAULT clock_timestamp(), completed_at timestamptz, redacted_at timestamptz,
 CONSTRAINT bound_mcp_registry_operation_shape CHECK(redacted_at IS NOT NULL AND request_json IS NULL AND receipt_json IS NULL OR redacted_at IS NULL AND (
  (state='admitted' AND request_json IS NOT NULL AND receipt_json IS NULL AND receipt_sha256 IS NULL AND completed_at IS NULL)
  OR (state='completed' AND receipt_json IS NOT NULL AND receipt_sha256 IS NOT NULL AND completed_at IS NOT NULL)
  OR (state IN ('failed','unknown') AND receipt_json IS NULL AND receipt_sha256 IS NULL AND completed_at IS NOT NULL))),
 PRIMARY KEY(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,operation_id),
 FOREIGN KEY(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id)
  REFERENCES secureshop_agents.bound_mcp_registry_heads ON DELETE RESTRICT
);
CREATE TABLE secureshop_agents.bound_mcp_registry_cleanup_receipts (
 cleanup_id uuid PRIMARY KEY, cleanup_kind text NOT NULL CHECK(cleanup_kind IN ('retirement','owner_deletion')),
 original_platform_owner_id integer NOT NULL, platform_launch_id uuid, platform_generation bigint,
 deleted_entries integer NOT NULL CHECK(deleted_entries>=0), redacted_records integer NOT NULL CHECK(redacted_records>=0),
 receipt_sha256 bytea NOT NULL CHECK(octet_length(receipt_sha256)=32)
);

CREATE FUNCTION secureshop_agents.guard_owned_mcp_registry_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$ BEGIN
 IF TG_TABLE_NAME='bound_mcp_registry_revisions' THEN
  IF TG_OP='DELETE' AND EXISTS(SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts WHERE original_platform_owner_id=OLD.original_platform_owner_id) THEN RETURN OLD; END IF;
  IF TG_OP='UPDATE' AND EXISTS(SELECT 1 FROM secureshop_agents.conversation_generation_retirements WHERE platform_launch_id=OLD.platform_launch_id AND platform_scenario_id=OLD.platform_scenario_id AND from_generation=OLD.platform_launch_generation AND original_platform_owner_id=OLD.original_platform_owner_id AND original_platform_session_id=OLD.original_platform_session_id)
   AND OLD.redacted_at IS NULL AND NEW.redacted_at IS NOT NULL AND NEW.endpoint_text IS NULL AND NEW.tools_json IS NULL AND NEW.effect_json IS NULL
   AND (to_jsonb(NEW)-ARRAY['endpoint_text','tools_json','effect_json','redacted_at'])=(to_jsonb(OLD)-ARRAY['endpoint_text','tools_json','effect_json','redacted_at']) THEN RETURN NEW; END IF;
 END IF;
 RAISE EXCEPTION 'Owned MCP registry evidence is immutable' USING ERRCODE='55000';
END $$;
CREATE TRIGGER bound_mcp_registry_revisions_immutable BEFORE UPDATE OR DELETE ON secureshop_agents.bound_mcp_registry_revisions
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_owned_mcp_registry_immutable();
CREATE TRIGGER bound_mcp_registry_cleanup_immutable BEFORE UPDATE OR DELETE ON secureshop_agents.bound_mcp_registry_cleanup_receipts
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_owned_mcp_registry_immutable();

-- Reconstruct the exact normalized JavaScript request serialization rather
-- than trusting a runtime-supplied digest. Field order is part of the public
-- recovery contract; each string is encoded by PostgreSQL's JSON encoder.
CREATE FUNCTION secureshop_agents.owned_mcp_registry_request_digest(requested jsonb)
RETURNS bytea LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT sha256(convert_to(CASE requested->>'action'
  WHEN 'register' THEN '{"version":1,"action":'||to_jsonb(requested->>'action')::text||',"operationId":'||to_jsonb(requested->>'operationId')::text||',"expectedVersion":'||to_jsonb(requested->>'expectedVersion')::text||',"name":'||to_jsonb(requested->>'name')::text||',"transport":'||to_jsonb(requested->>'transport')::text||',"url":'||to_jsonb(requested->>'url')::text||',"stdio_cmd":'||to_jsonb(requested->>'stdio_cmd')::text||'}'
  WHEN 'import' THEN '{"version":1,"action":'||to_jsonb(requested->>'action')::text||',"operationId":'||to_jsonb(requested->>'operationId')::text||',"expectedVersion":'||to_jsonb(requested->>'expectedVersion')::text||',"xml_url":'||to_jsonb(requested->>'xml_url')::text||'}'
  WHEN 'retire' THEN '{"version":1,"action":'||to_jsonb(requested->>'action')::text||',"operationId":'||to_jsonb(requested->>'operationId')::text||',"expectedVersion":'||to_jsonb(requested->>'expectedVersion')::text||',"name":'||to_jsonb(requested->>'name')::text||'}'
  ELSE '' END,'UTF8'))
$$;

CREATE FUNCTION secureshop_agents.assert_owned_mcp_registry_actor_current(
 requested_launch uuid, requested_scenario uuid, requested_generation bigint, requested_owner integer, requested_platform_session integer,
 requested_persona integer, requested_persona_session uuid, requested_authority bigint)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$ BEGIN
 IF EXISTS(SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts WHERE original_platform_owner_id=requested_owner)
  OR EXISTS(SELECT 1 FROM secureshop_agents.conversation_generation_retirements WHERE platform_launch_id=requested_launch AND platform_scenario_id=requested_scenario AND from_generation=requested_generation AND original_platform_owner_id=requested_owner AND original_platform_session_id=requested_platform_session)
  OR NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_persona_sessions s
   JOIN secureshop_agents.bound_persona_templates t ON t.shop_user_id=s.shop_user_id
   LEFT JOIN secureshop_agents.bound_persona_state st ON st.platform_launch_id=s.platform_launch_id AND st.platform_scenario_id=s.platform_scenario_id AND st.platform_launch_generation=s.platform_launch_generation AND st.original_platform_owner_id=s.original_platform_owner_id AND st.original_platform_session_id=s.original_platform_session_id AND st.shop_user_id=s.shop_user_id
   WHERE s.platform_launch_id=requested_launch AND s.platform_scenario_id=requested_scenario AND s.platform_launch_generation=requested_generation
   AND s.original_platform_owner_id=requested_owner AND s.original_platform_session_id=requested_platform_session
   AND s.shop_user_id=requested_persona AND s.session_id=requested_persona_session AND s.role='admin' AND s.revoked_at IS NULL
   AND s.expires_at>clock_timestamp() AND st.banned_at IS NULL AND COALESCE(st.effective_role,t.role)='admin'
   AND COALESCE(st.authority_version,1)=requested_authority
   AND s.credential_version=COALESCE((SELECT c.credential_version FROM secureshop_agents.bound_persona_credentials c
    WHERE c.platform_launch_id=requested_launch AND c.platform_scenario_id=requested_scenario AND c.platform_launch_generation=requested_generation
    AND c.original_platform_owner_id=requested_owner AND c.original_platform_session_id=requested_platform_session AND c.shop_user_id=requested_persona),1))
 THEN RAISE EXCEPTION 'Owned MCP authority unavailable' USING ERRCODE='55000'; END IF;
END $$;

CREATE FUNCTION secureshop_agents.admit_owned_mcp_registry_operation(
 requested_launch uuid, requested_scenario uuid, requested_generation bigint, requested_owner integer, requested_platform_session integer,
 requested_operation uuid, requested_persona integer, requested_persona_session uuid, requested_authority bigint,
 requested_mode text, requested_action text, requested_expected bigint, requested_request bytea, requested_binding bytea,
 requested_worker uuid, requested_json jsonb)
RETURNS SETOF secureshop_agents.bound_mcp_registry_operations
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE prior secureshop_agents.bound_mcp_registry_operations%ROWTYPE; current_version bigint;
BEGIN
 IF requested_launch IS NULL OR requested_scenario IS NULL OR requested_generation IS NULL OR requested_owner IS NULL
  OR requested_platform_session IS NULL OR requested_operation IS NULL OR requested_persona IS NULL OR requested_persona_session IS NULL
  OR requested_authority IS NULL OR requested_mode IS NULL OR requested_mode NOT IN ('vuln','fixed') OR requested_action IS NULL OR requested_expected IS NULL OR requested_request IS NULL
  OR requested_binding IS NULL OR requested_worker IS NULL OR requested_json IS NULL
  OR requested_action NOT IN ('register','import','retire') OR octet_length(requested_request)<>32 OR octet_length(requested_binding)<>32
  OR requested_request IS DISTINCT FROM secureshop_agents.owned_mcp_registry_request_digest(requested_json)
  OR jsonb_typeof(requested_json) IS DISTINCT FROM 'object'
  OR jsonb_typeof(requested_json->'version') IS DISTINCT FROM 'number' OR requested_json->>'version'<>'1'
  OR jsonb_typeof(requested_json->'action') IS DISTINCT FROM 'string' OR requested_json->>'action'<>requested_action
  OR jsonb_typeof(requested_json->'operationId') IS DISTINCT FROM 'string' OR requested_json->>'operationId'<>requested_operation::text
  OR jsonb_typeof(requested_json->'expectedVersion') IS DISTINCT FROM 'string' OR requested_json->>'expectedVersion'<>requested_expected::text
  OR (requested_action='register' AND ((SELECT count(*) FROM jsonb_object_keys(requested_json))<>8
   OR NOT (requested_json ?& ARRAY['version','action','operationId','expectedVersion','name','transport','url','stdio_cmd'])
   OR jsonb_typeof(requested_json->'name') IS DISTINCT FROM 'string' OR octet_length(requested_json->>'name') NOT BETWEEN 1 AND 256 OR btrim(requested_json->>'name')=''
   OR jsonb_typeof(requested_json->'transport') IS DISTINCT FROM 'string' OR requested_json->>'transport' NOT IN ('sse','streamable-http','stdio')
   OR jsonb_typeof(requested_json->'url') IS DISTINCT FROM 'string' OR jsonb_typeof(requested_json->'stdio_cmd') IS DISTINCT FROM 'string'
   OR (requested_json->>'transport'='stdio' AND requested_json->>'url'<>'')
   OR (requested_json->>'transport'='stdio' AND btrim(requested_json->>'stdio_cmd')='')
   OR (requested_json->>'transport'<>'stdio' AND (requested_json->>'stdio_cmd'<>'' OR btrim(requested_json->>'url')='' OR NOT (requested_json->>'url' ~ '^https?://')))
   OR octet_length(CASE WHEN requested_json->>'transport'='stdio' THEN requested_json->>'stdio_cmd' ELSE requested_json->>'url' END) NOT BETWEEN 1 AND 4096))
  OR (requested_action='import' AND ((SELECT count(*) FROM jsonb_object_keys(requested_json))<>5
   OR NOT (requested_json ?& ARRAY['version','action','operationId','expectedVersion','xml_url'])
   OR jsonb_typeof(requested_json->'xml_url') IS DISTINCT FROM 'string' OR octet_length(requested_json->>'xml_url') NOT BETWEEN 1 AND 4096 OR btrim(requested_json->>'xml_url')='' OR NOT (requested_json->>'xml_url' ~ '^https?://')))
  OR (requested_action='retire' AND ((SELECT count(*) FROM jsonb_object_keys(requested_json))<>5
   OR NOT (requested_json ?& ARRAY['version','action','operationId','expectedVersion','name'])
   OR jsonb_typeof(requested_json->'name') IS DISTINCT FROM 'string' OR octet_length(requested_json->>'name') NOT BETWEEN 1 AND 256 OR btrim(requested_json->>'name')=''))
 THEN RAISE EXCEPTION 'Owned MCP admission invalid' USING ERRCODE='55000'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||requested_owner::text,0));
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-conversation-admission:'||requested_launch::text,0));
 IF EXISTS(SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts WHERE original_platform_owner_id=requested_owner)
  OR EXISTS(SELECT 1 FROM secureshop_agents.conversation_generation_retirements WHERE platform_launch_id=requested_launch AND platform_scenario_id=requested_scenario AND from_generation=requested_generation AND original_platform_owner_id=requested_owner AND original_platform_session_id=requested_platform_session)
  OR NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_persona_sessions s
   JOIN secureshop_agents.bound_persona_templates t ON t.shop_user_id=s.shop_user_id
   LEFT JOIN secureshop_agents.bound_persona_state st ON st.platform_launch_id=s.platform_launch_id AND st.platform_scenario_id=s.platform_scenario_id AND st.platform_launch_generation=s.platform_launch_generation AND st.original_platform_owner_id=s.original_platform_owner_id AND st.original_platform_session_id=s.original_platform_session_id AND st.shop_user_id=s.shop_user_id
   WHERE s.platform_launch_id=requested_launch AND s.platform_scenario_id=requested_scenario AND s.platform_launch_generation=requested_generation
   AND s.original_platform_owner_id=requested_owner AND s.original_platform_session_id=requested_platform_session
   AND s.shop_user_id=requested_persona AND s.session_id=requested_persona_session AND s.role='admin' AND s.revoked_at IS NULL
   AND s.expires_at>clock_timestamp() AND st.banned_at IS NULL AND COALESCE(st.effective_role,t.role)='admin'
   AND COALESCE(st.authority_version,1)=requested_authority
   AND s.credential_version=COALESCE((SELECT c.credential_version FROM secureshop_agents.bound_persona_credentials c
    WHERE c.platform_launch_id=requested_launch AND c.platform_scenario_id=requested_scenario AND c.platform_launch_generation=requested_generation
    AND c.original_platform_owner_id=requested_owner AND c.original_platform_session_id=requested_platform_session AND c.shop_user_id=requested_persona),1))
 THEN RAISE EXCEPTION 'Owned MCP authority unavailable' USING ERRCODE='55000'; END IF;
 SELECT * INTO prior FROM secureshop_agents.bound_mcp_registry_operations WHERE platform_launch_id=requested_launch
  AND platform_scenario_id=requested_scenario AND platform_launch_generation=requested_generation
  AND original_platform_owner_id=requested_owner AND original_platform_session_id=requested_platform_session AND operation_id=requested_operation;
 IF prior.operation_id IS NOT NULL THEN
  IF prior.persona_id IS DISTINCT FROM requested_persona OR prior.persona_session_id IS DISTINCT FROM requested_persona_session
   OR prior.authority_version IS DISTINCT FROM requested_authority OR prior.mode IS DISTINCT FROM requested_mode OR prior.action IS DISTINCT FROM requested_action
   OR prior.expected_version IS DISTINCT FROM requested_expected OR prior.request_sha256 IS DISTINCT FROM requested_request
   OR prior.binding_sha256 IS DISTINCT FROM requested_binding
   OR prior.request_json IS DISTINCT FROM requested_json THEN RAISE EXCEPTION 'Owned MCP operation conflict' USING ERRCODE='55000'; END IF;
  RETURN NEXT prior; RETURN;
 END IF;
 INSERT INTO secureshop_agents.bound_mcp_registry_heads VALUES(requested_launch,requested_scenario,requested_generation,requested_owner,requested_platform_session,0,0) ON CONFLICT DO NOTHING;
 SELECT registry_version INTO current_version FROM secureshop_agents.bound_mcp_registry_heads WHERE platform_launch_id=requested_launch
  AND platform_scenario_id=requested_scenario AND platform_launch_generation=requested_generation AND original_platform_owner_id=requested_owner
  AND original_platform_session_id=requested_platform_session FOR UPDATE;
 IF current_version IS DISTINCT FROM requested_expected THEN RAISE EXCEPTION 'Owned MCP registry version conflict' USING ERRCODE='55000'; END IF;
 IF (SELECT count(*) FROM secureshop_agents.bound_mcp_registry_operations WHERE platform_launch_id=requested_launch AND platform_scenario_id=requested_scenario
  AND platform_launch_generation=requested_generation AND original_platform_owner_id=requested_owner AND original_platform_session_id=requested_platform_session)>=256
  OR (SELECT count(*) FROM secureshop_agents.bound_mcp_registry_operations WHERE platform_launch_id=requested_launch AND platform_scenario_id=requested_scenario
  AND platform_launch_generation=requested_generation AND original_platform_owner_id=requested_owner AND original_platform_session_id=requested_platform_session AND state='admitted')>=8
 THEN RAISE EXCEPTION 'Owned MCP registry quota exceeded' USING ERRCODE='55000'; END IF;
 INSERT INTO secureshop_agents.bound_mcp_registry_operations(platform_launch_id,platform_scenario_id,platform_launch_generation,original_platform_owner_id,original_platform_session_id,
  operation_id,persona_id,persona_session_id,persona_role,authority_version,mode,action,expected_version,request_sha256,binding_sha256,worker_token,state,request_json)
 VALUES(requested_launch,requested_scenario,requested_generation,requested_owner,requested_platform_session,requested_operation,requested_persona,
  requested_persona_session,'admin',requested_authority,requested_mode,requested_action,requested_expected,requested_request,requested_binding,requested_worker,'admitted',requested_json)
 RETURNING * INTO prior; RETURN NEXT prior;
END $$;

-- Publication remains a narrow security-definer API. The runtime role cannot
-- insert revisions, rewrite heads or manufacture terminal journal rows itself.
CREATE FUNCTION secureshop_agents.publish_owned_mcp_registry_operation(
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
 FOR item IN SELECT value FROM jsonb_array_elements(requested_changes) LOOP
  IF jsonb_typeof(item) IS DISTINCT FROM 'object' OR NOT (item ?& ARRAY['name','entryId','action','transport','endpoint','schemaSha256','tools','effect'])
   OR item-ARRAY['name','entryId','action','transport','endpoint','schemaSha256','tools','effect']<>'{}'::jsonb
   OR jsonb_typeof(item->'name') IS DISTINCT FROM 'string' OR octet_length(item->>'name') NOT BETWEEN 1 AND 256
   OR jsonb_typeof(item->'entryId') IS DISTINCT FROM 'string' OR NOT (item->>'entryId' ~ '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')
   OR jsonb_typeof(item->'action') IS DISTINCT FROM 'string' OR item->>'action' NOT IN ('register','import','retire')
   OR (op.action='register' AND item->>'action'<>'register') OR (op.action='retire' AND item->>'action'<>'retire')
   OR (op.action='import' AND item->>'action'<>'import') THEN RAISE EXCEPTION 'Owned MCP revision invalid' USING ERRCODE='55000'; END IF;
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

CREATE FUNCTION secureshop_agents.finish_owned_mcp_registry_operation(
 requested_launch uuid, requested_scenario uuid, requested_generation bigint, requested_owner integer, requested_platform_session integer,
 requested_operation uuid, requested_worker uuid, requested_request bytea, requested_binding bytea, requested_state text, requested_audit uuid)
RETURNS SETOF secureshop_agents.bound_mcp_registry_operations
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE op secureshop_agents.bound_mcp_registry_operations%ROWTYPE;
BEGIN
 IF requested_operation IS NULL OR requested_worker IS NULL OR requested_request IS NULL OR requested_binding IS NULL OR requested_audit IS NULL
  OR requested_state IS NULL OR requested_state NOT IN ('failed','unknown') OR octet_length(requested_request)<>32 OR octet_length(requested_binding)<>32
 THEN RAISE EXCEPTION 'Owned MCP terminal transition invalid' USING ERRCODE='55000'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||requested_owner::text,0));
 PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-conversation-admission:'||requested_launch::text,0));
 SELECT * INTO op FROM secureshop_agents.bound_mcp_registry_operations WHERE platform_launch_id=requested_launch
  AND platform_scenario_id=requested_scenario AND platform_launch_generation=requested_generation AND original_platform_owner_id=requested_owner
  AND original_platform_session_id=requested_platform_session AND operation_id=requested_operation FOR UPDATE;
 IF op.operation_id IS NULL OR op.worker_token IS DISTINCT FROM requested_worker OR op.request_sha256 IS DISTINCT FROM requested_request
  OR op.binding_sha256 IS DISTINCT FROM requested_binding THEN RAISE EXCEPTION 'Owned MCP terminal mismatch' USING ERRCODE='55000'; END IF;
 IF op.state=requested_state THEN RETURN NEXT op; RETURN; END IF;
 IF op.state<>'admitted' THEN RAISE EXCEPTION 'Owned MCP operation terminal' USING ERRCODE='55000'; END IF;
 PERFORM secureshop_agents.assert_owned_mcp_registry_actor_current(requested_launch,requested_scenario,requested_generation,requested_owner,requested_platform_session,op.persona_id,op.persona_session_id,op.authority_version);
 UPDATE secureshop_agents.bound_mcp_registry_operations SET state=requested_state,completed_at=clock_timestamp() WHERE platform_launch_id=requested_launch
  AND platform_scenario_id=requested_scenario AND platform_launch_generation=requested_generation AND original_platform_owner_id=requested_owner
  AND original_platform_session_id=requested_platform_session AND operation_id=requested_operation RETURNING * INTO op;
 INSERT INTO secureshop_agents.bound_audit_events(event_id,launch_id,scenario_id,generation,original_platform_owner_id,original_platform_session_id,
  shop_user_id,shop_role,actor,action,target,params_json,outcome,source_kind,source_id)
 VALUES(requested_audit,requested_launch,requested_scenario,requested_generation,requested_owner,requested_platform_session,op.persona_id,'admin',
  'admin','mcp_registry_'||op.action,'mcp-registry',jsonb_build_object('operationId',requested_operation,'state',requested_state)::text,
  CASE WHEN requested_state='failed' THEN 'failed' ELSE 'denied' END,'bound_mcp_registry_operation',requested_operation::text);
 RETURN NEXT op;
END $$;

CREATE FUNCTION secureshop_agents.cleanup_owned_mcp_registry() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE n integer:=0; m integer:=0; k integer; id uuid; kind text; l uuid; g bigint;
BEGIN
 IF TG_TABLE_NAME='conversation_generation_retirements' THEN
  id:=NEW.reset_id;kind:='retirement';l:=NEW.platform_launch_id;g:=NEW.from_generation;
  DELETE FROM secureshop_agents.bound_mcp_registry_entries WHERE platform_launch_id=l AND platform_scenario_id=NEW.platform_scenario_id
   AND platform_launch_generation=g AND original_platform_owner_id=NEW.original_platform_owner_id AND original_platform_session_id=NEW.original_platform_session_id; GET DIAGNOSTICS n=ROW_COUNT;
  UPDATE secureshop_agents.bound_mcp_registry_revisions SET endpoint_text=NULL,tools_json=NULL,effect_json=NULL,redacted_at=clock_timestamp()
   WHERE platform_launch_id=l AND platform_scenario_id=NEW.platform_scenario_id AND platform_launch_generation=g
   AND original_platform_owner_id=NEW.original_platform_owner_id AND original_platform_session_id=NEW.original_platform_session_id AND redacted_at IS NULL; GET DIAGNOSTICS k=ROW_COUNT;
  UPDATE secureshop_agents.bound_mcp_registry_operations SET request_json=NULL,receipt_json=NULL,redacted_at=clock_timestamp() WHERE platform_launch_id=l AND platform_launch_generation=g
   AND original_platform_owner_id=NEW.original_platform_owner_id AND original_platform_session_id=NEW.original_platform_session_id; GET DIAGNOSTICS m=ROW_COUNT;
  m:=m+k;
 ELSE
  id:=NEW.deletion_job_id;kind:='owner_deletion';
  DELETE FROM secureshop_agents.bound_mcp_registry_entries WHERE original_platform_owner_id=NEW.original_platform_owner_id; GET DIAGNOSTICS n=ROW_COUNT;
  DELETE FROM secureshop_agents.bound_mcp_registry_operations WHERE original_platform_owner_id=NEW.original_platform_owner_id; GET DIAGNOSTICS m=ROW_COUNT;
  DELETE FROM secureshop_agents.bound_mcp_registry_revisions WHERE original_platform_owner_id=NEW.original_platform_owner_id;
  DELETE FROM secureshop_agents.bound_mcp_registry_heads WHERE original_platform_owner_id=NEW.original_platform_owner_id;
 END IF;
 INSERT INTO secureshop_agents.bound_mcp_registry_cleanup_receipts VALUES(id,kind,NEW.original_platform_owner_id,l,g,n,m,
  sha256(convert_to(jsonb_build_array('owned-mcp-registry-cleanup-v1',id,kind,NEW.original_platform_owner_id,l,g,n,m)::text,'UTF8')));
 RETURN NEW;
END $$;
CREATE TRIGGER owned_mcp_registry_retirement AFTER INSERT ON secureshop_agents.conversation_generation_retirements
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.cleanup_owned_mcp_registry();
CREATE TRIGGER owned_mcp_registry_owner_delete AFTER INSERT ON secureshop_agents.bound_audit_owner_deletion_receipts
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.cleanup_owned_mcp_registry();

REVOKE ALL ON secureshop_agents.bound_mcp_registry_heads,secureshop_agents.bound_mcp_registry_entries,
 secureshop_agents.bound_mcp_registry_revisions,secureshop_agents.bound_mcp_registry_operations,
 secureshop_agents.bound_mcp_registry_cleanup_receipts FROM PUBLIC,dvaia_secureshop_agents_runtime;
GRANT SELECT ON secureshop_agents.bound_mcp_registry_heads,secureshop_agents.bound_mcp_registry_entries,
 secureshop_agents.bound_mcp_registry_revisions,secureshop_agents.bound_mcp_registry_operations,
 secureshop_agents.bound_mcp_registry_cleanup_receipts TO dvaia_secureshop_agents_runtime;
REVOKE ALL ON FUNCTION secureshop_agents.guard_owned_mcp_registry_immutable(),secureshop_agents.cleanup_owned_mcp_registry(),
 secureshop_agents.owned_mcp_registry_request_digest(jsonb) FROM PUBLIC,dvaia_secureshop_agents_runtime;
REVOKE ALL ON FUNCTION secureshop_agents.assert_owned_mcp_registry_actor_current(uuid,uuid,bigint,integer,integer,integer,uuid,bigint) FROM PUBLIC,dvaia_secureshop_agents_runtime;
REVOKE ALL ON FUNCTION secureshop_agents.admit_owned_mcp_registry_operation(uuid,uuid,bigint,integer,integer,uuid,integer,uuid,bigint,text,text,bigint,bytea,bytea,uuid,jsonb),
 secureshop_agents.publish_owned_mcp_registry_operation(uuid,uuid,bigint,integer,integer,uuid,uuid,bytea,bytea,jsonb,bytea,jsonb,uuid),
 secureshop_agents.finish_owned_mcp_registry_operation(uuid,uuid,bigint,integer,integer,uuid,uuid,bytea,bytea,text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_agents.admit_owned_mcp_registry_operation(uuid,uuid,bigint,integer,integer,uuid,integer,uuid,bigint,text,text,bigint,bytea,bytea,uuid,jsonb),
 secureshop_agents.publish_owned_mcp_registry_operation(uuid,uuid,bigint,integer,integer,uuid,uuid,bytea,bytea,jsonb,bytea,jsonb,uuid),
 secureshop_agents.finish_owned_mcp_registry_operation(uuid,uuid,bigint,integer,integer,uuid,uuid,bytea,bytea,text,uuid) TO dvaia_secureshop_agents_runtime;
REVOKE ALL ON FUNCTION secureshop_agents.cleanup_owned_mcp_registry() FROM PUBLIC,dvaia_secureshop_agents_runtime;
