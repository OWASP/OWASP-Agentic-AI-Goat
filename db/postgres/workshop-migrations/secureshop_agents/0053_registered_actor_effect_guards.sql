-- Admit registered actors through their exact current tenant membership while retaining
-- each journal and registry function's original scope, role, quota and receipt checks.

CREATE OR REPLACE FUNCTION secureshop_agents.guard_system_config_actor() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_persona_sessions s
  JOIN secureshop_agents.bound_actor_identities actor ON actor.shop_user_id=s.shop_user_id
  LEFT JOIN secureshop_agents.bound_actor_tenant_memberships membership
   ON membership.tenant_owner_id=s.original_platform_owner_id
   AND membership.shop_user_id=s.shop_user_id
   AND membership.membership_version=s.bootstrap_membership_version
   AND membership.principal_id=actor.principal_id AND membership.is_active
  LEFT JOIN secureshop_agents.bound_persona_state st ON st.platform_launch_id=s.platform_launch_id AND st.platform_scenario_id=s.platform_scenario_id AND st.platform_launch_generation=s.platform_launch_generation AND st.original_platform_owner_id=s.original_platform_owner_id AND st.original_platform_session_id=s.original_platform_session_id AND st.shop_user_id=s.shop_user_id
  WHERE s.platform_launch_id=NEW.platform_launch_id AND s.platform_scenario_id=NEW.platform_scenario_id AND s.platform_launch_generation=NEW.platform_launch_generation AND s.original_platform_owner_id=NEW.original_platform_owner_id AND s.original_platform_session_id=NEW.original_platform_session_id
  AND s.shop_user_id=NEW.persona_id AND s.session_id=NEW.persona_session_id AND s.role=NEW.persona_role
  AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND secureshop_agents.bound_actor_in_owner(s.shop_user_id,
    s.original_platform_owner_id,s.bootstrap_membership_version)
   AND (actor.principal_id IS NULL OR
    (s.standalone_principal_id=actor.principal_id AND s.standalone_session_id>0
     AND s.bootstrap_jti IS NOT NULL AND membership.principal_id IS NOT NULL))
   AND st.banned_at IS NULL
  AND COALESCE(st.effective_role,membership.role,actor.base_role)=NEW.persona_role AND COALESCE(st.authority_version,1)=NEW.authority_version
  AND s.credential_version=COALESCE((SELECT c.credential_version FROM secureshop_agents.bound_persona_credentials c
   WHERE c.platform_launch_id=NEW.platform_launch_id AND c.platform_scenario_id=NEW.platform_scenario_id AND c.platform_launch_generation=NEW.platform_launch_generation AND c.original_platform_owner_id=NEW.original_platform_owner_id AND c.original_platform_session_id=NEW.original_platform_session_id AND c.shop_user_id=NEW.persona_id),1)) THEN
  RAISE EXCEPTION 'System config persona unavailable' USING ERRCODE='55000'; END IF;

 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(':','secureshop-system-config',NEW.platform_launch_id::text,NEW.platform_scenario_id::text,NEW.platform_launch_generation::text,NEW.original_platform_owner_id::text,NEW.original_platform_session_id::text),0));
 IF TG_TABLE_NAME='bound_system_config_admissions' THEN
  IF NEW.request_json IS NULL OR (SELECT count(*) FROM secureshop_agents.bound_system_config_admissions a WHERE a.platform_launch_id=NEW.platform_launch_id AND a.platform_scenario_id=NEW.platform_scenario_id AND a.platform_launch_generation=NEW.platform_launch_generation AND a.original_platform_owner_id=NEW.original_platform_owner_id AND a.original_platform_session_id=NEW.original_platform_session_id)>=32 THEN RAISE EXCEPTION 'System config admission quota' USING ERRCODE='55000'; END IF;
 ELSE
  IF NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_system_config_admissions a WHERE a.platform_launch_id=NEW.platform_launch_id AND a.platform_scenario_id=NEW.platform_scenario_id AND a.platform_launch_generation=NEW.platform_launch_generation AND a.original_platform_owner_id=NEW.original_platform_owner_id AND a.original_platform_session_id=NEW.original_platform_session_id AND a.operation_id=NEW.operation_id AND a.persona_id=NEW.persona_id AND a.persona_session_id=NEW.persona_session_id AND a.persona_role=NEW.persona_role AND a.authority_version=NEW.authority_version AND a.request_sha256=NEW.request_sha256 AND a.binding_sha256=NEW.binding_sha256 AND a.request_json IS NOT NULL) OR (NEW.state='completed' AND NEW.receipt_json IS NULL) THEN RAISE EXCEPTION 'System config admission mismatch' USING ERRCODE='55000'; END IF;
 END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION secureshop_agents.guard_system_diagnostic_actor() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_persona_sessions s
  JOIN secureshop_agents.bound_actor_identities actor ON actor.shop_user_id=s.shop_user_id
  LEFT JOIN secureshop_agents.bound_actor_tenant_memberships membership
   ON membership.tenant_owner_id=s.original_platform_owner_id
   AND membership.shop_user_id=s.shop_user_id
   AND membership.membership_version=s.bootstrap_membership_version
   AND membership.principal_id=actor.principal_id AND membership.is_active
  LEFT JOIN secureshop_agents.bound_persona_state st ON st.platform_launch_id=s.platform_launch_id AND st.platform_scenario_id=s.platform_scenario_id AND st.platform_launch_generation=s.platform_launch_generation AND st.original_platform_owner_id=s.original_platform_owner_id AND st.original_platform_session_id=s.original_platform_session_id AND st.shop_user_id=s.shop_user_id
  WHERE s.platform_launch_id=NEW.platform_launch_id AND s.platform_scenario_id=NEW.platform_scenario_id AND s.platform_launch_generation=NEW.platform_launch_generation AND s.original_platform_owner_id=NEW.original_platform_owner_id AND s.original_platform_session_id=NEW.original_platform_session_id
  AND s.shop_user_id=NEW.persona_id AND s.session_id=NEW.persona_session_id AND s.role=NEW.persona_role
  AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND secureshop_agents.bound_actor_in_owner(s.shop_user_id,
    s.original_platform_owner_id,s.bootstrap_membership_version)
   AND (actor.principal_id IS NULL OR
    (s.standalone_principal_id=actor.principal_id AND s.standalone_session_id>0
     AND s.bootstrap_jti IS NOT NULL AND membership.principal_id IS NOT NULL))
   AND st.banned_at IS NULL
  AND COALESCE(st.effective_role,membership.role,actor.base_role)=NEW.persona_role AND COALESCE(st.authority_version,1)=NEW.authority_version
  AND s.credential_version=COALESCE((SELECT c.credential_version FROM secureshop_agents.bound_persona_credentials c
   WHERE c.platform_launch_id=NEW.platform_launch_id AND c.platform_scenario_id=NEW.platform_scenario_id AND c.platform_launch_generation=NEW.platform_launch_generation AND c.original_platform_owner_id=NEW.original_platform_owner_id AND c.original_platform_session_id=NEW.original_platform_session_id AND c.shop_user_id=NEW.persona_id),1)) THEN
  RAISE EXCEPTION 'System diagnostic persona unavailable' USING ERRCODE='55000'; END IF;

 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(':','secureshop-system-diagnostic',NEW.platform_launch_id::text,NEW.platform_scenario_id::text,NEW.platform_launch_generation::text,NEW.original_platform_owner_id::text,NEW.original_platform_session_id::text),0));
 IF TG_TABLE_NAME='bound_system_diagnostic_admissions' THEN
  IF NEW.target_id IS NULL OR NEW.request_json IS NULL OR (SELECT count(*) FROM secureshop_agents.bound_system_diagnostic_admissions a WHERE a.platform_launch_id=NEW.platform_launch_id AND a.platform_scenario_id=NEW.platform_scenario_id AND a.platform_launch_generation=NEW.platform_launch_generation AND a.original_platform_owner_id=NEW.original_platform_owner_id AND a.original_platform_session_id=NEW.original_platform_session_id)>=128 THEN RAISE EXCEPTION 'System diagnostic admission quota' USING ERRCODE='55000'; END IF;
  IF (SELECT count(*) FROM secureshop_agents.bound_system_diagnostic_admissions a WHERE a.platform_launch_id=NEW.platform_launch_id AND a.platform_scenario_id=NEW.platform_scenario_id AND a.platform_launch_generation=NEW.platform_launch_generation AND a.original_platform_owner_id=NEW.original_platform_owner_id AND a.original_platform_session_id=NEW.original_platform_session_id AND a.persona_session_id=NEW.persona_session_id AND NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_system_diagnostic_outcomes o WHERE (o.platform_launch_id,o.platform_scenario_id,o.platform_launch_generation,o.original_platform_owner_id,o.original_platform_session_id,o.operation_id)=(a.platform_launch_id,a.platform_scenario_id,a.platform_launch_generation,a.original_platform_owner_id,a.original_platform_session_id,a.operation_id)))>=8 THEN RAISE EXCEPTION 'System diagnostic pending quota' USING ERRCODE='55000'; END IF;
  IF (SELECT count(*) FROM jsonb_object_keys(NEW.request_json))<>3 OR jsonb_typeof(NEW.request_json->'cmd_template') IS DISTINCT FROM 'string' OR jsonb_typeof(NEW.request_json->'args') IS DISTINCT FROM 'string' OR NEW.request_json->>'operationId' IS DISTINCT FROM NEW.operation_id::text OR octet_length(NEW.request_json->>'cmd_template')>8192 OR octet_length(NEW.request_json->>'args')>8192 THEN RAISE EXCEPTION 'System diagnostic request mismatch' USING ERRCODE='55000'; END IF;
 ELSE
  IF NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_system_diagnostic_admissions a WHERE a.platform_launch_id=NEW.platform_launch_id AND a.platform_scenario_id=NEW.platform_scenario_id AND a.platform_launch_generation=NEW.platform_launch_generation AND a.original_platform_owner_id=NEW.original_platform_owner_id AND a.original_platform_session_id=NEW.original_platform_session_id AND a.operation_id=NEW.operation_id AND a.persona_id=NEW.persona_id AND a.persona_session_id=NEW.persona_session_id AND a.persona_role=NEW.persona_role AND a.authority_version=NEW.authority_version AND a.request_sha256=NEW.request_sha256 AND a.binding_sha256=NEW.binding_sha256 AND a.request_json IS NOT NULL AND a.target_id IS NOT NULL AND (NEW.state<>'completed' OR (NEW.receipt_json->>'targetId'=a.target_id::text AND NEW.receipt_json->>'hostname'='system-diag-'||replace(a.target_id::text,'-','') AND NEW.receipt_json->>'version'='secureshop-owned-system-diagnostic-http.v1' AND NEW.receipt_json->'result'->>'operationId'=a.operation_id::text AND NEW.receipt_json->'result'->>'requestSha256'=encode(a.request_sha256,'hex')))) OR (NEW.state='completed' AND NEW.receipt_json IS NULL) THEN RAISE EXCEPTION 'System diagnostic admission mismatch' USING ERRCODE='55000'; END IF;
 END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION secureshop_agents.guard_pricing_actor() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_persona_sessions s
  JOIN secureshop_agents.bound_actor_identities actor ON actor.shop_user_id=s.shop_user_id
  LEFT JOIN secureshop_agents.bound_actor_tenant_memberships membership
   ON membership.tenant_owner_id=s.original_platform_owner_id
   AND membership.shop_user_id=s.shop_user_id
   AND membership.membership_version=s.bootstrap_membership_version
   AND membership.principal_id=actor.principal_id AND membership.is_active
  LEFT JOIN secureshop_agents.bound_persona_state st ON st.platform_launch_id=s.platform_launch_id AND st.platform_scenario_id=s.platform_scenario_id AND st.platform_launch_generation=s.platform_launch_generation AND st.original_platform_owner_id=s.original_platform_owner_id AND st.original_platform_session_id=s.original_platform_session_id AND st.shop_user_id=s.shop_user_id
  WHERE s.platform_launch_id=NEW.platform_launch_id AND s.platform_scenario_id=NEW.platform_scenario_id AND s.platform_launch_generation=NEW.platform_launch_generation AND s.original_platform_owner_id=NEW.original_platform_owner_id AND s.original_platform_session_id=NEW.original_platform_session_id
  AND s.shop_user_id=NEW.persona_id AND s.session_id=NEW.persona_session_id AND s.role=NEW.persona_role
  AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND secureshop_agents.bound_actor_in_owner(s.shop_user_id,
    s.original_platform_owner_id,s.bootstrap_membership_version)
   AND (actor.principal_id IS NULL OR
    (s.standalone_principal_id=actor.principal_id AND s.standalone_session_id>0
     AND s.bootstrap_jti IS NOT NULL AND membership.principal_id IS NOT NULL))
   AND st.banned_at IS NULL
  AND COALESCE(st.effective_role,membership.role,actor.base_role)=NEW.persona_role AND COALESCE(st.authority_version,1)=NEW.authority_version
  AND s.credential_version=COALESCE((SELECT c.credential_version FROM secureshop_agents.bound_persona_credentials c
   WHERE c.platform_launch_id=NEW.platform_launch_id AND c.platform_scenario_id=NEW.platform_scenario_id AND c.platform_launch_generation=NEW.platform_launch_generation AND c.original_platform_owner_id=NEW.original_platform_owner_id AND c.original_platform_session_id=NEW.original_platform_session_id AND c.shop_user_id=NEW.persona_id),1)) THEN
  RAISE EXCEPTION 'Pricing persona unavailable' USING ERRCODE='55000'; END IF;

 PERFORM pg_advisory_xact_lock(hashtextextended(concat_ws(':','secureshop-pricing',NEW.platform_launch_id::text,NEW.platform_scenario_id::text,NEW.platform_launch_generation::text,NEW.original_platform_owner_id::text,NEW.original_platform_session_id::text),0));
 IF TG_TABLE_NAME='bound_pricing_admissions' THEN
  IF NEW.target_id IS NULL OR NEW.request_json IS NULL OR NEW.target_snapshot_json IS NULL OR (SELECT count(*) FROM secureshop_agents.bound_pricing_admissions a WHERE a.platform_launch_id=NEW.platform_launch_id AND a.platform_scenario_id=NEW.platform_scenario_id AND a.platform_launch_generation=NEW.platform_launch_generation AND a.original_platform_owner_id=NEW.original_platform_owner_id AND a.original_platform_session_id=NEW.original_platform_session_id)>=128 THEN RAISE EXCEPTION 'Pricing admission quota' USING ERRCODE='55000'; END IF;
  IF (SELECT count(*) FROM secureshop_agents.bound_pricing_admissions a WHERE a.platform_launch_id=NEW.platform_launch_id AND a.platform_scenario_id=NEW.platform_scenario_id AND a.platform_launch_generation=NEW.platform_launch_generation AND a.original_platform_owner_id=NEW.original_platform_owner_id AND a.original_platform_session_id=NEW.original_platform_session_id AND a.persona_session_id=NEW.persona_session_id AND NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_pricing_outcomes o WHERE (o.platform_launch_id,o.platform_scenario_id,o.platform_launch_generation,o.original_platform_owner_id,o.original_platform_session_id,o.operation_id)=(a.platform_launch_id,a.platform_scenario_id,a.platform_launch_generation,a.original_platform_owner_id,a.original_platform_session_id,a.operation_id)))>=8 THEN RAISE EXCEPTION 'Pricing pending quota' USING ERRCODE='55000'; END IF;
  IF (SELECT count(*) FROM jsonb_object_keys(NEW.request_json))<>4 OR jsonb_typeof(NEW.request_json->'message') IS DISTINCT FROM 'string' OR NEW.request_json->>'operationId' IS DISTINCT FROM NEW.operation_id::text OR octet_length(NEW.request_json->>'message') NOT BETWEEN 1 AND 8192 OR jsonb_typeof(NEW.request_json->'productId') IS DISTINCT FROM 'number' OR NOT (NEW.request_json->>'productId' ~ '^[1-9][0-9]{0,9}$') OR (NEW.request_json->>'productId')::numeric>2147483647 OR (CASE NEW.persona_role WHEN 'customer' THEN 'price-advisor' ELSE 'pricing-strategy' END) IS DISTINCT FROM NEW.request_json->>'task' THEN RAISE EXCEPTION 'Pricing request mismatch' USING ERRCODE='55000'; END IF;
 ELSE
  IF NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_pricing_admissions a WHERE a.platform_launch_id=NEW.platform_launch_id AND a.platform_scenario_id=NEW.platform_scenario_id AND a.platform_launch_generation=NEW.platform_launch_generation AND a.original_platform_owner_id=NEW.original_platform_owner_id AND a.original_platform_session_id=NEW.original_platform_session_id AND a.operation_id=NEW.operation_id AND a.run_id=NEW.run_id AND a.persona_id=NEW.persona_id AND a.persona_session_id=NEW.persona_session_id AND a.persona_role=NEW.persona_role AND a.authority_version=NEW.authority_version AND a.request_sha256=NEW.request_sha256 AND a.binding_sha256=NEW.binding_sha256 AND a.request_json IS NOT NULL AND a.target_id IS NOT NULL AND (NEW.state<>'completed' OR (NEW.receipt_json->>'targetId'=a.target_id::text AND NEW.receipt_json->>'version'='secureshop-pricing-execution.v1' AND NEW.receipt_json->>'operationId'=a.operation_id::text AND NEW.receipt_json->>'runId'=a.run_id::text AND NEW.receipt_json->>'requestSha256'=encode(a.request_sha256,'hex')))) OR (NEW.state='completed' AND NEW.receipt_json IS NULL) THEN RAISE EXCEPTION 'Pricing admission mismatch' USING ERRCODE='55000'; END IF;
 END IF;
 RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION secureshop_agents.assert_owned_mcp_registry_actor_current(
 requested_launch uuid, requested_scenario uuid, requested_generation bigint, requested_owner integer, requested_platform_session integer,
 requested_persona integer, requested_persona_session uuid, requested_authority bigint)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$ BEGIN
 IF EXISTS(SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts WHERE original_platform_owner_id=requested_owner)
  OR EXISTS(SELECT 1 FROM secureshop_agents.conversation_generation_retirements WHERE platform_launch_id=requested_launch AND platform_scenario_id=requested_scenario AND from_generation=requested_generation AND original_platform_owner_id=requested_owner AND original_platform_session_id=requested_platform_session)
  OR NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_persona_sessions s
   JOIN secureshop_agents.bound_actor_identities actor ON actor.shop_user_id=s.shop_user_id
  LEFT JOIN secureshop_agents.bound_actor_tenant_memberships membership
   ON membership.tenant_owner_id=s.original_platform_owner_id
   AND membership.shop_user_id=s.shop_user_id
   AND membership.membership_version=s.bootstrap_membership_version
   AND membership.principal_id=actor.principal_id AND membership.is_active
   LEFT JOIN secureshop_agents.bound_persona_state st ON st.platform_launch_id=s.platform_launch_id AND st.platform_scenario_id=s.platform_scenario_id AND st.platform_launch_generation=s.platform_launch_generation AND st.original_platform_owner_id=s.original_platform_owner_id AND st.original_platform_session_id=s.original_platform_session_id AND st.shop_user_id=s.shop_user_id
   WHERE s.platform_launch_id=requested_launch AND s.platform_scenario_id=requested_scenario AND s.platform_launch_generation=requested_generation
   AND s.original_platform_owner_id=requested_owner AND s.original_platform_session_id=requested_platform_session
   AND s.shop_user_id=requested_persona AND s.session_id=requested_persona_session AND s.role='admin' AND s.revoked_at IS NULL
   AND s.expires_at>clock_timestamp() AND secureshop_agents.bound_actor_in_owner(s.shop_user_id,
    s.original_platform_owner_id,s.bootstrap_membership_version)
   AND (actor.principal_id IS NULL OR
    (s.standalone_principal_id=actor.principal_id AND s.standalone_session_id>0
     AND s.bootstrap_jti IS NOT NULL AND membership.principal_id IS NOT NULL))
   AND st.banned_at IS NULL AND COALESCE(st.effective_role,membership.role,actor.base_role)='admin'
   AND COALESCE(st.authority_version,1)=requested_authority
   AND s.credential_version=COALESCE((SELECT c.credential_version FROM secureshop_agents.bound_persona_credentials c
    WHERE c.platform_launch_id=requested_launch AND c.platform_scenario_id=requested_scenario AND c.platform_launch_generation=requested_generation
    AND c.original_platform_owner_id=requested_owner AND c.original_platform_session_id=requested_platform_session AND c.shop_user_id=requested_persona),1))
 THEN RAISE EXCEPTION 'Owned MCP authority unavailable' USING ERRCODE='55000'; END IF;
END $$;

CREATE OR REPLACE FUNCTION secureshop_agents.admit_owned_mcp_registry_operation(
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
   JOIN secureshop_agents.bound_actor_identities actor ON actor.shop_user_id=s.shop_user_id
  LEFT JOIN secureshop_agents.bound_actor_tenant_memberships membership
   ON membership.tenant_owner_id=s.original_platform_owner_id
   AND membership.shop_user_id=s.shop_user_id
   AND membership.membership_version=s.bootstrap_membership_version
   AND membership.principal_id=actor.principal_id AND membership.is_active
   LEFT JOIN secureshop_agents.bound_persona_state st ON st.platform_launch_id=s.platform_launch_id AND st.platform_scenario_id=s.platform_scenario_id AND st.platform_launch_generation=s.platform_launch_generation AND st.original_platform_owner_id=s.original_platform_owner_id AND st.original_platform_session_id=s.original_platform_session_id AND st.shop_user_id=s.shop_user_id
   WHERE s.platform_launch_id=requested_launch AND s.platform_scenario_id=requested_scenario AND s.platform_launch_generation=requested_generation
   AND s.original_platform_owner_id=requested_owner AND s.original_platform_session_id=requested_platform_session
   AND s.shop_user_id=requested_persona AND s.session_id=requested_persona_session AND s.role='admin' AND s.revoked_at IS NULL
   AND s.expires_at>clock_timestamp() AND secureshop_agents.bound_actor_in_owner(s.shop_user_id,
    s.original_platform_owner_id,s.bootstrap_membership_version)
   AND (actor.principal_id IS NULL OR
    (s.standalone_principal_id=actor.principal_id AND s.standalone_session_id>0
     AND s.bootstrap_jti IS NOT NULL AND membership.principal_id IS NOT NULL))
   AND st.banned_at IS NULL AND COALESCE(st.effective_role,membership.role,actor.base_role)='admin'
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

REVOKE ALL ON FUNCTION secureshop_agents.guard_system_config_actor(),
 secureshop_agents.guard_system_diagnostic_actor(),
 secureshop_agents.guard_pricing_actor(),
 secureshop_agents.assert_owned_mcp_registry_actor_current(uuid,uuid,bigint,integer,integer,integer,uuid,bigint)
 FROM PUBLIC,dvaia_secureshop_agents_runtime;
REVOKE ALL ON FUNCTION secureshop_agents.admit_owned_mcp_registry_operation(uuid,uuid,bigint,integer,integer,uuid,integer,uuid,bigint,text,text,bigint,bytea,bytea,uuid,jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_agents.admit_owned_mcp_registry_operation(uuid,uuid,bigint,integer,integer,uuid,integer,uuid,bigint,text,text,bigint,bytea,bytea,uuid,jsonb) TO dvaia_secureshop_agents_runtime;
