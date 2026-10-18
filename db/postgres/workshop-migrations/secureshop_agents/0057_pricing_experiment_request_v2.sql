-- Admit the canonical closed Pricing v2 experiment request while retaining the v1 actor,
-- scene, quota, outcome and receipt guards from 0053. Applied migrations stay immutable.

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
  IF COALESCE((
    ((SELECT count(*) FROM jsonb_object_keys(NEW.request_json))=4
      AND NOT (NEW.request_json ? 'experiment'))
    OR ((SELECT count(*) FROM jsonb_object_keys(NEW.request_json))=5
      AND NEW.request_json->>'task'='pricing-strategy'
      AND CASE WHEN jsonb_typeof(NEW.request_json->'experiment')='object' THEN
        (SELECT count(*) FROM jsonb_object_keys(NEW.request_json->'experiment'))=2
        AND NEW.request_json->'experiment'->>'strategy' IN ('undercut','premium','bundle')
        AND jsonb_typeof(NEW.request_json->'experiment'->'durationDays')='number'
        AND NEW.request_json->'experiment'->>'durationDays' ~ '^([1-9]|[1-8][0-9]|90)$'
      ELSE FALSE END)
  ),FALSE)=FALSE OR jsonb_typeof(NEW.request_json->'message') IS DISTINCT FROM 'string' OR NEW.request_json->>'operationId' IS DISTINCT FROM NEW.operation_id::text OR octet_length(NEW.request_json->>'message') NOT BETWEEN 1 AND 8192 OR jsonb_typeof(NEW.request_json->'productId') IS DISTINCT FROM 'number' OR NOT (NEW.request_json->>'productId' ~ '^[1-9][0-9]{0,9}$') OR (NEW.request_json->>'productId')::numeric>2147483647 OR (CASE NEW.persona_role WHEN 'customer' THEN 'price-advisor' ELSE 'pricing-strategy' END) IS DISTINCT FROM NEW.request_json->>'task' THEN RAISE EXCEPTION 'Pricing request mismatch' USING ERRCODE='55000'; END IF;
 ELSE
  IF NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_pricing_admissions a WHERE a.platform_launch_id=NEW.platform_launch_id AND a.platform_scenario_id=NEW.platform_scenario_id AND a.platform_launch_generation=NEW.platform_launch_generation AND a.original_platform_owner_id=NEW.original_platform_owner_id AND a.original_platform_session_id=NEW.original_platform_session_id AND a.operation_id=NEW.operation_id AND a.run_id=NEW.run_id AND a.persona_id=NEW.persona_id AND a.persona_session_id=NEW.persona_session_id AND a.persona_role=NEW.persona_role AND a.authority_version=NEW.authority_version AND a.request_sha256=NEW.request_sha256 AND a.binding_sha256=NEW.binding_sha256 AND a.request_json IS NOT NULL AND a.target_id IS NOT NULL AND (NEW.state<>'completed' OR (NEW.receipt_json->>'targetId'=a.target_id::text AND NEW.receipt_json->>'version'='secureshop-pricing-execution.v1' AND NEW.receipt_json->>'operationId'=a.operation_id::text AND NEW.receipt_json->>'runId'=a.run_id::text AND NEW.receipt_json->>'requestSha256'=encode(a.request_sha256,'hex')))) OR (NEW.state='completed' AND NEW.receipt_json IS NULL) THEN RAISE EXCEPTION 'Pricing admission mismatch' USING ERRCODE='55000'; END IF;
 END IF;
 RETURN NEW;
END $$;

