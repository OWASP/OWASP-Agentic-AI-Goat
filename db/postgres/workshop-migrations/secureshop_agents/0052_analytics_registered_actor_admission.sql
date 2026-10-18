-- Admit a registered shop actor only through its current tenant membership.
-- Keep the original conversation, persona-session, credential and immutable
-- admission fences, including the three historical demonstration actors.
CREATE OR REPLACE FUNCTION secureshop_agents.guard_analytics_request_admission() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_OP='DELETE' THEN
  IF EXISTS(SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts WHERE original_platform_owner_id=OLD.platform_owner_id) THEN RETURN OLD; END IF;
  RAISE EXCEPTION 'Analytics request identity is immutable';
 END IF;
 IF TG_OP='INSERT' THEN
  IF NOT EXISTS(SELECT 1 FROM secureshop_agents.agent_sessions s WHERE s.id=NEW.session_id
   AND s.authority_mode='launch_bound' AND s.binding_state='active' AND s.conversation_purpose='secureshop_analytics'
   AND s.platform_launch_id=NEW.launch_id AND s.platform_scenario_id=NEW.scenario_id
   AND s.platform_launch_generation=NEW.generation AND s.original_platform_owner_id=NEW.platform_owner_id
   AND s.original_platform_session_id=NEW.platform_session_id AND s.user_id=NEW.persona_id AND s.role=NEW.role)
   THEN RAISE EXCEPTION 'Analytics conversation binding unavailable'; END IF;
  IF NEW.question IS NULL OR NEW.redacted_at IS NOT NULL THEN RAISE EXCEPTION 'New Analytics input required'; END IF;
  IF NEW.question_sha256<>encode(sha256(convert_to(NEW.question,'UTF8')),'hex') THEN RAISE EXCEPTION 'Analytics question digest mismatch'; END IF;
  IF NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_persona_sessions p
   JOIN secureshop_agents.bound_actor_identities actor ON actor.shop_user_id=p.shop_user_id
   LEFT JOIN secureshop_agents.bound_actor_tenant_memberships membership
    ON membership.tenant_owner_id=p.original_platform_owner_id
    AND membership.shop_user_id=p.shop_user_id
    AND membership.membership_version=p.bootstrap_membership_version
    AND membership.principal_id=actor.principal_id AND membership.is_active
   LEFT JOIN secureshop_agents.bound_persona_state st ON st.platform_launch_id=p.platform_launch_id AND st.platform_scenario_id=p.platform_scenario_id
    AND st.platform_launch_generation=p.platform_launch_generation AND st.original_platform_owner_id=p.original_platform_owner_id
    AND st.original_platform_session_id=p.original_platform_session_id AND st.shop_user_id=p.shop_user_id
   WHERE p.platform_launch_id=NEW.launch_id AND p.platform_scenario_id=NEW.scenario_id
   AND p.platform_launch_generation=NEW.generation AND p.original_platform_owner_id=NEW.platform_owner_id
   AND p.original_platform_session_id=NEW.platform_session_id AND p.shop_user_id=NEW.persona_id
   AND p.session_id=NEW.persona_session_id AND p.role=NEW.role AND p.revoked_at IS NULL AND p.expires_at>clock_timestamp()
   AND secureshop_agents.bound_actor_in_owner(p.shop_user_id,p.original_platform_owner_id,p.bootstrap_membership_version)
   AND (actor.principal_id IS NULL OR
    (p.standalone_principal_id=actor.principal_id AND p.standalone_session_id>0
     AND p.bootstrap_jti IS NOT NULL AND membership.principal_id IS NOT NULL))
   AND st.banned_at IS NULL AND COALESCE(st.effective_role,membership.role,actor.base_role)=NEW.role
   AND COALESCE(st.authority_version,1)=NEW.authority_version
   AND p.credential_version=COALESCE((SELECT c.credential_version FROM secureshop_agents.bound_persona_credentials c
    WHERE c.platform_launch_id=NEW.launch_id AND c.platform_scenario_id=NEW.scenario_id AND c.platform_launch_generation=NEW.generation
    AND c.original_platform_owner_id=NEW.platform_owner_id AND c.original_platform_session_id=NEW.platform_session_id
    AND c.shop_user_id=NEW.persona_id),1))
   THEN RAISE EXCEPTION 'Analytics original persona session unavailable'; END IF;
  RETURN NEW;
 END IF;
 IF (to_jsonb(NEW)-'question'-'redacted_at') IS DISTINCT FROM (to_jsonb(OLD)-'question'-'redacted_at')
  OR OLD.question IS NULL OR NEW.question IS NOT NULL OR NEW.redacted_at IS NULL
  OR NOT EXISTS(SELECT 1 FROM secureshop_agents.conversation_generation_retirements r WHERE r.platform_launch_id=OLD.launch_id AND r.platform_scenario_id=OLD.scenario_id AND r.from_generation=OLD.generation AND r.original_platform_owner_id=OLD.platform_owner_id AND r.original_platform_session_id=OLD.platform_session_id)
  THEN RAISE EXCEPTION 'Analytics request identity is immutable'; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION secureshop_agents.guard_analytics_request_admission() FROM PUBLIC,dvaia_secureshop_agents_runtime;
