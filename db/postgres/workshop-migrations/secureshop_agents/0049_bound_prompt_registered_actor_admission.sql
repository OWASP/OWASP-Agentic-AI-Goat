-- The original prompt-policy guard admitted only demonstration templates.
-- Preserve its live persona, credential, role, and policy mutation fences while
-- admitting registered actors through their exact tenant membership mirror.
CREATE OR REPLACE FUNCTION secureshop_agents.guard_prompt_policy_actor() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
BEGIN
  IF TG_TABLE_NAME='bound_prompt_policy_operations' THEN
    IF TG_OP='UPDATE' AND NEW.result_json IS NULL THEN RETURN NEW; END IF;
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM secureshop_agents.bound_persona_sessions s
    JOIN secureshop_agents.bound_actor_identities actor
      ON actor.shop_user_id=s.shop_user_id
    LEFT JOIN secureshop_agents.bound_actor_tenant_memberships membership
      ON membership.tenant_owner_id=s.original_platform_owner_id
      AND membership.shop_user_id=s.shop_user_id
      AND membership.membership_version=s.bootstrap_membership_version
      AND membership.principal_id=actor.principal_id
      AND membership.is_active
    LEFT JOIN secureshop_agents.bound_persona_state state
      ON state.platform_launch_id=s.platform_launch_id
      AND state.platform_scenario_id=s.platform_scenario_id
      AND state.platform_launch_generation=s.platform_launch_generation
      AND state.original_platform_owner_id=s.original_platform_owner_id
      AND state.original_platform_session_id=s.original_platform_session_id
      AND state.shop_user_id=s.shop_user_id
    WHERE s.platform_launch_id=NEW.platform_launch_id
      AND s.platform_scenario_id=NEW.platform_scenario_id
      AND s.platform_launch_generation=NEW.platform_launch_generation
      AND s.original_platform_owner_id=NEW.original_platform_owner_id
      AND s.original_platform_session_id=NEW.original_platform_session_id
      AND s.shop_user_id=NEW.persona_id
      AND s.session_id=NEW.persona_session_id
      AND s.role=NEW.persona_role
      AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
      AND secureshop_agents.bound_actor_in_owner(s.shop_user_id,
        s.original_platform_owner_id,s.bootstrap_membership_version)
      AND (actor.principal_id IS NULL
        OR (s.standalone_principal_id=actor.principal_id
          AND s.standalone_session_id>0 AND s.bootstrap_jti IS NOT NULL
          AND membership.principal_id IS NOT NULL))
      AND state.banned_at IS NULL
      AND COALESCE(state.effective_role,membership.role,actor.base_role)=NEW.persona_role
      AND COALESCE(state.authority_version,1)=NEW.authority_version
      AND s.credential_version=COALESCE((
        SELECT credential.credential_version
        FROM secureshop_agents.bound_persona_credentials credential
        WHERE credential.platform_launch_id=NEW.platform_launch_id
          AND credential.platform_scenario_id=NEW.platform_scenario_id
          AND credential.platform_launch_generation=NEW.platform_launch_generation
          AND credential.original_platform_owner_id=NEW.original_platform_owner_id
          AND credential.original_platform_session_id=NEW.original_platform_session_id
          AND credential.shop_user_id=NEW.persona_id),1)
  ) THEN
    RAISE EXCEPTION 'Prompt policy persona unavailable' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION secureshop_agents.guard_prompt_policy_actor() FROM PUBLIC,dvaia_secureshop_agents_runtime;
