-- Retain exact failed turns. A future prompt-admission rejection is attested
-- before any tool/model execution; older uncertain turns remain unresolved.
CREATE TABLE secureshop_agents.bound_mail_thread_attempts (
  session_id text NOT NULL,
  request_id uuid NOT NULL,
  claim_id uuid NOT NULL,
  request_hash text NOT NULL CHECK (request_hash ~ '^[a-f0-9]{64}$'),
  run_id uuid NOT NULL,
  target_id uuid NOT NULL REFERENCES secureshop_agents.persona_inbox_targets(target_id),
  persona_id integer NOT NULL CHECK (persona_id>0),
  persona_session_id uuid NOT NULL,
  authority_version bigint NOT NULL CHECK (authority_version>0),
  thread_id bigint NOT NULL CHECK (thread_id BETWEEN 1 AND 2147483647),
  mode text NOT NULL CHECK (mode IN ('vuln','fixed')),
  blocked boolean NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(session_id,request_id),
  FOREIGN KEY(session_id,request_id) REFERENCES secureshop_agents.turn_requests(session_id,request_id)
);
CREATE INDEX bound_mail_thread_attempts_thread
  ON secureshop_agents.bound_mail_thread_attempts(target_id,persona_id,thread_id,created_at);

CREATE TABLE secureshop_agents.bound_mail_preexecution_rejections (
  session_id text NOT NULL,
  request_id uuid NOT NULL,
  claim_id uuid NOT NULL,
  request_hash text NOT NULL CHECK (request_hash ~ '^[a-f0-9]{64}$'),
  run_id uuid NOT NULL,
  target_id uuid NOT NULL,
  persona_id integer NOT NULL CHECK (persona_id>0),
  thread_id bigint NOT NULL CHECK (thread_id BETWEEN 1 AND 2147483647),
  mode text NOT NULL CHECK (mode IN ('vuln','fixed')),
  stage text NOT NULL CHECK (stage IN ('thread_admission','prompt_policy_admission')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(session_id,request_id),
  FOREIGN KEY(session_id,request_id) REFERENCES secureshop_agents.bound_mail_thread_attempts(session_id,request_id)
);

CREATE TABLE secureshop_agents.bound_mail_unresolved_detaches (
  session_id text NOT NULL,
  request_id uuid NOT NULL,
  claim_id uuid NOT NULL,
  request_hash text NOT NULL CHECK (request_hash ~ '^[a-f0-9]{64}$'),
  target_id uuid NOT NULL REFERENCES secureshop_agents.persona_inbox_targets(target_id),
  persona_id integer NOT NULL CHECK (persona_id>0),
  persona_session_id uuid NOT NULL,
  authority_version bigint NOT NULL CHECK (authority_version>0),
  thread_id bigint NOT NULL CHECK (thread_id BETWEEN 1 AND 2147483647),
  mode text NOT NULL CHECK (mode IN ('vuln','fixed')),
  send_operation_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(session_id,request_id),
  FOREIGN KEY(session_id,request_id) REFERENCES secureshop_agents.turn_requests(session_id,request_id)
);
CREATE INDEX bound_mail_unresolved_detaches_thread
  ON secureshop_agents.bound_mail_unresolved_detaches(target_id,persona_id,thread_id);

CREATE FUNCTION secureshop_agents.bound_mail_live_actor(
  requested_launch uuid,requested_scenario uuid,requested_generation bigint,
  requested_owner integer,requested_platform_session integer,requested_persona integer,
  requested_persona_session uuid,requested_role text,requested_authority_version bigint)
RETURNS boolean LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
 SELECT EXISTS (
   SELECT 1 FROM secureshop_agents.bound_persona_sessions s
   JOIN secureshop_agents.bound_actor_identities actor
     ON actor.shop_user_id=s.shop_user_id
   LEFT JOIN secureshop_agents.bound_actor_tenant_memberships membership
     ON membership.tenant_owner_id=s.original_platform_owner_id
       AND membership.shop_user_id=s.shop_user_id
       AND membership.membership_version=s.bootstrap_membership_version
       AND membership.principal_id=actor.principal_id AND membership.is_active
   LEFT JOIN secureshop_agents.bound_persona_state state
     ON state.platform_launch_id=s.platform_launch_id
       AND state.platform_scenario_id=s.platform_scenario_id
       AND state.platform_launch_generation=s.platform_launch_generation
       AND state.original_platform_owner_id=s.original_platform_owner_id
       AND state.original_platform_session_id=s.original_platform_session_id
       AND state.shop_user_id=s.shop_user_id
   WHERE s.platform_launch_id=requested_launch
     AND s.platform_scenario_id=requested_scenario
     AND s.platform_launch_generation=requested_generation
     AND s.original_platform_owner_id=requested_owner
     AND s.original_platform_session_id=requested_platform_session
     AND s.shop_user_id=requested_persona
     AND s.session_id=requested_persona_session AND s.role=requested_role
     AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp()
     AND secureshop_agents.bound_actor_in_owner(s.shop_user_id,
       s.original_platform_owner_id,s.bootstrap_membership_version)
     AND (actor.principal_id IS NULL
       OR (s.standalone_principal_id=actor.principal_id
         AND s.standalone_session_id>0 AND s.bootstrap_jti IS NOT NULL
         AND membership.principal_id IS NOT NULL))
     AND state.banned_at IS NULL
     AND COALESCE(state.effective_role,membership.role,actor.base_role)=requested_role
     AND COALESCE(state.authority_version,1)=requested_authority_version
     AND s.credential_version=COALESCE((
       SELECT credential.credential_version
       FROM secureshop_agents.bound_persona_credentials credential
       WHERE credential.platform_launch_id=requested_launch
         AND credential.platform_scenario_id=requested_scenario
         AND credential.platform_launch_generation=requested_generation
         AND credential.original_platform_owner_id=requested_owner
         AND credential.original_platform_session_id=requested_platform_session
         AND credential.shop_user_id=requested_persona),1)
 )
$$;

CREATE FUNCTION secureshop_agents.guard_bound_mail_uncertain_receipt() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
BEGIN
  IF TG_OP<>'INSERT' THEN
    RAISE EXCEPTION 'Immutable mail uncertainty evidence' USING ERRCODE='55000';
  END IF;
  IF TG_TABLE_NAME='bound_mail_thread_attempts' THEN
    IF NOT EXISTS (
      SELECT 1 FROM secureshop_agents.turn_requests tr
      JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id
      JOIN secureshop_agents.persona_inbox_targets target ON target.target_id=NEW.target_id
      WHERE tr.session_id=NEW.session_id AND tr.request_id=NEW.request_id
        AND tr.claim_id=NEW.claim_id AND tr.request_hash=NEW.request_hash
        AND tr.status='started' AND s.conversation_purpose='secureshop_mail_reply'
        AND s.authority_mode='launch_bound' AND s.binding_state='active'
        AND s.user_id=NEW.persona_id
        AND target.launch_id=s.platform_launch_id AND target.scenario_id=s.platform_scenario_id
        AND target.generation=s.platform_launch_generation
        AND target.original_platform_owner_id=s.original_platform_owner_id
        AND target.original_platform_session_id=s.original_platform_session_id
        AND target.lifecycle='active'
        AND secureshop_agents.bound_mail_live_actor(s.platform_launch_id,
          s.platform_scenario_id,s.platform_launch_generation,
          s.original_platform_owner_id,s.original_platform_session_id,
          NEW.persona_id,NEW.persona_session_id,s.role,NEW.authority_version)
    ) THEN RAISE EXCEPTION 'Mail thread admission unavailable' USING ERRCODE='55000'; END IF;
  ELSIF TG_TABLE_NAME='bound_mail_preexecution_rejections' THEN
    IF NOT EXISTS (
      SELECT 1 FROM secureshop_agents.turn_requests tr
      JOIN secureshop_agents.bound_mail_thread_attempts attempt
        ON attempt.session_id=tr.session_id AND attempt.request_id=tr.request_id
      JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id
      WHERE tr.session_id=NEW.session_id AND tr.request_id=NEW.request_id
        AND tr.claim_id=NEW.claim_id AND tr.request_hash=NEW.request_hash
        AND tr.status='started' AND attempt.claim_id=NEW.claim_id
        AND attempt.request_hash=NEW.request_hash AND attempt.run_id=NEW.run_id
        AND attempt.target_id=NEW.target_id AND attempt.persona_id=NEW.persona_id
        AND attempt.thread_id=NEW.thread_id AND attempt.mode=NEW.mode
        AND attempt.blocked=(NEW.stage='thread_admission')
        AND secureshop_agents.bound_mail_live_actor(s.platform_launch_id,
          s.platform_scenario_id,s.platform_launch_generation,
          s.original_platform_owner_id,s.original_platform_session_id,
          attempt.persona_id,attempt.persona_session_id,s.role,attempt.authority_version)
    ) THEN RAISE EXCEPTION 'Mail rejection admission unavailable' USING ERRCODE='55000'; END IF;
  ELSIF TG_TABLE_NAME='bound_mail_unresolved_detaches' THEN
    IF NOT EXISTS (
      SELECT 1 FROM secureshop_agents.turn_requests tr
      JOIN secureshop_agents.agent_sessions s ON s.id=tr.session_id
      JOIN secureshop_agents.persona_inbox_targets target ON target.target_id=NEW.target_id
      WHERE tr.session_id=NEW.session_id AND tr.request_id=NEW.request_id
        AND tr.claim_id=NEW.claim_id AND tr.request_hash=NEW.request_hash
        AND tr.status='uncertain' AND s.conversation_purpose='secureshop_mail_reply'
        AND s.authority_mode='launch_bound' AND s.binding_state='active'
        AND s.user_id=NEW.persona_id
        AND target.launch_id=s.platform_launch_id AND target.scenario_id=s.platform_scenario_id
        AND target.generation=s.platform_launch_generation
        AND target.original_platform_owner_id=s.original_platform_owner_id
        AND target.original_platform_session_id=s.original_platform_session_id
        AND secureshop_agents.bound_mail_live_actor(s.platform_launch_id,
          s.platform_scenario_id,s.platform_launch_generation,
          s.original_platform_owner_id,s.original_platform_session_id,
          NEW.persona_id,NEW.persona_session_id,s.role,NEW.authority_version)
    ) THEN RAISE EXCEPTION 'Mail unresolved admission unavailable' USING ERRCODE='55000'; END IF;
  ELSE
    RAISE EXCEPTION 'Mail uncertainty table unavailable' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER bound_mail_thread_attempt_guard BEFORE INSERT OR UPDATE OR DELETE
  ON secureshop_agents.bound_mail_thread_attempts FOR EACH ROW
  EXECUTE FUNCTION secureshop_agents.guard_bound_mail_uncertain_receipt();
CREATE TRIGGER bound_mail_preexecution_guard BEFORE INSERT OR UPDATE OR DELETE
  ON secureshop_agents.bound_mail_preexecution_rejections FOR EACH ROW
  EXECUTE FUNCTION secureshop_agents.guard_bound_mail_uncertain_receipt();
CREATE TRIGGER bound_mail_unresolved_guard BEFORE INSERT OR UPDATE OR DELETE
  ON secureshop_agents.bound_mail_unresolved_detaches FOR EACH ROW
  EXECUTE FUNCTION secureshop_agents.guard_bound_mail_uncertain_receipt();
REVOKE ALL ON secureshop_agents.bound_mail_thread_attempts,
  secureshop_agents.bound_mail_preexecution_rejections,
  secureshop_agents.bound_mail_unresolved_detaches FROM PUBLIC;
GRANT SELECT,INSERT ON secureshop_agents.bound_mail_thread_attempts,
  secureshop_agents.bound_mail_preexecution_rejections,
  secureshop_agents.bound_mail_unresolved_detaches TO dvaia_secureshop_agents_runtime;
REVOKE ALL ON FUNCTION secureshop_agents.guard_bound_mail_uncertain_receipt()
  FROM PUBLIC,dvaia_secureshop_agents_runtime;
REVOKE ALL ON FUNCTION secureshop_agents.bound_mail_live_actor(
  uuid,uuid,bigint,integer,integer,integer,uuid,text,bigint)
  FROM PUBLIC,dvaia_secureshop_agents_runtime;
