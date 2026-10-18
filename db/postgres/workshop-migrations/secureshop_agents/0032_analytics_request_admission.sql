-- Unregistered candidate. Qualify lifecycle/grants/native recovery before promotion.
CREATE TABLE secureshop_agents.analytics_request_admissions (
 launch_id uuid NOT NULL,scenario_id uuid NOT NULL,generation bigint NOT NULL CHECK(generation>0),
 platform_owner_id integer NOT NULL CHECK(platform_owner_id>0),platform_session_id bigint NOT NULL CHECK(platform_session_id>0),
 persona_id integer NOT NULL CHECK(persona_id>0),role text NOT NULL CHECK(role IN ('merchant','admin')),
 request_id uuid NOT NULL,persona_session_id uuid NOT NULL,authority_version bigint NOT NULL CHECK(authority_version>0),
 session_id text NOT NULL REFERENCES secureshop_agents.agent_sessions(id),
 question_sha256 text NOT NULL CHECK(question_sha256 ~ '^[a-f0-9]{64}$'),
 question text CHECK(question IS NULL OR (octet_length(question)>0 AND octet_length(question)<=8192)),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),redacted_at timestamptz,
 PRIMARY KEY(launch_id,scenario_id,generation,platform_owner_id,platform_session_id,persona_id,role,request_id),
 UNIQUE(session_id,request_id),CHECK((question IS NULL)=(redacted_at IS NOT NULL))
);
CREATE FUNCTION secureshop_agents.guard_analytics_request_admission() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
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
   JOIN secureshop_agents.bound_persona_templates t ON t.shop_user_id=p.shop_user_id
   LEFT JOIN secureshop_agents.bound_persona_state st ON st.platform_launch_id=p.platform_launch_id AND st.platform_scenario_id=p.platform_scenario_id
    AND st.platform_launch_generation=p.platform_launch_generation AND st.original_platform_owner_id=p.original_platform_owner_id
    AND st.original_platform_session_id=p.original_platform_session_id AND st.shop_user_id=p.shop_user_id
   WHERE p.platform_launch_id=NEW.launch_id AND p.platform_scenario_id=NEW.scenario_id
   AND p.platform_launch_generation=NEW.generation AND p.original_platform_owner_id=NEW.platform_owner_id
   AND p.original_platform_session_id=NEW.platform_session_id AND p.shop_user_id=NEW.persona_id
   AND p.session_id=NEW.persona_session_id AND p.role=NEW.role AND p.revoked_at IS NULL AND p.expires_at>clock_timestamp()
   AND st.banned_at IS NULL AND COALESCE(st.effective_role,t.role)=NEW.role
   AND COALESCE(st.authority_version,1)=NEW.authority_version
   AND p.credential_version=COALESCE((SELECT c.credential_version FROM secureshop_agents.bound_persona_credentials c
    WHERE c.platform_launch_id=NEW.launch_id AND c.platform_scenario_id=NEW.scenario_id AND c.platform_launch_generation=NEW.generation
    AND c.original_platform_owner_id=NEW.platform_owner_id AND c.original_platform_session_id=NEW.platform_session_id AND c.shop_user_id=NEW.persona_id),1))
   THEN RAISE EXCEPTION 'Analytics original persona session unavailable'; END IF;
  RETURN NEW;
 END IF;
 IF (to_jsonb(NEW)-'question'-'redacted_at') IS DISTINCT FROM (to_jsonb(OLD)-'question'-'redacted_at')
  OR OLD.question IS NULL OR NEW.question IS NOT NULL OR NEW.redacted_at IS NULL
  OR NOT EXISTS(SELECT 1 FROM secureshop_agents.conversation_generation_retirements r WHERE r.platform_launch_id=OLD.launch_id AND r.platform_scenario_id=OLD.scenario_id AND r.from_generation=OLD.generation AND r.original_platform_owner_id=OLD.platform_owner_id AND r.original_platform_session_id=OLD.platform_session_id)
  THEN RAISE EXCEPTION 'Analytics request identity is immutable'; END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER analytics_request_admission_guard BEFORE INSERT OR UPDATE OR DELETE ON secureshop_agents.analytics_request_admissions
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_analytics_request_admission();
REVOKE ALL ON secureshop_agents.analytics_request_admissions FROM PUBLIC;
REVOKE ALL ON FUNCTION secureshop_agents.guard_analytics_request_admission() FROM PUBLIC;
GRANT SELECT,INSERT ON secureshop_agents.analytics_request_admissions TO dvaia_secureshop_agents_runtime;
-- Lifecycle triggers are the only redaction/deletion authority.
CREATE FUNCTION secureshop_agents.cleanup_analytics_request_admissions() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF TG_TABLE_NAME='conversation_generation_retirements' THEN
  UPDATE secureshop_agents.analytics_request_admissions SET question=NULL,redacted_at=clock_timestamp()
   WHERE launch_id=NEW.platform_launch_id AND scenario_id=NEW.platform_scenario_id AND generation=NEW.from_generation
   AND platform_owner_id=NEW.original_platform_owner_id AND platform_session_id=NEW.original_platform_session_id AND question IS NOT NULL;
 ELSE
  DELETE FROM secureshop_agents.analytics_request_admissions WHERE platform_owner_id=NEW.original_platform_owner_id;
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER analytics_request_retirement AFTER INSERT ON secureshop_agents.conversation_generation_retirements
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.cleanup_analytics_request_admissions();
CREATE TRIGGER analytics_request_owner_delete AFTER INSERT ON secureshop_agents.bound_audit_owner_deletion_receipts
 FOR EACH ROW EXECUTE FUNCTION secureshop_agents.cleanup_analytics_request_admissions();
REVOKE ALL ON FUNCTION secureshop_agents.cleanup_analytics_request_admissions() FROM PUBLIC,dvaia_secureshop_agents_runtime;
REVOKE ALL ON FUNCTION secureshop_agents.guard_analytics_request_admission() FROM dvaia_secureshop_agents_runtime;
-- No terminal status/result copy: secureshop_agents.turn_requests is authoritative.
