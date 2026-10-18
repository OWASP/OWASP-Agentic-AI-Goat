-- Shop assessment ownership is a principal within a tenant, never a platform
-- user surrogate. Launch, persona and model/effect provenance remain immutable.
CREATE TABLE secureshop_auth.assessment_objectives (
  objective_id text PRIMARY KEY, label text NOT NULL,
  is_enabled boolean NOT NULL DEFAULT false,catalog_active boolean NOT NULL DEFAULT true,
  qualification text NOT NULL,source_sha256 text NOT NULL CHECK(source_sha256~'^[a-f0-9]{64}$'),
  source_document jsonb NOT NULL,configuration_source text NOT NULL DEFAULT 'checked_in_default',
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE secureshop_auth.assessment_judgments (
  tenant_id uuid NOT NULL, principal_id uuid NOT NULL, evaluation_id uuid NOT NULL,
  shop_user_id integer NOT NULL, execution_json jsonb NOT NULL,
  workshop_key text NOT NULL DEFAULT 'secureshop_agent_security' CHECK(workshop_key='secureshop_agent_security'),
  objective_id text NOT NULL, family text NOT NULL, scenario text NOT NULL,
  rubric_version text NOT NULL, evidence_digest text NOT NULL CHECK(evidence_digest~'^[a-f0-9]{64}$'),
  run_id uuid NOT NULL, generation integer NOT NULL CHECK(generation>=0),
  mode text NOT NULL CHECK(mode IN ('vuln','fixed')), mode_stamp text NOT NULL,
  packet text, judge_version text, owner_key text NOT NULL, owner_generation bigint NOT NULL,
  verdict text CHECK(verdict IN ('pass','fail','inconclusive','unavailable')),
  disposition text, result_json jsonb, result_digest text, judge_observations jsonb,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(), evaluated_at timestamptz,
  PRIMARY KEY(tenant_id,principal_id,evaluation_id),
  FOREIGN KEY(tenant_id,principal_id) REFERENCES secureshop_auth.tenant_memberships(tenant_id,principal_id),
  FOREIGN KEY(objective_id) REFERENCES secureshop_auth.assessment_objectives(objective_id),
  CHECK(packet IS NULL OR octet_length(packet)<=2097152),
  CHECK((verdict IS NULL AND disposition IS NULL AND result_json IS NULL AND result_digest IS NULL AND evaluated_at IS NULL)
    OR (verdict IS NOT NULL AND disposition IS NOT NULL AND result_json IS NOT NULL
      AND result_digest~'^[a-f0-9]{64}$' AND evaluated_at IS NOT NULL))
);
CREATE TABLE secureshop_auth.assessment_completions (
  tenant_id uuid NOT NULL,principal_id uuid NOT NULL,objective_id text NOT NULL,
  generation integer NOT NULL,evaluation_id uuid NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(tenant_id,principal_id,objective_id,generation),
  FOREIGN KEY(tenant_id,principal_id,evaluation_id) REFERENCES secureshop_auth.assessment_judgments(tenant_id,principal_id,evaluation_id)
);
CREATE TABLE secureshop_auth.assessment_contributions (
  tenant_id uuid NOT NULL,principal_id uuid NOT NULL,evaluation_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(tenant_id,principal_id,evaluation_id),
  FOREIGN KEY(tenant_id,principal_id,evaluation_id) REFERENCES secureshop_auth.assessment_judgments(tenant_id,principal_id,evaluation_id)
);
CREATE TABLE secureshop_auth.assessment_retries (
  tenant_id uuid NOT NULL,principal_id uuid NOT NULL,parent_id uuid NOT NULL,child_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(tenant_id,principal_id,parent_id),UNIQUE(tenant_id,principal_id,child_id),
  FOREIGN KEY(tenant_id,principal_id,parent_id) REFERENCES secureshop_auth.assessment_judgments(tenant_id,principal_id,evaluation_id),
  FOREIGN KEY(tenant_id,principal_id,child_id) REFERENCES secureshop_auth.assessment_judgments(tenant_id,principal_id,evaluation_id)
);
CREATE FUNCTION secureshop_auth.guard_assessment_history() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,secureshop_auth AS $$
BEGIN
  IF TG_OP='DELETE' OR TG_TABLE_NAME<>'assessment_judgments' THEN
    RAISE EXCEPTION 'Shop assessment history is immutable' USING ERRCODE='55000';
  END IF;
  IF OLD.verdict IS NOT NULL OR NEW.verdict IS NULL OR
    (to_jsonb(NEW)-ARRAY['verdict','disposition','result_json','result_digest','evaluated_at','judge_observations'])
    IS DISTINCT FROM (to_jsonb(OLD)-ARRAY['verdict','disposition','result_json','result_digest','evaluated_at','judge_observations']) THEN
    RAISE EXCEPTION 'Shop assessment binding is immutable' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER assessment_judgment_history BEFORE UPDATE OR DELETE ON secureshop_auth.assessment_judgments
  FOR EACH ROW EXECUTE FUNCTION secureshop_auth.guard_assessment_history();
CREATE TRIGGER assessment_completion_history BEFORE UPDATE OR DELETE ON secureshop_auth.assessment_completions
  FOR EACH ROW EXECUTE FUNCTION secureshop_auth.guard_assessment_history();
CREATE TRIGGER assessment_contribution_history BEFORE UPDATE OR DELETE ON secureshop_auth.assessment_contributions
  FOR EACH ROW EXECUTE FUNCTION secureshop_auth.guard_assessment_history();
CREATE TRIGGER assessment_retry_history BEFORE UPDATE OR DELETE ON secureshop_auth.assessment_retries
  FOR EACH ROW EXECUTE FUNCTION secureshop_auth.guard_assessment_history();
REVOKE ALL ON secureshop_auth.assessment_judgments,secureshop_auth.assessment_completions,
  secureshop_auth.assessment_contributions,secureshop_auth.assessment_retries FROM PUBLIC;
GRANT SELECT,INSERT ON secureshop_auth.assessment_judgments,secureshop_auth.assessment_completions,
  secureshop_auth.assessment_contributions,secureshop_auth.assessment_retries TO dvaia_identity_runtime;
GRANT UPDATE(verdict,disposition,result_json,result_digest,evaluated_at,judge_observations)
  ON secureshop_auth.assessment_judgments TO dvaia_identity_runtime;
REVOKE ALL ON FUNCTION secureshop_auth.guard_assessment_history() FROM PUBLIC;
REVOKE ALL ON secureshop_auth.assessment_objectives FROM PUBLIC;
GRANT SELECT ON secureshop_auth.assessment_objectives TO dvaia_identity_runtime;

-- Defaults are shared source material; an administrator's choice is tenant-local.
CREATE TABLE secureshop_auth.assessment_configuration (
 tenant_id uuid NOT NULL REFERENCES secureshop_auth.tenants(tenant_id),
 objective_id text NOT NULL REFERENCES secureshop_auth.assessment_objectives(objective_id),
 is_enabled boolean NOT NULL,revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
 updated_by uuid NOT NULL REFERENCES secureshop_auth.principals(principal_id),
 updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,objective_id)
);
CREATE TABLE secureshop_auth.assessment_configuration_history (
 tenant_id uuid NOT NULL,objective_id text NOT NULL,revision bigint NOT NULL,
 is_enabled boolean NOT NULL,principal_id uuid NOT NULL,execution_session_id integer NOT NULL,
 changed_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(tenant_id,objective_id,revision)
);
CREATE TRIGGER assessment_configuration_history_guard BEFORE UPDATE OR DELETE ON secureshop_auth.assessment_configuration_history
 FOR EACH ROW EXECUTE FUNCTION secureshop_auth.guard_assessment_history();
REVOKE ALL ON secureshop_auth.assessment_configuration,secureshop_auth.assessment_configuration_history FROM PUBLIC;
GRANT SELECT ON secureshop_auth.assessment_configuration,secureshop_auth.assessment_configuration_history TO dvaia_identity_runtime;
CREATE FUNCTION secureshop_auth.set_assessment_objective(requested_session integer,requested_tenant uuid,
 requested_principal uuid,requested_objective text,requested_enabled boolean,expected_revision bigint)
RETURNS TABLE(objective_id text,is_enabled boolean,qualification text,revision text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_auth AS $$
DECLARE item secureshop_auth.assessment_objectives; prior bigint;
BEGIN
 IF expected_revision IS NULL OR expected_revision<1 OR requested_enabled IS NULL THEN
  RAISE EXCEPTION 'Invalid objective setting' USING ERRCODE='22023'; END IF;
 PERFORM 1 FROM secureshop_auth.execution_sessions e
 JOIN secureshop_auth.sessions s ON s.session_id=e.auth_session_id
 JOIN secureshop_auth.principals p ON p.principal_id=e.principal_id AND p.principal_id=s.principal_id
 JOIN secureshop_auth.tenant_memberships m ON m.tenant_id=e.tenant_id AND m.principal_id=e.principal_id
 JOIN secureshop_auth.tenants t ON t.tenant_id=e.tenant_id
 WHERE e.session_id=requested_session AND e.tenant_id=requested_tenant AND e.principal_id=requested_principal
 AND e.revoked_at IS NULL AND s.revoked_at IS NULL AND e.expires_at>clock_timestamp() AND s.expires_at>clock_timestamp()
 AND p.is_active AND p.role='admin' AND m.role='admin' AND m.is_active AND t.is_active
 AND (p.locked_until IS NULL OR p.locked_until<=clock_timestamp())
 AND s.credential_version=p.credential_version AND s.authority_version=p.authority_version
 AND e.membership_version=m.membership_version FOR SHARE OF e,s,p,m,t;
 IF NOT FOUND THEN RAISE EXCEPTION 'Shop administrator required' USING ERRCODE='28000'; END IF;
 SELECT * INTO item FROM secureshop_auth.assessment_objectives o WHERE o.objective_id=requested_objective AND o.catalog_active;
 IF NOT FOUND OR (requested_enabled AND item.qualification NOT IN ('native-model','native-browser-judge')) THEN
  RAISE EXCEPTION 'Objective is not qualified' USING ERRCODE='22023'; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('shop-objective:'||requested_tenant::text||':'||requested_objective,0));
 SELECT c.revision INTO prior FROM secureshop_auth.assessment_configuration c
 WHERE c.tenant_id=requested_tenant AND c.objective_id=requested_objective FOR UPDATE;
 IF COALESCE(prior,1)<>expected_revision THEN RAISE EXCEPTION 'Objective revision changed' USING ERRCODE='40001'; END IF;
 INSERT INTO secureshop_auth.assessment_configuration(tenant_id,objective_id,is_enabled,revision,updated_by)
 VALUES(requested_tenant,requested_objective,requested_enabled,expected_revision+1,requested_principal)
 ON CONFLICT ON CONSTRAINT assessment_configuration_pkey DO UPDATE SET is_enabled=EXCLUDED.is_enabled,revision=EXCLUDED.revision,
 updated_by=EXCLUDED.updated_by,updated_at=clock_timestamp();
 INSERT INTO secureshop_auth.assessment_configuration_history(tenant_id,objective_id,revision,is_enabled,principal_id,execution_session_id)
 VALUES(requested_tenant,requested_objective,expected_revision+1,requested_enabled,requested_principal,requested_session);
 RETURN QUERY SELECT requested_objective,requested_enabled,item.qualification,(expected_revision+1)::text;
END $$;
REVOKE ALL ON FUNCTION secureshop_auth.set_assessment_objective(integer,uuid,uuid,text,boolean,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_auth.set_assessment_objective(integer,uuid,uuid,text,boolean,bigint) TO dvaia_identity_runtime;

CREATE FUNCTION secureshop_auth.lock_assessment_mode(requested_session integer,requested_tenant uuid,requested_principal uuid)
RETURNS TABLE(mode text,generation integer,revision text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_auth AS $$
BEGIN
 PERFORM 1 FROM secureshop_auth.execution_authority_state e WHERE e.session_id=requested_session
 AND e.tenant_id=requested_tenant AND e.principal_id=requested_principal
 AND e.is_active=1 AND e.expires_at>clock_timestamp();
 IF NOT FOUND THEN RAISE EXCEPTION 'Shop execution unavailable' USING ERRCODE='28000'; END IF;
 RETURN QUERY SELECT m.mode,m.generation,m.revision::text FROM secureshop_auth.tenant_modes m
 WHERE m.tenant_id=requested_tenant AND m.principal_id=requested_principal FOR SHARE OF m;
END $$;
REVOKE ALL ON FUNCTION secureshop_auth.lock_assessment_mode(integer,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_auth.lock_assessment_mode(integer,uuid,uuid) TO dvaia_identity_runtime;
