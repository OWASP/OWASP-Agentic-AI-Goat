-- Standalone shop progress retires an exact launch generation. Evidence and
-- another execution's contributions remain immutable and independently usable.
CREATE TABLE secureshop_auth.assessment_cleanup_history (
 reset_id uuid PRIMARY KEY REFERENCES identity.secureshop_launch_resets(reset_id),
 launch_id uuid NOT NULL REFERENCES identity.secureshop_launches(launch_id),
 scenario_id uuid NOT NULL,from_generation bigint NOT NULL CHECK(from_generation>0),
 tenant_id uuid NOT NULL,principal_id uuid NOT NULL,
 original_owner_id integer NOT NULL,original_session_id integer NOT NULL,
 assessment_generation integer NOT NULL CHECK(assessment_generation>=0),
 retired_judgment_count integer NOT NULL CHECK(retired_judgment_count>=0),
 retired_contribution_count integer NOT NULL CHECK(retired_contribution_count>=0),
 projected_completion_count integer NOT NULL CHECK(projected_completion_count>=0),
 completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(launch_id,from_generation),
 FOREIGN KEY(tenant_id,principal_id) REFERENCES secureshop_auth.tenant_memberships(tenant_id,principal_id)
);
CREATE TRIGGER assessment_cleanup_history_immutable BEFORE UPDATE OR DELETE
 ON secureshop_auth.assessment_cleanup_history FOR EACH ROW
 EXECUTE FUNCTION secureshop_auth.guard_assessment_history();
REVOKE ALL ON secureshop_auth.assessment_cleanup_history FROM PUBLIC;
GRANT SELECT ON secureshop_auth.assessment_cleanup_history TO dvaia_identity_runtime;

CREATE VIEW secureshop_auth.active_assessment_contributions AS
 SELECT j.tenant_id,j.principal_id,j.objective_id,j.generation,j.evaluation_id,
   j.execution_json,j.created_at
 FROM secureshop_auth.assessment_contributions c
 JOIN secureshop_auth.assessment_judgments j USING(tenant_id,principal_id,evaluation_id)
 WHERE j.verdict='pass' AND j.disposition IN ('awarded','already_complete')
 AND NOT EXISTS(SELECT 1 FROM secureshop_auth.assessment_cleanup_history h
   WHERE h.tenant_id=j.tenant_id AND h.principal_id=j.principal_id
   AND j.execution_json->'scope'->>'launchId'=h.launch_id::text
   AND j.execution_json->'scope'->>'generation'=h.from_generation::text);
REVOKE ALL ON secureshop_auth.active_assessment_contributions FROM PUBLIC;
GRANT SELECT ON secureshop_auth.active_assessment_contributions TO dvaia_identity_runtime;

CREATE FUNCTION secureshop_auth.finalize_assessment_cleanup(requested_reset uuid)
RETURNS SETOF secureshop_auth.assessment_cleanup_history
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,identity,secureshop_auth AS $$
DECLARE coordinates identity.secureshop_launches;
DECLARE launch identity.secureshop_launches;
DECLARE operation identity.secureshop_launch_resets;
DECLARE prior secureshop_auth.assessment_cleanup_history;
DECLARE result secureshop_auth.assessment_cleanup_history;
DECLARE tenant uuid; DECLARE principal uuid; DECLARE mode_generation integer;
DECLARE judgments integer; DECLARE contributions integer; DECLARE projected integer;
BEGIN
 SELECT l.* INTO coordinates FROM identity.secureshop_launch_resets r
 JOIN identity.secureshop_launches l ON l.launch_id=r.launch_id WHERE r.reset_id=requested_reset;
 IF NOT FOUND THEN RAISE EXCEPTION 'Reset cleanup authority required' USING ERRCODE='55000'; END IF;
 -- Retained authority, not current authentication: recovery after revocation
 -- must finish cleanup, but cannot grant access or reactivate a launch.
 PERFORM 1 FROM identity.secureshop_authority_owners o
 WHERE o.id=coordinates.original_platform_owner_id AND o.realm='shop'
 AND o.shop_tenant_id IS NOT NULL FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Shop reset realm mismatch' USING ERRCODE='55000'; END IF;
 PERFORM 1 FROM identity.secureshop_authority_sessions s
 WHERE s.id=coordinates.original_platform_session_id AND s.user_id=coordinates.original_platform_owner_id
 AND s.realm='shop' AND s.shop_execution_session_id=s.id FOR SHARE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Shop reset session mismatch' USING ERRCODE='55000'; END IF;
 SELECT e.tenant_id,e.principal_id INTO tenant,principal FROM secureshop_auth.execution_sessions e
 JOIN secureshop_auth.tenants t ON t.tenant_id=e.tenant_id
 JOIN identity.secureshop_authority_owners o ON o.id=t.owner_id AND o.shop_tenant_id=t.tenant_id
 WHERE e.session_id=coordinates.original_platform_session_id AND t.owner_id=coordinates.original_platform_owner_id;
 IF NOT FOUND THEN RAISE EXCEPTION 'Shop reset execution mismatch' USING ERRCODE='55000'; END IF;
 SELECT * INTO launch FROM identity.secureshop_launches WHERE launch_id=coordinates.launch_id FOR UPDATE;
 SELECT * INTO operation FROM identity.secureshop_launch_resets
 WHERE reset_id=requested_reset AND launch_id=launch.launch_id FOR UPDATE;
 IF operation.reset_id IS NULL OR operation.status NOT IN ('fenced','committed','aborted') THEN
   RAISE EXCEPTION 'Reset cleanup authority required' USING ERRCODE='55000'; END IF;
 -- Grading takes this same row FOR SHARE after its launch lock. Do not bump
 -- mode/generation: another session's accepted contribution must survive.
 SELECT generation INTO mode_generation FROM secureshop_auth.tenant_modes
 WHERE tenant_id=tenant AND principal_id=principal FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'Shop assessment state unavailable' USING ERRCODE='55000'; END IF;
 SELECT * INTO prior FROM secureshop_auth.assessment_cleanup_history
 WHERE reset_id=requested_reset OR (launch_id=launch.launch_id AND from_generation=operation.from_generation);
 IF FOUND THEN
   IF prior.reset_id<>requested_reset OR prior.launch_id<>launch.launch_id
     OR prior.scenario_id<>launch.scenario_id OR prior.from_generation<>operation.from_generation
     OR prior.tenant_id<>tenant OR prior.principal_id<>principal
     OR prior.original_owner_id<>launch.original_platform_owner_id
     OR prior.original_session_id<>launch.original_platform_session_id
     OR operation.progress_reconciliation_required THEN
     RAISE EXCEPTION 'Shop progress checkpoint mismatch' USING ERRCODE='55000'; END IF;
   RETURN NEXT prior; RETURN;
 END IF;
 IF launch.generation<>operation.to_generation OR NOT operation.progress_reconciliation_required THEN
   RAISE EXCEPTION 'Shop progress generation mismatch' USING ERRCODE='55000'; END IF;
 SELECT count(*)::integer INTO judgments FROM secureshop_auth.assessment_judgments j
 WHERE j.tenant_id=tenant AND j.principal_id=principal
 AND j.execution_json->'scope'->>'launchId'=launch.launch_id::text
 AND j.execution_json->'scope'->>'generation'=operation.from_generation::text;
 SELECT count(*)::integer INTO contributions FROM secureshop_auth.assessment_contributions c
 JOIN secureshop_auth.assessment_judgments j USING(tenant_id,principal_id,evaluation_id)
 WHERE j.tenant_id=tenant AND j.principal_id=principal
 AND j.execution_json->'scope'->>'launchId'=launch.launch_id::text
 AND j.execution_json->'scope'->>'generation'=operation.from_generation::text;
 SELECT count(DISTINCT c.objective_id)::integer INTO projected
 FROM secureshop_auth.active_assessment_contributions c
 WHERE c.tenant_id=tenant AND c.principal_id=principal AND c.generation=mode_generation
 AND NOT(c.execution_json->'scope'->>'launchId'=launch.launch_id::text
   AND c.execution_json->'scope'->>'generation'=operation.from_generation::text);
 INSERT INTO secureshop_auth.assessment_cleanup_history(reset_id,launch_id,scenario_id,from_generation,
 tenant_id,principal_id,original_owner_id,original_session_id,assessment_generation,
 retired_judgment_count,retired_contribution_count,projected_completion_count)
 VALUES(requested_reset,launch.launch_id,launch.scenario_id,operation.from_generation,
 tenant,principal,launch.original_platform_owner_id,launch.original_platform_session_id,mode_generation,
 judgments,contributions,projected) RETURNING * INTO result;
 UPDATE identity.secureshop_launch_resets SET progress_reconciliation_required=false,updated_at=clock_timestamp()
 WHERE reset_id=requested_reset;
 RETURN NEXT result;
END $$;
REVOKE ALL ON FUNCTION secureshop_auth.finalize_assessment_cleanup(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_auth.finalize_assessment_cleanup(uuid) TO dvaia_identity_runtime;

CREATE OR REPLACE FUNCTION identity.guard_secureshop_progress_cleanup_gate()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,identity,secureshop_auth AS $$
DECLARE realm text; DECLARE valid boolean;
BEGIN
 IF NEW.progress_reconciliation_required IS DISTINCT FROM OLD.progress_reconciliation_required THEN
   SELECT o.realm INTO realm FROM identity.secureshop_launches l
   JOIN identity.secureshop_authority_owners o ON o.id=l.original_platform_owner_id WHERE l.launch_id=NEW.launch_id;
   IF realm='platform' THEN
     SELECT EXISTS(SELECT 1 FROM identity.secureshop_progress_cleanup_history h
       WHERE h.reset_id=NEW.reset_id AND h.launch_id=NEW.launch_id AND h.from_launch_generation=NEW.from_generation) INTO valid;
   ELSIF realm='shop' THEN
     SELECT EXISTS(SELECT 1 FROM secureshop_auth.assessment_cleanup_history h
       JOIN identity.secureshop_launches l ON l.launch_id=h.launch_id
       WHERE h.reset_id=NEW.reset_id AND h.launch_id=NEW.launch_id AND h.from_generation=NEW.from_generation
       AND h.scenario_id=l.scenario_id AND h.original_owner_id=l.original_platform_owner_id
       AND h.original_session_id=l.original_platform_session_id) INTO valid;
   END IF;
   IF OLD.progress_reconciliation_required IS NOT TRUE OR NEW.progress_reconciliation_required IS NOT FALSE OR valid IS NOT TRUE THEN
     RAISE EXCEPTION 'SecureShop progress cleanup gate requires canonical history' USING ERRCODE='55000'; END IF;
 END IF;
 IF NEW.status='committed' AND NEW.progress_reconciliation_required THEN
   RAISE EXCEPTION 'SecureShop canonical progress cleanup remains required' USING ERRCODE='55000'; END IF;
 RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION identity.guard_secureshop_progress_cleanup_gate() FROM PUBLIC;
