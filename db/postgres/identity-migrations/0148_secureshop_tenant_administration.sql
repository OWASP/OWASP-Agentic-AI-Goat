-- Tenant administration fences only the affected storefront. Principal identity,
-- sibling memberships and historical executions remain immutable evidence.
ALTER TABLE secureshop_auth.sessions ADD COLUMN renewed_from_session_id integer REFERENCES secureshop_auth.sessions(session_id);
ALTER TABLE secureshop_auth.tenant_memberships ADD COLUMN banned_at timestamptz;
ALTER TABLE secureshop_auth.tenant_memberships ADD COLUMN ban_reason text CHECK(octet_length(ban_reason)<=1024);
CREATE TABLE secureshop_auth.session_membership_snapshots (
 session_id integer NOT NULL REFERENCES secureshop_auth.sessions(session_id),
 tenant_id uuid NOT NULL REFERENCES secureshop_auth.tenants(tenant_id),
 membership_version bigint NOT NULL CHECK(membership_version>0),
 PRIMARY KEY(session_id,tenant_id)
);
CREATE FUNCTION secureshop_auth.capture_session_memberships() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_auth AS $$
BEGIN
 IF NEW.renewed_from_session_id IS NOT NULL THEN
  IF NOT EXISTS(SELECT 1 FROM secureshop_auth.sessions prior_session WHERE prior_session.session_id=NEW.renewed_from_session_id
   AND prior_session.principal_id=NEW.principal_id AND prior_session.credential_version=NEW.credential_version AND prior_session.authority_version=NEW.authority_version) THEN
   RAISE EXCEPTION 'Shop renewal identity mismatch' USING ERRCODE='28000';
  END IF;
  INSERT INTO secureshop_auth.session_membership_snapshots SELECT NEW.session_id,tenant_id,membership_version
   FROM secureshop_auth.session_membership_snapshots WHERE session_id=NEW.renewed_from_session_id;
  RETURN NEW;
 END IF;
 PERFORM 1 FROM secureshop_auth.tenant_memberships WHERE principal_id=NEW.principal_id ORDER BY tenant_id FOR SHARE;
 INSERT INTO secureshop_auth.session_membership_snapshots
 SELECT NEW.session_id,tenant_id,membership_version FROM secureshop_auth.tenant_memberships WHERE principal_id=NEW.principal_id;
 RETURN NEW;
END $$;
CREATE TRIGGER shop_session_memberships AFTER INSERT ON secureshop_auth.sessions
 FOR EACH ROW EXECUTE FUNCTION secureshop_auth.capture_session_memberships();
-- CREATE TRIGGER holds SHARE ROW EXCLUSIVE on sessions until commit;
-- backfill therefore includes every pre-trigger committed session.
-- Never upgrade a previously admitted stale execution while backfilling cookies.
INSERT INTO secureshop_auth.session_membership_snapshots
 SELECT s.session_id,m.tenant_id,COALESCE((SELECT min(e.membership_version)
  FROM secureshop_auth.execution_sessions e WHERE e.auth_session_id=s.session_id AND e.tenant_id=m.tenant_id),m.membership_version)
 FROM secureshop_auth.sessions s JOIN secureshop_auth.tenant_memberships m USING(principal_id);
CREATE FUNCTION secureshop_auth.guard_tenant_admin_history() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN RAISE EXCEPTION 'Tenant authority history is immutable' USING ERRCODE='55000'; END $$;
CREATE TRIGGER shop_session_memberships_immutable BEFORE UPDATE OR DELETE ON secureshop_auth.session_membership_snapshots
 FOR EACH ROW EXECUTE FUNCTION secureshop_auth.guard_tenant_admin_history();
CREATE FUNCTION secureshop_auth.guard_session_renewal_source() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF NEW.renewed_from_session_id IS DISTINCT FROM OLD.renewed_from_session_id THEN
  RAISE EXCEPTION 'Shop renewal source is immutable' USING ERRCODE='55000';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER shop_renewal_source BEFORE UPDATE ON secureshop_auth.sessions
 FOR EACH ROW EXECUTE FUNCTION secureshop_auth.guard_session_renewal_source();
REVOKE ALL ON FUNCTION secureshop_auth.guard_session_renewal_source() FROM PUBLIC;
CREATE FUNCTION secureshop_auth.guard_execution_snapshot() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,secureshop_auth AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM secureshop_auth.session_membership_snapshots
  WHERE session_id=NEW.auth_session_id AND tenant_id=NEW.tenant_id AND membership_version=NEW.membership_version) THEN
  RAISE EXCEPTION 'Shop login membership is stale' USING ERRCODE='28000';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER shop_execution_snapshot BEFORE INSERT ON secureshop_auth.execution_sessions
 FOR EACH ROW EXECUTE FUNCTION secureshop_auth.guard_execution_snapshot();
CREATE TABLE secureshop_auth.tenant_admin_operations (
 launch_id uuid NOT NULL REFERENCES identity.secureshop_launches(launch_id),
 scenario_id uuid NOT NULL,generation bigint NOT NULL CHECK(generation>0),owner_id integer NOT NULL,
 execution_session_id integer NOT NULL REFERENCES secureshop_auth.execution_sessions(session_id),
 operation_id uuid NOT NULL,tenant_id uuid NOT NULL REFERENCES secureshop_auth.tenants(tenant_id),
 actor_id integer NOT NULL REFERENCES secureshop_auth.principals(shop_user_id),actor_session_id uuid NOT NULL,
 target_id integer NOT NULL REFERENCES secureshop_auth.principals(shop_user_id),
 request_sha256 bytea NOT NULL CHECK(octet_length(request_sha256)=32),result_json jsonb NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(launch_id,generation,operation_id)
);
CREATE TRIGGER shop_tenant_admin_history BEFORE UPDATE OR DELETE ON secureshop_auth.tenant_admin_operations
 FOR EACH ROW EXECUTE FUNCTION secureshop_auth.guard_tenant_admin_history();
REVOKE ALL ON secureshop_auth.session_membership_snapshots,secureshop_auth.tenant_admin_operations FROM PUBLIC;
GRANT SELECT ON secureshop_auth.session_membership_snapshots TO dvaia_identity_runtime;
GRANT SELECT,INSERT ON secureshop_auth.tenant_admin_operations TO dvaia_identity_runtime;
REVOKE ALL ON FUNCTION secureshop_auth.capture_session_memberships(),secureshop_auth.guard_tenant_admin_history(),secureshop_auth.guard_execution_snapshot() FROM PUBLIC;

-- Promoted tenant administrators use canonical membership, never teaching state.
CREATE OR REPLACE FUNCTION secureshop_auth.set_assessment_objective(requested_session integer,requested_tenant uuid,
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
 AND p.is_active AND m.role='admin' AND m.is_active AND t.is_active
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

