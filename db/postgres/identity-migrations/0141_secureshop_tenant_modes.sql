-- Shop tenants are not workshop users. Their canonical feature mode belongs to
-- the hardened shop realm and never creates workshop progress or user rows.
CREATE TABLE secureshop_auth.tenant_modes (
  tenant_id uuid NOT NULL,
  principal_id uuid NOT NULL,
  mode text NOT NULL DEFAULT 'vuln' CHECK(mode IN ('vuln','fixed')),
  generation integer NOT NULL DEFAULT 0 CHECK(generation >= 0),
  revision bigint NOT NULL DEFAULT 1 CHECK(revision > 0),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(tenant_id,principal_id),
  FOREIGN KEY(tenant_id,principal_id) REFERENCES secureshop_auth.tenant_memberships(tenant_id,principal_id)
);
CREATE FUNCTION secureshop_auth.guard_tenant_mode() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,secureshop_auth AS $$
BEGIN
  IF TG_OP='DELETE' OR NEW.tenant_id<>OLD.tenant_id OR NEW.principal_id<>OLD.principal_id OR NEW.created_at<>OLD.created_at
      OR NEW.generation<OLD.generation THEN
    RAISE EXCEPTION 'Shop mode identity is immutable' USING ERRCODE='55000';
  END IF;
  NEW.revision:=OLD.revision+1;
  NEW.updated_at:=clock_timestamp();
  RETURN NEW;
END $$;
CREATE TRIGGER tenant_mode_revision BEFORE UPDATE OR DELETE ON secureshop_auth.tenant_modes
  FOR EACH ROW EXECUTE FUNCTION secureshop_auth.guard_tenant_mode();
CREATE FUNCTION secureshop_auth.seed_tenant_mode() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_auth AS $$
BEGIN
  INSERT INTO secureshop_auth.tenant_modes(tenant_id,principal_id) VALUES(NEW.tenant_id,NEW.principal_id)
    ON CONFLICT DO NOTHING;
  RETURN NEW;
END $$;
CREATE TRIGGER tenant_mode_default AFTER INSERT ON secureshop_auth.tenant_memberships
  FOR EACH ROW EXECUTE FUNCTION secureshop_auth.seed_tenant_mode();
INSERT INTO secureshop_auth.tenant_modes(tenant_id,principal_id)
  SELECT tenant_id,principal_id FROM secureshop_auth.tenant_memberships ON CONFLICT DO NOTHING;
REVOKE ALL ON secureshop_auth.tenant_modes FROM PUBLIC;
GRANT SELECT ON secureshop_auth.tenant_modes TO dvaia_identity_runtime;
REVOKE ALL ON FUNCTION secureshop_auth.guard_tenant_mode(),secureshop_auth.seed_tenant_mode() FROM PUBLIC;

CREATE FUNCTION secureshop_auth.set_principal_mode(requested_session integer,
  requested_tenant uuid,requested_principal uuid,expected_revision bigint,requested_mode text)
RETURNS TABLE(mode text,revision text) LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,secureshop_auth AS $$
BEGIN
  IF requested_mode IS NULL OR requested_mode NOT IN ('vuln','fixed') OR expected_revision<1 THEN
    RAISE EXCEPTION 'Invalid shop mode' USING ERRCODE='22023';
  END IF;
  PERFORM 1 FROM secureshop_auth.execution_sessions e
    JOIN secureshop_auth.sessions s ON s.session_id=e.auth_session_id
    JOIN secureshop_auth.principals p ON p.principal_id=e.principal_id AND p.principal_id=s.principal_id
    JOIN secureshop_auth.tenant_memberships m ON m.tenant_id=e.tenant_id AND m.principal_id=e.principal_id
    JOIN secureshop_auth.tenants t ON t.tenant_id=e.tenant_id
    WHERE e.session_id=requested_session AND e.tenant_id=requested_tenant
      AND e.principal_id=requested_principal AND e.revoked_at IS NULL AND s.revoked_at IS NULL
      AND e.expires_at>clock_timestamp() AND s.expires_at>clock_timestamp()
      AND p.is_active AND m.is_active AND t.is_active
      AND (p.locked_until IS NULL OR p.locked_until<=clock_timestamp())
      AND s.credential_version=p.credential_version AND s.authority_version=p.authority_version
      AND e.membership_version=m.membership_version
    FOR SHARE OF e,s,p,m,t;
  IF NOT FOUND THEN RAISE EXCEPTION 'Shop execution unavailable' USING ERRCODE='28000'; END IF;
  RETURN QUERY UPDATE secureshop_auth.tenant_modes AS modes SET mode=requested_mode
    WHERE modes.tenant_id=requested_tenant AND modes.principal_id=requested_principal
      AND modes.revision=expected_revision RETURNING modes.mode,modes.revision::text;
  IF NOT FOUND THEN RAISE EXCEPTION 'Shop mode revision changed' USING ERRCODE='40001'; END IF;
END $$;
REVOKE ALL ON FUNCTION secureshop_auth.set_principal_mode(integer,uuid,uuid,bigint,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_auth.set_principal_mode(integer,uuid,uuid,bigint,text) TO dvaia_identity_runtime;
