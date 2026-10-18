-- Versioned owner membership mirrors a branded identity-store admission.
-- Actor birth ownership and every prior launch/evidence coordinate remain intact.
CREATE TABLE secureshop_agents.bound_actor_tenants (
  tenant_owner_id integer PRIMARY KEY CHECK(tenant_owner_id>0),
  tenant_id uuid NOT NULL UNIQUE,
  admitted_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE secureshop_agents.bound_actor_tenant_memberships (
  tenant_owner_id integer NOT NULL CHECK(tenant_owner_id>0),
  tenant_id uuid NOT NULL,
  shop_user_id integer NOT NULL REFERENCES secureshop_agents.bound_actor_identities(shop_user_id),
  principal_id uuid NOT NULL,
  principal_owner_id integer NOT NULL CHECK(principal_owner_id>0),
  membership_version bigint NOT NULL CHECK(membership_version>0),
  role text NOT NULL CHECK(role IN ('customer','merchant','admin')),
  is_active boolean NOT NULL DEFAULT true,
  admitted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY(tenant_owner_id,shop_user_id,membership_version),
  UNIQUE(tenant_id,principal_id,membership_version)
);
CREATE FUNCTION secureshop_agents.guard_bound_actor_tenant_membership() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE actor secureshop_agents.bound_actor_identities%ROWTYPE;
BEGIN
  IF TG_OP<>'INSERT' THEN
    RAISE EXCEPTION 'Shop tenant membership history is immutable' USING ERRCODE='55000';
  END IF;
  PERFORM pg_advisory_xact_lock(hashtextextended(
    'secureshop-bound-audit-owner:'||NEW.tenant_owner_id::text,0));
  INSERT INTO secureshop_agents.bound_actor_tenants(tenant_owner_id,tenant_id)
    VALUES(NEW.tenant_owner_id,NEW.tenant_id)
    ON CONFLICT(tenant_owner_id) DO NOTHING;
  IF NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_actor_tenants
    WHERE tenant_owner_id=NEW.tenant_owner_id AND tenant_id=NEW.tenant_id) THEN
    RAISE EXCEPTION 'Shop tenant identity mismatch' USING ERRCODE='55000';
  END IF;
  SELECT * INTO actor FROM secureshop_agents.bound_actor_identities
    WHERE shop_user_id=NEW.shop_user_id;
  IF actor.principal_id IS NULL OR actor.principal_id<>NEW.principal_id
    OR actor.original_platform_owner_id<>NEW.principal_owner_id
    OR EXISTS(SELECT 1 FROM secureshop_agents.bound_actor_tenant_memberships m
      WHERE m.tenant_owner_id=NEW.tenant_owner_id AND m.shop_user_id=NEW.shop_user_id
        AND m.membership_version>=NEW.membership_version) THEN
    RAISE EXCEPTION 'Shop tenant membership is invalid' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;
CREATE FUNCTION secureshop_agents.guard_bound_actor_tenant_identity() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
BEGIN
  RAISE EXCEPTION 'Shop tenant identity is immutable' USING ERRCODE='55000';
END $$;
CREATE TRIGGER bound_actor_tenant_identity_immutable
BEFORE UPDATE OR DELETE ON secureshop_agents.bound_actor_tenants
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_actor_tenant_identity();
CREATE TRIGGER bound_actor_tenant_membership_guard
BEFORE INSERT OR UPDATE OR DELETE ON secureshop_agents.bound_actor_tenant_memberships
FOR EACH ROW EXECUTE FUNCTION secureshop_agents.guard_bound_actor_tenant_membership();

ALTER TABLE secureshop_agents.bound_persona_sessions
  ADD COLUMN bootstrap_membership_version bigint
    CHECK(bootstrap_membership_version IS NULL OR bootstrap_membership_version>0);
CREATE OR REPLACE FUNCTION secureshop_agents.guard_bound_standalone_bootstrap() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
BEGIN
  IF (NEW.standalone_principal_id,NEW.standalone_session_id,NEW.bootstrap_jti,
      NEW.standalone_credential_version,NEW.standalone_authority_version,
      NEW.bootstrap_persona_authority_version,NEW.bootstrap_membership_version)
     IS DISTINCT FROM
     (OLD.standalone_principal_id,OLD.standalone_session_id,OLD.bootstrap_jti,
      OLD.standalone_credential_version,OLD.standalone_authority_version,
      OLD.bootstrap_persona_authority_version,OLD.bootstrap_membership_version) THEN
    RAISE EXCEPTION 'Standalone bootstrap identity is immutable' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;

CREATE FUNCTION secureshop_agents.bound_actor_in_owner(
  actor_id integer, requested_owner integer, required_version bigint DEFAULT NULL)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER
SET search_path=pg_catalog,secureshop_agents AS $$
  SELECT EXISTS(SELECT 1 FROM secureshop_agents.bound_actor_identities a
    WHERE a.shop_user_id=actor_id AND (
      a.original_platform_owner_id IS NULL
      OR (a.original_platform_owner_id=requested_owner AND required_version IS NULL)
      OR EXISTS(SELECT 1 FROM secureshop_agents.bound_actor_tenant_memberships m
        WHERE m.shop_user_id=a.shop_user_id AND m.principal_id=a.principal_id
          AND m.principal_owner_id=a.original_platform_owner_id
          AND m.tenant_owner_id=requested_owner AND m.is_active
          AND (required_version IS NULL OR m.membership_version=required_version)
          AND NOT EXISTS(SELECT 1 FROM secureshop_agents.bound_actor_tenant_memberships newer
            WHERE newer.tenant_owner_id=m.tenant_owner_id
              AND newer.shop_user_id=m.shop_user_id
              AND newer.membership_version>m.membership_version))));
$$;

CREATE OR REPLACE FUNCTION secureshop_agents.assert_bound_actor_owner() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE actor_id integer; required_version bigint;
BEGIN
  actor_id := (to_jsonb(NEW)->>TG_ARGV[0])::integer;
  IF TG_TABLE_NAME='bound_persona_sessions' THEN
    required_version := NEW.bootstrap_membership_version;
  END IF;
  IF NOT secureshop_agents.bound_actor_in_owner(actor_id,NEW.original_platform_owner_id,
    required_version) THEN
    RAISE EXCEPTION 'Shop actor owner mismatch' USING ERRCODE='42501';
  END IF;
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION secureshop_agents.assert_target_bound_actor_owner() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE target_owner integer; actor_id integer; column_name text;
BEGIN
  SELECT original_platform_owner_id INTO target_owner
  FROM secureshop_agents.persona_inbox_targets WHERE target_id=NEW.target_id;
  IF NOT FOUND THEN RAISE EXCEPTION 'Shop target unavailable' USING ERRCODE='42501'; END IF;
  FOREACH column_name IN ARRAY TG_ARGV LOOP
    actor_id := (to_jsonb(NEW)->>column_name)::integer;
    IF NOT secureshop_agents.bound_actor_in_owner(actor_id,target_owner) THEN
      RAISE EXCEPTION 'Shop actor target owner mismatch' USING ERRCODE='42501';
    END IF;
  END LOOP;
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION secureshop_agents.guard_bound_persona_effective_session() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_agents AS $$
DECLARE effective text; banned timestamptz; membership_role text;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-bound-audit-owner:'||NEW.original_platform_owner_id::text,0));
  PERFORM pg_advisory_xact_lock(hashtextextended('secureshop-conversation-admission:'||NEW.platform_launch_id::text,0));
  IF NOT secureshop_agents.bound_actor_in_owner(NEW.shop_user_id,
    NEW.original_platform_owner_id,NEW.bootstrap_membership_version) THEN
    RAISE EXCEPTION 'Effective persona owner unavailable' USING ERRCODE='55000';
  END IF;
  SELECT m.role INTO membership_role FROM secureshop_agents.bound_actor_tenant_memberships m
    WHERE m.tenant_owner_id=NEW.original_platform_owner_id
      AND m.shop_user_id=NEW.shop_user_id
      AND m.membership_version=NEW.bootstrap_membership_version AND m.is_active;
  SELECT COALESCE(st.effective_role,membership_role,a.base_role),st.banned_at INTO effective,banned
  FROM secureshop_agents.bound_actor_identities a
  LEFT JOIN secureshop_agents.bound_persona_state st
    ON st.platform_launch_id=NEW.platform_launch_id
    AND st.platform_scenario_id=NEW.platform_scenario_id
    AND st.platform_launch_generation=NEW.platform_launch_generation
    AND st.original_platform_owner_id=NEW.original_platform_owner_id
    AND st.original_platform_session_id=NEW.original_platform_session_id
    AND st.shop_user_id=a.shop_user_id
  WHERE a.shop_user_id=NEW.shop_user_id AND a.username=NEW.username;
  IF effective IS NULL OR effective<>NEW.role OR banned IS NOT NULL
    OR EXISTS(SELECT 1 FROM secureshop_agents.bound_audit_owner_deletion_receipts
      WHERE original_platform_owner_id=NEW.original_platform_owner_id) THEN
    RAISE EXCEPTION 'Effective persona authority unavailable' USING ERRCODE='55000';
  END IF;
  RETURN NEW;
END $$;

REVOKE ALL ON secureshop_agents.bound_actor_tenants,
  secureshop_agents.bound_actor_tenant_memberships FROM PUBLIC;
GRANT SELECT ON secureshop_agents.bound_actor_tenants TO dvaia_secureshop_agents_runtime;
GRANT SELECT,INSERT ON secureshop_agents.bound_actor_tenant_memberships
  TO dvaia_secureshop_agents_runtime;
REVOKE ALL ON FUNCTION secureshop_agents.guard_bound_actor_tenant_membership(),
  secureshop_agents.guard_bound_actor_tenant_identity(),
  secureshop_agents.bound_actor_in_owner(integer,integer,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION secureshop_agents.bound_actor_in_owner(integer,integer,bigint)
  TO dvaia_secureshop_agents_runtime;
