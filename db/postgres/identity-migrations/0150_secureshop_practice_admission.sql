-- A practice has immutable birth authority. Choosing it is a caller preference,
-- not tenant-wide authority, and never changes a session membership snapshot.
CREATE TABLE secureshop_auth.practice_preferences (
  tenant_id uuid NOT NULL,
  principal_id uuid NOT NULL,
  scene_id uuid REFERENCES identity.secureshop_scenes(scene_id),
  revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
  PRIMARY KEY(tenant_id,principal_id),
  FOREIGN KEY(tenant_id,principal_id) REFERENCES secureshop_auth.tenant_memberships(tenant_id,principal_id)
);
CREATE TABLE secureshop_auth.practice_selections (
  auth_session_id integer NOT NULL REFERENCES secureshop_auth.sessions(session_id),
  tenant_id uuid NOT NULL,
  principal_id uuid NOT NULL,
  execution_session_id integer NOT NULL REFERENCES secureshop_auth.execution_sessions(session_id),
  scene_id uuid REFERENCES identity.secureshop_scenes(scene_id),
  revision bigint NOT NULL DEFAULT 1 CHECK(revision>0),
  PRIMARY KEY(auth_session_id,tenant_id),
  FOREIGN KEY(tenant_id,principal_id) REFERENCES secureshop_auth.tenant_memberships(tenant_id,principal_id)
);
-- Block concurrent execution creation before replacing its old uniqueness rule.
LOCK TABLE secureshop_auth.execution_sessions IN SHARE ROW EXCLUSIVE MODE;
INSERT INTO secureshop_auth.practice_selections(auth_session_id,tenant_id,principal_id,execution_session_id,scene_id)
  SELECT DISTINCT ON (e.auth_session_id,e.tenant_id) e.auth_session_id,e.tenant_id,e.principal_id,e.session_id,s.scene_id
  FROM secureshop_auth.execution_sessions e JOIN secureshop_auth.tenants t USING(tenant_id)
  LEFT JOIN identity.secureshop_scenes s ON s.original_platform_owner_id=t.owner_id
    AND s.status='active' AND s.is_default
  ORDER BY e.auth_session_id,e.tenant_id,e.membership_version DESC,e.session_id DESC;
INSERT INTO secureshop_auth.practice_preferences(tenant_id,principal_id,scene_id)
  SELECT m.tenant_id,m.principal_id,s.scene_id
  FROM secureshop_auth.tenant_memberships m JOIN secureshop_auth.tenants t USING(tenant_id)
  LEFT JOIN identity.secureshop_scenes s ON s.original_platform_owner_id=t.owner_id
    AND s.status='active' AND s.is_default;
DO $$ DECLARE constraint_name text; BEGIN
  SELECT c.conname INTO STRICT constraint_name FROM pg_constraint c
    WHERE c.conrelid='secureshop_auth.execution_sessions'::regclass AND c.contype='u'
      AND (SELECT array_agg(a.attname::text ORDER BY a.attname) FROM unnest(c.conkey) k
        JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k)
        =ARRAY['auth_session_id','membership_version','tenant_id'];
  EXECUTE format('ALTER TABLE secureshop_auth.execution_sessions DROP CONSTRAINT %I',constraint_name);
END $$;

CREATE TABLE secureshop_auth.practice_operations (
  operation_id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  principal_id uuid NOT NULL,
  auth_session_id integer NOT NULL REFERENCES secureshop_auth.sessions(session_id),
  membership_version bigint NOT NULL CHECK(membership_version>0),
  source_execution_id integer NOT NULL UNIQUE REFERENCES secureshop_auth.execution_sessions(session_id),
  source_launch_id uuid NOT NULL REFERENCES identity.secureshop_launches(launch_id),
  source_generation bigint NOT NULL CHECK(source_generation>0),
  source_scene_id uuid NOT NULL REFERENCES identity.secureshop_scenes(scene_id),
  source_selection_revision bigint NOT NULL CHECK(source_selection_revision>0),
  source_preference_revision bigint NOT NULL CHECK(source_preference_revision>0),
  execution_session_id integer NOT NULL UNIQUE REFERENCES secureshop_auth.execution_sessions(session_id),
  launch_id uuid NOT NULL UNIQUE REFERENCES identity.secureshop_launches(launch_id),
  scenario_id uuid NOT NULL,
  generation bigint NOT NULL CHECK(generation=1),
  owner_id integer NOT NULL REFERENCES identity.secureshop_authority_owners(id),
  target_id uuid NOT NULL UNIQUE REFERENCES identity.secureshop_target_reservations(target_id),
  scene_id uuid NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  FOREIGN KEY(tenant_id,principal_id) REFERENCES secureshop_auth.tenant_memberships(tenant_id,principal_id)
);
CREATE TABLE secureshop_auth.practice_publications (
  operation_id uuid PRIMARY KEY REFERENCES secureshop_auth.practice_operations(operation_id),
  scene_id uuid NOT NULL UNIQUE REFERENCES identity.secureshop_scenes(scene_id),
  source_sha256 bytea NOT NULL CHECK(octet_length(source_sha256)=32),
  published_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE FUNCTION secureshop_auth.guard_practice_history() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,secureshop_auth,identity AS $$
BEGIN
  IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'Practice history is immutable' USING ERRCODE='55000'; END IF;
  IF TG_TABLE_NAME='practice_operations' THEN
    IF NOT EXISTS(SELECT 1 FROM secureshop_auth.practice_selections x
      JOIN secureshop_auth.practice_preferences pref ON pref.tenant_id=x.tenant_id AND pref.principal_id=x.principal_id
      JOIN secureshop_auth.execution_sessions e ON e.session_id=NEW.execution_session_id
      JOIN secureshop_auth.execution_authority_state a ON a.session_id=e.session_id
      JOIN identity.secureshop_launches l ON l.launch_id=NEW.launch_id
      JOIN identity.secureshop_launches prior_launch ON prior_launch.launch_id=NEW.source_launch_id
      JOIN identity.secureshop_target_reservations r ON r.target_id=NEW.target_id
      WHERE x.auth_session_id=NEW.auth_session_id AND x.tenant_id=NEW.tenant_id
        AND x.principal_id=NEW.principal_id AND x.execution_session_id=NEW.source_execution_id
        AND x.scene_id=NEW.source_scene_id AND x.revision=NEW.source_selection_revision
        AND pref.revision=NEW.source_preference_revision
        AND e.auth_session_id=NEW.auth_session_id AND e.tenant_id=NEW.tenant_id
        AND e.principal_id=NEW.principal_id AND e.membership_version=NEW.membership_version
        AND a.is_active=1 AND a.expires_at>clock_timestamp() AND a.owner_id=NEW.owner_id
        AND prior_launch.platform_session_id=NEW.source_execution_id
        AND prior_launch.original_platform_owner_id=NEW.owner_id
        AND prior_launch.generation=NEW.source_generation AND prior_launch.status='active'
        AND prior_launch.expires_at>clock_timestamp()
        AND l.platform_session_id=e.session_id AND l.original_platform_owner_id=NEW.owner_id
        AND l.scenario_id=NEW.scenario_id AND l.generation=NEW.generation
        AND l.status='active' AND l.expires_at>clock_timestamp()
        AND r.launch_id=l.launch_id AND r.generation=l.generation
        AND r.original_platform_owner_id=NEW.owner_id AND r.target_kind='products') THEN
      RAISE EXCEPTION 'Practice admission authority mismatch' USING ERRCODE='55000';
    END IF;
  ELSE
    IF NOT EXISTS(SELECT 1 FROM secureshop_auth.practice_operations o
      JOIN identity.secureshop_scenes s ON s.scene_id=o.scene_id
      WHERE o.operation_id=NEW.operation_id AND s.scene_id=NEW.scene_id
        AND s.product_target_id=o.target_id AND s.original_platform_owner_id=o.owner_id
        AND s.birth_launch_id=o.launch_id AND s.birth_scenario_id=o.scenario_id
        AND s.birth_generation=o.generation AND s.birth_platform_session_id=o.execution_session_id
        AND s.status='active') THEN
      RAISE EXCEPTION 'Practice publication mismatch' USING ERRCODE='55000';
    END IF;
  END IF;
  RETURN NEW;
END $$;
CREATE TRIGGER practice_operation_immutable BEFORE INSERT OR UPDATE OR DELETE
  ON secureshop_auth.practice_operations FOR EACH ROW EXECUTE FUNCTION secureshop_auth.guard_practice_history();
CREATE TRIGGER practice_publication_immutable BEFORE INSERT OR UPDATE OR DELETE
  ON secureshop_auth.practice_publications FOR EACH ROW EXECUTE FUNCTION secureshop_auth.guard_practice_history();

CREATE FUNCTION secureshop_auth.guard_practice_selection() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,secureshop_auth,identity AS $$
BEGIN
  IF TG_OP='DELETE' OR (TG_OP='UPDATE' AND
    (NEW.tenant_id,NEW.principal_id) IS DISTINCT FROM (OLD.tenant_id,OLD.principal_id)) THEN
    RAISE EXCEPTION 'Practice selection identity is immutable' USING ERRCODE='55000';
  END IF;
  IF NEW.scene_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM identity.secureshop_scenes s
    JOIN secureshop_auth.tenants t ON t.owner_id=s.original_platform_owner_id
    WHERE t.tenant_id=NEW.tenant_id AND s.scene_id=NEW.scene_id AND s.status='active') THEN
    RAISE EXCEPTION 'Practice selection owner mismatch' USING ERRCODE='55000';
  END IF;
  IF TG_TABLE_NAME='practice_selections' THEN
    IF TG_OP='UPDATE' AND NEW.auth_session_id<>OLD.auth_session_id THEN
      RAISE EXCEPTION 'Practice auth session is immutable' USING ERRCODE='55000';
    END IF;
    IF NOT EXISTS(SELECT 1 FROM secureshop_auth.execution_sessions e
      JOIN secureshop_auth.execution_authority_state a USING(session_id)
      WHERE e.session_id=NEW.execution_session_id AND e.auth_session_id=NEW.auth_session_id
        AND e.tenant_id=NEW.tenant_id AND e.principal_id=NEW.principal_id
        AND a.is_active=1 AND a.expires_at>clock_timestamp()) THEN
      RAISE EXCEPTION 'Practice execution unavailable' USING ERRCODE='55000';
    END IF;
  END IF;
  NEW.revision:=CASE WHEN TG_OP='INSERT' THEN 1 ELSE OLD.revision+1 END;
  RETURN NEW;
END $$;
CREATE TRIGGER practice_selection_guard BEFORE INSERT OR UPDATE OR DELETE ON secureshop_auth.practice_selections
  FOR EACH ROW EXECUTE FUNCTION secureshop_auth.guard_practice_selection();
CREATE TRIGGER practice_preference_guard BEFORE INSERT OR UPDATE OR DELETE ON secureshop_auth.practice_preferences
  FOR EACH ROW EXECUTE FUNCTION secureshop_auth.guard_practice_selection();
REVOKE ALL ON secureshop_auth.practice_operations,secureshop_auth.practice_publications,
  secureshop_auth.practice_selections,secureshop_auth.practice_preferences FROM PUBLIC;
GRANT SELECT,INSERT ON secureshop_auth.practice_operations,secureshop_auth.practice_publications TO dvaia_identity_runtime;
GRANT SELECT,INSERT,UPDATE ON secureshop_auth.practice_selections,secureshop_auth.practice_preferences TO dvaia_identity_runtime;
REVOKE ALL ON FUNCTION secureshop_auth.guard_practice_history(),secureshop_auth.guard_practice_selection() FROM PUBLIC;
