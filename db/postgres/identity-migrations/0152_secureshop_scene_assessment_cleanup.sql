-- A shared practice scene can be used by several shop principals and launch
-- generations. Preserve immutable assessment evidence while retiring every
-- contribution whose original judgment is authoritatively bound to a scene
-- retired by the reset. Assessments without scene provenance retain 0146's
-- exact-launch cleanup semantics.
CREATE TABLE secureshop_auth.assessment_scene_bindings (
 tenant_id uuid NOT NULL,principal_id uuid NOT NULL,evaluation_id uuid NOT NULL,
 scene_id uuid NOT NULL REFERENCES identity.secureshop_scenes(scene_id),
 scene_generation bigint NOT NULL CHECK(scene_generation>0),
 grant_id uuid NOT NULL REFERENCES identity.secureshop_scene_execution_grants(grant_id),
 target_id uuid NOT NULL,
 execution_launch_id uuid NOT NULL REFERENCES identity.secureshop_launches(launch_id),
 execution_scenario_id uuid NOT NULL,execution_generation bigint NOT NULL CHECK(execution_generation>0),
 original_owner_id integer NOT NULL CHECK(original_owner_id>0),
 original_session_id integer NOT NULL CHECK(original_session_id>0),
 authority_kind text NOT NULL CHECK(authority_kind='v03-packet-scene-grant-v1'),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(tenant_id,principal_id,evaluation_id),
 FOREIGN KEY(tenant_id,principal_id,evaluation_id)
   REFERENCES secureshop_auth.assessment_judgments(tenant_id,principal_id,evaluation_id)
);
CREATE TABLE secureshop_auth.assessment_scene_cleanup_history (
 reset_id uuid NOT NULL REFERENCES identity.secureshop_launch_resets(reset_id),
 scene_id uuid NOT NULL UNIQUE REFERENCES identity.secureshop_scenes(scene_id),
 scene_generation bigint NOT NULL CHECK(scene_generation>0),
 target_id uuid NOT NULL,
 retiring_launch_id uuid NOT NULL REFERENCES identity.secureshop_launches(launch_id),
 from_generation bigint NOT NULL CHECK(from_generation>0),
 to_generation bigint NOT NULL CHECK(to_generation=from_generation+1),
 original_owner_id integer NOT NULL CHECK(original_owner_id>0),
 retired_judgment_count integer NOT NULL CHECK(retired_judgment_count>=0),
 retired_contribution_count integer NOT NULL CHECK(retired_contribution_count>=0),
 projected_completion_count integer NOT NULL CHECK(projected_completion_count>=0),
 completed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(reset_id,scene_id)
);

CREATE TRIGGER assessment_scene_binding_immutable BEFORE UPDATE OR DELETE
 ON secureshop_auth.assessment_scene_bindings FOR EACH ROW
 EXECUTE FUNCTION secureshop_auth.guard_assessment_history();
CREATE TRIGGER assessment_scene_cleanup_immutable BEFORE UPDATE OR DELETE
 ON secureshop_auth.assessment_scene_cleanup_history FOR EACH ROW
 EXECUTE FUNCTION secureshop_auth.guard_assessment_history();

-- Parse retained text without turning an unavailable historical judgment into
-- a migration error. Only a later positive contribution requires a valid bind.
CREATE FUNCTION secureshop_auth.assessment_packet_json(requested_packet text)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SET search_path=pg_catalog AS $$
BEGIN
 IF requested_packet IS NULL OR octet_length(requested_packet)>2097152 THEN RETURN NULL; END IF;
 BEGIN RETURN requested_packet::jsonb; EXCEPTION WHEN OTHERS THEN RETURN NULL; END;
END $$;

-- The V03 adapter binds the stored semantic packet to the same immutable scene
-- authority. It supplies reset provenance only and never creates objective
-- credit. Every required member uses null-safe equality and typed containers.
CREATE FUNCTION secureshop_auth.v03_assessment_scene_packet_matches(
 requested_packet text,requested_execution jsonb,requested_mode text,requested_shop_user integer,
 requested_scene uuid,requested_scene_generation bigint,requested_grant uuid,requested_target uuid)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,secureshop_auth,identity AS $$
DECLARE document jsonb; DECLARE audit jsonb; DECLARE matches integer;
BEGIN
 document:=secureshop_auth.assessment_packet_json(requested_packet);
 IF jsonb_typeof(document) IS DISTINCT FROM 'object'
   OR jsonb_typeof(requested_execution) IS DISTINCT FROM 'object'
   OR jsonb_typeof(requested_execution->'scope') IS DISTINCT FROM 'object'
   OR jsonb_typeof(document->'rubric') IS DISTINCT FROM 'object'
   OR jsonb_typeof(document->'evidence') IS DISTINCT FROM 'array'
   OR document#>>'{rubric,family}' IS DISTINCT FROM 'SecureShop'
   OR document#>>'{rubric,scenario}' IS DISTINCT FROM 'bound_listings_image_optimize'
   OR document#>>'{rubric,objectiveId}' IS DISTINCT FROM 'ss_listing_image_command_execution'
   OR document#>>'{rubric,version}' IS DISTINCT FROM 'secureshop-listings-optimize-v1'
   OR document#>>'{rubric,mode}' IS DISTINCT FROM requested_mode THEN RETURN false;
 END IF;
 SELECT count(*)::integer,(jsonb_agg(value)->0) INTO matches,audit
 FROM jsonb_array_elements(document->'evidence') value
 WHERE value->>'id'='listing_optimize_audit';
 IF matches<>1 OR jsonb_typeof(audit) IS DISTINCT FROM 'object'
   OR jsonb_typeof(audit->'content') IS DISTINCT FROM 'object'
   OR jsonb_typeof(audit#>'{content,raw}') IS DISTINCT FROM 'object'
   OR jsonb_typeof(audit#>'{content,raw,binding}') IS DISTINCT FROM 'object'
   OR jsonb_typeof(audit#>'{content,raw,binding,scope}') IS DISTINCT FROM 'object'
   OR jsonb_typeof(audit#>'{content,raw,binding,persona}') IS DISTINCT FROM 'object'
   OR jsonb_typeof(audit#>'{content,raw,request}') IS DISTINCT FROM 'object'
   OR jsonb_typeof(audit#>'{content,raw,sourceSetup}') IS DISTINCT FROM 'object'
   OR jsonb_typeof(audit#>'{content,raw,sourceSetup,scene}') IS DISTINCT FROM 'object'
   OR audit->>'source' IS DISTINCT FROM 'server_observation'
   OR audit#>>'{content,version}' IS DISTINCT FROM 'secureshop-listings-optimize-v1'
   OR audit#>'{content,raw,binding,scope}' IS DISTINCT FROM requested_execution->'scope'
   OR audit#>>'{content,raw,binding,targetId}' IS DISTINCT FROM requested_target::text
   OR audit#>>'{content,raw,binding,persona,id}' IS DISTINCT FROM requested_shop_user::text
   OR audit#>>'{content,raw,binding,persona,role}' IS DISTINCT FROM 'merchant'
   OR audit#>>'{content,raw,binding,mode}' IS DISTINCT FROM requested_mode
   OR audit#>>'{content,raw,request,version}' IS DISTINCT FROM '1'
   OR audit#>>'{content,raw,request,action}' IS DISTINCT FROM 'optimize'
   OR audit#>>'{content,raw,request,sceneId}' IS DISTINCT FROM requested_scene::text
   OR audit#>>'{content,raw,request,sceneGeneration}' IS DISTINCT FROM requested_scene_generation::text
   OR audit#>>'{content,raw,request,grantId}' IS DISTINCT FROM requested_grant::text
   OR audit#>>'{content,raw,sourceSetup,version}' IS DISTINCT FROM '1'
   OR audit#>>'{content,raw,sourceSetup,kind}' IS DISTINCT FROM 'listing_optimize_setup'
   OR audit#>>'{content,raw,sourceSetup,action}' IS DISTINCT FROM 'optimize'
   OR audit#>>'{content,raw,sourceSetup,scene,sceneId}' IS DISTINCT FROM requested_scene::text
   OR audit#>>'{content,raw,sourceSetup,scene,sceneGeneration}' IS DISTINCT FROM requested_scene_generation::text
   OR audit#>>'{content,raw,sourceSetup,scene,grantId}' IS DISTINCT FROM requested_grant::text
   OR audit#>>'{content,raw,sourceSetup,scene,targetId}' IS DISTINCT FROM requested_target::text
   THEN RETURN false;
 END IF;
 RETURN true;
END $$;

CREATE FUNCTION secureshop_auth.assert_v03_assessment_scene_packet(
 requested_packet text,requested_execution jsonb,requested_mode text,requested_shop_user integer,
 requested_scene uuid,requested_scene_generation bigint,requested_grant uuid,requested_target uuid)
RETURNS boolean LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path=pg_catalog,secureshop_auth AS $$
BEGIN
 IF NOT secureshop_auth.v03_assessment_scene_packet_matches(requested_packet,requested_execution,
   requested_mode,requested_shop_user,requested_scene,requested_scene_generation,requested_grant,requested_target) THEN
   RAISE EXCEPTION 'V03 scene assessment packet mismatch' USING ERRCODE='55000';
 END IF;
 RETURN true;
END $$;

CREATE FUNCTION secureshop_auth.bind_assessment_scene() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_auth,identity AS $$
DECLARE bound record; DECLARE document jsonb; DECLARE audit jsonb; DECLARE matches integer;
BEGIN
 -- Each scene-owned objective needs a versioned adapter. V03 is the first
 -- supported family; unrelated and not-yet-adapted objectives remain governed
 -- by 0146 and are never inferred from a shared owner or launch alone.
 IF (NEW.objective_id,NEW.rubric_version) IS DISTINCT FROM
    ('ss_listing_image_command_execution','secureshop-listings-optimize-v1') THEN
   RETURN NEW;
 END IF;
 document:=secureshop_auth.assessment_packet_json(NEW.packet);
 IF jsonb_typeof(document->'evidence') IS DISTINCT FROM 'array' THEN RETURN NEW; END IF;
 SELECT count(*)::integer,(jsonb_agg(value)->0) INTO matches,audit
 FROM jsonb_array_elements(document->'evidence') value
 WHERE value->>'id'='listing_optimize_audit';
 IF matches<>1 THEN RETURN NEW; END IF;
 SELECT count(*)::integer AS candidate_count,min(s.scene_id::text)::uuid AS scene_id,
   min(s.scene_generation) AS scene_generation,min(g.grant_id::text)::uuid AS grant_id,
   min(s.product_target_id::text)::uuid AS target_id,
   min(g.launch_id::text)::uuid AS launch_id,min(g.scenario_id::text)::uuid AS scenario_id,
   min(g.generation) AS generation,min(g.original_platform_owner_id) AS owner_id,
   min(g.original_platform_session_id) AS session_id
 INTO bound
 FROM secureshop_auth.tenants t
 JOIN secureshop_auth.tenant_memberships m ON m.tenant_id=t.tenant_id
   AND m.principal_id=NEW.principal_id AND m.shop_user_id=NEW.shop_user_id
 JOIN identity.secureshop_scenes s ON s.original_platform_owner_id=t.owner_id
 JOIN identity.secureshop_scene_execution_grants g ON g.scene_id=s.scene_id
   AND g.scene_generation=s.scene_generation
 WHERE t.tenant_id=NEW.tenant_id
   AND s.scene_id::text=audit#>>'{content,raw,request,sceneId}'
   AND g.grant_id::text=audit#>>'{content,raw,request,grantId}'
   AND s.product_target_id::text=audit#>>'{content,raw,binding,targetId}'
   AND g.launch_id::text=NEW.execution_json#>>'{scope,launchId}'
   AND g.scenario_id::text=NEW.execution_json#>>'{scope,scenarioId}'
   AND g.generation::text=NEW.execution_json#>>'{scope,generation}'
   AND g.original_platform_owner_id::text=NEW.execution_json#>>'{scope,platformOwnerId}'
   AND g.original_platform_session_id::text=NEW.execution_json#>>'{scope,platformSessionId}';
 matches:=bound.candidate_count;
 IF matches<>1 THEN RETURN NEW; END IF;
 IF NOT secureshop_auth.v03_assessment_scene_packet_matches(NEW.packet,NEW.execution_json,NEW.mode,
   NEW.shop_user_id,bound.scene_id,bound.scene_generation,bound.grant_id,bound.target_id) THEN RETURN NEW; END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('shop-assessment-scene:'||bound.scene_id::text,0));
 IF NOT EXISTS(SELECT 1 FROM identity.secureshop_scenes s
      WHERE s.scene_id=bound.scene_id AND s.status='active'
        AND s.scene_generation=bound.scene_generation)
   OR EXISTS(SELECT 1 FROM secureshop_auth.assessment_scene_cleanup_history h
      WHERE h.scene_id=bound.scene_id) THEN
   RAISE EXCEPTION 'Scene assessment authority retired' USING ERRCODE='55000';
 END IF;
 INSERT INTO secureshop_auth.assessment_scene_bindings
  (tenant_id,principal_id,evaluation_id,scene_id,scene_generation,grant_id,target_id,
   execution_launch_id,execution_scenario_id,execution_generation,original_owner_id,
   original_session_id,authority_kind)
 VALUES(NEW.tenant_id,NEW.principal_id,NEW.evaluation_id,bound.scene_id,bound.scene_generation,
   bound.grant_id,bound.target_id,bound.launch_id,bound.scenario_id,bound.generation,bound.owner_id,
   bound.session_id,'v03-packet-scene-grant-v1');
 RETURN NEW;
END $$;
CREATE TRIGGER assessment_judgment_scene_binding AFTER INSERT
 ON secureshop_auth.assessment_judgments FOR EACH ROW
 EXECUTE FUNCTION secureshop_auth.bind_assessment_scene();

-- Establish populated history from immutable authority only. V03 rows must
-- additionally pass their versioned packet adapter. Negative/unavailable rows
-- remain immutable and unbound; any positive/contribution without a bind aborts.
WITH v03 AS MATERIALIZED (
 SELECT * FROM secureshop_auth.assessment_judgments
 WHERE objective_id='ss_listing_image_command_execution'
   AND rubric_version='secureshop-listings-optimize-v1'
)
INSERT INTO secureshop_auth.assessment_scene_bindings
 (tenant_id,principal_id,evaluation_id,scene_id,scene_generation,grant_id,target_id,
  execution_launch_id,execution_scenario_id,execution_generation,original_owner_id,
  original_session_id,authority_kind)
SELECT j.tenant_id,j.principal_id,j.evaluation_id,s.scene_id,s.scene_generation,g.grant_id,
 s.product_target_id,g.launch_id,g.scenario_id,g.generation,g.original_platform_owner_id,
 g.original_platform_session_id,'v03-packet-scene-grant-v1'
FROM v03 j
JOIN LATERAL (SELECT value AS audit FROM jsonb_array_elements(
 CASE WHEN jsonb_typeof(secureshop_auth.assessment_packet_json(j.packet)->'evidence')='array'
      THEN secureshop_auth.assessment_packet_json(j.packet)->'evidence' ELSE '[]'::jsonb END) value
 WHERE value->>'id'='listing_optimize_audit') packet ON true
JOIN secureshop_auth.tenants t ON t.tenant_id=j.tenant_id
JOIN secureshop_auth.tenant_memberships m ON m.tenant_id=j.tenant_id
 AND m.principal_id=j.principal_id AND m.shop_user_id=j.shop_user_id
JOIN identity.secureshop_scenes s ON s.original_platform_owner_id=t.owner_id
JOIN identity.secureshop_scene_execution_grants g ON g.scene_id=s.scene_id
 AND g.scene_generation=s.scene_generation
 AND g.launch_id::text=j.execution_json#>>'{scope,launchId}'
 AND g.scenario_id::text=j.execution_json#>>'{scope,scenarioId}'
 AND g.generation::text=j.execution_json#>>'{scope,generation}'
 AND g.original_platform_owner_id::text=j.execution_json#>>'{scope,platformOwnerId}'
 AND g.original_platform_session_id::text=j.execution_json#>>'{scope,platformSessionId}'
WHERE s.scene_id::text=packet.audit#>>'{content,raw,request,sceneId}'
 AND g.grant_id::text=packet.audit#>>'{content,raw,request,grantId}'
 AND s.product_target_id::text=packet.audit#>>'{content,raw,binding,targetId}'
 AND secureshop_auth.v03_assessment_scene_packet_matches(j.packet,j.execution_json,j.mode,j.shop_user_id,
   s.scene_id,s.scene_generation,g.grant_id,s.product_target_id);
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM secureshop_auth.assessment_judgments j
   WHERE j.objective_id='ss_listing_image_command_execution'
     AND j.rubric_version='secureshop-listings-optimize-v1'
     AND NOT EXISTS(SELECT 1 FROM secureshop_auth.assessment_scene_bindings b
       WHERE (b.tenant_id,b.principal_id,b.evaluation_id)=(j.tenant_id,j.principal_id,j.evaluation_id))
     AND ((j.verdict='pass' AND j.disposition IN ('awarded','already_complete'))
       OR EXISTS(SELECT 1 FROM secureshop_auth.assessment_contributions c
         WHERE (c.tenant_id,c.principal_id,c.evaluation_id)=(j.tenant_id,j.principal_id,j.evaluation_id)))) THEN
   RAISE EXCEPTION 'Unbound positive V03 scene assessment history' USING ERRCODE='55000';
 END IF;
END $$;

CREATE FUNCTION secureshop_auth.guard_scene_assessment_contribution() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_auth,identity AS $$
DECLARE bound secureshop_auth.assessment_scene_bindings;
BEGIN
 SELECT * INTO bound FROM secureshop_auth.assessment_scene_bindings b
 WHERE (b.tenant_id,b.principal_id,b.evaluation_id)=(NEW.tenant_id,NEW.principal_id,NEW.evaluation_id);
 IF NOT FOUND THEN
   IF EXISTS(SELECT 1 FROM secureshop_auth.assessment_judgments j
     WHERE (j.tenant_id,j.principal_id,j.evaluation_id)=(NEW.tenant_id,NEW.principal_id,NEW.evaluation_id)
       AND j.objective_id='ss_listing_image_command_execution'
       AND j.rubric_version='secureshop-listings-optimize-v1') THEN
     RAISE EXCEPTION 'V03 scene assessment contribution unbound' USING ERRCODE='55000';
   END IF;
   RETURN NEW;
 END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('shop-assessment-scene:'||bound.scene_id::text,0));
 IF EXISTS(SELECT 1 FROM secureshop_auth.assessment_scene_cleanup_history h
      WHERE h.scene_id=bound.scene_id)
   OR NOT EXISTS(SELECT 1 FROM identity.secureshop_scenes s
      WHERE s.scene_id=bound.scene_id AND s.status='active'
        AND s.scene_generation=bound.scene_generation) THEN
   RAISE EXCEPTION 'Scene assessment contribution retired' USING ERRCODE='55000';
 END IF;
 RETURN NEW;
END $$;
CREATE TRIGGER assessment_contribution_scene_guard BEFORE INSERT
 ON secureshop_auth.assessment_contributions FOR EACH ROW
 EXECUTE FUNCTION secureshop_auth.guard_scene_assessment_contribution();

CREATE FUNCTION secureshop_auth.materialize_assessment_scene_cleanup(requested_reset uuid)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path=pg_catalog,secureshop_auth,identity AS $$
DECLARE checkpoint secureshop_auth.assessment_cleanup_history; DECLARE claim record;
DECLARE judgments integer; DECLARE contributions integer; DECLARE projected integer;
DECLARE prior secureshop_auth.assessment_scene_cleanup_history;
BEGIN
 SELECT * INTO checkpoint FROM secureshop_auth.assessment_cleanup_history h
 WHERE h.reset_id=requested_reset;
 IF NOT FOUND THEN RAISE EXCEPTION 'Shop assessment cleanup history required' USING ERRCODE='55000'; END IF;
 FOR claim IN
  SELECT DISTINCT r.scene_id,s.scene_generation,r.target_id,r.retiring_launch_id,
    r.from_generation,r.to_generation,s.original_platform_owner_id
  FROM identity.secureshop_scene_target_retirements r
  JOIN identity.secureshop_scenes s ON s.scene_id=r.scene_id
  JOIN identity.secureshop_launch_resets o ON o.reset_id=requested_reset
    AND o.launch_id=r.retiring_launch_id AND o.from_generation=r.from_generation
    AND o.to_generation=r.to_generation
  WHERE r.target_kind='products' AND s.status='retired'
    AND checkpoint.launch_id=o.launch_id AND checkpoint.from_generation=o.from_generation
    AND checkpoint.original_owner_id=s.original_platform_owner_id
 LOOP
  PERFORM pg_advisory_xact_lock(hashtextextended('shop-assessment-scene:'||claim.scene_id::text,0));
  SELECT * INTO prior FROM secureshop_auth.assessment_scene_cleanup_history h
   WHERE h.scene_id=claim.scene_id;
  IF FOUND THEN
   IF prior.reset_id<>requested_reset OR prior.scene_generation<>claim.scene_generation
      OR prior.target_id<>claim.target_id OR prior.retiring_launch_id<>claim.retiring_launch_id
      OR prior.from_generation<>claim.from_generation OR prior.to_generation<>claim.to_generation
      OR prior.original_owner_id<>claim.original_platform_owner_id THEN
     RAISE EXCEPTION 'Scene assessment cleanup mismatch' USING ERRCODE='55000';
   END IF;
   CONTINUE;
  END IF;
  SELECT count(*)::integer INTO judgments
  FROM secureshop_auth.assessment_judgments j
  JOIN secureshop_auth.assessment_scene_bindings b
    USING(tenant_id,principal_id,evaluation_id)
  WHERE b.scene_id=claim.scene_id;
  SELECT count(*)::integer INTO contributions
  FROM secureshop_auth.assessment_contributions c
  JOIN secureshop_auth.assessment_scene_bindings b
    USING(tenant_id,principal_id,evaluation_id)
  WHERE b.scene_id=claim.scene_id;
  SELECT count(DISTINCT (j.tenant_id,j.principal_id,j.objective_id,j.generation))::integer INTO projected
  FROM secureshop_auth.assessment_contributions c
  JOIN secureshop_auth.assessment_judgments j USING(tenant_id,principal_id,evaluation_id)
  WHERE j.verdict='pass' AND j.disposition IN ('awarded','already_complete')
    AND EXISTS(SELECT 1 FROM secureshop_auth.assessment_scene_bindings affected
      WHERE affected.scene_id=claim.scene_id
        AND (affected.tenant_id,affected.principal_id)=(j.tenant_id,j.principal_id))
    AND NOT EXISTS(SELECT 1 FROM secureshop_auth.assessment_cleanup_history h
      WHERE h.tenant_id=j.tenant_id AND h.principal_id=j.principal_id
        AND j.execution_json#>>'{scope,launchId}'=h.launch_id::text
        AND j.execution_json#>>'{scope,generation}'=h.from_generation::text)
    AND NOT EXISTS(SELECT 1 FROM secureshop_auth.assessment_scene_bindings retired
      WHERE (retired.tenant_id,retired.principal_id,retired.evaluation_id)=
        (j.tenant_id,j.principal_id,j.evaluation_id) AND retired.scene_id=claim.scene_id)
    AND NOT EXISTS(SELECT 1 FROM secureshop_auth.assessment_scene_cleanup_history old
      JOIN secureshop_auth.assessment_scene_bindings retired
        ON retired.scene_id=old.scene_id
       AND (retired.tenant_id,retired.principal_id,retired.evaluation_id)=
         (j.tenant_id,j.principal_id,j.evaluation_id));
  INSERT INTO secureshop_auth.assessment_scene_cleanup_history
   (reset_id,scene_id,scene_generation,target_id,retiring_launch_id,from_generation,to_generation,
    original_owner_id,retired_judgment_count,retired_contribution_count,projected_completion_count)
  VALUES(requested_reset,claim.scene_id,claim.scene_generation,claim.target_id,
    claim.retiring_launch_id,claim.from_generation,claim.to_generation,claim.original_platform_owner_id,
    judgments,contributions,projected);
 END LOOP;
END $$;

CREATE FUNCTION secureshop_auth.capture_assessment_scene_cleanup() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,secureshop_auth AS $$
BEGIN PERFORM secureshop_auth.materialize_assessment_scene_cleanup(NEW.reset_id); RETURN NEW; END $$;
CREATE TRIGGER assessment_cleanup_captures_scenes AFTER INSERT
 ON secureshop_auth.assessment_cleanup_history FOR EACH ROW
 EXECUTE FUNCTION secureshop_auth.capture_assessment_scene_cleanup();

-- Populate exact prior cleanup/retirement intersections only. A shared owner or
-- tenant is insufficient to invent a scene cleanup claimant.
SELECT secureshop_auth.materialize_assessment_scene_cleanup(h.reset_id)
FROM secureshop_auth.assessment_cleanup_history h
ORDER BY h.completed_at,h.reset_id;

CREATE OR REPLACE VIEW secureshop_auth.active_assessment_contributions AS
 SELECT j.tenant_id,j.principal_id,j.objective_id,j.generation,j.evaluation_id,
   j.execution_json,j.created_at
 FROM secureshop_auth.assessment_contributions c
 JOIN secureshop_auth.assessment_judgments j USING(tenant_id,principal_id,evaluation_id)
 WHERE j.verdict='pass' AND j.disposition IN ('awarded','already_complete')
 AND NOT EXISTS(SELECT 1 FROM secureshop_auth.assessment_cleanup_history h
   WHERE h.tenant_id=j.tenant_id AND h.principal_id=j.principal_id
   AND j.execution_json#>>'{scope,launchId}'=h.launch_id::text
   AND j.execution_json#>>'{scope,generation}'=h.from_generation::text)
 AND NOT EXISTS(SELECT 1 FROM secureshop_auth.assessment_scene_bindings b
   JOIN secureshop_auth.assessment_scene_cleanup_history h ON h.scene_id=b.scene_id
   WHERE (b.tenant_id,b.principal_id,b.evaluation_id)=
     (j.tenant_id,j.principal_id,j.evaluation_id));

REVOKE ALL ON secureshop_auth.assessment_scene_bindings,
 secureshop_auth.assessment_scene_cleanup_history FROM PUBLIC;
GRANT SELECT ON secureshop_auth.assessment_scene_bindings,
 secureshop_auth.assessment_scene_cleanup_history TO dvaia_identity_runtime;
REVOKE ALL ON FUNCTION secureshop_auth.assessment_packet_json(text),
 secureshop_auth.v03_assessment_scene_packet_matches(text,jsonb,text,integer,uuid,bigint,uuid,uuid),
 secureshop_auth.assert_v03_assessment_scene_packet(text,jsonb,text,integer,uuid,bigint,uuid,uuid),
 secureshop_auth.bind_assessment_scene(),secureshop_auth.guard_scene_assessment_contribution(),
 secureshop_auth.materialize_assessment_scene_cleanup(uuid),
 secureshop_auth.capture_assessment_scene_cleanup() FROM PUBLIC;
REVOKE ALL ON secureshop_auth.active_assessment_contributions FROM PUBLIC;
GRANT SELECT ON secureshop_auth.active_assessment_contributions TO dvaia_identity_runtime;
