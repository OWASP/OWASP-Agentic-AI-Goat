-- Unapplied candidate. No current startup registration.
ALTER TABLE workshop_platform.objective_judgments
 ADD COLUMN persona_authority_required boolean NOT NULL DEFAULT false;
CREATE TABLE workshop_platform.persona_evaluation_bindings (
 user_id integer NOT NULL, evaluation_id uuid NOT NULL,
 original_run_id uuid NOT NULL, platform_launch_id uuid NOT NULL,
 platform_scenario_id uuid NOT NULL, platform_launch_generation bigint NOT NULL CHECK(platform_launch_generation>0),
 platform_session_id bigint NOT NULL CHECK(platform_session_id>0),
 persona_id integer NOT NULL CHECK(persona_id>0), persona_session_id uuid NOT NULL,
 persona_role text NOT NULL CHECK(persona_role IN ('customer','merchant','admin')),
 authority_version bigint NOT NULL CHECK(authority_version>0),
 PRIMARY KEY(user_id,evaluation_id),
 FOREIGN KEY(user_id,evaluation_id) REFERENCES workshop_platform.objective_judgments(user_id,evaluation_id)
 DEFERRABLE INITIALLY DEFERRED
);
REVOKE ALL ON workshop_platform.persona_evaluation_bindings FROM PUBLIC,dvaia_identity_runtime;
GRANT SELECT ON workshop_platform.persona_evaluation_bindings TO dvaia_identity_runtime;
CREATE FUNCTION workshop_platform.check_persona_evaluation_binding()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE j workshop_platform.objective_judgments%ROWTYPE; b workshop_platform.persona_evaluation_bindings%ROWTYPE;
BEGIN
 SELECT * INTO j FROM workshop_platform.objective_judgments WHERE user_id=NEW.user_id AND evaluation_id=NEW.evaluation_id;
 SELECT * INTO b FROM workshop_platform.persona_evaluation_bindings WHERE user_id=NEW.user_id AND evaluation_id=NEW.evaluation_id;
 IF j.evaluation_id IS NULL OR j.persona_authority_required<>(b.evaluation_id IS NOT NULL) THEN
  RAISE EXCEPTION 'Persona evaluation binding required' USING ERRCODE='23514';
 END IF;
 IF j.persona_authority_required AND (j.run_id IS DISTINCT FROM b.original_run_id
  OR j.platform_launch_id IS DISTINCT FROM b.platform_launch_id
  OR j.platform_scenario_id IS DISTINCT FROM b.platform_scenario_id
  OR j.platform_launch_generation IS DISTINCT FROM b.platform_launch_generation
  OR NOT EXISTS(SELECT 1 FROM identity.secureshop_launches l WHERE l.launch_id=b.platform_launch_id
   AND l.original_platform_session_id=b.platform_session_id AND l.original_platform_owner_id=b.user_id)) THEN
  RAISE EXCEPTION 'Persona evaluation scope mismatch' USING ERRCODE='23514';
 END IF;
 RETURN NEW;
END $$;
CREATE CONSTRAINT TRIGGER persona_evaluation_binding_required AFTER INSERT OR UPDATE ON workshop_platform.objective_judgments
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION workshop_platform.check_persona_evaluation_binding();
CREATE CONSTRAINT TRIGGER persona_evaluation_binding_matches AFTER INSERT ON workshop_platform.persona_evaluation_bindings
 DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION workshop_platform.check_persona_evaluation_binding();
CREATE FUNCTION workshop_platform.immutable_persona_evaluation_binding()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $$
BEGIN
 IF TG_TABLE_NAME='objective_judgments' THEN
  IF NEW.persona_authority_required IS DISTINCT FROM OLD.persona_authority_required THEN
   RAISE EXCEPTION 'Persona authority marker is immutable' USING ERRCODE='23514';
  END IF;
  RETURN NEW;
 END IF;
 RAISE EXCEPTION 'Persona evaluation binding is immutable' USING ERRCODE='23514';
END $$;
CREATE TRIGGER persona_evaluation_marker_immutable BEFORE UPDATE ON workshop_platform.objective_judgments
 FOR EACH ROW EXECUTE FUNCTION workshop_platform.immutable_persona_evaluation_binding();
CREATE TRIGGER persona_evaluation_binding_immutable BEFORE UPDATE OR DELETE ON workshop_platform.persona_evaluation_bindings
 FOR EACH ROW EXECUTE FUNCTION workshop_platform.immutable_persona_evaluation_binding();
CREATE FUNCTION workshop_platform.bind_persona_evaluation(
 p_user integer,p_eval uuid,p_run uuid,p_launch uuid,p_scenario uuid,p_generation bigint,p_platform_session bigint,
 p_persona integer,p_persona_session uuid,p_role text,p_version bigint)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE old workshop_platform.persona_evaluation_bindings%ROWTYPE;
BEGIN
 INSERT INTO workshop_platform.persona_evaluation_bindings VALUES
 (p_user,p_eval,p_run,p_launch,p_scenario,p_generation,p_platform_session,p_persona,p_persona_session,p_role,p_version)
 ON CONFLICT(user_id,evaluation_id) DO NOTHING;
 SELECT * INTO old FROM workshop_platform.persona_evaluation_bindings WHERE user_id=p_user AND evaluation_id=p_eval;
 IF ROW(old.original_run_id,old.platform_launch_id,old.platform_scenario_id,old.platform_launch_generation,
 old.platform_session_id,old.persona_id,old.persona_session_id,old.persona_role,old.authority_version)
 IS DISTINCT FROM ROW(p_run,p_launch,p_scenario,p_generation,p_platform_session,p_persona,p_persona_session,p_role,p_version) THEN
  RAISE EXCEPTION 'Persona evaluation replay conflict' USING ERRCODE='23505';
 END IF;
END $$;
REVOKE ALL ON FUNCTION workshop_platform.check_persona_evaluation_binding(),workshop_platform.immutable_persona_evaluation_binding(),
 workshop_platform.bind_persona_evaluation(integer,uuid,uuid,uuid,uuid,bigint,bigint,integer,uuid,text,bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION workshop_platform.bind_persona_evaluation(integer,uuid,uuid,uuid,uuid,bigint,bigint,integer,uuid,text,bigint) TO dvaia_identity_runtime;
