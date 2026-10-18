-- DRAFT ONLY. Per-field catalog-default provenance. Unregistered and unnumbered.
-- Existing values are intentionally legacy_unknown; no migration can infer whether
-- an instructor customized one field from the row-level updated_by marker.

CREATE TABLE workshop_platform.catalog_field_defaults (
  entity_kind text NOT NULL CHECK (entity_kind IN ('exercise','objective')),
  workshop_key text NOT NULL,
  objective_id text NOT NULL DEFAULT '',
  field_name text NOT NULL,
  provenance_state text NOT NULL CHECK (provenance_state IN ('managed','custom','legacy_unknown')),
  source_version text,
  source_hash text CHECK (source_hash IS NULL OR source_hash ~ '^[0-9a-f]{64}$'),
  source_document jsonb,
  applied_default_version text,
  applied_default_hash text CHECK (applied_default_hash IS NULL OR applied_default_hash ~ '^[0-9a-f]{64}$'),
  applied_default_document jsonb,
  observed_document jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(entity_kind,workshop_key,objective_id,field_name),
  CHECK ((entity_kind='exercise' AND objective_id=''
          AND field_name IN ('challenge_name','challenge_description','category','difficulty','route'))
      OR (entity_kind='objective' AND objective_id<>''
          AND field_name IN ('label','category','hint_content','solution_content'))),
  CHECK ((provenance_state='managed' AND applied_default_hash IS NOT NULL
          AND applied_default_document IS NOT NULL AND applied_default_version IS NOT NULL)
      OR provenance_state<>'managed')
);

CREATE FUNCTION workshop_platform.validate_catalog_field_default_target()
RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog AS $catalog_target$
BEGIN
  IF NEW.entity_kind='exercise' THEN
    IF NOT EXISTS(SELECT 1 FROM workshop_platform.exercises e
                  WHERE e.workshop_key=NEW.workshop_key) THEN
      RAISE foreign_key_violation USING MESSAGE='catalog exercise provenance target is missing';
    END IF;
  ELSIF NOT EXISTS(SELECT 1 FROM workshop_platform.objectives o
                   WHERE o.workshop_key=NEW.workshop_key AND o.objective_id=NEW.objective_id) THEN
    RAISE foreign_key_violation USING MESSAGE='catalog objective provenance target is missing';
  END IF;
  RETURN NEW;
END
$catalog_target$;
CREATE TRIGGER catalog_field_default_target
BEFORE INSERT OR UPDATE OF entity_kind,workshop_key,objective_id
ON workshop_platform.catalog_field_defaults
FOR EACH ROW EXECUTE FUNCTION workshop_platform.validate_catalog_field_default_target();

INSERT INTO workshop_platform.catalog_field_defaults
  (entity_kind,workshop_key,objective_id,field_name,provenance_state,observed_document)
SELECT 'exercise',e.workshop_key,'',v.field_name,'legacy_unknown',
       jsonb_build_object('present',true,'value',v.field_value)
FROM workshop_platform.exercises e
CROSS JOIN LATERAL (VALUES
 ('challenge_name',to_jsonb(e.challenge_name)),
 ('challenge_description',to_jsonb(e.challenge_description)),
 ('category',to_jsonb(e.category)),
 ('difficulty',to_jsonb(e.difficulty)),
 ('route',to_jsonb(e.route))
) v(field_name,field_value)
ON CONFLICT DO NOTHING;

INSERT INTO workshop_platform.catalog_field_defaults
  (entity_kind,workshop_key,objective_id,field_name,provenance_state,observed_document)
SELECT 'objective',o.workshop_key,o.objective_id,v.field_name,'legacy_unknown',
       jsonb_build_object('present',true,'value',v.field_value)
FROM workshop_platform.objectives o
CROSS JOIN LATERAL (VALUES
 ('label',to_jsonb(o.label)),
 ('category',to_jsonb(o.category)),
 ('hint_content',to_jsonb(o.hint_content)),
 ('solution_content',to_jsonb(o.solution_content))
) v(field_name,field_value)
ON CONFLICT DO NOTHING;

REVOKE ALL ON workshop_platform.catalog_field_defaults FROM PUBLIC;
GRANT SELECT,INSERT,UPDATE ON workshop_platform.catalog_field_defaults TO dvaia_identity_runtime;
REVOKE ALL ON FUNCTION workshop_platform.validate_catalog_field_default_target() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION workshop_platform.validate_catalog_field_default_target()
TO dvaia_identity_runtime;
