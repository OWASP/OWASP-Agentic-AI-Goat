-- Objective descriptions are instructor-editable catalog content. Existing rows
-- begin at a known empty default so the provenance seed may upgrade only rows
-- that have not since been customized.
ALTER TABLE workshop_platform.objectives
  ADD COLUMN description text NOT NULL DEFAULT '';

DO $migration$
DECLARE
  old_constraint name;
  matches integer;
BEGIN
  SELECT count(*), min(conname::text)::name INTO matches, old_constraint
  FROM pg_constraint
  WHERE conrelid='workshop_platform.catalog_field_defaults'::regclass
    AND contype='c'
    AND pg_get_constraintdef(oid) LIKE '%field_name%'
    AND pg_get_constraintdef(oid) LIKE '%solution_content%';
  IF matches<>1 THEN
    RAISE EXCEPTION 'Expected one catalog field-name constraint, found %', matches;
  END IF;
  EXECUTE format('ALTER TABLE workshop_platform.catalog_field_defaults DROP CONSTRAINT %I',old_constraint);
END
$migration$;

ALTER TABLE workshop_platform.catalog_field_defaults
  ADD CONSTRAINT catalog_field_defaults_fields_v2 CHECK (
    (entity_kind='exercise' AND objective_id=''
      AND field_name IN ('challenge_name','challenge_description','category','difficulty','route'))
    OR (entity_kind='objective' AND objective_id<>''
      AND field_name IN ('label','description','category','hint_content','solution_content'))
  );

INSERT INTO workshop_platform.catalog_field_defaults
  (entity_kind,workshop_key,objective_id,field_name,provenance_state,
   source_version,source_hash,source_document,applied_default_version,
   applied_default_hash,applied_default_document,observed_document)
SELECT 'objective',o.workshop_key,o.objective_id,'description','managed',
  'objective-description-0132',
  '16b2a3fbe6384c970a031dfdb4bf6e133daed7b04de6ff65e80eaf79bf5a91ad',
  '{"present":true,"value":""}'::jsonb,
  'objective-description-0132',
  '16b2a3fbe6384c970a031dfdb4bf6e133daed7b04de6ff65e80eaf79bf5a91ad',
  '{"present":true,"value":""}'::jsonb,
  jsonb_build_object('present',true,'value',o.description)
FROM workshop_platform.objectives o
ON CONFLICT(entity_kind,workshop_key,objective_id,field_name) DO NOTHING;
