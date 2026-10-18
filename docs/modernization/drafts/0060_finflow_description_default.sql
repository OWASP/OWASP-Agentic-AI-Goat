-- Unregistered draft: replace only the recognized historical FinFlow default.
-- Canonical workshopChallengeFixtures already contains the replacement text.
-- Preserve custom descriptions, instructor flags, updated_by, objectives and progress.
WITH changed AS (
  UPDATE workshop_platform.exercises
  SET challenge_description = 'Explore path traversal, SSRF, and prompt injection in the FinFlow AI banking lab through its enabled objectives and isolated training resources.',
      updated_at = now()
  WHERE workshop_key = 'sensitive_info_disclosure'
    AND challenge_description = 'Exploit path traversal, SSRF, and prompt injection in the FinFlow AI banking agent. 5 user tools + 9 admin tools, 19 objectives.'
    AND NOT EXISTS (
      SELECT 1 FROM workshop_platform.catalog_field_defaults p
      WHERE p.entity_kind='exercise' AND p.workshop_key='sensitive_info_disclosure'
        AND p.objective_id='' AND p.field_name='challenge_description'
        AND p.provenance_state='custom'
    )
  RETURNING workshop_key
), adopted AS (
  UPDATE workshop_platform.catalog_field_defaults p
  SET provenance_state='managed',
      source_version='finflow-description-default-2026-09-15',
      source_hash='a002c709bb3138cfb0fb434a819be377498e86e0b2a1da629dd4a45bb76ab9df',
      source_document=$document${"present":true,"value":"Explore path traversal, SSRF, and prompt injection in the FinFlow AI banking lab through its enabled objectives and isolated training resources."}$document$::jsonb,
      applied_default_version='finflow-description-default-2026-09-15',
      applied_default_hash='a002c709bb3138cfb0fb434a819be377498e86e0b2a1da629dd4a45bb76ab9df',
      applied_default_document=$document${"present":true,"value":"Explore path traversal, SSRF, and prompt injection in the FinFlow AI banking lab through its enabled objectives and isolated training resources."}$document$::jsonb,
      observed_document=$document${"present":true,"value":"Explore path traversal, SSRF, and prompt injection in the FinFlow AI banking lab through its enabled objectives and isolated training resources."}$document$::jsonb, updated_at=now()
  FROM changed c
  WHERE p.entity_kind='exercise' AND p.workshop_key=c.workshop_key
    AND p.objective_id='' AND p.field_name='challenge_description'
    AND p.provenance_state IN ('managed','legacy_unknown')
  RETURNING 1
)
UPDATE workshop_platform.config_revision
SET revision = revision + 1, updated_at = now()
WHERE id = 1 AND EXISTS (SELECT 1 FROM changed);
