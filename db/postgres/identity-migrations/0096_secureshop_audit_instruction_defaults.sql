-- Adopt only byte-equivalent semantic defaults inserted by the previously pending audit instruction catalog.
-- Instructor-marked/custom and mismatching unknown values remain untouched.
WITH approved(field_name,document,hash) AS (VALUES
('hint_content','{"present":true,"value":{"hints":["This objective is registered for curriculum planning but is not yet available for instructor enablement.","Its owner-bound evidence, reset, and connected application path must be qualified before release."],"title":"Cause an audit summary to follow an instruction embedded in an owned event log"}}'::jsonb,'6a3416d49e0a83faf3c9496af1c8e4c8b82e269760ca59d1f82ba602dd0ddd95'),
('solution_content','{"present":true,"value":{"approach":"Unavailable until the server-owned evidence, reset, and application path are qualified.","difficulty":"advanced","examples":[{"action":"Unavailable","explanation":"This pending objective cannot be enabled until its connected evidence path is qualified."}],"hints":["This objective is registered for curriculum planning but is not yet available for instructor enablement.","Its owner-bound evidence, reset, and connected application path must be qualified before release."],"tips":["Instructor enablement is intentionally blocked."],"title":"Cause an audit summary to follow an instruction embedded in an owned event log"}}'::jsonb,'d4da60ce3e95619fa8619e83cfaf589cca5d2fe81e7ed50f6c31954a8522b56a')
), matches AS (
 SELECT a.* FROM workshop_platform.objectives o
 CROSS JOIN LATERAL (VALUES ('label',to_jsonb(o.label)),('category',to_jsonb(o.category)),
 ('hint_content',o.hint_content),('solution_content',o.solution_content)) current(field_name,value)
 JOIN approved a ON a.field_name=current.field_name AND a.document=jsonb_build_object('present',true,'value',current.value)
 WHERE o.workshop_key='secureshop_agent_security' AND o.objective_id='ss_audit_instruction_followed'
)
INSERT INTO workshop_platform.catalog_field_defaults(entity_kind,workshop_key,objective_id,field_name,
 provenance_state,source_version,source_hash,source_document,applied_default_version,applied_default_hash,
 applied_default_document,observed_document)
SELECT 'objective','secureshop_agent_security','ss_audit_instruction_followed',field_name,'managed',
 'audit-instruction-0096-known-defaults',hash,document,'audit-instruction-0096-known-defaults',hash,document,document FROM matches
ON CONFLICT(entity_kind,workshop_key,objective_id,field_name) DO UPDATE SET
 provenance_state='managed',source_version=excluded.source_version,source_hash=excluded.source_hash,
 source_document=excluded.source_document,applied_default_version=excluded.applied_default_version,
 applied_default_hash=excluded.applied_default_hash,applied_default_document=excluded.applied_default_document,
 observed_document=excluded.observed_document,updated_at=now()
WHERE catalog_field_defaults.provenance_state='legacy_unknown'
 AND catalog_field_defaults.observed_document=excluded.observed_document;
