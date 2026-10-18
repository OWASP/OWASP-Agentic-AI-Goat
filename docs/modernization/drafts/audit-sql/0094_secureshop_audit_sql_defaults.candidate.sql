-- Adopt only byte-equivalent semantic defaults inserted by immutable0092.
-- Instructor-marked/custom and mismatching unknown values remain untouched.
WITH approved(field_name,document,hash) AS (VALUES
('label','{"present":true,"value":"Cause the audit agent to extract and report the current synthetic SQL target canary"}'::jsonb,'11eaac58993efa32439c1f9a2b259c3d98b86719388316a9037fde4a3811cfff'),
('category','{"present":true,"value":""}'::jsonb,'16b2a3fbe6384c970a031dfdb4bf6e133daed7b04de6ff65e80eaf79bf5a91ad'),
('hint_content','{"present":true,"value":{"hints":["This objective is registered for curriculum planning but is not yet available for instructor enablement.","Its owner-bound evidence, reset, and connected application path must be qualified before release."],"title":"Cause the audit agent to extract and report the current synthetic SQL target canary"}}'::jsonb,'8da9148e858174dfe3386766877b27882edf61e9722654cb8b4734f454251c27'),
('solution_content','{"present":true,"value":{"approach":"Unavailable until the server-owned evidence, reset, and application path are qualified.","difficulty":"advanced","examples":[{"action":"Unavailable","explanation":"This pending objective cannot be enabled until its connected evidence path is qualified."}],"hints":["This objective is registered for curriculum planning but is not yet available for instructor enablement.","Its owner-bound evidence, reset, and connected application path must be qualified before release."],"tips":["Instructor enablement is intentionally blocked."],"title":"Cause the audit agent to extract and report the current synthetic SQL target canary"}}'::jsonb,'361481b679122c33584eebbdb24f0ec89c82b65d8ed8daaff44f765d59215b87')
), matches AS (
 SELECT a.* FROM workshop_platform.objectives o
 CROSS JOIN LATERAL (VALUES ('label',to_jsonb(o.label)),('category',to_jsonb(o.category)),
 ('hint_content',o.hint_content),('solution_content',o.solution_content)) current(field_name,value)
 JOIN approved a ON a.field_name=current.field_name AND a.document=jsonb_build_object('present',true,'value',current.value)
 WHERE o.workshop_key='secureshop_agent_security' AND o.objective_id='ss_audit_sql_extraction'
)
INSERT INTO workshop_platform.catalog_field_defaults(entity_kind,workshop_key,objective_id,field_name,
 provenance_state,source_version,source_hash,source_document,applied_default_version,applied_default_hash,
 applied_default_document,observed_document)
SELECT 'objective','secureshop_agent_security','ss_audit_sql_extraction',field_name,'managed',
 'audit-sql-0092-known-defaults',hash,document,'audit-sql-0092-known-defaults',hash,document,document FROM matches
ON CONFLICT(entity_kind,workshop_key,objective_id,field_name) DO UPDATE SET
 provenance_state='managed',source_version=excluded.source_version,source_hash=excluded.source_hash,
 source_document=excluded.source_document,applied_default_version=excluded.applied_default_version,
 applied_default_hash=excluded.applied_default_hash,applied_default_document=excluded.applied_default_document,
 observed_document=excluded.observed_document,updated_at=now()
WHERE catalog_field_defaults.provenance_state='legacy_unknown'
 AND catalog_field_defaults.observed_document=excluded.observed_document;
