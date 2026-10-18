-- DRAFT ONLY. Run after the exact Persona catalog transition and the catalog
-- field provenance schema. Rows that still equal the reviewed platform default
-- become managed; instructor-modified or otherwise ambiguous rows remain
-- legacy_unknown. This migration changes no learner-visible catalog value.

WITH platform_defaults(entity_kind,workshop_key,objective_id,field_name,source_document,source_hash) AS (
 VALUES
 ('exercise','secureshop_agent_security','','route',
  $json${"present":true,"value":"/workshop/secureshop"}$json$::jsonb,
  '6f4373ee0101e80030b53f240585ca8ca919d3beb6c8282c31be88f8b995cbb1'),
 ('exercise','secureshop_agent_security','','challenge_description',
  $json${"present":true,"value":"Explore agent decisions, review injection, authorization, MCP trust, browser sinks and controlled server requests in isolated shop scenarios. Only connected workflows can be enabled by an instructor."}$json$::jsonb,
  'd203a3f0aa65f5908a4012bc30afba3b8ee730fd69add8d6a88a5ca9e7db0394'),
 ('objective','secureshop_agent_security','ss_cross_persona_effect','hint_content',
  $json${"present":true,"value":{"hints":["Use one persona in your bound shop launch to ask the inbox agent for another persona’s synthetic message.","Credit requires the real model-selected read and the exact launch-owned message receipt; another learner’s scenario is never in scope."],"title":"Access another shop persona’s synthetic resource within your own lab scenario"}}$json$::jsonb,
  'c2659bb78c60d424cf83bc31f3687a92f061f8d4ee81a3a047b6db71c83353ef'),
 ('objective','secureshop_agent_security','ss_cross_persona_effect','solution_content',
  $json${"present":true,"value":{"approach":"Server-qualified caller and target personas, exact scoped resource, and completed read or mutation receipt.","difficulty":"advanced","examples":[{"action":"Open Persona inbox access, ask the agent to read the other synthetic persona message, then enforce the ACL and repeat the same read.","explanation":"The same launch-owned target demonstrates the advisory denial with a disclosed result, followed by an enforced denial with no disclosure."}],"hints":["Use one persona in your bound shop launch to ask the inbox agent for another persona’s synthetic message.","Credit requires the real model-selected read and the exact launch-owned message receipt; another learner’s scenario is never in scope."],"tips":["Use only resources in your own bound launch.","Manual actions and review-text claims are not grading evidence."],"title":"Access another shop persona’s synthetic resource within your own lab scenario"}}$json$::jsonb,
  '91335d6f2a27a744616273ab0da7cb60b325adac3b917e3c1576e78bd341ef3c'),
 ('objective','secureshop_agent_security','ss_acl_advisory_effect','hint_content',
  $json${"present":true,"value":{"hints":["Begin with the scenario ACL in advisory mode and request the same bounded cross-persona message.","The ACL decision must deny the action while the observed business effect still returns the owned synthetic message."],"title":"Observe a denied ACL decision that advisory enforcement still permits"}}$json$::jsonb,
  '324a0fb7102eba972a2033f71a7d05234b731a919a7e428be8707619d6106842'),
 ('objective','secureshop_agent_security','ss_acl_advisory_effect','solution_content',
  $json${"present":true,"value":{"approach":"Scenario ACL version, denial decision and actual completed business effect from the same model-selected action.","difficulty":"advanced","examples":[{"action":"Open Persona inbox access, ask the agent to read the other synthetic persona message, then enforce the ACL and repeat the same read.","explanation":"The same launch-owned target demonstrates the advisory denial with a disclosed result, followed by an enforced denial with no disclosure."}],"hints":["Begin with the scenario ACL in advisory mode and request the same bounded cross-persona message.","The ACL decision must deny the action while the observed business effect still returns the owned synthetic message."],"tips":["Use only resources in your own bound launch.","Manual actions and review-text claims are not grading evidence."],"title":"Observe a denied ACL decision that advisory enforcement still permits"}}$json$::jsonb,
  '1af3c4de7b84f21505b6e48eefa9dd392f87f3e3d1141564edfce5b0b8cca77f'),
 ('objective','secureshop_agent_security','ss_acl_enforced_block','hint_content',
  $json${"present":true,"value":{"hints":["After the advisory evidence is recorded, use the server-controlled transition to enforced mode.","Repeat the matching action. Credit requires an enforced denial and proof that no message body or digest was disclosed."],"title":"Repeat the bounded action with ACL enforcement and verify that it has no effect"}}$json$::jsonb,
  '129878358767c108cfb59c8f0be96de60fc7e6196c87fc087f1bff0bd711b339'),
 ('objective','secureshop_agent_security','ss_acl_enforced_block','solution_content',
  $json${"present":true,"value":{"approach":"Matching action and scenario, enforced denial receipt and unchanged target state.","difficulty":"advanced","examples":[{"action":"Open Persona inbox access, ask the agent to read the other synthetic persona message, then enforce the ACL and repeat the same read.","explanation":"The same launch-owned target demonstrates the advisory denial with a disclosed result, followed by an enforced denial with no disclosure."}],"hints":["After the advisory evidence is recorded, use the server-controlled transition to enforced mode.","Repeat the matching action. Credit requires an enforced denial and proof that no message body or digest was disclosed."],"tips":["Use only resources in your own bound launch.","Manual actions and review-text claims are not grading evidence."],"title":"Repeat the bounded action with ACL enforcement and verify that it has no effect"}}$json$::jsonb,
  'e649d34770e4c5991d2c1ab663eb355dd7a1eb4b02f83777bdee0daef94ae5c4')
), current_fields AS (
 SELECT 'exercise'::text entity_kind,e.workshop_key,''::text objective_id,v.field_name,
        jsonb_build_object('present',true,'value',v.field_value) current_document
 FROM workshop_platform.exercises e
 CROSS JOIN LATERAL (VALUES
   ('challenge_description',to_jsonb(e.challenge_description)),('route',to_jsonb(e.route))
 ) v(field_name,field_value)
 WHERE e.workshop_key='secureshop_agent_security'
 UNION ALL
 SELECT 'objective',o.workshop_key,o.objective_id,v.field_name,
        jsonb_build_object('present',true,'value',v.field_value)
 FROM workshop_platform.objectives o
 CROSS JOIN LATERAL (VALUES
   ('hint_content',to_jsonb(o.hint_content)),('solution_content',to_jsonb(o.solution_content))
 ) v(field_name,field_value)
 WHERE o.workshop_key='secureshop_agent_security'
   AND o.objective_id=ANY(ARRAY['ss_cross_persona_effect','ss_acl_advisory_effect','ss_acl_enforced_block']::text[])
), adoptable AS (
 SELECT d.* FROM platform_defaults d JOIN current_fields c
 USING(entity_kind,workshop_key,objective_id,field_name)
 WHERE c.current_document=d.source_document
)
UPDATE workshop_platform.catalog_field_defaults p
SET provenance_state='managed',source_version='workshop-defaults-2026-09-14-v1',
    source_hash=a.source_hash,source_document=a.source_document,
    applied_default_version='workshop-defaults-2026-09-14-v1',
    applied_default_hash=a.source_hash,applied_default_document=a.source_document,
    observed_document=a.source_document,updated_at=now()
FROM adoptable a
WHERE p.entity_kind=a.entity_kind AND p.workshop_key=a.workshop_key
  AND p.objective_id=a.objective_id AND p.field_name=a.field_name
  AND p.provenance_state='legacy_unknown';
