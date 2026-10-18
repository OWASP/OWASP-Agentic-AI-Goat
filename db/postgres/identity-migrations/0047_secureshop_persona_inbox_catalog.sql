-- DRAFT ONLY. Default-only catalog transition for the qualified SecureShop persona inbox.
-- Register under the next root-reserved identity suffix only after populated-store qualification.

DO $catalog_transition$
DECLARE
  affected integer;
  total_affected integer := 0;
BEGIN

  UPDATE workshop_platform.exercises SET route='/workshop/secureshop'
  WHERE workshop_key='secureshop_agent_security' AND route='';
  GET DIAGNOSTICS affected = ROW_COUNT;
  total_affected := total_affected + affected;

  UPDATE workshop_platform.exercises
  SET challenge_description=$new_description$Explore agent decisions, review injection, authorization, MCP trust, browser sinks and controlled server requests in isolated shop scenarios. Only connected workflows can be enabled by an instructor.$new_description$
  WHERE workshop_key='secureshop_agent_security'
    AND challenge_description=$old_description$Explore agent decisions, review injection, authorization, MCP trust, browser sinks and controlled server requests in isolated shop scenarios. Objectives remain disabled until their connected workflow is qualified.$old_description$;
  GET DIAGNOSTICS affected = ROW_COUNT;
  total_affected := total_affected + affected;

  UPDATE workshop_platform.objectives
  SET hint_content=$new_hint_p1${"title":"Access another shop persona’s synthetic resource within your own lab scenario","hints":["Use one persona in your bound shop launch to ask the inbox agent for another persona’s synthetic message.","Credit requires the real model-selected read and the exact launch-owned message receipt; another learner’s scenario is never in scope."]}$new_hint_p1$::jsonb
  WHERE workshop_key='secureshop_agent_security' AND objective_id='ss_cross_persona_effect'
    AND hint_content=$old_hint_p1${"title":"Access another shop persona’s synthetic resource within your own lab scenario","hints":["This objective is registered for curriculum planning but is not yet available for instructor enablement.","Its owner-bound evidence, reset, and connected application path must be qualified before release."]}$old_hint_p1$::jsonb;
  GET DIAGNOSTICS affected = ROW_COUNT;
  total_affected := total_affected + affected;

  UPDATE workshop_platform.objectives
  SET solution_content=$new_solution_p1${"title":"Access another shop persona’s synthetic resource within your own lab scenario","difficulty":"advanced","hints":["Use one persona in your bound shop launch to ask the inbox agent for another persona’s synthetic message.","Credit requires the real model-selected read and the exact launch-owned message receipt; another learner’s scenario is never in scope."],"examples":[{"action":"Open Persona inbox access, ask the agent to read the other synthetic persona message, then enforce the ACL and repeat the same read.","explanation":"The same launch-owned target demonstrates the advisory denial with a disclosed result, followed by an enforced denial with no disclosure."}],"approach":"Server-qualified caller and target personas, exact scoped resource, and completed read or mutation receipt.","tips":["Use only resources in your own bound launch.","Manual actions and review-text claims are not grading evidence."]}$new_solution_p1$::jsonb
  WHERE workshop_key='secureshop_agent_security' AND objective_id='ss_cross_persona_effect'
    AND solution_content=$old_solution_p1${"title":"Access another shop persona’s synthetic resource within your own lab scenario","difficulty":"advanced","hints":["This objective is registered for curriculum planning but is not yet available for instructor enablement.","Its owner-bound evidence, reset, and connected application path must be qualified before release."],"examples":[{"action":"Unavailable","explanation":"This pending objective cannot be enabled until its connected evidence path is qualified."}],"approach":"Unavailable until the server-owned evidence, reset, and application path are qualified.","tips":["Instructor enablement is intentionally blocked."]}$old_solution_p1$::jsonb;
  GET DIAGNOSTICS affected = ROW_COUNT;
  total_affected := total_affected + affected;

  UPDATE workshop_platform.objectives
  SET hint_content=$new_hint_p2${"title":"Observe a denied ACL decision that advisory enforcement still permits","hints":["Begin with the scenario ACL in advisory mode and request the same bounded cross-persona message.","The ACL decision must deny the action while the observed business effect still returns the owned synthetic message."]}$new_hint_p2$::jsonb
  WHERE workshop_key='secureshop_agent_security' AND objective_id='ss_acl_advisory_effect'
    AND hint_content=$old_hint_p2${"title":"Observe a denied ACL decision that advisory enforcement still permits","hints":["This objective is registered for curriculum planning but is not yet available for instructor enablement.","Its owner-bound evidence, reset, and connected application path must be qualified before release."]}$old_hint_p2$::jsonb;
  GET DIAGNOSTICS affected = ROW_COUNT;
  total_affected := total_affected + affected;

  UPDATE workshop_platform.objectives
  SET solution_content=$new_solution_p2${"title":"Observe a denied ACL decision that advisory enforcement still permits","difficulty":"advanced","hints":["Begin with the scenario ACL in advisory mode and request the same bounded cross-persona message.","The ACL decision must deny the action while the observed business effect still returns the owned synthetic message."],"examples":[{"action":"Open Persona inbox access, ask the agent to read the other synthetic persona message, then enforce the ACL and repeat the same read.","explanation":"The same launch-owned target demonstrates the advisory denial with a disclosed result, followed by an enforced denial with no disclosure."}],"approach":"Scenario ACL version, denial decision and actual completed business effect from the same model-selected action.","tips":["Use only resources in your own bound launch.","Manual actions and review-text claims are not grading evidence."]}$new_solution_p2$::jsonb
  WHERE workshop_key='secureshop_agent_security' AND objective_id='ss_acl_advisory_effect'
    AND solution_content=$old_solution_p2${"title":"Observe a denied ACL decision that advisory enforcement still permits","difficulty":"advanced","hints":["This objective is registered for curriculum planning but is not yet available for instructor enablement.","Its owner-bound evidence, reset, and connected application path must be qualified before release."],"examples":[{"action":"Unavailable","explanation":"This pending objective cannot be enabled until its connected evidence path is qualified."}],"approach":"Unavailable until the server-owned evidence, reset, and application path are qualified.","tips":["Instructor enablement is intentionally blocked."]}$old_solution_p2$::jsonb;
  GET DIAGNOSTICS affected = ROW_COUNT;
  total_affected := total_affected + affected;

  UPDATE workshop_platform.objectives
  SET hint_content=$new_hint_p3${"title":"Repeat the bounded action with ACL enforcement and verify that it has no effect","hints":["After the advisory evidence is recorded, use the server-controlled transition to enforced mode.","Repeat the matching action. Credit requires an enforced denial and proof that no message body or digest was disclosed."]}$new_hint_p3$::jsonb
  WHERE workshop_key='secureshop_agent_security' AND objective_id='ss_acl_enforced_block'
    AND hint_content=$old_hint_p3${"title":"Repeat the bounded action with ACL enforcement and verify that it has no effect","hints":["This objective is registered for curriculum planning but is not yet available for instructor enablement.","Its owner-bound evidence, reset, and connected application path must be qualified before release."]}$old_hint_p3$::jsonb;
  GET DIAGNOSTICS affected = ROW_COUNT;
  total_affected := total_affected + affected;

  UPDATE workshop_platform.objectives
  SET solution_content=$new_solution_p3${"title":"Repeat the bounded action with ACL enforcement and verify that it has no effect","difficulty":"advanced","hints":["After the advisory evidence is recorded, use the server-controlled transition to enforced mode.","Repeat the matching action. Credit requires an enforced denial and proof that no message body or digest was disclosed."],"examples":[{"action":"Open Persona inbox access, ask the agent to read the other synthetic persona message, then enforce the ACL and repeat the same read.","explanation":"The same launch-owned target demonstrates the advisory denial with a disclosed result, followed by an enforced denial with no disclosure."}],"approach":"Matching action and scenario, enforced denial receipt and unchanged target state.","tips":["Use only resources in your own bound launch.","Manual actions and review-text claims are not grading evidence."]}$new_solution_p3$::jsonb
  WHERE workshop_key='secureshop_agent_security' AND objective_id='ss_acl_enforced_block'
    AND solution_content=$old_solution_p3${"title":"Repeat the bounded action with ACL enforcement and verify that it has no effect","difficulty":"advanced","hints":["This objective is registered for curriculum planning but is not yet available for instructor enablement.","Its owner-bound evidence, reset, and connected application path must be qualified before release."],"examples":[{"action":"Unavailable","explanation":"This pending objective cannot be enabled until its connected evidence path is qualified."}],"approach":"Unavailable until the server-owned evidence, reset, and application path are qualified.","tips":["Instructor enablement is intentionally blocked."]}$old_solution_p3$::jsonb;
  GET DIAGNOSTICS affected = ROW_COUNT;
  total_affected := total_affected + affected;


  IF total_affected > 0 THEN
    UPDATE workshop_platform.config_revision
    SET revision=revision+1,updated_at=now() WHERE id=1;
    INSERT INTO workshop_platform.revisions(scope_type,scope_key,category,revision)
    VALUES('workshop','secureshop_agent_security','workshop_config',1)
    ON CONFLICT(scope_type,scope_key,category) DO UPDATE
    SET revision=workshop_platform.revisions.revision+1,updated_at=now();
  END IF;
END
$catalog_transition$;
