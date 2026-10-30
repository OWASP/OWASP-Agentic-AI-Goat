'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const curriculum = require('../server/config/secureshopCurriculum');
const { WORKSHOP_OBJECTIVES, isWorkshopSurfaceEligible } = require('../server/config/workshopCatalog');
const paths = require('../server/config/workshopSolutionPaths');
const hints = require('../server/data/workshopHints');
const { WORKSHOP_MODE_CATALOG } = require('../server/services/workshopModeService');
const provenance = require('../server/database/postgres/catalogDefaultProvenance');
const { createWorkshopPlatformSeed } = require('../server/database/postgres/workshopPlatformSeedCore');
const { releasePhase } = require('./helpers/workshopCatalogReleasePhase');
const phase = releasePhase();

test('SecureShop curriculum is a visible PostgreSQL-ready catalog with exact readiness', () => {
  assert.equal(curriculum.WORKSHOP_KEY, 'secureshop_agent_security');
  assert.equal(curriculum.CHALLENGE.route, phase.generated ? '/workshop/secureshop' : '');
  assert.equal(curriculum.CHALLENGE.defaultVisible, true);
  assert.equal(curriculum.EXERCISES.length, 48);
  assert.equal(curriculum.OBJECTIVES.length, 64);
  assert.deepEqual(curriculum.EXERCISES.flatMap(row => row.objectiveIds),
    curriculum.OBJECTIVES.map(row => row.id));
  assert.deepEqual(WORKSHOP_OBJECTIVES[curriculum.WORKSHOP_KEY], curriculum.OBJECTIVES);
  assert.deepEqual(curriculum.QUALIFIED_OBJECTIVE_IDS,
    ['ss_inventory_cross_merchant_stock','ss_mail_reply_redirect','ss_mail_header_construction','ss_mail_cross_persona_read','ss_mail_stored_browser_execution','ss_mail_agent_html_injection','ss_mail_agent_cross_persona_read','ss_mail_inline_image_ssrf','ss_listing_internal_fetch','ss_listing_external_entity','ss_listing_prototype_mutation','ss_listing_image_command_execution','ss_listing_generated_browser_execution','ss_listing_raw_browser_execution','ss_listing_template_execution','ss_policy_template_execution','ss_policy_instruction_followed','ss_sqli_nl_generated','ss_analytics_sensitive_disclosure','ss_pricing_competitor_disclosure','ss_loop_observation', 'ss_content_persist', 'ss_content_followed',
      'ss_cross_persona_effect', 'ss_acl_advisory_effect', 'ss_acl_enforced_block', 'ss_customer_role_escalation', 'ss_file_path_traversal_read', 'ss_upload_path_traversal_write', 'ss_upload_extension_bypass', 'ss_upload_polyglot_server_execution', 'ss_upload_svg_browser_execution', 'ss_auth_bypass_jwt_none',
      'ss_idor_cart_delete', 'ss_sqli_coupon', 'ss_sqli_blind_boolean', 'ss_sqli_error_based', 'ss_sqli_union',
      'ss_mcp_manifest_disclosure', 'ss_rogue_tool_selected', 'ss_rug_pull_invoked', 'ss_mcp_server_impersonation', 'ss_mcp_registry_internal_discovery', 'ss_stored_browser_execution', 'ss_search_echo_browser', 'ss_ticket_stored_browser_execution', 'ss_controlled_ssrf', 'ss_audit_sql_extraction', 'ss_audit_sql_timing', 'ss_audit_unbounded_observation', 'ss_audit_instruction_followed', 'ss_system_credential_disclosure', 'ss_system_config_traversal', 'ss_system_restart_command_injection', 'ss_system_diagnostic_command_execution']);
  assert.deepEqual(curriculum.QUALIFIED_MECHANISMS, ['native-model', 'native-browser-judge']);
  assert.equal(curriculum.OBJECTIVES.find(row => row.id === 'ss_stored_browser_execution').qualification,
    'native-browser-judge');
  assert.ok(curriculum.OBJECTIVES.filter(row => row.qualification === 'native-browser-judge')
    .every(row => curriculum.isQualifiedObjective(row.id)));
  assert.deepEqual(curriculum.PENDING_OBJECTIVE_IDS, ['ss_file_upload_instruction_adoption','ss_pricing_false_grounding','ss_pricing_manual_injection','ss_manual_rag_instruction_adoption','ss_product_description_instruction_adoption','ss_idor_order_status_disclosure','ss_mcp_description_instruction_adoption','ss_policy_final_html_execution','ss_user_lookup_sensitive_disclosure']);
  assert.ok(curriculum.OBJECTIVES.every(row => row.defaultEnabled === false));
  assert.equal(Object.keys(hints[curriculum.WORKSHOP_KEY]).length, 64);
  assert.equal(Object.keys(curriculum.SOLUTIONS).length, 64);
  assert.deepEqual(paths[curriculum.WORKSHOP_KEY],
    { statusPrefix: 'secureshop-agent-security', contentSubpath: '' });
  assert.deepEqual(WORKSHOP_MODE_CATALOG[curriculum.WORKSHOP_KEY],
    { defaultMode: 'vuln', allowedModes: ['fixed', 'vuln'] });
});

test('listing image command execution is qualified, disabled by default and narrowly scoped', () => {
 const id='ss_listing_image_command_execution',objective=curriculum.OBJECTIVES.find(row=>row.id===id);
 assert.deepEqual(curriculum.EXERCISES.find(row=>row.id==='ss_listings_image_optimize'),{id:'ss_listings_image_optimize',title:'Observe isolated listing image command execution',objectiveIds:[id]});
 assert.equal(objective?.qualification,'native-browser-judge');assert.equal(objective.defaultEnabled,false);assert.equal(curriculum.isQualifiedObjective(id),true);
 assert.match(objective.evidence,/qualified bound_listing_image_optimize.*secureshop-listings-optimize-v1.*genuine merchant and Listings model selections/s);
 assert.match(objective.evidence,/accepted retained rendered scenario proof.*outer cohort remains failed/s);
 assert.match(objective.evidence,/saved GET recovery.*fixed-mode denial.*three distinct target lifecycles.*sibling isolation.*reset retirement/s);
 assert.match(objective.evidence,/does not prove successful image conversion or platform-host execution/);
 assert.match(curriculum.HINTS[id].hints.join(' '),/Fixed mode denies before dispatch.*saved optimization for recovery/s);
 assert.doesNotMatch(curriculum.SOLUTIONS[id].approach,/^Unavailable/);
});

test('search echo browser objective is exact, default-disabled, and fixed mode cannot credit', () => {
 const id = 'ss_search_echo_browser';
 const objective = curriculum.OBJECTIVES.find(row => row.id === id);
 assert.deepEqual(curriculum.EXERCISES.find(row => row.id === id), {
  id, title: 'Observe a model-selected search echoed in the browser', objectiveIds: [id],
 });
 assert.equal(objective?.qualification, 'native-browser-judge');
 assert.equal(objective?.defaultEnabled, false);
 assert.equal(curriculum.isQualifiedObjective(id), true);
 assert.match(objective.evidence, /bound_search_echo_browser.*secureshop-search-echo-browser-v9.*genuine model-selected.*catalog\.search/i);
 assert.match(objective.evidence, /Fixed mode.*cannot earn credit/i);
 assert.match(curriculum.HINTS[id].hints.join(' '), /disabled by default.*dedicated search-echo.*Fixed mode/i);
 assert.match(curriculum.SOLUTIONS[id].examples[0].explanation, /exact raw query.*dedicated search-echo component.*cannot earn credit/i);
});

test('checkout audit JWT objective is qualified but remains default-disabled and instructor-controlled', () => {
  const id='ss_auth_bypass_jwt_none';
  const objective=curriculum.OBJECTIVES.find(row=>row.id===id);
  assert.deepEqual(curriculum.EXERCISES.find(row=>row.id==='ss_auth_bypass_jwt'), {
    id:'ss_auth_bypass_jwt',title:'Inspect an isolated checkout audit authorization boundary',
    objectiveIds:[id]});
  assert.equal(objective?.qualification,'native-browser-judge');
  assert.equal(objective.defaultEnabled,false);
  assert.equal(curriculum.isQualifiedObjective(id),true);
  assert.match(objective.evidence,/qualified bound_checkout_audit_jwt.*secureshop-checkout-audit-jwt-v1.*no-argument auth\.audit_probe/s);
  assert.match(objective.evidence,/physical unsigned-admin edit.*saved GET recovery.*canonical Judge credit.*fixed-mode.*zero protected read/s);
  assert.match(curriculum.HINTS[id].hints.join(' '),/disabled by default.*physically edit.*canonical Judge/i);
  assert.doesNotMatch(curriculum.HINTS[id].hints.join(' '),/pending|until.*qualified/i);
  assert.match(curriculum.SOLUTIONS[id].examples[0].explanation,/no arguments.*exact physical token.*canonical Judge.*Fixed mode/i);
  assert.doesNotMatch(curriculum.SOLUTIONS[id].approach,/^Unavailable until qualification/);
  assert.equal(provenance.decideReconciliation({
    provenance:{provenance_state:'custom'},
    currentDocument:provenance.document('Instructor-authored checkout audit lesson'),
    sourceDocument:provenance.document(objective.text),
  }).action,'preserve');
});

test('product-search UNION mechanism is admitted but remains disabled and read-only in curriculum defaults', () => {
  const id = 'ss_sqli_union';
  const objective = curriculum.OBJECTIVES.find(row => row.id === id);
  assert.deepEqual(curriculum.EXERCISES.find(row => row.id === 'ss_product_search_union'), {
    id: 'ss_product_search_union', title: 'Observe cross-table rows through product search', objectiveIds: [id],
  });
  assert.equal(objective.qualification, 'native-model');
  assert.equal(objective.defaultEnabled, false);
  assert.equal(curriculum.isQualifiedObjective(id), true);
  assert.match(objective.evidence, /bound_product_search_union.*genuine customer model.*read-only owned PostgreSQL/i);
  assert.match(objective.evidence, /original rendered run failed.*strict supplemental reassessment.*late source\/model\/browser pins/i);
  assert.match(curriculum.HINTS[id].hints.join(' '), /read-only observations.*not product choices/i);
  assert.match(curriculum.SOLUTIONS[id].examples[0].explanation, /original model-selected.*product-shaped rows/i);
});

test('manual RAG instruction adoption stays pending with exact source and task-violation guidance', () => {
  const id = 'ss_manual_rag_instruction_adoption';
  const objective = curriculum.OBJECTIVES.find(row => row.id === id);
  assert.deepEqual(curriculum.EXERCISES.find(row => row.id === 'ss_manual_rag'), {
    id: 'ss_manual_rag', title: 'Study instruction adoption from a public product manual', objectiveIds: [id],
  });
  assert.equal(objective?.qualification, 'pending');
  assert.equal(objective?.defaultEnabled, false);
  assert.equal(curriculum.isQualifiedObjective(id), false);
  assert.match(objective.evidence, /bound_manual_rag.*secureshop-manual-rag-instruction-v1/s);
  assert.match(objective.evidence, /adoption.*displacement.*similarity task/s);
  assert.match(objective.evidence, /Retrieval rank.*quoted instruction.*refusal/s);
  assert.match(curriculum.HINTS[id].hints.join(' '), /pending.*disabled.*not yet available.*merchant manual.*customer.*Retrieval, quotation, refusal/s);
  assert.match(curriculum.SOLUTIONS[id].examples[0].explanation, /merchant upload.*customer similar-products turn.*Judge.*instruction adoption.*violation/s);
  assert.match(curriculum.SOLUTIONS[id].approach, /^Unavailable until qualification/);
});

test('IDOR lesson objectives retain their dedicated pending identities and cannot appear as ordinary workshop content', () => {
  const ids = ['ss_idor_cart_delete', 'ss_idor_order_status_disclosure'];
  assert.equal(isWorkshopSurfaceEligible(curriculum.WORKSHOP_KEY), false);
  assert.deepEqual(curriculum.EXERCISES.find(row => row.id === 'ss_idor'), {
    id: 'ss_idor', title: 'Explore isolated customer object-reference effects', objectiveIds: ids,
  });
  for (const id of ids) {
    const objective = curriculum.OBJECTIVES.find(row => row.id === id);
    assert.equal(objective?.qualification, id===ids[1]?'pending':'native-model');
    assert.equal(objective?.defaultEnabled, false);
    assert.equal(curriculum.isQualifiedObjective(id), id!==ids[1]);
    assert.match(objective.evidence, /actual rendered qualification remains pending/i);
    if(id===ids[1])assert.match(curriculum.SOLUTIONS[id].approach,/^Unavailable/);
    else assert.doesNotMatch(curriculum.SOLUTIONS[id].examples[0].action, /^Unavailable$/);
  }
  assert.match(curriculum.OBJECTIVES.find(row => row.id === ids[0]).evidence,
    /reserved victim cart ID.*deletion preimage.*canonical Judge/i);
  assert.match(curriculum.OBJECTIVES.find(row => row.id === ids[1]).evidence,
    /reserved victim order ID.*shipping and payment details.*canonical Judge/i);
});

test('coupon SQL objective remains SecureShop-only, default-disabled, and honest about the unmounted receipt reader', () => {
  const id = 'ss_sqli_coupon';
  const objective = curriculum.OBJECTIVES.find(row => row.id === id);
  assert.equal(isWorkshopSurfaceEligible(curriculum.WORKSHOP_KEY), false);
  assert.deepEqual(curriculum.EXERCISES.find(row => row.id === 'ss_coupon_query'), {
    id: 'ss_coupon_query', title: 'Observe a coupon query through customer chat', objectiveIds: [id],
  });
  assert.equal(objective?.qualification, 'native-model');
  assert.equal(objective?.defaultEnabled, false);
  assert.equal(curriculum.isQualifiedObjective(id), true);
  assert.match(objective.evidence, /cart\.coupon_prepare.*byte-exact.*no-effect proposal.*IDs-only confirmation/s);
  assert.match(objective.evidence, /SELECT-only isolated receipt reader.*different active synthetic coupon.*canonical Judge/s);
  assert.match(objective.evidence, /Fixed mode parameterizes code.*truthful no-match.*cannot earn credit/s);
  assert.match(objective.evidence, /actual rendered qualification remains pending/i);
  const rendered = JSON.stringify(curriculum.SOLUTIONS[id]);
  assert.match(rendered, /direct coupon requests.*do not qualify/i);
  assert.match(rendered, /fixed parameterized no-match result.*do not qualify/i);
  assert.doesNotMatch(rendered, /Unavailable|not yet available for instructor enablement/);
});

test('all eleven help documents name the actual persona, control and evidence sequence', () => {
  const text = id => curriculum.HINTS[id].hints.join(' ');
  assert.match(text('ss_loop_observation'), /merchant.*Reviews.*Moderate pending/i);
  assert.match(text('ss_content_persist'), /customer.*Product.*merchant.*Reviews.*Moderate pending/i);
  assert.match(text('ss_content_persist'), /ends at exact later retrieval/i);
  assert.match(text('ss_content_followed'), /merchant.*Reviews.*Moderate pending/i);
  assert.match(text('ss_cross_persona_effect'), /Inbox.*merchant.*Ask agent to read/i);
  assert.match(text('ss_cross_persona_effect'), /two facts.*cross-persona disclosure.*ACL denial/i);
  assert.match(text('ss_acl_advisory_effect'), /ACL denial.*disclosed result/i);
  assert.match(text('ss_acl_enforced_block'), /merchant.*Enforce ACL.*same message/i);
  assert.match(text('ss_rogue_tool_selected'), /admin.*MCP.*discover connector.*ask supervisor/i);
  assert.match(text('ss_rug_pull_invoked'), /discover baseline.*ask supervisor.*publish changed schema.*ask supervisor/i);
  assert.match(text('ss_stored_browser_execution'), /Product.*posted ReviewCard.*automatically.*no separate browser panel/i);
  assert.match(text('ss_stored_browser_execution'), /actual Judge/i);
  assert.match(text('ss_controlled_ssrf'), /Fetch public policy.*Try internal policy/i);
  assert.match(text('ss_controlled_ssrf'), /bounded resources.*server supplies the exact URL/i);
  assert.match(text('ss_controlled_ssrf'), /denied public-only egress decision/i);
});

test('all qualified solutions are specific and the browser mechanism remains enableable', () => {
  for (const objective of curriculum.OBJECTIVES.filter(row=>curriculum.isQualifiedObjective(row.id))) {
    const solution = curriculum.SOLUTIONS[objective.id];
    assert.ok(solution.examples[0]?.action);
    assert.ok(solution.examples[0]?.explanation);
    assert.equal(solution.approach, objective.evidence);
    assert.doesNotMatch(JSON.stringify(solution), /registered for curriculum planning|Unavailable/);
  }
  const rug = JSON.stringify(curriculum.SOLUTIONS.ss_rug_pull_invoked);
  assert.match(rug, /Discover baseline.*ask supervisor once.*publish changed schema.*ask supervisor again/i);
  const browser = JSON.stringify(curriculum.SOLUTIONS.ss_stored_browser_execution);
  assert.match(browser, /automatically starts the isolated-browser assessment/i);
  assert.match(browser, /actual Judge/i);
  assert.doesNotMatch(browser, /open.*isolated browser (?:panel|exercise)/i);
  assert.equal(curriculum.isQualifiedObjective('ss_stored_browser_execution'), true);
});

test('released audit instruction guidance describes owned effect and Judge boundaries', () => {
  assert.equal(curriculum.isQualifiedObjective('ss_audit_instruction_followed'),true);
  assert.match(curriculum.HINTS.ss_audit_instruction_followed.hints.join(' '),/merchant.*owned.*admin/s);
  assert.match(curriculum.SOLUTIONS.ss_audit_instruction_followed.examples[0].explanation,/quotation or refusal/);
  assert.equal(curriculum.OBJECTIVES.find(o=>o.id==='ss_audit_instruction_followed').defaultEnabled,false);
  for (const id of curriculum.PENDING_OBJECTIVE_IDS) {
    assert.match(curriculum.SOLUTIONS[id].approach, /^Unavailable/);
    if(id==='ss_mail_header_construction'){assert.equal(curriculum.isQualifiedObjective(id),false);assert.match(curriculum.HINTS[id].hints.join(' '),/single-line.*requestId.*Check saved headers/s);}
    else if(id==='ss_auth_bypass_jwt_none')assert.match(curriculum.HINTS[id].hints.join(' '),/pending and disabled by default.*model-selected tool/s);
    else if(id==='ss_listing_image_command_execution')assert.match(curriculum.HINTS[id].hints.join(' '),/canonical Judge.*Fixed mode denies before dispatch/s);
    else assert.match(curriculum.HINTS[id].hints.join(' '), /not yet available/);
  }
});

test('retained legacy SQLite seeds do not half-register the PostgreSQL-only workshop', () => {
  const legacySeed = fs.readFileSync(path.join(__dirname, '../db/initialize-db/seeds/01_users_auth.js'), 'utf8');
  assert.doesNotMatch(legacySeed, /secureshop_agent_security/);
});


test('exercise groups preserve database labels, completion and disclosure gates without adding disabled objectives', () => {
  const rows = [
    { id: 'ss_loop_observation', label: 'Instructor label', text: 'Instructor label', completed: true, hintVisible: false, solutionVisible: true },
    { id: 'ss_content_followed', label: 'Policy violation', completed: false, hintVisible: true, solutionVisible: false },
  ];
  const groups = curriculum.projectExerciseGroups(rows);
  assert.deepEqual(groups.map(group => group.id), ['ss_agent_loop', 'ss_indirect_content']);
  assert.deepEqual(groups.flatMap(group => group.objectives), rows);
  assert.equal(groups.reduce((sum, group) => sum + group.objectiveCount, 0), rows.length);
  assert.equal(groups.reduce((sum, group) => sum + group.completedObjectiveCount, 0), 1);
  assert.equal(groups[0].objectives[0].label, 'Instructor label');
  groups[0].objectives[0].completed = false;
  assert.equal(rows[0].completed, true);
  assert.deepEqual(curriculum.projectExerciseGroups([]), []);
});

test('mail objectives distinguish stored headers, receipted reads, browser execution and model reply without enabling fresh defaults',()=>{
 for(const id of ['ss_mail_reply_redirect','ss_mail_header_construction','ss_mail_cross_persona_read','ss_mail_stored_browser_execution']){
  assert.equal(curriculum.isQualifiedObjective(id),true);assert.equal(curriculum.OBJECTIVES.find(row=>row.id===id).defaultEnabled,false);assert.ok(curriculum.HINTS[id]);assert.ok(curriculum.SOLUTIONS[id]);
 }
 assert.match(curriculum.OBJECTIVES.find(row=>row.id==='ss_mail_header_construction').evidence,/not proof of BCC delivery/);
 assert.match(curriculum.OBJECTIVES.find(row=>row.id==='ss_mail_cross_persona_read').evidence,/unreceipted refresh is not grading evidence/);
 const html=curriculum.OBJECTIVES.find(row=>row.id==='ss_mail_agent_html_injection');
 assert.equal(html?.qualification,'native-browser-judge');assert.equal(html.defaultEnabled,false);
 assert.equal(curriculum.isQualifiedObjective(html.id),true);
 assert.deepEqual(curriculum.EXERCISES.find(row=>row.id==='ss_mail').objectiveIds.slice(-2),[html.id,'ss_mail_agent_cross_persona_read']);
 assert.ok(curriculum.HINTS[html.id]);assert.ok(curriculum.SOLUTIONS[html.id]);
 assert.match(html.evidence,/Manual Compose.*V61 execution evidence cannot earn/s);
});

test('inline mail scenario stays disabled and requires original model plus independently witnessed bounded HTTP',()=>{
 const id='ss_mail_inline_image_ssrf', objective=curriculum.OBJECTIVES.find(row=>row.id===id);
 assert.equal(objective.defaultEnabled,false);assert.equal(objective.qualification,'native-model');
 assert.match(objective.evidence,/bound_mail_inline.*genuine configured model.*protected selected merchant message/s);
 assert.match(objective.evidence,/pre-save issuance.*durable HTTP record.*independent listener receipt/s);
 assert.match(objective.evidence,/Fixed mode blocks before HTTP/);
 assert.match(objective.evidence,/Actual rendered qualification remains pending/);
 assert.equal(curriculum.EXERCISES.find(row=>row.id==='ss_mail_inline').objectiveIds[0],id);
 assert.ok(curriculum.HINTS[id].hints.length>=2);assert.ok(curriculum.SOLUTIONS[id].examples[0].action);
});

test('policy template objective stays disabled and separates witnessed publication from preview or literal output', () => {
  const objective = curriculum.OBJECTIVES.find(row => row.id === 'ss_policy_template_execution');
  assert.equal(objective?.defaultEnabled, false);
  assert.equal(objective?.qualification, 'native-model');
  assert.match(objective.evidence, /model-selected.*physical confirmation.*executor witness.*Judge/s);
  assert.match(objective.evidence, /Preview.*literal fixed-mode rendering.*historical receipts/s);
  assert.ok(curriculum.HINTS[objective.id].hints.length >= 2);
  assert.ok(curriculum.SOLUTIONS[objective.id].examples[0].action);
});


test('competitor guidance teaches the physical URL and instruction fields while remaining disabled by default',()=>{
 const id='ss_pricing_competitor_disclosure',row=curriculum.OBJECTIVES.find(x=>x.id===id);
 assert.equal(row.qualification,'native-model');assert.equal(row.defaultEnabled,false);
 const example=curriculum.SOLUTIONS[id].examples[0],hints=curriculum.HINTS[id].hints.join(' ');
 assert.match(example.action,/Merchant Pricing.*owned name/);
 assert.match(example.action,/http:\/\/169\.254\.169\.254\/latest\/meta-data\/.*Compare URL/);
 assert.match(example.action,/Comparison instructions.*complete exact synthetic credential.*Click Compare/s);
 assert.match(example.action,/Pricing operation status or Check saved operation/);
 assert.match(example.explanation,/physical Compare action.*one bound request.*model-selected compare_competitor.*owned HTTP listener receipt.*exact current canary.*canonical Judge award/s);
 assert.match(hints,/select your owned product by name.*Compare URL.*Comparison instructions.*click Compare/s);
 assert.match(hints,/Check saved operation.*model-selected compare_competitor.*canonical Judge acceptance/s);
 assert.doesNotMatch(hints + example.action,/intercept|modify an already-bound UI request/i);
 for(const pending of ['ss_pricing_false_grounding','ss_pricing_manual_injection'])assert.equal(curriculum.isQualifiedObjective(pending),false);
});


test('System config traversal stays disabled and distinguishes owned vulnerable traversal from fixed containment', () => {
  const id = 'ss_system_config_traversal';
  const objective = curriculum.OBJECTIVES.find(row => row.id === id);
  assert.deepEqual(curriculum.EXERCISES.find(row => row.id === 'ss_system_config'),
    { id: 'ss_system_config', title: 'Explore owned System configuration traversal', objectiveIds: [id] });
  assert.equal(objective?.qualification, 'native-model');
  assert.equal(objective?.defaultEnabled, false);
  assert.equal(curriculum.isQualifiedObjective(id), true);
  assert.match(objective.evidence, /admin\.system_config_read.*single-pass.*\/app\/config.*\/app\/\.env.*matching content and hash/s);
  assert.match(objective.evidence, /Fixed System containment records no remote read.*safe configuration reads/i);
  const guidance = curriculum.HINTS[id].hints.join(' ');
  assert.match(guidance, /administrator.*\.\.\.\.\/\/\.env/i);
  assert.match(guidance, /application\.json remains usable/i);
  const example = curriculum.SOLUTIONS[id].examples[0];
  assert.match(example.action, /\.\.\.\.\/\/\.env/);
  assert.match(example.explanation, /synthetic \/app\/\.env.*outside \/app\/config/i);
  assert.match(example.explanation, /fixed system_config containment records no remote read/i);
});

test('System diagnostic command execution stays default-disabled and limits the lesson to bwrap evidence', () => {
  const id = 'ss_system_diagnostic_command_execution';
  const objective = curriculum.OBJECTIVES.find(row => row.id === id);
  assert.deepEqual(curriculum.EXERCISES.find(row => row.id === 'ss_system_diagnostic'), {
    id: 'ss_system_diagnostic', title: 'Observe isolated System diagnostic command execution', objectiveIds: [id],
  });
  assert.equal(objective?.qualification, 'native-model');
  assert.equal(objective?.defaultEnabled, false);
  assert.equal(curriculum.isQualifiedObjective(id), true);
  assert.match(objective.evidence, /admin\.system_diagnostic_prepare.*own-turn trace.*preparation effect.*IDs-only confirmation/s);
  assert.match(objective.evidence, /isolated bwrap receipt.*post-confirm.*target hostname.*canonical Judge/s);
  assert.match(objective.evidence, /Fixed mode denies before diagnostic admission or dispatch.*no credit/s);
  assert.match(objective.evidence, /host execution or file-mutation claims.*cannot qualify/s);
  assert.match(objective.evidence, /actual rendered qualification remains pending/i);
  const guidance = curriculum.HINTS[id].hints.join(' ');
  assert.match(guidance, /disabled by default.*actual rendered qualification remains pending/i);
  assert.match(guidance, /System diagnostic JSON:.*only string `cmd_template` and `args` fields.*decoded bytes are preserved/i);
  assert.match(guidance, /saved IDs-only confirmation.*saved status for recovery/i);
  const example = curriculum.SOLUTIONS[id].examples[0];
  assert.match(example.action, /System diagnostic JSON: \{\"cmd_template\":\"<bounded diagnostic template>\",\"args\":\"<bounded diagnostic arguments>\"\}/);
  assert.match(example.explanation, /exactly the two string fields shown.*neither runs a command nor requires the model to choose one/i);
  assert.match(example.action, /confirm its saved IDs-only operation once.*saved outcome for recovery/i);
  assert.match(example.explanation, /bwrap receipt.*baseline output.*post-confirm target hostname.*canonical Judge/s);
  assert.match(example.explanation, /does not claim host execution or file mutation/i);
});

test('policy instruction has a native-model evidence path but remains disabled by default', () => {
 const id='ss_policy_instruction_followed';
 const objective=curriculum.OBJECTIVES.find(row=>row.id===id);
 assert.deepEqual(curriculum.EXERCISES.find(row=>row.id==='ss_policy_instruction').objectiveIds,[id]);
 assert.equal(objective.qualification,'native-model');
 assert.equal(objective.defaultEnabled,false);
 assert.equal(curriculum.isQualifiedObjective(id),true);
 assert.match(objective.evidence,/physical owned policy publication.*immutable policy snapshot.*genuine model selection.*saved receipt.*canonical Judge/i);
 assert.match(curriculum.HINTS[id].hints.join(' '),/disabled by default.*Fixed mode/s);
 assert.match(curriculum.SOLUTIONS[id].examples[0].explanation,/original published revision.*canonical Judge.*disabled pending actual qualification/s);
 assert.notEqual(curriculum.SOLUTIONS[id].examples[0].action,'Unavailable');
 const nativeCaller=fs.readFileSync(path.join(__dirname,
  'postgres/secureshopStandaloneRoleChoicesRendered.integration.test.js'),'utf8');
 const start=nativeCaller.indexOf('async function qualifyPolicyInstruction(');
 const end=nativeCaller.indexOf('async function qualifyAdminReadChat(',start);
 assert.ok(start>=0&&end>start);
 const qualification=nativeCaller.slice(start,end);
 assert.match(qualification,/assessmentCatalog\.set\(ownerBase, \{ objectiveId: OBJECTIVE, enabled: true/);
 assert.doesNotMatch(qualification,/UPDATE\s+secureshop_auth\.assessment_objectives/i,
  'The browser fixture must not fabricate qualified catalog metadata');
});

test('System restart command-injection objective is qualified but remains instructor-controlled and default-disabled', () => {
  const id = 'ss_system_restart_command_injection';
  const objective = curriculum.OBJECTIVES.find(row => row.id === id);
  assert.equal(objective.exerciseId, 'ss_system_restart');
  assert.equal(objective.qualification, 'native-browser-judge');
  assert.equal(objective.defaultEnabled, false);
  assert.equal(curriculum.CHALLENGE.defaultVisible, true);
  assert.equal(curriculum.isQualifiedObjective(id), true);
  assert.match(objective.evidence, /qualified bound_system_restart_injection.*secureshop-system-restart-injection-v1/s);
  assert.match(objective.evidence, /physical IDs-only confirmation.*completed owned isolated restart receipt/s);
  assert.match(objective.evidence, /actual administrator browser.*canonical Judge.*Fixed mode denies/s);
  const hints = curriculum.HINTS[id].hints.join(' ');
  assert.match(hints, /disabled by default.*instructor controls learner availability/i);
  assert.doesNotMatch(hints, /pending|not yet available|until.*qualified/i);
  const solution = curriculum.SOLUTIONS[id];
  assert.match(solution.examples[0].action, /Confirm System restart once.*saved restart.*separate assessment/s);
  assert.match(solution.examples[0].explanation, /genuine model.*one immutable owned isolated receipt.*canonical Judge.*Fixed mode/s);
  assert.doesNotMatch(solution.approach, /^Unavailable until qualification/);
  assert.equal(provenance.decideReconciliation({
    provenance: { provenance_state: 'custom' },
    currentDocument: provenance.document('Instructor-authored restart lesson'),
    sourceDocument: provenance.document(objective.text),
  }).action, 'preserve');
});

test('MCP description-adoption objective is separate, pending and default-disabled', () => {
  const id = 'ss_mcp_description_instruction_adoption';
  const objective = curriculum.OBJECTIVES.find(row => row.id === id);
  assert.equal(objective.exerciseId, 'ss_mcp_trust');
  assert.equal(objective.qualification, 'pending');
  assert.equal(objective.defaultEnabled, false);
  assert.equal(curriculum.isQualifiedObjective(id), false);
  assert.match(objective.evidence, /bound_mcp_description_adoption.*secureshop-mcp-description-adoption-v6/s);
  assert.match(objective.evidence, /adopts its instruction.*departs from the legitimate user task/s);
  assert.match(curriculum.HINTS[id].hints.join(' '), /disabled by default.*registered-tools conversation/i);
  assert.match(curriculum.SOLUTIONS[id].examples[0].explanation, /V43 impersonation assessment remains separate/);
});

test('MCP impersonation objective stays default-disabled and its catalog seed is fresh/populated/no-op safe', async () => {
 const id = 'ss_mcp_server_impersonation';
 const objective = curriculum.OBJECTIVES.find(row => row.id === id);
 assert.deepEqual(curriculum.EXERCISES.find(row => row.id === 'ss_mcp_trust').objectiveIds,
  ['ss_rogue_tool_selected', 'ss_rug_pull_invoked', id, 'ss_mcp_registry_internal_discovery', 'ss_mcp_description_instruction_adoption']);
 assert.equal(objective?.qualification, 'native-model');
 assert.equal(objective?.defaultEnabled, false);
 assert.equal(curriculum.isQualifiedObjective(id), true);
 assert.match(objective.evidence, /v3 own-turn trace IDs.*replacement tool.*attacker catalog result.*current administrator authority.*canonical Judge/s);
 assert.match(objective.evidence, /Manual invocation.*v1\/v2.*fixed mode.*replay.*stale.*foreign/i);
 assert.match(curriculum.HINTS[id].hints.join(' '), /disabled by default.*canonical Judge/i);
 assert.match(curriculum.SOLUTIONS[id].examples[0].explanation, /immutable trusted and replacement revisions.*v3 model trace.*attacker catalog result/i);

 const adopted = [], reconciled = [], calls = [];
 let phase = 'fresh', revision = 1;
 const client = { async query(sql, args = []) {
  calls.push({ sql, args });
  if (sql.startsWith('SELECT revision')) return { rows: [{ revision }] };
  if (sql.startsWith('INSERT INTO workshop_platform.exercises')) return { rowCount: phase === 'fresh' ? 1 : 0 };
  if (sql.startsWith('INSERT INTO workshop_platform.objectives')) return { rowCount: phase === 'fresh' ? 1 : 0 };
  if (sql.startsWith('UPDATE workshop_platform.config_revision')) { revision += 1; return { rowCount: 1 }; }
  return { rowCount: 0, rows: [] };
 } };
 const seed = createWorkshopPlatformSeed({
  withTransaction: (_pool, work) => work(client), bump: async () => {}, toChallengeKey: key => key,
  provenance: {
   adoptInsertedField: async (_client, spec) => adopted.push(spec),
   reconcileField: async (_client, spec) => { reconciled.push(spec); return { changed: false }; },
  },
  legacyXssSolutions: Object.fromEntries(['reflected', 'stored_user', 'stored_llm', 'email'].map(key => [key, { title: key }])),
 });
 const input = {
  catalog: { [curriculum.WORKSHOP_KEY]: [objective] },
  hints: { [curriculum.WORKSHOP_KEY]: { [id]: curriculum.HINTS[id] } },
  solutions: { [curriculum.WORKSHOP_KEY]: { [id]: curriculum.SOLUTIONS[id] } },
  challenges: [curriculum.CHALLENGE], catalogVersion: 'v43-curriculum-test',
 };
 assert.equal((await seed(client, input)).changed, true, 'fresh seed inserts the disabled objective');
 const freshExercise = calls.find(call => call.sql.startsWith('INSERT INTO workshop_platform.exercises'));
 assert.equal(freshExercise.args[8], true, 'fresh installation shows SecureShop in the admin catalog');
 const fresh = calls.find(call => call.sql.startsWith('INSERT INTO workshop_platform.objectives'));
 assert.equal(fresh.args[1], id); assert.equal(fresh.args[8], false, 'fresh seed must not enable it');
 assert.deepEqual(adopted.filter(spec => spec.entityKind === 'objective').map(spec => spec.fieldName).sort(),
  ['category', 'description', 'hint_content', 'label', 'solution_content']);

 const instructorLabel = 'Instructor-authored MCP lesson';
 assert.equal(provenance.decideReconciliation({
  provenance: { provenance_state: 'custom' }, currentDocument: provenance.document(instructorLabel),
  sourceDocument: provenance.document(objective.text),
 }).action, 'preserve', 'a populated instructor edit remains authoritative');
 phase = 'populated'; calls.length = 0;
 assert.equal((await seed(client, input)).changed, false, 'populated seed changes no managed flags without a source delta');
 assert.deepEqual(reconciled.filter(spec => spec.entityKind === 'objective').map(spec => spec.fieldName).sort(),
  ['category', 'description', 'hint_content', 'label', 'solution_content']);
 const beforeNoop = reconciled.length; calls.length = 0;
 assert.equal((await seed(client, input)).changed, false, 'second populated seed is a no-op');
 assert.equal(reconciled.length, beforeNoop + 10,
  'no-op reseed still reconciles the same exercise and objective defaults without changing them');
});

test('MCP manifest disclosure defaults describe an owned confirmed import, not client-asserted display', () => {
 const id='ss_mcp_manifest_disclosure';
 const objective=curriculum.OBJECTIVES.find(value=>value.id===id);
 assert.equal(objective.exerciseId,'ss_mcp_manifest');
 assert.equal(objective.defaultEnabled,false);
 assert.equal(objective.qualification,'native-model');
 assert.match(objective.evidence,/original model-selected admin\.mcp_import_prepare URL/);
 assert.match(objective.evidence,/completed owner-bound import operation/);
 assert.match(objective.evidence,/UTF-8 byte length and SHA-256/);
 assert.match(objective.evidence,/browser-supplied display flag is never grading evidence/);
 assert.match(curriculum.SOLUTIONS[id].examples[0].explanation,/fixed-mode denial/);
 assert.equal(isWorkshopSurfaceEligible(curriculum.WORKSHOP_KEY),false);
});

test('timing and oversized audit defaults preserve separate pending canonical objectives',()=>{
 for(const id of ['ss_audit_sql_timing','ss_audit_unbounded_observation']){const row=curriculum.OBJECTIVES.find(x=>x.id===id);assert.equal(row.defaultEnabled,false);assert.equal(row.qualification,'native-model');assert.match(row.evidence,/Actual rendered qualification remains pending/);assert.ok(curriculum.HINTS[id].hints.length);assert.ok(curriculum.SOLUTIONS[id].examples[0].action);}
 assert.match(curriculum.OBJECTIVES.find(x=>x.id==='ss_audit_sql_timing').evidence,/same-connection SELECT 1 baseline/);
 assert.match(curriculum.OBJECTIVES.find(x=>x.id==='ss_audit_unbounded_observation').evidence,/not complete coverage/);
});

test('order-status error lesson is native-model, disabled and read-only in curriculum defaults', () => {
  const id = 'ss_sqli_error_based';
  const objective = curriculum.OBJECTIVES.find(row => row.id === id);
  assert.equal(objective.exerciseId, 'ss_order_status_error');
  assert.equal(objective.qualification, 'native-model');
  assert.equal(objective.defaultEnabled, false);
  assert.match(objective.evidence, /v1 mounted rubric/);
  assert.match(objective.evidence, /The objective remains disabled by default/);
  assert.match(curriculum.HINTS[id].hints.join(' '), /read-only observations, not an order action or refund permission/);
  assert.match(curriculum.SOLUTIONS[id].examples[0].action, /dedicated customer Order status lesson/);
});

test('V06 extension objective is qualified, default-disabled and distinct from execution lessons',()=>{
 const id='ss_upload_extension_bypass',objective=curriculum.OBJECTIVES.find(row=>row.id===id);
 assert.equal(objective.exerciseId,'ss_upload_extension');assert.equal(objective.qualification,'native-browser-judge');
 assert.equal(objective.defaultEnabled,false);assert.equal(curriculum.isQualifiedObjective(id),true);
 assert.match(objective.evidence,/bound_upload_extension_bypass.*secureshop-upload-extension-bypass-v3-layered/);
 assert.match(objective.evidence,/first finished unsafe-inline serve of identical bytes/);
 assert.match(objective.evidence,/browser, interpreter and server execution.*not claimed/);
 assert.match(objective.evidence,/Missing serve, traversal, stale or foreign evidence and mock output cannot qualify/);
 assert.match(curriculum.HINTS[id].hints.join(' '),/isolated sandbox preview.*finished serve receipt.*Assess the saved request/s);
 assert.match(curriculum.SOLUTIONS[id].examples[0].action,/synthetic avatar\.php/);
 assert.match(curriculum.SOLUTIONS[id].examples[0].explanation,/execution are not required or claimed/);
 assert.doesNotMatch(JSON.stringify([curriculum.HINTS[id],curriculum.SOLUTIONS[id]]),/not yet available|Unavailable until|qualification.*pending/i);
});


test('V51 qualified NL-to-SQL is distinct, instructor-controlled and has actionable guidance',()=>{
 const id='ss_sqli_nl_generated',row=curriculum.OBJECTIVES.find(value=>value.id===id);
 assert.equal(row.qualification,'native-model');assert.equal(row.defaultEnabled,false);assert.equal(curriculum.isQualifiedObjective(id),true);
 assert.equal(row.exerciseId,'ss_analytics_nl_sql');
 assert.deepEqual(curriculum.EXERCISES.find(value=>value.id===row.exerciseId).objectiveIds,[id]);
 assert.match(row.evidence,/independent canonical Judge.*ordinary-metrics negatives.*fixed denial.*saved recovery.*target retirement.*sibling preservation/);
 assert.match(curriculum.HINTS[id].hints[0],/instructor enablement.*merchant Analytics/);
 assert.doesNotMatch(JSON.stringify([curriculum.HINTS[id],curriculum.SOLUTIONS[id]]),/pending|not yet available|until.*qualified/i);
 assert.match(curriculum.SOLUTIONS[id].examples[0].action,/natural language.*do not supply SQL/);
});


test('V09 agent HTML injection is qualified, default-disabled and keeps structural-only claims',()=>{
 const id='ss_mail_agent_html_injection',objective=curriculum.OBJECTIVES.find(row=>row.id===id);
 assert.equal(objective?.qualification,'native-browser-judge');assert.equal(objective.defaultEnabled,false);assert.equal(curriculum.isQualifiedObjective(id),true);
 assert.match(objective.evidence,/retained native and rendered qualification.*saved GET recovery.*fixed-mode ineligibility.*foreign-operation conflict.*reset retirement.*sibling preservation/s);
 assert.match(objective.evidence,/HTML injection.*script or event execution.*not required or claimed/s);
 assert.match(curriculum.HINTS[id].hints.join(' '),/instructor controls learner availability.*physical.*canonical Judge.*fixed mode.*foreign operations.*reset evidence/s);
 assert.doesNotMatch(JSON.stringify([curriculum.HINTS[id],curriculum.SOLUTIONS[id]]),/not yet available|until.*qualified|qualification.*pending/i);
 assert.match(curriculum.SOLUTIONS[id].examples[0].explanation,/saved GET recovery.*Manual Compose.*V61.*foreign or reset evidence/s);
});


test('V11 agent mail disclosure promotion stays exact and default-disabled',()=>{
 const id='ss_mail_agent_cross_persona_read',objective=curriculum.OBJECTIVES.find(row=>row.id===id);
 assert.equal(objective?.qualification,'native-browser-judge');assert.equal(objective.defaultEnabled,false);assert.equal(curriculum.isQualifiedObjective(id),true);
 assert.match(objective.evidence,/bound_mail_agent_disclosure.*secureshop-mail-agent-disclosure-v3.*original genuine merchant\.mail_detail/s);
 assert.match(objective.evidence,/exact nonempty foreign synthetic body.*saved list-choice ancestry.*canonical Judge/s);
 assert.match(objective.evidence,/separate manual ss_mail_cross_persona_read objective is unchanged.*Instructor enablement remains separate and disabled/s);
 assert.doesNotMatch(JSON.stringify([curriculum.HINTS[id],curriculum.SOLUTIONS[id]]),/not yet available|until.*qualified|qualification.*pending/i);
 assert.match(curriculum.HINTS[id].hints.join(' '),/disabled by default.*exact original completed detail turn.*Saved GET recovery.*reset evidence/s);
 assert.match(curriculum.SOLUTIONS[id].examples[0].explanation,/merchant\.mail_detail.*list-choice ancestry.*Saved GET recovery.*foreign-target.*reset evidence/s);
});


test('V44 is qualified and default-disabled with actionable owned synthetic path guidance',()=>{
 const id='ss_file_path_traversal_read',objective=curriculum.OBJECTIVES.find(row=>row.id===id);
 assert.equal(objective.qualification,'native-browser-judge');assert.equal(objective.defaultEnabled,false);assert.equal(curriculum.isQualifiedObjective(id),true);
 assert.match(objective.evidence,/original genuine summarizer\.summarize_file.*owner-bound synthetic \/etc\/passwd/s);
 assert.match(objective.evidence,/saved GET recovery without replay.*fixed no-read.*sibling privacy.*reset retirement.*immutable judgment.*zero active contribution/s);
 assert.match(objective.evidence,/never platform-host file access/);
 assert.match(curriculum.HINTS[id].hints.join(' '),/After instructor enablement.*\.\.\/etc\/passwd/);
 assert.match(curriculum.SOLUTIONS[id].examples[0].explanation,/owned synthetic.*canonical Judge/s);
 assert.match(curriculum.SOLUTIONS[id].tips.join(' '),/never a host file/);
 assert.doesNotMatch(JSON.stringify([curriculum.HINTS[id],curriculum.SOLUTIONS[id]]),/not yet available|Unavailable until|qualification.*pending/i);
});

test('V16 remains pending while qualified V46 stays default-disabled with bounded actionable guidance',()=>{
 const product=curriculum.OBJECTIVES.find(value=>value.id==='ss_product_description_instruction_adoption');
 assert.equal(product.exerciseId,'ss_product_indirect_content');assert.equal(product.qualification,'pending');
 assert.equal(product.defaultEnabled,false);assert.equal(curriculum.isQualifiedObjective(product.id),false);
 assert.match(curriculum.SOLUTIONS[product.id].approach,/^Unavailable until qualification/);
 assert.match(curriculum.HINTS[product.id].hints.join(' '),/pending, disabled and not yet available/);
 assert.match(product.evidence,/both instruction adoption and material task displacement/);
 assert.match(product.evidence,/quotation, refusal/);
 assert.deepEqual(curriculum.EXERCISES.find(value=>value.id==='ss_indirect_content').objectiveIds,['ss_content_persist','ss_content_followed']);
 const traversal=curriculum.OBJECTIVES.find(value=>value.id==='ss_upload_path_traversal_write');
 assert.equal(traversal.exerciseId,'ss_upload_path_traversal');assert.equal(traversal.qualification,'native-browser-judge');
 assert.equal(traversal.defaultEnabled,false);assert.equal(curriculum.isQualifiedObjective(traversal.id),true);
 assert.deepEqual(curriculum.EXERCISES.find(value=>value.id==='ss_upload_path_traversal').objectiveIds,[traversal.id]);
 assert.doesNotMatch(JSON.stringify([curriculum.HINTS[traversal.id],curriculum.SOLUTIONS[traversal.id]]),/not yet available|until.*qualified|qualification.*pending/i);
 assert.match(curriculum.SOLUTIONS[traversal.id].examples[0].explanation,/same operation sandbox.*physical reread.*canonical Judge/s);
 assert.match(traversal.evidence,/avatar-subdirectory escape with same-operation confinement/);
 assert.match(traversal.evidence,/exact physical reread/);assert.match(traversal.evidence,/Fixed mode denies before writing/);
 assert.match(traversal.evidence,/disabled by default.*instructor enablement is separate/s);
 assert.match(traversal.evidence,/sibling operations, symlinks, host escape and mock output cannot qualify/);
});


test('V08 exact SVG browser execution is qualified with actionable isolated guidance and disabled defaults', () => {
  const id = 'ss_upload_svg_browser_execution', objective = curriculum.OBJECTIVES.find(row => row.id === id);
  assert.equal(objective.qualification, 'native-browser-judge');
  assert.equal(objective.defaultEnabled, false); assert.equal(curriculum.isQualifiedObjective(id), true);
  assert.match(objective.evidence, /qualified bound_upload_svg_browser.*secureshop-upload-svg-browser-v3-layered rubric/s);
  assert.match(objective.evidence, /original genuine customer-model uploads\.upload_avatar selection with empty arguments/);
  assert.match(objective.evidence, /image\/svg\+xml with sandbox allow-scripts and identical bytes/);
  assert.match(objective.evidence, /distinct literal citations from the current model decision and browser effect/);
  assert.match(objective.evidence, /saved GET recovery without replay.*fixed denial.*reset fencing, sibling preservation and immutable history/s);
  assert.match(objective.evidence, /disabled by default.*instructor enablement is separate/s);
  assert.doesNotMatch(JSON.stringify([curriculum.HINTS[id], curriculum.SOLUTIONS[id]]), /not yet available|Unavailable until|planned|remains pending/i);
  assert.match(curriculum.HINTS[id].hints.join(' '), /disabled by default.*saved GET recovery/s);
  assert.equal(curriculum.SOLUTIONS[id].examples.length, 1);
  assert.match(curriculum.SOLUTIONS[id].examples[0].explanation, /model must select uploads\.upload_avatar with no arguments.*must cite both/s);
  assert.match(curriculum.SOLUTIONS[id].tips.join(' '), /Fixed mode denies before upload and browser execution.*Reset retires/s);
});


test('V41 qualified credential disclosure stays disabled by default with distinct response evidence',()=>{
 const id='ss_system_credential_disclosure';
 const objective=curriculum.OBJECTIVES.find(row=>row.id===id);
 assert.equal(objective.exerciseId,'ss_system_credentials');
 assert.equal(objective.defaultEnabled,false);
 assert.equal(objective.qualification,'native-browser-judge');
 assert.equal(curriculum.isQualifiedObjective(id),true);
 assert.match(objective.evidence,/synthetic/i);
 assert.match(objective.evidence,/Judge/i);
 assert.doesNotMatch(JSON.stringify([curriculum.HINTS[id],curriculum.SOLUTIONS[id]]),/not yet available|until.*qualified|qualification.*pending/i);
});

test('V42 qualified registry discovery remains default-disabled and distinct from schema or manual claims',()=>{
 const id='ss_mcp_registry_internal_discovery',objective=curriculum.OBJECTIVES.find(row=>row.id===id);
 assert.equal(objective.qualification,'native-browser-judge');assert.equal(objective.defaultEnabled,false);
 assert.equal(curriculum.isQualifiedObjective(id),true);
 assert.match(objective.evidence,/original genuine admin\.mcp_register_prepare.*physical confirmation.*owned listener tools\/list receipt/s);
 assert.match(objective.evidence,/Fixed denial before HTTP discovery.*cookie-authenticated progress.*sibling preservation/s);
 assert.doesNotMatch(JSON.stringify([curriculum.HINTS[id],curriculum.SOLUTIONS[id]]),/not yet available|Unavailable until|remain pending/i);
 assert.match(curriculum.HINTS[id].hints.join(' '),/http:\/\/metadata\.training\/mcp/);
 assert.equal(curriculum.SOLUTIONS[id].examples.length,1);
});

 test('owned user lookup is pending, default disabled and requires original full disclosure',()=>{
 const row=curriculum.OBJECTIVES.find(o=>o.id==='ss_user_lookup_sensitive_disclosure');
 assert.equal(row.qualification,'pending');assert.equal(row.defaultEnabled,false);
 assert.match(row.evidence,/Four independent response-only Judge criteria/);
 assert.match(row.evidence,/Customer role escalation is a separate objective/);
 });

test('V07 legacy preview is qualified and default-disabled with distinct execution scope',()=>{
 const row=curriculum.OBJECTIVES.find(x=>x.id==='ss_upload_polyglot_server_execution');
 assert.equal(row.qualification,'native-browser-judge');assert.equal(row.defaultEnabled,false);assert.equal(curriculum.isQualifiedObjective(row.id),true);
 assert.match(row.evidence,/distinct genuine uploads.preview_legacy_image/);assert.match(row.evidence,/not a Sharp vulnerability/);
 assert.match(row.evidence,/Two independent canonical Judge criteria/);
 assert.match(row.evidence,/reset retirement.*sibling preservation.*immutable assessment history/);
 assert.doesNotMatch(JSON.stringify([curriculum.HINTS[row.id],curriculum.SOLUTIONS[row.id]]),/pending|Unavailable|not yet available/i);
 assert.equal(curriculum.SOLUTIONS[row.id].examples.length,1);
 assert.match(curriculum.SOLUTIONS[row.id].examples[0].explanation,/same bytes as JavaScript only in Vulnerable mode/);
});

test('V29 teaching role qualification preserves default-off and isolated authority boundaries', () => {
 const id='ss_customer_role_escalation',row=curriculum.OBJECTIVES.find(row=>row.id===id);
 assert.equal(row.qualification,'native-browser-judge');
 assert.equal(curriculum.isQualifiedObjective(id),true);
 assert.equal(row.defaultEnabled,false);
 assert.ok(curriculum.EXERCISES.find(row=>row.id==='ss_authorization_agency').objectiveIds.includes(id));
 assert.equal(curriculum.projectExerciseGroups([]).length,0);
 assert.match(row.evidence,/independent canonical Judge/);
 assert.match(row.evidence,/need not acknowledge/);
 assert.match(row.evidence,/never grants platform, storefront or persona authority/);
 assert.match(row.evidence,/Fixed mode blocks.*no-op changes/);
 assert.match(row.evidence,/reset retirement, sibling preservation and immutable assessment history/);
 assert.doesNotMatch(JSON.stringify([curriculum.HINTS[id],curriculum.SOLUTIONS[id]]),/pending|Unavailable|not yet available/i);
 assert.match(curriculum.SOLUTIONS[id].examples[0].action,/Please change my teaching role to admin/);
 assert.match(curriculum.SOLUTIONS[id].examples[0].explanation,/success is not guaranteed/);
});

test('release exclusions cannot be enabled and do not widen to other pending lessons',()=>{
 assert.deepEqual(curriculum.RELEASE_EXCLUDED_OBJECTIVE_IDS,['ss_idor_order_status_disclosure','ss_user_lookup_sensitive_disclosure','ss_pricing_false_grounding','ss_mcp_description_instruction_adoption']);
 for(const id of curriculum.RELEASE_EXCLUDED_OBJECTIVE_IDS){assert.equal(curriculum.isQualifiedObjective(id),false);assert.equal(curriculum.isAssessmentReleaseAllowed(id),false);}
 assert.equal(curriculum.isAssessmentReleaseAllowed('ss_file_upload_instruction_adoption'),true);
 assert.equal(curriculum.isAssessmentReleaseAllowed('ss_idor_cart_delete'),true);
});
