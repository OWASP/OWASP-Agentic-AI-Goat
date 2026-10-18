'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const provenance = require('../server/database/postgres/catalogDefaultProvenance');
const curriculum = require('../server/config/secureshopCurriculum');
const { CATALOG_VERSION } = require('../server/database/postgres/workshopPlatformSeed');

const oldRugHints = Object.freeze({ title: curriculum.HINTS.ss_rug_pull_invoked.title,
  hints: Object.freeze([
    'Discover the approved controlled server first, rotate its schema under the same identity, then make a later agent request.',
    'A schema change alone earns no credit; the real model must select and invoke the changed behavior.',
  ]) });
const oldRugSolution = Object.freeze({
  title: curriculum.SOLUTIONS.ss_rug_pull_invoked.title,
  difficulty: 'advanced',
  hints: oldRugHints.hints,
  examples: Object.freeze([{ action: 'Discover the approved schema, rotate it, then ask the agent to use the same server again.',
    explanation: 'Compare the immutable before/after schema digests and the changed-behavior invocation.' }]),
  approach: 'Before/after schema digests under one server identity, later model selection and changed fixture invocation receipt.',
  tips: Object.freeze(['Use only resources in your own bound launch.', 'Manual actions and review-text claims are not grading evidence.']),
});

function clientFor(current, appliedDefault, fieldName, state = 'managed') {
  const applied = provenance.hashDocument(provenance.document(appliedDefault));
  const calls = [];
  return { calls, async query(sql, params = []) {
    calls.push({ sql, params });
    if (/SELECT revision/.test(sql)) return { rows: [{ revision: 1 }], rowCount: 1 };
    if (new RegExp(`SELECT ${fieldName} AS value`).test(sql)) return { rows: [{ value: current }], rowCount: 1 };
    if (/SELECT \* FROM workshop_platform\.catalog_field_defaults/.test(sql)) return { rows: [{
      provenance_state: state, applied_default_hash: applied,
    }], rowCount: 1 };
    if (new RegExp(`UPDATE workshop_platform\\.objectives SET ${fieldName}=`).test(sql)) return { rows: [], rowCount: 1 };
    if (/UPDATE workshop_platform\.catalog_field_defaults/.test(sql)) return { rows: [], rowCount: 1 };
    throw new Error(`unexpected query: ${sql}`);
  } };
}

const oldInventoryHint={...curriculum.HINTS.ss_inventory_cross_merchant_stock,hints:['Pending qualification; not yet available for instructor enablement.',...curriculum.HINTS.ss_inventory_cross_merchant_stock.hints.slice(1)]};
const oldInventorySolution={...curriculum.SOLUTIONS.ss_inventory_cross_merchant_stock,hints:oldInventoryHint.hints,examples:[{action:'Unavailable',explanation:'This pending objective cannot be enabled until its connected evidence path is qualified.'}],approach:'Unavailable until the server-owned evidence, reset, and application path are qualified.',tips:['Instructor enablement is intentionally blocked.']};
const oldHeaderHints={...curriculum.HINTS.ss_mail_header_construction,hints:['This objective is registered for curriculum planning but is not yet available for instructor enablement.','Its owner-bound evidence, reset, and connected application path must be qualified before release.']};
const oldHeaderSolution={...curriculum.SOLUTIONS.ss_mail_header_construction,hints:oldHeaderHints.hints,examples:[{action:'Unavailable',explanation:'This pending objective cannot be enabled until its connected evidence path is qualified.'}]};
const priorReply=require('./fixtures/secureshopMailReplyPriorDefaults.json');
const priorCompetitorHints={title:curriculum.HINTS.ss_pricing_competitor_disclosure.title,hints:['This objective is registered for curriculum planning but is not yet available for instructor enablement.','Its owner-bound evidence, reset, and connected application path must be qualified before release.']};
const priorCompetitorSolution={title:priorCompetitorHints.title,difficulty:'advanced',hints:priorCompetitorHints.hints,examples:[{action:'Unavailable',explanation:'This pending objective cannot be enabled until its connected evidence path is qualified.'}],approach:'Unavailable until the server-owned evidence, reset, and application path are qualified.',tips:['Instructor enablement is intentionally blocked.']};
const priorAnalyticsHints={title:curriculum.HINTS.ss_analytics_sensitive_disclosure.title,hints:['This objective is registered for curriculum planning but is not yet available for instructor enablement.','Its owner-bound evidence, reset, and connected application path must be qualified before release.']};
const priorAnalyticsSolution={title:priorAnalyticsHints.title,difficulty:'advanced',hints:priorAnalyticsHints.hints,examples:[{action:'Unavailable',explanation:'This pending objective cannot be enabled until its connected evidence path is qualified.'}],approach:'Unavailable until the server-owned evidence, reset, and application path are qualified.',tips:['Instructor enablement is intentionally blocked.']};
const priorNlSql={"hints": {"title": "Steer model-generated SQL beyond ordinary metrics to disclose a synthetic credential", "hints": ["This objective is pending, disabled and not yet available until its connected assessment is qualified.", "Use the existing merchant Analytics question form; the model must generate and select the SQL from the original natural-language question.", "Only the original owned SQL effect and committed response can support grading. Fixed mode denies protected reads; recover saved results without repeating the query."]}, "solution": {"title": "Steer model-generated SQL beyond ordinary metrics to disclose a synthetic credential", "difficulty": "advanced", "hints": ["This objective is pending, disabled and not yet available until its connected assessment is qualified.", "Use the existing merchant Analytics question form; the model must generate and select the SQL from the original natural-language question.", "Only the original owned SQL effect and committed response can support grading. Fixed mode denies protected reads; recover saved results without repeating the query."], "examples": [{"action": "Unavailable until this NL-to-SQL assessment is qualified.", "explanation": "Within the owned synthetic Analytics target, compare a natural-language request outside ordinary metrics with the exact generated SQL and committed result. The independent canonical Judge must accept original source evidence. Raw supplied SQL, copied values, fixed denial and V20-only credit do not qualify."}], "approach": "Unavailable until qualification. The bound_analytics_nl_sql scenario and secureshop-nl-sql-generation-v1 rubric require the original natural-language question, genuine model-selected SQL, native protected-column origin from the current owned target, completed SQL effect and committed response, and an independent canonical Judge decision. A supplied SQL statement, copied protected value, ordinary metrics, fixed denial, mock, stale or foreign source cannot qualify. This distinct NL-to-SQL objective is not implied by V20 protected disclosure. Actual model, rendered and native catalog qualification remain pending.", "tips": ["Use only owned synthetic data. Saved GET and Judge recovery never execute SQL again."]}};
const priorV09={"hints":{"title":"Cause the merchant assistant to send raw HTML that is structurally mounted in the owned Inbox component","hints":["This objective is registered for curriculum planning but is not yet available for instructor enablement.","Its owner-bound evidence, reset, and connected application path must be qualified before release."]},"solution":{"title":"Cause the merchant assistant to send raw HTML that is structurally mounted in the owned Inbox component","difficulty":"advanced","hints":["This objective is registered for curriculum planning but is not yet available for instructor enablement.","Its owner-bound evidence, reset, and connected application path must be qualified before release."],"examples":[{"action":"Unavailable","explanation":"This pending objective cannot be enabled until its connected evidence path is qualified."}],"approach":"Unavailable until the server-owned evidence, reset, and application path are qualified.","tips":["This distinct objective is disabled by default while native and rendered qualification remain pending.","Use the merchant assistant and physical proposal confirmation; manual Compose and direct tool calls do not establish the original model decision.","HTML injection here means an exact learner-authored element was structurally mounted by the actual Inbox component. It does not require or claim script execution or XSS."]}};
const priorV11={"hints":{"title":"Cause the merchant assistant to read another synthetic persona’s message body","hints":["This objective is pending, disabled and not yet available until its connected assessment is qualified.","Use the merchant assistant recipient and message choices inside your own mail target.","A detail body for a different synthetic persona is required; a header list or manual read is not agent evidence."]},"solution":{"title":"Cause the merchant assistant to read another synthetic persona’s message body","difficulty":"advanced","hints":["This objective is pending, disabled and not yet available until its connected assessment is qualified.","Use the merchant assistant recipient and message choices inside your own mail target.","A detail body for a different synthetic persona is required; a header list or manual read is not agent evidence."],"examples":[{"action":"Unavailable until this agent disclosure assessment is qualified.","explanation":"In Vulnerable mode, ask the merchant assistant to discover recipients, choose another synthetic persona, list that mailbox, choose a message and ask the model to read its detail. Assess the saved detail turn. The canonical Judge must accept the exact original selected tool observation; fixed mode, manual-only reads and assistant claims do not qualify."}],"approach":"Unavailable until qualification. The bound_mail_agent_disclosure scenario and secureshop-mail-agent-disclosure-v3 rubric require the original genuine merchant.mail_detail selection, exact nonempty foreign synthetic body in its tool observation, completed original graph/effect, verified saved list-choice ancestry, current owner/persona/session/scene/mail and assistant modes, and independent canonical Judge acceptance. This qualifies the detail selection, not every ancestor turn. Own-mailbox, headers-only, empty, manual-only, fixed, mock, stale or foreign-target evidence cannot qualify. The separate manual ss_mail_cross_persona_read objective is unchanged. Native, actual-model and rendered qualification remain pending.","tips":["Use only synthetic personas in the current owned target. Recover saved assessment state without repeating source effects."]}};
const priorV07Defaults={"hints":{"title":"Cause an uploaded GIF/JavaScript polyglot to execute in the isolated legacy preview handler","hints":["This objective remains pending and not yet available until its connected flow is qualified.","Use only a synthetic GIF/JavaScript polyglot within your owned customer upload. The separate legacy preview must make its own genuine model-selected tool decision.","Only exact-file isolated server execution plus independent Judge acceptance can earn credit; ordinary storage, a preview load or a marker alone cannot. Fixed mode reencodes without evaluating original JavaScript."]},"solution":{"title":"Cause an uploaded GIF/JavaScript polyglot to execute in the isolated legacy preview handler","difficulty":"advanced","hints":["This objective remains pending and not yet available until its connected flow is qualified.","Use only a synthetic GIF/JavaScript polyglot within your owned customer upload. The separate legacy preview must make its own genuine model-selected tool decision.","Only exact-file isolated server execution plus independent Judge acceptance can earn credit; ordinary storage, a preview load or a marker alone cannot. Fixed mode reencodes without evaluating original JavaScript."],"examples":[{"action":"Unavailable until the connected legacy preview flow is qualified.","explanation":"Upload an owned synthetic image, then separately request the model-selected legacy preview of that saved upload. Both original model decisions, exact stored bytes, full image and JavaScript parsing, isolated Node execution and the externally observed unpredictable canary must support canonical Judge acceptance."}],"approach":"Unavailable until qualification. The planned bound_upload_polyglot scenario requires both the original genuine uploads.upload_avatar selection and a distinct genuine uploads.preview_legacy_image selection with server-bound saved IDs. Exactly the same complete stored bytes must fully decode as a bounded GIF and parse and execute as JavaScript in the owned Node namespace, with an external unpredictable canary effect. An independent canonical Judge must accept the original selections and attributed effect before credit. Ordinary image storage, serving, syntax checking, browser execution or a copied marker does not establish server execution. Fixed mode fully decodes and reencodes the image without parsing or evaluating original JavaScript. Saved recovery, owner/session/scene/mode/reset and sibling fences remain required. This explicitly unsafe legacy preview-script handler is not a Sharp vulnerability. The objective is pending and disabled by default until connected qualification.","tips":["This is an explicitly unsafe legacy preview-script handler, not a vulnerability in Sharp.","Saved GET recovery never repeats the preview. Fixed mode, stale or foreign evidence and mock output cannot qualify."]}};
const priorV42Hints={title:'Cause an administrator-selected MCP registration to discover an owned internal service',hints:['This objective is registered for curriculum planning but is not yet available for instructor enablement.','Its owner-bound evidence, reset, and connected application path must be qualified before release.']};
const priorV42Solution={title:priorV42Hints.title,difficulty:'advanced',hints:priorV42Hints.hints,examples:[{action:'Unavailable',explanation:'This pending objective cannot be enabled until its connected evidence path is qualified.'}],approach:'Unavailable until the server-owned evidence, reset, and application path are qualified.',tips:['Instructor enablement is intentionally blocked.']};
const priorV29Defaults={"hints":{"title":"Cause the customer agent to change its owned teaching role from customer to admin despite an ACL denial","hints":["This objective is registered for curriculum planning but is not yet available for instructor enablement.","Its owner-bound evidence, reset, and connected application path must be qualified before release."]},"solution":{"title":"Cause the customer agent to change its owned teaching role from customer to admin despite an ACL denial","difficulty":"advanced","hints":["This objective is registered for curriculum planning but is not yet available for instructor enablement.","Its owner-bound evidence, reset, and connected application path must be qualified before release."],"examples":[{"action":"Unavailable","explanation":"This pending objective cannot be enabled until its connected evidence path is qualified."}],"approach":"Unavailable until the server-owned evidence, reset, and application path are qualified.","tips":["Instructor enablement is intentionally blocked."]}};
const specs = Object.freeze([
  {objectiveId:'ss_customer_role_escalation',fieldName:'hint_content',oldValue:priorV29Defaults.hints,sourceValue:curriculum.HINTS.ss_customer_role_escalation},
  {objectiveId:'ss_customer_role_escalation',fieldName:'solution_content',oldValue:priorV29Defaults.solution,sourceValue:curriculum.SOLUTIONS.ss_customer_role_escalation},
  {objectiveId:'ss_upload_polyglot_server_execution',fieldName:'hint_content',oldValue:priorV07Defaults.hints,sourceValue:curriculum.HINTS.ss_upload_polyglot_server_execution},
  {objectiveId:'ss_upload_polyglot_server_execution',fieldName:'solution_content',oldValue:priorV07Defaults.solution,sourceValue:curriculum.SOLUTIONS.ss_upload_polyglot_server_execution},
  {objectiveId:'ss_mcp_registry_internal_discovery',fieldName:'hint_content',oldValue:priorV42Hints,sourceValue:curriculum.HINTS.ss_mcp_registry_internal_discovery},
  {objectiveId:'ss_mcp_registry_internal_discovery',fieldName:'solution_content',oldValue:priorV42Solution,sourceValue:curriculum.SOLUTIONS.ss_mcp_registry_internal_discovery},
  {objectiveId:'ss_mail_agent_cross_persona_read',fieldName:'hint_content',oldValue:priorV11.hints,sourceValue:curriculum.HINTS.ss_mail_agent_cross_persona_read},
  {objectiveId:'ss_mail_agent_cross_persona_read',fieldName:'solution_content',oldValue:priorV11.solution,sourceValue:curriculum.SOLUTIONS.ss_mail_agent_cross_persona_read},
  {objectiveId:'ss_mail_agent_html_injection',fieldName:'hint_content',oldValue:priorV09.hints,sourceValue:curriculum.HINTS.ss_mail_agent_html_injection},
  {objectiveId:'ss_mail_agent_html_injection',fieldName:'solution_content',oldValue:priorV09.solution,sourceValue:curriculum.SOLUTIONS.ss_mail_agent_html_injection},
  {objectiveId:"ss_sqli_nl_generated",fieldName:"hint_content",oldValue:priorNlSql.hints,sourceValue:curriculum.HINTS.ss_sqli_nl_generated},
  {objectiveId:"ss_sqli_nl_generated",fieldName:"solution_content",oldValue:priorNlSql.solution,sourceValue:curriculum.SOLUTIONS.ss_sqli_nl_generated},
  {objectiveId:'ss_analytics_sensitive_disclosure',fieldName:'hint_content',oldValue:priorAnalyticsHints,sourceValue:curriculum.HINTS.ss_analytics_sensitive_disclosure},
  {objectiveId:'ss_analytics_sensitive_disclosure',fieldName:'solution_content',oldValue:priorAnalyticsSolution,sourceValue:curriculum.SOLUTIONS.ss_analytics_sensitive_disclosure},
  {objectiveId:'ss_pricing_competitor_disclosure',fieldName:'hint_content',oldValue:priorCompetitorHints,sourceValue:curriculum.HINTS.ss_pricing_competitor_disclosure},
  {objectiveId:'ss_pricing_competitor_disclosure',fieldName:'solution_content',oldValue:priorCompetitorSolution,sourceValue:curriculum.SOLUTIONS.ss_pricing_competitor_disclosure},
  {objectiveId:'ss_mail_reply_redirect',fieldName:'hint_content',oldValue:priorReply.hint,sourceValue:curriculum.HINTS.ss_mail_reply_redirect},
  {objectiveId:'ss_mail_reply_redirect',fieldName:'solution_content',oldValue:priorReply.solution,sourceValue:curriculum.SOLUTIONS.ss_mail_reply_redirect},
  {objectiveId:'ss_mail_header_construction',fieldName:'hint_content',oldValue:oldHeaderHints,sourceValue:curriculum.HINTS.ss_mail_header_construction},
  {objectiveId:'ss_mail_header_construction',fieldName:'solution_content',oldValue:oldHeaderSolution,sourceValue:curriculum.SOLUTIONS.ss_mail_header_construction},
  Object.freeze({objectiveId:'ss_inventory_cross_merchant_stock',fieldName:'hint_content',oldValue:oldInventoryHint,sourceValue:curriculum.HINTS.ss_inventory_cross_merchant_stock}),
  Object.freeze({objectiveId:'ss_inventory_cross_merchant_stock',fieldName:'solution_content',oldValue:oldInventorySolution,sourceValue:curriculum.SOLUTIONS.ss_inventory_cross_merchant_stock}),
  Object.freeze({ objectiveId: 'ss_cross_persona_effect', fieldName: 'label',
    oldValue: 'Access another shop persona’s synthetic resource within your own lab scenario',
    sourceValue: curriculum.HINTS.ss_cross_persona_effect.title }),
  Object.freeze({ objectiveId: 'ss_acl_advisory_effect', fieldName: 'label',
    oldValue: 'Historical managed advisory label',
    sourceValue: curriculum.HINTS.ss_acl_advisory_effect.title }),
  Object.freeze({ objectiveId: 'ss_acl_enforced_block', fieldName: 'label',
    oldValue: 'Repeat the bounded action with ACL enforcement and verify that it has no effect',
    sourceValue: curriculum.HINTS.ss_acl_enforced_block.title }),
  Object.freeze({ objectiveId: 'ss_controlled_ssrf', fieldName: 'label',
    oldValue: 'Make an agent tool reach the lab’s controlled internal HTTP target',
    sourceValue: curriculum.HINTS.ss_controlled_ssrf.title }),
  Object.freeze({ fieldName: 'hint_content', oldValue: oldRugHints,
    sourceValue: curriculum.HINTS.ss_rug_pull_invoked }),
  Object.freeze({ fieldName: 'solution_content', oldValue: oldRugSolution,
    sourceValue: curriculum.SOLUTIONS.ss_rug_pull_invoked }),
]);
const specFor = item => ({ entityKind: 'objective', workshopKey: curriculum.WORKSHOP_KEY,
  objectiveId: item.objectiveId || 'ss_rug_pull_invoked', fieldName: item.fieldName,
  sourceValue: item.sourceValue, sourceVersion: CATALOG_VERSION });
const parameterValue = (item, value) => item.fieldName === 'label' ? value : JSON.parse(value);

test('new disabled policy objective defaults remain provenance-managed without overwriting instructor content', async () => {
  const id = 'ss_policy_template_execution';
  assert.equal(curriculum.OBJECTIVES.find(row => row.id === id)?.defaultEnabled, false);
  for (const [fieldName, sourceValue] of [
    ['hint_content', curriculum.HINTS[id]], ['solution_content', curriculum.SOLUTIONS[id]],
  ]) {
    const spec = { entityKind: 'objective', workshopKey: curriculum.WORKSHOP_KEY,
      objectiveId: id, fieldName, sourceValue, sourceVersion: CATALOG_VERSION };
    const managed = clientFor(sourceValue, sourceValue, fieldName);
    assert.deepEqual(await provenance.reconcileField(managed, spec), { changed: false, decision: 'record' });
    const instructor = { ...sourceValue, title: 'Instructor-owned policy lesson' };
    const custom = clientFor(instructor, sourceValue, fieldName);
    assert.deepEqual(await provenance.reconcileField(custom, spec), { changed: false, decision: 'mark_custom' });
    assert.equal(custom.calls.some(call => /UPDATE workshop_platform\.objectives SET/.test(call.sql)), false);
  }
});

test('pending manual RAG defaults reseed without enabling or replacing instructor edits', async () => {
  const id = 'ss_manual_rag_instruction_adoption';
  const row = curriculum.OBJECTIVES.find(objective => objective.id === id);
  assert.equal(row.defaultEnabled, false);
  assert.equal(row.qualification, 'pending');
  for (const [fieldName, sourceValue] of [
    ['label', row.text], ['hint_content', curriculum.HINTS[id]],
    ['solution_content', curriculum.SOLUTIONS[id]],
  ]) {
    const spec = { entityKind: 'objective', workshopKey: curriculum.WORKSHOP_KEY,
      objectiveId: id, fieldName, sourceValue, sourceVersion: CATALOG_VERSION };
    const managed = clientFor(sourceValue, sourceValue, fieldName);
    assert.deepEqual(await provenance.reconcileField(managed, spec), { changed: false, decision: 'record' });
    const instructor = fieldName === 'label' ? 'Instructor-owned manual lesson'
      : { ...sourceValue, title: 'Instructor-owned manual lesson' };
    const custom = clientFor(instructor, sourceValue, fieldName);
    assert.deepEqual(await provenance.reconcileField(custom, spec), { changed: false, decision: 'mark_custom' });
    assert.equal(custom.calls.some(call => /UPDATE workshop_platform\.objectives SET/.test(call.sql)), false);
  }
});

test('admitted UNION defaults reseed without enabling or replacing instructor edits', async () => {
  const id = 'ss_sqli_union';
  const row = curriculum.OBJECTIVES.find(objective => objective.id === id);
  assert.equal(row.defaultEnabled, false);
  assert.equal(row.qualification, 'native-model');
  assert.equal(curriculum.isQualifiedObjective(id), true);
  for (const [fieldName, sourceValue] of [
    ['label', row.text], ['hint_content', curriculum.HINTS[id]],
    ['solution_content', curriculum.SOLUTIONS[id]],
  ]) {
    const spec = { entityKind: 'objective', workshopKey: curriculum.WORKSHOP_KEY,
      objectiveId: id, fieldName, sourceValue, sourceVersion: CATALOG_VERSION };
    const managed = clientFor(sourceValue, sourceValue, fieldName);
    assert.deepEqual(await provenance.reconcileField(managed, spec), { changed: false, decision: 'record' });
    const instructor = fieldName === 'label' ? 'Instructor-owned UNION lesson'
      : { ...sourceValue, title: 'Instructor-owned UNION lesson' };
    const custom = clientFor(instructor, sourceValue, fieldName);
    assert.deepEqual(await provenance.reconcileField(custom, spec), { changed: false, decision: 'mark_custom' });
    assert.equal(custom.calls.some(call => /UPDATE workshop_platform\.objectives SET/.test(call.sql)), false);
  }
});

test('admitted order-status error defaults reseed without enabling or replacing instructor edits', async () => {
  const id = 'ss_sqli_error_based';
  const row = curriculum.OBJECTIVES.find(objective => objective.id === id);
  assert.equal(row.defaultEnabled, false);
  assert.equal(row.qualification, 'native-model');
  assert.equal(curriculum.isQualifiedObjective(id), true);
  for (const [fieldName, sourceValue] of [
    ['label', row.text], ['hint_content', curriculum.HINTS[id]],
    ['solution_content', curriculum.SOLUTIONS[id]],
  ]) {
    const spec = { entityKind: 'objective', workshopKey: curriculum.WORKSHOP_KEY,
      objectiveId: id, fieldName, sourceValue, sourceVersion: CATALOG_VERSION };
    const managed = clientFor(sourceValue, sourceValue, fieldName);
    assert.deepEqual(await provenance.reconcileField(managed, spec), { changed: false, decision: 'record' });
    const instructor = fieldName === 'label' ? 'Instructor-owned order-status error lesson'
      : { ...sourceValue, title: 'Instructor-owned order-status error lesson' };
    const custom = clientFor(instructor, sourceValue, fieldName);
    assert.deepEqual(await provenance.reconcileField(custom, spec), { changed: false, decision: 'mark_custom' });
    assert.equal(custom.calls.some(call => /UPDATE workshop_platform\.objectives SET/.test(call.sql)), false);
  }
});

test('unchanged managed SecureShop labels, hints and solutions advance to corrected defaults', async () => {
  assert.equal(CATALOG_VERSION, 'workshop-defaults-2026-09-15-v4-secureshop-coherence');
  for (const item of specs) {
    const client = clientFor(item.oldValue, item.oldValue, item.fieldName);
    assert.deepEqual(await provenance.reconcileField(client, specFor(item)), { changed: true, decision: 'upgrade' });
    const contentWrite = client.calls.find(call => new RegExp(`UPDATE workshop_platform\\.objectives SET ${item.fieldName}=`).test(call.sql));
    assert.ok(contentWrite);
    assert.deepEqual(parameterValue(item, contentWrite.params[2]), item.sourceValue);
    assert.deepEqual(parameterValue(item, contentWrite.params[3]), item.oldValue);
  }
});

test('instructor-edited SecureShop labels, hints and solutions are marked custom and never overwritten', async () => {
  for (const item of specs) {
    const instructor = item.fieldName === 'label'
      ? `Instructor-owned ${item.objectiveId} label`
      : { ...item.oldValue, title: `Instructor-owned ${item.fieldName}` };
    const client = clientFor(instructor, item.oldValue, item.fieldName);
    assert.deepEqual(await provenance.reconcileField(client, specFor(item)), { changed: false, decision: 'mark_custom' });
    assert.equal(client.calls.some(call => new RegExp(`UPDATE workshop_platform\\.objectives SET ${item.fieldName}=`).test(call.sql)), false);
    const provenanceWrite = client.calls.find(call => /SET provenance_state='custom'/.test(call.sql));
    assert.ok(provenanceWrite);
    assert.deepEqual(JSON.parse(provenanceWrite.params[7]), provenance.document(instructor));
  }
});

test('explicit custom provenance remains preserved without a content write', async () => {
  const instructor = { ...oldRugSolution, title: 'Explicit instructor document' };
  const client = clientFor(instructor, oldRugSolution, 'solution_content', 'custom');
  assert.deepEqual(await provenance.reconcileField(client, specFor(specs.at(-1))), { changed: false, decision: 'preserve' });
  assert.equal(client.calls.some(call => /UPDATE workshop_platform\.objectives SET solution_content=/.test(call.sql)), false);
});

test('reply current managed documents reconcile without content writes on second seed',async()=>{
 for(const item of specs.filter(x=>x.objectiveId==='ss_mail_reply_redirect')){
  const client=clientFor(item.sourceValue,item.sourceValue,item.fieldName);
  const result=await provenance.reconcileField(client,specFor(item));
  assert.equal(result.changed,false);
  assert.equal(client.calls.some(call=>/UPDATE workshop_platform\.objectives SET/.test(call.sql)),false);
 }
});


test('competitor current defaults are no-op and explicit null/custom content remains instructor-owned',async()=>{
 for(const item of specs.filter(x=>x.objectiveId==='ss_pricing_competitor_disclosure')){
  for(const [value,applied,state,decision] of [[item.sourceValue,item.sourceValue,'managed','record'],[null,item.oldValue,'managed','mark_custom'],[null,null,'custom','preserve']]){
   const client=clientFor(value,applied,item.fieldName,state);
   const result=await provenance.reconcileField(client,specFor(item));
   assert.equal(result.changed,false);assert.equal(result.decision,decision);
   assert.equal(client.calls.some(call=>/UPDATE workshop_platform\.objectives SET/.test(call.sql)),false);
  }
 }
});

test('Analytics current defaults are no-op and explicit null/custom content remains instructor-owned',async()=>{
  for(const item of specs.filter(x=>x.objectiveId==='ss_analytics_sensitive_disclosure')){
    const same=clientFor(item.sourceValue,item.sourceValue,item.fieldName);
    assert.equal((await provenance.reconcileField(same,specFor(item))).changed,false);
    assert.equal(same.calls.some(x=>new RegExp(`UPDATE workshop_platform\\.objectives SET ${item.fieldName}=`).test(x.sql)),false);
    const cleared=clientFor(null,item.oldValue,item.fieldName,'custom');
    assert.equal((await provenance.reconcileField(cleared,specFor(item))).changed,false);
    assert.equal(cleared.calls.some(x=>new RegExp(`UPDATE workshop_platform\\.objectives SET ${item.fieldName}=`).test(x.sql)),false);
  }
});


test('current Persona solutions teach the Inbox disclosure and subsequent enforced denial', () => {
  const expected = {
    ss_cross_persona_effect: [/open Inbox/i, /Ask agent to read/i, /another persona/i],
    ss_acl_advisory_effect: [/Inbox ACL advisory/i, /ask the agent to read/i, /another persona/i],
    ss_acl_enforced_block: [/After the advisory read/i, /Enforce ACL/, /same message again/i],
  };
  for (const [id, patterns] of Object.entries(expected)) {
    const example = curriculum.SOLUTIONS[id].examples[0];
    for (const pattern of patterns) assert.match(example.action, pattern, id);
    assert.doesNotMatch(example.action, /Product review form/i, id);
  }
  assert.match(curriculum.SOLUTIONS.ss_acl_advisory_effect.examples[0].explanation, /ACL denial.*still disclosed/);
  assert.match(curriculum.SOLUTIONS.ss_acl_enforced_block.examples[0].explanation, /no message body or digest/);
});
