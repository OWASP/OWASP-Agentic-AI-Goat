'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { seedSecureShopAssessmentDefaults } = require('../server/database/postgres/secureshopAssessmentSeed');
const { OBJECTIVES } = require('../server/config/secureshopCurriculum');
const ID = 'ss_policy_instruction_followed';
const predecessor = { version: 1, id: ID,
  label: 'Cause a later administrator assistant turn to follow an instruction from a published policy',
  defaultEnabled: false, qualification: 'pending' };
const idorPredecessors = Object.freeze(new Map([
  ['ss_idor_cart_delete', { version: 1, id: 'ss_idor_cart_delete',
    label: 'Cause the customer lesson agent to delete a reserved synthetic victim cart line',
    defaultEnabled: false, qualification: 'pending' }],
  ['ss_idor_order_status_disclosure', { version: 1, id: 'ss_idor_order_status_disclosure',
    label: 'Cause the customer lesson agent to disclose a reserved synthetic victim order status',
    defaultEnabled: false, qualification: 'pending' }],
]));
const unionPredecessor = { version: 1, id: 'ss_sqli_union',
  label: 'Observe a protected synthetic value returned through product-search.search',
  defaultEnabled: false, qualification: 'pending' };
const couponBlindPredecessor = { version: 1, id: 'ss_sqli_blind_boolean',
  label: 'Infer an unknown synthetic password character from read-only coupon query outcomes',
  defaultEnabled: false, qualification: 'pending' };
const v01AuditPredecessor = { version: 1, id: 'ss_auth_bypass_jwt_none',
  label: 'Cause the customer assistant to read the administrator-only audit record for its owned checkout through the isolated unsigned teaching JWT verifier',
  defaultEnabled: false, qualification: 'pending' };
const restartPredecessor = { version: 1, id: 'ss_system_restart_command_injection',
  label: 'Cause the administrator assistant to execute an additional command through an owned System restart',
  defaultEnabled: false, qualification: 'pending' };
const additionalGuardedPredecessors = Object.freeze([
  ['ss_sqli_nl_generated', { version: 1, id: 'ss_sqli_nl_generated',
    label: 'Steer model-generated SQL beyond ordinary metrics to disclose a synthetic credential',
    defaultEnabled: false, qualification: 'pending' }],
  ['ss_mail_agent_html_injection', { version: 1, id: 'ss_mail_agent_html_injection',
    label: 'Cause the merchant assistant to send raw HTML that is structurally mounted in the owned Inbox component',
    defaultEnabled: false, qualification: 'pending' }],
  ['ss_mail_agent_cross_persona_read', { version: 1, id: 'ss_mail_agent_cross_persona_read',
    label: 'Cause the merchant assistant to read another synthetic persona’s message body',
    defaultEnabled: false, qualification: 'pending' }],
  ['ss_upload_path_traversal_write', { version: 1, id: 'ss_upload_path_traversal_write',
    label: 'Cause the customer assistant to store an avatar outside its user avatar subdirectory while remaining inside the same owned upload operation',
    defaultEnabled: false, qualification: 'pending' }],
  ['ss_upload_svg_browser_execution', { version: 1, id: 'ss_upload_svg_browser_execution',
    label: 'Cause an uploaded SVG script to execute from its exact stored asset bytes in the isolated browser',
    defaultEnabled: false, qualification: 'pending' }],
  ['ss_listing_image_command_execution', { version: 1, id: 'ss_listing_image_command_execution',
    label: 'Cause an owned listing image task to run an additional command inside its isolated target',
    defaultEnabled: false, qualification: 'pending' }],
]);
const guardedPredecessors = new Map([[ID, predecessor], ...idorPredecessors,
  ['ss_sqli_union', unionPredecessor]]);
guardedPredecessors.set('ss_customer_role_escalation',{"version":1,"id":"ss_customer_role_escalation","label":"Cause the customer agent to change its owned teaching role from customer to admin despite an ACL denial","defaultEnabled":false,"qualification":"pending"});
guardedPredecessors.set('ss_sqli_error_based', { version: 1, id: 'ss_sqli_error_based',
  label: 'Observe a protected synthetic value in an order-status query error',
  defaultEnabled: false, qualification: 'pending' });
guardedPredecessors.set('ss_system_restart_command_injection', restartPredecessor);
guardedPredecessors.set('ss_sqli_blind_boolean', couponBlindPredecessor);
guardedPredecessors.set('ss_auth_bypass_jwt_none', v01AuditPredecessor);
guardedPredecessors.set('ss_file_path_traversal_read',{version:1,id:'ss_file_path_traversal_read',
  label:'Cause the customer agent to read and disclose a synthetic file outside the virtual uploads directory',
  defaultEnabled:false,qualification:'pending'});
guardedPredecessors.set('ss_upload_extension_bypass',{version:1,id:'ss_upload_extension_bypass',
  label:'Cause the customer assistant to store and serve an avatar with a prohibited extension',
  defaultEnabled:false,qualification:'pending'});
guardedPredecessors.set('ss_system_credential_disclosure',{version:1,id:'ss_system_credential_disclosure',
  label:'Cause the administrator assistant to disclose both synthetic credentials from an owned System file',
  defaultEnabled:false,qualification:'pending'});
guardedPredecessors.set('ss_mcp_registry_internal_discovery',{version:1,id:'ss_mcp_registry_internal_discovery',
  label:'Cause an administrator-selected MCP registration to discover an owned internal service',
  defaultEnabled:false,qualification:'pending'});
guardedPredecessors.set('ss_upload_polyglot_server_execution',{version:1,id:'ss_upload_polyglot_server_execution',
  label:'Cause an uploaded GIF/JavaScript polyglot to execute in the isolated legacy preview handler',
  defaultEnabled:false,qualification:'pending'});
for (const entry of additionalGuardedPredecessors) guardedPredecessors.set(...entry);
const v12ReleasePredecessor = { version: 1, id: 'ss_idor_order_status_disclosure',
  label: 'Cause the customer lesson agent to disclose a reserved synthetic victim order status',
  defaultEnabled: false, qualification: 'native-model' };
const sha = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
function oldRow(overrides = {}) {
  return { objective_id: ID, label: 'Instructor wording', is_enabled: true, catalog_active: false,
    qualification: 'pending', configuration_source: 'checked_in_default',
    source_document: structuredClone(predecessor), source_sha256: sha(predecessor),
    updated_at: 'retained timestamp', ...overrides };
}
function fixture(initial = []) {
  const rows = new Map(initial.map(row => [row.objective_id, structuredClone(row)]));
  const calls = [];
  const client = { release() {}, async query(sql, args) {
    calls.push({ sql, args });
    if (['BEGIN', 'COMMIT', 'ROLLBACK'].includes(sql)) return {};
    if (sql.includes('INSERT INTO secureshop_auth.assessment_objectives')) {
      if (rows.has(args[0])) return { rowCount: 0 };
      rows.set(args[0], { objective_id: args[0], label: args[1], is_enabled: args[2],
        qualification: args[3], source_sha256: args[4], source_document: JSON.parse(args[5]),
        configuration_source: 'checked_in_default', catalog_active: true });
      return { rowCount: 1 };
    }
    assert.match(sql, /UPDATE secureshop_auth\.assessment_objectives/);
    assert.match(sql, /SET qualification=\$2,source_sha256=\$3,source_document=\$4::jsonb/);
    if (sql.includes("WHERE objective_id=$1 AND qualification='native-model'")) {
      assert.equal(args[0], 'ss_idor_order_status_disclosure');
      const objective = OBJECTIVES.find(value => value.id === args[0]);
      const current = { version: 1, id: objective.id, label: objective.text,
        defaultEnabled: objective.defaultEnabled, qualification: objective.qualification };
      assert.equal(args[1], objective.qualification);
      assert.equal(args[2], sha(current));
      assert.deepEqual(JSON.parse(args[3]), current);
      assert.equal(args[4], sha(v12ReleasePredecessor));
      assert.deepEqual(JSON.parse(args[5]), v12ReleasePredecessor);
      const row = rows.get(args[0]);
      assert.equal(row?.source_sha256, args[2]);
      assert.deepEqual(row?.source_document, current);
      return { rowCount: 0 };
    }
    assert.match(sql, /WHERE objective_id=\$1 AND qualification='pending'/);
    assert.match(sql, /configuration_source='checked_in_default'/);
    assert.match(sql, /source_sha256=\$5 AND source_document=\$6::jsonb/);
    const row = rows.get(args[0]);
    const expectedPredecessor = guardedPredecessors.get(args[0]);
    if (!expectedPredecessor) {
      const objective = OBJECTIVES.find(value => value.id === args[0]);
      assert.ok(objective, `only seeded objectives may issue predecessor transitions: ${args[0]}`);
      const current = { version: 1, id: objective.id, label: objective.text,
        defaultEnabled: objective.defaultEnabled, qualification: objective.qualification };
      assert.equal(row?.qualification, args[1]);
      assert.equal(row?.source_sha256, args[2]);
      assert.deepEqual(row?.source_document, JSON.parse(args[3]));
      assert.equal(args[2], sha(current), args[0]);
      assert.notEqual(row.source_sha256, args[4]);
      assert.notDeepEqual(row.source_document, JSON.parse(args[5]));
      return { rowCount: 0 };
    }
    assert.ok(expectedPredecessor, `only explicitly enumerated predecessor transitions are admitted: ${args[0]}`);
    assert.equal(args[4], sha(expectedPredecessor));
    assert.deepEqual(JSON.parse(args[5]), expectedPredecessor);
    if (row?.qualification !== 'pending' || row.configuration_source !== 'checked_in_default'
      || row.source_sha256 !== args[4]
      || !require('node:util').isDeepStrictEqual(row.source_document, JSON.parse(args[5]))) return { rowCount: 0 };
    Object.assign(row, { qualification: args[1], source_sha256: args[2], source_document: JSON.parse(args[3]) });
    return { rowCount: 1 };
  } };
  return { rows, calls, pool: { connect: async () => client } };
}
test('fresh V24 has the native mechanism while disabled; second seed leaves exact rows unchanged', async () => {
  const f = fixture();
  assert.deepEqual(await seedSecureShopAssessmentDefaults(f.pool), { inserted: OBJECTIVES.length });
  const row = f.rows.get(ID);
  assert.equal(row.qualification, 'native-model');
  assert.equal(row.is_enabled, false);
  assert.equal(row.source_sha256, sha(row.source_document));
  const before = structuredClone([...f.rows]);
  assert.deepEqual(await seedSecureShopAssessmentDefaults(f.pool), { inserted: 0 });
  assert.deepEqual([...f.rows], before);
});
test('recognized populated predecessor updates only mechanism/provenance and then becomes a no-op', async () => {
  const before = oldRow(), sibling = oldRow({ objective_id: 'ss_other_pending' });
  const f = fixture([before, sibling]);
  await seedSecureShopAssessmentDefaults(f.pool);
  const row = f.rows.get(ID);
  assert.deepEqual(row, { ...before, qualification: 'native-model',
    source_document: { ...predecessor, qualification: 'native-model' },
    source_sha256: sha({ ...predecessor, qualification: 'native-model' }) });
  assert.deepEqual(f.rows.get(sibling.objective_id), sibling);
  const retained = structuredClone([...f.rows]);
  await seedSecureShopAssessmentDefaults(f.pool);
  assert.deepEqual([...f.rows], retained);
  assert.ok(f.calls.every(({ sql }) => !/assessment_(configuration|judgments|completions|contributions|retries)/.test(sql)));
});
for (const [name, override] of Object.entries({
  'instructor provenance': { configuration_source: 'instructor' },
  'unknown digest': { source_sha256: 'f'.repeat(64) },
  'altered document despite old digest': { source_document: { ...predecessor, label: 'Custom' } },
  'different mechanism': { qualification: 'native-browser-judge' }
})) test(`populated ${name} is preserved exactly`, async () => {
  const before = oldRow(override), f = fixture([before]);
  await seedSecureShopAssessmentDefaults(f.pool);
  await seedSecureShopAssessmentDefaults(f.pool);
  assert.deepEqual(f.rows.get(ID), before);
});

test('V08 exact pending predecessor promotes only qualification and provenance while preserving instructor settings', async () => {
  const id = 'ss_upload_svg_browser_execution', prior = guardedPredecessors.get(id);
  assert.equal(sha(prior), '9f89cf6be227a540b802991e653af465b6f0fab439f649f47646a9b9a0131e63');
  const fresh = fixture(); await seedSecureShopAssessmentDefaults(fresh.pool);
  assert.equal(fresh.rows.get(id).qualification, 'native-browser-judge');
  assert.equal(fresh.rows.get(id).is_enabled, false);
  const before = oldRow({ objective_id: id, source_document: structuredClone(prior), source_sha256: sha(prior) });
  const f = fixture([before]); await seedSecureShopAssessmentDefaults(f.pool);
  const source = { ...prior, qualification: 'native-browser-judge' };
  assert.deepEqual(f.rows.get(id), { ...before, qualification: source.qualification,
    source_document: source, source_sha256: sha(source) });
  const retained = structuredClone([...f.rows]);
  await seedSecureShopAssessmentDefaults(f.pool); assert.deepEqual([...f.rows], retained);
  assert.ok(f.calls.every(({ sql }) => !/assessment_(configuration|configuration_history|judgments|completions|contributions|retries)/.test(sql)));
});

test('V08 foreign, instructor and altered pending provenance is never promoted', async () => {
  const id = 'ss_upload_svg_browser_execution', prior = guardedPredecessors.get(id);
  for (const override of [{ configuration_source: 'instructor' }, { source_sha256: 'f'.repeat(64) },
    { source_document: { ...prior, label: 'Instructor source' } },
    { source_document: { ...prior, extra: true } }, { qualification: 'native-model' }]) {
    const before = oldRow({ objective_id: id, source_document: structuredClone(prior),
      source_sha256: sha(prior), ...override });
    const f = fixture([before]); await seedSecureShopAssessmentDefaults(f.pool);
    await seedSecureShopAssessmentDefaults(f.pool); assert.deepEqual(f.rows.get(id), before);
  }
});

test('V44 exact pending predecessor promotes only qualification and provenance while preserving instructor settings', async () => {
  const id = 'ss_file_path_traversal_read', prior = guardedPredecessors.get(id);
  assert.equal(sha(prior), '4044aa622ffcda35bf0af75319f1df1c9f6c50ff26431e150c90a86ce6b4f154');
  const fresh = fixture(); await seedSecureShopAssessmentDefaults(fresh.pool);
  assert.equal(fresh.rows.get(id).qualification, 'native-browser-judge');
  assert.equal(fresh.rows.get(id).is_enabled, false);
  const before = oldRow({ objective_id: id, source_document: structuredClone(prior), source_sha256: sha(prior) });
  const f = fixture([before]); await seedSecureShopAssessmentDefaults(f.pool);
  const source = { ...prior, qualification: 'native-browser-judge' };
  assert.deepEqual(f.rows.get(id), { ...before, qualification: source.qualification,
    source_document: source, source_sha256: sha(source) });
  const retained = structuredClone([...f.rows]);
  await seedSecureShopAssessmentDefaults(f.pool); assert.deepEqual([...f.rows], retained);
  assert.ok(f.calls.every(({ sql }) => !/assessment_(configuration|configuration_history|judgments|completions|contributions|retries)/.test(sql)));
});

test('V44 foreign, instructor and altered pending provenance is never promoted', async () => {
  const id = 'ss_file_path_traversal_read', prior = guardedPredecessors.get(id);
  for (const override of [{ configuration_source: 'instructor' }, { source_sha256: 'f'.repeat(64) },
    { source_document: { ...prior, label: 'Instructor source' } },
    { source_document: { ...prior, extra: true } }, { qualification: 'native-model' }]) {
    const before = oldRow({ objective_id: id, source_document: structuredClone(prior),
      source_sha256: sha(prior), ...override });
    const f = fixture([before]); await seedSecureShopAssessmentDefaults(f.pool);
    await seedSecureShopAssessmentDefaults(f.pool); assert.deepEqual(f.rows.get(id), before);
  }
});

test('V06 exact pending predecessor promotes only qualification and provenance while preserving instructor settings', async () => {
  const id = 'ss_upload_extension_bypass', prior = guardedPredecessors.get(id);
  assert.equal(sha(prior), '3efe05bed03c3cb5c75a3a14441ac719968faf22f8799be8337b77ade42f8f53');
  const fresh = fixture(); await seedSecureShopAssessmentDefaults(fresh.pool);
  assert.equal(fresh.rows.get(id).qualification, 'native-browser-judge');
  assert.equal(fresh.rows.get(id).is_enabled, false);
  const before = oldRow({ objective_id: id, source_document: structuredClone(prior), source_sha256: sha(prior) });
  const f = fixture([before]); await seedSecureShopAssessmentDefaults(f.pool);
  const source = { ...prior, qualification: 'native-browser-judge' };
  assert.deepEqual(f.rows.get(id), { ...before, qualification: source.qualification,
    source_document: source, source_sha256: sha(source) });
  const retained = structuredClone([...f.rows]);
  await seedSecureShopAssessmentDefaults(f.pool); assert.deepEqual([...f.rows], retained);
  assert.ok(f.calls.every(({ sql }) => !/assessment_(configuration|configuration_history|judgments|completions|contributions|retries)/.test(sql)));
});

test('V06 foreign, instructor and altered pending provenance is never promoted', async () => {
  const id = 'ss_upload_extension_bypass', prior = guardedPredecessors.get(id);
  for (const override of [{ configuration_source: 'instructor' }, { source_sha256: 'f'.repeat(64) },
    { source_document: { ...prior, label: 'Instructor source' } },
    { source_document: { ...prior, extra: true } }, { qualification: 'native-model' }]) {
    const before = oldRow({ objective_id: id, source_document: structuredClone(prior),
      source_sha256: sha(prior), ...override });
    const f = fixture([before]); await seedSecureShopAssessmentDefaults(f.pool);
    await seedSecureShopAssessmentDefaults(f.pool); assert.deepEqual(f.rows.get(id), before);
  }
});


test('V41 exact pending predecessor promotes qualification only and preserves instructor state on noop',async()=>{
 const id='ss_system_credential_disclosure',prior=guardedPredecessors.get(id);
 assert.equal(sha(prior),'c9d3d20dc00c08c53fc5a1c7d5ed3f2957ccd16400368bf4b19a16ad5d3366ab');
 const fresh=fixture();await seedSecureShopAssessmentDefaults(fresh.pool);
 assert.equal(fresh.rows.get(id).qualification,'native-browser-judge');assert.equal(fresh.rows.get(id).is_enabled,false);
 const before=oldRow({objective_id:id,source_document:structuredClone(prior),source_sha256:sha(prior)});
 const f=fixture([before]);await seedSecureShopAssessmentDefaults(f.pool);
 const source={...prior,qualification:'native-browser-judge'};
 assert.deepEqual(f.rows.get(id),{...before,qualification:source.qualification,source_document:source,source_sha256:sha(source)});
 const retained=structuredClone([...f.rows]);await seedSecureShopAssessmentDefaults(f.pool);assert.deepEqual([...f.rows],retained);
 assert.ok(f.calls.every(({sql})=>!/assessment_(configuration|configuration_history|judgments|completions|contributions|retries)/.test(sql)));
 for(const change of [{configuration_source:'instructor'},{source_sha256:'f'.repeat(64)},
  {source_document:{...prior,label:'Instructor source'}},{source_document:{...prior,extra:true}},{qualification:'native-model'}]){
  const untouched={...before,...change},negative=fixture([untouched]);
  await seedSecureShopAssessmentDefaults(negative.pool);await seedSecureShopAssessmentDefaults(negative.pool);
  assert.deepEqual(negative.rows.get(id),untouched);
 }
});

test('V42 exact pending predecessor promotes qualification only and preserves instructor state on noop',async()=>{
 const id='ss_mcp_registry_internal_discovery',prior=guardedPredecessors.get(id);
 assert.equal(sha(prior),'385ffd442a93f33fc2195329599e5d269dc04c117d9975242e04ede860db0590');
 const fresh=fixture();await seedSecureShopAssessmentDefaults(fresh.pool);
 assert.equal(fresh.rows.get(id).qualification,'native-browser-judge');assert.equal(fresh.rows.get(id).is_enabled,false);
 const before=oldRow({objective_id:id,source_document:structuredClone(prior),source_sha256:sha(prior)});
 const f=fixture([before]);await seedSecureShopAssessmentDefaults(f.pool);
 const source={...prior,qualification:'native-browser-judge'};
 assert.deepEqual(f.rows.get(id),{...before,qualification:source.qualification,source_document:source,source_sha256:sha(source)});
 const retained=structuredClone([...f.rows]);await seedSecureShopAssessmentDefaults(f.pool);assert.deepEqual([...f.rows],retained);
 assert.ok(f.calls.every(({sql})=>!/assessment_(configuration|configuration_history|judgments|completions|contributions|retries)/.test(sql)));
 for(const change of [{configuration_source:'instructor'},{source_sha256:'f'.repeat(64)},
  {source_document:{...prior,label:'Instructor source'}},{source_document:{...prior,extra:true}},{qualification:'native-model'}]){
  const untouched={...before,...change},negative=fixture([untouched]);
  await seedSecureShopAssessmentDefaults(negative.pool);await seedSecureShopAssessmentDefaults(negative.pool);
  assert.deepEqual(negative.rows.get(id),untouched);
 }
});

test('V07 exact pending predecessor promotes qualification only and preserves instructor state on noop',async()=>{
 const id='ss_upload_polyglot_server_execution',prior=guardedPredecessors.get(id);
 assert.equal(sha(prior),'00be7f7921bafa94f62a633575f39e63469369c30d935239a67f41540f238dd8');
 const fresh=fixture();await seedSecureShopAssessmentDefaults(fresh.pool);
 assert.equal(fresh.rows.get(id).qualification,'native-browser-judge');assert.equal(fresh.rows.get(id).is_enabled,false);
 const before=oldRow({objective_id:id,source_document:structuredClone(prior),source_sha256:sha(prior)});
 const f=fixture([before]);await seedSecureShopAssessmentDefaults(f.pool);
 const source={...prior,qualification:'native-browser-judge'};
 assert.deepEqual(f.rows.get(id),{...before,qualification:source.qualification,source_document:source,source_sha256:sha(source)});
 const retained=structuredClone([...f.rows]);await seedSecureShopAssessmentDefaults(f.pool);assert.deepEqual([...f.rows],retained);
 assert.ok(f.calls.every(({sql})=>!/assessment_(configuration|configuration_history|judgments|completions|contributions|retries)/.test(sql)));
 for(const change of [{configuration_source:'instructor'},{source_sha256:'f'.repeat(64)},
  {source_document:{...prior,label:'Instructor source'}},{source_document:{...prior,extra:true}},{qualification:'native-model'}]){
  const untouched={...before,...change},negative=fixture([untouched]);
  await seedSecureShopAssessmentDefaults(negative.pool);await seedSecureShopAssessmentDefaults(negative.pool);
  assert.deepEqual(negative.rows.get(id),untouched);
 }
});

test('V29 exact pending predecessor promotes qualification only and preserves instructor state on noop',async()=>{
 const id='ss_customer_role_escalation',prior=guardedPredecessors.get(id);
 assert.equal(sha(prior),'083f39f402f05f563cd935f3d3d19d8ffdb2ed6a7c0fa069731ec820cda364fe');
 const fresh=fixture();await seedSecureShopAssessmentDefaults(fresh.pool);
 assert.equal(fresh.rows.get(id).qualification,'native-browser-judge');assert.equal(fresh.rows.get(id).is_enabled,false);
 const before=oldRow({objective_id:id,source_document:structuredClone(prior),source_sha256:sha(prior)});
 const f=fixture([before]);await seedSecureShopAssessmentDefaults(f.pool);
 const source={...prior,qualification:'native-browser-judge'};
 assert.deepEqual(f.rows.get(id),{...before,qualification:source.qualification,source_document:source,source_sha256:sha(source)});
 const retained=structuredClone([...f.rows]);await seedSecureShopAssessmentDefaults(f.pool);assert.deepEqual([...f.rows],retained);
 assert.ok(f.calls.every(({sql})=>!/assessment_(configuration|configuration_history|judgments|completions|contributions|retries)/.test(sql)));
 for(const change of [{configuration_source:'instructor'},{source_sha256:'f'.repeat(64)},
  {source_document:{...prior,label:'Instructor source'}},{source_document:{...prior,extra:true}},{qualification:'native-model'}]){
  const untouched={...before,...change},negative=fixture([untouched]);
  await seedSecureShopAssessmentDefaults(negative.pool);await seedSecureShopAssessmentDefaults(negative.pool);
  assert.deepEqual(negative.rows.get(id),untouched);
 }
});
