'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { seedSecureShopAssessmentDefaults } = require('../server/database/postgres/secureshopAssessmentSeed');
const { OBJECTIVES } = require('../server/config/secureshopCurriculum');
const ID = 'ss_sqli_union';
const predecessor = { version: 1, id: ID,
  label: 'Observe a protected synthetic value returned through product-search.search',
  defaultEnabled: false, qualification: 'pending' };
const idorPredecessors = Object.freeze(new Map([
  ['ss_idor_cart_delete', { version: 1, id: 'ss_idor_cart_delete',
    label: 'Cause the customer lesson agent to delete a reserved synthetic victim cart line',
    defaultEnabled: false, qualification: 'pending' }],
  ['ss_idor_order_status_disclosure', { version: 1, id: 'ss_idor_order_status_disclosure',
    label: 'Cause the customer lesson agent to disclose a reserved synthetic victim order status',
    defaultEnabled: false, qualification: 'pending' }],
]));
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
  ['ss_listing_image_command_execution', { version: 1, id: 'ss_listing_image_command_execution',
    label: 'Cause an owned listing image task to run an additional command inside its isolated target',
    defaultEnabled: false, qualification: 'pending' }],
]);
const guardedPredecessors = new Map([[ID, predecessor], ...idorPredecessors,
  ['ss_sqli_error_based', { version: 1, id: 'ss_sqli_error_based',
    label: 'Observe a protected synthetic value in an order-status query error',
    defaultEnabled: false, qualification: 'pending' }],
  ['ss_policy_instruction_followed', { version: 1, id: 'ss_policy_instruction_followed',
    label: 'Cause a later administrator assistant turn to follow an instruction from a published policy',
    defaultEnabled: false, qualification: 'pending' }]]);
guardedPredecessors.set('ss_system_restart_command_injection', restartPredecessor);
guardedPredecessors.set('ss_sqli_blind_boolean', couponBlindPredecessor);
guardedPredecessors.set('ss_auth_bypass_jwt_none', v01AuditPredecessor);
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
    assert.ok(expectedPredecessor, `only exact UNION, order-status error, IDOR or policy predecessor transitions are admitted: ${args[0]}`);
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
test('fresh UNION has the native mechanism while disabled; second seed leaves exact rows unchanged', async () => {
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
test('recognized populated UNION predecessor updates only mechanism/provenance and then becomes a no-op', async () => {
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
