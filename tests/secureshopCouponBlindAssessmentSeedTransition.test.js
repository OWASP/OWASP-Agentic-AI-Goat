'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { seedSecureShopAssessmentDefaults } = require('../server/database/postgres/secureshopAssessmentSeed');
const { OBJECTIVES } = require('../server/config/secureshopCurriculum');

const ID = 'ss_sqli_blind_boolean';
const predecessor = { version: 1, id: ID,
  label: 'Infer an unknown synthetic password character from read-only coupon query outcomes',
  defaultEnabled: false, qualification: 'pending' };
const sha = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
function oldRow(overrides = {}) {
  return { objective_id: ID, label: 'Instructor coupon-blind wording', is_enabled: true,
    catalog_active: false, qualification: 'pending', configuration_source: 'checked_in_default',
    source_document: structuredClone(predecessor), source_sha256: sha(predecessor),
    updated_at: 'retained timestamp', revision: 17, ...overrides };
}
function fixture(initial = []) {
  const rows = new Map(initial.map(row => [row.objective_id, structuredClone(row)]));
  const calls = [];
  const client = { release() {}, async query(sql, args = []) {
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
    const expectedQualification = sql.match(/WHERE objective_id=\$1 AND qualification='([^']+)'/)?.[1];
    assert.ok(expectedQualification, 'closed predecessor qualification');
    if (args[0] === ID) assert.equal(expectedQualification, 'pending');
    assert.match(sql, /configuration_source='checked_in_default'/);
    assert.match(sql, /source_sha256=\$5 AND source_document=\$6::jsonb/);
    const row = rows.get(args[0]), prior = JSON.parse(args[5]);
    if (row?.qualification !== expectedQualification || row.configuration_source !== 'checked_in_default'
      || row.source_sha256 !== args[4]
      || !require('node:util').isDeepStrictEqual(row.source_document, prior)) return { rowCount: 0 };
    Object.assign(row, { qualification: args[1], source_sha256: args[2],
      source_document: JSON.parse(args[3]) });
    return { rowCount: 1 };
  } };
  return { rows, calls, pool: { connect: async () => client } };
}

test('fresh coupon-blind default records the qualified mechanism while disabled and reseeds unchanged', async () => {
  const f = fixture();
  assert.deepEqual(await seedSecureShopAssessmentDefaults(f.pool), { inserted: OBJECTIVES.length });
  const objective = OBJECTIVES.find(row => row.id === ID), row = f.rows.get(ID);
  assert.equal(objective.qualification, 'native-browser-judge');
  assert.equal(row.qualification, 'native-browser-judge');
  assert.equal(row.is_enabled, false);
  assert.equal(row.source_sha256, sha(row.source_document));
  const retained = structuredClone([...f.rows]);
  assert.deepEqual(await seedSecureShopAssessmentDefaults(f.pool), { inserted: 0 });
  assert.deepEqual([...f.rows], retained);
});

test('recognized coupon-blind predecessor updates only mechanism provenance and then becomes a no-op', async () => {
  const before = oldRow(), sibling = oldRow({ objective_id: 'ss_other_pending' });
  const f = fixture([before, sibling]);
  await seedSecureShopAssessmentDefaults(f.pool);
  const objective = OBJECTIVES.find(row => row.id === ID), row = f.rows.get(ID);
  assert.deepEqual(row, { ...before, qualification: 'native-browser-judge',
    source_document: { version: 1, id: ID, label: objective.text,
      defaultEnabled: false, qualification: 'native-browser-judge' },
    source_sha256: sha({ version: 1, id: ID, label: objective.text,
      defaultEnabled: false, qualification: 'native-browser-judge' }) });
  assert.deepEqual(f.rows.get(sibling.objective_id), sibling);
  assert.ok(f.calls.every(({ sql }) => !/assessment_(configuration|configuration_history|judgments|completions|contributions|retries)/.test(sql)));
  const retained = structuredClone([...f.rows]);
  await seedSecureShopAssessmentDefaults(f.pool);
  assert.deepEqual([...f.rows], retained);
});

for (const [name, override] of Object.entries({
  'instructor provenance': { configuration_source: 'instructor' },
  'unknown digest': { source_sha256: 'f'.repeat(64) },
  'altered document despite old digest': { source_document: { ...predecessor, label: 'Custom' } },
  'different mechanism': { qualification: 'native-model' },
})) test(`coupon-blind ${name} is preserved exactly`, async () => {
  const before = oldRow(override), f = fixture([before]);
  await seedSecureShopAssessmentDefaults(f.pool);
  await seedSecureShopAssessmentDefaults(f.pool);
  assert.deepEqual(f.rows.get(ID), before);
});
