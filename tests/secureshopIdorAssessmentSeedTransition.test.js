'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { seedSecureShopAssessmentDefaults } = require('../server/database/postgres/secureshopAssessmentSeed');
const { OBJECTIVES } = require('../server/config/secureshopCurriculum');

const IDS = Object.freeze(['ss_idor_cart_delete', 'ss_idor_order_status_disclosure']);
const predecessor = Object.freeze(Object.fromEntries(IDS.map(id => {
  const objective = OBJECTIVES.find(row => row.id === id);
  return [id, Object.freeze({ version: 1, id, label: objective.text,
    defaultEnabled: false, qualification: 'pending' })];
})));
const sha = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
function oldRow(id, overrides = {}) {
  return { objective_id: id, label: `Instructor label for ${id}`, is_enabled: true,
    catalog_active: false, qualification: 'pending', configuration_source: 'checked_in_default',
    source_document: structuredClone(predecessor[id]), source_sha256: sha(predecessor[id]),
    updated_at: 'retained timestamp', ...overrides };
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
    assert.match(sql, /WHERE objective_id=\$1 AND qualification='(?:pending|native-model)'/);
    const required=sql.includes("qualification='native-model'")?'native-model':'pending';
    assert.match(sql, /configuration_source='checked_in_default'/);
    assert.match(sql, /source_sha256=\$5 AND source_document=\$6::jsonb/);
    const row = rows.get(args[0]);
    if (row?.qualification !== required || row.configuration_source !== 'checked_in_default'
      || row.source_sha256 !== args[4]
      || !require('node:util').isDeepStrictEqual(row.source_document, JSON.parse(args[5]))) return { rowCount: 0 };
    Object.assign(row, { qualification: args[1], source_sha256: args[2], source_document: JSON.parse(args[3]) });
    return { rowCount: 1 };
  } };
  return { rows, calls, pool: { connect: async () => client } };
}

test('fresh IDOR defaults retain cart qualification and keep excluded order pending and disabled and then reseed unchanged', async () => {
  const f = fixture();
  assert.deepEqual(await seedSecureShopAssessmentDefaults(f.pool), { inserted: OBJECTIVES.length });
  for (const id of IDS) {
    const objective = OBJECTIVES.find(row => row.id === id), row = f.rows.get(id);
    assert.deepEqual(row.source_document, { version: 1, id, label: objective.text,
      defaultEnabled: false, qualification: objective.qualification });
    assert.equal(row.qualification, id===IDS[1]?'pending':'native-model');
    assert.equal(row.is_enabled, false);
    assert.equal(row.source_sha256, sha(row.source_document));
  }
  const retained = structuredClone([...f.rows]);
  assert.deepEqual(await seedSecureShopAssessmentDefaults(f.pool), { inserted: 0 });
  assert.deepEqual([...f.rows], retained);
});

test('only exact checked-in pending IDOR predecessors transition; instructor and tenant configuration are untouched', async () => {
  const old = IDS.map(id => oldRow(id));
  const sibling = oldRow(IDS[0], { objective_id: 'ss_other_pending' });
  const f = fixture([...old, sibling]);
  await seedSecureShopAssessmentDefaults(f.pool);
  for (const id of IDS) {
    const before = old.find(row => row.objective_id === id), row = f.rows.get(id);
    const qualification=id===IDS[1]?'pending':'native-model';
    assert.deepEqual(row, { ...before, qualification,
      source_document: { ...predecessor[id], qualification },
      source_sha256: sha({ ...predecessor[id], qualification }) });
  }
  assert.deepEqual(f.rows.get(sibling.objective_id), sibling);
  assert.ok(f.calls.every(({ sql }) => !/assessment_(configuration|configuration_history|judgments|completions|contributions|retries)/.test(sql)));
  const retained = structuredClone([...f.rows]);
  await seedSecureShopAssessmentDefaults(f.pool);
  assert.deepEqual([...f.rows], retained);
});

for (const [name, override] of Object.entries({
  'instructor-owned source': { configuration_source: 'instructor' },
  'unknown source digest': { source_sha256: 'f'.repeat(64) },
  'altered source document': { source_document: { ...predecessor[IDS[0]], label: 'Custom' } },
  'different mechanism': { qualification: 'native-browser-judge' },
})) test(`IDOR ${name} is preserved exactly`, async () => {
  const initial = IDS.map(id => oldRow(id, id === IDS[0] ? override : {}));
  const f = fixture(initial);
  await seedSecureShopAssessmentDefaults(f.pool);
  await seedSecureShopAssessmentDefaults(f.pool);
  assert.deepEqual(f.rows.get(IDS[0]), initial[0]);
});

test('only exact checked-in V12 native predecessor returns to pending without changing instructor settings or evidence',async()=>{
 const id=IDS[1],native={...predecessor[id],qualification:'native-model'};
 const before=oldRow(id,{qualification:'native-model',source_document:native,source_sha256:sha(native)});
 const f=fixture([before]);await seedSecureShopAssessmentDefaults(f.pool);
 assert.deepEqual(f.rows.get(id),{...before,qualification:'pending',source_document:predecessor[id],source_sha256:sha(predecessor[id])});
 const saved=structuredClone([...f.rows]);await seedSecureShopAssessmentDefaults(f.pool);assert.deepEqual([...f.rows],saved);
 assert.ok(f.calls.every(({sql})=>!/assessment_(configuration|configuration_history|judgments|completions|contributions|retries)/.test(sql)));
 for(const patch of [{configuration_source:'instructor'},{source_sha256:'f'.repeat(64)},{source_document:{...native,label:'Custom'}},{qualification:'native-browser-judge'}]){
  const custom={...before,...patch},g=fixture([custom]);await seedSecureShopAssessmentDefaults(g.pool);assert.deepEqual(g.rows.get(id),custom);
 }
});
