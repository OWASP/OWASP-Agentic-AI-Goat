'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash } = require('node:crypto');
const { seedSecureShopAssessmentDefaults } = require('../server/database/postgres/secureshopAssessmentSeed');
const { OBJECTIVES } = require('../server/config/secureshopCurriculum');

const ID = 'ss_sqli_coupon';
const sha = value => createHash('sha256').update(JSON.stringify(value)).digest('hex');
const sourceFor = objective => ({ version: 1, id: objective.id, label: objective.text,
  defaultEnabled: objective.defaultEnabled, qualification: objective.qualification });
function fixture(initial = []) {
  const rows = new Map(initial.map(row => [row.objective_id, structuredClone(row)]));
  const calls = [];
  const client = { release() {}, async query(sql, args = []) {
    calls.push({ sql, args });
    if (['BEGIN', 'COMMIT', 'ROLLBACK'].includes(sql)) return {};
    if (sql.includes('INSERT INTO secureshop_auth.assessment_objectives')) {
      if (rows.has(args[0])) return { rowCount: 0 };
      rows.set(args[0], { objective_id: args[0], label: args[1], is_enabled: args[2],
        catalog_active: true, qualification: args[3], source_sha256: args[4],
        source_document: JSON.parse(args[5]), configuration_source: 'checked_in_default' });
      return { rowCount: 1 };
    }
    assert.match(sql, /UPDATE secureshop_auth\.assessment_objectives/);
    const row = rows.get(args[0]), prior = JSON.parse(args[5]);
    if (row?.qualification !== 'pending' || row.configuration_source !== 'checked_in_default'
      || row.source_sha256 !== args[4]
      || !require('node:util').isDeepStrictEqual(row.source_document, prior)) return { rowCount: 0 };
    Object.assign(row, { qualification: args[1], source_sha256: args[2], source_document: JSON.parse(args[3]) });
    return { rowCount: 1 };
  } };
  return { rows, calls, pool: { connect: async () => client } };
}

test('fresh coupon objective records only a disabled supported mechanism and reseeds without changes', async () => {
  const f = fixture();
  assert.deepEqual(await seedSecureShopAssessmentDefaults(f.pool), { inserted: OBJECTIVES.length });
  const objective = OBJECTIVES.find(row => row.id === ID), row = f.rows.get(ID);
  assert.deepEqual(row.source_document, sourceFor(objective));
  assert.equal(row.qualification, 'native-model');
  assert.equal(row.is_enabled, false);
  assert.equal(row.source_sha256, sha(row.source_document));
  const retained = structuredClone([...f.rows]);
  assert.deepEqual(await seedSecureShopAssessmentDefaults(f.pool), { inserted: 0 });
  assert.deepEqual([...f.rows], retained);
});

test('existing coupon catalog state is preserved because no predecessor transition is admitted', async () => {
  const objective = OBJECTIVES.find(row => row.id === ID);
  const existing = { objective_id: ID, label: 'Instructor coupon wording', is_enabled: true,
    catalog_active: false, qualification: 'pending', configuration_source: 'instructor',
    source_document: { version: 1, id: ID, label: 'Instructor coupon wording',
      defaultEnabled: true, qualification: 'pending' }, source_sha256: 'f'.repeat(64),
    updated_at: 'retained timestamp' };
  const f = fixture([existing]);
  await seedSecureShopAssessmentDefaults(f.pool);
  await seedSecureShopAssessmentDefaults(f.pool);
  assert.deepEqual(f.rows.get(ID), existing);
  assert.equal(f.calls.filter(({ sql, args }) => /UPDATE secureshop_auth\.assessment_objectives/.test(sql)
    && args[0] === ID).length, 0);
  assert.ok(f.calls.every(({ sql }) => !/assessment_(configuration|configuration_history|judgments|completions|contributions|retries)/.test(sql)));
  assert.equal(objective.defaultEnabled, false);
});


test('V16 pending and V46 qualified defaults insert once and preserve instructor-owned reseeds', async()=>{
 const ids=['ss_product_description_instruction_adoption','ss_upload_path_traversal_write'];
 const fresh=fixture();await seedSecureShopAssessmentDefaults(fresh.pool);
 for(const id of ids){const row=fresh.rows.get(id),objective=OBJECTIVES.find(value=>value.id===id);
  assert.equal(row.is_enabled,false);assert.equal(row.qualification,objective.qualification);
  assert.equal(row.qualification,id==='ss_upload_path_traversal_write'?'native-browser-judge':'pending');
  assert.deepEqual(row.source_document,sourceFor(objective));assert.equal(row.source_sha256,sha(row.source_document));}
 const before=structuredClone([...fresh.rows]);assert.deepEqual(await seedSecureShopAssessmentDefaults(fresh.pool),{inserted:0});
 assert.deepEqual([...fresh.rows],before);
 const custom=ids.map(id=>({...structuredClone(fresh.rows.get(id)),label:'Instructor-owned '+id,
  is_enabled:true,catalog_active:false,configuration_source:'instructor',source_sha256:'a'.repeat(64),
  source_document:{custom:true},updated_at:'retained'}));
 const populated=fixture(custom);await seedSecureShopAssessmentDefaults(populated.pool);await seedSecureShopAssessmentDefaults(populated.pool);
 for(const row of custom)assert.deepEqual(populated.rows.get(row.objective_id),row);
 const guarded=populated.calls.filter(({sql,args})=>/UPDATE secureshop_auth\.assessment_objectives/.test(sql)&&ids.includes(args[0]));
 assert.equal(guarded.length,2);
 assert.ok(guarded.every(({sql,args})=>args[0]==='ss_upload_path_traversal_write'
  &&/qualification='pending'/.test(sql)&&/configuration_source='checked_in_default'/.test(sql)));
 assert.ok(populated.calls.every(({sql})=>!/assessment_(judgments|completions|contributions|retries)/.test(sql)));
});
