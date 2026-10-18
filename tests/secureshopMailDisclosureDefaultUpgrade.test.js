'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const provenance = require('../server/database/postgres/catalogDefaultProvenance');
const prior = require('./fixtures/secureshopMailDisclosurePriorDefaults.json');

// Evaluate the promoted curriculum in memory against retained prior defaults.
const file = path.join(__dirname, '../server/config/secureshopCurriculum.js');
const original = fs.readFileSync(file, 'utf8');
const pattern = /(\{ id: 'ss_mail_cross_persona_read',[^\n]*qualification: )'pending'/;
assert.equal([...original.matchAll(new RegExp(pattern.source, 'g'))].length, 0);
const obsolete = ' Production availability remains pending until the complete native, actual Judge and connected UI qualification is accepted.';
assert.equal(original.split(obsolete).length, 1);
const moduleObject = { exports: {} };
vm.runInNewContext(original.replace(pattern, "$1'native-model'").replace(obsolete, ''), { module: moduleObject });
const candidate = JSON.parse(JSON.stringify(moduleObject.exports));
const id = prior.objectiveId;

function client(current, applied, state = 'managed') {
 const writes = [];
 return { writes, async query(sql, params = []) {
  if (/SELECT revision/.test(sql)) return { rows: [{ revision: 1 }] };
  if (/SELECT (hint_content|solution_content) AS value/.test(sql)) return { rows: [{ value: current }], rowCount: 1 };
  if (/SELECT \* FROM workshop_platform.catalog_field_defaults/.test(sql)) return { rows: [{ provenance_state: state, applied_default_hash: provenance.hashDocument(provenance.document(applied)) }] };
  if (/UPDATE workshop_platform\.(objectives|catalog_field_defaults)/.test(sql)) { writes.push({ sql, params }); return { rows: [], rowCount: 1 }; }
  throw new Error('Unexpected query: ' + sql);
 } };
}
for (const [field, oldValue, sourceValue] of [
 ['hint_content', prior.hint, candidate.HINTS[id]],
 ['solution_content', prior.solution, candidate.SOLUTIONS[id]],
]) {
 const spec = { entityKind: 'objective', workshopKey: candidate.WORKSHOP_KEY, objectiveId: id, fieldName: field, sourceValue, sourceVersion: 'disclosure-candidate-only' };
 test(field + ': managed prior content reconciles exactly; second pass makes no content write', async () => {
  const db = client(oldValue, oldValue);
  const result = await provenance.reconcileField(db, spec);
  const changed = JSON.stringify(oldValue) !== JSON.stringify(sourceValue);
  assert.equal(result.changed, changed);
  const writes = db.writes.filter(w => /UPDATE workshop_platform\.objectives/.test(w.sql));
  assert.equal(writes.length, changed ? 1 : 0);
  if (changed) assert.deepEqual(JSON.parse(writes[0].params[2]), sourceValue);
  const second = client(sourceValue, sourceValue);
  assert.equal((await provenance.reconcileField(second, spec)).changed, false);
  assert.equal(second.writes.some(w => /UPDATE workshop_platform\.objectives/.test(w.sql)), false);
 });
 for (const current of [null, { title: 'Instructor-owned content' }]) {
  test(field + ': preserves instructor ' + (current === null ? 'null' : 'edit'), async () => {
   for (const state of ['managed', 'custom']) {
    const db = client(current, oldValue, state);
    assert.equal((await provenance.reconcileField(db, spec)).changed, false);
    assert.equal(db.writes.some(w => /UPDATE workshop_platform\.objectives/.test(w.sql)), false);
   }
  });
 }
}
test('candidate content retains manual-IDOR lesson and default-disabled policy', () => {
 assert(candidate.OBJECTIVES.every(o => o.defaultEnabled === false));
 assert.match(candidate.SOLUTIONS[id].examples[0].explanation, /manual IDOR/);
 assert(!candidate.SOLUTIONS[id].tips.some(t => t.includes('Production availability remains pending')));
 assert.equal(fs.readFileSync(file, 'utf8'), original);
});
