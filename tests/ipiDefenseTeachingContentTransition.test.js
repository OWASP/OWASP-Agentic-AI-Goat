'use strict';
const test = require('node:test'), assert = require('node:assert/strict');
const vm = require('node:vm'), crypto = require('node:crypto');
const retained = require('../tests/release-inputs/ipi-defense-content-predecessors-v1.json');
const provenance = require('../server/database/postgres/catalogDefaultProvenance');
const currentHints = require('../server/data/workshopHints');
const currentSolutions = require('../server/data/indirectPromptInjectionSolutions');
const objectiveId = 'rag_injected_doc';
function previous(path) {
  const entry = retained.files[path], raw = Buffer.from(entry.base64, 'base64');
  assert.equal(crypto.createHash('sha256').update(raw).digest('hex'), entry.sha256);
  const context = { module: { exports: {} }, require: require('node:module').createRequire(require('node:path').resolve(__dirname, '..', path)) }; vm.runInNewContext(raw.toString(), context);
  return JSON.parse(JSON.stringify(context.module.exports));
}
const oldHints = previous('server/data/workshopHints.js');
const oldSolutions = previous('server/data/indirectPromptInjectionSolutions.js');
const hash = value => provenance.hashDocument(provenance.document(value));
function client(current, old, state) {
  const calls = [];
  return { calls, async query(sql, args) {
    calls.push({sql,args});
    if (/SELECT revision/.test(sql)) return {rows:[{revision:1}],rowCount:1};
    if (/ AS value FROM/.test(sql)) return {rows:[{value:current}],rowCount:1};
    if (/SELECT \* FROM workshop_platform.catalog_field_defaults/.test(sql)) return {rows:state==='absent'?[]:[{provenance_state:state,applied_default_hash:hash(old)}],rowCount:state==='absent'?0:1};
    return {rows:[],rowCount:1};
  }};
}
test('defense content changes only its objective and preserves the attack lesson', () => {
  const clone = x => JSON.parse(JSON.stringify(x));
  const h = clone(currentHints), s = clone(currentSolutions);
  h.indirect_prompt_injection[objectiveId] = oldHints.indirect_prompt_injection[objectiveId];
  s[objectiveId] = oldSolutions[objectiveId];
  assert.deepEqual(h, oldHints); assert.deepEqual(s, oldSolutions);
  const rubric = require('../server/agent-runtime/indirectObjectiveJudge').buildIpiRubric(objectiveId);
  assert.equal(rubric.outcomeIntent, 'defense'); assert.equal(rubric.sourceComparison.outcome, 'defense_rejection');
  assert.match(currentSolutions[objectiveId].approach, /explicitly recognize/);
  assert.match(currentSolutions[objectiveId].approach, /refuse to follow it without performing/);
  assert.match(currentHints.indirect_prompt_injection[objectiveId].hints[2], /does not complete/);
});
for (const [fieldName, old, current] of [
  ['hint_content',oldHints.indirect_prompt_injection[objectiveId],currentHints.indirect_prompt_injection[objectiveId]],
  ['solution_content',oldSolutions[objectiveId],currentSolutions[objectiveId]],
]) test(`defense ${fieldName} upgrades managed defaults and preserves instructor content`, async () => {
  assert.notEqual(hash(old),hash(current));
  for (const [value,state,expected] of [[old,'managed','upgrade'],[{...old,title:'Instructor content'},'custom','preserve'],[{...old,title:'Unmarked instructor edit'},'managed','mark_custom'],[old,'legacy_unknown','preserve'],[null,'custom','preserve'],[old,'absent','preserve_unknown'],[current,'managed','record']]) {
    const c = client(value,expected==='record'?current:old,state);
    const result = await provenance.reconcileField(c,{entityKind:'objective',workshopKey:'indirect_prompt_injection',objectiveId,fieldName,sourceValue:current,sourceVersion:'ipi-defense-teaching-alignment-v1'});
    assert.equal(result.decision,expected);
    assert.equal(c.calls.some(x=>x.sql.startsWith('UPDATE workshop_platform.objectives SET')),expected==='upgrade');
  }
});
