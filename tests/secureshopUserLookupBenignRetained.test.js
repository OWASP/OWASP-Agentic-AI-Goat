'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const subject = require('./fixtures/secureshopUserLookupBenignRetained');
const root = path.join(__dirname, '../tasks/qualification', subject.RUN);
const capture = fs.readFileSync(path.join(root, 'user-lookup-disclosure-capture.json'));
const result = fs.readFileSync(path.join(root, 'result.json'));
test('retained genuine repaired actor is only a partial negative candidate', () => {
  const witness = subject.readRetainedNegative();
  assert.equal(witness.actorPhysicalCalls, 3);
  assert.equal(witness.authorizedSchemaRepairs, 1);
  assert.equal(witness.completedEffects, 1);
  assert.equal(witness.omittedFields.length, 6);
  for (const key of ['cohortPassed','lifecycleComplete','independentJudgeCalibration','assessmentAttempted','canonicalCredit']) assert.equal(witness[key], false);
  assert.equal(witness.judgeCalls, 0);
  assert.equal(witness.wire.length, 3);
});
for (const [name, mutate] of Object.entries({
  droppedRepair:c=>c.wire.splice(0,1),
  changedFinal:c=>c.cases[0].saved.text='replacement',
  changedSource:c=>c.cases[0].lookup.user.email='replacement',
  changedEffect:c=>c.cases[0].effects.pop(),
  forgedJudge:c=>c.canonicalJudge={verdict:'pass'},
  forgedLifecycle:c=>c.lifecycle={passed:true},
})) test(`immutable admission rejects ${name}`, () => {
  const changed = JSON.parse(capture); mutate(changed);
  assert.throws(()=>subject.admitBytes(Buffer.from(JSON.stringify(changed)), result), /unrecognized/);
});
test('failed receipt cannot be promoted, truncated, or replaced', () => {
  const changed=JSON.parse(result); changed.passed=true;
  assert.throws(()=>subject.admitBytes(capture, Buffer.from(JSON.stringify(changed))));
  assert.throws(()=>subject.admitBytes(capture.subarray(0,100), result));
  assert.throws(()=>subject.admitBytes(Buffer.alloc(4*1024*1024+1), result));
});
