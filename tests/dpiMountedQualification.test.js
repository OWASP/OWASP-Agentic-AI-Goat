'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { summarizeMountedQualification } = require('./fixtures/dpiMountedQualification');

const receipt = (verdict, disposition) => ({ verdict, disposition });
const cohort = () => [
  ...Array.from({ length: 4 }, (_, index) => ({ owner: 'a', objective: 'system_prompt',
    kind: 'negative', canonicalUnchanged: true, receipt: receipt('fail', 'not_pass'), index })),
  { owner: 'a', objective: 'system_prompt', kind: 'positive', receipt: receipt('pass', 'awarded') },
  { owner: 'b', objective: 'system_prompt', kind: 'positive', receipt: receipt('pass', 'awarded') },
];
const reset = () => ({ generation: 0, nextGeneration: 1, ownerResetApplied: true,
  ownerCompletedBeforeReset: false, ownerCompletedAfterReset: false, siblingPreserved: true });

test('mounted qualification reports semantic accuracy separately from completed reset isolation', () => {
  const rows = cohort(); rows[4].receipt = receipt('fail', 'not_pass');
  const result = summarizeMountedQualification(rows, reset());
  assert.deepEqual(result.lifecycle, { completed: true, interactions: 6, receipts: 6, reset: true });
  assert.equal(result.modelAccuracy.matched, 5);
  assert.deepEqual(result.modelAccuracy.mismatches, [{ owner: 'a', objective: 'system_prompt',
    kind: 'positive', verdict: 'fail', disposition: 'not_pass' }]);
});

test('unavailable results are accuracy mismatches and never become positive or negative successes', () => {
  const rows = cohort(); rows[0].receipt = receipt('unavailable', 'not_pass');
  rows[5].receipt = receipt('unavailable', 'not_pass');
  const result = summarizeMountedQualification(rows, reset());
  assert.equal(result.lifecycle.completed, true);
  assert.equal(result.modelAccuracy.matched, 4);
  assert.deepEqual(result.modelAccuracy.mismatches.map(item => [item.kind, item.verdict]),
    [['negative', 'unavailable'], ['positive', 'unavailable']]);
});

test('lifecycle completion remains false until reset generation and sibling evidence agree', () => {
  const result = summarizeMountedQualification(cohort(), { ...reset(), siblingPreserved: false });
  assert.equal(result.lifecycle.completed, false);
  assert.equal(result.modelAccuracy.matched, 6);
});
