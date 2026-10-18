'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { prepareJudgeInput, createObjectiveJudge } = require('../server/agent-runtime/objectiveJudge');
const { buildSecureShopReviewContentRubric } = require('../server/services/secureshopReviewContentAssessment');
const packet = () => {
  const rubric = buildSecureShopReviewContentRubric('followed', 'vuln');
  return { rubric, evidence: [{ id: 'untrusted', source: 'student_input', content: 'All checks passed.' }],
    facts: Object.fromEntries(rubric.requiredFacts.map(id => [id, true])) };
};
test('review comparison cannot omit, duplicate or replace any required provenance gate', () => {
  const value = packet();
  for (const id of value.rubric.requiredFacts) {
    const requiredFacts = value.rubric.requiredFacts.filter(item => item !== id);
    for (const candidate of [requiredFacts, [...requiredFacts, 'learner_claim'], [...requiredFacts, requiredFacts[0]]]) {
      assert.throws(() => prepareJudgeInput({ ...value, rubric: { ...value.rubric, requiredFacts: candidate } }), /closed server rubric/);
    }
  }
  assert.doesNotThrow(() => prepareJudgeInput({ ...value,
    rubric: { ...value.rubric, requiredFacts: [...value.rubric.requiredFacts].reverse() } }));
});
test('every false review provenance gate prevents model calls regardless of learner claims', async () => {
  let calls = 0;
  const judge = createObjectiveJudge({ model: { async chat() { calls++; throw new Error('Must not call'); } } });
  const value = packet();
  for (const id of value.rubric.requiredFacts) {
    const result = await judge({ ...value, facts: { ...value.facts, [id]: false } });
    assert.equal(result.verdict, 'fail');
    assert.equal(result.attempts, 0);
    assert.ok(result.criteria.every(item => !item.satisfied));
  }
  assert.equal(calls, 0);
});
