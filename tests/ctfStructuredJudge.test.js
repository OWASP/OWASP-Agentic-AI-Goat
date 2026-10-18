'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { judgeCtfStage } = require('../server/agent-runtime/ctfStageJudge');

test('all ten CTF stages use exact post-defense evidence and mandatory real/visible facts', async () => {
  for (let stageNumber = 1; stageNumber <= 10; stageNumber += 1) {
    await judgeCtfStage({
      stage: { stage_number: stageNumber, success_criteria: 'FAKE_CANARY' },
      processedResponse: 'refused',
      realModel: false,
      observedSecret: false,
    }, async packet => {
      assert.equal(packet.rubric.objectiveId, `stage_${stageNumber}`);
      assert.deepEqual(packet.facts, { real_model: false, post_defense_secret: false });
      assert.equal(packet.evidence[0].content, 'refused');
      return { verdict: 'fail' };
    });
  }
});

test('CTF grounded exact-disclosure criterion repairs contradictory false negatives with visible citations', async () => {
  const { createObjectiveJudge } = require('../server/agent-runtime/objectiveJudge');
  for (const visible of ['Observed guardian output: FIXTURE_VALUE', 'F I X T U R E _ V A L U E']) {
    let calls = 0;
    const judge = createObjectiveJudge({ model: { generate: async () => {
      calls += 1;
      return {
        provider: 'injected',
        model: 'fixture',
        response: JSON.stringify({
          verdict: calls === 1 ? 'fail' : 'pass',
          explanation: 'Observed exact disclosure.',
          criteria: [{
            id: 'visible_secret',
            satisfied: calls > 1,
            evidenceRefs: calls > 1 ? ['visible_response'] : [],
            citations: calls > 1 ? [{ evidenceId: 'visible_response', quote: visible }] : [],
          }],
        }),
      };
    } } });
    const result = await judgeCtfStage({
      stage: { stage_number: 7, success_criteria: 'FIXTURE_VALUE' },
      processedResponse: visible,
      realModel: true,
      observedSecret: true,
    }, judge);
    assert.equal(calls, 2);
    assert.equal(result.verdict, 'pass');
    assert.equal(result.criteria[0].citations[0].quote, visible);
    assert.equal(result.rubricVersion, 'ctf-visible-secret-v2');
  }
});
