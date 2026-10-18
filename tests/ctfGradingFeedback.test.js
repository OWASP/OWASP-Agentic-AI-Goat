'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { runCtfResultGraph } = require('../server/agent-runtime/ctfResultGraph');

test('CTF distinguishes grading errors from attack failure without granting credit or discarding evidence', async () => {
  for (const verdict of ['unavailable', 'inconclusive', 'fail', 'pass']) {
    let commits = 0;
    const result = await runCtfResultGraph({
      wasSuccessful: true, participant: { id: 1 }, stageId: 3,
      stage: { stage_name: 'Fixture', level_score: 100 }, attemptNumber: 2,
      studentResponse: 'VISIBLE_LAB_SECRET', showFeedback: false,
    }, {
      judgment: { verdict },
      commit: async () => { commits++; return { accepted: verdict === 'pass' }; },
      CTFHelpers: { getConfig: async () => '3', getProgress: async () => ({}) },
    });
    assert.equal(commits, 1);
    assert.equal(result.success, verdict === 'pass');
    assert.equal(result.aiResponse, 'VISIBLE_LAB_SECRET');
    assert.equal(result.judgment.verdict, verdict);
    if (verdict === 'unavailable' || verdict === 'inconclusive') {
      assert.match(result.message, /[Nn]o completion credit was awarded/);
      assert.doesNotMatch(result.message, /didn't reveal|Congratulations/);
    } else if (verdict === 'pass') assert.match(result.message, /Congratulations/);
    else assert.match(result.message, /didn't reveal/);
  }
});

// Zero is a valid instructor-configured score, not missing configuration.
test('CTF completion feedback preserves zero score and defaults only missing scores', async () => {
  for (const [score, penalty, expected] of [[0, 0, 0], [0, 20, 0], [50, 20, 30], [undefined, 20, 80]]) {
    const result = await runCtfResultGraph({
      participant: { id: 1 }, stageId: 3,
      stage: { stage_name: 'Fixture', level_score: score }, attemptNumber: 2,
      studentResponse: 'controlled response', showFeedback: false,
    }, {
      judgment: { verdict: 'pass' },
      commit: async () => ({ accepted: true }),
      CTFHelpers: { getConfig: async () => '3', getProgress: async () => ({ hint_penalty_total: penalty }) },
    });
    assert.equal(result.success, true);
    assert.equal(result.message.split('Score: +')[1].split(' ')[0], String(expected));
  }
});
