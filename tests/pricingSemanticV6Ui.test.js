'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

test('v6 labels separate source classes, task relation, and response support', async () => {
  const { judgeStageLabel } = await import('../client/src/utils/judgeFailureMessage.mjs');
  assert.deepEqual(['source', 'effect', 'relation', 'support'].map(stage => judgeStageLabel('pricing-semantic-decomposition-v6', stage)), [
    'Source inventory', 'Source coverage and fulfillment class', 'Task relation', 'Response assessment',
  ]);
});
