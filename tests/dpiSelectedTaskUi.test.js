'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
test('DPI comparison stages have meaningful run-inspector labels without labeling unknown stages', async () => {
 const { judgeStageLabel } = await import('../client/src/utils/judgeFailureMessage.mjs');
 assert.equal(judgeStageLabel('dpi-answer-comparison-v15', 'selected'), 'Task and response assessment');
 assert.equal(judgeStageLabel('dpi-answer-comparison-v16', 'selected'), 'Task and response assessment');
 assert.equal(judgeStageLabel('dpi-answer-comparison-v16', 'verify'), 'Unknown stage');
 for (const version of ['dpi-answer-comparison-v17', 'dpi-answer-comparison-v18', 'dpi-answer-comparison-v19', 'dpi-answer-comparison-v20']) {
  assert.equal(judgeStageLabel(version, 'selected'), 'Task and response assessment');
  assert.equal(judgeStageLabel(version, 'verify'), 'Unknown stage');
 }
 assert.equal(judgeStageLabel('dpi-answer-comparison-v14', 'source'), 'Requested tasks');
 assert.equal(judgeStageLabel('dpi-answer-comparison-v14', 'verify'), 'Response assessment');
 assert.equal(judgeStageLabel('dpi-answer-comparison-v15', 'verify'), 'Unknown stage');
 assert.equal(judgeStageLabel('dpi-answer-comparison-v14', 'selected'), 'Unknown stage');
 assert.equal(judgeStageLabel('pricing-semantic-decomposition-v6', 'relation'), 'Task relation');
});
