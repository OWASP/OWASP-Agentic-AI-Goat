'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { IDOR_LESSON_TOOLS, IDOR_LESSON_MANIFEST,
  normalizeIdorLessonSelection, normalizeIdorLessonTurnOrigin } =
  require('../server/services/secureshopIdorLessonContract');
const { shouldAssessCommittedIdorLesson } =
  require('../server/services/secureshopBoundIdorLessonChat');

const id = '11111111-1111-4111-8111-111111111111';
test('isolated lesson selects only one reserved numeric ID and its matching original tool', () => {
  assert.deepEqual(Object.keys(IDOR_LESSON_TOOLS), ['cart_remove', 'order_status']);
  assert.equal(IDOR_LESSON_MANIFEST.length, 2);
  for (const action of Object.keys(IDOR_LESSON_TOOLS)) {
    assert.deepEqual(normalizeIdorLessonSelection({ action, numericId: 42 }),
      { action, numericId: 42 });
    assert.deepEqual(normalizeIdorLessonTurnOrigin({ sessionId: id, requestId: id,
      runId: id, step: 1, callId: 'model-tool-1', toolKey: IDOR_LESSON_TOOLS[action] }, action),
    { sessionId: id, requestId: id, runId: id, step: 1, callId: 'model-tool-1',
      toolKey: IDOR_LESSON_TOOLS[action] });
  }
  for (const candidate of [
    { action: 'cart_remove', numericId: 0 },
    { action: 'cart_remove', numericId: Number.MAX_SAFE_INTEGER + 1 },
    { action: 'cart_remove', numericId: '42' },
    { action: 'cart_remove', numericId: 42, shopUserId: 7 },
    { action: 'orders.list', numericId: 42 },
  ]) assert.throws(() => normalizeIdorLessonSelection(candidate),
    { code: 'IDOR_LESSON_SELECTION_INVALID' });
  assert.throws(() => normalizeIdorLessonTurnOrigin({ sessionId: id, requestId: id,
    runId: id, step: 1, callId: 'model-tool-1', toolKey: 'lesson.order_status' }, 'cart_remove'),
  { code: 'IDOR_LESSON_SELECTION_INVALID' });
});

test('a terminal refusal with no selected tool never starts an assessment', () => {
  const receipt = { operationId: id, mode: { mode: 'vuln' },
    result: { status: 'deleted' } };
  const terminal = { taskMetadata: { idorLesson: { operationId: id } } };
  assert.equal(shouldAssessCommittedIdorLesson(terminal, null), false);
  assert.equal(shouldAssessCommittedIdorLesson({ taskMetadata: { idorLesson: null } },
    { receipt }), false);
  assert.equal(shouldAssessCommittedIdorLesson(terminal,
    { receipt: { ...receipt, operationId: 'other' } }), false);
  assert.equal(shouldAssessCommittedIdorLesson(terminal,
    { receipt: { ...receipt, result: { status: 'denied' } } }), false);
  assert.equal(shouldAssessCommittedIdorLesson(terminal, { receipt }), true);
});
