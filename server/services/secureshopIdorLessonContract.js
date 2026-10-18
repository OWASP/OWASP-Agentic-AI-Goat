'use strict';

// Numeric teaching IDs are deliberately separate from the opaque choices used
// by the ordinary owner-scoped customer commerce tools.
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[1-5][a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i;
const TOOLS = Object.freeze({
  cart_remove: 'lesson.cart_remove',
  order_status: 'lesson.order_status',
});
const MANIFEST = Object.freeze(Object.entries(TOOLS).map(([action, key]) => {
  const [agent, tool] = key.split('.');
  return Object.freeze({ agent, tool,
    description: action === 'cart_remove'
      ? 'Remove the selected reserved practice cart line by its numeric teaching ID.'
      : 'Read the selected reserved practice order by its numeric teaching ID.',
    inputSchema: Object.freeze({ type: 'object', properties: Object.freeze({
      numericId: Object.freeze({ type: 'integer', minimum: 1, maximum: Number.MAX_SAFE_INTEGER }),
    }), required: Object.freeze(['numericId']), additionalProperties: false }),
  });
}));

function fail() {
  return Object.assign(new TypeError('Invalid isolated access-control lesson selection'), {
    code: 'IDOR_LESSON_SELECTION_INVALID', executionBoundary: true,
  });
}
function exact(value, keys) {
  return value && Object.getPrototypeOf(value) === Object.prototype
    && Object.keys(value).sort().join(',') === keys.slice().sort().join(',');
}
function positiveId(value) {
  if (!Number.isSafeInteger(value) || value < 1) throw fail();
  return value;
}
function selection(value) {
  if (!exact(value, ['action', 'numericId']) || !Object.hasOwn(TOOLS, value.action)) throw fail();
  return Object.freeze({ action: value.action, numericId: positiveId(value.numericId) });
}
function turnOrigin(value, action) {
  if (!exact(value, ['sessionId', 'requestId', 'runId', 'step', 'callId', 'toolKey'])
      || ![value.sessionId, value.requestId, value.runId].every(id => typeof id === 'string' && UUID.test(id))
      || !Number.isSafeInteger(value.step) || value.step < 0 || value.step > 32
      || typeof value.callId !== 'string'
      || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value.callId)
      || value.toolKey !== TOOLS[action]) throw fail();
  return Object.freeze({ sessionId: value.sessionId.toLowerCase(),
    requestId: value.requestId.toLowerCase(), runId: value.runId.toLowerCase(),
    step: value.step, callId: value.callId, toolKey: value.toolKey });
}

module.exports = { IDOR_LESSON_TOOLS: TOOLS, IDOR_LESSON_MANIFEST: MANIFEST,
  normalizeIdorLessonSelection: selection, normalizeIdorLessonTurnOrigin: turnOrigin };
