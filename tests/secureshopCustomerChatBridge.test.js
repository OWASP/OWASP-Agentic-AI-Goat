'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');

test('customer chat bridge admits only the exact persisted request and recovery reference', async () => {
  const { compileOperation, matchOperationRequest } = await import('../client/src/pages/secureshop/bridge/operations.mjs');
  const sessionId = randomUUID(), requestId = randomUUID();
  const body = { sessionId, message: 'Show my cart', requestId };
  const chat = compileOperation('agent.customer.chat', { body });
  assert.equal(chat.method, 'POST');
  assert.equal(chat.responseKind, 'sse');
  assert.deepEqual(chat.body, body);
  assert.equal(matchOperationRequest({ pathname: chat.path, method: chat.method, body }).name, 'agent.customer.chat');
  const read = compileOperation('agent.customer.operation', { params: { sessionId, requestId } });
  assert.equal(read.path, `/api/secureshop/agents/customer/operations/${sessionId}/${requestId}`);
  assert.equal(read.method, 'GET');
  assert.equal(Object.hasOwn(read, 'body'), false);
  assert.equal(matchOperationRequest({ pathname: read.path, method: read.method }).name, 'agent.customer.operation');
  for (const field of ['ownerId', 'persona', 'targetId', 'tool']) {
    assert.throws(() => compileOperation('agent.customer.chat', { body: { ...body, [field]: 'forged' } }));
  }
  assert.throws(() => compileOperation('agent.customer.operation', {
    params: { sessionId, requestId: '../other' },
  }));
});
