'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { createHash, randomUUID } = require('node:crypto');
const express = require('express');
const { DECISION_SCHEMA, FINAL_RESPONSE_SCHEMA } =
  require('../server/services/secureshop/providers/ollamaProvider');
const { createSceneBinding } = require('../server/services/secureshopSceneBinding');
const { createLaunchScope } = require('../server/services/secureshopConversationBinding');
const { TICKET_SCOPE, TICKET_FLAGS, assertTicketRenderedReceipt,
  assertTicketActorWire, captureTicketAssessmentResponse, waitForOriginalAssessment } =
  require('./fixtures/secureshopTicketRenderedQualification');

const complete = () => Object.fromEntries([
  ...TICKET_FLAGS.map(flag => [flag, true]),
  ['passed', true], ['scope', TICKET_SCOPE], ['actorCalls', 3],
  ['judgeCalls', 2], ['roleTurns', 1], ['browserEffects', 1],
  ['genuineCredit', 1], ['cleanupErrors', []], ['errors', []],
]);

test('retained target birth stays shared while each reader has its own current scene grant', () => {
  const birth = { targetId: randomUUID(), launchId: randomUUID(),
    scenarioId: randomUUID(), generation: 1, platformOwnerId: 11,
    platformSessionId: 21 };
  const customer = { launchId: birth.launchId, scenarioId: birth.scenarioId,
    generation: 1, platformOwnerId: 11, platformSessionId: 21 };
  const admin = { launchId: randomUUID(), scenarioId: randomUUID(),
    generation: 1, platformOwnerId: 11, platformSessionId: 22 };
  const sceneId = randomUUID();
  const bind = execution => createSceneBinding(birth, { sceneId,
    sceneGeneration: 1, grantId: randomUUID(), execution,
    withLease: work => work() });
  const source = bind(customer), reader = bind(admin);
  assert.equal(reader.targetId, source.targetId);
  assert.equal(reader.launchId, source.launchId);
  assert.equal(reader.scene.sceneId, source.scene.sceneId);
  assert.deepEqual(reader.scene.execution, createLaunchScope(admin));
  assert.notEqual(reader.scene.execution.launchId, source.scene.execution.launchId);
  assert.notEqual(reader.scene.grantId, source.scene.grantId);
});

test('one confirmed ticket and same-body fixed/vulnerable viewer proof requires every distinct gate', () => {
  assert.deepEqual(assertTicketRenderedReceipt(complete()), complete());
  for (const flag of TICKET_FLAGS) assert.throws(() =>
    assertTicketRenderedReceipt({ ...complete(), [flag]: false }));
  for (const change of [
    { actorCalls: 1 }, { actorCalls: 5 }, { judgeCalls: 0 },
    { judgeCalls: 3 }, { actorCalls: 4, judgeCalls: 3 },
    { roleTurns: 2 }, { browserEffects: 0 }, { genuineCredit: 0 },
    { cleanupErrors: ['unretired browser'] }, { modelOutput: 'claimed' },
    { errors: [{ stage: 'failed' }] },
  ]) assert.throws(() => assertTicketRenderedReceipt({ ...complete(), ...change }));
});

test('raw selected ticket args and final text bind the saved turn without a claimed wire', () => {
  const digest = value => createHash('sha256').update(value).digest('hex');
  const makeWire = (schema, content) => {
    const request = JSON.stringify({ model: 'llama3.1:8b', messages: [{ role: 'user', content: 'ticket' }],
      format: schema });
    const response = `${JSON.stringify({ message: { content }, done: true })}\n`;
    return { kind: 'actor', status: 200, responseComplete: true,
      responseCaptureTruncated: false, request, response,
      requestSha256: digest(request), responseSha256: digest(response) };
  };
  const requestRef = '11111111-1111-5111-8111-111111111111';
  const callId = 'ollama_owned_call';
  const spans = [
    { method: 'chat', result: { stop_reason: 'tool_use', tool_uses: [{ id: callId,
      name: 'support.ticket_prepare', args: { requestRef } }] },
    wires: [makeWire(DECISION_SCHEMA, JSON.stringify({ tool_calls: [{ agent: 'support',
      tool: 'ticket_prepare', args: { requestRef } }] }))] },
    { method: 'finalResponse', result: { stop_reason: 'end_turn', text: 'Ready to review.' },
      wires: [makeWire(FINAL_RESPONSE_SCHEMA, JSON.stringify({ answer: 'Ready to review.' }))] },
  ];
  const input = { spans, turn: { text: 'Ready to review.' }, origin: { callId },
    requestRef, model: 'llama3.1:8b' };
  assert.equal(assertTicketActorWire(input), spans);
  assert.throws(() => assertTicketActorWire({ ...input,
    requestRef: '22222222-2222-5222-8222-222222222222' }));
  assert.throws(() => assertTicketActorWire({ ...input, turn: { text: 'claimed answer' } }));
  assert.throws(() => assertTicketActorWire({ ...input, origin: { callId: 'other' } }));
});

test('passive ticket assessment capture preserves the original HTTP response and request ID', async () => {
  const requestId = randomUUID();
  const payload = { completed: true, judgment: { evaluationId: randomUUID(),
    verdict: 'pass', canRetry: false }, replayed: false };
  const app = express(); app.use(express.json());
  let resolveCapture;
  const captured = new Promise(resolve => { resolveCapture = resolve; });
  app.use('/api/secureshop', (request, response, next) => {
    captureTicketAssessmentResponse(request, response, resolveCapture);
    next();
  });
  const router = express.Router();
  router.post('/admin/tickets/1/assessment', (request, response) => {
    request.body.requestId = randomUUID();
    response.status(200).json(payload);
  });
  app.use('/api/secureshop', router);
  const server = await new Promise(resolve => {
    const listening = app.listen(0, '127.0.0.1', () => resolve(listening));
  });
  try {
    const response = await fetch(`http://127.0.0.1:${server.address().port}/api/secureshop/admin/tickets/1/assessment`, {
      method: 'POST', headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ requestId }), signal: AbortSignal.timeout(3000) });
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), payload);
    let timer;
    const original = await Promise.race([captured,
      new Promise((_, reject) => { timer = setTimeout(() => reject(Error('capture timeout')), 3000); })]);
    clearTimeout(timer);
    assert.equal(original.method, 'POST');
    assert.equal(original.path, '/admin/tickets/1/assessment');
    assert.deepEqual(original.requestBody, { requestId });
    assert.equal(original.status, 200);
    assert.match(original.contentType, /^application\/json\b/);
    assert.equal(original.error, null);
    assert.equal(original.body, JSON.stringify(payload));
  } finally { await new Promise((resolve, reject) => server.close(error =>
    error ? reject(error) : resolve())); }
});

test('original assessment waiter ignores earlier responses and rejects duplicate request IDs', async () => {
  const path = '/admin/tickets/1/assessment', requestId = randomUUID();
  const old = { path, requestBody: { requestId: randomUUID() } };
  const matching = { path, requestBody: { requestId } };
  const captures = [old];
  setTimeout(() => captures.push(matching), 25);
  assert.equal(await waitForOriginalAssessment(captures, path, requestId, 200), matching);
  captures.push({ ...matching });
  await assert.rejects(waitForOriginalAssessment(captures, path, requestId, 50),
    /one original assessment response/);
});
