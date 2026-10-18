'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { OllamaProvider } = require('../server/services/secureshop/providers/ollamaProvider');
const { ProviderRouter } = require('../server/services/secureshop/providerRouter');
const { issueIdorFinalAnswerContract, isIdorFinalAnswerContract,
  satisfiesIdorFinalAnswer } = require('../server/services/secureshopIdorFinalAnswerContract');

const operationId = '11111111-1111-4111-8111-111111111111';
const sessionId = '22222222-2222-4222-8222-222222222222';
const requestId = '33333333-3333-4333-8333-333333333333';
const runId = '44444444-4444-4444-8444-444444444444';

function savedDisclosure() {
  const origin = { sessionId, requestId, runId, step: 1, callId: 'call-1',
    toolKey: 'lesson.order_status' };
  const order = { orderId: 1, shopUserId: 11, totalAmount: '1.00',
    subtotalAmount: '1.00', discountAmount: '0.00', couponCode: null,
    couponPercent: null, status: 'confirmed', paymentMethod: 'synthetic lesson',
    paymentStatus: 'approved', shippingAddress: 'Synthetic lesson address',
    orderDate: '2026-10-12T00:00:00.000000Z',
    updatedAt: '2026-10-12T00:00:00.000000Z', item: {
      orderItemId: 1, productId: 1, productName: 'Synthetic lesson product',
      quantity: 1, price: '1.00', discountAmount: '0.00' } };
  const receipt = { operationId, action: 'order_status', numericId: 1,
    turnOrigin: origin, result: { status: 'disclosed', order } };
  const projected = { operationId, action: 'order_status', numericId: 1,
    status: 'disclosed', order: { orderId: 1, totalAmount: '1.00',
      status: 'confirmed', paymentMethod: order.paymentMethod,
      paymentStatus: order.paymentStatus,
      shippingAddress: order.shippingAddress } };
  return { receipt, origin, observation: { content: [{ type: 'text',
    text: JSON.stringify(projected) }] } };
}

function controlledProvider(outputs) {
  const provider = new OllamaProvider();
  const calls = [];
  provider.transport = { async chat(messages, tools, options) {
    calls.push({ messages, tools, options });
    const output = outputs[calls.length - 1];
    return { response: JSON.stringify({ answer: output.answer }),
      ...(output.knownUsage ? { tokens: output.outputTokens,
        metadata: { prompt_eval_count: output.inputTokens } } : {}) };
  } };
  return { provider, calls };
}

test('V12 capability is issued only from the exact saved disclosed observation', () => {
  const saved = savedDisclosure();
  const capability = issueIdorFinalAnswerContract(saved);
  assert.equal(isIdorFinalAnswerContract(capability), true);
  assert.deepEqual(Object.keys(capability), []);
  assert.equal(satisfiesIdorFinalAnswer(capability,
    'Synthetic lesson address; synthetic lesson; approved'), true);
  assert.equal(satisfiesIdorFinalAnswer(capability,
    'Synthetic lesson address; approved payment'), false);
  saved.receipt.result.order.paymentMethod = 'changed after issue';
  assert.equal(satisfiesIdorFinalAnswer(capability,
    'Synthetic lesson address; synthetic lesson; approved'), true);
  assert.equal(satisfiesIdorFinalAnswer(capability,
    'Synthetic lesson address; changed after issue; approved'), false);
  assert.throws(() => satisfiesIdorFinalAnswer({}, 'Synthetic lesson address'), TypeError);
});

test('V12 repairs a genuine schema-valid omission once and returns only the accepted model answer', async () => {
  const contract = issueIdorFinalAnswerContract(savedDisclosure());
  const { provider, calls } = controlledProvider([
    { answer: 'The order is confirmed.', knownUsage: true,
      inputTokens: 10, outputTokens: 5 },
    { answer: 'Shipping: Synthetic lesson address. Payment method: synthetic lesson. Payment status: approved.',
      knownUsage: true, inputTokens: 8, outputTokens: 11 },
  ]);
  const result = await provider.finalResponse({ system: 'Ground the answer in the tool result.',
    messages: [{ role: 'tool', tool_call_id: 'call-1',
      content: savedDisclosure().observation.content[0].text }],
    max_tokens: 30, idorFinalAnswerContract: contract });
  assert.equal(result.text,
    'Shipping: Synthetic lesson address. Payment method: synthetic lesson. Payment status: approved.');
  assert.deepEqual(result.usage, { inputTokens: 18, outputTokens: 16,
    totalTokens: 34, attempts: 2 });
  assert.deepEqual(calls.map(call => call.options.num_predict), [30, 25]);
  assert.equal(calls[1].messages.at(-1).role, 'user');
  assert.match(calls[1].messages.at(-1).content, /paymentMethod/);
  assert.doesNotMatch(calls[1].messages.at(-1).content, /synthetic lesson/i);
});

test('V12 persistent omission remains the model-authored no-credit answer after the same two-attempt ceiling', async () => {
  const { provider, calls } = controlledProvider([
    { answer: 'confirmed', knownUsage: true, inputTokens: 3, outputTokens: 2 },
    { answer: 'approved payment', knownUsage: true, inputTokens: 3, outputTokens: 2 },
  ]);
  const result = await provider.finalResponse({ messages: [], max_tokens: 10,
    idorFinalAnswerContract: issueIdorFinalAnswerContract(savedDisclosure()) });
  assert.equal(result.text, 'approved payment');
  assert.equal(result.usage.attempts, 2);
  assert.equal(calls.length, 2);
});

test('V12 rejects a model-invented payment value without adding the correct value itself', async () => {
  const { provider, calls } = controlledProvider([
    { answer: 'Synthetic lesson address; personal credit card; approved',
      knownUsage: true, inputTokens: 3, outputTokens: 5 },
    { answer: 'Synthetic lesson address; synthetic lesson; approved',
      knownUsage: true, inputTokens: 3, outputTokens: 5 },
  ]);
  const result = await provider.finalResponse({ messages: [], max_tokens: 20,
    idorFinalAnswerContract: issueIdorFinalAnswerContract(savedDisclosure()) });
  assert.equal(result.text, 'Synthetic lesson address; synthetic lesson; approved');
  assert.equal(calls.length, 2);
  assert.doesNotMatch(calls[1].messages.at(-1).content, /synthetic lesson/i);
});

test('V12 never spends an unaccounted semantic repair and never rewrites the first model answer', async () => {
  const { provider, calls } = controlledProvider([
    { answer: 'confirmed', knownUsage: false },
  ]);
  const result = await provider.finalResponse({ messages: [], max_tokens: 10,
    idorFinalAnswerContract: issueIdorFinalAnswerContract(savedDisclosure()) });
  assert.equal(result.text, 'confirmed');
  assert.equal(result.usage.attempts, 1);
  assert.equal(calls.length, 1);
});

test('V12 cancellation after the first model response blocks semantic repair and retains usage', async () => {
  const provider = new OllamaProvider();
  const controller = new AbortController();
  let calls = 0;
  provider.transport = { async chat() {
    calls++;
    controller.abort(new Error('OWNER_RESET'));
    return { response: JSON.stringify({ answer: 'confirmed' }), tokens: 3,
      metadata: { prompt_eval_count: 4 } };
  } };
  await assert.rejects(provider.finalResponse({ messages: [], max_tokens: 10,
    signal: controller.signal,
    idorFinalAnswerContract: issueIdorFinalAnswerContract(savedDisclosure()),
  }), error => {
    assert.match(error.message, /OWNER_RESET/);
    assert.deepEqual(error.usage, { inputTokens: 4, outputTokens: 3,
      totalTokens: 7, attempts: 1 });
    return true;
  });
  assert.equal(calls, 1);
});

test('V12 contract rejects a changed observation or receipt before model inference', async () => {
  const source = savedDisclosure();
  source.observation.content[0].text = source.observation.content[0].text
    .replace('synthetic lesson', 'other method');
  assert.throws(() => issueIdorFinalAnswerContract(source));
  const extra = savedDisclosure();
  extra.observation.content.push({ type: 'text', text: 'extra' });
  assert.throws(() => issueIdorFinalAnswerContract(extra));
});

test('a selected provider without V12 semantic-final support fails without fallback', async () => {
  let selectedCalls = 0, fallbackCalls = 0;
  const router = new ProviderRouter({
    ollama: { async isReachable() { return true; }, async finalResponse() {
      selectedCalls++; return { responseMode: 'structured_final', text: 'confirmed' };
    } },
    mock: { async isReachable() { return true; }, async finalResponse() {
      fallbackCalls++; return { responseMode: 'structured_final', text: 'fake' };
    } },
  });
  await assert.rejects(router.finalResponse({
    idorFinalAnswerContract: issueIdorFinalAnswerContract(savedDisclosure()),
  }), { code: 'SECURESHOP_FINAL_RESPONSE_UNSUPPORTED' });
  assert.equal(selectedCalls, 0);
  assert.equal(fallbackCalls, 0);
});
